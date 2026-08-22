//! heraclitus-log — o único escritor da verdade.
//!
//! Um log segmentado, append-only e imutável de [`Episode`]s. Todo o resto
//! no HeraclitusDB é uma visão materializada sobre este log.
//!
//! Durabilidade: crc32 por registro, raiz Merkle blake3 por segmento selado,
//! recuperação de torn-writes ao abrir via engine de validação e reparo isolados.
//!
//! Propriedades do núcleo (honestas — ver revisão 2026-07-16):
//! - Catálogo com structural sharing (`Arc`): commits não copiam vetores globais.
//! - Buffers de serialização/cifra reutilizados no laço de escrita. NOTA: o
//!   hot-path NÃO é zero-alloc — cada append clona o episódio para o
//!   `StoragePayload` e a cifra (`seal`) aloca o ciphertext; é o custo real.
//! - Barreira de LSN: o `committed_lsn` só avança após o fsync confirmar.
//! - Varredura de passada única sob `BufReader` (recovery O(N) em I/O).
//! - Canais crossbeam uniformes no worker (sem mistura de runtimes).

pub mod cpm;
pub mod format;
pub mod mmap;
pub mod skip_scan; // SPEC-010: segment-level skip-I/O scan wired on zone maps
pub mod subscribe; // SPEC-022: StreamSubscriber ligado ao tail do log
pub mod v6; // SPEC-0050: HRKL v6 — canónico, PACKED, sidecars e lakehouse
pub mod vm_bridge;
pub mod zone_map; // SPEC-010: per-segment min/max skip-I/O primitive

use arc_swap::ArcSwap;
use format::{Decoded, SegmentFooter, SegmentHeader, HEADER_LEN};
use heraclitus_core::{
    Episode, EventId, EventKind, FsyncPolicy, HeraclitusError, Hlc, Lsn, ProductPoint, SegmentId,
};
use heraclitus_crypto::KeyStore;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();
const ENCRYPTED_FIELDS_ATTR: &str = "__heraclitus_encrypted_fields_v1";
const SHREDDED_ATTR: &str = "__heraclitus_shredded";

#[derive(serde::Serialize, serde::Deserialize)]
struct SensitiveFields {
    attrs: std::collections::BTreeMap<String, String>,
    embedding: Option<ProductPoint>,
}

fn is_public_technical_attr(name: &str) -> bool {
    matches!(
        name,
        "__heraclitus_idempotency_key" | "__heraclitus_idempotency_hash"
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

fn fields_aad(agent_id: &str) -> Vec<u8> {
    let mut aad = agent_id.as_bytes().to_vec();
    aad.extend_from_slice(b"\0fields-v1");
    aad
}

fn segment_path(dir: &Path, id: SegmentId) -> PathBuf {
    dir.join(format!("{id:020}.hrkl"))
}

#[derive(Debug, Clone)]
pub struct SegmentMeta {
    pub id: SegmentId,
    pub path: PathBuf,
    pub base_lsn: Lsn,
    pub max_lsn: Lsn,
    pub sealed: bool,
    pub blake3_root: Option<[u8; 32]>,
    /// FORMAT_VERSION do segmento no disco. Segmentos antigos permanecem
    /// legíveis: a versão decide a regra de CRC/leaf E o layout do payload
    /// (v<=2: `Episode` serializado direto; v3+: `StoragePayload`).
    pub version: u16,
}

#[derive(Copy, Clone, Debug)]
pub struct LsnEntry {
    pub lsn: Lsn,
    pub offset: u64,
    pub opaque_meta: [u8; 16],
}

pub struct SegmentIndex {
    /// Otimização de Memória Contígua: Substituição de BTreeMap por Smart Shared Array imutável.
    pub entries: Arc<Vec<LsnEntry>>,
}

pub struct SegmentContainer {
    pub meta: SegmentMeta,
    pub index: Arc<SegmentIndex>,
}

/// Catálogo com Structural Sharing Granular por Segmento.
pub struct LogCatalog {
    pub sealed: Arc<Vec<Arc<SegmentContainer>>>,
    pub active: Arc<SegmentContainer>,
}

struct Active {
    file: File,
    segment_id: SegmentId,
    bytes_written: u64,
    record_hashes: Vec<[u8; 32]>,
    base_lsn: Lsn,
    max_lsn: Lsn,
    last_sync: Instant,
}

enum LogCommand {
    Append {
        opaque_meta: [u8; 16],
        episode: Arc<Episode>,
        expected_lsn: Option<Lsn>,
        resp_tx: crossbeam_channel::Sender<Result<Lsn, HeraclitusError>>,
    },
    Flush {
        resp_tx: crossbeam_channel::Sender<Result<(), HeraclitusError>>,
    },
}

struct StashedUpdate {
    lsn: Lsn,
    opaque_meta: [u8; 16],
    offset: u64,
    episode: Arc<Episode>,
    resp_tx: crossbeam_channel::Sender<Result<Lsn, HeraclitusError>>,
}

struct WorkerDropGuard {
    poisoned: Arc<AtomicBool>,
}

impl Drop for WorkerDropGuard {
    fn drop(&mut self) {
        self.poisoned.store(true, Ordering::SeqCst);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoragePayload {
    pub opaque_meta: [u8; 16],
    pub id: EventId,
    pub agent_id: String,
    pub session_id: String,
    pub ts_hlc: u64,
    pub kind: EventKind,
    pub content: Vec<u8>,
    pub embedding: Option<ProductPoint>,
    pub attrs: std::collections::BTreeMap<String, String>,
    pub parents: Vec<EventId>,
    /// FORMAT v4: valid time nativo (mundo real), distinto do transaction time.
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
}

/// Só o PRIMEIRO campo do payload (v3+): os 16 bytes de `opaque_meta`.
///
/// O bincode desserializa os campos por ordem e pára quando o struct acaba,
/// portanto isto lê 16 bytes em vez do `Episode` inteiro. É o que o
/// `scan_segment_file` precisa — e só isso — para reconstruir o índice no
/// arranque. `StoragePayload` e `StoragePayloadV3` declaram `opaque_meta`
/// primeiro; se alguma geração futura mudar essa ordem, este struct tem de
/// mudar com ela (o teste `prefixo_opaque_meta_bate_com_payload_completo`
/// falha se divergirem).
#[derive(serde::Deserialize)]
struct OpaqueMetaPrefix {
    opaque_meta: [u8; 16],
}

/// Layout EXATO do payload FORMAT v3 (pré-Valid-Time). O bincode não é
/// autodescritivo: cada geração de formato precisa da sua réplica de struct.
/// (`pub` + Serialize só para os testes de compat fabricarem segmentos v3.)
#[doc(hidden)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StoragePayloadV3 {
    pub opaque_meta: [u8; 16],
    pub id: EventId,
    pub agent_id: String,
    pub session_id: String,
    pub ts_hlc: u64,
    pub kind: EventKind,
    pub content: Vec<u8>,
    pub embedding: Option<ProductPoint>,
    pub attrs: std::collections::BTreeMap<String, String>,
    pub parents: Vec<EventId>,
}

/// Layout EXATO do `Episode` como era persistido DIRETO nos payloads v<=2
/// (pré-M30): id, ts_hlc, agent, session, kind, content, embedding, attrs,
/// parents — sem opaque_meta e sem valid time.
#[derive(serde::Deserialize)]
struct EpisodeV2 {
    pub id: EventId,
    pub ts_hlc: u64,
    pub agent_id: String,
    pub session_id: String,
    pub kind: EventKind,
    pub content: Vec<u8>,
    pub embedding: Option<ProductPoint>,
    pub attrs: std::collections::BTreeMap<String, String>,
    pub parents: Vec<EventId>,
}

impl EpisodeV2 {
    fn into_episode(self) -> Episode {
        Episode {
            id: self.id,
            ts_hlc: self.ts_hlc,
            agent_id: self.agent_id,
            session_id: self.session_id,
            kind: self.kind,
            content: self.content,
            embedding: self.embedding,
            attrs: self.attrs,
            parents: self.parents,
            valid_from: None,
            valid_to: None,
        }
    }
}

impl StoragePayloadV3 {
    fn into_episode(self) -> Episode {
        Episode {
            id: self.id,
            ts_hlc: self.ts_hlc,
            agent_id: self.agent_id,
            session_id: self.session_id,
            kind: self.kind,
            content: self.content,
            embedding: self.embedding,
            attrs: self.attrs,
            parents: self.parents,
            valid_from: None,
            valid_to: None,
        }
    }
}

/// Descodifica o payload bincode de um registo físico para o `Episode`
/// completo, conforme a VERSÃO do segmento — o bincode não é autodescritivo,
/// por isso cada geração tem a sua réplica de layout:
///
/// - v<=2 (pré-M30): `Episode` (sem valid time) serializado direto;
/// - v3: `StoragePayloadV3` (opaque_meta + episódio completo, sem valid time);
/// - v4+: `StoragePayload` (com `valid_from`/`valid_to` nativos).
///
/// Descodificar com o layout errado desaloca os campos (Utf8Error).
/// Consumidores: read/scan internos e o tier (recall-on-demand). O `content`
/// volta como foi persistido (cifrado se havia keystore).
pub fn decode_episode_payload(version: u16, payload: &[u8]) -> Result<Episode, HeraclitusError> {
    Ok(decode_episode_payload_with_meta(version, payload)?.episode)
}

/// Resultado da descodificação do payload persistido.
///
/// O `Episode` público não carrega `opaque_meta`, mas esse campo faz parte da
/// identidade canónica do HRKL v6. Expor os dois juntos evita a armadilha de
/// reconstruir uma raiz lógica a partir de `Episode` e, sem querer, apagar os
/// 16 bytes de metadados de consenso da prova.
#[derive(Debug, Clone)]
pub struct DecodedStoragePayload {
    pub opaque_meta: [u8; 16],
    pub episode: Episode,
}

/// Descodifica um payload de armazenamento preservando o `opaque_meta`.
///
/// Esta é a ponte oficial entre o formato legado de payload (v1--v5) e o
/// codec canónico v6. O formato físico do segmento v6 mantém inicialmente o
/// `StoragePayload` v4/v5 (§42); portanto [`canonical_hash_storage_payload_v6`]
/// usa esta função para que writer, packer, `verify --logical` e `prove` tenham
/// exactamente a mesma regra.
pub fn decode_episode_payload_with_meta(
    version: u16,
    payload: &[u8],
) -> Result<DecodedStoragePayload, HeraclitusError> {
    if version >= 4 {
        let (sp, _): (StoragePayload, usize) =
            bincode::serde::decode_from_slice(payload, BINCODE_CFG)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        Ok(DecodedStoragePayload {
            opaque_meta: sp.opaque_meta,
            episode: sp.into_episode(),
        })
    } else if version == 3 {
        let (sp, _): (StoragePayloadV3, usize) =
            bincode::serde::decode_from_slice(payload, BINCODE_CFG)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        Ok(DecodedStoragePayload {
            opaque_meta: sp.opaque_meta,
            episode: sp.into_episode(),
        })
    } else {
        let (ep, _): (EpisodeV2, usize) =
            bincode::serde::decode_from_slice(payload, BINCODE_CFG)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        // v1/v2 não persistiam opaque_meta. Zero é a única representação
        // honesta para uma migração canónica desses formatos; a raiz legada
        // nunca é reinterpretada como raiz v6 (§131).
        Ok(DecodedStoragePayload {
            opaque_meta: [0; 16],
            episode: ep.into_episode(),
        })
    }
}

/// Calcula o hash canónico oficial de um payload `StoragePayload` que será
/// escrito num segmento v6 RAW/PACKED.
///
/// A função é intencionalmente pública: o packer e as ferramentas forenses
/// recebem apenas `(lsn, hlc, payload)` do formato físico. Centralizar aqui a
/// conversão impede que cada chamador invente uma interpretação de bincode ou
/// esqueça `opaque_meta`.
pub fn canonical_hash_storage_payload_v6(
    lsn: Lsn,
    record_hlc: u64,
    payload: &[u8],
) -> Result<[u8; 32], HeraclitusError> {
    let stored = decode_episode_payload_with_meta(format::FORMAT_VERSION, payload)?;
    Ok(v6::hash_episode_record(
        lsn,
        record_hlc,
        stored.opaque_meta,
        &stored.episode,
    ))
}

/// Codifica o payload que a primeira geração v6 mantém compatível com o
/// `StoragePayload` actual (§42). A cifra, quando configurada, é aplicada
/// **antes** do hash canónico: o leitor/packer vê exactamente os bytes que
/// ficaram persistidos e nunca plaintext acidentalmente.
pub(crate) fn encode_storage_payload_v6(
    opaque_meta: [u8; 16],
    episode: &Episode,
    keystore: Option<&KeyStore>,
) -> Result<Vec<u8>, HeraclitusError> {
    let (stored_content, stored_attrs, stored_embedding) = match keystore {
        Some(ks) => {
            let key = ks.get_or_create(&episode.agent_id).map_err(|e| {
                HeraclitusError::Crypto(format!("Keystore Isolation Fault: {e:?}"))
            })?;
            let stored_content = heraclitus_crypto::seal(
                &key,
                &episode.content,
                episode.agent_id.as_bytes(),
            );
            let public_attrs = episode
                .attrs
                .iter()
                .filter(|(k, _)| is_public_technical_attr(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<std::collections::BTreeMap<_, _>>();
            let sensitive = SensitiveFields {
                attrs: episode
                    .attrs
                    .iter()
                    .filter(|(k, _)| !is_public_technical_attr(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                embedding: episode.embedding.clone(),
            };
            let encoded = bincode::serde::encode_to_vec(&sensitive, BINCODE_CFG)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
            let sealed_fields = heraclitus_crypto::seal(&key, &encoded, &fields_aad(&episode.agent_id));
            let mut attrs = public_attrs;
            attrs.insert(ENCRYPTED_FIELDS_ATTR.into(), hex_encode(&sealed_fields));
            (stored_content, attrs, None)
        }
        None => (
            episode.content.clone(),
            episode.attrs.clone(),
            episode.embedding.clone(),
        ),
    };

    let storage_payload = StoragePayload {
        opaque_meta,
        id: episode.id,
        agent_id: episode.agent_id.clone(),
        session_id: episode.session_id.clone(),
        ts_hlc: episode.ts_hlc,
        kind: episode.kind.clone(),
        content: stored_content,
        embedding: stored_embedding,
        attrs: stored_attrs,
        parents: episode.parents.clone(),
        valid_from: episode.valid_from,
        valid_to: episode.valid_to,
    };
    bincode::serde::encode_to_vec(&storage_payload, BINCODE_CFG)
        .map_err(|e| HeraclitusError::Serialization(e.to_string()))
}

/// Reverte a cifra de um `Episode` já reconstruído do payload persistido.
/// Mantida fora de [`Log`] para que o reader v6 siga exactamente a mesma
/// semântica de crypto-shredding do reader legado.
pub(crate) fn decrypt_storage_episode_in_place(
    ep: &mut Episode,
    keystore: Option<&KeyStore>,
) -> Result<(), HeraclitusError> {
    let Some(ks) = keystore else {
        return Ok(());
    };
    let encrypted_content = heraclitus_crypto::is_encrypted(&ep.content);
    let encrypted_fields = ep.attrs.remove(ENCRYPTED_FIELDS_ATTR);
    if !encrypted_content && encrypted_fields.is_none() {
        return Ok(());
    }

    let Some(key) = ks.get(&ep.agent_id) else {
        // Ausência é a semântica normal de crypto-shredding, não corrupção.
        ep.content = heraclitus_crypto::SHREDDED.to_vec();
        ep.embedding = None;
        ep.attrs.retain(|k, _| is_public_technical_attr(k));
        ep.attrs.insert(SHREDDED_ATTR.into(), "true".into());
        return Ok(());
    };

    if encrypted_content {
        let opened = heraclitus_crypto::open(&key, &ep.content, ep.agent_id.as_bytes())
            .ok_or_else(|| {
                HeraclitusError::Crypto(format!(
                    "Assinatura inválida detectada na cifra do agente: {}",
                    ep.agent_id
                ))
            })?;
        ep.content = opened;
    }

    if let Some(encoded_hex) = encrypted_fields {
        let sealed = hex_decode(&encoded_hex).ok_or_else(|| {
            HeraclitusError::Crypto(format!(
                "Envelope de atributos ilegível para o agente: {}",
                ep.agent_id
            ))
        })?;
        let opened = heraclitus_crypto::open(&key, &sealed, &fields_aad(&ep.agent_id))
            .ok_or_else(|| {
                HeraclitusError::Crypto(format!(
                    "Assinatura inválida no envelope de atributos do agente: {}",
                    ep.agent_id
                ))
            })?;
        let (sensitive, _): (SensitiveFields, usize) =
            bincode::serde::decode_from_slice(&opened, BINCODE_CFG)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        ep.attrs.extend(sensitive.attrs);
        ep.embedding = sensitive.embedding;
    }
    Ok(())
}

impl StoragePayload {
    /// Reconstrói o `Episode` completo a partir do payload persistido. O
    /// `content` volta cifrado; quem chama aplica `decrypt_in_place` se preciso.
    fn into_episode(self) -> Episode {
        Episode {
            id: self.id,
            ts_hlc: self.ts_hlc,
            agent_id: self.agent_id,
            session_id: self.session_id,
            kind: self.kind,
            content: self.content,
            embedding: self.embedding,
            attrs: self.attrs,
            parents: self.parents,
            valid_from: self.valid_from,
            valid_to: self.valid_to,
        }
    }
}

pub struct Log {
    dir: PathBuf,
    hlc: Arc<Hlc>,
    committed_lsn: Arc<AtomicU64>,
    poisoned: Arc<AtomicBool>,
    catalog: Arc<ArcSwap<LogCatalog>>,
    tail_tx: broadcast::Sender<(Lsn, Arc<Episode>)>,
    cmd_tx: crossbeam_channel::Sender<LogCommand>,
    keystore: Option<Arc<KeyStore>>,
    /// Serializa (carimbo HLC + entrada na fila) para que a ordem de `ts` seja a
    /// mesma dos LSNs — contrato de que a busca binária do AS OF TIMESTAMP depende.
    stamp_lock: std::sync::Mutex<()>,
    /// Descritores abertos por segmento, partilhados entre leitores.
    ///
    /// Antes, CADA leitura pontual fazia `File::open` + `close`. Com o log de
    /// 20M (1 164 segmentos, 9,8 GB) isso era um par de syscalls por leitura,
    /// no caminho mais sensível a latência do motor. O cache guarda `Arc<File>`
    /// e as leituras são POSICIONAIS (`seek_read`/`read_at`), que aceitam
    /// `&File` — portanto o lock só cobre a consulta ao mapa, nunca o I/O, e
    /// vários leitores usam o mesmo descritor em paralelo sem se bloquearem.
    ///
    /// Medido (`benches/otim_leitura.rs`, 2026-08-19): 22 959 → 236 244
    /// leituras/s, **10,3×**, somando este cache e o fim da releitura do
    /// cabeçalho do segmento.
    ///
    /// Segmentos são imutáveis depois de selados e o ficheiro ativo só cresce,
    /// por isso um descritor nunca fica obsoleto: só o `truncate` o invalidaria,
    /// e essa superfície já não existe.
    fds: std::sync::Mutex<std::collections::HashMap<SegmentId, Arc<File>>>,
}

/// Leitura posicional: não move o cursor do ficheiro, portanto aceita `&File` e
/// pode ser chamada por vários leitores em paralelo sobre o MESMO descritor.
/// Substitui o par `seek` + `read_exact`, que exigia `&mut File`.
fn ler_exato_em(f: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        let n = {
            #[cfg(windows)]
            {
                use std::os::windows::fs::FileExt;
                f.seek_read(buf, offset)?
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileExt;
                f.read_at(buf, offset)?
            }
        };
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fim de ficheiro a meio do registo",
            ));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

fn sync_parent_dir(dir: &Path) -> Result<(), HeraclitusError> {
    #[cfg(unix)]
    {
        OpenOptions::new().read(true).open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn rollback_active_file(file: &mut File, bytes_written: u64) {
    let _ = file.set_len(bytes_written);
    let _ = file.seek(SeekFrom::Start(bytes_written));
    let _ = file.sync_data();
}

impl Log {
    pub fn open(
        dir: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
    ) -> Result<Self, HeraclitusError> {
        Self::open_with_keystore(dir, segment_max_bytes, fsync, None)
    }

    /// Abre o motor HRKL v6 explícito, isolado do layout legado v1--v5.
    ///
    /// O retorno é [`v6::V6Log`], não `Log`: trocar o backend por baixo de
    /// uma base existente seria uma migração implícita e insegura. Chamadores
    /// novos podem adoptar este caminho; bases legadas continuam em `open` até
    /// uma migração v1--v5→v6 auditável ser executada.
    pub fn open_v6(
        dir: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
    ) -> Result<v6::V6Log, HeraclitusError> {
        v6::V6Log::open(dir, segment_max_bytes, fsync)
    }

    /// Variante v6 com a mesma cifra por `agent_id` do caminho legado.
    pub fn open_v6_with_keystore(
        dir: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
        keystore: Option<Arc<KeyStore>>,
    ) -> Result<v6::V6Log, HeraclitusError> {
        v6::V6Log::open_with_keystore(dir, segment_max_bytes, fsync, keystore)
    }

    pub fn open_with_keystore(
        dir: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
        keystore: Option<Arc<KeyStore>>,
    ) -> Result<Self, HeraclitusError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;

        check_and_recover_truncate_intent(&dir)?;

        let hlc = Arc::new(Hlc::new());
        let mut ids: Vec<SegmentId> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                name.strip_suffix(".hrkl")?.parse::<u64>().ok()
            })
            .collect();
        ids.sort_unstable();

        let mut initial_sealed = Vec::new();
        let mut max_recovered_lsn: Option<Lsn> = None;
        let mut tail_scan: Option<(SegmentId, SegmentScan)> = None;

        // Os segmentos são ficheiros INDEPENDENTES: varrê-los é puro por
        // ficheiro. O tratamento a seguir (ordem dos LSN, selagem, catálogo)
        // continua serial e por ordem de id — só a varredura é paralela.
        // Medido a 1 187 segmentos: 3,47x só com isto (`benches/otim_boot.rs`).
        let mut scans = varrer_segmentos_em_paralelo(&dir, &ids)?;

        for (idx, id) in ids.iter().enumerate() {
            let path = segment_path(&dir, *id);
            let is_last = Some(*id) == ids.last().copied();

            let scan = scans[idx]
                .take()
                .expect("cada segmento é varrido exatamente uma vez");
            // O relógio HLC nunca arranca ATRÁS do que já está persistido:
            // sem isto, um wall clock que recuasse entre execuções quebraria
            // a monotonicidade de ts por LSN (o contrato do AS OF TIMESTAMP).
            hlc.observe(scan.max_hlc);
            if scan.corruption_detected || scan.valid_len < scan.file_len {
                // Uma cauda torn (crash a meio de uma escrita) só é legítima no
                // segmento ATIVO — o último. Num segmento ANTERIOR, que já estava
                // completo e normalmente selado, um registo ilegível é BIT ROT, e
                // truncar era catastrófico e silencioso: (1) apagava para sempre
                // todos os registos a seguir ao ponto corrompido, (2) o ramo de
                // re-selagem reescrevia a raiz Merkle só sobre os sobreviventes,
                // fazendo `verify_segment` responder `valid: true` — a prova de
                // adulteração era DESTRUÍDA em vez de reportada — e (3) ficava uma
                // LACUNA de LSN (o segmento seguinte mantém o seu base_lsn), pelo
                // que views reconstruídas do LSN 0 e leituras AS OF passavam a ver
                // um histórico com buraco. `Log::open` devolvia `Ok`.
                // Mesma política já aplicada ao WAL do raft (durable.rs): falhar
                // alto e preservar o ficheiro para perícia/restauro.
                if !is_last {
                    return Err(HeraclitusError::Corruption {
                        context: format!("segmento {id} ({})", path.display()),
                        detail: format!(
                            "registo ilegível no offset {} de um segmento NÃO-ativo \
                             (bit rot / falha de hardware). Recuso truncar: perderia os \
                             registos seguintes e reescreveria a raiz Merkle sobre o que \
                             sobrasse. Restaure este segmento de backup ou de uma réplica.",
                            scan.valid_len
                        ),
                    });
                }
                execute_physical_repair(&path, scan.valid_len)?;
            }

            let mut entries = Vec::with_capacity(scan.locs.len());
            for &(l, off, meta) in &scan.locs {
                entries.push(LsnEntry {
                    lsn: l,
                    offset: off,
                    opaque_meta: meta,
                });
                max_recovered_lsn = Some(max_recovered_lsn.map_or(l, |m| m.max(l)));
            }

            let base_l = scan
                .min_lsn
                .unwrap_or_else(|| max_recovered_lsn.map(|l| l + 1).unwrap_or(0));

            if scan.sealed {
                initial_sealed.push(Arc::new(SegmentContainer {
                    meta: SegmentMeta {
                        id: *id,
                        path: path.clone(),
                        base_lsn: base_l,
                        max_lsn: scan.max_lsn.unwrap_or(base_l),
                        sealed: true,
                        blake3_root: scan.blake3_root,
                        version: scan.version,
                    },
                    index: Arc::new(SegmentIndex {
                        entries: Arc::new(entries),
                    }),
                }));
            } else if is_last && scan.version == format::FORMAT_VERSION {
                tail_scan = Some((*id, scan));
            } else {
                seal_file(&path, &scan)?;
                initial_sealed.push(Arc::new(SegmentContainer {
                    meta: SegmentMeta {
                        id: *id,
                        path: path.clone(),
                        base_lsn: base_l,
                        max_lsn: scan.max_lsn.unwrap_or(base_l),
                        sealed: true,
                        blake3_root: Some(merkle_root(&scan.record_hashes)),
                        version: scan.version,
                    },
                    index: Arc::new(SegmentIndex {
                        entries: Arc::new(entries),
                    }),
                }));
            }
        }

        let initial_lsn = max_recovered_lsn.map(|l| l + 1).unwrap_or(0);

        let (active_state, active_container) = match tail_scan {
            Some((id, scan)) => {
                let file = OpenOptions::new()
                    .append(true)
                    .open(segment_path(&dir, id))?;
                let mut entries = Vec::with_capacity(scan.locs.len());
                for (l, off, meta) in scan.locs {
                    entries.push(LsnEntry {
                        lsn: l,
                        offset: off,
                        opaque_meta: meta,
                    });
                }

                let container = Arc::new(SegmentContainer {
                    meta: SegmentMeta {
                        id,
                        path: segment_path(&dir, id),
                        base_lsn: scan.min_lsn.unwrap_or(initial_lsn),
                        max_lsn: u64::MAX,
                        sealed: false,
                        blake3_root: None,
                        // tail_scan só é aceite quando scan.version == FORMAT_VERSION
                        version: format::FORMAT_VERSION,
                    },
                    index: Arc::new(SegmentIndex {
                        entries: Arc::new(entries),
                    }),
                });

                let state = Active {
                    file,
                    segment_id: id,
                    bytes_written: scan.valid_len,
                    record_hashes: scan.record_hashes,
                    base_lsn: scan.min_lsn.unwrap_or(initial_lsn),
                    max_lsn: scan.max_lsn.unwrap_or(initial_lsn),
                    last_sync: Instant::now(),
                };

                (state, container)
            }
            None => {
                let id = initial_sealed
                    .iter()
                    .map(|c| c.meta.id)
                    .max()
                    .map(|m| m + 1)
                    .unwrap_or(0);
                let state = new_active(&dir, id, initial_lsn, &hlc)?;

                let container = Arc::new(SegmentContainer {
                    meta: SegmentMeta {
                        id,
                        path: segment_path(&dir, id),
                        base_lsn: initial_lsn,
                        max_lsn: u64::MAX,
                        sealed: false,
                        blake3_root: None,
                        version: format::FORMAT_VERSION,
                    },
                    index: Arc::new(SegmentIndex {
                        entries: Arc::new(Vec::new()),
                    }),
                });

                (state, container)
            }
        };

        initial_sealed.sort_by_key(|c| c.meta.base_lsn);

        let catalog = Arc::new(ArcSwap::from_pointee(LogCatalog {
            sealed: Arc::new(initial_sealed),
            active: active_container,
        }));

        let committed_lsn = Arc::new(AtomicU64::new(initial_lsn));
        let poisoned = Arc::new(AtomicBool::new(false));
        let (tail_tx, _) = broadcast::channel(4096);
        let (cmd_tx, cmd_rx) = crossbeam_channel::bounded::<LogCommand>(65536);

        let worker_dir = dir.clone();
        let worker_catalog = catalog.clone();
        let worker_committed_lsn = committed_lsn.clone();
        let worker_tail_tx = tail_tx.clone();
        let worker_keystore = keystore.clone();
        let worker_hlc = hlc.clone();
        let worker_poisoned = poisoned.clone();
        let worker_fsync_policy = fsync;

        std::thread::spawn(move || {
            let _drop_guard = WorkerDropGuard {
                poisoned: worker_poisoned.clone(),
            };
            let fsync_policy = worker_fsync_policy;

            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let mut active = active_state;
                let mut current_lsn = initial_lsn;
                let mut batch = Vec::with_capacity(128);
                let mut stashed_updates: Vec<StashedUpdate> = Vec::with_capacity(128);
                let mut stashed_flushes = Vec::with_capacity(32);

                let mut scratch_buffer = Vec::with_capacity(262144);
                let mut crypto_scratch = Vec::with_capacity(262144);

                loop {
                    batch.clear();
                    stashed_updates.clear();
                    stashed_flushes.clear();
                    // Início (em `stashed_updates`) das entradas que ainda
                    // pertencem ao segmento ATIVO. Tudo antes disto já foi
                    // publicado no catálogo e selado num segmento anterior por
                    // um roll a meio do lote.
                    let mut pending_index_start = 0usize;

                    let first_cmd = match cmd_rx.recv() {
                        Ok(cmd) => cmd,
                        Err(_) => break,
                    };

                    batch.push(first_cmd);
                    while batch.len() < 128 {
                        match cmd_rx.try_recv() {
                            Ok(cmd) => batch.push(cmd),
                            Err(_) => break,
                        }
                    }

                    let mut sync_required = false;
                    // Baseline de rollback do ficheiro ATIVO. Mutável (R7): um
                    // roll de segmento a meio do lote troca o ficheiro ativo, e
                    // o baseline tem de acompanhar — aplicar o byte-count do
                    // segmento antigo ao novo estendia-o com zeros no set_len.
                    let mut initial_bytes_written = active.bytes_written;
                    let mut initial_hashes_len = active.record_hashes.len();
                    let mut initial_max_lsn = active.max_lsn;
                    let mut physical_io_error = false;
                    let mut tentative_lsn = current_lsn;

                    // PIPELINE — FASE 2: PHYSICAL WRITES BOUNDARY (Zera os Gaps)
                    for cmd in &mut batch {
                        match cmd {
                            LogCommand::Append {
                                opaque_meta,
                                episode,
                                expected_lsn,
                                resp_tx,
                            } => {
                                if let Some(expected) = expected_lsn {
                                    if tentative_lsn != *expected {
                                        let _ = resp_tx.send(Err(HeraclitusError::CasConflict {
                                            expected: *expected,
                                            head: tentative_lsn,
                                        }));
                                        continue;
                                    }
                                }

                                let (stored_content, stored_attrs, stored_embedding) =
                                    match &worker_keystore {
                                        Some(ks) => match ks.get_or_create(&episode.agent_id) {
                                            Ok(key) => {
                                                crypto_scratch.clear();
                                                crypto_scratch = heraclitus_crypto::seal(
                                                    &key,
                                                    &episode.content,
                                                    episode.agent_id.as_bytes(),
                                                );

                                                let public_attrs = episode
                                                    .attrs
                                                    .iter()
                                                    .filter(|(k, _)| is_public_technical_attr(k))
                                                    .map(|(k, v)| (k.clone(), v.clone()))
                                                    .collect::<std::collections::BTreeMap<_, _>>();
                                                let sensitive = SensitiveFields {
                                                    attrs: episode
                                                        .attrs
                                                        .iter()
                                                        .filter(|(k, _)| {
                                                            !is_public_technical_attr(k)
                                                        })
                                                        .map(|(k, v)| (k.clone(), v.clone()))
                                                        .collect(),
                                                    embedding: episode.embedding.clone(),
                                                };
                                                let encoded = match bincode::serde::encode_to_vec(
                                                    &sensitive,
                                                    BINCODE_CFG,
                                                ) {
                                                    Ok(v) => v,
                                                    Err(e) => {
                                                        let _ = resp_tx.send(Err(
                                                            HeraclitusError::Serialization(
                                                                e.to_string(),
                                                            ),
                                                        ));
                                                        continue;
                                                    }
                                                };
                                                let sealed_fields = heraclitus_crypto::seal(
                                                    &key,
                                                    &encoded,
                                                    &fields_aad(&episode.agent_id),
                                                );
                                                let mut attrs = public_attrs;
                                                attrs.insert(
                                                    ENCRYPTED_FIELDS_ATTR.into(),
                                                    hex_encode(&sealed_fields),
                                                );
                                                (crypto_scratch.clone(), attrs, None)
                                            }
                                            Err(e) => {
                                                let _ = resp_tx.send(Err(HeraclitusError::Crypto(
                                                    format!("Keystore Isolation Fault: {e:?}"),
                                                )));
                                                continue;
                                            }
                                        },
                                        None => (
                                            episode.content.clone(),
                                            episode.attrs.clone(),
                                            episode.embedding.clone(),
                                        ),
                                    };

                                let storage_payload = StoragePayload {
                                    opaque_meta: *opaque_meta,
                                    id: episode.id,
                                    agent_id: episode.agent_id.clone(),
                                    session_id: episode.session_id.clone(),
                                    ts_hlc: episode.ts_hlc,
                                    kind: episode.kind.clone(),
                                    content: stored_content,
                                    embedding: stored_embedding,
                                    attrs: stored_attrs,
                                    parents: episode.parents.clone(),
                                    valid_from: episode.valid_from,
                                    valid_to: episode.valid_to,
                                };

                                scratch_buffer.clear();
                                if let Err(e) = bincode::serde::encode_into_std_write(
                                    &storage_payload,
                                    &mut scratch_buffer,
                                    BINCODE_CFG,
                                ) {
                                    let _ = resp_tx
                                        .send(Err(HeraclitusError::Serialization(e.to_string())));
                                    continue;
                                }

                                let record = format::encode_record(
                                    format::FORMAT_VERSION,
                                    tentative_lsn,
                                    episode.ts_hlc,
                                    &scratch_buffer,
                                );

                                if active.bytes_written + record.len() as u64 > segment_max_bytes {
                                    // CORREÇÃO DE PERDA NO ROLL: publicar no
                                    // catálogo as entradas deste lote que
                                    // pertencem ao segmento prestes a ser
                                    // SELADO. `roll_segment` sela com
                                    // `catalog.active.index`; sem isto o
                                    // segmento ficava com um índice INCOMPLETO
                                    // (os registos já escritos neste lote
                                    // desapareciam) e, pior, a FASE 4 colava-os
                                    // depois ao segmento NOVO com offsets do
                                    // ficheiro ANTIGO — seeks para o sítio
                                    // errado. Media-se ~1 registo perdido por
                                    // roll.
                                    if pending_index_start < stashed_updates.len() {
                                        let cat = worker_catalog.load();
                                        let mut entries = Vec::with_capacity(
                                            cat.active.index.entries.len()
                                                + (stashed_updates.len() - pending_index_start),
                                        );
                                        entries.extend_from_slice(&cat.active.index.entries);
                                        for u in &stashed_updates[pending_index_start..] {
                                            entries.push(LsnEntry {
                                                lsn: u.lsn,
                                                offset: u.offset,
                                                opaque_meta: u.opaque_meta,
                                            });
                                        }
                                        let mut meta = cat.active.meta.clone();
                                        meta.max_lsn = active.max_lsn;
                                        worker_catalog.store(Arc::new(LogCatalog {
                                            sealed: cat.sealed.clone(),
                                            active: Arc::new(SegmentContainer {
                                                meta,
                                                index: Arc::new(SegmentIndex {
                                                    entries: Arc::new(entries),
                                                }),
                                            }),
                                        }));
                                        pending_index_start = stashed_updates.len();
                                    }
                                    if let Err(e) = roll_segment(
                                        &worker_dir,
                                        &mut active,
                                        &worker_catalog,
                                        tentative_lsn,
                                        &worker_hlc,
                                    ) {
                                        let _ = resp_tx.send(Err(e));
                                        physical_io_error = true;
                                        break;
                                    }
                                    // R7: novo ficheiro ativo ⇒ novo baseline de
                                    // rollback. Os registos anteriores do lote já
                                    // ficaram selados no segmento anterior (com
                                    // fsync); um erro daqui em diante só pode
                                    // reverter o ficheiro ATUAL. Nota honesta:
                                    // esses registos selados ficam duráveis mesmo
                                    // que o cliente receba erro (ambiguidade
                                    // inerente a qualquer WAL — documentada).
                                    initial_bytes_written = active.bytes_written;
                                    initial_hashes_len = active.record_hashes.len();
                                    initial_max_lsn = active.max_lsn;
                                }

                                // RESOLUÇÃO DE DRIFT: Captura do offset físico EXATO antes do write_all
                                let record_offset = active.bytes_written;

                                if let Err(e) = active.file.write_all(&record) {
                                    physical_io_error = true;
                                    let _ = resp_tx.send(Err(e.into()));
                                    break;
                                }

                                stashed_updates.push(StashedUpdate {
                                    lsn: tentative_lsn,
                                    opaque_meta: *opaque_meta,
                                    offset: record_offset,
                                    episode: episode.clone(),
                                    resp_tx: resp_tx.clone(),
                                });

                                active.bytes_written += record.len() as u64;
                                active
                                    .record_hashes
                                    .push(format::record_leaf(format::FORMAT_VERSION, &record));
                                active.max_lsn = active.max_lsn.max(tentative_lsn);

                                // Incremento adiado: Ocorre estritamente pós sucesso da escrita
                                tentative_lsn += 1;

                                match &fsync_policy {
                                    FsyncPolicy::Always => sync_required = true,
                                    FsyncPolicy::GroupCommit { interval_ms } => {
                                        if active.last_sync.elapsed().as_millis() as u64
                                            >= *interval_ms
                                        {
                                            sync_required = true;
                                        }
                                    }
                                }
                            }
                            LogCommand::Flush { resp_tx } => {
                                sync_required = true;
                                stashed_flushes.push(resp_tx.clone());
                            }
                        }
                    }

                    // RECOVERY TRANSACIONAL DE MEMÓRIA: Restaura o alinhamento em falhas físicas parciais
                    if physical_io_error {
                        rollback_active_file(&mut active.file, initial_bytes_written);
                        active.bytes_written = initial_bytes_written;
                        active.record_hashes.truncate(initial_hashes_len);
                        active.max_lsn = initial_max_lsn;
                        worker_poisoned.store(true, Ordering::SeqCst);
                        break;
                    }

                    // PIPELINE — FASE 3: FS DATA HARDWARE BARRIER
                    if sync_required {
                        if active.file.sync_data().is_err() {
                            rollback_active_file(&mut active.file, initial_bytes_written);
                            active.bytes_written = initial_bytes_written;
                            active.record_hashes.truncate(initial_hashes_len);
                            active.max_lsn = initial_max_lsn;
                            worker_poisoned.store(true, Ordering::SeqCst);
                            break;
                        }
                        active.last_sync = Instant::now();
                    }

                    // PIPELINE — FASE 4: COW ATOMIZADO NO SEGMENTO ATIVO (Splat-Free Completo)
                    // O `committed_lsn` cobre o lote INTEIRO, inclusive os
                    // registos já publicados antes de um roll a meio — por isso
                    // sai de `stashed_updates` completo, e não do sub-lote que
                    // ainda falta indexar.
                    let highest_committed_lsn_in_batch = stashed_updates.last().map(|u| u.lsn);

                    if pending_index_start < stashed_updates.len() {
                        let current_catalog = worker_catalog.load();
                        let old_active_container = &current_catalog.active;

                        // Só as entradas do segmento ATIVO (as anteriores a um
                        // roll já foram publicadas e seladas com ele).
                        let tail = &stashed_updates[pending_index_start..];
                        let mut updated_entries = Vec::with_capacity(
                            old_active_container.index.entries.len() + tail.len(),
                        );
                        updated_entries.extend_from_slice(&old_active_container.index.entries);

                        for update in tail {
                            updated_entries.push(LsnEntry {
                                lsn: update.lsn,
                                offset: update.offset,
                                opaque_meta: update.opaque_meta,
                            });
                        }

                        let mut updated_meta = old_active_container.meta.clone();
                        updated_meta.max_lsn = active.max_lsn;

                        worker_catalog.store(Arc::new(LogCatalog {
                            sealed: current_catalog.sealed.clone(),
                            active: Arc::new(SegmentContainer {
                                meta: updated_meta,
                                index: Arc::new(SegmentIndex {
                                    entries: Arc::new(updated_entries),
                                }),
                            }),
                        }));
                    }

                    std::sync::atomic::compiler_fence(Ordering::Release);

                    // PIPELINE — FASE 5: PONTEIRO LINEARIZÁVEL. Publica o
                    // committed_lsn ANTES de responder aos clientes: quem
                    // recebe o ACK de um append tem de conseguir ler o próprio
                    // registo de imediato (read-your-writes). Responder
                    // primeiro, como antes, deixava head()/scan() atrasados
                    // face ao ACK — uma corrida de visibilidade real.
                    if let Some(highest_lsn) = highest_committed_lsn_in_batch {
                        current_lsn = highest_lsn + 1;
                        worker_committed_lsn.store(current_lsn, Ordering::Release);
                    }

                    // PIPELINE — FASE 6: REPLICATION ROUTER STREAM, ACKs E
                    // LIBERAÇÃO DE BARREIRAS DE FLUSH
                    for update in &stashed_updates {
                        let _ = worker_tail_tx.send((update.lsn, update.episode.clone()));
                        let _ = update.resp_tx.send(Ok(update.lsn));
                    }

                    for flush_tx in stashed_flushes.drain(..) {
                        let _ = flush_tx.send(Ok(()));
                    }

                }
            }));
        });

        Ok(Self {
            dir,
            hlc,
            committed_lsn,
            poisoned,
            catalog,
            tail_tx,
            cmd_tx,
            keystore,
            stamp_lock: std::sync::Mutex::new(()),
            fds: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn check_poison(&self) -> Result<(), HeraclitusError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(HeraclitusError::StorageEngine(
                "Fail-Fast: Motor desativado devido a falhas fisicas ou corrupcao de dados".into(),
            ));
        }
        Ok(())
    }

    pub fn resolve_lsn_from_consensus_index(&self, target_raft_index: u64) -> Lsn {
        let catalog = self.catalog.load();

        if let Some(entry) = catalog.active.index.entries.iter().rev().find(|e| {
            let r_idx = u64::from_le_bytes(e.opaque_meta[8..16].try_into().unwrap_or([0u8; 8]));
            r_idx <= target_raft_index
        }) {
            return entry.lsn + 1;
        }

        for container in catalog.sealed.iter().rev() {
            if let Some(entry) = container.index.entries.iter().rev().find(|e| {
                let r_idx = u64::from_le_bytes(e.opaque_meta[8..16].try_into().unwrap_or([0u8; 8]));
                r_idx <= target_raft_index
            }) {
                return entry.lsn + 1;
            }
        }
        // R13: sem entrada classificável, o default é PROTETOR — devolver o
        // head bloqueia qualquer truncate (`from_lsn < allowed_max` rejeita),
        // em vez do antigo `0`, que desligava a proteção de quórum por completo
        // num log misto/ilegível.
        self.head()
    }

    pub fn read_committed(
        &self,
        lsn: Lsn,
        allowed_max_lsn: Lsn,
    ) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        if lsn >= allowed_max_lsn {
            return Ok(None);
        }
        self.read(lsn)
    }

    pub fn head(&self) -> Lsn {
        self.committed_lsn.load(Ordering::Acquire)
    }

    pub fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        self.tail_tx.subscribe()
    }

    pub fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        if lsn >= self.committed_lsn.load(Ordering::Acquire) {
            return Ok(None);
        }

        let catalog = self.catalog.load();

        // INDEXAÇÃO DIRETA O(1): Aproveita a invariante gapless eliminando buscas binárias no hot path
        if lsn >= catalog.active.meta.base_lsn {
            let active_container = &catalog.active;
            let offset_idx = (lsn - active_container.meta.base_lsn) as usize;
            // O atalho O(1) assume o índice DENSO (`entries[i].lsn == base_lsn+i`).
            // Essa invariante NÃO se verifica com appends concorrentes + roll de
            // segmento (repro: 8 threads, segmentos pequenos → entry.lsn=16 na
            // posição do LSN 19). O `debug_assert_eq!` que a protegia é compilado
            // FORA em release, portanto produção devolvia SILENCIOSAMENTE o
            // episódio errado. Agora confirma-se o LSN e, se não bater, procura-se
            // a sério (as entradas são gravadas por ordem de LSN).
            if let Some(entry) = active_container.index.entries.get(offset_idx) {
                if entry.lsn == lsn {
                    return self.read_at(active_container.meta.id, entry.offset);
                }
            }
            if let Ok(j) = active_container
                .index
                .entries
                .binary_search_by_key(&lsn, |e| e.lsn)
            {
                let entry = &active_container.index.entries[j];
                return self.read_at(active_container.meta.id, entry.offset);
            }
        } else {
            let idx = match catalog
                .sealed
                .binary_search_by_key(&lsn, |c| c.meta.base_lsn)
            {
                Ok(i) => Some(i),
                Err(i) => {
                    if i > 0 {
                        Some(i - 1)
                    } else {
                        None
                    }
                }
            };

            if let Some(i) = idx {
                let container = &catalog.sealed[i];
                let offset_idx = (lsn - container.meta.base_lsn) as usize;
                // Mesma correção do container ativo: o acesso posicional só vale
                // se o índice for denso — confirmar o LSN e, caso contrário,
                // localizar a entrada por busca binária em vez de devolver o
                // registo errado (ou panicar em debug).
                if let Some(entry) = container.index.entries.get(offset_idx) {
                    if entry.lsn == lsn {
                        return self.read_at(container.meta.id, entry.offset);
                    }
                }
                if let Ok(j) = container
                    .index
                    .entries
                    .binary_search_by_key(&lsn, |e| e.lsn)
                {
                    let entry = &container.index.entries[j];
                    return self.read_at(container.meta.id, entry.offset);
                }
            }
        }
        Ok(self.scan(lsn, lsn + 1)?.into_iter().next())
    }

    /// Descritor do segmento, do cache. Abre-o na primeira utilização.
    ///
    /// O lock cobre só a consulta ao mapa; o `Arc<File>` devolvido é usado FORA
    /// dele, com leituras posicionais, por isso vários leitores partilham o
    /// mesmo descritor sem serializar o I/O.
    fn descritor_do_segmento(&self, seg: SegmentId) -> Result<Option<Arc<File>>, HeraclitusError> {
        if let Some(f) = self.fds.lock().unwrap_or_else(|e| e.into_inner()).get(&seg) {
            return Ok(Some(f.clone()));
        }
        let path = segment_path(&self.dir, seg);
        let file = match File::open(&path) {
            Ok(f) => Arc::new(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        // Corrida benigna: dois leitores podem abrir o mesmo segmento em
        // paralelo. `or_insert_with` faz o primeiro ganhar e o segundo larga o
        // seu descritor — mais barato que segurar o lock durante o `open`.
        let mut guarda = self.fds.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Some(guarda.entry(seg).or_insert(file).clone()))
    }

    /// A versão de FORMATO de um segmento, vinda do catálogo em memória.
    ///
    /// Antes, `read_at` descobria-a fazendo `seek(0)` + ler 22 bytes do próprio
    /// ficheiro, EM CADA LEITURA — quando `SegmentMeta.version` já a tem. Era
    /// um seek e uma leitura extra por leitura pontual (1,40x sozinho, medido).
    fn versao_do_segmento(&self, seg: SegmentId) -> Option<u16> {
        let catalogo = self.catalog.load();
        if catalogo.active.meta.id == seg {
            return Some(catalogo.active.meta.version);
        }
        catalogo
            .sealed
            .iter()
            .find(|c| c.meta.id == seg)
            .map(|c| c.meta.version)
    }

    pub fn read_at(
        &self,
        seg: SegmentId,
        off: u64,
    ) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        let version = match self.versao_do_segmento(seg) {
            Some(v) => v,
            // Segmento fora do catálogo: cai para a leitura do cabeçalho do
            // ficheiro. Não acontece no caminho normal (`read` só passa ids que
            // acabou de tirar do catálogo), mas `read_at` é público.
            None => match self.versao_do_ficheiro(seg)? {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        self.ler_registo_em(seg, off, version)
    }

    /// Fallback: lê a versão do cabeçalho do ficheiro (22 B).
    fn versao_do_ficheiro(&self, seg: SegmentId) -> Result<Option<u16>, HeraclitusError> {
        let Some(f) = self.descritor_do_segmento(seg)? else {
            return Ok(None);
        };
        let mut hdr = [0u8; HEADER_LEN];
        match ler_exato_em(&f, &mut hdr, 0) {
            Ok(()) => Ok(Some(format::SegmentHeader::decode(&hdr)?.version)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Lê UM registo no offset dado, com a versão já conhecida.
    fn ler_registo_em(
        &self,
        seg: SegmentId,
        off: u64,
        version: u16,
    ) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        let Some(f) = self.descritor_do_segmento(seg)? else {
            return Ok(None);
        };

        let mut rh = [0u8; format::RECORD_HEADER_LEN];
        if let Err(e) = ler_exato_em(&f, &mut rh, off) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(e.into());
        }

        let len = u32::from_le_bytes(rh[..4].try_into().unwrap_or([0u8; 4])) as usize;
        if len > 512 * 1024 * 1024 {
            return Err(HeraclitusError::Corruption {
                context: format!("Segmento: {seg}, Offset: {off}"),
                detail: "Defesa de Estouro de Memória: Carga abusiva rejeitada".into(),
            });
        }

        let mut buf = vec![0u8; format::RECORD_HEADER_LEN + len];
        buf[..format::RECORD_HEADER_LEN].copy_from_slice(&rh);
        if let Err(e) = ler_exato_em(
            &f,
            &mut buf[format::RECORD_HEADER_LEN..],
            off + format::RECORD_HEADER_LEN as u64,
        ) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(e.into());
        }

        match format::decode_record(version, &buf) {
            Decoded::Record(rlsn, _hlc, payload, _) => {
                let mut ep = decode_episode_payload(version, payload)?;
                self.decrypt_in_place(&mut ep)?;
                Ok(Some((rlsn, ep)))
            }
            _ => Err(HeraclitusError::Corruption {
                context: format!("Segmento: {seg}"),
                detail: "CRC-32C violado no registo".into(),
            }),
        }
    }

    pub fn scan(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.scan_capped(from, to, usize::MAX)
    }

    pub fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        let stable_limit = self.committed_lsn.load(Ordering::Acquire);
        let effective_to = to.min(stable_limit);
        if from >= effective_to || max == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(max.min(2048));
        let mut scan_lsn = from;

        // `BufReader` e não `File` cru. O varrimento faz DOIS `read_exact` por
        // registo (cabeçalho, depois corpo); sem buffer isso são duas syscalls
        // por registo — 40 milhões num varrimento do log de 20M, medido.
        //
        // Sonda `benches/otim_leitura.rs` (2026-08-19), mesmo segmento real:
        //   File cru          : 235 941 reg/s ·  109 MB/s
        //   BufReader de 1 MiB: 767 419 reg/s ·  356 MB/s   3,25x
        //   mmap (zero-copy)  : 624 805 reg/s ·  290 MB/s   2,65x
        //
        // Nota de arquivo: o `mmap.rs` foi medido em 2026-08-15 contra um
        // leitor COM `BufReader` e perdeu — mas este caminho, o vivo, nunca
        // teve buffer nenhum. A conclusão certa não era "o mmap é mau", era
        // "falta um `BufReader` aqui". Com ele posto, o mmap continua a não
        // compensar, agora por comparação justa.
        //
        // O buffer é de 1 MiB e o `BufReader` implementa `Seek` (descartando o
        // que tem em buffer), portanto o salto para `entry.offset` na troca de
        // segmento continua correto.
        let mut active_file_handle: Option<(SegmentId, BufReader<File>)> = None;
        let mut record_header_buffer = [0u8; format::RECORD_HEADER_LEN];
        let mut record_buf = Vec::with_capacity(65536);

        let catalog = self.catalog.load();

        while scan_lsn < effective_to && out.len() < max {
            // GARANTIA DE TERMINAÇÃO: o loop interno tem vários `break` que NÃO
            // avançam o cursor (footer, EOF, read_exact falhado, `scan_lsn >
            // max_lsn`). Todos devolviam ao loop externo, que reescolhia o MESMO
            // container e refazia o mesmo seek/leitura — scan infinito a queimar
            // CPU. Guardar o cursor no início de cada iteração e forçar +1 se não
            // houver progresso torna a terminação independente de qualquer
            // inconsistência de metadados do segmento.
            let scan_lsn_at_iter_start = scan_lsn;
            let container = if scan_lsn >= catalog.active.meta.base_lsn {
                Some(&catalog.active)
            } else {
                let idx = match catalog
                    .sealed
                    .binary_search_by_key(&scan_lsn, |c| c.meta.base_lsn)
                {
                    Ok(i) => Some(i),
                    Err(i) => {
                        if i > 0 {
                            Some(i - 1)
                        } else {
                            None
                        }
                    }
                };
                idx.map(|i| &catalog.sealed[i])
            };

            if let Some(container) = container {
                let offset_idx = (scan_lsn - container.meta.base_lsn) as usize;

                // FRONTEIRA VALIDADA: Impede leituras trans-segmento inconsistentes ou transições inválidas
                if offset_idx >= container.index.entries.len() {
                    // PROGRESSO ESTRITO (obrigatório): `max_lsn + 1` só avança se
                    // for MAIOR que o `scan_lsn` atual. Havendo uma lacuna de LSN
                    // entre segmentos (o `binary_search` volta a escolher ESTE
                    // container porque o seguinte tem `base_lsn > scan_lsn`), o
                    // salto repunha o mesmo valor e o `while` girava para sempre —
                    // scan infinito a queimar CPU, alcançável a partir do replay
                    // de boot (`ViewRegistry::catch_up`) e do `subscribe`.
                    let next = container.meta.max_lsn.saturating_add(1);
                    scan_lsn = if next > scan_lsn { next } else { scan_lsn + 1 };
                    continue;
                }

                if let Some(entry) = container.index.entries.get(offset_idx) {
                    let file_ref = match &mut active_file_handle {
                        Some((cached_seg, ref mut file)) if *cached_seg == container.meta.id => {
                            file
                        }
                        _ => {
                            let path = segment_path(&self.dir, container.meta.id);
                            let file = File::open(&path)?;
                            active_file_handle = Some((
                                container.meta.id,
                                BufReader::with_capacity(1 << 20, file),
                            ));
                            &mut active_file_handle.as_mut().unwrap().1
                        }
                    };

                    // Um `seek` NUNCA falha por fim-de-ficheiro (posicionar além do
                    // EOF é legal): qualquer erro aqui é I/O real. Saltar o LSN em
                    // silêncio, como antes, devolvia `Ok` com um buraco no histórico
                    // — exatamente o que o guard de CRC mais abaixo recusa fazer.
                    file_ref.seek(SeekFrom::Start(entry.offset))?;

                    while scan_lsn < effective_to && out.len() < max {
                        // Fronteira de segmento SELADO: depois do último registo
                        // vem o FOOTER — lê-lo como header de registo fazia o
                        // guard de payload explodir com falso "Corruption" em
                        // qualquer scan que atravessasse segmentos. Sai para o
                        // loop externo escolher o próximo container.
                        if container.meta.sealed && scan_lsn > container.meta.max_lsn {
                            break;
                        }
                        // `UnexpectedEof` é fronteira legítima (cauda do segmento
                        // ativo); qualquer OUTRO erro é falha de I/O e tem de subir.
                        // Tratar os dois como "fim do segmento" — o que o código
                        // fazia — transformava um EIO/EACCES num histórico truncado
                        // em silêncio, com `Ok`. Mesma correção já aplicada a
                        // `read_at`, agora no caminho de leitura principal (`scan`
                        // serve catch_up/rebuild/subscribe/REST).
                        if let Err(e) = file_ref.read_exact(&mut record_header_buffer) {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                break;
                            }
                            return Err(e.into());
                        }
                        if record_header_buffer[..4] == format::FOOTER_MAGIC {
                            break;
                        }

                        let len = u32::from_le_bytes(
                            record_header_buffer[..4].try_into().unwrap_or([0u8; 4]),
                        ) as usize;
                        if len > 512 * 1024 * 1024 {
                            return Err(HeraclitusError::Corruption {
                                context: format!("Segmento: {}", container.meta.id),
                                detail: "Varredura abortada por anomalia de payload".into(),
                            });
                        }

                        record_buf.resize(format::RECORD_HEADER_LEN + len, 0);
                        record_buf[..format::RECORD_HEADER_LEN]
                            .copy_from_slice(&record_header_buffer);
                        // Idem para o corpo do registo: EOF = cauda torn legítima,
                        // erro de I/O = falha que não pode virar buraco silencioso.
                        if let Err(e) =
                            file_ref.read_exact(&mut record_buf[format::RECORD_HEADER_LEN..])
                        {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                break;
                            }
                            return Err(e.into());
                        }

                        match format::decode_record(container.meta.version, &record_buf) {
                            Decoded::Record(rlsn, _hlc, payload, _) => {
                                if rlsn == scan_lsn {
                                    let mut ep =
                                        decode_episode_payload(container.meta.version, payload)?;

                                    self.decrypt_in_place(&mut ep)?;
                                    out.push((rlsn, ep));
                                    scan_lsn += 1;
                                } else {
                                    // PROGRESSO ESTRITO: sem o `+1` mínimo, um
                                    // registo cujo LSN esteja ATRÁS do `scan_lsn`
                                    // deixava o cursor no mesmo sítio; o `break`
                                    // devolvia ao loop externo, que reescolhia o
                                    // mesmo container, fazia seek ao mesmo offset
                                    // e relia o MESMO registo — scan infinito a
                                    // queimar CPU (o `continue` a seguir salta o
                                    // `scan_lsn += 1` de fallback). Alcançável do
                                    // replay de boot e do subscribe.
                                    scan_lsn = rlsn.saturating_add(1).max(scan_lsn + 1);
                                    break;
                                }
                            }
                            _ => {
                                // Um registo que não descodifica DENTRO do
                                // intervalo comprometido é corrupção (CRC-32C
                                // violado / bit rot) — nunca uma cauda torn, que
                                // fica acima do `committed_lsn` e por isso fora
                                // do `effective_to`. Antes saltava-se o LSN em
                                // silêncio e devolvia-se `Ok`, enquanto
                                // `Log::read` do MESMO LSN devolvia `Corruption`:
                                // os dois caminhos de leitura discordavam, e como
                                // `catch_up`/`rebuild`/replay do H-VM usam o scan,
                                // as views eram reconstruídas SEM o episódio, sem
                                // erro, sem métrica, sem tracing — contra o
                                // contrato de heraclitus-core/src/error.rs
                                // ("`Corruption` is never silently swallowed").
                                return Err(HeraclitusError::Corruption {
                                    context: format!("Segmento: {}", container.meta.id),
                                    detail: format!(
                                        "registo ilegível no LSN {scan_lsn} durante o scan \
                                         (CRC-32C violado?) — recuso devolver um histórico \
                                         com buracos silenciosos"
                                    ),
                                });
                            }
                        }
                    }
                    // Progresso obrigatório: se o loop interno saiu por um `break`
                    // que não moveu o cursor, avança 1 (salta o LSN problemático)
                    // em vez de reprocessar o mesmo container para sempre.
                    if scan_lsn == scan_lsn_at_iter_start {
                        scan_lsn += 1;
                    }
                    continue;
                }
            }
            scan_lsn += 1;
        }
        Ok(out)
    }

    /// Verificação pontual de UM segmento (introspecção operacional, padrão
    /// immudb `verify_row`): re-varre o ficheiro, recomputa a raiz Merkle com
    /// a regra de leaf da versão do segmento e compara com o rodapé/catálogo.
    /// `None` se o id não existir no catálogo.
    pub fn verify_segment(
        &self,
        id: SegmentId,
    ) -> Result<Option<SegmentVerifyReport>, HeraclitusError> {
        let catalog = self.catalog.load();
        let meta = catalog
            .sealed
            .iter()
            .map(|c| &c.meta)
            .chain(std::iter::once(&catalog.active.meta))
            .find(|m| m.id == id)
            .cloned();
        let Some(meta) = meta else { return Ok(None) };
        let scan = scan_segment_file(&meta.path, id, true)?;
        let computed_root = merkle_root(&scan.record_hashes);
        let stored_root = scan.blake3_root.or(meta.blake3_root);
        // Um segmento selado é válido se a raiz recomputada bate com a do
        // rodapé; o ativo (sem rodapé ainda) é válido se a varredura não
        // detectou corrupção física.
        let valid =
            !scan.corruption_detected && stored_root.map_or(!meta.sealed, |s| s == computed_root);
        Ok(Some(SegmentVerifyReport {
            id,
            version: scan.version,
            sealed: meta.sealed,
            records: scan.locs.len() as u64,
            base_lsn: meta.base_lsn,
            max_lsn: scan.max_lsn.unwrap_or(meta.base_lsn),
            computed_root,
            stored_root,
            valid,
        }))
    }

    pub fn verify_durable(&self) -> Result<VerifyReport, HeraclitusError> {
        self.flush()?;
        self.verify()
    }

    /// Varre os segmentos de `paths` em paralelo, COM leaf hashes, na ordem
    /// dada. Ver a nota em [`varrer_segmentos_em_paralelo`] sobre porque o erro
    /// devolvido é o do menor índice.
    fn varrer_para_verificacao(
        &self,
        paths: &[PathBuf],
    ) -> Result<Vec<SegmentScan>, HeraclitusError> {
        if paths.len() < 2 {
            let mut out = Vec::with_capacity(paths.len());
            for p in paths {
                out.push(scan_segment_file(p, segment_id_from_path(p)?, true)?);
            }
            return Ok(out);
        }

        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(paths.len());
        let proximo = AtomicU64::new(0);
        let recolhidos: std::sync::Mutex<Vec<(usize, Result<SegmentScan, HeraclitusError>)>> =
            std::sync::Mutex::new(Vec::with_capacity(paths.len()));

        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = proximo.fetch_add(1, Ordering::Relaxed) as usize;
                    if i >= paths.len() {
                        break;
                    }
                    let p = &paths[i];
                    let r = segment_id_from_path(p)
                        .and_then(|id| scan_segment_file(p, id, true));
                    recolhidos
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((i, r));
                });
            }
        });

        let mut recolhidos = recolhidos.into_inner().unwrap_or_else(|e| e.into_inner());
        recolhidos.sort_by_key(|(i, _)| *i);
        let mut out = Vec::with_capacity(paths.len());
        for (_, r) in recolhidos {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn verify(&self) -> Result<VerifyReport, HeraclitusError> {
        let catalog = self.catalog.load();
        let mut report = VerifyReport::default();

        let mut paths: Vec<PathBuf> = catalog.sealed.iter().map(|c| c.meta.path.clone()).collect();
        paths.push(catalog.active.meta.path.clone());

        // Paralelo pela mesma razão do `Log::open`: cada segmento é um ficheiro
        // independente e `scan_segment_file` é puro. A DIFERENÇA é que aqui os
        // leaf hashes são obrigatórios — `verify` existe para recomputar a raiz
        // Merkle e a comparar com a do rodapé; confiar no rodapé aqui seria
        // verificar a prova contra ela própria.
        //
        // A agregação continua serial e por ordem de path, para o relatório e a
        // mensagem de erro serem reproduzíveis entre corridas.
        let scans = self.varrer_para_verificacao(&paths)?;

        for (path, scan) in paths.iter().zip(scans) {
            report.segments += 1;
            report.records += scan.locs.len() as u64;
            if scan.sealed {
                report.sealed += 1;
                let root = merkle_root(&scan.record_hashes);
                match scan.blake3_root {
                    Some(stored) if stored == root => report.merkle_ok += 1,
                    Some(_) => return Err(HeraclitusError::Corruption {
                        context: format!("{}", path.display()),
                        detail:
                            "Mismatch catastrófico detectado na raiz Merkle permanente do rodapé"
                                .into(),
                    }),
                    None => {}
                }
            }
        }
        Ok(report)
    }

    pub fn flush(&self) -> Result<(), HeraclitusError> {
        self.check_poison()?;
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.cmd_tx
            .send(LogCommand::Flush { resp_tx: tx })
            .map_err(|_| {
                HeraclitusError::StorageEngine("Pipeline abortado na injeção de Flush".into())
            })?;
        rx.recv().map_err(|_| {
            HeraclitusError::StorageEngine(
                "A thread principal do worker falhou em processar o Flush".into(),
            )
        })?
    }

    /// Caminho de escrita público: envia um `LogCommand::Append` e devolve o LSN
    /// atribuído. O `ts_hlc` do episódio é carimbado pelo HLC do log — o
    /// produtor não manda no relógio (`Episode::new` deixa 0); a monotonicidade
    /// estrita de ts por LSN é o contrato de que `lsn_for_timestamp` (AS OF
    /// TIMESTAMP) depende. `opaque_meta` transporta o `EventId` (Ulid, 16 bytes)
    /// para reconstrução do `id` na leitura.
    pub fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.enqueue_append_inner(episode, None, "append", true)
            .map(|(lsn, _)| lsn)
    }

    /// Como [`Log::append`], mas devolve TAMBÉM o episódio com o `ts_hlc` já
    /// carimbado. Quem indexa views derivadas TEM de usar esta versão: indexar
    /// a cópia pré-carimbo mete `ts_hlc = 0` nas views enquanto o log guarda o
    /// valor real, e a view reconstruída do LSN 0 (que lê o log) fica DIFERENTE
    /// da view viva — quebra do invariante I6. A `activation`, por exemplo, usa
    /// `ts_hlc >> 16` como instante de acesso.
    pub fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        let mut copia = episode.clone();
        let (lsn, ts) = self.enqueue_append_inner(episode, None, "append", true)?;
        copia.ts_hlc = ts; // o carimbo real, feito dentro da secção crítica
        Ok((lsn, copia))
    }

    /// Aplicação replicada (follower): grava a entrada do líder na posição exata
    /// `lsn`. PRESERVA o carimbo HLC do líder — replicar não re-carimba — e
    /// fá-lo observar pelo HLC local para manter o relógio monotónico.
    ///
    /// Semântica (V2.3):
    /// - `lsn == head`: append normal (CAS garante contiguidade — sem gaps);
    /// - `lsn > head`: gap → `CasConflict` (o follower pede o backlog);
    /// - `lsn < head`: RE-APLICAÇÃO. Idempotente se for o MESMO evento (mesmo
    ///   `EventId`) — um follower que repete um lote após reconexão não pode
    ///   falhar. Um evento DIFERENTE na mesma posição é divergência real de
    ///   histórico e continua a falhar (o log imutável nunca se reescreve).
    pub fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.hlc.observe(episode.ts_hlc);
        let head = self.head();
        if lsn < head {
            return match self.read(lsn)? {
                Some((_, existing)) if existing.id == episode.id => Ok(lsn),
                _ => Err(HeraclitusError::CasConflict {
                    expected: lsn,
                    head,
                }),
            };
        }
        self.enqueue_append(episode, Some(lsn), "append_replicated")
    }

    fn enqueue_append(
        &self,
        episode: Episode,
        expected_lsn: Option<Lsn>,
        ctx: &str,
    ) -> Result<Lsn, HeraclitusError> {
        self.enqueue_append_inner(episode, expected_lsn, ctx, false)
            .map(|(lsn, _)| lsn)
    }

    /// Devolve `(lsn, ts_hlc)`. Com `stamp = true` o carimbo HLC é feito AQUI,
    /// dentro da secção crítica que também enfileira o comando.
    ///
    /// Porquê: o `ts` era carimbado no chamador e só DEPOIS a mensagem entrava no
    /// canal, mas é o worker (FIFO) que atribui o LSN. Dois appends concorrentes
    /// podiam então inverter-se — o que carimbou primeiro entrava na fila depois
    /// e ficava com um LSN maior E um ts menor. Medido: **69 inversões em 1200
    /// registos (5,75%)**. Como `lsn_for_timestamp` (AS OF TIMESTAMP) faz BUSCA
    /// BINÁRIA assumindo ts monotónico por LSN, operava sobre dados desordenados
    /// e devolvia snapshots errados. Carimbar dentro do lock que enfileira torna
    /// a ordem de `ts` igual à ordem de chegada à fila — e portanto à dos LSNs.
    /// A secção crítica é minúscula (um tick do HLC + um `send`); a espera pela
    /// resposta fica DE FORA, para não serializar as escritas.
    fn enqueue_append_inner(
        &self,
        mut episode: Episode,
        expected_lsn: Option<Lsn>,
        ctx: &str,
        stamp: bool,
    ) -> Result<(Lsn, u64), HeraclitusError> {
        self.check_poison()?;
        let (tx, rx) = crossbeam_channel::bounded(1);
        let opaque_meta = episode.id.0.to_bytes();
        let ts;
        {
            let _ordem = self.stamp_lock.lock().unwrap_or_else(|e| e.into_inner());
            if stamp {
                episode.ts_hlc = self.hlc.now();
            }
            ts = episode.ts_hlc;
            self.cmd_tx
                .send_timeout(
                    LogCommand::Append {
                        opaque_meta,
                        episode: Arc::new(episode),
                        expected_lsn,
                        resp_tx: tx,
                    },
                    std::time::Duration::from_secs(10),
                )
                .map_err(|_| {
                    HeraclitusError::StorageEngine(format!(
                        "Timeout de canal: pipeline saturado ({ctx})"
                    ))
                })?;
        }
        let lsn = rx.recv().map_err(|_| {
            HeraclitusError::StorageEngine(format!("Worker interrompido no {ctx}"))
        })??;
        Ok((lsn, ts))
    }

    pub fn sealed_segments(&self) -> Vec<SegmentMeta> {
        let catalog = self.catalog.load();
        catalog.sealed.iter().map(|c| c.meta.clone()).collect()
    }

    /// SPEC-011 wired — o macro-estado do storage como `DatabaseManifest`
    /// (SegmentDescriptors + watermark committed). Derivado do catálogo em
    /// memória: barato, sem I/O, e consistente com o head fsync-acked.
    pub fn manifest(&self) -> heraclitus_core::DatabaseManifest {
        use heraclitus_core::runtime::{SegmentDescriptor, SegmentState};
        let catalog = self.catalog.load();
        let mut segments: Vec<SegmentDescriptor> = catalog
            .sealed
            .iter()
            .map(|c| SegmentDescriptor {
                segment_id: c.meta.id,
                first_lsn: c.meta.base_lsn,
                last_lsn: c.meta.max_lsn,
                event_count: c.meta.max_lsn - c.meta.base_lsn + 1,
                payload_hash: c.meta.blake3_root.unwrap_or([0; 32]),
                state: SegmentState::Frozen,
            })
            .collect();
        let active = &catalog.active.meta;
        let head = self.head();
        if head > active.base_lsn {
            segments.push(SegmentDescriptor {
                segment_id: active.id,
                first_lsn: active.base_lsn,
                last_lsn: head.saturating_sub(1),
                event_count: head - active.base_lsn,
                payload_hash: [0; 32], // ativo: Merkle só ao selar
                state: SegmentState::Active,
            });
        }
        heraclitus_core::DatabaseManifest {
            manifest_version: 1,
            format_identifier: *b"HRKL",
            segments,
            cumulative_watermark: head,
            statistics_root_hash: [0; 32],
            // SPEC-0050 §70: o catálogo v2 é povoado pelo `.hrkm`
            // (`v6::manifest::ManifestStore`), não por esta vista derivada do
            // catálogo em memória. Deixá-lo vazio aqui é deliberado — o v1 é
            // uma projecção barata do estado do writer, o v2 é o catálogo
            // persistido com gerações físicas.
            ..Default::default()
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// SPEC-024 wired — o Log implementa o contrato de catálogo de segmentos: o
/// planner resolve que segmentos são visíveis sob um snapshot sem conhecer o
/// layout físico.
impl heraclitus_core::contracts::SegmentCatalog for Log {
    fn resolve_visible(&self, target_lsn: Lsn) -> Vec<SegmentId> {
        self.manifest()
            .visible_segments(target_lsn)
            .map(|s| s.segment_id)
            .collect()
    }
}

#[allow(clippy::needless_lifetimes)]
impl Log {
    fn decrypt_in_place(&self, ep: &mut Episode) -> Result<(), HeraclitusError> {
        decrypt_storage_episode_in_place(ep, self.keystore.as_deref())
    }
}


fn new_active(
    dir: &Path,
    id: SegmentId,
    base_lsn: Lsn,
    hlc: &Hlc,
) -> Result<Active, HeraclitusError> {
    let path = segment_path(dir, id);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .append(true)
        .open(&path)?;
    let header = SegmentHeader {
        version: format::FORMAT_VERSION,
        segment_id: id,
        created_hlc: hlc.now(),
    };
    file.write_all(&header.encode())?;
    file.sync_data()?;
    sync_parent_dir(dir)?;

    Ok(Active {
        file,
        segment_id: id,
        bytes_written: HEADER_LEN as u64,
        record_hashes: Vec::new(),
        base_lsn,
        max_lsn: base_lsn,
        last_sync: Instant::now(),
    })
}

fn roll_segment(
    dir: &Path,
    active: &mut Active,
    catalog_swap: &ArcSwap<LogCatalog>,
    next_base_lsn: Lsn,
    hlc: &Hlc,
) -> Result<(), HeraclitusError> {
    active.file.sync_data()?;
    let footer = SegmentFooter {
        record_count: active.record_hashes.len() as u64,
        min_lsn: active.base_lsn,
        max_lsn: active.max_lsn,
        blake3_root: merkle_root(&active.record_hashes),
    };
    active.file.write_all(&footer.encode())?;
    active.file.sync_data()?;

    let next_id = active.segment_id + 1;
    let old_base_lsn = active.base_lsn;

    let current_catalog = catalog_swap.load();
    let mut new_sealed = (*current_catalog.sealed).clone();

    new_sealed.push(Arc::new(SegmentContainer {
        meta: SegmentMeta {
            id: active.segment_id,
            path: segment_path(dir, active.segment_id),
            base_lsn: old_base_lsn,
            max_lsn: footer.max_lsn,
            sealed: true,
            blake3_root: Some(footer.blake3_root),
            version: format::FORMAT_VERSION,
        },
        index: current_catalog.active.index.clone(),
    }));
    // Sem `sort_by_key` aqui: os segmentos são criados por ordem monotónica de
    // `base_lsn` e o `push` preserva-a, portanto o vetor JÁ está ordenado. O
    // sort era O(s log s) a cada selagem — 1 164 selagens na carga de 20M — a
    // reordenar o que já estava em ordem. A ordenação é invariante de que a
    // `binary_search_by_key(base_lsn)` em `read`/`scan_capped` depende; o teste
    // `selados_ficam_ordenados_por_base_lsn` fixa-a.

    *active = new_active(dir, next_id, next_base_lsn, hlc)?;

    let next_active_container = Arc::new(SegmentContainer {
        meta: SegmentMeta {
            id: next_id,
            path: segment_path(dir, next_id),
            base_lsn: next_base_lsn,
            max_lsn: u64::MAX,
            sealed: false,
            blake3_root: None,
            version: format::FORMAT_VERSION,
        },
        index: Arc::new(SegmentIndex {
            entries: Arc::new(Vec::new()),
        }),
    });

    catalog_swap.store(Arc::new(LogCatalog {
        sealed: Arc::new(new_sealed),
        active: next_active_container,
    }));
    Ok(())
}

/// Recuperação de boot para um `truncate.intent` deixado em disco.
///
/// **Nada neste crate volta a escrever esse ficheiro:** a superfície de
/// truncate (o trait `RaftLogStorage` v0, o `LogCommand::Truncate` e o
/// `handle_truncation_protected`) foi removida em 2026-08-19 por não ter um
/// único chamador — o consenso real usa `append_replicated` + `FileRaftLog`.
///
/// Esta função FICA porque um data-dir criado por uma versão anterior pode
/// ainda ter o ficheiro, e ignorá-lo deixaria o log num estado meio-truncado
/// sem ninguém a reparar. Custa um `exists()` por arranque. Só pode sair
/// depois de existir a garantia de que nenhum data-dir em uso vem de uma
/// versão com truncate.
fn check_and_recover_truncate_intent(dir: &Path) -> Result<(), HeraclitusError> {
    let intent_path = dir.join("truncate.intent");
    if intent_path.exists() {
        let mut f = File::open(&intent_path)?;
        let mut buf = [0u8; 16];
        if f.read_exact(&mut buf).is_ok() {
            let seg_id = u64::from_le_bytes(buf[..8].try_into().unwrap_or([0u8; 8]));
            let valid_len = u64::from_le_bytes(buf[8..16].try_into().unwrap_or([0u8; 8]));
            let seg_p = segment_path(dir, seg_id);
            if seg_p.exists() {
                let target_f = OpenOptions::new().write(true).open(&seg_p)?;
                target_f.set_len(valid_len)?;
                target_f.sync_all()?;
            }
            // R5: o intent (formato novo) lista também os segmentos seguintes a
            // remover — completa a remoção que um crash interrompeu, para que os
            // LSNs truncados não ressuscitem. Um intent antigo de 16 bytes não
            // tem lista e cai fora do read_exact (best-effort, idempotente).
            let mut cnt = [0u8; 4];
            if f.read_exact(&mut cnt).is_ok() {
                let n = u32::from_le_bytes(cnt);
                for _ in 0..n {
                    let mut idb = [0u8; 8];
                    if f.read_exact(&mut idb).is_err() {
                        break;
                    }
                    let victim = u64::from_le_bytes(idb);
                    if victim != seg_id {
                        let _ = std::fs::remove_file(segment_path(dir, victim));
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&intent_path);
        sync_parent_dir(dir)?;
    }
    Ok(())
}

struct SegmentScan {
    valid_len: u64,
    file_len: u64,
    record_hashes: Vec<[u8; 32]>,
    locs: Vec<(Lsn, u64, [u8; 16])>,
    min_lsn: Option<Lsn>,
    max_lsn: Option<Lsn>,
    sealed: bool,
    blake3_root: Option<[u8; 32]>,
    version: u16,
    corruption_detected: bool,
    /// Maior HLC persistido no segmento — o `open` observa-o para que o
    /// relógio NUNCA arranque atrás do que já está no disco (a monotonicidade
    /// de ts por LSN é o contrato do `AS OF TIMESTAMP`; um wall clock que
    /// recuasse entre execuções quebrá-la-ia sem isto).
    max_hlc: u64,
}

/// Varre vários segmentos em paralelo, devolvendo os resultados **na ordem dos
/// `ids`**.
///
/// `scan_segment_file` é puro por ficheiro — não toca em estado partilhado —
/// portanto a paralelização é segura por construção. O que NÃO é paralelizado
/// é o tratamento a seguir (ordem de LSN, selagem, montagem do catálogo), que
/// continua serial e determinístico.
///
/// O erro devolvido é o do **menor índice** que falhou, não o primeiro a
/// chegar: sem isso, dois segmentos corrompidos dariam mensagens diferentes
/// conforme o escalonamento das threads, e um relatório forense tem de ser
/// reproduzível.
///
/// Medido em 1 187 segmentos (`benches/otim_boot.rs`, 2026-08-19): 3,47x só
/// com a paralelização, e 14,3x somada às outras duas poupanças do arranque.
fn varrer_segmentos_em_paralelo(
    dir: &Path,
    ids: &[SegmentId],
) -> Result<Vec<Option<SegmentScan>>, HeraclitusError> {
    let varrer_um = |id: SegmentId| -> Result<SegmentScan, HeraclitusError> {
        let path = segment_path(dir, id);
        scan_segment_file(&path, id, !tem_rodape_selado(&path))
    };

    // Abaixo de dois segmentos, arrancar threads custa mais do que poupa.
    if ids.len() < 2 {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(Some(varrer_um(*id)?));
        }
        return Ok(out);
    }

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(ids.len());
    let proximo = AtomicU64::new(0);
    let recolhidos: std::sync::Mutex<Vec<(usize, Result<SegmentScan, HeraclitusError>)>> =
        std::sync::Mutex::new(Vec::with_capacity(ids.len()));

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = proximo.fetch_add(1, Ordering::Relaxed) as usize;
                if i >= ids.len() {
                    break;
                }
                let r = varrer_um(ids[i]);
                recolhidos
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((i, r));
            });
        }
    });

    let mut recolhidos = recolhidos.into_inner().unwrap_or_else(|e| e.into_inner());
    recolhidos.sort_by_key(|(i, _)| *i);

    let mut out = Vec::with_capacity(ids.len());
    for (_, r) in recolhidos {
        match r {
            Ok(scan) => out.push(Some(scan)),
            Err(e) => return Err(e), // menor índice, por causa do sort acima
        }
    }
    Ok(out)
}

/// Espreita o RODAPÉ sem varrer o segmento: lê os últimos `FOOTER_LEN` bytes e
/// confirma o magic. Um `true` significa "este segmento está selado e traz a
/// sua raiz Merkle gravada".
///
/// Serve para o `Log::open` decidir, ANTES de varrer, se precisa dos leaf
/// hashes: se a raiz já está no rodapé, calcular blake3 sobre o segmento
/// inteiro é trabalho para deitar fora. Custa um `seek` + 60 bytes por
/// segmento. Só o `verify()` — que existe precisamente para RECOMPUTAR a raiz
/// e a comparar — é que continua a pedir os hashes sempre.
fn tem_rodape_selado(path: &Path) -> bool {
    let Ok(f) = File::open(path) else {
        return false;
    };
    let Ok(meta) = f.metadata() else {
        return false;
    };
    let len = meta.len();
    if len < (HEADER_LEN + format::FOOTER_LEN) as u64 {
        return false;
    }
    let mut buf = [0u8; format::FOOTER_LEN];
    if ler_exato_em(&f, &mut buf, len - format::FOOTER_LEN as u64).is_err() {
        return false;
    }
    // Só aceita como selado se o rodapé DESCODIFICA — um magic solto no meio
    // de dados não chega.
    SegmentFooter::decode(&buf).is_some()
}

/// PASSADA ÚNICA ( BufReader streaming): Varre o log de forma estritamente sequencial sem seek recursivo O(N²).
fn scan_segment_file(
    path: &Path,
    _id: SegmentId,
    com_leaf_hashes: bool,
) -> Result<SegmentScan, HeraclitusError> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();

    if file_len < HEADER_LEN as u64 {
        return Ok(SegmentScan {
            valid_len: HEADER_LEN as u64,
            file_len,
            record_hashes: Vec::new(),
            locs: Vec::new(),
            min_lsn: None,
            max_lsn: None,
            sealed: false,
            blake3_root: None,
            version: format::FORMAT_VERSION,
            corruption_detected: file_len > 0,
            max_hlc: 0,
        });
    }

    let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
    let mut hdr = [0u8; HEADER_LEN];
    reader.read_exact(&mut hdr)?;
    let version = SegmentHeader::decode(&hdr)?.version;

    let mut offset = HEADER_LEN as u64;
    let mut hashes = Vec::new();
    let mut locs = Vec::new();
    let mut min_lsn = None;
    let mut max_lsn = None;
    let mut sealed = false;
    let mut root = None;
    let mut last_lsn: Option<Lsn> = None;
    let mut corruption = false;
    let mut max_hlc = 0u64;

    while offset < file_len {
        let mut magic_peek = [0u8; 4];
        // Enche o buffer interno e espia de forma sequencial pura
        if reader.read_exact(&mut magic_peek).is_err() {
            break;
        }

        if magic_peek == format::FOOTER_MAGIC {
            let mut footer_rem = [0u8; format::FOOTER_LEN - 4];
            if reader.read_exact(&mut footer_rem).is_err() {
                corruption = true;
                break;
            }
            let mut footer_buf = [0u8; format::FOOTER_LEN];
            footer_buf[..4].copy_from_slice(&magic_peek);
            footer_buf[4..].copy_from_slice(&footer_rem);

            if let Some(f) = SegmentFooter::decode(&footer_buf) {
                sealed = true;
                root = Some(f.blake3_root);
                offset += format::FOOTER_LEN as u64;
                // Segmento selado VAZIO (roll disparado com o 1º registo maior
                // que o segmento): o footer carrega min=max=base_lsn mas o scan
                // não viu registo nenhum (min/max = None) — não é corrupção.
                let bounds_ok = if f.record_count == 0 {
                    min_lsn.is_none() && max_lsn.is_none()
                } else {
                    min_lsn == Some(f.min_lsn) && max_lsn == Some(f.max_lsn)
                };
                // A contagem vem de `locs`, NÃO de `hashes`.
                //
                // `hashes` deixou de ser preenchido quando o chamador não
                // precisa dos leaf hashes (segmento já selado, raiz no
                // rodapé). Usá-lo como contador fazia `0 != record_count` em
                // TODO segmento selado — ou seja, marcava o log inteiro como
                // corrompido. A suite de crash-injection apanhou-o
                // imediatamente. `locs` é preenchido sempre, por registo, e é
                // o contador correto.
                if offset != file_len || locs.len() as u64 != f.record_count || !bounds_ok {
                    corruption = true;
                }
                break;
            } else {
                corruption = true;
                break;
            }
        } else {
            let len = u32::from_le_bytes(magic_peek) as usize;
            if len > 512 * 1024 * 1024
                || offset + format::RECORD_HEADER_LEN as u64 + len as u64 > file_len
            {
                corruption = true;
                break;
            }

            // Lê o restante do RecordHeader mais o payload dinâmico sequencialmente
            let remainder_len = (format::RECORD_HEADER_LEN - 4) + len;
            let mut remainder_buf = vec![0u8; remainder_len];
            if reader.read_exact(&mut remainder_buf).is_err() {
                corruption = true;
                break;
            }

            let mut record_buf = vec![0u8; format::RECORD_HEADER_LEN + len];
            record_buf[..4].copy_from_slice(&magic_peek);
            record_buf[4..].copy_from_slice(&remainder_buf);

            match format::decode_record(version, &record_buf) {
                Decoded::Record(lsn, hlc, payload, consumed) => {
                    if let Some(prev) = last_lsn {
                        if lsn <= prev {
                            corruption = true;
                            break;
                        }
                    }
                    last_lsn = Some(lsn);
                    max_hlc = max_hlc.max(hlc);

                    // Versão do segmento decide o layout: v3+ traz opaque_meta
                    // como PRIMEIRO campo do payload; v<=2 deriva-o do
                    // EventId do Episode.
                    //
                    // Antes desserializava-se o `StoragePayload` INTEIRO — o
                    // `content`, o `BTreeMap` de attrs, o `embedding`, os
                    // `parents`, todos alocados — para ler 16 bytes. Como
                    // `opaque_meta` é o primeiro campo, um struct só com ele
                    // descodifica o prefixo e pára. Medido: 1,98x no
                    // arranque a frio (`benches/otim_boot.rs`).
                    let opaque_meta = if version >= 3 {
                        let (p, _): (OpaqueMetaPrefix, usize) =
                            bincode::serde::decode_from_slice(payload, BINCODE_CFG)
                                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
                        p.opaque_meta
                    } else {
                        let (ep, _): (EpisodeV2, usize) =
                            bincode::serde::decode_from_slice(payload, BINCODE_CFG)
                                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
                        ep.id.0.to_bytes()
                    };

                    // O leaf hash só é preciso para quem vai COMPARAR raízes
                    // Merkle (`verify`) ou continuar a selagem (o segmento
                    // ativo). Num segmento já selado com rodapé válido, o
                    // `Log::open` usa a raiz do rodapé e DEITA FORA estes
                    // hashes — calcular blake3 sobre 9,8 GB para os descartar
                    // era o segundo maior desperdício do arranque (2,88x
                    // acumulado com o prefixo, medido).
                    if com_leaf_hashes {
                        hashes.push(format::record_leaf(version, &record_buf[..consumed]));
                    }
                    locs.push((lsn, offset, opaque_meta));
                    min_lsn = Some(min_lsn.map_or(lsn, |m: u64| m.min(lsn)));
                    max_lsn = Some(max_lsn.map_or(lsn, |m: u64| m.max(lsn)));
                    offset += consumed as u64;
                }
                _ => {
                    corruption = true;
                    break;
                }
            }
        }
    }

    Ok(SegmentScan {
        valid_len: offset,
        file_len,
        record_hashes: hashes,
        locs,
        min_lsn,
        max_lsn,
        sealed,
        blake3_root: root,
        version,
        corruption_detected: corruption,
        max_hlc,
    })
}

fn execute_physical_repair(path: &Path, valid_offset: u64) -> Result<(), HeraclitusError> {
    if valid_offset == HEADER_LEN as u64 {
        let assigned_id = segment_id_from_path(path)?;
        let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
        let header = SegmentHeader {
            version: format::FORMAT_VERSION,
            segment_id: assigned_id,
            created_hlc: 0,
        };
        f.write_all(&header.encode())?;
        f.sync_all()?;
    } else {
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(valid_offset)?;
        f.sync_all()?;
    }
    sync_parent_dir(path.parent().unwrap_or(path))?;
    Ok(())
}

fn seal_file(path: &Path, scan: &SegmentScan) -> Result<(), HeraclitusError> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(scan.valid_len))?;
    let footer = SegmentFooter {
        record_count: scan.record_hashes.len() as u64,
        min_lsn: scan.min_lsn.unwrap_or(0),
        max_lsn: scan.max_lsn.unwrap_or(0),
        blake3_root: merkle_root(&scan.record_hashes),
    };
    file.write_all(&footer.encode())?;
    file.sync_data()?;
    sync_parent_dir(path.parent().unwrap_or(path))?;
    Ok(())
}

fn segment_id_from_path(path: &Path) -> Result<SegmentId, HeraclitusError> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| HeraclitusError::Corruption {
            context: format!("{}", path.display()),
            detail: "Identificador numérico inválido ou fora de padrão".into(),
        })
}

/// Raiz Merkle (blake3) sobre os leaf hashes de um segmento.
///
/// NOTA (revisão 2026-07-16): níveis ímpares duplicam o último nó — o padrão
/// com a ambiguidade clássica CVE-2012-2459 ([A,B] vs [A,B,B] partilham raiz).
/// Aqui está MITIGADA porque o `record_count` viaja no footer e nas provas
/// (`DemotionReceipt`), e a verificação compara contagem E raiz. Mudar a regra
/// (p.ex. domain separation por nível) invalidaria todas as raízes já seladas
/// — só com bump de FORMAT_VERSION; deliberadamente adiado.
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut current = hashes.to_vec();
    let mut len = current.len();
    while len > 1 {
        let mut i = 0;
        for chunk in (0..len).step_by(2) {
            let mut hasher = blake3::Hasher::new();
            if chunk + 1 < len {
                hasher.update(&current[chunk]);
                hasher.update(&current[chunk + 1]);
            } else {
                hasher.update(&current[chunk]);
                hasher.update(&current[chunk]);
            }
            current[i] = hasher.finalize().into();
            i += 1;
        }
        len = i;
    }
    current[0]
}

#[derive(Default)]
pub struct VerifyReport {
    /// Total de segmentos varridos, **incluindo o ativo**.
    pub segments: u64,
    /// Quantos desses estavam SELADOS. O ativo nunca está, portanto
    /// `sealed == segments - 1` no caso normal.
    ///
    /// Existe porque sem ele o relatório não conseguia exprimir "íntegro":
    /// quem comparasse `merkle_ok == segments` nunca obtinha verdadeiro num log
    /// saudável, e um painel chegou a declarar FALHA DE INTEGRIDADE em bases
    /// perfeitamente sãs por causa disso.
    pub sealed: u64,
    pub records: u64,
    /// Selados cuja raiz gravada no rodapé bate com a recomputada. Um selado
    /// sem raiz gravada não conta aqui **e não é falha** — é não-verificável.
    pub merkle_ok: u64,
}

/// Relatório da verificação pontual de um segmento ([`Log::verify_segment`]).
#[derive(Debug, Clone)]
pub struct SegmentVerifyReport {
    pub id: SegmentId,
    pub version: u16,
    pub sealed: bool,
    pub records: u64,
    pub base_lsn: Lsn,
    pub max_lsn: Lsn,
    pub computed_root: [u8; 32],
    pub stored_root: Option<[u8; 32]>,
    pub valid: bool,
}
