//! SPEC-0072 §5–§8 — snapshot durável do estado derivado do Sentinel.
//!
//! O snapshot é o que torna o INV-5 possível: com ele, o custo do arranque é
//! proporcional à cauda `[watermark, head)` e não ao tamanho da base.
//!
//! Duas propriedades governam tudo o resto neste ficheiro, e valem a pena
//! declarar antes do código:
//!
//! 1. **É derivado (INV-4).** Nada aqui é source of truth. Um snapshot
//!    ilegível, com digest errado, de outro formato ou de outra versão de
//!    pipeline é DESCARTADO e o estado é reconstruído do log — nunca ao
//!    contrário. Por isso `carregar` não devolve `Err` para conteúdo mau:
//!    devolve o motivo pelo qual não serve, e o arranque reconstrói.
//! 2. **É publicado atomicamente (§7).** `tmp` → `write` → `flush` →
//!    `sync_all` → `rename` → fsync do directório. Um crash em qualquer ponto
//!    deixa ou o snapshot antigo intacto ou o novo completo; nunca meio
//!    ficheiro a fazer-se passar por estado válido — e o digest apanha o caso
//!    em que o sistema de ficheiros mentiu na mesma.

use crate::behavior::BehavioralSnapshot;
use crate::correlation::{DetectorChannel, EvidenceFusion, IncidentEngine, TemporalSecurityGraph};
use crate::error::SentinelError;
use crate::event::{EntityRef, EvidenceRef, SecurityEvent};
use crate::state::startup::RebuildReason;
use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Versão do formato em disco. Sobe quando a representação muda de maneira
/// que um binário antigo leria mal — o que, com bincode, é qualquer alteração
/// à ordem ou ao tipo dos campos.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// `HRKSNAP1`. Distingue um snapshot de qualquer outro ficheiro que apareça no
/// mesmo directório, e torna óbvio no `hexdump` o que se está a ver.
const MAGIC: [u8; 8] = *b"HRKSNAP1";

/// `MAGIC || format_version(4) || digest(32) || body_len(8)`.
const HEADER_LEN: usize = 8 + 4 + 32 + 8;

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

/// Estado do acumulador de fusão, na forma que atravessa o disco.
///
/// O `FusionAccumulator` do runtime é privado a `lib.rs`; esta é a sua
/// projecção pública. São tipos separados de propósito: o formato em disco não
/// deve mudar só porque um campo interno do runtime mudou de nome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusionAccumulatorState {
    pub subject: EntityRef,
    pub rule_score: f32,
    pub behavioral_score: f32,
    pub graph_score: f32,
    pub threat_intel_score: f32,
    pub evidence: Vec<EvidenceRef>,
    pub detectors: BTreeMap<String, DetectorChannel>,
}

/// O estado derivado do Sentinel, válido até `applied_until_exclusive`.
///
/// Contém apenas o necessário para retomar (§5). Não guarda eventos brutos
/// além do histórico L1, que já está limitado pelo horizonte do ruleset — e é
/// essa limitação que torna o snapshot viável de todo: um `rule_history` sem
/// tecto tornaria cada publicação Θ(N) sobre uma base que só cresce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentinelStateSnapshot {
    pub format_version: u32,
    pub pipeline_version: u32,
    /// LSN até ao qual — exclusivo — este estado foi aplicado. O watermark.
    pub applied_until_exclusive: Lsn,
    /// O head do log no momento da publicação. Não é usado para decidir nada;
    /// serve para auditar quão atrasado o snapshot estava quando saiu.
    pub canonical_head_at_snapshot: Lsn,

    pub rule_history: Vec<(Lsn, SecurityEvent)>,
    pub behavior_state: Option<BehavioralSnapshot>,
    pub graph_state: Option<TemporalSecurityGraph>,
    pub incident_state: Option<IncidentEngine>,
    pub fusion_state: Option<EvidenceFusion>,
    pub fusion_accumulators: BTreeMap<String, FusionAccumulatorState>,

    pub signal_ids: BTreeSet<String>,
    pub derived_sources: Vec<Lsn>,
    pub incident_revision_ids: BTreeSet<String>,
    pub risk_revision_ids: BTreeSet<String>,
    pub checkpoint_ids: BTreeSet<String>,
    pub last_checkpoint_lsn: Option<Lsn>,
    pub l4_ids: BTreeMap<String, Lsn>,
}

impl SentinelStateSnapshot {
    /// Um snapshot vazio de um pipeline, para o caso em que ainda não há nada
    /// aplicado.
    pub fn vazio(pipeline_version: u32) -> Self {
        Self {
            format_version: SNAPSHOT_FORMAT_VERSION,
            pipeline_version,
            applied_until_exclusive: 0,
            canonical_head_at_snapshot: 0,
            rule_history: Vec::new(),
            behavior_state: None,
            graph_state: None,
            incident_state: None,
            fusion_state: None,
            fusion_accumulators: BTreeMap::new(),
            signal_ids: BTreeSet::new(),
            derived_sources: Vec::new(),
            incident_revision_ids: BTreeSet::new(),
            risk_revision_ids: BTreeSet::new(),
            checkpoint_ids: BTreeSet::new(),
            last_checkpoint_lsn: None,
            l4_ids: BTreeMap::new(),
        }
    }

    fn corpo(&self) -> Result<Vec<u8>, SentinelError> {
        bincode::serde::encode_to_vec(self, BINCODE_CFG)
            .map_err(|error| SentinelError::Cursor(format!("snapshot encode: {error}")))
    }
}

/// O digest da §8, sobre `format_version || pipeline_version ||
/// applied_until_exclusive || corpo_serializado`.
///
/// Os três escalares entram explicitamente apesar de já estarem dentro do
/// corpo. Não é redundância inútil: é o que impede que um corpo válido de um
/// snapshot seja colado por baixo de um cabeçalho que anuncia outra versão de
/// formato — o cabeçalho é lido ANTES de o corpo ser desserializado, e é
/// preciso que a verificação cubra o que foi lido primeiro.
fn digest(format_version: u32, pipeline_version: u32, watermark: Lsn, corpo: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&format_version.to_le_bytes());
    hasher.update(&pipeline_version.to_le_bytes());
    hasher.update(&watermark.to_le_bytes());
    hasher.update(corpo);
    *hasher.finalize().as_bytes()
}

/// O que saiu de uma tentativa de carregar o snapshot.
///
/// Não é `Result`: "o snapshot não serve" é um resultado normal do arranque,
/// não um erro. Só I/O verdadeiramente inesperado sobe como `Err`.
#[derive(Debug)]
pub enum SnapshotLoad {
    Utilizavel(Box<SentinelStateSnapshot>),
    Descartado(RebuildReason),
}

/// Persistência do snapshot em `<data_dir>/sentinel/`.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    path: PathBuf,
}

impl SnapshotStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Caminho do snapshot anterior, guardado por [`Self::publicar`] para o
    /// rollback opcional da §6.
    pub fn path_anterior(&self) -> PathBuf {
        self.path.with_extension("snapshot.prev")
    }

    /// Lê o snapshot, verifica-o, e diz se serve.
    ///
    /// Qualquer resultado que não seja `Utilizavel` manda reconstruir a partir
    /// do log. Em nenhum caminho desta função o log é tocado — é o INV-8 da
    /// §8: "jamais alterar o log por causa de snapshot inválido".
    pub fn carregar(&self, pipeline_version: u32) -> Result<SnapshotLoad, SentinelError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SnapshotLoad::Descartado(RebuildReason::SnapshotAusente));
            }
            Err(error) => {
                // Um erro de I/O que não seja "não existe" também não impede o
                // arranque: o estado é reconstruível. O que não pode acontecer
                // é ficar silencioso, e por isso a razão viaja com o texto.
                return Ok(SnapshotLoad::Descartado(RebuildReason::Ilegivel(
                    error.to_string(),
                )));
            }
        };
        Ok(self.verificar(&bytes, pipeline_version))
    }

    fn verificar(&self, bytes: &[u8], pipeline_version: u32) -> SnapshotLoad {
        if bytes.len() < HEADER_LEN {
            return SnapshotLoad::Descartado(RebuildReason::Ilegivel(format!(
                "{} bytes, menos que o cabeçalho de {HEADER_LEN}",
                bytes.len()
            )));
        }
        if bytes[..8] != MAGIC {
            return SnapshotLoad::Descartado(RebuildReason::Ilegivel("magic inválido".into()));
        }
        let formato = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if formato != SNAPSHOT_FORMAT_VERSION {
            return SnapshotLoad::Descartado(RebuildReason::FormatoDesconhecido {
                encontrado: formato,
                suportado: SNAPSHOT_FORMAT_VERSION,
            });
        }
        let esperado: [u8; 32] = bytes[12..44].try_into().expect("32 bytes");
        let corpo_len = u64::from_le_bytes(bytes[44..52].try_into().expect("8 bytes")) as usize;
        let Some(corpo) = bytes.get(HEADER_LEN..HEADER_LEN + corpo_len) else {
            return SnapshotLoad::Descartado(RebuildReason::Ilegivel(format!(
                "corpo truncado: anunciados {corpo_len} bytes, existem {}",
                bytes.len().saturating_sub(HEADER_LEN)
            )));
        };

        // O corpo é desserializado ANTES de o digest ser verificado porque o
        // digest cobre `pipeline_version` e `applied_until_exclusive`, que
        // vivem lá dentro. Desserializar não é confiar: nada é usado antes de
        // o digest bater.
        let (snapshot, _): (SentinelStateSnapshot, usize) =
            match bincode::serde::decode_from_slice(corpo, BINCODE_CFG) {
                Ok(valor) => valor,
                Err(error) => {
                    return SnapshotLoad::Descartado(RebuildReason::Ilegivel(format!(
                        "decode: {error}"
                    )));
                }
            };
        let obtido = digest(
            formato,
            snapshot.pipeline_version,
            snapshot.applied_until_exclusive,
            corpo,
        );
        if obtido != esperado {
            return SnapshotLoad::Descartado(RebuildReason::DigestInvalido);
        }
        if snapshot.pipeline_version != pipeline_version {
            // §46 — um pipeline diferente produz estado derivado diferente.
            // Aceitá-lo seria continuar com baselines e incidentes calculados
            // por regras que já não são as que estão a correr.
            return SnapshotLoad::Descartado(RebuildReason::PipelineDiferente {
                encontrado: snapshot.pipeline_version,
                configurado: pipeline_version,
            });
        }
        SnapshotLoad::Utilizavel(Box::new(snapshot))
    }

    /// Publicação atómica (§7).
    ///
    /// A ordem é a da spec e não é negociável: o `sync_all` do temporário tem
    /// de acontecer ANTES do rename, senão o rename pode ficar durável antes do
    /// conteúdo e um crash publica um ficheiro com lixo. O fsync do directório
    /// no fim é o que torna o próprio rename durável — sem ele, "sync_all"
    /// prova o conteúdo do ficheiro, não a entrada que lhe dá o nome.
    pub fn publicar(&self, snapshot: &SentinelStateSnapshot) -> Result<(), SentinelError> {
        let parent = self.path.parent().ok_or_else(|| {
            SentinelError::Cursor("snapshot path must have an explicit parent".into())
        })?;
        std::fs::create_dir_all(parent)?;

        let corpo = snapshot.corpo()?;
        let d = digest(
            SNAPSHOT_FORMAT_VERSION,
            snapshot.pipeline_version,
            snapshot.applied_until_exclusive,
            &corpo,
        );
        let mut bytes = Vec::with_capacity(HEADER_LEN + corpo.len());
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&d);
        bytes.extend_from_slice(&(corpo.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&corpo);

        let temp = self.path.with_extension("snapshot.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.flush()?;
            file.sync_all()?;
        }

        // O anterior é guardado antes de ser substituído. É barato (um rename)
        // e dá à §6 o `state.snapshot.prev` para rollback manual — ver um
        // snapshot mau é muito mais útil do que descobrir que já não existe.
        if self.path.exists() {
            let _ = std::fs::rename(&self.path, self.path_anterior());
        }

        match std::fs::rename(&temp, &self.path) {
            Ok(()) => {}
            Err(error) => {
                #[cfg(windows)]
                {
                    // Mesma semântica que o `CursorStore`: o Windows recusa
                    // substituir. O temporário já está completo e durável, e o
                    // anterior já foi movido para `.prev`, portanto não há
                    // janela em que os dois se percam.
                    if self.path.exists() {
                        std::fs::remove_file(&self.path)?;
                        std::fs::rename(&temp, &self.path)?;
                    } else {
                        return Err(error.into());
                    }
                }
                #[cfg(not(windows))]
                {
                    // Em POSIX o rename substitui sempre; se falhou, falhou por
                    // uma razão real (ENOSPC, EIO). Apagar o destino e tentar
                    // outra vez destruiria o snapshot que ainda serve.
                    let _ = std::fs::remove_file(&temp);
                    return Err(error.into());
                }
            }
        }

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::{BaselinePolicy, BehavioralEngine};

    fn snapshot_de_teste(pipeline: u32, watermark: Lsn) -> SentinelStateSnapshot {
        let mut s = SentinelStateSnapshot::vazio(pipeline);
        s.applied_until_exclusive = watermark;
        s.canonical_head_at_snapshot = watermark + 3;
        s.signal_ids.insert("sig-um".into());
        s.derived_sources.extend([1, 2, 3]);
        s.l4_ids.insert("investigation:abc".into(), 9);
        s.behavior_state = Some(
            BehavioralEngine::new(BaselinePolicy::default())
                .unwrap()
                .snapshot(),
        );
        s
    }

    #[test]
    fn um_snapshot_publicado_volta_identico() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        let original = snapshot_de_teste(2, 4_096);
        store.publicar(&original).unwrap();
        match store.carregar(2).unwrap() {
            SnapshotLoad::Utilizavel(lido) => assert_eq!(*lido, original),
            outro => panic!("esperava utilizável, veio {outro:?}"),
        }
    }

    #[test]
    fn um_snapshot_ausente_e_primeiro_arranque_e_nao_um_erro() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        assert!(matches!(
            store.carregar(1).unwrap(),
            SnapshotLoad::Descartado(RebuildReason::SnapshotAusente)
        ));
    }

    #[test]
    fn um_byte_trocado_no_corpo_invalida_o_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();

        let mut bytes = std::fs::read(store.path()).unwrap();
        let ultimo = bytes.len() - 1;
        bytes[ultimo] ^= 0xFF;
        std::fs::write(store.path(), &bytes).unwrap();

        match store.carregar(1).unwrap() {
            SnapshotLoad::Descartado(RebuildReason::DigestInvalido)
            | SnapshotLoad::Descartado(RebuildReason::Ilegivel(_)) => {}
            outro => panic!("um corpo corrompido tem de ser descartado, veio {outro:?}"),
        }
    }

    #[test]
    fn um_digest_trocado_invalida_o_snapshot_mesmo_com_corpo_bom() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();

        let mut bytes = std::fs::read(store.path()).unwrap();
        bytes[12] ^= 0x01;
        std::fs::write(store.path(), &bytes).unwrap();

        assert!(matches!(
            store.carregar(1).unwrap(),
            SnapshotLoad::Descartado(RebuildReason::DigestInvalido)
        ));
    }

    #[test]
    fn um_formato_desconhecido_e_descartado_sem_desserializar() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();

        let mut bytes = std::fs::read(store.path()).unwrap();
        bytes[8..12].copy_from_slice(&999u32.to_le_bytes());
        std::fs::write(store.path(), &bytes).unwrap();

        assert!(matches!(
            store.carregar(1).unwrap(),
            SnapshotLoad::Descartado(RebuildReason::FormatoDesconhecido {
                encontrado: 999,
                suportado: SNAPSHOT_FORMAT_VERSION,
            })
        ));
    }

    #[test]
    fn um_snapshot_de_outro_pipeline_nao_e_aceite() {
        // §46: continuar com baselines calculados por outra versão do pipeline
        // seria pior do que reconstruir — o estado estaria certo para regras
        // que já não correm.
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();
        assert!(matches!(
            store.carregar(2).unwrap(),
            SnapshotLoad::Descartado(RebuildReason::PipelineDiferente {
                encontrado: 1,
                configurado: 2,
            })
        ));
    }

    #[test]
    fn um_ficheiro_truncado_e_descartado_e_nao_faz_panico() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();
        let bytes = std::fs::read(store.path()).unwrap();

        for corte in [0, 1, 8, 11, 43, HEADER_LEN - 1, HEADER_LEN, bytes.len() / 2] {
            std::fs::write(store.path(), &bytes[..corte.min(bytes.len())]).unwrap();
            assert!(
                matches!(store.carregar(1).unwrap(), SnapshotLoad::Descartado(_)),
                "corte em {corte} tinha de ser descartado"
            );
        }
    }

    #[test]
    fn publicar_por_cima_preserva_o_anterior() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();
        store.publicar(&snapshot_de_teste(1, 20)).unwrap();

        match store.carregar(1).unwrap() {
            SnapshotLoad::Utilizavel(lido) => assert_eq!(lido.applied_until_exclusive, 20),
            outro => panic!("{outro:?}"),
        }
        let anterior = SnapshotStore::new(store.path_anterior());
        match anterior.carregar(1).unwrap() {
            SnapshotLoad::Utilizavel(lido) => assert_eq!(lido.applied_until_exclusive, 10),
            outro => panic!("o anterior tinha de continuar legível, veio {outro:?}"),
        }
    }

    #[test]
    fn nenhum_temporario_fica_para_tras() {
        let temp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(temp.path().join("sentinel/state.snapshot"));
        store.publicar(&snapshot_de_teste(1, 10)).unwrap();
        let dir = store.path().parent().unwrap();
        let sobras: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|nome| nome.ends_with(".tmp"))
            .collect();
        assert!(sobras.is_empty(), "ficheiros temporários por limpar: {sobras:?}");
    }
}
