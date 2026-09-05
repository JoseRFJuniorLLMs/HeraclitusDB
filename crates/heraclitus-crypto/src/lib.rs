//! heraclitus-crypto — encryption at rest with per-agent keys + crypto-shredding (§3.10).
//!
//! Each `agent_id` owns a 32-byte key, persisted as a file **outside the
//! immutable log**. Episode content plus the sensitive attribute/embedding
//! envelope are sealed at rest with ChaCha20-Poly1305 (AEAD), with `agent_id`
//! bound as associated data. "Erasure" (LGPD/GDPR)
//! is **crypto-shredding**: destroy the key file and that agent's ciphertext
//! becomes permanently unreadable — the append-only log is never mutated.
//!
//! Backward compatibility: sealed blobs carry an 8-byte magic prefix. Legacy
//! plaintext content never starts with it, so a mixed log (old plaintext +
//! new ciphertext) reads correctly.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use dashmap::DashMap;
use rand::RngCore;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Magic prefix marking a sealed (encrypted) content blob.
pub const ENC_MAGIC: &[u8; 8] = b"HRKLENC1";
const NONCE_LEN: usize = 12;

/// Tombstone substituted for content whose key was crypto-shredded.
pub const SHREDDED: &[u8] = b"[shredded]";

/// True if `blob` looks like a sealed content blob.
pub fn is_encrypted(blob: &[u8]) -> bool {
    blob.len() >= ENC_MAGIC.len() + NONCE_LEN && blob[..ENC_MAGIC.len()] == ENC_MAGIC[..]
}

/// Seal `plaintext`: `MAGIC || nonce(12) || ciphertext+tag`. `aad` (the
/// agent_id) is authenticated but not encrypted.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20poly1305 encrypt never fails for valid key/nonce");
    let mut out = Vec::with_capacity(ENC_MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(&ENC_MAGIC[..]);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a sealed blob. Returns `None` if the blob is not sealed, the key is
/// wrong, or the tag fails (tamper / corruption).
pub fn open(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if !is_encrypted(blob) {
        return None;
    }
    let nonce = &blob[ENC_MAGIC.len()..ENC_MAGIC.len() + NONCE_LEN];
    let ct = &blob[ENC_MAGIC.len() + NONCE_LEN..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

/// Per-agent key store. One key file per agent so a single agent can be
/// crypto-shredded by destroying exactly one file.
pub struct KeyStore {
    dir: PathBuf,
    cache: DashMap<String, [u8; 32]>,
    /// Ordena o `shred` (escrita) contra `get`/`get_or_create` (leitura).
    ///
    /// A DashMap protege cada ENTRADA, nao a SEQUENCIA. O shred faz
    /// remove-da-cache -> sobrescrever-a-zeros -> apagar; sem isto, um
    /// `get_or_create` concorrente do mesmo agente caia entre os passos:
    /// falhava a cache, relia o ficheiro JA A ZEROS, e `read_key` aceitava-o
    /// — o agente passava a cifrar com uma chave de 32 bytes nulos, cacheada
    /// para o resto da vida do processo. Na janela mais estreita voltava a
    /// cachear a chave REAL, e o "apagado" que o servidor reportara revertia.
    guarda: RwLock<()>,
    /// Costura SO de teste (ver `shred`): barreira POR INSTANCIA, para um
    /// teste parar o seu proprio shred na janela critica sem prender os
    /// shreds dos outros testes que correm em paralelo no mesmo binario.
    #[cfg(test)]
    ponto_shred: std::sync::Mutex<Option<Arc<std::sync::Barrier>>>,
}

/// Restringe o diretório de chaves a owner-only (0700) no Unix. No Windows os
/// ficheiros herdam a ACL do perfil do utilizador e não há API std para endurecer
/// mais sem uma dependência de ACLs — no-op documentado, best-effort no Unix.
#[cfg(unix)]
fn restrict_dir_perms(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_dir_perms(_dir: &Path) {}

/// Restringe um ficheiro de chave a owner-only (0600) no Unix. Aplica-se ao tmp
/// ANTES do rename atómico, para o ficheiro final nunca existir com permissões
/// largas (a chave em claro nunca fica world-readable, nem por um instante).
#[cfg(unix)]
fn restrict_file_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_file_perms(_path: &Path) {}

/// Torna durável a *entrada de directório*, não só o conteúdo do ficheiro.
///
/// Sem isto o keystore tinha dois modos de falha simétricos e ambos graves:
/// uma chave criada com `sync_all` podia perder a sua entrada de directório
/// numa falha de energia — e com a chave desaparece tudo o que ela cifra; e um
/// `remove_file` do crypto-shred podia não ser durável — o ficheiro voltava, e
/// **um apagamento que reverte não é um apagamento**, o que numa base que
/// promete erasure por crypto-shred é falha de conformidade, não um detalhe.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Em Windows não é possível abrir um directório como ficheiro; o NTFS
        // torna a operação de metadados durável por outra via.
        let _ = dir;
        Ok(())
    }
}

impl KeyStore {
    /// Open (or create) the key directory.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Arc<Self>> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        restrict_dir_perms(&dir);
        Ok(Arc::new(Self {
            dir,
            cache: DashMap::new(),
            guarda: RwLock::new(()),
            #[cfg(test)]
            ponto_shred: std::sync::Mutex::new(None),
        }))
    }

    fn key_path(&self, agent_id: &str) -> PathBuf {
        // hex-encode the agent_id so the filename is always filesystem-safe.
        let hex: String = agent_id.bytes().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{hex}.key"))
    }

    fn read_key(path: &Path) -> Option<[u8; 32]> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        // Uma chave toda a zeros nunca e uma chave: e o que o `shred` deixa no
        // ficheiro entre sobrescrever e apagar, e e publicamente conhecida.
        // Tratar isso como "nao ha chave" e defesa em profundidade por baixo
        // do lock — se alguma vez a ordenacao falhar, o pior caso passa a ser
        // "chave nova" em vez de "cifrar com zeros".
        if k.iter().all(|&b| b == 0) {
            return None;
        }
        Some(k)
    }

    /// Fetch the agent's key, generating and persisting one on first use.
    ///
    /// Corrida do primeiro uso (TOCTOU): dois threads que falham a cache e o
    /// ficheiro geravam chaves DIFERENTES e ambos faziam rename para o mesmo
    /// destino — o último ganhava o disco, mas cada thread cacheava a SUA
    /// chave. Dados selados com a chave perdedora ficavam ilegíveis após
    /// restart. O árbitro agora é `create_new` no caminho final: exatamente um
    /// thread cria; os outros leem a chave do vencedor.
    pub fn get_or_create(&self, agent_id: &str) -> io::Result<[u8; 32]> {
        // Leitura partilhada: varios agentes criam chaves em paralelo; um
        // `shred` espera que todos saiam, e nenhum entra a meio dele.
        let _g = self.guarda.read().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = self.cache.get(agent_id) {
            return Ok(*k);
        }
        let path = self.key_path(agent_id);
        let key = match Self::read_key(&path) {
            Some(k) => k,
            None => {
                use std::io::Write as _;
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(mut f) => {
                        // Vencedor: 0600 ANTES de escrever os bytes da chave.
                        restrict_file_perms(&path);
                        let mut k = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut k);
                        f.write_all(&k)?;
                        f.sync_all()?;
                        // A chave só existe de verdade quando a ENTRADA DE
                        // DIRECTÓRIO for durável. Sem isto, uma falha de
                        // energia entre o `sync_all` e o flush dos metadados
                        // levava a chave — e com ela todos os episódios que
                        // ela cifra, de forma irrecuperável.
                        sync_dir(&self.dir)?;
                        k
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        // Perdedor: o vencedor pode estar a meio do write_all —
                        // espera curta e limitada pela chave completa (32 bytes).
                        let mut got = None;
                        for _ in 0..100 {
                            if let Some(k) = Self::read_key(&path) {
                                got = Some(k);
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        got.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "ficheiro de chave existe mas está incompleto (artefacto de crash?)",
                            )
                        })?
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        self.cache.insert(agent_id.to_string(), key);
        Ok(key)
    }

    /// Fetch the agent's key if it still exists (`None` if never created or
    /// already shredded).
    pub fn get(&self, agent_id: &str) -> Option<[u8; 32]> {
        // Mesma corrida que o `get_or_create`: cache -> ficheiro -> insere.
        let _g = self.guarda.read().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = self.cache.get(agent_id) {
            return Some(*k);
        }
        let k = Self::read_key(&self.key_path(agent_id))?;
        self.cache.insert(agent_id.to_string(), k);
        Some(k)
    }

    /// Crypto-shred (SPEC-0050 §98): destroy the agent's key, so the events
    /// encrypted with it stop being readable while staying in the log.
    ///
    /// Returns whether a key was present. Idempotent; never touches the log.
    ///
    /// # What this guarantees, and what it does not
    ///
    /// **The guarantee is the deletion of the key**, not the erasure of its
    /// bytes. `remove_file` unlinks it, the cache entry goes, and nothing in
    /// this process can decrypt those events again.
    ///
    /// The zero-fill before the unlink is **belt, and a weak one**: it is a
    /// rewrite *in place*, and in-place rewrites do not reliably erase
    /// anything on the storage this actually runs on. A copy-on-write
    /// filesystem (ReFS, btrfs, ZFS) writes the zeros to a new extent and
    /// leaves the old one until it is reclaimed; an SSD with wear levelling
    /// does the same at the flash-translation layer, whatever the filesystem
    /// asked for. Snapshots, replicas and backups are untouched by
    /// construction.
    ///
    /// So: do not tell anyone the key material is gone from the medium. Tell
    /// them the key is destroyed — which is the property §98 asks for and the
    /// one that holds. Erasure at the medium level needs full-disk encryption
    /// with a destroyed volume key, or physical destruction.
    pub fn shred(&self, agent_id: &str) -> io::Result<bool> {
        // Exclusivo durante a sequencia inteira (ver `guarda`).
        let _g = self.guarda.write().unwrap_or_else(|e| e.into_inner());
        self.cache.remove(agent_id);
        // Costura SO de teste: para o shred exactamente na janela entre limpar
        // a cache e zerar o ficheiro — a janela em que, sem o lock, um leitor
        // re-cacheava a chave real e o apagamento revertia. Sem isto a corrida
        // dura microssegundos e nao e provavel por mutacao.
        #[cfg(test)]
        if let Some(b) = self.ponto_shred.lock().unwrap().clone() {
            b.wait();
        }
        let path = self.key_path(agent_id);
        if !path.exists() {
            return Ok(false);
        }
        // Sobrescrever antes de remover, para os bytes da chave não ficarem no
        // disco. O `sync_all` a seguir não é zelo: sem ele os zeros ficam em
        // buffers e o bloco original pode sobreviver à falha.
        if let Ok(meta) = std::fs::metadata(&path) {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) {
                use std::io::Write as _;
                let mut f = f;
                let _ = f.write_all(&vec![0u8; meta.len() as usize]);
                let _ = f.sync_all();
            }
        }
        std::fs::remove_file(&path)?;
        // O apagamento só conta depois de a remoção ser durável. Sem este
        // fsync do directório, um crash logo a seguir ressuscitava a chave —
        // e um crypto-shred que reverte devolve acesso a dados que foram
        // declarados apagados.
        sync_dir(&self.dir)?;
        Ok(true)
    }

    /// Number of agents with a live key on disk.
    pub fn agent_count(&self) -> usize {
        std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|x| x == "key"))
                    .count()
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let blob = seal(&key, b"segredo do agente", b"eva");
        assert!(is_encrypted(&blob));
        assert_eq!(open(&key, &blob, b"eva").unwrap(), b"segredo do agente");
        // wrong aad (agent) fails
        assert!(open(&key, &blob, b"outro").is_none());
        // wrong key fails
        assert!(open(&[9u8; 32], &blob, b"eva").is_none());
    }

    #[test]
    fn plaintext_is_not_encrypted() {
        assert!(!is_encrypted(b"empresa X trocou de socio"));
        assert!(!is_encrypted(b""));
    }

    #[test]
    fn keystore_create_get_shred() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path()).unwrap();
        let k1 = ks.get_or_create("eva").unwrap();
        // stable across calls
        assert_eq!(k1, ks.get_or_create("eva").unwrap());
        assert_eq!(Some(k1), ks.get("eva"));
        assert_eq!(ks.agent_count(), 1);

        // seal with the agent key, then shred -> key gone -> cannot open
        let blob = seal(&k1, b"dados pessoais", b"eva");
        assert!(ks.shred("eva").unwrap());
        assert!(ks.get("eva").is_none());
        assert!(!ks.shred("eva").unwrap()); // idempotent
                                            // a fresh key for the same agent cannot decrypt the old blob
        let k2 = ks.get_or_create("eva").unwrap();
        assert!(open(&k2, &blob, b"eva").is_none());
    }

    // No Unix (VM/produção Linux), a chave em claro no disco fica owner-only.
    // No Windows compila-se fora (ACLs herdam do perfil; sem API std).
    #[test]
    #[cfg(unix)]
    fn key_file_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path()).unwrap();
        ks.get_or_create("eva").unwrap();
        let kmode = std::fs::metadata(ks.key_path("eva"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(kmode & 0o777, 0o600, "ficheiro .key deve ser 0600");
        let dmode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(dmode & 0o777, 0o700, "dir de chaves deve ser 0700");
    }
}

#[cfg(test)]
mod testes_shred {
    use super::*;

    /// PROVA DETERMINISTA do lock. O shred desta instancia e parado na janela
    /// critica; um leitor tenta `get_or_create` durante a janela. COM
    /// exclusividade o leitor bloqueia ate o shred acabar e sai com uma chave
    /// NOVA. SEM ela (a mutacao) entra, le a chave real, re-cacheia-a, e depois
    /// do shred o `get` devolve a chave declarada apagada.
    #[test]
    fn leitor_na_janela_do_shred_nunca_reaviva_a_chave_apagada() {
        let (_d, ks) = loja();
        let antiga = ks.get_or_create("ana").unwrap();
        let barreira = Arc::new(std::sync::Barrier::new(2));
        *ks.ponto_shred.lock().unwrap() = Some(barreira.clone());

        let ks_shred = ks.clone();
        let fio_shred = std::thread::spawn(move || ks_shred.shred("ana"));
        // Esperar pelo FACTO, nao pelo relogio: a cache vazia para "ana"
        // significa que o shred ja executou o `remove` — e como o faz DEPOIS
        // de tomar o write-lock, esta agora parado na barreira com o lock na
        // mao. Um `sleep` aqui era uma corrida (o leitor podia ler a chave
        // antiga antes de o shred sequer comecar, o que e legitimo e nao e o
        // bug).
        let t0 = std::time::Instant::now();
        while ks.cache.get("ana").is_some() {
            assert!(
                t0.elapsed() < std::time::Duration::from_secs(5),
                "o shred nunca chegou a janela"
            );
            std::thread::yield_now();
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let ks_leitor = ks.clone();
        std::thread::spawn(move || {
            let _ = tx.send(ks_leitor.get_or_create("ana"));
        });
        let na_janela = rx.recv_timeout(std::time::Duration::from_millis(300)).ok();

        barreira.wait();
        assert!(
            fio_shred.join().unwrap().unwrap(),
            "o shred tem de ter apagado"
        );
        *ks.ponto_shred.lock().unwrap() = None;

        if let Some(Ok(k)) = na_janela {
            assert_ne!(
                k, antiga,
                "o leitor entrou na janela e leu a chave que estava a ser apagada"
            );
        }
        assert_ne!(
            ks.get("ana"),
            Some(antiga),
            "o shred REVERTEU: a chave apagada voltou"
        );
    }

    /// O defeito: `shred` limpava a cache ANTES de zerar o ficheiro; um
    /// `get_or_create` concorrente relia o ficheiro a zeros, `read_key`
    /// aceitava-o, e o agente passava a cifrar com `[0; 32]` — cacheado para
    /// sempre. Estes testes fecham as duas portas: a chave nula nunca e uma
    /// chave, e o shred e exclusivo contra as leituras.
    fn loja() -> (tempfile::TempDir, Arc<KeyStore>) {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path()).unwrap();
        (d, ks)
    }

    /// Um ficheiro de chave todo a zeros — o que o shred deixa entre
    /// sobrescrever e apagar, ou um crash a meio — NUNCA pode virar chave.
    #[test]
    fn ficheiro_a_zeros_nunca_e_uma_chave() {
        let (_d, ks) = loja();
        let k = ks.get_or_create("ana").unwrap();
        assert!(k.iter().any(|&b| b != 0), "uma chave a serio nao e nula");
        // Simular o estado intermedio do shred: ficheiro a zeros, cache vazia.
        ks.cache.remove("ana");
        std::fs::write(ks.key_path("ana"), [0u8; 32]).unwrap();
        // `get` nao pode devolver zeros.
        assert!(ks.get("ana").is_none(), "zeros no disco nao sao uma chave");
        // `get_or_create` tambem nao: falha alto (artefacto de crash) em vez
        // de cifrar com uma chave que toda a gente conhece.
        // Recusar e aceitavel; devolver [0;32] nunca.
        if let Ok(k) = ks.get_or_create("ana") {
            assert!(k.iter().any(|&b| b != 0), "devolveu a chave nula");
        }
        assert!(
            ks.cache
                .get("ana")
                .is_none_or(|k| k.iter().any(|&b| b != 0)),
            "a cache nao pode ficar envenenada com zeros"
        );
    }

    /// Depois do shred, o agente NAO tem chave (get = None, cache vazia) e a
    /// chave seguinte e nova — o apagamento nao reverte.
    #[test]
    fn shred_e_definitivo_e_a_chave_seguinte_e_nova() {
        let (_d, ks) = loja();
        let antiga = ks.get_or_create("ana").unwrap();
        assert!(ks.shred("ana").unwrap());
        assert!(ks.get("ana").is_none(), "depois do shred nao ha chave");
        assert!(
            ks.cache.get("ana").is_none(),
            "a cache nao pode ressuscitar o agente"
        );
        let nova = ks.get_or_create("ana").unwrap();
        assert_ne!(nova, antiga, "a chave nova nao pode ser a apagada");
        assert!(nova.iter().any(|&b| b != 0));
    }

    /// Stress: leitores concorrentes durante um shred nunca veem zeros nem a
    /// chave antiga depois de o shred ter devolvido. Com o lock isto e
    /// deterministicamente seguro; sem ele, apanhava zeros ou a chave velha.
    #[test]
    fn leitores_concorrentes_nunca_veem_zeros_durante_o_shred() {
        let (_d, ks) = loja();
        let antiga = ks.get_or_create("ana").unwrap();
        let vistas: std::sync::Arc<std::sync::Mutex<Vec<[u8; 32]>>> = Default::default();
        let mut fios = Vec::new();
        for _ in 0..8 {
            let ks = ks.clone();
            let vistas = vistas.clone();
            fios.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    if let Ok(k) = ks.get_or_create("ana") {
                        vistas.lock().unwrap().push(k);
                    }
                }
            }));
        }
        // O que o lock garante e que ninguem tem em maos a chave que existia
        // ANTES de um shred depois de esse shred ter devolvido. Sem
        // exclusividade, um leitor cai entre o `remove` da cache e os zeros,
        // re-cacheia a chave real, e o "apagado" reverte em silencio.
        let mut revertidos = 0;
        for _ in 0..50 {
            let antes = ks.get_or_create("ana").unwrap();
            if ks.shred("ana").unwrap_or(false) && ks.get("ana") == Some(antes) {
                revertidos += 1;
            }
        }
        for f in fios {
            f.join().unwrap();
        }
        let vistas = vistas.lock().unwrap();
        assert!(!vistas.is_empty());
        assert!(
            vistas.iter().all(|k| k.iter().any(|&b| b != 0)),
            "um leitor viu a chave nula"
        );
        assert_eq!(
            revertidos, 0,
            "a chave apagada voltou a cache {revertidos} vezes: o shred reverteu"
        );
        let _ = antiga;
    }
}
