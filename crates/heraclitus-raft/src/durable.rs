//! SPEC-015/021 — raft-log **durável em disco** (`FileRaftLog`).
//!
//! O [`crate::consensus::MemRaftLog`] perde tudo num restart — o que quebra a
//! segurança do raft: um nó que reinicia sem se lembrar do voto do termo atual
//! pode votar DUAS VEZES no mesmo termo ⇒ split-brain. Este módulo fecha essa
//! lacuna: um WAL append-only com recuperação, onde o `fsync` acontece ANTES de
//! `log_io_completed` — ou seja, o ack de quórum passa a ser respaldado por
//! durabilidade real, não por memória.
//!
//! Layout em disco (um diretório):
//! - `entries.wal` — registos append-only enquadrados por `u32` de comprimento:
//!   `Insert(Entry)`, `Truncate(index)`, `Purge(LogId)`. A cauda meia-escrita
//!   por um crash é truncada no `open` (o último registo incompleto é descartado
//!   — determinístico, sem corrupção silenciosa).
//! - `meta.bin` — `vote` + `committed`, reescrito atomicamente (tmp+rename) a
//!   cada mudança.
//!
//! O estado da máquina (o log de episódios) já é durável no `heraclitus_log`; a
//! recuperação COMPLETA do nó (state machine + este raft-log) é o passo seguinte
//! — ver o teste de restart e a nota de honestidade no header do
//! [`crate::consensus`].
//!
//! (`result_large_err` é inerente ao `StorageError` do openraft — silenciado.)
#![allow(clippy::result_large_err)]

use crate::consensus::{NodeId, TypeConfig};
use openraft::storage::{LogFlushed, LogState, RaftLogReader, RaftLogStorage};
use openraft::{Entry, LogId, StorageError, StorageIOError, Vote};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

/// Um registo do WAL do raft-log.
#[derive(serde::Serialize, serde::Deserialize)]
enum LogRecord {
    Insert(Entry<TypeConfig>),
    /// Descarta entradas com `index >= self.0`.
    Truncate(u64),
    /// Descarta entradas com `index <= self.0.index`; fixa `last_purged`.
    Purge(LogId<NodeId>),
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Meta {
    vote: Option<Vote<NodeId>>,
    committed: Option<LogId<NodeId>>,
}

struct Inner {
    dir: PathBuf,
    wal: File,
    entries: BTreeMap<u64, Entry<TypeConfig>>,
    last_purged: Option<LogId<NodeId>>,
    meta: Meta,
}

fn io_err(e: impl std::fmt::Display) -> openraft::AnyError {
    openraft::AnyError::error(e.to_string())
}

/// Torna DURÁVEL a entrada de diretório (o `rename`/criação de um ficheiro só
/// altera metadados do diretório; sem este fsync um crash pode reverter o
/// rename e perder o voto acabado de gravar — split-brain).
///
/// Best-effort e honesto por plataforma: no **Linux** (alvo de produção) abrir o
/// diretório e `sync_all` funciona e dá durabilidade total; no **Windows** não
/// se pode abrir um diretório como `File` (isto vira no-op) e a durabilidade do
/// rename fica dependente da atomicidade do NTFS + journaling de metadados.
pub(crate) fn fsync_dir(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

impl Inner {
    /// Serializa um registo no formato do WAL (`u32` LE de comprimento + bincode).
    fn encode_record(rec: &LogRecord) -> Result<Vec<u8>, StorageError<NodeId>> {
        let bytes = bincode::serde::encode_to_vec(rec, BINCODE_CFG)
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    fn append_record(&mut self, rec: &LogRecord) -> Result<(), StorageError<NodeId>> {
        let framed = Self::encode_record(rec)?;
        self.wal
            .write_all(&framed)
            .and_then(|_| self.wal.sync_all()) // fsync ANTES do ack — durabilidade real
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        Ok(())
    }

    /// R23: reescreve o WAL COMPACTADO (um `Purge(last_purged)` + os Inserts
    /// vivos), atomicamente (tmp + fsync + rename + fsync do diretório). Sem
    /// isto o `entries.wal` crescia PARA SEMPRE — Insert/Truncate/Purge são
    /// todos appends e nada nunca removia os bytes mortos (fuga de disco sem
    /// bound num cluster de vida longa). Chamado no `purge` (pós-snapshot, os
    /// vivos são poucos) e no `open` quando o replay consumiu compactações.
    fn rewrite_wal(&mut self) -> Result<(), StorageError<NodeId>> {
        let wal_path = self.dir.join("entries.wal");
        let tmp = self.dir.join("entries.wal.tmp");
        {
            let mut f = File::create(&tmp)
                .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
            if let Some(p) = self.last_purged {
                f.write_all(&Self::encode_record(&LogRecord::Purge(p))?)
                    .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
            }
            for e in self.entries.values() {
                f.write_all(&Self::encode_record(&LogRecord::Insert(e.clone()))?)
                    .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
            }
            f.sync_all()
                .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        }
        std::fs::rename(&tmp, &wal_path)
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        fsync_dir(&self.dir);
        let mut wal = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        wal.seek(SeekFrom::End(0))
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        self.wal = wal;
        Ok(())
    }

    fn write_meta(&mut self) -> Result<(), StorageError<NodeId>> {
        let bytes = bincode::serde::encode_to_vec(&self.meta, BINCODE_CFG)
            .map_err(|e| StorageError::from(StorageIOError::write_vote(io_err(e))))?;
        let tmp = self.dir.join("meta.bin.tmp");
        let final_path = self.dir.join("meta.bin");
        // Escrita atómica: grava no tmp, fsync, rename por cima.
        {
            let mut f = File::create(&tmp)
                .map_err(|e| StorageError::from(StorageIOError::write_vote(io_err(e))))?;
            f.write_all(&bytes)
                .and_then(|_| f.sync_all())
                .map_err(|e| StorageError::from(StorageIOError::write_vote(io_err(e))))?;
        }
        std::fs::rename(&tmp, &final_path)
            .map_err(|e| StorageError::from(StorageIOError::write_vote(io_err(e))))?;
        // Torna o rename durável — sem isto o voto podia reverter num crash.
        fsync_dir(&self.dir);
        Ok(())
    }

    fn last_log_id(&self) -> Option<LogId<NodeId>> {
        self.entries
            .values()
            .next_back()
            .map(|e| e.log_id)
            .or(self.last_purged)
    }
}

/// Raft-log durável: WAL append-only + meta atómica, recuperado no `open`.
#[derive(Clone)]
pub struct FileRaftLog {
    inner: Arc<Mutex<Inner>>,
}

impl FileRaftLog {
    /// Abre (ou cria) o raft-log durável no diretório. Replaya o WAL para
    /// reconstruir as entradas + `last_purged`, trunca a cauda meia-escrita, e
    /// carrega o `meta.bin` (voto + committed).
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StorageError<NodeId>> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)
            .map_err(|e| StorageError::from(StorageIOError::read_logs(io_err(e))))?;

        let wal_path = dir.join("entries.wal");
        let (entries, last_purged, valid_len, saw_compaction) = Self::replay(&wal_path)?;

        // Trunca a cauda meia-escrita (o último registo incompleto após crash).
        let wal = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false) // preserva o conteúdo existente; truncamos a cauda torn à mão
            .open(&wal_path)
            .map_err(|e| StorageError::from(StorageIOError::read_logs(io_err(e))))?;
        wal.set_len(valid_len)
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        let mut wal = wal;
        wal.seek(SeekFrom::End(0))
            .map_err(|e| StorageError::from(StorageIOError::write_logs(io_err(e))))?;
        // A entrada de diretório do WAL recém-criado tem de ser durável também.
        fsync_dir(&dir);

        let meta = Self::load_meta(&dir.join("meta.bin"))?;

        let mut inner = Inner {
            dir,
            wal,
            entries,
            last_purged,
            meta,
        };
        // R23: se o replay consumiu Truncate/Purge, o ficheiro tem lixo morto —
        // compacta já, para que reaberturas sucessivas não acumulem para sempre.
        if saw_compaction {
            inner.rewrite_wal()?;
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Replaya o WAL registo a registo. Devolve (entradas, last_purged, offset
    /// do último registo COMPLETO, viu-compactações) — o offset serve para
    /// truncar a cauda torn; a flag dispara o rewrite compactado (R23).
    #[allow(clippy::type_complexity)]
    fn replay(
        wal_path: &Path,
    ) -> Result<
        (BTreeMap<u64, Entry<TypeConfig>>, Option<LogId<NodeId>>, u64, bool),
        StorageError<NodeId>,
    > {
        let mut entries: BTreeMap<u64, Entry<TypeConfig>> = BTreeMap::new();
        let mut last_purged: Option<LogId<NodeId>> = None;
        let mut valid_len: u64 = 0;
        let mut saw_compaction = false;

        let file = match File::open(wal_path) {
            Ok(f) => f,
            Err(_) => return Ok((entries, last_purged, 0, false)), // WAL ainda não existe
        };
        let file_size = file
            .metadata()
            .map_err(|e| StorageError::from(StorageIOError::read_logs(io_err(e))))?
            .len();
        let mut reader = BufReader::new(file);
        let mut pos: u64 = 0;
        loop {
            // Cauda torn vs corrupção a meio: uma cauda torn é um SUFIXO curto
            // (o crash parou a meio do write_all) — o ficheiro acaba DENTRO do
            // registo. Um registo cujos bytes estão TODOS presentes mas não
            // decodificam é bit-rot/corrupção — truncar aí descartava em
            // silêncio TODAS as entradas raft comprometidas a seguir (e
            // marcadores Truncate/Purge). Falha-se alto, como no meta.bin.
            if file_size - pos < 4 {
                break; // EOF limpo, ou prefixo de comprimento torn (< 4 bytes)
            }
            let mut len_buf = [0u8; 4];
            reader
                .read_exact(&mut len_buf)
                .map_err(|e| StorageError::from(StorageIOError::read_logs(io_err(e))))?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if (len as u64) > file_size - pos - 4 {
                break; // registo declarado além do EOF — cauda torn genuína
            }
            // Alocação LIMITADA pelos bytes que restam no ficheiro (nunca pelo
            // prefixo cru — um prefixo corrompido não pode pedir 4 GiB).
            let mut payload = vec![0u8; len];
            reader
                .read_exact(&mut payload)
                .map_err(|e| StorageError::from(StorageIOError::read_logs(io_err(e))))?;
            let rec: LogRecord = match bincode::serde::decode_from_slice(&payload, BINCODE_CFG) {
                Ok((r, _)) => r,
                Err(e) => {
                    // Payload completo que não decodifica = corrupção a meio do
                    // WAL. Recusar arrancar (o operador limpa o dir e o nó
                    // re-replica dos pares) em vez de perder entradas em silêncio.
                    return Err(StorageError::from(StorageIOError::read_logs(io_err(
                        format!(
                            "registo corrupto no WAL raft (offset {pos}, {len} bytes): {e}; \
                             recuso truncar — apagar o diretório raft e re-replicar"
                        ),
                    ))));
                }
            };
            match rec {
                LogRecord::Insert(e) => {
                    // Um Insert que SUBSTITUI um índice existente também é lixo
                    // morto no ficheiro (entrada antiga sobrescrita).
                    if entries.insert(e.log_id.index, e).is_some() {
                        saw_compaction = true;
                    }
                }
                LogRecord::Truncate(idx) => {
                    let before = entries.len();
                    entries.split_off(&idx);
                    // Só conta como lixo se descartou algo — um WAL já compactado
                    // (que abre com um marcador Purge) não dispara rewrite eterno.
                    if entries.len() != before {
                        saw_compaction = true;
                    }
                }
                LogRecord::Purge(log_id) => {
                    let before = entries.len();
                    entries = entries.split_off(&(log_id.index + 1));
                    if entries.len() != before {
                        saw_compaction = true;
                    }
                    last_purged = Some(log_id);
                }
            }
            pos += 4 + len as u64;
            valid_len = pos;
        }
        Ok((entries, last_purged, valid_len, saw_compaction))
    }

    /// Escreve entradas de forma durável (WAL + fsync) e atualiza o espelho em
    /// memória, SEM o callback de flush do openraft. É o núcleo partilhado pelo
    /// trait `append` (que dispara o callback a seguir) e pelos testes.
    pub fn append_sync<I>(&self, entries: I) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>>,
    {
        let mut inner = self.inner.lock().unwrap();
        for e in entries {
            inner.append_record(&LogRecord::Insert(e.clone()))?;
            inner.entries.insert(e.log_id.index, e);
        }
        Ok(())
    }

    fn load_meta(path: &Path) -> Result<Meta, StorageError<NodeId>> {
        match File::open(path) {
            Ok(mut f) => {
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes)
                    .map_err(|e| StorageError::from(StorageIOError::read_vote(io_err(e))))?;
                // `meta.bin` é escrito atomicamente (tmp+rename) — nunca fica
                // meio-escrito. Um decode que falhe = corrupção real (bit-rot) ou
                // mudança de formato: FALHAR ALTO. Descartar em silêncio um voto
                // persistido permitiria votar de novo no mesmo termo (split-brain).
                bincode::serde::decode_from_slice(&bytes, BINCODE_CFG)
                    .map(|(m, _)| m)
                    .map_err(|e| {
                        StorageError::from(StorageIOError::read_vote(io_err(format!(
                            "meta.bin corrompido (recusa arrancar em vez de perder o voto): {e}"
                        ))))
                    })
            }
            Err(_) => Ok(Meta::default()), // primeiro arranque: ainda não há meta
        }
    }
}

impl RaftLogReader<TypeConfig> for FileRaftLog {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftLogStorage<TypeConfig> for FileRaftLog {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let inner = self.inner.lock().unwrap();
        Ok(LogState {
            last_purged_log_id: inner.last_purged,
            last_log_id: inner.last_log_id(),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().unwrap();
        inner.meta.vote = Some(*vote);
        inner.write_meta()
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().unwrap().meta.vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().unwrap();
        inner.meta.committed = committed;
        inner.write_meta()
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().unwrap().meta.committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        self.append_sync(entries)?; // fsync por registo lá dentro
        // O fsync já aconteceu ⇒ o ack de quórum é respaldado por durabilidade.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().unwrap();
        inner.append_record(&LogRecord::Truncate(log_id.index))?;
        inner.entries.split_off(&log_id.index);
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().unwrap();
        inner.append_record(&LogRecord::Purge(log_id))?;
        inner.entries = inner.entries.split_off(&(log_id.index + 1));
        inner.last_purged = Some(log_id);
        // R23: o purge (pós-snapshot) deixa poucas entradas vivas — o momento
        // certo para compactar o ficheiro em vez de o deixar crescer para sempre.
        inner.rewrite_wal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::episode_bytes;
    use heraclitus_core::{Episode, EventKind};
    use openraft::{CommittedLeaderId, EntryPayload};

    fn entry(index: u64, term: u64, body: &str) -> Entry<TypeConfig> {
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(term, 0), index),
            payload: EntryPayload::Normal(episode_bytes(&Episode::new(
                "n",
                EventKind::Observation,
                body.as_bytes().to_vec(),
            ))),
        }
    }

    async fn append(log: &mut FileRaftLog, entries: Vec<Entry<TypeConfig>>) {
        // Vai pelo mesmo caminho durável do trait `append`, sem precisar do
        // `LogFlushed` (que é `pub(crate)` no openraft).
        log.append_sync(entries).unwrap();
    }

    #[tokio::test]
    async fn corrupt_meta_refuses_to_start_instead_of_losing_the_vote() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = FileRaftLog::open(dir.path()).unwrap();
            log.save_vote(&Vote::new(3, 1)).await.unwrap();
        }
        // Corrupção real (bit-rot / mudança de formato) no meta.bin.
        std::fs::write(dir.path().join("meta.bin"), b"lixo nao-decodificavel").unwrap();
        // NÃO reinicia em silêncio a perder o voto (o que permitiria votar de
        // novo no mesmo termo → split-brain): falha alto.
        assert!(
            FileRaftLog::open(dir.path()).is_err(),
            "meta corrompido tem de recusar arrancar, não repor o voto a None"
        );
    }

    #[tokio::test]
    async fn entries_and_vote_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = FileRaftLog::open(dir.path()).unwrap();
            append(
                &mut log,
                vec![entry(1, 1, "a"), entry(2, 1, "b"), entry(3, 1, "c")],
            )
            .await;
            // O VOTO é a garantia anti-split-brain: tem de sobreviver ao restart.
            let vote = Vote::new(7, 2);
            log.save_vote(&vote).await.unwrap();
            log.save_committed(Some(LogId::new(CommittedLeaderId::new(1, 0), 2)))
                .await
                .unwrap();
        }
        // Reabre a partir do disco — nada em memória sobrevive.
        let mut log = FileRaftLog::open(dir.path()).unwrap();
        let st = log.get_log_state().await.unwrap();
        assert_eq!(st.last_log_id.unwrap().index, 3, "entradas recuperadas do WAL");
        assert_eq!(log.read_vote().await.unwrap(), Some(Vote::new(7, 2)), "voto durável");
        assert_eq!(log.read_committed().await.unwrap().unwrap().index, 2);
        let got = log.try_get_log_entries(1..4).await.unwrap();
        assert_eq!(got.len(), 3);
    }

    #[tokio::test]
    async fn truncate_and_purge_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = FileRaftLog::open(dir.path()).unwrap();
            append(
                &mut log,
                (1..=6).map(|i| entry(i, 1, "x")).collect(),
            )
            .await;
            // Trunca de 5 para cima (conflito de líder) e purga até 2 (snapshot).
            log.truncate(LogId::new(CommittedLeaderId::new(1, 0), 5))
                .await
                .unwrap();
            log.purge(LogId::new(CommittedLeaderId::new(1, 0), 2))
                .await
                .unwrap();
        }
        let mut log = FileRaftLog::open(dir.path()).unwrap();
        let st = log.get_log_state().await.unwrap();
        // Sobrevivem 3 e 4 (5,6 truncados; 1,2 purgados); last_purged = 2.
        assert_eq!(st.last_purged_log_id.unwrap().index, 2, "purge durável");
        assert_eq!(st.last_log_id.unwrap().index, 4, "truncate durável");
        let got = log.try_get_log_entries(0..100).await.unwrap();
        let idxs: Vec<u64> = got.iter().map(|e| e.log_id.index).collect();
        assert_eq!(idxs, vec![3, 4]);
    }

    #[tokio::test]
    async fn torn_tail_is_discarded_on_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = FileRaftLog::open(dir.path()).unwrap();
            append(&mut log, vec![entry(1, 1, "a"), entry(2, 1, "b")]).await;
        }
        // Simula um crash a meio da escrita do 3.º registo: acrescenta um prefixo
        // de comprimento a dizer 999 bytes mas só 3 bytes de payload.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join("entries.wal"))
                .unwrap();
            f.write_all(&(999u32).to_le_bytes()).unwrap();
            f.write_all(&[1, 2, 3]).unwrap();
            f.sync_all().unwrap();
        }
        // O open descarta a cauda torn e recupera exatamente os 2 registos bons.
        let mut log = FileRaftLog::open(dir.path()).unwrap();
        assert_eq!(log.get_log_state().await.unwrap().last_log_id.unwrap().index, 2);
        // E o WAL foi truncado, por isso um novo append continua limpo.
        append(&mut log, vec![entry(3, 1, "c")]).await;
        let mut log2 = FileRaftLog::open(dir.path()).unwrap();
        assert_eq!(log2.get_log_state().await.unwrap().last_log_id.unwrap().index, 3);
    }

    #[tokio::test]
    async fn midfile_corruption_fails_loud_instead_of_truncating() {
        // Durabilidade raft: bit-rot num registo A MEIO do WAL não pode ser
        // tratado como cauda torn — truncar aí descartava em silêncio todas as
        // entradas COMPROMETIDAS a seguir. O open tem de recusar arrancar
        // (como já faz com meta.bin corrupto), preservando o ficheiro intacto.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = FileRaftLog::open(dir.path()).unwrap();
            append(
                &mut log,
                vec![entry(1, 1, "a"), entry(2, 1, "b"), entry(3, 1, "c")],
            )
            .await;
        }
        let wal_path = dir.path().join("entries.wal");
        let before = std::fs::metadata(&wal_path).unwrap().len();
        // Corrompe o discriminante do enum do 1.º registo (primeiro byte do
        // payload, offset 4): o payload continua COMPLETO (len intacto) mas o
        // decode falha garantidamente (variante inválida) — e os registos 2 e 3,
        // comprometidos, ficam depois do ponto corrupto.
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&wal_path).unwrap();
            f.seek(SeekFrom::Start(4)).unwrap();
            f.write_all(&[0xFF]).unwrap();
            f.sync_all().unwrap();
        }
        // Recusa alto — nada de truncar entradas comprometidas em silêncio.
        assert!(
            FileRaftLog::open(dir.path()).is_err(),
            "open devia falhar com corrupção a meio do WAL"
        );
        // E o ficheiro NÃO foi truncado (os dados ficam para forense/recuperação).
        assert_eq!(std::fs::metadata(&wal_path).unwrap().len(), before);
    }
}
