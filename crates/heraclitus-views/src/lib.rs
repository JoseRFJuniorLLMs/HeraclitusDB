//! heraclitus-views — the replay engine (§3.5).
//!
//! Every index in HeraclitusDB is a [`View`]: derived, asynchronous and
//! rebuildable from LSN 0 by deterministic replay. View application must be
//! deterministic — no wall-clock reads, no unseeded RNG.
//!
//! v0 persistence note (RFC-002): watermarks and checkpoints are stored as
//! plain files under `<data_dir>/views/`. RocksDB-backed checkpoints are a
//! planned optimization; correctness never depends on them, because the
//! recovery story is *always* "rebuild from LSN 0".

use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn};
use heraclitus_log::EpisodeLog;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Helpers partilhados de checkpoint (§fast boot): cada view persiste um
/// snapshot bincode do estado derivado em `<views>/<nome>.ckpt` com escrita
/// atómica (tmp + fsync + rename). A correção NUNCA depende disto — sem
/// checkpoint a view reconstrói-se do LSN 0; com ele, o boot replaya só a
/// cauda `(watermark, head]` em vez do log inteiro (a lição operacional da
/// carga massiva de 2026-07-02: replay total não escala).
///
/// # Formato (v1, conferência de 2026-10-02)
///
/// `MAGIC (4) | versão u16 LE | CRC-32 u32 LE | comprimento do corpo u64 LE |
/// corpo bincode`.
///
/// Até aqui o ficheiro era bincode cru: sem magic, sem versão, sem CRC, e lido
/// com `fs::read` inteiro antes de descodificar. Duas consequências:
/// - um bit trocado dentro de uma posting continuava a descodificar e a view
///   servia resultados errados com aspecto válido (o índice de atributos já
///   tinha CRC desde a R89; as outras views não);
/// - o ficheiro inteiro e o estado descodificado coexistiam em RAM no
///   arranque — o pico duplicava (o `text.ckpt` chegou a 4,4 GB).
///
/// Agora o CRC é verificado numa passagem em streaming ANTES de descodificar
/// (um corpo corrompido podia trazer um comprimento de `Vec` absurdo e abortar
/// o processo na alocação), e a descodificação também é em streaming. Ficheiros
/// do formato antigo (sem magic) continuam a ler-se, em streaming, e são
/// regravados no formato novo no checkpoint seguinte.
pub mod ckpt {
    use super::HeraclitusError;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::Path;

    const MAGIC: &[u8; 4] = b"HRKV";
    const VERSAO: u16 = 1;
    const CABECALHO: usize = 4 + 2 + 4 + 8;

    struct Contador<W> {
        inner: W,
        crc: crc32fast::Hasher,
        bytes: u64,
    }

    impl<W: Write> Write for Contador<W> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.crc.update(&buf[..n]);
            self.bytes += n as u64;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    pub fn save<T: serde::Serialize>(
        dir: &Path,
        name: &str,
        value: &T,
    ) -> Result<(), HeraclitusError> {
        let tmp = dir.join(format!("{name}.ckpt.tmp"));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&[0u8; CABECALHO])?;
            let mut w = Contador {
                inner: std::io::BufWriter::with_capacity(64 << 10, f),
                crc: crc32fast::Hasher::new(),
                bytes: 0,
            };
            bincode::serde::encode_into_std_write(value, &mut w, bincode::config::standard())
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
            w.flush()?;
            let (crc, bytes) = (w.crc.finalize(), w.bytes);
            let mut f = w
                .inner
                .into_inner()
                .map_err(|e| HeraclitusError::from(e.into_error()))?;
            let mut cabeca = [0u8; CABECALHO];
            cabeca[..4].copy_from_slice(MAGIC);
            cabeca[4..6].copy_from_slice(&VERSAO.to_le_bytes());
            cabeca[6..10].copy_from_slice(&crc.to_le_bytes());
            cabeca[10..18].copy_from_slice(&bytes.to_le_bytes());
            f.seek(SeekFrom::Start(0))?;
            f.write_all(&cabeca)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(format!("{name}.ckpt")))?;
        // O rename só é durável depois do fsync do directório (POSIX). No
        // Windows não há fsync de directório: o NTFS regista o rename no seu
        // próprio journal de metadados.
        #[cfg(unix)]
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// `Ok(None)` = sem checkpoint OU checkpoint ilegível (formato
    /// desconhecido / corrompido / CRC errado) — a view nasce vazia e o
    /// registry força replay desde 0. Um snapshot ilegível NUNCA pode impedir o
    /// boot: o estado é derivado e o log é a verdade; degradar para rebuild é
    /// correto por construção. Um ficheiro que EXISTE e é recusado deixa um
    /// aviso — trocar um arranque de cauda por um rebuild integral não pode
    /// ser silencioso.
    pub fn load<T: serde::de::DeserializeOwned>(
        dir: &Path,
        name: &str,
    ) -> Result<Option<T>, HeraclitusError> {
        let path = dir.join(format!("{name}.ckpt"));
        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                tracing::warn!(path = %path.display(), erro = %e,
                    "checkpoint existe mas não se abriu; a view será reconstruída desde o LSN 0");
                return Ok(None);
            }
        };
        match ler(&mut f) {
            Ok(v) => Ok(Some(v)),
            Err(motivo) => {
                tracing::warn!(path = %path.display(), motivo = %motivo,
                    "checkpoint RECUSADO; a view será reconstruída desde o LSN 0 \
                     (arranque mais lento, sem perda de dados)");
                Ok(None)
            }
        }
    }

    fn ler<T: serde::de::DeserializeOwned>(f: &mut std::fs::File) -> Result<T, String> {
        let tamanho = f.metadata().map_err(|e| e.to_string())?.len();
        let mut cabeca = [0u8; CABECALHO];
        let tem_cabeca = tamanho >= CABECALHO as u64
            && f.read_exact(&mut cabeca).is_ok()
            && &cabeca[..4] == MAGIC;
        if !tem_cabeca {
            // Formato antigo: bincode cru desde o byte 0.
            f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut r = std::io::BufReader::with_capacity(1 << 20, &mut *f);
            return bincode::serde::decode_from_std_read(&mut r, bincode::config::standard())
                .map_err(|e| format!("formato antigo ilegível: {e}"));
        }
        let versao = u16::from_le_bytes([cabeca[4], cabeca[5]]);
        if versao != VERSAO {
            return Err(format!("versão {versao} desconhecida"));
        }
        let crc = u32::from_le_bytes([cabeca[6], cabeca[7], cabeca[8], cabeca[9]]);
        let mut comprimento = [0u8; 8];
        comprimento.copy_from_slice(&cabeca[10..18]);
        let corpo = u64::from_le_bytes(comprimento);
        // `checked_add`: o comprimento vem do cabeçalho, que o CRC não cobre;
        // com `overflow-checks` uma soma que transborda entrava em pânico no
        // arranque (revisão de 2026-10-03), e um checkpoint ilegível nunca pode
        // impedir o boot.
        if (CABECALHO as u64).checked_add(corpo) != Some(tamanho) {
            return Err(format!(
                "comprimento {tamanho} não bate com o cabeçalho ({CABECALHO} + {corpo})"
            ));
        }
        // 1.ª passagem: CRC em streaming, antes de qualquer descodificação.
        let mut hasher = crc32fast::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut r = (&mut *f).take(corpo);
        loop {
            let n = r.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        drop(buf);
        if hasher.finalize() != crc {
            return Err("CRC do corpo não confere".into());
        }
        // 2.ª passagem: descodifica em streaming e exige consumir o corpo todo.
        f.seek(SeekFrom::Start(CABECALHO as u64))
            .map_err(|e| e.to_string())?;
        let mut r = std::io::BufReader::with_capacity(1 << 20, (&mut *f).take(corpo));
        let valor = bincode::serde::decode_from_std_read(&mut r, bincode::config::standard())
            .map_err(|e| format!("corpo não descodifica: {e}"))?;
        let mut resto = [0u8; 1];
        if r.read(&mut resto).map_err(|e| e.to_string())? != 0 {
            return Err("bytes a mais depois do corpo".into());
        }
        Ok(valor)
    }
}

/// A materialized view over the log.
fn is_agent_evidence(event: &Episode) -> bool {
    matches!(&event.kind, EventKind::Custom(kind) if kind == "AgentEvidence")
}

/// AgentEvidence is canonical security-plane data. It remains in HRKL and is
/// projected by the dedicated Agent APIs; generic views intentionally ignore
/// it so a denied-action flood cannot become graph/text/activation RAM growth.
pub trait View: Send + Sync {
    fn name(&self) -> &str;
    /// Apply one event. MUST be deterministic in (lsn, event).
    fn apply(&mut self, lsn: Lsn, event: &Episode);
    /// Highest LSN applied.
    fn watermark(&self) -> Lsn;
    /// Persist derived state (optional; views may be RAM-only).
    fn checkpoint(&self, _dir: &Path) -> Result<(), HeraclitusError> {
        Ok(())
    }
    /// Restaura o estado derivado persistido por [`checkpoint`](View::checkpoint).
    /// Devolve `true` se restaurou (o watermark persistido passa a ser válido) ou
    /// `false` (default) se a view nasce vazia — nesse caso o registry FORÇA o
    /// replay desde 0 para não perder `(0, watermark]`. Sem este par
    /// checkpoint+restore, confiar no watermark persistido esvazia a view no restart.
    fn restore(&mut self, _dir: &Path) -> Result<bool, HeraclitusError> {
        Ok(false)
    }
    /// Canonical BLAKE3 digest of the view's derived state (Fase 1.3 / M8–M18
    /// acceptance gate). Default `None` = the view opts out. Any view that
    /// implements it MUST be deterministic: the digest is bit-identical after a
    /// wipe + rebuild-from-0, independent of thread count or CPU architecture.
    fn state_hash(&self) -> Option<[u8; 32]> {
        None
    }
    /// Reset internal state ahead of a rebuild from `lsn`.
    fn reset(&mut self);
}

/// Owns the registered views, their watermarks and the replay loop.
pub struct ViewRegistry {
    dir: PathBuf,
    views: Vec<Box<dyn View>>,
    names: Vec<String>,
    watermarks: HashMap<String, Lsn>,
    watermarks_vec: Vec<Lsn>,
    /// As views deste registry NÃO descrevem o log (arranque com o replay
    /// saltado). Enquanto estiver a `true`, `checkpoint()` é um no-op — ver
    /// [`ViewRegistry::mark_unmaterialized`].
    nao_materializado: bool,
    checkpoint_watermarks: Vec<Option<Lsn>>,
    dirty: Vec<bool>,
}

impl ViewRegistry {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self, HeraclitusError> {
        let dir = data_dir.into().join("views");
        std::fs::create_dir_all(&dir)?;
        let wm_path = dir.join("watermarks.json");
        // Um `watermarks.json` ilegível NÃO pode matar o arranque. As
        // watermarks são estado derivado — dizem só até onde as views já foram
        // materializadas — e perdê-las custa um rebuild, que é lento mas
        // correcto. A assimetria era o defeito: o ficheiro ausente dava mapa
        // vazio e arrancava, um checkpoint corrompido degradava para rebuild,
        // mas um JSON malformado propagava o erro e o servidor não abria de
        // todo, exigindo intervenção manual para apagar um ficheiro
        // reconstruível.
        let watermarks = match std::fs::read_to_string(&wm_path) {
            Ok(raw) => match serde_json::from_str(&raw) {
                Ok(mapa) => mapa,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        path = %wm_path.display(),
                        "watermarks.json ilegível; as views vão ser reconstruídas do LSN 0"
                    );
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            dir,
            views: Vec::new(),
            names: Vec::new(),
            watermarks,
            watermarks_vec: Vec::new(),
            nao_materializado: false,
            checkpoint_watermarks: Vec::new(),
            dirty: Vec::new(),
        })
    }

    pub fn register(&mut self, view: Box<dyn View>) {
        let name = view.name().to_string();
        let wm = self.watermarks.get(&name).copied().unwrap_or(0);
        self.names.push(name);
        self.watermarks_vec.push(wm);
        self.views.push(view);
        self.checkpoint_watermarks.push(None);
        self.dirty.push(true);
    }

    pub fn view_names(&self) -> Vec<String> {
        self.names.clone()
    }

    /// Sincroniza o vetor de watermarks rápido com o HashMap interno para persistência.
    fn sync_watermarks_map(&mut self) {
        for (i, name) in self.names.iter().enumerate() {
            self.watermarks.insert(name.clone(), self.watermarks_vec[i]);
        }
    }

    /// Apply one live tail event to every view sem alocações no hot path.
    pub fn apply(&mut self, lsn: Lsn, event: &Episode) {
        if heraclitus_log::vm_bridge::is_hvm(event) || is_agent_evidence(event) {
            return;
        }
        for (i, v) in self.views.iter_mut().enumerate() {
            v.apply(lsn, event);
            self.dirty[i] = true;
            if lsn > self.watermarks_vec[i] {
                self.watermarks_vec[i] = lsn;
            }
        }
    }

    /// Watermarks por view (introspecção: `heraclitus_state()`).
    pub fn watermarks(&mut self) -> &HashMap<String, Lsn> {
        self.sync_watermarks_map();
        &self.watermarks
    }

    pub fn reset_watermarks(&mut self) {
        self.watermarks.clear();
        for wm in self.watermarks_vec.iter_mut() {
            *wm = 0;
        }
    }

    /// Declara que as views deste registry NÃO descrevem o log — arrancaram
    /// vazias com o replay saltado (`HERACLITUS_SKIP_VIEW_REPLAY` /
    /// `HERACLITUS_LOG_ONLY`) — e por isso nenhum snapshot delas pode ir para
    /// disco até serem materializadas a partir do log.
    ///
    /// Auditoria 2026-09-05 (A50): zerar as watermarks (`reset_watermarks`) não
    /// chegava. Nesse modo o banco continua a ACEITAR escritas, e cada append
    /// vivo chega às views por `apply`, onde toda a view faz
    /// `self.watermark = self.watermark.max(lsn)`. O watermark INTERNO — que é
    /// a AUTORIDADE em [`catch_up`](ViewRegistry::catch_up), ver o comentário
    /// lá — salta assim para o LSN corrente por cima de uma view sem histórico,
    /// fora do alcance de `reset_watermarks`, que só zera a cópia do registry.
    /// O checkpoint seguinte (o periódico ou o de shutdown) persistia o par
    /// mentiroso ⟨conteúdo de um punhado de eventos, watermark alto⟩ e o
    /// arranque normal seguinte replayava só a cauda: tudo o que estava abaixo
    /// desse watermark ficava invisível às views PARA SEMPRE, sem um único
    /// erro, e o estado errado era re-persistido em cada checkpoint.
    ///
    /// Um checkpoint que não descreve o log é PIOR do que checkpoint nenhum:
    /// sem ele o arranque seguinte é lento (replay do log inteiro) mas
    /// correcto. Daí o no-op em vez de uma escrita "melhor que nada".
    ///
    /// Também zera o estado das views (`View::reset`) e as watermarks, para que
    /// a autoridade — o watermark interno — parta mesmo de 0 e não dependa de
    /// ninguém se lembrar de chamar os dois métodos.
    ///
    /// A marca vive AQUI, e não numa bandeira do `Engine`, de propósito: é o
    /// registry o dono dos snapshots, e há quem chame
    /// [`checkpoint`](ViewRegistry::checkpoint) sem passar pelo
    /// `Engine::checkpoint_views` — o `Engine::shred`. Baixa-se em
    /// [`catch_up`](ViewRegistry::catch_up) e num
    /// [`rebuild`](ViewRegistry::rebuild) integral, que são exactamente os dois
    /// caminhos que voltam a pôr as views a descrever o log. O índice de
    /// atributos tem o buraco IRMÃO e uma marca SEPARADA no `Engine`
    /// (`attr_nao_materializado`, auditoria A47): `view rebuild` materializa as
    /// views sem lhe tocar, logo baixar uma não pode baixar a outra.
    pub fn mark_unmaterialized(&mut self) {
        for v in self.views.iter_mut() {
            v.reset();
            self.checkpoint_watermarks.fill(None);
        }
        self.reset_watermarks();
        self.nao_materializado = true;
    }

    /// `true` enquanto as views não tiverem sido materializadas a partir do log
    /// (ver [`mark_unmaterialized`](ViewRegistry::mark_unmaterialized)).
    ///
    /// É a face de LEITURA do invariante, para quem precise de saber se um
    /// checkpoint vai ser gravado antes de o pedir — a inibição em si não
    /// depende de ninguém a consultar: quem recusa é o
    /// [`checkpoint`](ViewRegistry::checkpoint). O índice de atributos, que tem
    /// o buraco irmão, é governado pela marca dele no `Engine`
    /// (`attr_nao_materializado`, auditoria A47) e não por esta.
    pub fn unmaterialized(&self) -> bool {
        self.nao_materializado
    }

    /// Minimum watermark across views (safe prune point for the memtable).
    pub fn min_watermark(&self) -> Lsn {
        self.watermarks_vec.iter().copied().min().unwrap_or(0)
    }

    /// On startup: replay `(watermark, head]` for each view com vetores diretos.
    pub fn catch_up<L: EpisodeLog + ?Sized>(&mut self, log: &L) -> Result<u64, HeraclitusError> {
        self.catch_up_com(log, None)
    }

    /// Como [`catch_up`](Self::catch_up), entregando também cada evento a um
    /// índice EXTRA que não está registado (o índice de atributos do
    /// servidor), a partir do LSN `desde` dele, na MESMA passagem pelo log.
    ///
    /// Auditoria boot.md P1-C (conferida em 2026-10-02): o arranque varria e
    /// decifrava o log duas vezes — uma para as views, outra só para o índice
    /// de atributos. O extra recebe exactamente o que o seu laço antigo
    /// recebia: todos os eventos com LSN >= `desde` excepto frames H-VM
    /// (o `AgentEvidence` é tratado pelo próprio `apply` dele).
    pub fn catch_up_com<L: EpisodeLog + ?Sized>(
        &mut self,
        log: &L,
        mut extra: Option<(&mut dyn View, Lsn)>,
    ) -> Result<u64, HeraclitusError> {
        let dir = self.dir.clone();
        for (i, v) in self.views.iter_mut().enumerate() {
            if !v.restore(&dir)? {
                self.watermarks_vec[i] = 0;
                self.watermarks.remove(&self.names[i]);
                continue;
            }
            // A AUTORIDADE É O SNAPSHOT, não o `watermarks.json`.
            //
            // O par (snapshot, watermarks.json) é escrito em dois passos: o
            // `checkpoint` grava primeiro o snapshot de cada view e só depois o
            // JSON. Não há atomicidade entre eles, e o JSON era quem mandava —
            // o lado errado, porque descreve o snapshot em vez de fazer parte
            // dele. As duas formas de divergir têm consequências opostas e
            // ambas más:
            //
            //   JSON atrasado (crash entre os dois passos) → reaplicavam-se
            //     eventos que o snapshot já absorveu. Uma view idempotente
            //     aguenta; uma que CONTE soma duas vezes, em silêncio.
            //   JSON adiantado (restauro parcial, cópia de um dir mais novo)
            //     → saltavam-se eventos que o snapshot não tem. Perda de dados
            //     derivados, também em silêncio.
            //
            // `View::watermark()` é, por contrato, "o LSN mais alto aplicado" —
            // vem do próprio estado restaurado, portanto não pode discordar
            // dele. Usá-lo elimina o modo de falha em vez de escolher o menos
            // mau: não há par a coordenar.
            //
            // O JSON fica como cache e introspecção (é o que `min_watermark` e
            // as ferramentas lêem), e é reescrito a partir da verdade logo
            // abaixo.
            let do_snapshot = v.watermark();
            // Auditoria recursiva, iteração 3: snapshots legados usam zero
            // tanto para uma view vazia como para uma que já aplicou LSN 0.
            // Reiniciar antes do replay evita que views não idempotentes
            // acumulem esse evento em cada arranque.
            if do_snapshot == 0 {
                v.reset();
                self.watermarks_vec[i] = 0;
                self.watermarks.remove(&self.names[i]);
                self.checkpoint_watermarks[i] = None;
                self.dirty[i] = true;
                continue;
            }
            let do_json = self.watermarks.get(&self.names[i]).copied().unwrap_or(0);
            if do_json != do_snapshot {
                tracing::warn!(
                    view = %self.names[i],
                    snapshot = do_snapshot,
                    json = do_json,
                    "watermarks.json diverge do snapshot restaurado; vale o snapshot"
                );
            }
            self.watermarks_vec[i] = do_snapshot;
            self.checkpoint_watermarks[i] = Some(do_snapshot);
            self.dirty[i] = false;
        }

        let from = self
            .watermarks_vec
            .iter()
            .copied()
            .map(|w| if w > 0 { w + 1 } else { 0 })
            .min()
            .unwrap_or(0);
        // O extra pode estar mais atrás do que as views (checkpoint dele mais
        // antigo, ou ilegível): a passagem começa no mais atrasado dos dois.
        let from = match &extra {
            Some((_, desde)) if self.views.is_empty() => *desde,
            Some((_, desde)) => from.min(*desde),
            None => from,
        };

        let head = log.head();
        let mut applied = 0u64;
        let mut cur = from;
        // Auditoria boot.md P0/P1 (conferida em 2026-10-02): o replay não
        // dizia nada até acabar. Num log grande são minutos ou horas em que o
        // operador não distingue "a avançar" de "pendurado". Progresso a cada
        // 10 s, com o ritmo e a estimativa do que falta.
        if head > from {
            tracing::info!(desde = from, ate = head, "views: replay da cauda a começar");
        }
        let inicio = std::time::Instant::now();
        let mut ultimo_aviso = inicio;
        while cur <= head {
            if ultimo_aviso.elapsed() >= std::time::Duration::from_secs(10) {
                ultimo_aviso = std::time::Instant::now();
                let feitos = cur.saturating_sub(from);
                let ritmo = feitos as f64 / inicio.elapsed().as_secs_f64().max(1e-9);
                let faltam = head.saturating_sub(cur);
                tracing::info!(
                    lsn = cur,
                    head,
                    eventos_por_s = ritmo as u64,
                    faltam_s = (faltam as f64 / ritmo.max(1.0)) as u64,
                    "views: replay em curso"
                );
            }
            let batch = log.scan_capped(cur, head, 256)?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().unwrap().0;
            for (lsn, ep) in &batch {
                if let Some((indice, desde)) = extra.as_mut() {
                    if *lsn >= *desde && !heraclitus_log::vm_bridge::is_hvm(ep) {
                        indice.apply(*lsn, ep);
                    }
                }
                if heraclitus_log::vm_bridge::is_hvm(ep) || is_agent_evidence(ep) {
                    continue;
                }
                for (i, v) in self.views.iter_mut().enumerate() {
                    let wm = self.watermarks_vec[i];
                    if wm == 0 || *lsn > wm {
                        v.apply(*lsn, ep);
                        self.dirty[i] = true;
                        self.watermarks_vec[i] = *lsn;
                        applied += 1;
                    }
                }
            }
            cur = last + 1;
        }
        // O replay chegou ao fim sem erro: as views voltam a descrever o log e
        // o checkpoint volta a ser seguro (Auditoria 2026-09-05, A50). Se o
        // `?` acima tivesse saltado para fora, a marca ficava de pé — que é o
        // lado conservador certo.
        self.nao_materializado = false;
        self.sync_watermarks_map();
        self.persist_watermarks()?;
        Ok(applied)
    }

    /// `heraclitus-cli view rebuild --view X` — must always work from LSN 0.
    ///
    /// Auditoria 2026-09-05 (A50): um rebuild INTEGRAL (`view_name == None`)
    /// BAIXA a marca de [`mark_unmaterialized`](ViewRegistry::mark_unmaterialized) —
    /// reconstruiu todas as views do LSN 0, portanto elas voltaram a descrever
    /// o log e não há razão para continuar a proibir o checkpoint. Um rebuild
    /// de UMA view só não a baixa: as outras continuam como estavam.
    ///
    /// A primeira versão desta correcção decidiu o contrário — "o rebuild nunca
    /// baixa a marca" — com o argumento de que quem grava o checkpoint (o
    /// `Engine`) grava no MESMO passo o índice de atributos, que este método
    /// não toca. Esse argumento não se sustenta e a decisão fazia um estrago
    /// concreto:
    /// - o índice de atributos tem a sua PRÓPRIA marca no `Engine`
    ///   (`attr_nao_materializado`, auditoria A47) e a sua própria guarda em
    ///   `checkpoint_attr`; não precisa de ser protegido pela marca das views;
    /// - o único chamador vivo de rebuild-integral-seguido-de-checkpoint é o
    ///   `Engine::shred` (crypto-shred, §3.10), e aí o índice de atributos é
    ///   reconstruído do LSN 0 e gravado pelo próprio `shred`. Não havia
    ///   nenhum buraco do attr para proteger — só o do shred a ser criado: com
    ///   a marca de pé, o `views.checkpoint()` do shred virava um no-op
    ///   silencioso, os snapshots PRÉ-shred (com o plaintext derivado da
    ///   titular) ficavam em disco, o marcador `privacy-rebuild-required` era
    ///   apagado a seguir e o arranque seguinte RESSUSCITAVA o plaintext
    ///   depois de a chave ter sido destruída.
    ///
    /// Baixar a marca aqui é também o que restaura a recuperação documentada do
    /// modo `HERACLITUS_SKIP_VIEW_REPLAY` ("as views ficam vazias até um
    /// `view rebuild`"): sem isto, o fast-boot só voltava depois de um reinício
    /// sem a variável.
    pub fn rebuild<L: EpisodeLog + ?Sized>(
        &mut self,
        log: &L,
        view_name: Option<&str>,
    ) -> Result<(), HeraclitusError> {
        for (i, v) in self.views.iter_mut().enumerate() {
            if view_name
                .map(|n| n == self.names[i].as_str())
                .unwrap_or(true)
            {
                v.reset();
                self.checkpoint_watermarks.fill(None);
                self.watermarks_vec[i] = 0;
                self.watermarks.remove(&self.names[i]);
            }
        }
        let head = log.head();
        let mut cur = 0u64;
        while cur < head {
            let batch = log.scan_capped(cur, head, 256)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (lsn, ep) in &batch {
                if heraclitus_log::vm_bridge::is_hvm(ep) || is_agent_evidence(ep) {
                    continue;
                }
                for (i, v) in self.views.iter_mut().enumerate() {
                    if view_name
                        .map(|n| n == self.names[i].as_str())
                        .unwrap_or(true)
                    {
                        v.apply(*lsn, ep);
                        self.dirty[i] = true;
                        self.watermarks_vec[i] = *lsn;
                    }
                }
            }
            cur = last + 1;
        }
        if view_name.is_none() {
            // Todas as views foram reconstruídas do LSN 0: voltam a descrever o
            // log e o checkpoint volta a ser seguro (auditoria 2026-09-05,
            // A50 — ver o PORQUÊ na doc deste método). Com um nome, só uma foi
            // reconstruída e as outras continuam por materializar.
            self.nao_materializado = false;
        }
        self.sync_watermarks_map();
        self.persist_watermarks()?;
        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<(), HeraclitusError> {
        // Auditoria 2026-09-05 (A50): gravar snapshots de views que não
        // descrevem o log corrompe o estado em disco de forma permanente e
        // silenciosa — ver `mark_unmaterialized`. Saltar é a única opção
        // segura; o arranque seguinte replaya o log inteiro (lento, CORRECTO).
        if self.nao_materializado {
            tracing::warn!(
                "views não materializadas (replay saltado no arranque): checkpoint SALTADO \
                 para não gravar snapshots que não descrevem o log; corre `view rebuild` \
                 ou reinicia sem HERACLITUS_SKIP_VIEW_REPLAY"
            );
            return Ok(());
        }
        for i in 0..self.views.len() {
            self.checkpoint_view(i)?;
        }
        self.finish_checkpoint()
    }

    /// Número de views registadas (para checkpoints view a view).
    pub fn view_count(&self) -> usize {
        self.views.len()
    }

    /// Checkpoint de UMA view, se estiver suja. `Ok(true)` = gravou.
    ///
    /// Auditoria boot.md P0-D (conferida em 2026-10-02): o `Engine` segurava
    /// o lock do registry durante a serialização + fsync de TODAS as views
    /// seguidas, e o `index_applied` de cada append precisa desse lock — a
    /// escrita parava pela soma de todos os checkpoints. Cada snapshot leva o
    /// seu próprio watermark, que é a autoridade no arranque (`catch_up`),
    /// portanto as views não precisam de ser gravadas no MESMO instante: o
    /// chamador pode largar o lock entre views e as escritas avançam entre
    /// elas. No-op silencioso enquanto as views não estiverem materializadas
    /// (o aviso sai em [`finish_checkpoint`](Self::finish_checkpoint)).
    pub fn checkpoint_view(&mut self, i: usize) -> Result<bool, HeraclitusError> {
        if self.nao_materializado {
            return Ok(false);
        }
        let v = &self.views[i];
        if self.dirty[i] || self.checkpoint_watermarks[i] != Some(v.watermark()) {
            v.checkpoint(&self.dir)?;
            self.checkpoint_watermarks[i] = Some(v.watermark());
            self.dirty[i] = false;
            return Ok(true);
        }
        Ok(false)
    }

    /// Fecha uma ronda de checkpoints: grava o `watermarks.json`.
    pub fn finish_checkpoint(&mut self) -> Result<(), HeraclitusError> {
        if self.nao_materializado {
            tracing::warn!(
                "views não materializadas (replay saltado no arranque): checkpoint SALTADO \
                 para não gravar snapshots que não descrevem o log; corre `view rebuild` \
                 ou reinicia sem HERACLITUS_SKIP_VIEW_REPLAY"
            );
            return Ok(());
        }
        self.sync_watermarks_map();
        // Depois de uma ronda de checkpoints o JSON descreve os SNAPSHOTS em
        // disco (o watermark com que cada um foi gravado), não o estado vivo:
        // com checkpoints view a view as escritas avançam entre views, e gravar
        // o watermark vivo faria o JSON divergir do snapshot — e o arranque
        // avisaria de uma divergência que não é problema nenhum.
        let em_disco: HashMap<&str, Lsn> = self
            .names
            .iter()
            .zip(&self.checkpoint_watermarks)
            .filter_map(|(nome, wm)| wm.map(|wm| (nome.as_str(), wm)))
            .collect();
        self.persist_watermarks_map(&em_disco)
    }

    fn persist_watermarks(&self) -> Result<(), HeraclitusError> {
        self.persist_watermarks_map(&self.watermarks)
    }

    fn persist_watermarks_map(&self, mapa: &impl serde::Serialize) -> Result<(), HeraclitusError> {
        let raw = serde_json::to_string_pretty(mapa)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let tmp = self.dir.join("watermarks.json.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(raw.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.dir.join("watermarks.json"))?;
        // O `sync_all` acima torna o CONTEÚDO durável; sem este fsync do
        // directório, o `rename` pode não sobreviver a uma falha de energia e
        // o arranque seguinte lê o watermark ANTIGO — reaplicando eventos que
        // as views já materializaram. Uma view idempotente absorve isso; uma
        // que conte, soma duas vezes.
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(&self.dir) {
            d.sync_all()?;
        }
        Ok(())
    }

    /// Borrow a registered view for querying.
    pub fn get(&self, name: &str) -> Option<&dyn View> {
        self.views
            .iter()
            .find(|v| v.name() == name)
            .map(|v| v.as_ref())
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Box<dyn View>> {
        self.views.iter_mut().find(|v| v.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventKind, FsyncPolicy};

    use std::sync::{Arc, Mutex};

    /// Toy deterministic view: counts events and folds their LSNs into a
    /// state cell shared with the test.
    struct CountView {
        state: Arc<Mutex<(u64, u64)>>, // (count, fold)
        wm: Lsn,
    }

    impl View for CountView {
        fn name(&self) -> &str {
            "count"
        }
        fn apply(&mut self, lsn: Lsn, _e: &Episode) {
            let mut s = self.state.lock().unwrap();
            s.0 += 1;
            s.1 = s.1.wrapping_mul(31).wrapping_add(lsn);
            self.wm = lsn;
        }
        fn watermark(&self) -> Lsn {
            self.wm
        }
        fn reset(&mut self) {
            *self.state.lock().unwrap() = (0, 0);
            self.wm = 0;
        }
    }

    /// View que PERSISTE — é o caso que expõe o par (snapshot, watermarks.json).
    /// Conta aplicações e não é idempotente, de propósito: é assim que se vê
    /// uma reaplicação em vez de a deixar passar despercebida.
    struct SnapshotView {
        state: Arc<Mutex<(u64, u64)>>,
        wm: Lsn,
    }

    impl View for SnapshotView {
        fn name(&self) -> &str {
            "snap"
        }
        fn apply(&mut self, lsn: Lsn, _e: &Episode) {
            let mut s = self.state.lock().unwrap();
            s.0 += 1;
            s.1 = s.1.wrapping_mul(31).wrapping_add(lsn);
            self.wm = lsn;
        }
        fn watermark(&self) -> Lsn {
            self.wm
        }
        fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
            let s = self.state.lock().unwrap();
            std::fs::write(
                dir.join("snap.ckpt"),
                format!("{} {} {}", s.0, s.1, self.wm),
            )?;
            Ok(())
        }
        fn restore(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
            let Ok(raw) = std::fs::read_to_string(dir.join("snap.ckpt")) else {
                return Ok(false);
            };
            let campos: Vec<u64> = raw
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            if campos.len() != 3 {
                return Ok(false);
            }
            *self.state.lock().unwrap() = (campos[0], campos[1]);
            self.wm = campos[2];
            Ok(true)
        }
        fn reset(&mut self) {
            *self.state.lock().unwrap() = (0, 0);
            self.wm = 0;
        }
    }

    #[test]
    fn restored_zero_watermark_does_not_accumulate_on_repeated_boots() {
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
        assert_eq!(
            log.append(Episode::new("a", EventKind::Observation, vec![]))
                .unwrap(),
            0
        );
        for _ in 0..4 {
            let state = Arc::new(Mutex::new((0, 0)));
            let mut registry = ViewRegistry::open(dir.path()).unwrap();
            registry.register(Box::new(SnapshotView {
                state: state.clone(),
                wm: 0,
            }));
            registry.catch_up(&log).unwrap();
            assert_eq!(*state.lock().unwrap(), (1, 0));
            registry.checkpoint().unwrap();
        }
    }

    #[test]
    fn empty_checkpoint_still_receives_first_lsn_zero() {
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
        let mut empty = ViewRegistry::open(dir.path()).unwrap();
        empty.register(Box::new(SnapshotView {
            state: Arc::new(Mutex::new((0, 0))),
            wm: 0,
        }));
        empty.checkpoint().unwrap();
        assert_eq!(
            log.append(Episode::new("a", EventKind::Observation, vec![]))
                .unwrap(),
            0
        );
        let state = Arc::new(Mutex::new((0, 0)));
        let mut restored = ViewRegistry::open(dir.path()).unwrap();
        restored.register(Box::new(SnapshotView {
            state: state.clone(),
            wm: 0,
        }));
        restored.catch_up(&log).unwrap();
        assert_eq!(*state.lock().unwrap(), (1, 0));
    }

    #[test]
    fn unchanged_restored_view_is_not_rewritten_but_live_change_is() {
        struct CountedCheckpoint {
            inner: SnapshotView,
            calls: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl View for CountedCheckpoint {
            fn name(&self) -> &str {
                self.inner.name()
            }
            fn watermark(&self) -> Lsn {
                self.inner.watermark()
            }
            fn apply(&mut self, lsn: Lsn, event: &Episode) {
                self.inner.apply(lsn, event);
            }
            fn reset(&mut self) {
                self.inner.reset();
            }
            fn restore(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
                self.inner.restore(dir)
            }
            fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
                self.calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.inner.checkpoint(dir)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
        for _ in 0..3 {
            log.append(Episode::new("a", EventKind::Observation, vec![]))
                .unwrap();
        }
        let state = Arc::new(Mutex::new((0, 0)));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut first = ViewRegistry::open(dir.path()).unwrap();
        first.register(Box::new(CountedCheckpoint {
            inner: SnapshotView {
                state: state.clone(),
                wm: 0,
            },
            calls: calls.clone(),
        }));
        first.catch_up(&log).unwrap();
        first.checkpoint().unwrap();
        let mut restored = ViewRegistry::open(dir.path()).unwrap();
        restored.register(Box::new(CountedCheckpoint {
            inner: SnapshotView { state, wm: 0 },
            calls: calls.clone(),
        }));
        assert_eq!(restored.catch_up(&log).unwrap(), 0);
        restored.checkpoint().unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        restored.apply(3, &Episode::new("a", EventKind::Observation, vec![]));
        restored.checkpoint().unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// O `watermarks.json` não pode mandar sobre o snapshot restaurado.
    ///
    /// O `checkpoint` grava primeiro o snapshot de cada view e só depois o
    /// JSON; não há atomicidade entre os dois passos. Um crash no meio deixa o
    /// JSON ATRASADO, e enquanto era ele a decidir de onde retomar, os eventos
    /// entre os dois watermarks eram reaplicados — o que numa view que conta é
    /// contar a dobrar, em silêncio.
    #[test]
    fn um_watermarks_json_atrasado_nao_faz_a_view_contar_a_dobrar() {
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
        for i in 0..10u8 {
            log.append(Episode::new("a", EventKind::Observation, vec![i]))
                .unwrap();
        }

        let estado = Arc::new(Mutex::new((0u64, 0u64)));
        {
            let mut reg = ViewRegistry::open(dir.path()).unwrap();
            reg.register(Box::new(SnapshotView {
                state: estado.clone(),
                wm: 0,
            }));
            reg.catch_up(&log).unwrap();
            reg.checkpoint().unwrap();
        }
        let aplicados = estado.lock().unwrap().0;
        assert_eq!(aplicados, 10, "as dez linhas tinham de ter sido aplicadas");

        // O crash entre os dois passos: o snapshot tem os 10, o JSON ficou nos 4.
        let wm_path = dir.path().join("views").join("watermarks.json");
        std::fs::write(&wm_path, r#"{"snap":4}"#).unwrap();

        let estado2 = Arc::new(Mutex::new((0u64, 0u64)));
        let mut reg = ViewRegistry::open(dir.path()).unwrap();
        reg.register(Box::new(SnapshotView {
            state: estado2.clone(),
            wm: 0,
        }));
        reg.catch_up(&log).unwrap();

        // Com o JSON a mandar, os LSN 5..9 eram reaplicados por cima do
        // snapshot que já os tinha: 15 em vez de 10.
        assert_eq!(
            estado2.lock().unwrap().0,
            10,
            "o watermarks.json atrasado fez reaplicar eventos que o snapshot ja tinha"
        );
        assert_eq!(
            estado.lock().unwrap().1,
            estado2.lock().unwrap().1,
            "o estado restaurado tem de ser identico ao original"
        );
    }

    #[test]
    fn wipe_and_replay_is_deterministic() {
        // M2 acceptance gate: rebuild from LSN 0 yields bit-identical state.
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
        for i in 0..50 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }

        let state = Arc::new(Mutex::new((0u64, 0u64)));
        let mut reg = ViewRegistry::open(dir.path()).unwrap();
        reg.register(Box::new(CountView {
            state: state.clone(),
            wm: 0,
        }));
        reg.catch_up(&log).unwrap();
        let first = *state.lock().unwrap();

        reg.rebuild(&log, Some("count")).unwrap();
        let second = *state.lock().unwrap();

        assert_eq!(first.0, 50);
        assert_eq!(first, second, "replay must be deterministic");
    }

    #[test]
    fn empty_view_replays_from_zero_despite_persisted_watermark() {
        // Regressão: watermarks.json persiste watermarks avançados, mas se a view
        // nasce vazia (restore()==false) e catch_up confiasse no watermark, ela
        // ficaria sem `(0, watermark]` no restart. O fix força replay desde 0.
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
        for i in 0..50 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }

        // 1ª sessão: aplica tudo e persiste watermarks.json (= head).
        {
            let state = Arc::new(Mutex::new((0u64, 0u64)));
            let mut reg = ViewRegistry::open(dir.path()).unwrap();
            reg.register(Box::new(CountView {
                state: state.clone(),
                wm: 0,
            }));
            reg.catch_up(&log).unwrap();
            assert_eq!(state.lock().unwrap().0, 50);
        }

        // Restart: NOVO registry lê watermarks.json (avançado), view NASCE VAZIA.
        let state2 = Arc::new(Mutex::new((0u64, 0u64)));
        let mut reg2 = ViewRegistry::open(dir.path()).unwrap();
        reg2.register(Box::new(CountView {
            state: state2.clone(),
            wm: 0,
        }));
        reg2.catch_up(&log).unwrap();

        // Sem o fix isto seria 0 (view vazia, replay saltado). Com o fix: 50.
        assert_eq!(
            state2.lock().unwrap().0,
            50,
            "view vazia (restore=false) tem de replayar TODO o histórico desde 0"
        );
    }
}
