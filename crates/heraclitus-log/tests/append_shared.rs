//! `append_shared`: o episódio carimbado que o append devolve é o MESMO `Arc`
//! que o `tail_subscribe` entrega — sem cópia profunda no caminho quente — e o
//! comportamento observável (LSN, carimbo HLC, conteúdo persistido) é o de
//! `append_stamped`.

use std::path::Path;
use std::sync::Arc;

use heraclitus_core::{
    DatabaseManifest, Episode, EventKind, FsyncPolicy, HeraclitusError, Lsn, ProductPoint,
    StorageFormat,
};
use heraclitus_log::{AnyLog, EpisodeLog};
use tokio::sync::broadcast;

/// Um episódio com todos os campos que custam a copiar preenchidos: se o
/// append voltasse a clonar, era isto que se duplicava.
fn episodio_pesado(tag: &str) -> Episode {
    let mut e = Episode::new(
        "append-shared-test",
        EventKind::Custom("Pesado".into()),
        format!("conteudo {tag}").repeat(64).into_bytes(),
    );
    e.session_id = "sessao".into();
    e.attrs.insert("tag".into(), tag.into());
    e.attrs.insert("outro".into(), "valor".into());
    e.embedding = Some(ProductPoint {
        hyp: vec![0.1, 0.2, 0.3],
        sph: vec![0.6, 0.8],
        euc: vec![1.0, -1.0],
    });
    e.valid_from = Some(7);
    e
}

fn json(e: &Episode) -> serde_json::Value {
    serde_json::to_value(e).unwrap()
}

/// O episódio devolvido tem de ser o original com o carimbo do log e mais
/// nada mudado.
fn assert_carimbado_igual(original: &Episode, carimbado: &Episode) {
    assert_ne!(carimbado.ts_hlc, 0, "o log tem de carimbar o HLC");
    let mut esperado = original.clone();
    esperado.ts_hlc = carimbado.ts_hlc;
    assert_eq!(json(&esperado), json(carimbado));
}

fn partilha_com_o_broadcast(format: StorageFormat) {
    let temp = tempfile::tempdir().unwrap();
    let log = AnyLog::open(
        format,
        temp.path().join("log"),
        1 << 20,
        FsyncPolicy::Always,
    )
    .unwrap();
    let mut rx = log.tail_subscribe();

    let mut ultimo_ts = 0;
    for i in 0..3u64 {
        let original = episodio_pesado(&i.to_string());
        let (lsn, partilhado) = log.append_shared(original.clone()).unwrap();
        assert_eq!(lsn, i, "{format:?}: LSN denso");

        // Os dois motores publicam no broadcast antes de responder ao append.
        let (lsn_tail, entregue) = rx.try_recv().unwrap();
        assert_eq!(lsn_tail, lsn);
        assert!(
            Arc::ptr_eq(&partilhado, &entregue),
            "{format:?}: o append devolveu uma cópia em vez do Arc publicado"
        );

        assert_carimbado_igual(&original, &partilhado);
        assert!(
            partilhado.ts_hlc > ultimo_ts,
            "{format:?}: HLC monotónico por LSN"
        );
        ultimo_ts = partilhado.ts_hlc;

        let (_, persistido) = log.read(lsn).unwrap().unwrap();
        assert_eq!(json(&persistido), json(&partilhado));
    }

    // Pelo objecto-trait e pelo blanket `Arc<T>` o caminho é o mesmo.
    let objecto: &dyn EpisodeLog = &log;
    let (lsn, partilhado) = objecto.append_shared(episodio_pesado("dyn")).unwrap();
    let (lsn_tail, entregue) = rx.try_recv().unwrap();
    assert_eq!((lsn, lsn_tail), (3, 3));
    assert!(Arc::ptr_eq(&partilhado, &entregue));

    let embrulhado = Arc::new(log);
    let (lsn, partilhado) = EpisodeLog::append_shared(&embrulhado, episodio_pesado("arc")).unwrap();
    let (lsn_tail, entregue) = rx.try_recv().unwrap();
    assert_eq!((lsn, lsn_tail), (4, 4));
    assert!(Arc::ptr_eq(&partilhado, &entregue));
}

#[test]
fn append_shared_partilha_o_arc_do_broadcast_no_legado() {
    partilha_com_o_broadcast(StorageFormat::Legacy);
}

#[test]
fn append_shared_partilha_o_arc_do_broadcast_no_v6() {
    partilha_com_o_broadcast(StorageFormat::V6);
}

/// Sem subscritores a segurar o `Arc`, o `append_stamped` (agora por cima de
/// `append_shared`) devolve o mesmo que devolvia: o episódio original com o
/// carimbo real, igual ao que ficou no log.
fn append_stamped_mantem_o_contrato(format: StorageFormat) {
    let temp = tempfile::tempdir().unwrap();
    let log = AnyLog::open(
        format,
        temp.path().join("log"),
        1 << 20,
        FsyncPolicy::Always,
    )
    .unwrap();
    // Um subscritor que não lê: o `append_stamped` tem de cair na cópia em
    // vez de falhar ou devolver algo diferente.
    let _parado = log.tail_subscribe();
    for i in 0..2u64 {
        let original = episodio_pesado(&format!("stamped-{i}"));
        let (lsn, carimbado) = log.append_stamped(original.clone()).unwrap();
        assert_eq!(lsn, i);
        assert_carimbado_igual(&original, &carimbado);
        let (_, persistido) = log.read(lsn).unwrap().unwrap();
        assert_eq!(json(&persistido), json(&carimbado));
    }
}

#[test]
fn append_stamped_mantem_o_contrato_no_legado() {
    append_stamped_mantem_o_contrato(StorageFormat::Legacy);
}

#[test]
fn append_stamped_mantem_o_contrato_no_v6() {
    append_stamped_mantem_o_contrato(StorageFormat::V6);
}

/// Um implementador de fora do crate que só conhece os métodos obrigatórios
/// continua a compilar: `append_shared` tem implementação por defeito, por
/// cima de `append_stamped`.
struct SoObrigatorios(AnyLog);

impl EpisodeLog for SoObrigatorios {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.0.append(episode)
    }

    fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        self.0.append_stamped(episode)
    }

    fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.0.append_replicated(lsn, episode)
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        self.0.flush()
    }

    fn head(&self) -> Lsn {
        self.0.head()
    }

    fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        self.0.tail_subscribe()
    }

    fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        self.0.read(lsn)
    }

    fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.0.scan_capped(from, to, max)
    }

    fn manifest(&self) -> DatabaseManifest {
        self.0.manifest()
    }

    fn dir(&self) -> &Path {
        self.0.dir()
    }
}

#[test]
fn implementacao_por_defeito_devolve_o_episodio_carimbado() {
    let temp = tempfile::tempdir().unwrap();
    let log = SoObrigatorios(
        AnyLog::open(
            StorageFormat::Legacy,
            temp.path().join("log"),
            1 << 20,
            FsyncPolicy::Always,
        )
        .unwrap(),
    );
    let original = episodio_pesado("defeito");
    let (lsn, partilhado) = log.append_shared(original.clone()).unwrap();
    assert_eq!(lsn, 0);
    assert_carimbado_igual(&original, &partilhado);
    let (_, persistido) = log.read(lsn).unwrap().unwrap();
    assert_eq!(json(&persistido), json(&partilhado));
}
