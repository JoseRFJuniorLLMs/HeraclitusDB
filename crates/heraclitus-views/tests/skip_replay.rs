//! Regressão: arrancar com o replay SALTADO não pode deixar eventos órfãos.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError, Lsn};
use heraclitus_log::Log;
use heraclitus_views::{View, ViewRegistry};
use std::sync::{Arc, Mutex};

/// View que PERSISTE (como as reais), com o estado exposto ao teste. É
/// necessária para reproduzir o bug: um snapshot vazio-mas-presente faz
/// `restore()` devolver `true`, e o watermark antigo sobrevive — por isso a
/// verificação TEM de ser sobre o que a view indexou, não sobre o watermark
/// (é o watermark que mente).
struct PersistView {
    /// O nome é por instância (e não a constante `"persist"`) porque há testes
    /// que registam DUAS views para distinguir o rebuild integral do rebuild de
    /// uma só view. É também a chave do ficheiro de checkpoint.
    nome: &'static str,
    seen: Arc<Mutex<Vec<Lsn>>>,
    wm: Lsn,
}

impl View for PersistView {
    fn name(&self) -> &str {
        self.nome
    }
    fn apply(&mut self, lsn: Lsn, _e: &Episode) {
        self.seen.lock().unwrap().push(lsn);
        self.wm = self.wm.max(lsn);
    }
    fn watermark(&self) -> Lsn {
        self.wm
    }
    fn reset(&mut self) {
        self.seen.lock().unwrap().clear();
        self.wm = 0;
    }
    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), HeraclitusError> {
        let seen = self.seen.lock().unwrap().clone();
        heraclitus_views::ckpt::save(dir, self.nome, &(seen, self.wm))
    }
    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, HeraclitusError> {
        match heraclitus_views::ckpt::load::<(Vec<Lsn>, Lsn)>(dir, self.nome)? {
            Some((seen, wm)) => {
                *self.seen.lock().unwrap() = seen;
                self.wm = wm;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

fn view_with(state: &Arc<Mutex<Vec<Lsn>>>) -> Box<PersistView> {
    view_chamada("persist", state)
}

fn view_chamada(nome: &'static str, state: &Arc<Mutex<Vec<Lsn>>>) -> Box<PersistView> {
    Box::new(PersistView {
        nome,
        seen: state.clone(),
        wm: 0,
    })
}

/// PERDA DE DADOS SILENCIOSA (corrigida): arrancar com `HERACLITUS_SKIP_VIEW_REPLAY`
/// deixava as views VAZIAS mas com os watermarks altos carregados do disco. Um
/// checkpoint nesse estado (o periódico — 300 s por omissão — ou o de shutdown)
/// gravava snapshots VAZIOS sob esses watermarks. Como `restore()` devolve
/// `true` para um snapshot vazio-mas-presente, o arranque normal seguinte
/// mantinha o watermark e replayava só `(W, head]`: TUDO ≤ W ficava invisível
/// às views PARA SEMPRE (só recuperável com um `view rebuild` explícito).
///
/// Nota: verificar o watermark NÃO apanha o bug (ele fica "certo" nos dois
/// casos, e é essa a mentira); a asserção é sobre os eventos indexados.
#[test]
fn skip_replay_then_checkpoint_does_not_orphan_events() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..30 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
    let head = log.head();

    // 1) Arranque normal: materializa as views e faz checkpoint (estado bom).
    {
        let st = Arc::new(Mutex::new(Vec::new()));
        let mut r = ViewRegistry::open(dir.path()).unwrap();
        r.register(view_with(&st));
        r.catch_up(&log).unwrap();
        r.checkpoint().unwrap();
        assert_eq!(
            st.lock().unwrap().len() as u64,
            head,
            "setup: a view devia ver tudo"
        );
    }

    // 2) Arranque com o replay SALTADO, seguido de um checkpoint (o periódico
    //    ou o de shutdown) — o caminho que corrompia o estado em disco.
    {
        let st = Arc::new(Mutex::new(Vec::new()));
        let mut r = ViewRegistry::open(dir.path()).unwrap();
        r.register(view_with(&st));
        r.reset_watermarks(); // a correção: views vazias ⇒ watermark 0
        r.checkpoint().unwrap();
    }

    // 3) Arranque normal seguinte: a view TEM de voltar a conter o log inteiro.
    let st = Arc::new(Mutex::new(Vec::new()));
    let mut r = ViewRegistry::open(dir.path()).unwrap();
    r.register(view_with(&st));
    r.catch_up(&log).unwrap();
    let indexados = st.lock().unwrap().len() as u64;
    assert_eq!(
        indexados, head,
        "views órfãs: só {indexados} de {head} eventos ficaram indexados"
    );
}

/// Auditoria 2026-09-05 (A50): zerar os watermarks NÃO chega — basta UM evento
/// vivo entre o arranque saltado e o checkpoint para o buraco voltar.
///
/// O modo `HERACLITUS_SKIP_VIEW_REPLAY` sobe o banco a servir o log e ACEITA
/// escritas: cada append passa por `index_applied` → `ViewRegistry::apply` →
/// `view.apply(lsn, ep)`, e todas as views fazem `self.watermark =
/// self.watermark.max(lsn)`. O watermark INTERNO — que é a autoridade em
/// `catch_up` — salta assim para o LSN vivo por cima de uma view SEM histórico,
/// e `reset_watermarks()` não lhe chega (zera só a cópia do registry). O
/// checkpoint seguinte (o periódico, 300 s por omissão, ou o de shutdown)
/// persiste esse par mentiroso — conteúdo de 1 evento, watermark do LSN vivo —
/// e o arranque normal seguinte replaya só `(LSN vivo, head]`: todo o histórico
/// fica invisível às views PARA SEMPRE.
///
/// Como no teste acima, a asserção é sobre EVENTOS INDEXADOS: o watermark
/// parece "certo" nos dois casos, e é precisamente essa a mentira.
#[test]
fn um_apply_vivo_depois_do_skip_replay_nao_pode_envenenar_o_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..30 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }

    // 1) Arranque normal: materializa e faz checkpoint (o estado BOM em disco).
    {
        let st = Arc::new(Mutex::new(Vec::new()));
        let mut r = ViewRegistry::open(dir.path()).unwrap();
        r.register(view_with(&st));
        r.catch_up(&log).unwrap();
        r.checkpoint().unwrap();
        assert_eq!(
            st.lock().unwrap().len() as u64,
            log.head(),
            "setup: a view devia ver tudo"
        );
    }

    // 2) Arranque com o replay SALTADO: view VAZIA, um append vivo (o banco
    //    aceita escritas neste modo) e o checkpoint periódico logo a seguir.
    {
        let st = Arc::new(Mutex::new(Vec::new()));
        let mut r = ViewRegistry::open(dir.path()).unwrap();
        r.register(view_with(&st));
        r.mark_unmaterialized(); // é o que o Engine faz no ramo do skip_replay
        let ep = Episode::new("a", EventKind::Observation, b"vivo".to_vec());
        let lsn = log.append(ep.clone()).unwrap();
        r.apply(lsn, &ep);
        r.checkpoint().unwrap();
    }
    let head = log.head();

    // 3) Arranque normal seguinte: a view TEM de voltar a conter o log inteiro.
    let st = Arc::new(Mutex::new(Vec::new()));
    let mut r = ViewRegistry::open(dir.path()).unwrap();
    r.register(view_with(&st));
    r.catch_up(&log).unwrap();
    let indexados = st.lock().unwrap().len() as u64;
    assert_eq!(
        indexados, head,
        "views órfãs: só {indexados} de {head} eventos ficaram indexados"
    );
}

/// A marca de "não materializado" é um travão, não um interruptor de sentido
/// único: assim que o `catch_up` materializa as views a partir do log, o
/// checkpoint TEM de voltar a ser gravado — senão o fast boot morria calado e
/// todo o arranque passava a replayar o log inteiro (Auditoria 2026-09-05, A50).
#[test]
fn depois_do_catch_up_a_marca_cai_e_o_checkpoint_volta_a_ser_gravado() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..20 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
    let head = log.head();

    let st = Arc::new(Mutex::new(Vec::new()));
    let mut r = ViewRegistry::open(dir.path()).unwrap();
    r.register(view_with(&st));
    r.mark_unmaterialized();
    assert!(r.unmaterialized(), "a marca tinha de estar de pé");
    r.catch_up(&log).unwrap();
    r.checkpoint().unwrap();

    // A prova é o snapshot em disco a descrever o log, não a marca em RAM.
    let (seen, wm) =
        heraclitus_views::ckpt::load::<(Vec<Lsn>, Lsn)>(&dir.path().join("views"), "persist")
            .unwrap()
            .expect("o checkpoint tinha de ter sido gravado depois do catch_up");
    assert_eq!(
        seen.len() as u64,
        head,
        "o snapshot tem de ter o log inteiro"
    );
    // `head` é o PRÓXIMO LSN a escrever; o mais alto já aplicado é `head - 1`.
    assert_eq!(
        wm,
        head - 1,
        "o watermark do snapshot tem de ser o LSN mais alto do log"
    );
}

/// Um rebuild INTEGRAL baixa a marca, e o checkpoint volta a ir para disco
/// (auditoria 2026-09-05, A50 — retrabalho pós-revisão).
///
/// A primeira versão desta correcção decidiu o CONTRÁRIO — "o rebuild nunca
/// baixa a marca, nem o integral" — com o argumento de que quem grava o
/// checkpoint (o `Engine`) grava no mesmo passo o índice de atributos, que este
/// método não toca. O argumento não se sustenta: o índice de atributos tem a
/// sua PRÓPRIA marca e a sua própria guarda no `Engine` (auditoria A47), e o
/// único chamador vivo de rebuild-integral-seguido-de-checkpoint é o
/// `Engine::shred`, onde o attr é reconstruído do LSN 0 pelo próprio shred. Não
/// havia ali buraco do attr para proteger — havia um estrago a ser criado: com
/// a marca de pé, o `views.checkpoint()` do crypto-shred virava um no-op
/// silencioso, os snapshots PRÉ-shred (com o plaintext derivado da titular)
/// ficavam em disco, o marcador `privacy-rebuild-required` era apagado a seguir
/// e o arranque normal seguinte RESSUSCITAVA o plaintext depois de a chave ter
/// sido destruída. Ver `shred_com_replay_saltado_reescreve_os_snapshots.rs` no
/// `heraclitus-server`.
///
/// A prova é o snapshot em disco, não a marca em RAM.
#[test]
fn rebuild_integral_baixa_a_marca_e_o_checkpoint_volta_a_ser_gravado() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..12 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
    let head = log.head();

    let st = Arc::new(Mutex::new(Vec::new()));
    let mut r = ViewRegistry::open(dir.path()).unwrap();
    r.register(view_with(&st));
    r.mark_unmaterialized();
    r.rebuild(&log, None).unwrap();
    assert_eq!(
        st.lock().unwrap().len() as u64,
        head,
        "montagem: o rebuild integral tinha de materializar a view"
    );
    r.checkpoint().unwrap();

    let (seen, wm) =
        heraclitus_views::ckpt::load::<(Vec<Lsn>, Lsn)>(&dir.path().join("views"), "persist")
            .unwrap()
            .expect(
                "o checkpoint tinha de ter sido gravado depois do rebuild integral: é o \
                 que o crypto-shred faz, e sem ele os snapshots PRÉ-shred ficam em disco",
            );
    assert_eq!(
        seen.len() as u64,
        head,
        "o snapshot tem de descrever o log inteiro"
    );
    // `head` é o PRÓXIMO LSN a escrever; o mais alto já aplicado é `head - 1`.
    assert_eq!(
        wm,
        head - 1,
        "o watermark do snapshot tem de ser o LSN mais alto do log"
    );
}

/// ...mas um rebuild de UMA view só NÃO baixa a marca: as outras views deste
/// registry continuam por materializar, e gravar aí persistia exactamente os
/// snapshots vazios-sob-watermark-alto que a marca existe para impedir
/// (auditoria 2026-09-05, A50).
#[test]
fn rebuild_de_uma_so_view_nao_baixa_a_marca() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..8 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }

    let uma = Arc::new(Mutex::new(Vec::new()));
    let outra = Arc::new(Mutex::new(Vec::new()));
    let mut r = ViewRegistry::open(dir.path()).unwrap();
    r.register(view_chamada("persist", &uma));
    r.register(view_chamada("outra", &outra));
    r.mark_unmaterialized();
    r.rebuild(&log, Some("persist")).unwrap();
    assert_eq!(
        uma.lock().unwrap().len() as u64,
        log.head(),
        "montagem: a view nomeada tinha de ser reconstruída"
    );
    assert!(
        outra.lock().unwrap().is_empty(),
        "montagem: a outra view tinha de continuar vazia"
    );
    assert!(
        r.unmaterialized(),
        "com uma das views ainda vazia, a marca tem de ficar de pé"
    );

    r.checkpoint().unwrap();
    assert!(
        heraclitus_views::ckpt::load::<(Vec<Lsn>, Lsn)>(&dir.path().join("views"), "outra")
            .unwrap()
            .is_none(),
        "com a marca de pé nenhum snapshot pode ser gravado"
    );
}
