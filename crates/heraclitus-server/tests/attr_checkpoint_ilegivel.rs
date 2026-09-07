//! Auditoria recursiva 2026-09-05, vaga 2 (R90): um checkpoint do índice de
//! atributos que é RECUSADO tem de deixar rasto.
//!
//! O arranque continua correcto sem isto — o log é a verdade e o índice
//! reconstrói-se por replay. O que falta é observabilidade: um checkpoint
//! corrompido troca um arranque de cauda por um rebuild integral (minutos ou
//! horas num log grande) e, sem aviso, a fase de boot imprime exactamente a
//! mesma linha que num arranque normal. O operador não distingue "lento porque
//! o checkpoint estava corrompido" de "lento por outra razão", e uma corrupção
//! recorrente (disco, fsync, downgrade de formato) nunca chega a ser notada.
//!
//! O teste unitário de `heraclitus-index-attr` prova que `open_reportando`
//! distingue os casos; este prova que o chamador AVISA. Sem ele, apagar o
//! `tracing::warn!` do `Engine::open` passava despercebido.
//!
//! Binário de teste próprio: instala um subscriber de `tracing` (mesmo sendo
//! `with_default`, isto é estado de thread) e corrompe ficheiros no data_dir.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};
use heraclitus_server::engine::Engine;

use std::sync::{Arc, Mutex};

/// Escritor partilhado para o subscriber de teste.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn texto(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn abrir_capturando(dir: &std::path::Path) -> (Engine, String) {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let cfg = HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };
    let engine = tracing::subscriber::with_default(subscriber, || Engine::open(&cfg).unwrap());
    let texto = buffer.texto();
    (engine, texto)
}

fn episodio(i: usize) -> Episode {
    let mut e = Episode::new(
        "ana",
        EventKind::Observation,
        format!("registo {i}").into_bytes(),
    );
    e.attrs.insert("dossie".into(), "alfa".into());
    e
}

#[test]
fn checkpoint_ilegivel_do_indice_de_atributos_avisa_no_arranque() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("views").join("attr_index.bin");

    // 1) Sessão normal: grava um checkpoint válido do índice de atributos.
    {
        let (engine, avisos) = abrir_capturando(dir.path());
        for i in 0..30 {
            engine.append(episodio(i)).unwrap();
        }
        engine.checkpoint_views().unwrap();
        assert!(
            !avisos.contains("ILEGÍVEL"),
            "um log virgem NÃO pode avisar de checkpoint ilegível: {avisos}"
        );
    }
    assert!(snapshot.is_file(), "montagem: checkpoint tem de existir");

    // 2) Arranque com o checkpoint intacto: continua sem aviso.
    {
        let (_engine, avisos) = abrir_capturando(dir.path());
        assert!(
            !avisos.contains("ILEGÍVEL"),
            "checkpoint válido não pode avisar: {avisos}"
        );
    }

    // 3) Corrompe o corpo mantendo o magic — o CRC v6 (R89) recusa-o.
    let mut bytes = std::fs::read(&snapshot).unwrap();
    let meio = bytes.len() / 2;
    bytes[meio] ^= 0xFF;
    std::fs::write(&snapshot, &bytes).unwrap();

    let (engine, avisos) = abrir_capturando(dir.path());
    assert!(
        avisos.contains("ILEGÍVEL"),
        "checkpoint recusado tem de avisar em vez de reconstruir em silêncio; \
         avisos capturados: {avisos:?}"
    );
    // O aviso não pode ser o consolo de uma resposta errada: o replay repõe
    // tudo, porque o log — e não o checkpoint — é a fonte de verdade.
    let vistos = heraclitus_query::execute("MATCH (n) WHERE n.dossie = \"alfa\" RETURN n", &engine)
        .unwrap()
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    assert_eq!(vistos, 30, "o rebuild por replay tem de repor os 30");
}
