//! Quanta memória cada índice residente gasta por evento, com episódios iguais
//! aos da carga `mixed` do soak nightly.
//!
//! Soak de 20/10/2026: o RSS do servidor cresceu ~5 KiB por evento gravado,
//! estável. Antes de pôr um teto global e despejo para disco é preciso saber
//! QUEM gasta. Mede-se cada índice isolado (sem `Engine` nem servidor), com um
//! `GlobalAlloc` contador: bytes vivos pedidos ao alocador depois de aplicar N
//! episódios, divididos por N. Não inclui fragmentação nem a sobrecarga do
//! jemalloc, que o RSS inclui — por isso a soma fica abaixo dos 5 KiB.
//!
//! Corre à mão: `cargo test -p heraclitus-server --test memoria_por_indice
//! -- --ignored --nocapture`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use heraclitus_activation::ActivationStore;
use heraclitus_core::{Episode, EventKind, ProductPoint};
use heraclitus_index_attr::AttrIndex;
use heraclitus_index_graph::entity::EntityResolver;
use heraclitus_index_graph::temporal::TemporalGraph;
use heraclitus_index_graph::GraphIndex;
use heraclitus_index_text::TextIndex;
use heraclitus_index_vector::VectorIndex;
use heraclitus_manifold::ProductMetric;
use heraclitus_memtable::Memtable;
use heraclitus_telemetry_health::TelemetryHealthGraph;
use heraclitus_views::View;

struct Contador;

static VIVOS: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Contador {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        VIVOS.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        VIVOS.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l);
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, novo: usize) -> *mut u8 {
        VIVOS.fetch_add(novo as isize - l.size() as isize, Ordering::Relaxed);
        System.realloc(p, l, novo)
    }
}

#[global_allocator]
static ALOCADOR: Contador = Contador;

/// O episódio que `load.rs::execute_operation` grava na pista `Ingest`, com os
/// dois atributos que `Engine::append_idempotent` acrescenta.
fn episodio(sequencia: u64) -> Episode {
    let chave = mix(0x428931 ^ sequencia);
    let classes = [
        "authentication",
        "network",
        "dns",
        "http",
        "process",
        "endpoint",
        "iam",
        "kubernetes",
        "cloud_audit",
        "database_audit",
        "application_log",
    ];
    let classe = classes[(chave as usize) % classes.len()];
    let conteudo = format!(
        "synthetic qualification {classe} sequence={sequencia} marker={chave:016x} {}",
        "x".repeat(96 + (chave as usize % 512))
    );
    let mut e = Episode::new(
        format!("soc-agent-{}", chave % 4_096),
        EventKind::Custom(classe.into()),
        conteudo.into_bytes(),
    );
    e.session_id = "qualification-428931".into();
    e.ts_hlc = (1_792_485_435_000 + sequencia * 7) << 16;
    e.embedding = Some(ProductPoint {
        hyp: vec![
            (chave % 20) as f32 / 100.0,
            ((chave >> 8) % 20) as f32 / 100.0,
        ],
        sph: vec![],
        euc: vec![],
    });
    e.attrs
        .insert("tenant".into(), format!("tenant-{}", chave % 32));
    e.attrs
        .insert("sensor".into(), format!("sensor-{}", chave % 512));
    e.attrs
        .insert("severity".into(), format!("{}", chave % 10 + 1));
    e.attrs.insert(
        heraclitus_index_attr::IDEMPOTENCY_KEY_FIELD.into(),
        format!("qualifier-428931-{sequencia}"),
    );
    e.attrs.insert(
        "__heraclitus_idempotency_hash".into(),
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            mix(chave),
            mix(chave + 1),
            mix(chave + 2),
            mix(chave + 3)
        ),
    );
    e
}

fn mix(mut v: u64) -> u64 {
    v = v.wrapping_add(0x9E37_79B9_7F4A_7C15);
    v = (v ^ (v >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    v = (v ^ (v >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    v ^ (v >> 31)
}

/// Bytes vivos por evento depois de `n` episódios aplicados à view.
fn medir(n: u64, view: &mut dyn View, episodios: &[Episode]) -> f64 {
    let antes = VIVOS.load(Ordering::Relaxed);
    for (lsn, e) in episodios.iter().enumerate().take(n as usize) {
        view.apply(lsn as u64, e);
    }
    (VIVOS.load(Ordering::Relaxed) - antes) as f64 / n as f64
}

#[test]
#[ignore = "medição manual; ver o cabeçalho"]
fn memoria_por_evento_de_cada_indice() {
    const N: u64 = 20_000;
    let episodios: Vec<Episode> = (0..N).map(episodio).collect();
    let mut linhas = Vec::new();

    let mut vetor = VectorIndex::new(ProductMetric::default());
    linhas.push(("vector (HNSW)", medir(N, &mut vetor, &episodios)));
    let mut texto = TextIndex::new();
    linhas.push(("text (BM25)", medir(N, &mut texto, &episodios)));
    let mut grafo = GraphIndex::new();
    linhas.push(("graph", medir(N, &mut grafo, &episodios)));
    let mut temporal = TemporalGraph::new();
    linhas.push(("temporal graph", medir(N, &mut temporal, &episodios)));
    let mut entidades = EntityResolver::new();
    linhas.push(("entity", medir(N, &mut entidades, &episodios)));
    let mut ativacao = ActivationStore::new(0.5);
    linhas.push(("activation", medir(N, &mut ativacao, &episodios)));
    let mut saude = TelemetryHealthGraph::new();
    linhas.push(("telemetry health", medir(N, &mut saude, &episodios)));
    let mut atributos = AttrIndex::new();
    linhas.push(("attr", medir(N, &mut atributos, &episodios)));

    let antes = VIVOS.load(Ordering::Relaxed);
    let memtable = Memtable::new(100_000);
    for (lsn, e) in episodios.iter().enumerate() {
        memtable.apply(lsn as u64, e.clone());
    }
    let memtable_por_evento = (VIVOS.load(Ordering::Relaxed) - antes) as f64 / N as f64;
    linhas.push(("memtable (até ao cap)", memtable_por_evento));

    let total: f64 = linhas.iter().map(|(_, b)| b).sum();
    println!("\n{N} episódios da carga mixed — bytes vivos por evento:");
    for (nome, bytes) in &linhas {
        println!(
            "  {nome:<24} {bytes:>9.0}  ({:>4.1}%)",
            100.0 * bytes / total
        );
    }
    println!("  {:<24} {total:>9.0}", "total");
    assert!(total > 0.0);
}
