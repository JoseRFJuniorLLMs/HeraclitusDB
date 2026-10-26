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
use std::cell::Cell;

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

thread_local! {
    /// Bytes vivos pedidos por ESTA thread: os testes do binário correm em
    /// paralelo, e um contador global misturava as medições.
    static VIVOS: Cell<isize> = const { Cell::new(0) };
}

fn somar(delta: isize) {
    let _ = VIVOS.try_with(|v| v.set(v.get() + delta));
}

fn vivos() -> isize {
    VIVOS.with(Cell::get)
}

unsafe impl GlobalAlloc for Contador {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        somar(l.size() as isize);
        System.alloc(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        somar(-(l.size() as isize));
        System.dealloc(p, l);
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, novo: usize) -> *mut u8 {
        somar(novo as isize - l.size() as isize);
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
fn medir<V: View>(n: u64, view: &mut V, episodios: &[Episode]) -> f64 {
    let antes = vivos();
    for (lsn, e) in episodios.iter().enumerate().take(n as usize) {
        view.apply(lsn as u64, e);
    }
    (vivos() - antes) as f64 / n as f64
}

/// Uma linha da medição: o que o alocador viu e o que o índice estima.
struct Linha {
    nome: &'static str,
    medido: f64,
    estimado: Option<f64>,
}

fn linha<V: View>(
    nome: &'static str,
    view: &mut V,
    episodios: &[Episode],
    estimar: impl Fn(&V) -> u64,
) -> Linha {
    let n = episodios.len() as u64;
    let medido = medir(n, view, episodios);
    Linha {
        nome,
        medido,
        estimado: Some(estimar(view) as f64 / n as f64),
    }
}

#[test]
#[ignore = "medição manual; ver o cabeçalho"]
fn memoria_por_evento_de_cada_indice() {
    const N: u64 = 20_000;
    let episodios: Vec<Episode> = (0..N).map(episodio).collect();
    let mut linhas = vec![
        linha(
            "vector (HNSW)",
            &mut VectorIndex::new(ProductMetric::default()),
            &episodios,
            VectorIndex::resident_bytes,
        ),
        linha(
            "text (BM25)",
            &mut TextIndex::new(),
            &episodios,
            TextIndex::resident_bytes,
        ),
        linha(
            "graph",
            &mut GraphIndex::new(),
            &episodios,
            GraphIndex::resident_bytes,
        ),
        linha(
            "activation",
            &mut ActivationStore::new(0.5),
            &episodios,
            ActivationStore::resident_bytes,
        ),
        linha(
            "attr",
            &mut AttrIndex::new(),
            &episodios,
            AttrIndex::resident_bytes,
        ),
    ];
    for (nome, medido) in [
        (
            "temporal graph",
            medir(N, &mut TemporalGraph::new(), &episodios),
        ),
        ("entity", medir(N, &mut EntityResolver::new(), &episodios)),
        (
            "telemetry health",
            medir(N, &mut TelemetryHealthGraph::new(), &episodios),
        ),
    ] {
        linhas.push(Linha {
            nome,
            medido,
            estimado: None,
        });
    }

    let antes = vivos();
    let memtable = Memtable::new(100_000);
    for (lsn, e) in episodios.iter().enumerate() {
        memtable.apply(lsn as u64, e.clone());
    }
    linhas.push(Linha {
        nome: "memtable (até ao cap)",
        medido: (vivos() - antes) as f64 / N as f64,
        estimado: Some(memtable.resident_bytes() as f64 / N as f64),
    });

    let total: f64 = linhas.iter().map(|l| l.medido).sum();
    println!("\n{N} episódios da carga mixed — bytes por evento (medido / estimado):");
    for l in &linhas {
        let estimado = l
            .estimado
            .map(|e| {
                format!(
                    "{e:>9.0}  ({:>+5.1}%)",
                    100.0 * (e - l.medido) / l.medido.max(1.0)
                )
            })
            .unwrap_or_else(|| "        —".into());
        println!(
            "  {:<24} {:>9.0}  {estimado}   ({:>4.1}% do total)",
            l.nome,
            l.medido,
            100.0 * l.medido / total
        );
    }
    println!("  {:<24} {total:>9.0}", "total");
    assert!(total > 0.0);
}

/// A contabilidade que o teto de memória usa (`resident_bytes` de cada
/// índice) tem de acompanhar o que o alocador vê. Corre sempre: se alguém mudar
/// uma estrutura e esquecer a estimativa, isto falha.
#[test]
fn estimativas_de_memoria_acompanham_o_alocador() {
    let episodios: Vec<Episode> = (0..5_000).map(episodio).collect();
    let linhas = [
        linha(
            "vector",
            &mut VectorIndex::new(ProductMetric::default()),
            &episodios,
            VectorIndex::resident_bytes,
        ),
        linha(
            "text",
            &mut TextIndex::new(),
            &episodios,
            TextIndex::resident_bytes,
        ),
        linha(
            "graph",
            &mut GraphIndex::new(),
            &episodios,
            GraphIndex::resident_bytes,
        ),
        linha(
            "activation",
            &mut ActivationStore::new(0.5),
            &episodios,
            ActivationStore::resident_bytes,
        ),
        linha(
            "attr",
            &mut AttrIndex::new(),
            &episodios,
            AttrIndex::resident_bytes,
        ),
    ];
    for l in linhas {
        let estimado = l.estimado.unwrap();
        let desvio = (estimado - l.medido).abs() / l.medido;
        assert!(
            desvio <= 0.20,
            "{}: estimado {estimado:.0} B/evento, medido {:.0} ({:+.1}%)",
            l.nome,
            l.medido,
            100.0 * (estimado - l.medido) / l.medido
        );
    }
}
