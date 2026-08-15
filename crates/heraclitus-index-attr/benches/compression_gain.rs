//! Ganho da compressão de postings no checkpoint do índice de atributos.
//!
//! Existe pela mesma razão que o `mmap_vs_read` e o `gpu_vs_cpu`: **números em
//! prosa apodrecem, medição refaz-se.** O ganho da compressão depende
//! inteiramente do perfil do índice — e o intervalo é enorme, entre −83% e
//! zero. Escrever "comprime 83%" num documento seria verdade em laboratório e
//! mentira em produção.
//!
//! ```bash
//! cargo bench -p heraclitus-index-attr --bench compression_gain
//! ```
//!
//! Se o número real do teu banco importa, aponta a variável de ambiente
//! `HERACLITUS_DATA_DIR` ao data dir e o benchmark mede o checkpoint **real**
//! em vez de perfis sintéticos.

use heraclitus_core::{Episode, EventKind};
use heraclitus_index_attr::AttrIndex;
use heraclitus_views::View;

/// Índice onde os POSTINGS dominam: poucos valores distintos, muitos eventos
/// cada. É o caso que a compressão ataca — `risk_level`, `action_class`,
/// `agent_id` num log de auditoria.
fn postings_longos(n: u64, valores: u64) -> AttrIndex {
    let mut ix = AttrIndex::new();
    for lsn in 0..n {
        let mut ep = Episode::new("a", EventKind::Custom("T".into()), b"x".to_vec());
        ep.attrs.insert("classe".into(), format!("c{}", lsn % valores));
        ix.apply(lsn, &ep);
    }
    ix
}

/// Índice dominado por valores quase únicos: os postings são curtos e o bincode
/// varint já é bom. Aqui a compressão não pode PIORAR — é o contrapeso.
fn quase_unicos(n: u64) -> AttrIndex {
    let mut ix = AttrIndex::new();
    for lsn in 0..n {
        let mut ep = Episode::new("a", EventKind::Custom("T".into()), b"x".to_vec());
        ep.attrs.insert("comum".into(), "sempre-o-mesmo".into());
        ep.attrs.insert("seq".into(), lsn.to_string());
        ix.apply(lsn, &ep);
    }
    ix
}

fn medir(rotulo: &str, ix: &AttrIndex) {
    let dir = tempfile::tempdir().unwrap();
    ix.save(dir.path()).unwrap();
    let comprimido = std::fs::metadata(dir.path().join("attr_index.bin"))
        .unwrap()
        .len();
    let cru = ix.snapshot_bincode_len();
    let pct = 100.0 - (comprimido as f64 / cru as f64 * 100.0);
    println!("  {rotulo:<42} {cru:>9} -> {comprimido:>9}  {pct:>6.1}%");
}

fn main() {
    println!("\nGanho da compressão de postings (checkpoint do índice de atributos)\n");
    println!("  {:<42} {:>9}    {:>9}  {:>6}", "perfil", "sem", "com", "ganho");

    medir("postings longos (10 valores x 50k)", &postings_longos(50_000, 10));
    medir("postings medios (500 valores x 50k)", &postings_longos(50_000, 500));
    medir("quase unicos (20k distintos)", &quase_unicos(20_000));

    // O número que decide de facto: o checkpoint REAL, se existir.
    if let Ok(data) = std::env::var("HERACLITUS_DATA_DIR") {
        let views = std::path::Path::new(&data).join("views");
        if views.join("attr_index.bin").exists() {
            println!();
            medir("REAL (HERACLITUS_DATA_DIR)", &AttrIndex::open(&views));
        }
    }

    println!(
        "\n  O intervalo e enorme e depende do perfil: postings longos ganham\n  \
         muito, valores quase unicos nao ganham nada. Por isso este numero\n  \
         mede-se em vez de se citar -- e por isso a escolha do codec e feita\n  \
         POR COLUNA, medindo, e nunca pode expandir.\n"
    );
}
