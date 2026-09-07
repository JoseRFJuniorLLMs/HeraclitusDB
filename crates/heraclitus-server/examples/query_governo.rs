//! Consulta de amostra sobre uma base carregada com `ingest_governo` — prova
//! que os dados são legíveis e que o índice de atributos responde (inclui o
//! caminho corrigido do `attr_lookup`, que sobre valores não-indexados devia
//! recuar para o varrimento em vez de devolver vazio).
//!
//!   cargo run --release -p heraclitus-server --example query_governo -- <data_dir>

use heraclitus_core::{FsyncPolicy, HeraclitusConfig, StorageFormat};
use heraclitus_server::Engine;
use std::path::PathBuf;

fn main() {
    let data_dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("uso: query_governo <data_dir>");
        std::process::exit(2);
    }));
    let cfg = HeraclitusConfig {
        data_dir,
        fsync: FsyncPolicy::Always,
        storage_format: StorageFormat::V6,
        ..Default::default()
    };
    let engine = Engine::open(&cfg).expect("abrir a base");
    println!("head do log = {}", engine.head());

    let consultas = [
        // Por tipo (kind), via o índice `_kind` — prova a cobertura dos datasets.
        "MATCH (n:Despesas) RETURN n LIMIT 5",
        "MATCH (n:Licitação) RETURN n LIMIT 3",
        "MATCH (n:Transferencias) RETURN n LIMIT 2",
        "MATCH (n:Cadastro) RETURN n LIMIT 2",
        "MATCH (n:CPGF) RETURN n LIMIT 2",
        // Filtro por atributo `arquivo` (baixa cardinalidade, indexado).
        "MATCH (n) WHERE n.arquivo = \"202601_Cadastro\" RETURN n LIMIT 3",
    ];

    for q in consultas {
        print!("\n>>> {q}\n");
        match heraclitus_query::execute(q, &engine) {
            Ok(v) => {
                let arr = v.as_array().map(|a| a.len()).unwrap_or(0);
                println!("    {arr} linhas");
                // Mostra o primeiro resultado, resumido.
                if let Some(primeiro) = v.as_array().and_then(|a| a.first()) {
                    let s = primeiro.to_string();
                    let corte = s.char_indices().nth(240).map(|(i, _)| i).unwrap_or(s.len());
                    println!("    ex: {}…", &s[..corte]);
                }
            }
            Err(e) => println!("    ERRO: {e}"),
        }
    }
}
