//! Carga em massa dos dados de transparência do governo (Portal da
//! Transparência) para uma base HeraclitusDB nova.
//!
//! Os CSV vêm em ISO-8859-1 com `;` como separador e aspas para campos que
//! contêm o separador — este importador trata as três coisas sem dependências
//! externas. Cada linha vira um `Episode`:
//!
//!   - `agent_id` = a pasta do conjunto (ex.: `202401_Licitacoes`);
//!   - `kind`     = `Custom(<tipo derivado do nome do ficheiro>)`, que fica
//!     indexado sob `_kind` e é o predicado de `MATCH (n:Tipo)`;
//!   - `content`  = a linha inteira como objecto JSON `{coluna: valor}`, UTF-8,
//!     auto-descritiva;
//!   - `attrs`    = só `arquivo` (baixa cardinalidade) — indexar cada coluna
//!     encheria o índice de atributos sem discriminar nada.
//!
//! Uso:
//!   cargo run --release -p heraclitus-server --example ingest_governo -- \
//!       <dir_origem> <data_dir> [--limite-por-ficheiro N]
//!
//! O `data_dir` é criado se não existir. A carga é aditiva (append-only), como
//! todo o HeraclitusDB.

use heraclitus_core::Episode;
use heraclitus_core::{EventKind, FsyncPolicy, HeraclitusConfig, StorageFormat};
use heraclitus_server::Engine;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let origem = PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("uso: ingest_governo <dir_origem> <data_dir> [--limite-por-ficheiro N]");
        std::process::exit(2);
    }));
    let data_dir = PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("falta <data_dir>");
        std::process::exit(2);
    }));
    let mut limite: Option<usize> = None;
    while let Some(a) = args.next() {
        if a == "--limite-por-ficheiro" {
            limite = args.next().and_then(|n| n.parse().ok());
        }
    }

    // Group commit: numa carga em massa, fsync por append mataria o débito e não
    // acrescenta garantia nenhuma que uma reexecução não dê (a fonte é imutável).
    let cfg = HeraclitusConfig {
        data_dir: data_dir.clone(),
        fsync: FsyncPolicy::GroupCommit { interval_ms: 200 },
        storage_format: StorageFormat::V6,
        ..Default::default()
    };
    let engine = Engine::open(&cfg).expect("abrir a base");

    // Ficheiros CSV, por ordem determinística.
    let mut csvs: Vec<PathBuf> = Vec::new();
    recolher_csvs(&origem, &mut csvs);
    csvs.sort();
    eprintln!("{} ficheiros CSV em {}", csvs.len(), origem.display());

    let inicio = Instant::now();
    let mut total: u64 = 0;
    let mut falhas: u64 = 0;
    for csv in &csvs {
        let conjunto = csv
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("desconhecido")
            .to_string();
        let arquivo = csv
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("arquivo")
            .to_string();
        let tipo = tipo_do_arquivo(&arquivo);

        let bytes = match std::fs::read(csv) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ! {}: {e}", csv.display());
                continue;
            }
        };
        let texto = latin1_para_utf8(&bytes);
        let mut linhas = parse_csv(&texto, ';');
        if linhas.is_empty() {
            continue;
        }
        let cabecalho = linhas.remove(0);
        let inicio_ficheiro = Instant::now();
        let mut deste = 0u64;
        for campos in linhas {
            if let Some(l) = limite {
                if deste as usize >= l {
                    break;
                }
            }
            let conteudo = linha_json(&cabecalho, &campos);
            let mut ep = Episode::new(
                conjunto.clone(),
                EventKind::Custom(tipo.clone()),
                conteudo.into_bytes(),
            );
            ep.attrs.insert("arquivo".into(), arquivo.clone());
            match engine.append(ep) {
                Ok(_) => {
                    deste += 1;
                    total += 1;
                }
                Err(e) => {
                    falhas += 1;
                    if falhas <= 5 {
                        eprintln!("  ! append falhou: {e}");
                    }
                }
            }
            if total.is_multiple_of(100_000) {
                let taxa = total as f64 / inicio.elapsed().as_secs_f64();
                eprintln!("  … {total} episódios ({taxa:.0}/s)");
            }
        }
        let dt = inicio_ficheiro.elapsed();
        eprintln!(
            "  ✓ {conjunto}/{arquivo}: {deste} linhas em {dt:.1?} (kind={tipo})",
            dt = dt
        );
    }

    let dt = inicio.elapsed();
    let head = engine.head();
    eprintln!("---");
    eprintln!(
        "TOTAL: {total} episódios em {:.1?} ({:.0}/s), {falhas} falhas",
        dt,
        total as f64 / dt.as_secs_f64()
    );
    eprintln!("head do log = {head}");
}

fn recolher_csvs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            // Saltar a pasta .git do repositório de dados.
            if p.file_name().and_then(|s| s.to_str()) == Some(".git") {
                continue;
            }
            recolher_csvs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("csv") {
            out.push(p);
        }
    }
}

/// `202401_Licitação` → `Licitação`; `202601_Servidores_SIAPE` → `Servidores_SIAPE`.
/// Um prefixo de 6 dígitos (AAAAMM) e o `_` seguinte são retirados.
fn tipo_do_arquivo(arquivo: &str) -> String {
    let bytes = arquivo.as_bytes();
    if bytes.len() > 7 && bytes[..6].iter().all(|b| b.is_ascii_digit()) && bytes[6] == b'_' {
        arquivo[7..].to_string()
    } else {
        arquivo.to_string()
    }
}

/// ISO-8859-1 (Latin-1) → UTF-8. Em Latin-1 cada byte é exactamente o code
/// point Unicode com o mesmo valor, portanto o mapa é 1:1 e sem perdas.
fn latin1_para_utf8(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Parser de CSV mínimo mas correcto: separador configurável, aspas duplas com
/// `""` a escapar uma aspa, e campos que abrangem várias linhas dentro de aspas.
fn parse_csv(texto: &str, sep: char) -> Vec<Vec<String>> {
    let mut linhas = Vec::new();
    let mut campo = String::new();
    let mut linha: Vec<String> = Vec::new();
    let mut em_aspas = false;
    let mut chars = texto.chars().peekable();
    while let Some(c) = chars.next() {
        if em_aspas {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    campo.push('"');
                    chars.next();
                } else {
                    em_aspas = false;
                }
            } else {
                campo.push(c);
            }
        } else if c == '"' {
            em_aspas = true;
        } else if c == sep {
            linha.push(std::mem::take(&mut campo));
        } else if c == '\n' {
            linha.push(std::mem::take(&mut campo));
            linhas.push(std::mem::take(&mut linha));
        } else if c == '\r' {
            // ignora — o \n seguinte fecha a linha
        } else {
            campo.push(c);
        }
    }
    // Última linha sem \n final.
    if !campo.is_empty() || !linha.is_empty() {
        linha.push(campo);
        linhas.push(linha);
    }
    linhas
}

/// `{coluna: valor}` como JSON, com escape correcto. Colunas a mais/menos que o
/// cabeçalho são toleradas (linhas malformadas existem em dados reais).
fn linha_json(cabecalho: &[String], campos: &[String]) -> String {
    let mut s = String::from("{");
    for (i, col) in cabecalho.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        escapar_json(col, &mut s);
        s.push(':');
        escapar_json(campos.get(i).map(String::as_str).unwrap_or(""), &mut s);
    }
    s.push('}');
    s
}

fn escapar_json(v: &str, out: &mut String) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
