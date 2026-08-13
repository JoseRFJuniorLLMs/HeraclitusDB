//! Dataset: Quadro Societário (QSA) — Dados Abertos CNPJ da Receita Federal.
//! Kind: "Socio"
//!
//! Fonte: arquivos `*.SOCIOCSV` / `Socios*.csv` do repositório aberto da RFB
//! (https://dadosabertos.rfb.gov.br/CNPJ/). São **sem cabeçalho**, `;`-separados,
//! encoding Latin-1, com colunas POSICIONAIS:
//!   0 CNPJ_BASICO (8 díg)        1 IDENTIFICADOR_SOCIO (1=PJ,2=PF,3=estrang.)
//!   2 NOME_SOCIO / RAZÃO         3 CPF_CNPJ_SOCIO  (CPF mascarado `***XXXXXX**` p/ PF)
//!   4 QUALIFICACAO_SOCIO         5 DATA_ENTRADA_SOCIEDADE (YYYYMMDD)
//!   6 PAIS                       7 CPF_REPRESENTANTE_LEGAL
//!   8 NOME_REPRESENTANTE         9 QUALIFICACAO_REPRESENTANTE   10 FAIXA_ETARIA
//!
//! ## Por que isto é a peça-chave anti-fraude
//! Liga **sócio (CPF) ↔ empresa (CNPJ)**. Como a RFB mascara o CPF com os MESMOS
//! 6 dígitos do meio que o Portal (`***XXXXXX**` ≡ `***.XXX.XXX-**`), o
//! `cpf_fragmento` casa entre as bases: o RESOLVE liga **Socio ≈ Servidor** por
//! fragmento + nome, e `cnpj_basico` liga **Socio → Contrato** (empresa
//! fornecedora). Resultado: detecta servidor que é sócio de fornecedor da União.

use crate::utils::{enviar_lote, ler_csv_latin1, sanitizar};
use heraclitus_client::Client;
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

pub async fn ingerir(
    dir: &Path,
    nome_dir: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    // RFB distribui os sócios em vários ficheiros (Socios0..9). Processa todos.
    let csvs: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_uppercase();
            n.ends_with(".CSV") || n.contains("SOCIO")
        })
        .collect();

    if csvs.is_empty() {
        info!("  ⚠ Nenhum CSV de sócios em {}", dir.display());
        return Ok(0);
    }

    let mut total = 0u64;
    for csv_path in &csvs {
        info!("  📄 Sócios: {}", csv_path.display());
        total += ingerir_arquivo(csv_path, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }
    Ok(total)
}

async fn ingerir_arquivo(
    path: &Path,
    nome_dir: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let conteudo = ler_csv_latin1(path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .has_headers(false) // RFB: ficheiros SEM cabeçalho
        .flexible(true)
        .from_reader(conteudo.as_bytes());

    let get = |rec: &csv::StringRecord, i: usize| -> String {
        rec.get(i).map(sanitizar).unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);

    for result in reader.records() {
        let rec = result?;
        if rec.is_empty() {
            continue;
        }

        let cnpj_basico = get(&rec, 0);
        let tipo = match get(&rec, 1).as_str() {
            "1" => "PJ",
            "2" => "PF",
            "3" => "ESTRANGEIRO",
            _ => "?",
        };
        let nome_socio = get(&rec, 2);
        let cpf_cnpj = get(&rec, 3);
        if cnpj_basico.is_empty() || nome_socio.is_empty() {
            continue;
        }

        let mut attrs = HashMap::new();
        attrs.insert("cnpj_basico".into(), cnpj_basico.clone());
        attrs.insert("tipo_socio".into(), tipo.to_string());
        attrs.insert("nome_socio".into(), nome_socio.clone());
        // CPF mascarado (PF) ou CNPJ (PJ) do sócio — chave de RESOLVE p/ Servidor.
        attrs.insert("cpf_cnpj_socio".into(), cpf_cnpj.clone());
        attrs.insert("qualificacao".into(), get(&rec, 4));
        attrs.insert("data_entrada".into(), get(&rec, 5));
        attrs.insert("cpf_representante".into(), get(&rec, 7));
        attrs.insert("nome_representante".into(), get(&rec, 8));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content =
            format!("Socio {} | {} | empresa {}", nome_socio, tipo, cnpj_basico).into_bytes();
        lote.push(("Socio".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, "ingestor-socios").await;
            lote.clear();
        }
    }
    if !lote.is_empty() {
        total += enviar_lote(client, &lote, "ingestor-socios").await;
    }

    info!("    {} sócios ingeridos", total);
    Ok(total)
}
