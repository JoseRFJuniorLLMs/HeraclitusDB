//! Dataset: Licitações
//! Kind: "Licitacao" | "ItemLicitacao" | "ParticipanteLicitacao"
//! Fonte: *_Licitação.csv, *_ItemLicitação.csv, *_ParticipantesLicitação.csv

use crate::utils::{enviar_lote, ler_csv_latin1, sanitizar, sanitizar_valor};
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
    let mut total = 0u64;

    // Licitação principal
    if let Some(path) = encontrar_csv(dir, "LICITA") {
        if !path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_uppercase()
            .contains("ITEM")
            && !path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_uppercase()
                .contains("PARTICIP")
        {
            info!("  📄 Licitações: {}", path.display());
            total +=
                ingerir_licitacoes(&path, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
        }
    }

    // Todos os CSVs do diretório
    let csvs: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_uppercase();
            n.ends_with(".CSV")
        })
        .collect();

    for csv_path in &csvs {
        let nome_arq = csv_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_uppercase();
        let (kind, skip) = if nome_arq.contains("ITEM") {
            ("ItemLicitacao", false)
        } else if nome_arq.contains("PARTICIP") {
            ("ParticipanteLicitacao", false)
        } else if nome_arq.contains("EMPENHO") {
            ("EmpenhoLicitacao", false)
        } else {
            ("Licitacao", true) // já processado acima
        };

        if skip {
            continue;
        }

        info!("  📄 {}: {}", kind, csv_path.display());
        total += ingerir_csv_generico(
            csv_path,
            nome_dir,
            kind,
            client.as_deref_mut(),
            batch,
            dry_run,
        )
        .await?;
    }

    Ok(total)
}

fn encontrar_csv(dir: &Path, substr: &str) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_uppercase();
            n.ends_with(".CSV") && n.contains(substr)
        })
}

async fn ingerir_licitacoes(
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
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();
    let idx = |nome: &str| {
        h.iter().position(|x| {
            x.to_uppercase()
                .replace(['Ã', 'Á', 'À', 'Â'], "A")
                .replace(['Ó', 'Ô', 'Õ'], "O")
                .replace(['Ç'], "C")
                .replace(['Ê', 'É', 'È'], "E")
                .contains(nome)
        })
    };

    let i_num = idx("NUMERO LICITACAO").or_else(|| idx("NUMERO"));
    let i_ug = idx("NOME UG").or_else(|| idx("UG"));
    let i_modalidade = idx("MODALIDADE COMPRA").or_else(|| idx("MODALIDADE"));
    let i_processo = idx("NUMERO PROCESSO").or_else(|| idx("PROCESSO"));
    let i_objeto = idx("OBJETO");
    let i_situacao = idx("SITUACAO");
    let i_codsup = idx("CODIGO ORGAO SUPERIOR").or_else(|| idx("COD"));
    let i_orgsup = idx("NOME ORGAO SUPERIOR").or_else(|| idx("ORGAO"));
    let i_uf = idx("UF");
    let i_municipio = idx("MUNICIPIO").or_else(|| idx("MUNIC"));
    let i_dt_result = idx("DATA RESULTADO").or_else(|| idx("RESULTADO"));
    let i_dt_aber = idx("DATA ABERTURA").or_else(|| idx("ABERTURA"));
    let i_valor = idx("VALOR LICITACAO").or_else(|| idx("VALOR"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-licitacoes";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let num = get(&record, i_num);
        let objeto = get(&record, i_objeto);
        let valor = get(&record, i_valor);

        attrs.insert("numero_licitacao".into(), num.clone());
        attrs.insert("ug".into(), get(&record, i_ug));
        attrs.insert("modalidade".into(), get(&record, i_modalidade));
        attrs.insert("numero_processo".into(), get(&record, i_processo));
        attrs.insert("objeto".into(), objeto.clone());
        attrs.insert("situacao".into(), get(&record, i_situacao));
        attrs.insert("cod_orgao_superior".into(), get(&record, i_codsup));
        attrs.insert("orgao_superior".into(), get(&record, i_orgsup));
        attrs.insert("uf".into(), get(&record, i_uf));
        attrs.insert("municipio".into(), get(&record, i_municipio));
        attrs.insert("data_resultado".into(), get(&record, i_dt_result));
        attrs.insert("data_abertura".into(), get(&record, i_dt_aber));
        attrs.insert("valor".into(), sanitizar_valor(&valor));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("Licitacao {} | {} | Valor: {}", num, objeto, valor)
            .chars()
            .take(200)
            .collect::<String>()
            .into_bytes();

        lote.push(("Licitacao".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total licitações: {}", total);
    Ok(total)
}

async fn ingerir_csv_generico(
    path: &Path,
    nome_dir: &str,
    kind: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let conteudo = ler_csv_latin1(path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-licitacoes";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();
        for (col, val) in h.iter().zip(record.iter()) {
            if !col.is_empty() {
                attrs.insert(col.to_lowercase().replace(' ', "_"), sanitizar(val));
            }
        }
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = record
            .iter()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ")
            .into_bytes();

        lote.push((kind.to_string(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
            if total.is_multiple_of(50_000) {
                info!("    ... {} registros '{}' ingeridos", total, kind);
            }
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total {}: {}", kind, total);
    Ok(total)
}
