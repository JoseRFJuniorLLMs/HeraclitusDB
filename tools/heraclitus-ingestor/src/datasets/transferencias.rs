//! Dataset: Transferências (repasses, convênios, etc.)
//! Kind: "Transferencia"
//! Fonte: *_Transferencias.csv

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
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let csv_path = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_uppercase();
            n.ends_with(".CSV") && n.contains("TRANSFER")
        })
        .ok_or_else(|| format!("Nenhum CSV de Transferências em {}", dir.display()))?;

    info!("  📄 Lendo: {}", csv_path.display());
    let conteudo = ler_csv_latin1(&csv_path)?;
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

    let i_anomes = idx("ANO");
    let i_tipo = idx("TIPO TRANSFERENCIA").or_else(|| idx("TIPO"));
    let i_nome_trans = idx("NOME TRANSFERENCIA").or_else(|| idx("NOME TRANSF"));
    let i_cod_org = idx("CODIGO ORGAO SUPERIOR").or_else(|| idx("COD"));
    let i_org = idx("NOME ORGAO SUPERIOR").or_else(|| idx("ORGAO"));
    let i_favorecido = idx("NOME FAVORECIDO").or_else(|| idx("FAVORECIDO"));
    let i_cnpj_cpf = idx("CNPJ/CPF FAVORECIDO").or_else(|| idx("CNPJ"));
    let i_uf = idx("UF");
    let i_municipio = idx("MUNICIPIO").or_else(|| idx("MUNIC"));
    let i_valor = idx("VALOR TRANSFERIDO").or_else(|| idx("VALOR"));
    let i_acao = idx("ACAO").or_else(|| idx("PROGRAMA"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-transferencias";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let anomes = get(&record, i_anomes);
        let favorecido = get(&record, i_favorecido);
        let valor = get(&record, i_valor);

        attrs.insert("ano_mes".into(), anomes.clone());
        attrs.insert("tipo".into(), get(&record, i_tipo));
        attrs.insert("nome_transferencia".into(), get(&record, i_nome_trans));
        attrs.insert("cod_orgao_superior".into(), get(&record, i_cod_org));
        attrs.insert("orgao".into(), get(&record, i_org));
        attrs.insert("favorecido".into(), favorecido.clone());
        attrs.insert("cnpj_cpf".into(), get(&record, i_cnpj_cpf));
        attrs.insert("uf".into(), get(&record, i_uf));
        attrs.insert("municipio".into(), get(&record, i_municipio));
        attrs.insert("valor".into(), sanitizar_valor(&valor));
        attrs.insert("acao".into(), get(&record, i_acao));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content =
            format!("{} | Favorecido: {} | Valor: {}", anomes, favorecido, valor).into_bytes();

        lote.push(("Transferencia".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(
                unsafe { std::mem::transmute(client.as_deref_mut()) },
                &lote,
                agent_id,
            )
            .await;
            lote.clear();
            if total.is_multiple_of(50_000) {
                info!("    ... {} transferências ingeridas", total);
            }
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(unsafe { std::mem::transmute(client) }, &lote, agent_id).await;
    }

    info!("  Total transferências: {}", total);
    Ok(total)
}
