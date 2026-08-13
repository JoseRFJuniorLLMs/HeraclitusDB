//! Dataset: Despesas Orçamentárias
//! Kind: "Despesa"
//! Fonte: *_Despesas.csv (separador ";", encoding Windows-1252)
//!
//! Campos mapeados:
//!   ano_mes, cod_orgao_superior, orgao_superior, cod_orgao, orgao,
//!   funcao, subfuncao, programa, acao, categoria_economica,
//!   grupo_despesa, elemento_despesa, modalidade,
//!   valor_empenhado, valor_liquidado, valor_pago, uf, municipio

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
    // Encontrar o arquivo CSV de Despesas (não "(1)")
    let csv_path = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_uppercase();
            n.ends_with(".CSV") && n.contains("DESPESA") && !n.contains("(1)")
        })
        .ok_or_else(|| format!("Nenhum CSV de Despesas em {}", dir.display()))?;

    info!("  📄 Lendo: {}", csv_path.display());

    let conteudo = ler_csv_latin1(&csv_path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();

    // Índices das colunas de interesse
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_anomes = idx("ANO");
    let i_codsup = idx("CÓDIGO ÓRGÃO SUPERIOR").or_else(|| idx("COD"));
    let i_orgsup = idx("NOME ÓRGÃO SUPERIOR").or_else(|| idx("NOME ÓRGÃO SUP"));
    let i_codorg = idx("CÓDIGO ÓRGÃO SUBORDINADO");
    let i_org = idx("NOME ÓRGÃO SUBORDINADO");
    let i_funcao = idx("NOME FUNÇÃO");
    let i_subfuncao = idx("NOME SUBFUNÇÃO").or_else(|| idx("NOME SUBFUN"));
    let i_programa = idx("NOME PROGRAMA ORÇAMENTÁRIO").or_else(|| idx("PROGRAMA"));
    let i_acao = idx("NOME AÇÃO");
    let i_cat = idx("NOME CATEGORIA ECONÔMICA").or_else(|| idx("CATEGORIA"));
    let i_grupo = idx("NOME GRUPO DE DESPESA").or_else(|| idx("GRUPO"));
    let i_elemento = idx("NOME ELEMENTO DE DESPESA").or_else(|| idx("ELEMENTO"));
    let i_modalidade = idx("MODALIDADE DA DESPESA");
    let i_val_emp = idx("VALOR EMPENHADO");
    let i_val_liq = idx("VALOR LIQUIDADO");
    let i_val_pago = idx("VALOR PAGO");
    let i_uf = idx("UF");
    let i_municipio = idx("MUNICÍPIO").or_else(|| idx("MUNICIPIO"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-despesas";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let anomes = get(&record, i_anomes);
        let orgao = get(&record, i_org);
        let val_pago = get(&record, i_val_pago);

        attrs.insert("ano_mes".into(), anomes.clone());
        attrs.insert("cod_orgao_superior".into(), get(&record, i_codsup));
        attrs.insert("orgao_superior".into(), get(&record, i_orgsup));
        attrs.insert("cod_orgao".into(), get(&record, i_codorg));
        attrs.insert("orgao".into(), orgao.clone());
        attrs.insert("funcao".into(), get(&record, i_funcao));
        attrs.insert("subfuncao".into(), get(&record, i_subfuncao));
        attrs.insert("programa".into(), get(&record, i_programa));
        attrs.insert("acao".into(), get(&record, i_acao));
        attrs.insert("categoria_economica".into(), get(&record, i_cat));
        attrs.insert("grupo_despesa".into(), get(&record, i_grupo));
        attrs.insert("elemento_despesa".into(), get(&record, i_elemento));
        attrs.insert("modalidade".into(), get(&record, i_modalidade));
        attrs.insert(
            "valor_empenhado".into(),
            sanitizar_valor(&get(&record, i_val_emp)),
        );
        attrs.insert(
            "valor_liquidado".into(),
            sanitizar_valor(&get(&record, i_val_liq)),
        );
        attrs.insert("valor_pago".into(), sanitizar_valor(&val_pago));
        attrs.insert("uf".into(), get(&record, i_uf));
        attrs.insert("municipio".into(), get(&record, i_municipio));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("{} | {} | Pago: {}", anomes, orgao, val_pago).into_bytes();

        lote.push(("Despesa".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(
                // SAFETY: transmute de vida — necessário pelo padrão do código de lote
                unsafe { std::mem::transmute(client.as_deref_mut()) },
                &lote,
                agent_id,
            )
            .await;
            lote.clear();
            if total.is_multiple_of(10_000) {
                info!("    ... {} despesas ingeridas", total);
            }
        }
    }

    // Enviar restante
    if !lote.is_empty() {
        total += enviar_lote(unsafe { std::mem::transmute(client) }, &lote, agent_id).await;
        lote.clear();
    }

    info!("  Total despesas: {}", total);
    Ok(total)
}
