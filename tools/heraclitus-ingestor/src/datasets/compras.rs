//! Dataset: Compras / Contratos
//! Kind: "Contrato" | "ItemContrato" | "TermoAditivo" | "Apostilamento"
//! Fonte: *_Compras.csv, *_ItemCompra.csv, *_TermoAditivo.csv, *_Apostilamento.csv
//!
//! Campos-ponte preservados:
//!   Contrato: numero_contrato, numero_licitacao, cod_orgao_superior, cod_orgao, codigo_contratado
//!   ItemContrato: numero_contrato, codigo_item_compra, cod_orgao
//!   TermoAditivo / Apostilamento: numero_contrato

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

    // Contrato principal
    if let Some(path) = encontrar_csv(dir, "COMPRAS") {
        info!("  📄 Contratos: {}", path.display());
        total += ingerir_contratos(&path, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }

    // Itens do contrato
    if let Some(path) = encontrar_csv(dir, "ITEMCOMPRA").or_else(|| encontrar_csv(dir, "ITEM")) {
        info!("  📄 Itens: {}", path.display());
        total += ingerir_genericos(
            &path,
            nome_dir,
            "ItemContrato",
            client.as_deref_mut(),
            batch,
            dry_run,
        )
        .await?;
    }

    // Termos aditivos
    if let Some(path) = encontrar_csv(dir, "TERMOADITIVO").or_else(|| encontrar_csv(dir, "TERMO")) {
        info!("  📄 Termos aditivos: {}", path.display());
        total += ingerir_genericos(
            &path,
            nome_dir,
            "TermoAditivo",
            client.as_deref_mut(),
            batch,
            dry_run,
        )
        .await?;
    }

    // Apostilamentos (antes ignorados)
    if let Some(path) = encontrar_csv(dir, "APOSTILAMENTO") {
        info!("  📄 Apostilamentos: {}", path.display());
        total +=
            ingerir_genericos(&path, nome_dir, "Apostilamento", client, batch, dry_run).await?;
    }

    Ok(total)
}

fn encontrar_csv(dir: &Path, sufixo: &str) -> Option<std::path::PathBuf> {
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
            n.ends_with(".CSV") && n.replace(['_', ' '], "").contains(sufixo)
        })
}

async fn ingerir_contratos(
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
                .contains(nome)
        })
    };

    let i_num = idx("NUMERO DO CONTRATO").or_else(|| idx("NUMERO"));
    let i_objeto = idx("OBJETO");
    let i_modalidade = idx("MODALIDADE COMPRA").or_else(|| idx("MODALIDADE"));
    let i_situacao = idx("SITUACAO CONTRATO").or_else(|| idx("SITUACAO"));
    let i_codsup = idx("CODIGO ORGAO SUPERIOR").or_else(|| idx("COD"));
    let i_orgsup = idx("NOME ORGAO SUPERIOR").or_else(|| idx("NOME ORGAO SUP"));
    let i_codorg = idx("CODIGO ORGAO").or_else(|| idx("CODIGO UG"));
    let i_org = idx("NOME ORGAO");
    let i_codug = idx("CODIGO UG").or_else(|| idx("COD UG"));
    let i_nomug = idx("NOME UG");
    let i_contratado = idx("NOME CONTRATADO").or_else(|| idx("CONTRATADO"));
    let i_cod_cont = idx("CODIGO CONTRATADO");
    let i_val_ini = idx("VALOR INICIAL");
    let i_val_fin = idx("VALOR FINAL");
    let i_dt_ass = idx("DATA ASSINATURA").or_else(|| idx("DATA ASS"));
    let i_dt_pub = idx("DATA PUBLICACAO").or_else(|| idx("DATA PUB"));
    let i_dt_ini = idx("DATA INICIO VIGENCIA").or_else(|| idx("DATA INICIO"));
    let i_dt_fim = idx("DATA FIM VIGENCIA").or_else(|| idx("DATA FIM"));
    let i_fundamento = idx("FUNDAMENTO LEGAL").or_else(|| idx("FUNDAMENTO"));
    // CAMPO-PONTE CRÍTICO: liga Contrato → Licitação no grafo
    let i_num_licit = idx("NUMERO LICITACAO").or_else(|| idx("LICITACAO"));
    let i_ug_licit = idx("CODIGO UG LICITACAO").or_else(|| idx("UG LICIT"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-contratos";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let num = get(&record, i_num);
        let contratado = get(&record, i_contratado);
        let val_fin = get(&record, i_val_fin);

        attrs.insert("numero_contrato".into(), num.clone());
        attrs.insert("objeto".into(), get(&record, i_objeto));
        attrs.insert("modalidade".into(), get(&record, i_modalidade));
        attrs.insert("situacao".into(), get(&record, i_situacao));
        attrs.insert("cod_orgao_superior".into(), get(&record, i_codsup));
        attrs.insert("orgao_superior".into(), get(&record, i_orgsup));
        attrs.insert("cod_orgao".into(), get(&record, i_codorg));
        attrs.insert("orgao".into(), get(&record, i_org));
        attrs.insert("cod_ug".into(), get(&record, i_codug));
        attrs.insert("nome_ug".into(), get(&record, i_nomug));
        attrs.insert("contratado".into(), contratado.clone());
        let cod_cont = get(&record, i_cod_cont);
        attrs.insert("codigo_contratado".into(), cod_cont.clone());
        // CAMPO-PONTE p/ QSA: raiz do CNPJ (8 díg) liga a Socio.cnpj_basico.
        let cnpj_basico: String = cod_cont
            .chars()
            .filter(|c| c.is_ascii_digit())
            .take(8)
            .collect();
        if cnpj_basico.len() == 8 {
            attrs.insert("cnpj_basico_contratado".into(), cnpj_basico);
        }
        attrs.insert(
            "valor_inicial".into(),
            sanitizar_valor(&get(&record, i_val_ini)),
        );
        attrs.insert("valor_final".into(), sanitizar_valor(&val_fin));
        attrs.insert("data_assinatura".into(), get(&record, i_dt_ass));
        attrs.insert("data_publicacao_dou".into(), get(&record, i_dt_pub));
        attrs.insert("data_inicio".into(), get(&record, i_dt_ini));
        attrs.insert("data_fim".into(), get(&record, i_dt_fim));
        attrs.insert("fundamento_legal".into(), get(&record, i_fundamento));
        // CAMPO-PONTE: FK → Licitacao (numero_licitacao)
        attrs.insert("numero_licitacao".into(), get(&record, i_num_licit));
        attrs.insert("cod_ug_licitacao".into(), get(&record, i_ug_licit));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!(
            "Contrato {} | Contratado: {} | Valor: {}",
            num, contratado, val_fin
        )
        .into_bytes();

        lote.push(("Contrato".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total contratos: {}", total);
    Ok(total)
}

async fn ingerir_genericos(
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
    let agent_id = "ingestor-compras";

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
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total {}: {}", kind, total);
    Ok(total)
}
