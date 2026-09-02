//! Dataset: Compliance e Investigação (Anti-Fraude)
//! Kind: "PunicaoCEIS" | "PunicaoCNEP" | "ImpedimentoCEPIM" | "ExpulsaoCEAF" | "GastoCartaoCPGF"
//! Fonte: Portal da Transparência (CEIS, CNEP, CEPIM, CEAF, CPGF)
//!
//! Campos-ponte preservados:
//!   - CEIS/CNEP: cnpj_sancionado (ou cpf_sancionado) -> liga a Fornecedores/Favorecidos
//!   - CEPIM: cnpj_entidade -> liga a Transferências (ONGs impedidas)
//!   - CEAF: cpf_punido -> liga a Servidor
//!   - CPGF: cpf_portador -> liga a Servidor, cnpj_favorecido -> liga a Empresa

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

    // 1. CEIS / CNEP (Punições de Empresas)
    if nome_dir.contains("_CEIS") {
        total += ingerir_punicoes(
            dir,
            nome_dir,
            "PunicaoCEIS",
            client.as_deref_mut(),
            batch,
            dry_run,
        )
        .await?;
    } else if nome_dir.contains("_CNEP") {
        total += ingerir_punicoes(
            dir,
            nome_dir,
            "PunicaoCNEP",
            client.as_deref_mut(),
            batch,
            dry_run,
        )
        .await?;
    }
    // 2. CEPIM (Impedimentos de ONGs)
    else if nome_dir.contains("_CEPIM") {
        total += ingerir_cepim(dir, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }
    // 3. CEAF (Servidores Expulsos)
    else if nome_dir.contains("_CEAF") {
        total += ingerir_ceaf(dir, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }
    // 4. CPGF (Cartão Corporativo)
    else if nome_dir.contains("_CPGF") && !nome_dir.contains("ComprasCentralizadas") {
        total += ingerir_cpgf(dir, nome_dir, client, batch, dry_run).await?;
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
            n.ends_with(".CSV") && n.contains(sufixo)
        })
}

async fn ingerir_punicoes(
    dir: &Path,
    nome_dir: &str,
    kind: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let path = match encontrar_csv(dir, "") {
        Some(p) => p,
        None => return Ok(0),
    };

    info!("  📄 Lendo Punições ({}): {}", kind, path.display());
    let conteudo = ler_csv_latin1(&path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_doc = idx("CPF OU CNPJ DO SANCIONADO");
    let i_nome = idx("NOME DO SANCIONADO");
    let i_cat = idx("CATEGORIA DA SANCAO");
    let i_inicio = idx("DATA INICIO SANCAO");
    let i_fim = idx("DATA FINAL SANCAO");

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = format!("ingestor-{}", kind.to_lowercase());

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let doc = get(&record, i_doc);
        let nome = get(&record, i_nome);

        attrs.insert("cnpj_sancionado".into(), doc.clone());
        attrs.insert("nome_sancionado".into(), nome.clone());
        attrs.insert("categoria_sancao".into(), get(&record, i_cat));
        attrs.insert("data_inicio".into(), get(&record, i_inicio));
        attrs.insert("data_fim".into(), get(&record, i_fim));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("{} | {} | {}", kind, doc, nome).into_bytes();
        lote.push((kind.to_string(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, &agent_id).await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, &agent_id).await;
    }

    Ok(total)
}

async fn ingerir_cepim(
    dir: &Path,
    nome_dir: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let path = match encontrar_csv(dir, "") {
        Some(p) => p,
        None => return Ok(0),
    };

    info!("  📄 Lendo CEPIM: {}", path.display());
    let conteudo = ler_csv_latin1(&path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_cnpj = idx("CNPJ ENTIDADE");
    let i_nome = idx("NOME ENTIDADE");
    let i_motivo = idx("MOTIVO DO IMPEDIMENTO");

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let cnpj = get(&record, i_cnpj);
        let nome = get(&record, i_nome);

        attrs.insert("cnpj_entidade".into(), cnpj.clone());
        attrs.insert("nome_entidade".into(), nome.clone());
        attrs.insert("motivo_impedimento".into(), get(&record, i_motivo));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("ImpedimentoCEPIM | {} | {}", cnpj, nome).into_bytes();
        lote.push(("ImpedimentoCEPIM".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, "ingestor-cepim").await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, "ingestor-cepim").await;
    }

    Ok(total)
}

async fn ingerir_ceaf(
    dir: &Path,
    nome_dir: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let path = match encontrar_csv(dir, "") {
        Some(p) => p,
        None => return Ok(0),
    };

    info!("  📄 Lendo CEAF: {}", path.display());
    let conteudo = ler_csv_latin1(&path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_cpf = idx("CPF OU CNPJ DO SANCIONADO");
    let i_nome = idx("NOME DO SANCIONADO");
    let i_cargo = idx("CARGO EFETIVO");
    let i_orgao = idx("ORGAO DE LOTACAO");

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let cpf = get(&record, i_cpf);
        let nome = get(&record, i_nome);

        attrs.insert("cpf_punido".into(), cpf.clone());
        attrs.insert("nome_sancionado".into(), nome.clone());
        attrs.insert("cargo_efetivo".into(), get(&record, i_cargo));
        attrs.insert("orgao_lotacao".into(), get(&record, i_orgao));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("ExpulsaoCEAF | {} | {}", cpf, nome).into_bytes();
        lote.push(("ExpulsaoCEAF".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, "ingestor-ceaf").await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, "ingestor-ceaf").await;
    }

    Ok(total)
}

async fn ingerir_cpgf(
    dir: &Path,
    nome_dir: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let path = match encontrar_csv(dir, "") {
        Some(p) => p,
        None => return Ok(0),
    };

    info!("  📄 Lendo CPGF: {}", path.display());
    let conteudo = ler_csv_latin1(&path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .quoting(true)
        .from_reader(conteudo.as_bytes());

    let headers = reader.headers()?.clone();
    let h: Vec<String> = headers.iter().map(sanitizar).collect();
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_cpf = idx("CPF PORTADOR");
    let i_nome = idx("NOME PORTADOR");
    let i_cnpj_fav = idx("CNPJ OU CPF FAVORECIDO");
    let i_nome_fav = idx("NOME FAVORECIDO");
    let i_valor = idx("VALOR TRANSACAO");
    let i_data = idx("DATA TRANSACAO");

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let cpf = get(&record, i_cpf);
        let cnpj_fav = get(&record, i_cnpj_fav);
        let valor = sanitizar_valor(&get(&record, i_valor));

        attrs.insert("cpf_portador".into(), cpf.clone());
        attrs.insert("nome_portador".into(), get(&record, i_nome));
        attrs.insert("cnpj_favorecido".into(), cnpj_fav.clone());
        attrs.insert("nome_favorecido".into(), get(&record, i_nome_fav));
        attrs.insert("valor".into(), valor.clone());
        attrs.insert("data_transacao".into(), get(&record, i_data));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!(
            "CPGF | Portador: {} | Empresa: {} | R$ {}",
            cpf, cnpj_fav, valor
        )
        .into_bytes();
        lote.push(("GastoCartaoCPGF".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, "ingestor-cpgf").await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, "ingestor-cpgf").await;
    }

    Ok(total)
}
