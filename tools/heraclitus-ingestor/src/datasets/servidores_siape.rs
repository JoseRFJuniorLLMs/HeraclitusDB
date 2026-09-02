//! Dataset: Servidores SIAPE / Aposentados / Pensionistas / BACEN
//! Kind: "Servidor" | "Remuneracao" | "Afastamento" | "ObservacaoServidor"
//!      | "Aposentado" | "Pensionista" | "ServidorBACEN"
//! Fonte: *_Cadastro.csv, *_Remuneracao.csv, *_Afastamentos.csv, *_Observacoes.csv
//!
//! Campos Cadastro: id_servidor, cpf_mascarado, matricula_mascarada,
//!   cargo, classe, padrao, nivel, funcao, orgao, uf_exercicio,
//!   situacao_vinculo, jornada, data_ingresso_orgao, tipo_vinculo
//!
//! Campos Remuneração: id_servidor, remuneracao_basica, gratificacao,
//!   adicional_qualificacao, remuneracao_apos_deducoes, abate_teto, verbas_indenizatorias
//!
//! Campos Afastamentos: id_servidor, data_inicio_afastamento, data_fim_afastamento
//!
//! Campos Observações: id_servidor, observacao

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

    // Processar Cadastro
    if let Some(path) = encontrar_csv(dir, "CADASTRO") {
        info!("  📄 Lendo: {}", path.display());
        total += ingerir_cadastro(&path, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }

    // Processar Remuneração
    if let Some(path) = encontrar_csv(dir, "REMUNERACAO") {
        info!("  📄 Lendo: {}", path.display());
        total +=
            ingerir_remuneracao(&path, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }

    // Processar Afastamentos (SIAPE e BACEN)
    if let Some(path) = encontrar_csv(dir, "AFASTAMENTO") {
        info!("  📄 Lendo: {}", path.display());
        total +=
            ingerir_afastamentos(&path, nome_dir, client.as_deref_mut(), batch, dry_run).await?;
    }

    // Processar Observações
    if let Some(path) = encontrar_csv(dir, "OBSERVACAO") {
        info!("  📄 Lendo: {}", path.display());
        total += ingerir_observacoes(&path, nome_dir, client, batch, dry_run).await?;
    }

    Ok(total)
}

/// Carga genérica para Aposentados, Pensionistas, BACEN (mesma estrutura)
pub async fn ingerir_generico(
    dir: &Path,
    nome_dir: &str,
    client: Option<&mut Client>,
    batch: usize,
    dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let kind = if nome_dir.to_uppercase().contains("APOSENTADO") {
        "Aposentado"
    } else if nome_dir.to_uppercase().contains("PENSIONISTA") {
        "Pensionista"
    } else {
        "ServidorBACEN"
    };
    ingerir_csv_generico(dir, nome_dir, kind, client, batch, dry_run).await
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

async fn ingerir_cadastro(
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
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_id = idx("ID_SERVIDOR").or_else(|| idx("ID_SER"));
    let i_cpf = idx("CPF");
    let i_nome = idx("NOME");
    let i_cargo = idx("DESCRICAO_CARGO").or_else(|| idx("CARGO"));
    let i_classe = idx("CLASSE_CARGO");
    let i_funcao = idx("FUNCAO");
    let i_org = idx("ORG_LOTACAO");
    let i_orgsup = idx("ORGSUP_LOTACAO");
    let i_vinculo = idx("TIPO_VINCULO");
    let i_situacao = idx("SITUACAO_VINCULO");
    let i_jornada = idx("JORNADA_DE_TRABALHO").or_else(|| idx("JORNADA"));
    let i_dt_org = idx("DATA_INGRESSO_ORGAO");
    let i_uf = idx("UF_EXERCICIO").or_else(|| idx("UF"));
    let i_regime = idx("REGIME_JURIDICO");

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-servidores";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let id = get(&record, i_id);
        let cpf = get(&record, i_cpf);
        let nome = get(&record, i_nome);
        let cargo = get(&record, i_cargo);
        let org = get(&record, i_org);
        let uf = get(&record, i_uf);

        attrs.insert("id_servidor".into(), id.clone());
        attrs.insert("cpf".into(), cpf.clone());
        attrs.insert("nome".into(), nome.clone());
        attrs.insert("cargo".into(), cargo.clone());
        attrs.insert("classe_cargo".into(), get(&record, i_classe));
        attrs.insert("funcao".into(), get(&record, i_funcao));
        attrs.insert("orgao".into(), org.clone());
        attrs.insert("orgao_superior".into(), get(&record, i_orgsup));
        attrs.insert("tipo_vinculo".into(), get(&record, i_vinculo));
        attrs.insert("situacao".into(), get(&record, i_situacao));
        attrs.insert("jornada".into(), get(&record, i_jornada));
        attrs.insert("data_ingresso_orgao".into(), get(&record, i_dt_org));
        attrs.insert("uf_exercicio".into(), uf.clone());
        attrs.insert("regime_juridico".into(), get(&record, i_regime));
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("Servidor {} | {} | {} | {}", id, cargo, org, uf).into_bytes();

        lote.push(("Servidor".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
            if total.is_multiple_of(50_000) {
                info!("    ... {} servidores ingeridos", total);
            }
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total cadastros: {}", total);
    Ok(total)
}

async fn ingerir_remuneracao(
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
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_id = idx("ID_SERVIDOR").or_else(|| idx("ID_SER"));
    let i_rem_basica = idx("REMUNERACAO_BASICA_BRUTA").or_else(|| idx("REMUNERACAO"));
    let i_grat = idx("GRATIFICACAO_NATALINA");
    let i_ferias = idx("FERIAS");
    let i_outras = idx("OUTRAS_REMUNERACOES");
    let i_apos_ded = idx("REMUNERACAO_APOS_DEDUCOES");
    let i_teto = idx("ABATE_TETO");
    let i_verbas = idx("VERBAS_INDENIZATORIAS");
    let i_total = idx("TOTAL_DE_RENDIMENTOS_LIQUIDOS").or_else(|| idx("TOTAL"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-remuneracao";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let id = get(&record, i_id);
        let rem = get(&record, i_rem_basica);

        attrs.insert("id_servidor".into(), id.clone());
        attrs.insert("remuneracao_basica".into(), sanitizar_valor(&rem));
        attrs.insert(
            "gratificacao_natalina".into(),
            sanitizar_valor(&get(&record, i_grat)),
        );
        attrs.insert("ferias".into(), sanitizar_valor(&get(&record, i_ferias)));
        attrs.insert(
            "outras_remuneracoes".into(),
            sanitizar_valor(&get(&record, i_outras)),
        );
        attrs.insert(
            "rem_apos_deducoes".into(),
            sanitizar_valor(&get(&record, i_apos_ded)),
        );
        attrs.insert("abate_teto".into(), sanitizar_valor(&get(&record, i_teto)));
        attrs.insert(
            "verbas_indenizatorias".into(),
            sanitizar_valor(&get(&record, i_verbas)),
        );
        attrs.insert(
            "total_rendimentos".into(),
            sanitizar_valor(&get(&record, i_total)),
        );
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("Remuneracao {} | Basica: {}", id, rem).into_bytes();
        lote.push(("Remuneracao".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
            if total.is_multiple_of(50_000) {
                info!("    ... {} remunerações ingeridas", total);
            }
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total remunerações: {}", total);
    Ok(total)
}

/// Ingestão de Afastamentos — Kind: `Afastamento`
/// Campos: id_servidor, data_inicio_afastamento, data_fim_afastamento, dataset
async fn ingerir_afastamentos(
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
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_id = idx("ID_SERVIDOR").or_else(|| idx("ID_SER"));
    let i_inicio = idx("DATA_INICIO_AFASTAMENTO").or_else(|| idx("INICIO"));
    let i_fim = idx("DATA_FIM_AFASTAMENTO")
        .or_else(|| idx("DATA_TERMINO_AFASTAMENTO"))
        .or_else(|| idx("FIM"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-afastamentos";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let id = get(&record, i_id);
        let inicio = get(&record, i_inicio);
        let fim = get(&record, i_fim);

        attrs.insert("id_servidor".into(), id.clone());
        attrs.insert("data_inicio_afastamento".into(), inicio.clone());
        attrs.insert("data_fim_afastamento".into(), fim.clone());
        attrs.insert("dataset".into(), nome_dir.to_string());

        let content = format!("Afastamento {} | {} → {}", id, inicio, fim).into_bytes();
        lote.push(("Afastamento".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
            if total.is_multiple_of(10_000) {
                info!("    ... {} afastamentos ingeridos", total);
            }
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total afastamentos: {}", total);
    Ok(total)
}

/// Ingestão de Observações — Kind: `ObservacaoServidor`
/// Campos: id_servidor, observacao, dataset
async fn ingerir_observacoes(
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
    let idx = |nome: &str| h.iter().position(|x| x.to_uppercase().contains(nome));

    let i_id = idx("ID_SERVIDOR").or_else(|| idx("ID_SER"));
    let i_obs = idx("OBSERVACAO").or_else(|| idx("OBS"));

    let get = |record: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| record.get(i))
            .map(sanitizar)
            .unwrap_or_default()
    };

    let mut total = 0u64;
    let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);
    let agent_id = "ingestor-observacoes";

    for result in reader.records() {
        let record = result?;
        let mut attrs = HashMap::new();

        let id = get(&record, i_id);
        let obs = get(&record, i_obs);

        attrs.insert("id_servidor".into(), id.clone());
        attrs.insert("observacao".into(), obs.clone());
        attrs.insert("dataset".into(), nome_dir.to_string());

        // O texto da observação é rico semanticamente — bom para busca vetorial/textual
        let content = format!("Observacao {} | {}", id, obs).into_bytes();
        lote.push(("ObservacaoServidor".into(), content, attrs));

        if lote.len() >= batch {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
            lote.clear();
        }
    }

    if !lote.is_empty() {
        total += enviar_lote(client, &lote, agent_id).await;
    }

    info!("  Total observações: {}", total);
    Ok(total)
}

/// Carga genérica: lê qualquer CSV com separador ";" e converte cada linha em Observation
async fn ingerir_csv_generico(
    dir: &Path,
    nome_dir: &str,
    kind: &str,
    mut client: Option<&mut Client>,
    batch: usize,
    _dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let mut total = 0u64;
    let agent_id = "ingestor-generico";

    let csvs: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|e| e.to_string_lossy().to_uppercase() == "CSV")
                .unwrap_or(false)
        })
        .collect();

    for csv_path in csvs {
        info!("  📄 Lendo: {}", csv_path.display());
        let conteudo = ler_csv_latin1(&csv_path)?;
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(b';')
            .quoting(true)
            .from_reader(conteudo.as_bytes());

        let headers = reader.headers()?.clone();
        let h: Vec<String> = headers.iter().map(sanitizar).collect();

        let mut lote: Vec<(String, Vec<u8>, HashMap<String, String>)> = Vec::with_capacity(batch);

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
                if total.is_multiple_of(10_000) {
                    info!("    ... {} registros ingeridos", total);
                }
            }
        }

        if !lote.is_empty() {
            total += enviar_lote(client.as_deref_mut(), &lote, agent_id).await;
        }
    }

    Ok(total)
}
