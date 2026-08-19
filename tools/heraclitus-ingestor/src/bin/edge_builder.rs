//! edge-builder — pós-processador de arestas para o HeraclitusDB
//!
//! Lê eventos já ingeridos via GQL (`MATCH (n:Kind) RETURN n`),
//! aplica as EdgeRules definidas em `datasets::edge_rules` e emite
//! arestas como eventos de kind "Edge" no log imutável.
//!
//! As arestas são IDEMPOTENTES: o campo `edge_id` é determinístico
//! (hash blake3 de "from_lsn|relation|to_lsn"), então re-executar
//! o edge-builder não duplica arestas no grafo.
//!
//! Uso:
//!   edge-builder --server http://127.0.0.1:7474 [--dry-run] [--rule TEM_REMUNERACAO]

// Ferramenta ETL (fora do core): dead_code intencional — este binário reutiliza
// só um subconjunto dos módulos de datasets partilhados. Silencia o ruído de
// estilo para o clippy do CI (o core fica clippy-clean sem allows).
#![allow(
    dead_code,
    clippy::redundant_closure,
    clippy::manual_is_multiple_of,
    clippy::missing_transmute_annotations, // clap derive macro-generated
    clippy::doc_lazy_continuation
)]

// edge_builder vive em src/bin/, mas partilha os módulos de src/. Aponta para eles.
#[path = "../datasets/mod.rs"]
mod datasets;
#[path = "../utils.rs"]
mod utils;

use clap::Parser;
use datasets::edge_rules::{todas_as_regras, EdgeRule};
use datasets::resolve::{processar_resolucao, todas_as_resolucoes};
use datasets::scan::{coletar_kind, descobrir_head};
use heraclitus_client::{AppendOptions, Client};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "edge-builder",
    about = "Constrói arestas de grafo no HeraclitusDB a partir dos eventos ingeridos"
)]
struct Cli {
    /// Endereço gRPC do HeraclitusDB
    #[arg(long, default_value = "http://127.0.0.1:7474")]
    server: String,

    /// Apenas simula — não envia eventos
    #[arg(long)]
    dry_run: bool,

    /// Executar apenas esta regra (ex: TEM_REMUNERACAO). Omitir = todas.
    #[arg(long)]
    rule: Option<String>,

    /// Limite de eventos por kind (0 = sem limite — útil para testes)
    #[arg(long, default_value_t = 0)]
    limit: usize,

    /// Bearer token RBAC (ver `--token-file`, preferível).
    #[arg(long)]
    token: Option<String>,

    /// Ficheiro com o token (ex.: `secrets-v1/writer.token`).
    #[arg(long)]
    token_file: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  HeraclitusDB — Edge Builder (grafo de relações)        ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("  Servidor  : {}", cli.server);
    if cli.dry_run {
        warn!("  MODO DRY-RUN — nenhuma aresta será gravada");
    }

    // Mesmo problema do ingestor: sem bearer token, um servidor com RBAC
    // recusa a primeira query e o edge-builder morre antes de ler um nó.
    let token = match &cli.token_file {
        Some(p) => {
            let t = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("nao foi possivel ler {}: {e}", p.display()))?
                .trim()
                .to_string();
            if t.is_empty() {
                anyhow::bail!("ficheiro de token vazio: {}", p.display());
            }
            Some(t)
        }
        None => cli
            .token
            .clone()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty()),
    };
    let mut client = if !cli.dry_run {
        info!("Conectando ao HeraclitusDB...");
        let c = Client::connect(cli.server.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Falha ao conectar: {e}"))?;
        Some(match &token {
            Some(t) => c
                .with_bearer_token(t)
                .map_err(|e| anyhow::anyhow!("token invalido para cabecalho HTTP: {e}"))?,
            None => c,
        })
    } else {
        None
    };
    info!("Conexão estabelecida ✓");

    // head do log: limita o loop de varredura por janelas (contorna o cap 250k).
    let head = match client.as_mut() {
        Some(c) => {
            let h = descobrir_head(c).await?;
            info!(
                "  Head ~{} (varredura por janelas de {} eventos)",
                h,
                datasets::scan::SCAN_WINDOW
            );
            h
        }
        None => 0,
    };

    let regras = todas_as_regras();
    let regras_ativas: Vec<&EdgeRule> = regras
        .iter()
        .filter(|r| {
            cli.rule
                .as_deref()
                .map(|nome| r.relation == nome)
                .unwrap_or(true)
        })
        .collect();
    let resolucoes = todas_as_resolucoes();
    let resolucoes_ativas: Vec<_> = resolucoes
        .iter()
        .filter(|r| cli.rule.as_deref().map(|n| r.relation == n).unwrap_or(true))
        .collect();
    info!(
        "Regras ativas: {} edge + {} resolve",
        regras_ativas.len(),
        resolucoes_ativas.len()
    );

    // #4 — CACHE POR KIND: coleta cada kind único UMA vez (em vez de re-varrer o
    // log por regra). Muitas regras partilham kinds (Servidor, Contrato, …), por
    // isso a varredura passa de O(regras×2) para O(kinds únicos).
    let mut cache: HashMap<String, serde_json::Value> = HashMap::new();
    if let Some(c) = client.as_mut() {
        let mut kinds: Vec<&str> = Vec::new();
        for r in &regras_ativas {
            kinds.push(r.from_kind);
            kinds.push(r.to_kind);
        }
        for r in &resolucoes_ativas {
            kinds.push(r.from_kind);
            kinds.push(r.to_kind);
        }
        kinds.sort_unstable();
        kinds.dedup();
        info!(
            "Pré-coletando {} kinds únicos (1 varredura cada)...",
            kinds.len()
        );
        for k in kinds {
            let mut rows = coletar_kind(c, k, head).await?;
            // `--limit` estava DECLARADA e nunca lida: prometia uma válvula de
            // segurança para testes que não existia. Importa porque o cache
            // guarda TODOS os nós de TODOS os kinds em RAM ao mesmo tempo, como
            // `serde_json::Value` — a ~500-1000 B por nó, os 21 kinds das
            // regras num log de 10M pedem vários GB, e sem teto o processo
            // morre a meio em vez de dar um resultado parcial útil.
            if cli.limit > 0 {
                if let Some(a) = rows.as_array_mut() {
                    if a.len() > cli.limit {
                        warn!(
                            "   '{k}': {} nós truncados para {} por --limit — as arestas \
                             deste kind ficam INCOMPLETAS",
                            a.len(),
                            cli.limit
                        );
                        a.truncate(cli.limit);
                    }
                }
            }
            cache.insert(k.to_string(), rows);
        }
    }

    let mut total_arestas = 0u64;

    for regra in &regras_ativas {
        info!("─────────────────────────────────────────");
        info!(
            "🔗 Regra: {} [{}→{}]",
            regra.relation, regra.from_kind, regra.to_kind
        );
        info!("   {}", regra.descricao);

        let n = processar_regra(regra, &cache, client.as_mut(), cli.dry_run).await?;
        info!("   ✓ {} arestas emitidas", n);
        total_arestas += n;
    }

    // ── Passe de RESOLVE — ligações por identidade quando o CPF é mascarado ──
    if !resolucoes_ativas.is_empty() {
        info!("─────────────────────────────────────────");
        info!(
            "🧬 RESOLVE — {} regra(s) de entity resolution",
            resolucoes_ativas.len()
        );
        for regra in &resolucoes_ativas {
            info!(
                "🔗 {} [{}≈{}]",
                regra.relation, regra.from_kind, regra.to_kind
            );
            info!("   {}", regra.descricao);
            let n = processar_resolucao(regra, &cache, client.as_mut(), cli.dry_run).await?;
            total_arestas += n;
        }
    }

    info!("═════════════════════════════════════════════════════════");
    info!("✅ EDGE-BUILDER CONCLUÍDO");
    info!("   Total de arestas : {}", total_arestas);

    if let Some(ref mut c) = client {
        info!("Selando segmento final (snapshot)...");
        match c.snapshot().await {
            Ok(lsn) => info!("  Snapshot em LSN {lsn} ✓"),
            Err(e) => warn!("  Aviso no snapshot: {e}"),
        }
    }

    Ok(())
}

/// Processa uma única EdgeRule:
/// 1. Busca todos os eventos do `from_kind` → constrói índice from_attr → lsn
/// 2. Busca todos os eventos do `to_kind`   → constrói índice to_attr → lsn
/// 3. Para cada par (from_lsn, to_lsn) que casa, emite uma aresta
async fn processar_regra(
    regra: &EdgeRule,
    cache: &HashMap<String, serde_json::Value>,
    mut client: Option<&mut Client>,
    dry_run: bool,
) -> anyhow::Result<u64> {
    // ── Passo 1: indexar eventos de origem a partir do cache (já varrido) ────
    let from_index: HashMap<String, Vec<(String, String)>> = match cache.get(regra.from_kind) {
        Some(val) => construir_indice(val, regra.from_attr),
        None => HashMap::new(),
    };

    if from_index.is_empty() {
        warn!("  Nenhum evento encontrado para kind '{}'", regra.from_kind);
        return Ok(0);
    }
    info!(
        "  {} chaves distintas em '{}'",
        from_index.len(),
        regra.from_kind
    );

    // ── Passo 2: indexar eventos de destino a partir do cache ───────────────
    let to_index: HashMap<String, Vec<(String, String)>> = match cache.get(regra.to_kind) {
        Some(val) => construir_indice(val, regra.to_attr),
        None => HashMap::new(),
    };

    if to_index.is_empty() {
        warn!("  Nenhum evento encontrado para kind '{}'", regra.to_kind);
        return Ok(0);
    }
    info!(
        "  {} chaves distintas em '{}'",
        to_index.len(),
        regra.to_kind
    );

    // ── Passo 3: emitir arestas para pares que casam ────────────────────────
    let mut total = 0u64;
    let mut sem_match = 0u64;

    for (chave, from_lsns) in &from_index {
        let Some(to_lsns) = to_index.get(chave) else {
            sem_match += 1;
            continue;
        };

        // Produto cartesiano from × to (geralmente 1×1; pode ser 1×N para remunerações)
        for (from_lsn, from_id) in from_lsns {
            for (to_lsn, to_id) in to_lsns {
                // edge_id determinístico — garante idempotência
                let edge_id = format!("{}|{}|{}", from_lsn, regra.relation, to_lsn);

                let mut attrs = HashMap::new();
                attrs.insert("from_lsn".into(), from_lsn.clone());
                attrs.insert("to_lsn".into(), to_lsn.clone());
                attrs.insert("from_kind".into(), regra.from_kind.to_string());
                attrs.insert("to_kind".into(), regra.to_kind.to_string());
                attrs.insert("relation".into(), regra.relation.to_string());
                attrs.insert("fk_value".into(), chave.clone());
                attrs.insert("edge_id".into(), edge_id.clone());

                let content = format!(
                    "EDGE {} | {} → {} | via {}={}",
                    regra.relation, from_lsn, to_lsn, regra.from_attr, chave
                )
                .into_bytes();

                if !dry_run {
                    if let Some(c) = client.as_deref_mut() {
                        let opts = AppendOptions {
                            kind: "Edge".into(),
                            attrs,
                            parents: vec![from_id.clone(), to_id.clone()], // ULIDs (não lsn)
                            ..Default::default()
                        };
                        match c.append("edge-builder", &content, opts).await {
                            Ok(_) => total += 1,
                            Err(e) => warn!("  gRPC falhou em aresta {edge_id}: {e}"),
                        }
                    }
                } else {
                    // dry-run: contar sem gravar
                    total += 1;
                }
            }
        }
    }

    if sem_match > 0 {
        warn!(
            "  {} chaves sem correspondência em '{}'",
            sem_match, regra.to_kind
        );
    }

    Ok(total)
}

/// Constrói um índice `attr_value → Vec<lsn>` a partir de uma resposta GQL JSON.
///
/// O HeraclitusDB retorna JSON com array de nós:
/// `[{"lsn": 42, "attrs": {"id_servidor": "123", ...}}, ...]`
fn construir_indice(val: &serde_json::Value, attr: &str) -> HashMap<String, Vec<(String, String)>> {
    // attr_value → Vec<(lsn, id_ULID)>. O `lsn` vai para os attrs (o dashboard
    // mapeia arestas por lsn); o `id` (ULID) vai para os `parents` — o servidor
    // valida parents como ULIDs ("bad parent ULID" se receber um lsn).
    let mut idx: HashMap<String, Vec<(String, String)>> = HashMap::new();

    // Suporta tanto array de topo quanto {"rows": [...]}
    let rows = if let Some(arr) = val.as_array() {
        arr.as_slice()
    } else if let Some(arr) = val.get("rows").and_then(|v| v.as_array()) {
        arr.as_slice()
    } else {
        return idx;
    };

    for node in rows {
        // lsn / id podem estar direto no objeto ou dentro de "n"
        let lsn_val = node
            .get("lsn")
            .or_else(|| node.get("n").and_then(|n| n.get("lsn")));
        let id_val = node
            .get("id")
            .or_else(|| node.get("n").and_then(|n| n.get("id")));
        let attrs_val = node
            .get("attrs")
            .or_else(|| node.get("n").and_then(|n| n.get("attrs")));

        let (Some(lsn_v), Some(id_v), Some(attrs_v)) = (lsn_val, id_val, attrs_val) else {
            continue;
        };

        let lsn = lsn_v.to_string().trim_matches('"').to_string();
        let id = id_v.as_str().unwrap_or("").to_string();
        if id.is_empty() {
            continue;
        }

        if let Some(chave) = attrs_v.get(attr).and_then(|v| v.as_str()) {
            if !chave.is_empty() {
                idx.entry(chave.to_string()).or_default().push((lsn, id));
            }
        }
    }

    idx
}
