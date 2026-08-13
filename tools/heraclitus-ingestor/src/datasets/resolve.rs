//! RESOLVE — ligação por *entity resolution* quando o CPF está mascarado.
//!
//! ## Porquê isto existe
//! Os datasets de pessoal (Servidor), expulsões (CEAF) e cartão corporativo
//! (CPGF/CPDC) só expõem o CPF **mascarado** (`***.DEF.GHI-**`) por exigência da
//! LGPD. Um join por igualdade exata do CPF mascarado (como faziam as EdgeRules
//! `SERVIDOR_EXPULSO` e `TEM_CARTAO_CORPORATIVO`) é **inseguro**: dois CPFs
//! diferentes que partilhem os 6 dígitos do meio colidem na mesma string
//! mascarada → aresta falsa, acusação errada.
//!
//! Em vez de tentar reconstruir o CPF (re-identificação proibida e prova
//! contaminada), resolvemos a identidade de forma **probabilística**:
//!   1. **Blocking** pelos 6 dígitos visíveis do CPF (`cpf_fragmento`).
//!   2. Dentro do bloco, comparamos o **NOME** (texto claro) normalizado.
//!   3. **Órgão** como reforço/desempate.
//! O resultado é uma aresta `MESMA_PESSOA_*` com `score` e `confianca` — um
//! *lead* auditável para investigação, nunca uma identificação definitiva.
//!
//! Nenhuma destas operações expõe ou deriva o CPF completo.

use crate::utils::{cpf_fragmento, normalizar_nome, similaridade_nome};
use heraclitus_client::{AppendOptions, Client};
use std::collections::HashMap;
use tracing::{info, warn};

/// Limiar mínimo de nome para sequer considerar um candidato.
const SIM_NOME_MIN: f64 = 0.60;
/// Score mínimo para emitir a aresta.
const SCORE_MIN: f64 = 0.50;
/// Score a partir do qual a confiança é considerada ALTA.
const SCORE_ALTA: f64 = 0.85;
/// Bónus de score quando o órgão também coincide.
const BONUS_ORGAO: f64 = 0.10;
/// Penalização multiplicativa quando há >1 candidato plausível no bloco (homónimos).
const PENALIZA_AMBIGUO: f64 = 0.70;

/// Regra de resolução entre um kind "origem" (CEAF, CPGF…) e o Servidor.
#[derive(Debug, Clone)]
pub struct ResolveRule {
    pub from_kind: &'static str,
    /// Attr do CPF mascarado na origem (ex.: "cpf_punido", "cpf_portador").
    pub from_cpf: &'static str,
    /// Attr do nome na origem (ex.: "nome_sancionado", "nome_portador").
    pub from_nome: &'static str,
    /// Attr de órgão na origem para desempate (pode ser "" se não houver).
    pub from_orgao: &'static str,
    /// Kind de destino — quase sempre "Servidor".
    pub to_kind: &'static str,
    pub to_cpf: &'static str,
    pub to_nome: &'static str,
    pub to_orgao: &'static str,
    /// Nome da relação resultante.
    pub relation: &'static str,
    pub descricao: &'static str,
}

/// Regras de resolução que SUBSTITUEM os joins exatos inseguros de `edge_rules`.
pub fn todas_as_resolucoes() -> Vec<ResolveRule> {
    vec![
        ResolveRule {
            from_kind: "ExpulsaoCEAF",
            from_cpf: "cpf_punido",
            from_nome: "nome_sancionado",
            from_orgao: "orgao_lotacao",
            to_kind: "Servidor",
            to_cpf: "cpf",
            to_nome: "nome",
            to_orgao: "orgao",
            relation: "MESMA_PESSOA_EXPULSO",
            descricao: "ExpulsaoCEAF ≈ Servidor (CPF mascarado + nome + órgão)",
        },
        ResolveRule {
            from_kind: "GastoCartaoCPGF",
            from_cpf: "cpf_portador",
            from_nome: "nome_portador",
            from_orgao: "", // CPGF não carrega órgão de lotação do portador
            to_kind: "Servidor",
            to_cpf: "cpf",
            to_nome: "nome",
            to_orgao: "orgao",
            relation: "MESMA_PESSOA_CARTAO",
            descricao: "GastoCartaoCPGF ≈ Servidor (CPF mascarado + nome)",
        },
        // QSA: o CPF do sócio (RFB) é mascarado com os MESMOS 6 dígitos do meio
        // que o Portal → o fragmento casa. Liga sócio de empresa ≈ servidor.
        // (Sócios PJ têm CNPJ no campo → fragmento vazio → ignorados aqui.)
        ResolveRule {
            from_kind: "Socio",
            from_cpf: "cpf_cnpj_socio",
            from_nome: "nome_socio",
            from_orgao: "", // QSA não traz órgão
            to_kind: "Servidor",
            to_cpf: "cpf",
            to_nome: "nome",
            to_orgao: "orgao",
            relation: "MESMA_PESSOA_SOCIO",
            descricao: "Socio ≈ Servidor (CPF mascarado + nome) — servidor é sócio de empresa",
        },
    ]
}

/// Um nó indexado para resolução.
struct No {
    lsn: String,
    id: String, // ULID — vai para os parents da aresta (o servidor valida ULID)
    nome_norm: String,
    orgao: String,
}

/// Indexa os nós de um kind por fragmento de CPF: `frag → Vec<No>`.
/// (Reaproveita o formato JSON devolvido pelo HeraclitusDB.)
fn indexar_por_fragmento(
    val: &serde_json::Value,
    attr_cpf: &str,
    attr_nome: &str,
    attr_orgao: &str,
) -> HashMap<String, Vec<No>> {
    let mut idx: HashMap<String, Vec<No>> = HashMap::new();

    let rows = if let Some(arr) = val.as_array() {
        arr.as_slice()
    } else if let Some(arr) = val.get("rows").and_then(|v| v.as_array()) {
        arr.as_slice()
    } else {
        return idx;
    };

    for node in rows {
        let lsn_v = node
            .get("lsn")
            .or_else(|| node.get("n").and_then(|n| n.get("lsn")));
        let id_v = node
            .get("id")
            .or_else(|| node.get("n").and_then(|n| n.get("id")));
        let attrs_v = node
            .get("attrs")
            .or_else(|| node.get("n").and_then(|n| n.get("attrs")));
        let (Some(lsn_v), Some(id_v), Some(attrs)) = (lsn_v, id_v, attrs_v) else {
            continue;
        };
        let id = id_v.as_str().unwrap_or("").to_string();
        if id.is_empty() {
            continue;
        }

        let get = |k: &str| attrs.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let frag = cpf_fragmento(get(attr_cpf));
        if frag.is_empty() {
            continue;
        }
        idx.entry(frag).or_default().push(No {
            lsn: lsn_v.to_string().trim_matches('"').to_string(),
            id,
            nome_norm: normalizar_nome(get(attr_nome)),
            orgao: normalizar_nome(get(attr_orgao)),
        });
    }
    idx
}

/// Calcula score [0,1] e banda de confiança entre um nó de origem e um candidato.
/// `n_candidatos` = quantos no bloco passam o limiar de nome (mede ambiguidade).
fn pontuar(origem: &No, alvo: &No, n_candidatos: usize) -> (f64, &'static str) {
    let sim = similaridade_nome(&origem.nome_norm, &alvo.nome_norm);
    if sim < SIM_NOME_MIN {
        return (0.0, "NENHUMA");
    }
    let mut score = sim;
    if !origem.orgao.is_empty() && !alvo.orgao.is_empty() && origem.orgao == alvo.orgao {
        score = (score + BONUS_ORGAO).min(1.0);
    }
    if n_candidatos > 1 {
        score *= PENALIZA_AMBIGUO; // há homónimos plausíveis → menos confiança
    }
    let banda = if score >= SCORE_ALTA {
        "ALTA"
    } else if score >= SCORE_MIN {
        "MEDIA"
    } else {
        "BAIXA"
    };
    (score, banda)
}

/// Processa uma ResolveRule: busca os dois kinds, faz blocking por fragmento de
/// CPF, pontua candidatos e emite arestas `MESMA_PESSOA_*` (score ≥ SCORE_MIN).
pub async fn processar_resolucao(
    regra: &ResolveRule,
    cache: &HashMap<String, serde_json::Value>,
    mut client: Option<&mut Client>,
    dry_run: bool,
) -> anyhow::Result<u64> {
    // Destino (Servidor) e origem vêm do cache já varrido (#4 — sem re-varrer).
    let to_idx = match cache.get(regra.to_kind) {
        Some(v) => indexar_por_fragmento(v, regra.to_cpf, regra.to_nome, regra.to_orgao),
        None => HashMap::new(),
    };
    let from_idx = match cache.get(regra.from_kind) {
        Some(v) => indexar_por_fragmento(v, regra.from_cpf, regra.from_nome, regra.from_orgao),
        None => HashMap::new(),
    };

    if from_idx.is_empty() || to_idx.is_empty() {
        warn!(
            "  Sem dados para resolver ({} ou {} vazio)",
            regra.from_kind, regra.to_kind
        );
        return Ok(0);
    }
    info!(
        "  {} blocos na origem, {} blocos de Servidor",
        from_idx.len(),
        to_idx.len()
    );

    let (mut emitidas, mut altas, mut ambiguas) = (0u64, 0u64, 0u64);

    for (frag, origens) in &from_idx {
        let Some(servidores) = to_idx.get(frag) else {
            continue;
        };

        for origem in origens {
            // candidatos do bloco que passam o limiar de nome
            let candidatos: Vec<&No> = servidores
                .iter()
                .filter(|s| similaridade_nome(&origem.nome_norm, &s.nome_norm) >= SIM_NOME_MIN)
                .collect();
            if candidatos.is_empty() {
                continue;
            }
            if candidatos.len() > 1 {
                ambiguas += 1;
            }

            for alvo in &candidatos {
                let (score, banda) = pontuar(origem, alvo, candidatos.len());
                if score < SCORE_MIN {
                    continue;
                }
                if banda == "ALTA" {
                    altas += 1;
                }

                let edge_id = format!("{}|{}|{}", origem.lsn, regra.relation, alvo.lsn);
                let mut attrs = HashMap::new();
                attrs.insert("relation".into(), regra.relation.to_string());
                attrs.insert("from_lsn".into(), origem.lsn.clone());
                attrs.insert("to_lsn".into(), alvo.lsn.clone());
                attrs.insert("from_kind".into(), regra.from_kind.to_string());
                attrs.insert("to_kind".into(), regra.to_kind.to_string());
                attrs.insert("metodo".into(), "resolve_cpf_frag_nome".into());
                attrs.insert("cpf_frag".into(), frag.clone());
                attrs.insert("score".into(), format!("{score:.3}"));
                attrs.insert("confianca".into(), banda.to_string());
                attrs.insert("bloco_tamanho".into(), candidatos.len().to_string());
                attrs.insert("edge_id".into(), edge_id.clone());

                let content = format!(
                    "RESOLVE {} | {} ≈ {} | frag {} | score {:.3} ({})",
                    regra.relation, origem.lsn, alvo.lsn, frag, score, banda
                )
                .into_bytes();

                if dry_run {
                    emitidas += 1;
                    continue;
                }
                if let Some(c) = client.as_deref_mut() {
                    let opts = AppendOptions {
                        kind: "Edge".into(),
                        attrs,
                        parents: vec![origem.id.clone(), alvo.id.clone()], // ULIDs (não lsn)
                        ..Default::default()
                    };
                    match c.append("resolve-builder", &content, opts).await {
                        Ok(_) => emitidas += 1,
                        Err(e) => warn!("  gRPC falhou em {edge_id}: {e}"),
                    }
                }
            }
        }
    }

    info!("  ✓ {emitidas} arestas ({altas} ALTA confiança; {ambiguas} blocos com homónimos)");
    Ok(emitidas)
}
