//! Rule-based planner v0 + EXPLAIN + executor.
//!
//! Per-field counters are collected at execution time so a later cost-based
//! planner has statistics to feed on (§3.12).

use crate::ast::*;
use crate::backend::{materialize_virtual, EdgeRow, QueryBackend, VirtualBackend};
use crate::fusion::FusionWeights;
use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn};
use heraclitus_index_graph::decision::DecisionPolicy;
use serde_json::{json, Value as Json};

#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    ScanFilter {
        label: Option<String>,
        conditions: Vec<(BoolOp, Condition)>,
        valid_at: Option<u64>,
        as_of: Option<AsOf>,
        order_by: Option<(OrderKey, bool)>,
        limit: Option<u32>,
    },
    Recall {
        text: String,
        k: u32,
        as_of: Option<AsOf>,
    },
    Nearest {
        vector: Vec<f32>,
        k: u32,
        as_of: Option<AsOf>,
    },
    Provenance {
        id: String,
    },
    GraphMatch {
        from_var: String,
        to_var: String,
        rel_var: String,
        rel_type: Option<String>,
        conditions: Vec<(BoolOp, Condition)>,
        valid_at: Option<u64>,
        as_of: Option<AsOf>,
        returns: Vec<RetItem>,
        limit: Option<u32>,
    },
    Neighbors {
        node: String,
        etype: Option<String>,
        as_of: Option<AsOf>,
    },
    Traverse {
        start: String,
        max_depth: u32,
        as_of: Option<AsOf>,
    },
    Fuse {
        text: String,
        vector: Vec<f32>,
        node: String,
        k: u32,
        as_of: Option<AsOf>,
    },
    Resolve {
        key: String,
        as_of: Option<AsOf>,
    },
    Cluster {
        entity: String,
        as_of: Option<AsOf>,
    },
    Hypotheses {
        from: String,
        to: String,
        etype: String,
        as_of: Option<AsOf>,
    },
    Why {
        target: String,
        max_depth: Option<u32>,
        until: Option<String>,
        as_of: Option<AsOf>,
    },
    Community {
        node: String,
        leiden: bool,
        as_of: Option<AsOf>,
    },
    Metrics {
        node: String,
        as_of: Option<AsOf>,
    },
    Decide {
        as_of: Option<AsOf>,
    },
    Simulate {
        op: SimulateOp,
        from: String,
        to: String,
        etype: String,
        then: Box<Plan>,
    },
    Adapt {
        as_of: Option<AsOf>,
    },
    Append {
        label: Option<String>,
        props: Vec<(String, Value)>,
    },
}

/// Audit #4: AS OF TIMESTAMP is NOT an LSN. Resolution happens at
/// execution time through `QueryBackend::lsn_for_timestamp`.
fn resolve_as_of(a: &Option<AsOf>, be: &dyn QueryBackend) -> Result<Option<Lsn>, HeraclitusError> {
    Ok(match a {
        Some(AsOf::Lsn(n)) => Some(*n),
        Some(AsOf::Timestamp(t)) => Some(be.lsn_for_timestamp(*t)?),
        None => None,
    })
}

pub fn plan(stmt: &Stmt) -> Plan {
    match stmt {
        // M9: a relationship pattern lowers to a graph match, not a scan.
        Stmt::Match(m) if m.edge.is_some() => {
            let e = m.edge.as_ref().unwrap();
            Plan::GraphMatch {
                from_var: m.var.clone(),
                to_var: e.to_var.clone(),
                rel_var: e.rel_var.clone(),
                rel_type: e.rel_type.clone(),
                conditions: m.conditions.clone(),
                valid_at: m.valid_at,
                as_of: m.as_of,
                returns: m.returns.clone(),
                limit: m.limit,
            }
        }
        Stmt::Match(m) => Plan::ScanFilter {
            label: m.label.clone(),
            conditions: m.conditions.clone(),
            valid_at: m.valid_at,
            as_of: m.as_of,
            order_by: m.order_by.clone(),
            limit: m.limit,
        },
        Stmt::Recall { text, k, as_of } => Plan::Recall {
            text: text.clone(),
            k: *k,
            as_of: *as_of,
        },
        Stmt::Nearest { vector, k, as_of } => Plan::Nearest {
            vector: vector.clone(),
            k: *k,
            as_of: *as_of,
        },
        Stmt::Provenance { id } => Plan::Provenance { id: id.clone() },
        Stmt::Neighbors { node, etype, as_of } => Plan::Neighbors {
            node: node.clone(),
            etype: etype.clone(),
            as_of: *as_of,
        },
        Stmt::Traverse {
            start,
            max_depth,
            as_of,
        } => Plan::Traverse {
            start: start.clone(),
            max_depth: *max_depth,
            as_of: *as_of,
        },
        Stmt::Fuse {
            text,
            vector,
            node,
            k,
            as_of,
        } => Plan::Fuse {
            text: text.clone(),
            vector: vector.clone(),
            node: node.clone(),
            k: *k,
            as_of: *as_of,
        },
        Stmt::Resolve { key, as_of } => Plan::Resolve {
            key: key.clone(),
            as_of: *as_of,
        },
        Stmt::Cluster { entity, as_of } => Plan::Cluster {
            entity: entity.clone(),
            as_of: *as_of,
        },
        Stmt::Hypotheses {
            from,
            to,
            etype,
            as_of,
        } => Plan::Hypotheses {
            from: from.clone(),
            to: to.clone(),
            etype: etype.clone(),
            as_of: *as_of,
        },
        Stmt::Why {
            target,
            max_depth,
            until,
            as_of,
        } => Plan::Why {
            target: target.clone(),
            max_depth: *max_depth,
            until: until.clone(),
            as_of: *as_of,
        },
        Stmt::Community {
            node,
            leiden,
            as_of,
        } => Plan::Community {
            node: node.clone(),
            leiden: *leiden,
            as_of: *as_of,
        },
        Stmt::Metrics { node, as_of } => Plan::Metrics {
            node: node.clone(),
            as_of: *as_of,
        },
        Stmt::Decide { as_of } => Plan::Decide { as_of: *as_of },
        Stmt::Simulate {
            op,
            from,
            to,
            etype,
            then,
        } => Plan::Simulate {
            op: *op,
            from: from.clone(),
            to: to.clone(),
            etype: etype.clone(),
            then: Box::new(plan(then)),
        },
        Stmt::Adapt { as_of } => Plan::Adapt { as_of: *as_of },
        Stmt::Create(c) => Plan::Append {
            label: c.label.clone(),
            props: c.props.clone(),
        },
    }
}

/// Render a plan as indented text — the EXPLAIN output.
pub fn render(plan: &Plan) -> String {
    match plan {
        Plan::ScanFilter {
            label,
            conditions,
            valid_at,
            as_of,
            order_by,
            limit,
        } => {
            let mut s = String::from("ScanFilter\n");
            if let Some(l) = label {
                s += &format!("  label = {l}\n");
            }
            for (op, c) in conditions {
                s += &format!("  cond[{op:?}] {:?} {:?} {:?}\n", c.lhs, c.cmp, c.rhs);
            }
            if let Some(t) = valid_at {
                s += &format!("  ValidAt({t})\n");
            }
            if let Some(a) = as_of {
                s += &format!("  AsOf({a:?})\n");
            }
            if let Some((key, asc)) = order_by {
                match key {
                    OrderKey::Field(f) => s += &format!("  OrderBy({f}, asc={asc})\n"),
                    OrderKey::Dist(kind, v) => {
                        s += &format!("  OrderBy(DIST_{kind:?}[{} dims], asc={asc})\n", v.len())
                    }
                }
            }
            if let Some(l) = limit {
                s += &format!("  Limit({l})\n");
            }
            s
        }
        Plan::Recall { text, k, as_of } => {
            format!("Recall(two-stage)\n  text = {text:?}\n  k = {k}\n  as_of = {as_of:?}\n")
        }
        Plan::Nearest { vector, k, as_of } => format!(
            "Nearest(ANN)\n  dims = {}\n  k = {k}\n  as_of = {as_of:?}\n",
            vector.len()
        ),
        Plan::Provenance { id } => format!("ProvenanceExpand\n  id = {id}\n"),
        Plan::GraphMatch {
            from_var,
            to_var,
            rel_var,
            rel_type,
            conditions,
            valid_at,
            as_of,
            limit,
            ..
        } => {
            let mut s = format!(
                "GraphMatch\n  ({from_var})-[{rel_var}{}]->({to_var})\n",
                rel_type
                    .as_ref()
                    .map(|t| format!(":{t}"))
                    .unwrap_or_default()
            );
            for (op, c) in conditions {
                s += &format!("  cond[{op:?}] {:?} {:?} {:?}\n", c.lhs, c.cmp, c.rhs);
            }
            if let Some(t) = valid_at {
                s += &format!("  ValidAt({t})\n");
            }
            if let Some(a) = as_of {
                s += &format!("  AsOf({a:?})\n");
            }
            if let Some(l) = limit {
                s += &format!("  Limit({l})\n");
            }
            s
        }
        Plan::Neighbors { node, etype, as_of } => format!(
            "GraphNeighbors\n  node = {node}\n  etype = {etype:?}\n  as_of = {as_of:?}\n"
        ),
        Plan::Traverse { start, max_depth, as_of } => format!(
            "GraphTraverse(BFS)\n  start = {start}\n  max_depth = {max_depth}\n  as_of = {as_of:?}\n"
        ),
        Plan::Fuse { text, vector, node, k, as_of } => format!(
            "HybridFusion(graph+vector+text)\n  anchor = {node}\n  text = {text:?}\n  dims = {}\n  k = {k}\n  as_of = {as_of:?}\n",
            vector.len()
        ),
        Plan::Resolve { key, as_of } => {
            format!("EntityResolve\n  key = {key}\n  as_of = {as_of:?}\n")
        }
        Plan::Cluster { entity, as_of } => {
            format!("EntityCluster\n  entity = {entity}\n  as_of = {as_of:?}\n")
        }
        Plan::Hypotheses { from, to, etype, as_of } => format!(
            "HypothesisGraph\n  edge = ({from})-[{etype}]->({to})\n  as_of = {as_of:?}\n"
        ),
        Plan::Why { target, max_depth, until, as_of } => format!(
            "CausalTrace(WHY)\n  target = {target}\n  max_depth = {max_depth:?}\n  until = {until:?}\n  as_of = {as_of:?}\n"
        ),
        Plan::Community { node, leiden, as_of } => {
            let algo = if *leiden { "Leiden" } else { "ConnectedComponents" };
            format!("GraphCommunity({algo})\n  node = {node}\n  as_of = {as_of:?}\n")
        }
        Plan::Metrics { node, as_of } => {
            format!("GraphMetrics\n  node = {node}\n  as_of = {as_of:?}\n")
        }
        Plan::Decide { as_of } => format!("DecisionEngine(act)\n  as_of = {as_of:?}\n"),
        Plan::Adapt { as_of } => format!("AdaptiveLearner\n  as_of = {as_of:?}\n"),
        Plan::Simulate { op, from, to, etype, then } => {
            let inner = render(then)
                .lines()
                .map(|l| format!("    {l}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "Counterfactual({op:?})\n  edge = ({from})-[{etype}]->({to})\n  then =\n{inner}\n"
            )
        }
        Plan::Append { label, props } => {
            format!(
                "Append(log)\n  label = {label:?}\n  props = {}\n",
                props.len()
            )
        }
    }
}

fn episode_to_json(lsn: Lsn, e: &Episode) -> Json {
    json!({
        "lsn": lsn,
        "id": e.id.to_string(),
        "agent_id": e.agent_id,
        "session_id": e.session_id,
        "kind": format!("{:?}", e.kind),
        "content": String::from_utf8_lossy(&e.content),
        "attrs": e.attrs,
        "ts_hlc": e.ts_hlc,
        // Provenance parents travel with the node so a windowed graph can draw
        // its edges with zero extra queries (the on-demand dashboard relies on
        // this: in-window edges are free, no per-node provenance lookup).
        "parents": e.parents.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
    })
}

/// Rótulo limpo do kind para filtros/labels: variantes conhecidas → o seu nome,
/// `Custom(s)` → a string interna `s`. Sem isto, `Custom("ItemLicitacao")`
/// formatava-se como `Custom("ItemLicitacao")` e nunca casava com `MATCH
/// (n:ItemLicitacao)` nem com `WHERE n.kind = "ItemLicitacao"` (kinds Custom
/// — gerados pela ingestão de dados — eram invisíveis às queries por tipo).
fn kind_label(k: &EventKind) -> String {
    match k {
        EventKind::Custom(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

fn field_of(lsn: Lsn, e: &Episode, field: &str) -> Option<Json> {
    match field {
        "lsn" => Some(json!(lsn)),
        "id" => Some(json!(e.id.to_string())),
        "agent_id" => Some(json!(e.agent_id)),
        "session_id" => Some(json!(e.session_id)),
        // `tipo` é alias de `kind`; ambos devolvem o rótulo limpo (ver kind_label).
        "kind" | "tipo" => Some(json!(kind_label(&e.kind))),
        "content" => Some(json!(String::from_utf8_lossy(&e.content))),
        "ts_hlc" => Some(json!(e.ts_hlc)),
        other => e.attrs.get(other).map(|v| json!(v)),
    }
}

fn eval_operand(op: &Operand, lsn: Lsn, e: &Episode) -> Option<Json> {
    match op {
        Operand::Prop(_, field) => field_of(lsn, e, field),
        Operand::Ident(field) => field_of(lsn, e, field),
        Operand::Num(n) => Some(json!(n)),
        Operand::Str(s) => Some(json!(s)),
        Operand::Dist(kind, v) => eval_dist(*kind, v, e).map(|d| json!(d)),
    }
}

/// Distância do embedding do episódio ao vetor literal da query, na Variedade
/// Produto (curvaturas da assinatura default do manifold). `None` quando o
/// episódio não tem embedding — a condição simplesmente não casa.
fn eval_dist(kind: DistKind, q: &[f32], e: &Episode) -> Option<f64> {
    let emb = e.embedding.as_ref()?;
    let sig = &heraclitus_manifold::ProductMetric::default().sig;
    Some(match kind {
        DistKind::Hyp => heraclitus_manifold::dist_hyp(q, &emb.hyp, -sig.k1),
        DistKind::Sph => heraclitus_manifold::dist_sph(q, &emb.sph, sig.k2),
        DistKind::Euc => heraclitus_manifold::dist_euc(q, &emb.euc),
        DistKind::Product => {
            // O vetor plano da query é fatiado pelas dimensões do PRÓPRIO
            // episódio (a mesma convenção do canal vetorial do FUSE).
            let (a, b) = (emb.hyp.len(), emb.sph.len());
            if q.len() != a + b + emb.euc.len() {
                return None;
            }
            let qp = heraclitus_core::ProductPoint {
                hyp: q[..a].to_vec(),
                sph: q[a..a + b].to_vec(),
                euc: q[a + b..].to_vec(),
            };
            heraclitus_manifold::ProductMetric::default().dist(&qp, emb)
        }
    })
}

fn cmp_json(a: &Json, b: &Json, cmp: Cmp) -> bool {
    // Coerção numérica: attrs vivem como STRINGS no Episode; se um dos lados é
    // um número genuíno e o outro é uma string numérica, compara-se como
    // números — sem isto, `WHERE n.valor > 10` nunca casava (string vs número
    // caía no caminho de strings e devolvia None). Strings puras dos dois
    // lados continuam a comparar lexicograficamente (CPFs com zeros à esquerda
    // não mudam de semântica).
    let coerce = |j: &Json| {
        j.as_f64()
            .or_else(|| j.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
    };
    let ord = match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        (Some(_), None) | (None, Some(_)) => match (coerce(a), coerce(b)) {
            (Some(x), Some(y)) => x.partial_cmp(&y),
            _ => None,
        },
        _ => a.as_str().and_then(|x| b.as_str().map(|y| x.cmp(y))),
    };
    match (ord, cmp) {
        (Some(o), Cmp::Eq) => o.is_eq(),
        (Some(o), Cmp::Ne) => !o.is_eq(),
        (Some(o), Cmp::Gt) => o.is_gt(),
        (Some(o), Cmp::Lt) => o.is_lt(),
        (Some(o), Cmp::Ge) => o.is_ge(),
        (Some(o), Cmp::Le) => o.is_le(),
        (None, Cmp::Ne) => true,
        (None, _) => false,
    }
}

/// Bi-temporalidade (VALID AT t): o facto é válido em `t` se
/// `valid_from <= t` (ausente = desde sempre) E `t < valid_to` (ausente =
/// ainda válido). Intervalo meio-aberto `[from, to)` — a mesma convenção dos
/// intervalos de LSN. Um facto sem valid time é atemporal e passa sempre.
/// Lê primeiro os campos NATIVOS do Episode (FORMAT v4); attrs são o
/// fallback de compatibilidade (a convenção pré-v4).
fn valid_at_matches(e: &Episode, t: u64) -> bool {
    let num = |k: &str| e.attrs.get(k).and_then(|v| v.trim().parse::<f64>().ok());
    let from = e.valid_from.map(|v| v as f64).or_else(|| num("valid_from"));
    let to = e.valid_to.map(|v| v as f64).or_else(|| num("valid_to"));
    let from_ok = from.is_none_or(|from| from <= t as f64);
    let to_ok = to.is_none_or(|to| (t as f64) < to);
    from_ok && to_ok
}

/// Avalia a lista `(op, cond)` com precedência SQL: **AND liga mais forte que
/// OR** — `A OR B AND C` = `A OR (B AND C)`. (Correção R19: a avaliação
/// anterior era estritamente esquerda→direita, o que dava `(A OR B) AND C`.)
/// Lista vazia = sem filtro = `true`.
fn eval_bool(conditions: &[(BoolOp, Condition)], mut hit: impl FnMut(&Condition) -> bool) -> bool {
    if conditions.is_empty() {
        return true;
    }
    let mut any = false; // OR dos grupos AND já fechados
    let mut cur = true; // grupo AND corrente
    for (op, c) in conditions {
        let h = hit(c);
        match op {
            BoolOp::First => cur = h,
            BoolOp::And => cur = cur && h,
            BoolOp::Or => {
                any = any || cur;
                cur = h;
            }
        }
    }
    any || cur
}

fn matches(conditions: &[(BoolOp, Condition)], lsn: Lsn, e: &Episode) -> bool {
    eval_bool(conditions, |c| {
        let lhs = eval_operand(&c.lhs, lsn, e);
        let rhs = eval_operand(&c.rhs, lsn, e);
        match (lhs, rhs) {
            (Some(a), Some(b)) => cmp_json(&a, &b, c.cmp),
            _ => false,
        }
    })
}

/// Avalia um operando no CONTEXTO de uma aresta do GraphMatch (correção R1):
/// as variáveis do padrão resolvem para from/to/edge_id, e `r.type`/`r.belief`/
/// `r.id` para os campos da aresta. Campo desconhecido ⇒ `None` — a condição
/// não casa (a mesma regra do ScanFilter para attrs inexistentes).
fn eval_edge_operand(
    op: &Operand,
    r: &EdgeRow,
    from_var: &str,
    to_var: &str,
    rel_var: &str,
) -> Option<Json> {
    match op {
        Operand::Num(n) => Some(json!(n)),
        Operand::Str(s) => Some(json!(s)),
        Operand::Dist(..) => None, // sem embedding num contexto de aresta
        Operand::Ident(v) => {
            if v == from_var {
                Some(json!(r.from))
            } else if v == to_var {
                Some(json!(r.to))
            } else if v == rel_var {
                Some(json!(r.edge_id))
            } else {
                None
            }
        }
        Operand::Prop(v, f) => {
            if v == rel_var {
                match f.as_str() {
                    "type" => Some(json!(r.etype)),
                    "belief" => Some(json!(r.belief)),
                    "id" => Some(json!(r.edge_id)),
                    _ => None,
                }
            } else if v == from_var && f == "id" {
                Some(json!(r.from))
            } else if v == to_var && f == "id" {
                Some(json!(r.to))
            } else {
                None
            }
        }
    }
}

/// Pós-filtro do GraphMatch (correção R1): TODAS as condições do WHERE são
/// revalidadas contra cada aresta — antes, só as igualdades src/dst/etype eram
/// empurradas e o resto era silenciosamente ignorado (resultados errados).
fn edge_matches(
    conditions: &[(BoolOp, Condition)],
    r: &EdgeRow,
    from_var: &str,
    to_var: &str,
    rel_var: &str,
) -> bool {
    eval_bool(conditions, |c| {
        let lhs = eval_edge_operand(&c.lhs, r, from_var, to_var, rel_var);
        let rhs = eval_edge_operand(&c.rhs, r, from_var, to_var, rel_var);
        match (lhs, rhs) {
            (Some(a), Some(b)) => cmp_json(&a, &b, c.cmp),
            _ => false,
        }
    })
}

/// Ordem total para ORDER BY (correção R3): números (com coerção de strings
/// numéricas, a mesma do `cmp_json`) comparam numericamente e vêm primeiro;
/// o resto compara lexicograficamente. Antes tudo era comparado como string
/// JSON — `ORDER BY n.lsn ASC` dava [0,1,10,11,2,...].
fn cmp_order(a: &Json, b: &Json) -> std::cmp::Ordering {
    let coerce = |j: &Json| {
        j.as_f64()
            .or_else(|| j.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
    };
    match (coerce(a), coerce(b)) {
        (Some(x), Some(y)) => x.total_cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.to_string().cmp(&b.to_string()),
    }
}

/// Push a pattern-variable equality (`var = "x"` or `var.field = "x"`) from the
/// WHERE clause down into the graph query. Returns the literal if found.
/// Um `OR` desqualifica o pushdown (correção R1): a igualdade pode valer só
/// num ramo — empurrá-la restringiria o match antes do pós-filtro e perderia
/// linhas dos outros ramos. O `edge_matches` revalida tudo na mesma.
fn eq_filter(conditions: &[(BoolOp, Condition)], var: &str, field: &str) -> Option<String> {
    if conditions.iter().any(|(op, _)| matches!(op, BoolOp::Or)) {
        return None;
    }
    fn var_lit(a: &Operand, b: &Operand, var: &str, field: &str) -> Option<String> {
        let is_var = match a {
            Operand::Ident(v) => v == var,
            Operand::Prop(v, f) => v == var && f == field,
            _ => false,
        };
        match (is_var, b) {
            (true, Operand::Str(s)) => Some(s.clone()),
            _ => None,
        }
    }
    conditions.iter().find_map(|(_, c)| {
        if c.cmp != Cmp::Eq {
            return None;
        }
        var_lit(&c.lhs, &c.rhs, var, field).or_else(|| var_lit(&c.rhs, &c.lhs, var, field))
    })
}

fn is_lsn_operand(op: &Operand) -> bool {
    matches!(op, Operand::Ident(f) if f == "lsn") || matches!(op, Operand::Prop(_, f) if f == "lsn")
}

fn flip_cmp(c: Cmp) -> Cmp {
    match c {
        Cmp::Gt => Cmp::Lt,
        Cmp::Lt => Cmp::Gt,
        Cmp::Ge => Cmp::Le,
        Cmp::Le => Cmp::Ge,
        other => other, // Eq / Ne are symmetric
    }
}

/// Campos servidos diretamente do envelope do evento (não são `attrs`), logo
/// não passam pelo índice de atributos.
fn is_builtin_field(f: &str) -> bool {
    matches!(
        f,
        "lsn" | "id" | "agent_id" | "session_id" | "kind" | "tipo" | "content"
    )
}

/// Se o `WHERE` for conjuntivo e limitar `n.<campo>` por comparações NUMÉRICAS
/// (`>`, `>=`, `<`, `<=`, campo não-builtin), devolve `(campo, min, max)` com
/// bounds `(valor, inclusivo?)` para o índice ordenado resolver (C1.6, padrão
/// Qdrant). `None` ⇒ scan por janela. O pós-filtro `matches` revalida tudo —
/// a correção nunca depende do hint.
/// Um limite numérico: `(valor, inclusivo?)`.
type NumBound = Option<(f64, bool)>;

fn attr_range_hint(conditions: &[(BoolOp, Condition)]) -> Option<(String, NumBound, NumBound)> {
    if conditions.iter().any(|(op, _)| matches!(op, BoolOp::Or)) {
        return None;
    }
    let mut field: Option<String> = None;
    let mut min: Option<(f64, bool)> = None;
    let mut max: Option<(f64, bool)> = None;
    for (_, c) in conditions {
        // Normaliza para a forma `n.<campo> <cmp> <número>`.
        let (f, cmp, n) = match (&c.lhs, &c.rhs) {
            (Operand::Prop(_, f), Operand::Num(n)) => (f, c.cmp, *n),
            (Operand::Num(n), Operand::Prop(_, f)) => (f, flip_cmp(c.cmp), *n),
            _ => continue,
        };
        if is_builtin_field(f) {
            continue;
        }
        // Um único campo por hint: o primeiro com bounds numéricos ganha.
        match &field {
            Some(existing) if existing != f => continue,
            None => field = Some(f.clone()),
            _ => {}
        }
        let tighter_min = |cur: Option<(f64, bool)>, cand: (f64, bool)| match cur {
            Some((v, _)) if v >= cand.0 => cur,
            _ => Some(cand),
        };
        let tighter_max = |cur: Option<(f64, bool)>, cand: (f64, bool)| match cur {
            Some((v, _)) if v <= cand.0 => cur,
            _ => Some(cand),
        };
        match cmp {
            Cmp::Gt => min = tighter_min(min, (n, false)),
            Cmp::Ge => min = tighter_min(min, (n, true)),
            Cmp::Lt => max = tighter_max(max, (n, false)),
            Cmp::Le => max = tighter_max(max, (n, true)),
            _ => {}
        }
    }
    let field = field?;
    if min.is_none() && max.is_none() {
        return None;
    }
    Some((field, min, max))
}

/// Se o `WHERE` for conjuntivo e fixar `n.<campo> = "valor"` (igualdade, valor
/// string, campo não-builtin), devolve `(campo, valor)` para o índice de
/// atributos resolver. `None` ⇒ usar o scan por janela.
fn attr_eq_hint(conditions: &[(BoolOp, Condition)]) -> Option<(String, String)> {
    if conditions.iter().any(|(op, _)| matches!(op, BoolOp::Or)) {
        return None; // um OR partiria a semântica de um único lookup
    }
    for (_, c) in conditions {
        if c.cmp != Cmp::Eq {
            continue;
        }
        let pair = match (&c.lhs, &c.rhs) {
            (Operand::Prop(_, f), Operand::Str(v)) => Some((f.clone(), v.clone())),
            (Operand::Str(v), Operand::Prop(_, f)) => Some((f.clone(), v.clone())),
            _ => None,
        };
        if let Some((f, v)) = pair {
            if !is_builtin_field(&f) {
                return Some((f, v));
            }
        }
    }
    None
}

/// Like [`attr_eq_hint`] but for zone-mapped builtin fields (`agent_id`,
/// `session_id`): extracts `(field, value)` from a conjunctive `WHERE
/// <field> = "v"` so the planner can push it down to the zone-map skip scan
/// (`scan_builtin_eq`). An `OR` disqualifies it.
fn builtin_skip_hint(conditions: &[(BoolOp, Condition)]) -> Option<(String, String)> {
    if conditions.iter().any(|(op, _)| matches!(op, BoolOp::Or)) {
        return None;
    }
    for (_, c) in conditions {
        if c.cmp != Cmp::Eq {
            continue;
        }
        let pair = match (&c.lhs, &c.rhs) {
            (Operand::Prop(_, f), Operand::Str(v)) => Some((f.as_str(), v.clone())),
            (Operand::Str(v), Operand::Prop(_, f)) => Some((f.as_str(), v.clone())),
            _ => None,
        };
        if let Some((f, v)) = pair {
            if f == "agent_id" || f == "session_id" {
                return Some((f.to_string(), v));
            }
        }
    }
    None
}

/// Derive the LSN scan window `[lo, hi)` from the `WHERE` clause and the `AS OF`
/// bound, so `MATCH` pushes a time filter down to a pruned, capped scan
/// (§query guard). Only conjunctive (`AND`) numeric `n.lsn` comparisons are
/// pushed; anything with an `OR` (or no lsn bound) falls back to the full
/// `[0, bound)` window — still capped by the backend. The post-scan `matches`
/// re-checks every condition, so a too-wide window can never return wrong rows;
/// only a *too-narrow* window would, which is why the rules below are exact.
fn lsn_window(conditions: &[(BoolOp, Condition)], bound: Option<Lsn>) -> (Lsn, Lsn) {
    let mut lo: Lsn = 0;
    let mut hi: Lsn = bound.unwrap_or(u64::MAX);
    if conditions.iter().any(|(op, _)| matches!(op, BoolOp::Or)) {
        return (lo, hi);
    }
    for (_, c) in conditions {
        let (cmp, n) = if is_lsn_operand(&c.lhs) {
            match &c.rhs {
                Operand::Num(n) => (c.cmp, *n),
                _ => continue,
            }
        } else if is_lsn_operand(&c.rhs) {
            match &c.lhs {
                Operand::Num(n) => (flip_cmp(c.cmp), *n),
                _ => continue,
            }
        } else {
            continue;
        };
        let n = if n < 0.0 { 0u64 } else { n as u64 };
        match cmp {
            Cmp::Ge => lo = lo.max(n),
            Cmp::Gt => lo = lo.max(n.saturating_add(1)),
            Cmp::Le => hi = hi.min(n.saturating_add(1)),
            Cmp::Lt => hi = hi.min(n),
            Cmp::Eq => {
                lo = lo.max(n);
                hi = hi.min(n.saturating_add(1));
            }
            Cmp::Ne => {}
        }
    }
    if lo >= hi {
        (lo, lo) // empty window
    } else {
        (lo, hi)
    }
}

fn project_edge(
    r: &EdgeRow,
    returns: &[RetItem],
    from_var: &str,
    to_var: &str,
    rel_var: &str,
) -> Json {
    // Star (or an empty RETURN) yields the whole edge.
    if returns.is_empty() || returns.iter().any(|i| matches!(i, RetItem::Star)) {
        return json!({
            "from": r.from, "to": r.to,
            "edge_id": r.edge_id, "etype": r.etype, "belief": r.belief,
        });
    }
    let mut obj = serde_json::Map::new();
    for item in returns {
        match item {
            RetItem::Star => {}
            RetItem::Ident(v) => {
                let val = if v == from_var {
                    json!(r.from)
                } else if v == to_var {
                    json!(r.to)
                } else if v == rel_var {
                    json!(r.edge_id)
                } else {
                    Json::Null
                };
                obj.insert(v.clone(), val);
            }
            RetItem::Prop(v, f) => {
                let val = if v == rel_var {
                    match f.as_str() {
                        "type" => json!(r.etype),
                        "belief" => json!(r.belief),
                        "id" => json!(r.edge_id),
                        _ => Json::Null,
                    }
                } else if v == from_var && f == "id" {
                    json!(r.from)
                } else if v == to_var && f == "id" {
                    json!(r.to)
                } else {
                    Json::Null
                };
                obj.insert(format!("{v}.{f}"), val);
            }
        }
    }
    Json::Object(obj)
}

pub fn execute(plan: &Plan, be: &dyn QueryBackend) -> Result<Json, HeraclitusError> {
    match plan {
        Plan::ScanFilter {
            label,
            conditions,
            valid_at,
            as_of,
            order_by,
            limit,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            // ÍNDICE SECUNDÁRIO: se o WHERE (tudo AND) fixa `n.<campo> = "v"` num
            // campo não-builtin, resolve pelo índice de atributos (global,
            // O(postings)) em vez de varrer a janela capada. O pós-filtro
            // `matches` revalida tudo, por isso a correção nunca depende disto.
            let indexed: Option<Vec<(Lsn, Episode)>> = match attr_eq_hint(conditions) {
                Some((field, value)) => be.attr_lookup(&field, &value, bound)?,
                None => match attr_range_hint(conditions) {
                    // ÍNDICE ORDENADO (C1.6): WHERE n.<campo> >/< número resolve
                    // pelo range do índice de atributos em vez do scan.
                    Some((field, min, max)) => be.attr_range_lookup(&field, min, max, bound)?,
                    None => match builtin_skip_hint(conditions) {
                        // SPEC-010 skip-I/O: WHERE agent_id/session_id = "v" salta
                        // segmentos selados cujo zone map não contém o valor
                        // (scan_builtin_eq). São builtins (fora do índice de
                        // atributos); o pós-filtro `matches` revalida o exato.
                        Some((field, value)) => be.scan_builtin_eq(&field, &value, bound)?,
                        None => None,
                    },
                },
            };
            let candidates: Vec<(Lsn, Episode)> = match indexed {
                Some(hit) => hit,
                None => {
                    // Push any `n.lsn` bounds down to a pruned, capped scan window.
                    let (lo, hi) = lsn_window(conditions, bound);
                    be.scan_range(lo, hi)?
                }
            };
            let mut rows: Vec<(Lsn, Episode)> = candidates
                .into_iter()
                .filter(|(_, e)| {
                    label
                        .as_ref()
                        .map(|l| kind_label(&e.kind).eq_ignore_ascii_case(l))
                        .unwrap_or(true)
                })
                .filter(|(_, e)| valid_at.is_none_or(|t| valid_at_matches(e, t)))
                .filter(|(l, e)| matches(conditions, *l, e))
                .collect();
            if let Some((key, asc)) = order_by {
                match key {
                    // Correção R3: comparação numérica (com coerção) em vez de
                    // comparar as representações string dos valores JSON.
                    OrderKey::Field(field) => rows.sort_by(|(la, ea), (lb, eb)| {
                        let a = field_of(*la, ea, field).unwrap_or(Json::Null);
                        let b = field_of(*lb, eb, field).unwrap_or(Json::Null);
                        let ord = cmp_order(&a, &b);
                        if *asc {
                            ord
                        } else {
                            ord.reverse()
                        }
                    }),
                    // Ordenação numérica por distância; sem embedding vai para o fim.
                    OrderKey::Dist(kind, v) => rows.sort_by(|(_, ea), (_, eb)| {
                        let a = eval_dist(*kind, v, ea).unwrap_or(f64::INFINITY);
                        let b = eval_dist(*kind, v, eb).unwrap_or(f64::INFINITY);
                        if *asc {
                            a.total_cmp(&b)
                        } else {
                            b.total_cmp(&a)
                        }
                    }),
                }
            }
            if let Some(l) = limit {
                rows.truncate(*l as usize);
            }
            Ok(Json::Array(
                rows.iter().map(|(l, e)| episode_to_json(*l, e)).collect(),
            ))
        }
        Plan::Recall { text, k, as_of } => {
            let hits = be.recall(text, *k as usize, resolve_as_of(as_of, be)?)?;
            Ok(Json::Array(
                hits.iter()
                    .map(|(l, e, score)| {
                        let mut j = episode_to_json(*l, e);
                        j["score"] = json!(score);
                        j
                    })
                    .collect(),
            ))
        }
        Plan::Nearest { vector, k, as_of } => {
            let hits = be.nearest(vector, *k as usize, resolve_as_of(as_of, be)?)?;
            Ok(Json::Array(
                hits.iter()
                    .map(|(l, e, dist)| {
                        let mut j = episode_to_json(*l, e);
                        j["dist"] = json!(dist);
                        j
                    })
                    .collect(),
            ))
        }
        Plan::Provenance { id } => {
            let parents = be.provenance(id)?;
            Ok(Json::Array(parents.into_iter().map(|p| json!(p)).collect()))
        }
        Plan::GraphMatch {
            from_var,
            to_var,
            rel_var,
            rel_type,
            conditions,
            valid_at,
            as_of,
            returns,
            limit,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            // Pattern variables constrained in WHERE become graph filters; the
            // inline `[r:type]` label is the default edge type (a WHERE
            // `r.type = ...` overrides it).
            let src = eq_filter(conditions, from_var, "id");
            let dst = eq_filter(conditions, to_var, "id");
            let etype = rel_type
                .clone()
                .or_else(|| eq_filter(conditions, rel_var, "type"));
            let rows = be.match_edges(src.as_deref(), etype.as_deref(), dst.as_deref(), bound)?;
            let mut out: Vec<Json> = rows
                .iter()
                // Bi-temporal em ARESTAS (V2.4): VALID AT filtra pelo valid
                // time do mundo herdado do episódio que assertou a aresta.
                .filter(|r| {
                    valid_at.is_none_or(|t| {
                        r.world_valid_from.is_none_or(|from| from <= t)
                            && r.world_valid_to.is_none_or(|to| t < to)
                    })
                })
                // Correção R1: pós-filtro que revalida TODAS as condições do
                // WHERE contra a aresta (o pushdown src/dst/etype é só um hint;
                // antes, condições não-empurráveis eram ignoradas em silêncio).
                .filter(|r| edge_matches(conditions, r, from_var, to_var, rel_var))
                .map(|r| project_edge(r, returns, from_var, to_var, rel_var))
                .collect();
            if let Some(l) = limit {
                out.truncate(*l as usize);
            }
            Ok(Json::Array(out))
        }
        Plan::Neighbors { node, etype, as_of } => {
            let bound = resolve_as_of(as_of, be)?;
            let rows = be.neighbors(node, etype.as_deref(), bound, 0.0)?;
            Ok(Json::Array(
                rows.into_iter()
                    .map(|n| {
                        json!({
                            "edge_id": n.edge_id,
                            "to": n.to,
                            "etype": n.etype,
                            "belief": n.belief,
                            "weight": n.weight,
                            "lsn": n.lsn,
                        })
                    })
                    .collect(),
            ))
        }
        Plan::Traverse {
            start,
            max_depth,
            as_of,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            let rows = be.traverse(start, *max_depth as usize, bound, 0.0)?;
            Ok(Json::Array(
                rows.into_iter()
                    .map(|(node, depth)| json!({ "node": node, "depth": depth }))
                    .collect(),
            ))
        }
        Plan::Fuse {
            text,
            vector,
            node,
            k,
            as_of,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            let hits = be.find_fused(
                text,
                vector,
                node,
                FusionWeights::default(),
                *k as usize,
                bound,
            )?;
            Ok(Json::Array(
                hits.into_iter()
                    .map(|h| {
                        json!({
                            "id": h.id,
                            "lsn": h.lsn,
                            "score": h.score,
                            "graph_score": h.input.graph_score,
                            "vector_score": h.input.vector_score,
                            "text_score": h.input.text_score,
                        })
                    })
                    .collect(),
            ))
        }
        Plan::Resolve { key, as_of } => {
            let bound = resolve_as_of(as_of, be)?;
            let entity = be.resolve_entity(key, bound)?;
            Ok(json!({ "key": key, "entity_id": entity }))
        }
        Plan::Cluster { entity, as_of } => {
            let bound = resolve_as_of(as_of, be)?;
            let keys = be.entity_cluster(entity, bound)?;
            Ok(Json::Array(keys.into_iter().map(|k| json!(k)).collect()))
        }
        Plan::Community {
            node,
            leiden,
            as_of,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            let result = if *leiden {
                be.community_leiden(node, bound)?
            } else {
                be.community(node, bound)?
            };
            match result {
                None => Ok(Json::Null),
                Some(c) => Ok(json!({
                    "node": c.node,
                    "community": c.community,
                    "members": c.members,
                })),
            }
        }
        Plan::Metrics { node, as_of } => {
            let bound = resolve_as_of(as_of, be)?;
            match be.node_metrics(node, bound)? {
                None => Ok(Json::Null),
                Some(m) => Ok(json!({
                    "node": m.node,
                    "community": m.community,
                    "degree": m.degree,
                    "centrality": m.centrality,
                    "anomaly_score": m.anomaly_score,
                })),
            }
        }
        Plan::Simulate {
            op,
            from,
            to,
            etype,
            then,
        } => {
            // Sobrepõe o contrafactual numa cópia do grafo; o grafo base e o
            // log nunca são tocados (divergência isolada). `be.graph()` — e não
            // um replay do log — para que um SIMULATE aninhado veja a mutação
            // do SIMULATE exterior (o VirtualBackend devolve o overlay).
            let base = be.graph()?;
            let virt = materialize_virtual(&base, *op, from, to, etype);
            let vb = VirtualBackend::new(be, virt);
            execute(then, &vb)
        }
        Plan::Adapt { as_of } => {
            let bound = resolve_as_of(as_of, be)?;
            let r = be.adapt(bound)?;
            let eval = |e: &heraclitus_index_graph::adaptive::PolicyEval| {
                json!({
                    "threshold": e.threshold,
                    "precision": e.precision,
                    "recall": e.recall,
                    "f1": e.f1,
                })
            };
            Ok(json!({
                "rule": r.rule,
                "samples": r.samples,
                "learned_threshold": r.learned_threshold,
                "default": eval(&r.default),
                "adapted": eval(&r.adapted),
            }))
        }
        Plan::Decide { as_of } => {
            let bound = resolve_as_of(as_of, be)?;
            let report = be.decide(DecisionPolicy::default(), bound)?;
            Ok(json!({
                "fired": report.fired.into_iter().map(|a| json!({
                    "action_id": a.action_id,
                    "rule": a.rule,
                    "subject": a.subject,
                    "reason": a.reason,
                    "lsn": a.lsn,
                })).collect::<Vec<_>>(),
                "skipped": report.skipped,
            }))
        }
        Plan::Why {
            target,
            max_depth,
            until,
            as_of,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            // SPEC-014: `UNTIL "cause"` → minimal causal chain (shortest path in
            // the parent DAG) instead of the ancestor trace.
            if let Some(cause) = until {
                let chain = be.why_chain(target, cause, bound)?;
                return Ok(json!({
                    "target": target,
                    "cause": cause,
                    "minimal_chain": chain,
                    "linked": !chain.is_empty(),
                }));
            }
            let trace = be.why(target, max_depth.unwrap_or(64) as usize, bound)?;
            Ok(json!({
                "target": trace.target,
                "roots": trace.roots,
                "steps": trace.steps.into_iter().map(|s| json!({
                    "id": s.id,
                    "depth": s.depth,
                    "causes": s.causes,
                })).collect::<Vec<_>>(),
            }))
        }
        Plan::Hypotheses {
            from,
            to,
            etype,
            as_of,
        } => {
            let bound = resolve_as_of(as_of, be)?;
            match be.edge_hypotheses(from, to, etype, bound)? {
                None => Ok(Json::Null),
                Some(h) => Ok(json!({
                    "edge_id": h.edge_id,
                    "alive": h.alive,
                    "belief": h.belief,
                    "hypotheses": h.versions.into_iter().map(|v| json!({
                        "hypothesis_id": v.hypothesis_id,
                        "confidence": v.confidence,
                        "polarity": v.polarity,
                        "source": v.source,
                    })).collect::<Vec<_>>(),
                })),
            }
        }
        Plan::Append { label, props } => {
            let lsn = be.append(label.as_deref(), props)?;
            Ok(json!({ "lsn": lsn }))
        }
    }
}
