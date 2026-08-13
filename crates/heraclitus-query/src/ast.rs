//! AST + pest-tree lowering. Pure functions; never panic on parser output.

use crate::Rule;
use heraclitus_core::HeraclitusError;
use pest::iterators::Pair;

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub explain: bool,
    /// M18: `REQUIRE LSN >= X` — the minimum consistency point this query needs.
    pub require_lsn: Option<u64>,
    pub stmt: Stmt,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Match(MatchStmt),
    Create(CreateStmt),
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
        /// SPEC-014: `UNTIL "cause"` — return the minimal causal chain to `cause`
        /// instead of the ancestor trace.
        until: Option<String>,
        as_of: Option<AsOf>,
    },
    Community {
        node: String,
        /// V2.4: partição LEIDEN (modularidade) em vez de componentes conexas.
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
        then: Box<Stmt>,
    },
    Adapt {
        as_of: Option<AsOf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SimulateOp {
    AddEdge,
    RemoveEdge,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchStmt {
    pub var: String,
    pub label: Option<String>,
    /// M9: when present, this is a relationship match `(var)-[rel]->(to)`.
    pub edge: Option<EdgePattern>,
    pub conditions: Vec<(BoolOp, Condition)>,
    /// Bi-temporalidade: `VALID AT t` filtra pelo tempo de VALIDADE do facto
    /// (attrs `valid_from`/`valid_to`, numéricos; ausente = aberto) — ortogonal
    /// ao `AS OF` (transaction time). Eventos sem valid time são atemporais e
    /// passam sempre.
    pub valid_at: Option<u64>,
    pub as_of: Option<AsOf>,
    pub returns: Vec<RetItem>,
    pub order_by: Option<(OrderKey, bool)>, // (chave, ascending)
    pub limit: Option<u32>,
}

/// The relationship half of `(a)-[r:type]->(b)` (M9).
#[derive(Debug, Clone, PartialEq)]
pub struct EdgePattern {
    pub rel_var: String,
    pub rel_type: Option<String>,
    pub to_var: String,
    pub to_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateStmt {
    pub var: String,
    pub label: Option<String>,
    pub props: Vec<(String, Value)>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BoolOp {
    First, // the first condition has no preceding operator
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    pub lhs: Operand,
    pub cmp: Cmp,
    pub rhs: Operand,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Prop(String, String),
    Ident(String),
    Num(f64),
    Str(String),
    /// Distância do embedding do nó ao vetor literal (Variedade Produto).
    Dist(DistKind, Vec<f32>),
}

/// Componente da Variedade Produto H×S×E usado por um operador `DIST_*`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DistKind {
    Hyp,
    Sph,
    Euc,
    Product,
}

/// Chave do ORDER BY: um campo do episódio ou uma distância `DIST_*`.
#[derive(Debug, Clone, PartialEq)]
pub enum OrderKey {
    Field(String),
    Dist(DistKind, Vec<f32>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cmp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AsOf {
    Lsn(u64),
    Timestamp(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RetItem {
    Star,
    Ident(String),
    Prop(String, String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Num(f64),
    Str(String),
}

fn perr(msg: impl Into<String>) -> HeraclitusError {
    HeraclitusError::Query(msg.into())
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}

/// Reads the (name, optional `:label`/`:type`) pair from a `node_pat` or `rel`
/// pest node — both share the `ident (":" ~ ident)?` shape.
fn node_idents(pair: Pair<Rule>) -> (String, Option<String>) {
    let mut idents = pair.into_inner().filter(|x| x.as_rule() == Rule::ident);
    let name = idents
        .next()
        .map(|x| x.as_str().to_string())
        .unwrap_or_default();
    let label = idents.next().map(|x| x.as_str().to_string());
    (name, label)
}

pub fn build_query(pair: Pair<Rule>) -> Result<Query, HeraclitusError> {
    let mut explain = false;
    let mut require_lsn = None;
    let mut stmt = None;
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::explain => explain = true,
            Rule::require => {
                let n = p
                    .into_inner()
                    .find(|x| x.as_rule() == Rule::int)
                    .ok_or_else(|| perr("REQUIRE needs an LSN"))?
                    .as_str()
                    .parse()
                    .map_err(|_| perr("bad REQUIRE LSN"))?;
                require_lsn = Some(n);
            }
            Rule::stmt => stmt = Some(build_stmt(p)?),
            Rule::EOI => {}
            r => return Err(perr(format!("unexpected rule {r:?}"))),
        }
    }
    Ok(Query {
        explain,
        require_lsn,
        stmt: stmt.ok_or_else(|| perr("missing statement"))?,
    })
}

fn build_stmt(pair: Pair<Rule>) -> Result<Stmt, HeraclitusError> {
    let inner = pair.into_inner().next().ok_or_else(|| perr("empty stmt"))?;
    match inner.as_rule() {
        Rule::match_stmt => build_match(inner).map(Stmt::Match),
        Rule::create_stmt => build_create(inner).map(Stmt::Create),
        Rule::recall_stmt => {
            let mut text = String::new();
            let mut k = 10;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => text = unquote(p.as_str()),
                    Rule::int => k = p.as_str().parse().map_err(|_| perr("bad k"))?,
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            Ok(Stmt::Recall { text, k, as_of })
        }
        Rule::nearest_stmt => {
            let mut vector = Vec::new();
            let mut k = 10;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::vector => {
                        for n in p.into_inner() {
                            vector.push(n.as_str().parse().map_err(|_| perr("bad number"))?);
                        }
                    }
                    Rule::int => k = p.as_str().parse().map_err(|_| perr("bad k"))?,
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            Ok(Stmt::Nearest { vector, k, as_of })
        }
        Rule::provenance_stmt => {
            let id = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::string)
                .map(|p| unquote(p.as_str()))
                .ok_or_else(|| perr("PROVENANCE needs an id"))?;
            Ok(Stmt::Provenance { id })
        }
        Rule::neighbors_stmt => {
            let mut node = String::new();
            let mut etype = None;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    // first string = node, optional second string = edge type
                    Rule::string if node.is_empty() => node = unquote(p.as_str()),
                    Rule::string => etype = Some(unquote(p.as_str())),
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if node.is_empty() {
                return Err(perr("NEIGHBORS needs a node id"));
            }
            Ok(Stmt::Neighbors { node, etype, as_of })
        }
        Rule::traverse_stmt => {
            let mut start = String::new();
            let mut max_depth = 1;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => start = unquote(p.as_str()),
                    Rule::int => max_depth = p.as_str().parse().map_err(|_| perr("bad depth"))?,
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if start.is_empty() {
                return Err(perr("TRAVERSE needs a start id"));
            }
            Ok(Stmt::Traverse {
                start,
                max_depth,
                as_of,
            })
        }
        Rule::fuse_stmt => {
            let mut text = String::new();
            let mut vector = Vec::new();
            let mut node = String::new();
            let mut k = 10;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    // first string = query text, second string = anchor node
                    Rule::string if text.is_empty() => text = unquote(p.as_str()),
                    Rule::string => node = unquote(p.as_str()),
                    Rule::vector => {
                        for n in p.into_inner() {
                            vector.push(n.as_str().parse().map_err(|_| perr("bad number"))?);
                        }
                    }
                    Rule::int => k = p.as_str().parse().map_err(|_| perr("bad k"))?,
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if node.is_empty() {
                return Err(perr("FUSE needs an anchor node id"));
            }
            Ok(Stmt::Fuse {
                text,
                vector,
                node,
                k,
                as_of,
            })
        }
        Rule::resolve_stmt => {
            let mut key = String::new();
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => key = unquote(p.as_str()),
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if key.is_empty() {
                return Err(perr("RESOLVE needs a key"));
            }
            Ok(Stmt::Resolve { key, as_of })
        }
        Rule::cluster_stmt => {
            let mut entity = String::new();
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => entity = unquote(p.as_str()),
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if entity.is_empty() {
                return Err(perr("CLUSTER needs an entity id"));
            }
            Ok(Stmt::Cluster { entity, as_of })
        }
        Rule::hypotheses_stmt => {
            let mut strs: Vec<String> = Vec::new();
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => strs.push(unquote(p.as_str())),
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if strs.len() < 3 {
                return Err(perr("HYPOTHESES needs (from, to, edge_type)"));
            }
            Ok(Stmt::Hypotheses {
                from: strs[0].clone(),
                to: strs[1].clone(),
                etype: strs[2].clone(),
                as_of,
            })
        }
        Rule::why_stmt => {
            // Two `string`s may appear: the first is the target, the second
            // (after UNTIL) is the cause. Literals like WHY/UNTIL are not
            // captured as pairs, so ordering distinguishes them.
            let mut strings: Vec<String> = Vec::new();
            let mut max_depth = None;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => strings.push(unquote(p.as_str())),
                    Rule::int => {
                        max_depth = Some(p.as_str().parse().map_err(|_| perr("bad depth"))?)
                    }
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            let target = strings.first().cloned().unwrap_or_default();
            let until = strings.get(1).cloned();
            if target.is_empty() {
                return Err(perr("WHY needs a target id"));
            }
            Ok(Stmt::Why {
                target,
                max_depth,
                until,
                as_of,
            })
        }
        Rule::community_stmt => {
            let mut node = String::new();
            let mut leiden = false;
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => node = unquote(p.as_str()),
                    Rule::leiden_kw => leiden = true,
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if node.is_empty() {
                return Err(perr("COMMUNITY needs a node id"));
            }
            Ok(Stmt::Community {
                node,
                leiden,
                as_of,
            })
        }
        Rule::metrics_stmt => {
            let mut node = String::new();
            let mut as_of = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::string => node = unquote(p.as_str()),
                    Rule::as_of => as_of = Some(build_as_of(p)?),
                    _ => {}
                }
            }
            if node.is_empty() {
                return Err(perr("METRICS needs a node id"));
            }
            Ok(Stmt::Metrics { node, as_of })
        }
        Rule::decide_stmt => {
            let as_of = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::as_of)
                .map(build_as_of)
                .transpose()?;
            Ok(Stmt::Decide { as_of })
        }
        Rule::adapt_stmt => {
            let as_of = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::as_of)
                .map(build_as_of)
                .transpose()?;
            Ok(Stmt::Adapt { as_of })
        }
        Rule::simulate_stmt => {
            let mut op = SimulateOp::AddEdge;
            let mut strs = Vec::new();
            let mut then = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::simulate_op => {
                        if p.as_str().eq_ignore_ascii_case("remove") {
                            op = SimulateOp::RemoveEdge;
                        }
                    }
                    Rule::string => strs.push(unquote(p.as_str())),
                    Rule::stmt => then = Some(Box::new(build_stmt(p)?)),
                    _ => {}
                }
            }
            if strs.len() < 3 {
                return Err(perr("SIMULATE EDGE needs (from, to, etype)"));
            }
            let then = then.ok_or_else(|| perr("SIMULATE needs a THEN statement"))?;
            Ok(Stmt::Simulate {
                op,
                from: strs[0].clone(),
                to: strs[1].clone(),
                etype: strs[2].clone(),
                then,
            })
        }
        r => Err(perr(format!("unexpected stmt {r:?}"))),
    }
}

fn build_match(pair: Pair<Rule>) -> Result<MatchStmt, HeraclitusError> {
    let mut m = MatchStmt {
        var: String::new(),
        label: None,
        edge: None,
        conditions: Vec::new(),
        valid_at: None,
        as_of: None,
        returns: Vec::new(),
        order_by: None,
        limit: None,
    };
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::pattern => {
                let mut nodes: Vec<(String, Option<String>)> = Vec::new();
                let mut rel: Option<(String, Option<String>)> = None;
                for inner in p.into_inner() {
                    match inner.as_rule() {
                        Rule::node_pat => nodes.push(node_idents(inner)),
                        Rule::rel => rel = Some(node_idents(inner)),
                        _ => {}
                    }
                }
                let (v, l) = nodes.first().cloned().unwrap_or_default();
                m.var = v;
                m.label = l;
                if let Some((rel_var, rel_type)) = rel {
                    let (to_var, to_label) = nodes.get(1).cloned().unwrap_or_default();
                    m.edge = Some(EdgePattern {
                        rel_var,
                        rel_type,
                        to_var,
                        to_label,
                    });
                }
            }
            Rule::where_clause => {
                let mut op = BoolOp::First;
                for c in p.into_inner() {
                    match c.as_rule() {
                        Rule::bool_op => {
                            op = if c.as_str().eq_ignore_ascii_case("or") {
                                BoolOp::Or
                            } else {
                                BoolOp::And
                            };
                        }
                        Rule::condition => {
                            m.conditions.push((op, build_condition(c)?));
                            op = BoolOp::And;
                        }
                        _ => {}
                    }
                }
            }
            Rule::valid_at => {
                let n = p
                    .into_inner()
                    .find(|x| x.as_rule() == Rule::int)
                    .ok_or_else(|| perr("VALID AT needs a number"))?
                    .as_str()
                    .parse()
                    .map_err(|_| perr("bad VALID AT number"))?;
                m.valid_at = Some(n);
            }
            Rule::as_of => m.as_of = Some(build_as_of(p)?),
            Rule::return_clause => {
                for r in p.into_inner() {
                    if r.as_rule() == Rule::ret_item {
                        let item = r.into_inner().next().ok_or_else(|| perr("empty return"))?;
                        m.returns.push(match item.as_rule() {
                            Rule::star => RetItem::Star,
                            Rule::prop => {
                                let (a, b) = split_prop(item.as_str())?;
                                RetItem::Prop(a, b)
                            }
                            _ => RetItem::Ident(item.as_str().to_string()),
                        });
                    }
                }
            }
            Rule::order_by => {
                let mut key = None;
                let mut asc = true;
                for o in p.into_inner() {
                    match o.as_rule() {
                        Rule::prop => key = Some(OrderKey::Field(split_prop(o.as_str())?.1)),
                        Rule::ident => key = Some(OrderKey::Field(o.as_str().to_string())),
                        Rule::dist_fn => {
                            let (kind, vector) = build_dist_fn(o)?;
                            key = Some(OrderKey::Dist(kind, vector));
                        }
                        Rule::direction => asc = !o.as_str().eq_ignore_ascii_case("desc"),
                        _ => {}
                    }
                }
                if let Some(key) = key {
                    m.order_by = Some((key, asc));
                }
            }
            Rule::limit => {
                let n = p.into_inner().next().ok_or_else(|| perr("empty limit"))?;
                m.limit = Some(n.as_str().parse().map_err(|_| perr("bad limit"))?);
            }
            _ => {}
        }
    }
    Ok(m)
}

fn build_create(pair: Pair<Rule>) -> Result<CreateStmt, HeraclitusError> {
    let mut c = CreateStmt {
        var: String::new(),
        label: None,
        props: Vec::new(),
    };
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::ident => {
                if c.var.is_empty() {
                    c.var = p.as_str().to_string();
                } else {
                    c.label = Some(p.as_str().to_string());
                }
            }
            Rule::props => {
                for pr in p.into_inner() {
                    if pr.as_rule() == Rule::pair {
                        let mut it = pr.into_inner();
                        let key = it
                            .next()
                            .ok_or_else(|| perr("bad pair"))?
                            .as_str()
                            .to_string();
                        let val = it.next().ok_or_else(|| perr("bad pair"))?;
                        let value = match val.as_rule() {
                            Rule::string => Value::Str(unquote(val.as_str())),
                            _ => Value::Num(val.as_str().parse().map_err(|_| perr("bad number"))?),
                        };
                        c.props.push((key, value));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(c)
}

fn build_condition(pair: Pair<Rule>) -> Result<Condition, HeraclitusError> {
    let mut it = pair.into_inner();
    let lhs = build_operand(it.next().ok_or_else(|| perr("missing lhs"))?)?;
    let cmp = match it.next().ok_or_else(|| perr("missing op"))?.as_str() {
        "=" => Cmp::Eq,
        "!=" => Cmp::Ne,
        ">" => Cmp::Gt,
        "<" => Cmp::Lt,
        ">=" => Cmp::Ge,
        "<=" => Cmp::Le,
        other => return Err(perr(format!("unknown operator {other}"))),
    };
    let rhs = build_operand(it.next().ok_or_else(|| perr("missing rhs"))?)?;
    Ok(Condition { lhs, cmp, rhs })
}

fn build_operand(pair: Pair<Rule>) -> Result<Operand, HeraclitusError> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| perr("empty operand"))?;
    Ok(match inner.as_rule() {
        Rule::prop => {
            let (a, b) = split_prop(inner.as_str())?;
            Operand::Prop(a, b)
        }
        Rule::number => Operand::Num(inner.as_str().parse().map_err(|_| perr("bad number"))?),
        Rule::string => Operand::Str(unquote(inner.as_str())),
        Rule::dist_fn => {
            let (kind, vector) = build_dist_fn(inner)?;
            Operand::Dist(kind, vector)
        }
        _ => Operand::Ident(inner.as_str().to_string()),
    })
}

fn build_dist_fn(pair: Pair<Rule>) -> Result<(DistKind, Vec<f32>), HeraclitusError> {
    let mut kind = DistKind::Product;
    let mut vector = Vec::new();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::dist_kind => {
                kind = match p.as_str().to_ascii_uppercase().as_str() {
                    "DIST_HYP" => DistKind::Hyp,
                    "DIST_SPH" => DistKind::Sph,
                    "DIST_EUC" => DistKind::Euc,
                    _ => DistKind::Product,
                };
            }
            Rule::vector => {
                for n in p.into_inner() {
                    vector.push(n.as_str().parse().map_err(|_| perr("bad number"))?);
                }
            }
            _ => {}
        }
    }
    if vector.is_empty() {
        return Err(perr("DIST_* needs a non-empty vector"));
    }
    Ok((kind, vector))
}

fn build_as_of(pair: Pair<Rule>) -> Result<AsOf, HeraclitusError> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| perr("empty AS OF"))?;
    let n: u64 = inner
        .clone()
        .into_inner()
        .next()
        .ok_or_else(|| perr("AS OF needs a number"))?
        .as_str()
        .parse()
        .map_err(|_| perr("bad AS OF number"))?;
    Ok(match inner.as_rule() {
        Rule::as_of_lsn => AsOf::Lsn(n),
        _ => AsOf::Timestamp(n),
    })
}

fn split_prop(s: &str) -> Result<(String, String), HeraclitusError> {
    let (a, b) = s.split_once('.').ok_or_else(|| perr("bad property"))?;
    Ok((a.to_string(), b.to_string()))
}
