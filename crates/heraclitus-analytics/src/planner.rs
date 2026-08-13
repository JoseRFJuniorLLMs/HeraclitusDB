//! SPEC-024 `Planner` — the sixth subsystem contract (reference implementation).
//!
//! > **ESTADO: REFERÊNCIA DE I&D — NÃO LIGADO** (decisão P1, 2026-07-16 —
//! > `docs/md/DECISAO-P1-motor-analitico.md`). `AnalyticalPlanner`/`run_analytical`
//! > não têm caller de produção; a via de agregação ligada é o `LogAnalytics`
//! > (DataFusion) em `POST /sql`. Mantém-se como referência do contrato Planner.
//!
//! This closes the **Compiler-1 front-end**: a query *string* → `LogicalPlan`.
//! Together with [`SelectivityOptimizer`] (SPEC-012 `Optimizer`) and
//! [`VecExecutor`] (SPEC-013 `TaskScheduler`), the three planning contracts of
//! SPEC-024 now run **end to end from text** — previously a `LogicalPlan` could
//! only be hand-built in a test.
//!
//! ```text
//! query str ──[AnalyticalPlanner/024]──▶ LogicalPlan
//!                     │
//!   [SelectivityOptimizer/012]──▶ DAG de PhysicalIr
//!                     │
//!         [VecExecutor/013]──▶ batches Arrow
//! ```
//!
//! **Honestidade de escopo (invariante #4 — não inventamos linguagem):** isto
//! **não** é uma segunda linguagem de grafo. GQL/Cypher continua a ÚNICA
//! linguagem da superfície de grafo/temporal (`heraclitus-query`). Este é um
//! *front-end analítico* mínimo — o irmão OLAP colunar — que só endereça a
//! tabela `events` (o schema de [`batch_schema`]). Gramática (keywords
//! case-insensitive):
//!
//! ```text
//! SELECT [WHERE <pred> (AND <pred>)*] [GROUP BY <col> (, <col>)* [SUM <col> (, <col>)*]]
//!   <pred> ::= <col> <op> <lit>
//!   <op>   ::= '=' | '>' | '<'
//!   <lit>  ::= <inteiro> | '"' <string> '"'
//!   <col>  ::= lsn | agent_id | kind | ts_hlc | content_len
//! ```
//! `COUNT(*)` por grupo é sempre produzido pelo executor; `SUM` é opcional.

use crate::vectorized::{
    batch_schema, episodes_to_batches, CmpOp, Literal, Predicate, SelectivityOptimizer, VecExecutor,
};
use crate::AnalyticsError;
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::DataType;
use heraclitus_core::contracts::{Optimizer, Planner, TaskScheduler};
use heraclitus_core::ir::LogicalPlan;
use heraclitus_core::{Episode, Lsn};
use std::collections::HashMap;

/// SPEC-024 `Planner`: parses the analytical SELECT grammar over the `events`
/// schema into a `LogicalPlan`. Column names/types are bound from
/// [`batch_schema`] at construction, so the planner and the executor can never
/// disagree on column layout.
pub struct AnalyticalPlanner {
    /// column name → (índice colunar, é string?)
    columns: HashMap<String, (usize, bool)>,
}

impl Default for AnalyticalPlanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyticalPlanner {
    pub fn new() -> Self {
        let schema = batch_schema();
        let mut columns = HashMap::new();
        for (i, f) in schema.fields().iter().enumerate() {
            columns.insert(f.name().to_string(), (i, *f.data_type() == DataType::Utf8));
        }
        Self { columns }
    }

    fn col(&self, name: &str) -> Result<(usize, bool), String> {
        self.columns.get(name).copied().ok_or_else(|| {
            format!("coluna desconhecida `{name}` (schema events: lsn, agent_id, kind, ts_hlc, content_len)")
        })
    }

    /// Compilação completa: o `LogicalPlan` **e** o registo de predicados que o
    /// executor precisa (o id do predicado no plano = índice neste `Vec`). O
    /// trait `Planner` devolve só o plano; este método inerente devolve ambos —
    /// é o que fecha o laço Planner→Optimizer→Executor.
    pub fn compile(&self, query: &str) -> Result<(LogicalPlan, Vec<Predicate>), String> {
        let toks = tokenize(query)?;
        let mut p = Cursor { toks: &toks, i: 0 };
        p.expect_word("SELECT")?;

        let mut predicates = Vec::new();
        if p.eat_word("WHERE") {
            loop {
                let (col, is_str) = self.col(&p.word()?)?;
                let op = p.op()?;
                let value = p.literal(is_str)?;
                predicates.push(Predicate { column: col, op, value });
                if !p.eat_word("AND") {
                    break;
                }
            }
        }

        let mut aggregate = None;
        if p.eat_word("GROUP") {
            p.expect_word("BY")?;
            let mut keys = vec![self.col(&p.word()?)?.0 as u32];
            while p.eat_comma() {
                keys.push(self.col(&p.word()?)?.0 as u32);
            }
            let mut sums = Vec::new();
            if p.eat_word("SUM") {
                sums.push(self.sum_col(&p.word()?)?);
                while p.eat_comma() {
                    sums.push(self.sum_col(&p.word()?)?);
                }
            }
            aggregate = Some((keys, sums));
        }
        p.expect_end()?;

        // ids posicionais: predicates[id] resolve no VecExecutor sem indireção.
        let predicate_ids = (0..predicates.len() as u32).collect();
        Ok((
            LogicalPlan::Select {
                relations: vec!["events".into()],
                predicates: predicate_ids,
                aggregate,
            },
            predicates,
        ))
    }

    fn sum_col(&self, name: &str) -> Result<u32, String> {
        let (col, is_str) = self.col(name)?;
        if is_str {
            return Err(format!("SUM não se aplica à coluna de texto `{name}`"));
        }
        Ok(col as u32)
    }
}

impl Planner for AnalyticalPlanner {
    fn plan(&self, query: &str) -> Result<LogicalPlan, String> {
        self.compile(query).map(|(plan, _)| plan)
    }
}

/// Pipeline analítico ponta-a-ponta a partir de texto: Planner (024) →
/// Optimizer (012) → Executor (013). `selectivities` alimenta a decisão
/// cost-based do optimizer (id do predicado → fração sobrevivente estimada); um
/// mapa vazio ⇒ 0.5 para todos. A ordem física dos filtros muda a latência,
/// nunca o resultado (Gate C).
pub fn run_analytical(
    query: &str,
    events: &[(Lsn, Episode)],
    selectivities: HashMap<u32, f64>,
) -> Result<Vec<RecordBatch>, AnalyticsError> {
    let (plan, predicates) = AnalyticalPlanner::new()
        .compile(query)
        .map_err(AnalyticsError::Arrow)?;
    let dag = SelectivityOptimizer { selectivities: selectivities.clone() }
        .optimize(plan)
        .map_err(AnalyticsError::Arrow)?;
    let batches = episodes_to_batches(events)?;
    // As mesmas estimativas alimentam a decisão adaptativa de fusão do executor.
    let mut exec = VecExecutor::new(batches, predicates);
    exec.selectivities = selectivities;
    exec.execute(dag).map_err(AnalyticsError::Arrow)
}

// ── tokenizer + cursor ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Num(u64),
    Str(String),
    Op(CmpOp),
    Comma,
}

/// Nunca entra em pânico: qualquer entrada ⇒ `Ok(tokens)` ou `Err(msg)`.
fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            ',' => {
                chars.next();
                toks.push(Tok::Comma);
            }
            '=' => {
                chars.next();
                toks.push(Tok::Op(CmpOp::Eq));
            }
            '>' => {
                chars.next();
                toks.push(Tok::Op(CmpOp::Gt));
            }
            '<' => {
                chars.next();
                toks.push(Tok::Op(CmpOp::Lt));
            }
            '"' => {
                chars.next(); // abre aspas
                let mut s = String::new();
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == '"' {
                        closed = true;
                        break;
                    }
                    s.push(ch);
                }
                if !closed {
                    return Err(format!("string sem aspas de fecho: \"{s}"));
                }
                toks.push(Tok::Str(s));
            }
            c if c.is_alphanumeric() || c == '_' => {
                let mut w = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        w.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Ok(n) = w.parse::<u64>() {
                    toks.push(Tok::Num(n));
                } else {
                    toks.push(Tok::Word(w));
                }
            }
            other => return Err(format!("carácter inesperado `{other}`")),
        }
    }
    Ok(toks)
}

struct Cursor<'a> {
    toks: &'a [Tok],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }

    /// Case-insensitive keyword match on a `Word`.
    fn eat_word(&mut self, kw: &str) -> bool {
        match self.peek() {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw) => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }

    fn expect_word(&mut self, kw: &str) -> Result<(), String> {
        if self.eat_word(kw) {
            Ok(())
        } else {
            Err(format!("esperava `{kw}`, encontrei {:?}", self.peek()))
        }
    }

    fn eat_comma(&mut self) -> bool {
        if matches!(self.peek(), Some(Tok::Comma)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// A bareword identifier (column name). Rejects keywords-as-values only by
    /// context: any `Word` is accepted here and resolved by the caller.
    fn word(&mut self) -> Result<String, String> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.i += 1;
                Ok(w)
            }
            other => Err(format!("esperava um nome de coluna, encontrei {other:?}")),
        }
    }

    fn op(&mut self) -> Result<CmpOp, String> {
        match self.peek() {
            Some(Tok::Op(o)) => {
                let o = *o;
                self.i += 1;
                Ok(o)
            }
            other => Err(format!("esperava um operador (=,>,<), encontrei {other:?}")),
        }
    }

    /// A literal whose type must match the column (`is_str`): string columns
    /// take a quoted string, numeric columns take an integer.
    fn literal(&mut self, is_str: bool) -> Result<Literal, String> {
        match (self.peek(), is_str) {
            (Some(Tok::Str(s)), true) => {
                let v = Literal::Str(s.clone());
                self.i += 1;
                Ok(v)
            }
            (Some(Tok::Num(n)), false) => {
                let v = Literal::U64(*n);
                self.i += 1;
                Ok(v)
            }
            (Some(Tok::Str(_)), false) => {
                Err("coluna numérica exige um inteiro, não uma string".into())
            }
            (Some(Tok::Num(_)), true) => {
                Err("coluna de texto exige uma string entre aspas, não um inteiro".into())
            }
            (other, _) => Err(format!("esperava um literal, encontrei {other:?}")),
        }
    }

    fn expect_end(&mut self) -> Result<(), String> {
        if self.i == self.toks.len() {
            Ok(())
        } else {
            Err(format!("tokens a mais a partir de {:?}", &self.toks[self.i..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{StringArray, UInt64Array};
    use heraclitus_core::EventKind;

    fn eps(n: usize) -> Vec<(Lsn, Episode)> {
        (0..n)
            .map(|i| {
                let mut e = Episode::new(
                    if i % 2 == 0 { "alice" } else { "bob" },
                    if i % 3 == 0 { EventKind::Action } else { EventKind::Observation },
                    vec![0u8; i % 7],
                );
                e.ts_hlc = i as u64;
                (i as u64, e)
            })
            .collect()
    }

    #[test]
    fn parses_where_group_and_sum_into_logical_plan() {
        let planner = AnalyticalPlanner::new();
        let (plan, preds) = planner
            .compile("SELECT WHERE agent_id = \"alice\" AND lsn < 100 GROUP BY kind SUM content_len")
            .unwrap();
        // Dois predicados registados na ordem de aparição.
        assert_eq!(preds.len(), 2);
        assert_eq!(preds[0].column, 1); // agent_id
        assert!(matches!(preds[0].value, Literal::Str(ref s) if s == "alice"));
        assert_eq!(preds[1].column, 0); // lsn
        assert!(matches!((preds[1].op, &preds[1].value), (CmpOp::Lt, Literal::U64(100))));
        match plan {
            LogicalPlan::Select { relations, predicates, aggregate } => {
                assert_eq!(relations, vec!["events".to_string()]);
                assert_eq!(predicates, vec![0, 1]); // ids posicionais
                assert_eq!(aggregate, Some((vec![2], vec![4]))); // group by kind, sum content_len
            }
            other => panic!("esperava Select, veio {other:?}"),
        }
    }

    #[test]
    fn keywords_are_case_insensitive_and_where_is_optional() {
        let planner = AnalyticalPlanner::new();
        // Sem WHERE, sem SUM.
        let (plan, preds) = planner.compile("select group by agent_id").unwrap();
        assert!(preds.is_empty());
        assert!(matches!(
            plan,
            LogicalPlan::Select { aggregate: Some((ref k, ref s)), .. } if *k == vec![1] && s.is_empty()
        ));
    }

    #[test]
    fn rejects_bad_queries_without_panicking() {
        let p = AnalyticalPlanner::new();
        assert!(p.compile("SELECT WHERE nope = \"x\"").is_err()); // coluna inexistente
        assert!(p.compile("SELECT WHERE lsn < \"x\"").is_err()); // tipo trocado
        assert!(p.compile("SELECT WHERE agent_id = 5").is_err()); // tipo trocado
        assert!(p.compile("SELECT GROUP BY kind SUM agent_id").is_err()); // SUM de string
        assert!(p.compile("SELECT WHERE agent_id = \"unterminated").is_err()); // aspas abertas
        assert!(p.compile("SELECT WHERE lsn < 10 lixo").is_err()); // lixo à direita
        assert!(p.compile("").is_err()); // falta SELECT
    }

    #[test]
    fn planner_optimizer_executor_end_to_end_matches_brute_force() {
        // O caminho completo dos SPEC-024→012→013 a partir de uma STRING.
        let events = eps(3000);
        let out = run_analytical(
            "SELECT WHERE agent_id = \"alice\" AND lsn < 100 GROUP BY kind SUM content_len",
            &events,
            // p1 (lsn<100) é muito mais seletivo — o optimizer põe-no primeiro.
            HashMap::from([(0u32, 0.5), (1u32, 0.03)]),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        let b = &out[0];

        // Referência por força bruta.
        let mut expect: HashMap<String, (u64, u64)> = HashMap::new();
        for (l, e) in &events {
            if e.agent_id == "alice" && *l < 100 {
                let k = crate::kind_label(&e.kind);
                let en = expect.entry(k).or_default();
                en.0 += 1;
                en.1 += e.content.len() as u64;
            }
        }
        let keys = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        let counts = b.column(1).as_any().downcast_ref::<UInt64Array>().unwrap();
        let sums = b.column(2).as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(b.num_rows(), expect.len());
        for i in 0..b.num_rows() {
            let (c, s) = expect[keys.value(i)];
            assert_eq!(counts.value(i), c);
            assert_eq!(sums.value(i), s);
        }
    }

    #[test]
    fn gate_c_selectivity_hints_never_change_the_result() {
        // Mesmíssima query, hints de seletividade opostos ⇒ ordens de filtro
        // opostas no DAG ⇒ resultado bit-idêntico (Gate C, agora a partir de texto).
        let events = eps(3000);
        let q = "SELECT WHERE agent_id = \"alice\" AND lsn < 100 GROUP BY agent_id";
        let a = run_analytical(q, &events, HashMap::from([(0u32, 0.1), (1u32, 0.9)])).unwrap();
        let b = run_analytical(q, &events, HashMap::from([(0u32, 0.9), (1u32, 0.1)])).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}
