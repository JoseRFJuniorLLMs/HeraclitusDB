//! SPEC-012/013 — motor de execução vetorizada Arrow (v1 honesto).
//!
//! > **ESTADO: REFERÊNCIA DE I&D — NÃO LIGADO AO CAMINHO VIVO** (decisão P1,
//! > 2026-07-16 — `docs/md/DECISAO-P1-motor-analitico.md`). Nenhum handler do
//! > servidor/CLI/GQL invoca `VecExecutor`/`run_analytical`. A via de agregação
//! > sobre o log **ligada** é o `LogAnalytics` (DataFusion) em `POST /sql`, que
//! > não duplicamos (I4). Este módulo mantém-se como implementação de
//! > referência dos contratos SPEC-012/013 e substrato de I&D do `hume-kernel`;
//! > não o promover ao caminho vivo sem reabrir a decisão P1.
//!
//! O pipeline completo dos specs, a funcionar de verdade:
//!
//! ```text
//! LogicalPlan ──[SelectivityOptimizer/012]──▶ DAG de PhysicalIr
//!                                              │
//!                     VecExecutor (013) ───────┘
//!            batches Arrow de 1024 linhas · kernels colunares
//! ```
//!
//! - **Optimizer (SPEC-012):** baixa `LogicalPlan::Select` para um DAG de
//!   `ExecutionNode`, ordenando os filtros por **seletividade estimada**
//!   (mais seletivo primeiro) — a decisão cost-based clássica. A ordem muda a
//!   latência; **nunca muda o resultado** (Gate C, testado).
//! - **Executor (SPEC-013):** opera sobre `RecordBatch`es Arrow de
//!   [`BATCH_ROWS`] linhas. Filter usa o kernel colunar
//!   `filter_record_batch`; aggregate agrupa por chaves e soma colunas u64;
//!   hash join constrói do lado esquerdo e sonda o direito.
//! - **Contratos (SPEC-024):** implementa `Optimizer` e `TaskScheduler` do
//!   `heraclitus_core::contracts`.
//!
//! Honestidade de escopo: o SQL do `LogAnalytics` continua no DataFusion (que
//! JÁ é um motor vetorizado Arrow maduro — não o duplicamos). Este módulo é o
//! caminho de execução dos DAGs `PhysicalIr` dos specs: micro-planos
//! programáticos sobre o log, com a decisão de custo nossa e testável.
//! Loop-unrolling/AVX explícito fica para um benchmark que o justifique — os
//! kernels Arrow já são SIMD por baixo.

use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, RecordBatch, StringArray, UInt64Array,
};
use datafusion::arrow::compute::{concat_batches, filter_record_batch, take};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use heraclitus_core::contracts::{Optimizer, TaskScheduler};
use heraclitus_core::ir::{ExecutionNode, LogicalPlan, PhysicalIr};
use heraclitus_core::{Episode, Lsn};
use hume_kernel::{MorselSizer, SelectionVector};
use std::collections::HashMap;
use std::sync::Arc;

use crate::AnalyticsError;

/// Tamanho de lote fixo para *streaming* (SPEC-013). Já não é o default de
/// materialização (ver [`episodes_to_batches`], agora adaptativo), mas continua
/// a ser o chunk incremental do plano de dados Arrow Flight e o piso da escada
/// de morsels.
pub const BATCH_ROWS: usize = 1024;

// ── Fonte: episódios → batches Arrow (morsel adaptativo / tamanho fixo) ─────

/// Schema público da tabela `events` (Flight `get_schema`).
pub fn batch_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("lsn", DataType::UInt64, false),
        Field::new("agent_id", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("ts_hlc", DataType::UInt64, false),
        Field::new("content_len", DataType::UInt64, false),
    ]))
}

/// Materializa episódios em batches Arrow com **morsel adaptativo** (o default).
/// O tamanho do lote é escolhido pela largura da linha via
/// `hume_kernel::MorselSizer` (SPEC-0041 §2, Marco 3), em vez do antigo fixo de
/// 1024. O tamanho fixo continua disponível em [`episodes_to_batches_sized`].
///
/// **Invariante (Gate C):** o tamanho do morsel muda apenas a granularidade da
/// materialização, **nunca** o resultado da consulta a jusante — provado no
/// teste `gate_c_morsel_size_never_changes_results`.
pub fn episodes_to_batches(events: &[(Lsn, Episode)]) -> Result<Vec<RecordBatch>, AnalyticsError> {
    // Alvo: cache L2 típico (256 KiB). A linha do schema `events` é estreita —
    // 3 colunas u64 (lsn/ts/content_len) = 24 B fixos + 2 refs de string; usamos
    // os bytes fixos como estimativa conservadora da largura por linha.
    const L2_TARGET_BYTES: usize = 256 * 1024;
    const BYTES_PER_ROW: usize = 3 * std::mem::size_of::<u64>();
    let rows = MorselSizer::new(L2_TARGET_BYTES).fit(BYTES_PER_ROW);
    episodes_to_batches_sized(events, rows)
}

/// Materializa episódios em batches de tamanho **fixo** `rows_per_batch`.
/// É o caminho que o plano de dados Arrow Flight usa deliberadamente
/// (streaming incremental em lotes de [`BATCH_ROWS`]), e a base partilhada do
/// default adaptativo.
pub fn episodes_to_batches_sized(
    events: &[(Lsn, Episode)],
    rows_per_batch: usize,
) -> Result<Vec<RecordBatch>, AnalyticsError> {
    let rows_per_batch = rows_per_batch.max(1);
    let schema = batch_schema();
    let mut out = Vec::with_capacity(events.len().div_ceil(rows_per_batch));
    for chunk in events.chunks(rows_per_batch) {
        let lsn: UInt64Array = chunk.iter().map(|(l, _)| *l).collect();
        let agent: StringArray = chunk.iter().map(|(_, e)| Some(e.agent_id.as_str())).collect();
        let kind: StringArray = chunk
            .iter()
            .map(|(_, e)| Some(crate::kind_label(&e.kind)))
            .collect();
        let ts: UInt64Array = chunk.iter().map(|(_, e)| e.ts_hlc).collect();
        let clen: UInt64Array = chunk.iter().map(|(_, e)| e.content.len() as u64).collect();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(lsn) as ArrayRef,
                Arc::new(agent),
                Arc::new(kind),
                Arc::new(ts),
                Arc::new(clen),
            ],
        )
        .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        out.push(batch);
    }
    Ok(out)
}

// ── Predicados registados (referenciados por id no PhysicalIr) ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Gt,
    Lt,
}

#[derive(Debug, Clone)]
pub enum Literal {
    U64(u64),
    Str(String),
}

/// Um predicado colunar: `column <op> literal`.
#[derive(Debug, Clone)]
pub struct Predicate {
    pub column: usize,
    pub op: CmpOp,
    pub value: Literal,
}

/// Fecho de avaliação por-linha de um predicado: faz o `downcast` da coluna
/// UMA vez e devolve `Fn(row) -> bool`. É a fonte única da semântica de
/// comparação (usada tanto pelo `eval_predicate` denso como pelo retain esparso
/// do `fused_filter_one`), evitando divergência entre os dois caminhos.
fn predicate_matcher<'a>(
    batch: &'a RecordBatch,
    p: &'a Predicate,
) -> Result<Box<dyn Fn(usize) -> bool + 'a>, AnalyticsError> {
    let col = batch.column(p.column);
    let op = p.op;
    match (&p.value, col.data_type()) {
        (Literal::U64(v), DataType::UInt64) => {
            let a = col.as_any().downcast_ref::<UInt64Array>().unwrap();
            let v = *v;
            Ok(Box::new(move |i| match op {
                CmpOp::Eq => a.value(i) == v,
                CmpOp::Gt => a.value(i) > v,
                CmpOp::Lt => a.value(i) < v,
            }))
        }
        (Literal::Str(v), DataType::Utf8) => {
            let a = col.as_any().downcast_ref::<StringArray>().unwrap();
            let v = v.as_str();
            Ok(Box::new(move |i| match op {
                CmpOp::Eq => a.value(i) == v,
                CmpOp::Gt => a.value(i) > v,
                CmpOp::Lt => a.value(i) < v,
            }))
        }
        (lit, dt) => Err(AnalyticsError::Arrow(format!(
            "predicate type mismatch: literal {lit:?} vs column {dt}"
        ))),
    }
}

// Caminho eager: loop direto monomorfizado (rápido, sem dispatch dinâmico). NÃO
// partilha o `predicate_matcher` boxed de propósito — o `Box<dyn Fn>` custaria
// uma chamada virtual por linha e abrandaria o filtro vivo.
fn eval_predicate(batch: &RecordBatch, p: &Predicate) -> Result<BooleanArray, AnalyticsError> {
    let col = batch.column(p.column);
    let mask: BooleanArray = match (&p.value, col.data_type()) {
        (Literal::U64(v), DataType::UInt64) => {
            let a = col.as_any().downcast_ref::<UInt64Array>().unwrap();
            (0..a.len())
                .map(|i| {
                    Some(match p.op {
                        CmpOp::Eq => a.value(i) == *v,
                        CmpOp::Gt => a.value(i) > *v,
                        CmpOp::Lt => a.value(i) < *v,
                    })
                })
                .collect()
        }
        (Literal::Str(v), DataType::Utf8) => {
            let a = col.as_any().downcast_ref::<StringArray>().unwrap();
            (0..a.len())
                .map(|i| {
                    Some(match p.op {
                        CmpOp::Eq => a.value(i) == v.as_str(),
                        CmpOp::Gt => a.value(i) > v.as_str(),
                        CmpOp::Lt => a.value(i) < v.as_str(),
                    })
                })
                .collect()
        }
        (lit, dt) => {
            return Err(AnalyticsError::Arrow(format!(
                "predicate type mismatch: literal {lit:?} vs column {dt}"
            )))
        }
    };
    Ok(mask)
}

// ── SPEC-012: optimizer por seletividade ────────────────────────────────────

/// Baixa `LogicalPlan::Select` para o DAG físico, ordenando os filtros por
/// seletividade estimada (menor fração sobrevivente PRIMEIRO — corta mais
/// cedo). Sem estatística para um predicado, assume 0.5.
pub struct SelectivityOptimizer {
    /// `predicate_id → fração estimada de linhas que SOBREVIVEM (0..1)`.
    pub selectivities: HashMap<u32, f64>,
}

impl Optimizer for SelectivityOptimizer {
    fn optimize(&self, plan: LogicalPlan) -> Result<Vec<ExecutionNode>, String> {
        match plan {
            LogicalPlan::Select { predicates, aggregate, .. } => {
                let mut ordered = predicates;
                ordered.sort_by(|a, b| {
                    let sa = self.selectivities.get(a).copied().unwrap_or(0.5);
                    let sb = self.selectivities.get(b).copied().unwrap_or(0.5);
                    sa.total_cmp(&sb)
                });
                let mut nodes = vec![ExecutionNode::new(
                    0,
                    PhysicalIr::ColumnScan { projection: vec![] },
                    vec![],
                )];
                let mut prev = 0u64;
                for pid in ordered {
                    let id = nodes.len() as u64;
                    nodes.push(ExecutionNode::new(
                        id,
                        PhysicalIr::VectorFilter { predicate_id: pid },
                        vec![prev],
                    ));
                    prev = id;
                }
                if let Some((keys, aggs)) = aggregate {
                    let id = nodes.len() as u64;
                    nodes.push(ExecutionNode::new(
                        id,
                        PhysicalIr::VectorAggregate { keys, aggregations: aggs },
                        vec![prev],
                    ));
                }
                Ok(nodes)
            }
            other => Err(format!("SelectivityOptimizer: plano não suportado: {other:?}")),
        }
    }
}

// ── SPEC-013: executor vetorizado ───────────────────────────────────────────

/// Executa um DAG de `PhysicalIr` sobre batches Arrow. `sources[i]` alimenta o
/// i-ésimo `ColumnScan` do DAG (ordem de definição).
///
/// SPEC-026 wired: o executor consulta o [`CapabilityCatalog`] REAL do host —
/// com >1 CPU lógico e input grande, o filtro corre em PARALELO por batch
/// (threads com escopo, uma partição por CPU). A escolha muda a latência,
/// nunca o resultado (Gate C — a ordem dos batches é preservada por partição
/// indexada; testado serial vs paralelo bit-idêntico).
pub struct VecExecutor {
    pub sources: Vec<Vec<RecordBatch>>,
    pub predicates: Vec<Predicate>,
    pub capabilities: heraclitus_core::CapabilityCatalog,
    /// SPEC-033: pinar as worker threads do filtro paralelo a cores físicos
    /// (round-robin). Off por default — só compensa em multi-socket.
    pub pin_workers: bool,
    /// `predicate_id → fração sobrevivente estimada` (do `SelectivityOptimizer`).
    /// Alimenta a decisão ADAPTATIVA de fundir uma cadeia de filtros: só quando
    /// o produto estimado fica abaixo de [`ADAPTIVE_FUSE_THRESHOLD`]. Vazio ⇒
    /// 0.5 por predicado ⇒ nunca funde (caminho eager, o default seguro).
    pub selectivities: HashMap<u32, f64>,
}

/// Abaixo desta seletividade **final** estimada, fundir uma cadeia de filtros
/// (materialização tardia) compensa; acima, o eager é melhor. Calibrado pelo
/// benchmark `benches/fused_vs_sequential.rs` (ganho limpo só em ~0.01; empate
/// em ~0.1; perda em ~0.5) — 0.05 é o ponto conservador que colhe o ganho sem a
/// regressão de meio-termo.
pub const ADAPTIVE_FUSE_THRESHOLD: f64 = 0.05;

impl VecExecutor {
    pub fn new(source: Vec<RecordBatch>, predicates: Vec<Predicate>) -> Self {
        Self {
            sources: vec![source],
            predicates,
            capabilities: heraclitus_core::CapabilityCatalog::detect(),
            pin_workers: false,
            selectivities: HashMap::new(),
        }
    }

    /// Filtro simples de um predicado (materialização ansiosa via
    /// `filter_record_batch`). Público como primitiva de execução/benchmark.
    pub fn run_filter(
        &self,
        input: &[RecordBatch],
        pid: u32,
    ) -> Result<Vec<RecordBatch>, AnalyticsError> {
        let p = self
            .predicates
            .get(pid as usize)
            .ok_or_else(|| AnalyticsError::Arrow(format!("predicate {pid} não registado")))?
            .clone();
        let cpus = self.capabilities.logical_cpus.max(1);
        // SPEC-026: decisão capability-driven — paralelo só quando o host tem
        // CPUs e o input justifica o overhead de threads.
        if cpus > 1 && input.len() >= 4 {
            return self.run_filter_parallel(input, &p, cpus);
        }
        let mut out = Vec::with_capacity(input.len());
        for b in input {
            let fb = Self::filter_one(b, &p)?;
            if fb.num_rows() > 0 {
                out.push(fb);
            }
        }
        Ok(out)
    }

    fn filter_one(b: &RecordBatch, p: &Predicate) -> Result<RecordBatch, AnalyticsError> {
        let mask = eval_predicate(b, p)?;
        // Kernel colunar do Arrow — o filtro vetorizado real.
        filter_record_batch(b, &mask).map_err(|e| AnalyticsError::Arrow(e.to_string()))
    }

    /// Filtro paralelo: partições indexadas por chunk; a ordem global dos
    /// batches é reconstruída pelo índice ⇒ resultado idêntico ao serial.
    fn run_filter_parallel(
        &self,
        input: &[RecordBatch],
        p: &Predicate,
        cpus: usize,
    ) -> Result<Vec<RecordBatch>, AnalyticsError> {
        let chunk = input.len().div_ceil(cpus);
        let pin = self.pin_workers;
        let results: Vec<Result<Vec<RecordBatch>, AnalyticsError>> = std::thread::scope(|s| {
            let handles: Vec<_> = input
                .chunks(chunk)
                .enumerate()
                .map(|(wi, part)| {
                    s.spawn(move || {
                        // SPEC-033: afinidade round-robin worker→core (opt-in).
                        if pin {
                            let cores = core_affinity::get_core_ids().unwrap_or_default();
                            if !cores.is_empty() {
                                let _ = core_affinity::set_for_current(cores[wi % cores.len()]);
                            }
                        }
                        let mut out = Vec::with_capacity(part.len());
                        for b in part {
                            let fb = Self::filter_one(b, p)?;
                            if fb.num_rows() > 0 {
                                out.push(fb);
                            }
                        }
                        Ok(out)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut out = Vec::new();
        for r in results {
            out.extend(r?); // ordem por partição indexada = ordem global serial
        }
        Ok(out)
    }

    /// Filtro **fundido** de uma cadeia de predicados com materialização tardia
    /// (hume-kernel `SelectionVector` wired). Em vez de materializar um
    /// `RecordBatch` novo por predicado (N filtros ⇒ N cópias), acumula a
    /// seleção de todos os predicados num único `SelectionVector` — a moeda de
    /// troca do SPEC-0040 §5 — e materializa **uma só vez** no fim via `take()`.
    ///
    /// **VEREDICTO DO BENCHMARK v2 (medido, `benches/fused_vs_sequential.rs`):**
    /// depois de otimizado (retain esparso — o 2.º predicado avaliado só nas
    /// linhas sobreviventes — sem dupla varredura e com materialização única),
    /// este caminho **ganha ao eager em BAIXA seletividade** (~0.01 → ~20% mais
    /// rápido, faixas separadas), **empata** no meio (~0.1) e **ainda perde
    /// ~14%** a ~0.5 (o acesso disperso do retain domina). Não é ganho
    /// universal, e a variância da máquina é alta. Crossover físico: em queries
    /// muito seletivas a poupança de materialização domina; a meio, não.
    ///
    /// Por isso **NÃO é o `execute()` default** (regrediria queries a meio
    /// termo). Candidata a **wiring ADAPTATIVO**: usar só quando o
    /// `SelectivityOptimizer` estima seletividade final muito baixa. O resultado
    /// é sempre bit-idêntico ao filtro sequencial (Gate C).
    pub fn run_fused_filters(
        &self,
        input: &[RecordBatch],
        pids: &[u32],
    ) -> Result<Vec<RecordBatch>, AnalyticsError> {
        let preds: Vec<Predicate> = pids
            .iter()
            .map(|p| {
                self.predicates
                    .get(*p as usize)
                    .cloned()
                    .ok_or_else(|| AnalyticsError::Arrow(format!("predicate {p} não registado")))
            })
            .collect::<Result<_, _>>()?;
        let cpus = self.capabilities.logical_cpus.max(1);
        if cpus > 1 && input.len() >= 4 {
            let chunk = input.len().div_ceil(cpus);
            let pin = self.pin_workers;
            let preds_ref = &preds;
            let results: Vec<Result<Vec<RecordBatch>, AnalyticsError>> = std::thread::scope(|s| {
                let handles: Vec<_> = input
                    .chunks(chunk)
                    .enumerate()
                    .map(|(wi, part)| {
                        s.spawn(move || {
                            if pin {
                                let cores = core_affinity::get_core_ids().unwrap_or_default();
                                if !cores.is_empty() {
                                    let _ = core_affinity::set_for_current(cores[wi % cores.len()]);
                                }
                            }
                            let mut out = Vec::with_capacity(part.len());
                            for b in part {
                                let fb = Self::fused_filter_one(b, preds_ref)?;
                                if fb.num_rows() > 0 {
                                    out.push(fb);
                                }
                            }
                            Ok(out)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let mut out = Vec::new();
            for r in results {
                out.extend(r?);
            }
            return Ok(out);
        }
        let mut out = Vec::with_capacity(input.len());
        for b in input {
            let fb = Self::fused_filter_one(b, &preds)?;
            if fb.num_rows() > 0 {
                out.push(fb);
            }
        }
        Ok(out)
    }

    /// Materialização tardia de um batch (v2 — otimizada).
    ///
    /// - **Sem dupla varredura:** o 1.º predicado é avaliado numa única passagem
    ///   que já constrói a lista de índices sobreviventes (nada de `BooleanArray`
    ///   intermédio).
    /// - **AND no domínio esparso:** os predicados seguintes são avaliados
    ///   **só nas linhas sobreviventes** (`retain`) — a interseção acontece
    ///   sobre a lista esparsa que encolhe, sem tocar nas linhas já cortadas nem
    ///   materializar bitmaps densos.
    /// - **Materialização única:** um só `take()` no fim, das linhas finais.
    fn fused_filter_one(b: &RecordBatch, preds: &[Predicate]) -> Result<RecordBatch, AnalyticsError> {
        let n = b.num_rows();
        let mut survivors: Vec<u32> = if let Some((p0, rest)) = preds.split_first() {
            let m0 = predicate_matcher(b, p0)?;
            let mut s: Vec<u32> = (0..n).filter(|&i| m0(i)).map(|i| i as u32).collect();
            for p in rest {
                if s.is_empty() {
                    break;
                }
                let m = predicate_matcher(b, p)?;
                s.retain(|&i| m(i as usize));
            }
            s
        } else {
            (0..n as u32).collect()
        };
        // SelectionVector como container esparso adaptativo (sem bitmap denso no
        // caso esparso); `survivors` já está ordenado e único.
        let sel = SelectionVector::from_sorted_indices(n, std::mem::take(&mut survivors));
        let idx: UInt64Array = sel.to_indices().into_iter().map(|x| x as u64).collect();
        let cols: Result<Vec<ArrayRef>, AnalyticsError> = b
            .columns()
            .iter()
            .map(|c| take(c.as_ref(), &idx, None).map_err(|e| AnalyticsError::Arrow(e.to_string())))
            .collect();
        RecordBatch::try_new(b.schema(), cols?).map_err(|e| AnalyticsError::Arrow(e.to_string()))
    }

    fn run_aggregate(
        &self,
        input: &[RecordBatch],
        keys: &[u32],
        aggs: &[u32],
    ) -> Result<Vec<RecordBatch>, AnalyticsError> {
        // Pipeline breaker: consome tudo, emite um batch (chaves, count, somas).
        let mut groups: HashMap<Vec<String>, (u64, Vec<u64>)> = HashMap::new();
        for b in input {
            for row in 0..b.num_rows() {
                let key: Vec<String> = keys
                    .iter()
                    .map(|k| array_cell_string(b.column(*k as usize), row))
                    .collect();
                let entry = groups.entry(key).or_insert_with(|| (0, vec![0; aggs.len()]));
                entry.0 += 1;
                for (i, a) in aggs.iter().enumerate() {
                    let col = b.column(*a as usize);
                    if let Some(u) = col.as_any().downcast_ref::<UInt64Array>() {
                        entry.1[i] += u.value(row);
                    }
                }
            }
        }
        // Saída determinística: ordena por chave.
        let mut rows: Vec<(Vec<String>, (u64, Vec<u64>))> = groups.into_iter().collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        let mut fields: Vec<Field> = keys
            .iter()
            .enumerate()
            .map(|(i, _)| Field::new(format!("key{i}"), DataType::Utf8, false))
            .collect();
        fields.push(Field::new("count", DataType::UInt64, false));
        for (i, _) in aggs.iter().enumerate() {
            fields.push(Field::new(format!("sum{i}"), DataType::UInt64, false));
        }
        let schema = Arc::new(Schema::new(fields));

        let mut cols: Vec<ArrayRef> = Vec::new();
        for i in 0..keys.len() {
            let a: StringArray = rows.iter().map(|(k, _)| Some(k[i].as_str())).collect();
            cols.push(Arc::new(a));
        }
        cols.push(Arc::new(rows.iter().map(|(_, (c, _))| *c).collect::<UInt64Array>()));
        for i in 0..aggs.len() {
            cols.push(Arc::new(
                rows.iter().map(|(_, (_, s))| s[i]).collect::<UInt64Array>(),
            ));
        }
        let batch = RecordBatch::try_new(schema, cols)
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        Ok(vec![batch])
    }

    fn run_hash_join(
        &self,
        left: &[RecordBatch],
        right: &[RecordBatch],
        lk: u32,
        rk: u32,
    ) -> Result<Vec<RecordBatch>, AnalyticsError> {
        if left.is_empty() || right.is_empty() {
            return Ok(Vec::new());
        }
        // BUILD: hash do lado esquerdo inteiro (chave → índices de linha).
        let lschema = left[0].schema();
        let lall = concat_batches(&lschema, left).map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        let mut table: HashMap<String, Vec<usize>> = HashMap::new();
        for row in 0..lall.num_rows() {
            table
                .entry(array_cell_string(lall.column(lk as usize), row))
                .or_default()
                .push(row);
        }
        // PROBE: lado direito em streaming; emite (esq ++ dir) por par casado.
        let rschema = right[0].schema();
        let rall = concat_batches(&rschema, right).map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        let (mut lrows, mut rrows): (Vec<usize>, Vec<usize>) = (Vec::new(), Vec::new());
        for rrow in 0..rall.num_rows() {
            if let Some(ls) = table.get(&array_cell_string(rall.column(rk as usize), rrow)) {
                for l in ls {
                    lrows.push(*l);
                    rrows.push(rrow);
                }
            }
        }
        // Materializa o resultado com take() por índice.
        let lidx: UInt64Array = lrows.iter().map(|i| *i as u64).collect();
        let ridx: UInt64Array = rrows.iter().map(|i| *i as u64).collect();
        let take = |b: &RecordBatch, idx: &UInt64Array| -> Result<Vec<ArrayRef>, AnalyticsError> {
            b.columns()
                .iter()
                .map(|c| {
                    datafusion::arrow::compute::take(c.as_ref(), idx, None)
                        .map_err(|e| AnalyticsError::Arrow(e.to_string()))
                })
                .collect()
        };
        let mut cols = take(&lall, &lidx)?;
        cols.extend(take(&rall, &ridx)?);
        let mut fields: Vec<Field> = lschema.fields().iter().map(|f| f.as_ref().clone()).collect();
        fields.extend(
            rschema
                .fields()
                .iter()
                .map(|f| Field::new(format!("{}_r", f.name()), f.data_type().clone(), true)),
        );
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), cols)
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        Ok(vec![batch])
    }
}

fn array_cell_string(col: &ArrayRef, row: usize) -> String {
    if let Some(s) = col.as_any().downcast_ref::<StringArray>() {
        s.value(row).to_string()
    } else if let Some(u) = col.as_any().downcast_ref::<UInt64Array>() {
        u.value(row).to_string()
    } else {
        format!("{:?}", col.slice(row, 1))
    }
}

impl TaskScheduler for VecExecutor {
    type Batch = RecordBatch;

    /// Executa o DAG em ordem topológica (deps antes do nó — validado pelo
    /// `PhysicalPlan::is_well_formed`); devolve os batches do nó final.
    fn execute(&self, dag: Vec<ExecutionNode>) -> Result<Vec<RecordBatch>, String> {
        // WIRING ADAPTATIVO (benchmark v2): uma cadeia de filtros consecutivos é
        // FUNDIDA (materialização tardia) só quando a seletividade final
        // estimada fica abaixo de ADAPTIVE_FUSE_THRESHOLD — o regime onde o
        // benchmark mostra ganho. Caso contrário corre eager (um filtro por
        // passo). A escolha muda a latência, NUNCA o resultado (Gate C testado).
        let mut consumers: HashMap<u64, usize> = HashMap::new();
        for node in &dag {
            for d in &node.dependencies {
                *consumers.entry(*d).or_insert(0) += 1;
            }
        }
        let mut results: HashMap<u64, Vec<RecordBatch>> = HashMap::new();
        let mut scans_seen = 0usize;
        let mut last = None;
        let mut i = 0;
        while i < dag.len() {
            let node = &dag[i];
            let (out, produced_id, next_i) = match &node.operation {
                PhysicalIr::ColumnScan { .. } => {
                    let src = self
                        .sources
                        .get(scans_seen)
                        .ok_or_else(|| format!("sem source para o ColumnScan #{scans_seen}"))?
                        .clone();
                    scans_seen += 1;
                    (src, node.node_id, i + 1)
                }
                PhysicalIr::VectorFilter { predicate_id } => {
                    // Cadeia maximal de filtros consecutivos (guarda de consumidor
                    // único → seguro em DAGs com fan-out).
                    let mut pids = vec![*predicate_id];
                    let mut j = i;
                    while j + 1 < dag.len() {
                        let nxt = &dag[j + 1];
                        let chains =
                            nxt.dependencies.len() == 1 && nxt.dependencies[0] == dag[j].node_id;
                        let single = consumers.get(&dag[j].node_id).copied().unwrap_or(0) == 1;
                        if let (true, true, PhysicalIr::VectorFilter { predicate_id: np }) =
                            (chains, single, &nxt.operation)
                        {
                            pids.push(*np);
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    // Seletividade final estimada = produto (0.5 por omissão).
                    let est: f64 = pids
                        .iter()
                        .map(|p| self.selectivities.get(p).copied().unwrap_or(0.5))
                        .product();
                    let out = {
                        let input = results.get(&node.dependencies[0]).ok_or("filter sem input")?;
                        if pids.len() >= 2 && est < ADAPTIVE_FUSE_THRESHOLD {
                            // Muito seletivo → materialização tardia (fundido).
                            self.run_fused_filters(input, &pids).map_err(|e| e.to_string())?
                        } else {
                            // Eager: um filtro por passo (materializa entre eles).
                            let mut cur =
                                self.run_filter(input, pids[0]).map_err(|e| e.to_string())?;
                            for &pid in &pids[1..] {
                                cur = self.run_filter(&cur, pid).map_err(|e| e.to_string())?;
                            }
                            cur
                        }
                    };
                    (out, dag[j].node_id, j + 1)
                }
                PhysicalIr::VectorAggregate { keys, aggregations } => {
                    let out = {
                        let input =
                            results.get(&node.dependencies[0]).ok_or("aggregate sem input")?;
                        self.run_aggregate(input, keys, aggregations)
                            .map_err(|e| e.to_string())?
                    };
                    (out, node.node_id, i + 1)
                }
                PhysicalIr::HashJoin { left_key, right_key } => {
                    let out = {
                        let l = results.get(&node.dependencies[0]).ok_or("join sem lado esq")?;
                        let r = results.get(&node.dependencies[1]).ok_or("join sem lado dir")?;
                        self.run_hash_join(l, r, *left_key, *right_key)
                            .map_err(|e| e.to_string())?
                    };
                    (out, node.node_id, i + 1)
                }
            };
            results.insert(produced_id, out);
            last = Some(produced_id);
            i = next_i;
        }
        let last = last.ok_or("DAG vazio")?;
        Ok(results.remove(&last).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn default_is_adaptive_morsel() {
        // O default passou a adaptativo: a linha de `events` é estreita → o
        // MorselSizer sobe ao topo da escada (131 072), logo 3000 episódios
        // cabem num único batch.
        let b = episodes_to_batches(&eps(3000)).unwrap();
        assert_eq!(b.len(), 1, "default adaptativo agrega linhas estreitas");
        assert_eq!(b[0].num_rows(), 3000);
    }

    #[test]
    fn fixed_sized_batching_still_available() {
        // O caminho fixo (usado pelo streaming Flight) continua a existir e a
        // fatiar em lotes de 1024 — o contrato SPEC-013, agora explícito.
        let b = episodes_to_batches_sized(&eps(3000), BATCH_ROWS).unwrap();
        let sizes: Vec<usize> = b.iter().map(|x| x.num_rows()).collect();
        assert_eq!(sizes, vec![1024, 1024, 952], "SPEC-013: lotes fixos de 1024");
    }

    #[test]
    fn gate_c_morsel_size_never_changes_results() {
        // Gate C aplicado ao dimensionamento de morsel (hume-kernel wired):
        // o tamanho do lote muda a granularidade da materialização, NUNCA um bit
        // do resultado. Mesmo DAG, fontes fatiadas de forma diferente (1024 fixo
        // vs. adaptativo default) → saída bit-idêntica.
        let events = eps(3000);
        let fixed =
            VecExecutor::new(episodes_to_batches_sized(&events, BATCH_ROWS).unwrap(), preds());
        let adaptive = VecExecutor::new(episodes_to_batches(&events).unwrap(), preds());
        let dag = || {
            SelectivityOptimizer { selectivities: HashMap::new() }
                .optimize(LogicalPlan::Select {
                    relations: vec![],
                    predicates: vec![0, 1],
                    aggregate: Some((vec![2], vec![4])), // group by kind; sum content_len
                })
                .unwrap()
        };
        let a = fixed.execute(dag()).unwrap();
        let b = adaptive.execute(dag()).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "morsel-size ≡ resultado bit a bit");
    }

    fn preds() -> Vec<Predicate> {
        vec![
            // p0: agent_id == "alice"  (sobrevive ~50%)
            Predicate { column: 1, op: CmpOp::Eq, value: Literal::Str("alice".into()) },
            // p1: lsn < 100            (sobrevive ~3%)
            Predicate { column: 0, op: CmpOp::Lt, value: Literal::U64(100) },
        ]
    }

    #[test]
    fn fused_filters_equal_sequential_late_materialization() {
        // A primitiva fundida (run_fused_filters, materialização tardia via
        // SelectionVector) dá bit-idêntico ao filtro sequencial. Prova de
        // CORREÇÃO — a performance está no benchmark (e perde ao eager).
        let batches = episodes_to_batches_sized(&eps(3000), 512).unwrap(); // 6 batches
        let mut exec = VecExecutor::new(batches.clone(), preds());
        exec.capabilities.logical_cpus = 1; // serial determinístico
        let fused = exec.run_fused_filters(&batches, &[0, 1]).unwrap();

        // Referência: a materialização ANSIOSA (dois filter_record_batch).
        let p = preds();
        let mut refb = Vec::new();
        for b in &batches {
            let m0 = eval_predicate(b, &p[0]).unwrap();
            let f0 = filter_record_batch(b, &m0).unwrap();
            let m1 = eval_predicate(&f0, &p[1]).unwrap();
            let f1 = filter_record_batch(&f0, &m1).unwrap();
            if f1.num_rows() > 0 {
                refb.push(f1);
            }
        }
        let sch = batch_schema();
        let f = concat_batches(&sch, &fused).unwrap();
        let r = concat_batches(&sch, &refb).unwrap();
        assert!(f.num_rows() > 0, "há sobreviventes (alice ∩ lsn<100)");
        assert_eq!(format!("{f:?}"), format!("{r:?}"), "fundido ≡ sequencial, bit a bit");
    }

    #[test]
    fn gate_c_adaptive_fusion_never_changes_results() {
        // O wiring adaptativo escolhe fundido (baixa seletividade) ou eager, mas
        // o resultado tem de ser bit-idêntico entre as duas rotas — a escolha só
        // muda a latência.
        let batches = episodes_to_batches_sized(&eps(3000), 512).unwrap();
        let dag = || {
            vec![
                ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![] }, vec![]),
                ExecutionNode::new(1, PhysicalIr::VectorFilter { predicate_id: 0 }, vec![0]),
                ExecutionNode::new(2, PhysicalIr::VectorFilter { predicate_id: 1 }, vec![1]),
            ]
        };
        // Rota fundida: seletividade final estimada 0.03·0.5 = 0.015 < 0.05.
        let mut fused_route = VecExecutor::new(batches.clone(), preds());
        fused_route.selectivities = HashMap::from([(0u32, 0.03), (1u32, 0.5)]);
        // Rota eager: sem estimativas ⇒ 0.5·0.5 = 0.25 > 0.05.
        let eager_route = VecExecutor::new(batches, preds());

        let a = fused_route.execute(dag()).unwrap();
        let b = eager_route.execute(dag()).unwrap();
        assert!(!a.is_empty(), "há sobreviventes");
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "adaptativo (fundido) ≡ eager, bit a bit");
    }

    #[test]
    fn fused_filter_parallel_equals_serial() {
        // Gate C na primitiva fundida: paralelo (partições indexadas) ≡ serial.
        let batches = episodes_to_batches_sized(&eps(4096), 512).unwrap(); // 8 batches
        let mut serial = VecExecutor::new(batches.clone(), preds());
        serial.capabilities.logical_cpus = 1;
        let mut parallel = VecExecutor::new(batches.clone(), preds());
        parallel.capabilities.logical_cpus = 8;
        let a = serial.run_fused_filters(&batches, &[0, 1]).unwrap();
        let b = parallel.run_fused_filters(&batches, &[0, 1]).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "fundido paralelo ≡ serial");
    }

    #[test]
    fn optimizer_orders_filters_by_selectivity() {
        // SPEC-012: o filtro MAIS seletivo (p1: 3%) vai primeiro.
        let opt = SelectivityOptimizer {
            selectivities: HashMap::from([(0u32, 0.5), (1u32, 0.03)]),
        };
        let dag = opt
            .optimize(LogicalPlan::Select {
                relations: vec!["events".into()],
                predicates: vec![0, 1],
                aggregate: None,
            })
            .unwrap();
        let order: Vec<u32> = dag
            .iter()
            .filter_map(|n| match n.operation {
                PhysicalIr::VectorFilter { predicate_id } => Some(predicate_id),
                _ => None,
            })
            .collect();
        assert_eq!(order, vec![1, 0], "mais seletivo primeiro");
        assert!(heraclitus_core::ir::PhysicalPlan { nodes: dag }.is_well_formed());
    }

    #[test]
    fn filter_and_aggregate_match_brute_force() {
        let events = eps(3000);
        let batches = episodes_to_batches(&events).unwrap();
        let exec = VecExecutor::new(batches, preds());
        let opt = SelectivityOptimizer { selectivities: HashMap::new() };
        // WHERE agent=alice AND lsn<100 GROUP BY kind → count por kind.
        let dag = opt
            .optimize(LogicalPlan::Select {
                relations: vec![],
                predicates: vec![0, 1],
                aggregate: Some((vec![2], vec![4])), // group by kind; sum content_len
            })
            .unwrap();
        let out = exec.execute(dag).unwrap();
        assert_eq!(out.len(), 1);
        let b = &out[0];

        // Força bruta de referência.
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
            assert_eq!(counts.value(i), c, "count de {}", keys.value(i));
            assert_eq!(sums.value(i), s, "sum de {}", keys.value(i));
        }
    }

    #[test]
    fn gate_c_plan_order_never_changes_results() {
        // Gate C: planos físicos diferentes (ordens de filtro opostas) mudam a
        // latência, NUNCA um bit do resultado.
        let batches = episodes_to_batches(&eps(3000)).unwrap();
        let exec = VecExecutor::new(batches, preds());
        let plan = |sel: HashMap<u32, f64>| {
            SelectivityOptimizer { selectivities: sel }
                .optimize(LogicalPlan::Select {
                    relations: vec![],
                    predicates: vec![0, 1],
                    aggregate: Some((vec![1], vec![])), // group by agent
                })
                .unwrap()
        };
        let a = exec
            .execute(plan(HashMap::from([(0u32, 0.1), (1u32, 0.9)])))
            .unwrap();
        let b = exec
            .execute(plan(HashMap::from([(0u32, 0.9), (1u32, 0.1)])))
            .unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "bit-idêntico");
    }

    #[test]
    fn spec026_parallel_and_serial_filters_are_bit_identical() {
        // SPEC-026: a decisão capability-driven (paralelo vs serial) NUNCA muda
        // o resultado — só a latência (Gate C aplicado ao paralelismo).
        // Tamanho fixo de 1024 (8 batches) para exercitar de facto o caminho
        // multi-batch paralelo, independentemente do default adaptativo.
        let batches = episodes_to_batches_sized(&eps(8192), BATCH_ROWS).unwrap(); // 8 batches
        let mut serial = VecExecutor::new(batches.clone(), preds());
        serial.capabilities.logical_cpus = 1; // força o caminho serial
        let mut parallel = VecExecutor::new(batches, preds());
        parallel.capabilities.logical_cpus = 8; // força o caminho paralelo

        let dag = || {
            vec![
                ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![] }, vec![]),
                ExecutionNode::new(1, PhysicalIr::VectorFilter { predicate_id: 0 }, vec![0]),
            ]
        };
        let a = serial.execute(dag()).unwrap();
        let b = parallel.execute(dag()).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "paralelo ≡ serial, bit a bit");
        assert!(!a.is_empty());
    }

    #[test]
    fn spec033_worker_pinning_executes_and_preserves_results() {
        // SPEC-033: com pin_workers, as worker threads pedem afinidade a cores
        // reais (round-robin). Em qualquer host o resultado é idêntico.
        // Tamanho fixo (múltiplos batches) para exercitar o round-robin real.
        let batches = episodes_to_batches_sized(&eps(8192), BATCH_ROWS).unwrap();
        let mut pinned = VecExecutor::new(batches.clone(), preds());
        pinned.capabilities.logical_cpus = 4;
        pinned.pin_workers = true;
        let plain = VecExecutor::new(batches, preds());

        let dag = || {
            vec![
                ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![] }, vec![]),
                ExecutionNode::new(1, PhysicalIr::VectorFilter { predicate_id: 1 }, vec![0]),
            ]
        };
        let a = pinned.execute(dag()).unwrap();
        let b = plain.execute(dag()).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        // E o próprio mecanismo de afinidade funciona neste host:
        let cores = core_affinity::get_core_ids().unwrap_or_default();
        if let Some(c) = cores.first() {
            assert!(core_affinity::set_for_current(*c), "pinning real no host");
        }
    }

    #[test]
    fn hash_join_pairs_matching_keys() {
        // Duas fontes juntas por agent_id (coluna 1 dos dois lados).
        let left = episodes_to_batches(&eps(10)).unwrap(); // 5 alice, 5 bob
        let right = episodes_to_batches(&eps(4)).unwrap(); // 2 alice, 2 bob
        let exec = VecExecutor {
            sources: vec![left, right],
            predicates: vec![],
            capabilities: heraclitus_core::CapabilityCatalog::detect(),
            pin_workers: false,
            selectivities: HashMap::new(),
        };
        let dag = vec![
            ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![] }, vec![]),
            ExecutionNode::new(1, PhysicalIr::ColumnScan { projection: vec![] }, vec![]),
            ExecutionNode::new(2, PhysicalIr::HashJoin { left_key: 1, right_key: 1 }, vec![0, 1]),
        ];
        let out = exec.execute(dag).unwrap();
        // 5 alice × 2 alice + 5 bob × 2 bob = 20 pares.
        assert_eq!(out[0].num_rows(), 20);
        // Chave igual dos dois lados em todas as linhas.
        let l = out[0].column(1).as_any().downcast_ref::<StringArray>().unwrap();
        let ridx = out[0].schema().index_of("agent_id_r").unwrap();
        let r = out[0].column(ridx).as_any().downcast_ref::<StringArray>().unwrap();
        for i in 0..out[0].num_rows() {
            assert_eq!(l.value(i), r.value(i));
        }
    }
}
