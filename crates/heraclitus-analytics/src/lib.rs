//! heraclitus-analytics — SQL analítico (DataFusion) sobre o log imutável.
//!
//! O log é *append-only* e a verdade; esta camada é **read-only** e derivada:
//! materializa os episódios num `RecordBatch` colunar (Apache Arrow — o mesmo
//! schema do espelho Parquet do `heraclitus-tier`) e regista-o como a tabela
//! `events` numa `SessionContext` do DataFusion. SQL OLAP (`SELECT ... GROUP
//! BY ...`) corre sobre isso sem descodificar bincode à mão e **sem tocar no
//! core**. Um snapshot `AS OF LSN n` limita a materialização a `lsn < n`.
//!
//! ```no_run
//! # async fn demo(log: &heraclitus_log::Log) -> Result<(), heraclitus_analytics::AnalyticsError> {
//! let a = heraclitus_analytics::LogAnalytics::from_log(log, None)?;
//! let rows = a.sql("SELECT agent_id, COUNT(*) AS n FROM events GROUP BY agent_id ORDER BY n DESC").await?;
//! # Ok(()) }
//! ```

pub use datafusion;
pub mod flight; // SPEC-016: data plane Flight (Arrow IPC) sobre o log
pub mod planner; // SPEC-024: Planner (query string → LogicalPlan) — front-end do Compiler 1
pub mod vectorized; // SPEC-012/013: motor de execução vetorizada Arrow

use datafusion::arrow::array::{ArrayRef, RecordBatch, StringArray, UInt64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use heraclitus_core::{EventKind, HeraclitusError, Lsn};
use heraclitus_log::Log;
use std::sync::Arc;

#[derive(Debug)]
pub enum AnalyticsError {
    Log(HeraclitusError),
    Arrow(String),
    Sql(String),
    /// A materialização excedeu o orçamento de linhas/bytes desta chamada.
    Budget {
        limit: String,
        rows: usize,
        bytes: usize,
    },
}

impl std::fmt::Display for AnalyticsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyticsError::Log(e) => write!(f, "log: {e}"),
            AnalyticsError::Arrow(e) => write!(f, "arrow: {e}"),
            AnalyticsError::Sql(e) => write!(f, "sql: {e}"),
            AnalyticsError::Budget { limit, rows, bytes } => write!(
                f,
                "orçamento de materialização excedido ({limit}): {rows} linhas, \
                 ~{bytes} bytes — restrinja com `as_of` (AS OF LSN) para limitar \
                 a janela do log materializada"
            ),
        }
    }
}
impl std::error::Error for AnalyticsError {}
impl From<HeraclitusError> for AnalyticsError {
    fn from(e: HeraclitusError) -> Self {
        AnalyticsError::Log(e)
    }
}

pub(crate) fn kind_label(k: &EventKind) -> String {
    match k {
        EventKind::Custom(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// Tecto por omissão de linhas materializadas numa sessão de analytics.
pub const DEFAULT_MAX_ROWS: usize = 5_000_000;
/// Tecto por omissão (aproximado) de bytes residentes numa sessão de analytics.
pub const DEFAULT_MAX_BYTES: usize = 512 * 1024 * 1024;

/// Sessão de analytics com a tabela `events` materializada do log.
pub struct LogAnalytics {
    ctx: SessionContext,
}

impl LogAnalytics {
    /// Materializa `events` a partir do log com o orçamento por omissão
    /// ([`DEFAULT_MAX_ROWS`] / [`DEFAULT_MAX_BYTES`]). Ver [`Self::from_log_capped`].
    pub fn from_log(log: &Log, as_of: Option<Lsn>) -> Result<Self, AnalyticsError> {
        Self::from_log_capped(log, as_of, DEFAULT_MAX_ROWS, DEFAULT_MAX_BYTES)
    }

    /// Materializa `events` a partir do log. `as_of = Some(n)` limita a
    /// `lsn < n` (snapshot temporal); `None` = tudo até ao head.
    ///
    /// **Orçamento (admission control).** O scan é janelado, mas as colunas
    /// ACUMULAM ao longo das janelas — o pico de RAM era, portanto, o log
    /// INTEIRO, e a janela não limitava nada disso. Um `POST /sql` autorizado
    /// sobre um log grande derrubava o servidor por OOM. `max_rows`/`max_bytes`
    /// cortam a materialização a meio e devolvem [`AnalyticsError::Budget`],
    /// para o pedido falhar depressa e barato em vez de matar o processo.
    ///
    /// O corte é verificado POR JANELA (não só no fim): o custo máximo excedido
    /// é de uma janela de `scan_capped`, não do log todo.
    pub fn from_log_capped(
        log: &Log,
        as_of: Option<Lsn>,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Self, AnalyticsError> {
        let head = log.head();
        let to = as_of.unwrap_or(head).min(head);
        let mut approx_bytes: usize = 0;

        let mut lsns: Vec<u64> = Vec::new();
        let mut ids: Vec<String> = Vec::new();
        let mut agents: Vec<String> = Vec::new();
        let mut sessions: Vec<String> = Vec::new();
        let mut ts: Vec<u64> = Vec::new();
        let mut kinds: Vec<String> = Vec::new();
        let mut contents: Vec<String> = Vec::new();
        let mut attrs_json: Vec<String> = Vec::new();
        let mut valid_from: Vec<u64> = Vec::new();
        let mut valid_to: Vec<u64> = Vec::new();

        let mut cur = 0u64;
        while cur < to {
            let batch = log.scan_capped(cur, to, 50_000)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (lsn, e) in &batch {
                let content = String::from_utf8_lossy(&e.content).into_owned();
                let attrs = serde_json::to_string(&e.attrs).unwrap_or_else(|_| "{}".into());
                // Custo residente aproximado desta linha: as colunas variáveis
                // dominam; os 5 campos fixos (u64) somam 40 bytes.
                approx_bytes = approx_bytes.saturating_add(
                    content.len()
                        + attrs.len()
                        + e.agent_id.len()
                        + e.session_id.len()
                        + 40
                        + 26 // ULID em texto
                        + 16, // rótulo de kind (estimativa)
                );
                lsns.push(*lsn);
                ids.push(e.id.to_string());
                agents.push(e.agent_id.clone());
                sessions.push(e.session_id.clone());
                ts.push(e.ts_hlc);
                kinds.push(kind_label(&e.kind));
                contents.push(content);
                attrs_json.push(attrs);
                valid_from.push(e.valid_from.unwrap_or(0));
                valid_to.push(e.valid_to.unwrap_or(0));
            }

            if lsns.len() > max_rows {
                return Err(AnalyticsError::Budget {
                    limit: format!("max_rows={max_rows}"),
                    rows: lsns.len(),
                    bytes: approx_bytes,
                });
            }
            if approx_bytes > max_bytes {
                return Err(AnalyticsError::Budget {
                    limit: format!("max_bytes={max_bytes}"),
                    rows: lsns.len(),
                    bytes: approx_bytes,
                });
            }
            cur = last + 1;
        }

        let schema = Arc::new(Schema::new(vec![
            Field::new("lsn", DataType::UInt64, false),
            Field::new("id", DataType::Utf8, false),
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("session_id", DataType::Utf8, false),
            Field::new("ts_hlc", DataType::UInt64, false),
            Field::new("kind", DataType::Utf8, false),
            Field::new("content", DataType::Utf8, false),
            Field::new("attrs_json", DataType::Utf8, false),
            // 0 = ausente (aberto); o SQL pode filtrar `valid_from > 0`.
            Field::new("valid_from", DataType::UInt64, false),
            Field::new("valid_to", DataType::UInt64, false),
        ]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(UInt64Array::from(lsns)) as ArrayRef,
                Arc::new(StringArray::from(ids)),
                Arc::new(StringArray::from(agents)),
                Arc::new(StringArray::from(sessions)),
                Arc::new(UInt64Array::from(ts)),
                Arc::new(StringArray::from(kinds)),
                Arc::new(StringArray::from(contents)),
                Arc::new(StringArray::from(attrs_json)),
                Arc::new(UInt64Array::from(valid_from)),
                Arc::new(UInt64Array::from(valid_to)),
            ],
        )
        .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;

        let ctx = SessionContext::new();
        let table = MemTable::try_new(schema, vec![vec![batch]])
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        ctx.register_table("events", Arc::new(table))
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        Ok(Self { ctx })
    }

    /// Executa SQL sobre `events` e devolve as linhas como `Vec` de objetos
    /// JSON (uma chave por coluna). A fonte é imutável — isto é read-only.
    pub async fn sql(&self, query: &str) -> Result<Vec<serde_json::Value>, AnalyticsError> {
        // SÓ leitura, imposto (não só documentado): sem SQLOptions, o `sql()`
        // do DataFusion aceita DDL/DML/statements — p.ex. `CREATE EXTERNAL
        // TABLE ... LOCATION '/qualquer/ficheiro'` lia ficheiros arbitrários do
        // servidor através de um endpoint "read-only".
        let opts = datafusion::execution::context::SQLOptions::new()
            .with_allow_ddl(false)
            .with_allow_dml(false)
            .with_allow_statements(false);
        let df = self
            .ctx
            .sql_with_options(query, opts)
            .await
            .map_err(|e| AnalyticsError::Sql(e.to_string()))?;
        let batches = df
            .collect()
            .await
            .map_err(|e| AnalyticsError::Sql(e.to_string()))?;
        let buf = Vec::new();
        let mut writer = datafusion::arrow::json::ArrayWriter::new(buf);
        for b in &batches {
            writer
                .write(b)
                .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        }
        writer
            .finish()
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        let bytes = writer.into_inner();
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        Ok(value.as_array().cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, FsyncPolicy};

    #[tokio::test]
    async fn sql_group_by_over_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..12 {
            let mut e = Episode::new(
                if i % 3 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                format!("evento {i}").into_bytes(),
            );
            e.attrs.insert("topic".into(), "rios".into());
            log.append(e).unwrap();
        }

        let a = LogAnalytics::from_log(&log, None).unwrap();
        let rows = a
            .sql("SELECT agent_id, COUNT(*) AS n FROM events GROUP BY agent_id ORDER BY agent_id")
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["agent_id"], "alice");
        assert_eq!(rows[0]["n"], 4);
        assert_eq!(rows[1]["agent_id"], "bob");
        assert_eq!(rows[1]["n"], 8);

        // Snapshot AS OF: só lsn < 6.
        let a6 = LogAnalytics::from_log(&log, Some(6)).unwrap();
        let total = a6.sql("SELECT COUNT(*) AS n FROM events").await.unwrap();
        assert_eq!(total[0]["n"], 6);

        // Colunas de valid time expostas ao SQL.
        let cols = a
            .sql("SELECT lsn, kind, valid_from FROM events WHERE lsn = 0")
            .await
            .unwrap();
        assert_eq!(cols[0]["kind"], "Observation");
        assert_eq!(cols[0]["valid_from"], 0);
    }

    /// ADMISSION CONTROL: o scan era janelado mas as colunas ACUMULAM ao longo
    /// das janelas, por isso o pico de RAM era o log INTEIRO — um `POST /sql`
    /// autorizado sobre um log grande derrubava o servidor por OOM, e o
    /// `tokio::time::timeout` à volta do `spawn_blocking` não protegia nada
    /// (não cancela a tarefa bloqueante). O corte tem de ser DENTRO do trabalho.
    #[test]
    fn materializacao_respeita_o_orcamento() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..40 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("evento {i} {}", "x".repeat(200)).into_bytes(),
            ))
            .unwrap();
        }

        // Teto de linhas: corta e identifica o limite que estourou.
        match LogAnalytics::from_log_capped(&log, None, 10, usize::MAX) {
            Err(AnalyticsError::Budget { limit, rows, .. }) => {
                assert!(limit.contains("max_rows"), "limite reportado: {limit}");
                assert!(rows > 10, "reporta as linhas efetivamente materializadas");
            }
            Err(e) => panic!("erro errado: {e}"),
            Ok(_) => panic!("materializou 40 linhas com teto de 10"),
        }

        // Teto de bytes: idem, pela via do custo residente.
        match LogAnalytics::from_log_capped(&log, None, usize::MAX, 1024) {
            Err(AnalyticsError::Budget { limit, bytes, .. }) => {
                assert!(limit.contains("max_bytes"), "limite reportado: {limit}");
                assert!(bytes > 1024);
            }
            Err(e) => panic!("erro errado: {e}"),
            Ok(_) => panic!("materializou ~8KB com teto de 1KB"),
        }

        // Dentro do orçamento continua a funcionar normalmente.
        assert!(LogAnalytics::from_log_capped(&log, None, 10_000, 10 << 20).is_ok());
        // E o `as_of` é a saída documentada para caber no orçamento.
        assert!(LogAnalytics::from_log_capped(&log, Some(5), 10, usize::MAX).is_ok());
    }

    #[tokio::test]
    async fn sql_refuses_ddl_dml_and_statements() {
        // O endpoint é read-only IMPOSTO: sem isto, `CREATE EXTERNAL TABLE ...
        // LOCATION` lia ficheiros arbitrários do servidor via /sql.
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        log.append(Episode::new("a", EventKind::Observation, b"x".to_vec()))
            .unwrap();
        let a = LogAnalytics::from_log(&log, None).unwrap();

        for bad in [
            "CREATE EXTERNAL TABLE pwn STORED AS CSV LOCATION '/etc/passwd'",
            "CREATE TABLE t AS SELECT * FROM events",
            "INSERT INTO events VALUES (1)",
            "SET datafusion.execution.batch_size = 1",
        ] {
            assert!(a.sql(bad).await.is_err(), "devia recusar: {bad}");
        }
        // E o SELECT legítimo continua a funcionar.
        assert!(a.sql("SELECT COUNT(*) AS n FROM events").await.is_ok());
    }
}
