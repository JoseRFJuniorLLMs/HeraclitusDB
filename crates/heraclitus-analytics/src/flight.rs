//! SPEC-016 — data plane Flight sobre o log (Arrow IPC, v1 honesto).
//!
//! Implementa o contrato [`FlightService`](heraclitus_core::flight::FlightService)
//! com o **wire format real do Arrow Flight** (streams IPC): `do_get` serve os
//! episódios do log como RecordBatches de 1024 linhas codificados em IPC —
//! prontos para Polars/DuckDB/pyarrow lerem sem parsing por linha; `do_put`
//! ingere batches IPC como episódios append-only.
//!
//! Tickets suportados (UTF-8): `"events"` · `"events?as_of=N"`.
//!
//! Honestidade de escopo: isto é o DATA PLANE (IPC ponta-a-ponta, testado em
//! round-trip). O protocolo gRPC `arrow.flight.protocol.FlightService` completo
//! exige o crate `arrow-flight` version-locked ao arrow do DataFusion — é o
//! passo seguinte natural; a superfície REST do server já serve estes bytes.

use crate::vectorized::{episodes_to_batches_sized, BATCH_ROWS};
use crate::AnalyticsError;
use datafusion::arrow::array::{RecordBatch, StringArray};
use datafusion::arrow::ipc::reader::StreamReader;
use datafusion::arrow::ipc::writer::StreamWriter;
use heraclitus_core::flight::{BatchBytes, FlightService, Ticket};
use heraclitus_core::{Episode, EventKind};
use heraclitus_log::EpisodeLog;
use std::sync::Arc;

/// Codifica um RecordBatch num stream Arrow IPC autocontido.
pub fn batch_to_ipc(batch: &RecordBatch) -> Result<Vec<u8>, AnalyticsError> {
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::try_new(&mut buf, batch.schema().as_ref())
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        w.write(batch)
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        w.finish()
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
    }
    Ok(buf)
}

/// Descodifica um stream Arrow IPC (1+ batches).
pub fn ipc_to_batches(bytes: &[u8]) -> Result<Vec<RecordBatch>, AnalyticsError> {
    let reader = StreamReader::try_new(std::io::Cursor::new(bytes), None)
        .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
    reader
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AnalyticsError::Arrow(e.to_string()))
}

/// Os episódios do log como UM único stream IPC (todos os batches) — o corpo
/// HTTP que a rota `/flight/events` do server serve a clientes Arrow.
pub fn events_as_single_ipc<L: EpisodeLog + ?Sized>(
    log: &L,
    as_of: Option<u64>,
) -> Result<Vec<u8>, AnalyticsError> {
    let to = as_of.unwrap_or(u64::MAX).min(log.head());
    let mut buf = BoundedIpc(Vec::new());
    {
        let schema = crate::vectorized::batch_schema();
        let mut writer = StreamWriter::try_new(&mut buf, schema.as_ref())
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
        visit_batches(log, to, |batch| {
            writer
                .write(&batch)
                .map_err(|e| AnalyticsError::Arrow(e.to_string()))
        })?;
        writer
            .finish()
            .map_err(|e| AnalyticsError::Arrow(e.to_string()))?;
    }
    Ok(buf.0)
}

// The synchronous compatibility APIs return a Vec and therefore need a hard
// output budget. Large exports use the server's streaming gRPC Flight API.
const MAX_IPC_BYTES: usize = 128 << 20;
struct BoundedIpc(Vec<u8>);
impl std::io::Write for BoundedIpc {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_IPC_BYTES {
            return Err(std::io::Error::other(
                "IPC output exceeds 128MiB; use streaming Flight",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn visit_batches<L: EpisodeLog + ?Sized>(
    log: &L,
    to: u64,
    mut visit: impl FnMut(RecordBatch) -> Result<(), AnalyticsError>,
) -> Result<(), AnalyticsError> {
    let mut cur = 0u64;
    let mut pending = Vec::new();
    let mut resident = 0usize;
    while cur < to {
        let window = log.scan_capped(cur, to, 16)?;
        let Some(&(last, _)) = window.last() else {
            break;
        };
        for row in window {
            let charge = row.1.resident_bytes();
            if !pending.is_empty()
                && (pending.len() >= BATCH_ROWS || resident.saturating_add(charge) > 16 << 20)
            {
                for batch in episodes_to_batches_sized(&pending, BATCH_ROWS)? {
                    visit(batch)?;
                }
                pending.clear();
                resident = 0;
            }
            resident = resident.saturating_add(charge);
            pending.push(row);
        }
        cur = last.saturating_add(1);
    }
    for batch in episodes_to_batches_sized(&pending, BATCH_ROWS)? {
        visit(batch)?;
    }
    Ok(())
}

/// Serviço Flight sobre o log real.
pub struct IpcFlightService {
    log: Arc<dyn EpisodeLog>,
}

impl IpcFlightService {
    pub fn new<L: EpisodeLog + 'static>(log: Arc<L>) -> Self {
        Self { log }
    }

    fn parse_ticket(ticket: &Ticket) -> Result<Option<u64>, String> {
        let s = std::str::from_utf8(&ticket.0).map_err(|_| "ticket não-UTF8".to_string())?;
        if s == "events" {
            return Ok(None);
        }
        if let Some(rest) = s.strip_prefix("events?as_of=") {
            let n: u64 = rest
                .parse()
                .map_err(|_| format!("as_of inválido: {rest}"))?;
            return Ok(Some(n));
        }
        Err(format!("ticket desconhecido: {s}"))
    }
}

impl FlightService for IpcFlightService {
    /// `events[?as_of=N]` → um stream IPC por batch de 1024 episódios.
    fn do_get(&self, ticket: &Ticket) -> Result<Vec<BatchBytes>, String> {
        let as_of = Self::parse_ticket(ticket)?;
        let to = as_of.unwrap_or(u64::MAX).min(self.log.head());
        let mut streams = Vec::new();
        let mut total = 0usize;
        visit_batches(self.log.as_ref(), to, |batch| {
            let bytes = batch_to_ipc(&batch)?;
            total = total.saturating_add(bytes.len());
            if total > MAX_IPC_BYTES {
                return Err(AnalyticsError::Arrow(
                    "IPC output exceeds 128MiB; use streaming Flight".into(),
                ));
            }
            streams.push(bytes);
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        Ok(streams)
    }

    /// Ingere batches IPC como episódios (colunas exigidas: `agent_id`,
    /// `kind`, ambas Utf8). Devolve quantas LINHAS foram appendadas.
    fn do_put(&self, batches: Vec<BatchBytes>) -> Result<usize, String> {
        let mut appended = 0usize;
        for bytes in &batches {
            for batch in ipc_to_batches(bytes).map_err(|e| e.to_string())? {
                let agent_ix = batch
                    .schema()
                    .index_of("agent_id")
                    .map_err(|e| e.to_string())?;
                let kind_ix = batch.schema().index_of("kind").map_err(|e| e.to_string())?;
                let agents = batch
                    .column(agent_ix)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or("agent_id tem de ser Utf8")?;
                let kinds = batch
                    .column(kind_ix)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or("kind tem de ser Utf8")?;
                for row in 0..batch.num_rows() {
                    let kind = match kinds.value(row) {
                        "Observation" => EventKind::Observation,
                        "Action" => EventKind::Action,
                        "Message" => EventKind::Message,
                        other => EventKind::Custom(other.to_string()),
                    };
                    self.log
                        .append(Episode::new(agents.value(row), kind, Vec::new()))
                        .map_err(|e| e.to_string())?;
                    appended += 1;
                }
            }
        }
        Ok(appended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::ArrayRef;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use heraclitus_core::FsyncPolicy;
    use heraclitus_log::Log;

    fn seeded_log(n: usize) -> (tempfile::TempDir, Arc<Log>) {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for i in 0..n {
            log.append(Episode::new(
                if i % 2 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }
        (dir, log)
    }

    #[test]
    fn do_get_round_trips_the_log_as_ipc() {
        let (_d, log) = seeded_log(2500);
        let svc = IpcFlightService::new(log);
        let streams = svc.do_get(&Ticket(b"events".to_vec())).unwrap();
        assert_eq!(streams.len(), 3, "2500 eventos → 3 batches de ≤1024");
        // Round-trip IPC: descodifica e confere linhas + schema.
        let mut rows = 0usize;
        for s in &streams {
            for b in ipc_to_batches(s).unwrap() {
                assert!(b.num_rows() <= 1024);
                assert_eq!(b.schema().field(1).name(), "agent_id");
                rows += b.num_rows();
            }
        }
        assert_eq!(rows, 2500, "nenhuma linha perdida no wire");
    }

    #[test]
    fn do_get_respects_as_of_and_rejects_bad_tickets() {
        let (_d, log) = seeded_log(100);
        let svc = IpcFlightService::new(log);
        let streams = svc.do_get(&Ticket(b"events?as_of=10".to_vec())).unwrap();
        let rows: usize = streams
            .iter()
            .flat_map(|s| ipc_to_batches(s).unwrap())
            .map(|b| b.num_rows())
            .sum();
        assert_eq!(rows, 10, "AS OF corta no LSN pedido");
        assert!(svc.do_get(&Ticket(b"drop tables".to_vec())).is_err());
    }

    #[test]
    fn single_ipc_stream_carries_all_batches() {
        let (_d, log) = seeded_log(2500);
        let body = events_as_single_ipc(&log, None).unwrap();
        let rows: usize = ipc_to_batches(&body)
            .unwrap()
            .iter()
            .map(|b| b.num_rows())
            .sum();
        assert_eq!(rows, 2500, "um só stream HTTP com o log inteiro");
    }

    #[test]
    fn do_put_ingests_ipc_batches_as_episodes() {
        let (_d, log) = seeded_log(0);
        let svc = IpcFlightService::new(log.clone());
        // Batch de ingestão: (agent_id, kind).
        let schema = Arc::new(Schema::new(vec![
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("kind", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["carol", "dave"])) as ArrayRef,
                Arc::new(StringArray::from(vec!["Observation", "Sensor"])) as ArrayRef,
            ],
        )
        .unwrap();
        let n = svc.do_put(vec![batch_to_ipc(&batch).unwrap()]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(log.head(), 2, "episódios appendados no log real");
        let events = log.scan(0, u64::MAX).unwrap();
        assert_eq!(events[0].1.agent_id, "carol");
        assert_eq!(events[1].1.kind, EventKind::Custom("Sensor".into()));
    }
}
