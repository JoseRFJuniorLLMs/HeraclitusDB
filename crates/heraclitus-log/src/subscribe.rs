//! SPEC-022 wiring — StreamSubscriber ligado ao tail real do log.
//!
//! [`attach_subscriber`] faz a ponte entre o broadcast interno do log
//! (`tail_subscribe`) e o contrato público [`StreamSubscriber`] do core: cada
//! append sincronizado dispara `on_append` com uma `NotificationEvent` leve;
//! um subscritor lento que perca eventos do buffer recebe `on_buffer_overflow`
//! com o LSN a partir do qual deve fazer catch-up via `scan` (histórico).
//!
//! O trabalho corre numa thread própria (`blocking_recv` fora de runtime) para
//! nunca bloquear o caminho de escrita — o contrato exige handlers baratos.

use crate::Log;
use heraclitus_core::{NotificationEvent, StreamSubscriber};
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;

/// Liga `sub` ao tail do log. Devolve o handle da thread; ela termina sozinha
/// quando o log é dropado (canal fechado).
pub fn attach_subscriber(
    log: &Log,
    sub: Arc<dyn StreamSubscriber>,
) -> std::thread::JoinHandle<()> {
    let mut rx = log.tail_subscribe();
    std::thread::spawn(move || {
        // R15: `Option` em vez de `0` — um overflow ANTES do primeiro evento
        // recebido tem de mandar o catch-up começar no LSN 0 (com `0` inicial,
        // `last_seen + 1 = 1` perdia o LSN 0 para sempre).
        let mut last_seen: Option<u64> = None;
        loop {
            match rx.blocking_recv() {
                Ok((lsn, ep)) => {
                    last_seen = Some(lsn);
                    sub.on_append(&NotificationEvent {
                        lsn,
                        event_id: ep.id,
                        agent_id: ep.agent_id.clone(),
                    });
                }
                Err(RecvError::Lagged(_missed)) => {
                    // O subscritor ficou para trás e o buffer rodou: manda-o
                    // fazer catch-up do histórico a partir do próximo LSN.
                    sub.on_buffer_overflow(last_seen.map_or(0, |l| l + 1));
                }
                Err(RecvError::Closed) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct Counter {
        seen: AtomicU64,
        last_lsn: AtomicU64,
        overflows: AtomicU64,
    }
    impl StreamSubscriber for Counter {
        fn on_append(&self, e: &NotificationEvent) {
            self.seen.fetch_add(1, Ordering::SeqCst);
            self.last_lsn.store(e.lsn, Ordering::SeqCst);
        }
        fn on_buffer_overflow(&self, _expected: Lsn) {
            self.overflows.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn subscriber_sees_every_append_in_real_time() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let sub = Arc::new(Counter::default());
        let _h = attach_subscriber(&log, sub.clone());

        for i in 0..10 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }
        // Espera (com timeout) que o adapter entregue os 10 eventos.
        let deadline = Instant::now() + Duration::from_secs(5);
        while sub.seen.load(Ordering::SeqCst) < 10 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(sub.seen.load(Ordering::SeqCst), 10, "todos os appends notificados");
        assert_eq!(sub.last_lsn.load(Ordering::SeqCst), 9, "último LSN correto");
        assert_eq!(sub.overflows.load(Ordering::SeqCst), 0);
    }
}
