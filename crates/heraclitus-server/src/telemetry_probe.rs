//! SPEC-0071 §9.1 — a ponte entre a view de Telemetry Health e o health gate
//! da política de resposta.
//!
//! O `heraclitus-sentinel` define a pergunta (`TelemetryHealthProbe`) e o
//! `heraclitus-telemetry-health` sabe a resposta, mas nenhum dos dois conhece o
//! outro — de propósito. A política PERGUNTA pela saúde e não a calcula; a view
//! calcula-a e não sabe para que serve. Quem os junta é o servidor, que é quem
//! tem os dois.

use std::sync::{Arc, RwLock};

use heraclitus_log::AnyLog;
use heraclitus_sentinel::{TelemetryHealthProbe, TelemetryHealthReading};
use heraclitus_telemetry_health::TelemetryHealthGraph;

/// Lê a saúde agregada de um datasource a partir da view materializada.
pub struct ViewTelemetryProbe {
    log: Arc<AnyLog>,
    health: Arc<RwLock<TelemetryHealthGraph>>,
    tenant_id: String,
}

impl ViewTelemetryProbe {
    /// `tenant_id` é o inquilino cujas classes a política interroga.
    ///
    /// É explícito e não inferido do pedido porque a decisão de política é
    /// tomada pelo Sentinel, que corre em nome do sistema e não de um
    /// utilizador: deixar o inquilino ser escolhido pelo caminho de dados
    /// permitiria satisfazer um requisito de saúde com a telemetria de outro.
    pub fn new(
        log: Arc<AnyLog>,
        health: Arc<RwLock<TelemetryHealthGraph>>,
        tenant_id: impl Into<String>,
    ) -> Self {
        Self {
            log,
            health,
            tenant_id: tenant_id.into(),
        }
    }
}

impl TelemetryHealthProbe for ViewTelemetryProbe {
    fn leitura(&self, datasource_class: &str) -> TelemetryHealthReading {
        // Até a §6.3a introduzir uma taxonomia de classes, a CLASSE é o
        // `datasource_id`. Está dito aqui para que quem acrescentar a taxonomia
        // saiba que este é o sítio a mudar — e para que ninguém leia o campo
        // `datasource_class` da política como se já existisse um conceito
        // separado por trás dele.
        let agora_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        // O head é lido AGORA: a política decide sobre o presente, e um limite
        // mais antigo daria uma resposta correcta sobre um passado que já não
        // é o estado do sistema.
        let ate = self.log.head();
        let Ok(view) = self.health.write() else {
            // Um lock envenenado é uma thread que entrou em pânico com o estado
            // da view na mão. Não saber é `Unknown`, e `Unknown` não aprova —
            // que é a resposta certa, e não um erro a propagar para cima.
            return TelemetryHealthReading::desconhecida();
        };
        match view.datasource_health_as_of(&self.tenant_id, datasource_class, ate, agora_micros) {
            Some(saude) => TelemetryHealthReading {
                saudavel: saude.saudavel,
                confianca: saude.confianca(),
                idade_secs: saude.idade_secs(),
            },
            // Datasource desconhecido. A §9.1 põe `Unknown` ao lado de
            // `Silent`: não saber se um sensor existe não é melhor do que saber
            // que está calado.
            None => TelemetryHealthReading::desconhecida(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_telemetry_health::{
        ExpectationConfigured, IngestionWindowClosed, SensorIdentity, TelemetryHealthEnvelope,
        TelemetryHealthEvent,
    };

    /// Alimenta o log E a view com os mesmos LSNs.
    ///
    /// Não é cerimónia de teste: a sonda limita a leitura por `log.head()`, e
    /// alimentar só a view deixaria os eventos ACIMA desse limite — invisíveis,
    /// como devem ser. Foi o que o primeiro teste apanhou. Em produção os dois
    /// vêm do mesmo log, e o teste tem de reproduzir isso para provar alguma
    /// coisa.
    fn log_e_grafo(
        eventos: Vec<(SensorIdentity, u64, TelemetryHealthEvent)>,
    ) -> (
        tempfile::TempDir,
        Arc<AnyLog>,
        Arc<RwLock<TelemetryHealthGraph>>,
    ) {
        let (temp, log) = log_vazio();
        let grafo = Arc::new(RwLock::new(TelemetryHealthGraph::new()));
        {
            let mut g = grafo.write().unwrap();
            for (identity, emitido, evento) in eventos {
                let envelope = TelemetryHealthEnvelope::new(identity, emitido, evento);
                let lsn = log.append(envelope.to_episode().unwrap()).unwrap();
                g.apply_envelope(lsn, envelope).unwrap();
            }
        }
        (temp, log, grafo)
    }

    fn janela(fim_micros: u64, digest: &str) -> TelemetryHealthEvent {
        TelemetryHealthEvent::IngestionWindowClosed(IngestionWindowClosed {
            window_start_micros: fim_micros.saturating_sub(60_000_000),
            window_end_micros: fim_micros,
            received: 100,
            parsed: 100,
            normalized: 100,
            duplicated: 0,
            dropped: 0,
            quarantined: 0,
            parser_errors: 0,
            max_observed_lateness_millis: 10,
            connector_digest: digest.into(),
        })
    }

    fn expectativa() -> TelemetryHealthEvent {
        TelemetryHealthEvent::ExpectationConfigured(ExpectationConfigured {
            heartbeat_cadence_micros: Some(60_000_000),
            max_lateness_micros: 30_000_000,
            minimum_events_per_window: Some(1),
            duplicate_storm_basis_points: 5_000,
        })
    }

    fn log_vazio() -> (tempfile::TempDir, Arc<AnyLog>) {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                heraclitus_core::FsyncPolicy::Always,
            )
            .unwrap(),
        );
        (temp, log)
    }

    #[test]
    fn um_datasource_desconhecido_e_unknown_e_nao_saudavel() {
        let (_t, log, grafo) = log_e_grafo(vec![]);
        let probe = ViewTelemetryProbe::new(log, grafo, "tenant-1");
        let leitura = probe.leitura("identity");
        assert!(
            !leitura.saudavel,
            "um datasource de que não se sabe nada não pode passar por saudável"
        );
        assert_eq!(leitura.confianca, 0.0);
        assert_eq!(
            leitura.idade_secs,
            u64::MAX,
            "sem sensor nenhum a idade e infinita, nao um numero grande"
        );
    }

    #[test]
    fn a_leitura_atravessa_a_view_ate_a_politica() {
        let sensor = SensorIdentity::new("tenant-1", "identity", "okta-1");
        let (_t, log, grafo) = log_e_grafo(vec![
            (sensor.clone(), 1_000, expectativa()),
            (
                sensor.clone(),
                2_000,
                janela(2_000, "a".repeat(64).as_str()),
            ),
        ]);
        let probe = ViewTelemetryProbe::new(log, grafo, "tenant-1");
        let leitura = probe.leitura("identity");
        assert!(
            (0.0..=1.0).contains(&leitura.confianca),
            "a confiança tem de sair normalizada em [0,1]: {}",
            leitura.confianca
        );
        assert_ne!(
            leitura.idade_secs,
            u64::MAX,
            "com uma janela fechada a idade tem de ser finita"
        );
    }

    #[test]
    fn o_inquilino_errado_nao_satisfaz_o_requisito() {
        // Sem isto, a telemetria de um inquilino satisfaria um requisito de
        // outro — o que faria do gate um teatro.
        let sensor = SensorIdentity::new("tenant-A", "identity", "okta-1");
        let (_t, log, grafo) = log_e_grafo(vec![
            (sensor.clone(), 1_000, expectativa()),
            (
                sensor.clone(),
                2_000,
                janela(2_000, "a".repeat(64).as_str()),
            ),
        ]);
        let probe = ViewTelemetryProbe::new(log, grafo, "tenant-B");
        assert!(!probe.leitura("identity").saudavel);
    }
}
