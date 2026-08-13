//! Modo EMBEDDED (C2.6, padrão Chroma): o motor completo in-process, sem
//! servidor gRPC — para agentes de IA locais, testes e prototipagem. O mesmo
//! `Engine` que o servidor compõe, com a mesma durabilidade (log append-only,
//! Merkle, views determinísticas); só desaparece a camada de rede.
//!
//! ```no_run
//! use heraclitus_server::Embedded;
//! use heraclitus_core::{Episode, EventKind};
//!
//! let db = Embedded::open("./data").unwrap();
//! let mut e = Episode::new("agente", EventKind::Observation, b"facto".to_vec());
//! e.attrs.insert("caso".into(), "1".into());
//! db.append(e).unwrap();
//! let rows = db.query("MATCH (n) RETURN n").unwrap();
//! assert_eq!(rows.as_array().unwrap().len(), 1);
//! ```

use crate::engine::Engine;
use heraclitus_core::{Episode, HeraclitusConfig, HeraclitusError, Lsn};
use std::path::PathBuf;
use std::sync::Arc;

/// Um HeraclitusDB embutido: abre o engine diretamente sobre `data_dir`.
pub struct Embedded {
    engine: Arc<Engine>,
}

impl Embedded {
    /// Abre (ou cria) a base em `data_dir` com a configuração default —
    /// fsync, memtable e views idênticos aos do servidor.
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self, HeraclitusError> {
        let config = HeraclitusConfig {
            data_dir: data_dir.into(),
            ..HeraclitusConfig::default()
        };
        Self::open_with(&config)
    }

    /// Abre com configuração explícita (cifra em repouso, fsync, caps...).
    pub fn open_with(config: &HeraclitusConfig) -> Result<Self, HeraclitusError> {
        Ok(Self {
            engine: Arc::new(Engine::open(config)?),
        })
    }

    /// Grava um episódio no log (a fonte da verdade) e nas views.
    pub fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.engine.append(episode)
    }

    /// Executa GQL — todo o dialeto do servidor, incluindo `AS OF`, `VALID AT`,
    /// `SIMULATE`, `FUSE`, `WHY`, `DIST_*` e range numérico.
    pub fn query(&self, gql: &str) -> Result<serde_json::Value, HeraclitusError> {
        heraclitus_query::execute(gql, self.engine.as_ref())
    }

    /// Verificação criptográfica (Merkle) do log inteiro.
    pub fn verify(&self) -> Result<serde_json::Value, HeraclitusError> {
        self.engine.verify()
    }

    /// Introspecção `heraclitus_state()` (head, segmentos, watermarks).
    pub fn state(&self) -> serde_json::Value {
        self.engine.state()
    }

    /// Fast boot: persiste os snapshots das views (o próximo `open` replaya
    /// só a cauda). Chamar antes de largar o processo.
    pub fn checkpoint(&self) -> Result<(), HeraclitusError> {
        self.engine.checkpoint_views()
    }

    /// Escape hatch: o `Engine` completo (recall, fusão, hvm_*, ...).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// SQL analítico (DataFusion) sobre o log — feature `analytics`. Read-only
    /// e derivado: materializa `events` do log (`as_of = Some(n)` ⇒ `lsn < n`)
    /// e corre `SELECT ... GROUP BY ...` sem tocar no core.
    #[cfg(feature = "analytics")]
    pub fn analytics(
        &self,
        as_of: Option<Lsn>,
    ) -> Result<heraclitus_analytics::LogAnalytics, heraclitus_analytics::AnalyticsError> {
        heraclitus_analytics::LogAnalytics::from_log(&self.engine.log, as_of)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    #[test]
    fn embedded_append_query_verify_roundtrip() {
        // C2.6: sem gRPC — append, query GQL, verify e fast boot in-process.
        let dir = tempfile::tempdir().unwrap();
        let db = Embedded::open(dir.path()).unwrap();

        for i in 0..5 {
            let mut e = Episode::new(
                "agente",
                EventKind::Observation,
                format!("f{i}").into_bytes(),
            );
            e.attrs.insert("valor".into(), format!("{}", i * 100));
            db.append(e).unwrap();
        }

        let rows = db.query("MATCH (n) RETURN n").unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 5);

        // O dialeto completo funciona embutido (range numérico via índice).
        let rows = db.query("MATCH (n) WHERE n.valor > 150 RETURN n").unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 3);

        let v = db.verify().unwrap();
        assert!(v["records"].as_u64().unwrap() >= 5);
        assert_eq!(db.state()["head_lsn"].as_u64().unwrap(), 5);

        // Fast boot embutido: checkpoint → reabrir → estado presente.
        db.checkpoint().unwrap();
        drop(db);
        let db2 = Embedded::open(dir.path()).unwrap();
        let rows = db2.query("MATCH (n) RETURN n").unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 5);
    }
}
