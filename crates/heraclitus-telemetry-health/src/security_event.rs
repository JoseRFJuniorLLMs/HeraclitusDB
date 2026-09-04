//! SPEC-0071 §3/§4.1 — o evento canónico de segurança, tipado do lado do banco.
//!
//! O modelo canónico (`heraclitus-security-event/1.0`) existe no
//! `Heraclitus-Forge`, e é lá que ele é produzido e validado. Do lado do
//! HeraclitusDB não existia **nada**: o `bridge.py` sobe os campos como
//! atributos planos `security_*` e o banco guarda-os opacos — sem tipo, sem
//! filtro, sem forma de perguntar "que eventos de autenticação falharam neste
//! datasource".
//!
//! Este módulo fecha esse lado da fronteira.
//!
//! ## É DERIVADO, e isso é o desenho e não uma limitação
//!
//! Nada aqui é fonte da verdade. O log continua a ser o único canónico
//! (SPEC-0073 I-1), e este tipo é uma **projecção** dos atributos que já lá
//! estão. Não se persiste, não se indexa por si próprio, não se corrige — se um
//! campo estiver errado no log, corrige-se acrescentando um evento novo, como
//! tudo o resto neste sistema.
//!
//! A consequência prática é a que interessa: reconstruir esta vista `AS OF LSN
//! n` dá exactamente o que estava lá nesse ponto, e nunca o que alguém decidiu
//! depois que devia ter estado.
//!
//! ## Ausência é ausência
//!
//! O `bridge.py` remove os atributos vazios antes de escrever, com uma razão
//! escrita no sítio: "uma chave a mentir é pior que chave nenhuma numa query".
//! Este lado respeita a mesma regra ao contrário — um facto legado sem bloco
//! `security` produz `None`, nunca um valor inventado. É o gate CM3 visto do
//! lado do banco.

use heraclitus_core::{Episode, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A versão de esquema que o Forge emite e que este módulo entende.
pub const SECURITY_EVENT_SCHEMA: &str = "heraclitus-security-event/1.0";

/// Prefixo dos atributos planos escritos pelo `bridge.py`.
pub const ATTR_PREFIX: &str = "security_";

/// A projecção tipada de um evento canónico de segurança que está no log.
///
/// Só os campos que o `bridge.py` faz subir. O evento canónico COMPLETO
/// continua reconstituível a partir do Forge; o que atravessa a fronteira é o
/// que serve para filtrar e correlacionar, e é sobre isso que este tipo se
/// pronuncia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventView {
    /// O LSN do episódio de onde isto foi projectado. É o que torna a vista
    /// rastreável até ao log — sem ele seria uma afirmação sem origem.
    pub lsn: Lsn,
    pub schema: String,
    pub category: String,
    pub event_type: String,
    /// `None` quando o conector não o declarou. Ausente é ausente.
    pub outcome: Option<String>,
    pub severity: Option<u8>,
    pub tenant_id: Option<String>,
    pub datasource_id: Option<String>,
    pub sensor_id: Option<String>,
    /// Microssegundos epoch, tal como o Forge os emite.
    pub observed_at_micros: Option<i64>,
    pub source_sequence: Option<String>,
    /// Liga o evento ao artefacto `.hcx` exacto que o produziu (gate CM1).
    pub connector_digest: Option<String>,
}

impl SecurityEventView {
    /// Projecta um episódio, ou `None` se ele não trouxer o bloco canónico.
    ///
    /// Exige `security_schema`, `security_category` e `security_event_type`:
    /// sem os três não há evento de segurança nenhum, só atributos soltos que
    /// por acaso começam pelo mesmo prefixo. Aceitar menos do que isso deixaria
    /// entrar na vista qualquer facto com um `security_severity` perdido.
    pub fn projectar(lsn: Lsn, episode: &Episode) -> Option<Self> {
        let attr = |nome: &str| episode.attrs.get(nome).map(String::as_str);
        let schema = attr("security_schema")?.to_string();
        let category = attr("security_category")?.to_string();
        let event_type = attr("security_event_type")?.to_string();
        Some(Self {
            lsn,
            schema,
            category,
            event_type,
            outcome: attr("security_outcome").map(str::to_owned),
            // Um número malformado é ausência, não zero: `severity = 0` é uma
            // afirmação, e não é a que o log faz.
            severity: attr("security_severity").and_then(|v| v.parse().ok()),
            tenant_id: attr("security_tenant_id").map(str::to_owned),
            datasource_id: attr("security_datasource_id").map(str::to_owned),
            sensor_id: attr("security_sensor_id").map(str::to_owned),
            observed_at_micros: attr("security_observed_at").and_then(|v| v.parse().ok()),
            source_sequence: attr("security_source_sequence").map(str::to_owned),
            connector_digest: attr("security_connector_digest").map(str::to_owned),
        })
    }

    /// A versão de esquema é a que este binário sabe ler?
    ///
    /// Não é a mesma pergunta que "projectou". Um evento de um esquema futuro
    /// projecta-se na mesma — os campos base são os mesmos — mas quem o consome
    /// tem de poder saber que não o entende por completo, em vez de o tratar
    /// como se entendesse.
    pub fn esquema_conhecido(&self) -> bool {
        self.schema == SECURITY_EVENT_SCHEMA
    }
}

/// Filtro para interrogar a vista.
///
/// Cada campo `None` é "não filtra por isto". Todos os campos presentes são
/// conjuntivos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityEventFilter {
    pub tenant_id: Option<String>,
    pub datasource_id: Option<String>,
    pub category: Option<String>,
    pub outcome: Option<String>,
    /// Severidade mínima, inclusive. Um evento SEM severidade nunca satisfaz
    /// este filtro: não se sabe se satisfaz, e "não se sabe" não é "sim".
    pub severidade_minima: Option<u8>,
}

impl SecurityEventFilter {
    pub fn aceita(&self, e: &SecurityEventView) -> bool {
        let igual = |filtro: &Option<String>, valor: Option<&String>| match filtro {
            None => true,
            Some(f) => valor.is_some_and(|v| v == f),
        };
        if !igual(&self.tenant_id, e.tenant_id.as_ref()) {
            return false;
        }
        if !igual(&self.datasource_id, e.datasource_id.as_ref()) {
            return false;
        }
        if self.category.as_ref().is_some_and(|c| c != &e.category) {
            return false;
        }
        if !igual(&self.outcome, e.outcome.as_ref()) {
            return false;
        }
        if let Some(minima) = self.severidade_minima {
            match e.severity {
                Some(s) if s >= minima => {}
                _ => return false,
            }
        }
        true
    }
}

/// Contagens por dimensão, para o painel e para a correlação.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventCounts {
    pub total: u64,
    pub por_categoria: BTreeMap<String, u64>,
    pub por_datasource: BTreeMap<String, u64>,
    pub por_outcome: BTreeMap<String, u64>,
    /// Quantos vieram de um esquema que este binário não conhece.
    pub esquema_desconhecido: u64,
}

impl SecurityEventCounts {
    pub fn contar(&mut self, e: &SecurityEventView) {
        self.total += 1;
        *self.por_categoria.entry(e.category.clone()).or_default() += 1;
        if let Some(ds) = &e.datasource_id {
            *self.por_datasource.entry(ds.clone()).or_default() += 1;
        }
        if let Some(o) = &e.outcome {
            *self.por_outcome.entry(o.clone()).or_default() += 1;
        }
        if !e.esquema_conhecido() {
            self.esquema_desconhecido += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    fn episodio(pares: &[(&str, &str)]) -> Episode {
        let mut e = Episode::new("forge-bridge", EventKind::Observation, b"{}".to_vec());
        for (k, v) in pares {
            e.attrs.insert((*k).to_string(), (*v).to_string());
        }
        e
    }

    fn completo() -> Episode {
        episodio(&[
            ("security_schema", SECURITY_EVENT_SCHEMA),
            ("security_category", "authentication"),
            ("security_event_type", "login"),
            ("security_outcome", "failure"),
            ("security_severity", "7"),
            ("security_tenant_id", "tenant-a"),
            ("security_datasource_id", "identity"),
            ("security_sensor_id", "okta-1"),
            ("security_observed_at", "1700000000000000"),
            ("security_source_sequence", "42"),
            ("security_connector_digest", &"ab".repeat(32)),
        ])
    }

    #[test]
    fn um_episodio_canonico_sai_tipado_e_filtravel() {
        let v = SecurityEventView::projectar(7, &completo()).expect("devia projectar");
        assert_eq!(v.lsn, 7);
        assert_eq!(v.category, "authentication");
        assert_eq!(v.outcome.as_deref(), Some("failure"));
        assert_eq!(v.severity, Some(7));
        assert_eq!(v.datasource_id.as_deref(), Some("identity"));
        assert_eq!(v.observed_at_micros, Some(1_700_000_000_000_000));
        assert_eq!(v.connector_digest.as_deref(), Some(&"ab".repeat(32)[..]));
        assert!(v.esquema_conhecido());
    }

    #[test]
    fn um_facto_legado_sem_bloco_security_produz_ausencia_e_nao_um_valor() {
        // O gate CM3 visto do lado do banco. Inventar um "unknown" aqui poria
        // na vista eventos que nunca existiram.
        assert!(SecurityEventView::projectar(1, &episodio(&[])).is_none());
        assert!(SecurityEventView::projectar(
            1,
            &episodio(&[("forge_artifact", "postgresql-1.0.0")])
        )
        .is_none());
    }

    #[test]
    fn attrs_soltos_com_o_prefixo_nao_fazem_um_evento() {
        // Sem os tres campos base nao ha evento de seguranca, so atributos que
        // por acaso comecam pelo mesmo prefixo.
        assert!(
            SecurityEventView::projectar(1, &episodio(&[("security_severity", "9")])).is_none()
        );
        assert!(SecurityEventView::projectar(
            1,
            &episodio(&[
                ("security_schema", SECURITY_EVENT_SCHEMA),
                ("security_category", "authentication"),
            ])
        )
        .is_none());
    }

    #[test]
    fn um_campo_opcional_ausente_fica_none_e_nao_zero() {
        let e = episodio(&[
            ("security_schema", SECURITY_EVENT_SCHEMA),
            ("security_category", "network"),
            ("security_event_type", "connection"),
        ]);
        let v = SecurityEventView::projectar(3, &e).unwrap();
        assert_eq!(v.outcome, None);
        assert_eq!(v.severity, None, "ausencia nao e severidade zero");
        assert_eq!(v.tenant_id, None);
        assert_eq!(v.connector_digest, None);
    }

    #[test]
    fn um_numero_malformado_e_ausencia_e_nao_zero() {
        let mut e = completo();
        e.attrs
            .insert("security_severity".into(), "muito grave".into());
        e.attrs
            .insert("security_observed_at".into(), "ontem".into());
        let v = SecurityEventView::projectar(1, &e).unwrap();
        assert_eq!(v.severity, None);
        assert_eq!(v.observed_at_micros, None);
    }

    #[test]
    fn um_esquema_futuro_projecta_mas_declara_se_desconhecido() {
        let mut e = completo();
        e.attrs.insert(
            "security_schema".into(),
            "heraclitus-security-event/2.0".into(),
        );
        let v = SecurityEventView::projectar(1, &e).unwrap();
        assert!(
            !v.esquema_conhecido(),
            "quem consome tem de poder saber que nao o entende por completo"
        );
    }

    #[test]
    fn o_filtro_e_conjuntivo_e_ausencia_nunca_satisfaz() {
        let v = SecurityEventView::projectar(1, &completo()).unwrap();

        let mut f = SecurityEventFilter {
            tenant_id: Some("tenant-a".into()),
            category: Some("authentication".into()),
            severidade_minima: Some(5),
            ..Default::default()
        };
        assert!(f.aceita(&v));

        f.category = Some("network".into());
        assert!(!f.aceita(&v), "categoria diferente nao passa");

        f.category = Some("authentication".into());
        f.severidade_minima = Some(8);
        assert!(!f.aceita(&v), "7 nao satisfaz um minimo de 8");

        // Um evento SEM severidade nunca satisfaz um minimo: nao se sabe se
        // satisfaz, e "nao se sabe" nao e "sim".
        let mut sem = v.clone();
        sem.severity = None;
        f.severidade_minima = Some(1);
        assert!(!f.aceita(&sem));
    }

    #[test]
    fn as_contagens_separam_o_que_nao_se_entende() {
        let mut c = SecurityEventCounts::default();
        let v = SecurityEventView::projectar(1, &completo()).unwrap();
        c.contar(&v);
        let mut futuro = v.clone();
        futuro.schema = "heraclitus-security-event/9.0".into();
        c.contar(&futuro);

        assert_eq!(c.total, 2);
        assert_eq!(c.por_categoria["authentication"], 2);
        assert_eq!(c.por_datasource["identity"], 2);
        assert_eq!(c.por_outcome["failure"], 2);
        assert_eq!(
            c.esquema_desconhecido, 1,
            "um esquema que nao se entende tem de ser contado a parte"
        );
    }
}
