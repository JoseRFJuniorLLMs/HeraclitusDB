//! SPEC-0047 — o plano de threat intelligence ligado ao runtime.
//!
//! Os outros módulos deste directório são as peças; este é o que as põe a
//! correr. Sem ele o `threat` era código completo, testado, e sem um único
//! chamador — o padrão que esta base já repetiu três vezes e que a auditoria
//! de 2026-08-30 nomeou.
//!
//! # O que corre, e quando
//!
//! ```text
//! arranque   feeds_dir/*.json → StixImporter → admit (§10/§12) → IocIndex
//! por evento SecurityEvent → indicadores → lookup exacto → SecuritySignal
//!                                                        + ThreatSighting
//! ```
//!
//! Nada disto autoriza uma acção: §11 diz que um match produz evidência, e a
//! evidência atravessa a fusão e o policy engine como qualquer outra. O que
//! este módulo pode devolver é um [`SecuritySignal`] e uma
//! [`ThreatSighting`] — não tem tipo nenhum que seja uma acção.
//!
//! # A extracção é declarada, não adivinhada
//!
//! A tentação é varrer o `attributes` do evento à procura de qualquer coisa
//! que *pareça* um domínio ou um hash. Isso produz falsos positivos com ar de
//! autoridade: um `user_agent` que contém `evil.com` não é uma ligação a
//! `evil.com`, e um campo de 64 hex pode ser um id de sessão. Um analista que
//! receba esse match não tem como saber que ele foi inventado por uma
//! heurística.
//!
//! Por isso a extracção sai de campos **tipados** (`src`/`dst`) e de um
//! conjunto **declarado** de chaves de atributo. Um indicador que a base
//! observa mas não está nesta lista não é correlacionado — e isso é uma
//! lacuna visível (basta acrescentar a chave) em vez de um match errado.

use std::collections::BTreeSet;
use std::path::Path;

use heraclitus_core::{EventId, Lsn};

use crate::event::{EntityRef, EvidenceRef, SecurityEvent, SecuritySignal};

use super::canonical::{canonical_domain, canonical_email, canonical_file_hash, canonical_ip};
use super::index::{ConfirmedMatch, IocIndex};
use super::ir::{HashAlgorithm, Indicator};
use super::sighting::ThreatSighting;
use super::stix::{ImportReport, StixImporter};
use super::trust::{
    Admission, ThreatIntelDetector, ThreatSourcePolicy, ThreatSourceRegistry, TrustLevel,
};

/// Chaves de atributo de onde um indicador é extraído.
///
/// Fechada de propósito (ver o cabeçalho). Acrescentar uma chave é uma linha;
/// adivinhar a partir do valor não tem volta.
const ATTR_DOMAIN: [&str; 3] = ["dns.query", "http.host", "tls.sni"];
const ATTR_URL: [&str; 2] = ["http.url", "url"];
const ATTR_EMAIL: [&str; 2] = ["email.sender", "email.from"];
const ATTR_SHA256: [&str; 2] = ["file.sha256", "process.sha256"];
const ATTR_MD5: [&str; 1] = ["file.md5"];
const ATTR_SHA1: [&str; 1] = ["file.sha1"];

/// O que o carregamento dos feeds apurou. Vai para o arranque e para o status:
/// um índice vazio porque nenhum ficheiro importou tem de ser distinguível de
/// um índice vazio porque não há feeds configurados.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreatLoadReport {
    pub files_read: usize,
    pub files_failed: Vec<(String, String)>,
    pub objects_imported: usize,
    pub objects_admitted: usize,
    pub objects_quarantined: usize,
    pub objects_rejected: Vec<String>,
    pub indicators_indexed: usize,
    pub unsupported_patterns: usize,
}

/// O plano de threat intel de uma instância: índice, políticas e detector.
#[derive(Debug)]
pub struct ThreatPlane {
    index: IocIndex,
    registry: ThreatSourceRegistry,
    detector: ThreatIntelDetector,
    report: ThreatLoadReport,
}

impl ThreatPlane {
    /// Carrega um directório de bundles STIX 2.1.
    ///
    /// Um ficheiro que não importe **não** aborta o carregamento: fica no
    /// relatório e o resto continua. Um feed malformado é um problema do feed,
    /// e deixá-lo impedir o servidor de arrancar transforma um problema de
    /// terceiros numa indisponibilidade nossa.
    ///
    /// `now_ms` é injectado em vez de lido de um relógio para que dois
    /// carregamentos dos mesmos bytes dêem o mesmo estado — os TTL derivados
    /// de §12 dependem dele.
    pub fn load(feeds_dir: &Path, policy: ThreatSourcePolicy, now_ms: u64) -> Self {
        let mut registry = ThreatSourceRegistry::new();
        let source_id = policy.source_id.clone();
        registry.insert(policy);

        let mut index = IocIndex::new(4_096);
        let mut report = ThreatLoadReport::default();

        let mut ficheiros: Vec<_> = std::fs::read_dir(feeds_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        // Ordem determinística: dois arranques sobre os mesmos ficheiros têm
        // de produzir o mesmo índice, e `read_dir` não promete ordem nenhuma.
        ficheiros.sort();

        for path in ficheiros {
            let nome = path.display().to_string();
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    report.files_failed.push((nome, e.to_string()));
                    continue;
                }
            };
            let importer = StixImporter::new(
                source_id.clone(),
                path.file_name().unwrap_or_default().to_string_lossy(),
                now_ms,
            );
            let (objects, import): (Vec<_>, ImportReport) =
                match importer.import_with_report(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        report.files_failed.push((nome, e.to_string()));
                        continue;
                    }
                };
            report.files_read += 1;
            report.objects_imported += objects.len();
            report.unsupported_patterns += import.unsupported_patterns;

            for object in objects {
                match registry.admit(object, now_ms) {
                    Ok(Admission::Accepted(o)) => {
                        report.objects_admitted += 1;
                        report.indicators_indexed += index.insert_object(&o);
                    }
                    Ok(Admission::Quarantined { .. }) => report.objects_quarantined += 1,
                    Err(e) => report.objects_rejected.push(e.to_string()),
                }
            }
        }

        Self {
            index,
            registry,
            detector: ThreatIntelDetector::new(env!("CARGO_PKG_VERSION")),
            report,
        }
    }

    pub fn report(&self) -> &ThreatLoadReport {
        &self.report
    }

    pub fn indicator_count(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Correlaciona um evento contra o índice.
    ///
    /// `now_ms` decide o ciclo de vida (§12): um indicador expirado não casa, e
    /// um replay a um instante anterior reproduz a decisão que era correcta
    /// nessa altura.
    pub fn correlate(&self, event: &SecurityEvent, now_ms: u64) -> Vec<ConfirmedMatch> {
        let mut hits = Vec::new();
        let mut vistos: BTreeSet<Vec<u8>> = BTreeSet::new();
        for indicator in indicadores_do_evento(event) {
            // O mesmo indicador pode aparecer em `src` e num atributo; casar
            // duas vezes inflaria o score de §11 sem evidência nova.
            if !vistos.insert(indicator.index_key()) {
                continue;
            }
            hits.extend(self.index.lookup(&indicator, now_ms));
        }
        hits
    }

    /// §11 — o único output de um match: evidência.
    ///
    /// `None` quando nada casou, ou quando tudo o que casou pesa zero (fonte
    /// untrusted). Um sinal com score zero seria lido como significando algo.
    pub fn signal_for(
        &self,
        event: &SecurityEvent,
        hits: &[ConfirmedMatch],
        source_lsn: Lsn,
        derived_event_id: EventId,
    ) -> Option<SecuritySignal> {
        let subject = sujeito(event)?;
        let evidence = vec![EvidenceRef {
            lsn: source_lsn,
            event_id: derived_event_id,
        }];
        self.detector
            .signal(subject, hits, evidence, &self.registry, source_lsn)
    }

    /// §36 — uma observação local por match, que **não** altera o objecto
    /// original.
    pub fn sightings(
        &self,
        hits: &[ConfirmedMatch],
        derived_event_id: EventId,
        source_lsn: Lsn,
        observed_at: u64,
    ) -> Vec<ThreatSighting> {
        hits.iter()
            .map(|hit| ThreatSighting::from_match(hit, derived_event_id, source_lsn, observed_at))
            .collect()
    }
}

/// O sujeito a que o sinal se refere.
///
/// Preferência por host, depois user, depois o endereço de destino: é a
/// entidade que um analista procura primeiro quando um IOC dispara. Sem
/// nenhuma delas não há sinal — um sinal sem sujeito não é accionável e
/// enche o incidente.
fn sujeito(event: &SecurityEvent) -> Option<EntityRef> {
    if let Some(host) = &event.host {
        return Some(host.clone());
    }
    if let Some(user) = &event.user {
        return Some(user.clone());
    }
    let ip = event
        .src
        .as_ref()
        .and_then(|e| e.ip.clone())
        .or_else(|| event.dst.as_ref().and_then(|e| e.ip.clone()))?;
    Some(EntityRef::new("ip", ip))
}

/// Extrai os indicadores candidatos de um evento — só de campos tipados e das
/// chaves de atributo declaradas acima.
///
/// Valores que não canonicalizam são **descartados em silêncio** aqui, e isso
/// é deliberado: um `dns.query` malformado é ruído de telemetria, não um
/// problema que valha um erro por evento num caminho que corre milhões de
/// vezes. O que não é silencioso é o lado da ingestão — lá, um valor que não
/// canonicaliza entra no `ImportReport`, porque aí é o feed que está errado.
fn indicadores_do_evento(event: &SecurityEvent) -> Vec<Indicator> {
    let mut out = Vec::new();
    for endpoint in [event.src.as_ref(), event.dst.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(ip) = &endpoint.ip {
            if let Ok(i) = canonical_ip(ip) {
                out.push(i);
            }
        }
        if let Some(host) = &endpoint.hostname {
            if let Ok(d) = canonical_domain(host) {
                out.push(Indicator::Domain(d));
            }
        }
    }
    for key in ATTR_DOMAIN {
        if let Some(v) = event.attributes.get(key) {
            if let Ok(d) = canonical_domain(v) {
                out.push(Indicator::Domain(d));
            }
        }
    }
    for key in ATTR_URL {
        if let Some(v) = event.attributes.get(key) {
            if let Ok(u) = super::canonical::canonical_url(v) {
                out.push(Indicator::Url(u));
            }
        }
    }
    for key in ATTR_EMAIL {
        if let Some(v) = event.attributes.get(key) {
            if let Ok(e) = canonical_email(v) {
                out.push(e);
            }
        }
    }
    for (keys, algorithm) in [
        (ATTR_SHA256.as_slice(), HashAlgorithm::Sha256),
        (ATTR_MD5.as_slice(), HashAlgorithm::Md5),
        (ATTR_SHA1.as_slice(), HashAlgorithm::Sha1),
    ] {
        for key in keys {
            if let Some(v) = event.attributes.get(*key) {
                if let Ok(h) = canonical_file_hash(algorithm.clone(), v) {
                    out.push(h);
                }
            }
        }
    }
    out
}

/// Converte o `trust_level` da config no enum, recusando um valor
/// desconhecido para o lado seguro.
pub fn trust_from_config(value: &str) -> TrustLevel {
    match value.trim().to_ascii_lowercase().as_str() {
        "community" => TrustLevel::Community,
        "commercial" => TrustLevel::Commercial,
        "institutional" => TrustLevel::Institutional,
        "internal" => TrustLevel::Internal,
        // Inclui "untrusted" e qualquer coisa que alguém escreva mal. §13: um
        // erro de configuração não pode transformar um feed em autoridade.
        _ => TrustLevel::Untrusted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{NetworkEndpoint, SecuritySource};
    use heraclitus_core::EventId;

    fn evento() -> SecurityEvent {
        let mut e = SecurityEvent::unmapped(EventId::new(), SecuritySource::Nginx);
        e.host = Some(EntityRef::new("host", "web-01"));
        e.dst = Some(NetworkEndpoint {
            ip: Some("203.0.113.42".into()),
            port: Some(443),
            hostname: Some("EVIL.example".into()),
            protocol: Some("tcp".into()),
        });
        e.observed_at = 1_000;
        e
    }

    fn bundle(dir: &Path, nome: &str, corpo: &str) {
        std::fs::write(dir.join(nome), corpo).unwrap();
    }

    fn feed_padrao(dir: &Path) {
        bundle(
            dir,
            "feed.json",
            r#"{"type":"bundle","id":"bundle--1","objects":[
                {"type":"marking-definition","id":"marking-definition--amber","name":"TLP:AMBER"},
                {"type":"indicator","id":"indicator--net","confidence":90,
                 "pattern":"[ipv4-addr:value = '203.0.113.0/24']",
                 "object_marking_refs":["marking-definition--amber"]},
                {"type":"indicator","id":"indicator--dom","confidence":80,
                 "pattern":"[domain-name:value = 'evil.example']",
                 "object_marking_refs":["marking-definition--amber"]}
            ]}"#,
        );
    }

    fn politica(trust: TrustLevel) -> ThreatSourcePolicy {
        ThreatSourcePolicy {
            source_id: "feed".into(),
            trust_level: trust,
            minimum_confidence: 0,
            auto_block_allowed: false,
            default_ttl_secs: 3_600,
        }
    }

    #[test]
    fn carrega_indexa_e_correlaciona() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);

        assert_eq!(plane.report().files_read, 1);
        assert_eq!(plane.report().objects_admitted, 2);
        assert_eq!(plane.indicator_count(), 2);

        let hits = plane.correlate(&evento(), 1_000);
        assert_eq!(hits.len(), 2, "o IP e o hostname deviam casar: {hits:?}");

        let signal = plane
            .signal_for(&evento(), &hits, 7, EventId::new())
            .expect("evidencia");
        assert_eq!(signal.detector.id, "threat-intel");
        assert_eq!(signal.subject.unwrap().id, "web-01");
        assert_eq!(signal.created_at_lsn, 7);
    }

    #[test]
    fn um_ficheiro_partido_nao_impede_o_resto() {
        // Um feed malformado e um problema do feed; deixa-lo impedir o
        // arranque transforma-o numa indisponibilidade nossa.
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        bundle(dir.path(), "a-partido.json", "{isto nao e json");

        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);
        assert_eq!(plane.report().files_read, 1);
        assert_eq!(plane.report().files_failed.len(), 1);
        assert_eq!(
            plane.indicator_count(),
            2,
            "o feed bom continuou a carregar"
        );
    }

    #[test]
    fn o_mesmo_indicador_em_dois_campos_conta_uma_vez() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);

        let mut e = evento();
        // O mesmo dominio no hostname e no atributo.
        e.attributes
            .insert("dns.query".into(), "evil.example".into());
        let hits = plane.correlate(&e, 1_000);
        assert_eq!(
            hits.len(),
            2,
            "duas fontes do mesmo dominio nao podem inflar o score: {hits:?}"
        );
    }

    #[test]
    fn atributos_fora_da_lista_declarada_nao_sao_correlacionados() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);

        let mut e = SecurityEvent::unmapped(EventId::new(), SecuritySource::Nginx);
        e.host = Some(EntityRef::new("host", "h"));
        // Um user agent que MENCIONA o dominio nao e uma ligacao a ele.
        e.attributes.insert(
            "http.user_agent".into(),
            "Mozilla/5.0 (compatible; evil.example)".into(),
        );
        assert!(plane.correlate(&e, 1_000).is_empty());
    }

    #[test]
    fn um_indicador_expirado_deixa_de_casar() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        // TTL de 1h a partir de now=0.
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);
        assert_eq!(plane.correlate(&evento(), 3_599_999).len(), 2);
        assert!(plane.correlate(&evento(), 3_600_000).is_empty());
    }

    #[test]
    fn feed_untrusted_indexa_nada_e_nao_produz_evidencia() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Untrusted), 0);
        assert_eq!(plane.report().objects_quarantined, 2);
        assert_eq!(plane.indicator_count(), 0);
        assert!(plane.correlate(&evento(), 1_000).is_empty());
    }

    #[test]
    fn um_evento_sem_sujeito_nao_produz_sinal() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);
        let mut e = evento();
        e.host = None;
        e.user = None;
        e.src = None;
        e.dst = Some(NetworkEndpoint {
            ip: None,
            port: None,
            hostname: Some("evil.example".into()),
            protocol: None,
        });
        let hits = plane.correlate(&e, 1_000);
        assert_eq!(hits.len(), 1);
        assert!(plane.signal_for(&e, &hits, 1, EventId::new()).is_none());
    }

    #[test]
    fn as_sightings_apontam_para_o_evento_e_para_o_indicador() {
        let dir = tempfile::tempdir().unwrap();
        feed_padrao(dir.path());
        let plane = ThreatPlane::load(dir.path(), politica(TrustLevel::Institutional), 0);
        let hits = plane.correlate(&evento(), 1_000);
        let id = EventId::new();
        let s = plane.sightings(&hits, id, 9, 1_000);
        assert_eq!(s.len(), hits.len());
        assert!(s.iter().all(|x| x.event_id == id && x.lsn == 9));
        assert!(s.iter().any(|x| x.match_kind == "ip-prefix"));
    }

    #[test]
    fn um_trust_level_mal_escrito_cai_para_untrusted() {
        // §13: um erro de configuracao nao pode promover um feed a autoridade.
        assert_eq!(trust_from_config("institucional"), TrustLevel::Untrusted);
        assert_eq!(trust_from_config(""), TrustLevel::Untrusted);
        assert_eq!(
            trust_from_config("Institutional"),
            TrustLevel::Institutional
        );
    }

    #[test]
    fn um_directorio_inexistente_da_um_plano_vazio_e_nao_um_panico() {
        let plane = ThreatPlane::load(
            Path::new("D:/nao/existe/de/certeza"),
            politica(TrustLevel::Institutional),
            0,
        );
        assert!(plane.is_empty());
        assert_eq!(plane.report().files_read, 0);
    }
}
