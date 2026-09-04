//! SPEC-0071 §9.2 — Playbook como conteúdo.
//!
//! ## Quem executa, e quem não
//!
//! A §9.2 divide as responsabilidades em três e é explícita sobre a última:
//!
//! > O Forge pode authorar e simular Playbook IR. O `.hcx`/`.hrkp` pode
//! > distribuí-lo. **Somente `heraclitus-orchestrator` o executa** depois de
//! > assinatura, ativação, policy e aprovação.
//!
//! Este módulo é o meio da frase: a **representação** e a **activação**. Não
//! executa nada — não há aqui um `run()`, um `execute()`, nem uma chamada a
//! shell. Um playbook activo é um facto no log que a política de resposta pode
//! consultar; transformá-lo em acção é de outro componente, que ainda não
//! existe.
//!
//! Isso não é uma limitação por preguiça: a §9.3 herda da SPEC-0048 o
//! invariante "nada de arbitrary shell por default", e um executor escrito ao
//! lado do modelo, sem aprovação nem RBAC, seria a maneira mais directa de o
//! violar.
//!
//! ## O que isto desbloqueia hoje
//!
//! O health gate da §9.1 já está implementado no `heraclitus-sentinel`, e o seu
//! `required_telemetry` estava **vazio por omissão** porque quem o declara é o
//! playbook — que não existia. Agora existe: [`PlaybookIr::required_telemetry`]
//! é a fonte que faltava, e [`requisitos_activos`] devolve o que uma acção deve
//! exigir num tenant, lido do log.

use crate::{ContentRef, ContentState};
use serde::{Deserialize, Serialize};

pub const PLAYBOOK_SCHEMA: &str = "heraclitus-playbook/1.0";

/// Uma exigência de saúde de telemetria, tal como a §9.1 a escreve:
///
/// ```yaml
/// required_telemetry:
///   - datasource_class: identity
///     minimum_trust: 0.90
///     maximum_age_secs: 300
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequiredTelemetry {
    pub datasource_class: String,
    pub minimum_trust: f32,
    pub maximum_age_secs: u64,
}

impl RequiredTelemetry {
    pub fn validar(&self) -> Result<(), String> {
        if self.datasource_class.trim().is_empty() {
            return Err("datasource_class vazio".into());
        }
        if !self.minimum_trust.is_finite() || !(0.0..=1.0).contains(&self.minimum_trust) {
            return Err(format!("minimum_trust inválido: {}", self.minimum_trust));
        }
        if self.maximum_age_secs == 0 {
            return Err("maximum_age_secs tem de ser > 0".into());
        }
        Ok(())
    }
}

/// Um passo do playbook.
///
/// `action` é um NOME de acção enumerada — nunca um comando. A SPEC-0048
/// proíbe shell arbitrário por omissão, e a maneira de o garantir é o modelo
/// não ter onde o guardar: não há campo `command`, `script` ou `exec`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step_id: String,
    /// Corresponde a um `ActionKind` do plano de resposta. Um nome que o
    /// executor não conheça é recusado por ele, não interpretado.
    pub action: String,
    /// Exigir aprovação humana para ESTE passo, independentemente da política
    /// global. Um playbook pode ser mais restritivo que a política; nunca menos.
    #[serde(default)]
    pub requires_approval: bool,
}

/// A representação intermédia de um playbook (§9.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaybookIr {
    pub schema: String,
    pub playbook_id: String,
    pub version: String,
    /// A que acções este playbook se aplica.
    pub applies_to_actions: Vec<String>,
    /// §9.1 — a telemetria que estas acções exigem ver saudável.
    #[serde(default)]
    pub required_telemetry: Vec<RequiredTelemetry>,
    pub steps: Vec<PlaybookStep>,
}

impl PlaybookIr {
    pub fn validar(&self) -> Result<(), String> {
        if self.schema != PLAYBOOK_SCHEMA {
            return Err(format!("esquema não suportado: {}", self.schema));
        }
        if self.playbook_id.trim().is_empty() || self.version.trim().is_empty() {
            return Err("playbook_id/version vazios".into());
        }
        if self.steps.is_empty() {
            return Err("um playbook sem passos não é um playbook".into());
        }
        for r in &self.required_telemetry {
            r.validar()?;
        }
        for s in &self.steps {
            if s.step_id.trim().is_empty() || s.action.trim().is_empty() {
                return Err("passo com step_id/action vazios".into());
            }
        }
        Ok(())
    }
}

/// Os requisitos de telemetria que estão EM VIGOR para uma acção, num tenant.
///
/// Lê do estado do Content Hub: só contam playbooks cujo artefacto esteja
/// activo (ou em canário) nesse tenant. Um playbook publicado e não activado
/// não impõe nada — é a §7.3 aplicada ao caso concreto, e é o que impede que
/// publicar conteúdo mude o comportamento de quem ainda não o adoptou.
///
/// A união é o MÁXIMO de exigência, não a interseção: se dois playbooks activos
/// pedirem confiança mínima diferente para a mesma classe, vale a mais alta. O
/// critério é o mesmo do agregado de saúde por datasource — em segurança, o
/// requisito mais forte é o que protege, e escolher o mais fraco anularia o
/// mais forte sem ninguém decidir isso.
pub fn requisitos_activos(
    estado: &ContentState,
    playbooks: &[(ContentRef, PlaybookIr)],
    tenant_id: &str,
    action: &str,
) -> Vec<RequiredTelemetry> {
    let mut por_classe: std::collections::BTreeMap<String, RequiredTelemetry> =
        std::collections::BTreeMap::new();

    for (artefacto, ir) in playbooks {
        if !estado.esta_activo(artefacto, tenant_id) {
            continue;
        }
        if !ir.applies_to_actions.iter().any(|a| a == action) {
            continue;
        }
        for r in &ir.required_telemetry {
            por_classe
                .entry(r.datasource_class.clone())
                .and_modify(|existente| {
                    // Mais confiança exigida e menos idade tolerada: os dois
                    // sentidos apertam.
                    if r.minimum_trust > existente.minimum_trust {
                        existente.minimum_trust = r.minimum_trust;
                    }
                    if r.maximum_age_secs < existente.maximum_age_secs {
                        existente.maximum_age_secs = r.maximum_age_secs;
                    }
                })
                .or_insert_with(|| r.clone());
        }
    }
    por_classe.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentEnvelope, ContentEvent, TenantRollout};

    fn artefacto(id: &str, d: u8) -> ContentRef {
        ContentRef {
            content_id: id.into(),
            version: "1.0.0".into(),
            digest: format!("{d:02x}").repeat(32),
        }
    }

    fn ir(id: &str, classe: &str, trust: f32, idade: u64) -> PlaybookIr {
        PlaybookIr {
            schema: PLAYBOOK_SCHEMA.into(),
            playbook_id: id.into(),
            version: "1.0.0".into(),
            applies_to_actions: vec!["RequireMfa".into()],
            required_telemetry: vec![RequiredTelemetry {
                datasource_class: classe.into(),
                minimum_trust: trust,
                maximum_age_secs: idade,
            }],
            steps: vec![PlaybookStep {
                step_id: "s1".into(),
                action: "RequireMfa".into(),
                requires_approval: false,
            }],
        }
    }

    fn hub(eventos: Vec<ContentEvent>) -> ContentState {
        let envelopes: Vec<ContentEnvelope> = eventos
            .into_iter()
            .enumerate()
            .map(|(i, e)| ContentEnvelope::novo(format!("c{i}"), "p", "r", e))
            .collect();
        crate::reconstruir(&envelopes)
    }

    /// §7.3 aplicada ao caso concreto: um playbook PUBLICADO e nao activado nao
    /// impoe nada. Publicar conteudo nao pode mudar o comportamento de quem
    /// ainda nao o adoptou.
    #[test]
    fn um_playbook_publicado_e_nao_activado_nao_exige_nada() {
        let a = artefacto("pb-mfa", 0xaa);
        let estado = hub(vec![ContentEvent::Published {
            artefacto: a.clone(),
            publisher: "orgao".into(),
            signing_key: "ed25519:k".into(),
        }]);
        let req = requisitos_activos(
            &estado,
            &[(a, ir("pb-mfa", "identity", 0.9, 300))],
            "t1",
            "RequireMfa",
        );
        assert!(req.is_empty());
    }

    #[test]
    fn um_playbook_activo_da_a_fonte_que_faltava_ao_health_gate() {
        let a = artefacto("pb-mfa", 0xaa);
        let estado = hub(vec![
            ContentEvent::Published {
                artefacto: a.clone(),
                publisher: "orgao".into(),
                signing_key: "ed25519:k".into(),
            },
            ContentEvent::RolloutChanged {
                artefacto: a.clone(),
                tenant_id: "t1".into(),
                rollout: TenantRollout::Active,
                datasources: vec![],
            },
        ]);
        let req = requisitos_activos(
            &estado,
            &[(a, ir("pb-mfa", "identity", 0.9, 300))],
            "t1",
            "RequireMfa",
        );
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].datasource_class, "identity");
        assert_eq!(req[0].minimum_trust, 0.9);
        assert_eq!(req[0].maximum_age_secs, 300);
    }

    /// A uniao e o MAXIMO de exigencia. Escolher o requisito mais fraco
    /// anularia o mais forte sem ninguem decidir isso.
    #[test]
    fn dois_playbooks_activos_dao_o_requisito_mais_apertado() {
        let a1 = artefacto("pb-1", 0x11);
        let a2 = artefacto("pb-2", 0x22);
        let mut eventos = Vec::new();
        for a in [&a1, &a2] {
            eventos.push(ContentEvent::Published {
                artefacto: a.clone(),
                publisher: "orgao".into(),
                signing_key: "ed25519:k".into(),
            });
            eventos.push(ContentEvent::RolloutChanged {
                artefacto: a.clone(),
                tenant_id: "t1".into(),
                rollout: TenantRollout::Active,
                datasources: vec![],
            });
        }
        let estado = hub(eventos);
        let req = requisitos_activos(
            &estado,
            &[
                (a1, ir("pb-1", "identity", 0.80, 600)),
                (a2, ir("pb-2", "identity", 0.95, 120)),
            ],
            "t1",
            "RequireMfa",
        );
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].minimum_trust, 0.95, "vale a confianca mais alta");
        assert_eq!(req[0].maximum_age_secs, 120, "e a idade mais curta");
    }

    #[test]
    fn um_playbook_de_outro_tenant_ou_de_outra_accao_nao_conta() {
        let a = artefacto("pb-mfa", 0xaa);
        let estado = hub(vec![
            ContentEvent::Published {
                artefacto: a.clone(),
                publisher: "orgao".into(),
                signing_key: "ed25519:k".into(),
            },
            ContentEvent::RolloutChanged {
                artefacto: a.clone(),
                tenant_id: "t1".into(),
                rollout: TenantRollout::Active,
                datasources: vec![],
            },
        ]);
        let playbooks = [(a, ir("pb-mfa", "identity", 0.9, 300))];
        assert!(requisitos_activos(&estado, &playbooks, "t2", "RequireMfa").is_empty());
        assert!(requisitos_activos(&estado, &playbooks, "t1", "BlockIp").is_empty());
    }

    /// Revogar o artefacto tira o requisito, porque tira o playbook.
    #[test]
    fn revogar_o_artefacto_retira_os_requisitos() {
        let a = artefacto("pb-mfa", 0xaa);
        let estado = hub(vec![
            ContentEvent::Published {
                artefacto: a.clone(),
                publisher: "orgao".into(),
                signing_key: "ed25519:k".into(),
            },
            ContentEvent::RolloutChanged {
                artefacto: a.clone(),
                tenant_id: "t1".into(),
                rollout: TenantRollout::Active,
                datasources: vec![],
            },
            ContentEvent::Revoked {
                artefacto: a.clone(),
                reason: "passo perigoso".into(),
            },
        ]);
        assert!(requisitos_activos(
            &estado,
            &[(a, ir("pb-mfa", "identity", 0.9, 300))],
            "t1",
            "RequireMfa"
        )
        .is_empty());
    }

    /// O modelo NAO tem onde guardar um comando. A SPEC-0048 proibe shell
    /// arbitrario por omissao, e a garantia e a ausencia de campo.
    #[test]
    fn o_modelo_nao_tem_campo_para_um_comando() {
        let json = serde_json::to_string(&ir("pb", "identity", 0.9, 300)).unwrap();
        for proibido in ["\"command\"", "\"script\"", "\"exec\"", "\"shell\""] {
            assert!(
                !json.contains(proibido),
                "o IR nao pode ter {proibido}: {json}"
            );
        }
    }

    #[test]
    fn um_playbook_malformado_e_recusado() {
        let mut p = ir("pb", "identity", 0.9, 300);
        p.steps.clear();
        assert!(p.validar().is_err(), "sem passos nao e um playbook");

        let mut p = ir("pb", "identity", 1.5, 300);
        assert!(p.validar().is_err(), "trust fora de [0,1]");

        p = ir("pb", "identity", 0.9, 0);
        assert!(p.validar().is_err(), "idade maxima zero");

        p = ir("pb", "  ", 0.9, 300);
        assert!(p.validar().is_err(), "classe vazia");

        assert!(ir("pb", "identity", 0.9, 300).validar().is_ok());
    }
}
