//! SPEC-0076 §28–§29 — autenticação da Consola e RBAC.
//!
//! # O modelo que a SPEC proíbe
//!
//! > O modelo não pode ser "admin ou nada" (§29).
//!
//! E, dentro disso, a separação que interessa mais do que todas as outras:
//!
//! > `approver` e `policy_admin` precisam de ser separados (§28).
//!
//! Quem escreve a regra não pode ser quem a dispensa. Se os dois papéis
//! colapsassem, uma pessoa poderia activar uma policy que exige a sua própria
//! aprovação e depois aprovar-se a si própria — e o registo mostraria duas
//! acções perfeitamente legítimas.
//!
//! # DEV_LOCAL é explícito, não implícito
//!
//! No perfil de desenvolvimento não há autenticação e o principal tem todos os
//! papéis. Isso é aceitável **porque o produto o diz em voz alta**: a Consola
//! mostra um banner, `/api/v1/agent/status` devolve `auth: "dev_local"`, e a
//! [`heraclitus_agent::config::AgentGatewayConfig::validate`] recusa arrancar
//! em produção sem OIDC.

use crate::runtime::AgentRuntime;
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use std::sync::Arc;

/// Os papéis de §29.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Auditor,
    Approver,
    PolicyAdmin,
    SystemAdmin,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Auditor => "auditor",
            Self::Approver => "approver",
            Self::PolicyAdmin => "policy_admin",
            Self::SystemAdmin => "system_admin",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "viewer" => Self::Viewer,
            "auditor" => Self::Auditor,
            "approver" => Self::Approver,
            "policy_admin" => Self::PolicyAdmin,
            "system_admin" => Self::SystemAdmin,
            _ => return None,
        })
    }
}

/// As operações que o RBAC governa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    ViewRuns,
    ViewProofs,
    ExportBundle,
    ApproveAction,
    SimulatePolicy,
    ActivatePolicy,
    ChangeCapture,
}

impl Operation {
    /// A tabela de §29, escrita uma vez.
    pub fn allowed_roles(self) -> &'static [Role] {
        match self {
            Self::ViewRuns | Self::ViewProofs => &[
                Role::Viewer,
                Role::Auditor,
                Role::Approver,
                Role::PolicyAdmin,
                Role::SystemAdmin,
            ],
            Self::ExportBundle => &[Role::Auditor, Role::PolicyAdmin, Role::SystemAdmin],
            // `system_admin` aprova porque tem de haver uma saída quando o
            // aprovador está indisponível; `policy_admin` NÃO aprova, e é essa
            // a separação que §28 exige.
            Self::ApproveAction => &[Role::Approver, Role::SystemAdmin],
            Self::SimulatePolicy | Self::ActivatePolicy => &[Role::PolicyAdmin, Role::SystemAdmin],
            Self::ChangeCapture => &[Role::SystemAdmin],
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ViewRuns => "ver runs",
            Self::ViewProofs => "ver provas",
            Self::ExportBundle => "exportar bundle",
            Self::ApproveAction => "aprovar acção",
            Self::SimulatePolicy => "simular policy",
            Self::ActivatePolicy => "activar policy",
            Self::ChangeCapture => "alterar captura",
        }
    }
}

/// Quem está a chamar.
#[derive(Debug, Clone, Serialize)]
pub struct Principal {
    pub subject: String,
    pub issuer: String,
    pub roles: Vec<Role>,
    /// `true` quando o perfil é de desenvolvimento e ninguém provou nada.
    pub dev_local: bool,
}

impl Principal {
    pub fn can(&self, op: Operation) -> bool {
        op.allowed_roles().iter().any(|r| self.roles.contains(r))
    }

    pub fn require(&self, op: Operation) -> Result<(), (StatusCode, String)> {
        if self.can(op) {
            return Ok(());
        }
        Err((
            StatusCode::FORBIDDEN,
            format!(
                "o papel necessário para {} é um de [{}]; `{}` tem [{}]",
                op.label(),
                op.allowed_roles()
                    .iter()
                    .map(|r| r.label())
                    .collect::<Vec<_>>()
                    .join(", "),
                self.subject,
                self.roles
                    .iter()
                    .map(|r| r.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ))
    }
}

/// Extrai o principal dos cabeçalhos.
///
/// Com validador OIDC configurado, exige um bearer válido. Sem validador, o
/// perfil é de desenvolvimento e o principal é anónimo com todos os papéis — o
/// que só é seguro porque a configuração de produção recusa este caminho.
pub fn principal_from(
    runtime: &Arc<AgentRuntime>,
    headers: &HeaderMap,
    now_unix_seconds: u64,
) -> Result<Principal, (StatusCode, String)> {
    let Some(validator) = runtime.validator() else {
        return Ok(Principal {
            subject: "dev-local".to_string(),
            issuer: "dev-local".to_string(),
            roles: vec![
                Role::Viewer,
                Role::Auditor,
                Role::Approver,
                Role::PolicyAdmin,
                Role::SystemAdmin,
            ],
            dev_local: true,
        });
    };
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "é necessário `Authorization: Bearer <token>`".to_string(),
        ))?;
    let identity = validator.validate(token, now_unix_seconds).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("IDENTITY_VALIDATION_FAILED: {e}"),
        )
    })?;
    let mut roles: Vec<Role> = identity
        .roles
        .iter()
        .filter_map(|r| Role::parse(r))
        .collect();
    // Quem tem um token válido consegue sempre ver; é o mínimo que a Consola
    // precisa e não abre nada que a autenticação já não tenha aberto.
    if roles.is_empty() {
        roles.push(Role::Viewer);
    }
    roles.sort();
    roles.dedup();
    Ok(Principal {
        subject: identity.subject,
        issuer: identity.issuer,
        roles,
        dev_local: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn com(roles: &[Role]) -> Principal {
        Principal {
            subject: "p".into(),
            issuer: "i".into(),
            roles: roles.to_vec(),
            dev_local: false,
        }
    }

    #[test]
    fn aprovador_e_administrador_de_policy_sao_papeis_separados() {
        // §28: a separação que impede alguém de escrever a regra e dispensá-la.
        let aprovador = com(&[Role::Approver]);
        let admin_policy = com(&[Role::PolicyAdmin]);
        assert!(aprovador.can(Operation::ApproveAction));
        assert!(!aprovador.can(Operation::ActivatePolicy));
        assert!(admin_policy.can(Operation::ActivatePolicy));
        assert!(!admin_policy.can(Operation::ApproveAction));
    }

    #[test]
    fn a_tabela_de_29_e_respeitada() {
        let viewer = com(&[Role::Viewer]);
        assert!(viewer.can(Operation::ViewRuns));
        assert!(viewer.can(Operation::ViewProofs));
        assert!(!viewer.can(Operation::ExportBundle));
        assert!(!viewer.can(Operation::ApproveAction));
        assert!(!viewer.can(Operation::SimulatePolicy));
        assert!(!viewer.can(Operation::ChangeCapture));

        let auditor = com(&[Role::Auditor]);
        assert!(auditor.can(Operation::ExportBundle));
        assert!(!auditor.can(Operation::ApproveAction));
        assert!(!auditor.can(Operation::ActivatePolicy));

        let sys = com(&[Role::SystemAdmin]);
        for op in [
            Operation::ViewRuns,
            Operation::ViewProofs,
            Operation::ExportBundle,
            Operation::ApproveAction,
            Operation::SimulatePolicy,
            Operation::ActivatePolicy,
            Operation::ChangeCapture,
        ] {
            assert!(sys.can(op), "system_admin devia poder {}", op.label());
        }
    }

    #[test]
    fn alterar_captura_e_so_do_system_admin() {
        for r in [
            Role::Viewer,
            Role::Auditor,
            Role::Approver,
            Role::PolicyAdmin,
        ] {
            assert!(!com(&[r]).can(Operation::ChangeCapture), "{}", r.label());
        }
    }

    #[test]
    fn a_recusa_diz_o_que_falta() {
        let e = com(&[Role::Viewer])
            .require(Operation::ApproveAction)
            .unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert!(e.1.contains("approver"), "{}", e.1);
        assert!(e.1.contains("viewer"), "{}", e.1);
    }

    #[test]
    fn papeis_desconhecidos_sao_ignorados_e_nao_promovem() {
        assert_eq!(Role::parse("ceo"), None);
        assert_eq!(Role::parse("policy-admin"), Some(Role::PolicyAdmin));
    }
}
