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
//! # Três modos, e cada um diz o que é
//!
//! | modo | o que prova | papéis |
//! |---|---|---|
//! | `dev_local` | nada | todos |
//! | `basic` | que quem chama conhece UMA senha partilhada | todos, sob um só sujeito |
//! | `oidc` | quem é a pessoa, validado pelo emissor dela | os que o token declara |
//!
//! O `basic` fecha a porta mas **não** resolve a §28: uma senha partilhada não
//! distingue pessoas, portanto `approver` e `policy_admin` colapsam num único
//! principal e uma aprovação fica registada em nome da credencial, não de quem
//! carregou no botão.
//!
//! Isso é aceitável para um portátil ou uma rede interna — e é **dito em voz
//! alta** em três sítios, porque o perigo não é o modo fraco, é alguém supor
//! que tem o modo forte: o banner da Consola, o campo `auth` de
//! `/api/v1/agent/status`, e o `approver_issuer` de cada evidência de
//! aprovação, que fica `basic-shared` para uma auditoria futura ver que aquela
//! assinatura não identifica ninguém.
//!
//! Em produção, a [`heraclitus_agent::config::AgentGatewayConfig::validate`]
//! continua a exigir OIDC: `basic` não é promovido a identidade por ser
//! conveniente.

use crate::runtime::AgentRuntime;
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use std::sync::Arc;

/// O emissor registado nas evidências quando a credencial é partilhada.
///
/// Fica na evidência de propósito: uma aprovação assinada por `admin` via senha
/// partilhada e uma assinada por `jose@example` via OIDC não valem o mesmo, e
/// quem auditar o bundle daqui a um ano tem de conseguir ver a diferença sem
/// perguntar a ninguém.
pub const SHARED_ISSUER: &str = "basic-shared";

/// Comparação em tempo constante.
///
/// O tempo não depende do prefixo coincidente, o que fecha o canal lateral de
/// temporização do `==` de strings. O comprimento continua observável —
/// inevitável e inócuo, porque o segredo não é o comprimento. É a mesma função
/// que o REST de administração usa (`heraclitus-server/src/rest.rs`, R17);
/// está duplicada aqui para não obrigar este crate a depender do servidor.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Base64 padrão (RFC 4648, com padding), só para montar o valor esperado do
/// cabeçalho. Nunca se descodifica o input do cliente: compara-se o cabeçalho
/// inteiro contra o esperado, o que evita ter um descodificador a mastigar
/// bytes de quem quer que bata à porta.
pub(crate) fn b64(input: &[u8]) -> String {
    const AB: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(AB[(n >> 18) as usize & 63] as char);
        out.push(AB[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            AB[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            AB[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A credencial partilhada, já na forma em que é comparada.
///
/// Guarda o cabeçalho **esperado** e não a senha: o segredo em claro não fica a
/// passear pela struct, e o `Debug` não o pode imprimir por acidente.
#[derive(Clone)]
pub struct SharedCredential {
    expected_header: Arc<String>,
    username: Arc<String>,
}

impl std::fmt::Debug for SharedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nunca imprimir o cabeçalho: um `{:?}` num log de erro entregaria a
        // senha em base64, que é o mesmo que a entregar.
        f.debug_struct("SharedCredential")
            .field("username", &self.username)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl SharedCredential {
    /// Constrói a partir de `utilizador:senha`. `None` se a forma for ambígua.
    pub fn parse(raw: &str) -> Option<Self> {
        let (utilizador, senha) = raw.split_once(':')?;
        if utilizador.is_empty() || senha.is_empty() {
            return None;
        }
        Some(Self {
            expected_header: Arc::new(format!("Basic {}", b64(raw.as_bytes()))),
            username: Arc::new(utilizador.to_string()),
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// Confere o cabeçalho `Authorization` inteiro, em tempo constante.
    pub fn matches(&self, header: Option<&str>) -> bool {
        header.is_some_and(|v| ct_eq(v.as_bytes(), self.expected_header.as_bytes()))
    }
}

/// Uma recusa de autenticação, com o que a resposta HTTP precisa.
#[derive(Debug, Clone)]
pub struct AuthRejection {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: String,
    /// `true` quando a resposta deve levar `WWW-Authenticate: Basic`, para o
    /// browser mostrar a caixa de login nativa em vez de uma página de erro.
    pub challenge: bool,
}

impl AuthRejection {
    pub fn unauthorized(detail: impl Into<String>, challenge: bool) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "IDENTITY_VALIDATION_FAILED",
            detail: detail.into(),
            challenge,
        }
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "FORBIDDEN",
            detail: detail.into(),
            challenge: false,
        }
    }
}

/// O `realm` do desafio. Aparece na caixa de login do browser.
pub const BASIC_REALM: &str = "Basic realm=\"Heraclitus Agent Black Box\", charset=\"UTF-8\"";

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

/// Como é que este principal foi estabelecido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Ninguém provou nada.
    DevLocal,
    /// Alguém provou conhecer uma senha partilhada. Não identifica a pessoa.
    Basic,
    /// Um emissor validou quem é a pessoa.
    Oidc,
}

impl AuthMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::DevLocal => "dev_local",
            Self::Basic => "basic",
            Self::Oidc => "oidc",
        }
    }

    /// Se este modo distingue PESSOAS. É o que decide se a separação de papéis
    /// de §28 é real ou nominal — e o que a Consola tem de mostrar.
    pub fn identifies_people(self) -> bool {
        self == Self::Oidc
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
    pub mode: AuthMode,
}

impl Principal {
    pub fn can(&self, op: Operation) -> bool {
        op.allowed_roles().iter().any(|r| self.roles.contains(r))
    }

    pub fn require(&self, op: Operation) -> Result<(), AuthRejection> {
        if self.can(op) {
            return Ok(());
        }
        Err(AuthRejection::forbidden(format!(
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
        )))
    }

    /// Todos os papéis. É o que `dev_local` e `basic` recebem: nenhum dos dois
    /// distingue pessoas, portanto dar-lhes um subconjunto seria teatro — a
    /// mesma credencial trocaria de papel mudando um campo.
    fn all_roles() -> Vec<Role> {
        vec![
            Role::Viewer,
            Role::Auditor,
            Role::Approver,
            Role::PolicyAdmin,
            Role::SystemAdmin,
        ]
    }
}

/// Extrai o principal dos cabeçalhos.
///
/// A ordem é deliberada e vai do mais forte para o mais fraco:
///
/// 1. **OIDC**, se houver validador — a única via que identifica pessoas.
/// 2. **Basic**, se houver credencial partilhada — fecha a porta, não diz quem
///    entrou. Uma falha aqui devolve `WWW-Authenticate`, para o browser pedir
///    utilizador e senha em vez de mostrar uma página de erro.
/// 3. **Aberto**, se não houver nem uma nem outra.
///
/// O OIDC vem primeiro para que configurar os dois não degrade em silêncio para
/// o mais fraco.
pub fn principal_from(
    runtime: &Arc<AgentRuntime>,
    headers: &HeaderMap,
    now_unix_seconds: u64,
) -> Result<Principal, AuthRejection> {
    let cabecalho = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(validator) = runtime.validator() else {
        // ── 2. credencial partilhada ────────────────────────────────────────
        if let Some(credencial) = runtime.console_credential() {
            if !credencial.matches(cabecalho) {
                return Err(AuthRejection::unauthorized(
                    "esta consola exige utilizador e senha",
                    true,
                ));
            }
            return Ok(Principal {
                subject: credencial.username().to_string(),
                // NÃO é o emissor de uma identidade: é a marca de que aquilo
                // que se provou foi o conhecimento de uma senha. Fica assim na
                // evidência de cada aprovação.
                issuer: SHARED_ISSUER.to_string(),
                roles: Principal::all_roles(),
                dev_local: false,
                mode: AuthMode::Basic,
            });
        }
        // ── 3. aberto ───────────────────────────────────────────────────────
        return Ok(Principal {
            subject: "dev-local".to_string(),
            issuer: "dev-local".to_string(),
            roles: Principal::all_roles(),
            dev_local: true,
            mode: AuthMode::DevLocal,
        });
    };
    // ── 1. OIDC ─────────────────────────────────────────────────────────────
    let token =
        cabecalho
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthRejection::unauthorized(
                "é necessário `Authorization: Bearer <token>`",
                false,
            ))?;
    let identity = validator
        .validate(token, now_unix_seconds)
        .map_err(|e| AuthRejection::unauthorized(format!("{e}"), false))?;
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
        mode: AuthMode::Oidc,
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
            mode: AuthMode::Oidc,
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
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert!(
            !e.challenge,
            "um 403 por papel não deve pedir credencial nova"
        );
        assert!(e.detail.contains("approver"), "{}", e.detail);
        assert!(e.detail.contains("viewer"), "{}", e.detail);
    }

    #[test]
    fn papeis_desconhecidos_sao_ignorados_e_nao_promovem() {
        assert_eq!(Role::parse("ceo"), None);
        assert_eq!(Role::parse("policy-admin"), Some(Role::PolicyAdmin));
    }
}
