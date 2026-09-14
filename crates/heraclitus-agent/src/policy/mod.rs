//! SPEC-0075 §11–§18 — a policy declarativa determinística.
//!
//! # Os dois princípios que o código tem de tornar mecânicos
//!
//! ### Policy is code, model output is data (§2.1)
//!
//! Nada do que um LLM produz altera a policy. O avaliador só vê campos
//! tipados, explicitamente projectados por quem chama — nunca o texto do
//! modelo, nunca o payload em bruto.
//!
//! ### Fail closed (§2.2)
//!
//! Se a acção é protegida e a policy não consegue ser avaliada, a decisão é
//! `DENY`. Nunca `ALLOW because policy service unavailable`. Isto está no
//! próprio tipo: o default do documento é `deny` e [`DeterministicAgentPolicyEngine::evaluate`]
//! não tem caminho que devolva `Allow` sem uma regra que o diga.
//!
//! # Determinismo (§17)
//!
//! Mesmos inputs canónicos + mesma versão de policy => mesma decisão. Isto
//! exclui, por construção: ordem de mapas (tudo é `BTreeMap`), locale
//! (comparações ASCII explícitas), fuso horário (o tempo entra como input),
//! thread, reinício, ordem de `HashMap` e aleatoriedade.
//!
//! Os decimais são comparados **sobre os dígitos**, nunca convertidos para
//! `f64`: `0.1 + 0.2 > 0.3` é verdadeiro em binário e falso em dinheiro, e uma
//! policy de pagamentos não pode depender de qual dos dois o compilador
//! escolheu.

pub mod yaml;

use crate::canonical::{
    domain_hash, hex32, CanonicalWriter, DOMAIN_POLICY_DOC, DOMAIN_POLICY_INPUT,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Identificador da versão de esquema aceite.
pub const POLICY_SCHEMA_V1: &str = "agent-policy-v1";
/// Tecto de regras. Um documento sem tecto é uma forma de negação de serviço.
pub const MAX_RULES: usize = 4096;
/// Tecto de condições por regra.
pub const MAX_CONDITIONS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy ilegível: {0}")]
    Parse(#[from] yaml::YamlError),
    #[error("policy inválida: {0}")]
    Invalid(String),
    #[error("esquema não suportado: `{0}` (esperava `{POLICY_SCHEMA_V1}`)")]
    UnsupportedSchema(String),
}

/// Valor tipado — o que entra numa condição e o que a projecção de input dá.
///
/// Não há variante de vírgula flutuante, de propósito (§12: "decimal-safe
/// representation").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyValueV1 {
    Bool(bool),
    Int(i64),
    /// Decimal preservado como texto (`"5000.00"`). Comparado dígito a dígito.
    Str(String),
    Set(Vec<String>),
}

impl PolicyValueV1 {
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(match v {
            Value::Bool(b) => Self::Bool(*b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Self::Int(i),
                // Um número JSON que não cabe em i64 vira texto e continua
                // comparável como decimal — em vez de perder precisão num f64.
                None => Self::Str(n.to_string()),
            },
            Value::String(s) => Self::Str(s.clone()),
            Value::Array(a) => Self::Set(
                a.iter()
                    .map(|x| match x {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect(),
            ),
            Value::Null | Value::Object(_) => return None,
        })
    }

    pub fn as_text(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Str(s) => s.clone(),
            Self::Set(v) => v.join(","),
        }
    }

    fn write_canonical(&self, w: &mut CanonicalWriter) {
        match self {
            Self::Bool(b) => {
                w.u8v(1);
                w.bool(*b);
            }
            Self::Int(i) => {
                w.u8v(2);
                w.i64le(*i);
            }
            Self::Str(s) => {
                w.u8v(3);
                w.str(s);
            }
            Self::Set(v) => {
                w.u8v(4);
                w.str_list(v);
            }
        }
    }
}

/// Operadores do MVP (§12). Sem regex: um motor de regex sobre input hostil é
/// uma superfície de DoS que uma fronteira de autorização não pode ter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Prefix,
    Suffix,
    Contains,
    Exists,
}

impl ConditionOp {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            "prefix" => Self::Prefix,
            "suffix" => Self::Suffix,
            "contains" => Self::Contains,
            "exists" => Self::Exists,
            _ => return None,
        })
    }
    fn tag(self) -> u8 {
        match self {
            Self::Eq => 1,
            Self::Neq => 2,
            Self::Lt => 3,
            Self::Lte => 4,
            Self::Gt => 5,
            Self::Gte => 6,
            Self::In => 7,
            Self::NotIn => 8,
            Self::Prefix => 9,
            Self::Suffix => 10,
            Self::Contains => 11,
            Self::Exists => 12,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::In => "in",
            Self::NotIn => "not_in",
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
            Self::Contains => "contains",
            Self::Exists => "exists",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub op: ConditionOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<PolicyValueV1>,
}

/// A que acções a regra se aplica.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<PolicyCondition>,
}

/// A decisão que uma regra declara.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    Allow,
    Deny,
    RequireApproval,
    Redact,
    RateLimit,
    SandboxHint,
}

impl RuleDecision {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "allow" => Self::Allow,
            "deny" => Self::Deny,
            "require_approval" => Self::RequireApproval,
            "redact" => Self::Redact,
            "rate_limit" => Self::RateLimit,
            "sandbox_hint" => Self::SandboxHint,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
            Self::Redact => "redact",
            Self::RateLimit => "rate_limit",
            Self::SandboxHint => "sandbox_hint",
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
            Self::RequireApproval => 3,
            Self::Redact => 4,
            Self::RateLimit => 5,
            Self::SandboxHint => 6,
        }
    }
    /// Se esta decisão impede a acção de chegar ao upstream em modo `enforce`.
    pub fn blocks(self) -> bool {
        matches!(self, Self::Deny | Self::RequireApproval | Self::RateLimit)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSpec {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultSpec {
    #[serde(default)]
    pub redact_fields: Vec<String>,
    #[serde(default)]
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitSpec {
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub retry_after_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicyRule {
    pub id: String,
    #[serde(default, rename = "match")]
    pub matcher: PolicyMatch,
    pub decision: RuleDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// O documento de policy interpretado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicyDocument {
    pub version: String,
    /// Identidade estável da policy ao longo das versões.
    pub id: String,
    /// Rótulo desta revisão (`v17`). Não confundir com [`Self::version`], que
    /// é a versão do **esquema**.
    pub revision: String,
    pub default_decision: RuleDecision,
    pub rules: Vec<AgentPolicyRule>,
}

impl Default for AgentPolicyDocument {
    /// O documento vazio nega tudo. É o único default defensável para uma
    /// fronteira de autorização.
    fn default() -> Self {
        Self {
            version: POLICY_SCHEMA_V1.to_string(),
            id: "agent-policy".to_string(),
            revision: "v0".to_string(),
            default_decision: RuleDecision::Deny,
            rules: Vec::new(),
        }
    }
}

impl AgentPolicyDocument {
    /// Lê YAML (subconjunto) ou JSON.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let v = yaml::parse_document(text)?;
        Self::from_value(&v)
    }

    pub fn from_value(v: &Value) -> Result<Self, PolicyError> {
        let version = v
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or(POLICY_SCHEMA_V1)
            .to_string();
        if version != POLICY_SCHEMA_V1 {
            return Err(PolicyError::UnsupportedSchema(version));
        }
        let default_decision = v
            .get("defaults")
            .and_then(|d| d.get("decision"))
            .and_then(Value::as_str)
            .map(|s| {
                RuleDecision::parse(s)
                    .ok_or_else(|| PolicyError::Invalid(format!("decisão default inválida: {s}")))
            })
            .transpose()?
            .unwrap_or(RuleDecision::Deny);
        if matches!(default_decision, RuleDecision::Allow) {
            // Não é proibido, mas tem de ser gritado: `defaults.decision: allow`
            // desliga o fail-closed inteiro. Recusar em silêncio seria pior; o
            // erro nomeia exactamente o que está a acontecer.
            return Err(PolicyError::Invalid(
                "defaults.decision: allow desliga o fail-closed de §2.2. \
                 Se é mesmo isso que quer, declare uma regra explícita que \
                 corresponda a tudo em vez de mudar o default."
                    .into(),
            ));
        }

        let rules_raw = v.get("rules").and_then(Value::as_array);
        let mut rules = Vec::new();
        if let Some(list) = rules_raw {
            if list.len() > MAX_RULES {
                return Err(PolicyError::Invalid(format!(
                    "policy com {} regras excede o tecto de {MAX_RULES}",
                    list.len()
                )));
            }
            for (i, r) in list.iter().enumerate() {
                rules.push(parse_rule(r, i)?);
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for r in &rules {
            if !seen.insert(r.id.clone()) {
                return Err(PolicyError::Invalid(format!("regra duplicada: {}", r.id)));
            }
        }
        Ok(Self {
            version,
            id: v
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("agent-policy")
                .to_string(),
            revision: v
                .get("revision")
                .and_then(Value::as_str)
                .unwrap_or("v1")
                .to_string(),
            default_decision,
            rules,
        })
    }

    /// Bytes canónicos do documento **interpretado**.
    ///
    /// Hashear os bytes do ficheiro tornaria o `policy_hash` sensível a
    /// comentários, indentação e à escolha entre YAML e JSON — e duas escritas
    /// da mesma policy dariam versões diferentes sem nenhuma diferença de
    /// comportamento. O que interessa provar é *que regras estavam em vigor*.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.str(&self.version);
        w.str(&self.id);
        w.str(&self.revision);
        w.u8v(self.default_decision.tag());
        w.u64v(self.rules.len() as u64);
        for r in &self.rules {
            w.str(&r.id);
            w.u8v(r.decision.tag());
            w.opt_str(r.matcher.server.as_deref());
            w.opt_str(r.matcher.tool.as_deref());
            w.opt_str(r.matcher.agent.as_deref());
            w.opt_str(r.matcher.environment.as_deref());
            w.opt_str(r.matcher.protocol.as_deref());
            w.u64v(r.matcher.conditions.len() as u64);
            for c in &r.matcher.conditions {
                w.str(&c.field);
                w.u8v(c.op.tag());
                match &c.value {
                    Some(v) => {
                        w.u8v(1);
                        v.write_canonical(&mut w);
                    }
                    None => {
                        w.u8v(0);
                    }
                }
            }
            match &r.approval {
                Some(a) => {
                    w.u8v(1);
                    w.str_list(&a.roles);
                    w.u64v(a.ttl_seconds);
                }
                None => {
                    w.u8v(0);
                }
            }
            match &r.result {
                Some(x) => {
                    w.u8v(1);
                    w.str_list(&x.redact_fields);
                    w.u64v(x.max_bytes);
                }
                None => {
                    w.u8v(0);
                }
            }
            match &r.rate_limit {
                Some(x) => {
                    w.u8v(1);
                    w.str(&x.bucket);
                    w.u64v(x.retry_after_ms);
                }
                None => {
                    w.u8v(0);
                }
            }
            w.opt_str(r.sandbox_profile.as_deref());
            w.opt_str(r.reason_code.as_deref());
        }
        w.into_bytes()
    }

    pub fn hash(&self) -> String {
        hex32(&domain_hash(DOMAIN_POLICY_DOC, &self.canonical_bytes()))
    }
}

fn parse_rule(v: &Value, index: usize) -> Result<AgentPolicyRule, PolicyError> {
    let id = v
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::Invalid(format!("regra {index} sem `id`")))?
        .to_string();
    let decision_str = v
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::Invalid(format!("regra `{id}` sem `decision`")))?;
    let decision = RuleDecision::parse(decision_str).ok_or_else(|| {
        PolicyError::Invalid(format!(
            "regra `{id}`: decisão `{decision_str}` desconhecida"
        ))
    })?;

    let m = v.get("match");
    let mut matcher = PolicyMatch {
        server: m
            .and_then(|x| x.get("server"))
            .and_then(Value::as_str)
            .map(str::to_string),
        tool: m
            .and_then(|x| x.get("tool"))
            .and_then(Value::as_str)
            .map(str::to_string),
        agent: m
            .and_then(|x| x.get("agent"))
            .and_then(Value::as_str)
            .map(str::to_string),
        environment: m
            .and_then(|x| x.get("environment"))
            .and_then(Value::as_str)
            .map(str::to_string),
        protocol: m
            .and_then(|x| x.get("protocol"))
            .and_then(Value::as_str)
            .map(str::to_string),
        conditions: Vec::new(),
    };
    if let Some(conds) = m
        .and_then(|x| x.get("conditions"))
        .and_then(Value::as_array)
    {
        if conds.len() > MAX_CONDITIONS {
            return Err(PolicyError::Invalid(format!(
                "regra `{id}` com {} condições excede o tecto de {MAX_CONDITIONS}",
                conds.len()
            )));
        }
        for c in conds {
            let field = c
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| PolicyError::Invalid(format!("regra `{id}`: condição sem `field`")))?
                .to_string();
            let op_str = c
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(|| PolicyError::Invalid(format!("regra `{id}`: condição sem `op`")))?;
            let op = ConditionOp::parse(op_str).ok_or_else(|| {
                PolicyError::Invalid(format!(
                    "regra `{id}`: operador `{op_str}` não existe no MVP"
                ))
            })?;
            let value = c.get("value").and_then(PolicyValueV1::from_json);
            if op != ConditionOp::Exists && value.is_none() {
                return Err(PolicyError::Invalid(format!(
                    "regra `{id}`: a condição `{field} {op_str}` precisa de `value`"
                )));
            }
            matcher
                .conditions
                .push(PolicyCondition { field, op, value });
        }
    }

    let approval = v.get("approval").map(|a| ApprovalSpec {
        roles: a
            .get("roles")
            .and_then(Value::as_array)
            .map(|x| {
                x.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        ttl_seconds: a.get("ttl_seconds").and_then(Value::as_u64).unwrap_or(300),
    });
    if decision == RuleDecision::RequireApproval {
        let roles_empty = approval
            .as_ref()
            .map(|a| a.roles.is_empty())
            .unwrap_or(true);
        if roles_empty {
            return Err(PolicyError::Invalid(format!(
                "regra `{id}`: `require_approval` sem `approval.roles` autorizaria qualquer pessoa a aprovar"
            )));
        }
    }

    Ok(AgentPolicyRule {
        id,
        matcher,
        decision,
        approval,
        result: v.get("result").map(|r| ResultSpec {
            redact_fields: r
                .get("redact_fields")
                .and_then(Value::as_array)
                .map(|x| {
                    x.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            max_bytes: r.get("max_bytes").and_then(Value::as_u64).unwrap_or(0),
        }),
        rate_limit: v.get("rate_limit").map(|r| RateLimitSpec {
            bucket: r
                .get("bucket")
                .and_then(Value::as_str)
                .unwrap_or("default")
                .to_string(),
            retry_after_ms: r
                .get("retry_after_ms")
                .and_then(Value::as_u64)
                .unwrap_or(1000),
        }),
        sandbox_profile: v
            .get("sandbox_profile")
            .and_then(Value::as_str)
            .map(str::to_string),
        reason_code: v
            .get("reason_code")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// O que o avaliador vê. Nunca o payload em bruto (§6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInput {
    pub server_id: String,
    pub tool_name: String,
    pub agent_subject: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    /// Campos explicitamente permitidos para decisão.
    #[serde(default)]
    pub fields: BTreeMap<String, PolicyValueV1>,
    /// Tempo como INPUT explícito (§17). Nunca lido do relógio dentro do
    /// avaliador — senão a mesma decisão deixaria de ser reproduzível.
    #[serde(default)]
    pub now_unix_seconds: u64,
}

impl PolicyInput {
    /// Hash da projecção — o que a evidência guarda para provar *sobre que
    /// inputs* a decisão foi tomada, sem guardar os inputs.
    pub fn projection_hash(&self) -> String {
        let mut w = CanonicalWriter::new();
        w.str(&self.server_id);
        w.str(&self.tool_name);
        w.str(&self.agent_subject);
        w.opt_str(self.environment.as_deref());
        w.opt_str(self.protocol.as_deref());
        w.u64v(self.fields.len() as u64);
        for (k, v) in &self.fields {
            w.str(k);
            v.write_canonical(&mut w);
        }
        // `now` NÃO entra: duas avaliações iguais em instantes diferentes têm de
        // dar a mesma projecção, senão o hash deixa de identificar a decisão.
        hex32(&domain_hash(DOMAIN_POLICY_INPUT, w.as_slice()))
    }
}

/// A decisão, na forma que o gateway consome (§13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AgentPolicyDecisionV1 {
    Allow,
    Deny {
        reason_code: String,
        rule_id: Option<String>,
    },
    RequireApproval {
        roles: Vec<String>,
        ttl_seconds: u64,
        rule_id: String,
    },
    Redact {
        profile_id: String,
        redact_fields: Vec<String>,
        max_bytes: u64,
    },
    RateLimit {
        bucket_id: String,
        retry_after_ms: u64,
    },
    SandboxHint {
        profile_id: String,
    },
}

impl AgentPolicyDecisionV1 {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny { .. } => "deny",
            Self::RequireApproval { .. } => "require_approval",
            Self::Redact { .. } => "redact",
            Self::RateLimit { .. } => "rate_limit",
            Self::SandboxHint { .. } => "sandbox_hint",
        }
    }
    /// Se impede a acção de chegar ao upstream num gateway em `enforce`.
    pub fn blocks(&self) -> bool {
        matches!(
            self,
            Self::Deny { .. } | Self::RequireApproval { .. } | Self::RateLimit { .. }
        )
    }
}

/// Resultado completo de uma avaliação, com a proveniência que a evidência
/// exige (§18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub decision: AgentPolicyDecisionV1,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub rule_id: Option<String>,
    pub reason_code: Option<String>,
    pub input_projection_hash: String,
}

/// Avaliador determinístico.
#[derive(Debug, Clone)]
pub struct DeterministicAgentPolicyEngine {
    document: AgentPolicyDocument,
    hash: String,
}

impl DeterministicAgentPolicyEngine {
    pub fn new(document: AgentPolicyDocument) -> Self {
        let hash = document.hash();
        Self { document, hash }
    }

    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        Ok(Self::new(AgentPolicyDocument::parse(text)?))
    }

    /// O avaliador que nega tudo. É o que o gateway usa quando não há policy
    /// activa — fail closed, e não "sem policy, sem restrições".
    pub fn deny_all() -> Self {
        Self::new(AgentPolicyDocument::default())
    }

    pub fn document(&self) -> &AgentPolicyDocument {
        &self.document
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn revision(&self) -> &str {
        &self.document.revision
    }

    /// Primeira regra que corresponde ganha; sem correspondência, o default.
    pub fn evaluate(&self, input: &PolicyInput) -> PolicyEvaluation {
        let projection = input.projection_hash();
        for rule in &self.document.rules {
            if !matches_rule(rule, input) {
                continue;
            }
            let decision = match rule.decision {
                RuleDecision::Allow => AgentPolicyDecisionV1::Allow,
                RuleDecision::Deny => AgentPolicyDecisionV1::Deny {
                    reason_code: rule
                        .reason_code
                        .clone()
                        .unwrap_or_else(|| "POLICY_DENY".to_string()),
                    rule_id: Some(rule.id.clone()),
                },
                RuleDecision::RequireApproval => {
                    let a = rule.approval.clone().unwrap_or_default();
                    AgentPolicyDecisionV1::RequireApproval {
                        roles: a.roles,
                        ttl_seconds: if a.ttl_seconds == 0 {
                            300
                        } else {
                            a.ttl_seconds
                        },
                        rule_id: rule.id.clone(),
                    }
                }
                RuleDecision::Redact => {
                    let r = rule.result.clone().unwrap_or_default();
                    AgentPolicyDecisionV1::Redact {
                        profile_id: rule.id.clone(),
                        redact_fields: r.redact_fields,
                        max_bytes: r.max_bytes,
                    }
                }
                RuleDecision::RateLimit => {
                    let r = rule.rate_limit.clone().unwrap_or_default();
                    AgentPolicyDecisionV1::RateLimit {
                        bucket_id: if r.bucket.is_empty() {
                            rule.id.clone()
                        } else {
                            r.bucket
                        },
                        retry_after_ms: if r.retry_after_ms == 0 {
                            1000
                        } else {
                            r.retry_after_ms
                        },
                    }
                }
                RuleDecision::SandboxHint => AgentPolicyDecisionV1::SandboxHint {
                    profile_id: rule
                        .sandbox_profile
                        .clone()
                        .unwrap_or_else(|| rule.id.clone()),
                },
            };
            return PolicyEvaluation {
                decision,
                policy_id: self.document.id.clone(),
                policy_version: self.document.revision.clone(),
                policy_hash: self.hash.clone(),
                rule_id: Some(rule.id.clone()),
                reason_code: rule.reason_code.clone(),
                input_projection_hash: projection,
            };
        }
        // Nenhuma regra: o default. Que é `deny` — ver `AgentPolicyDocument::default`.
        let decision = match self.document.default_decision {
            RuleDecision::Allow => AgentPolicyDecisionV1::Allow,
            _ => AgentPolicyDecisionV1::Deny {
                reason_code: "DEFAULT_DENY".to_string(),
                rule_id: None,
            },
        };
        PolicyEvaluation {
            decision,
            policy_id: self.document.id.clone(),
            policy_version: self.document.revision.clone(),
            policy_hash: self.hash.clone(),
            rule_id: None,
            reason_code: Some("DEFAULT_DENY".to_string()),
            input_projection_hash: projection,
        }
    }
}

fn matches_rule(rule: &AgentPolicyRule, input: &PolicyInput) -> bool {
    let m = &rule.matcher;
    if let Some(s) = &m.server {
        if s != &input.server_id {
            return false;
        }
    }
    if let Some(t) = &m.tool {
        if t != &input.tool_name {
            return false;
        }
    }
    if let Some(a) = &m.agent {
        if a != &input.agent_subject {
            return false;
        }
    }
    if let Some(env) = &m.environment {
        if input.environment.as_deref() != Some(env.as_str()) {
            return false;
        }
    }
    if let Some(p) = &m.protocol {
        if input.protocol.as_deref() != Some(p.as_str()) {
            return false;
        }
    }
    m.conditions
        .iter()
        .all(|c| evaluate_condition(c, &input.fields))
}

fn evaluate_condition(c: &PolicyCondition, fields: &BTreeMap<String, PolicyValueV1>) -> bool {
    let actual = fields.get(&c.field);
    if c.op == ConditionOp::Exists {
        let want = matches!(c.value, Some(PolicyValueV1::Bool(false)));
        return actual.is_some() != want;
    }
    // Campo ausente NUNCA satisfaz uma condição. É a leitura fail-closed: uma
    // regra "amount <= 5000" não pode passar sobre uma acção que não declarou
    // `amount` nenhum.
    let (Some(actual), Some(expected)) = (actual, c.value.as_ref()) else {
        return false;
    };
    match c.op {
        ConditionOp::Eq => values_equal(actual, expected),
        ConditionOp::Neq => !values_equal(actual, expected),
        ConditionOp::Lt => compare(actual, expected) == Some(std::cmp::Ordering::Less),
        ConditionOp::Lte => matches!(
            compare(actual, expected),
            Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)
        ),
        ConditionOp::Gt => compare(actual, expected) == Some(std::cmp::Ordering::Greater),
        ConditionOp::Gte => matches!(
            compare(actual, expected),
            Some(std::cmp::Ordering::Greater) | Some(std::cmp::Ordering::Equal)
        ),
        ConditionOp::In => match expected {
            PolicyValueV1::Set(set) => set.contains(&actual.as_text()),
            other => values_equal(actual, other),
        },
        ConditionOp::NotIn => match expected {
            PolicyValueV1::Set(set) => !set.contains(&actual.as_text()),
            other => !values_equal(actual, other),
        },
        ConditionOp::Prefix => actual.as_text().starts_with(&expected.as_text()),
        ConditionOp::Suffix => actual.as_text().ends_with(&expected.as_text()),
        ConditionOp::Contains => match actual {
            PolicyValueV1::Set(set) => set.contains(&expected.as_text()),
            other => other.as_text().contains(&expected.as_text()),
        },
        ConditionOp::Exists => unreachable!("tratado acima"),
    }
}

fn values_equal(a: &PolicyValueV1, b: &PolicyValueV1) -> bool {
    match compare(a, b) {
        Some(std::cmp::Ordering::Equal) => true,
        Some(_) => false,
        // Tipos não comparáveis numericamente: igualdade textual exacta.
        None => a.as_text() == b.as_text(),
    }
}

/// Comparação numérica **decimal-safe**, ou `None` quando os valores não são
/// numéricos.
fn compare(a: &PolicyValueV1, b: &PolicyValueV1) -> Option<std::cmp::Ordering> {
    let (x, y) = (numeric(a)?, numeric(b)?);
    Some(compare_decimal(&x, &y))
}

/// Extrai a forma decimal de um valor, se tiver.
fn numeric(v: &PolicyValueV1) -> Option<Decimal> {
    match v {
        PolicyValueV1::Int(i) => Some(Decimal::from_i64(*i)),
        PolicyValueV1::Str(s) => Decimal::parse(s),
        _ => None,
    }
}

/// Decimal de precisão arbitrária, guardado como dígitos.
///
/// Existe porque `"0.1"` em `f64` não é 0,1 — e uma policy que autoriza
/// pagamentos até 5000,00 não pode depender de o valor 5000,00 ter sobrevivido
/// a uma conversão binária.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decimal {
    negative: bool,
    int_digits: String,
    frac_digits: String,
}

impl Decimal {
    fn from_i64(v: i64) -> Self {
        Self {
            negative: v < 0,
            int_digits: v.unsigned_abs().to_string(),
            frac_digits: String::new(),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (negative, rest) = match s.as_bytes()[0] {
            b'-' => (true, &s[1..]),
            b'+' => (false, &s[1..]),
            _ => (false, s),
        };
        let (int_part, frac_part) = match rest.split_once('.') {
            Some((i, f)) => (i, f),
            None => (rest, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let int_digits = int_part.trim_start_matches('0').to_string();
        Some(Self {
            negative,
            int_digits: if int_digits.is_empty() {
                "0".to_string()
            } else {
                int_digits
            },
            frac_digits: frac_part.trim_end_matches('0').to_string(),
        })
    }

    fn is_zero(&self) -> bool {
        self.int_digits == "0" && self.frac_digits.is_empty()
    }
}

fn compare_decimal(a: &Decimal, b: &Decimal) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    // O zero não tem sinal: `-0` e `0` são o mesmo número.
    let (an, bn) = (a.negative && !a.is_zero(), b.negative && !b.is_zero());
    match (an, bn) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    let magnitude = compare_magnitude(a, b);
    if an {
        magnitude.reverse()
    } else {
        magnitude
    }
}

fn compare_magnitude(a: &Decimal, b: &Decimal) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match a.int_digits.len().cmp(&b.int_digits.len()) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.int_digits.cmp(&b.int_digits) {
        Ordering::Equal => {}
        other => return other,
    }
    // Fracções: comparar dígito a dígito, com zero implícito à direita.
    let n = a.frac_digits.len().max(b.frac_digits.len());
    let (fa, fb) = (a.frac_digits.as_bytes(), b.frac_digits.as_bytes());
    for i in 0..n {
        let da = fa.get(i).copied().unwrap_or(b'0');
        let db = fb.get(i).copied().unwrap_or(b'0');
        match da.cmp(&db) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests;
