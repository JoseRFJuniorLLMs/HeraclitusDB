use heraclitus_core::{AccessCredential, AccessRole, HeraclitusConfig, HeraclitusError};
use std::sync::Arc;
use tonic::{Request, Status};

#[derive(Debug, Clone)]
pub struct Principal {
    pub name: String,
    pub roles: Arc<Vec<AccessRole>>,
}

impl Principal {
    pub fn allows(&self, required: AccessRole) -> bool {
        self.roles.iter().any(|role| role.allows(required))
    }
}

#[derive(Clone)]
pub struct Authenticator {
    credentials: Arc<Vec<(Principal, [u8; 32])>>,
    auth_required: bool,
    /// Ha credenciais que carregam PAPEIS (`access_credentials`), por oposicao
    /// ao `auth_token` unico legado, que e sempre Admin.
    ///
    /// A distincao decide se vale a pena o REST aplicar papeis: com so o token
    /// legado nao existe papel nenhum para contornar — tudo e Admin de
    /// qualquer maneira — e exigir autenticacao ali seria mudar o
    /// comportamento sem fechar buraco nenhum.
    com_papeis: bool,
}

impl Authenticator {
    pub fn from_config(config: &HeraclitusConfig) -> Result<Self, HeraclitusError> {
        let mut credentials = Vec::new();
        for credential in &config.access_credentials {
            credentials.push((
                principal(credential),
                decode_digest(&credential.token_blake3).map_err(|e| {
                    HeraclitusError::Config(format!(
                        "token_blake3 inválido para {}: {e}",
                        credential.principal
                    ))
                })?,
            ));
        }
        // Compatibilidade de transição: o token único antigo conserva poder de
        // admin, mas production_mode o proíbe na validação de configuração.
        if let Some(token) = &config.auth_token {
            credentials.push((
                Principal {
                    name: "legacy-admin".into(),
                    roles: Arc::new(vec![AccessRole::Admin]),
                },
                *blake3::hash(token.as_bytes()).as_bytes(),
            ));
        }
        Ok(Self {
            auth_required: !credentials.is_empty(),
            com_papeis: !config.access_credentials.is_empty(),
            credentials: Arc::new(credentials),
        })
    }

    pub fn is_required(&self) -> bool {
        self.auth_required
    }

    /// `true` quando estao configuradas credenciais com papeis.
    pub fn tem_papeis(&self) -> bool {
        self.com_papeis
    }

    /// Resolve um segredo em bruto no `Principal` correspondente, sem saber de
    /// que superficie veio.
    ///
    /// Existe para o REST poder reutilizar exactamente esta politica em vez de
    /// a reescrever: a comparacao em tempo constante, o hash do segredo, e —
    /// sobretudo — a regra de aberto-por-omissao. Duas copias desta decisao era
    /// como as duas superficies ficaram com autorizacoes diferentes.
    pub fn resolver(&self, segredo: Option<&str>) -> Option<Principal> {
        if !self.auth_required {
            return Some(Principal {
                name: "local-loopback".into(),
                roles: Arc::new(vec![AccessRole::Admin]),
            });
        }
        let segredo = segredo.filter(|s| !s.is_empty())?;
        let got = blake3::hash(segredo.as_bytes());
        self.credentials
            .iter()
            .find(|(_, expected)| crate::rest::ct_eq(got.as_bytes(), expected))
            .map(|(principal, _)| principal.clone())
    }

    #[allow(clippy::result_large_err)]
    pub fn authenticate(&self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        match self.resolver(token.as_deref()) {
            Some(principal) => {
                req.extensions_mut().insert(principal);
                Ok(req)
            }
            None => Err(Status::unauthenticated("missing or invalid bearer token")),
        }
    }
}

fn principal(credential: &AccessCredential) -> Principal {
    Principal {
        name: credential.principal.clone(),
        roles: Arc::new(credential.roles.clone()),
    }
}

fn decode_digest(hex: &str) -> Result<[u8; 32], &'static str> {
    if hex.len() != 64 {
        return Err("comprimento deve ser 64");
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "digest não hexadecimal")?;
    }
    Ok(out)
}

pub fn require<T>(req: &Request<T>, role: AccessRole) -> Result<Principal, Status> {
    let principal = req
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal ausente"))?;
    if principal.allows(role) {
        Ok(principal)
    } else {
        Err(Status::permission_denied(format!(
            "principal '{}' não possui papel {:?}",
            principal.name, role
        )))
    }
}

/// Vincula o aprovador de uma accao humana a identidade AUTENTICADA.
///
/// # Porque e que isto existe
///
/// As duas superficies recebiam o `approver` no CORPO do pedido e persistiam-no
/// tal e qual. Um registo de aprovacao humana existe precisamente para atribuir
/// responsabilidade — e assim qualquer chamador registava uma aprovacao em nome
/// de outra pessoa. Pior: o gRPC ja mandava a identidade real para
/// `audit_admin`, portanto a auditoria sabia quem era e o registo de aprovacao
/// nao sabia.
///
/// # A regra
///
/// O aprovador registado e SEMPRE `identidade`. O campo do corpo passa a ser
/// opcional e, quando vem, e apenas VERIFICADO: divergir e um erro, nao uma
/// correccao silenciosa, para que a tentativa fique visivel a quem le os logs.
///
/// Vive aqui, e nao em cada superficie, porque uma politica escrita duas vezes
/// diverge — foi exactamente assim que o REST e o gRPC ficaram com regras de
/// autorizacao diferentes.
pub fn vincular_aprovador<'a>(
    pedido: Option<&str>,
    identidade: &'a str,
) -> Result<&'a str, String> {
    match pedido {
        Some(p) if p != identidade => Err(format!(
            "approver '{p}' nao coincide com a identidade autenticada '{identidade}' —              uma aprovacao so pode ser registada em nome de quem a faz"
        )),
        _ => Ok(identidade),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aprovador_e_sempre_a_identidade_autenticada() {
        // Ausente: fica a identidade, sem drama.
        assert_eq!(vincular_aprovador(None, "ana"), Ok("ana"));
        // Coincidente: idem.
        assert_eq!(vincular_aprovador(Some("ana"), "ana"), Ok("ana"));
        // Divergente: recusado, e a mensagem nomeia os DOIS lados — quem le o
        // log precisa de saber quem tentou e em nome de quem.
        let erro = vincular_aprovador(Some("a-directora"), "ana").unwrap_err();
        assert!(
            erro.contains("a-directora") && erro.contains("ana"),
            "{erro}"
        );
    }

    #[test]
    fn authenticates_hashed_token_and_enforces_roles() {
        let token = "0123456789abcdef0123456789abcdef"; // gitleaks:allow -- unit-test vector
        let mut cfg = HeraclitusConfig::default();
        cfg.access_credentials.push(AccessCredential {
            principal: "forge-ingestor".into(),
            token_blake3: blake3::hash(token.as_bytes()).to_hex().to_string(),
            roles: vec![AccessRole::Writer],
        });
        let auth = Authenticator::from_config(&cfg).unwrap();
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let req = auth.authenticate(req).unwrap();
        assert_eq!(
            require(&req, AccessRole::Reader).unwrap().name,
            "forge-ingestor"
        );
        assert!(require(&req, AccessRole::Writer).is_ok());
        assert!(require(&req, AccessRole::Admin).is_err());
    }
}
