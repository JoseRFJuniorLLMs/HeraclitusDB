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
            credentials: Arc::new(credentials),
        })
    }

    pub fn is_required(&self) -> bool {
        self.auth_required
    }

    #[allow(clippy::result_large_err)]
    pub fn authenticate(&self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if !self.auth_required {
            req.extensions_mut().insert(Principal {
                name: "local-loopback".into(),
                roles: Arc::new(vec![AccessRole::Admin]),
            });
            return Ok(req);
        }
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Status::unauthenticated("missing or invalid bearer token"))?;
        let got = blake3::hash(token.as_bytes());
        let matched = self
            .credentials
            .iter()
            .find(|(_, expected)| crate::rest::ct_eq(got.as_bytes(), expected));
        match matched {
            Some((principal, _)) => {
                req.extensions_mut().insert(principal.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

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
