//! SPEC-0046 §9 — as restrições de emissão da RFC 5280 que a cadeia tem de
//! honrar, e que até aqui eram **ignoradas**.
//!
//! # A afirmação que estava errada
//!
//! O documento de bloqueios dizia que a validação de cadeia "recusa em vez de
//! adivinhar". Isso era verdade para a *construção* do caminho — uma cadeia que
//! não chega a uma âncora é recusada. Não era verdade para as **restrições**: um
//! certificado com `nameConstraints`, `pathLenConstraint` ou `keyUsage` era
//! aceite como se essas extensões não existissem. Ignorar uma restrição não é
//! adivinhar; é o contrário de recusar.
//!
//! O que isso permitia, concretamente:
//!
//! - Uma AC intermédia restringida pela raiz a emitir só para `C=BR,O=ICP-Brasil`
//!   podia emitir uma ACT para qualquer nome, e a cadeia fechava. A restrição
//!   existe precisamente para limitar o estrago de uma AC comprometida, e era
//!   como se não estivesse lá.
//! - Uma AC com `pathLenConstraint=0` — que a raiz emitiu para não poder criar
//!   sub-ACs — podia emitir outra AC, que emitia a ACT. Três elos onde a
//!   política permitia dois.
//! - Um certificado sem `keyCertSign` podia emitir. O bit que declara "esta
//!   chave assina certificados" não era lido.
//!
//! # Extensões críticas
//!
//! A RFC 5280 §6.1.4(f) é categórica: uma extensão marcada como crítica que o
//! validador não processa **tem** de causar rejeição. É o mecanismo pelo qual
//! uma AC diz "se não percebes isto, não uses este certificado". Ignorá-la
//! transforma um mecanismo de segurança no seu oposto.
//!
//! Cumprir isto pode recusar um certificado legítimo cuja extensão crítica não
//! saibamos processar. É o comportamento certo, e por isso há uma escotilha
//! **declarada** — [`RestricoesPolicy::criticas_toleradas`] — em vez de uma
//! tolerância silenciosa. O operador que a usa está a assumir a decisão, e o
//! erro nomeia o OID exacto para que ele saiba o que está a assumir.

use std::collections::BTreeSet;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::CompError;

pub const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
pub const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
pub const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
pub const OID_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
pub const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// As extensões críticas que este validador sabe processar. Qualquer outra,
/// marcada como crítica, faz recusar (§6.1.4(f)).
const CRITICAS_PROCESSADAS: [ObjectIdentifier; 5] = [
    OID_KEY_USAGE,
    OID_SUBJECT_ALT_NAME,
    OID_BASIC_CONSTRAINTS,
    OID_NAME_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
];

/// Decisões que o operador toma sobre a rigidez da validação de cadeia.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestricoesPolicy {
    /// OIDs de extensões críticas que este validador **não** processa e que o
    /// operador decidiu tolerar mesmo assim.
    ///
    /// Vazio por defeito. Cada OID aqui é uma afirmação do operador de que
    /// leu aquela extensão e concluiu que a ignorar não muda a decisão. Não é
    /// uma opção de conveniência: uma extensão é marcada crítica precisamente
    /// porque quem a emitiu acha que ignorá-la é inseguro.
    pub criticas_toleradas: BTreeSet<ObjectIdentifier>,
}

fn erro(d: String) -> CompError {
    CompError::Verify(d)
}

// ---------------------------------------------------------------------------
// keyUsage
// ---------------------------------------------------------------------------

/// Exige um bit de `keyUsage`, quando a extensão existe.
///
/// A ausência da extensão **não** é erro: a RFC 5280 §4.2.1.3 diz que uma chave
/// sem `keyUsage` não está restringida. Tratar a ausência como recusa partiria
/// certificados legítimos antigos, e tratar a presença como decorativa — o que
/// se fazia — anula a extensão. A regra é: se está lá, obedece-se.
pub fn exigir_key_usage(
    cert: &Certificate,
    bit: KeyUsages,
    para_que: &str,
) -> Result<(), CompError> {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(());
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE) else {
        return Ok(());
    };
    let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|e| erro(format!("keyUsage inválido em `{}`: {e}", cert.tbs_certificate.subject)))?;
    if ku.0.contains(bit) {
        return Ok(());
    }
    Err(erro(format!(
        "certificado `{}` tem keyUsage sem o bit necessário para {para_que}: a própria AC \
         declarou que esta chave não serve para isso",
        cert.tbs_certificate.subject
    )))
}

/// A folha da ACT tem de poder assinar. `digitalSignature` ou `nonRepudiation`
/// servem — a ICP-Brasil usa ambos em contextos diferentes, e exigir um deles em
/// concreto recusaria certificados legítimos.
pub fn exigir_assinatura_de_folha(cert: &Certificate) -> Result<(), CompError> {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(());
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE) else {
        return Ok(());
    };
    let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|e| erro(format!("keyUsage inválido: {e}")))?;
    if ku.0.contains(KeyUsages::DigitalSignature) || ku.0.contains(KeyUsages::NonRepudiation) {
        return Ok(());
    }
    Err(erro(format!(
        "certificado da ACT `{}` tem keyUsage sem digitalSignature nem nonRepudiation: \
         não está autorizado a assinar o carimbo",
        cert.tbs_certificate.subject
    )))
}

// ---------------------------------------------------------------------------
// basicConstraints: pathLenConstraint
// ---------------------------------------------------------------------------

/// `pathLenConstraint` de um certificado de AC, se declarado.
fn path_len(cert: &Certificate) -> Result<Option<u32>, CompError> {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(None);
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_BASIC_CONSTRAINTS) else {
        return Ok(None);
    };
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|e| erro(format!("basicConstraints inválido: {e}")))?;
    Ok(bc.path_len_constraint.map(u32::from))
}

/// Impõe o `pathLenConstraint` de cada AC do caminho.
///
/// `cadeia` vem da folha para cima (índice 0 = folha) e `ancora` fecha-a. Para
/// uma AC, a RFC 5280 §4.2.1.9 limita o número de intermédios **não
/// auto-emitidos** que a podem seguir no caminho — a folha não conta.
pub fn verificar_path_len(cadeia: &[Certificate], ancora: &Certificate) -> Result<(), CompError> {
    // Cada AC em `cadeia[i]` (i >= 1) é seguida por `i - 1` intermédios.
    for (i, cert) in cadeia.iter().enumerate().skip(1) {
        if let Some(limite) = path_len(cert)? {
            let seguintes = (i - 1) as u32;
            if seguintes > limite {
                return Err(erro(format!(
                    "pathLenConstraint violado: `{}` permite {limite} intermédio(s) abaixo de si \
                     e o caminho tem {seguintes}",
                    cert.tbs_certificate.subject
                )));
            }
        }
    }
    // A âncora é seguida por todos os intermédios da cadeia (tudo menos a folha).
    if let Some(limite) = path_len(ancora)? {
        let seguintes = cadeia.len().saturating_sub(1) as u32;
        if seguintes > limite {
            return Err(erro(format!(
                "pathLenConstraint violado na âncora `{}`: permite {limite} intermédio(s) e o \
                 caminho tem {seguintes}",
                ancora.tbs_certificate.subject
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extensões críticas não reconhecidas
// ---------------------------------------------------------------------------

/// §4.2 e §6.1.4(f) — sanidade das extensões: nenhuma repetida, e nenhuma
/// crítica que não saibamos processar.
pub fn verificar_criticas(
    cert: &Certificate,
    policy: &RestricoesPolicy,
) -> Result<(), CompError> {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(());
    };
    // §4.2 — "A certificate MUST NOT include more than one instance of a
    // particular extension". Com duas, qualquer procura por OID lê UMA delas e
    // ignora a outra — e quem escreve o certificado escolhe qual, pela ordem.
    // Um `basicConstraints` com `pathLen: 0` a seguir a outro sem limite passa
    // a ser decorativo. A norma proíbe isto exactamente por isso.
    let mut vistos: BTreeSet<ObjectIdentifier> = BTreeSet::new();
    for ext in exts.iter() {
        if !vistos.insert(ext.extn_id) {
            return Err(erro(format!(
                "certificado `{}` repete a extensão {}: §4.2 proíbe-o, porque com duas cópias é a ordem — e não a norma — que decide qual delas vale",
                cert.tbs_certificate.subject, ext.extn_id
            )));
        }
    }
    for ext in exts.iter() {
        if !ext.critical {
            continue;
        }
        if CRITICAS_PROCESSADAS.contains(&ext.extn_id)
            || policy.criticas_toleradas.contains(&ext.extn_id)
        {
            continue;
        }
        return Err(erro(format!(
            "certificado `{}` tem a extensão crítica {} que este validador não processa. \
             A RFC 5280 §6.1.4(f) obriga a recusar: crítica significa que quem emitiu \
             considera inseguro ignorá-la. Para a tolerar conscientemente, acrescente o OID \
             a `criticas_toleradas`",
            cert.tbs_certificate.subject, ext.extn_id
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// nameConstraints
// ---------------------------------------------------------------------------

/// As restrições que uma AC impõe a tudo o que emite.
#[derive(Debug, Clone, Default)]
pub struct Restricoes {
    permitidos: Vec<GeneralSubtree>,
    excluidos: Vec<GeneralSubtree>,
}

impl Restricoes {
    pub fn vazio(&self) -> bool {
        self.permitidos.is_empty() && self.excluidos.is_empty()
    }

    /// Lê e acumula as `nameConstraints` de um certificado de AC.
    pub fn acumular(&mut self, cert: &Certificate) -> Result<(), CompError> {
        let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
            return Ok(());
        };
        let Some(ext) = exts.iter().find(|e| e.extn_id == OID_NAME_CONSTRAINTS) else {
            return Ok(());
        };
        let nc = NameConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
            erro(format!(
                "nameConstraints inválido em `{}`: {e}",
                cert.tbs_certificate.subject
            ))
        })?;
        // A intersecção é acumulativa: uma AC nunca pode ALARGAR o que o seu
        // emissor lhe permitiu. Juntar os conjuntos e exigir que o nome satisfaça
        // todos é exactamente a intersecção.
        if let Some(p) = nc.permitted_subtrees {
            self.permitidos.extend(p);
        }
        if let Some(x) = nc.excluded_subtrees {
            self.excluidos.extend(x);
        }
        Ok(())
    }

    /// Confronta o sujeito e os SAN de `cert` com tudo o que foi acumulado.
    pub fn verificar(&self, cert: &Certificate) -> Result<(), CompError> {
        if self.vazio() {
            return Ok(());
        }
        let mut nomes: Vec<GeneralName> = Vec::new();
        // O sujeito é sempre um directoryName, mesmo quando vazio.
        nomes.push(GeneralName::DirectoryName(
            cert.tbs_certificate.subject.clone(),
        ));
        if let Some(exts) = cert.tbs_certificate.extensions.as_ref() {
            if let Some(ext) = exts.iter().find(|e| e.extn_id == OID_SUBJECT_ALT_NAME) {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| erro(format!("subjectAltName inválido: {e}")))?;
                nomes.extend(san.0);
            }
        }

        for nome in &nomes {
            // Excluídos: bastar um a bater para recusar.
            for sub in &self.excluidos {
                if bate(&sub.base, nome)? {
                    return Err(erro(format!(
                        "nameConstraints: o nome de `{}` cai numa excludedSubtree do emissor",
                        cert.tbs_certificate.subject
                    )));
                }
            }
            // Permitidos: só restringem os tipos sobre os quais há regra. Se não
            // há regra nenhuma para o tipo deste nome, o nome não é restringido —
            // é o que diz §4.2.1.10, e o contrário recusaria tudo o que uma AC
            // restringisse apenas por DNS.
            let mesmo_tipo: Vec<&GeneralSubtree> = self
                .permitidos
                .iter()
                .filter(|s| mesmo_tipo(&s.base, nome))
                .collect();
            if mesmo_tipo.is_empty() {
                continue;
            }
            let mut algum = false;
            for sub in mesmo_tipo {
                if bate(&sub.base, nome)? {
                    algum = true;
                    break;
                }
            }
            if !algum {
                return Err(erro(format!(
                    "nameConstraints: o nome de `{}` não cai em nenhuma permittedSubtree do \
                     emissor — a AC que o emitiu não estava autorizada a emitir para este nome",
                    cert.tbs_certificate.subject
                )));
            }
        }
        Ok(())
    }
}

fn discriminante(g: &GeneralName) -> u8 {
    match g {
        GeneralName::OtherName(_) => 0,
        GeneralName::Rfc822Name(_) => 1,
        GeneralName::DnsName(_) => 2,
        GeneralName::DirectoryName(_) => 4,
        GeneralName::EdiPartyName(_) => 5,
        GeneralName::UniformResourceIdentifier(_) => 6,
        GeneralName::IpAddress(_) => 7,
        GeneralName::RegisteredId(_) => 8,
    }
}

fn mesmo_tipo(a: &GeneralName, b: &GeneralName) -> bool {
    discriminante(a) == discriminante(b)
}

/// `base` (de uma subtree) cobre `nome`?
///
/// Um tipo que não sabemos comparar devolve `Err`, e não `false`. `false`
/// diria "não é excluído" e "não é permitido" ao mesmo tempo — e a primeira
/// leitura deixaria passar exactamente o que a restrição existe para impedir.
fn bate(base: &GeneralName, nome: &GeneralName) -> Result<bool, CompError> {
    match (base, nome) {
        (GeneralName::DirectoryName(b), GeneralName::DirectoryName(n)) => dn_cobre(b, n),
        (GeneralName::DnsName(b), GeneralName::DnsName(n)) => {
            Ok(dns_cobre(b.as_str(), n.as_str()))
        }
        (GeneralName::Rfc822Name(b), GeneralName::Rfc822Name(n)) => {
            Ok(rfc822_cobre(b.as_str(), n.as_str()))
        }
        (GeneralName::UniformResourceIdentifier(b), GeneralName::UniformResourceIdentifier(n)) => {
            Ok(uri_cobre(b.as_str(), n.as_str()))
        }
        (GeneralName::IpAddress(b), GeneralName::IpAddress(n)) => {
            Ok(ip_cobre(b.as_bytes(), n.as_bytes()))
        }
        (b, n) if discriminante(b) != discriminante(n) => Ok(false),
        (b, _) => Err(erro(format!(
            "nameConstraints com uma subtree do tipo [{}] que este validador não sabe comparar, \
             e o certificado tem um nome desse tipo: recusar é a única resposta segura",
            discriminante(b)
        ))),
    }
}

/// §4.2.1.10 — uma base directoryName cobre um nome se for um **prefixo** da
/// sequência de RDNs. `C=BR,O=ICP-Brasil` cobre `C=BR,O=ICP-Brasil,CN=ACT`.
fn dn_cobre(base: &Name, nome: &Name) -> Result<bool, CompError> {
    let b = &base.0;
    let n = &nome.0;
    if b.len() > n.len() {
        return Ok(false);
    }
    for (rb, rn) in b.iter().zip(n.iter()) {
        let db = rb
            .to_der()
            .map_err(|e| erro(format!("RDN da subtree não codifica: {e}")))?;
        let dn = rn
            .to_der()
            .map_err(|e| erro(format!("RDN do sujeito não codifica: {e}")))?;
        if db != dn {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `example.com` cobre `example.com` e `a.example.com`, mas não `notexample.com`.
fn dns_cobre(base: &str, nome: &str) -> bool {
    let b = base.trim_start_matches('.').to_ascii_lowercase();
    let n = nome.to_ascii_lowercase();
    if b.is_empty() {
        return true;
    }
    if n == b {
        return true;
    }
    n.len() > b.len() && n.ends_with(&b) && n.as_bytes()[n.len() - b.len() - 1] == b'.'
}

/// Uma base com `@` é um endereço exacto; sem `@` é um host ou um domínio.
fn rfc822_cobre(base: &str, nome: &str) -> bool {
    let b = base.to_ascii_lowercase();
    let n = nome.to_ascii_lowercase();
    if b.contains('@') {
        return b == n;
    }
    let Some((_, host)) = n.split_once('@') else {
        return false;
    };
    if b.starts_with('.') {
        let sufixo = &b;
        return host.len() > sufixo.len() && host.ends_with(sufixo.as_str());
    }
    host == b
}

fn uri_cobre(base: &str, nome: &str) -> bool {
    // A restrição aplica-se ao host do URI (§4.2.1.10).
    let host = |s: &str| -> String {
        let sem_esquema = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
        let ate_barra = sem_esquema.split('/').next().unwrap_or(sem_esquema);
        let sem_utilizador = ate_barra.rsplit('@').next().unwrap_or(ate_barra);
        sem_utilizador
            .split(':')
            .next()
            .unwrap_or(sem_utilizador)
            .to_ascii_lowercase()
    };
    dns_cobre(base, &host(nome))
}

/// A base é endereço + máscara (8 bytes em IPv4, 32 em IPv6).
fn ip_cobre(base: &[u8], nome: &[u8]) -> bool {
    if base.len() != nome.len() * 2 {
        return false;
    }
    let (addr, mask) = base.split_at(nome.len());
    addr.iter()
        .zip(mask.iter())
        .zip(nome.iter())
        .all(|((a, m), n)| (a & m) == (n & m))
}
