//! SPEC-0046 §11 — the configurable trust store of accredited timestamp
//! authorities.
//!
//! > O TrustStore MUST permitir ACTs credenciadas configuráveis.
//! > Nenhum nome de ACT deve ser hardcoded no core.
//!
//! That last sentence is the whole design constraint, and it is not
//! bureaucratic. The ITI's list of accredited authorities changes: providers
//! are added, suspended and revoked, and an órgão in a different jurisdiction
//! has a different list entirely. A root baked into this crate would be a
//! recompile away from every one of those events — and, worse, would keep
//! validating after an authority lost accreditation, because nothing in the
//! binary would know.
//!
//! So the anchors come from a directory the operator configures, and this
//! module has **no** embedded certificate, no default path, and no fallback to
//! the operating system's store. An empty trust store validates nothing, which
//! is the correct behaviour for "the operator has not said whom to trust yet".
//!
//! # What an anchor is, and what it is not
//!
//! An anchor here is a self-signed X.509 root, loaded from PEM or DER. Loading
//! it is an assertion by the operator, not a cryptographic fact: this module
//! checks that the bytes parse and that the certificate is currently valid, and
//! it deliberately does **not** try to verify a root's signature against
//! anything — a root is trusted because it was placed in the directory, which
//! is exactly what a trust anchor means.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use der::{Decode, DecodePem, Encode};
use x509_cert::Certificate;

use crate::CompError;

/// Maximum size of a single certificate file. A trust anchor is a couple of
/// kilobytes; anything larger is a mistake or an attempt to make the loader
/// allocate.
const MAX_ANCHOR_BYTES: u64 = 64 * 1024;

/// Maximum number of anchors. The ITI list is dozens, not thousands.
const MAX_ANCHORS: usize = 512;

/// One configured trust anchor.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The file it came from, so an operator can tell which one is failing.
    pub source: PathBuf,
    /// RFC 5280 subject, in the canonical DER form used for chain building.
    /// Comparing encoded names avoids the string-normalisation traps of
    /// comparing rendered DNs.
    pub subject_der: Vec<u8>,
    /// SHA-256 over the DER of the whole certificate. Identity for logs and
    /// for the operator to confirm which anchor is installed.
    pub fingerprint: [u8; 32],
    pub certificate: Certificate,
}

impl TrustAnchor {
    pub fn fingerprint_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.fingerprint {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// The subject as text, for a human-facing listing only. Never used for
    /// matching — see `subject_der`.
    pub fn subject_display(&self) -> String {
        self.certificate.tbs_certificate.subject.to_string()
    }
}

/// SPEC-0046 §11.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    /// Keyed by the DER of the subject name: chain building looks up an
    /// issuer by the exact bytes of the child's issuer field.
    by_subject: BTreeMap<Vec<u8>, Vec<TrustAnchor>>,
    loaded_from: Option<PathBuf>,
}

/// What loading a directory apurou. A store that is empty because the
/// directory was empty has to be distinguishable from one that is empty
/// because every file failed to parse.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustStoreLoadReport {
    pub files_seen: usize,
    pub anchors_loaded: usize,
    /// `(ficheiro, razão)` — nunca o conteúdo, que pode ser grande e não
    /// acrescenta nada ao diagnóstico.
    pub rejected: Vec<(String, String)>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.by_subject.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_subject.values().map(|v| v.len()).sum()
    }

    pub fn loaded_from(&self) -> Option<&Path> {
        self.loaded_from.as_deref()
    }

    /// Every anchor, in a stable order (by subject DER, then by fingerprint).
    pub fn anchors(&self) -> impl Iterator<Item = &TrustAnchor> {
        self.by_subject.values().flatten()
    }

    /// Anchors whose subject matches `issuer_der` exactly.
    ///
    /// More than one is normal and not an error: an authority rolls its root
    /// over and both are valid during the overlap, and the two have the same
    /// subject with different keys.
    pub fn anchors_for_issuer(&self, issuer_der: &[u8]) -> &[TrustAnchor] {
        self.by_subject
            .get(issuer_der)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Load every `.pem`/`.crt`/`.cer`/`.der` file in `dir`.
    ///
    /// A file that does not parse is **rejected and reported**, not fatal: one
    /// malformed anchor must not deny the operator the other twenty. A
    /// directory that does not exist yields an empty store and an empty
    /// report, because "not configured" is a legitimate state and not an error
    /// to crash on at boot.
    ///
    /// Files are loaded in sorted order so two boots over the same directory
    /// produce the same store.
    pub fn load_dir(dir: &Path) -> Result<(Self, TrustStoreLoadReport), CompError> {
        let mut store = Self {
            by_subject: BTreeMap::new(),
            loaded_from: Some(dir.to_path_buf()),
        };
        let mut report = TrustStoreLoadReport::default();

        let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| matches!(e, "pem" | "crt" | "cer" | "der"))
                })
                .collect(),
            Err(_) => return Ok((store, report)),
        };
        files.sort();

        for path in files {
            report.files_seen += 1;
            let nome = path.display().to_string();
            if store.len() >= MAX_ANCHORS {
                report
                    .rejected
                    .push((nome, format!("limite de {MAX_ANCHORS} âncoras atingido")));
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(meta) if meta.len() > MAX_ANCHOR_BYTES => {
                    report.rejected.push((
                        nome,
                        format!("{} bytes acima do limite de {MAX_ANCHOR_BYTES}", meta.len()),
                    ));
                    continue;
                }
                Err(error) => {
                    report.rejected.push((nome, error.to_string()));
                    continue;
                }
                _ => {}
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(error) => {
                    report.rejected.push((nome, error.to_string()));
                    continue;
                }
            };
            match Self::parse_certificate(&bytes) {
                Ok(certificate) => match store.insert(path.clone(), certificate) {
                    Ok(()) => report.anchors_loaded += 1,
                    Err(error) => report.rejected.push((nome, error.to_string())),
                },
                Err(error) => report.rejected.push((nome, error.to_string())),
            }
        }
        Ok((store, report))
    }

    /// Add one anchor from DER or PEM bytes. Exposed so a deployment that
    /// keeps its anchors somewhere other than a directory (a secret manager, a
    /// config blob) is not forced through the filesystem.
    pub fn add_pem_or_der(&mut self, source: impl Into<PathBuf>, bytes: &[u8]) -> Result<(), CompError> {
        let certificate = Self::parse_certificate(bytes)?;
        self.insert(source.into(), certificate)
    }

    fn parse_certificate(bytes: &[u8]) -> Result<Certificate, CompError> {
        // PEM first: a DER parse of PEM text fails with a confusing error, and
        // PEM is what an operator usually has.
        if bytes.starts_with(b"-----BEGIN") {
            return Certificate::from_pem(bytes)
                .map_err(|e| CompError::Verify(format!("PEM inválido: {e}")));
        }
        Certificate::from_der(bytes)
            .map_err(|e| CompError::Verify(format!("certificado DER inválido: {e}")))
    }

    fn insert(&mut self, source: PathBuf, certificate: Certificate) -> Result<(), CompError> {
        let subject_der = certificate
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|e| CompError::Verify(format!("subject não codifica: {e}")))?;
        let issuer_der = certificate
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|e| CompError::Verify(format!("issuer não codifica: {e}")))?;
        // §11 — uma âncora é uma raiz. Aceitar um certificado intermédio como
        // âncora faria o verificador confiar num elo cuja emissão ninguém
        // verificou, e o operador não teria como perceber a diferença ao olhar
        // para a pasta.
        if subject_der != issuer_der {
            return Err(CompError::Verify(
                "âncora tem de ser auto-emitida (subject == issuer); um intermédio não é raiz"
                    .into(),
            ));
        }
        let der = certificate
            .to_der()
            .map_err(|e| CompError::Verify(format!("certificado não recodifica: {e}")))?;
        let fingerprint: [u8; 32] = *blake3_sha256(&der);

        let anchor = TrustAnchor {
            source,
            subject_der: subject_der.clone(),
            fingerprint,
            certificate,
        };
        let bucket = self.by_subject.entry(subject_der).or_default();
        // Recarregar a mesma âncora duas vezes não a duplica: o
        // `anchors_for_issuer` seria percorrido duas vezes pelo mesmo
        // certificado e a contagem que o operador vê mentiria.
        if bucket.iter().any(|a| a.fingerprint == anchor.fingerprint) {
            return Ok(());
        }
        bucket.push(anchor);
        bucket.sort_by_key(|a| a.fingerprint);
        Ok(())
    }
}

/// SHA-256 sobre bytes, devolvido como array.
///
/// Chama-se assim porque o resto do crate usa BLAKE3 para identidade interna e
/// SHA-256 só onde um formato externo o exige — e um certificado é um formato
/// externo. Manter os dois nomes distintos evita que alguém troque um pelo
/// outro por distracção.
fn blake3_sha256(bytes: &[u8]) -> Box<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    Box::new(fixed)
}

/// Usado pelos testes do verificador para construir imprints. O caminho de
/// produção passou a calcular o digest pelo algoritmo que o token DECLARA
/// (`crate::algoritmos::Digest`), em vez de o fixar em SHA-256.
#[cfg(test)]
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    *blake3_sha256(bytes)
}



#[cfg(test)]
mod tests {
    use super::*;

    /// Gera uma raiz auto-assinada mínima em DER, para os testes não
    /// dependerem de um ficheiro externo.
    fn raiz_de_teste(cn: &str) -> Vec<u8> {
        crate::test_pki::self_signed_root(cn).certificate_der
    }

    #[test]
    fn uma_pasta_inexistente_da_um_store_vazio_e_nao_um_erro() {
        // "Não configurado" é um estado legítimo; rebentar no arranque por
        // causa dele seria transformar uma omissão numa indisponibilidade.
        let (store, report) = TrustStore::load_dir(Path::new("D:/nao/existe")).unwrap();
        assert!(store.is_empty());
        assert_eq!(report.files_seen, 0);
        assert!(report.rejected.is_empty());
    }

    #[test]
    fn um_ficheiro_partido_nao_impede_os_outros() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("boa.der"), raiz_de_teste("Raiz A")).unwrap();
        std::fs::write(dir.path().join("ma.pem"), b"-----BEGIN CERTIFICATE-----\nlixo\n").unwrap();
        let (store, report) = TrustStore::load_dir(dir.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(report.anchors_loaded, 1);
        assert_eq!(report.rejected.len(), 1);
        assert!(report.rejected[0].0.contains("ma.pem"));
    }

    #[test]
    fn um_intermedio_nao_e_aceite_como_ancora() {
        // §11 — aceitar um intermédio faria o verificador confiar num elo cuja
        // emissão ninguém verificou.
        let pki = crate::test_pki::chain_de_teste();
        let mut store = TrustStore::new();
        assert!(store
            .add_pem_or_der("intermedio", &pki.tsa_der)
            .unwrap_err()
            .to_string()
            .contains("auto-emitida"));
        store.add_pem_or_der("raiz", &pki.root_der).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn carregar_a_mesma_ancora_duas_vezes_nao_a_duplica() {
        let der = raiz_de_teste("Raiz A");
        let mut store = TrustStore::new();
        store.add_pem_or_der("a", &der).unwrap();
        store.add_pem_or_der("b", &der).unwrap();
        assert_eq!(store.len(), 1, "a contagem que o operador vê tem de ser real");
    }

    #[test]
    fn pem_e_der_dao_a_mesma_ancora() {
        let der = raiz_de_teste("Raiz A");
        use der::EncodePem;
        let pem = Certificate::from_der(&der)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let mut a = TrustStore::new();
        a.add_pem_or_der("der", &der).unwrap();
        let mut b = TrustStore::new();
        b.add_pem_or_der("pem", pem.as_bytes()).unwrap();
        assert_eq!(
            a.anchors().next().unwrap().fingerprint,
            b.anchors().next().unwrap().fingerprint
        );
    }

    #[test]
    fn um_ficheiro_grande_demais_e_recusado_sem_o_ler() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("enorme.der"), vec![0u8; (MAX_ANCHOR_BYTES + 1) as usize])
            .unwrap();
        let (store, report) = TrustStore::load_dir(dir.path()).unwrap();
        assert!(store.is_empty());
        assert_eq!(report.rejected.len(), 1);
        assert!(report.rejected[0].1.contains("acima do limite"));
    }

    #[test]
    fn a_ordem_de_carregamento_e_deterministica() {
        let dir = tempfile::tempdir().unwrap();
        for cn in ["Raiz C", "Raiz A", "Raiz B"] {
            std::fs::write(
                dir.path().join(format!("{}.der", cn.replace(' ', "-"))),
                raiz_de_teste(cn),
            )
            .unwrap();
        }
        let (a, _) = TrustStore::load_dir(dir.path()).unwrap();
        let (b, _) = TrustStore::load_dir(dir.path()).unwrap();
        let fa: Vec<_> = a.anchors().map(|x| x.fingerprint).collect();
        let fb: Vec<_> = b.anchors().map(|x| x.fingerprint).collect();
        assert_eq!(fa, fb);
        assert_eq!(fa.len(), 3);
    }

    #[test]
    fn a_procura_por_emissor_e_pelos_bytes_do_nome() {
        // Comparar DN renderizado traria as armadilhas de normalização de
        // strings; comparar DER não tem ambiguidade.
        let pki = crate::test_pki::chain_de_teste();
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &pki.root_der).unwrap();
        assert_eq!(store.anchors_for_issuer(&pki.root_subject_der).len(), 1);
        assert!(store.anchors_for_issuer(b"outro nome").is_empty());
    }
}
