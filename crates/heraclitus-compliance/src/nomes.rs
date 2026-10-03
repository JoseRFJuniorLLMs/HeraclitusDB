//! Comparação de nomes X.500 segundo a RFC 5280 §7.1 (regras de
//! preparação de strings da RFC 4518, na parte que interessa à interoperação).
//!
//! # Porque existe (conferência de 2026-10-02)
//!
//! Os nomes eram comparados como bytes DER crus — em `nameConstraints`
//! (`dn_cobre`), na escolha das CRLs de um emissor (`CrlStore::for_issuer`) e
//! na ligação emissor/assinante do carimbo do tempo (`icp.rs`). Dois DER
//! diferentes podem ser o MESMO nome: uma AC que codifica o `O=` como
//! `PrintableString` no certificado e como `UTF8String` na CRL, ou que muda
//! a capitalização ou os espaços, é perfeitamente conforme. A comparação por
//! bytes falhava fechado (recusava), o que é seguro mas parte a interoperação
//! com ACs reais: "não há CRL do emissor" com a CRL certa na pasta.
//!
//! # A regra implementada
//!
//! Dois nomes são iguais quando têm o mesmo número de RDNs e cada par de RDNs
//! tem o mesmo CONJUNTO de pares (tipo, valor), com os valores comparados
//! assim:
//! - tipos de string de diretório (UTF8String, PrintableString, IA5String,
//!   TeletexString, BMPString, UniversalString, VisibleString): descodificados
//!   para Unicode, sem espaços nas pontas, com sequências de espaços
//!   reduzidas a um, e comparados sem distinção de maiúsculas;
//! - qualquer outro tipo: bytes DER exactos (não se adivinha semântica).
//!
//! Não é a preparação RFC 4518 completa (normalização NFKC e mapeamentos de
//! caracteres ficam de fora: exigiriam tabelas Unicode que o crate não tem).
//! O que fica de fora continua a falhar FECHADO — dois nomes que só a
//! normalização completa igualaria são tratados como diferentes, nunca o
//! contrário.

use der::Tagged;
use x509_cert::name::{Name, RelativeDistinguishedName};

/// Chave canónica de um nome: dois nomes equivalentes têm a mesma chave.
///
/// Codificação sem ambiguidade (prefixos de comprimento em todos os
/// campos), para poder servir de chave de mapa.
pub fn chave_canonica(nome: &Name) -> Vec<u8> {
    let mut out = Vec::new();
    for rdn in nome.0.iter() {
        let chave = chave_rdn(rdn);
        out.extend_from_slice(&(chave.len() as u32).to_be_bytes());
        out.extend_from_slice(&chave);
    }
    out
}

/// `true` se os dois nomes são o mesmo nome segundo a RFC 5280 §7.1.
pub fn nomes_equivalentes(a: &Name, b: &Name) -> bool {
    a.0.len() == b.0.len() && a.0.iter().zip(b.0.iter()).all(|(x, y)| rdns_equivalentes(x, y))
}

/// `true` se os dois RDNs têm o mesmo conjunto de (tipo, valor).
pub fn rdns_equivalentes(a: &RelativeDistinguishedName, b: &RelativeDistinguishedName) -> bool {
    chave_rdn(a) == chave_rdn(b)
}

fn chave_rdn(rdn: &RelativeDistinguishedName) -> Vec<u8> {
    // Um RDN é um SET: a ordem dos seus atributos não conta.
    let mut atributos: Vec<Vec<u8>> = rdn
        .0
        .iter()
        .map(|atv| {
            let oid = atv.oid.as_bytes();
            let valor = valor_canonico(atv.value.tag().octet(), atv.value.value());
            let mut a = Vec::with_capacity(8 + oid.len() + valor.len());
            a.extend_from_slice(&(oid.len() as u32).to_be_bytes());
            a.extend_from_slice(oid);
            a.extend_from_slice(&(valor.len() as u32).to_be_bytes());
            a.extend_from_slice(&valor);
            a
        })
        .collect();
    atributos.sort();
    let mut out = Vec::new();
    for a in atributos {
        out.extend_from_slice(&a);
    }
    out
}

/// `S` + texto preparado para strings de diretório; `D` + tag + bytes para o
/// resto (comparação exacta).
fn valor_canonico(tag: u8, bytes: &[u8]) -> Vec<u8> {
    match texto_de_diretorio(tag, bytes) {
        Some(texto) => {
            let mut out = vec![b'S'];
            out.extend_from_slice(preparar(&texto).as_bytes());
            out
        }
        None => {
            let mut out = vec![b'D', tag];
            out.extend_from_slice(bytes);
            out
        }
    }
}

/// Descodifica os tipos de string de diretório. `None` = não é string (ou
/// está mal codificada) → compara-se por bytes.
fn texto_de_diretorio(tag: u8, bytes: &[u8]) -> Option<String> {
    match tag {
        // UTF8String, PrintableString, IA5String, VisibleString
        0x0C | 0x13 | 0x16 | 0x1A => std::str::from_utf8(bytes).ok().map(str::to_owned),
        // TeletexString: na prática é Latin-1 nas ACs que ainda o usam.
        0x14 => Some(bytes.iter().map(|&b| b as char).collect()),
        // BMPString: UCS-2 big-endian.
        0x1E => {
            if bytes.len() % 2 != 0 {
                return None;
            }
            let unidades: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&unidades).ok()
        }
        // UniversalString: UCS-4 big-endian.
        0x1C => {
            if bytes.len() % 4 != 0 {
                return None;
            }
            bytes
                .chunks_exact(4)
                .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
                .collect()
        }
        _ => None,
    }
}

/// Espaços nas pontas fora, sequências de espaços reduzidas a um, sem
/// distinção de maiúsculas (RFC 4518 §2.6 "insignificant space handling" e
/// o caseIgnoreMatch da RFC 5280 §7.1).
fn preparar(texto: &str) -> String {
    let mut out = String::with_capacity(texto.len());
    for palavra in texto.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.extend(palavra.chars().flat_map(char::to_lowercase));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{PrintableStringRef, Utf8StringRef};
    use der::{Any, Decode, Encode};
    use std::str::FromStr;

    fn nome(texto: &str) -> Name {
        Name::from_str(texto).unwrap()
    }

    /// Reescreve o valor do atributo `indice` do RDN `rdn` com outro tipo de
    /// string — a variação que uma AC conforme pode fazer entre certificado e
    /// CRL.
    fn trocar_tipo(n: &Name, rdn: usize, para_utf8: bool) -> Name {
        let der = n.to_der().unwrap();
        let mut copia = Name::from_der(&der).unwrap();
        let rdns = &mut copia.0;
        let original = rdns[rdn].0.iter().next().unwrap().clone();
        let texto = std::str::from_utf8(original.value.value()).unwrap().to_owned();
        let valor = if para_utf8 {
            Any::encode_from(&Utf8StringRef::new(&texto).unwrap()).unwrap()
        } else {
            Any::encode_from(&PrintableStringRef::new(&texto).unwrap()).unwrap()
        };
        let novo = x509_cert::attr::AttributeTypeAndValue {
            oid: original.oid,
            value: valor,
        };
        rdns[rdn] = RelativeDistinguishedName(der::asn1::SetOfVec::try_from(vec![novo]).unwrap());
        copia
    }

    #[test]
    fn printable_e_utf8_com_o_mesmo_texto_sao_o_mesmo_nome() {
        let a = nome("CN=AC Raiz,O=ICP-Brasil,C=BR");
        let b = trocar_tipo(&a, 1, true);
        let c = trocar_tipo(&a, 1, false);
        assert_ne!(b.to_der().unwrap(), c.to_der().unwrap(), "montagem: DER diferentes");
        assert!(nomes_equivalentes(&b, &c));
        assert_eq!(chave_canonica(&b), chave_canonica(&c));
    }

    #[test]
    fn maiusculas_e_espacos_insignificantes_nao_distinguem() {
        let a = nome("CN=AC  Raiz ,O=ICP-Brasil,C=BR");
        let b = nome("CN=ac raiz,O=icp-brasil,C=br");
        assert!(nomes_equivalentes(&a, &b));
    }

    #[test]
    fn nomes_diferentes_continuam_diferentes() {
        assert!(!nomes_equivalentes(
            &nome("CN=AC Raiz,O=ICP-Brasil,C=BR"),
            &nome("CN=AC Raiz v2,O=ICP-Brasil,C=BR")
        ));
        // Mesmo texto, atributo diferente.
        assert!(!nomes_equivalentes(&nome("CN=BR"), &nome("C=BR")));
        // Prefixo não é igualdade.
        assert!(!nomes_equivalentes(
            &nome("O=ICP-Brasil,C=BR"),
            &nome("CN=AC,O=ICP-Brasil,C=BR")
        ));
    }
}
