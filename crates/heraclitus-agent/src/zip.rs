//! ZIP mínimo (método STORE) — o contentor do Evidence Bundle.
//!
//! # Porque escrever isto em vez de puxar uma dependência
//!
//! O bundle tem de ser aberto por um perito, num computador que não é o nosso,
//! anos depois. O formato tem de ser o mais banal possível: `unzip`,
//! Explorador do Windows, `zipfile` do Python. O método **STORE** (sem
//! compressão) é o único que qualquer leitor de ZIP suporta desde 1989, e
//! escrevê-lo são duzentas linhas de estruturas fixas.
//!
//! A alternativa — uma dependência de compressão — traria ganho de espaço
//! (os ficheiros do bundle são NDJSON, comprimem bem) ao custo de mais uma
//! entrada no SBOM e de mais uma superfície de parsing num artefacto que
//! recebe input de terceiros no verificador. Para um pacote pericial, a
//! transparência ganha ao tamanho.
//!
//! Os digests que provam o conteúdo estão no `manifest.json` e no `SHA256SUMS`
//! e são calculados sobre os bytes **descomprimidos**, portanto nada aqui
//! participa da prova: este módulo é embalagem.
//!
//! Limitações assumidas e documentadas: sem ZIP64 (o tecto é 4 GiB por ficheiro
//! e por arquivo — um bundle maior do que isso é um erro de selecção, não um
//! caso de uso), sem cifra, sem directórios explícitos.

use std::collections::BTreeMap;
use std::io::{self, Write};

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
/// Versão mínima para extrair: 2.0 (STORE + nomes em UTF-8 com o bit 11).
const VERSION_NEEDED: u16 = 20;
/// Bit 11 do flag geral: o nome do ficheiro está em UTF-8.
const FLAG_UTF8: u16 = 1 << 11;

#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("escrita do zip falhou: {0}")]
    Io(#[from] io::Error),
    #[error("zip inválido: {0}")]
    Invalid(&'static str),
    #[error("zip demasiado grande para o formato sem ZIP64 ({0} bytes)")]
    TooLarge(u64),
    #[error("nome de ficheiro recusado: {0}")]
    BadName(String),
}

struct Entry {
    name: String,
    crc: u32,
    size: u32,
    local_offset: u32,
}

/// Escritor de ZIP STORE.
pub struct ZipWriter<W: Write> {
    out: W,
    offset: u64,
    entries: Vec<Entry>,
}

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            offset: 0,
            entries: Vec::new(),
        }
    }

    /// Acrescenta um ficheiro. O nome é validado: nada de caminhos absolutos,
    /// nada de `..`, nada de barras invertidas.
    ///
    /// A validação está **na escrita** e não só na leitura de propósito. Um
    /// bundle é um artefacto que sai da nossa mão e entra na de um perito; se
    /// conseguíssemos produzir um ZIP com `../../etc/passwd` lá dentro, a culpa
    /// do zip-slip seria nossa mesmo que o extractor dele fosse ingénuo.
    pub fn add(&mut self, name: &str, data: &[u8]) -> Result<(), ZipError> {
        validate_name(name)?;
        if data.len() > u32::MAX as usize {
            return Err(ZipError::TooLarge(data.len() as u64));
        }
        let crc = crc32fast::hash(data);
        let size = data.len() as u32;
        let local_offset =
            u32::try_from(self.offset).map_err(|_| ZipError::TooLarge(self.offset))?;
        let name_bytes = name.as_bytes();

        let mut head = Vec::with_capacity(30 + name_bytes.len());
        head.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        head.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        head.extend_from_slice(&FLAG_UTF8.to_le_bytes());
        head.extend_from_slice(&0u16.to_le_bytes()); // método 0 = STORE
        head.extend_from_slice(&0u16.to_le_bytes()); // hora MS-DOS
        head.extend_from_slice(&0u16.to_le_bytes()); // data MS-DOS
        head.extend_from_slice(&crc.to_le_bytes());
        head.extend_from_slice(&size.to_le_bytes()); // comprimido
        head.extend_from_slice(&size.to_le_bytes()); // descomprimido
        head.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        head.extend_from_slice(&0u16.to_le_bytes()); // extra
        head.extend_from_slice(name_bytes);
        self.out.write_all(&head)?;
        self.out.write_all(data)?;
        self.offset += head.len() as u64 + data.len() as u64;

        self.entries.push(Entry {
            name: name.to_string(),
            crc,
            size,
            local_offset,
        });
        Ok(())
    }

    /// Fecha o arquivo (directório central + EOCD) e devolve o escritor.
    pub fn finish(mut self) -> Result<W, ZipError> {
        let central_start = self.offset;
        let mut central = Vec::new();
        for e in &self.entries {
            let name = e.name.as_bytes();
            central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            central.extend_from_slice(&VERSION_NEEDED.to_le_bytes()); // version made by
            central.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
            central.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&e.crc.to_le_bytes());
            central.extend_from_slice(&e.size.to_le_bytes());
            central.extend_from_slice(&e.size.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comentário
            central.extend_from_slice(&0u16.to_le_bytes()); // disco
            central.extend_from_slice(&0u16.to_le_bytes()); // atributos internos
            central.extend_from_slice(&0u32.to_le_bytes()); // atributos externos
            central.extend_from_slice(&e.local_offset.to_le_bytes());
            central.extend_from_slice(name);
        }
        self.out.write_all(&central)?;

        let count = u16::try_from(self.entries.len())
            .map_err(|_| ZipError::TooLarge(self.entries.len() as u64))?;
        let central_size =
            u32::try_from(central.len()).map_err(|_| ZipError::TooLarge(central.len() as u64))?;
        let central_off =
            u32::try_from(central_start).map_err(|_| ZipError::TooLarge(central_start))?;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&central_size.to_le_bytes());
        eocd.extend_from_slice(&central_off.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        self.out.write_all(&eocd)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

fn validate_name(name: &str) -> Result<(), ZipError> {
    let bad = name.is_empty()
        || name.len() > 512
        || name.starts_with('/')
        || name.contains('\\')
        || name.split('/').any(|seg| seg == ".." || seg == ".")
        || name.chars().any(|c| c.is_control())
        // Windows: `C:\...` chega aqui como `C:/...` depois da normalização.
        || (name.len() > 1 && name.as_bytes()[1] == b':');
    if bad {
        return Err(ZipError::BadName(name.to_string()));
    }
    Ok(())
}

/// Lê um ZIP STORE inteiro para memória.
///
/// Percorre os cabeçalhos locais em vez do directório central de propósito: o
/// verificador quer saber o que está **realmente** no ficheiro, e um arquivo
/// adulterado pode ter um directório central que descreve outra coisa.
pub fn read_all(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ZipError> {
    let mut out = BTreeMap::new();
    let mut pos = 0usize;
    while pos + 30 <= bytes.len() {
        let sig = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        if sig != LOCAL_SIG {
            break;
        }
        let method = u16::from_le_bytes(bytes[pos + 8..pos + 10].try_into().unwrap());
        let crc = u32::from_le_bytes(bytes[pos + 14..pos + 18].try_into().unwrap());
        let comp_size = u32::from_le_bytes(bytes[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(bytes[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
        if method != 0 {
            return Err(ZipError::Invalid(
                "o Evidence Bundle usa método STORE; este arquivo está comprimido",
            ));
        }
        let name_start = pos + 30;
        let data_start = name_start
            .checked_add(name_len)
            .and_then(|x| x.checked_add(extra_len))
            .ok_or(ZipError::Invalid(
                "cabeçalho local aritmeticamente inválido",
            ))?;
        let data_end = data_start
            .checked_add(comp_size)
            .ok_or(ZipError::Invalid("tamanho de entrada inválido"))?;
        if data_end > bytes.len() || name_start + name_len > bytes.len() {
            return Err(ZipError::Invalid("entrada truncada"));
        }
        let name = std::str::from_utf8(&bytes[name_start..name_start + name_len])
            .map_err(|_| ZipError::Invalid("nome de ficheiro não é UTF-8"))?
            .to_string();
        validate_name(&name)?;
        let data = bytes[data_start..data_end].to_vec();
        if crc32fast::hash(&data) != crc {
            return Err(ZipError::Invalid("CRC do ZIP não bate"));
        }
        out.insert(name, data);
        pos = data_end;
    }
    if out.is_empty() {
        return Err(ZipError::Invalid("nenhuma entrada legível no arquivo"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Vec::new());
        for (n, d) in entries {
            w.add(n, d).unwrap();
        }
        w.finish().unwrap()
    }

    #[test]
    fn ida_e_volta() {
        let bytes = make(&[
            ("manifest.json", b"{}"),
            ("timeline.ndjson", b"{\"a\":1}\n"),
            ("proofs/E1.json", b"[]"),
        ]);
        let back = read_all(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back["manifest.json"], b"{}");
        assert_eq!(back["proofs/E1.json"], b"[]");
    }

    #[test]
    fn ficheiro_vazio_e_aceite() {
        let bytes = make(&[("README.txt", b"")]);
        assert_eq!(read_all(&bytes).unwrap()["README.txt"], Vec::<u8>::new());
    }

    #[test]
    fn um_byte_alterado_falha_o_crc() {
        let mut bytes = make(&[("a.json", b"conteudo original")]);
        let idx = bytes
            .windows(17)
            .position(|w| w == b"conteudo original")
            .unwrap();
        bytes[idx] = b'C';
        assert!(read_all(&bytes).is_err());
    }

    #[test]
    fn zip_slip_e_recusado_na_escrita() {
        let mut w = ZipWriter::new(Vec::new());
        assert!(w.add("../etc/passwd", b"x").is_err());
        assert!(w.add("/absoluto", b"x").is_err());
        assert!(w.add("C:/janela", b"x").is_err());
        assert!(w.add("com\\barra", b"x").is_err());
    }

    #[test]
    fn arquivo_truncado_e_erro_e_nao_panico() {
        let bytes = make(&[("a.json", b"12345678")]);
        for cut in [5usize, 20, 31, 40] {
            if cut < bytes.len() {
                let _ = read_all(&bytes[..cut]);
            }
        }
    }

    #[test]
    fn lixo_nao_e_zip() {
        assert!(read_all(b"nao sou um zip").is_err());
        assert!(read_all(&[]).is_err());
    }

    #[test]
    fn unzip_externo_reconhece_a_estrutura() {
        // Não invocamos `unzip` no teste, mas garantimos as invariantes que ele
        // exige: assinatura EOCD no fim e contagem coerente.
        let bytes = make(&[("a", b"1"), ("b", b"2")]);
        let eocd = &bytes[bytes.len() - 22..];
        assert_eq!(u32::from_le_bytes(eocd[0..4].try_into().unwrap()), EOCD_SIG);
        assert_eq!(u16::from_le_bytes(eocd[8..10].try_into().unwrap()), 2);
    }
}
