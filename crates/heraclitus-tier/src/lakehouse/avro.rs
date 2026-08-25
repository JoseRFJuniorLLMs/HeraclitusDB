//! Escritor (e leitor de verificação) de Avro **Object Container Files**.
//!
//! ## Porque é que isto existe em vez de uma dependência
//!
//! O exportador Iceberg de §209 precisa de escrever manifestos, e o Iceberg
//! define-os em Avro. Não há nenhum crate de Avro na árvore, e acrescentar
//! `apache-avro` traria um runtime de esquema dinâmico inteiro para escrever
//! **dois** records de forma fixa.
//!
//! O que este módulo cobre é deliberadamente estreito: o container OCF e a
//! codificação binária dos tipos que os manifestos Iceberg usam. Não é um
//! Avro genérico e não pretende ser — não há resolução de esquema, não há
//! `fixed`, não há `enum`, não há compressão. Cada uma dessas omissões é uma
//! coisa que não pode partir em silêncio.
//!
//! ## O formato, e onde ele engana
//!
//! ```text
//! "Obj" 0x01
//! map<string,bytes>   metadata  (avro.schema, avro.codec)
//! 16 bytes            sync marker
//! bloco*              [ count:long | size:long | dados | sync ]
//! ```
//!
//! As duas armadilhas reais:
//!
//! 1. **`long` é zigzag varint**, não little-endian. Um `-1` mal codificado
//!    passa a ser um inteiro enorme e o leitor tenta alocar gigabytes.
//! 2. **O `size` do bloco conta os bytes dos dados**, não o número de objectos
//!    nem o total com o sync. Errá-lo desalinha tudo o que vem depois, e o
//!    ficheiro só falha no fim — longe da causa.
//!
//! Por isso este módulo traz um **leitor** ([`read_ocf`]) que só existe para
//! os testes: tudo o que se escreve é relido e comparado. Um escritor sem
//! leitor é uma afirmação; com leitor é uma verificação.
//!
//! ## Honestidade sobre o alcance
//!
//! Isto está verificado contra si próprio (round-trip) e contra vectores
//! dourados da codificação primitiva. **Não** foi validado por um leitor Avro
//! de terceiros, porque não há nenhum nesta árvore nem rede para o obter. Ver
//! a mesma nota em [`super::iceberg`].

use heraclitus_core::HeraclitusError;

pub const OCF_MAGIC: [u8; 4] = [b'O', b'b', b'j', 1];
pub const SYNC_LEN: usize = 16;

fn erro(detalhe: impl Into<String>) -> HeraclitusError {
    HeraclitusError::Serialization(format!("avro: {}", detalhe.into()))
}

// ---------------------------------------------------------------------------
// Codificação primitiva
// ---------------------------------------------------------------------------

/// `long`/`int` Avro: zigzag + varint de 7 bits, little-endian nos grupos.
pub fn write_long(out: &mut Vec<u8>, v: i64) {
    // Zigzag: mapeia inteiros com sinal para não-negativos preservando a
    // magnitude pequena. `-1 -> 1`, `1 -> 2`, `-2 -> 3`.
    let mut n = ((v << 1) ^ (v >> 63)) as u64;
    loop {
        if n & !0x7F == 0 {
            out.push(n as u8);
            return;
        }
        out.push(((n & 0x7F) | 0x80) as u8);
        n >>= 7;
    }
}

pub fn write_int(out: &mut Vec<u8>, v: i32) {
    write_long(out, v as i64);
}

/// `bytes`: comprimento como `long`, depois os bytes crus.
pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_long(out, b.len() as i64);
    out.extend_from_slice(b);
}

/// `string`: idêntico a `bytes`, com UTF-8.
pub fn write_string(out: &mut Vec<u8>, s: &str) {
    write_bytes(out, s.as_bytes());
}

pub fn write_boolean(out: &mut Vec<u8>, v: bool) {
    out.push(if v { 1 } else { 0 });
}

/// Um `union` Avro é codificado como o **índice do ramo** seguido do valor.
/// Para `["null", T]` — a forma que o Iceberg usa em todos os campos
/// opcionais — `null` é o índice 0 e o valor presente é o índice 1.
pub fn write_union_null(out: &mut Vec<u8>) {
    write_long(out, 0);
}

pub fn write_union_some(out: &mut Vec<u8>) {
    write_long(out, 1);
}

/// Lê um `long` zigzag. Devolve `(valor, bytes consumidos)`.
pub fn read_long(buf: &[u8]) -> Result<(i64, usize), HeraclitusError> {
    let mut n: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        // 10 grupos de 7 bits chegam para 64 bits; mais do que isso é input
        // malformado a tentar arrastar o leitor.
        if i >= 10 {
            return Err(erro("varint com mais de 10 bytes"));
        }
        n |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            let v = ((n >> 1) as i64) ^ -((n & 1) as i64);
            return Ok((v, i + 1));
        }
        shift += 7;
    }
    Err(erro("varint truncado"))
}

pub fn read_bytes(buf: &[u8]) -> Result<(&[u8], usize), HeraclitusError> {
    let (len, n) = read_long(buf)?;
    let len = usize::try_from(len).map_err(|_| erro("comprimento negativo"))?;
    let fim = n.checked_add(len).ok_or_else(|| erro("comprimento transborda"))?;
    let s = buf.get(n..fim).ok_or_else(|| erro("bytes truncados"))?;
    Ok((s, fim))
}

pub fn read_string(buf: &[u8]) -> Result<(String, usize), HeraclitusError> {
    let (b, n) = read_bytes(buf)?;
    Ok((
        String::from_utf8(b.to_vec()).map_err(|e| erro(e.to_string()))?,
        n,
    ))
}

// ---------------------------------------------------------------------------
// Container
// ---------------------------------------------------------------------------

/// Escreve um OCF com um único bloco.
///
/// `datums` são os objectos **já serializados**, um por elemento — este módulo
/// não conhece os esquemas do Iceberg, e não deve conhecer.
///
/// `sync` é fornecido pelo chamador em vez de gerado aleatoriamente: um
/// exportador determinístico (§209, idempotência) não pode ter 16 bytes de
/// aleatoriedade nos seus ficheiros. O Avro não exige que o marcador seja
/// aleatório, só que seja o mesmo dentro do ficheiro.
pub fn write_ocf(
    schema_json: &str,
    metadata_extra: &[(&str, &[u8])],
    datums: &[Vec<u8>],
    sync: [u8; SYNC_LEN],
) -> Result<Vec<u8>, HeraclitusError> {
    let mut out = Vec::new();
    out.extend_from_slice(&OCF_MAGIC);

    // metadata: map<string,bytes>. Um bloco com N pares, terminado por 0.
    let mut pares: Vec<(&str, &[u8])> = Vec::with_capacity(metadata_extra.len() + 2);
    pares.push(("avro.schema", schema_json.as_bytes()));
    pares.push(("avro.codec", b"null"));
    pares.extend_from_slice(metadata_extra);
    // Ordenar torna o ficheiro determinístico mesmo que o chamador varie a
    // ordem dos extras.
    pares.sort_by_key(|(k, _)| *k);

    write_long(&mut out, pares.len() as i64);
    for (k, v) in &pares {
        write_string(&mut out, k);
        write_bytes(&mut out, v);
    }
    write_long(&mut out, 0); // fim do map

    out.extend_from_slice(&sync);

    if !datums.is_empty() {
        let mut dados = Vec::new();
        for d in datums {
            dados.extend_from_slice(d);
        }
        write_long(&mut out, datums.len() as i64);
        // O `size` do bloco são os bytes dos DADOS. Ver a nota do topo.
        write_long(&mut out, dados.len() as i64);
        out.extend_from_slice(&dados);
        out.extend_from_slice(&sync);
    }
    Ok(out)
}

/// O que um OCF contém, do ponto de vista de quem o verifica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ocf {
    pub schema_json: String,
    pub metadata: Vec<(String, Vec<u8>)>,
    pub sync: [u8; SYNC_LEN],
    /// Bytes crus de cada bloco de dados, e quantos objectos ele declara.
    pub blocos: Vec<(u64, Vec<u8>)>,
}

impl Ocf {
    pub fn total_datums(&self) -> u64 {
        self.blocos.iter().map(|(n, _)| *n).sum()
    }

    pub fn metadata_get(&self, chave: &str) -> Option<&[u8]> {
        self.metadata
            .iter()
            .find(|(k, _)| k == chave)
            .map(|(_, v)| v.as_slice())
    }
}

/// Relê um OCF. Existe para os testes provarem o que o escritor produziu — e
/// para um `doctor` conseguir inspeccionar um manifesto sem um engine.
pub fn read_ocf(buf: &[u8]) -> Result<Ocf, HeraclitusError> {
    if buf.len() < 4 || buf[..4] != OCF_MAGIC {
        return Err(erro("magic OCF inválido"));
    }
    let mut i = 4;

    let mut metadata: Vec<(String, Vec<u8>)> = Vec::new();
    loop {
        let (n, used) = read_long(&buf[i..])?;
        i += used;
        if n == 0 {
            break;
        }
        // Um count negativo significa "count seguido do tamanho em bytes do
        // bloco". Não o escrevemos, mas um ficheiro de terceiros pode trazê-lo.
        let (n, _skip_size) = if n < 0 {
            let (size, used2) = read_long(&buf[i..])?;
            i += used2;
            (-n, Some(size))
        } else {
            (n, None)
        };
        for _ in 0..n {
            let (k, u1) = read_string(&buf[i..])?;
            i += u1;
            let (v, u2) = read_bytes(&buf[i..])?;
            i += u2;
            metadata.push((k, v.to_vec()));
        }
    }

    let sync: [u8; SYNC_LEN] = buf
        .get(i..i + SYNC_LEN)
        .ok_or_else(|| erro("sync marker truncado"))?
        .try_into()
        .map_err(|_| erro("sync marker inválido"))?;
    i += SYNC_LEN;

    let mut blocos = Vec::new();
    while i < buf.len() {
        let (count, u1) = read_long(&buf[i..])?;
        i += u1;
        let (size, u2) = read_long(&buf[i..])?;
        i += u2;
        let size = usize::try_from(size).map_err(|_| erro("tamanho de bloco negativo"))?;
        let dados = buf
            .get(i..i + size)
            .ok_or_else(|| erro("bloco truncado"))?
            .to_vec();
        i += size;
        let marca = buf
            .get(i..i + SYNC_LEN)
            .ok_or_else(|| erro("sync do bloco truncado"))?;
        if marca != sync {
            return Err(erro("sync marker do bloco não bate com o do header"));
        }
        i += SYNC_LEN;
        blocos.push((count as u64, dados));
    }

    let schema_json = metadata
        .iter()
        .find(|(k, _)| k == "avro.schema")
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        .ok_or_else(|| erro("`avro.schema` ausente na metadata"))?;

    Ok(Ocf {
        schema_json,
        metadata,
        sync,
        blocos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(v: i64) {
        let mut b = Vec::new();
        write_long(&mut b, v);
        let (lido, n) = read_long(&b).unwrap();
        assert_eq!(lido, v, "round-trip de {v}");
        assert_eq!(n, b.len());
    }

    #[test]
    fn zigzag_varint_bate_com_os_vectores_da_spec() {
        // Vectores da especificação Avro. Se estes mudarem, o formato mudou —
        // e nenhum leitor de terceiros conseguiria ler o que escrevemos.
        let casos: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (-1, &[0x01]),
            (1, &[0x02]),
            (-2, &[0x03]),
            (2, &[0x04]),
            (-64, &[0x7f]),
            (64, &[0x80, 0x01]),
            (8192, &[0x80, 0x80, 0x01]),
            (-8193, &[0x81, 0x80, 0x01]),
        ];
        for (v, esperado) in casos {
            let mut b = Vec::new();
            write_long(&mut b, *v);
            assert_eq!(&b, esperado, "codificação de {v}");
        }
    }

    #[test]
    fn varint_faz_round_trip_nos_extremos() {
        for v in [0, 1, -1, 63, 64, -64, -65, i32::MAX as i64, i64::MAX, i64::MIN] {
            rt(v);
        }
    }

    #[test]
    fn varint_malformado_e_erro_e_nao_panico_nem_alocacao() {
        // 11 bytes com o bit de continuação sempre ligado.
        assert!(read_long(&[0xFF; 11]).is_err());
        // Truncado no meio.
        assert!(read_long(&[0x80, 0x80]).is_err());
        assert!(read_long(&[]).is_err());
        // Comprimento absurdo num `bytes`: tem de falhar por falta de bytes,
        // nunca por tentar alocar.
        let mut b = Vec::new();
        write_long(&mut b, i64::MAX);
        assert!(read_bytes(&b).is_err());
    }

    #[test]
    fn strings_e_bytes_fazem_round_trip() {
        for s in ["", "a", "acentuação é UTF-8", &"x".repeat(1000)] {
            let mut b = Vec::new();
            write_string(&mut b, s);
            let (lido, n) = read_string(&b).unwrap();
            assert_eq!(lido, s);
            assert_eq!(n, b.len());
        }
    }

    #[test]
    fn container_faz_round_trip_com_metadata_e_blocos() {
        let schema = r#"{"type":"record","name":"t","fields":[{"name":"x","type":"long"}]}"#;
        let mut d1 = Vec::new();
        write_long(&mut d1, 42);
        let mut d2 = Vec::new();
        write_long(&mut d2, -7);

        let bytes = write_ocf(
            schema,
            &[("iceberg.schema", b"{}"), ("format-version", b"2")],
            &[d1.clone(), d2.clone()],
            [9u8; SYNC_LEN],
        )
        .unwrap();

        let ocf = read_ocf(&bytes).unwrap();
        assert_eq!(ocf.schema_json, schema);
        assert_eq!(ocf.sync, [9u8; SYNC_LEN]);
        assert_eq!(ocf.total_datums(), 2);
        assert_eq!(ocf.metadata_get("avro.codec"), Some(&b"null"[..]));
        assert_eq!(ocf.metadata_get("format-version"), Some(&b"2"[..]));
        assert_eq!(ocf.metadata_get("nao-existe"), None);

        let mut esperado = d1.clone();
        esperado.extend_from_slice(&d2);
        assert_eq!(ocf.blocos[0].1, esperado);
    }

    #[test]
    fn container_sem_datums_continua_valido() {
        let schema = r#"{"type":"record","name":"t","fields":[]}"#;
        let bytes = write_ocf(schema, &[], &[], [0u8; SYNC_LEN]).unwrap();
        let ocf = read_ocf(&bytes).unwrap();
        assert_eq!(ocf.total_datums(), 0);
        assert!(ocf.blocos.is_empty());
    }

    #[test]
    fn o_escritor_e_deterministico() {
        // §209: sem isto, dois exports do mesmo segmento dariam manifestos
        // diferentes e a idempotência seria inverificável por digest.
        let schema = r#"{"type":"record","name":"t","fields":[]}"#;
        let a = write_ocf(schema, &[("b", b"2"), ("a", b"1")], &[], [3u8; 16]).unwrap();
        let b = write_ocf(schema, &[("a", b"1"), ("b", b"2")], &[], [3u8; 16]).unwrap();
        assert_eq!(a, b, "a ordem dos extras mudou os bytes");
    }

    #[test]
    fn sync_marker_trocado_e_detectado() {
        let schema = r#"{"type":"record","name":"t","fields":[]}"#;
        let mut d = Vec::new();
        write_long(&mut d, 1);
        let mut bytes = write_ocf(schema, &[], &[d], [5u8; 16]).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        let e = read_ocf(&bytes).unwrap_err();
        assert!(e.to_string().contains("sync"), "erro inesperado: {e}");
    }

    #[test]
    fn magic_errado_e_recusado() {
        assert!(read_ocf(b"nao e avro").is_err());
        assert!(read_ocf(&[]).is_err());
        let mut b = write_ocf(r#"{"type":"null"}"#, &[], &[], [0; 16]).unwrap();
        b[3] = 0x02; // versão de container desconhecida
        assert!(read_ocf(&b).is_err());
    }

    #[test]
    fn union_usa_o_indice_do_ramo() {
        // ["null", T]: null = 0, presente = 1. Trocar isto faz um leitor
        // interpretar o valor como null e perder o campo em silêncio — a
        // classe de bug mais cara neste formato.
        let mut b = Vec::new();
        write_union_null(&mut b);
        assert_eq!(b, vec![0x00]);
        let mut b = Vec::new();
        write_union_some(&mut b);
        write_long(&mut b, 7);
        assert_eq!(b, vec![0x02, 0x0e]);
    }

    #[test]
    fn boolean_e_um_byte() {
        let mut b = Vec::new();
        write_boolean(&mut b, true);
        write_boolean(&mut b, false);
        assert_eq!(b, vec![1, 0]);
    }
}
