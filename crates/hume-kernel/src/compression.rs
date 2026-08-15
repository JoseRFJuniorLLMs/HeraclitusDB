//! Codecs de compressão densa para colunas de inteiros (SPEC-0039 §5,
//! SPEC-0041 §4 `compression/`).
//!
//! Cada codec é um par `encode`/`decode` com roundtrip exato (testado). São
//! primitivas de referência — não estão ligadas ao caminho de storage vivo.
//!
//! - [`rle`] — Run-Length Encoding (colunas de baixa cardinalidade / com runs).
//! - [`delta`] — diferenças sucessivas (sequências monótonas: timestamps, ids).
//! - [`frame_of_reference`] — mínimo + offsets (inteiros num intervalo estreito).
//! - [`bitpack`] — empacotamento em largura mínima de bits (combina com FOR).

/// Run-Length Encoding: `[7,7,7,3,3] → [(7,3),(3,2)]`.
pub mod rle {
    /// Codifica em pares `(valor, contagem)`.
    pub fn encode(data: &[u64]) -> Vec<(u64, u32)> {
        let mut out: Vec<(u64, u32)> = Vec::new();
        for &v in data {
            match out.last_mut() {
                Some((val, count)) if *val == v => *count += 1,
                _ => out.push((v, 1)),
            }
        }
        out
    }

    /// Reconstrói a sequência original.
    pub fn decode(runs: &[(u64, u32)]) -> Vec<u64> {
        let mut out = Vec::with_capacity(runs.iter().map(|(_, c)| *c as usize).sum());
        for &(v, c) in runs {
            out.extend(std::iter::repeat_n(v, c as usize));
        }
        out
    }
}

/// Delta encoding: guarda o 1.º valor absoluto e depois as diferenças (i64,
/// para permitir sequências decrescentes).
pub mod delta {
    /// `[100,102,105] → [100, 2, 3]`.
    ///
    /// A aritmética é **envolvente** (`wrapping`) de propósito. Com `u64`
    /// grandes — hashes, ids aleatórios, `u64::MAX` — o `v as i64` fica negativo
    /// e a subtração transbordava: pânico em debug e, pior, um resultado
    /// silenciosamente errado em release. Envolver é total e continua a ser
    /// exatamente invertível pelo [`decode`], que envolve na direção oposta, por
    /// isso o roundtrip mantém-se exato para QUALQUER entrada.
    pub fn encode(data: &[u64]) -> Vec<i64> {
        let mut out = Vec::with_capacity(data.len());
        let mut prev: i64 = 0;
        for (i, &v) in data.iter().enumerate() {
            let v = v as i64;
            out.push(if i == 0 { v } else { v.wrapping_sub(prev) });
            prev = v;
        }
        out
    }

    /// Reconstrói a sequência original.
    pub fn decode(deltas: &[i64]) -> Vec<u64> {
        let mut out = Vec::with_capacity(deltas.len());
        let mut acc: i64 = 0;
        for (i, &d) in deltas.iter().enumerate() {
            acc = if i == 0 { d } else { acc.wrapping_add(d) };
            out.push(acc as u64);
        }
        out
    }
}

/// Frame of Reference: subtrai o mínimo, deixando offsets pequenos (que o
/// [`super::compression::bitpack`] depois empacota bem).
pub mod frame_of_reference {
    /// Devolve `(min, offsets)`.
    pub fn encode(data: &[u64]) -> (u64, Vec<u64>) {
        let min = data.iter().copied().min().unwrap_or(0);
        let offsets = data.iter().map(|&v| v - min).collect();
        (min, offsets)
    }

    /// Reconstrói a sequência original.
    pub fn decode(min: u64, offsets: &[u64]) -> Vec<u64> {
        offsets.iter().map(|&o| min + o).collect()
    }
}

/// Bit-packing: empacota inteiros usando exatamente `bits` bits cada, num fluxo
/// contíguo de palavras de 64 bits.
pub mod bitpack {
    /// Bits mínimos para representar todos os valores (`max_value`).
    pub fn min_bits(max_value: u64) -> u32 {
        if max_value == 0 {
            1
        } else {
            64 - max_value.leading_zeros()
        }
    }

    /// Empacota `values` com `bits` bits cada (`1..=64`).
    ///
    /// # Panics
    /// Se `bits` estiver fora de `1..=64`, ou se algum valor não couber em
    /// `bits` bits.
    pub fn pack(values: &[u64], bits: u32) -> Vec<u64> {
        assert!((1..=64).contains(&bits), "bits fora de 1..=64");
        if bits == 64 {
            return values.to_vec();
        }
        let mask = (1u64 << bits) - 1;
        let total_bits = values.len() * bits as usize;
        let mut out = vec![0u64; total_bits.div_ceil(64)];
        let mut bit_pos = 0usize;
        for &v in values {
            assert!(v <= mask, "valor {v} não cabe em {bits} bits");
            let word = bit_pos / 64;
            let off = bit_pos % 64;
            out[word] |= v << off;
            if off + bits as usize > 64 {
                out[word + 1] |= v >> (64 - off);
            }
            bit_pos += bits as usize;
        }
        out
    }

    /// Desempacota `count` valores de `bits` bits cada.
    pub fn unpack(packed: &[u64], bits: u32, count: usize) -> Vec<u64> {
        assert!((1..=64).contains(&bits), "bits fora de 1..=64");
        if bits == 64 {
            return packed[..count].to_vec();
        }
        let mask = (1u64 << bits) - 1;
        let mut out = Vec::with_capacity(count);
        let mut bit_pos = 0usize;
        for _ in 0..count {
            let word = bit_pos / 64;
            let off = bit_pos % 64;
            let mut v = packed[word] >> off;
            if off + bits as usize > 64 {
                v |= packed[word + 1] << (64 - off);
            }
            out.push(v & mask);
            bit_pos += bits as usize;
        }
        out
    }
}

/// `column` — a peça que faltava entre os codecs e o storage.
///
/// Os codecs acima são primitivas: quem chama tem de saber qual usar, com que
/// largura de bits, e guardar isso algures para conseguir ler de volta. Este
/// módulo fecha essa lacuna — **analisa** a coluna, **escolhe** o codec,
/// **serializa** com o cabeçalho que descreve a escolha, e o `decode` reverte
/// sem precisar de contexto nenhum.
///
/// ```text
/// coluna de u64  ->  analisa  ->  escolhe  ->  [tag|meta|payload]  ->  disco
///                                RLE / Δ+bitpack / FOR+bitpack / cru
/// ```
///
/// **Garantia de não-expansão.** Se nenhum codec ganhar, sai `Raw`. O resultado
/// nunca é maior do que a coluna crua mais o cabeçalho — comprimir não pode ser
/// um risco de crescimento, senão ninguém o liga no caminho de escrita.
pub mod column {
    use super::{bitpack, delta, frame_of_reference, rle};

    /// Byte de tag no início do blob. Mudar um valor destes parte ficheiros já
    /// escritos — só acrescentar.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Codec {
        Raw = 0,
        Rle = 1,
        /// Diferenças sucessivas + bitpack. Ganha em sequências monótonas —
        /// LSNs, timestamps, ids — que é o caso dominante num log append-only.
        DeltaBitpack = 2,
        /// Mínimo + offsets + bitpack. Ganha em inteiros num intervalo estreito
        /// mas fora de ordem.
        ForBitpack = 3,
    }

    impl Codec {
        fn from_tag(t: u8) -> Option<Self> {
            Some(match t {
                0 => Codec::Raw,
                1 => Codec::Rle,
                2 => Codec::DeltaBitpack,
                3 => Codec::ForBitpack,
                _ => return None,
            })
        }
    }

    fn put_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn take_u64(b: &[u8], at: &mut usize) -> Option<u64> {
        let s = b.get(*at..*at + 8)?;
        *at += 8;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    }

    fn pack_words(out: &mut Vec<u8>, words: &[u64]) {
        for w in words {
            put_u64(out, *w);
        }
    }

    /// Codifica escolhendo o melhor codec. O blob é autodescritivo.
    pub fn encode(data: &[u64]) -> Vec<u8> {
        let cru = 1 + 8 + data.len() * 8; // tag + contagem + valores
        let mut melhor = encode_raw(data);

        // RLE só faz sentido com repetição; medir é mais barato do que adivinhar.
        let runs = rle::encode(data);
        if runs.len() * 12 + 9 < melhor.len() {
            let mut v = vec![Codec::Rle as u8];
            put_u64(&mut v, runs.len() as u64);
            for (val, count) in &runs {
                put_u64(&mut v, *val);
                v.extend_from_slice(&count.to_le_bytes());
            }
            if v.len() < melhor.len() {
                melhor = v;
            }
        }

        // Delta + bitpack: o caso dos postings ordenados.
        if let Some(v) = encode_delta_bitpack(data) {
            if v.len() < melhor.len() {
                melhor = v;
            }
        }
        // FOR + bitpack: intervalo estreito sem ordem.
        if let Some(v) = encode_for_bitpack(data) {
            if v.len() < melhor.len() {
                melhor = v;
            }
        }

        debug_assert!(melhor.len() <= cru, "codec nunca pode expandir");
        melhor
    }

    fn encode_raw(data: &[u64]) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + data.len() * 8);
        v.push(Codec::Raw as u8);
        put_u64(&mut v, data.len() as u64);
        pack_words(&mut v, data);
        v
    }

    fn encode_delta_bitpack(data: &[u64]) -> Option<Vec<u8>> {
        if data.len() < 2 {
            return None;
        }
        // Só se aplica a sequências não-decrescentes: aí as diferenças são >= 0
        // e cabem num u64 sem sinal. Fora disso, o FOR trata do caso.
        let deltas = delta::encode(data);
        if deltas[1..].iter().any(|d| *d < 0) {
            return None;
        }
        let sem_sinal: Vec<u64> = deltas[1..].iter().map(|d| *d as u64).collect();
        let max = sem_sinal.iter().copied().max().unwrap_or(0);
        let bits = bitpack::min_bits(max);
        let packed = bitpack::pack(&sem_sinal, bits);

        let mut v = Vec::with_capacity(26 + packed.len() * 8);
        v.push(Codec::DeltaBitpack as u8);
        put_u64(&mut v, data.len() as u64);
        put_u64(&mut v, data[0]); // base
        v.push(bits as u8);
        pack_words(&mut v, &packed);
        Some(v)
    }

    fn encode_for_bitpack(data: &[u64]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        let (min, offsets) = frame_of_reference::encode(data);
        let max = offsets.iter().copied().max().unwrap_or(0);
        let bits = bitpack::min_bits(max);
        let packed = bitpack::pack(&offsets, bits);

        let mut v = Vec::with_capacity(26 + packed.len() * 8);
        v.push(Codec::ForBitpack as u8);
        put_u64(&mut v, data.len() as u64);
        put_u64(&mut v, min);
        v.push(bits as u8);
        pack_words(&mut v, &packed);
        Some(v)
    }

    /// Reconstrói a coluna. `None` se o blob estiver truncado ou tiver uma tag
    /// desconhecida — nunca entra em pânico com bytes de disco.
    pub fn decode(blob: &[u8]) -> Option<Vec<u64>> {
        let codec = Codec::from_tag(*blob.first()?)?;
        let mut at = 1usize;
        let n = take_u64(blob, &mut at)? as usize;
        // O comprimento vem do DISCO. Validar ANTES de qualquer `with_capacity`:
        // um ficheiro corrompido com n = 2^63 fazia o processo abortar na
        // alocação, sem sequer chegar a olhar para os bytes seguintes.
        if n > MAX_VALORES {
            return None;
        }

        match codec {
            Codec::Raw => {
                // Cada valor ocupa 8 bytes: se não estão lá, o blob está
                // truncado e não vale a pena reservar espaço para eles.
                if blob.len().checked_sub(at)? < n.checked_mul(8)? {
                    return None;
                }
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push(take_u64(blob, &mut at)?);
                }
                Some(out)
            }
            Codec::Rle => {
                let mut runs = Vec::with_capacity(n);
                let mut total = 0usize;
                for _ in 0..n {
                    let val = take_u64(blob, &mut at)?;
                    let c = blob.get(at..at + 4)?;
                    at += 4;
                    let count = u32::from_le_bytes(c.try_into().ok()?);
                    total = total.checked_add(count as usize)?;
                    // Guarda contra um `count` do disco que pediria uma
                    // alocação absurda antes de qualquer validação.
                    if total > MAX_VALORES {
                        return None;
                    }
                    runs.push((val, count));
                }
                Some(rle::decode(&runs))
            }
            Codec::DeltaBitpack | Codec::ForBitpack => {
                let base = take_u64(blob, &mut at)?;
                let bits = *blob.get(at)? as u32;
                at += 1;
                // `bitpack::unpack` indexa `packed[word]` diretamente e entra em
                // pânico se as palavras não chegarem. Como `bits` e `n` vêm do
                // disco, a validação tem de acontecer AQUI — na fronteira onde
                // os bytes não confiáveis entram — e não lá dentro.
                if !(1..=64).contains(&bits) {
                    return None;
                }
                let valores = if codec == Codec::DeltaBitpack { n.checked_sub(1)? } else { n };
                let precisas = (valores.checked_mul(bits as usize)?).div_ceil(64);
                let restantes = blob.len().checked_sub(at)? / 8;
                if restantes < precisas {
                    return None;
                }
                let mut words = Vec::with_capacity(restantes);
                for _ in 0..restantes {
                    words.push(take_u64(blob, &mut at)?);
                }
                if codec == Codec::DeltaBitpack {
                    if n == 0 {
                        return Some(Vec::new());
                    }
                    let vals = bitpack::unpack(&words, bits, n - 1);
                    let mut deltas: Vec<i64> = Vec::with_capacity(n);
                    deltas.push(base as i64);
                    deltas.extend(vals.into_iter().map(|v| v as i64));
                    Some(delta::decode(&deltas))
                } else {
                    let offsets = bitpack::unpack(&words, bits, n);
                    Some(frame_of_reference::decode(base, &offsets))
                }
            }
        }
    }

    /// Tecto de valores por coluna ao DESCODIFICAR. O comprimento vem do disco e
    /// não é confiável: sem isto, um ficheiro corrompido (ou hostil) pede uma
    /// alocação de gigabytes antes de qualquer validação.
    const MAX_VALORES: usize = 1 << 28; // 268M valores ~ 2 GB descomprimidos

    /// Qual o codec de um blob já escrito (diagnóstico/telemetria).
    pub fn codec_of(blob: &[u8]) -> Option<Codec> {
        Codec::from_tag(*blob.first()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rle_roundtrip() {
        let data = vec![7, 7, 7, 3, 3, 9, 9, 9, 9];
        let enc = rle::encode(&data);
        assert_eq!(enc, vec![(7, 3), (3, 2), (9, 4)]);
        assert_eq!(rle::decode(&enc), data);
        assert!(rle::encode(&[]).is_empty());
    }

    #[test]
    fn delta_roundtrip_including_decreasing() {
        let data = vec![100u64, 102, 105, 104, 1000];
        let enc = delta::encode(&data);
        assert_eq!(enc, vec![100, 2, 3, -1, 896]);
        assert_eq!(delta::decode(&enc), data);
    }

    #[test]
    fn for_roundtrip() {
        let data = vec![1000u64, 1005, 1002, 1010];
        let (min, offs) = frame_of_reference::encode(&data);
        assert_eq!(min, 1000);
        assert_eq!(offs, vec![0, 5, 2, 10]);
        assert_eq!(frame_of_reference::decode(min, &offs), data);
    }

    #[test]
    fn bitpack_roundtrip_various_widths() {
        for bits in [1u32, 3, 7, 13, 32, 63, 64] {
            let mask = if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            let values: Vec<u64> = (0..500u64)
                .map(|i| (i.wrapping_mul(2654435761)) & mask)
                .collect();
            let packed = bitpack::pack(&values, bits);
            let got = bitpack::unpack(&packed, bits, values.len());
            assert_eq!(got, values, "roundtrip falhou em bits={bits}");
        }
    }

    #[test]
    fn min_bits_is_tight() {
        assert_eq!(bitpack::min_bits(0), 1);
        assert_eq!(bitpack::min_bits(1), 1);
        assert_eq!(bitpack::min_bits(2), 2);
        assert_eq!(bitpack::min_bits(255), 8);
        assert_eq!(bitpack::min_bits(256), 9);
    }

    #[test]
    fn for_plus_bitpack_compose() {
        // O caso canónico: inteiros grandes num intervalo estreito → FOR reduz a
        // magnitude, bitpack empacota os offsets pequenos.
        let data: Vec<u64> = (0..1000).map(|i| 1_000_000 + (i % 50)).collect();
        let (min, offs) = frame_of_reference::encode(&data);
        let bits = bitpack::min_bits(*offs.iter().max().unwrap());
        assert!(bits <= 6, "offsets 0..49 cabem em 6 bits");
        let packed = bitpack::pack(&offs, bits);
        let unpacked = bitpack::unpack(&packed, bits, offs.len());
        assert_eq!(frame_of_reference::decode(min, &unpacked), data);
        // Densidade: 1000 valores em ~6 bits vs 64 bits ⇒ >10x menos palavras.
        assert!(packed.len() * 10 < data.len());
    }
}

#[cfg(test)]
mod column_tests {
    use super::column::{self, Codec};

    fn round(data: &[u64]) -> Vec<u64> {
        column::decode(&column::encode(data)).expect("decode tem de reconstruir")
    }

    #[test]
    fn roundtrip_exato_em_varias_formas() {
        for caso in [
            vec![],
            vec![42],
            vec![7, 7, 7, 7, 7, 7, 7, 7],                 // RLE
            (0..1000).collect::<Vec<u64>>(),               // delta = 1
            (0..500).map(|i| i * 7 + 3).collect(),         // delta constante
            vec![u64::MAX, 0, u64::MAX / 2],               // extremos
            vec![1000, 1001, 1000, 1002, 999],             // fora de ordem, faixa estreita
        ] {
            assert_eq!(round(&caso), caso, "roundtrip falhou em {caso:?}");
        }
    }

    /// A propriedade que torna isto seguro de ligar no caminho de escrita: se
    /// nenhum codec ganhar, sai cru. Comprimir nunca pode fazer crescer -- senao
    /// um dia alguem desliga a compressao por medo e o motor volta para a
    /// bancada.
    #[test]
    fn nunca_expande_para_alem_do_cru() {
        for caso in [
            (0..64).map(|i| i * 0x1234_5678_9abc).collect::<Vec<u64>>(),
            vec![u64::MAX; 3],
            (0..100).map(|i: u64| i.wrapping_mul(6364136223846793005)).collect(),
        ] {
            let cru = 9 + caso.len() * 8;
            assert!(
                column::encode(&caso).len() <= cru,
                "expandiu: {} > {cru}", column::encode(&caso).len()
            );
        }
    }

    /// Postings de um indice sao LSNs ordenados -- o caso dominante. Delta e o
    /// codec certo e a densidade tem de ser real, nao marginal.
    #[test]
    fn postings_ordenados_escolhem_delta_e_encolhem_muito() {
        let postings: Vec<u64> = (0..10_000).map(|i| i * 3 + 1_000_000).collect();
        let blob = column::encode(&postings);
        assert_eq!(column::codec_of(&blob), Some(Codec::DeltaBitpack));
        let cru = postings.len() * 8;
        assert!(blob.len() * 8 < cru, "esperado >8x menor; {} vs {cru}", blob.len());
        assert_eq!(column::decode(&blob).unwrap(), postings);
    }

    #[test]
    fn coluna_repetida_escolhe_rle() {
        let data = vec![99u64; 5000];
        let blob = column::encode(&data);
        assert_eq!(column::codec_of(&blob), Some(Codec::Rle));
        assert!(blob.len() < 100);
        assert_eq!(column::decode(&blob).unwrap(), data);
    }

    /// Bytes de disco NUNCA podem entrar em panico nem pedir uma alocacao
    /// absurda. O comprimento vem do ficheiro e nao e confiavel.
    #[test]
    fn blob_corrompido_devolve_none_em_vez_de_panicar() {
        assert!(column::decode(&[]).is_none());
        assert!(column::decode(&[200]).is_none(), "tag desconhecida");
        assert!(column::decode(&[0, 255, 255, 255, 255, 255, 255, 255, 255]).is_none(),
                "conta gigante sem bytes que a sustentem");
        // Truncar um blob valido em qualquer ponto: None, nunca panico.
        let bom = column::encode(&(0..200).collect::<Vec<u64>>());
        for corte in 1..bom.len() {
            let _ = column::decode(&bom[..corte]);
        }
    }

    #[test]
    fn rle_com_contagem_hostil_nao_aloca_gigabytes() {
        // 1 run com count = u32::MAX repetido muitas vezes estouraria a memoria.
        let mut hostil = vec![Codec::Rle as u8];
        hostil.extend_from_slice(&1000u64.to_le_bytes());
        for _ in 0..1000 {
            hostil.extend_from_slice(&7u64.to_le_bytes());
            hostil.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        assert!(column::decode(&hostil).is_none(), "tem de recusar, nao alocar");
    }
}
