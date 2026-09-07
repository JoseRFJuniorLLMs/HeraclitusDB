//! SPEC-0050 §49–§51 — o **Block Directory**.
//!
//! Índice físico mínimo **obrigatório dentro do próprio `.hrkl`**. Não pertence
//! ao `.hrki` (§49) por uma razão de correcção, não de gosto: o `.hrki` é
//! descartável e reconstruível, e um segmento PACKED tem de continuar navegável
//! sem qualquer sidecar. Se a navegação dependesse do sidecar, apagar um
//! ficheiro derivado tornaria o canónico ilegível — exactamente o contrário do
//! invariante 4.
//!
//! Duplica campos que também vivem no `BlockHeader` (§51). É deliberado:
//! permite descobrir offsets, tamanhos e intervalos de LSN/HLC **sem abrir cada
//! bloco**, que é o que torna o point lookup uma leitura só.
//!
//! ```text
//! offset            u64
//! stored_len        u32
//! uncompressed_len  u32
//! record_count      u32
//! flags             u32
//! first_lsn         u64
//! last_lsn          u64
//! min_hlc           u64
//! max_hlc           u64
//!                   = 56 bytes
//! ```

use heraclitus_core::Lsn;

use super::error::{corrupt, V6Result, HARD_MAX_BLOCKS};
use super::footer::FooterV6;

pub const DIR_ENTRY_LEN: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDirectoryEntryV1 {
    pub offset: u64,
    pub stored_len: u32,
    pub uncompressed_len: u32,
    pub record_count: u32,
    pub flags: u32,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub min_hlc: u64,
    pub max_hlc: u64,
}

impl BlockDirectoryEntryV1 {
    pub fn encode(&self) -> [u8; DIR_ENTRY_LEN] {
        let mut b = [0u8; DIR_ENTRY_LEN];
        b[0..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..12].copy_from_slice(&self.stored_len.to_le_bytes());
        b[12..16].copy_from_slice(&self.uncompressed_len.to_le_bytes());
        b[16..20].copy_from_slice(&self.record_count.to_le_bytes());
        b[20..24].copy_from_slice(&self.flags.to_le_bytes());
        b[24..32].copy_from_slice(&self.first_lsn.to_le_bytes());
        b[32..40].copy_from_slice(&self.last_lsn.to_le_bytes());
        b[40..48].copy_from_slice(&self.min_hlc.to_le_bytes());
        b[48..56].copy_from_slice(&self.max_hlc.to_le_bytes());
        b
    }

    pub fn decode(buf: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 block directory entry";
        if buf.len() < DIR_ENTRY_LEN {
            return Err(corrupt(CTX, "short directory entry"));
        }
        Ok(Self {
            offset: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            stored_len: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            uncompressed_len: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            record_count: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            first_lsn: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            last_lsn: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            min_hlc: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            max_hlc: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
        })
    }

    /// `true` se `lsn` cai no intervalo declarado deste bloco.
    #[inline]
    pub fn contains_lsn(&self, lsn: Lsn) -> bool {
        self.record_count > 0 && lsn >= self.first_lsn && lsn <= self.last_lsn
    }

    /// Zone map de HLC ao nível do bloco (SPEC-0050 §59). Conservador por
    /// construção: devolver `true` custa uma leitura, devolver `false` a
    /// mais perderia registos, e por isso `false` só sai quando o intervalo
    /// declarado é **disjunto** do pedido.
    #[inline]
    pub fn may_contain_hlc_range(&self, lo: u64, hi: u64) -> bool {
        self.record_count > 0 && self.max_hlc >= lo && self.min_hlc <= hi
    }

    #[inline]
    pub fn may_contain_lsn_range(&self, lo: Lsn, hi: Lsn) -> bool {
        self.record_count > 0 && self.last_lsn >= lo && self.first_lsn <= hi
    }
}

/// O directório completo de um segmento PACKED.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockDirectory {
    pub entries: Vec<BlockDirectoryEntryV1>,
}

impl BlockDirectory {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * DIR_ENTRY_LEN);
        for e in &self.entries {
            out.extend_from_slice(&e.encode());
        }
        out
    }

    /// Descodifica `count` entradas, validando cada bloco contra o fim da
    /// região de blocos (`blocks_region_end` — normalmente o offset do próprio
    /// directório). §137: todo o length é verificado contra os bytes que
    /// existem, não contra o que o ficheiro afirma sobre si próprio.
    pub fn decode(buf: &[u8], count: u32, blocks_region_end: u64) -> V6Result<Self> {
        let file_len = blocks_region_end;
        const CTX: &str = "hrkl v6 block directory";
        if count > HARD_MAX_BLOCKS {
            return Err(corrupt(
                CTX,
                format!("block_count {count} above hard maximum"),
            ));
        }
        let need = count as usize * DIR_ENTRY_LEN;
        if buf.len() < need {
            return Err(corrupt(
                CTX,
                format!("directory needs {need} bytes, got {}", buf.len()),
            ));
        }
        let mut entries = Vec::with_capacity(count as usize);
        let mut prev_end: u64 = 0;
        for i in 0..count as usize {
            let e = BlockDirectoryEntryV1::decode(&buf[i * DIR_ENTRY_LEN..])?;
            let end = e
                .offset
                .checked_add(e.stored_len as u64)
                .ok_or_else(|| corrupt(CTX, "block offset+len overflows u64"))?;
            if end > file_len {
                return Err(corrupt(
                    CTX,
                    format!("block {i} ends at {end}, past file length {file_len}"),
                ));
            }
            if e.offset < prev_end {
                return Err(corrupt(
                    CTX,
                    format!("block {i} overlaps the previous block"),
                ));
            }
            if e.record_count > 0 && e.first_lsn > e.last_lsn {
                return Err(corrupt(CTX, format!("block {i} has first_lsn > last_lsn")));
            }
            if e.uncompressed_len as usize > super::error::HARD_MAX_BLOCK_BYTES {
                return Err(corrupt(
                    CTX,
                    format!(
                        "block {i} declares {} uncompressed bytes",
                        e.uncompressed_len
                    ),
                ));
            }
            prev_end = end;
            entries.push(e);
        }
        // Os blocos são gravados por ordem crescente de LSN; um directório que
        // não o respeite quebra a busca binária, e a busca binária é o que
        // torna o point lookup O(log n).
        for w in entries.windows(2) {
            if w[0].record_count > 0 && w[1].record_count > 0 && w[0].first_lsn > w[1].first_lsn {
                return Err(corrupt(CTX, "directory is not ordered by first_lsn"));
            }
        }
        Ok(Self { entries })
    }

    /// Confronta o directório com o footer que sela o segmento.
    ///
    /// Auditoria 2026-09-05 (A05): o directório é a **única** região do `.hrkl`
    /// PACKED sem checksum — o header tem CRC, cada bloco tem CRC sobre
    /// header+payload, o footer tem CRC, o directório não tem nada. E as
    /// guardas de [`BlockDirectory::decode`] (offsets dentro do ficheiro,
    /// não-sobreposição física, `first_lsn <= last_lsn`, ordem por `first_lsn`)
    /// não são violadas por um bit rot que apenas *encolha* um `last_lsn`. O
    /// efeito é o pior possível num log auditável: `find_block_for_lsn` deixa de
    /// encontrar o bloco e o point lookup responde `Ok(None)` para um LSN
    /// comitado e durado — sem erro, sem `Corruption`, sem métrica. A guarda que
    /// existia (`read_block` compara o header do bloco com a entrada) só corre
    /// *depois* do pruning, portanto nunca é alcançada nesse caminho.
    ///
    /// O footer é a âncora certa para o confronto: tem CRC próprio e os seus
    /// `record_count`/`min_lsn`/`max_lsn` já foram comparados com o manifesto no
    /// arranque. Não se escreve nem se lê um byte novo — só se comparam campos
    /// que já existem —, logo ficheiros antigos continuam a abrir.
    ///
    /// Limite conhecido: num segmento **sem** `CONTIGUOUS_LSN`, um encolhimento
    /// no meio que continue disjunto e dentro das pontas fica por apanhar;
    /// fechá-lo exige um CRC-32C da região do directório guardado no footer, o
    /// que obriga a subir a versão do footer.
    pub fn check_against_footer(&self, footer: &FooterV6) -> V6Result<()> {
        const CTX: &str = "hrkl v6 block directory";
        let declared: u64 = self.entries.iter().map(|e| e.record_count as u64).sum();
        if declared != footer.record_count {
            return Err(corrupt(
                CTX,
                format!(
                    "directory accounts for {declared} records, footer declares {}",
                    footer.record_count
                ),
            ));
        }
        // Entradas vazias não declaram intervalo nenhum: `contains_lsn` e
        // `may_contain_lsn_range` já as ignoram, e ignorá-las aqui impede que um
        // bloco sem registos invente pontas ou buracos.
        let mut anterior: Option<&BlockDirectoryEntryV1> = None;
        let mut primeiro_lsn: Option<Lsn> = None;
        let mut ultimo_lsn: Lsn = 0;
        let mut soma_dos_intervalos: u64 = 0;
        for (i, e) in self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.record_count > 0)
        {
            if let Some(prev) = anterior {
                // Intervalos disjuntos e estritamente crescentes é o que a busca
                // binária de `find_block_for_lsn` (partition_point sobre
                // `last_lsn`) pressupõe; pôr isso em causa é pôr em causa o
                // point lookup.
                if prev.last_lsn >= e.first_lsn {
                    return Err(corrupt(
                        CTX,
                        format!(
                            "block {i} starts at LSN {} but the previous block ends at {}",
                            e.first_lsn, prev.last_lsn
                        ),
                    ));
                }
            }
            if primeiro_lsn.is_none() {
                primeiro_lsn = Some(e.first_lsn);
            }
            ultimo_lsn = e.last_lsn;
            if footer.is_contiguous_lsn() {
                // Só se soma quando o footer declara contiguidade, que é quando
                // a soma é comparada: assim um segmento legítimo com buracos
                // largos nunca corre o risco de ser recusado por transbordo. E
                // aritmética VERIFICADA, e não `-` e `+ 1` crus: com
                // `overflow-checks = true`, um directório forjado com
                // `last_lsn = u64::MAX` trocaria a rejeição por um pânico ao
                // abrir o log — o mesmo bug já corrigido em
                // `FooterV6::lsn_span_is_contiguous`.
                soma_dos_intervalos = e
                    .last_lsn
                    .checked_sub(e.first_lsn)
                    .and_then(|span| span.checked_add(1))
                    .and_then(|span| soma_dos_intervalos.checked_add(span))
                    .ok_or_else(|| {
                        corrupt(CTX, format!("block {i} declares an impossible LSN span"))
                    })?;
            }
            anterior = Some(e);
        }
        // Sem blocos com registos o `declared` acima já provou que o footer
        // também não declara nenhum.
        let Some(primeiro_lsn) = primeiro_lsn else {
            return Ok(());
        };
        if primeiro_lsn != footer.min_lsn || ultimo_lsn != footer.max_lsn {
            return Err(corrupt(
                CTX,
                format!(
                    "directory covers LSN {primeiro_lsn}..={ultimo_lsn}, footer seals {}..={}",
                    footer.min_lsn, footer.max_lsn
                ),
            ));
        }
        // Com as pontas presas ao footer e os intervalos disjuntos, esta soma
        // fecha a contiguidade sem precisar de comparar bloco a bloco: um
        // buraco obrigaria os blocos a cobrir menos LSNs do que os registos que
        // declaram, e sobrepô-los para compensar já foi recusado acima.
        if footer.is_contiguous_lsn() && soma_dos_intervalos != footer.record_count {
            return Err(corrupt(
                CTX,
                format!(
                    "footer declares {} contiguous records but the directory spans {soma_dos_intervalos} LSNs",
                    footer.record_count
                ),
            ));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Busca binária pelo bloco que contém `lsn` (SPEC-0050 §77).
    pub fn find_block_for_lsn(&self, lsn: Lsn) -> Option<usize> {
        let idx = self.entries.partition_point(|e| e.last_lsn < lsn);
        let e = self.entries.get(idx)?;
        if e.contains_lsn(lsn) {
            Some(idx)
        } else {
            None
        }
    }

    /// Índices dos blocos que podem conter LSNs em `[lo, hi]`.
    pub fn blocks_for_lsn_range(&self, lo: Lsn, hi: Lsn) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.may_contain_lsn_range(lo, hi))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn total_stored_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.stored_len as u64).sum()
    }
    pub fn total_uncompressed_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.uncompressed_len as u64).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u64, first: u64, last: u64) -> BlockDirectoryEntryV1 {
        BlockDirectoryEntryV1 {
            offset: 64 + i * 1000,
            stored_len: 900,
            uncompressed_len: 2000,
            record_count: (last - first + 1) as u32,
            flags: 0,
            first_lsn: first,
            last_lsn: last,
            min_hlc: 100 + first,
            max_hlc: 100 + last,
        }
    }

    fn dir() -> BlockDirectory {
        BlockDirectory {
            entries: (0..5)
                .map(|i| entry(i, 1000 + i * 10, 1009 + i * 10))
                .collect(),
        }
    }

    #[test]
    fn entrada_tem_56_bytes_e_roundtrip() {
        let e = entry(0, 10, 20);
        assert_eq!(e.encode().len(), 56);
        assert_eq!(BlockDirectoryEntryV1::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn roundtrip_do_directorio() {
        let d = dir();
        let bytes = d.encode();
        assert_eq!(BlockDirectory::decode(&bytes, 5, 1_000_000).unwrap(), d);
    }

    #[test]
    fn busca_binaria_encontra_o_bloco_certo() {
        let d = dir();
        assert_eq!(d.find_block_for_lsn(1000), Some(0));
        assert_eq!(d.find_block_for_lsn(1009), Some(0));
        assert_eq!(d.find_block_for_lsn(1010), Some(1));
        assert_eq!(d.find_block_for_lsn(1049), Some(4));
        assert_eq!(d.find_block_for_lsn(999), None);
        assert_eq!(d.find_block_for_lsn(1050), None);
    }

    #[test]
    fn range_scan_selecciona_apenas_os_blocos_sobrepostos() {
        let d = dir();
        assert_eq!(d.blocks_for_lsn_range(1015, 1025), vec![1, 2]);
        assert_eq!(d.blocks_for_lsn_range(0, 10).len(), 0);
        assert_eq!(d.blocks_for_lsn_range(0, u64::MAX).len(), 5);
    }

    #[test]
    fn bloco_fora_do_ficheiro_e_recusado() {
        let d = dir();
        assert!(BlockDirectory::decode(&d.encode(), 5, 100).is_err());
    }

    #[test]
    fn blocos_sobrepostos_sao_recusados() {
        let mut d = dir();
        d.entries[2].offset = d.entries[1].offset;
        assert!(BlockDirectory::decode(&d.encode(), 5, 1_000_000).is_err());
    }

    #[test]
    fn directorio_desordenado_e_recusado() {
        let mut d = dir();
        d.entries.swap(1, 3);
        // repõe offsets crescentes para isolar a falha de ordenação por LSN
        for (i, e) in d.entries.iter_mut().enumerate() {
            e.offset = 64 + i as u64 * 1000;
        }
        assert!(BlockDirectory::decode(&d.encode(), 5, 1_000_000).is_err());
    }

    #[test]
    fn contagem_absurda_nao_aloca() {
        assert!(BlockDirectory::decode(&[], u32::MAX, 1_000_000).is_err());
        assert!(BlockDirectory::decode(&[0u8; 10], 1000, 1_000_000).is_err());
    }

    /// Footer que sela exactamente o que `d` declara — o que o
    /// `PackedSegmentWriter::finish` produziria para este directório.
    fn footer_de(d: &BlockDirectory, contiguo: bool) -> FooterV6 {
        let cheias: Vec<_> = d.entries.iter().filter(|e| e.record_count > 0).collect();
        FooterV6 {
            record_count: d.entries.iter().map(|e| e.record_count as u64).sum(),
            min_lsn: cheias.first().map(|e| e.first_lsn).unwrap_or(0),
            max_lsn: cheias.last().map(|e| e.last_lsn).unwrap_or(0),
            min_hlc: cheias.first().map(|e| e.min_hlc).unwrap_or(0),
            max_hlc: cheias.last().map(|e| e.max_hlc).unwrap_or(0),
            block_count: d.len() as u32,
            flags: if contiguo {
                super::super::footer::footer_flags::CONTIGUOUS_LSN
            } else {
                0
            },
            block_directory_offset: 4096,
            block_directory_len: d.len() as u64 * DIR_ENTRY_LEN as u64,
            logical_root: [0u8; 32],
        }
    }

    #[test]
    fn directorio_coerente_passa_o_confronto_com_o_footer() {
        let d = dir();
        d.check_against_footer(&footer_de(&d, true)).unwrap();
        d.check_against_footer(&footer_de(&d, false)).unwrap();
        // Um segmento vazio (sem blocos) também é coerente.
        let vazio = BlockDirectory::default();
        vazio
            .check_against_footer(&footer_de(&vazio, false))
            .unwrap();
    }

    #[test]
    fn soma_de_record_count_diferente_do_footer_e_recusada() {
        // Só o confronto das contagens apanha isto: os intervalos de LSN ficam
        // intactos, logo as pontas e a soma dos intervalos continuam a bater.
        let mut d = dir();
        d.entries[2].record_count -= 5;
        assert!(d.check_against_footer(&footer_de(&dir(), false)).is_err());
        assert!(d.check_against_footer(&footer_de(&dir(), true)).is_err());
    }

    #[test]
    fn intervalo_que_nao_bate_com_as_pontas_do_footer_e_recusado() {
        // Auditoria 2026-09-05 (A05): sem o flag de contiguidade, são as pontas
        // seladas no footer que denunciam um bloco cujo intervalo encolheu.
        let mut d = dir();
        d.entries[4].last_lsn -= 3;
        assert!(d.check_against_footer(&footer_de(&dir(), false)).is_err());

        let mut d = dir();
        d.entries[0].first_lsn += 3;
        assert!(d.check_against_footer(&footer_de(&dir(), false)).is_err());
    }

    #[test]
    fn buraco_no_meio_e_recusado_quando_o_footer_declara_contiguidade() {
        // Auditoria 2026-09-05 (A05): encolher o `last_lsn` de um bloco do meio
        // mantém as pontas, a ordem e a não-sobreposição — só a contiguidade
        // declarada no footer o apanha.
        let mut d = dir();
        d.entries[1].last_lsn -= 2;
        assert!(d.check_against_footer(&footer_de(&dir(), true)).is_err());
        // Dívida conhecida e deliberada: sem o flag CONTIGUOUS_LSN o mesmo
        // encolhimento no meio passa. Fechá-lo exige um CRC do directório no
        // footer, e isso obriga a subir a versão do footer.
        assert!(d.check_against_footer(&footer_de(&dir(), false)).is_ok());
    }

    #[test]
    fn blocos_com_intervalos_de_lsn_sobrepostos_sao_recusados() {
        // A busca binária de `find_block_for_lsn` pressupõe intervalos
        // disjuntos e crescentes; um directório que os sobreponha faz o point
        // lookup responder pelo bloco errado.
        let mut d = dir();
        d.entries[2].first_lsn = d.entries[1].last_lsn;
        assert!(d.check_against_footer(&footer_de(&dir(), false)).is_err());
    }

    #[test]
    fn intervalo_absurdo_e_recusado_sem_entrar_em_panico() {
        // `overflow-checks = true`: a aritmética do confronto tem de ser
        // verificada, senão um directório forjado troca a rejeição por um
        // pânico ao abrir o log — o mesmo bug já corrigido em
        // `FooterV6::lsn_span_is_contiguous`.

        // Um bloco só, a cobrir todo o espaço de LSN: `last - first + 1`
        // transborda.
        let mut d = BlockDirectory {
            entries: vec![entry(0, 0, 10)],
        };
        d.entries[0].last_lsn = u64::MAX;
        assert!(d.check_against_footer(&footer_de(&d, true)).is_err());

        // Dois blocos cujos intervalos, somados, transbordam.
        let meio = u64::MAX / 2;
        let mut d = BlockDirectory {
            entries: vec![entry(0, 0, 10), entry(1, 0, 10)],
        };
        d.entries[0].last_lsn = meio;
        d.entries[1].first_lsn = meio + 1;
        d.entries[1].last_lsn = u64::MAX;
        assert!(d.check_against_footer(&footer_de(&d, true)).is_err());
    }

    #[test]
    fn pruning_nunca_da_falso_negativo_em_hlc() {
        let e = entry(0, 10, 20); // min_hlc=110, max_hlc=120
        assert!(e.may_contain_hlc_range(110, 120));
        assert!(e.may_contain_hlc_range(0, 110));
        assert!(e.may_contain_hlc_range(120, u64::MAX));
        assert!(!e.may_contain_hlc_range(121, u64::MAX));
        assert!(!e.may_contain_hlc_range(0, 109));
    }
}
