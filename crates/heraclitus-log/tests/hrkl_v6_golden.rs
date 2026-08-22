//! SPEC-0050 §165 — **golden vectors** do HRKL v6.
//!
//! Estes bytes fazem parte do contrato de compatibilidade. Um teste que falhe
//! aqui não é um teste partido: é um aviso de que o formato em disco mudou e
//! que segmentos já escritos deixam de ser interpretáveis da mesma maneira. A
//! resposta correcta é **uma versão nova de codec**, não actualizar a constante.
//!
//! # O que é congelado e o que não é
//!
//! Congelado: tudo o que é determinístico por construção — os bytes do
//! `CanonicalRecordCodecV1`, o `FileHeaderV6`, o `FooterV6`, o registo RAW com
//! o seu CRC-32C, a entrada do block directory e o **corpo descomprimido** de
//! um bloco.
//!
//! Não congelado: os bytes comprimidos. §167 é explícito — a identidade lógica
//! não depende de o Zstd produzir os mesmos bytes entre versões, e escrever um
//! golden vector sobre a saída do compressor transformaria uma actualização de
//! biblioteca num falso alarme de corrupção. O que se verifica desse lado é o
//! round-trip e a igualdade da `logical_root`.

use std::collections::BTreeMap;

use heraclitus_core::{Episode, EventId, EventKind, ProductPoint};
use heraclitus_log::v6::block::{build_block, PendingRecord, BLOCK_HEADER_LEN};
use heraclitus_log::v6::block_directory::{BlockDirectoryEntryV1, DIR_ENTRY_LEN};
use heraclitus_log::v6::canonical::{canonical_record_bytes, kind_tag, CanonicalRecordV1};
use heraclitus_log::v6::compress::{CompressionCodec, PackingProfile};
use heraclitus_log::v6::footer::{footer_flags, FooterV6, FOOTER_LEN};
use heraclitus_log::v6::header::{header_flags, FileHeaderV6, PhysicalLayout, FILE_HEADER_LEN};
use heraclitus_log::v6::raw::{decode_raw_record, encode_raw_record, RawDecoded};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ulid_de(byte: u8) -> EventId {
    EventId(ulid::Ulid::from_bytes([byte; 16]))
}

fn episodio_base(id: u8) -> Episode {
    Episode {
        id: ulid_de(id),
        ts_hlc: 0,
        agent_id: String::new(),
        session_id: String::new(),
        kind: EventKind::Observation,
        content: Vec::new(),
        embedding: None,
        attrs: BTreeMap::new(),
        parents: Vec::new(),
        valid_from: None,
        valid_to: None,
    }
}

// ---------------------------------------------------------------------------
// CanonicalRecordCodecV1
// ---------------------------------------------------------------------------

/// Registo mínimo: tudo a zero, `Observation`, sem embedding, attrs ou parents.
const GOLDEN_CANONICAL_MINIMAL: &str =
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    000000000000000000000000000001000000000000";

/// Registo típico: agente, sessão, `Message`, conteúdo, dois atributos, um
/// parent e `valid_from`.
const GOLDEN_CANONICAL_TYPICAL: &str =
    "41548900000000006478e76800000000abababababababababababababababab111111111111111111111111\
    111111116478e76800000000086167656e742d303106736573732d4103096f6c61206d756e646f0002016101\
    3101620132012222222222222222222222222222222201e80300000000000000";

/// `Custom` kind e um embedding com `-0.0` e `NaN` — o vector que prova a
/// canonicalização IEEE-754 de §14.
const GOLDEN_CANONICAL_CUSTOM: &str =
    "0700000000000000080000000000000000000000000000000000000000000000333333333333333333333333\
    333333330000000000000000000007086d65752d6b696e64000102000000000000c03f010000c07f00000001\
    0100000000000000010200000000000000";

#[test]
fn canonical_codec_minimal() {
    let e = episodio_base(0);
    let r = CanonicalRecordV1 {
        lsn: 0,
        record_hlc: 0,
        opaque_meta: [0u8; 16],
        episode: &e,
    };
    assert_eq!(hex(&canonical_record_bytes(&r)), GOLDEN_CANONICAL_MINIMAL);
}

#[test]
fn canonical_codec_tipico() {
    let mut e = episodio_base(0x11);
    e.ts_hlc = 1_760_000_100;
    e.agent_id = "agent-01".into();
    e.session_id = "sess-A".into();
    e.kind = EventKind::Message;
    e.content = b"ola mundo".to_vec();
    e.attrs.insert("a".into(), "1".into());
    e.attrs.insert("b".into(), "2".into());
    e.parents = vec![ulid_de(0x22)];
    e.valid_from = Some(1000);
    let r = CanonicalRecordV1 {
        lsn: 9_000_001,
        record_hlc: 1_760_000_100,
        opaque_meta: [0xAB; 16],
        episode: &e,
    };
    assert_eq!(hex(&canonical_record_bytes(&r)), GOLDEN_CANONICAL_TYPICAL);
}

#[test]
fn canonical_codec_custom_e_floats() {
    let mut e = episodio_base(0x33);
    e.kind = EventKind::Custom("meu-kind".into());
    e.embedding = Some(ProductPoint {
        hyp: vec![-0.0, 1.5],
        sph: vec![f32::NAN],
        euc: vec![],
    });
    e.valid_from = Some(1);
    e.valid_to = Some(2);
    let r = CanonicalRecordV1 {
        lsn: 7,
        record_hlc: 8,
        opaque_meta: [0u8; 16],
        episode: &e,
    };
    let bytes = canonical_record_bytes(&r);
    assert_eq!(hex(&bytes), GOLDEN_CANONICAL_CUSTOM);

    // O mesmo registo com +0.0 e outro payload de NaN tem de dar os MESMOS
    // bytes: é isso que a canonicalização de §14 promete.
    let mut e2 = episodio_base(0x33);
    e2.kind = EventKind::Custom("meu-kind".into());
    e2.embedding = Some(ProductPoint {
        hyp: vec![0.0, 1.5],
        sph: vec![f32::from_bits(0x7fff_ffff)],
        euc: vec![],
    });
    e2.valid_from = Some(1);
    e2.valid_to = Some(2);
    let r2 = CanonicalRecordV1 {
        lsn: 7,
        record_hlc: 8,
        opaque_meta: [0u8; 16],
        episode: &e2,
    };
    assert_eq!(canonical_record_bytes(&r2), bytes);
}

/// §11 — os tags de `EventKind` são permanentes. Este teste é a lista
/// publicada; mudar um número aqui invalida histórico já escrito.
#[test]
fn tags_de_event_kind_sao_permanentes() {
    const OFFSET_DO_TAG: usize = 8 + 8 + 16 + 16 + 8 + 1 + 1;
    let casos: [(EventKind, u8); 8] = [
        (EventKind::Observation, kind_tag::OBSERVATION),
        (EventKind::Action, kind_tag::ACTION),
        (EventKind::Message, kind_tag::MESSAGE),
        (EventKind::RetrievalFeedback, kind_tag::RETRIEVAL_FEEDBACK),
        (EventKind::FactDerived, kind_tag::FACT_DERIVED),
        (EventKind::DemotionReceipt, kind_tag::DEMOTION_RECEIPT),
        (EventKind::Custom(String::new()), kind_tag::CUSTOM),
        (EventKind::SystemMetric, kind_tag::SYSTEM_METRIC),
    ];
    assert_eq!(kind_tag::OBSERVATION, 0x01);
    assert_eq!(kind_tag::ACTION, 0x02);
    assert_eq!(kind_tag::MESSAGE, 0x03);
    assert_eq!(kind_tag::RETRIEVAL_FEEDBACK, 0x04);
    assert_eq!(kind_tag::FACT_DERIVED, 0x05);
    assert_eq!(kind_tag::DEMOTION_RECEIPT, 0x06);
    assert_eq!(kind_tag::CUSTOM, 0x07);
    assert_eq!(kind_tag::SYSTEM_METRIC, 0x08);

    for (kind, tag) in casos {
        let mut e = episodio_base(0);
        e.kind = kind;
        let r = CanonicalRecordV1 {
            lsn: 0,
            record_hlc: 0,
            opaque_meta: [0u8; 16],
            episode: &e,
        };
        let bytes = canonical_record_bytes(&r);
        assert_eq!(
            bytes[OFFSET_DO_TAG], tag,
            "tag errado no offset {OFFSET_DO_TAG}"
        );
    }
}

// ---------------------------------------------------------------------------
// Estruturas em disco
// ---------------------------------------------------------------------------

const GOLDEN_FILE_HEADER: &str =
    "48524b4c06004000000101002c03000000000000efcdab89674523012f643105000000000700000000000000\
    abababababababababababababababab0f125e3d";

const GOLDEN_FOOTER: &str =
    "48465452010080000300000000000000640000000000000066000000000000000a000000000000001e000000\
    000000000000000001000000000000000000000000000000000000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\
    5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5ad40678610000000000000000000000000000000000000000";

const GOLDEN_RAW_RECORD: &str = "0400000039fad01564000000000000000a00000000000000616c6661";

const GOLDEN_DIR_ENTRY: &str =
    "400000000000000084030000d00700000b0000000000000064000000000000006e000000000000000a000000\
    000000001e00000000000000";

/// Corpo **descomprimido** de um bloco de três registos com
/// `restart_interval = 2`.
const GOLDEN_BLOCK_BODY: &str =
    "100a7230100a7231101e723200000000000000000a0000000000000064000000000000000200000008000000\
    1e000000000000006600000000000000";

#[test]
fn file_header_v6_tem_64_bytes_e_bytes_congelados() {
    let h = FileHeaderV6 {
        physical_layout: PhysicalLayout::Raw,
        canonical_codec: 1,
        flags: header_flags::CONTIGUOUS_LSN,
        segment_id: 812,
        created_hlc: 0x0123_4567_89ab_cdef,
        first_lsn: 87_122_991,
        writer_epoch: 7,
        storage_namespace_id: [0xAB; 16],
    };
    let bytes = h.encode();
    assert_eq!(bytes.len(), FILE_HEADER_LEN);
    assert_eq!(FILE_HEADER_LEN, 64);
    assert_eq!(hex(&bytes), GOLDEN_FILE_HEADER);
    assert_eq!(FileHeaderV6::decode(&bytes).unwrap(), h);
}

#[test]
fn footer_v6_tem_128_bytes_e_bytes_congelados() {
    let f = FooterV6 {
        record_count: 3,
        min_lsn: 100,
        max_lsn: 102,
        min_hlc: 10,
        max_hlc: 30,
        block_count: 0,
        flags: footer_flags::CONTIGUOUS_LSN,
        block_directory_offset: 0,
        block_directory_len: 0,
        logical_root: [0x5A; 32],
    };
    let bytes = f.encode();
    assert_eq!(bytes.len(), FOOTER_LEN);
    assert_eq!(FOOTER_LEN, 128);
    assert_eq!(hex(&bytes), GOLDEN_FOOTER);
    assert_eq!(FooterV6::decode(&bytes).unwrap(), f);
}

#[test]
fn registo_raw_v6_tem_24_bytes_de_overhead_e_bytes_congelados() {
    let bytes = encode_raw_record(100, 10, b"alfa");
    assert_eq!(bytes.len(), 24 + 4);
    assert_eq!(hex(&bytes), GOLDEN_RAW_RECORD);
    match decode_raw_record(&bytes) {
        RawDecoded::Record {
            lsn,
            hlc,
            payload,
            total,
        } => {
            assert_eq!(
                (lsn, hlc, payload, total),
                (100, 10, &b"alfa"[..], bytes.len())
            );
        }
        _ => panic!("golden vector deixou de descodificar"),
    }
}

#[test]
fn entrada_do_block_directory_tem_56_bytes_e_bytes_congelados() {
    let e = BlockDirectoryEntryV1 {
        offset: 64,
        stored_len: 900,
        uncompressed_len: 2000,
        record_count: 11,
        flags: 0,
        first_lsn: 100,
        last_lsn: 110,
        min_hlc: 10,
        max_hlc: 30,
    };
    let bytes = e.encode();
    assert_eq!(bytes.len(), DIR_ENTRY_LEN);
    assert_eq!(DIR_ENTRY_LEN, 56);
    assert_eq!(hex(&bytes), GOLDEN_DIR_ENTRY);
    assert_eq!(BlockDirectoryEntryV1::decode(&bytes).unwrap(), e);
}

#[test]
fn corpo_de_bloco_descomprimido_tem_bytes_congelados() {
    let recs: Vec<PendingRecord> = (0..3u64)
        .map(|i| PendingRecord {
            lsn: 100 + i,
            hlc: 10 + i * 10,
            payload: format!("r{i}").into_bytes(),
        })
        .collect();
    // `raw_fallback_ratio = 0.0` força o codec RAW, para que o corpo gravado
    // seja exactamente o corpo lógico — os bytes do compressor NÃO são
    // contrato (§167).
    let b = build_block(&recs, 2, PackingProfile::Balanced, 0.0).unwrap();
    assert_eq!(b.header.codec, CompressionCodec::Raw);
    assert_eq!(b.header_bytes.len(), BLOCK_HEADER_LEN);
    assert_eq!(BLOCK_HEADER_LEN, 64);
    assert_eq!(hex(&b.stored), GOLDEN_BLOCK_BODY);
    assert_eq!(b.header.restart_count, 2);
    assert_eq!(b.header.first_lsn, 100);
    assert_eq!(b.header.last_lsn, 102);
    assert_eq!(b.header.base_hlc, 10);
    assert_eq!(b.header.max_hlc, 30);
}
