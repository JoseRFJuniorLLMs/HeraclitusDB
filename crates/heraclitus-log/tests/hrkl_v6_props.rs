//! SPEC-0050 §152 e §164 — **property tests** do HRKL v6 sobre o corpus mínimo.
//!
//! §164 lista as propriedades obrigatórias. As que dependem apenas das Fases
//! 0–2 estão todas aqui:
//!
//! ```text
//! RAW decode == PACKED decode                          ✓
//! RAW logical_root == PACKED logical_root              ✓
//! pack(pack(x)) logical-equivalent to pack(x)          ✓
//! unpack(pack(x)) == logical x                         ✓
//! different physical codec same logical root           ✓
//! block/manifest pruning never false-negative          ✓
//! malformed input never panics                         ✓
//! HRKI pruning never false-negative                    — Fase 4
//! corrupt HRKI never corrupts HRKL                     — Fase 4
//! legacy decode preserves events                       — Fase 1 (migração v1–v5)
//! ```
//!
//! # O corpus (§152)
//!
//! Sete perfis, porque a compressão é uma propriedade dos **dados** e não do
//! codec: eventos pequenos altamente repetitivos, eventos médios realistas,
//! conteúdo incompressível, embeddings, atributos de alta cardinalidade,
//! payloads grandes e uma mistura com conteúdo cifrado. O oitavo item de §152 —
//! 20M+ registos — corre com `HRKL_V6_CORPUS=20000000`; o default mantém-se
//! pequeno para a suíte normal ser rápida.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heraclitus_core::{Episode, EventId, EventKind, Lsn, ProductPoint};
use heraclitus_log::v6::block::{MAX_BLOCK_TARGET, MIN_BLOCK_TARGET};
use heraclitus_log::v6::canonical::{
    canonical_record_bytes, canonical_record_hash, CanonicalRecordV1, DOMAIN_CANONICAL_RECORD,
};
use heraclitus_log::v6::compress::PackingProfile;
use heraclitus_log::v6::error::V6Result;
use heraclitus_log::v6::packed::{open_packed, PackOptions, ScanCounters};
use heraclitus_log::v6::packer::{pack_segment, repack_segment};
use heraclitus_log::v6::raw::{decode_raw_record, scan_raw_segment, RawSegmentWriter, SegmentInit};
use heraclitus_log::v6::verify::{verify_segment, IntegrityLevel};

// ---------------------------------------------------------------------------
// Infra-estrutura
// ---------------------------------------------------------------------------

/// PRNG determinístico — os testes têm de falhar sempre da mesma maneira.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn ulid_de(v: u128) -> EventId {
    EventId(ulid::Ulid::from_bytes(v.to_be_bytes()))
}

/// Os sete perfis de dados de §152.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perfil {
    PequenoRepetitivo,
    MedioRealista,
    Incompressivel,
    Embeddings,
    AtributosAltaCardinalidade,
    PayloadGrande,
    Cifrado,
}

const PERFIS: [Perfil; 7] = [
    Perfil::PequenoRepetitivo,
    Perfil::MedioRealista,
    Perfil::Incompressivel,
    Perfil::Embeddings,
    Perfil::AtributosAltaCardinalidade,
    Perfil::PayloadGrande,
    Perfil::Cifrado,
];

fn episodio(perfil: Perfil, i: u64, rng: &mut Rng) -> Episode {
    let mut e = Episode {
        id: ulid_de(i as u128 * 0x1_0000_0001),
        ts_hlc: 1_760_000_000 + i,
        agent_id: String::new(),
        session_id: String::new(),
        kind: EventKind::Observation,
        content: Vec::new(),
        embedding: None,
        attrs: BTreeMap::new(),
        parents: Vec::new(),
        valid_from: None,
        valid_to: None,
    };
    match perfil {
        Perfil::PequenoRepetitivo => {
            e.agent_id = "agent-01".into();
            e.session_id = "sess-0001".into();
            e.kind = EventKind::Observation;
            e.content = b"ping".to_vec();
        }
        Perfil::MedioRealista => {
            e.agent_id = format!("agent-{:02}", i % 8);
            e.session_id = format!("sess-{:04}", i % 64);
            e.kind = if i.is_multiple_of(3) {
                EventKind::Message
            } else {
                EventKind::Action
            };
            e.content = format!(
                "{{\"op\":\"update\",\"entity\":{},\"campo\":\"estado\",\"valor\":\"pendente\",\"seq\":{i}}}",
                i % 500
            )
            .into_bytes();
            e.attrs.insert("tenant".into(), format!("t{}", i % 12));
            e.attrs.insert("_kind".into(), e.kind.label());
            e.valid_from = Some(1_000 + i);
            if i.is_multiple_of(7) {
                e.valid_to = Some(2_000 + i);
            }
            if i > 0 && i.is_multiple_of(5) {
                e.parents = vec![ulid_de((i - 1) as u128 * 0x1_0000_0001)];
            }
        }
        Perfil::Incompressivel => {
            e.agent_id = format!("a{}", rng.below(1_000_000));
            e.content = rng.bytes(180);
        }
        Perfil::Embeddings => {
            e.agent_id = "embedder".into();
            e.kind = EventKind::FactDerived;
            let f = |r: &mut Rng| (r.next() >> 40) as f32 / 16_777_216.0 - 0.5;
            let hyp: Vec<f32> = (0..16).map(|_| f(rng)).collect();
            let sph: Vec<f32> = (0..16).map(|_| f(rng)).collect();
            let euc: Vec<f32> = (0..32).map(|_| f(rng)).collect();
            e.embedding = Some(ProductPoint { hyp, sph, euc });
        }
        Perfil::AtributosAltaCardinalidade => {
            e.agent_id = format!("agent-{i}");
            e.session_id = format!("sess-{}", rng.next());
            e.kind = EventKind::Custom(format!("kind-{}", i % 97));
            for k in 0..6 {
                e.attrs
                    .insert(format!("attr-{k}-{}", i % 31), format!("{}", rng.next()));
            }
        }
        Perfil::PayloadGrande => {
            let n = 4_000 + rng.below(20_000) as usize;
            e.agent_id = "bulk".into();
            e.content = b"lorem ipsum dolor sit amet ".repeat(n / 27 + 1)[..n].to_vec();
        }
        Perfil::Cifrado => {
            // Conteúdo já cifrado no momento da persistência (§47): o packer
            // vê-o como bytes opacos e nunca decifra.
            e.agent_id = "vault".into();
            e.kind = EventKind::DemotionReceipt;
            let n = 96 + rng.below(64) as usize;
            e.content = rng.bytes(n);
            e.attrs.insert("enc".into(), "chacha20poly1305".into());
        }
    }
    e
}

/// Um registo do corpus, já na forma persistida.
struct Amostra {
    lsn: Lsn,
    hlc: u64,
    payload: Vec<u8>,
    hash: [u8; 32],
}

/// Gera `n` registos misturando os sete perfis.
///
/// O `payload` persistido é aqui a codificação canónica do registo. No motor a
/// sério é o `StoragePayload` em bincode; o que importa para estas propriedades
/// é que o packer o trate como **opaco** (§42) e que exista uma função
/// determinística de bytes persistidos para identidade lógica.
fn corpus(n: u64, first_lsn: Lsn, seed: u64) -> Vec<Amostra> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let perfil = PERFIS[(i % PERFIS.len() as u64) as usize];
        let ep = episodio(perfil, i, &mut rng);
        let lsn = first_lsn + i;
        let hlc = 1_700_000_000 + i * 3;
        let mut opaque_meta = [0u8; 16];
        opaque_meta[..8].copy_from_slice(&(i ^ 0xA5A5_A5A5).to_le_bytes());
        let rec = CanonicalRecordV1 {
            lsn,
            record_hlc: hlc,
            opaque_meta,
            episode: &ep,
        };
        out.push(Amostra {
            lsn,
            hlc,
            payload: canonical_record_bytes(&rec),
            hash: canonical_record_hash(&rec),
        });
    }
    out
}

/// O hasher que o packer recebe (§42): dos bytes persistidos para a identidade
/// lógica, sem conhecer o layout do payload.
fn hasher(_lsn: Lsn, _hlc: u64, payload: &[u8]) -> V6Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_CANONICAL_RECORD);
    h.update(payload);
    Ok(*h.finalize().as_bytes())
}

fn corpus_size() -> u64 {
    std::env::var("HRKL_V6_CORPUS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30_000)
}

fn dir_teste(nome: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hrkl6-props-{}-{nome}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn escreve_raw(path: &Path, amostras: &[Amostra]) -> heraclitus_log::v6::FooterV6 {
    let init = SegmentInit {
        segment_id: 4242,
        created_hlc: 1_700_000_000,
        first_lsn: amostras[0].lsn,
        writer_epoch: 1,
        storage_namespace_id: [0xC0; 16],
    };
    let mut w = RawSegmentWriter::create(path, init).unwrap();
    for a in amostras {
        w.append(a.lsn, a.hlc, &a.payload, &a.hash).unwrap();
    }
    w.seal().unwrap()
}

// ---------------------------------------------------------------------------
// Propriedades
// ---------------------------------------------------------------------------

#[test]
fn hash_do_corpus_bate_com_o_hasher_do_packer() {
    // Pré-condição de tudo o resto: as duas vias de calcular a identidade
    // lógica — a do writer, que tem o `Episode`, e a do packer, que só tem os
    // bytes persistidos — produzem o mesmo hash.
    for a in corpus(500, 1, 7) {
        assert_eq!(a.hash, hasher(a.lsn, a.hlc, &a.payload).unwrap());
    }
}

#[test]
fn raw_e_packed_decodificam_para_os_mesmos_registos_e_a_mesma_raiz() {
    let d = dir_teste("equivalencia");
    let raw = d.join("seg.hrkl");
    let packed = d.join("seg.g1.hrkl");
    let amostras = corpus(corpus_size(), 9_000_001, 11);
    let raw_footer = escreve_raw(&raw, &amostras);

    let out = pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

    // §164: RAW logical_root == PACKED logical_root.
    assert_eq!(out.footer.logical_root, raw_footer.logical_root);
    // §7.3: os digests físicos são diferentes, de propósito.
    assert_ne!(
        out.receipt.source_physical_digest,
        out.receipt.target_physical_digest
    );

    // §164: RAW decode == PACKED decode.
    let do_raw = scan_raw_segment(&raw).unwrap().records;
    let reader = open_packed(&packed, 1 << 26).unwrap();
    let mut c = ScanCounters::default();
    let do_packed = reader.scan_all(&mut c).unwrap();

    assert_eq!(do_raw.len(), amostras.len());
    assert_eq!(do_packed.len(), amostras.len());
    for ((r, p), a) in do_raw.iter().zip(&do_packed).zip(&amostras) {
        assert_eq!((r.lsn, r.hlc, &r.payload), (a.lsn, a.hlc, &a.payload));
        assert_eq!((p.0, p.1, &p.2), (a.lsn, a.hlc, &a.payload));
    }
}

#[test]
fn unpack_de_pack_devolve_x_logicamente_igual() {
    let d = dir_teste("unpack");
    let raw = d.join("seg.hrkl");
    let packed = d.join("seg.g1.hrkl");
    let amostras = corpus(corpus_size() / 3, 1_000, 23);
    escreve_raw(&raw, &amostras);
    pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

    let reader = open_packed(&packed, 1 << 26).unwrap();
    let mut c = ScanCounters::default();
    let lidos = reader.scan_all(&mut c).unwrap();
    for (got, a) in lidos.iter().zip(&amostras) {
        assert_eq!(got.2, a.payload, "payload alterado no lsn {}", a.lsn);
        assert_eq!(hasher(got.0, got.1, &got.2).unwrap(), a.hash);
    }
}

#[test]
fn codecs_e_block_sizes_diferentes_dao_a_mesma_raiz_logica() {
    // §164 "different physical codec same logical root" + §188 (repacking).
    let d = dir_teste("codecs");
    let raw = d.join("seg.hrkl");
    let amostras = corpus(corpus_size() / 3, 500_000, 31);
    let raw_footer = escreve_raw(&raw, &amostras);

    let variantes = [
        (PackingProfile::Fast, MIN_BLOCK_TARGET, 32u16),
        (PackingProfile::Balanced, 262_144, 64),
        (PackingProfile::Archive, MAX_BLOCK_TARGET, 128),
    ];
    let mut caminhos = Vec::new();
    for (i, (profile, block, restart)) in variantes.into_iter().enumerate() {
        let p = d.join(format!("seg.g{}.hrkl", i + 1));
        let opts = PackOptions {
            profile,
            block_target_bytes: block,
            restart_interval: restart,
            ..PackOptions::default()
        };
        let out = pack_segment(&raw, &p, opts, 0, (i + 1) as u32, &hasher).unwrap();
        assert_eq!(
            out.footer.logical_root, raw_footer.logical_root,
            "perfil {profile:?} mudou a identidade lógica"
        );
        caminhos.push(p);
    }
    // Cada variante organiza os bytes de maneira diferente...
    let contagens: Vec<usize> = caminhos
        .iter()
        .map(|p| open_packed(p, 1 << 26).unwrap().block_count())
        .collect();
    assert!(
        contagens[0] > contagens[2],
        "block sizes diferentes deviam dar contagens diferentes"
    );
    // ...e continua a ser a mesma verdade.
    for p in &caminhos {
        assert_eq!(
            open_packed(p, 1 << 26).unwrap().logical_root(),
            raw_footer.logical_root
        );
    }
}

#[test]
fn repack_de_repack_preserva_a_raiz() {
    // §164: pack(pack(x)) é logicamente equivalente a pack(x).
    let d = dir_teste("repack2");
    let raw = d.join("seg.hrkl");
    let amostras = corpus(corpus_size() / 5, 77, 41);
    let raw_footer = escreve_raw(&raw, &amostras);

    let g1 = d.join("seg.g1.hrkl");
    pack_segment(&raw, &g1, PackOptions::default(), 0, 1, &hasher).unwrap();
    let g2 = d.join("seg.g2.hrkl");
    let opts = PackOptions {
        profile: PackingProfile::Archive,
        block_target_bytes: MAX_BLOCK_TARGET,
        ..PackOptions::default()
    };
    repack_segment(&g1, &g2, opts, 1, 2, &hasher).unwrap();
    let g3 = d.join("seg.g3.hrkl");
    repack_segment(&g2, &g3, PackOptions::default(), 2, 3, &hasher).unwrap();

    for p in [&g1, &g2, &g3] {
        assert_eq!(
            open_packed(p, 1 << 26).unwrap().logical_root(),
            raw_footer.logical_root
        );
    }
    // §190: repacking não é compactação lógica — nenhum registo desapareceu.
    let mut c = ScanCounters::default();
    assert_eq!(
        open_packed(&g3, 1 << 26)
            .unwrap()
            .scan_all(&mut c)
            .unwrap()
            .len(),
        amostras.len()
    );
}

#[test]
fn pruning_nunca_produz_falso_negativo() {
    // §170/invariante 8: `pruner false -> definitely cannot match`. Um único
    // falso negativo esconderia registos que existem.
    let d = dir_teste("pruning");
    let raw = d.join("seg.hrkl");
    let packed = d.join("seg.g1.hrkl");
    let amostras = corpus(corpus_size() / 3, 4_000_000, 53);
    escreve_raw(&raw, &amostras);
    let opts = PackOptions {
        block_target_bytes: MIN_BLOCK_TARGET,
        ..PackOptions::default()
    };
    pack_segment(&raw, &packed, opts, 0, 1, &hasher).unwrap();

    let reader = open_packed(&packed, 1 << 26).unwrap();
    assert!(reader.block_count() > 4, "o teste precisa de vários blocos");

    // Todo o registo que existe tem de ser encontrado pelo point lookup...
    let mut rng = Rng::new(99);
    for _ in 0..300 {
        let a = &amostras[rng.below(amostras.len() as u64) as usize];
        let mut c = ScanCounters::default();
        let got = reader.get(a.lsn, &mut c).unwrap();
        let (hlc, payload) = got.unwrap_or_else(|| panic!("falso negativo no lsn {}", a.lsn));
        assert_eq!(hlc, a.hlc);
        assert_eq!(payload, a.payload);
        // §157: no máximo um bloco descomprimido.
        assert_eq!(c.blocks_read, 1);
    }

    // ...e todo o intervalo tem de devolver exactamente os registos do intervalo.
    for _ in 0..40 {
        let lo_i = rng.below(amostras.len() as u64);
        let hi_i = (lo_i + 1 + rng.below(500)).min(amostras.len() as u64 - 1);
        let (lo, hi) = (amostras[lo_i as usize].lsn, amostras[hi_i as usize].lsn);
        let mut c = ScanCounters::default();
        let hits = reader.scan_lsn_range(lo, hi, &mut c).unwrap();
        let esperados: Vec<&Amostra> = amostras
            .iter()
            .filter(|a| a.lsn >= lo && a.lsn <= hi)
            .collect();
        assert_eq!(
            hits.len(),
            esperados.len(),
            "intervalo [{lo},{hi}] perdeu registos"
        );
        for (got, want) in hits.iter().zip(esperados) {
            assert_eq!(got.0, want.lsn);
            assert_eq!(got.2, want.payload);
        }
    }

    // E os zone maps de HLC também são conservadores.
    for e in &reader.directory.entries {
        for a in amostras
            .iter()
            .filter(|a| a.lsn >= e.first_lsn && a.lsn <= e.last_lsn)
        {
            assert!(
                e.may_contain_hlc_range(a.hlc, a.hlc),
                "zone map do bloco excluiu um HLC que ele contém ({})",
                a.hlc
            );
        }
    }
}

#[test]
fn verificacao_logica_fecha_nos_dois_layouts() {
    let d = dir_teste("verify");
    let raw = d.join("seg.hrkl");
    let packed = d.join("seg.g1.hrkl");
    let amostras = corpus(corpus_size() / 4, 12_345, 61);
    escreve_raw(&raw, &amostras);
    pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

    for p in [&raw, &packed] {
        let r = verify_segment(p, IntegrityLevel::Forensic, 1 << 26, Some(&hasher)).unwrap();
        assert!(r.is_ok(), "{p:?} falhou: {:?}", r.notes);
        assert_eq!(r.recomputed_root, Some(r.declared_root));
        assert_eq!(r.record_count, amostras.len() as u64);
    }
}

#[test]
fn compressao_no_corpus_operacional() {
    // §154: nada de promessas universais. Mede-se no corpus e reporta-se. O
    // gate duro que este teste faz cumprir é o de §155 — dados incompressíveis
    // não podem crescer mais de 2%.
    let d = dir_teste("gates");
    for perfil in PERFIS {
        let mut rng = Rng::new(perfil as u64 + 1);
        let n = 4_000u64;
        let amostras: Vec<Amostra> = (0..n)
            .map(|i| {
                let ep = episodio(perfil, i, &mut rng);
                let lsn = 1 + i;
                let hlc = 1_700_000_000 + i * 3;
                let rec = CanonicalRecordV1 {
                    lsn,
                    record_hlc: hlc,
                    opaque_meta: [0u8; 16],
                    episode: &ep,
                };
                Amostra {
                    lsn,
                    hlc,
                    payload: canonical_record_bytes(&rec),
                    hash: canonical_record_hash(&rec),
                }
            })
            .collect();
        let sub = d.join(format!("{perfil:?}"));
        std::fs::create_dir_all(&sub).unwrap();
        let raw = sub.join("seg.hrkl");
        let packed = sub.join("seg.g1.hrkl");
        escreve_raw(&raw, &amostras);
        let out = pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

        let logico: u64 = amostras.iter().map(|a| a.payload.len() as u64).sum();
        let ratio_fisico = out.receipt.target_physical_size as f64 / logico as f64;
        println!(
            "{perfil:?}: logico {logico} B, packed {} B, ratio {:.3}",
            out.receipt.target_physical_size, ratio_fisico
        );
        if perfil == Perfil::Incompressivel || perfil == Perfil::Cifrado {
            assert!(
                ratio_fisico <= 1.02,
                "§155: {perfil:?} expandiu {:.4}x, acima do tecto de 2%",
                ratio_fisico
            );
        }
    }
}

#[test]
fn overhead_de_metadados_cai_pelo_menos_60_porcento() {
    // §156, medido como a SPEC pede: metadados FÍSICOS por registo em carga
    // contígua e monotónica, sem contar com a compressão do payload.
    let d = dir_teste("metadados");
    let raw = d.join("seg.hrkl");
    let packed = d.join("seg.g1.hrkl");
    let amostras = corpus(20_000, 1, 71);
    escreve_raw(&raw, &amostras);
    // `raw_fallback_ratio = 0.0` desliga a compressão para isolar o overhead
    // estrutural — é essa a grandeza que §156 compara com os 24 bytes do RAW.
    let opts = PackOptions {
        raw_fallback_ratio: 0.0,
        ..PackOptions::default()
    };
    pack_segment(&raw, &packed, opts, 0, 1, &hasher).unwrap();

    let reader = open_packed(&packed, 1 << 26).unwrap();
    let logico: u64 = amostras.iter().map(|a| a.payload.len() as u64).sum();
    let fisico = reader.directory.total_uncompressed_bytes();
    let por_registo = (fisico - logico) as f64 / amostras.len() as f64;
    println!("overhead PACKED: {por_registo:.2} B/registo (RAW: 24.00)");
    assert!(
        por_registo <= 24.0 * 0.4,
        "§156: {por_registo:.2} B/registo não é uma redução de 60% face a 24"
    );
}

#[test]
fn input_malformado_nunca_entra_em_panico() {
    // §163: os decoders são alvos de fuzzing. Aqui é uma varredura
    // determinística de mutações; o fuzzer a sério vive em `fuzz/`.
    let d = dir_teste("malformado");
    let raw = d.join("seg.hrkl");
    let packed = d.join("seg.g1.hrkl");
    let amostras = corpus(2_000, 900, 83);
    escreve_raw(&raw, &amostras);
    pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

    for origem in [&raw, &packed] {
        let bons = std::fs::read(origem).unwrap();
        let mut rng = Rng::new(1234);
        let alvo = d.join("mutante.hrkl");

        for _ in 0..400 {
            let mut bytes = bons.clone();
            // Uma a quatro mutações por iteração, em sítios arbitrários.
            for _ in 0..=rng.below(4) {
                let at = rng.below(bytes.len() as u64) as usize;
                bytes[at] ^= (rng.next() % 255 + 1) as u8;
            }
            // E, de vez em quando, um truncamento.
            if rng.below(4) == 0 {
                let n = rng.below(bytes.len() as u64) as usize;
                bytes.truncate(n);
            }
            let _ = std::fs::remove_file(&alvo);
            std::fs::write(&alvo, &bytes).unwrap();

            // Nenhuma destas chamadas pode entrar em panico, fazer overflow ou
            // alocar sem limite; devolver `Err` é o comportamento correcto.
            let _ = scan_raw_segment(&alvo);
            let _ = open_packed(&alvo, 1 << 26).map(|r| {
                let mut c = ScanCounters::default();
                let _ = r.scan_all(&mut c);
                let _ = r.get(1_000, &mut c);
            });
            let _ = verify_segment(&alvo, IntegrityLevel::Logical, 1 << 26, Some(&hasher));
        }

        // E os decoders puros, alimentados com lixo directo.
        let mut rng = Rng::new(4321);
        for n in [0usize, 1, 4, 23, 24, 25, 64, 128, 200] {
            let _ = decode_raw_record(&rng.bytes(n));
            let _ = decode_raw_record(&vec![0xffu8; n]);
            let _ = decode_raw_record(&vec![0u8; n]);
        }
    }
}

#[test]
fn opaque_meta_faz_parte_da_identidade_em_todo_o_corpus() {
    // §8: se `opaque_meta` afecta recuperação, indexação ou semântica interna,
    // modificá-lo tem de alterar a identidade lógica.
    let mut rng = Rng::new(5);
    for perfil in PERFIS {
        let ep = episodio(perfil, 3, &mut rng);
        let a = CanonicalRecordV1 {
            lsn: 1,
            record_hlc: 2,
            opaque_meta: [0u8; 16],
            episode: &ep,
        };
        let b = CanonicalRecordV1 {
            lsn: 1,
            record_hlc: 2,
            opaque_meta: [1u8; 16],
            episode: &ep,
        };
        assert_ne!(
            canonical_record_hash(&a),
            canonical_record_hash(&b),
            "{perfil:?}"
        );
    }
}

#[test]
fn identidade_logica_e_independente_da_ordem_de_construcao_dos_attrs() {
    // §12: `attrs` sai por ordem lexicográfica. Inserir pela ordem inversa não
    // pode mudar a identidade.
    let mut a = episodio(Perfil::MedioRealista, 9, &mut Rng::new(2));
    let mut b = a.clone();
    a.attrs.clear();
    b.attrs.clear();
    let pares = [("zeta", "1"), ("alfa", "2"), ("mu", "3"), ("beta", "4")];
    for (k, v) in pares {
        a.attrs.insert(k.into(), v.into());
    }
    for (k, v) in pares.iter().rev() {
        b.attrs.insert((*k).into(), (*v).into());
    }
    let ra = CanonicalRecordV1 {
        lsn: 1,
        record_hlc: 1,
        opaque_meta: [0u8; 16],
        episode: &a,
    };
    let rb = CanonicalRecordV1 {
        lsn: 1,
        record_hlc: 1,
        opaque_meta: [0u8; 16],
        episode: &b,
    };
    assert_eq!(canonical_record_hash(&ra), canonical_record_hash(&rb));
}

#[test]
fn ordem_dos_parents_e_significativa() {
    // §13: o v1 NÃO reordena parents. Trocar a ordem muda a identidade — e é
    // por isso que declarar a ordem irrelevante exigiria um codec novo.
    let mut a = episodio(Perfil::MedioRealista, 10, &mut Rng::new(3));
    a.parents = vec![ulid_de(1), ulid_de(2)];
    let mut b = a.clone();
    b.parents.reverse();
    let ra = CanonicalRecordV1 {
        lsn: 1,
        record_hlc: 1,
        opaque_meta: [0u8; 16],
        episode: &a,
    };
    let rb = CanonicalRecordV1 {
        lsn: 1,
        record_hlc: 1,
        opaque_meta: [0u8; 16],
        episode: &b,
    };
    assert_ne!(canonical_record_hash(&ra), canonical_record_hash(&rb));
}
