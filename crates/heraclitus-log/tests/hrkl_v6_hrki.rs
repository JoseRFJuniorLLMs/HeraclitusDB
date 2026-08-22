//! SPEC-0050 §54–§67, Fase 4 — o sidecar `.hrki` sobre um segmento PACKED real.
//!
//! Os testes unitários em `v6::hrki` cobrem o formato e as invariantes de
//! privacidade. Este ficheiro cobre a coisa que interessa a quem usa: escrever
//! um segmento a sério, empacotá-lo, construir o sidecar a partir do PACKED
//! publicado, e confirmar que o pruning elimina os blocos certos **sem nunca
//! eliminar um bloco que interessa**.
//!
//! A propriedade central é assimétrica e vale a pena ser explícita:
//!
//! * eliminar um bloco a mais é um **bug de correção** — a query devolve menos
//!   linhas do que existem, em silêncio;
//! * eliminar um bloco a menos é apenas trabalho desperdiçado.
//!
//! Por isso os testes verificam sempre os dois lados: que o conjunto podado
//! contém tudo o que devia, e que é estritamente menor que o total.

use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::v6::canonical::{canonical_record_hash, CanonicalRecordV1};
use heraclitus_log::v6::hrki::{
    construir_para_packed, caminho_sidecar, Hrki, IndexPolicy, IndexPolicySet,
};
use heraclitus_log::v6::packed::{open_packed, PackOptions};
use heraclitus_log::v6::packer::pack_segment;
use heraclitus_log::v6::raw::{RawSegmentWriter, SegmentInit};
use std::path::{Path, PathBuf};

const MAX_BLOCK: usize = 1 << 20;

fn evento(i: u64) -> Episode {
    let uf = if i % 3 == 0 { "SP" } else { "RJ" };
    let mut e = Episode::new(
        "ag",
        EventKind::Custom(if i < 200 { "Contrato" } else { "Licitacao" }.into()),
        format!("payload-{i}-{}", "x".repeat(64)).into_bytes(),
    );
    e.attrs.insert("uf".into(), uf.into());
    e.attrs.insert("cpf".into(), format!("cpf-{i}"));
    e.valid_from = Some(10_000 + i);
    e
}

fn escrever_raw(dir: &Path, n: u64) -> PathBuf {
    let p = dir.join("00000000000000000001.hrkl");
    let mut w = RawSegmentWriter::create(
        &p,
        SegmentInit {
            segment_id: 1,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [5u8; 16],
        },
    )
    .unwrap();
    for i in 0..n {
        let ep = evento(i);
        let opaque = ep.id.0.to_bytes();
        let h = canonical_record_hash(&CanonicalRecordV1 {
            lsn: i,
            record_hlc: 1_000 + i,
            opaque_meta: opaque,
            episode: &ep,
        });
        let payload = serde_json::to_vec(&ep).unwrap();
        w.append(i, 1_000 + i, &payload, &h).unwrap();
    }
    w.seal().unwrap();
    p
}

fn empacotar(dir: &Path, raw: &Path) -> PathBuf {
    let packed = dir.join("00000000000000000001.g2.hrkl");
    let opts = PackOptions {
        block_target_bytes: 4 * 1024,
        ..Default::default()
    };
    // O packer recalcula o hash canónico de cada registo para reconferir a
    // `logical_root` do PACKED contra a do RAW antes de publicar (§88).
    pack_segment(raw, &packed, opts, 1, 2, &|lsn, hlc, payload| {
        let ep: Episode = serde_json::from_slice(payload)
            .map_err(|e| heraclitus_core::HeraclitusError::Serialization(e.to_string()))?;
        Ok(canonical_record_hash(&CanonicalRecordV1 {
            lsn,
            record_hlc: hlc,
            opaque_meta: ep.id.0.to_bytes(),
            episode: &ep,
        }))
    })
    .expect("pack");
    packed
}

fn politica() -> IndexPolicySet {
    IndexPolicySet::new()
        .com("uf", IndexPolicy::PublicTechnical)
        .com("cpf", IndexPolicy::HashedEquality)
}

fn decodificador() -> impl Fn(&[u8]) -> Option<Episode> {
    |b: &[u8]| serde_json::from_slice::<Episode>(b).ok()
}

#[test]
fn sidecar_poda_blocos_sem_nunca_perder_um_que_interessa() {
    let dir = tempfile::tempdir().unwrap();
    let raw = escrever_raw(dir.path(), 400);
    let packed = empacotar(dir.path(), &raw);

    let h = construir_para_packed(
        &packed,
        &politica(),
        Some([7u8; 32]),
        0.01,
        MAX_BLOCK,
        &decodificador(),
    )
    .expect("construir hrki");

    let reader = open_packed(&packed, MAX_BLOCK).unwrap();
    let total = reader.block_count();
    assert!(total > 3, "o teste precisa de varios blocos; houve {total}");
    assert_eq!(h.zonas.len(), total, "uma zona por bloco");

    // Para cada janela de LSN, o conjunto podado TEM de conter todos os blocos
    // que realmente contêm algum LSN da janela.
    for (de, ate) in [(0u64, 50u64), (100, 140), (390, 400), (0, 400)] {
        let podados = h.blocos_para_lsn(de, ate);
        for (i, e) in reader.directory.entries.iter().enumerate() {
            let intersecta = de <= e.last_lsn && e.first_lsn < ate;
            if intersecta {
                assert!(
                    podados.contains(&i),
                    "janela [{de},{ate}) perdeu o bloco {i} (lsn {}..{})",
                    e.first_lsn,
                    e.last_lsn
                );
            }
        }
    }

    // E numa janela estreita tem de podar mesmo alguma coisa, senão o sidecar
    // não está a servir para nada.
    let estreita = h.blocos_para_lsn(0, 20);
    assert!(
        estreita.len() < total,
        "janela estreita nao podou nada: {} de {total}",
        estreita.len()
    );
}

#[test]
fn pruning_por_kind_elimina_o_segmento_inteiro_quando_pode() {
    let dir = tempfile::tempdir().unwrap();
    let raw = escrever_raw(dir.path(), 300);
    let packed = empacotar(dir.path(), &raw);
    let h = construir_para_packed(
        &packed,
        &politica(),
        Some([7u8; 32]),
        0.01,
        MAX_BLOCK,
        &decodificador(),
    )
    .unwrap();

    assert!(h.talvez_contenha_kind(&EventKind::Custom("Contrato".into())));
    assert!(h.talvez_contenha_kind(&EventKind::Custom("Licitacao".into())));
    // Um kind que nunca foi escrito: o segmento inteiro pode ser saltado.
    assert!(!h.talvez_contenha_kind(&EventKind::Custom("NaoExiste".into())));
    assert!(!h.talvez_contenha_kind(&EventKind::Action));
}

#[test]
fn filtro_de_igualdade_serve_o_campo_publico_e_esconde_o_sensivel() {
    let dir = tempfile::tempdir().unwrap();
    let raw = escrever_raw(dir.path(), 120);
    let packed = empacotar(dir.path(), &raw);
    construir_para_packed(
        &packed,
        &politica(),
        Some([7u8; 32]),
        0.01,
        MAX_BLOCK,
        &decodificador(),
    )
    .unwrap();

    let bytes = std::fs::read(caminho_sidecar(&packed)).unwrap();

    // §64: nenhum CPF em claro no sidecar.
    for i in 0..120u64 {
        let agulha = format!("cpf-{i}");
        assert!(
            bytes
                .windows(agulha.len())
                .all(|w| w != agulha.as_bytes()),
            "o valor sensivel '{agulha}' apareceu em claro no .hrki"
        );
    }

    let h = Hrki::decode(&bytes).unwrap();
    assert!(h.talvez_contenha("uf", b"SP"));
    assert!(h.talvez_contenha("uf", b"RJ"));
    assert!(!h.talvez_contenha("uf", b"ZZ"), "uf inexistente devia podar");
}

#[test]
fn sidecar_desactualizado_e_ignorado_e_nao_estraga_o_segmento() {
    // §56: a regra que impede um sidecar mau de parecer corrupção do .hrkl.
    let dir = tempfile::tempdir().unwrap();
    let raw = escrever_raw(dir.path(), 80);
    let packed = empacotar(dir.path(), &raw);
    construir_para_packed(
        &packed,
        &politica(),
        Some([7u8; 32]),
        0.01,
        MAX_BLOCK,
        &decodificador(),
    )
    .unwrap();

    let reader = open_packed(&packed, MAX_BLOCK).unwrap();
    let raiz = reader.logical_root();

    // Com a raiz certa, é aceite.
    assert!(Hrki::ler_validado(&packed, 1, &raiz).is_some());

    // Corrompe o sidecar de alto a baixo: continua a ser ignorado, sem erro,
    // e o segmento continua legível.
    std::fs::write(caminho_sidecar(&packed), b"isto nao e um hrki").unwrap();
    assert!(Hrki::ler_validado(&packed, 1, &raiz).is_none());

    let mut c = Default::default();
    let todos = reader.scan_all(&mut c).expect("o .hrkl continua legivel");
    assert_eq!(todos.len(), 80, "o segmento nao pode ser afectado");

    // Apagar o sidecar também é legítimo — é descartável (§54).
    std::fs::remove_file(caminho_sidecar(&packed)).unwrap();
    assert!(Hrki::ler_validado(&packed, 1, &raiz).is_none());
    let mut c = Default::default();
    assert_eq!(reader.scan_all(&mut c).unwrap().len(), 80);
}

#[test]
fn pruning_por_valid_time_e_conservador() {
    let dir = tempfile::tempdir().unwrap();
    let raw = escrever_raw(dir.path(), 200);
    let packed = empacotar(dir.path(), &raw);
    let h = construir_para_packed(
        &packed,
        &politica(),
        Some([7u8; 32]),
        0.01,
        MAX_BLOCK,
        &decodificador(),
    )
    .unwrap();

    // Todos os eventos têm valid_from = 10_000 + i e valid_to = None, portanto
    // ficam abertos: nenhum instante futuro pode ser excluído.
    assert_eq!(
        h.blocos_validos_em(u64::MAX).len(),
        h.zonas.len(),
        "com intervalos abertos, nada pode ser podado no futuro"
    );
    // Antes do primeiro valid_from de todos, alguma coisa tem de ser podada.
    let cedo = h.blocos_validos_em(0);
    assert!(
        cedo.len() < h.zonas.len(),
        "instante anterior a todos os valid_from devia podar"
    );
}

/// O `.hrki` não é obrigatório para ler o segmento (§54). Este teste existe
/// para fixar isso: um leitor que nunca ouviu falar de sidecars funciona.
#[test]
fn packed_e_totalmente_legivel_sem_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let raw = escrever_raw(dir.path(), 150);
    let packed = empacotar(dir.path(), &raw);
    assert!(!caminho_sidecar(&packed).exists(), "ainda nao ha sidecar");

    let reader = open_packed(&packed, MAX_BLOCK).unwrap();
    let mut c = Default::default();
    let todos = reader.scan_all(&mut c).unwrap();
    assert_eq!(todos.len(), 150);
    let lsns: Vec<Lsn> = todos.iter().map(|(l, _, _)| *l).collect();
    assert_eq!(lsns.first(), Some(&0));
    assert_eq!(lsns.last(), Some(&149));
}
