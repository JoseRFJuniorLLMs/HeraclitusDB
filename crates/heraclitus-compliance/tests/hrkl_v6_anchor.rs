//! Compliance sobre HRKL v6 — ancoragem pela raiz **lógica** canónica.
//!
//! Até aqui o worker de compliance só sabia falar com o `Log` legado, e o
//! servidor recusava arrancar em `storage_format = "v6"` com ancoragem ligada.
//! A recusa era honesta (melhor falhar fechado do que fingir garantias), mas
//! não era necessária: o compromisso é uma Merkle sobre as raízes dos segmentos
//! selados, e ambos os backends publicam essas raízes no `DatabaseManifest`.
//!
//! O que muda com o v6 é *qual* raiz é dobrada, e isso não é um detalhe:
//!
//! | | raiz do segmento | sobrevive a repack? |
//! |---|---|---|
//! | v1--v5 | Merkle **física** dos bytes do ficheiro | não |
//! | HRKL v6 | raiz **lógica** canónica (§7.2) | sim |
//!
//! Um recibo notarizado sob o esquema legado é invalidado por um repack — os
//! bytes físicos mudam, a raiz muda, e a reverificação acusa "log alterado
//! retroativamente" sobre uma história que não mudou uma linha. Sob o v6 isso
//! não acontece, e é essa a propriedade que o último teste deste ficheiro
//! prova.

use heraclitus_compliance::commit::{commit_at, current_watermark, CommitmentDomain};
use heraclitus_compliance::{anchor, verify_receipt, LocalTsa, ReceiptVerification};
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::v6::{PackingProfile, V6Log};

fn banco(dir: &std::path::Path, n: usize) -> V6Log {
    let log = V6Log::open(dir, 4_096, FsyncPolicy::Always).unwrap();
    for i in 0..n {
        log.append(Episode::new(
            "compliance",
            EventKind::Observation,
            format!("evento-{i}-{}", "q".repeat(64)).into_bytes(),
        ))
        .unwrap();
    }
    log.seal_active().unwrap();
    log
}

/// O compromisso em v6 existe, cobre os segmentos selados e é reproduzível.
#[test]
fn o_compromisso_v6_cobre_os_selados_e_e_reproduzivel() {
    let dir = tempfile::tempdir().unwrap();
    let log = banco(dir.path(), 200);

    let wm = current_watermark(&log);
    assert!(wm > 0, "nada selado; o teste não prova nada");

    let c1 = commit_at(&log, wm);
    let c2 = commit_at(&log, wm);
    assert_eq!(c1, c2, "o compromisso tem de ser reproduzível");
    assert_eq!(c1.domain, CommitmentDomain::V6Logical);
    assert!(c1.segments > 0);
    assert_ne!(c1.root, [0; 32]);

    // Um watermark diferente é um compromisso diferente.
    let anterior = commit_at(&log, wm / 2);
    assert_ne!(anterior.root, c1.root);
    assert_ne!(
        anterior.message_imprint_sha256(),
        c1.message_imprint_sha256()
    );
}

/// Os dois domínios nunca colidem.
///
/// Se as raízes fossem dobradas sob o mesmo separador, um verificador que
/// aplicasse o esquema errado obteria um imprint plausível — e a diferença
/// entre "prova válida" e "prova de outro formato" deixaria de ser exprimível.
#[test]
fn o_dominio_legado_e_o_dominio_v6_nunca_produzem_o_mesmo_imprint() {
    use heraclitus_compliance::commit::Commitment;
    let base = Commitment {
        lsn: 1_000,
        root: [0x5A; 32],
        segments: 4,
        domain: CommitmentDomain::LegacyPhysical,
    };
    let v6 = Commitment {
        domain: CommitmentDomain::V6Logical,
        ..base
    };
    assert_ne!(base.message_imprint_sha256(), v6.message_imprint_sha256());
    assert_eq!(base.domain.as_str(), "legacy-physical");
    assert_eq!(v6.domain.as_str(), "hrkl-v6-logical");
}

/// Ancorar e reverificar, ponta a ponta, sobre um banco v6.
#[test]
fn ancorar_e_verificar_um_recibo_v6() {
    let dir = tempfile::tempdir().unwrap();
    let log = banco(dir.path(), 200);
    let recibos = dir.path().join("receipts");
    let tsa = LocalTsa::generate("teste-v6");

    let recibo = anchor(&log, &tsa, &recibos, None).unwrap();
    assert!(recibo.lsn > 0);
    assert!(recibo.segments > 0);
    assert_eq!(
        recibo.commitment_domain, "hrkl-v6-logical",
        "o recibo tem de dizer que raízes dobrou"
    );

    match verify_receipt(&log, &recibos, &recibo).unwrap() {
        ReceiptVerification::DevelopmentOnly(_) => {}
        outro => panic!("esperava um token de desenvolvimento verificado, veio {outro:?}"),
    }
}

/// A propriedade que justifica migrar o compliance para o v6.
///
/// Empacotar um segmento substitui os seus bytes físicos por outros — mesma
/// história, representação nova. Sob o esquema legado isso mudaria a raiz e a
/// reverificação de um recibo já emitido falharia, acusando adulteração de uma
/// história intacta. Sob o v6, a raiz lógica é invariante entre RAW e PACKED,
/// portanto o recibo continua a verificar.
#[test]
fn um_repack_nao_invalida_um_recibo_ja_emitido() {
    let dir = tempfile::tempdir().unwrap();
    let log = banco(dir.path(), 200);
    let recibos = dir.path().join("receipts");
    let tsa = LocalTsa::generate("teste-v6");

    // Recibo emitido enquanto os segmentos ainda são RAW.
    let recibo = anchor(&log, &tsa, &recibos, None).unwrap();
    let antes = commit_at(&log, recibo.lsn);

    // Empacotar: os bytes físicos de cada segmento passam a ser outros.
    let empacotados = log.pack_pending(PackingProfile::Balanced).unwrap();
    assert!(!empacotados.is_empty(), "nada foi empacotado");
    assert!(
        empacotados
            .iter()
            .any(|o| o.receipt.target_physical_size != o.receipt.source_physical_size),
        "o packing não mudou nenhum tamanho físico; o teste seria vácuo"
    );

    let depois = commit_at(&log, recibo.lsn);
    assert_eq!(
        antes, depois,
        "a raiz lógica mudou com o packing — a promessa de §7.2 estaria quebrada"
    );
    assert!(
        matches!(
            verify_receipt(&log, &recibos, &recibo).unwrap(),
            ReceiptVerification::DevelopmentOnly(_)
        ),
        "o recibo deixou de verificar depois de um repack"
    );
}
