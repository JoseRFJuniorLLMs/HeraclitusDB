//! SPEC-0050 §129–§133 — migração de uma **base** v1–v5 para HRKL v6.
//!
//! Os testes unitários de `v6::migrate` cobrem um segmento de cada vez: cada
//! versão do formato, `opaque_meta`, cauda rasgada, não sobrescrever o alvo.
//! Nenhum deles prova a única coisa que faz a migração servir para alguma
//! coisa — que **uma base escrita pelo motor legado real se abre depois pelo
//! motor v6 real, com a mesma história lá dentro**.
//!
//! É a diferença entre ter as peças e ter o caminho. Antes disto, a biblioteca
//! de migração tinha 9 testes a passar e zero chamadores: nenhuma instalação
//! existente conseguia adoptar o v6, porque não havia nada que migrasse uma
//! base inteira.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
use heraclitus_log::v6::{migrate_database, MigrateDatabaseOptions, V6Log};
use heraclitus_log::Log;

const N: u64 = 400;
const SEGMENT_BYTES: u64 = 8 * 1024;

fn conteudo(i: u64) -> Vec<u8> {
    format!("evento-legado-{i}-{}", "m".repeat(48)).into_bytes()
}

/// Uma base legada real, escrita pelo `Log` de produção.
///
/// Deliberadamente **não** se fabricam bytes à mão: o que interessa migrar são
/// os `.hrkl` que o motor legado escreve, com os seus `StoragePayload`, o seu
/// HLC e os seus rodapés Merkle. Um teste que serializasse à mão provaria o
/// formato errado.
///
/// O estado que sai daqui é o **realista**, não um construído: o log legado
/// sela um segmento quando ele rola, portanto uma base fechada tem sempre
/// vários segmentos selados **e uma cauda activa sem rodapé**. Não há API
/// pública para selar a cauda, e forçar um estado "tudo selado" seria testar
/// uma configuração que nenhuma instalação real tem.
fn base_legada(dir: &std::path::Path) -> Vec<(Lsn, Episode)> {
    let log = Log::open(dir, SEGMENT_BYTES, FsyncPolicy::Always).unwrap();
    for i in 0..N {
        let mut ep = Episode::new("legado", EventKind::Observation, conteudo(i));
        ep.attrs
            .insert("uf".into(), if i % 2 == 0 { "SP" } else { "BA" }.into());
        log.append(ep).unwrap();
    }
    log.flush().unwrap();
    let head = log.head();
    let esperado = log.scan(0, head).unwrap();
    assert_eq!(esperado.len() as u64, N);
    drop(log);
    esperado
}

/// O caminho completo: base legada → migrar → abrir em v6 → ler tudo.
#[test]
fn uma_base_legada_migra_e_abre_como_v6_com_a_mesma_historia() {
    let dir = tempfile::tempdir().unwrap();
    let legado = dir.path().join("legacy");
    let v6 = dir.path().join("v6");
    let esperado = base_legada(&legado);

    let relatorio = migrate_database(&legado, &v6, MigrateDatabaseOptions::default()).unwrap();
    assert!(relatorio.is_clean(), "{relatorio:?}");
    assert_eq!(relatorio.records, N);
    assert!(
        relatorio.segments.len() >= 2,
        "o teste precisa de vários segmentos; saiu {}",
        relatorio.segments.len()
    );
    assert!(relatorio.manifest_generation > 0, "o HRKM não foi comitado");

    // Cada segmento traz um recibo persistido com as DUAS raízes (§132).
    let ultimo = relatorio.segments.len() - 1;
    for (i, s) in relatorio.segments.iter().enumerate() {
        assert!(s.receipt_path.exists(), "recibo não ficou em disco: {s:?}");
        assert_ne!(
            s.receipt.legacy_root, s.receipt.v6_logical_root,
            "§131: a raiz legada e a raiz lógica v6 são conceitos diferentes e \
             não podem coincidir por construção"
        );
        assert!(s.equivalence.as_ref().unwrap().equivalente);
        let relido = heraclitus_log::v6::read_migration_receipt(&s.receipt_path).unwrap();
        assert_eq!(relido, s.receipt, "o recibo não faz round-trip pelo disco");

        // A confrontação de raízes só é possível onde havia uma raiz gravada.
        // Um segmento SELADO tem rodapé, e a sua raiz recomputada tem de bater
        // com a gravada; a CAUDA activa não tem rodapé nenhum, e `None` é a
        // única resposta honesta — inventar `Some(true)` para ela seria afirmar
        // uma confrontação que nunca aconteceu.
        if i == ultimo {
            assert_eq!(
                s.legacy_root_ok, None,
                "a cauda activa não tem raiz legada com que confrontar"
            );
        } else {
            assert_eq!(
                s.legacy_root_ok,
                Some(true),
                "o segmento selado {} tem raiz gravada divergente da recomputada",
                s.segment_id
            );
        }
    }

    // O que interessa: a base v6 abre e devolve a mesma história.
    let novo = V6Log::open(&v6, 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(novo.head(), esperado.last().unwrap().0 + 1);
    let lido = novo.scan(0, novo.head()).unwrap();
    assert_eq!(lido.len(), esperado.len(), "contagem de registos mudou");
    for ((lsn_a, a), (lsn_b, b)) in esperado.iter().zip(&lido) {
        assert_eq!(lsn_a, lsn_b);
        assert_eq!(a.id, b.id, "EventId mudou no LSN {lsn_a}");
        assert_eq!(a.content, b.content);
        assert_eq!(a.attrs, b.attrs);
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.parents, b.parents);
    }

    // E continua a ser um banco vivo: aceita escritas novas em v6.
    let antes = novo.head();
    novo.append(Episode::new(
        "pos-migracao",
        EventKind::Action,
        b"novo".to_vec(),
    ))
    .unwrap();
    assert_eq!(novo.head(), antes + 1);
}

/// §133 — a origem legada nunca é tocada.
///
/// É o item com mais consequências da migração inteira: pode haver um carimbo
/// RFC 3161, uma assinatura ou uma perícia a apontar para o hash antigo. Uma
/// migração que "arrumasse" o legado destruiria prova.
#[test]
fn a_base_legada_fica_byte_a_byte_intacta() {
    let dir = tempfile::tempdir().unwrap();
    let legado = dir.path().join("legacy");
    let v6 = dir.path().join("v6");
    base_legada(&legado);

    let antes: Vec<(String, Vec<u8>)> = std::fs::read_dir(&legado)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();

    migrate_database(&legado, &v6, MigrateDatabaseOptions::default()).unwrap();

    let depois: Vec<(String, Vec<u8>)> = std::fs::read_dir(&legado)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();

    assert_eq!(
        antes.len(),
        depois.len(),
        "o número de ficheiros legados mudou"
    );
    let mut a = antes;
    let mut b = depois;
    a.sort();
    b.sort();
    assert_eq!(a, b, "a migração alterou a base legada");
}

/// §130 — a cauda activa legada sai selada, e não continua a receber v6.
#[test]
fn a_cauda_activa_legada_e_selada_e_nao_prolongada() {
    let dir = tempfile::tempdir().unwrap();
    let legado = dir.path().join("legacy");
    let v6 = dir.path().join("v6");
    let esperado = base_legada(&legado);

    let relatorio = migrate_database(&legado, &v6, MigrateDatabaseOptions::default()).unwrap();
    assert!(
        relatorio.legacy_tail_sealed,
        "havia uma cauda activa e o relatório não o diz"
    );
    assert_eq!(relatorio.records, N, "a cauda não foi migrada por inteiro");

    let novo = V6Log::open(&v6, 1 << 20, FsyncPolicy::Always).unwrap();
    let lido = novo.scan(0, novo.head()).unwrap();
    assert_eq!(lido.len(), esperado.len());

    // O segmento novo que a base v6 abre é OUTRO — não uma continuação do
    // ficheiro legado. Todos os segmentos catalogados vieram da migração.
    let manifesto = novo.manifest();
    let migrados: Vec<_> = relatorio.segments.iter().map(|s| s.segment_id).collect();
    for s in &manifesto.segments_v2 {
        assert!(
            migrados.contains(&s.segment_id),
            "apareceu um segmento {} que não veio da migração",
            s.segment_id
        );
    }
}

/// §83 — migrar para um destino já povoado misturaria duas histórias.
#[test]
fn nao_migra_para_dentro_de_um_banco_existente() {
    let dir = tempfile::tempdir().unwrap();
    let legado = dir.path().join("legacy");
    let v6 = dir.path().join("v6");
    base_legada(&legado);

    migrate_database(&legado, &v6, MigrateDatabaseOptions::default()).unwrap();
    let erro = migrate_database(&legado, &v6, MigrateDatabaseOptions::default())
        .unwrap_err()
        .to_string();
    assert!(erro.contains("já existe"), "{erro}");
}

/// Um banco migrado é um banco NOVO: identidade de storage própria (§20).
#[test]
fn o_banco_migrado_tem_um_namespace_proprio() {
    let dir = tempfile::tempdir().unwrap();
    let legado = dir.path().join("legacy");
    base_legada(&legado);

    let a = migrate_database(
        &legado,
        &dir.path().join("v6-a"),
        MigrateDatabaseOptions::default(),
    )
    .unwrap();
    let b = migrate_database(
        &legado,
        &dir.path().join("v6-b"),
        MigrateDatabaseOptions::default(),
    )
    .unwrap();

    assert_ne!(
        a.storage_namespace_id, b.storage_namespace_id,
        "duas migrações da mesma origem produziram bancos com a mesma identidade"
    );
    // Mas a HISTÓRIA é a mesma: as raízes lógicas por segmento têm de bater.
    let raizes_a: Vec<_> = a
        .segments
        .iter()
        .map(|s| s.receipt.v6_logical_root)
        .collect();
    let raizes_b: Vec<_> = b
        .segments
        .iter()
        .map(|s| s.receipt.v6_logical_root)
        .collect();
    assert_eq!(
        raizes_a, raizes_b,
        "a raiz lógica canónica não pode depender do namespace do banco"
    );
}

/// §5 — um buraco de LSN entre segmentos é erro duro, não algo a contornar.
#[test]
fn um_buraco_de_lsn_entre_segmentos_recusa_migrar() {
    let dir = tempfile::tempdir().unwrap();
    let legado = dir.path().join("legacy");
    let v6 = dir.path().join("v6");
    base_legada(&legado);

    // Apagar um segmento do meio abre um buraco na história.
    let mut ids: Vec<u64> = std::fs::read_dir(&legado)
        .unwrap()
        .filter_map(|e| {
            let n = e.ok()?.file_name().into_string().ok()?;
            n.strip_suffix(".hrkl")?.parse::<u64>().ok()
        })
        .collect();
    ids.sort_unstable();
    assert!(ids.len() >= 3, "o teste precisa de 3+ segmentos: {ids:?}");
    let meio = ids[ids.len() / 2];
    std::fs::remove_file(legado.join(format!("{meio:020}.hrkl"))).unwrap();

    let erro = migrate_database(&legado, &v6, MigrateDatabaseOptions::default())
        .unwrap_err()
        .to_string();
    assert!(erro.contains("buraco de LSN"), "{erro}");
}
