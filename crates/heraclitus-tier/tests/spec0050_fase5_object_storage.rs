//! SPEC-0050 Fase 5 — object storage, ponta-a-ponta sobre um segmento real.
//!
//! Os testes unitários cobrem formato de chave, recibo e origem esparsa. Este
//! ficheiro cobre a única coisa que justifica a fase: **um segmento escrito
//! pelo motor v6 real, empacotado pelo packer real, publicado num object store,
//! e relido de lá sem descarregar o objecto inteiro**.
//!
//! Três propriedades são verificadas em vez de assumidas:
//!
//! 1. **§85 é mensurável.** Um recall de um intervalo estreito transfere uma
//!    fracção do objecto, e as linhas devolvidas são exactamente as mesmas que
//!    o log local devolve. Poupar bytes perdendo linhas não é poupar nada.
//! 2. **§83 é mecânico.** Republicar bytes diferentes na mesma chave é erro,
//!    não um `PUT`. Republicar os mesmos bytes é idempotente (um retry de rede
//!    não pode falhar).
//! 3. **§84 é a autoridade certa.** Um objecto adulterado falha a verificação
//!    pelo `physical_digest` recalculado — o `ETag` do backend nunca entra na
//!    decisão.

use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::v6::packed::{open_packed, PackOptions};
use heraclitus_log::v6::packer::pack_segment;
use heraclitus_log::v6::{physical_digest, IntegrityLevel, V6Log};
use heraclitus_core::config::FsyncPolicy;
use heraclitus_tier::generation::GenerationKey;
use heraclitus_tier::receipts_v2::{decode_receipt_payload, AnyDemotionReceipt};
use heraclitus_tier::ColdTierV6;
use object_store::path::Path as ObjPath;
use object_store::ObjectStoreExt;
use std::path::{Path, PathBuf};

const N: u64 = 4_000;

/// Conteúdo de alta entropia, determinístico.
///
/// Um payload repetitivo (`"x".repeat(96)`) faz o Zstd colapsar 4000 registos
/// em dezenas de KiB — e um objecto mais pequeno que a sonda da cauda é
/// transferido inteiro num GET, o que é o comportamento **certo** mas torna o
/// teste de §85 vácuo. Aqui o objecto tem de ser grande o suficiente para que
/// poupar bytes seja mensurável.
fn conteudo(i: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let mut j = 0u64;
    while out.len() < 512 {
        let mut h = blake3::Hasher::new();
        h.update(&i.to_le_bytes());
        h.update(&j.to_le_bytes());
        out.extend_from_slice(h.finalize().as_bytes());
        j += 1;
    }
    out.truncate(512);
    out
}

/// Escreve `N` episódios pelo motor v6 real e devolve `(raw, packed)`.
///
/// Deliberadamente **não** se inventa aqui um payload de teste: os episódios
/// passam por `V6Log::append`, portanto os bytes no segmento são os mesmos
/// `StoragePayload` de produção, e o hasher canónico oficial aplica-se sem
/// tradução. Um teste que serializasse JSON à mão provaria o formato errado.
fn segmento_real(dir: &Path) -> (PathBuf, PathBuf, Vec<(Lsn, Episode)>) {
    let root = dir.join("v6");
    let log = V6Log::open(&root, 1 << 30, FsyncPolicy::Always).unwrap();
    for i in 0..N {
        let mut ep = Episode::new("fase5", EventKind::Observation, conteudo(i));
        ep.attrs
            .insert("uf".into(), if i % 3 == 0 { "SP" } else { "RJ" }.into());
        log.append(ep).unwrap();
    }
    log.seal_active().unwrap();
    // `scan` é `[from, to)` — exclusivo no topo.
    let esperado = log.scan(0, N).unwrap();
    assert_eq!(esperado.len() as u64, N);

    let raw = root
        .join("segments")
        .join("00000000000000000000.g0000.raw.hrkl");
    assert!(raw.exists(), "segmento RAW selado não apareceu: {raw:?}");

    // Blocos pequenos de propósito: o pruning de §85 só se demonstra num
    // segmento com muitos blocos, e o default de 256 KiB daria poucos.
    let packed = dir.join("segmento.packed.hrkl");
    pack_segment(
        &raw,
        &packed,
        PackOptions {
            block_target_bytes: 8 * 1024,
            ..Default::default()
        },
        0,
        1,
        &heraclitus_log::canonical_hash_storage_payload_v6,
    )
    .unwrap();

    // A premissa dos testes de §85: o objecto tem de ser bem maior que a sonda
    // da cauda, senão "abrir" e "descarregar tudo" seriam a mesma coisa.
    let tamanho = std::fs::metadata(&packed).unwrap().len();
    assert!(
        tamanho > 8 * heraclitus_tier::object_source::TAIL_PROBE_BYTES,
        "segmento de teste pequeno demais ({tamanho} bytes) para demonstrar range reads"
    );
    (raw, packed, esperado)
}

#[tokio::test]
async fn publica_verifica_e_rele_por_intervalos() {
    let dir = tempfile::tempdir().unwrap();
    let (_raw, packed, esperado) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();

    let recibo = tier
        .publish_generation(&packed, 1, Some(0), 42)
        .await
        .unwrap();

    // ---- o recibo diz a verdade sobre o objecto (§86) --------------------
    let local = open_packed(&packed, 1 << 20).unwrap();
    assert_eq!(recibo.record_count, N);
    assert_eq!(recibo.first_lsn, 0);
    assert_eq!(recibo.last_lsn, N - 1);
    assert_eq!(recibo.logical_root_bytes().unwrap(), local.footer.logical_root);
    assert_eq!(recibo.generation, 1);
    assert_eq!(recibo.source_generation, Some(0));
    assert_eq!(recibo.physical_layout, "PACKED");
    assert_eq!(
        recibo.physical_size,
        std::fs::metadata(&packed).unwrap().len()
    );
    recibo.check_path_consistency().unwrap();
    let key = recibo.key().unwrap();
    assert!(recibo.object_path.starts_with("canonical/"));

    // ---- §84: a verificação recalcula, não confia no backend -------------
    let rel = tier
        .verify_generation(
            &recibo,
            IntegrityLevel::Logical,
            Some(&heraclitus_log::canonical_hash_storage_payload_v6),
        )
        .await
        .unwrap();
    assert!(rel.is_ok(), "verificação falhou: {rel:?}");
    assert!(rel.physical_digest_ok && rel.logical_root_ok && rel.path_ok);
    assert_eq!(rel.report.recomputed_root, Some(local.footer.logical_root));
    assert_eq!(rel.report.record_count, N);

    // Uma geração verificada em nível LOGICAL pode ser promovida; publicar por
    // si só não promove nada (§72).
    assert_eq!(
        recibo.physical_generation().unwrap().state,
        heraclitus_core::runtime::GenerationState::Active
    );
    let g = ColdTierV6::verified_generation(&recibo, &rel, 99).unwrap();
    assert_eq!(g.state, heraclitus_core::runtime::GenerationState::Verified);
    assert_eq!(g.verified_hlc, 99);
    assert_eq!(g.location, recibo.object_path);

    // ---- §85: abrir custa duas leituras pequenas -------------------------
    let leitor = tier.open_cold(&key).await.unwrap();
    let abertura = leitor.stats();
    let tamanho = leitor.object_size();
    assert_eq!(tamanho, recibo.physical_size);
    assert!(
        abertura.requests <= 2,
        "abrir custou {} pedidos",
        abertura.requests
    );
    assert!(
        abertura.bytes_fetched < tamanho / 4,
        "abrir transferiu {} de {tamanho} bytes",
        abertura.bytes_fetched
    );
    assert!(
        leitor.directory.len() > 8,
        "o segmento devia ter muitos blocos, tem {}",
        leitor.directory.len()
    );

    // ---- §85: um recall estreito paga pouco, e paga certo ----------------
    let (lo, hi) = (500, 519);
    let (relido, custo) = tier.recall_lsn_range(&key, lo, hi).await.unwrap();

    let esperado_intervalo: Vec<_> = esperado
        .iter()
        .filter(|(l, _)| *l >= lo && *l <= hi)
        .collect();
    assert_eq!(relido.len(), esperado_intervalo.len());
    for ((l_frio, ep_frio), (l_quente, ep_quente)) in relido.iter().zip(&esperado_intervalo) {
        assert_eq!(l_frio, l_quente);
        assert_eq!(ep_frio.id, ep_quente.id);
        assert_eq!(ep_frio.content, ep_quente.content);
        assert_eq!(ep_frio.attrs, ep_quente.attrs);
    }
    assert!(custo.blocks_pruned > 0, "nada foi podado: {custo:?}");
    assert!(
        custo.fetch_ratio() < 0.10,
        "recall de {} linhas transferiu {:.0}% do objecto ({custo:?})",
        relido.len(),
        custo.fetch_ratio() * 100.0
    );
}

#[tokio::test]
async fn point_lookup_frio_traz_um_bloco_e_nao_o_segmento() {
    let dir = tempfile::tempdir().unwrap();
    let (_raw, packed, esperado) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let recibo = tier.publish_generation(&packed, 1, None, 1).await.unwrap();
    let key = recibo.key().unwrap();

    let mut leitor = tier.open_cold(&key).await.unwrap();
    let achado = leitor.get(777).await.unwrap();
    assert!(achado.is_some(), "LSN 777 devia existir");

    let st = leitor.stats();
    assert_eq!(st.blocks_fetched, 1, "trouxe mais de um bloco: {st:?}");
    assert!(
        st.fetch_ratio() < 0.1,
        "point lookup transferiu {:.0}% do objecto",
        st.fetch_ratio() * 100.0
    );

    // E um LSN fora do segmento não transfere bloco nenhum.
    let antes = leitor.stats().blocks_fetched;
    assert!(leitor.get(N + 10_000).await.unwrap().is_none());
    assert_eq!(leitor.stats().blocks_fetched, antes);

    // O payload devolvido é o mesmo do log quente.
    let (_lsn, payload) = achado.unwrap();
    let ep = heraclitus_log::decode_episode_payload(
        heraclitus_log::format::FORMAT_VERSION,
        &payload,
    )
    .unwrap();
    let (_l, esperado_777) = esperado.iter().find(|(l, _)| *l == 777).unwrap();
    assert_eq!(ep.id, esperado_777.id);
    assert_eq!(ep.content, esperado_777.content);
}

#[tokio::test]
async fn geracao_publicada_nunca_e_sobrescrita() {
    let dir = tempfile::tempdir().unwrap();
    let (_raw, packed, _) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();

    let a = tier.publish_generation(&packed, 1, None, 1).await.unwrap();

    // Republicar os MESMOS bytes na mesma chave é idempotente: um retry de
    // rede não pode transformar-se numa falha operacional.
    let b = tier.publish_generation(&packed, 1, None, 1).await.unwrap();
    assert_eq!(a, b);

    // Bytes DIFERENTES na mesma chave são erro duro (§83) — publica-se a
    // geração seguinte, não se escreve por cima.
    let store = tier.store();
    let path = ObjPath::from(a.object_path.clone());
    let originais = store.get(&path).await.unwrap().bytes().await.unwrap();
    store.delete(&path).await.unwrap();
    let mut adulterados = originais.to_vec();
    let n = adulterados.len();
    adulterados[n - 200] ^= 0xFF;
    store.put(&path, adulterados.into()).await.unwrap();

    let erro = tier
        .publish_generation(&packed, 1, None, 1)
        .await
        .unwrap_err();
    let msg = erro.to_string();
    assert!(msg.contains("§83"), "erro não invoca §83: {msg}");

    // A geração SEGUINTE é sempre publicável — é o caminho legítimo.
    let c = tier.publish_generation(&packed, 2, Some(1), 2).await.unwrap();
    assert_ne!(c.object_path, a.object_path);
    assert_eq!(c.logical_root, a.logical_root, "o histórico é o mesmo");
    assert_eq!(c.physical_digest, a.physical_digest);
}

#[tokio::test]
async fn objecto_adulterado_falha_pela_autoridade_do_heraclitus() {
    let dir = tempfile::tempdir().unwrap();
    let (_raw, packed, _) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let recibo = tier.publish_generation(&packed, 1, None, 1).await.unwrap();

    // Trocar um byte no corpo de um bloco: o objecto continua a ter o tamanho
    // certo e o backend continua a servi-lo sem se queixar.
    let store = tier.store();
    let path = ObjPath::from(recibo.object_path.clone());
    let mut bytes = store.get(&path).await.unwrap().bytes().await.unwrap().to_vec();
    let alvo = bytes.len() / 2;
    bytes[alvo] ^= 0xFF;
    assert_ne!(
        physical_digest(&bytes),
        recibo.physical_digest_bytes().unwrap()
    );
    store.delete(&path).await.unwrap();
    store.put(&path, bytes.into()).await.unwrap();

    let rel = tier
        .verify_generation(
            &recibo,
            IntegrityLevel::Physical,
            None,
        )
        .await
        .unwrap();
    assert!(!rel.physical_digest_ok, "digest adulterado passou: {rel:?}");
    assert!(!rel.is_ok());

    // E a geração correspondente vai para quarentena, não para verificada.
    let g = ColdTierV6::verified_generation(&recibo, &rel, 5).unwrap();
    assert_eq!(
        g.state,
        heraclitus_core::runtime::GenerationState::Quarantined
    );
}

#[tokio::test]
async fn recibo_v2_atravessa_o_log_como_episodio() {
    let dir = tempfile::tempdir().unwrap();
    let (_raw, packed, _) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let recibo = tier.publish_generation(&packed, 1, None, 7).await.unwrap();

    let ep = recibo.episode().unwrap();
    assert_eq!(ep.kind, EventKind::DemotionReceipt);

    match decode_receipt_payload(&ep.content).unwrap() {
        AnyDemotionReceipt::V2(r) => {
            assert_eq!(*r, recibo);
            assert_eq!(r.digest().unwrap(), recibo.digest().unwrap());
            // A chave reconstruída do caminho bate com a dos campos.
            assert_eq!(
                GenerationKey::parse(&r.object_path).unwrap(),
                r.key().unwrap()
            );
        }
        AnyDemotionReceipt::V1(_) => panic!("recibo v2 lido como v1"),
    }
}

#[tokio::test]
async fn sidecar_hrki_acompanha_a_geracao_quando_existe() {
    use heraclitus_log::v6::hrki::{caminho_sidecar, construir_para_packed, IndexPolicySet};

    let dir = tempfile::tempdir().unwrap();
    let (_raw, packed, _) = segmento_real(dir.path());

    // Sem sidecar: a publicação não inventa um (§56 — derivado, opcional).
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let sem = tier.publish_generation(&packed, 1, None, 1).await.unwrap();
    assert!(sem.hrki_path.is_none());

    // Com sidecar ao lado do segmento: viaja junto, sob a mesma geração.
    let h = construir_para_packed(
        &packed,
        &IndexPolicySet::new(),
        None,
        0.01,
        1 << 20,
        &|b: &[u8]| {
            heraclitus_log::decode_episode_payload(heraclitus_log::format::FORMAT_VERSION, b).ok()
        },
    )
    .unwrap();
    h.escrever(&packed).unwrap();
    assert!(caminho_sidecar(&packed).exists());

    let com = tier.publish_generation(&packed, 2, Some(1), 2).await.unwrap();
    let hrki = com.hrki_path.clone().expect("sidecar devia ter sido publicado");
    assert!(hrki.ends_with("generation-2.hrki"));
    assert_eq!(
        GenerationKey::parse(&hrki).unwrap(),
        com.key().unwrap(),
        "o sidecar tem de partilhar a chave da geração"
    );
    let store = tier.store();
    assert!(store.head(&ObjPath::from(hrki)).await.is_ok());
}
