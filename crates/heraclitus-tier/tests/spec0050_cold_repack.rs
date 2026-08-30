//! SPEC-0050 §96/§97, §189/§190 — compactação do tier frio, ponta-a-ponta.
//!
//! O que estes testes existem para provar, por ordem de importância:
//!
//! 1. **§190 é mecânico, não uma promessa.** O repack muda os bytes físicos e
//!    não muda uma única `CanonicalRecord`: mesma raiz lógica, mesma contagem,
//!    mesmos LSN, e as linhas relidas das duas gerações são idênticas entre si
//!    e às do log local.
//! 2. **§83/§91 continuam de pé depois do repack.** A geração antiga não é
//!    sobrescrita nem apagada: continua no bucket, continua a verificar, e
//!    continua a devolver as mesmas linhas.
//! 3. **§96/§97 são impossíveis de contornar por distracção.** Um output com
//!    outro conjunto de registos tem outra raiz lógica e, por causa disso,
//!    outra pasta — nunca pode ocupar a chave canónica do original.
//! 4. **§84 vale também aqui.** Um objecto adulterado no bucket não é
//!    repackado: seria dar-lhe um recibo novo e limpo.
//! 5. **A recolha é execução, não decisão** — e é idempotente.

use heraclitus_core::config::FsyncPolicy;
use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::v6::compress::PackingProfile;
use heraclitus_log::v6::gc::{classify_compaction, CompactionClass};
use heraclitus_log::v6::packed::{open_packed, PackOptions, PackedSegmentReader};
use heraclitus_log::v6::packer::pack_segment;
use heraclitus_log::v6::{physical_digest, IntegrityLevel, MemorySource, V6Log};
use heraclitus_tier::generation::GenerationKey;
use heraclitus_tier::ColdTierV6;
use object_store::path::Path as ObjPath;
use object_store::ObjectStoreExt;
use std::path::{Path, PathBuf};

const N: u64 = 3_000;

/// Nº de blocos de um objecto publicado, lido dos bytes que estão no bucket.
///
/// O backend é um `LocalFileSystem`, por isso a chave é um caminho relativo à
/// raiz do bucket — ler o ficheiro directamente evita montar um leitor frio só
/// para contar blocos.
fn blocos(bucket: &Path, object_path: &str) -> usize {
    let fisico = bucket.join(object_path.replace('/', std::path::MAIN_SEPARATOR_STR));
    let bytes = std::fs::read(fisico).unwrap();
    let r: PackedSegmentReader<MemorySource> =
        PackedSegmentReader::open(MemorySource(bytes), 1 << 20).unwrap();
    r.block_count()
}

/// Conteúdo determinístico de alta entropia — o mesmo raciocínio do teste da
/// Fase 5: com um payload repetitivo o Zstd colapsa tudo e o objecto fica mais
/// pequeno que a sonda da cauda, o que torna vácua qualquer medição.
fn conteudo(i: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(384);
    let mut j = 0u64;
    while out.len() < 384 {
        let mut h = blake3::Hasher::new();
        h.update(&i.to_le_bytes());
        h.update(&j.to_le_bytes());
        out.extend_from_slice(h.finalize().as_bytes());
        j += 1;
    }
    out.truncate(384);
    out
}

/// Escreve `N` episódios pelo motor v6 real, sela, e empacota a geração 1.
fn segmento_real(dir: &Path) -> (PathBuf, Vec<(Lsn, Episode)>) {
    let root = dir.join("v6");
    let log = V6Log::open(&root, 1 << 30, FsyncPolicy::Always).unwrap();
    for i in 0..N {
        let mut ep = Episode::new("repack", EventKind::Observation, conteudo(i));
        ep.attrs
            .insert("uf".into(), if i % 2 == 0 { "SP" } else { "MG" }.into());
        log.append(ep).unwrap();
    }
    log.seal_active().unwrap();
    let esperado = log.scan(0, N).unwrap();
    assert_eq!(esperado.len() as u64, N);

    let raw = root
        .join("segments")
        .join("00000000000000000000.g0000.raw.hrkl");
    let packed = dir.join("g1.packed.hrkl");
    pack_segment(
        &raw,
        &packed,
        PackOptions {
            block_target_bytes: 8 * 1024,
            profile: PackingProfile::Fast,
            ..Default::default()
        },
        0,
        1,
        &heraclitus_log::canonical_hash_storage_payload_v6,
    )
    .unwrap();
    (packed, esperado)
}

#[tokio::test]
async fn repack_muda_os_bytes_e_nao_muda_o_historico() {
    let dir = tempfile::tempdir().unwrap();
    let (g1_local, esperado) = segmento_real(dir.path());
    let bucket = dir.path().join("bucket");
    let tier = ColdTierV6::open_local(&bucket).unwrap();
    let scratch = dir.path().join("scratch");

    let g1 = tier.publish_generation(&g1_local, 1, Some(0), 10).await.unwrap();

    // Blocos maiores e Zstd: é a operação de §189 — trocar densidade por CPU
    // de leitura sem tocar no histórico.
    let out = tier
        .repack_generation(
            &g1,
            2,
            PackOptions {
                block_target_bytes: 64 * 1024,
                profile: PackingProfile::Archive,
                ..Default::default()
            },
            &scratch,
            20,
        )
        .await
        .unwrap();
    let g2 = &out.receipt;

    // ---- §190: o histórico é bit-a-bit o mesmo -------------------------
    assert_eq!(g2.logical_root, g1.logical_root, "§97: a raiz lógica mudou");
    assert_eq!(g2.record_count, g1.record_count);
    assert_eq!((g2.first_lsn, g2.last_lsn), (g1.first_lsn, g1.last_lsn));
    assert_eq!(g2.storage_namespace_id, g1.storage_namespace_id);
    assert_eq!(g2.segment_id, g1.segment_id);

    // ---- ...e os bytes físicos NÃO são os mesmos -----------------------
    assert_ne!(
        g2.physical_digest, g1.physical_digest,
        "um repack que não muda bytes nenhuns não repackou nada"
    );
    assert_eq!(g2.generation, 2);
    assert_eq!(g2.source_generation, Some(1));
    // O layout físico mudou de facto: blocos de 64 KiB dão menos blocos que os
    // de 8 KiB. É a prova de que o repack reorganizou os bytes — e o codec não
    // serve para isto, porque com conteúdo incompressível §34 cai para RAW nos
    // dois perfis e o rótulo ficaria igual nas duas gerações.
    let b1 = blocos(&bucket, &g1.object_path);
    let b2 = blocos(&bucket, &g2.object_path);
    assert!(b2 < b1, "blocos não mudaram: g1={b1}, g2={b2}");
    assert_eq!(out.pack.source_generation, 1);
    assert_eq!(out.pack.target_generation, 2);
    assert_eq!(out.bytes_before, g1.physical_size);
    assert_eq!(out.bytes_after, g2.physical_size);

    // ---- §83: a geração antiga continua lá, intacta e verificável ------
    let store = tier.store();
    assert!(
        store.head(&ObjPath::from(g1.object_path.clone())).await.is_ok(),
        "§83: a geração de origem foi sobrescrita ou apagada pelo repack"
    );
    let rel = tier
        .verify_generation(
            &g1,
            IntegrityLevel::Logical,
            Some(&heraclitus_log::canonical_hash_storage_payload_v6),
        )
        .await
        .unwrap();
    assert!(rel.is_ok(), "a geração de origem deixou de verificar: {rel:?}");

    // ---- as duas gerações devolvem exactamente as mesmas linhas --------
    let (linhas_g1, _) = tier
        .recall_lsn_range(&g1.key().unwrap(), 0, N - 1)
        .await
        .unwrap();
    let (linhas_g2, _) = tier
        .recall_lsn_range(&g2.key().unwrap(), 0, N - 1)
        .await
        .unwrap();
    assert_eq!(linhas_g1.len() as u64, N);
    assert_eq!(linhas_g2.len(), linhas_g1.len());
    for (i, ((l1, e1), (l2, e2))) in linhas_g1.iter().zip(&linhas_g2).enumerate() {
        assert_eq!(l1, l2, "LSN divergiu na posição {i}");
        assert_eq!(e1.content, e2.content, "conteúdo divergiu no LSN {l1}");
        assert_eq!(e1.attrs, e2.attrs, "attrs divergiram no LSN {l1}");
        // E contra a verdade local, não só uma contra a outra: duas leituras
        // igualmente erradas seriam consistentes entre si.
        assert_eq!(&esperado[i].1.content, &e2.content);
    }

    // O `.hrki` da origem não é herdado: indexa offsets de blocos de 8 KiB que
    // deixaram de existir num objecto de blocos de 64 KiB.
    assert!(g2.hrki_path.is_none());

    // ---- a geração nova é a que o manifesto chamaria `Active` ----------
    let local = open_packed(&g1_local, 1 << 20).unwrap();
    assert_eq!(g2.logical_root_bytes().unwrap(), local.footer.logical_root);
}

#[tokio::test]
async fn output_com_outros_registos_nunca_ocupa_a_chave_canonica() {
    // §96/§97 — o que o `compact_cold` do v1 fazia (omitir registos) produz
    // outra raiz lógica. A consequência não é uma convenção: a raiz está no
    // **caminho** (§82), portanto o output cai noutra pasta e é fisicamente
    // incapaz de substituir o segmento canónico.
    let dir = tempfile::tempdir().unwrap();
    let (g1_local, _) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let g1 = tier.publish_generation(&g1_local, 1, Some(0), 10).await.unwrap();

    let raiz_canonica = g1.logical_root_bytes().unwrap();
    // Uma raiz qualquer diferente representa qualquer output que tenha perdido
    // (ou ganho) um registo — o mecanismo é o mesmo seja qual for o registo.
    let mut raiz_projeccao = raiz_canonica;
    raiz_projeccao[0] ^= 0x01;

    assert_eq!(
        classify_compaction(&raiz_canonica, &raiz_projeccao),
        CompactionClass::Projection
    );
    let canonica = GenerationKey::new(
        g1.namespace_bytes().unwrap(),
        g1.segment_id,
        raiz_canonica,
        2,
    );
    let projeccao = GenerationKey::new(
        g1.namespace_bytes().unwrap(),
        g1.segment_id,
        raiz_projeccao,
        2,
    );
    assert_ne!(canonica.dir(), projeccao.dir());
    assert_ne!(canonica.segment_path(), projeccao.segment_path());
    assert_ne!(projeccao.segment_path(), ObjPath::from(g1.object_path.clone()));
}

#[tokio::test]
async fn objecto_adulterado_no_bucket_nao_e_repackado() {
    let dir = tempfile::tempdir().unwrap();
    let (g1_local, _) = segmento_real(dir.path());
    let bucket = dir.path().join("bucket");
    let tier = ColdTierV6::open_local(&bucket).unwrap();
    let g1 = tier.publish_generation(&g1_local, 1, Some(0), 10).await.unwrap();

    // Um bit no meio dos dados, por baixo do object store: é o bit-rot que
    // §84 manda apanhar pelo digest recalculado, não pelo `ETag`.
    let fisico = bucket.join(g1.object_path.replace('/', std::path::MAIN_SEPARATOR_STR));
    let mut bytes = std::fs::read(&fisico).unwrap();
    let meio = bytes.len() / 2;
    bytes[meio] ^= 0xFF;
    assert_ne!(physical_digest(&bytes), g1.physical_digest_bytes().unwrap());
    std::fs::write(&fisico, &bytes).unwrap();

    let erro = tier
        .repack_generation(
            &g1,
            2,
            PackOptions::default(),
            &dir.path().join("scratch"),
            20,
        )
        .await
        .expect_err("repackou um objecto adulterado");
    assert!(
        format!("{erro}").contains("physical_digest"),
        "erro não nomeia a causa: {erro}"
    );

    // E nada foi publicado: a geração 2 não existe.
    let g2 = GenerationKey::new(
        g1.namespace_bytes().unwrap(),
        g1.segment_id,
        g1.logical_root_bytes().unwrap(),
        2,
    );
    assert!(tier.store().head(&g2.segment_path()).await.is_err());
}

#[tokio::test]
async fn recolha_remove_a_geracao_superseded_e_deixa_a_activa() {
    let dir = tempfile::tempdir().unwrap();
    let (g1_local, _) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let g1 = tier.publish_generation(&g1_local, 1, Some(0), 10).await.unwrap();
    let out = tier
        .repack_generation(
            &g1,
            2,
            PackOptions {
                block_target_bytes: 32 * 1024,
                ..Default::default()
            },
            &dir.path().join("scratch"),
            20,
        )
        .await
        .unwrap();
    let g2 = out.receipt;

    let r = tier
        .collect_cold_locations(std::slice::from_ref(&g1.object_path))
        .await
        .unwrap();
    assert_eq!(r.removed, vec![g1.object_path.clone()]);
    assert!(r.is_clean());

    let store = tier.store();
    assert!(store.head(&ObjPath::from(g1.object_path.clone())).await.is_err());
    assert!(store.head(&ObjPath::from(g2.object_path.clone())).await.is_ok());

    // A geração activa continua a servir o histórico completo depois de a
    // antiga desaparecer — que é a única razão pela qual apagá-la era seguro.
    let (linhas, _) = tier.recall_lsn_range(&g2.key().unwrap(), 0, N - 1).await.unwrap();
    assert_eq!(linhas.len() as u64, N);

    // Idempotência: repetir não é erro, e não inventa remoções.
    let de_novo = tier
        .collect_cold_locations(std::slice::from_ref(&g1.object_path))
        .await
        .unwrap();
    assert!(de_novo.removed.is_empty());
    assert_eq!(de_novo.already_absent, vec![g1.object_path]);
}

#[tokio::test]
async fn geracao_alvo_tem_de_ser_posterior() {
    let dir = tempfile::tempdir().unwrap();
    let (g1_local, _) = segmento_real(dir.path());
    let tier = ColdTierV6::open_local(dir.path().join("bucket")).unwrap();
    let g1 = tier.publish_generation(&g1_local, 1, Some(0), 10).await.unwrap();

    for alvo in [0, 1] {
        let erro = tier
            .repack_generation(
                &g1,
                alvo,
                PackOptions::default(),
                &dir.path().join("scratch"),
                20,
            )
            .await
            .expect_err("aceitou geração alvo {alvo}");
        assert!(format!("{erro}").contains("§83"), "{erro}");
    }
}
