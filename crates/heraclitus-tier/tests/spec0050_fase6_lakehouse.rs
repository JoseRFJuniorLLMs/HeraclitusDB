//! SPEC-0050 Fase 6 — lakehouse, ponta-a-ponta sobre um banco v6 real.
//!
//! Os testes unitários do módulo `lakehouse` cobrem cada peça isolada: o
//! contentor Avro, o commit Delta, a metadata Iceberg, a decisão de watermark.
//! Nenhum deles prova a única coisa que justifica a fase — que **um banco
//! escrito pelo motor v6 real, selado e empacotado pelo packer real, produz
//! uma tabela lakehouse consultável cuja proveniência aponta de volta para os
//! segmentos canónicos**, e que o HRKM fica a saber disso.
//!
//! Este ficheiro percorre a Definition of Done de §209, item a item:
//!
//! | §209 | onde se prova |
//! |---|---|
//! | export Parquet preserva LSN | `os_lsn_sobrevivem_a_ida_e_volta` |
//! | export preserva segment provenance | `a_proveniencia_aponta_para_o_segmento_canonico` |
//! | export é idempotente | `reexportar_nao_duplica_nem_reescreve` |
//! | watermark é persistido | `o_watermark_do_hrkm_avanca_e_sobrevive_a_restart` |
//! | Iceberg exporter gera metadata Iceberg real | `iceberg_e_delta_descrevem_os_mesmos_ficheiros` |
//! | HRKM não é apresentado como Iceberg | `o_hrkm_nunca_entra_na_tabela` |
//! | Delta utiliza Parquet derivado | `iceberg_e_delta_descrevem_os_mesmos_ficheiros` |
//! | nenhuma projecção participa da durabilidade do append | `o_log_continua_a_aceitar_escritas_com_o_lakehouse_partido` |

use std::path::Path;
use std::sync::Arc;

use heraclitus_core::config::FsyncPolicy;
use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::v6::{PackingProfile, V6Log};
use heraclitus_tier::lakehouse::parquet_export::{read_lsns, read_provenance};
use heraclitus_tier::lakehouse::ExportDecision;
use heraclitus_tier::LakehouseWorker;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt};

/// Poucos episódios por segmento, para haver mais do que um segmento selado —
/// o watermark contíguo de §104 só tem conteúdo com vários.
const N: u64 = 600;
const SEGMENT_BYTES: u64 = 96 * 1024;

fn conteudo(i: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let mut j = 0u64;
    while out.len() < 256 {
        let mut h = blake3::Hasher::new();
        h.update(&i.to_le_bytes());
        h.update(&j.to_le_bytes());
        out.extend_from_slice(h.finalize().as_bytes());
        j += 1;
    }
    out.truncate(256);
    out
}

/// Um banco v6 real: appends pelo motor, selo, e packing pelo packer real.
///
/// Nada aqui é fabricado: os bytes no `.hrkl` são os mesmos `StoragePayload`
/// de produção, e o HRKM é publicado pelo caminho normal do `pack_pending`.
fn banco_empacotado(dir: &Path) -> (Arc<V6Log>, Vec<(Lsn, Episode)>) {
    let root = dir.join("v6");
    let log = Arc::new(V6Log::open(&root, SEGMENT_BYTES, FsyncPolicy::Always).unwrap());
    for i in 0..N {
        let mut ep = Episode::new("fase6", EventKind::Observation, conteudo(i));
        ep.attrs
            .insert("uf".into(), if i % 3 == 0 { "SP" } else { "RJ" }.into());
        log.append(ep).unwrap();
    }
    log.seal_active().unwrap();
    let empacotados = log.pack_pending(PackingProfile::Balanced).unwrap();
    assert!(
        empacotados.len() >= 2,
        "o teste precisa de vários segmentos selados; saíram {}",
        empacotados.len()
    );
    let esperado = log.scan(0, N).unwrap();
    assert_eq!(esperado.len() as u64, N);
    (log, esperado)
}

fn worker(tabela: &Path, log: &V6Log) -> LakehouseWorker {
    std::fs::create_dir_all(tabela).unwrap();
    LakehouseWorker::open_location(
        &tabela.to_string_lossy(),
        "episodios",
        log.manifest().storage_namespace_id,
    )
    .unwrap()
}

async fn ler(store: &Arc<dyn ObjectStore>, caminho: &str) -> Vec<u8> {
    store
        .get(&ObjPath::from(caminho))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec()
}

async fn listar(store: &Arc<dyn ObjectStore>) -> Vec<String> {
    use futures::StreamExt;
    let mut nomes = Vec::new();
    let mut stream = store.list(None);
    while let Some(meta) = stream.next().await {
        nomes.push(meta.unwrap().location.to_string());
    }
    nomes.sort();
    nomes
}

/// §209 — "export Parquet preserva LSN".
///
/// Não basta o Parquet ter uma coluna `lsn`: a união dos LSN de todos os
/// ficheiros exportados tem de ser **exactamente** o que o log devolve, sem
/// buracos e sem repetições. Um exportador que perdesse o último bloco de cada
/// segmento passaria num teste de amostragem e falharia neste.
#[tokio::test]
async fn os_lsn_sobrevivem_a_ida_e_volta() {
    let dir = tempfile::tempdir().unwrap();
    let (log, esperado) = banco_empacotado(dir.path());
    let tabela = dir.path().join("lakehouse");
    let w = worker(&tabela, &log);
    let store = heraclitus_tier::ColdTier::store_for(&tabela.to_string_lossy()).unwrap();

    let saidas = w.export_pending(&log).await.unwrap();
    assert!(!saidas.is_empty(), "nada foi exportado");
    assert!(
        saidas.iter().all(|s| s.attached),
        "toda a exportação devia ter sido ligada ao HRKM"
    );

    let mut vistos: Vec<Lsn> = Vec::new();
    for saida in &saidas {
        let bytes = ler(&store, &saida.path).await;
        vistos.extend(read_lsns(&bytes).unwrap());
    }
    vistos.sort_unstable();

    let mut do_log: Vec<Lsn> = esperado.iter().map(|(lsn, _)| *lsn).collect();
    do_log.sort_unstable();
    assert_eq!(
        vistos, do_log,
        "a tabela lakehouse não contém exactamente os LSN do log"
    );
}

/// §102/§209 — "export preserva segment provenance".
///
/// A proveniência é o que permite a um consumidor do lakehouse voltar ao
/// segmento canónico e provar a linha. Se a raiz lógica ou o digest físico
/// gravados no Parquet não forem os do segmento de origem, a tabela é um
/// conjunto de números sem autoridade por trás.
#[tokio::test]
async fn a_proveniencia_aponta_para_o_segmento_canonico() {
    let dir = tempfile::tempdir().unwrap();
    let (log, _) = banco_empacotado(dir.path());
    let tabela = dir.path().join("lakehouse");
    let w = worker(&tabela, &log);
    let store = heraclitus_tier::ColdTier::store_for(&tabela.to_string_lossy()).unwrap();

    let saidas = w.export_pending(&log).await.unwrap();
    let manifesto = log.manifest();

    for saida in &saidas {
        let bytes = ler(&store, &saida.path).await;
        let p = read_provenance(&bytes).unwrap();
        let desc = manifesto
            .segment(saida.segment_id)
            .expect("segmento exportado tem de estar catalogado");
        assert_eq!(p.segment_id, desc.segment_id);
        assert_eq!(p.generation, desc.active_generation);
        assert_eq!(
            p.logical_root,
            hex(&desc.logical_root),
            "a raiz lógica do Parquet não é a do segmento"
        );
        assert_eq!(p.first_lsn, desc.first_lsn);
        assert_eq!(p.last_lsn, desc.last_lsn);
        assert_eq!(
            p.storage_namespace_id,
            hex(&manifesto.storage_namespace_id),
            "o namespace do banco não viajou para a projecção"
        );

        // O HRKM tem de ter guardado a MESMA raiz lógica na referência da
        // projecção. É isso que faz `attach_parquet` recusar ligar Parquet de
        // outra geração, e é o que o GC usa para saber que ficou obsoleto.
        let referencia = desc.parquet.as_ref().expect("HRKM sem referência Parquet");
        assert_eq!(referencia.logical_root, desc.logical_root);
        assert_eq!(referencia.size, saida.size);
    }
}

/// §105/§209 — "export é idempotente".
///
/// Correr o trabalhador duas vezes tem de ser indistinguível de o correr uma.
/// A segunda passagem não exporta nada (a fila do HRKM esvaziou-se) e o
/// conjunto de objectos no store fica byte a byte igual — nenhum commit Delta
/// novo, nenhuma metadata Iceberg nova, nenhum Parquet duplicado sob outro
/// nome.
#[tokio::test]
async fn reexportar_nao_duplica_nem_reescreve() {
    let dir = tempfile::tempdir().unwrap();
    let (log, _) = banco_empacotado(dir.path());
    let tabela = dir.path().join("lakehouse");
    let w = worker(&tabela, &log);
    let store = heraclitus_tier::ColdTier::store_for(&tabela.to_string_lossy()).unwrap();

    let primeira = w.export_pending(&log).await.unwrap();
    assert!(primeira
        .iter()
        .all(|s| s.decision == ExportDecision::Exported));
    let depois_da_primeira = listar(&store).await;
    let mut bytes_da_primeira = Vec::new();
    for nome in &depois_da_primeira {
        bytes_da_primeira.push(ler(&store, nome).await);
    }

    // A fila do HRKM já não tem nada: a segunda passagem é um no-op.
    let segunda = w.export_pending(&log).await.unwrap();
    assert!(
        segunda.is_empty(),
        "a fila do HRKM devia estar vazia depois do primeiro ciclo, saiu {segunda:?}"
    );
    assert_eq!(listar(&store).await, depois_da_primeira);

    // E um trabalhador NOVO sobre a mesma tabela — o caso do reinício do
    // processo com um HRKM que ainda não soubesse — reexporta sem duplicar.
    let fresco = worker(&tabela, &log);
    let saidas = fresco.export_pending(&log).await.unwrap();
    assert!(saidas.is_empty());

    let depois_de_tudo = listar(&store).await;
    assert_eq!(depois_de_tudo, depois_da_primeira);
    for (i, nome) in depois_de_tudo.iter().enumerate() {
        assert_eq!(
            ler(&store, nome).await,
            bytes_da_primeira[i],
            "os bytes de `{nome}` mudaram numa reexportação"
        );
    }
}

/// §104/§209 — "watermark é persistido".
///
/// O watermark que interessa é o do HRKM, porque é ele que responde "até onde
/// é que a tabela analítica está em dia com o log". Tem de avançar até ao
/// último LSN exportado de forma **contígua** e tem de sobreviver a fechar e
/// reabrir o banco — se vivesse só em memória, um reinício reexportaria tudo.
#[tokio::test]
async fn o_watermark_do_hrkm_avanca_e_sobrevive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let raiz = dir.path().join("v6");
    let (log, _) = banco_empacotado(dir.path());
    let tabela = dir.path().join("lakehouse");
    let w = worker(&tabela, &log);

    assert_eq!(
        log.manifest().exported_through_lsn,
        0,
        "sem exportação, o watermark tem de ser zero"
    );
    let antes = log.metrics_snapshot().unwrap().parquet_export_lag_lsn;
    assert!(antes > 0, "o atraso de exportação devia ser visível");

    let saidas = w.export_pending(&log).await.unwrap();
    let ultimo_exportado = saidas.iter().map(|s| s.last_lsn).max().unwrap();
    let manifesto = log.manifest();
    assert_eq!(
        manifesto.exported_through_lsn, ultimo_exportado,
        "o watermark devia cobrir todos os segmentos exportados"
    );
    assert_eq!(
        log.metrics_snapshot().unwrap().parquet_export_lag_lsn,
        manifesto
            .cumulative_watermark
            .saturating_sub(ultimo_exportado),
        "o atraso tem de ser exactamente o que ainda não foi exportado"
    );

    // Fechar e reabrir: o HRKM em disco tem de trazer o watermark de volta.
    drop(log);
    let reaberto = Arc::new(V6Log::open(&raiz, SEGMENT_BYTES, FsyncPolicy::Always).unwrap());
    assert_eq!(
        reaberto.manifest().exported_through_lsn,
        ultimo_exportado,
        "o watermark não sobreviveu ao restart"
    );
    assert!(
        reaberto.lakehouse_pending().unwrap().is_empty(),
        "depois do restart a fila devia continuar vazia"
    );
}

/// §106/§109/§209 — Iceberg real, Delta sobre o **mesmo** Parquet derivado.
///
/// A tentação é cada camada materializar as suas próprias linhas. Aí um
/// `count(*)` por Iceberg e por Delta podem divergir sem que nada esteja
/// visivelmente partido. Aqui há uma materialização e duas camadas de
/// metadados: este teste vai aos ficheiros de metadata reais e compara os
/// caminhos que ambas declaram.
#[tokio::test]
async fn iceberg_e_delta_descrevem_os_mesmos_ficheiros() {
    let dir = tempfile::tempdir().unwrap();
    let (log, _) = banco_empacotado(dir.path());
    let tabela = dir.path().join("lakehouse");
    let w = worker(&tabela, &log);
    let store = heraclitus_tier::ColdTier::store_for(&tabela.to_string_lossy()).unwrap();

    let saidas = w.export_pending(&log).await.unwrap();
    let exportados: std::collections::BTreeSet<String> =
        saidas.iter().map(|s| s.path.clone()).collect();

    let nomes = listar(&store).await;
    // Metadata Iceberg v2 a sério: os três níveis (metadata JSON, manifest
    // list, manifest) têm de existir como ficheiros próprios.
    assert!(
        nomes.iter().any(|n| n.starts_with("metadata/")
            && n.ends_with(".metadata.json")),
        "sem metadata JSON Iceberg em {nomes:?}"
    );
    assert!(
        nomes.iter().any(|n| n.contains("snap-") && n.ends_with(".avro")),
        "sem manifest list Iceberg em {nomes:?}"
    );
    assert!(
        nomes
            .iter()
            .any(|n| n.starts_with("_delta_log/") && n.ends_with(".json")),
        "sem log Delta em {nomes:?}"
    );

    // Delta: os `add.path` vivos.
    let mut delta: std::collections::BTreeSet<String> = Default::default();
    for nome in nomes.iter().filter(|n| n.starts_with("_delta_log/")) {
        let texto = String::from_utf8(ler(&store, nome).await).unwrap();
        for linha in texto.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(linha).unwrap();
            if let Some(caminho) = v.get("add").and_then(|a| a.get("path")).and_then(|p| p.as_str())
            {
                delta.insert(caminho.to_string());
            }
            if let Some(caminho) = v
                .get("remove")
                .and_then(|a| a.get("path"))
                .and_then(|p| p.as_str())
            {
                delta.remove(caminho);
            }
        }
    }
    assert_eq!(
        delta, exportados,
        "o log Delta não descreve exactamente os Parquet exportados"
    );

    // Iceberg: o manifest Avro carrega os mesmos caminhos. Basta procurar
    // cada caminho nos bytes do manifest — o formato já tem testes próprios;
    // aqui interessa a coincidência entre as duas camadas.
    let manifests: Vec<String> = nomes
        .iter()
        .filter(|n| n.ends_with(".avro") && !n.contains("snap-"))
        .cloned()
        .collect();
    assert!(!manifests.is_empty(), "sem manifest Iceberg em {nomes:?}");
    let mut avro = Vec::new();
    for nome in &manifests {
        avro.extend(ler(&store, nome).await);
    }
    let texto_avro = String::from_utf8_lossy(&avro).to_string();
    for caminho in &exportados {
        assert!(
            texto_avro.contains(caminho),
            "o manifest Iceberg não menciona `{caminho}`"
        );
    }
}

/// §106/§209 — "HRKM não é apresentado como Iceberg".
///
/// O `.hrkm` é o catálogo canónico do Heraclitus. Renomeá-lo, copiá-lo ou
/// reetiquetá-lo como metadata Iceberg daria uma tabela que parece Iceberg até
/// um motor a sério a tentar abrir. Nenhum byte do manifesto interno pode
/// aparecer na tabela.
#[tokio::test]
async fn o_hrkm_nunca_entra_na_tabela() {
    let dir = tempfile::tempdir().unwrap();
    let (log, _) = banco_empacotado(dir.path());
    let tabela = dir.path().join("lakehouse");
    let w = worker(&tabela, &log);
    let store = heraclitus_tier::ColdTier::store_for(&tabela.to_string_lossy()).unwrap();
    w.export_pending(&log).await.unwrap();

    for nome in listar(&store).await {
        assert!(
            !nome.ends_with(".hrkm"),
            "um `.hrkm` apareceu na tabela lakehouse: {nome}"
        );
        let bytes = ler(&store, &nome).await;
        assert!(
            !bytes.starts_with(b"HRKM"),
            "`{nome}` começa com a magia do manifesto interno"
        );
    }
}

/// §209 — "nenhuma projecção lakehouse participa da durabilidade do append".
///
/// É o item mais importante da lista, porque é o único que transforma um
/// exportador analítico numa fonte de perda de dados se for violado. Com o
/// destino do lakehouse inutilizável, o append tem de continuar a funcionar e
/// os dados têm de continuar a ler-se; só a projecção fica por fazer.
#[tokio::test]
async fn o_log_continua_a_aceitar_escritas_com_o_lakehouse_partido() {
    let dir = tempfile::tempdir().unwrap();
    let (log, _) = banco_empacotado(dir.path());

    // Um destino que não é um diretório utilizável: o worker nem consegue
    // abrir. O log não sabe que isto aconteceu.
    let ficheiro = dir.path().join("nao-e-um-diretorio");
    std::fs::write(&ficheiro, b"x").unwrap();
    let falhou = LakehouseWorker::open_location(
        &ficheiro.to_string_lossy(),
        "episodios",
        log.manifest().storage_namespace_id,
    );

    // Abrir pode falhar já aqui ou só ao publicar, conforme o backend; o que
    // não pode acontecer é o log ficar afectado.
    if let Ok(w) = falhou {
        let _ = w.export_pending(&log).await;
    }

    let cabeca = log.head();
    for i in 0..50u64 {
        log.append(Episode::new(
            "depois-da-falha",
            EventKind::Observation,
            conteudo(i),
        ))
        .unwrap();
    }
    assert_eq!(log.head(), cabeca + 50, "o append parou por causa do export");
    let lidos = log.scan(cabeca, cabeca + 50).unwrap();
    assert_eq!(lidos.len(), 50);
    assert_eq!(
        log.manifest().exported_through_lsn,
        0,
        "nada foi exportado, portanto o watermark não pode ter avançado"
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
