//! heraclitus-tier — forgetting with receipts (§3.10).
//!
//! Demotion = remove from hot indexes + upload sealed segments to object
//! storage + append a `DemotionReceipt` log event carrying a blake3 Merkle
//! proof. **Nothing is ever deleted.** Recall-on-demand fetches and
//! re-scans cold segments. GDPR-style erasure is crypto-shredding
//! (docs/CONSISTENCY.md) — planned, not yet implemented here.

use arrow_array::{ArrayRef, BinaryArray, RecordBatch, StringArray, UInt64Array};
use arrow_schema::{DataType, Field, Schema};
use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn, SegmentId};
use heraclitus_log::format::{Decoded, SegmentHeader, HEADER_LEN};
use heraclitus_log::{decode_episode_payload, merkle_root, Log};
use object_store::{local::LocalFileSystem, path::Path as ObjPath, ObjectStore};
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The receipt persisted to the log (kind = DemotionReceipt, JSON payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionReceipt {
    pub segment_id: SegmentId,
    pub object_path: String,
    pub record_count: u64,
    pub min_lsn: Lsn,
    pub max_lsn: Lsn,
    /// Hex blake3 Merkle root over the segment's per-record leaf hashes
    /// (v2: each leaf covers the record's authenticated region, not just the
    /// payload — see `heraclitus_log::format::record_leaf`).
    pub blake3_root: String,
    /// C2.4 (dual-write): caminho do espelho Parquet do segmento no object
    /// store — analytics SQL (DataFusion/DuckDB/Spark) sem descodificar
    /// bincode. `None` em recibos antigos (campo com default para compat).
    #[serde(default)]
    pub parquet_path: Option<String>,
    /// V2.7: quando este recibo é produto de uma COMPACTION, o objeto de
    /// origem (o recibo antigo continua no log — a linhagem é auditável).
    #[serde(default)]
    pub compacted_from: Option<String>,
    /// V2.7: nº de eventos logicamente apagados que a compaction removeu.
    #[serde(default)]
    pub dropped: u64,
}

/// C2.6 (padrão Milvus DataCoord): política de compaction do tier frio. Um
/// segmento ganha reescrita quando a fração de eventos logicamente apagados
/// (tombstones semânticos) cruza o limiar — o recibo novo re-prova o Merkle.
/// A reescrita em si é uma operação separada; isto é o TRIGGER determinístico.
#[derive(Debug, Clone)]
pub struct CompactionPolicy {
    /// Fração `apagados/total` a partir da qual compactar (default 0.3).
    pub delta_ratio_threshold: f64,
    /// Segmentos pequenos nunca compensam a reescrita (default 1024 registos).
    pub min_records: u64,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            delta_ratio_threshold: 0.3,
            min_records: 1024,
        }
    }
}

impl CompactionPolicy {
    pub fn should_compact(&self, deleted: u64, total: u64) -> bool {
        total >= self.min_records
            && total > 0
            && (deleted as f64 / total as f64) >= self.delta_ratio_threshold
    }
}

pub struct ColdTier {
    /// Backend genérico: local (default), ou nuvem (GCS/S3) atrás das features
    /// `gcp`/`aws`. Os métodos usam só a trait `ObjectStore`, por isso trocar
    /// de backend é configuração — os paths `cold/{id}.hrkl` são relativos ao
    /// prefixo/bucket configurado.
    store: Arc<dyn ObjectStore>,
}

impl ColdTier {
    /// v0 backend: local filesystem via the `object_store` API — the same
    /// trait surface as S3/GCS, so swapping backends is configuration.
    pub fn open_local(root: impl AsRef<std::path::Path>) -> Result<Self, HeraclitusError> {
        std::fs::create_dir_all(root.as_ref())?;
        let store = LocalFileSystem::new_with_prefix(root.as_ref())
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        Ok(Self { store: Arc::new(store) })
    }

    /// Abre o backend a partir de um `location`: um URL de nuvem
    /// (`gs://bucket/prefixo`, `s3://bucket/prefixo`) ou um caminho local
    /// (qualquer coisa sem scheme de nuvem). As credenciais vêm do AMBIENTE
    /// (o `object_store` lê `GOOGLE_APPLICATION_CREDENTIALS`/
    /// `GOOGLE_SERVICE_ACCOUNT` para GCS; `AWS_*` para S3), nunca da config —
    /// o segredo não passa pelo TOML. Os prefixos GCS/S3 exigem as features
    /// `gcp`/`aws`; sem elas um URL de nuvem é um erro claro.
    ///
    /// NOTA: só o object store é partilhado; o recibo continua a entrar pelo
    /// consenso via `Engine::append`. Um object store de nuvem é o que
    /// desbloqueia o demote em cluster (o objeto deixa de ser local ao nó).
    pub fn open_location(location: &str) -> Result<Self, HeraclitusError> {
        let lower = location.to_ascii_lowercase();
        if lower.starts_with("gs://") {
            #[cfg(feature = "gcp")]
            {
                let store = object_store::gcp::GoogleCloudStorageBuilder::from_env()
                    .with_url(location)
                    .build()
                    .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
                return Ok(Self { store: Arc::new(store) });
            }
            #[cfg(not(feature = "gcp"))]
            return Err(HeraclitusError::Config(
                "cold_tier gs:// requer a feature `gcp` do heraclitus-tier".into(),
            ));
        }
        if lower.starts_with("s3://") {
            #[cfg(feature = "aws")]
            {
                let store = object_store::aws::AmazonS3Builder::from_env()
                    .with_url(location)
                    .build()
                    .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
                return Ok(Self { store: Arc::new(store) });
            }
            #[cfg(not(feature = "aws"))]
            return Err(HeraclitusError::Config(
                "cold_tier s3:// requer a feature `aws` do heraclitus-tier".into(),
            ));
        }
        // Sem scheme de nuvem ⇒ caminho local (o default).
        Self::open_local(location)
    }

    /// O episódio-recibo canónico (kind = `DemotionReceipt`, payload JSON).
    /// Exposto para o caminho unificado §2.6: quem appenda é o HOST (via
    /// `Engine::append` — indexação viva + consenso), não este crate.
    pub fn receipt_episode(receipt: &DemotionReceipt) -> Result<Episode, HeraclitusError> {
        let payload = serde_json::to_vec(receipt)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        Ok(Episode::new("tier", EventKind::DemotionReceipt, payload))
    }

    /// §2.6 (caminho unificado de evento derivado): materializa o segmento no
    /// object store (`.hrkl` + espelho Parquet) e devolve o recibo SEM o
    /// appendar — o chamador appenda `receipt_episode(..)` pelo seu caminho
    /// (o `Engine::append`, que indexa ao vivo e passa pelo consenso).
    pub async fn demote_prepared(
        &self,
        log: &Log,
        segment_id: SegmentId,
    ) -> Result<DemotionReceipt, HeraclitusError> {
        let meta = log
            .sealed_segments()
            .into_iter()
            .find(|s| s.id == segment_id)
            .ok_or_else(|| HeraclitusError::Query(format!("segment {segment_id} not sealed")))?;

        let bytes = std::fs::read(&meta.path)?;
        let (count, root) = scan_and_root(&bytes)?;

        let obj_path = ObjPath::from(format!("cold/{segment_id:020}.hrkl"));
        self.store
            .put(&obj_path, bytes.clone().into())
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;

        // C2.4 (dual-write): espelho Parquet colunar do segmento — analytics
        // SQL diretas (DataFusion/DuckDB) sem descodificar bincode. O .hrkl
        // continua a ser a verdade (Merkle); o Parquet é derivado e re-gerável.
        let parquet_path = ObjPath::from(format!("cold/{segment_id:020}.parquet"));
        let parquet_bytes = segment_to_parquet(&bytes)?;
        self.store
            .put(&parquet_path, parquet_bytes.into())
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;

        Ok(DemotionReceipt {
            segment_id,
            object_path: obj_path.to_string(),
            record_count: count,
            min_lsn: meta.base_lsn,
            max_lsn: meta.max_lsn,
            blake3_root: hex(&root),
            parquet_path: Some(parquet_path.to_string()),
            compacted_from: None,
            dropped: 0,
        })
    }

    /// Demote one sealed segment: upload bytes + append the receipt event.
    /// Returns the receipt and the LSN of the receipt event. (Conveniência
    /// standalone; um host com Engine deve usar [`Self::demote_prepared`] e
    /// appendar pelo caminho unificado §2.6.)
    pub async fn demote(
        &self,
        log: &Log,
        segment_id: SegmentId,
    ) -> Result<(DemotionReceipt, Lsn), HeraclitusError> {
        let receipt = self.demote_prepared(log, segment_id).await?;
        let lsn = log.append(Self::receipt_episode(&receipt)?)?;
        Ok((receipt, lsn))
    }

    /// Verify a receipt: fetch the cold object, recompute the Merkle root
    /// over its per-record leaf hashes, compare. M5 acceptance gate.
    pub async fn verify_receipt(&self, receipt: &DemotionReceipt) -> Result<bool, HeraclitusError> {
        let obj = self
            .store
            .get(&ObjPath::from(receipt.object_path.clone()))
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        let bytes = obj
            .bytes()
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        let (count, root) = scan_and_root(&bytes)?;
        Ok(count == receipt.record_count && hex(&root) == receipt.blake3_root)
    }

    /// V2.7 — COMPACTION física de um segmento cold (o rewrite que o trigger
    /// [`CompactionPolicy`] decide): reescreve o objeto SEM os eventos que
    /// `is_deleted` marca, produzindo um novo objeto (`...-cN.hrkl`), novo
    /// espelho Parquet e um NOVO recibo Merkle apenso ao log. Os registos
    /// sobreviventes são copiados **byte a byte** (o leaf Merkle depende só
    /// dos bytes do registo + versão — determinístico, sem re-encode). O
    /// objeto de origem NÃO é apagado aqui: o recibo novo aponta a linhagem
    /// (`compacted_from`) e a remoção do antigo é decisão do operador.
    pub async fn compact_cold(
        &self,
        log: &Log,
        receipt: &DemotionReceipt,
        is_deleted: impl Fn(Lsn, &Episode) -> bool,
    ) -> Result<(DemotionReceipt, Lsn), HeraclitusError> {
        let new_receipt = self.compact_cold_prepared(receipt, is_deleted).await?;
        let lsn = log.append(Self::receipt_episode(&new_receipt)?)?;
        Ok((new_receipt, lsn))
    }

    /// §2.6: a compaction física SEM o append do recibo — o chamador appenda
    /// `receipt_episode(..)` pelo caminho unificado (ver `demote_prepared`).
    pub async fn compact_cold_prepared(
        &self,
        receipt: &DemotionReceipt,
        is_deleted: impl Fn(Lsn, &Episode) -> bool,
    ) -> Result<DemotionReceipt, HeraclitusError> {
        let obj = self
            .store
            .get(&ObjPath::from(receipt.object_path.clone()))
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        let bytes = obj
            .bytes()
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        let version = SegmentHeader::decode(&bytes)?.version;

        // Novo segmento: header original + registos sobreviventes (bytes
        // intactos) + rodapé novo com a raiz Merkle recomputada.
        let mut out: Vec<u8> = bytes[..HEADER_LEN].to_vec();
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        let mut min_lsn: Option<Lsn> = None;
        let mut max_lsn: Option<Lsn> = None;
        let (mut kept, mut dropped) = (0u64, 0u64);
        visit_records(&bytes, &mut |lsn, payload, record| {
            let ep = decode_episode_payload(version, payload)?;
            if is_deleted(lsn, &ep) {
                dropped += 1;
                return Ok(());
            }
            kept += 1;
            out.extend_from_slice(record);
            hashes.push(heraclitus_log::format::record_leaf(version, record));
            min_lsn = Some(min_lsn.map_or(lsn, |m| m.min(lsn)));
            max_lsn = Some(max_lsn.map_or(lsn, |m| m.max(lsn)));
            Ok(())
        })?;
        let root = merkle_root(&hashes);
        let footer = heraclitus_log::format::SegmentFooter {
            record_count: kept,
            min_lsn: min_lsn.unwrap_or(0),
            max_lsn: max_lsn.unwrap_or(0),
            blake3_root: root,
        };
        out.extend_from_slice(&footer.encode());

        // Geração da compaction no nome (idempotência de caminho): -c1, -c2...
        let generation = receipt
            .object_path
            .rsplit_once("-c")
            .and_then(|(_, n)| n.strip_suffix(".hrkl"))
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0)
            + 1;
        let new_path = ObjPath::from(format!(
            "cold/{:020}-c{generation}.hrkl",
            receipt.segment_id
        ));
        self.store
            .put(&new_path, out.clone().into())
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;

        // Espelho Parquet do segmento compactado (mesma regra do demote).
        let parquet_path = ObjPath::from(format!(
            "cold/{:020}-c{generation}.parquet",
            receipt.segment_id
        ));
        let parquet_bytes = segment_to_parquet(&out)?;
        self.store
            .put(&parquet_path, parquet_bytes.into())
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;

        Ok(DemotionReceipt {
            segment_id: receipt.segment_id,
            object_path: new_path.to_string(),
            record_count: kept,
            min_lsn: min_lsn.unwrap_or(receipt.min_lsn),
            max_lsn: max_lsn.unwrap_or(receipt.max_lsn),
            blake3_root: hex(&root),
            parquet_path: Some(parquet_path.to_string()),
            compacted_from: Some(receipt.object_path.clone()),
            dropped,
        })
    }

    /// Recall-on-demand (`INCLUDE COLD`): fetch and decode a cold segment's
    /// episodes for temporary re-indexing.
    pub async fn fetch_cold(
        &self,
        receipt: &DemotionReceipt,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        let obj = self
            .store
            .get(&ObjPath::from(receipt.object_path.clone()))
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        let bytes = obj
            .bytes()
            .await
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        // Integridade: o objeto cold TEM de conferir com o recibo (contagem +
        // raiz Merkle). Sem isto, um objeto truncado/corrompido (bit-flip, corpo
        // curto de um backend S3) devolvia um resultado PARCIAL em silêncio e o
        // chamador re-indexava dados incompletos.
        let (count, root) = scan_and_root(&bytes)?;
        if count != receipt.record_count || hex(&root) != receipt.blake3_root {
            return Err(HeraclitusError::Corruption {
                context: receipt.object_path.clone(),
                detail: format!(
                    "objeto cold não confere com o recibo (registos {count}≠{}; root {}≠{})",
                    receipt.record_count,
                    hex(&root),
                    receipt.blake3_root
                ),
            });
        }
        let version = SegmentHeader::decode(&bytes)?.version;
        let mut out = Vec::new();
        visit_records(&bytes, &mut |lsn, payload, _record| {
            // O descodificador canónico vive no log e é versionado: v3 traz
            // StoragePayload; v<=2 (pré-M30) é o Episode serializado direto.
            let ep = decode_episode_payload(version, payload)?;
            out.push((lsn, ep));
            Ok(())
        })?;
        Ok(out)
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Rótulo limpo do kind para a coluna Parquet (Custom(s) → s).
fn kind_label(k: &EventKind) -> String {
    match k {
        EventKind::Custom(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// C2.4: converte os episódios de um segmento `.hrkl` num ficheiro Parquet em
/// memória (colunas: lsn, id, agent_id, session_id, ts_hlc, kind, content,
/// attrs_json, parents_json, valid_from, valid_to, embedding_json). O `content`
/// vai como veio do log (cifrado se a cifra em repouso estiver ligada — os
/// METADADOS continuam analisáveis).
///
/// `valid_from`/`valid_to` (bi-temporalidade nativa) e `embedding_json` são
/// **nuláveis**: `NULL` = ausente/aberto, distinto de um `0` real. Sem estas
/// colunas o analytics bitemporal sobre o Parquet tratava tudo como
/// sempre-válido e perdia o embedding do episódio.
fn segment_to_parquet(bytes: &[u8]) -> Result<Vec<u8>, HeraclitusError> {
    let version = SegmentHeader::decode(bytes)?.version;
    let mut rows: Vec<(Lsn, Episode)> = Vec::new();
    visit_records(bytes, &mut |lsn, payload, _| {
        rows.push((lsn, decode_episode_payload(version, payload)?));
        Ok(())
    })?;

    let serr = |e: String| HeraclitusError::Serialization(e);
    let schema = Arc::new(Schema::new(vec![
        Field::new("lsn", DataType::UInt64, false),
        Field::new("id", DataType::Utf8, false),
        Field::new("agent_id", DataType::Utf8, false),
        Field::new("session_id", DataType::Utf8, false),
        Field::new("ts_hlc", DataType::UInt64, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("content", DataType::Binary, false),
        Field::new("attrs_json", DataType::Utf8, false),
        Field::new("parents_json", DataType::Utf8, false),
        // Bi-temporalidade: NULL = aberto (desde/até sempre), não um 0 real.
        Field::new("valid_from", DataType::UInt64, true),
        Field::new("valid_to", DataType::UInt64, true),
        // Embedding no manifold produto, serializado em JSON; NULL se ausente.
        Field::new("embedding_json", DataType::Utf8, true),
    ]));

    let attrs_json = |e: &Episode| serde_json::to_string(&e.attrs).unwrap_or_else(|_| "{}".into());
    let parents_json = |e: &Episode| {
        serde_json::to_string(&e.parents.iter().map(|p| p.to_string()).collect::<Vec<_>>())
            .unwrap_or_else(|_| "[]".into())
    };
    let embedding_json = |e: &Episode| {
        e.embedding
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "null".into()))
    };
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(UInt64Array::from(
                rows.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
            )) as ArrayRef,
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|(_, e)| e.id.to_string())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|(_, e)| e.agent_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|(_, e)| e.session_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(UInt64Array::from(
                rows.iter().map(|(_, e)| e.ts_hlc).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|(_, e)| kind_label(&e.kind))
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BinaryArray::from(
                rows.iter()
                    .map(|(_, e)| e.content.as_slice())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|(_, e)| attrs_json(e)).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|(_, e)| parents_json(e))
                    .collect::<Vec<_>>(),
            )),
            Arc::new(UInt64Array::from(
                rows.iter().map(|(_, e)| e.valid_from).collect::<Vec<_>>(),
            )),
            Arc::new(UInt64Array::from(
                rows.iter().map(|(_, e)| e.valid_to).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|(_, e)| embedding_json(e)).collect::<Vec<_>>(),
            )),
        ],
    )
    .map_err(|e| serr(e.to_string()))?;

    let mut buf = Vec::new();
    let mut writer =
        ArrowWriter::try_new(&mut buf, schema, None).map_err(|e| serr(e.to_string()))?;
    writer.write(&batch).map_err(|e| serr(e.to_string()))?;
    writer.close().map_err(|e| serr(e.to_string()))?;
    Ok(buf)
}

// Callback receives `(lsn, payload, full_record_bytes)`. The full record is
// needed to recompute the version-correct Merkle leaf (which, on v2, covers the
// header, not just the payload).
type RecordVisitor<'a> = &'a mut dyn FnMut(Lsn, &[u8], &[u8]) -> Result<(), HeraclitusError>;

fn visit_records(bytes: &[u8], f: RecordVisitor<'_>) -> Result<(), HeraclitusError> {
    let version = SegmentHeader::decode(bytes)?.version;
    let mut offset = HEADER_LEN;
    while offset < bytes.len() {
        match heraclitus_log::format::decode_record(version, &bytes[offset..]) {
            Decoded::Record(lsn, _h, payload, consumed) => {
                f(lsn, payload, &bytes[offset..offset + consumed])?;
                offset += consumed;
            }
            Decoded::Footer(_) | Decoded::Torn => break,
        }
    }
    Ok(())
}

fn scan_and_root(bytes: &[u8]) -> Result<(u64, [u8; 32]), HeraclitusError> {
    let version = SegmentHeader::decode(bytes)?.version;
    let mut hashes = Vec::new();
    visit_records(bytes, &mut |_l, _payload, record| {
        // Must match the writer/recovery leaf for the segment's version, or the
        // recomputed root will not equal the receipt's.
        hashes.push(heraclitus_log::format::record_leaf(version, record));
        Ok(())
    })?;
    Ok((hashes.len() as u64, merkle_root(&hashes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::FsyncPolicy;

    #[tokio::test]
    async fn open_location_resolves_local_and_gates_cloud() {
        // Um caminho sem scheme de nuvem abre como object store local (default)
        // e faz o round-trip demote→verify — a mesma superfície do open_local.
        let dir = tempfile::tempdir().unwrap();
        let log = seeded_log(&dir.path().join("log"));
        let tier = ColdTier::open_location(&dir.path().join("cold").to_string_lossy()).unwrap();
        let seg = log.sealed_segments()[0].id;
        let (receipt, _) = tier.demote(&log, seg).await.unwrap();
        assert!(tier.verify_receipt(&receipt).await.unwrap());

        // Um URL de nuvem sem a feature respetiva é um erro CLARO (não um
        // pânico nem um fallback silencioso para local).
        #[cfg(not(feature = "gcp"))]
        assert!(ColdTier::open_location("gs://bucket/prefixo").is_err());
        #[cfg(not(feature = "aws"))]
        assert!(ColdTier::open_location("s3://bucket/prefixo").is_err());
    }

    fn seeded_log(dir: &std::path::Path) -> Log {
        // Tiny segments force at least one sealed segment.
        let log = Log::open(dir, 2048, FsyncPolicy::Always).unwrap();
        for i in 0..120 {
            log.append(Episode::new(
                "tier",
                EventKind::Observation,
                format!("cold candidate {i}").into_bytes(),
            ))
            .unwrap();
        }
        assert!(!log.sealed_segments().is_empty());
        log
    }

    #[tokio::test]
    async fn demotion_receipt_verifies_and_recalls() {
        // M5 acceptance gate: demotion receipt verification + recall-on-demand.
        let dir = tempfile::tempdir().unwrap();
        let log = seeded_log(&dir.path().join("log"));
        let tier = ColdTier::open_local(dir.path().join("cold")).unwrap();

        let seg = log.sealed_segments()[0].clone();
        let (receipt, receipt_lsn) = tier.demote(&log, seg.id).await.unwrap();

        // Receipt is an ordinary log event.
        let (_, ev) = log.read(receipt_lsn).unwrap().unwrap();
        assert_eq!(ev.kind, EventKind::DemotionReceipt);
        let back: DemotionReceipt = serde_json::from_slice(&ev.content).unwrap();
        assert_eq!(back.blake3_root, receipt.blake3_root);

        // Cryptographic verification passes.
        assert!(tier.verify_receipt(&receipt).await.unwrap());

        // Recall-on-demand returns every record of the demoted segment.
        let cold = tier.fetch_cold(&receipt).await.unwrap();
        assert_eq!(cold.len() as u64, receipt.record_count);
        assert_eq!(cold.first().unwrap().0, receipt.min_lsn);
        assert_eq!(cold.last().unwrap().0, receipt.max_lsn);
    }

    #[tokio::test]
    async fn fetch_cold_rejects_corrupted_object() {
        // Contrato do recall: NUNCA devolver dados parciais/corrompidos em
        // silêncio. Se o objeto cold não confere com o recibo (bit-flip, corpo
        // truncado de um backend remoto), fetch_cold TEM de falhar — não
        // re-indexar lixo. Prova a verificação de integridade contra o recibo.
        let dir = tempfile::tempdir().unwrap();
        let log = seeded_log(&dir.path().join("log"));
        let tier = ColdTier::open_local(dir.path().join("cold")).unwrap();
        let seg = log.sealed_segments()[0].clone();
        let (receipt, _) = tier.demote(&log, seg.id).await.unwrap();

        // Sanidade: íntegro ⇒ recuperável.
        assert!(tier.fetch_cold(&receipt).await.is_ok());

        // Corrompe o objeto: um byte no meio do corpo (bem depois do cabeçalho
        // do segmento) muda a raiz Merkle sem partir o enquadramento.
        let obj = tier
            .store
            .get(&ObjPath::from(receipt.object_path.clone()))
            .await
            .unwrap();
        let mut bytes = obj.bytes().await.unwrap().to_vec();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        tier.store
            .put(&ObjPath::from(receipt.object_path.clone()), bytes.into())
            .await
            .unwrap();

        // Agora o recall recusa em vez de devolver registos silenciosamente errados.
        let err = tier.fetch_cold(&receipt).await;
        assert!(err.is_err(), "fetch_cold devia recusar objeto corrompido");
    }

    #[tokio::test]
    async fn demotion_writes_parquet_mirror() {
        // C2.4: a demoção gera também o espelho Parquet — legível por qualquer
        // motor colunar, com as mesmas linhas do segmento.
        let dir = tempfile::tempdir().unwrap();
        let log = seeded_log(&dir.path().join("log"));
        let tier = ColdTier::open_local(dir.path().join("cold")).unwrap();
        let seg = log.sealed_segments()[0].clone();
        let (receipt, _) = tier.demote(&log, seg.id).await.unwrap();

        let ppath = receipt
            .parquet_path
            .clone()
            .expect("recibo aponta o parquet");
        let obj = tier.store.get(&ObjPath::from(ppath)).await.unwrap();
        let bytes = obj.bytes().await.unwrap();

        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let mut rows = 0usize;
        let mut saw_lsn_col = false;
        for batch in reader {
            let batch = batch.unwrap();
            rows += batch.num_rows();
            saw_lsn_col = batch.schema().field_with_name("lsn").is_ok();
        }
        assert_eq!(
            rows as u64, receipt.record_count,
            "parquet == segmento, linha a linha"
        );
        assert!(saw_lsn_col, "schema colunar com lsn");
    }

    #[tokio::test]
    async fn parquet_mirror_carries_bitemporal_and_embedding() {
        // Auditoria §6.2: o espelho Parquet tem de preservar a bi-temporalidade
        // (valid_from/valid_to) e o embedding — colunas NULÁVEIS, com NULL a
        // significar "aberto/ausente", não um 0 real. Sem elas o analytics
        // bitemporal sobre o Parquet tratava tudo como sempre-válido e perdia
        // o embedding.
        use arrow_array::{Array, StringArray, UInt64Array};
        let dir = tempfile::tempdir().unwrap();
        // Segmentos minúsculos forçam um selado; primeiro episódio enriquecido.
        let log = Log::open(&dir.path().join("log"), 2048, FsyncPolicy::Always).unwrap();
        let mut enriched =
            Episode::new("tier", EventKind::Observation, b"enriquecido".to_vec());
        enriched.valid_from = Some(100);
        enriched.valid_to = Some(200);
        enriched.embedding = Some(heraclitus_core::ProductPoint {
            hyp: vec![0.1, 0.2],
            sph: vec![],
            euc: vec![0.5],
        });
        log.append(enriched).unwrap();
        for i in 0..120 {
            log.append(Episode::new(
                "tier",
                EventKind::Observation,
                format!("plain {i}").into_bytes(),
            ))
            .unwrap();
        }
        assert!(!log.sealed_segments().is_empty());

        let tier = ColdTier::open_local(dir.path().join("cold")).unwrap();
        let seg = log.sealed_segments()[0].clone();
        let (receipt, _) = tier.demote(&log, seg.id).await.unwrap();
        let ppath = receipt.parquet_path.clone().expect("recibo aponta o parquet");
        let obj = tier.store.get(&ObjPath::from(ppath)).await.unwrap();
        let bytes = obj.bytes().await.unwrap();

        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let batches: Vec<_> = reader.map(|b| b.unwrap()).collect();
        let b = &batches[0];

        // As três colunas novas existem e são nuláveis.
        for col in ["valid_from", "valid_to", "embedding_json"] {
            let f = b.schema().field_with_name(col).unwrap().clone();
            assert!(f.is_nullable(), "{col} tem de ser nulável");
        }

        let vf = b
            .column_by_name("valid_from")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        let vt = b
            .column_by_name("valid_to")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        let emb = b
            .column_by_name("embedding_json")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        // Linha 0 = o episódio enriquecido (append mais antigo do segmento).
        assert_eq!(vf.value(0), 100);
        assert_eq!(vt.value(0), 200);
        assert!(!emb.is_null(0), "embedding presente na linha enriquecida");
        assert!(emb.value(0).contains("hyp"), "embedding serializado em JSON");

        // Linhas simples ⇒ NULL (aberto/ausente), NÃO 0 — a distinção que faltava.
        assert!(vf.is_null(1), "sem valid_from → NULL, não 0");
        assert!(vt.is_null(1), "sem valid_to → NULL, não 0");
        assert!(emb.is_null(1), "sem embedding → NULL");
    }

    #[tokio::test]
    async fn compaction_rewrites_without_deleted_and_reproves_merkle() {
        // V2.7: o rewrite físico que o CompactionPolicy dispara — objeto novo
        // sem os apagados, raiz Merkle re-provada, linhagem no recibo.
        let dir = tempfile::tempdir().unwrap();
        let log = seeded_log(&dir.path().join("log"));
        let tier = ColdTier::open_local(dir.path().join("cold")).unwrap();
        let seg = log.sealed_segments()[0].clone();
        let (receipt, _) = tier.demote(&log, seg.id).await.unwrap();
        assert!(receipt.record_count > 4);

        // Compacta removendo os LSNs ímpares (metade "logicamente apagada").
        let (new_receipt, _lsn) = tier
            .compact_cold(&log, &receipt, |lsn, _ep| lsn % 2 == 1)
            .await
            .unwrap();

        assert_eq!(
            new_receipt.compacted_from.as_deref(),
            Some(receipt.object_path.as_str())
        );
        assert_eq!(
            new_receipt.record_count + new_receipt.dropped,
            receipt.record_count
        );
        assert!(new_receipt.dropped > 0);
        assert_ne!(new_receipt.blake3_root, receipt.blake3_root, "raiz nova");

        // O objeto compactado passa a verificação criptográfica.
        assert!(tier.verify_receipt(&new_receipt).await.unwrap());
        // E o original continua verificável (linhagem intacta até o operador decidir).
        assert!(tier.verify_receipt(&receipt).await.unwrap());

        // O recall devolve SÓ os sobreviventes (LSNs pares).
        let cold = tier.fetch_cold(&new_receipt).await.unwrap();
        assert_eq!(cold.len() as u64, new_receipt.record_count);
        assert!(
            cold.iter().all(|(l, _)| l % 2 == 0),
            "só os pares sobrevivem"
        );

        // Compaction em cadeia: geração seguinte -c2 funciona sobre -c1.
        let (gen2, _) = tier
            .compact_cold(&log, &new_receipt, |lsn, _| lsn % 4 == 2)
            .await
            .unwrap();
        assert!(gen2.object_path.contains("-c2"), "{}", gen2.object_path);
        assert!(tier.verify_receipt(&gen2).await.unwrap());
    }

    #[test]
    fn compaction_policy_triggers_on_delta_ratio() {
        // C2.6 (padrão Milvus): compacta quando apagados/total cruza o limiar,
        // nunca para segmentos pequenos.
        let p = CompactionPolicy::default();
        assert!(!p.should_compact(500, 1000), "abaixo de min_records: nunca");
        assert!(!p.should_compact(100, 2000), "5% < 30%: não compacta");
        assert!(p.should_compact(600, 2000), "30% atingido: compacta");
        assert!(p.should_compact(2000, 2000), "tudo apagado: compacta");
        assert!(!p.should_compact(0, 0), "vazio nunca compacta");
    }

    #[tokio::test]
    async fn tampered_cold_object_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let log = seeded_log(&dir.path().join("log"));
        let cold_root = dir.path().join("cold");
        let tier = ColdTier::open_local(&cold_root).unwrap();
        let seg = log.sealed_segments()[0].clone();
        let (receipt, _) = tier.demote(&log, seg.id).await.unwrap();

        // Flip one payload byte deep inside the cold object.
        let obj = cold_root.join(
            receipt
                .object_path
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        let mut bytes = std::fs::read(&obj).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&obj, bytes).unwrap();

        assert!(
            !tier.verify_receipt(&receipt).await.unwrap(),
            "tampering must be detected by the Merkle proof"
        );
    }
}
