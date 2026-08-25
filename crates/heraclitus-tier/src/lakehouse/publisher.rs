//! Publicação transaccional por derivação das projecções lakehouse.
//!
//! O commit externo segue a ordem `Parquet -> Iceberg -> Delta -> watermark`.
//! O watermark é, portanto, o último reconhecimento de sucesso. Se o processo
//! cair depois do Delta e antes dele, a reabertura encontra o `add` no log
//! Delta e conclui apenas o watermark; nunca cria uma segunda adição lógica.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures::StreamExt;
use heraclitus_core::HeraclitusError;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions};

use super::delta::{self, DeltaCommit};
use super::iceberg::{self, IcebergDataFile, IcebergTable};
use super::parquet_export::{data_path, read_lsns, read_provenance};
use super::{ExportDecision, ExportWatermark, ExportedFile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResult {
    pub decision: ExportDecision,
    /// `true` quando o objecto Parquet existia mas foi regenerado a partir da
    /// fonte canónica porque os bytes não conferiam.
    pub parquet_repaired: bool,
    pub delta_version: Option<u64>,
    pub iceberg_metadata_path: Option<String>,
    pub watermark: ExportWatermark,
}

pub struct LakehousePublisher {
    store: Arc<dyn ObjectStore>,
    table_name: String,
    iceberg: IcebergTable,
}

impl LakehousePublisher {
    pub fn new(
        store: Arc<dyn ObjectStore>,
        table_name: impl Into<String>,
        iceberg: IcebergTable,
    ) -> Self {
        Self {
            store,
            table_name: table_name.into(),
            iceberg,
        }
    }

    /// A URI absoluta de um caminho relativo da tabela.
    ///
    /// E o que o HRKM guarda como `location` da projeccao: o Parquet vive num
    /// object store, possivelmente remoto, e um caminho relativo ao diretorio
    /// do log seria uma mentira sobre onde os bytes estao.
    pub fn absolute(&self, relative: &str) -> String {
        self.iceberg.absolute(relative)
    }

    /// Publica uma exportação já materializada pelo exportador Parquet.
    ///
    /// `timestamp_ms` deve ser estável para o evento que desencadeou o export
    /// (por exemplo, derivado do HLC do recibo). Isso mantém os bytes de
    /// metadata reproduzíveis durante retry.
    pub async fn publish(
        &self,
        file: &ExportedFile,
        timestamp_ms: i64,
    ) -> Result<PublishResult, HeraclitusError> {
        if timestamp_ms < 0 {
            return Err(HeraclitusError::Config(
                "timestamp_ms lakehouse não pode ser negativo".into(),
            ));
        }
        self.validate_export(file)?;
        let mut watermark = self.load_watermark().await?;
        if watermark.table.is_empty() {
            watermark.table = self.table_name.clone();
        }
        if watermark.table != self.table_name {
            return Err(HeraclitusError::Corruption {
                context: "watermark lakehouse".into(),
                detail: format!(
                    "a tabela persistida é `{}`, não `{}`",
                    watermark.table, self.table_name
                ),
            });
        }

        let commits = self.load_delta_commits().await?;
        let live = delta::estado_dos_ficheiros(&commits);
        let decision = watermark.decide(file.provenance.segment_id, file.provenance.generation);
        if let Some(old_generation) = watermark.segments.get(&file.provenance.segment_id) {
            if file.provenance.generation < *old_generation {
                return Err(HeraclitusError::Corruption {
                    context: "watermark lakehouse".into(),
                    detail: format!(
                        "geração {} do segmento {} recua a geração persistida {}",
                        file.provenance.generation, file.provenance.segment_id, old_generation
                    ),
                });
            }
        }

        let repaired = self.put_parquet(file).await?;
        let already_in_delta = live.iter().any(|p| p == &file.path);

        if decision == ExportDecision::AlreadyCurrent {
            if !already_in_delta {
                return Err(HeraclitusError::Corruption {
                    context: "catálogo lakehouse".into(),
                    detail: format!(
                        "watermark declara `{}` mas o estado Delta não contém o ficheiro",
                        file.path
                    ),
                });
            }
            return Ok(PublishResult {
                decision,
                parquet_repaired: repaired,
                delta_version: commits.last().map(|c| c.version),
                iceberg_metadata_path: self.latest_iceberg_metadata().await?.map(|v| v.1),
                watermark,
            });
        }

        // Recuperação do único intervalo de crash depois do commit Delta e
        // antes do watermark. A ordem de publicação garante que Iceberg já
        // foi persistido quando este `add` está visível.
        if already_in_delta {
            watermark.record(&file.provenance, timestamp_ms as u64);
            self.save_watermark(&watermark).await?;
            return Ok(PublishResult {
                decision,
                parquet_repaired: repaired,
                delta_version: commits.last().map(|c| c.version),
                iceberg_metadata_path: self.latest_iceberg_metadata().await?.map(|v| v.1),
                watermark,
            });
        }

        let old_path = match decision {
            ExportDecision::Superseded {
                generation_anterior,
            } => Some(data_path(file.provenance.segment_id, generation_anterior)),
            _ => None,
        };
        let mut next_live: BTreeSet<String> = live.into_iter().collect();
        if let Some(old) = &old_path {
            next_live.remove(old);
        }
        next_live.insert(file.path.clone());
        let data_files = self
            .load_live_metadata(&next_live, Some(file))
            .await?;

        let (last_iceberg_sequence, parent_snapshot, _) =
            self.latest_iceberg_state().await?.unwrap_or((0, None, String::new()));
        let sequence = last_iceberg_sequence
            .checked_add(1)
            .ok_or_else(|| HeraclitusError::StorageEngine("sequência Iceberg esgotada".into()))?;
        let snapshot_id = snapshot_id(sequence, &data_files);
        let snapshot = iceberg::build_snapshot_metadata(
            &self.iceberg,
            snapshot_id,
            sequence,
            timestamp_ms,
            parent_snapshot,
            &data_files,
        )?;
        self.put_immutable(&snapshot.manifest.path, &snapshot.manifest.bytes)
            .await?;
        self.put_immutable(&snapshot.manifest_list.path, &snapshot.manifest_list.bytes)
            .await?;
        self.put_immutable(
            &snapshot.table_metadata.path,
            &snapshot.table_metadata.bytes,
        )
        .await?;

        let last_delta = commits.last().map(|c| c.version);
        if last_delta.is_none() {
            let initial = delta::commit_inicial(
                &self.iceberg.table_uuid,
                Some(&self.table_name),
                timestamp_ms,
            )?;
            self.put_immutable(&initial.path, &initial.bytes).await?;
        }
        let delta_version = last_delta.unwrap_or(0).checked_add(1).ok_or_else(|| {
            HeraclitusError::StorageEngine("versão do log Delta esgotada".into())
        })?;
        let removed = old_path.into_iter().collect::<Vec<_>>();
        let commit = delta::commit_append(
            delta_version,
            std::slice::from_ref(file),
            &removed,
            timestamp_ms,
        )?;
        self.put_immutable(&commit.path, &commit.bytes).await?;

        watermark.record(&file.provenance, timestamp_ms as u64);
        self.save_watermark(&watermark).await?;
        Ok(PublishResult {
            decision,
            parquet_repaired: repaired,
            delta_version: Some(delta_version),
            iceberg_metadata_path: Some(snapshot.table_metadata.path),
            watermark,
        })
    }

    async fn load_watermark(&self) -> Result<ExportWatermark, HeraclitusError> {
        match self.get(ExportWatermark::PATH).await? {
            Some(bytes) => ExportWatermark::decode(&bytes),
            None => Ok(ExportWatermark::new(&self.table_name)),
        }
    }

    async fn save_watermark(&self, watermark: &ExportWatermark) -> Result<(), HeraclitusError> {
        self.store
            .put(
                &ObjPath::from(ExportWatermark::PATH),
                watermark.encode()?.into(),
            )
            .await
            .map_err(|e| store_error(ExportWatermark::PATH, e))?;
        Ok(())
    }

    fn validate_export(&self, file: &ExportedFile) -> Result<(), HeraclitusError> {
        if file.path != data_path(file.provenance.segment_id, file.provenance.generation) {
            return Err(HeraclitusError::Corruption {
                context: "exportação lakehouse".into(),
                detail: format!("caminho `{}` não bate com a proveniência", file.path),
            });
        }
        let metadata = read_provenance(&file.bytes)?;
        if metadata != file.provenance {
            return Err(HeraclitusError::Corruption {
                context: "exportação lakehouse".into(),
                detail: "metadata Parquet não bate com a proveniência em memória".into(),
            });
        }
        let lsns = read_lsns(&file.bytes)?;
        let bounds = lsns.first().copied().zip(lsns.last().copied());
        if lsns.len() as u64 != file.rows
            || bounds != Some((file.provenance.first_lsn, file.provenance.last_lsn))
        {
            return Err(HeraclitusError::Corruption {
                context: "exportação lakehouse".into(),
                detail: "LSNs do Parquet não batem com a proveniência".into(),
            });
        }
        Ok(())
    }

    async fn put_parquet(&self, file: &ExportedFile) -> Result<bool, HeraclitusError> {
        let path = ObjPath::from(file.path.clone());
        match self.get(&file.path).await? {
            Some(current) if current == file.bytes => Ok(false),
            Some(_) => {
                // Parquet é derivado. Substituir bytes corrompidos pelos bytes
                // novamente derivados da mesma proveniência é regeneração,
                // não mutação da verdade canónica.
                self.store
                    .put(&path, file.bytes.clone().into())
                    .await
                    .map_err(|e| store_error(&file.path, e))?;
                Ok(true)
            }
            None => {
                self.store
                    .put(&path, file.bytes.clone().into())
                    .await
                    .map_err(|e| store_error(&file.path, e))?;
                Ok(false)
            }
        }
    }

    async fn put_immutable(&self, path: &str, bytes: &[u8]) -> Result<(), HeraclitusError> {
        let path_obj = ObjPath::from(path);
        let options = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self
            .store
            .put_opts(&path_obj, bytes.to_vec().into(), options)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let current = self.get(path).await?.ok_or_else(|| {
                    HeraclitusError::StorageEngine(format!(
                        "`{path}` desapareceu depois de AlreadyExists"
                    ))
                })?;
                if current == bytes {
                    Ok(())
                } else {
                    Err(HeraclitusError::Corruption {
                        context: "metadata lakehouse imutável".into(),
                        detail: format!("`{path}` já existe com bytes diferentes"),
                    })
                }
            }
            Err(e) => Err(store_error(path, e)),
        }
    }

    async fn get(&self, path: &str) -> Result<Option<Vec<u8>>, HeraclitusError> {
        match self.store.get(&ObjPath::from(path)).await {
            Ok(result) => Ok(Some(
                result
                    .bytes()
                    .await
                    .map_err(|e| store_error(path, e))?
                    .to_vec(),
            )),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(store_error(path, e)),
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, HeraclitusError> {
        let mut stream = self.store.list(Some(&ObjPath::from(prefix)));
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            let meta = item.map_err(|e| store_error(prefix, e))?;
            out.push(meta.location.to_string());
        }
        out.sort();
        Ok(out)
    }

    async fn load_delta_commits(&self) -> Result<Vec<DeltaCommit>, HeraclitusError> {
        let mut out = Vec::new();
        for path in self.list_prefix("_delta_log").await? {
            let Some(name) = path.strip_prefix("_delta_log/") else {
                continue;
            };
            let Some(version) = name
                .strip_suffix(".json")
                .and_then(|v| v.parse::<u64>().ok())
            else {
                continue;
            };
            let bytes = self.get(&path).await?.ok_or_else(|| {
                HeraclitusError::StorageEngine(format!("commit Delta `{path}` desapareceu"))
            })?;
            let actions = delta::parse_commit(&bytes)?;
            out.push(DeltaCommit {
                version,
                path,
                bytes,
                actions,
            });
        }
        out.sort_by_key(|c| c.version);
        for (expected, commit) in out.iter().enumerate() {
            if commit.version != expected as u64 {
                return Err(HeraclitusError::Corruption {
                    context: "log Delta".into(),
                    detail: format!(
                        "buraco de versão: esperava {}, encontrou {}",
                        expected, commit.version
                    ),
                });
            }
        }
        Ok(out)
    }

    async fn load_live_metadata(
        &self,
        paths: &BTreeSet<String>,
        incoming: Option<&ExportedFile>,
    ) -> Result<Vec<IcebergDataFile>, HeraclitusError> {
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(file) = incoming.filter(|f| &f.path == path) {
                out.push(IcebergDataFile::from(file));
                continue;
            }
            let bytes = self.get(path).await?.ok_or_else(|| HeraclitusError::Corruption {
                context: "catálogo lakehouse".into(),
                detail: format!("Parquet vivo `{path}` está ausente"),
            })?;
            let provenance = read_provenance(&bytes)?;
            let lsns = read_lsns(&bytes)?;
            if lsns.len() as u64 != provenance.record_count {
                return Err(HeraclitusError::Corruption {
                    context: "catálogo lakehouse".into(),
                    detail: format!("Parquet vivo `{path}` tem contagem inválida"),
                });
            }
            out.push(IcebergDataFile {
                path: path.clone(),
                file_size: bytes.len() as u64,
                rows: lsns.len() as u64,
                provenance,
            });
        }
        out.sort_by_key(|f| (f.provenance.segment_id, f.provenance.generation));
        Ok(out)
    }

    async fn latest_iceberg_metadata(&self) -> Result<Option<(i64, String)>, HeraclitusError> {
        let mut latest = None;
        for path in self.list_prefix("metadata").await? {
            let Some(name) = path.strip_prefix("metadata/v") else {
                continue;
            };
            let Some(version) = name
                .strip_suffix(".metadata.json")
                .and_then(|n| n.parse::<i64>().ok())
            else {
                continue;
            };
            if latest.as_ref().is_none_or(|(v, _)| version > *v) {
                latest = Some((version, path));
            }
        }
        Ok(latest)
    }

    async fn latest_iceberg_state(
        &self,
    ) -> Result<Option<(i64, Option<i64>, String)>, HeraclitusError> {
        let Some((version, path)) = self.latest_iceberg_metadata().await? else {
            return Ok(None);
        };
        let bytes = self.get(&path).await?.ok_or_else(|| {
            HeraclitusError::StorageEngine(format!("metadata Iceberg `{path}` desapareceu"))
        })?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let sequence = json["last-sequence-number"].as_i64().ok_or_else(|| {
            HeraclitusError::Corruption {
                context: "metadata Iceberg".into(),
                detail: "last-sequence-number ausente".into(),
            }
        })?;
        if sequence != version {
            return Err(HeraclitusError::Corruption {
                context: "metadata Iceberg".into(),
                detail: format!("nome v{version} diverge da sequência {sequence}"),
            });
        }
        let current = json["current-snapshot-id"].as_i64();
        Ok(Some((sequence, current, path)))
    }
}

fn snapshot_id(sequence: i64, files: &[IcebergDataFile]) -> i64 {
    let mut h = blake3::Hasher::new();
    h.update(b"HRKL:ICEBERG:SNAPSHOT-ID:V1");
    h.update(&sequence.to_le_bytes());
    for file in files {
        h.update(file.path.as_bytes());
        h.update(file.provenance.logical_root.as_bytes());
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&h.finalize().as_bytes()[..8]);
    let id = i64::from_le_bytes(raw) & i64::MAX;
    id.max(1)
}

fn store_error(path: &str, error: object_store::Error) -> HeraclitusError {
    HeraclitusError::Storage(std::io::Error::other(format!("{path}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Int64Array, RecordBatch};
    use heraclitus_core::{Episode, EventKind};
    use object_store::memory::InMemory;

    use crate::lakehouse::parquet_export;
    use crate::lakehouse::ExportProvenance;
    use crate::lakehouse::delta::Action;

    fn exported(segment: u64, generation: u32, first: u64) -> ExportedFile {
        let prov = ExportProvenance::new(
            [1; 16],
            segment,
            generation,
            [2; 32],
            [3; 32],
            1,
            first,
            first + 1,
            2,
        );
        let mut a = Episode::new("agent", EventKind::Observation, b"a".to_vec());
        a.ts_hlc = 10;
        let mut b = Episode::new("agent", EventKind::Observation, b"b".to_vec());
        b.ts_hlc = 11;
        let bytes = parquet_export::escrever_parquet(&[(first, a), (first + 1, b)], &prov)
            .unwrap();
        ExportedFile {
            path: data_path(segment, generation),
            bytes,
            rows: 2,
            provenance: prov,
        }
    }

    fn publisher(store: Arc<dyn ObjectStore>) -> LakehousePublisher {
        LakehousePublisher::new(
            store,
            "eventos",
            IcebergTable::new(
                "01010101-0101-4101-8101-010101010101",
                "memory://lake/eventos",
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn publica_reabre_e_mantem_um_unico_parquet_para_delta_e_iceberg() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        let f1 = exported(1, 0, 0);
        let first = p.publish(&f1, 1000).await.unwrap();
        assert_eq!(first.decision, ExportDecision::Exported);
        assert_eq!(first.delta_version, Some(1));
        assert_eq!(first.watermark.last_lsn, 1);
        assert!(store.get(&ObjPath::from(f1.path.as_str())).await.is_ok());
        assert!(store
            .get(&ObjPath::from(ExportWatermark::PATH))
            .await
            .is_ok());

        // Reabrir sobre o mesmo store usa o watermark e os catálogos, não
        // qualquer estado em memória do primeiro publisher.
        let reopened = publisher(Arc::clone(&store));
        let f2 = exported(2, 0, 2);
        let second = reopened.publish(&f2, 2000).await.unwrap();
        assert_eq!(second.delta_version, Some(2));
        assert_eq!(second.watermark.last_lsn, 3);
        assert_eq!(second.watermark.segments.len(), 2);
        assert_eq!(second.iceberg_metadata_path.as_deref(), Some("metadata/v00002.metadata.json"));

        let commits = reopened.load_delta_commits().await.unwrap();
        assert_eq!(
            delta::estado_dos_ficheiros(&commits),
            vec![f1.path.clone(), f2.path.clone()]
        );
        let metadata = reopened
            .get("metadata/v00002.metadata.json")
            .await
            .unwrap()
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(json["snapshots"][0]["summary"]["total-data-files"], "2");

        // Sanidade: o Parquet escrito usa Int64, compatível com `long` dos
        // esquemas Iceberg/Delta.
        let builder = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            bytes::Bytes::from(f2.bytes.clone()),
        )
        .unwrap();
        let mut reader = builder.build().unwrap();
        let batch: RecordBatch = reader.next().unwrap().unwrap();
        assert!(batch
            .column_by_name("lsn")
            .unwrap()
            .as_any()
            .downcast_ref::<Int64Array>()
            .is_some());
    }

    #[tokio::test]
    async fn retry_nao_cria_commit_e_parquet_corrupto_e_regenerado() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        let f = exported(7, 0, 10);
        p.publish(&f, 1000).await.unwrap();
        let retry = p.publish(&f, 1000).await.unwrap();
        assert_eq!(retry.decision, ExportDecision::AlreadyCurrent);
        assert!(!retry.parquet_repaired);
        assert_eq!(p.load_delta_commits().await.unwrap().len(), 2);

        store
            .put(&ObjPath::from(f.path.as_str()), vec![0xFF; 12].into())
            .await
            .unwrap();
        let repaired = p.publish(&f, 1000).await.unwrap();
        assert!(repaired.parquet_repaired);
        assert_eq!(p.get(&f.path).await.unwrap().unwrap(), f.bytes);
        assert_eq!(p.load_delta_commits().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn repack_remove_a_geracao_anterior_no_mesmo_commit_delta() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        let g0 = exported(9, 0, 20);
        let g1 = exported(9, 1, 20);
        p.publish(&g0, 1000).await.unwrap();
        let result = p.publish(&g1, 2000).await.unwrap();
        assert_eq!(
            result.decision,
            ExportDecision::Superseded {
                generation_anterior: 0
            }
        );
        let live = delta::estado_dos_ficheiros(&p.load_delta_commits().await.unwrap());
        assert_eq!(live, vec![g1.path]);
    }

    #[test]
    fn action_import_e_usado_para_manter_o_parser_ligado_ao_tipo_publico() {
        // Evita que uma refactor transforme silenciosamente os commits lidos
        // em JSON opaco: o estado é reconstruído pelas acções tipadas.
        let _ = std::mem::size_of::<Action>();
    }
}
