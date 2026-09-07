//! Publicação transaccional por derivação das projecções lakehouse.
//!
//! O commit externo segue a ordem `Parquet -> Iceberg -> Delta -> watermark`.
//! O watermark é, portanto, o último reconhecimento de sucesso. Se o processo
//! cair depois do Delta e antes dele, a reabertura encontra o `add` no log
//! Delta e conclui apenas o watermark; nunca cria uma segunda adição lógica.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use futures::StreamExt;
use heraclitus_core::HeraclitusError;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions};

use super::delta::{self, Action, Add, DeltaCommit};
use super::iceberg::{self, IcebergDataFile, IcebergTable};
use super::parquet_export::{data_path, read_lsns, read_provenance};
use super::{ExportDecision, ExportProvenance, ExportWatermark, ExportedFile};

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
            .load_live_metadata(&next_live, Some(file), &commits)
            .await?;

        let (last_iceberg_sequence, parent_snapshot, _) = self
            .latest_iceberg_state()
            .await?
            .unwrap_or((0, None, String::new()));
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
        let delta_version = last_delta
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| HeraclitusError::StorageEngine("versão do log Delta esgotada".into()))?;
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
        Ok(self
            .list_prefix_com_tamanho(prefix)
            .await?
            .into_iter()
            .map(|(caminho, _)| caminho)
            .collect())
    }

    /// O mesmo LIST, guardando o `size` que o `ObjectMeta` já traz.
    ///
    /// Auditoria 2026-09-05, A16: um LIST diz, num único pedido e sem
    /// transferir dados, que objectos existem e quanto pesam. É o que
    /// substitui o GET integral de cada Parquet vivo a cada publicação.
    async fn list_prefix_com_tamanho(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, u64)>, HeraclitusError> {
        let mut stream = self.store.list(Some(&ObjPath::from(prefix)));
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            let meta = item.map_err(|e| store_error(prefix, e))?;
            out.push((meta.location.to_string(), meta.size));
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

    /// Os metadados dos Parquet vivos que entram no snapshot Iceberg.
    ///
    /// Auditoria 2026-09-05, A16: isto fazia um GET integral de CADA ficheiro
    /// vivo e duas passagens de Parquet por cima (`read_provenance` +
    /// `read_lsns`) a cada publicação. Como o conjunto vivo cresce um ficheiro
    /// por segmento e só encolhe num repack, publicar N segmentos custava
    /// O(N²) bytes de rede — com o `segment_max_bytes` por omissão de 8 MiB,
    /// publicar 625 segmentos lia centenas de GB só para preencher quatro
    /// campos que o log Delta já guarda em cada acção `add` e que
    /// `load_delta_commits` já trouxe para RAM: `path`, `size`,
    /// `stats.numRecords` e as `tags` de proveniência. Passam a ser derivados
    /// daí.
    ///
    /// O que se perde, e onde foi parar: o GET era também a única
    /// reverificação dos bytes dos ficheiros ANTIGOS. Presença e tamanho
    /// continuam verificados — agora por um único LIST, O(1) em pedidos — e a
    /// verificação interna (LSNs contra a proveniência) passa a viver em
    /// [`Self::verificar_ficheiros_vivos`], que um `doctor` corre quando
    /// quiser em vez de N vezes ao publicar N segmentos. O ficheiro que ENTRA
    /// continua verificado byte a byte por `validate_export` e `put_parquet`.
    async fn load_live_metadata(
        &self,
        paths: &BTreeSet<String>,
        incoming: Option<&ExportedFile>,
        commits: &[DeltaCommit],
    ) -> Result<Vec<IcebergDataFile>, HeraclitusError> {
        let adds = ultimos_adds(commits);
        let mut tamanhos: BTreeMap<String, u64> = BTreeMap::new();
        let mut listado = false;
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(file) = incoming.filter(|f| &f.path == path) {
                out.push(IcebergDataFile::from(file));
                continue;
            }
            let derivado = match adds.get(path.as_str()) {
                Some(add) => data_file_do_add(path, add)?,
                None => None,
            };
            let Some(data_file) = derivado else {
                // Acção `add` sem tudo o que é preciso (log escrito por uma
                // versão anterior): lê-se o ficheiro, e só este.
                out.push(self.data_file_do_store(path).await?);
                continue;
            };
            if !listado {
                tamanhos = self
                    .list_prefix_com_tamanho("data")
                    .await?
                    .into_iter()
                    .collect();
                listado = true;
            }
            let Some(tamanho) = tamanhos.get(path.as_str()).copied() else {
                return Err(HeraclitusError::Corruption {
                    context: "catálogo lakehouse".into(),
                    detail: format!("Parquet vivo `{path}` está ausente"),
                });
            };
            if tamanho != data_file.file_size {
                return Err(HeraclitusError::Corruption {
                    context: "catálogo lakehouse".into(),
                    detail: format!(
                        "Parquet vivo `{path}` tem {tamanho} bytes, o log Delta declara {}",
                        data_file.file_size
                    ),
                });
            }
            out.push(data_file);
        }
        out.sort_by_key(|f| (f.provenance.segment_id, f.provenance.generation));
        Ok(out)
    }

    /// Os metadados de um Parquet vivo lidos dos próprios bytes.
    ///
    /// O caminho lento e completo: vivia inline em `load_live_metadata` e
    /// continua a ser o oráculo contra o qual a derivação pelas acções `add` é
    /// comparada nos testes.
    async fn data_file_do_store(&self, path: &str) -> Result<IcebergDataFile, HeraclitusError> {
        let bytes = self
            .get(path)
            .await?
            .ok_or_else(|| HeraclitusError::Corruption {
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
        Ok(IcebergDataFile {
            path: path.to_string(),
            file_size: bytes.len() as u64,
            rows: lsns.len() as u64,
            provenance,
        })
    }

    /// Relê, byte a byte, todos os Parquet vivos da tabela.
    ///
    /// Auditoria 2026-09-05, A16: é aqui que passa a viver a verificação
    /// completa que a publicação deixou de fazer por cada segmento. Não está
    /// no caminho de escrita de propósito: custa O(bytes da tabela) e um
    /// `doctor` corre-a quando quer, não N vezes ao publicar N segmentos.
    pub async fn verificar_ficheiros_vivos(&self) -> Result<Vec<IcebergDataFile>, HeraclitusError> {
        let commits = self.load_delta_commits().await?;
        let mut out = Vec::new();
        for path in delta::estado_dos_ficheiros(&commits) {
            out.push(self.data_file_do_store(&path).await?);
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
        let sequence =
            json["last-sequence-number"]
                .as_i64()
                .ok_or_else(|| HeraclitusError::Corruption {
                    context: "metadata Iceberg".into(),
                    detail: "last-sequence-number ausente".into(),
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

/// A última acção `add` de cada caminho, por ordem de versão do log.
///
/// Um repack reescreve o segmento numa geração nova, logo num caminho novo;
/// mas um caminho removido e mais tarde readicionado tem de ficar com o `add`
/// mais recente, e é por isso que a iteração é ordenada por versão.
fn ultimos_adds(commits: &[DeltaCommit]) -> BTreeMap<&str, &Add> {
    let mut ordenados: Vec<&DeltaCommit> = commits.iter().collect();
    ordenados.sort_by_key(|c| c.version);
    let mut out: BTreeMap<&str, &Add> = BTreeMap::new();
    for commit in ordenados {
        for accao in &commit.actions {
            if let Action::Add(add) = accao {
                out.insert(add.path.as_str(), add.as_ref());
            }
        }
    }
    out
}

/// Reconstrói os metadados Iceberg de um Parquet vivo a partir da acção `add`
/// que o log Delta já guarda — sem tocar nos bytes do ficheiro.
///
/// `Ok(None)` significa "esta acção não chega": quem chama lê o Parquet. Nunca
/// se inventa um valor por omissão, porque estes quatro campos entram nos
/// bytes do manifest Iceberg e um `unwrap_or(0)` mudaria o `snapshot_id` sem
/// barulho nenhum.
fn data_file_do_add(path: &str, add: &Add) -> Result<Option<IcebergDataFile>, HeraclitusError> {
    let Some(tags) = add.tags.as_ref() else {
        return Ok(None);
    };
    let Ok(provenance) = ExportProvenance::from_key_values(tags) else {
        return Ok(None);
    };
    let Some(stats) = add.stats.as_ref() else {
        return Ok(None);
    };
    let Ok(stats) = serde_json::from_str::<serde_json::Value>(stats) else {
        return Ok(None);
    };
    let Some(rows) = stats.get("numRecords").and_then(|v| v.as_u64()) else {
        return Ok(None);
    };
    // O que o GET apurava de caminho sobre os ficheiros antigos: contagem e
    // proveniência têm de concordar. Aqui a comparação é entre duas partes do
    // MESMO `add`, e uma discordância significa um log Delta incoerente.
    if rows != provenance.record_count {
        return Err(HeraclitusError::Corruption {
            context: "catálogo lakehouse".into(),
            detail: format!(
                "Parquet vivo `{path}` tem contagem inválida: o `add` declara {rows} registos \
                 e a proveniência {}",
                provenance.record_count
            ),
        });
    }
    Ok(Some(IcebergDataFile {
        path: path.to_string(),
        file_size: add.size,
        rows,
        provenance,
    }))
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

    use crate::lakehouse::delta::Action;
    use crate::lakehouse::parquet_export;
    use crate::lakehouse::ExportProvenance;

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
        let bytes = parquet_export::escrever_parquet(&[(first, a), (first + 1, b)], &prov).unwrap();
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
        assert_eq!(
            second.iceberg_metadata_path.as_deref(),
            Some("metadata/v00002.metadata.json")
        );

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

    #[tokio::test]
    async fn publicar_nao_rele_os_bytes_dos_parquet_ja_publicados() {
        // Auditoria 2026-09-05, A16: a publicação derivava os metadados de
        // TODOS os Parquet vivos relendo-os do object store, o que torna
        // publicar N segmentos O(N^2) em bytes. Prova-se aqui pela
        // consequência observável: substituir os bytes dos ficheiros ANTIGOS
        // por lixo do MESMO tamanho não pode mudar um único byte da metadata
        // publicada — se mudasse (ou rebentasse), é porque foram lidos.
        let ficheiros = [exported(1, 0, 0), exported(2, 0, 2), exported(3, 0, 4)];

        let store_ref: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p_ref = publisher(Arc::clone(&store_ref));
        for (i, f) in ficheiros.iter().enumerate() {
            p_ref.publish(f, 1000 + i as i64).await.unwrap();
        }
        let esperado = p_ref
            .get("metadata/v00003.metadata.json")
            .await
            .unwrap()
            .unwrap();

        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        for (i, f) in ficheiros.iter().enumerate() {
            for anterior in &ficheiros[..i] {
                store
                    .put(
                        &ObjPath::from(anterior.path.as_str()),
                        vec![0xAB; anterior.bytes.len()].into(),
                    )
                    .await
                    .unwrap();
            }
            p.publish(f, 1000 + i as i64).await.unwrap();
        }
        let obtido = p
            .get("metadata/v00003.metadata.json")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            obtido, esperado,
            "a metadata publicada dependeu dos bytes dos Parquet antigos"
        );
    }

    #[tokio::test]
    async fn parquet_vivo_ausente_ou_com_tamanho_errado_continua_a_ser_detectado() {
        // Auditoria 2026-09-05, A16: deixar de reler os bytes não pode
        // significar deixar de olhar. Presença e tamanho de cada Parquet vivo
        // passam a ser verificados por um único LIST, e continuam a ser
        // `Corruption` — não um snapshot Iceberg a apontar para o vazio.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        let f1 = exported(1, 0, 0);
        let f2 = exported(2, 0, 2);
        p.publish(&f1, 1000).await.unwrap();

        store
            .put(&ObjPath::from(f1.path.as_str()), vec![0xAB; 7].into())
            .await
            .unwrap();
        let e = p.publish(&f2, 2000).await.unwrap_err().to_string();
        assert!(e.contains("tem 7 bytes"), "erro inesperado: {e}");

        store
            .delete(&ObjPath::from(f1.path.as_str()))
            .await
            .unwrap();
        let e = p.publish(&f2, 2000).await.unwrap_err().to_string();
        assert!(e.contains("está ausente"), "erro inesperado: {e}");
    }

    #[tokio::test]
    async fn metadados_das_accoes_add_sao_iguais_aos_lidos_do_parquet() {
        // Auditoria 2026-09-05, A16: a optimização só é legítima se o
        // resultado for o MESMO. O oráculo é o caminho antigo, que continua a
        // existir em `verificar_ficheiros_vivos`; a comparação é campo a campo
        // e por ordem, porque é a ordem que fixa os bytes do manifest.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        p.publish(&exported(1, 0, 0), 1000).await.unwrap();
        p.publish(&exported(2, 0, 2), 2000).await.unwrap();
        // Um repack, para o conjunto vivo não ser só uma lista de `add`.
        p.publish(&exported(9, 0, 4), 3000).await.unwrap();
        p.publish(&exported(9, 1, 4), 4000).await.unwrap();

        let commits = p.load_delta_commits().await.unwrap();
        let vivos: BTreeSet<String> = delta::estado_dos_ficheiros(&commits).into_iter().collect();
        assert_eq!(vivos.len(), 3, "o repack não removeu a geração anterior");

        let derivado = p.load_live_metadata(&vivos, None, &commits).await.unwrap();
        let do_store = p.verificar_ficheiros_vivos().await.unwrap();
        assert_eq!(derivado, do_store);
    }

    #[tokio::test]
    async fn o_doctor_rele_os_bytes_e_apanha_o_parquet_corrompido() {
        // Auditoria 2026-09-05, A16: a verificação byte a byte dos ficheiros
        // antigos saiu do caminho de escrita, mas não desapareceu. Este é o
        // sítio onde ela passou a viver.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let p = publisher(Arc::clone(&store));
        let f = exported(4, 0, 8);
        p.publish(&f, 1000).await.unwrap();
        assert_eq!(p.verificar_ficheiros_vivos().await.unwrap().len(), 1);

        // Lixo do MESMO tamanho: o LIST da publicação não o distingue, o
        // `doctor` sim.
        store
            .put(
                &ObjPath::from(f.path.as_str()),
                vec![0xAB; f.bytes.len()].into(),
            )
            .await
            .unwrap();
        let e = p.verificar_ficheiros_vivos().await.unwrap_err().to_string();
        assert!(e.contains("Parquet"), "erro inesperado: {e}");
    }

    #[test]
    fn action_import_e_usado_para_manter_o_parser_ligado_ao_tipo_publico() {
        // Evita que uma refactor transforme silenciosamente os commits lidos
        // em JSON opaco: o estado é reconstruído pelas acções tipadas.
        let _ = std::mem::size_of::<Action>();
    }
}
