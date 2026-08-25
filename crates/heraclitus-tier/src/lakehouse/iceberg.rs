//! SPEC-0050 §209 — metadata Apache Iceberg v2 sobre o Parquet derivado.
//!
//! Este módulo não chama o catálogo interno `.hrkm` de Iceberg. Ele produz os
//! três artefactos externos exigidos pelo formato: manifest Avro, manifest
//! list Avro e table metadata JSON. Os dois primeiros usam os field ids
//! definidos pela especificação Iceberg v2; a metadata aponta para eles por
//! URI absoluta e para os mesmos ficheiros Parquet usados pelo exportador
//! Delta.

use heraclitus_core::HeraclitusError;
use serde::{Deserialize, Serialize};

use super::avro::{
    write_int, write_long, write_ocf, write_string, write_union_null, write_union_some, SYNC_LEN,
};
use super::ExportedFile;
use super::ExportProvenance;

pub const FORMAT_VERSION: u32 = 2;
pub const SCHEMA_ID: i32 = 0;
pub const PARTITION_SPEC_ID: i32 = 0;
pub const SORT_ORDER_ID: i32 = 0;
pub const LAST_COLUMN_ID: i32 = 14;

/// Um objecto que deve ser publicado no directório da tabela.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcebergObject {
    /// Chave relativa ao `location` da tabela.
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Snapshot Iceberg completo, pronto para publicação.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcebergSnapshot {
    pub snapshot_id: i64,
    pub sequence_number: i64,
    pub manifest: IcebergObject,
    pub manifest_list: IcebergObject,
    pub table_metadata: IcebergObject,
}

/// Identidade estável de uma tabela Iceberg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcebergTable {
    /// UUID textual RFC 4122. É fornecido pelo chamador e nunca gerado ao
    /// exportar, para retries produzirem exactamente os mesmos bytes.
    pub table_uuid: String,
    /// URI absoluta (`file:///`, `s3://`, `gs://`, ...), sem barra final.
    pub location: String,
}

/// Descrição persistível de um Parquet vivo. Ao contrário de
/// [`ExportedFile`], não carrega o corpo inteiro do ficheiro; por isso o
/// publisher consegue reconstruir snapshots Iceberg depois de reiniciar sem
/// reler gigabytes do object store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcebergDataFile {
    pub path: String,
    pub file_size: u64,
    pub rows: u64,
    pub provenance: ExportProvenance,
}

impl From<&ExportedFile> for IcebergDataFile {
    fn from(value: &ExportedFile) -> Self {
        Self {
            path: value.path.clone(),
            file_size: value.size(),
            rows: value.rows,
            provenance: value.provenance.clone(),
        }
    }
}

impl IcebergTable {
    pub fn new(
        table_uuid: impl Into<String>,
        location: impl Into<String>,
    ) -> Result<Self, HeraclitusError> {
        let table_uuid = table_uuid.into();
        let location = location.into().trim_end_matches('/').to_string();
        if !uuid_valido(&table_uuid) {
            return Err(HeraclitusError::Config(format!(
                "table_uuid Iceberg inválido: `{table_uuid}`"
            )));
        }
        if !uri_absoluta(&location) {
            return Err(HeraclitusError::Config(format!(
                "location Iceberg deve ser URI absoluta: `{location}`"
            )));
        }
        Ok(Self {
            table_uuid,
            location,
        })
    }

    pub fn absolute(&self, relative: &str) -> String {
        format!("{}/{}", self.location, relative.trim_start_matches('/'))
    }
}

/// Constrói um snapshot Iceberg v2 que representa exactamente `files`.
///
/// O snapshot usa um manifest novo contendo todos os ficheiros vivos. Isso é
/// deliberadamente simples e correcto: uma futura compactação de manifests
/// pode reutilizar entradas `EXISTING`, mas não é necessária para que o
/// snapshot seja uma representação completa e independente da projecção.
pub fn build_snapshot(
    table: &IcebergTable,
    snapshot_id: i64,
    sequence_number: i64,
    timestamp_ms: i64,
    parent_snapshot_id: Option<i64>,
    files: &[ExportedFile],
) -> Result<IcebergSnapshot, HeraclitusError> {
    let files = files.iter().map(IcebergDataFile::from).collect::<Vec<_>>();
    build_snapshot_metadata(
        table,
        snapshot_id,
        sequence_number,
        timestamp_ms,
        parent_snapshot_id,
        &files,
    )
}

/// Igual a [`build_snapshot`], mas recebe só metadata dos Parquet já
/// publicados. É a variante usada ao reabrir uma tabela.
pub fn build_snapshot_metadata(
    table: &IcebergTable,
    snapshot_id: i64,
    sequence_number: i64,
    timestamp_ms: i64,
    parent_snapshot_id: Option<i64>,
    files: &[IcebergDataFile],
) -> Result<IcebergSnapshot, HeraclitusError> {
    if snapshot_id <= 0 {
        return Err(HeraclitusError::Config(
            "snapshot_id Iceberg deve ser positivo".into(),
        ));
    }
    if sequence_number <= 0 {
        return Err(HeraclitusError::Config(
            "sequence_number Iceberg deve ser positivo".into(),
        ));
    }
    validar_ficheiros(files)?;

    let manifest_path = format!(
        "metadata/{snapshot_id:020}-m0-{sequence_number:010}.avro"
    );
    let manifest_list_path = format!(
        "metadata/snap-{snapshot_id:020}-{sequence_number:010}.avro"
    );
    let metadata_path = format!("metadata/v{sequence_number:05}.metadata.json");

    let manifest_bytes = build_manifest(table, snapshot_id, files)?;
    let manifest = IcebergObject {
        path: manifest_path.clone(),
        bytes: manifest_bytes,
    };
    let manifest_list = IcebergObject {
        path: manifest_list_path.clone(),
        bytes: build_manifest_list(
            table,
            snapshot_id,
            sequence_number,
            files,
            &manifest_path,
            manifest.bytes.len() as u64,
        )?,
    };
    let table_metadata = IcebergObject {
        path: metadata_path,
        bytes: build_table_metadata(
            table,
            snapshot_id,
            sequence_number,
            timestamp_ms,
            parent_snapshot_id,
            files,
            &manifest_list_path,
        )?,
    };

    Ok(IcebergSnapshot {
        snapshot_id,
        sequence_number,
        manifest,
        manifest_list,
        table_metadata,
    })
}

fn build_manifest(
    table: &IcebergTable,
    snapshot_id: i64,
    files: &[IcebergDataFile],
) -> Result<Vec<u8>, HeraclitusError> {
    let mut datums = Vec::with_capacity(files.len());
    for file in files {
        let mut d = Vec::new();
        // manifest_entry.status = ADDED
        write_int(&mut d, 1);
        write_union_some(&mut d);
        write_long(&mut d, snapshot_id);
        // Os sequence numbers dos ADDED podem ser herdados da manifest list.
        write_union_null(&mut d);
        write_union_null(&mut d);

        // data_file
        write_int(&mut d, 0); // content = DATA
        write_string(&mut d, &table.absolute(&file.path));
        write_string(&mut d, "PARQUET");
        // partition é um record vazio: esta primeira versão é unpartitioned.
        write_long(
            &mut d,
            i64::try_from(file.rows).map_err(|_| overflow("record_count"))?,
        );
        write_long(
            &mut d,
            i64::try_from(file.file_size).map_err(|_| overflow("file_size_in_bytes"))?,
        );
        // Métricas opcionais. Continuam no Parquet e no summary; não se
        // inventam mapas incompletos no manifest.
        for _ in 0..10 {
            write_union_null(&mut d);
        }
        datums.push(d);
    }

    let schema = manifest_schema();
    let table_schema = serde_json::to_string(&iceberg_schema())
        .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
    let sync = sync_marker(b"HRKL:ICEBERG:MANIFEST:V2", snapshot_id, files);
    write_ocf(
        &schema,
        &[
            ("content", b"data"),
            ("format-version", b"2"),
            ("partition-spec", b"[]"),
            ("partition-spec-id", b"0"),
            ("schema", table_schema.as_bytes()),
            ("schema-id", b"0"),
        ],
        &datums,
        sync,
    )
}

fn build_manifest_list(
    table: &IcebergTable,
    snapshot_id: i64,
    sequence_number: i64,
    files: &[IcebergDataFile],
    manifest_path: &str,
    manifest_len: u64,
) -> Result<Vec<u8>, HeraclitusError> {
    let rows = files.iter().try_fold(0u64, |n, f| {
        n.checked_add(f.rows).ok_or_else(|| overflow("added_rows_count"))
    })?;
    let mut d = Vec::new();
    write_string(&mut d, &table.absolute(manifest_path));
    write_long(
        &mut d,
        i64::try_from(manifest_len).map_err(|_| overflow("manifest_length"))?,
    );
    write_int(&mut d, PARTITION_SPEC_ID);
    write_int(&mut d, 0); // content = data
    write_long(&mut d, sequence_number);
    write_long(&mut d, sequence_number);
    write_long(&mut d, snapshot_id);
    write_int(
        &mut d,
        i32::try_from(files.len()).map_err(|_| overflow("added_files_count"))?,
    );
    write_int(&mut d, 0); // existing files
    write_int(&mut d, 0); // deleted files
    write_long(
        &mut d,
        i64::try_from(rows).map_err(|_| overflow("added_rows_count"))?,
    );
    write_long(&mut d, 0); // existing rows
    write_long(&mut d, 0); // deleted rows
    write_union_null(&mut d); // partitions (unpartitioned)
    write_union_null(&mut d); // key_metadata

    let sync = sync_marker(b"HRKL:ICEBERG:MANIFEST-LIST:V2", snapshot_id, files);
    write_ocf(&manifest_list_schema(), &[], &[d], sync)
}

#[allow(clippy::too_many_arguments)]
fn build_table_metadata(
    table: &IcebergTable,
    snapshot_id: i64,
    sequence_number: i64,
    timestamp_ms: i64,
    parent_snapshot_id: Option<i64>,
    files: &[IcebergDataFile],
    manifest_list_path: &str,
) -> Result<Vec<u8>, HeraclitusError> {
    let total_rows = files.iter().try_fold(0u64, |n, f| {
        n.checked_add(f.rows).ok_or_else(|| overflow("total-records"))
    })?;
    let exported_through_lsn = files
        .iter()
        .map(|f| f.provenance.last_lsn)
        .max()
        .unwrap_or(0);

    let mut snapshot = serde_json::json!({
        "snapshot-id": snapshot_id,
        "sequence-number": sequence_number,
        "timestamp-ms": timestamp_ms,
        "manifest-list": table.absolute(manifest_list_path),
        "summary": {
            "operation": "append",
            "added-data-files": files.len().to_string(),
            "added-records": total_rows.to_string(),
            "total-data-files": files.len().to_string(),
            "total-records": total_rows.to_string(),
            "heraclitus.exported_through_lsn": exported_through_lsn.to_string()
        },
        "schema-id": SCHEMA_ID
    });
    if let Some(parent) = parent_snapshot_id {
        snapshot["parent-snapshot-id"] = serde_json::json!(parent);
    }

    let metadata = serde_json::json!({
        "format-version": FORMAT_VERSION,
        "table-uuid": table.table_uuid,
        "location": table.location,
        "last-sequence-number": sequence_number,
        "last-updated-ms": timestamp_ms,
        "last-column-id": LAST_COLUMN_ID,
        "schemas": [iceberg_schema()],
        "current-schema-id": SCHEMA_ID,
        "partition-specs": [{"spec-id": PARTITION_SPEC_ID, "fields": []}],
        "default-spec-id": PARTITION_SPEC_ID,
        "last-partition-id": 999,
        "properties": {
            "heraclitus.export_format_version": super::EXPORT_FORMAT_VERSION.to_string(),
            "heraclitus.exported_through_lsn": exported_through_lsn.to_string()
        },
        "current-snapshot-id": snapshot_id,
        "snapshots": [snapshot],
        "snapshot-log": [{"timestamp-ms": timestamp_ms, "snapshot-id": snapshot_id}],
        "metadata-log": [],
        "sort-orders": [{"order-id": SORT_ORDER_ID, "fields": []}],
        "default-sort-order-id": SORT_ORDER_ID,
        "refs": {"main": {"snapshot-id": snapshot_id, "type": "branch"}}
    });
    serde_json::to_vec_pretty(&metadata)
        .map_err(|e| HeraclitusError::Serialization(e.to_string()))
}

fn iceberg_schema() -> serde_json::Value {
    let required = |id: i32, name: &str, ty: &str| {
        serde_json::json!({"id": id, "name": name, "required": true, "type": ty})
    };
    let optional = |id: i32, name: &str, ty: &str| {
        serde_json::json!({"id": id, "name": name, "required": false, "type": ty})
    };
    serde_json::json!({
        "type": "struct",
        "schema-id": SCHEMA_ID,
        "fields": [
            required(1, "lsn", "long"),
            required(2, "id", "string"),
            required(3, "agent_id", "string"),
            required(4, "session_id", "string"),
            required(5, "ts_hlc", "long"),
            required(6, "kind", "string"),
            required(7, "content", "binary"),
            required(8, "attrs_json", "string"),
            required(9, "parents_json", "string"),
            optional(10, "valid_from", "long"),
            optional(11, "valid_to", "long"),
            optional(12, "embedding_json", "string"),
            required(13, "segment_id", "long"),
            required(14, "generation", "long")
        ]
    })
}

fn manifest_schema() -> String {
    // O schema inclui todos os campos v2 obrigatórios e as métricas opcionais.
    // Os `field-id` não são decoração: leitores Iceberg fazem projection por
    // id, não por posição nem apenas por nome.
    serde_json::json!({
        "type": "record", "name": "manifest_entry", "fields": [
            {"name":"status", "type":"int", "field-id":0},
            {"name":"snapshot_id", "type":["null","long"], "default":null, "field-id":1},
            {"name":"sequence_number", "type":["null","long"], "default":null, "field-id":3},
            {"name":"file_sequence_number", "type":["null","long"], "default":null, "field-id":4},
            {"name":"data_file", "field-id":2, "type":{
                "type":"record", "name":"data_file", "fields":[
                    {"name":"content", "type":"int", "field-id":134},
                    {"name":"file_path", "type":"string", "field-id":100},
                    {"name":"file_format", "type":"string", "field-id":101},
                    {"name":"partition", "field-id":102, "type":{"type":"record","name":"r102","fields":[]}},
                    {"name":"record_count", "type":"long", "field-id":103},
                    {"name":"file_size_in_bytes", "type":"long", "field-id":104},
                    {"name":"column_sizes", "type":["null",{"type":"map","values":"long","key-id":117,"value-id":118}], "default":null, "field-id":108},
                    {"name":"value_counts", "type":["null",{"type":"map","values":"long","key-id":119,"value-id":120}], "default":null, "field-id":109},
                    {"name":"null_value_counts", "type":["null",{"type":"map","values":"long","key-id":121,"value-id":122}], "default":null, "field-id":110},
                    {"name":"nan_value_counts", "type":["null",{"type":"map","values":"long","key-id":138,"value-id":139}], "default":null, "field-id":137},
                    {"name":"lower_bounds", "type":["null",{"type":"map","values":"bytes","key-id":126,"value-id":127}], "default":null, "field-id":125},
                    {"name":"upper_bounds", "type":["null",{"type":"map","values":"bytes","key-id":129,"value-id":130}], "default":null, "field-id":128},
                    {"name":"key_metadata", "type":["null","bytes"], "default":null, "field-id":131},
                    {"name":"split_offsets", "type":["null",{"type":"array","items":"long","element-id":133}], "default":null, "field-id":132},
                    {"name":"equality_ids", "type":["null",{"type":"array","items":"int","element-id":136}], "default":null, "field-id":135},
                    {"name":"sort_order_id", "type":["null","int"], "default":null, "field-id":140}
                ]
            }}
        ]
    })
    .to_string()
}

fn manifest_list_schema() -> String {
    serde_json::json!({
        "type":"record", "name":"manifest_file", "fields":[
            {"name":"manifest_path", "type":"string", "field-id":500},
            {"name":"manifest_length", "type":"long", "field-id":501},
            {"name":"partition_spec_id", "type":"int", "field-id":502},
            {"name":"content", "type":"int", "field-id":517},
            {"name":"sequence_number", "type":"long", "field-id":515},
            {"name":"min_sequence_number", "type":"long", "field-id":516},
            {"name":"added_snapshot_id", "type":"long", "field-id":503},
            {"name":"added_files_count", "type":"int", "field-id":504},
            {"name":"existing_files_count", "type":"int", "field-id":505},
            {"name":"deleted_files_count", "type":"int", "field-id":506},
            {"name":"added_rows_count", "type":"long", "field-id":512},
            {"name":"existing_rows_count", "type":"long", "field-id":513},
            {"name":"deleted_rows_count", "type":"long", "field-id":514},
            {"name":"partitions", "type":["null",{"type":"array","element-id":508,"items":{
                "type":"record", "name":"field_summary", "fields":[
                    {"name":"contains_null", "type":"boolean", "field-id":509},
                    {"name":"contains_nan", "type":["null","boolean"], "default":null, "field-id":518},
                    {"name":"lower_bound", "type":["null","bytes"], "default":null, "field-id":510},
                    {"name":"upper_bound", "type":["null","bytes"], "default":null, "field-id":511}
                ]
            }}], "default":null, "field-id":507},
            {"name":"key_metadata", "type":["null","bytes"], "default":null, "field-id":519}
        ]
    })
    .to_string()
}

fn validar_ficheiros(files: &[IcebergDataFile]) -> Result<(), HeraclitusError> {
    let mut anteriores = std::collections::BTreeSet::new();
    for f in files {
        if !f.path.ends_with(".parquet") || f.path.starts_with('/') || uri_absoluta(&f.path) {
            return Err(HeraclitusError::Config(format!(
                "caminho Parquet deve ser relativo à tabela: `{}`",
                f.path
            )));
        }
        if !anteriores.insert(&f.path) {
            return Err(HeraclitusError::Config(format!(
                "ficheiro Parquet duplicado no snapshot: `{}`",
                f.path
            )));
        }
        if f.rows != f.provenance.record_count {
            return Err(HeraclitusError::Corruption {
                context: "snapshot Iceberg".into(),
                detail: format!(
                    "{} declara {} linhas mas a proveniência declara {}",
                    f.path, f.rows, f.provenance.record_count
                ),
            });
        }
    }
    Ok(())
}

fn sync_marker(domain: &[u8], snapshot_id: i64, files: &[IcebergDataFile]) -> [u8; SYNC_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&snapshot_id.to_le_bytes());
    for f in files {
        h.update(f.path.as_bytes());
        h.update(f.provenance.logical_root.as_bytes());
    }
    let mut out = [0u8; SYNC_LEN];
    out.copy_from_slice(&h.finalize().as_bytes()[..SYNC_LEN]);
    out
}

fn uuid_valido(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 8 | 13 | 18 | 23) && *b == b'-' || !matches!(i, 8 | 13 | 18 | 23) && b.is_ascii_hexdigit())
}

fn uri_absoluta(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || i > 0 && (b.is_ascii_digit() || b == b'+' || b == b'-' || b == b'.'))
        && !rest.is_empty()
}

fn overflow(campo: &str) -> HeraclitusError {
    HeraclitusError::Serialization(format!("Iceberg `{campo}` excede o tipo do formato"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lakehouse::avro::read_ocf;
    use crate::lakehouse::{ExportProvenance, ExportedFile};

    fn file(seg: u64, generation: u32, lo: u64, hi: u64) -> ExportedFile {
        ExportedFile {
            path: format!("data/segment-{seg:010}-gen-{generation:04}.parquet"),
            bytes: vec![0x50; 100 + seg as usize],
            rows: hi - lo + 1,
            provenance: ExportProvenance::new(
                [1; 16],
                seg,
                generation,
                [2; 32],
                [3; 32],
                1,
                lo,
                hi,
                hi - lo + 1,
            ),
        }
    }

    fn table() -> IcebergTable {
        IcebergTable::new(
            "01010101-0101-4101-8101-010101010101",
            "s3://lake/eventos",
        )
        .unwrap()
    }

    #[test]
    fn gera_os_tres_niveis_reais_de_metadata_v2() {
        let files = vec![file(1, 0, 0, 9), file(2, 0, 10, 19)];
        let out = build_snapshot(&table(), 77, 1, 1234, None, &files).unwrap();

        let manifest = read_ocf(&out.manifest.bytes).unwrap();
        assert_eq!(manifest.total_datums(), 2);
        assert_eq!(manifest.metadata_get("format-version"), Some(&b"2"[..]));
        assert_eq!(manifest.metadata_get("content"), Some(&b"data"[..]));
        assert!(manifest.schema_json.contains("\"field-id\":134"));

        let list = read_ocf(&out.manifest_list.bytes).unwrap();
        assert_eq!(list.total_datums(), 1);
        assert!(list.schema_json.contains("\"field-id\":500"));

        let metadata: serde_json::Value =
            serde_json::from_slice(&out.table_metadata.bytes).unwrap();
        assert_eq!(metadata["format-version"], 2);
        assert_eq!(metadata["last-sequence-number"], 1);
        assert_eq!(metadata["current-snapshot-id"], 77);
        assert_eq!(metadata["partition-specs"][0]["fields"], serde_json::json!([]));
        assert_eq!(metadata["sort-orders"][0]["fields"], serde_json::json!([]));
        assert_eq!(
            metadata["snapshots"][0]["summary"]["heraclitus.exported_through_lsn"],
            "19"
        );
        assert_eq!(
            metadata["snapshots"][0]["manifest-list"],
            table().absolute(&out.manifest_list.path)
        );
    }

    #[test]
    fn iceberg_e_delta_apontam_para_o_mesmo_parquet_derivado() {
        let f = file(8, 2, 40, 49);
        let ice = build_snapshot(&table(), 88, 1, 10, None, std::slice::from_ref(&f)).unwrap();
        let delta = crate::lakehouse::delta::commit_append(
            1,
            std::slice::from_ref(&f),
            &[],
            10,
        )
        .unwrap();
        let delta_json = String::from_utf8(delta.bytes).unwrap();
        assert!(delta_json.contains(&f.path));

        // O path dentro do manifest é Avro, portanto verificamos os bytes do
        // datum; não há uma segunda materialização de dados no snapshot.
        let manifest = read_ocf(&ice.manifest.bytes).unwrap();
        assert!(manifest.blocos[0]
            .1
            .windows(f.path.len())
            .any(|w| w == f.path.as_bytes()));
    }

    #[test]
    fn build_e_deterministico_e_nao_aceita_duplicados() {
        let f = file(1, 0, 0, 9);
        let a = build_snapshot(&table(), 9, 1, 7, None, std::slice::from_ref(&f)).unwrap();
        let b = build_snapshot(&table(), 9, 1, 7, None, std::slice::from_ref(&f)).unwrap();
        assert_eq!(a, b);
        assert!(build_snapshot(&table(), 9, 1, 7, None, &[f.clone(), f]).is_err());
    }

    #[test]
    fn hrkm_nunca_vira_metadata_iceberg() {
        let out = build_snapshot(&table(), 1, 1, 1, None, &[file(1, 0, 0, 0)]).unwrap();
        for object in [&out.manifest, &out.manifest_list, &out.table_metadata] {
            assert!(!object.path.ends_with(".hrkm"));
            assert!(!object.bytes.windows(5).any(|w| w == b".hrkm"));
        }
    }

    #[test]
    fn location_e_uuid_sao_validados() {
        assert!(IcebergTable::new("não-é-uuid", "s3://b/t").is_err());
        assert!(IcebergTable::new(
            "01010101-0101-4101-8101-010101010101",
            "caminho/relativo"
        )
        .is_err());
    }
}
