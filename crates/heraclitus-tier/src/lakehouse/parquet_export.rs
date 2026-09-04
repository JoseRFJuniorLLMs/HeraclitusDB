//! SPEC-0050 §209 — o exportador Parquet v2, a **única** materialização de
//! linhas do lakehouse.
//!
//! ## Porque não se reaproveitou o espelho Parquet do tier v1
//!
//! [`crate::segment_to_parquet`] (C2.4) já escrevia Parquet de um segmento
//! v1–v5. Falha três dos oito itens de §209 e nenhum deles é acrescentável sem
//! mudar o contrato:
//!
//! | item de §209 | espelho v1 | aqui |
//! |---|---|---|
//! | preserva segment provenance | nenhuma metadata: o ficheiro é anónimo | key-value metadata com geração, raiz lógica e digest físico |
//! | é idempotente | nunca comparado; sem watermark | bytes determinísticos + [`super::ExportWatermark`] |
//! | export preserva LSN | sim | sim (coluna `lsn`, não-nula) |
//!
//! O espelho v1 continua a existir para os recibos antigos que o referenciam.
//! Este é o caminho v6.
//!
//! ## Determinismo
//!
//! "Export é idempotente" só é verificável se reexportar produzir **os mesmos
//! bytes**. Três coisas o garantem, e as três estão fixadas explicitamente:
//!
//! 1. `created_by` fixo — o default do `parquet-rs` traz a versão do crate, o
//!    que faria os bytes mudarem numa actualização de dependência sem que uma
//!    linha de dados mudasse.
//! 2. Um único row group, com a ordem de LSN do segmento.
//! 3. Metadata ordenada ([`super::ExportProvenance::key_values`] devolve um
//!    `BTreeMap`).
//!
//! O teste `exportar_duas_vezes_da_os_mesmos_bytes` é o que impede uma
//! regressão silenciosa aqui.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use arrow_array::{ArrayRef, BinaryArray, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use heraclitus_core::{Episode, HeraclitusError, Lsn};
use heraclitus_log::v6::canonical::CANONICAL_CODEC_V1;
use heraclitus_log::v6::error::HARD_MAX_BLOCK_BYTES;
use heraclitus_log::v6::{
    open_packed, physical_digest_of_file, BlockSource, PackedSegmentReader, ScanCounters,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::file::metadata::KeyValue;
use parquet::file::properties::WriterProperties;

use super::{ExportProvenance, ExportedFile};

/// `created_by` fixo. Ver a nota de determinismo no topo do módulo.
pub const CREATED_BY: &str = "heraclitus lakehouse exporter v1 (SPEC-0050 §209)";

/// Esquema da tabela exportada.
///
/// É o mesmo do espelho v1 mais nada: mudar colunas aqui obriga a subir
/// [`super::EXPORT_FORMAT_VERSION`], porque um consumidor que já leu a tabela
/// antiga tem de conseguir detectar a mudança.
pub fn export_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        // §209: "export Parquet preserva LSN". Não-nula: uma linha sem LSN
        // não é rastreável até ao log, e a projecção deixa de ser auditável.
        // Iceberg e Delta só têm `long` assinado. Arrow UInt64 escreveria a
        // annotation Parquet UINT_64, que não é um tipo Iceberg válido.
        Field::new("lsn", DataType::Int64, false),
        Field::new("id", DataType::Utf8, false),
        Field::new("agent_id", DataType::Utf8, false),
        Field::new("session_id", DataType::Utf8, false),
        Field::new("ts_hlc", DataType::Int64, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("content", DataType::Binary, false),
        Field::new("attrs_json", DataType::Utf8, false),
        Field::new("parents_json", DataType::Utf8, false),
        // Bi-temporalidade: NULL = aberto, distinto de um 0 real.
        Field::new("valid_from", DataType::Int64, true),
        Field::new("valid_to", DataType::Int64, true),
        Field::new("embedding_json", DataType::Utf8, true),
        // §209: a proveniência também vive EM COLUNA, não só na metadata do
        // ficheiro. Sem isto, juntar vários Parquet numa tabela só perde a
        // origem de cada linha — e é precisamente o que um lakehouse faz.
        Field::new("segment_id", DataType::Int64, false),
        Field::new("generation", DataType::Int64, false),
    ]))
}

/// Nome canónico do ficheiro de dados de uma geração.
///
/// Inclui a geração de propósito: um repack publica um ficheiro **novo** em
/// vez de sobrescrever o antigo, o que mantém a projecção alinhada com §83 e
/// permite que o commit Iceberg/Delta seja um `add`+`remove` em vez de uma
/// escrita destrutiva.
pub fn data_path(segment_id: u64, generation: u32) -> String {
    format!("data/segment-{segment_id:010}-gen-{generation:04}.parquet")
}

/// De onde vêm as linhas.
///
/// Só aceita um segmento **selado**: um segmento activo ainda cresce, e
/// exportá-lo produziria uma projecção que nunca corresponde a nada. É a
/// metade estrutural da garantia de §209 ("nenhuma projecção lakehouse
/// participa da durabilidade do append").
pub struct ExportSource<S: BlockSource> {
    reader: PackedSegmentReader<S>,
    generation: u32,
    physical_digest: [u8; 32],
}

impl<S: BlockSource> ExportSource<S> {
    pub fn new(reader: PackedSegmentReader<S>, generation: u32, physical_digest: [u8; 32]) -> Self {
        Self {
            reader,
            generation,
            physical_digest,
        }
    }

    /// O maior HLC do segmento selado.
    ///
    /// Serve de carimbo temporal estavel para a metadata Iceberg/Delta: e
    /// imutavel depois do selo, portanto reexportar a mesma geracao produz os
    /// mesmos bytes (§105, §167).
    pub fn max_hlc(&self) -> u64 {
        self.reader.footer.max_hlc
    }

    pub fn provenance(&self) -> ExportProvenance {
        ExportProvenance::new(
            self.reader.header.storage_namespace_id,
            self.reader.header.segment_id,
            self.generation,
            self.reader.footer.logical_root,
            self.physical_digest,
            CANONICAL_CODEC_V1 as u16,
            self.reader.footer.min_lsn,
            self.reader.footer.max_lsn,
            self.reader.footer.record_count,
        )
    }
}

/// Abre um `.hrkl` PACKED local como origem de exportação.
pub fn source_from_path(
    packed: &Path,
    generation: u32,
) -> Result<ExportSource<heraclitus_log::v6::FileSource>, HeraclitusError> {
    // SPEC-0073 §17.1 — o digest é calculado em streaming, não sobre uma cópia
    // integral do segmento em RAM.
    //
    // `std::fs::read` trazia o ficheiro inteiro para memória só para o passar
    // ao hasher e o deitar fora a seguir: um pico de RAM do tamanho do
    // segmento, por exportação, sem ninguém precisar dos bytes.
    //
    // O digest é BYTE A BYTE o mesmo — `physical_digest_of_file` é o mesmo
    // BLAKE3 sobre o mesmo ficheiro, só que em blocos de 1 MiB. Tinha de ser:
    // este valor já está publicado em `DerivedArtifactRef`, e mudá-lo
    // invalidaria a idempotência da SPEC-0050 §209.
    let digest = physical_digest_of_file(packed)?;
    Ok(ExportSource::new(
        open_packed(packed, HARD_MAX_BLOCK_BYTES)?,
        generation,
        digest,
    ))
}

/// Exporta um segmento PACKED para Parquet.
///
/// O `content` sai **como foi persistido** — cifrado, se a cifra em repouso
/// estiver ligada. Decifrar aqui exportaria plaintext para uma tabela
/// analítica que ninguém protege com o mesmo cuidado do log.
pub fn export_segment<S: BlockSource>(
    source: &ExportSource<S>,
) -> Result<ExportedFile, HeraclitusError> {
    let provenance = source.provenance();
    let mut counters = ScanCounters::default();
    let mut linhas: Vec<(Lsn, Episode)> = Vec::with_capacity(provenance.record_count as usize);
    source.reader.for_each_record(&mut counters, |r| {
        linhas.push((
            r.lsn,
            heraclitus_log::decode_episode_payload(
                heraclitus_log::format::FORMAT_VERSION,
                r.payload,
            )?,
        ));
        Ok(())
    })?;
    if linhas.len() as u64 != provenance.record_count {
        return Err(HeraclitusError::Corruption {
            context: "exportação lakehouse".into(),
            detail: format!(
                "o footer declara {} registos, o varrimento leu {}",
                provenance.record_count,
                linhas.len()
            ),
        });
    }

    let bytes = escrever_parquet(&linhas, &provenance)?;
    Ok(ExportedFile {
        path: data_path(provenance.segment_id, provenance.generation),
        rows: linhas.len() as u64,
        bytes,
        provenance,
    })
}

pub(crate) fn escrever_parquet(
    linhas: &[(Lsn, Episode)],
    prov: &ExportProvenance,
) -> Result<Vec<u8>, HeraclitusError> {
    let serr = |e: String| HeraclitusError::Serialization(e);
    let schema = export_schema();

    let signed = |campo: &str, value: u64| -> Result<i64, HeraclitusError> {
        i64::try_from(value).map_err(|_| {
            HeraclitusError::Serialization(format!(
                "`{campo}`={value} excede o long assinado de Iceberg/Delta"
            ))
        })
    };
    let lsns = linhas
        .iter()
        .map(|(lsn, _)| signed("lsn", *lsn))
        .collect::<Result<Vec<_>, _>>()?;
    let hlcs = linhas
        .iter()
        .map(|(_, e)| signed("ts_hlc", e.ts_hlc))
        .collect::<Result<Vec<_>, _>>()?;
    let valid_from = linhas
        .iter()
        .map(|(_, e)| e.valid_from.map(|v| signed("valid_from", v)).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let valid_to = linhas
        .iter()
        .map(|(_, e)| e.valid_to.map(|v| signed("valid_to", v)).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let segment_id = signed("segment_id", prov.segment_id)?;
    let generation = i64::from(prov.generation);

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
            Arc::new(Int64Array::from(lsns)) as ArrayRef,
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| e.id.to_string())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| e.agent_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| e.session_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int64Array::from(hlcs)),
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| crate::kind_label(&e.kind))
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BinaryArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| e.content.as_slice())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| attrs_json(e))
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| parents_json(e))
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int64Array::from(valid_from)),
            Arc::new(Int64Array::from(valid_to)),
            Arc::new(StringArray::from(
                linhas
                    .iter()
                    .map(|(_, e)| embedding_json(e))
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int64Array::from(vec![segment_id; linhas.len()])),
            Arc::new(Int64Array::from(vec![generation; linhas.len()])),
        ],
    )
    .map_err(|e| serr(e.to_string()))?;

    let props = WriterProperties::builder()
        .set_created_by(CREATED_BY.to_string())
        .set_key_value_metadata(Some(
            prov.key_values()
                .into_iter()
                .map(|(k, v)| KeyValue::new(k, v))
                .collect(),
        ))
        // Um row group só: a ordem de LSN do segmento é a ordem do ficheiro, e
        // o corte em row groups deixaria de depender só dos dados.
        .set_max_row_group_row_count(Some(usize::MAX))
        .build();

    let mut buf = Vec::new();
    let mut w =
        ArrowWriter::try_new(&mut buf, schema, Some(props)).map_err(|e| serr(e.to_string()))?;
    w.write(&batch).map_err(|e| serr(e.to_string()))?;
    w.close().map_err(|e| serr(e.to_string()))?;
    Ok(buf)
}

/// Relê a proveniência de um Parquet exportado.
///
/// É o que permite a um auditor pegar num ficheiro solto de uma tabela e
/// provar de que geração de que segmento ele veio, sem consultar o catálogo.
pub fn read_provenance(parquet: &[u8]) -> Result<ExportProvenance, HeraclitusError> {
    let serr = |e: String| HeraclitusError::Serialization(e);
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes_reader(parquet))
        .map_err(|e| serr(e.to_string()))?;
    let mut kv = BTreeMap::new();
    if let Some(pares) = builder.metadata().file_metadata().key_value_metadata() {
        for p in pares {
            if let Some(v) = &p.value {
                kv.insert(p.key.clone(), v.clone());
            }
        }
    }
    ExportProvenance::from_key_values(&kv)
}

/// Lê os LSN de um Parquet exportado — o que o teste de preservação de LSN
/// precisa, e o que um `doctor` usaria para confrontar a projecção com o log.
pub fn read_lsns(parquet: &[u8]) -> Result<Vec<Lsn>, HeraclitusError> {
    let serr = |e: String| HeraclitusError::Serialization(e);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes_reader(parquet))
        .map_err(|e| serr(e.to_string()))?
        .build()
        .map_err(|e| serr(e.to_string()))?;
    let mut out = Vec::new();
    for lote in reader {
        let lote = lote.map_err(|e| serr(e.to_string()))?;
        let col = lote
            .column_by_name("lsn")
            .ok_or_else(|| serr("coluna `lsn` ausente no Parquet exportado".into()))?
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| serr("coluna `lsn` não é Int64".into()))?;
        for value in col.iter().flatten() {
            out.push(
                u64::try_from(value)
                    .map_err(|_| serr(format!("LSN negativo no Parquet: {value}")))?,
            );
        }
    }
    Ok(out)
}

fn bytes_reader(b: &[u8]) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(b)
}
