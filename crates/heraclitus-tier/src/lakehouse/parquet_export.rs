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
//! 2. Row groups de tamanho FIXO em linhas (`EXPORT_BATCH_ROWS`), na ordem de
//!    LSN do segmento. Era um row group só, e o motivo dado era que "o corte
//!    em row groups deixaria de depender só dos dados" — legítimo, mas a
//!    apontar para o alvo errado: um corte por BYTES dependeria da codificação
//!    e da compressão; um corte por número de LINHAS depende só do índice da
//!    linha. E era o row group único que obrigava o writer a segurar o segmento
//!    inteiro em memória (SPEC-0073 §15).
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

/// SPEC-0073 §16 — linhas por lote de exportação, e por row group.
///
/// É o valor da spec (`export_batch_rows = 8192`). Governa duas coisas ao
/// mesmo tempo, de propósito: quantos `Episode` ficam em RAM de cada vez, e
/// onde o Parquet corta os row groups. Serem o mesmo número é o que torna a
/// saída determinística — o corte depende do índice da linha e de mais nada.
pub const EXPORT_BATCH_ROWS: usize = 8_192;

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
    export_segment_com_lote(source, EXPORT_BATCH_ROWS)
}

/// SPEC-0073 §15/§16 — exporta em lotes, com memória limitada pelo lote.
///
/// O caminho anterior era exactamente o que a §15 proíbe por escrito:
///
/// ```text
/// segment -> Vec<Episode> gigante -> RecordBatch gigante -> Vec<u8> gigante
/// ```
///
/// `Vec::with_capacity(provenance.record_count)` reservava, de uma vez, um
/// `Episode` desserializado por registo do segmento — conteúdo, atributos,
/// parents e embedding incluídos. Num segmento de vários GiB isso é o segmento
/// inteiro em RAM, e mais um pouco, antes de escrever o primeiro byte.
///
/// Agora os registos são acumulados até `lote_linhas` e despejados num
/// `RecordBatch` de cada vez. A memória de leitura passa a ser O(lote) em vez
/// de O(segmento).
pub fn export_segment_com_lote<S: BlockSource>(
    source: &ExportSource<S>,
    lote_linhas: usize,
) -> Result<ExportedFile, HeraclitusError> {
    let lote_linhas = lote_linhas.max(1);
    let provenance = source.provenance();
    let mut counters = ScanCounters::default();

    let mut escritor = EscritorParquet::novo(&provenance, lote_linhas)?;
    let mut lote: Vec<(Lsn, Episode)> = Vec::with_capacity(lote_linhas);
    let mut total: u64 = 0;

    source.reader.for_each_record(&mut counters, |r| {
        lote.push((
            r.lsn,
            heraclitus_log::decode_episode_payload(
                heraclitus_log::format::FORMAT_VERSION,
                r.payload,
            )?,
        ));
        if lote.len() >= lote_linhas {
            total += lote.len() as u64;
            escritor.escrever(&lote, &provenance)?;
            lote.clear();
        }
        Ok(())
    })?;
    if !lote.is_empty() {
        total += lote.len() as u64;
        escritor.escrever(&lote, &provenance)?;
        lote.clear();
    }

    if total != provenance.record_count {
        return Err(HeraclitusError::Corruption {
            context: "exportação lakehouse".into(),
            detail: format!(
                "o footer declara {} registos, o varrimento leu {total}",
                provenance.record_count,
            ),
        });
    }

    let bytes = escritor.fechar()?;
    Ok(ExportedFile {
        path: data_path(provenance.segment_id, provenance.generation),
        rows: total,
        bytes,
        provenance,
    })
}

/// Envolve o `ArrowWriter` com as propriedades que tornam a saída
/// determinística.
/// Escreve um Parquet completo a partir de um lote unico.
///
/// So para testes e para chamadores que ja tem as linhas todas na mao: o
/// caminho de producao e o `export_segment_com_lote`, que nunca as tem.
#[cfg(test)]
pub(crate) fn escrever_parquet(
    linhas: &[(Lsn, Episode)],
    prov: &ExportProvenance,
) -> Result<Vec<u8>, HeraclitusError> {
    let mut escritor = EscritorParquet::novo(prov, EXPORT_BATCH_ROWS)?;
    for pedaco in linhas.chunks(EXPORT_BATCH_ROWS) {
        escritor.escrever(pedaco, prov)?;
    }
    escritor.fechar()
}

struct EscritorParquet {
    writer: ArrowWriter<Vec<u8>>,
}

impl EscritorParquet {
    fn novo(prov: &ExportProvenance, lote_linhas: usize) -> Result<Self, HeraclitusError> {
        let serr = |e: String| HeraclitusError::Serialization(e);
        let props = WriterProperties::builder()
            .set_created_by(CREATED_BY.to_string())
            .set_key_value_metadata(Some(
                prov.key_values()
                    .into_iter()
                    .map(|(k, v)| KeyValue::new(k, v))
                    .collect(),
            ))
            // O corte em row groups é por CONTAGEM DE LINHAS, e é isso que o
            // mantém determinístico.
            //
            // Antes era `usize::MAX` — um row group só — com a justificação de
            // que "o corte em row groups deixaria de depender só dos dados".
            // A preocupação era legítima e apontava para o alvo errado: um
            // corte por BYTES dependeria da codificação e da compressão, mas um
            // corte por número de linhas depende só do índice da linha. Duas
            // exportações do mesmo segmento cortam nos mesmos sítios.
            //
            // E era o `usize::MAX` que obrigava o writer a segurar as colunas
            // todas em memória até ao `close()`, o que anulava qualquer ganho
            // de ler por lotes.
            .set_max_row_group_row_count(Some(lote_linhas))
            .build();
        Ok(Self {
            writer: ArrowWriter::try_new(Vec::new(), export_schema(), Some(props))
                .map_err(|e| serr(e.to_string()))?,
        })
    }

    fn escrever(
        &mut self,
        linhas: &[(Lsn, Episode)],
        prov: &ExportProvenance,
    ) -> Result<(), HeraclitusError> {
        let batch = construir_batch(linhas, prov)?;
        self.writer
            .write(&batch)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))
    }

    fn fechar(self) -> Result<Vec<u8>, HeraclitusError> {
        self.writer
            .into_inner()
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))
    }
}

/// Constroi UM `RecordBatch` a partir de um lote de linhas.
///
/// Era o corpo do `escrever_parquet`, que fazia batch e ficheiro de uma vez
/// sobre a totalidade das linhas. Separar as duas coisas e o que permite
/// escrever N lotes para o mesmo ficheiro.
fn construir_batch(
    linhas: &[(Lsn, Episode)],
    prov: &ExportProvenance,
) -> Result<RecordBatch, HeraclitusError> {
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

    RecordBatch::try_new(
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
    .map_err(|e| serr(e.to_string()))
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

#[cfg(test)]
mod testes_streaming_spec0073 {
    use super::*;
    use heraclitus_core::EventKind;

    fn episodio(i: u64) -> Episode {
        let mut e = Episode::new(
            "agente",
            EventKind::Observation,
            format!("payload numero {i}").into_bytes(),
        );
        e.ts_hlc = i;
        e
    }

    fn proveniencia(registos: u64) -> ExportProvenance {
        ExportProvenance::new(
            [7u8; 16],
            42,
            3,
            [1u8; 32],
            [2u8; 32],
            CANONICAL_CODEC_V1 as u16,
            0,
            registos.saturating_sub(1),
            registos,
        )
    }

    fn linhas(n: u64) -> Vec<(Lsn, Episode)> {
        (0..n).map(|i| (i, episodio(i))).collect()
    }

    fn numero_de_row_groups(parquet: &[u8]) -> usize {
        ParquetRecordBatchReaderBuilder::try_new(bytes_reader(parquet))
            .unwrap()
            .metadata()
            .num_row_groups()
    }

    /// SPEC-0073 §16 — o corte em row groups e por CONTAGEM DE LINHAS.
    ///
    /// E o que prova que a memoria do writer fica limitada: um row group unico
    /// obrigava-o a segurar as colunas todas ate ao `close()`, que era metade
    /// do problema que a §15 descreve.
    #[test]
    fn o_corte_em_row_groups_segue_o_lote() {
        let n = 100u64;
        let dados = linhas(n);
        let prov = proveniencia(n);
        for lote in [1usize, 7, 32, 100, 1_000] {
            let mut escritor = EscritorParquet::novo(&prov, lote).unwrap();
            for pedaco in dados.chunks(lote) {
                escritor.escrever(pedaco, &prov).unwrap();
            }
            let bytes = escritor.fechar().unwrap();
            let esperados = (n as usize).div_ceil(lote);
            assert_eq!(
                numero_de_row_groups(&bytes),
                esperados,
                "lote={lote}: {n} linhas deviam dar {esperados} row groups"
            );
        }
    }

    /// O determinismo da §209 sobrevive ao lote: o mesmo segmento, exportado
    /// duas vezes com o mesmo lote, da os MESMOS bytes.
    #[test]
    fn o_mesmo_lote_da_sempre_os_mesmos_bytes() {
        let dados = linhas(50);
        let prov = proveniencia(50);
        let uma = escrever_parquet(&dados, &prov).unwrap();
        let outra = escrever_parquet(&dados, &prov).unwrap();
        assert_eq!(uma, outra, "a exportacao deixou de ser determinista");
    }

    /// O conteudo LOGICO nao depende do lote — so o layout fisico depende.
    ///
    /// Sem isto, uma mudanca de `export_batch_rows` podia estar a mudar dados e
    /// nao so o corte, e ninguem daria por ela.
    #[test]
    fn o_conteudo_nao_depende_do_tamanho_do_lote() {
        let n = 60u64;
        let dados = linhas(n);
        let prov = proveniencia(n);

        let mut referencia: Option<Vec<(i64, String)>> = None;
        for lote in [1usize, 8, 60, 500] {
            let mut escritor = EscritorParquet::novo(&prov, lote).unwrap();
            for pedaco in dados.chunks(lote) {
                escritor.escrever(pedaco, &prov).unwrap();
            }
            let bytes = escritor.fechar().unwrap();

            let leitor = ParquetRecordBatchReaderBuilder::try_new(bytes_reader(&bytes))
                .unwrap()
                .build()
                .unwrap();
            let mut lidas: Vec<(i64, String)> = Vec::new();
            for batch in leitor {
                let batch = batch.unwrap();
                let lsns = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .unwrap();
                let ids = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();
                for i in 0..batch.num_rows() {
                    lidas.push((lsns.value(i), ids.value(i).to_string()));
                }
            }
            assert_eq!(lidas.len(), n as usize, "lote={lote}: perdeu linhas");
            match &referencia {
                None => referencia = Some(lidas),
                Some(esperado) => assert_eq!(
                    &lidas, esperado,
                    "lote={lote} devolveu outro conteudo; o lote e uma decisao de \
                     MEMORIA, nunca de dados"
                ),
            }
        }
    }
}
