//! SPEC-0050 §146/§203 — o trabalhador que fecha o ciclo da Fase 6.
//!
//! Até aqui a Fase 6 tinha as duas pontas e nenhuma corda: o `heraclitus-log`
//! sabia registar uma projecção Parquet no HRKM e recalcular o watermark
//! contíguo; este crate sabia materializar Parquet, Iceberg e Delta. Nada
//! ligava os dois, e por isso `parquet_export_lag_lsn` crescia para sempre —
//! era a métrica de um pipeline que nunca corria.
//!
//! ## Onde este código vive, e porquê aqui
//!
//! No `heraclitus-tier`, pela mesma razão da Fase 5: o `heraclitus-log` não
//! conhece `object_store` nem `async`, e não vai passar a conhecer por causa
//! de uma projecção analítica. O log expõe a fronteira
//! ([`V6Log::lakehouse_pending`] e [`V6Log::attach_parquet_projection`]) e o
//! tier atravessa-a. A dependência aponta só de fora para dentro; o
//! compilador impede o contrário.
//!
//! ## A ordem das operações não é arbitrária
//!
//! ```text
//! exportar -> publicar (Parquet -> Iceberg -> Delta -> watermark) -> HRKM
//! ```
//!
//! O HRKM é o **último** passo. A razão é a assimetria dos dois modos de
//! falha: um Parquet publicado que o HRKM ainda não conhece é reexportado no
//! ciclo seguinte, e o `PutMode::Create` do publisher torna isso idempotente;
//! já um HRKM que declarasse uma projecção antes de ela existir faria
//! `exported_through_lsn` avançar sobre bytes ausentes — um watermark a
//! mentir, que é precisamente o que §104 existe para impedir.
//!
//! ## O carimbo temporal é derivado dos dados, não do relógio
//!
//! §105 exige que um retry não produza duplicação lógica, e §167 exige bytes
//! reprodutíveis. Um `SystemTime::now()` no commit Delta/Iceberg violaria os
//! dois: a mesma exportação repetida daria metadata diferente. O carimbo sai
//! do `max_hlc` do próprio segmento (`hlc >> 16` = milissegundos físicos),
//! que é imutável depois do selo. Reexportar a mesma geração produz os mesmos
//! bytes.

use std::sync::Arc;

use heraclitus_core::runtime::DerivedArtifactRef;
use heraclitus_core::{HeraclitusError, Lsn, SegmentId};
use heraclitus_log::v6::{physical_digest, LakehousePending, V6Log};
use object_store::ObjectStore;

use super::iceberg::IcebergTable;
use super::parquet_export::{export_segment, source_from_path};
use super::publisher::LakehousePublisher;
use super::{ExportDecision, ExportedFile};
use crate::generation::hex;

/// O que aconteceu a um segmento numa passagem do trabalhador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    pub segment_id: SegmentId,
    pub generation: u32,
    /// Caminho relativo do Parquet dentro da tabela.
    pub path: String,
    pub size: u64,
    pub rows: u64,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub decision: ExportDecision,
    pub delta_version: Option<u64>,
    /// `false` quando a geração física se moveu entre exportar e comitar o
    /// HRKM (um repack pelo meio). O Parquet fica órfão e reexportável; o
    /// manifesto não é tocado.
    pub attached: bool,
}

/// Publica as projecções lakehouse dos segmentos que o HRKM ainda não conhece.
pub struct LakehouseWorker {
    publisher: LakehousePublisher,
    table_name: String,
}

impl LakehouseWorker {
    pub fn new(
        store: Arc<dyn ObjectStore>,
        table_name: impl Into<String>,
        iceberg: IcebergTable,
    ) -> Self {
        let table_name = table_name.into();
        Self {
            publisher: LakehousePublisher::new(store, table_name.clone(), iceberg),
            table_name,
        }
    }

    /// Abre um trabalhador sobre uma localização de object store.
    ///
    /// O `table_uuid` do Iceberg **não** é gerado aqui: é o
    /// `storage_namespace_id` do banco, que já é um identificador de 16 bytes
    /// estável e persistido (§20). Gerar um UUID novo faria cada reinício
    /// publicar metadata Iceberg de uma tabela diferente da anterior.
    pub fn open_location(
        location: &str,
        table_name: impl Into<String>,
        storage_namespace_id: [u8; 16],
    ) -> Result<Self, HeraclitusError> {
        let store = crate::ColdTier::store_for(location)?;
        let iceberg = IcebergTable::new(
            uuid_do_namespace(storage_namespace_id),
            uri_absoluta_para(location)?,
        )?;
        Ok(Self::new(store, table_name, iceberg))
    }

    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Uma passagem completa: fila do HRKM -> Parquet -> Iceberg/Delta ->
    /// watermark -> HRKM.
    ///
    /// Falhar aqui nunca propaga para o caminho de escrita. Quem chama recebe
    /// o `Result` e decide; o log não sabe sequer que esta função existe.
    pub async fn export_pending(
        &self,
        log: &Arc<V6Log>,
    ) -> Result<Vec<ExportOutcome>, HeraclitusError> {
        let pendentes = log.lakehouse_pending()?;
        let mut out = Vec::with_capacity(pendentes.len());
        for pendente in pendentes {
            out.push(self.export_one(log, pendente).await?);
        }
        Ok(out)
    }

    async fn export_one(
        &self,
        log: &Arc<V6Log>,
        pendente: LakehousePending,
    ) -> Result<ExportOutcome, HeraclitusError> {
        // Ler e recodificar o segmento inteiro é trabalho de CPU e de disco
        // síncrono. Corrê-lo no executor assíncrono parquearia um worker do
        // tokio durante todo o export — o mesmo erro que causou o deadlock do
        // handler `query` no wiring do consenso.
        let packed = pendente.packed.clone();
        let generation = pendente.generation;
        let (ficheiro, timestamp_ms) =
            tokio::task::spawn_blocking(move || -> Result<(ExportedFile, i64), HeraclitusError> {
                let fonte = source_from_path(&packed, generation)?;
                let carimbo = (fonte.max_hlc() >> 16) as i64;
                Ok((export_segment(&fonte)?, carimbo))
            })
            .await
            .map_err(|e| HeraclitusError::StorageEngine(format!("worker lakehouse: {e}")))??;

        self.assert_identidade(&pendente, &ficheiro)?;

        let publicado = self.publisher.publish(&ficheiro, timestamp_ms).await?;

        let artifact = DerivedArtifactRef {
            location: self.publisher.absolute(&ficheiro.path),
            size: ficheiro.size(),
            digest: physical_digest(&ficheiro.bytes),
            logical_root: pendente.logical_root,
            created_hlc: log.now_hlc(),
        };
        let attached = log.attach_parquet_projection(
            pendente.segment_id,
            pendente.generation,
            pendente.logical_root,
            artifact,
        )?;

        Ok(ExportOutcome {
            segment_id: pendente.segment_id,
            generation: pendente.generation,
            path: ficheiro.path.clone(),
            size: ficheiro.size(),
            rows: ficheiro.rows,
            first_lsn: pendente.first_lsn,
            last_lsn: pendente.last_lsn,
            decision: publicado.decision,
            delta_version: publicado.delta_version,
            attached,
        })
    }

    /// O Parquet exportado tem de descrever o segmento que a fila indicou.
    ///
    /// Sem isto, um erro de indexação na fila publicaria a proveniência de um
    /// segmento sobre os dados de outro — e como é a proveniência que viaja
    /// para a metadata Iceberg/Delta, a troca passaria em silêncio.
    fn assert_identidade(
        &self,
        pendente: &LakehousePending,
        ficheiro: &ExportedFile,
    ) -> Result<(), HeraclitusError> {
        let p = &ficheiro.provenance;
        if p.segment_id != pendente.segment_id
            || p.generation != pendente.generation
            || p.logical_root != hex(&pendente.logical_root)
        {
            return Err(HeraclitusError::Corruption {
                context: "exportação lakehouse".into(),
                detail: format!(
                    "o Parquet descreve o segmento {}/g{} e a fila pediu {}/g{}",
                    p.segment_id, p.generation, pendente.segment_id, pendente.generation
                ),
            });
        }
        Ok(())
    }
}

/// Os 16 bytes do namespace escritos como UUID RFC 4122 textual.
fn uuid_do_namespace(id: [u8; 16]) -> String {
    let h = hex(&id);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// O Iceberg exige `location` como URI absoluta (§106). Uma localização já em
/// forma de URI passa intacta; um caminho local é convertido em `file:///`.
fn uri_absoluta_para(location: &str) -> Result<String, HeraclitusError> {
    if location.contains("://") {
        return Ok(location.trim_end_matches('/').to_string());
    }
    let absoluto = std::path::Path::new(location).canonicalize().map_err(|e| {
        HeraclitusError::Config(format!(
            "localização lakehouse `{location}` não pôde ser resolvida: {e}"
        ))
    })?;
    let texto = absoluto.to_string_lossy().replace('\\', "/");
    let texto = texto.strip_prefix("//?/").unwrap_or(&texto).to_string();
    Ok(format!("file:///{}", texto.trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_uuid_da_tabela_e_o_namespace_do_banco() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(
            uuid_do_namespace(id),
            "01234567-89ab-cdef-fedc-ba9876543210"
        );
    }

    #[test]
    fn uma_uri_ja_absoluta_passa_intacta() {
        assert_eq!(
            uri_absoluta_para("s3://bucket/tabela/").unwrap(),
            "s3://bucket/tabela"
        );
    }
}
