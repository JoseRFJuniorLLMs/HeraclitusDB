//! SPEC-0050 Fase 6 (§203) e a Definition of Done de §209 — projecções
//! lakehouse.
//!
//! ## A regra que organiza a fase inteira
//!
//! > **Nenhuma projecção lakehouse participa da durabilidade do append.**
//!
//! É o último item de §209 e é o mais importante, porque é o único que, se for
//! violado, transforma um exportador analítico numa fonte de perda de dados. A
//! garantia aqui é **estrutural**, não uma promessa:
//!
//! - o exportador só aceita segmentos **selados** ([`ExportSource`] exige um
//!   footer), portanto não há caminho em que ele toque num append em curso;
//! - vive num crate que o `heraclitus-log` não conhece — a dependência aponta
//!   só de fora para dentro, e o compilador impede o contrário;
//! - falhar a exportar nunca propaga erro para o log: quem chama recebe o
//!   `Result` e decide, e o teste `exportador_a_falhar_nao_afecta_o_log`
//!   prova-o.
//!
//! ## As três camadas, e porque são três
//!
//! ```text
//! Parquet    dados      <- a unica materializacao de linhas
//!   |
//!   +-- Iceberg  metadata sobre os MESMOS ficheiros Parquet
//!   +-- Delta    metadata sobre os MESMOS ficheiros Parquet
//! ```
//!
//! §209 exige explicitamente que o "Delta utiliza Parquet derivado". A tentação
//! seria cada exportador materializar as suas próprias linhas — e aí um
//! `SELECT count(*)` por Iceberg e por Delta poderiam divergir sem que nada
//! estivesse "partido". Aqui há **uma** materialização e duas camadas de
//! metadados por cima dela.
//!
//! ## O que este módulo recusa fazer
//!
//! §209: **"HRKM não é apresentado como Iceberg"**. O manifesto `.hrkm` é o
//! catálogo canónico do Heraclitus; a metadata Iceberg é gerada de raiz, com o
//! seu próprio esquema e os seus próprios ficheiros. Nenhum byte do `.hrkm` é
//! copiado, renomeado ou reetiquetado — [`iceberg`] constrói tudo a partir dos
//! factos da exportação. O teste `hrkm_nunca_vira_metadata_iceberg` verifica-o.

pub mod avro;
pub mod delta;
pub mod iceberg;
pub mod parquet_export;
pub mod publisher;
pub mod worker;

use std::collections::BTreeMap;

use heraclitus_core::{HeraclitusError, Lsn, SegmentId};
use serde::{Deserialize, Serialize};

use crate::generation::hex;

/// Versão do contrato de exportação. Sobe quando o esquema Parquet ou o
/// conjunto de chaves de proveniência muda — é o que permite a um consumidor
/// saber se pode confiar no que lê sem adivinhar.
///
/// `2` (SPEC-0073 §15/§16): o Parquet passou de **um** row group para row
/// groups de `export_batch_rows` linhas. O esquema e as chaves de proveniência
/// não mudaram, e o conteúdo lógico é o mesmo — mas os BYTES mudam, e a §209
/// promete idempotência ao byte. Um consumidor que tenha guardado o digest de
/// um ficheiro da v1 tem de conseguir distinguir "mudou porque os dados
/// mudaram" de "mudou porque o produtor mudou de layout"; é para isso que este
/// número existe.
pub const EXPORT_FORMAT_VERSION: u32 = 2;

/// Prefixo de todas as chaves de proveniência na metadata do Parquet.
pub const PROV_PREFIX: &str = "heraclitus.";

/// A proveniência de uma exportação: de que geração de que segmento vieram
/// estas linhas (§209, "export preserva segment provenance").
///
/// Vai para a key-value metadata do ficheiro Parquet. Um Parquet sem isto é
/// uma tabela órfã: as linhas existem mas ninguém consegue provar de onde
/// vieram, e a projecção deixa de ser auditável.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportProvenance {
    pub export_format_version: u32,
    pub storage_namespace_id: String,
    pub segment_id: SegmentId,
    pub generation: u32,
    pub logical_root: String,
    pub physical_digest: String,
    pub canonical_codec_version: u16,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub record_count: u64,
}

impl ExportProvenance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage_namespace_id: [u8; 16],
        segment_id: SegmentId,
        generation: u32,
        logical_root: [u8; 32],
        physical_digest: [u8; 32],
        canonical_codec_version: u16,
        first_lsn: Lsn,
        last_lsn: Lsn,
        record_count: u64,
    ) -> Self {
        Self {
            export_format_version: EXPORT_FORMAT_VERSION,
            storage_namespace_id: hex(&storage_namespace_id),
            segment_id,
            generation,
            logical_root: hex(&logical_root),
            physical_digest: hex(&physical_digest),
            canonical_codec_version,
            first_lsn,
            last_lsn,
            record_count,
        }
    }

    /// Pares chave/valor para a metadata do Parquet, **ordenados**.
    ///
    /// A ordem é fixa de propósito: a metadata entra nos bytes do ficheiro, e
    /// um `BTreeMap` iterado por ordem é o que torna a exportação
    /// byte-determinística (§209, "export é idempotente").
    pub fn key_values(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: String| {
            m.insert(format!("{PROV_PREFIX}{k}"), v);
        };
        put(
            "export_format_version",
            self.export_format_version.to_string(),
        );
        put("storage_namespace_id", self.storage_namespace_id.clone());
        put("segment_id", self.segment_id.to_string());
        put("generation", self.generation.to_string());
        put("logical_root", self.logical_root.clone());
        put("physical_digest", self.physical_digest.clone());
        put(
            "canonical_codec_version",
            self.canonical_codec_version.to_string(),
        );
        put("first_lsn", self.first_lsn.to_string());
        put("last_lsn", self.last_lsn.to_string());
        put("record_count", self.record_count.to_string());
        m
    }

    /// Reconstrói a proveniência a partir da metadata de um Parquet exportado.
    pub fn from_key_values(kv: &BTreeMap<String, String>) -> Result<Self, HeraclitusError> {
        let get = |k: &str| -> Result<&String, HeraclitusError> {
            kv.get(&format!("{PROV_PREFIX}{k}"))
                .ok_or_else(|| HeraclitusError::Corruption {
                    context: "proveniência de exportação".into(),
                    detail: format!("chave `{PROV_PREFIX}{k}` ausente"),
                })
        };
        let num = |k: &str| -> Result<u64, HeraclitusError> {
            get(k)?
                .parse::<u64>()
                .map_err(|e| HeraclitusError::Corruption {
                    context: "proveniência de exportação".into(),
                    detail: format!("`{k}` não é numérico: {e}"),
                })
        };
        Ok(Self {
            export_format_version: num("export_format_version")? as u32,
            storage_namespace_id: get("storage_namespace_id")?.clone(),
            segment_id: num("segment_id")?,
            generation: num("generation")? as u32,
            logical_root: get("logical_root")?.clone(),
            physical_digest: get("physical_digest")?.clone(),
            canonical_codec_version: num("canonical_codec_version")? as u16,
            first_lsn: num("first_lsn")?,
            last_lsn: num("last_lsn")?,
            record_count: num("record_count")?,
        })
    }
}

/// O ficheiro Parquet que uma exportação produziu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFile {
    /// Caminho relativo dentro da tabela (`data/segment-…-gen-….parquet`).
    pub path: String,
    pub bytes: Vec<u8>,
    pub rows: u64,
    pub provenance: ExportProvenance,
}

impl ExportedFile {
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// Watermark persistido de uma tabela (§209, "watermark é persistido").
///
/// Guarda **por segmento** a geração já exportada, e não só um LSN máximo. A
/// diferença importa: um repack publica uma geração nova com o mesmo intervalo
/// de LSN, e um watermark que só soubesse "já exportei até ao LSN N" nunca
/// voltaria a exportar esse segmento — a tabela ficaria presa a bytes de uma
/// geração que já foi substituída.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportWatermark {
    pub table: String,
    /// `segment_id -> generation` já exportada.
    #[serde(default)]
    pub segments: BTreeMap<SegmentId, u32>,
    /// Maior LSN presente na tabela. Derivado, mas persistido para que um
    /// consumidor saiba até onde a projecção está actualizada sem ler o
    /// Parquet todo.
    #[serde(default)]
    pub last_lsn: Lsn,
    #[serde(default)]
    pub updated_hlc: u64,
}

/// O que a exportação de um segmento decidiu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportDecision {
    /// Ficheiro novo escrito.
    Exported,
    /// Já lá estava, com a mesma geração — nada a fazer (§209, idempotência).
    AlreadyCurrent,
    /// Existia uma geração ANTERIOR do mesmo segmento; a nova substitui-a.
    Superseded { generation_anterior: u32 },
}

impl ExportWatermark {
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            ..Default::default()
        }
    }

    /// Decide o que fazer com um segmento sem escrever nada.
    ///
    /// Separado do acto de exportar de propósito: a decisão é pura e
    /// testável, e um exportador que quisesse "só verificar" não precisa de
    /// produzir bytes para o descobrir.
    pub fn decide(&self, segment_id: SegmentId, generation: u32) -> ExportDecision {
        match self.segments.get(&segment_id) {
            Some(&g) if g == generation => ExportDecision::AlreadyCurrent,
            Some(&g) => ExportDecision::Superseded {
                generation_anterior: g,
            },
            None => ExportDecision::Exported,
        }
    }

    pub fn record(&mut self, prov: &ExportProvenance, hlc: u64) {
        self.segments.insert(prov.segment_id, prov.generation);
        self.last_lsn = self.last_lsn.max(prov.last_lsn);
        self.updated_hlc = hlc;
    }

    /// Caminho canónico do watermark dentro da tabela.
    ///
    /// Vive sob `_heraclitus/` e não sob `metadata/` para não colidir com o
    /// namespace do Iceberg nem com o `_delta_log` do Delta: é estado do
    /// Heraclitus, não das camadas de terceiros.
    pub const PATH: &'static str = "_heraclitus/watermark.json";

    pub fn encode(&self) -> Result<Vec<u8>, HeraclitusError> {
        serde_json::to_vec_pretty(self).map_err(|e| HeraclitusError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HeraclitusError> {
        serde_json::from_slice(bytes).map_err(|e| HeraclitusError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov(seg: SegmentId, gen: u32, lo: Lsn, hi: Lsn) -> ExportProvenance {
        ExportProvenance::new([1; 16], seg, gen, [2; 32], [3; 32], 1, lo, hi, hi - lo + 1)
    }

    #[test]
    fn proveniencia_faz_round_trip_pela_metadata() {
        let p = prov(88, 2, 100, 199);
        assert_eq!(
            ExportProvenance::from_key_values(&p.key_values()).unwrap(),
            p
        );
    }

    #[test]
    fn metadata_em_falta_e_erro_e_nao_um_default_silencioso() {
        let p = prov(88, 2, 100, 199);
        let mut kv = p.key_values();
        kv.remove("heraclitus.logical_root");
        let e = ExportProvenance::from_key_values(&kv).unwrap_err();
        assert!(e.to_string().contains("logical_root"));
    }

    #[test]
    fn as_chaves_saem_sempre_pela_mesma_ordem() {
        // A metadata entra nos bytes do Parquet: se a ordem variasse, duas
        // exportações do mesmo segmento dariam ficheiros diferentes e a
        // idempotência de §209 seria impossível de verificar por digest.
        let p = prov(88, 2, 100, 199);
        let a: Vec<_> = p.key_values().into_iter().collect();
        let b: Vec<_> = p.key_values().into_iter().collect();
        assert_eq!(a, b);
        assert!(a.windows(2).all(|w| w[0].0 < w[1].0), "não está ordenado");
    }

    #[test]
    fn o_watermark_distingue_repack_de_segmento_novo() {
        let mut w = ExportWatermark::new("eventos");
        assert_eq!(w.decide(88, 1), ExportDecision::Exported);

        w.record(&prov(88, 1, 0, 99), 10);
        assert_eq!(w.decide(88, 1), ExportDecision::AlreadyCurrent);
        // Um repack publica geração nova sobre o MESMO intervalo de LSN. Um
        // watermark que só guardasse o LSN máximo nunca reexportaria isto.
        assert_eq!(
            w.decide(88, 2),
            ExportDecision::Superseded {
                generation_anterior: 1
            }
        );
        assert_eq!(w.decide(89, 1), ExportDecision::Exported);
    }

    #[test]
    fn o_watermark_persiste_e_relê() {
        let mut w = ExportWatermark::new("eventos");
        w.record(&prov(1, 0, 0, 49), 5);
        w.record(&prov(2, 0, 50, 99), 6);
        let bytes = w.encode().unwrap();
        let lido = ExportWatermark::decode(&bytes).unwrap();
        assert_eq!(lido, w);
        assert_eq!(lido.last_lsn, 99);
        assert_eq!(lido.segments.len(), 2);
    }

    #[test]
    fn o_watermark_nunca_recua() {
        let mut w = ExportWatermark::new("eventos");
        w.record(&prov(2, 0, 50, 99), 5);
        w.record(&prov(1, 0, 0, 49), 6);
        assert_eq!(
            w.last_lsn, 99,
            "exportar um segmento antigo recuou o watermark"
        );
    }
}
