//! SPEC-0050 §86 — `DemotionReceipt` v2.
//!
//! O recibo v1 provava uma coisa só: *estes bytes têm esta raiz Merkle*. Isso
//! chegava enquanto um segmento tinha exactamente um objecto no tier frio. Com
//! gerações imutáveis (§83) deixa de chegar: o mesmo histórico lógico passa a
//! ter várias representações físicas, e um recibo que não diga **qual** delas
//! está a atestar é ambíguo no momento em que mais importa.
//!
//! O v2 fecha isso registando as três identidades de §7 lado a lado:
//!
//! | campo | responde a |
//! |---|---|
//! | `logical_root` | *que histórico é este?* |
//! | `physical_digest` | *que bytes são estes?* |
//! | `object_path` + `generation` | *onde é que estes bytes estão?* |
//!
//! §84 é a razão de o `physical_digest` estar aqui em vez de se confiar no
//! `ETag` do backend: o `ETag` do S3 é o MD5 de um upload simples, mas o de um
//! multipart é o hash dos hashes das partes — muda com o tamanho da parte,
//! sem que um byte mude. A autoridade é sempre o que o Heraclitus calculou.

use heraclitus_core::runtime::{CompressionCodec, PhysicalGeneration, PhysicalLayout};
use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn, SegmentId};
use heraclitus_log::v6::header::StorageNamespaceId;
use heraclitus_log::v6::AttestationEnvelopeV1;
use serde::{Deserialize, Serialize};

use crate::generation::{hex, unhex, GenerationKey};

pub const DEMOTION_RECEIPT_V2: u32 = 2;
pub const DOMAIN_DEMOTION_RECEIPT: &[u8] = b"HRKL6:DEMOTION_RECEIPT:V2";

/// O recibo de §86. Serializado em JSON no episódio `DemotionReceipt`, como o
/// v1 — o que muda é o conteúdo, não o transporte.
///
/// Os campos binários viajam em hex por uma razão operacional: um recibo é lido
/// por humanos e por ferramentas externas durante uma perícia, e um array de 32
/// bytes em JSON é ilegível para ambos. A identidade canónica não depende desta
/// escolha — [`Self::digest`] hasheia os bytes, não o JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionReceiptV2 {
    pub receipt_version: u32,
    pub segment_id: SegmentId,
    pub generation: u32,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub record_count: u64,
    pub canonical_codec_version: u16,
    /// Hex de 16 bytes.
    pub storage_namespace_id: String,
    /// Hex de 32 bytes.
    pub logical_root: String,
    /// Hex de 32 bytes.
    pub physical_digest: String,
    pub physical_size: u64,
    /// `RAW` ou `PACKED`.
    pub physical_layout: String,
    /// `RAW`, `ZSTD`, `LZ4_RAW` ou `MIXED` (blocos com codecs diferentes).
    pub compression_codec: String,
    pub object_path: String,
    #[serde(default)]
    pub hrki_path: Option<String>,
    #[serde(default)]
    pub parquet_path: Option<String>,
    /// A geração de onde esta veio, quando é produto de um repack (§87).
    #[serde(default)]
    pub source_generation: Option<u32>,
    pub created_hlc: u64,
}

impl DemotionReceiptV2 {
    /// Codificação canónica — determinística, independente de `serde` e da
    /// ordem dos campos no JSON. É o que se assina.
    pub fn encode(&self) -> Result<Vec<u8>, HeraclitusError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.receipt_version.to_le_bytes());
        out.extend_from_slice(&self.segment_id.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.first_lsn.to_le_bytes());
        out.extend_from_slice(&self.last_lsn.to_le_bytes());
        out.extend_from_slice(&self.record_count.to_le_bytes());
        out.extend_from_slice(&self.canonical_codec_version.to_le_bytes());
        out.extend_from_slice(&self.namespace_bytes()?);
        out.extend_from_slice(&self.logical_root_bytes()?);
        out.extend_from_slice(&self.physical_digest_bytes()?);
        out.extend_from_slice(&self.physical_size.to_le_bytes());
        // Campos textuais entram com o comprimento à frente: sem isso,
        // `("AB", "C")` e `("A", "BC")` colidiriam no mesmo digest.
        for s in [
            self.physical_layout.as_str(),
            self.compression_codec.as_str(),
            self.object_path.as_str(),
            self.hrki_path.as_deref().unwrap_or(""),
            self.parquet_path.as_deref().unwrap_or(""),
        ] {
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.source_generation.unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&self.created_hlc.to_le_bytes());
        Ok(out)
    }

    pub fn digest(&self) -> Result<[u8; 32], HeraclitusError> {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_DEMOTION_RECEIPT);
        h.update(&self.encode()?);
        Ok(*h.finalize().as_bytes())
    }

    pub fn namespace_bytes(&self) -> Result<StorageNamespaceId, HeraclitusError> {
        unhex::<16>(&self.storage_namespace_id).ok_or_else(|| bad("storage_namespace_id"))
    }

    pub fn logical_root_bytes(&self) -> Result<[u8; 32], HeraclitusError> {
        unhex::<32>(&self.logical_root).ok_or_else(|| bad("logical_root"))
    }

    pub fn physical_digest_bytes(&self) -> Result<[u8; 32], HeraclitusError> {
        unhex::<32>(&self.physical_digest).ok_or_else(|| bad("physical_digest"))
    }

    /// A chave a partir dos campos do recibo — e **não** do `object_path`.
    ///
    /// [`Self::check_path_consistency`] compara as duas: se um recibo foi
    /// editado à mão ou migrado mal, a divergência aparece em vez de passar.
    pub fn key(&self) -> Result<GenerationKey, HeraclitusError> {
        Ok(GenerationKey::new(
            self.namespace_bytes()?,
            self.segment_id,
            self.logical_root_bytes()?,
            self.generation,
        ))
    }

    /// Confirma que o caminho publicado é o que os campos do recibo implicam.
    pub fn check_path_consistency(&self) -> Result<(), HeraclitusError> {
        let derivada = self.key()?.segment_path().to_string();
        if derivada != self.object_path {
            return Err(HeraclitusError::Corruption {
                context: "recibo de demoção v2".into(),
                detail: format!(
                    "object_path `{}` não corresponde aos campos do recibo (`{derivada}`)",
                    self.object_path
                ),
            });
        }
        Ok(())
    }

    /// O envelope de §19: é isto que vai ao carimbo do tempo, não a raiz solta.
    pub fn attestation(&self) -> Result<AttestationEnvelopeV1, HeraclitusError> {
        Ok(AttestationEnvelopeV1 {
            storage_namespace_id: self.namespace_bytes()?,
            segment_id: self.segment_id,
            canonical_codec_version: self.canonical_codec_version,
            first_lsn: self.first_lsn,
            last_lsn: self.last_lsn,
            record_count: self.record_count,
            logical_root: self.logical_root_bytes()?,
        })
    }

    /// A entrada de manifesto correspondente (§71): o recibo e o catálogo
    /// contam a mesma história, e não há uma segunda noção de "geração".
    pub fn physical_generation(&self) -> Result<PhysicalGeneration, HeraclitusError> {
        Ok(PhysicalGeneration {
            generation: self.generation,
            layout: match self.physical_layout.as_str() {
                "PACKED" => PhysicalLayout::Packed,
                "RAW" => PhysicalLayout::Raw,
                other => return Err(bad_detail(format!("physical_layout `{other}`"))),
            },
            compression: match self.compression_codec.as_str() {
                "RAW" => CompressionCodec::Raw,
                "ZSTD" => CompressionCodec::Zstd,
                "LZ4_RAW" => CompressionCodec::Lz4Raw,
                // MIXED não é um codec de bloco: o manifesto guarda o codec
                // dominante do packing, e o recibo mantém a verdade completa.
                "MIXED" => CompressionCodec::Zstd,
                other => return Err(bad_detail(format!("compression_codec `{other}`"))),
            },
            location: self.object_path.clone(),
            physical_size: self.physical_size,
            physical_digest: self.physical_digest_bytes()?,
            // Publicar não é verificar. Quem publica marca `Active`; só
            // `verify_generation` promove a `Verified` (§72).
            state: heraclitus_core::runtime::GenerationState::Active,
            created_hlc: self.created_hlc,
            verified_hlc: 0,
            superseded_hlc: 0,
            verified_copies: 1,
        })
    }

    /// O episódio que entra no log. Quem appenda é o host (via `Engine::append`
    /// — indexação viva + consenso), como no v1.
    pub fn episode(&self) -> Result<Episode, HeraclitusError> {
        let payload =
            serde_json::to_vec(self).map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        Ok(Episode::new("tier", EventKind::DemotionReceipt, payload))
    }
}

/// Recibo de demoção de qualquer versão.
///
/// Existe porque o log é imutável: os recibos v1 escritos antes desta fase
/// continuam lá e continuam válidos para o que provavam. Ler um log antigo não
/// pode falhar só porque o formato evoluiu.
#[derive(Debug, Clone)]
pub enum AnyDemotionReceipt {
    V1(crate::DemotionReceipt),
    V2(Box<DemotionReceiptV2>),
}

/// Descodifica o payload JSON de um episódio `DemotionReceipt`.
///
/// A discriminação é pelo campo `receipt_version`, que o v1 não tem — não por
/// tentativa e erro de desserialização, que aceitaria um v2 truncado como v1.
pub fn decode_receipt_payload(payload: &[u8]) -> Result<AnyDemotionReceipt, HeraclitusError> {
    #[derive(Deserialize)]
    struct Sonda {
        #[serde(default)]
        receipt_version: u32,
    }
    let sonda: Sonda = serde_json::from_slice(payload)
        .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
    match sonda.receipt_version {
        0 => Ok(AnyDemotionReceipt::V1(
            serde_json::from_slice(payload)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
        )),
        DEMOTION_RECEIPT_V2 => Ok(AnyDemotionReceipt::V2(Box::new(
            serde_json::from_slice(payload)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
        ))),
        other => Err(bad_detail(format!(
            "receipt_version {other} é desconhecida desta build"
        ))),
    }
}

fn bad(campo: &str) -> HeraclitusError {
    bad_detail(format!("campo `{campo}` não é hex do comprimento esperado"))
}

fn bad_detail(detail: String) -> HeraclitusError {
    HeraclitusError::Corruption {
        context: "recibo de demoção v2".into(),
        detail,
    }
}

/// Constrói o hex de um digest — reexportado para quem monta recibos à mão.
pub fn hex32(b: &[u8; 32]) -> String {
    hex(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recibo() -> DemotionReceiptV2 {
        let key = GenerationKey::new([0xAB; 16], 88, [0xCD; 32], 2);
        DemotionReceiptV2 {
            receipt_version: DEMOTION_RECEIPT_V2,
            segment_id: 88,
            generation: 2,
            first_lsn: 100,
            last_lsn: 199,
            record_count: 100,
            canonical_codec_version: 1,
            storage_namespace_id: hex(&[0xAB; 16]),
            logical_root: hex(&[0xCD; 32]),
            physical_digest: hex(&[0xEF; 32]),
            physical_size: 4096,
            physical_layout: "PACKED".into(),
            compression_codec: "ZSTD".into(),
            object_path: key.segment_path().to_string(),
            hrki_path: Some(key.hrki_path().to_string()),
            parquet_path: None,
            source_generation: Some(1),
            created_hlc: 7,
        }
    }

    #[test]
    fn digest_e_deterministico_e_sensivel() {
        let r = recibo();
        assert_eq!(r.digest().unwrap(), recibo().digest().unwrap());

        // §84: mudar os bytes físicos sem mudar o histórico tem de mudar o
        // digest do recibo.
        let mut outro = recibo();
        outro.physical_digest = hex(&[0x11; 32]);
        assert_ne!(r.digest().unwrap(), outro.digest().unwrap());

        // E mudar de geração também.
        let mut g = recibo();
        g.generation = 3;
        assert_ne!(r.digest().unwrap(), g.digest().unwrap());
    }

    #[test]
    fn campos_textuais_nao_colidem_por_concatenacao() {
        let mut a = recibo();
        let mut b = recibo();
        a.physical_layout = "PACKE".into();
        a.compression_codec = "DZSTD".into();
        b.physical_layout = "PACKED".into();
        b.compression_codec = "ZSTD".into();
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn caminho_tem_de_bater_com_os_campos() {
        recibo().check_path_consistency().unwrap();
        let mut adulterado = recibo();
        adulterado.object_path = "canonical/outro/segment-0000000001/x/generation-1.hrkl".into();
        assert!(adulterado.check_path_consistency().is_err());
    }

    #[test]
    fn envelope_amarra_a_raiz_ao_segmento() {
        let e = recibo().attestation().unwrap();
        assert_eq!(e.segment_id, 88);
        assert_eq!(e.logical_root, [0xCD; 32]);
        let mut noutro_banco = recibo();
        noutro_banco.storage_namespace_id = hex(&[0x01; 16]);
        assert_ne!(e.imprint(), noutro_banco.attestation().unwrap().imprint());
    }

    #[test]
    fn geracao_publicada_nao_nasce_verificada() {
        let g = recibo().physical_generation().unwrap();
        assert_eq!(g.state, heraclitus_core::runtime::GenerationState::Active);
        assert_eq!(g.verified_hlc, 0);
        assert_eq!(g.physical_digest, [0xEF; 32]);
        assert_eq!(g.location, recibo().object_path);
    }

    #[test]
    fn v1_e_v2_coexistem_no_mesmo_log() {
        let v2 = recibo();
        let bytes = serde_json::to_vec(&v2).unwrap();
        match decode_receipt_payload(&bytes).unwrap() {
            AnyDemotionReceipt::V2(r) => assert_eq!(*r, v2),
            AnyDemotionReceipt::V1(_) => panic!("v2 lido como v1"),
        }

        let v1 = crate::DemotionReceipt {
            segment_id: 7,
            object_path: "cold/00000000000000000007.hrkl".into(),
            record_count: 3,
            min_lsn: 0,
            max_lsn: 2,
            blake3_root: "00".repeat(32),
            parquet_path: None,
            compacted_from: None,
            dropped: 0,
        };
        let bytes = serde_json::to_vec(&v1).unwrap();
        match decode_receipt_payload(&bytes).unwrap() {
            AnyDemotionReceipt::V1(r) => assert_eq!(r.segment_id, 7),
            AnyDemotionReceipt::V2(_) => panic!("v1 lido como v2"),
        }
    }

    #[test]
    fn versao_futura_e_recusada_em_vez_de_adivinhada() {
        let mut v = serde_json::to_value(recibo()).unwrap();
        v["receipt_version"] = serde_json::json!(99);
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(decode_receipt_payload(&bytes).is_err());
    }

    #[test]
    fn hex_malformado_e_erro_e_nao_panico() {
        let mut r = recibo();
        r.logical_root = "zz".into();
        assert!(r.logical_root_bytes().is_err());
        assert!(r.digest().is_err());
        assert!(r.key().is_err());
    }
}
