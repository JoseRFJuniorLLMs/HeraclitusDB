//! SPEC-0050 Fase 5 — publicar, verificar e reler gerações em object storage.
//!
//! Junta as três peças da fase numa só superfície:
//!
//! | §  | peça | onde |
//! |---|---|---|
//! | §82–§83 | chaves de geração imutáveis | [`crate::generation`] |
//! | §85 | cold range reads | [`crate::object_source`] |
//! | §86 | recibo v2 | [`crate::receipts_v2`] |
//! | §84 | verificação pela autoridade do Heraclitus | aqui |
//!
//! ## O que este módulo recusa fazer
//!
//! - **Sobrescrever uma geração publicada.** O `PUT` é condicional
//!   ([`object_store::PutMode::Create`]). Republicar os mesmos bytes na mesma
//!   chave é idempotente; republicar bytes *diferentes* é erro duro, não um
//!   `PUT` silencioso.
//! - **Confiar no `ETag`.** [`ColdTierV6::verify_generation`] recalcula
//!   `physical_digest` e `logical_root` a partir dos bytes descarregados. §84.
//! - **Marcar como verificada uma geração que só foi publicada.** O recibo
//!   nasce `Active`; só a verificação promove a `Verified` (§72).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use heraclitus_core::runtime::{GenerationState, PhysicalGeneration, PhysicalLayout};
use heraclitus_core::{Episode, HeraclitusError, Lsn};
use heraclitus_log::v6::canonical::CANONICAL_CODEC_V1;
use heraclitus_log::v6::error::HARD_MAX_BLOCK_BYTES;
use heraclitus_log::v6::hrki::caminho_sidecar;
use heraclitus_log::v6::{
    open_packed, physical_digest, verify_packed_reader, CompressionCodec, IntegrityLevel,
    MemorySource, PackedSegmentReader, ScanCounters, VerifyReport,
};
use heraclitus_log::v6::packer::CanonicalHasher;
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions};

use crate::generation::{hex, GenerationKey};
use crate::object_source::{store_err, ColdReadStats, ColdSegmentReader};
use crate::receipts_v2::{DemotionReceiptV2, DEMOTION_RECEIPT_V2};

/// O tier frio sobre gerações HRKL v6.
///
/// Coexiste com o [`crate::ColdTier`] v1 de propósito: o layout `cold/{id}.hrkl`
/// continua a ser lido por quem tem recibos antigos, e os dois prefixos nunca
/// se cruzam no mesmo bucket.
pub struct ColdTierV6 {
    store: Arc<dyn ObjectStore>,
    max_block_bytes: usize,
}

/// O que uma verificação de geração apurou.
#[derive(Debug, Clone)]
pub struct ColdVerifyReport {
    /// `physical_digest` recalculado bate com o do recibo (§84).
    pub physical_digest_ok: bool,
    /// `logical_root` do footer bate com a do recibo (§7).
    pub logical_root_ok: bool,
    /// O caminho publicado corresponde aos campos do recibo.
    pub path_ok: bool,
    pub bytes_downloaded: u64,
    pub report: VerifyReport,
}

impl ColdVerifyReport {
    /// Só é verdade quando **todas** as identidades fecham. Uma raiz lógica
    /// correcta sobre bytes trocados continua a ser uma falha.
    pub fn is_ok(&self) -> bool {
        self.physical_digest_ok && self.logical_root_ok && self.path_ok && self.report.is_ok()
    }
}

impl ColdTierV6 {
    pub fn with_store(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            max_block_bytes: HARD_MAX_BLOCK_BYTES,
        }
    }

    pub fn open_local(root: impl AsRef<Path>) -> Result<Self, HeraclitusError> {
        std::fs::create_dir_all(root.as_ref())?;
        let store = LocalFileSystem::new_with_prefix(root.as_ref())
            .map_err(|e| HeraclitusError::Storage(std::io::Error::other(e)))?;
        Ok(Self::with_store(Arc::new(store)))
    }

    /// Mesmo contrato de [`crate::ColdTier::open_location`]: URL de nuvem atrás
    /// das features `gcp`/`aws`, credenciais do ambiente, nunca do TOML.
    pub fn open_location(location: &str) -> Result<Self, HeraclitusError> {
        Ok(Self::with_store(crate::ColdTier::store_for(location)?))
    }

    pub fn store(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.store)
    }

    /// Publica um `.hrkl` v6 PACKED local sob a chave de geração de §82.
    ///
    /// `generation` é o número da geração física no manifesto — o mesmo que o
    /// [`heraclitus_log::v6::PackReceipt`] atribuiu ao empacotar. Não é
    /// inventado aqui: inventá-lo seria criar uma segunda contagem de gerações,
    /// que é exactamente o segundo catálogo que §69 proíbe.
    pub async fn publish_generation(
        &self,
        local_hrkl: &Path,
        generation: u32,
        source_generation: Option<u32>,
        created_hlc: u64,
    ) -> Result<DemotionReceiptV2, HeraclitusError> {
        let reader = open_packed(local_hrkl, self.max_block_bytes)?;

        // Ler cada bloco valida o CRC de §48 **e** revela o codec usado. Um
        // objecto não sai daqui sem que os seus bytes tenham sido lidos ao
        // menos uma vez: publicar um segmento corrompido para o tier frio é a
        // maneira mais cara de descobrir a corrupção.
        let mut counters = ScanCounters::default();
        let mut codecs: BTreeSet<u8> = BTreeSet::new();
        for i in 0..reader.block_count() {
            let (h, _) = reader.read_block(i, &mut counters)?;
            codecs.insert(h.codec as u8);
        }
        let compression_codec = codec_label(&codecs);

        let bytes = std::fs::read(local_hrkl)?;
        let digest = physical_digest(&bytes);
        let key = GenerationKey::new(
            reader.header.storage_namespace_id,
            reader.header.segment_id,
            reader.footer.logical_root,
            generation,
        );

        self.put_immutable(&key.segment_path(), bytes.clone(), &digest)
            .await?;

        // O `.hrki` é derivado (§56): se não existir ao lado do segmento, não
        // se inventa nem se bloqueia a publicação — reconstrói-se depois.
        let hrki_local = caminho_sidecar(local_hrkl);
        let hrki_path = if hrki_local.exists() {
            let hb = std::fs::read(&hrki_local)?;
            let hd = physical_digest(&hb);
            self.put_immutable(&key.hrki_path(), hb, &hd).await?;
            Some(key.hrki_path().to_string())
        } else {
            None
        };

        let receipt = DemotionReceiptV2 {
            receipt_version: DEMOTION_RECEIPT_V2,
            segment_id: reader.header.segment_id,
            generation,
            first_lsn: reader.footer.min_lsn,
            last_lsn: reader.footer.max_lsn,
            record_count: reader.footer.record_count,
            canonical_codec_version: CANONICAL_CODEC_V1 as u16,
            storage_namespace_id: hex(&reader.header.storage_namespace_id),
            logical_root: hex(&reader.footer.logical_root),
            physical_digest: hex(&digest),
            physical_size: bytes.len() as u64,
            physical_layout: "PACKED".into(),
            compression_codec,
            object_path: key.segment_path().to_string(),
            hrki_path,
            parquet_path: None,
            source_generation,
            created_hlc,
        };
        receipt.check_path_consistency()?;
        Ok(receipt)
    }

    /// `PUT` condicional de §83.
    ///
    /// Se a chave já existe, os bytes têm de ser **os mesmos** — republicar é
    /// então idempotente (um retry de rede não deve falhar). Bytes diferentes
    /// na mesma chave são um erro duro: a geração seguinte é que devia mudar.
    async fn put_immutable(
        &self,
        path: &ObjPath,
        bytes: Vec<u8>,
        digest: &[u8; 32],
    ) -> Result<(), HeraclitusError> {
        let opts = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self.store.put_opts(path, bytes.into(), opts).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existente = self
                    .store
                    .get(path)
                    .await
                    .map_err(|e| store_err(path, e))?
                    .bytes()
                    .await
                    .map_err(|e| store_err(path, e))?;
                if &physical_digest(&existente) == digest {
                    Ok(())
                } else {
                    Err(HeraclitusError::Corruption {
                        context: "publicação de geração HRKL".into(),
                        detail: format!(
                            "§83: `{path}` já existe com bytes diferentes; \
                             uma geração publicada não é sobrescrita — publique a geração seguinte"
                        ),
                    })
                }
            }
            Err(e) => Err(store_err(path, e)),
        }
    }

    /// Abre um segmento frio para leitura por intervalos (§85).
    pub async fn open_cold(&self, key: &GenerationKey) -> Result<ColdSegmentReader, HeraclitusError> {
        ColdSegmentReader::open(
            Arc::clone(&self.store),
            key.segment_path(),
            self.max_block_bytes,
        )
        .await
    }

    /// Recall de um intervalo de LSN: só os blocos que sobrevivem ao pruning
    /// atravessam a rede. Devolve também o que a leitura custou.
    pub async fn recall_lsn_range(
        &self,
        key: &GenerationKey,
        lo: Lsn,
        hi: Lsn,
    ) -> Result<(Vec<(Lsn, Episode)>, ColdReadStats), HeraclitusError> {
        let mut reader = self.open_cold(key).await?;
        let brutos = reader.scan_lsn_range(lo, hi).await?;
        let mut out = Vec::with_capacity(brutos.len());
        for (lsn, _hlc, payload) in brutos {
            out.push((
                lsn,
                heraclitus_log::decode_episode_payload(
                    heraclitus_log::format::FORMAT_VERSION,
                    &payload,
                )?,
            ));
        }
        Ok((out, reader.stats()))
    }

    /// Verifica uma geração publicada contra o seu recibo (§84).
    ///
    /// Transfere o objecto inteiro de propósito: `physical_digest` é sobre o
    /// ficheiro todo e a verificação lógica precisa de todos os registos. É o
    /// único caminho desta fase em que descarregar tudo é a resposta certa.
    pub async fn verify_generation(
        &self,
        receipt: &DemotionReceiptV2,
        level: IntegrityLevel,
        hasher: Option<CanonicalHasher<'_>>,
    ) -> Result<ColdVerifyReport, HeraclitusError> {
        let path_ok = receipt.check_path_consistency().is_ok();
        let path = ObjPath::from(receipt.object_path.clone());
        let bytes = self
            .store
            .get(&path)
            .await
            .map_err(|e| store_err(&path, e))?
            .bytes()
            .await
            .map_err(|e| store_err(&path, e))?
            .to_vec();

        let bytes_downloaded = bytes.len() as u64;
        let physical_digest_ok = physical_digest(&bytes) == receipt.physical_digest_bytes()?;

        let reader: PackedSegmentReader<MemorySource> =
            PackedSegmentReader::open(MemorySource(bytes), self.max_block_bytes)?;
        let logical_root_ok = reader.footer.logical_root == receipt.logical_root_bytes()?;
        let report = verify_packed_reader(&reader, level, hasher)?;

        Ok(ColdVerifyReport {
            physical_digest_ok,
            logical_root_ok,
            path_ok,
            bytes_downloaded,
            report,
        })
    }

    /// A entrada de manifesto de uma geração **já verificada** (§72).
    ///
    /// Separada de [`DemotionReceiptV2::physical_generation`] porque o estado
    /// não é uma opinião do publicador: só quem correu a verificação pode
    /// carimbar `Verified`.
    pub fn verified_generation(
        receipt: &DemotionReceiptV2,
        report: &ColdVerifyReport,
        verified_hlc: u64,
    ) -> Result<PhysicalGeneration, HeraclitusError> {
        let mut g = receipt.physical_generation()?;
        if report.is_ok() && report.report.level >= IntegrityLevel::Logical {
            g.state = GenerationState::Verified;
            g.verified_hlc = verified_hlc;
        } else if !report.is_ok() {
            g.state = GenerationState::Quarantined;
        }
        Ok(g)
    }
}

/// `RAW`/`ZSTD`/`LZ4_RAW` quando todos os blocos concordam; `MIXED` quando não.
///
/// `MIXED` não é um defeito: §34 manda cair para RAW quando a compressão não
/// compensa, bloco a bloco. O recibo diz a verdade em vez de escolher um
/// vencedor.
fn codec_label(codecs: &BTreeSet<u8>) -> String {
    let mut it = codecs.iter();
    match (it.next(), it.next()) {
        (Some(&c), None) => CompressionCodec::from_u8(c)
            .map(|c| c.as_str().to_string())
            .unwrap_or_else(|_| "MIXED".into()),
        (Some(_), Some(_)) => "MIXED".into(),
        // Segmento PACKED sem blocos: legítimo (zero registos selados).
        _ => CompressionCodec::Raw.as_str().to_string(),
    }
}

/// O layout físico que um recibo declara, em texto.
pub fn layout_label(l: PhysicalLayout) -> &'static str {
    match l {
        PhysicalLayout::Raw => "RAW",
        PhysicalLayout::Packed => "PACKED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotulo_do_codec() {
        assert_eq!(codec_label(&BTreeSet::from([1])), "ZSTD");
        assert_eq!(codec_label(&BTreeSet::from([0])), "RAW");
        assert_eq!(codec_label(&BTreeSet::from([2])), "LZ4_RAW");
        assert_eq!(codec_label(&BTreeSet::from([0, 1])), "MIXED");
        assert_eq!(codec_label(&BTreeSet::new()), "RAW");
    }

    #[test]
    fn rotulo_do_layout() {
        assert_eq!(layout_label(PhysicalLayout::Packed), "PACKED");
        assert_eq!(layout_label(PhysicalLayout::Raw), "RAW");
    }
}
