//! SPEC-0050 §96/§97, §189/§190 — compactação de gerações no tier frio.
//!
//! # Porque é que isto não é o `compact_cold` do v1
//!
//! O tier v1 tem [`crate::ColdTier::compact_cold`]: recebe um predicado
//! `is_deleted`, reescreve o segmento **sem** os registos marcados e recomputa
//! a raiz Merkle. Em v1 isso era coerente — a raiz era a identidade daqueles
//! bytes e mais nada.
//!
//! Em v6 deixa de ser. A `logical_root` é a identidade do **histórico**, e §97
//! é explícito:
//!
//! > Se `input CanonicalRecords != output CanonicalRecords`, então
//! > `input.logical_root != output.logical_root` e o output **não** substitui o
//! > segmento canónico original.
//!
//! §96 vai mais longe e nomeia a operação: um `.hrkl` que omite registos é uma
//! *projection compaction*, não uma representação canónica. Portar o
//! `compact_cold` do v1 para recibos v2 seria implementar exactamente o que a
//! spec que se diz cumprir proíbe — e o pior é que **pareceria** funcionar: o
//! recibo v2 novo seria internamente consistente, verificaria, e só se
//! descobriria o problema quando alguém tentasse provar um LSN que já lá não
//! estava.
//!
//! O que sobra, e é o que este módulo faz, é o repack de §189/§190: mudar os
//! bytes físicos (outro codec, outro block size) preservando registo a registo
//! o histórico. Ganha-se espaço e latência de leitura sem tocar na identidade.
//!
//! | quero | v1 | v6 |
//! |---|---|---|
//! | recuperar espaço de tombstones | `compact_cold(is_deleted)` | **não existe**; §95 diz que o tombstone é um evento e o registo antigo fica |
//! | recomprimir/reorganizar | — | [`ColdTierV6::repack_generation`] |
//! | tornar dado pessoal irrecuperável | — | crypto-shredding (§98), no `heraclitus-compliance` |
//! | reduzir ficheiros da projecção | espelho Parquet reescrito | compactação lakehouse (§175), ainda por fazer |
//!
//! # A geração antiga não desaparece
//!
//! Um repack publica a geração N+1 e **não** apaga a N: §83 (as chaves são
//! imutáveis) e §91 (o GC nunca remove a última autoridade canónica). Quem
//! decide coletar é o `plan_gc` do log, com pins, grace period e legal hold; a
//! remoção física dos bytes no bucket é
//! [`ColdTierV6::collect_cold_locations`], que executa uma decisão já tomada
//! noutro sítio e não a toma sozinha.

use std::path::{Path, PathBuf};

use heraclitus_core::runtime::is_object_store_location;
use heraclitus_core::HeraclitusError;
use heraclitus_log::v6::gc::{classify_compaction, CompactionClass};
use heraclitus_log::v6::packed::PackOptions;
use heraclitus_log::v6::packer::repack_segment;
use heraclitus_log::v6::{persisted_record_hash, physical_digest, PackReceipt};
use object_store::path::Path as ObjPath;
use object_store::ObjectStoreExt;

use crate::demotion::ColdTierV6;
use crate::generation::GenerationKey;
use crate::object_source::store_err;
use crate::receipts_v2::DemotionReceiptV2;

const CTX: &str = "compactação de geração fria";

/// O que um repack de geração fria produziu.
#[derive(Debug, Clone)]
pub struct ColdRepackOutcome {
    /// O recibo da geração publicada (N+1).
    pub receipt: DemotionReceiptV2,
    /// O recibo de packing de §88, com as duas identidades físicas lado a lado.
    pub pack: PackReceipt,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

impl ColdRepackOutcome {
    /// Bytes poupados. **Pode ser negativo**: repackar para `Fast` (LZ4) a
    /// partir de `Archive` (Zstd de nível alto) cresce, e é uma troca legítima
    /// quando o que se quer é latência de leitura. Devolver `u64` aqui
    /// obrigaria a um `saturating_sub` que reportaria «0 poupados» para um
    /// objecto que engordou 30%.
    pub fn saved_bytes(&self) -> i64 {
        self.bytes_before as i64 - self.bytes_after as i64
    }

    /// `depois/antes`. `1.0` = mesmo tamanho; `< 1.0` = encolheu.
    pub fn ratio(&self) -> f64 {
        if self.bytes_before == 0 {
            return 1.0;
        }
        self.bytes_after as f64 / self.bytes_before as f64
    }
}

/// O que uma passagem de recolha física apurou.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColdCollectReport {
    /// Objectos efectivamente removidos do bucket.
    pub removed: Vec<String>,
    /// Já não existiam. Não é erro: o estado final desejado é o mesmo, e um GC
    /// que falhasse por causa disto não seria retomável depois de um crash a
    /// meio da remoção.
    pub already_absent: Vec<String>,
    /// Falharam a remoção (permissões, rede). Ficam como dívida visível em vez
    /// de serem contadas como removidas.
    pub failed: Vec<(String, String)>,
}

impl ColdCollectReport {
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }
}

impl ColdTierV6 {
    /// §189/§190 — repack de uma geração fria para outra, preservando a
    /// `logical_root`.
    ///
    /// O caminho é: descarregar → **autenticar** → repackar em disco local →
    /// publicar a geração seguinte. `scratch` é onde os dois ficheiros
    /// temporários vivem; ambos são removidos no fim, incluindo em erro.
    ///
    /// ## Autenticar antes de repackar não é zelo a mais
    ///
    /// Se os bytes descarregados não conferirem com o `physical_digest` do
    /// recibo, o repack **não acontece**. Sem esta paragem, um objecto
    /// corrompido no bucket seria relido, reempacotado e publicado como uma
    /// geração nova com recibo próprio, internamente consistente — a corrupção
    /// ganharia uma certidão de nascimento limpa, e a geração de origem, ainda
    /// correcta noutra réplica, ficaria marcada como superseded por ela.
    ///
    /// Nota: o `repack_segment` recusa por conta própria uma raiz lógica
    /// diferente. A classificação de §96/§97 é feita **outra vez** aqui, com
    /// [`classify_compaction`], porque as duas verificações são escritas
    /// separadamente de propósito — é o mesmo raciocínio do
    /// `assert_gc_invariant`.
    pub async fn repack_generation(
        &self,
        receipt: &DemotionReceiptV2,
        target_generation: u32,
        opts: PackOptions,
        scratch: &Path,
        created_hlc: u64,
    ) -> Result<ColdRepackOutcome, HeraclitusError> {
        receipt.check_path_consistency()?;
        if target_generation <= receipt.generation {
            return Err(corrupt(format!(
                "§83: a geração alvo ({target_generation}) tem de ser posterior à de origem ({}); \
                 reutilizar um número de geração colide com uma chave imutável",
                receipt.generation
            )));
        }

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

        let esperado = receipt.physical_digest_bytes()?;
        if physical_digest(&bytes) != esperado {
            return Err(corrupt(format!(
                "§84: os bytes de `{}` não conferem com o `physical_digest` do recibo; \
                 um objecto adulterado não é repackado — seria lavá-lo numa geração nova",
                receipt.object_path
            )));
        }

        std::fs::create_dir_all(scratch)?;
        let origem = scratch.join(format!(
            "repack-{:010}-g{}.origem.hrkl",
            receipt.segment_id, receipt.generation
        ));
        let alvo = scratch.join(format!(
            "repack-{:010}-g{target_generation}.alvo.hrkl",
            receipt.segment_id
        ));
        let _limpeza = Limpeza(vec![origem.clone(), alvo.clone()]);
        // Um alvo deixado por uma corrida anterior faria `repack_segment`
        // recusar («target generation already exists»), o que aqui seria um
        // falso positivo: a imutabilidade que interessa é a da chave no bucket,
        // não a de um ficheiro de scratch.
        let _ = std::fs::remove_file(&alvo);
        std::fs::write(&origem, &bytes)?;

        let outcome = repack_segment(
            &origem,
            &alvo,
            opts,
            receipt.generation,
            target_generation,
            &persisted_record_hash,
        )?;

        let raiz_origem = receipt.logical_root_bytes()?;
        if classify_compaction(&raiz_origem, &outcome.footer.logical_root)
            != CompactionClass::Canonical
        {
            return Err(corrupt(
                "§96/§97: o output tem outras CanonicalRecords — é uma projecção analítica \
                 e nunca substitui o segmento canónico"
                    .to_string(),
            ));
        }
        // §190, item a item: nem episódios removidos, nem LSN reordenados.
        if outcome.footer.record_count != receipt.record_count
            || outcome.footer.min_lsn != receipt.first_lsn
            || outcome.footer.max_lsn != receipt.last_lsn
        {
            return Err(corrupt(format!(
                "§190: o repack alterou o histórico ({} registos [{}, {}] → {} registos [{}, {}])",
                receipt.record_count,
                receipt.first_lsn,
                receipt.last_lsn,
                outcome.footer.record_count,
                outcome.footer.min_lsn,
                outcome.footer.max_lsn
            )));
        }

        // O `.hrki` da origem **não** é copiado, e é a coisa mais fácil de
        // errar aqui: o sidecar indexa blocos por offset (§56), e um repack com
        // outro `block_target_bytes` muda todos os offsets. Um sidecar herdado
        // apontaria para dentro de bytes que já não são os mesmos e o pruning
        // devolveria os blocos errados — em silêncio, porque a raiz lógica
        // continuaria a bater. Publicar sem sidecar é correcto: §56 manda
        // reconstruí-lo, e o recall por intervalo de LSN usa o directório de
        // blocos do próprio segmento.
        let novo = self
            .publish_generation(
                &alvo,
                target_generation,
                Some(receipt.generation),
                created_hlc,
            )
            .await?;
        let bytes_after = std::fs::metadata(&alvo)?.len();

        Ok(ColdRepackOutcome {
            receipt: novo,
            pack: outcome.receipt,
            bytes_before: receipt.physical_size,
            bytes_after,
        })
    }

    /// Remove fisicamente objectos de gerações frias que o HRKM já não
    /// referencia — tipicamente o `cold_detached` do `commit_gc` do log.
    ///
    /// **Não decide nada.** Pins, grace period, legal hold e o invariante de
    /// §91 são do `plan_gc`; esta função executa. O que ela garante por conta
    /// própria é que só toca em chaves que são gerações canónicas de §82: uma
    /// entrada que não faça `GenerationKey::parse` é recusada antes de qualquer
    /// `DELETE`, para que um `location` corrompido no manifesto não se
    /// transforme num apagamento arbitrário no bucket.
    ///
    /// Remove também o `.hrki` da mesma geração, quando existe: o sidecar
    /// indexa offsets dentro de bytes que deixaram de existir e não serve mais
    /// ninguém. O Parquet **não** é tocado — §176 dá-o às regras do lakehouse.
    pub async fn collect_cold_locations(
        &self,
        locations: &[String],
    ) -> Result<ColdCollectReport, HeraclitusError> {
        // Validar tudo antes de apagar o que quer que seja: uma passagem que
        // apagasse metade e depois recusasse a outra metade deixaria o operador
        // sem saber onde parou.
        let mut chaves = Vec::with_capacity(locations.len());
        for location in locations {
            if !is_object_store_location(location) {
                return Err(corrupt(format!(
                    "`{location}` não é uma chave de object storage; \
                     um caminho local não se apaga por aqui"
                )));
            }
            chaves.push((location.clone(), GenerationKey::parse(location)?));
        }

        let mut report = ColdCollectReport::default();
        for (location, key) in chaves {
            let segmento = ObjPath::from(location);
            self.remove_one(&segmento, &mut report).await;
            let sidecar = key.hrki_path();
            // O sidecar entra no relatório só quando existia: listá-lo sempre
            // como `already_absent` encheria o relatório de ruído, já que a
            // maioria das gerações não tem `.hrki` publicado.
            if self.store.head(&sidecar).await.is_ok() {
                self.remove_one(&sidecar, &mut report).await;
            }
        }
        Ok(report)
    }

    async fn remove_one(&self, path: &ObjPath, report: &mut ColdCollectReport) {
        match self.store.delete(path).await {
            Ok(()) => report.removed.push(path.to_string()),
            Err(object_store::Error::NotFound { .. }) => {
                report.already_absent.push(path.to_string())
            }
            Err(e) => report.failed.push((path.to_string(), e.to_string())),
        }
    }
}

/// Remove ficheiros de scratch no fim, incluindo no caminho de erro (`?`).
struct Limpeza(Vec<PathBuf>);

impl Drop for Limpeza {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn corrupt(detail: String) -> HeraclitusError {
    HeraclitusError::Corruption {
        context: CTX.into(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recolha_recusa_o_que_nao_e_chave_de_geracao() {
        let dir = tempfile::tempdir().unwrap();
        let tier = ColdTierV6::open_local(dir.path()).unwrap();

        // Caminho local disfarçado: o GC do log manda `segments/…` para o ramo
        // local, mas se alguma vez chegasse aqui não podia ser apagado.
        assert!(tier
            .collect_cold_locations(&["segments/00000000000000000000.g0001.packed.hrkl".into()])
            .await
            .is_err());
        // Prefixo certo, forma errada.
        assert!(tier
            .collect_cold_locations(&["canonical/nao-e-uma-chave".into()])
            .await
            .is_err());
        // O layout v1 também não: os recibos v1 apontam para `cold/…` e são
        // coletados pelo caminho v1, se e quando isso existir.
        assert!(tier
            .collect_cold_locations(&["cold/00000000000000000007.hrkl".into()])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn recolha_de_chave_ausente_e_idempotente() {
        let dir = tempfile::tempdir().unwrap();
        let tier = ColdTierV6::open_local(dir.path()).unwrap();
        let key = GenerationKey::new([0xAB; 16], 3, [0xCD; 32], 2);

        let r = tier
            .collect_cold_locations(&[key.segment_path().to_string()])
            .await
            .unwrap();
        assert!(r.removed.is_empty());
        assert_eq!(r.already_absent, vec![key.segment_path().to_string()]);
        assert!(r.is_clean());
    }

    #[test]
    fn poupanca_negativa_e_dita_e_nao_saturada() {
        let o = ColdRepackOutcome {
            receipt: recibo_vazio(),
            pack: pack_vazio(),
            bytes_before: 100,
            bytes_after: 130,
        };
        assert_eq!(o.saved_bytes(), -30);
        assert!((o.ratio() - 1.3).abs() < 1e-9);
    }

    fn recibo_vazio() -> DemotionReceiptV2 {
        let key = GenerationKey::new([0; 16], 0, [0; 32], 1);
        DemotionReceiptV2 {
            receipt_version: crate::receipts_v2::DEMOTION_RECEIPT_V2,
            segment_id: 0,
            generation: 1,
            first_lsn: 0,
            last_lsn: 0,
            record_count: 0,
            canonical_codec_version: 1,
            storage_namespace_id: crate::generation::hex(&[0u8; 16]),
            logical_root: crate::generation::hex(&[0u8; 32]),
            physical_digest: crate::generation::hex(&[0u8; 32]),
            physical_size: 0,
            physical_layout: "PACKED".into(),
            compression_codec: "ZSTD".into(),
            object_path: key.segment_path().to_string(),
            hrki_path: None,
            parquet_path: None,
            source_generation: None,
            created_hlc: 0,
        }
    }

    fn pack_vazio() -> PackReceipt {
        PackReceipt {
            segment_id: 0,
            storage_namespace_id: [0; 16],
            source_generation: 0,
            source_physical_digest: [0; 32],
            target_generation: 1,
            target_physical_digest: [0; 32],
            logical_root: [0; 32],
            canonical_codec: 1,
            codec: heraclitus_core::runtime::CompressionCodec::Zstd,
            block_size: 4096,
            first_lsn: 0,
            last_lsn: 0,
            record_count: 0,
            source_physical_size: 0,
            target_physical_size: 0,
            packer_version: heraclitus_log::v6::PACKER_VERSION,
            created_hlc: 0,
        }
    }
}
