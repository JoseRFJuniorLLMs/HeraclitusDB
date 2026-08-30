//! SPEC-0050 §82–§84 — chaves de geração imutáveis em object storage.
//!
//! O tier v1 escrevia `cold/{segment_id}.hrkl`: uma chave por segmento. Isso
//! obriga a que republicar um segmento — repack, recompressão, mudança de
//! codec — seja um `PUT` por cima do mesmo objecto, o que §83 proíbe. Uma
//! geração publicada nunca é sobrescrita; publica-se **outra geração**.
//!
//! A chave carrega a `logical_root` no caminho de propósito: dois objectos com
//! a mesma raiz lógica são o mesmo histórico (podem diferir nos bytes físicos),
//! e dois objectos com raízes diferentes nunca colidem na mesma pasta, mesmo
//! que o número de geração seja reutilizado por engano depois de um restore.
//!
//! ```text
//! canonical/<namespace>/segment-0000000088/<logical-root>/generation-1.hrkl
//!                                                          generation-1.hrki
//!                                                          generation-1.parquet
//! ```
//!
//! §84 é o que este módulo **não** faz: nunca compara `ETag`. A autoridade é
//! `physical_digest` + `logical_root`, ambos calculados pelo Heraclitus a
//! partir dos bytes — ver [`crate::demotion`].

use heraclitus_core::{HeraclitusError, SegmentId};
use heraclitus_log::v6::header::StorageNamespaceId;
use object_store::path::Path as ObjPath;

/// Prefixo de todas as gerações canónicas. Deliberadamente distinto de `cold/`
/// (o layout v1), para que os dois possam coexistir no mesmo bucket durante a
/// migração sem que uma listagem confunda os dois esquemas.
pub const CANONICAL_PREFIX: &str = "canonical";

/// Extensões dos objectos de uma geração.
pub const EXT_SEGMENT: &str = "hrkl";
pub const EXT_HRKI: &str = "hrki";
pub const EXT_PARQUET: &str = "parquet";

/// Identidade de um objecto publicado (§82).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationKey {
    pub storage_namespace_id: StorageNamespaceId,
    pub segment_id: SegmentId,
    pub logical_root: [u8; 32],
    pub generation: u32,
}

impl GenerationKey {
    pub fn new(
        storage_namespace_id: StorageNamespaceId,
        segment_id: SegmentId,
        logical_root: [u8; 32],
        generation: u32,
    ) -> Self {
        Self {
            storage_namespace_id,
            segment_id,
            logical_root,
            generation,
        }
    }

    /// O directório da geração, sem barra final.
    pub fn dir(&self) -> String {
        format!(
            "{CANONICAL_PREFIX}/{}/segment-{:010}/{}",
            hex(&self.storage_namespace_id),
            self.segment_id,
            hex(&self.logical_root),
        )
    }

    fn with_ext(&self, ext: &str) -> ObjPath {
        ObjPath::from(format!("{}/generation-{}.{ext}", self.dir(), self.generation))
    }

    /// O `.hrkl` — a verdade física da geração.
    pub fn segment_path(&self) -> ObjPath {
        self.with_ext(EXT_SEGMENT)
    }

    /// O sidecar `.hrki` (Fase 4). Derivado: pode faltar sem perda.
    pub fn hrki_path(&self) -> ObjPath {
        self.with_ext(EXT_HRKI)
    }

    /// A projecção Parquet. Derivada e re-gerável (§56).
    pub fn parquet_path(&self) -> ObjPath {
        self.with_ext(EXT_PARQUET)
    }

    /// Reconstrói a chave a partir do caminho de um objecto publicado.
    ///
    /// Existe para que um recibo antigo continue a ser accionável sem confiar
    /// em nenhum outro campo: se o caminho e os campos do recibo divergirem, a
    /// divergência é detectável em vez de silenciosa.
    pub fn parse(path: &str) -> Result<Self, HeraclitusError> {
        let bad = |detail: String| HeraclitusError::Corruption {
            context: "chave de geração HRKL".into(),
            detail,
        };
        let path = path.trim_matches('/');
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 5 || parts[0] != CANONICAL_PREFIX {
            return Err(bad(format!(
                "esperado `{CANONICAL_PREFIX}/<ns>/segment-<id>/<root>/generation-<n>.<ext>`, veio `{path}`"
            )));
        }
        let storage_namespace_id: StorageNamespaceId = unhex::<16>(parts[1])
            .ok_or_else(|| bad(format!("namespace não é hex de 16 bytes: `{}`", parts[1])))?;
        let segment_id: SegmentId = parts[2]
            .strip_prefix("segment-")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad(format!("segmento malformado: `{}`", parts[2])))?;
        let logical_root = unhex::<32>(parts[3])
            .ok_or_else(|| bad(format!("raiz lógica não é hex de 32 bytes: `{}`", parts[3])))?;
        let file = parts[4];
        let stem = file
            .rsplit_once('.')
            .map(|(s, _)| s)
            .ok_or_else(|| bad(format!("objecto sem extensão: `{file}`")))?;
        let generation: u32 = stem
            .strip_prefix("generation-")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad(format!("geração malformada: `{file}`")))?;
        Ok(Self {
            storage_namespace_id,
            segment_id,
            logical_root,
            generation,
        })
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Descodifica exactamente `N` bytes de hex minúsculo/maiúsculo. `None` para
/// qualquer input que não seja exactamente isso — comprimento incluído.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> GenerationKey {
        GenerationKey::new([0xAB; 16], 88, [0xCD; 32], 3)
    }

    #[test]
    fn caminho_segue_o_layout_de_82() {
        let k = key();
        assert_eq!(
            k.segment_path().to_string(),
            format!(
                "canonical/{}/segment-0000000088/{}/generation-3.hrkl",
                "ab".repeat(16),
                "cd".repeat(32)
            )
        );
        assert!(k.hrki_path().to_string().ends_with("generation-3.hrki"));
        assert!(k
            .parquet_path()
            .to_string()
            .ends_with("generation-3.parquet"));
    }

    #[test]
    fn round_trip_do_caminho() {
        let k = key();
        for p in [k.segment_path(), k.hrki_path(), k.parquet_path()] {
            assert_eq!(GenerationKey::parse(p.as_ref()).unwrap(), k);
        }
    }

    #[test]
    fn geracoes_diferentes_nunca_partilham_objecto() {
        // §83: publicar de novo é mudar de geração, não escrever por cima.
        let a = key();
        let mut b = key();
        b.generation = 4;
        assert_ne!(a.segment_path(), b.segment_path());
        // Mesma pasta, porque a raiz lógica é a mesma: o histórico é o mesmo.
        assert_eq!(a.dir(), b.dir());
    }

    #[test]
    fn raizes_diferentes_nunca_colidem() {
        let a = key();
        let mut b = key();
        b.logical_root = [0xEF; 32];
        assert_ne!(a.dir(), b.dir());
    }

    #[test]
    fn caminho_malformado_e_erro_e_nao_panico() {
        for mau in [
            "",
            "cold/0000000088.hrkl",
            "canonical/xx/segment-88/yy/generation-1.hrkl",
            "canonical/ab/segment-88/cd/generation-1.hrkl",
            &format!("canonical/{}/segment-x/{}/generation-1.hrkl", "ab".repeat(16), "cd".repeat(32)),
            &format!("canonical/{}/segment-88/{}/generation-.hrkl", "ab".repeat(16), "cd".repeat(32)),
            &format!("canonical/{}/segment-88/{}/generation-1", "ab".repeat(16), "cd".repeat(32)),
        ] {
            assert!(GenerationKey::parse(mau).is_err(), "aceitou `{mau}`");
        }
    }

    #[test]
    fn o_prefixo_nao_pode_derivar_do_que_o_gc_reconhece() {
        // O GC do log decide entre `remove_file` e "dívida do tier" por este
        // prefixo (§82). Se um dos lados mudar sozinho, o GC volta a tentar
        // apagar chaves de bucket com `std::fs` — e falha antes do commit,
        // travando o GC do banco inteiro.
        assert_eq!(
            format!("{CANONICAL_PREFIX}/"),
            heraclitus_core::runtime::OBJECT_STORE_GENERATION_PREFIX
        );
        assert!(heraclitus_core::runtime::is_object_store_location(
            key().segment_path().as_ref()
        ));
    }

    #[test]
    fn unhex_recusa_comprimento_errado() {
        assert!(unhex::<16>(&"ab".repeat(15)).is_none());
        assert!(unhex::<16>(&"ab".repeat(17)).is_none());
        assert_eq!(unhex::<2>("00ff"), Some([0x00, 0xff]));
        assert_eq!(unhex::<2>("00FF"), Some([0x00, 0xff]));
        assert!(unhex::<2>("00fg").is_none());
    }
}
