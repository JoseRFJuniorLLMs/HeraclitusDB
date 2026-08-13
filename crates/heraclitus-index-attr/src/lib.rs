//! heraclitus-index-attr — o índice secundário AUTOMÁTICO.
//!
//! Um banco sem índices não é um banco. Esta view indexa **todos os atributos**
//! de cada evento — `(campo, valor) -> [LSN]` — para que uma consulta por CPF,
//! CNPJ, nome ou qualquer outro campo seja O(postings), não um scan do log.
//!
//! - **Automático/inteligente:** indexa qualquer campo presente nos `attrs`; não
//!   é preciso declarar índices.
//! - **View materializada:** `apply(lsn, event)` no append (read-your-own-writes)
//!   e reconstruível por replay determinístico a partir do LSN 0.
//! - **Persistido:** `checkpoint`/`open` (bincode) — num log de milhões de nós o
//!   arranque carrega o índice e só replaya a cauda, em vez de reconstruir tudo.
//!
//! O planeador de queries usa `lookup` para resolver `WHERE n.<campo> = "v"` sem
//! varrer a janela (ver heraclitus-query::plan).

use heraclitus_core::{CanonicalKeyCodec, Episode, HeraclitusError, Lsn};
use heraclitus_views::View;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::path::Path;

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();
const SNAPSHOT_FILE: &str = "attr_index.bin";
/// Separador entre campo e valor na chave do índice (US, nunca aparece em dados).
const SEP: char = '\u{1f}';
/// Valores quase-ubíquos sem poder discriminante são ignorados (evita postings
/// gigantes que não ajudam a localizar nada).
const SKIP_VALUES: &[&str] = &["", "0", "-1", "nao", "sim", "true", "false", "null", "none"];
/// Valores maiores que isto são texto livre (descrições) — inúteis para busca
/// exata e fariam o índice explodir em RAM/disco. Identificadores e nomes
/// (CPF/CNPJ/códigos/razão social) ficam muito abaixo.
const MAX_VALUE_LEN: usize = 80;

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    watermark: Lsn,
    applied: bool,
    /// `"campo\u{1f}valor" -> [LSN]` (postings em ordem crescente de LSN).
    exact: HashMap<String, Vec<Lsn>>,
    /// Índice ORDENADO por valor numérico: `campo -> valor(f64 ordenável) ->
    /// [LSN]` (padrão Qdrant de range filtering). A chave é o f64 mapeado num
    /// u64 que preserva a ordem total, para o BTreeMap poder fazer `range()`.
    /// Formato de checkpoint incompatível com o anterior: `open` degrada para
    /// rebuild por replay (correto por construção).
    numeric: HashMap<String, BTreeMap<u64, Vec<Lsn>>>,
}

// SPEC-009: a chave numérica ordenável é o `CanonicalKeyCodec::encode_f64` do
// core — ordem total correta, com colapso de NaN e normalização de -0.0→+0.0
// (o `f64_ordered` ad-hoc anterior não tratava esses casos). Para todo valor
// finito ≠ -0.0 a codificação é bit-idêntica à anterior, logo os checkpoints
// existentes permanecem legíveis.

/// Índice invertido de atributos. Persistido e reconstruível por replay.
#[derive(Default)]
pub struct AttrIndex {
    inner: Snapshot,
}

fn ikey(field: &str, value: &str) -> String {
    let mut s = String::with_capacity(field.len() + value.len() + 1);
    s.push_str(field);
    s.push(SEP);
    s.push_str(value);
    s
}

impl AttrIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abre o índice carregando o checkpoint de `dir` (vazio se não existir).
    pub fn open(dir: impl AsRef<Path>) -> Self {
        let path = dir.as_ref().join(SNAPSHOT_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => {
                match bincode::serde::decode_from_slice::<Snapshot, _>(&bytes, BINCODE_CFG) {
                    Ok((snap, _)) => AttrIndex { inner: snap },
                    Err(_) => AttrIndex::new(), // checkpoint corrompido -> rebuild por replay
                }
            }
            Err(_) => AttrIndex::new(),
        }
    }

    /// LSNs (ordenados) dos eventos cujo `field == value`. Vazio se nada bate.
    pub fn lookup(&self, field: &str, value: &str) -> &[Lsn] {
        self.inner
            .exact
            .get(&ikey(field, value))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// LSNs (ordenados, sem duplicados) dos eventos cujo valor NUMÉRICO de
    /// `field` cai no intervalo `[min, max]` (bounds à la `BTreeMap::range`).
    /// Vazio se o campo não tem valores numéricos indexados.
    pub fn lookup_range(&self, field: &str, min: Bound<f64>, max: Bound<f64>) -> Vec<Lsn> {
        let Some(by_value) = self.inner.numeric.get(field) else {
            return Vec::new();
        };
        let enc = |b: Bound<f64>| match b {
            Bound::Included(v) => Bound::Included(CanonicalKeyCodec::encode_f64(v)),
            Bound::Excluded(v) => Bound::Excluded(CanonicalKeyCodec::encode_f64(v)),
            Bound::Unbounded => Bound::Unbounded,
        };
        let (lo, hi) = (enc(min), enc(max));
        // `BTreeMap::range` PANICA se o início for maior que o fim (ou se ambos
        // forem Excluded e iguais). Uma query GQL de sintaxe VÁLIDA chega aqui
        // com um intervalo vazio — p.ex. `WHERE n.v > 100 AND n.v < 10`. Como
        // este código corre com o Mutex do índice de atributos BLOQUEADO, o
        // panic ENVENENAVA-O: a partir daí todo `index_applied` falhava e o nó
        // deixava de aceitar escritas até reiniciar. Intervalo vazio ⇒ zero
        // resultados, que é a resposta correta.
        let vazio = match (&lo, &hi) {
            (Bound::Included(a), Bound::Included(b)) => a > b,
            (Bound::Included(a), Bound::Excluded(b))
            | (Bound::Excluded(a), Bound::Included(b))
            | (Bound::Excluded(a), Bound::Excluded(b)) => a >= b,
            _ => false,
        };
        if vazio {
            return Vec::new();
        }
        let mut out: Vec<Lsn> = by_value
            .range((lo, hi))
            .flat_map(|(_, postings)| postings.iter().copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Nº de pares (campo,valor) distintos indexados.
    pub fn keys(&self) -> usize {
        self.inner.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.exact.is_empty()
    }

    /// Grava o checkpoint em `dir` (escrita atómica tmp+rename).
    pub fn save(&self, dir: impl AsRef<Path>) -> Result<(), HeraclitusError> {
        std::fs::create_dir_all(dir.as_ref())?;
        let bytes = bincode::serde::encode_to_vec(&self.inner, BINCODE_CFG)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let dst = dir.as_ref().join(SNAPSHOT_FILE);
        let tmp = dir.as_ref().join(format!("{SNAPSHOT_FILE}.tmp"));
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &dst)?;
        Ok(())
    }
}

impl View for AttrIndex {
    fn name(&self) -> &str {
        "attr"
    }

    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        // Inserção ORDENADA com dedup por LSN (binary_search): torna o apply
        // idempotente (replay que sobrepõe o watermark re-entrega LSNs já
        // aplicados → skip) E tolerante a entregas fora de ordem (dois appends
        // concorrentes podem indexar 6 antes de 5 — o guard antigo
        // `lsn <= watermark → return` DESCARTAVA o 5 para sempre, um buraco
        // silencioso na view). Mantém o invariante "postings em ordem crescente".
        fn insert_sorted(v: &mut Vec<Lsn>, lsn: Lsn) {
            if let Err(i) = v.binary_search(&lsn) {
                v.insert(i, lsn);
            }
        }
        for (field, value) in &event.attrs {
            let v = value.trim();
            if v.len() > MAX_VALUE_LEN || SKIP_VALUES.contains(&v.to_ascii_lowercase().as_str()) {
                continue;
            }
            insert_sorted(self.inner.exact.entry(ikey(field, v)).or_default(), lsn);
            // Valor numérico entra também no índice ordenado (range filtering).
            // Os SKIP_VALUES continuam de fora — "0"/"-1" ubíquos gerariam
            // postings gigantes sem poder discriminante.
            if let Ok(n) = v.parse::<f64>() {
                if n.is_finite() {
                    insert_sorted(
                        self.inner
                            .numeric
                            .entry(field.clone())
                            .or_default()
                            .entry(CanonicalKeyCodec::encode_f64(n))
                            .or_default(),
                        lsn,
                    );
                }
            }
        }
        // Watermark só avança (max): regressão persistida causaria re-replay —
        // agora inócuo (idempotente), mas o avanço-só mantém a semântica exata.
        self.inner.watermark = self.inner.watermark.max(lsn);
        self.inner.applied = true;
    }

    fn watermark(&self) -> Lsn {
        self.inner.watermark
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        self.save(dir)
    }

    fn reset(&mut self) {
        self.inner = Snapshot::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};

    fn ep(cnpj: &str, nome: &str) -> Episode {
        let mut e = Episode::new("etl", EventKind::Observation, nome.as_bytes().to_vec());
        e.attrs.insert("cnpj".into(), cnpj.into());
        e.attrs.insert("nome".into(), nome.into());
        e
    }

    #[test]
    fn indexes_any_field_and_looks_up_fast() {
        let mut idx = AttrIndex::new();
        idx.apply(0, &ep("11222333000144", "OMEGA LTDA"));
        idx.apply(1, &ep("99888777000100", "ALFA SA"));
        idx.apply(2, &ep("11222333000144", "OMEGA LTDA")); // mesma empresa, outro evento

        assert_eq!(idx.lookup("cnpj", "11222333000144"), &[0, 2]);
        assert_eq!(idx.lookup("cnpj", "99888777000100"), &[1]);
        assert_eq!(idx.lookup("nome", "ALFA SA"), &[1]);
        assert!(idx.lookup("cnpj", "inexistente").is_empty());
        assert_eq!(idx.watermark(), 2);
    }

    #[test]
    fn replay_idempotent_no_duplicate_postings() {
        let mut idx = AttrIndex::new();
        let e = ep("11222333000144", "OMEGA LTDA");
        idx.apply(0, &e);
        idx.apply(0, &e); // replay sobreposto do MESMO lsn -> ignorado
        assert_eq!(idx.lookup("cnpj", "11222333000144"), &[0]);
    }

    #[test]
    fn out_of_order_apply_indexes_both_events() {
        // Appends concorrentes podem entregar 6 antes de 5 (o log atribui o LSN,
        // mas o index_applied corre fora de qualquer guarda de ordem). O guard
        // antigo `lsn <= watermark → return` DESCARTAVA o 5 para sempre — um
        // buraco silencioso na view que nem o replay pós-restart cobria (o
        // watermark persistido dizia 6). Ambos têm de ficar indexados, ordenados.
        let mut idx = AttrIndex::new();
        idx.apply(6, &ep("11222333000144", "OMEGA LTDA"));
        idx.apply(5, &ep("11222333000144", "OMEGA LTDA")); // atrasado, fora de ordem
        assert_eq!(idx.lookup("cnpj", "11222333000144"), &[5, 6]);
        // E o watermark não regrediu.
        assert_eq!(idx.watermark(), 6);
    }

    #[test]
    fn skips_ubiquitous_placeholder_values() {
        let mut idx = AttrIndex::new();
        let mut e = Episode::new("etl", EventKind::Observation, vec![]);
        e.attrs.insert("vencedor_flag".into(), "0".into());
        e.attrs.insert("cnpj".into(), "".into());
        idx.apply(0, &e);
        assert!(idx.lookup("vencedor_flag", "0").is_empty());
        assert!(idx.lookup("cnpj", "").is_empty());
    }

    #[test]
    fn skips_long_free_text_values() {
        let mut idx = AttrIndex::new();
        let mut e = Episode::new("etl", EventKind::Observation, vec![]);
        let desc = "objeto: ".to_string() + &"contratacao de servicos diversos ".repeat(5);
        assert!(desc.len() > 80);
        e.attrs.insert("objeto".into(), desc.clone());
        e.attrs.insert("cnpj".into(), "11222333000144".into());
        idx.apply(0, &e);
        assert!(
            idx.lookup("objeto", &desc).is_empty(),
            "texto livre não é indexado"
        );
        assert_eq!(
            idx.lookup("cnpj", "11222333000144"),
            &[0],
            "identificador curto é indexado"
        );
    }

    #[test]
    fn range_lookup_over_numeric_values() {
        // C1.6 (padrão Qdrant): WHERE n.valor > x AND n.valor < y sem scan.
        let mut idx = AttrIndex::new();
        let val = |v: &str| {
            let mut e = Episode::new("etl", EventKind::Observation, vec![]);
            e.attrs.insert("valor".into(), v.into());
            e
        };
        for (lsn, v) in [
            (0, "-50.5"),
            (1, "10"),
            (2, "99.9"),
            (3, "100"),
            (4, "3000"),
            (5, "abc"),
        ] {
            idx.apply(lsn, &val(v));
        }

        use std::ops::Bound::*;
        assert_eq!(
            idx.lookup_range("valor", Included(10.0), Included(100.0)),
            &[1, 2, 3]
        );
        assert_eq!(
            idx.lookup_range("valor", Excluded(10.0), Excluded(100.0)),
            &[2]
        );
        // Negativos ordenam corretamente (f64_ordered preserva a ordem total).
        assert_eq!(idx.lookup_range("valor", Unbounded, Excluded(0.0)), &[0]);
        assert_eq!(
            idx.lookup_range("valor", Included(100.0), Unbounded),
            &[3, 4]
        );
        // Não-numéricos ("abc") ficam fora do índice ordenado; campo inexistente = vazio.
        assert!(idx.lookup_range("outro", Unbounded, Unbounded).is_empty());

        // O checkpoint preserva o índice numérico.
        let dir = tempfile::tempdir().unwrap();
        idx.save(dir.path()).unwrap();
        let re = AttrIndex::open(dir.path());
        assert_eq!(
            re.lookup_range("valor", Included(10.0), Included(100.0)),
            &[1, 2, 3]
        );
    }

    #[test]
    fn negative_zero_unifies_with_positive_zero_in_range() {
        // Regressão do `f64_ordered` ad-hoc: "-0.0" recebia uma chave distinta de
        // "0.0", pelo que um range [0,0] perdia o evento com -0.0. O
        // CanonicalKeyCodec normaliza -0.0→+0.0, corrigindo isto.
        let mut idx = AttrIndex::new();
        let val = |v: &str| {
            let mut e = Episode::new("etl", EventKind::Observation, vec![]);
            e.attrs.insert("saldo".into(), v.into());
            e
        };
        idx.apply(0, &val("0.0"));
        idx.apply(1, &val("-0.0"));

        use std::ops::Bound::*;
        // Um range exatamente em zero deve apanhar AMBOS os eventos.
        assert_eq!(
            idx.lookup_range("saldo", Included(0.0), Included(0.0)),
            &[0, 1],
            "-0.0 e +0.0 são o mesmo número e têm de partilhar a chave"
        );
    }

    #[test]
    fn checkpoint_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut idx = AttrIndex::new();
        idx.apply(0, &ep("11222333000144", "OMEGA LTDA"));
        idx.apply(1, &ep("99888777000100", "ALFA SA"));
        idx.save(dir.path()).unwrap();

        let re = AttrIndex::open(dir.path());
        assert_eq!(re.lookup("cnpj", "11222333000144"), &[0]);
        assert_eq!(re.lookup("nome", "ALFA SA"), &[1]);
        assert_eq!(re.watermark(), 1);
    }

    #[test]
    fn rebuild_by_replay_equals_incremental() {
        // determinismo: indexar 0..N incrementalmente == reconstruir do zero.
        let build = |n: u64| {
            let mut idx = AttrIndex::new();
            for i in 0..n {
                idx.apply(i, &ep(&format!("cnpj{}", i % 3), &format!("nome{i}")));
            }
            idx
        };
        let a = build(30);
        let mut b = AttrIndex::new();
        b.reset();
        for i in 0..30u64 {
            b.apply(i, &ep(&format!("cnpj{}", i % 3), &format!("nome{i}")));
        }
        assert_eq!(a.lookup("cnpj", "cnpj0"), b.lookup("cnpj", "cnpj0"));
        assert_eq!(
            a.lookup("cnpj", "cnpj0"),
            &[0, 3, 6, 9, 12, 15, 18, 21, 24, 27]
        );
    }
}
