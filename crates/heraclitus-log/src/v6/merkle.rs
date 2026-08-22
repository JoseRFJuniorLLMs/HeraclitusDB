//! SPEC-0050 §16–§18 — `MerkleAccumulatorV1`.
//!
//! # A raiz não pode saber o que é um bloco
//!
//! A tentação é construir a árvore por blocos: `root(root(block0), root(block1),
//! …)`. Está errado, e a SPEC diz-lo em §16: se a divisão física entrar na
//! árvore, então **repackar com blocos de 1 MiB em vez de 256 KiB muda a raiz**
//! — e a equivalência lógica entre gerações, que é a coisa toda que autoriza o
//! GC da geração RAW, deixa de poder ser afirmada.
//!
//! Aqui a árvore vê apenas a sequência de folhas por LSN. Os blocos guardam
//! raízes auxiliares (§18) para verificação localizada, mas essas nunca definem
//! a identidade do segmento.
//!
//! # Regra das folhas ímpares
//!
//! Definida **uma vez** e testada com vectores golden: um nível com número
//! ímpar de nós **promove** o último sem par para o nível seguinte, em vez de o
//! duplicar. Duplicar é o padrão que dá a ambiguidade estilo CVE-2012-2459
//! (duas listas de folhas diferentes com a mesma raiz).
//!
//! A promoção sozinha ainda deixaria ambiguidade entre certas contagens, por
//! isso a raiz final sela também o número de folhas:
//!
//! ```text
//! root = BLAKE3("HRKL6:MERKLE:ROOT" || leaf_count u64 LE || accumulator)
//! ```
//!
//! Com a contagem lá dentro, duas sequências de comprimentos diferentes não
//! podem partilhar raiz, e o segmento vazio tem uma raiz bem definida em vez de
//! um caso especial.
//!
//! # Memória
//!
//! O acumulador é um contador binário de 64 níveis: `O(log N)` de estado, sem
//! nunca ter as folhas todas em RAM. Um segmento de 20M registos custa 64
//! entradas de 32 bytes.

pub const DOMAIN_LEAF: &[u8] = b"HRKL6:MERKLE:LEAF";
pub const DOMAIN_NODE: &[u8] = b"HRKL6:MERKLE:NODE";
pub const DOMAIN_ROOT: &[u8] = b"HRKL6:MERKLE:ROOT";

/// 64 níveis chegam para 2^64 folhas.
const MAX_LEVELS: usize = 64;

/// `BLAKE3("HRKL6:MERKLE:LEAF" || canonical_record_hash)`.
#[inline]
pub fn merkle_leaf(canonical_record_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_LEAF);
    h.update(canonical_record_hash);
    *h.finalize().as_bytes()
}

/// `BLAKE3("HRKL6:MERKLE:NODE" || left || right)`.
#[inline]
pub fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_NODE);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

#[inline]
fn seal_root(leaf_count: u64, acc: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_ROOT);
    h.update(&leaf_count.to_le_bytes());
    h.update(acc);
    *h.finalize().as_bytes()
}

/// Acumulador determinístico e streaming da raiz lógica de um segmento.
#[derive(Clone)]
pub struct MerkleAccumulatorV1 {
    /// `levels[i]` guarda a sub-árvore pendente de altura `i`, se houver.
    levels: [Option<[u8; 32]>; MAX_LEVELS],
    leaf_count: u64,
}

impl Default for MerkleAccumulatorV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleAccumulatorV1 {
    pub fn new() -> Self {
        Self {
            levels: [None; MAX_LEVELS],
            leaf_count: 0,
        }
    }

    /// Absorve a folha correspondente a um `canonical_record_hash`.
    ///
    /// **A ordem é a ordem por LSN**; quem chama é responsável por respeitá-la
    /// (o writer e o packer fazem-no por construção, porque percorrem o
    /// segmento sequencialmente).
    pub fn push_record_hash(&mut self, canonical_record_hash: &[u8; 32]) {
        self.push_leaf(merkle_leaf(canonical_record_hash));
    }

    /// Absorve uma folha já preparada. Só para quem cacheia folhas.
    pub fn push_leaf(&mut self, leaf: [u8; 32]) {
        let mut carry = leaf;
        let mut level = 0usize;
        while let Some(pending) = self.levels[level].take() {
            carry = merkle_node(&pending, &carry);
            level += 1;
            debug_assert!(level < MAX_LEVELS, "mais de 2^64 folhas é impossível");
        }
        self.levels[level] = Some(carry);
        self.leaf_count += 1;
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Fecha a árvore e devolve a `segment_logical_root`.
    ///
    /// Consome por valor: uma raiz é um facto, não um estado intermédio que se
    /// espreita a meio da escrita.
    pub fn finalize(self) -> [u8; 32] {
        let mut carry: Option<[u8; 32]> = None;
        for node in self.levels.iter().flatten() {
            carry = Some(match carry {
                // O pendente é sempre a sub-árvore ESQUERDA (chegou antes);
                // o carry acumulado é o lado direito.
                Some(right) => merkle_node(node, &right),
                None => *node,
            });
        }
        seal_root(self.leaf_count, &carry.unwrap_or([0u8; 32]))
    }

    /// Raiz sem consumir — para o `inspect` e para o packer confirmar a meio.
    pub fn peek_root(&self) -> [u8; 32] {
        self.clone().finalize()
    }
}

/// Raiz de uma lista completa de hashes canónicos. Referência simples usada
/// pelos testes e pelo `verify --logical` de segmentos pequenos.
pub fn root_of_record_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = MerkleAccumulatorV1::new();
    for h in hashes {
        acc.push_record_hash(h);
    }
    acc.finalize()
}

// ---------------------------------------------------------------------------
// Provas de inclusão (SPEC-0050 §122 — `heraclitus prove --lsn X`)
// ---------------------------------------------------------------------------

/// Um passo da prova: o irmão e o lado em que ele está.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    /// `true` se o irmão é o nó da ESQUERDA (ou seja, nós somos o direito).
    pub sibling_is_left: bool,
}

/// Prova de inclusão de uma folha numa `segment_logical_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub path: Vec<ProofStep>,
}

/// Constrói a prova de inclusão de `index` a partir da lista completa de
/// hashes canónicos.
///
/// Requer as folhas todas — é a operação pericial, não o caminho quente. Um
/// segmento cabe em memória como 32 bytes/registo (20M registos = 640 MiB);
/// para segmentos maiores a prova far-se-á em duas passagens sobre o ficheiro.
pub fn build_inclusion_proof(hashes: &[[u8; 32]], index: usize) -> Option<InclusionProof> {
    if index >= hashes.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = hashes.iter().map(merkle_leaf).collect();
    let mut idx = index;
    let mut path = Vec::new();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            if idx == i {
                path.push(ProofStep {
                    sibling: level[i + 1],
                    sibling_is_left: false,
                });
                idx = next.len();
            } else if idx == i + 1 {
                path.push(ProofStep {
                    sibling: level[i],
                    sibling_is_left: true,
                });
                idx = next.len();
            }
            next.push(merkle_node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            // Promoção do ímpar: sobe sem par e sem entrada na prova.
            if idx == i {
                idx = next.len();
            }
            next.push(level[i]);
        }
        level = next;
    }

    Some(InclusionProof {
        leaf_index: index as u64,
        leaf_count: hashes.len() as u64,
        path,
    })
}

/// Verifica que `canonical_record_hash` está em `root` sob `proof`.
pub fn verify_inclusion_proof(
    canonical_record_hash: &[u8; 32],
    proof: &InclusionProof,
    root: &[u8; 32],
) -> bool {
    let mut acc = merkle_leaf(canonical_record_hash);
    for step in &proof.path {
        acc = if step.sibling_is_left {
            merkle_node(&step.sibling, &acc)
        } else {
            merkle_node(&acc, &step.sibling)
        };
    }
    seal_root(proof.leaf_count, &acc) == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = i;
        x
    }

    #[test]
    fn vazio_tem_raiz_definida_e_estavel() {
        let a = MerkleAccumulatorV1::new().finalize();
        let b = MerkleAccumulatorV1::new().finalize();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn raiz_depende_da_ordem() {
        let a = root_of_record_hashes(&[h(1), h(2)]);
        let b = root_of_record_hashes(&[h(2), h(1)]);
        assert_ne!(a, b);
    }

    #[test]
    fn contagem_diferente_nunca_colide() {
        // O caso clássico: [a] vs [a, a] com duplicação de ímpares daria a
        // mesma raiz. Com promoção + leaf_count selado, não dá.
        assert_ne!(
            root_of_record_hashes(&[h(1)]),
            root_of_record_hashes(&[h(1), h(1)])
        );
        assert_ne!(
            root_of_record_hashes(&[h(1), h(2), h(3)]),
            root_of_record_hashes(&[h(1), h(2), h(3), h(3)])
        );
    }

    #[test]
    fn streaming_bate_com_o_lote_em_todos_os_tamanhos() {
        for n in 0..=257usize {
            let hs: Vec<[u8; 32]> = (0..n).map(|i| h((i % 251) as u8 + 1)).collect();
            let mut acc = MerkleAccumulatorV1::new();
            for x in &hs {
                acc.push_record_hash(x);
            }
            assert_eq!(acc.leaf_count(), n as u64);
            assert_eq!(
                acc.finalize(),
                root_of_record_hashes(&hs),
                "divergiu com n={n}"
            );
        }
    }

    #[test]
    fn peek_nao_altera_o_acumulador() {
        let mut acc = MerkleAccumulatorV1::new();
        for i in 0..5u8 {
            acc.push_record_hash(&h(i + 1));
        }
        let p1 = acc.peek_root();
        let p2 = acc.peek_root();
        assert_eq!(p1, p2);
        assert_eq!(p1, acc.finalize());
    }

    #[test]
    fn provas_de_inclusao_fecham_para_qualquer_indice() {
        for n in 1..=40usize {
            let hs: Vec<[u8; 32]> = (0..n).map(|i| h(i as u8 + 1)).collect();
            let root = root_of_record_hashes(&hs);
            for i in 0..n {
                let proof = build_inclusion_proof(&hs, i).unwrap();
                assert!(verify_inclusion_proof(&hs[i], &proof, &root), "n={n} i={i}");
                // Uma folha errada não pode fechar na mesma prova.
                let errada = h(200);
                assert!(
                    !verify_inclusion_proof(&errada, &proof, &root),
                    "n={n} i={i} aceitou folha errada"
                );
            }
        }
        assert!(build_inclusion_proof(&[h(1)], 1).is_none());
    }

    #[test]
    fn prova_adulterada_nao_fecha() {
        let hs: Vec<[u8; 32]> = (0..9).map(|i| h(i as u8 + 1)).collect();
        let root = root_of_record_hashes(&hs);
        let mut proof = build_inclusion_proof(&hs, 3).unwrap();
        assert!(verify_inclusion_proof(&hs[3], &proof, &root));
        proof.leaf_count += 1;
        assert!(!verify_inclusion_proof(&hs[3], &proof, &root));
    }
}
