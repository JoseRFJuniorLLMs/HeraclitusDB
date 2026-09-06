//! heraclitus-index-vector — in-crate HNSW (§3.6).
//!
//! We deliberately do NOT depend on an external HNSW crate: the metric is a
//! custom product-manifold distance and we need RoaringBitmap filter
//! push-down. The index is derived state: losing it means replay, not data
//! loss.

pub mod gate;

use heraclitus_core::{Episode, EventId, HeraclitusError, Lsn, ProductPoint};
use heraclitus_manifold::{PreparedPoint, PreparedQuery, ProductMetric, Signature};
use heraclitus_views::View;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::path::Path;

const DEFAULT_M: usize = 16;
const DEFAULT_EF_CONSTRUCTION: usize = 200;

/// Intervalos aceitáveis para os parâmetros do HNSW quando eles vêm de um
/// ficheiro (auditoria 2026-09-05, A26).
///
/// `m` não é um número decorativo: é o divisor logarítmico de `random_level`
/// e a régua de truncagem da poda de vizinhos. `m = 0` transforma
/// `truncate(self.m * 2)` em `truncate(0)` — apaga a lista de adjacência de
/// cada vizinho ligado, e o grafo erode em silêncio; `m = 1` faz
/// `1/ln(1) = +inf`, o nível sorteado satura em `usize::MAX` e `level + 1`
/// transborda. O tecto existe pela mesma razão que o chão: `m` grande faz
/// `vec![Vec::new(); level + 1]` alocar sem relação com o corpus.
const M_MIN: usize = 2;
const M_MAX: usize = 1024;
/// `ef_construction = 0` não panica (`search_layer` só devolve ~nada), mas
/// constrói um grafo sem arestas úteis — degradação silenciosa de recall.
const EF_CONSTRUCTION_MIN: usize = 1;
const EF_CONSTRUCTION_MAX: usize = 65_536;

#[derive(Clone, Serialize, Deserialize)]
struct Node {
    point: ProductPoint,
    /// Cache derivado das normas do ponto residente. `serde(skip)` e
    /// intencional: mantem o formato binario de `vector.ckpt` identico ao
    /// anterior e permite abrir checkpoints existentes. O cache e reconstruido
    /// depois do decode, sob a assinatura restaurada.
    #[serde(skip)]
    prepared: PreparedPoint,
    level: usize,
    /// neighbors[level] = ids
    neighbors: Vec<Vec<u32>>,
}

/// Min-ordering helper for the search heaps.
#[derive(PartialEq)]
struct Candidate {
    dist: f64,
    id: u32,
}
/// Conjunto de nós já visitados numa travessia, por marcas de época.
///
/// # Porque não um `HashSet<u32>`
///
/// A versão anterior criava um `HashSet<u32>` por chamada a `search_layer`, e
/// `search_layer` é chamada uma vez por nível em cada busca e em cada inserção.
/// Cada `insert` no conjunto é um hash mais uma sondagem, e o conjunto inteiro é
/// alocado e destruído a cada camada — num índice grande, com `ef` alto, isso é
/// a operação mais repetida do caminho quente.
///
/// Aqui a pertença é um `u32` por nó num vector contíguo: a verificação é uma
/// leitura indexada e a inserção é uma escrita. Limpar entre travessias não
/// custa nada — incrementa-se a época, e todas as marcas antigas passam a ser
/// automaticamente diferentes da actual.
///
/// # O transbordo da época, que é o único caso subtil
///
/// A época é um `u32`. Depois de 2³²−1 travessias na mesma thread ela volta a
/// zero, e uma marca antiga voltaria a coincidir com a época actual — um nó
/// nunca visitado apareceria como visitado, e a busca saltava-o. Por isso, ao
/// dar a volta, o vector é limpo uma vez. É O(n) uma vez em quatro mil milhões
/// de travessias.
#[derive(Debug, Default)]
struct Visitados {
    marcas: Vec<u32>,
    epoca: u32,
}

impl Visitados {
    /// Prepara para uma travessia nova sobre `n` nós.
    fn preparar(&mut self, n: usize) {
        if self.marcas.len() < n {
            self.marcas.resize(n, 0);
        }
        self.epoca = self.epoca.wrapping_add(1);
        if self.epoca == 0 {
            // Deu a volta: uma marca antiga a zero seria confundida com a época
            // actual. Limpa-se, e recomeça-se em 1 para que zero continue a
            // significar "nunca marcado".
            self.marcas.iter_mut().for_each(|m| *m = 0);
            self.epoca = 1;
        }
    }

    /// `true` se o nó é NOVO nesta travessia — mesma semântica de
    /// `HashSet::insert`.
    #[inline]
    fn marcar(&mut self, id: u32) -> bool {
        let i = id as usize;
        // Um id fora do intervalo tinha, na versão anterior, de rebentar mais à
        // frente em `self.nodes[id]`. Devolver `true` mantém exactamente esse
        // percurso em vez de introduzir aqui um sítio de pânico novo.
        match self.marcas.get_mut(i) {
            Some(m) if *m == self.epoca => false,
            Some(m) => {
                *m = self.epoca;
                true
            }
            None => true,
        }
    }
}

thread_local! {
    /// Scratch por thread: reutilizado entre travessias, sem contenção e sem
    /// alocação por chamada.
    ///
    /// `search_layer` não é reentrante — `search` e `insert` chamam-na em ciclo
    /// sobre os níveis, uma de cada vez, nunca uma dentro da outra — pelo que
    /// manter o empréstimo durante a travessia é seguro. Se alguém a tornar
    /// reentrante, o `borrow_mut` rebenta alto em vez de corromper resultados
    /// em silêncio, que é a falha certa a ter.
    static VISITADOS: std::cell::RefCell<Visitados> =
        const { std::cell::RefCell::new(Visitados { marcas: Vec::new(), epoca: 0 }) };
}

#[cfg(test)]
thread_local! {
    /// Instrumentacao de testes para provar que a descida dos niveis
    /// superiores nao passa silenciosamente pelo algoritmo geral.
    static SEARCH_LAYER_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static GREEDY_DESCENT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Contador de avaliacoes da metrica. Serve para provar que a poda de
    /// vizinhos calcula a distancia UMA vez por vizinho e nao uma vez por
    /// comparacao do `sort` (auditoria 2026-09-05, A27).
    static DIST2_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Eq for Candidate {}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.dist.total_cmp(&self.dist) // reversed: BinaryHeap becomes min-heap
    }
}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct VectorIndex {
    metric: ProductMetric,
    m: usize,
    ef_construction: usize,
    nodes: Vec<Node>,
    entry: Option<u32>,
    by_event: HashMap<EventId, u32>,
    ids: Vec<EventId>,
    lsns: Vec<Lsn>,
    watermark: Lsn,
    rng: StdRng,
    /// Tombstones semânticos (padrão Qdrant): ids internos "retirados" ficam
    /// FORA dos resultados sem reconstruir o grafo — o nó continua traversável
    /// para preservar a conectividade do HNSW. Nada é apagado do log: um
    /// tombstone é ele próprio um evento (`attrs.tombstone_of = <event_id>`).
    tombstones: RoaringBitmap,
}

#[derive(Debug, Clone)]
pub struct VectorHit {
    pub id: EventId,
    pub lsn: Lsn,
    pub dist: f32,
}

/// Estado serializável do índice (#12 — checkpoint/restore para boot rápido).
/// `by_event` reconstrói-se de `ids`; `rng` fica no seed determinístico (só
/// afeta os níveis de inserções FUTURAS, não o estado restaurado).
#[derive(Serialize, Deserialize)]
struct VectorSnapshot {
    m: usize,
    ef_construction: usize,
    nodes: Vec<Node>,
    entry: Option<u32>,
    ids: Vec<EventId>,
    lsns: Vec<Lsn>,
    watermark: Lsn,
    sig: Signature,
    tombstones: Vec<u32>,
}

const VECTOR_CKPT_FILE: &str = "vector.ckpt";

impl VectorIndex {
    pub fn new(metric: ProductMetric) -> Self {
        Self {
            metric,
            m: DEFAULT_M,
            ef_construction: DEFAULT_EF_CONSTRUCTION,
            nodes: Vec::new(),
            entry: None,
            by_event: HashMap::new(),
            ids: Vec::new(),
            lsns: Vec::new(),
            watermark: 0,
            // Determinism requirement (§3.5): RNG seeded from a constant; the
            // level sequence is then a pure function of insertion order.
            rng: StdRng::seed_from_u64(0x48524B4C),
            tombstones: RoaringBitmap::new(),
        }
    }

    /// Marca o vetor de `event` como retirado (tombstone semântico). Devolve
    /// `true` se o evento estava indexado. Idempotente.
    pub fn tombstone_event(&mut self, event: &EventId) -> bool {
        match self.by_event.get(event) {
            Some(&id) => {
                self.tombstones.insert(id);
                true
            }
            None => false,
        }
    }

    pub fn is_tombstoned(&self, internal: u32) -> bool {
        self.tombstones.contains(internal)
    }

    /// Nº de vetores retirados — alimenta o trigger de compaction (delta ratio).
    pub fn tombstone_count(&self) -> u64 {
        self.tombstones.len()
    }

    /// Distância AO QUADRADO do nó `a` à consulta preparada.
    fn dist2(&self, a: u32, q: &PreparedQuery) -> f64 {
        #[cfg(test)]
        DIST2_CALLS.with(|calls| calls.set(calls.get() + 1));
        let node = &self.nodes[a as usize];
        q.dist2_prepared(&node.point, &node.prepared)
    }

    fn random_level(&mut self) -> usize {
        // `1/ln(m)` só está definido para `m >= 2`: `ln(1) = 0` dá `+inf`, e
        // `(+inf).floor() as usize` satura em `usize::MAX` (o cast float->int é
        // saturante desde Rust 1.45), pelo que o `vec![Vec::new(); level + 1]`
        // de `insert` transbordava — pânico com `overflow-checks = true`.
        // `ln(0) = -inf` dá `-0.0` e prende todos os nós no nível 0.
        // `load_checkpoint` já recusa `m` fora de `M_MIN..=M_MAX`; esta guarda
        // é a segunda linha, para que a função seja TOTAL e nenhum caminho
        // futuro a possa fazer panicar (auditoria 2026-09-05, A26).
        let ml = if self.m >= M_MIN {
            1.0 / (self.m as f64).ln()
        } else {
            1.0
        };
        let r: f64 = self.rng.gen_range(f64::MIN_POSITIVE..1.0);
        ((-r.ln()) * ml).floor() as usize
    }

    /// Greedy search at one level, returning up to `ef` nearest candidates.
    ///
    /// Filter push-down (audit02 #3): traversal explores the whole reachable
    /// graph for connectivity, but only `filter`-passing nodes are admitted to
    /// `results`. So a selective filter keeps expanding until it has `ef`
    /// filtered hits (or the reachable set is exhausted) instead of returning
    /// fewer than `k` after a post-hoc filter. `filter = None` is identical to
    /// the unfiltered behavior.
    /// `query` chega já preparado: as constantes da curvatura e as normas da
    /// consulta são calculadas UMA vez por busca, não uma vez por candidato.
    /// A ordenação usa a distância ao QUADRADO — a raiz é monótona, portanto a
    /// ordem é a mesma, e quem precisa do valor tira-a no fim sobre os `k`
    /// resultados em vez de sobre todos os candidatos visitados.
    fn search_layer(
        &self,
        query: &PreparedQuery,
        entry: u32,
        level: usize,
        ef: usize,
        filter: Option<&RoaringBitmap>,
    ) -> Vec<Candidate> {
        #[cfg(test)]
        SEARCH_LAYER_CALLS.with(|calls| calls.set(calls.get() + 1));
        // Tombstones nunca entram nos RESULTADOS mas continuam a ser
        // atravessados (visited/candidates) — remover nós do grafo partiria a
        // conectividade; excluí-los só da seleção preserva o recall.
        let passes = |id: u32| {
            !self.tombstones.contains(id) && filter.map(|f| f.contains(id)).unwrap_or(true)
        };
        let d0 = self.dist2(entry, query);
        // `candidates` drives traversal over every reachable node; `results`
        // keeps only filter-passing nodes (the ones we may return).
        let mut candidates = BinaryHeap::from([Candidate {
            dist: d0,
            id: entry,
        }]);
        // `results` como MAX-heap (via Reverse): o pior (maior dist) é o topo, então
        // consultar/descartar o pior é O(1)/O(log ef) em vez do fold O(ef) por
        // vizinho visitado. Semântica de seleção idêntica à versão em Vec.
        let mut results: BinaryHeap<Reverse<Candidate>> = BinaryHeap::new();
        if passes(entry) {
            results.push(Reverse(Candidate {
                dist: d0,
                id: entry,
            }));
        }

        VISITADOS.with(|v| {
            let mut visitados = v.borrow_mut();
            visitados.preparar(self.nodes.len());
            visitados.marcar(entry);
            while let Some(c) = candidates.pop() {
                let worst = results.peek().map(|r| r.0.dist).unwrap_or(f64::MIN);
                // Stop only once we have ef filtered hits AND cannot improve them.
                if results.len() >= ef && c.dist > worst {
                    break;
                }
                for &n in &self.nodes[c.id as usize].neighbors
                    [level.min(self.nodes[c.id as usize].neighbors.len() - 1)]
                {
                    if visitados.marcar(n) {
                        let d = self.dist2(n, query);
                        let worst = results.peek().map(|r| r.0.dist).unwrap_or(f64::MIN);
                        // Keep exploring while we still need filtered hits, or while
                        // n could improve the current frontier.
                        if results.len() < ef || d < worst {
                            candidates.push(Candidate { dist: d, id: n });
                            if passes(n) {
                                results.push(Reverse(Candidate { dist: d, id: n }));
                                if results.len() > ef {
                                    results.pop(); // drop the worst (largest dist) filtered result
                                }
                            }
                        }
                    }
                }
            }
        });
        let mut out: Vec<Candidate> = results.into_iter().map(|r| r.0).collect();
        out.sort_by(|a, b| a.dist.total_cmp(&b.dist));
        out
    }

    /// Descida HNSW especializada para os niveis superiores (`ef = 1`).
    ///
    /// A busca geral precisa de dois heaps e de uma ordenacao final porque
    /// preserva ate `ef` alternativas. Nos niveis acima de zero queremos apenas
    /// o melhor ponto de entrada para a camada seguinte: percorremos os
    /// vizinhos do atual, movemos para o melhor que o melhora estritamente e
    /// repetimos ate atingir um minimo local. As marcas de epoca ja existentes
    /// sao reutilizadas apenas para nao recalcular um vizinho visto por dois
    /// nos consecutivos; nao ha `HashSet` nem alocacao por chamada.
    ///
    /// Nao ha filtro aqui por desenho. Camadas superiores sao apenas rotas;
    /// tombstones continuam atravessaveis e o bitmap/tombstone e aplicado pelo
    /// `search_layer` completo na camada zero. A comparacao estrita (`<`) e a
    /// ordem dos vizinhos preservam o desempate deterministico do antigo
    /// `search_layer(ef=1)`.
    fn search_layer_greedy(&self, query: &PreparedQuery, entry: u32, level: usize) -> Candidate {
        #[cfg(test)]
        GREEDY_DESCENT_CALLS.with(|calls| calls.set(calls.get() + 1));

        VISITADOS.with(|visited| {
            let mut visited = visited.borrow_mut();
            visited.preparar(self.nodes.len());
            visited.marcar(entry);
            let mut current = Candidate {
                dist: self.dist2(entry, query),
                id: entry,
            };
            loop {
                let node = &self.nodes[current.id as usize];
                let layer = level.min(node.neighbors.len() - 1);
                let mut best_id = current.id;
                let mut best_dist = current.dist;
                for &neighbor in &node.neighbors[layer] {
                    if !visited.marcar(neighbor) {
                        continue;
                    }
                    let dist = self.dist2(neighbor, query);
                    if dist < best_dist {
                        best_id = neighbor;
                        best_dist = dist;
                    }
                }
                if best_id == current.id {
                    return current;
                }
                current = Candidate {
                    dist: best_dist,
                    id: best_id,
                };
            }
        })
    }

    /// Poda a lista de adjacência do nó `n` no nível `l`, guardando os
    /// `m * 2` vizinhos mais próximos de `n`.
    ///
    /// # Porque a chave é calculada ANTES de ordenar
    ///
    /// A versão anterior chamava `self.dist2(...)` dentro do comparador do
    /// `sort_by`, ou seja DUAS avaliações da métrica por comparação: com os
    /// 33 elementos do caso típico (`DEFAULT_M = 16`, poda em `m * 2 + 1`)
    /// isso media-se em 510 avaliações onde 33 bastavam. E não é trabalho
    /// barato — cada `dist2` percorre os vectores em f64 e paga um `acosh`
    /// (`PreparedQuery::dist2_prepared`); o `PreparedPoint` residente só
    /// poupa as normas, nunca o produto interno. Isto está no caminho quente
    /// de escrita (`View::apply` -> `insert`, uma vez por episódio com
    /// embedding) e repete-se para cada um dos até `m` vizinhos ligados, em
    /// cada nível (auditoria 2026-09-05, A27).
    ///
    /// A ordenação continua ESTÁVEL e sem critério de desempate novo: `dist2`
    /// é uma função pura do par (nó, consulta), portanto ordenar pelas mesmas
    /// chaves dá exactamente a mesma lista. Um desempate por id — ou um
    /// `select_nth_unstable_by`, que é uma partição instável — mudaria qual
    /// dos empatados sobrevive ao `truncate`, e com ele o grafo, o resultado
    /// das buscas e o checkpoint: uma alteração de semântica disfarçada de
    /// optimização.
    fn podar_vizinhos(&mut self, n: u32, l: usize) {
        let np = PreparedQuery::new(&self.metric, &self.nodes[n as usize].point);
        // `mem::take` liberta o empréstimo mutável de `self.nodes` antes de
        // chamar `self.dist2`, que empresta `&self`.
        let nb = std::mem::take(&mut self.nodes[n as usize].neighbors[l]);
        let mut decorados: Vec<(f64, u32)> =
            nb.into_iter().map(|v| (self.dist2(v, &np), v)).collect();
        decorados.sort_by(|a, b| a.0.total_cmp(&b.0));
        decorados.truncate(self.m * 2);
        self.nodes[n as usize].neighbors[l] = decorados.into_iter().map(|(_, v)| v).collect();
    }

    pub fn insert(&mut self, event_id: EventId, lsn: Lsn, point: ProductPoint) {
        if self.by_event.contains_key(&event_id) {
            return; // idempotent replay
        }
        let id = self.nodes.len() as u32;
        let level = self.random_level();
        // A consulta e as normas residentes sao preparadas antes de mover o
        // ponto para o no. Assim nao precisamos do clone integral que existia
        // apenas para voltar a consultar o ponto durante a ligacao HNSW.
        let pq = PreparedQuery::new(&self.metric, &point);
        let prepared = PreparedPoint::new(&self.metric, &point);
        // The node is inserted (with empty adjacency) BEFORE any back-links
        // are created: a search during connection may already traverse it.
        self.nodes.push(Node {
            point,
            prepared,
            level,
            neighbors: vec![Vec::new(); level + 1],
        });
        self.by_event.insert(event_id, id);
        self.ids.push(event_id);
        self.lsns.push(lsn);
        let old_entry = self.entry;
        if let Some(mut ep) = old_entry {
            let top = self.nodes[ep as usize].level;
            // descend greedily above the new node's level
            for l in ((level + 1)..=top).rev() {
                ep = self
                    .search_layer_greedy(&pq, ep, l.min(self.nodes[ep as usize].level))
                    .id;
            }
            // connect at each level from min(level, top) down to 0
            for l in (0..=level.min(top)).rev() {
                let neighbors = self.search_layer(&pq, ep, l, self.ef_construction, None);
                let mut selected: Vec<u32> = neighbors
                    .iter()
                    .filter(|c| c.id != id)
                    .take(self.m)
                    .map(|c| c.id)
                    .collect::<Vec<u32>>();
                // ÓRFÃO: `search_layer` nunca devolve tombstoned nos resultados.
                // Se TODOS os nós alcançáveis a partir do entry estão
                // tombstoned, `selected` fica vazio — e sem back-links o nó novo
                // fica sem UMA aresta sequer, inalcançável em qualquer busca
                // futura (uma inserção que se perde a si própria). Ligar ao
                // `ep` garante a entrada no grafo: o `ep` é alcançável a partir
                // da raiz por construção, e os tombstoned CONTINUAM a ser
                // atravessados na busca (só não entram nos resultados), portanto
                // um back-link através dele preserva a conectividade.
                if selected.is_empty() && ep != id {
                    selected.push(ep);
                }
                for &n in &selected {
                    let nl = self.nodes[n as usize].neighbors.len();
                    if l < nl {
                        self.nodes[n as usize].neighbors[l].push(id);
                        if self.nodes[n as usize].neighbors[l].len() > self.m * 2 {
                            self.podar_vizinhos(n, l);
                        }
                    }
                }
                self.nodes[id as usize].neighbors[l] = selected;
                if let Some(n0) = neighbors.first() {
                    ep = n0.id;
                }
            }
            if level > top {
                self.entry = Some(id);
            }
        } else {
            self.entry = Some(id);
        }
    }

    /// Search top-k. `filter`: only internal ids present in the bitmap are
    /// returned (push-down happens during result selection). Results carry
    /// the LSN they are valid at.
    pub fn search(
        &self,
        query: &ProductPoint,
        k: usize,
        ef: usize,
        filter: Option<&RoaringBitmap>,
    ) -> Vec<VectorHit> {
        let Some(mut ep) = self.entry else {
            return Vec::new();
        };
        // UMA vez por busca, não uma vez por candidato.
        let pq = PreparedQuery::new(&self.metric, query);
        let top = self.nodes[ep as usize].level;
        // Entry-point descent ignores the filter (we want the best entry into
        // level 0 regardless); the filter is pushed down only at level 0.
        for l in (1..=top).rev() {
            ep = self.search_layer_greedy(&pq, ep, l).id;
        }
        let ef = ef.max(k);
        let candidates =
            self.search_layer(&pq, ep, 0, ef.max(self.ef_construction.min(64)), filter);
        candidates
            .into_iter()
            .take(k)
            .map(|c| VectorHit {
                id: self.ids[c.id as usize],
                lsn: self.lsns[c.id as usize],
                // `c.dist` e a distancia AO QUADRADO — a travessia ordena por
                // ela porque a raiz e monotona. A raiz e tirada aqui, sobre os
                // `k` resultados, e nao sobre os milhares de candidatos.
                dist: (c.dist.max(0.0)).sqrt() as f32,
            })
            .collect()
    }

    /// Exact Top-k by brute-force over ALL points, accelerated by the GPU when
    /// available (M20.3.1b2). The GPU computes the batch product-manifold
    /// distance (RECALL, ≥30× oversample) via `heraclitus_gpu::topm_product`; the
    /// CPU then rescores the candidates with the exact f64 [`ProductMetric`] and
    /// has the final say — so the result is the true nearest set regardless of
    /// GPU float precision. Without a GPU it falls back to a CPU brute-force.
    /// The approximate HNSW [`search`](Self::search) is never affected.
    pub fn search_exact_gpu(&self, query: &ProductPoint, k: usize) -> Vec<VectorHit> {
        if self.nodes.is_empty() || k == 0 {
            return Vec::new();
        }
        let (a, b, c) = (query.hyp.len(), query.sph.len(), query.euc.len());
        let dim = a + b + c;

        let mut qflat = Vec::with_capacity(dim);
        qflat.extend_from_slice(&query.hyp);
        qflat.extend_from_slice(&query.sph);
        qflat.extend_from_slice(&query.euc);

        let mut vflat = Vec::with_capacity(self.nodes.len() * dim);
        for node in &self.nodes {
            if node.point.hyp.len() != a || node.point.sph.len() != b || node.point.euc.len() != c {
                // Heterogeneous point layout — stay exact via the CPU metric.
                return self.rescore(query, 0..self.nodes.len(), k);
            }
            vflat.extend_from_slice(&node.point.hyp);
            vflat.extend_from_slice(&node.point.sph);
            vflat.extend_from_slice(&node.point.euc);
        }

        let sig = heraclitus_gpu::ProductSig {
            a,
            b,
            c,
            c1: (-self.metric.sig.k1) as f32,
            k2: self.metric.sig.k2 as f32,
            weights: [
                self.metric.sig.weights[0] as f32,
                self.metric.sig.weights[1] as f32,
                self.metric.sig.weights[2] as f32,
            ],
            ball_eps: heraclitus_manifold::BALL_EPS as f32,
        };

        // GPU RECALL with ≥30× oversample, then exact f64 CPU rescore (final say).
        let m = k.saturating_mul(30).min(self.nodes.len());
        let cands = heraclitus_gpu::topm_product(&qflat, &vflat, &sig, m, 1e6);
        self.rescore(query, cands.iter().map(|c| c.index as usize), k)
    }

    /// Rescore candidate internal ids with the exact f64 metric, take Top-k.
    /// Tombstones ficam fora do rescore (mesma semântica do search HNSW).
    fn rescore(
        &self,
        query: &ProductPoint,
        cand: impl Iterator<Item = usize>,
        k: usize,
    ) -> Vec<VectorHit> {
        let mut scored: Vec<(f64, usize)> = cand
            .filter(|i| !self.tombstones.contains(*i as u32))
            .map(|i| (self.metric.dist(query, &self.nodes[i].point), i))
            .collect();
        scored.sort_by(|x, y| x.0.total_cmp(&y.0));
        scored.truncate(k);
        scored
            .into_iter()
            .map(|(d, i)| VectorHit {
                id: self.ids[i],
                lsn: self.lsns[i],
                dist: d as f32,
            })
            .collect()
    }

    /// Internal id for an event (to build filter bitmaps).
    pub fn internal_id(&self, event: &EventId) -> Option<u32> {
        self.by_event.get(event).copied()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// #12 — Persiste o estado completo do HNSW (`<dir>/vector.ckpt`) com escrita
    /// atómica (tmp + rename). Correção nunca depende disto: sem checkpoint, a
    /// view reconstrói-se do LSN 0 (ver `heraclitus_views`).
    pub fn save_checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        let snap = VectorSnapshot {
            m: self.m,
            ef_construction: self.ef_construction,
            nodes: self.nodes.clone(),
            entry: self.entry,
            ids: self.ids.clone(),
            lsns: self.lsns.clone(),
            watermark: self.watermark,
            sig: self.metric.sig.clone(),
            tombstones: self.tombstones.iter().collect(),
        };
        let bytes = bincode::serde::encode_to_vec(&snap, bincode::config::standard())
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let tmp = dir.join("vector.ckpt.tmp");
        // fsync ANTES do rename (alinhado com views::ckpt::save): sem ele, um
        // crash pós-rename podia deixar um ficheiro vazio/parcial — degradava
        // com segurança para rebuild, mas custava o boot inteiro.
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(VECTOR_CKPT_FILE))?;
        Ok(())
    }

    /// #12 — Restaura o HNSW do checkpoint. Devolve `false` se não houver
    /// ficheiro OU se ele não descodificar (formato antigo/corrompido) — a
    /// view fica vazia e o registry força replay desde 0. Um checkpoint
    /// ilegível NUNCA pode impedir o boot: o estado é derivado, o log é a verdade.
    pub fn load_checkpoint(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
        let bytes = match std::fs::read(dir.join(VECTOR_CKPT_FILE)) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        let Ok((snap, _)) = bincode::serde::decode_from_slice::<VectorSnapshot, _>(
            &bytes,
            bincode::config::standard(),
        ) else {
            return Ok(false);
        };
        // Invariante estrutural do HNSW: todo nó tem `level + 1` camadas de
        // vizinhos (nunca vazio — `search_layer` indexa `neighbors[..len()-1]`
        // e um vec vazio dava underflow/panic em TODA pesquisa futura). Um
        // checkpoint decodável mas violado degrada para rebuild do log (I6),
        // nunca para um índice que panica.
        let n_nodes = snap.nodes.len();
        let coherent =
            // Os PARÂMETROS também vêm do ficheiro e também têm de ser
            // validados (auditoria 2026-09-05, A26). `m` é adoptado sem filtro
            // logo abaixo e passa a ser o divisor de `ln` em `random_level` e a
            // régua de `truncate(self.m * 2)` na poda: `m = 0` apaga as listas
            // de adjacência a cada inserção (perda de recall TOTAL e silenciosa)
            // e `m = 1` faz o nível saturar em `usize::MAX` e `level + 1`
            // transbordar na primeira inserção pós-restore. O ficheiro não tem
            // magic nem CRC e `m` é o primeiro campo, um varint de um byte para
            // 16 — uma troca de bit continua a descodificar. Nenhum checkpoint
            // escrito por este código sai destes intervalos (DEFAULT_M = 16,
            // DEFAULT_EF_CONSTRUCTION = 200), portanto isto só recusa ficheiros
            // que já eram venenosos.
            (M_MIN..=M_MAX).contains(&snap.m)
            && (EF_CONSTRUCTION_MIN..=EF_CONSTRUCTION_MAX).contains(&snap.ef_construction)
            && n_nodes == snap.ids.len()
            && n_nodes == snap.lsns.len()
            // A comparação é feita do lado do COMPRIMENTO, nunca somando sobre
            // `level` (auditoria 2026-09-05, A51). `level` é um varint sem
            // tecto lido do ficheiro: com `usize::MAX`, o `level + 1` que aqui
            // estava transbordava e o próprio guarda anti-pânico entrava em
            // pânico — dentro de `load_checkpoint`, ou seja no boot, por causa
            // de um ficheiro puramente derivado. `checked_sub` sobre
            // `neighbors.len()` (esse sim, o comprimento real de um Vec já
            // alocado) devolve `None` para o vec vazio, pelo que subsume também
            // a defesa do `!is_empty()` que aqui estava.
            && snap
                .nodes
                .iter()
                .all(|n| n.neighbors.len().checked_sub(1) == Some(n.level))
            && snap
                .entry
                .map(|e| (e as usize) < n_nodes)
                .unwrap_or(true)
            // Cada id de vizinho, em TODAS as camadas, tem de existir. Um id
            // fora de `nodes.len()` decodifica sem erro e só rebenta depois, num
            // `self.nodes[vizinho]` fora de limites durante a pesquisa — pânico
            // que envenena o índice inteiro. Faltava esta parte da coerência.
            && snap
                .nodes
                .iter()
                .all(|n| n.neighbors.iter().flatten().all(|&v| (v as usize) < n_nodes));
        if !coherent {
            return Ok(false);
        }
        let metric = ProductMetric { sig: snap.sig };
        let mut nodes = snap.nodes;
        for node in &mut nodes {
            node.prepared = PreparedPoint::new(&metric, &node.point);
        }
        self.by_event = snap
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i as u32))
            .collect();
        self.m = snap.m;
        self.ef_construction = snap.ef_construction;
        self.nodes = nodes;
        self.entry = snap.entry;
        self.ids = snap.ids;
        self.lsns = snap.lsns;
        self.watermark = snap.watermark;
        self.metric = metric;
        self.tombstones = snap.tombstones.into_iter().collect();
        Ok(true)
    }
}

impl View for VectorIndex {
    fn name(&self) -> &str {
        "vector"
    }

    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        if let Some(emb) = &event.embedding {
            self.insert(event.id, lsn, emb.clone());
        }
        // Tombstone semântico como EVENTO (nada se apaga do log): um episódio
        // com `attrs.tombstone_of = <event_id>` retira o vetor alvo dos
        // resultados. Replay-determinístico como qualquer outra derivação.
        if let Some(target) = event.attrs.get("tombstone_of") {
            if let Ok(id) = target.parse::<EventId>() {
                self.tombstone_event(&id);
            }
        }
        // Avanço-só (ver activation/text/attr): entrega fora de ordem não pode
        // regredir o watermark persistido no checkpoint.
        self.watermark = self.watermark.max(lsn);
    }

    fn watermark(&self) -> Lsn {
        self.watermark
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        self.save_checkpoint(dir)
    }

    fn restore(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
        self.load_checkpoint(dir)
    }

    fn reset(&mut self) {
        *self = VectorIndex::new(self.metric.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Espelho do formato de checkpoint anterior ao `PreparedPoint`. Mantido
    /// apenas no teste para provar que o novo cache nao mudou um unico campo no
    /// wire format.
    #[derive(Serialize, Deserialize)]
    struct LegacyNode {
        point: ProductPoint,
        level: usize,
        neighbors: Vec<Vec<u32>>,
    }

    #[derive(Serialize, Deserialize)]
    struct LegacyVectorSnapshot {
        m: usize,
        ef_construction: usize,
        nodes: Vec<LegacyNode>,
        entry: Option<u32>,
        ids: Vec<EventId>,
        lsns: Vec<Lsn>,
        watermark: Lsn,
        sig: Signature,
        tombstones: Vec<u32>,
    }

    fn pt(hyp: Vec<f32>) -> ProductPoint {
        ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        }
    }

    #[test]
    fn finds_nearest_in_small_set() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..200 {
            let x = (i as f32) / 250.0;
            let id = EventId::new();
            ids.push(id);
            idx.insert(id, i as u64, pt(vec![x, 0.1]));
        }
        let hits = idx.search(&pt(vec![0.4, 0.1]), 5, 64, None);
        assert_eq!(hits.len(), 5);
        // exact nearest is i=100 (x=0.4)
        assert_eq!(hits[0].id, ids[100]);
    }

    #[test]
    fn filter_push_down() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut keep = RoaringBitmap::new();
        let mut kept_ids = Vec::new();
        for i in 0..100 {
            let id = EventId::new();
            idx.insert(id, i as u64, pt(vec![(i as f32) / 200.0, 0.0]));
            if i % 2 == 0 {
                keep.insert(idx.internal_id(&id).unwrap());
                kept_ids.push(id);
            }
        }
        let hits = idx.search(&pt(vec![0.25, 0.0]), 10, 128, Some(&keep));
        assert!(!hits.is_empty());
        for h in &hits {
            assert!(kept_ids.contains(&h.id), "filtered-out id leaked");
        }
    }

    #[test]
    fn filter_push_down_recall_under_high_selectivity() {
        // Regression (auditoria02 #3): with a highly selective filter (5% kept),
        // post-filtering an ef≈64 pool around the query returns fewer than k.
        // Push-down must keep expanding until it has k filtered hits.
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut keep = RoaringBitmap::new();
        let mut kept = Vec::new();
        for i in 0..500u64 {
            let id = EventId(ulid::Ulid::from_parts(i, i as u128));
            idx.insert(id, i, pt(vec![(i as f32) / 600.0, 0.02]));
            if i % 20 == 0 {
                keep.insert(idx.internal_id(&id).unwrap());
                kept.push(id);
            }
        }
        let hits = idx.search(&pt(vec![300.0 / 600.0, 0.02]), 5, 64, Some(&keep));
        assert_eq!(
            hits.len(),
            5,
            "push-down must return k even under a 5% filter"
        );
        for h in &hits {
            assert!(kept.contains(&h.id), "filtered-out id leaked");
        }
    }

    #[test]
    fn deterministic_replay() {
        let build = || {
            let mut idx = VectorIndex::new(ProductMetric::default());
            for i in 0..100u64 {
                let id = EventId(ulid::Ulid::from_parts(i, i as u128));
                idx.insert(id, i, pt(vec![(i as f32) / 150.0, 0.05]));
            }
            let hits = idx.search(&pt(vec![0.3, 0.05]), 10, 64, None);
            hits.iter().map(|h| h.id).collect::<Vec<_>>()
        };
        assert_eq!(build(), build(), "same input order must give same index");
    }

    /// M20.3.1b2 GATE: GPU-accelerated exact search must equal the f64
    /// brute-force ground truth over the *full* product metric (hyp+sph+euc).
    /// With `--features gpu` on real hardware this validates the wired GPU RECALL
    /// followed by CPU rescore; without it, the CPU fallback. Either way the HNSW
    /// `search()` is untouched.
    #[test]
    fn search_exact_gpu_matches_bruteforce() {
        let metric = ProductMetric::default();
        let mut idx = VectorIndex::new(metric.clone());
        // Well-separated product points: hyp, sph and euc all move with i.
        let mk = |i: usize| -> ProductPoint {
            let fi = i as f32;
            ProductPoint {
                hyp: vec![fi * 0.004, fi * 0.003],
                sph: vec![(fi * 0.02).cos(), (fi * 0.02).sin()],
                euc: vec![fi * 0.2, fi * 0.1],
            }
        };
        let mut ids = Vec::new();
        for i in 0..120usize {
            let id = EventId(ulid::Ulid::from_parts(i as u64, i as u128));
            ids.push(id);
            idx.insert(id, i as u64, mk(i));
        }
        let query = mk(0);
        let k = 8;

        // Ground truth: exact f64 brute-force with the REAL ProductMetric.
        let mut gt: Vec<(f64, usize)> =
            (0..120).map(|i| (metric.dist(&query, &mk(i)), i)).collect();
        gt.sort_by(|a, b| a.0.total_cmp(&b.0));
        let gt_ids: Vec<EventId> = gt.iter().take(k).map(|(_, i)| ids[*i]).collect();

        let got: Vec<EventId> = idx
            .search_exact_gpu(&query, k)
            .iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(
            got, gt_ids,
            "GPU-accelerated exact search must equal f64 brute-force"
        );
    }

    /// Um nó inserido quando TODOS os nós alcançáveis estão tombstoned não pode
    /// ficar órfão. `search_layer` nunca devolve tombstoned nos resultados,
    /// portanto os vizinhos candidatos vinham vazios e o nó novo ficava sem uma
    /// aresta sequer — invisível a qualquer busca futura. Tem de ligar-se ao
    /// grafo à mesma.
    #[test]
    fn no_novo_nao_fica_orfao_com_tudo_tombstoned() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        // Muitos nós: o entry fica estável num nível alto, para que o B
        // inserido depois NÃO se torne o entry (o que trivializaria a busca).
        let mut ids = Vec::new();
        for i in 0..64u64 {
            let e = EventId::new();
            ids.push(e);
            idx.insert(e, i, pt(vec![i as f32 / 64.0]));
        }
        // Tombstone de TODOS: qualquer caminho a partir do entry é só tombstoned.
        for e in &ids {
            assert!(idx.tombstone_event(e));
        }
        // Inserir B nesse estado.
        let b = EventId::new();
        idx.insert(b, 64, pt(vec![0.5]));

        // B TEM de ser encontrável — senão a inserção perdeu-se a si própria.
        let hits = idx.search(&pt(vec![0.5]), 1, 32, None);
        assert_eq!(hits.len(), 1, "B tem de aparecer, não ficar órfão");
        assert_eq!(hits[0].id, b);
    }

    #[test]
    fn tombstones_hide_from_results_but_preserve_graph() {
        // C2.1 (padrão Qdrant): o vetor retirado sai dos RESULTADOS sem
        // remontar o índice; a travessia continua a passar por ele.
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..50 {
            let e = EventId::new();
            ids.push(e);
            idx.insert(e, i as u64, pt(vec![i as f32 / 50.0]));
        }
        let q = pt(vec![0.5]);

        // Antes: o mais próximo de 0.5 é o vetor 25.
        let hits = idx.search(&q, 3, 32, None);
        assert_eq!(hits[0].id, ids[25]);

        // Tombstone no 25: sai dos resultados; o 24/26 assumem o topo.
        assert!(idx.tombstone_event(&ids[25]));
        assert_eq!(idx.tombstone_count(), 1);
        let hits = idx.search(&q, 3, 32, None);
        assert!(hits.iter().all(|h| h.id != ids[25]), "retirado não aparece");
        assert!(hits[0].id == ids[24] || hits[0].id == ids[26]);

        // O rescore exato (GPU/brute-force) respeita o tombstone.
        let exact = idx.search_exact_gpu(&q, 3);
        assert!(exact.iter().all(|h| h.id != ids[25]));

        // Inserções novas continuam a funcionar com tombstones presentes.
        let novo = EventId::new();
        idx.insert(novo, 50, pt(vec![0.501]));
        let hits = idx.search(&q, 1, 32, None);
        assert_eq!(hits[0].id, novo);

        // Round-trip de checkpoint preserva os tombstones.
        let dir = tempfile::tempdir().unwrap();
        idx.save_checkpoint(dir.path()).unwrap();
        let mut re = VectorIndex::new(ProductMetric::default());
        assert!(re.load_checkpoint(dir.path()).unwrap());
        assert_eq!(re.tombstone_count(), 1);
        let hits = re.search(&q, 3, 32, None);
        assert!(hits.iter().all(|h| h.id != ids[25]));
    }

    #[test]
    fn unreadable_checkpoint_degrades_to_rebuild() {
        // Um snapshot de formato antigo/corrompido NUNCA impede o boot: o
        // restore devolve false e o registry replaya desde 0.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vector.ckpt"), b"formato antigo qualquer").unwrap();
        let mut idx = VectorIndex::new(ProductMetric::default());
        assert!(!idx.load_checkpoint(dir.path()).unwrap());
        assert!(idx.is_empty());
    }

    #[test]
    fn checkpoint_restore_preserves_search() {
        // #12 — o HNSW restaurado do checkpoint deve dar buscas idênticas ao
        // original (boot rápido sem reconstruir do LSN 0).
        let dir = tempfile::tempdir().unwrap();
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..200u64 {
            let id = EventId(ulid::Ulid::from_parts(i, i as u128));
            ids.push(id);
            idx.insert(id, i, pt(vec![(i as f32) / 250.0, 0.1]));
        }
        let query = pt(vec![0.4, 0.1]);
        let before: Vec<EventId> = idx
            .search(&query, 5, 64, None)
            .iter()
            .map(|h| h.id)
            .collect();

        idx.save_checkpoint(dir.path()).unwrap();

        // Nova instância vazia restaura do disco (simula restart).
        let mut restored = VectorIndex::new(ProductMetric::default());
        assert!(
            restored.load_checkpoint(dir.path()).unwrap(),
            "checkpoint deve existir"
        );
        assert_eq!(restored.len(), 200);
        assert_eq!(restored.internal_id(&ids[100]), idx.internal_id(&ids[100]));
        let after: Vec<EventId> = restored
            .search(&query, 5, 64, None)
            .iter()
            .map(|h| h.id)
            .collect();

        assert_eq!(
            before, after,
            "busca no índice restaurado deve ser idêntica"
        );

        // Sem ficheiro → restore devolve false (view fica vazia → replay desde 0).
        let empty_dir = tempfile::tempdir().unwrap();
        let mut fresh = VectorIndex::new(ProductMetric::default());
        assert!(!fresh.load_checkpoint(empty_dir.path()).unwrap());
    }

    #[test]
    fn prepared_point_preserva_wire_format_e_e_reconstruido_no_restore() {
        let dir = tempfile::tempdir().unwrap();
        let mut idx = VectorIndex::new(ProductMetric::default());
        for i in 0..80u64 {
            idx.insert(
                EventId(ulid::Ulid::from_parts(i, i as u128)),
                i,
                pt(vec![(i as f32) / 100.0, 0.1]),
            );
        }
        idx.save_checkpoint(dir.path()).unwrap();
        let path = dir.path().join(VECTOR_CKPT_FILE);
        let bytes = std::fs::read(&path).unwrap();

        // Um leitor antigo continua a descodificar exactamente todo o ficheiro:
        // `prepared` nao foi acrescentado ao stream bincode.
        let (legacy, consumed) = bincode::serde::decode_from_slice::<LegacyVectorSnapshot, _>(
            &bytes,
            bincode::config::standard(),
        )
        .expect("checkpoint novo deve manter o formato antigo");
        assert_eq!(consumed, bytes.len());
        assert_eq!(legacy.nodes.len(), idx.nodes.len());

        // E o sentido inverso: bytes emitidos pelo schema antigo entram no
        // loader novo, que recalcula o cache derivado sob a Signature gravada.
        let legacy_bytes =
            bincode::serde::encode_to_vec(&legacy, bincode::config::standard()).unwrap();
        assert_eq!(legacy_bytes, bytes, "o wire format deve ser identico");
        std::fs::write(&path, legacy_bytes).unwrap();

        let mut restored = VectorIndex::new(ProductMetric::default());
        assert!(restored.load_checkpoint(dir.path()).unwrap());
        assert_eq!(restored.nodes.len(), idx.nodes.len());
        for node in &restored.nodes {
            assert_eq!(
                node.prepared,
                PreparedPoint::new(&restored.metric, &node.point),
                "restore deixou um cache de normas vazio ou obsoleto"
            );
        }
    }

    fn xorshift(estado: &mut u64) -> u64 {
        *estado ^= *estado << 13;
        *estado ^= *estado >> 7;
        *estado ^= *estado << 17;
        *estado
    }

    /// Vetor de 32 dims dentro da bola, o formato real dos embeddings.
    fn hyp32(semente: &mut u64) -> Vec<f32> {
        let mut v: Vec<f32> = (0..32)
            .map(|_| ((xorshift(semente) % 20_001) as f32 / 10_000.0 - 1.0) * 0.1)
            .collect();
        heraclitus_manifold::project_to_ball(&mut v);
        v
    }

    /// Auditoria 2026-09-05 (A03): UM append com um embedding de dimensao
    /// diferente — `hyp` vazio e so `sph` preenchido, que e exactamente o que a
    /// barreira de ingestao do gRPC deixa passar — envenenava a busca INTEIRA.
    /// A metrica truncava o par pelo mais curto, o no ficava a distancia ZERO
    /// de qualquer consulta e saia em primeiro lugar em quase todas. Como o log
    /// e append-only, ficava la ate alguem lhe fazer tombstone.
    #[test]
    fn um_embedding_de_dimensao_diferente_nao_envenena_a_busca() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut semente = 0x243f_6a88_85a3_08d3u64;
        for i in 0..200u64 {
            idx.insert(EventId::new(), i, pt(hyp32(&mut semente)));
        }
        let envenenado = EventId::new();
        idx.insert(
            envenenado,
            200,
            ProductPoint {
                hyp: vec![],
                sph: vec![1.0],
                euc: vec![],
            },
        );

        let mut primeiros = 0usize;
        for _ in 0..50 {
            let hits = idx.search(&pt(hyp32(&mut semente)), 5, 128, None);
            assert_eq!(hits.len(), 5);
            if hits[0].id == envenenado {
                primeiros += 1;
            }
            assert!(
                hits.iter().all(|h| h.id != envenenado),
                "o no de dimensao diferente voltou aos resultados (foi 1o em \
                 {primeiros} consultas); distancias: {:?}",
                hits.iter().map(|h| h.dist).collect::<Vec<_>>()
            );
        }
    }
}

#[cfg(test)]
mod testes_visitados {
    use super::*;

    fn pt2(hyp: Vec<f32>) -> ProductPoint {
        ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        }
    }

    /// O caso que a substituicao do `HashSet` introduziu e que nenhum teste
    /// existente alcanca: a epoca e um `u32` e ao dar a volta uma marca antiga
    /// coincidiria com a epoca actual — um no nunca visitado apareceria como
    /// visitado, e a busca saltava-o.
    ///
    /// Testa-se a estrutura directamente porque provocar 2^32 travessias reais
    /// levaria dias.
    #[test]
    fn o_transbordo_da_epoca_nao_faz_um_no_novo_parecer_visitado() {
        let mut v = Visitados::default();
        v.preparar(4);
        // Leva a epoca ate ao limite.
        v.epoca = u32::MAX;
        assert!(v.marcar(2), "novo nesta epoca");
        assert!(!v.marcar(2), "ja marcado nesta epoca");
        assert_eq!(v.marcas[2], u32::MAX);

        // A travessia seguinte da a volta.
        v.preparar(4);
        assert_eq!(v.epoca, 1, "recomeca em 1, nao em 0");
        assert_eq!(v.marcas[2], 0, "as marcas antigas foram limpas");
        assert!(
            v.marcar(2),
            "sem a limpeza, a marca antiga passaria por visitada e o no seria saltado"
        );
    }

    /// A semantica basica: mesma resposta que `HashSet::insert`.
    #[test]
    fn marcar_tem_a_semantica_de_hashset_insert() {
        let mut v = Visitados::default();
        v.preparar(8);
        assert!(v.marcar(0));
        assert!(v.marcar(7));
        assert!(!v.marcar(0));
        assert!(!v.marcar(7));
        // Travessia nova: tudo volta a ser novo.
        v.preparar(8);
        assert!(v.marcar(0));
        assert!(v.marcar(7));
    }

    /// Um id fora do intervalo devolve `true`, para manter exactamente o
    /// percurso da versao anterior (que so rebentava mais a frente, ao indexar
    /// `self.nodes`) em vez de introduzir aqui um sitio de panico novo.
    #[test]
    fn um_id_fora_do_intervalo_nao_entra_em_panico_aqui() {
        let mut v = Visitados::default();
        v.preparar(4);
        assert!(v.marcar(999), "fora do intervalo conta como novo");
    }

    /// O scratch cresce com o indice e nunca encolhe — uma travessia sobre um
    /// indice maior tem de continuar correcta.
    #[test]
    fn o_scratch_cresce_com_o_indice() {
        let mut v = Visitados::default();
        v.preparar(4);
        assert!(v.marcar(3));
        v.preparar(1000);
        assert!(v.marcar(999), "o no novo cabe depois de crescer");
        assert!(v.marcar(3), "e a travessia nova reinicia tudo");
    }

    /// A busca continua a devolver o vizinho exacto — a prova de que a troca
    /// nao mexeu no recall.
    #[test]
    fn a_busca_continua_a_encontrar_o_vizinho_exacto() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..500 {
            let x = (i as f32) / 600.0;
            let id = EventId::new();
            ids.push(id);
            idx.insert(id, i as u64, pt2(vec![x, 0.1]));
        }
        for alvo in [0usize, 137, 250, 499] {
            let x = (alvo as f32) / 600.0;
            let hits = idx.search(&pt2(vec![x, 0.1]), 3, 64, None);
            assert_eq!(hits[0].id, ids[alvo], "vizinho exacto para {alvo}");
        }
    }
}

#[cfg(test)]
mod testes_greedy_descent {
    use super::*;

    fn ponto(semente: u64) -> ProductPoint {
        let mut x = semente.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut proximo = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ((x % 2001) as f32 / 2000.0 - 0.5) * 0.35
        };
        ProductPoint {
            hyp: (0..32).map(|_| proximo()).collect(),
            sph: (0..8).map(|_| proximo()).collect(),
            euc: (0..8).map(|_| proximo()).collect(),
        }
    }

    fn indice(n: usize) -> VectorIndex {
        let mut index = VectorIndex::new(ProductMetric::default());
        for i in 0..n {
            index.insert(
                EventId(ulid::Ulid::from_parts(i as u64, i as u128)),
                i as u64,
                ponto(i as u64 + 1),
            );
        }
        assert!(
            index.nodes.iter().any(|node| node.level > 0),
            "o corpus deterministico precisa exercitar camadas superiores"
        );
        index
    }

    /// Referencia congelada do caminho anterior: `search_layer` geral com
    /// `ef=1`, sem filtro. Serve apenas para provar equivalencia da descida.
    fn referencia_ef1(
        index: &VectorIndex,
        query: &PreparedQuery,
        entry: u32,
        level: usize,
    ) -> Candidate {
        index
            .search_layer(query, entry, level, 1, None)
            .into_iter()
            .next()
            .expect("sem tombstones, ef=1 sempre devolve o entry ou uma melhora")
    }

    fn busca_com_descida_de_referencia(
        index: &VectorIndex,
        query: &ProductPoint,
        k: usize,
        ef: usize,
        filter: Option<&RoaringBitmap>,
    ) -> Vec<(EventId, Lsn, u32)> {
        let Some(mut entry) = index.entry else {
            return Vec::new();
        };
        let prepared = PreparedQuery::new(&index.metric, query);
        let top = index.nodes[entry as usize].level;
        for level in (1..=top).rev() {
            entry = referencia_ef1(index, &prepared, entry, level).id;
        }
        index
            .search_layer(
                &prepared,
                entry,
                0,
                ef.max(k).max(index.ef_construction.min(64)),
                filter,
            )
            .into_iter()
            .take(k)
            .map(|candidate| {
                (
                    index.ids[candidate.id as usize],
                    index.lsns[candidate.id as usize],
                    (candidate.dist.max(0.0).sqrt() as f32).to_bits(),
                )
            })
            .collect()
    }

    #[test]
    fn greedy_e_bit_a_bit_equivalente_ao_search_layer_ef1() {
        let index = indice(700);
        for seed in 10_000..10_100u64 {
            let query_point = ponto(seed);
            let query = PreparedQuery::new(&index.metric, &query_point);
            let mut greedy_entry = index.entry.unwrap();
            let mut reference_entry = greedy_entry;
            let top = index.nodes[greedy_entry as usize].level;
            for level in (1..=top).rev() {
                let greedy = index.search_layer_greedy(&query, greedy_entry, level);
                let reference = referencia_ef1(&index, &query, reference_entry, level);
                assert_eq!(greedy.id, reference.id, "seed={seed}, level={level}");
                assert_eq!(
                    greedy.dist.to_bits(),
                    reference.dist.to_bits(),
                    "seed={seed}, level={level}"
                );
                greedy_entry = greedy.id;
                reference_entry = reference.id;
            }
        }
    }

    #[test]
    fn busca_filtrada_preserva_ranking_e_usa_um_unico_search_layer_completo() {
        let index = indice(900);
        let mut filter = RoaringBitmap::new();
        for id in (0..index.len() as u32).step_by(11) {
            filter.insert(id);
        }
        let query = ponto(99_999);
        let reference = busca_com_descida_de_referencia(&index, &query, 12, 96, Some(&filter));

        SEARCH_LAYER_CALLS.with(|calls| calls.set(0));
        GREEDY_DESCENT_CALLS.with(|calls| calls.set(0));
        let actual: Vec<(EventId, Lsn, u32)> = index
            .search(&query, 12, 96, Some(&filter))
            .into_iter()
            .map(|hit| (hit.id, hit.lsn, hit.dist.to_bits()))
            .collect();

        assert_eq!(actual, reference, "filtro/ranking mudaram com a descida");
        let top = index.nodes[index.entry.unwrap() as usize].level;
        let greedy_calls = GREEDY_DESCENT_CALLS.with(std::cell::Cell::get);
        let full_calls = SEARCH_LAYER_CALLS.with(std::cell::Cell::get);
        assert_eq!(greedy_calls, top, "uma descida especializada por nivel");
        assert_eq!(
            full_calls, 1,
            "somente a camada zero pode chamar o search_layer completo"
        );

        // Prova direta: o helper especializado nao delega escondido para o
        // caminho geral.
        let prepared = PreparedQuery::new(&index.metric, &query);
        SEARCH_LAYER_CALLS.with(|calls| calls.set(0));
        GREEDY_DESCENT_CALLS.with(|calls| calls.set(0));
        index.search_layer_greedy(&prepared, index.entry.unwrap(), top);
        assert_eq!(SEARCH_LAYER_CALLS.with(std::cell::Cell::get), 0);
        assert_eq!(GREEDY_DESCENT_CALLS.with(std::cell::Cell::get), 1);
    }
}

#[cfg(test)]
mod medicao_hnsw {
    use super::*;
    use std::time::Instant;

    /// Geometria REALISTA: H32 x S8 x E8, as 48 dimensoes que o arranque do
    /// servidor reporta. A primeira versao deste benchmark usava 2 dimensoes
    /// hiperbolicas e as outras componentes vazias — media o custo de uma
    /// forma que a producao nao tem, e por isso nao via o trabalho que a
    /// consulta preparada existe para poupar (duas normas completas e as
    /// constantes da curvatura, por candidato).
    fn ponto_realista(semente: u64) -> ProductPoint {
        let mut x = semente.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut proximo = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ((x % 2001) as f32 / 2000.0 - 0.5) * 0.8
        };
        ProductPoint {
            hyp: (0..32).map(|_| proximo()).collect(),
            sph: (0..8).map(|_| proximo()).collect(),
            euc: (0..8).map(|_| proximo()).collect(),
        }
    }

    /// `#[ignore]`: mede, nao afirma. Um numero de milissegundos falharia na
    /// maquina de outra pessoa.
    ///
    ///   cargo test -p heraclitus-index-vector --lib medicao -- --ignored --nocapture
    #[test]
    #[ignore]
    fn custo_da_busca() {
        for n in [2_000usize, 10_000] {
            let mut idx = VectorIndex::new(ProductMetric::default());
            for i in 0..n {
                idx.insert(EventId::new(), i as u64, ponto_realista(i as u64));
            }
            let consultas: Vec<ProductPoint> = (0..200)
                .map(|q| ponto_realista(1_000_000 + q as u64))
                .collect();

            // Aquece: a primeira travessia paga o crescimento do scratch.
            for c in consultas.iter().take(10) {
                idx.search(c, 10, 64, None);
            }
            let t0 = Instant::now();
            let mut total = 0usize;
            for c in &consultas {
                total += idx.search(c, 10, 64, None).len();
            }
            let dt = t0.elapsed();
            println!(
                "n={n:>6} ef=64  {} consultas em {:>10.3?}  ({:>8.1?}/consulta, {total} hits)",
                consultas.len(),
                dt,
                dt / consultas.len() as u32
            );
        }
    }

    /// Mede somente a descida das camadas superiores: algoritmo geral `ef=1`
    /// contra scan/move/repeat sem heaps. Ignorado porque tempo de parede nao e
    /// uma assercao portavel.
    ///
    ///   cargo test -p heraclitus-index-vector --release --lib \
    ///     greedy_vs_search_layer -- --ignored --nocapture
    #[test]
    #[ignore]
    fn greedy_vs_search_layer_ef1() {
        let mut index = VectorIndex::new(ProductMetric::default());
        for i in 0..10_000 {
            index.insert(EventId::new(), i as u64, ponto_realista(i as u64));
        }
        let queries: Vec<PreparedQuery> = (0..2_000)
            .map(|i| PreparedQuery::new(&index.metric, &ponto_realista(1_000_000 + i as u64)))
            .collect();
        let entry = index.entry.unwrap();
        let top = index.nodes[entry as usize].level;
        assert!(top > 0);

        let started = Instant::now();
        let mut checksum_greedy = 0u64;
        for query in &queries {
            let mut current = entry;
            for level in (1..=top).rev() {
                current = index.search_layer_greedy(query, current, level).id;
            }
            checksum_greedy = checksum_greedy.wrapping_add(current as u64);
        }
        let greedy_time = started.elapsed();

        let started = Instant::now();
        let mut checksum_reference = 0u64;
        for query in &queries {
            let mut current = entry;
            for level in (1..=top).rev() {
                current = index
                    .search_layer(query, current, level, 1, None)
                    .first()
                    .expect("corpus sem tombstones")
                    .id;
            }
            checksum_reference = checksum_reference.wrapping_add(current as u64);
        }
        let reference_time = started.elapsed();

        assert_eq!(checksum_greedy, checksum_reference);
        println!(
            "upper descent: greedy={greedy_time:?}, search_layer(ef=1)={reference_time:?}, speedup={:.2}x, checksum={checksum_greedy}",
            reference_time.as_secs_f64() / greedy_time.as_secs_f64()
        );
    }
}

#[cfg(test)]
mod testes_prepared_query {
    use super::*;

    fn pt4(hyp: Vec<f32>) -> ProductPoint {
        ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        }
    }

    /// A travessia passou a ordenar pela distancia AO QUADRADO. O campo
    /// `VectorHit.dist` e publico e tem de continuar a ser a distancia REAL —
    /// se a raiz se perdesse, a API mentia sem que nenhum teste de recall desse
    /// por isso, porque a ORDEM ficaria na mesma.
    #[test]
    fn o_dist_devolvido_e_a_distancia_canonica_e_nao_o_quadrado() {
        let metric = ProductMetric::default();
        let mut idx = VectorIndex::new(metric.clone());
        let mut pontos = Vec::new();
        let mut ids = Vec::new();
        for i in 0..300 {
            let x = (i as f32) / 400.0;
            let p = pt4(vec![x, 0.1, x * 0.3]);
            let id = EventId::new();
            ids.push(id);
            pontos.push(p.clone());
            idx.insert(id, i as u64, p);
        }
        let q = pt4(vec![0.37, 0.1, 0.11]);
        let hits = idx.search(&q, 5, 64, None);
        assert_eq!(hits.len(), 5);
        for h in &hits {
            let i = ids.iter().position(|x| *x == h.id).expect("id conhecido");
            let canonica = metric.dist(&pontos[i], &q) as f32;
            assert!(
                (h.dist - canonica).abs() < 1e-4,
                "dist devolvida {} vs canonica {canonica}",
                h.dist
            );
            // E a prova de que nao e o quadrado: para distancias < 1 o
            // quadrado seria MENOR, para > 1 seria MAIOR.
            assert!(
                (h.dist - canonica * canonica).abs() > 1e-6 || canonica < 1e-3,
                "o valor devolvido coincide com o quadrado — a raiz perdeu-se"
            );
        }
        // E vem ordenado.
        for par in hits.windows(2) {
            assert!(par[0].dist <= par[1].dist);
        }
    }

    /// Um checkpoint decodável mas com um id de vizinho fora de `nodes.len()`
    /// passava a verificação de coerência e só rebentava depois, num
    /// `self.nodes[vizinho]` fora de limites durante a pesquisa — pânico que
    /// envenena o índice inteiro. Agora degrada para rebuild (`Ok(false)`).
    #[test]
    fn checkpoint_com_vizinho_fora_de_intervalo_degrada() {
        let dir = tempfile::tempdir().unwrap();
        let mut idx = VectorIndex::new(ProductMetric::default());
        for i in 0..4u64 {
            let id = EventId::new();
            idx.insert(
                id,
                i,
                ProductPoint {
                    hyp: vec![(i as f32) / 10.0, 0.1],
                    sph: vec![],
                    euc: vec![],
                },
            );
        }
        idx.save_checkpoint(dir.path()).unwrap();

        // Decodificar, envenenar um id de vizinho, re-escrever.
        let bytes = std::fs::read(dir.path().join(VECTOR_CKPT_FILE)).unwrap();
        let (mut snap, _): (VectorSnapshot, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        // Um vizinho que aponta muito para lá do fim.
        snap.nodes[0].neighbors[0] = vec![9_999];
        let envenenado = bincode::serde::encode_to_vec(&snap, bincode::config::standard()).unwrap();
        std::fs::write(dir.path().join(VECTOR_CKPT_FILE), &envenenado).unwrap();

        // Restore tem de degradar, nao adoptar o estado que panica.
        let mut fresco = VectorIndex::new(ProductMetric::default());
        assert!(
            !fresco.restore(dir.path()).unwrap(),
            "checkpoint com vizinho fora de intervalo degrada para rebuild"
        );

        // E um checkpoint SÃO continua a restaurar.
        let mut bom = VectorIndex::new(ProductMetric::default());
        assert!(bom.restore(dir.path()).is_ok());
    }
}

#[cfg(test)]
mod testes_coerencia_do_checkpoint {
    use super::*;

    fn indice_com_quatro_pontos(dir: &Path) -> VectorIndex {
        let mut idx = VectorIndex::new(ProductMetric::default());
        for i in 0..4u64 {
            let id = EventId(ulid::Ulid::from_parts(i, i as u128));
            idx.insert(
                id,
                i,
                ProductPoint {
                    hyp: vec![(i as f32) / 10.0, 0.1],
                    sph: vec![],
                    euc: vec![],
                },
            );
        }
        idx.save_checkpoint(dir).unwrap();
        idx
    }

    /// Reescreve `vector.ckpt` com o snapshot decodificado e alterado por
    /// `envenenar`, e devolve o que um indice fresco faz do ficheiro.
    fn restaurar_com_snapshot_envenenado(
        dir: &Path,
        envenenar: impl FnOnce(&mut VectorSnapshot),
    ) -> bool {
        let bytes = std::fs::read(dir.join(VECTOR_CKPT_FILE)).unwrap();
        let (mut snap, _): (VectorSnapshot, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        envenenar(&mut snap);
        let envenenado = bincode::serde::encode_to_vec(&snap, bincode::config::standard()).unwrap();
        std::fs::write(dir.join(VECTOR_CKPT_FILE), &envenenado).unwrap();
        let mut fresco = VectorIndex::new(ProductMetric::default());
        fresco.restore(dir).unwrap()
    }

    /// Auditoria 2026-09-05, A26. `m` e `ef_construction` sao restaurados do
    /// ficheiro sem validacao nenhuma, e `m` e divisor de `ln` em
    /// `random_level` e regua de truncagem em `insert`. Com `m = 0` a poda
    /// vira `truncate(0)` e apaga as listas de adjacencia em silencio; com
    /// `m = 1` o nivel sorteado satura em `usize::MAX` e `level + 1` transborda.
    /// Um checkpoint assim tem de degradar para rebuild do log, como o
    /// comentario de `load_checkpoint` ja promete.
    #[test]
    fn checkpoint_com_m_ou_ef_construction_degenerados_degrada() {
        for degenerado in [0usize, 1] {
            let dir = tempfile::tempdir().unwrap();
            indice_com_quatro_pontos(dir.path());
            assert!(
                !restaurar_com_snapshot_envenenado(dir.path(), |snap| snap.m = degenerado),
                "checkpoint com m = {degenerado} tem de degradar para rebuild"
            );
        }

        let dir = tempfile::tempdir().unwrap();
        indice_com_quatro_pontos(dir.path());
        assert!(
            !restaurar_com_snapshot_envenenado(dir.path(), |snap| snap.ef_construction = 0),
            "checkpoint com ef_construction = 0 tem de degradar para rebuild"
        );

        // E um checkpoint SAO continua a restaurar — a guarda nao pode virar
        // uma recusa cega.
        let dir = tempfile::tempdir().unwrap();
        indice_com_quatro_pontos(dir.path());
        let mut bom = VectorIndex::new(ProductMetric::default());
        assert!(
            bom.restore(dir.path()).unwrap(),
            "checkpoint intacto tem de restaurar"
        );
        assert_eq!(bom.len(), 4);
    }

    /// Auditoria 2026-09-05, A51. O PROPRIO guarda de coerencia somava sobre um
    /// valor nao confiavel: `n.neighbors.len() == n.level + 1`, com `level` a
    /// vir do ficheiro como varint sem tecto. Com `level = usize::MAX` a soma
    /// transbordava — e `overflow-checks = true` tambem no perfil release, logo
    /// panico dentro de `load_checkpoint`, que sobe por `View::restore` ->
    /// `ViewRegistry::catch_up` -> `Engine::open_with_boot`: o servidor nao
    /// arrancava por causa de um ficheiro puramente derivado. Tem de degradar
    /// para rebuild do log, como a funcao promete.
    #[test]
    fn checkpoint_com_nivel_absurdo_degrada_em_vez_de_transbordar() {
        let dir = tempfile::tempdir().unwrap();
        indice_com_quatro_pontos(dir.path());
        assert!(
            !restaurar_com_snapshot_envenenado(dir.path(), |snap| snap.nodes[0].level = usize::MAX),
            "nivel absurdo degrada para rebuild, nao panica"
        );

        // O vec de vizinhos vazio continua recusado — `search_layer` indexa
        // `neighbors[..len()-1]` e um vec vazio dava underflow em toda pesquisa
        // futura. O `checked_sub` subsume esta defesa; o teste prende-a.
        let dir = tempfile::tempdir().unwrap();
        indice_com_quatro_pontos(dir.path());
        assert!(
            !restaurar_com_snapshot_envenenado(dir.path(), |snap| snap.nodes[0].neighbors.clear()),
            "checkpoint com lista de vizinhos vazia degrada para rebuild"
        );

        // E a combinacao das duas: vec vazio COM `level = usize::MAX`. Um
        // `wrapping_sub(1)` daria `usize::MAX`, que casa com o `level` do
        // ficheiro — o snapshot passava a coerencia e `search_layer` ia
        // indexar `neighbors[..len()-1]` num vec vazio.
        let dir = tempfile::tempdir().unwrap();
        indice_com_quatro_pontos(dir.path());
        assert!(
            !restaurar_com_snapshot_envenenado(dir.path(), |snap| {
                snap.nodes[0].level = usize::MAX;
                snap.nodes[0].neighbors.clear();
            }),
            "vec vazio com nivel usize::MAX nao pode passar por dar a volta"
        );
    }

    /// Auditoria 2026-09-05, A26 (defesa em profundidade). `random_level`
    /// divide por `ln(m)`: com `m = 1` isso e `1/0 = +inf`, o `floor() as usize`
    /// satura em `usize::MAX` e a alocacao `vec![Vec::new(); level + 1]` de
    /// `insert` transborda — panico, nao degradacao. A funcao tem de ser total.
    #[test]
    fn random_level_e_total_quando_m_e_um() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        idx.m = 1;
        for i in 0..8u64 {
            let id = EventId(ulid::Ulid::from_parts(i, i as u128));
            idx.insert(
                id,
                i,
                ProductPoint {
                    hyp: vec![(i as f32) / 10.0, 0.1],
                    sph: vec![],
                    euc: vec![],
                },
            );
        }
        assert_eq!(idx.len(), 8);
        assert!(
            idx.nodes.iter().all(|n| n.level < 1024),
            "nivel sorteado com m = 1 saturou"
        );
    }
}

#[cfg(test)]
mod testes_poda_de_vizinhos {
    use super::*;

    fn ponto(i: u32) -> ProductPoint {
        ProductPoint {
            hyp: vec![(i as f32) / 25.0, 0.1],
            sph: vec![],
            euc: vec![],
        }
    }

    /// 40 nos em que `i` e `i + 20` partilham EXACTAMENTE o mesmo ponto — e
    /// portanto a mesma distancia a qualquer outro no. Os empates sao o que
    /// prende a ESTABILIDADE da ordenacao da poda.
    fn indice_com_pontos_repetidos() -> VectorIndex {
        let mut idx = VectorIndex::new(ProductMetric::default());
        for i in 0..40u32 {
            let id = EventId(ulid::Ulid::from_parts(i as u64, i as u128));
            idx.insert(id, i as u64, ponto(i % 20));
        }
        idx
    }

    /// Lista de 33 vizinhos (um a mais do que `m * 2 = 32`, logo a poda corta)
    /// com os pares empatados deliberadamente pela ordem id-ALTO primeiro: se
    /// alguem acrescentar um desempate por id, a ordem muda e o teste morre.
    fn lista_de_vizinhos() -> Vec<u32> {
        let mut lista = Vec::new();
        for i in 1..=13u32 {
            lista.push(i + 20);
            lista.push(i);
        }
        lista.extend(14..=20u32);
        assert_eq!(lista.len(), 33);
        lista
    }

    /// Assinatura de TODO o grafo: niveis e listas de adjacencia de cada no.
    /// Qualquer aresta diferente muda o valor.
    fn assinatura_do_grafo(idx: &VectorIndex) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let misturar = |h: &mut u64, v: u64| {
            *h ^= v;
            *h = h.wrapping_mul(0x1000_0000_01b3);
        };
        for no in &idx.nodes {
            misturar(&mut h, no.level as u64);
            for camada in &no.neighbors {
                misturar(&mut h, camada.len() as u64);
                for &v in camada {
                    misturar(&mut h, v as u64);
                }
            }
        }
        h
    }

    /// Auditoria 2026-09-05, A27. A poda recalculava a distancia DENTRO do
    /// comparador do `sort_by` — duas avaliacoes da metrica por comparacao,
    /// ~2·n·log2(n) onde n bastavam, no caminho quente de escrita (`View::apply`
    /// -> `insert`, uma vez por episodio com embedding). Cada avaliacao percorre
    /// os vectores em f64 e paga um `acosh`.
    #[test]
    fn poda_calcula_a_distancia_uma_vez_por_vizinho() {
        let mut idx = indice_com_pontos_repetidos();
        let lista = lista_de_vizinhos();
        let n = 39u32;
        idx.nodes[n as usize].neighbors[0] = lista.clone();

        DIST2_CALLS.with(|c| c.set(0));
        idx.podar_vizinhos(n, 0);
        let chamadas = DIST2_CALLS.with(|c| c.get());

        assert_eq!(
            chamadas,
            lista.len(),
            "a poda tem de avaliar a metrica uma vez por vizinho ({} vizinhos), nao uma vez por comparacao",
            lista.len()
        );
    }

    /// Guarda de neutralidade: a poda optimizada tem de dar EXACTAMENTE a
    /// mesma lista que o caminho antigo, incluindo a ordem dos empatados (o
    /// `sort_by` e estavel, e a ordem da lista de adjacencia e observavel no
    /// checkpoint e na travessia). Um desempate novo — por id ou por uma
    /// particao instavel tipo `select_nth_unstable_by` — seria uma mudanca de
    /// grafo travestida de optimizacao.
    #[test]
    fn poda_preserva_exactamente_a_ordem_do_caminho_antigo() {
        let mut idx = indice_com_pontos_repetidos();
        let lista = lista_de_vizinhos();
        let n = 39u32;

        // Oraculo: literalmente o caminho antigo (chave recalculada dentro do
        // comparador, `sort_by` estavel, truncar).
        let np = PreparedQuery::new(&idx.metric, &idx.nodes[n as usize].point);
        let empatados = lista
            .windows(2)
            .filter(|par| idx.dist2(par[0], &np) == idx.dist2(par[1], &np))
            .count();
        assert!(
            empatados >= 13,
            "o teste so prende a estabilidade se houver empates; encontrei {empatados}"
        );
        let mut esperado = lista.clone();
        esperado.sort_by(|&a, &b| idx.dist2(a, &np).total_cmp(&idx.dist2(b, &np)));
        esperado.truncate(idx.m * 2);

        idx.nodes[n as usize].neighbors[0] = lista;
        idx.podar_vizinhos(n, 0);

        assert_eq!(
            idx.nodes[n as usize].neighbors[0], esperado,
            "a poda mudou a lista de adjacencia — a optimizacao nao e neutra"
        );
    }

    /// Golden capturado com o codigo ANTERIOR a optimizacao da poda: a
    /// construcao de um indice de 300 nos (que satura as listas e passa pela
    /// poda muitas vezes) tem de produzir o MESMO grafo, aresta a aresta.
    #[test]
    fn a_optimizacao_da_poda_nao_muda_o_grafo_construido() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        for i in 0..300u32 {
            let id = EventId(ulid::Ulid::from_parts(i as u64, i as u128));
            idx.insert(id, i as u64, ponto(i % 20));
        }
        assert_eq!(
            assinatura_do_grafo(&idx),
            10_880_861_797_930_025_899,
            "a construcao deixou de dar o mesmo grafo que o caminho antigo"
        );
    }
}
