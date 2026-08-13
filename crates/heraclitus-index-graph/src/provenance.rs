//! SPEC-014 — provenance engine (Compiler 2 surface).
//!
//! Promotes `WHY` from a utility function to a first-class engine over the
//! causal DAG (`Episode.parents`). It answers the two provenance questions:
//! the full ancestor set (`why`) and the *minimal* causal chain linking an
//! effect back to a specific cause (`minimal_causal_chain`, a shortest path in
//! the parent DAG). Reads only the derived graph view — never mutates the log.

use crate::GraphIndex;
use heraclitus_core::EventId;
use std::collections::{HashMap, VecDeque};

pub struct ProvenanceEngine<'a> {
    graph: &'a GraphIndex,
}

impl<'a> ProvenanceEngine<'a> {
    pub fn new(graph: &'a GraphIndex) -> Self {
        Self { graph }
    }

    /// `WHY(effect)` — provenance ancestors up to `depth` hops.
    pub fn why(&self, effect: &EventId, depth: usize) -> Vec<EventId> {
        self.graph.ancestors(effect, depth)
    }

    /// Minimal causal chain `[effect, …, cause]` (shortest path up the parent
    /// DAG), or `None` if `cause` is not an ancestor of `effect`.
    pub fn minimal_causal_chain(&self, effect: &EventId, cause: &EventId) -> Option<Vec<EventId>> {
        if effect == cause {
            return Some(vec![*effect]);
        }
        // Breadth-first over parents = shortest hop count to the cause.
        let mut came_from: HashMap<EventId, EventId> = HashMap::new();
        let mut queue = VecDeque::from([*effect]);
        let mut seen = std::collections::HashSet::from([*effect]);
        while let Some(node) = queue.pop_front() {
            for parent in self.graph.parents(&node) {
                if !seen.insert(parent) {
                    continue;
                }
                came_from.insert(parent, node);
                if parent == *cause {
                    // Reconstruct effect → … → cause.
                    let mut chain = vec![parent];
                    let mut cur = parent;
                    while let Some(&child) = came_from.get(&cur) {
                        chain.push(child);
                        cur = child;
                    }
                    chain.reverse();
                    return Some(chain);
                }
                queue.push_back(parent);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};
    use heraclitus_views::View;

    fn ev(s: &str, parents: &[EventId]) -> Episode {
        let mut e = Episode::new("x", EventKind::Observation, s.as_bytes().to_vec());
        e.parents = parents.to_vec();
        e
    }

    #[test]
    fn minimal_chain_is_shortest_path() {
        // Chain e0 ← e1 ← e2 ← e3, plus a shortcut e0 ← e3direct.
        let mut g = GraphIndex::new();
        let e0 = ev("e0", &[]);
        let e1 = ev("e1", &[e0.id]);
        let e2 = ev("e2", &[e1.id]);
        // e3 has two parents: e2 (long path) and e0 (direct shortcut).
        let e3 = ev("e3", &[e2.id, e0.id]);
        for (i, e) in [&e0, &e1, &e2, &e3].iter().enumerate() {
            g.apply(i as u64, e);
        }
        let pe = ProvenanceEngine::new(&g);

        // Shortest chain e3 → e0 is the direct edge: [e3, e0].
        let chain = pe.minimal_causal_chain(&e3.id, &e0.id).unwrap();
        assert_eq!(chain, vec![e3.id, e0.id]);

        // e3 → e1 must go through e2: [e3, e2, e1].
        let chain = pe.minimal_causal_chain(&e3.id, &e1.id).unwrap();
        assert_eq!(chain, vec![e3.id, e2.id, e1.id]);

        // Unrelated cause → None.
        let stranger = ev("s", &[]);
        assert_eq!(pe.minimal_causal_chain(&e3.id, &stranger.id), None);
    }
}
