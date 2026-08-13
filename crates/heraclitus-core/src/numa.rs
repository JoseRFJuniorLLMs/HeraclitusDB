//! SPEC-033 — NUMA memory governance (policy layer).
//!
//! Decides, by structure size, whether a `DerivedExecutionArtifact` accessed
//! from a remote NUMA node should be *replicated* (small: copy to the local
//! node) or *recompiled locally* (large: rebuild from the log-read cache rather
//! than drag gigabytes across the interconnect).
//!
//! Honest scope: this is the *policy* + topology descriptor. Actual thread↔node
//! pinning and node-local allocation need OS/libnuma calls and are a deliberate
//! follow-up — the plan defers real NUMA pinning behind a benchmark gate. On a
//! single-node host `detect()` reports one node and every access is "local".

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaTopology {
    pub nodes: usize,
}

impl NumaTopology {
    /// Conservative detection: absent a real libnuma probe, assume a single
    /// node (correct behaviour: everything is treated as node-local).
    pub fn detect() -> Self {
        Self { nodes: 1 }
    }

    pub fn is_multi_node(&self) -> bool {
        self.nodes > 1
    }
}

/// What to do when a task on node `local` needs an artifact resident on node
/// `remote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransnodeStrategy {
    /// Same node — no action.
    Local,
    /// Small artifact — duplicate it onto the local node.
    Replicate,
    /// Large artifact — rebuild locally from the log-read cache instead of
    /// shipping bytes across the interconnect.
    RecompileLocal,
}

/// Choose a strategy. `small_threshold_bytes` is the cutoff below which copying
/// is cheaper than a local rebuild.
pub fn plan_transnode_access(
    local_node: usize,
    remote_node: usize,
    artifact_bytes: usize,
    small_threshold_bytes: usize,
) -> TransnodeStrategy {
    if local_node == remote_node {
        TransnodeStrategy::Local
    } else if artifact_bytes <= small_threshold_bytes {
        TransnodeStrategy::Replicate
    } else {
        TransnodeStrategy::RecompileLocal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_node_host_is_all_local() {
        assert!(!NumaTopology::detect().is_multi_node());
    }

    #[test]
    fn strategy_by_size_and_locality() {
        assert_eq!(plan_transnode_access(0, 0, 10_000, 1024), TransnodeStrategy::Local);
        assert_eq!(plan_transnode_access(0, 1, 512, 1024), TransnodeStrategy::Replicate);
        assert_eq!(
            plan_transnode_access(0, 1, 1 << 30, 1024),
            TransnodeStrategy::RecompileLocal
        );
    }
}
