//! SPEC-024 — subsystem API boundaries.
//!
//! The six clean trait contracts that keep the engine's subsystems decoupled
//! and independently replaceable: storage, replay, planning, optimization,
//! execution and catalog. `StorageEngine` and the replay `ReplaySink` live in
//! their own modules ([`crate::runtime`], [`crate::dispatcher`]); this module
//! adds the planning/execution/catalog boundaries so all six exist as stable
//! Rust traits.

use crate::ir::{ExecutionNode, LogicalPlan};
use crate::{Lsn, SegmentId};

/// Parses a query string into a logical plan (Compiler 1 front).
pub trait Planner: Send + Sync {
    fn plan(&self, query: &str) -> Result<LogicalPlan, String>;
}

/// Lowers a logical plan into a physical operator DAG.
pub trait Optimizer: Send + Sync {
    fn optimize(&self, plan: LogicalPlan) -> Result<Vec<ExecutionNode>, String>;
}

/// Executes a physical DAG into batches. `Batch` is an associated type so the
/// contract stays Arrow-agnostic in `core` (concrete engines bind it to an
/// Arrow `RecordBatch`).
pub trait TaskScheduler: Send + Sync {
    type Batch;
    fn execute(&self, dag: Vec<ExecutionNode>) -> Result<Vec<Self::Batch>, String>;
}

/// Resolves which segments are visible under a read snapshot.
pub trait SegmentCatalog: Send + Sync {
    fn resolve_visible(&self, target_lsn: Lsn) -> Vec<SegmentId>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::PhysicalIr;

    struct DummyCatalog {
        segs: Vec<(SegmentId, Lsn)>, // (id, first_lsn)
    }
    impl SegmentCatalog for DummyCatalog {
        fn resolve_visible(&self, target_lsn: Lsn) -> Vec<SegmentId> {
            self.segs
                .iter()
                .filter(|(_, first)| *first <= target_lsn)
                .map(|(id, _)| *id)
                .collect()
        }
    }

    struct DummySched;
    impl TaskScheduler for DummySched {
        type Batch = usize;
        fn execute(&self, dag: Vec<ExecutionNode>) -> Result<Vec<usize>, String> {
            Ok(dag.iter().map(|n| n.dependencies.len()).collect())
        }
    }

    #[test]
    fn catalog_and_scheduler_contracts_work() {
        let cat = DummyCatalog { segs: vec![(0, 0), (1, 10), (2, 20)] };
        assert_eq!(cat.resolve_visible(15), vec![0, 1]);

        let sched = DummySched;
        let dag = vec![
            ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![] }, vec![]),
            ExecutionNode::new(1, PhysicalIr::VectorFilter { predicate_id: 1 }, vec![0]),
        ];
        assert_eq!(sched.execute(dag).unwrap(), vec![0, 1]);
    }
}
