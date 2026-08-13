//! SPEC-012/013 — logical & physical intermediate representations.
//!
//! `LogicalPlan` is the declarative intent parsed from a query; the optimizer
//! lowers it into a DAG of `ExecutionNode`s carrying `PhysicalIr` operators for
//! the vectorized runtime. `ExplainIr` is the parallel lowering for the
//! provenance engine (Compiler 2). Ids: logical plans reference user-facing
//! `EventId`s; physical operators reference dense `u32` column/entity ids.

use crate::EventId;

/// Declarative query intent (Compiler 1 input).
#[derive(Debug, Clone, PartialEq)]
pub enum LogicalPlan {
    Select {
        relations: Vec<String>,
        /// Conjunctive predicate ids (registered with the executor). The
        /// OPTIMIZER decides their physical order by estimated selectivity —
        /// the cost-based decision of SPEC-012.
        predicates: Vec<u32>,
        /// Optional aggregation: `(group_key_columns, sum_columns)`. Count is
        /// always produced per group.
        aggregate: Option<(Vec<u32>, Vec<u32>)>,
    },
    GraphMatch { pattern_id: u32 },
    TraceProvenance { target: EventId },
}

/// Low-level operator interpreted by the vectorized runtime.
#[derive(Debug, Clone, PartialEq)]
pub enum PhysicalIr {
    ColumnScan { projection: Vec<u32> },
    VectorFilter { predicate_id: u32 },
    HashJoin { left_key: u32, right_key: u32 },
    VectorAggregate { keys: Vec<u32>, aggregations: Vec<u32> },
}

/// Sparse dependency lowering for the provenance/explain engine (Compiler 2).
#[derive(Debug, Clone, PartialEq)]
pub enum ExplainIr {
    BuildCausalSubGraph { target: EventId },
    ExtractCsrCoordinates { matrix_id: u64 },
    InvertSparseMatrixLinear,
}

/// A node in the physical operator DAG.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionNode {
    pub node_id: u64,
    pub operation: PhysicalIr,
    pub dependencies: Vec<u64>,
}

impl ExecutionNode {
    pub fn new(node_id: u64, operation: PhysicalIr, dependencies: Vec<u64>) -> Self {
        Self { node_id, operation, dependencies }
    }
}

/// A physical plan: nodes plus a check that dependencies are acyclic and refer
/// only to earlier-defined nodes (a valid topological order exists).
#[derive(Debug, Clone, Default)]
pub struct PhysicalPlan {
    pub nodes: Vec<ExecutionNode>,
}

impl PhysicalPlan {
    pub fn push(&mut self, node: ExecutionNode) {
        self.nodes.push(node);
    }

    /// True iff every dependency points at a node id defined before it — i.e.
    /// the plan is a DAG presented in topological order.
    pub fn is_well_formed(&self) -> bool {
        let mut defined = std::collections::HashSet::new();
        for n in &self.nodes {
            if n.dependencies.iter().any(|d| !defined.contains(d)) {
                return false;
            }
            defined.insert(n.node_id);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_dag_accepted_cycle_rejected() {
        let mut p = PhysicalPlan::default();
        p.push(ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![0, 1] }, vec![]));
        p.push(ExecutionNode::new(1, PhysicalIr::VectorFilter { predicate_id: 7 }, vec![0]));
        p.push(ExecutionNode::new(2, PhysicalIr::VectorAggregate { keys: vec![0], aggregations: vec![1] }, vec![1]));
        assert!(p.is_well_formed());

        // Forward reference (node 0 depends on not-yet-defined node 9) → invalid.
        let mut bad = PhysicalPlan::default();
        bad.push(ExecutionNode::new(0, PhysicalIr::ColumnScan { projection: vec![] }, vec![9]));
        assert!(!bad.is_well_formed());
    }
}
