//! The H-VM interpreter — a pure, deterministic left-fold reducer (M20.0).
//!
//! Design thesis (SPEC-HVM-001 / `docs/md/M20_hvm_fractal_gpu.md`): the physical
//! state `S` is not "the saved data" — it is the accumulator of a deterministic
//! left-fold of an immutable instruction stream. [`ConsistencyVirtualMachine::
//! reduce_step`] is therefore a pure function `(S_t, Inst) -> S_{t+1}` with no
//! wall-clock reads, no unseeded RNG and no timing-dependent allocation — the
//! same discipline the `View` trait (`heraclitus-views`) already mandates.
//!
//! Two executions over the same instructions, applied in the same canonical LSN
//! order, must converge on a **bit-for-bit identical** state regardless of how
//! the stream was chunked or reordered in transit. That is the M20.0 gate.

use crate::{EventId, Lsn};
use std::collections::BTreeMap;

/// Schema version of the machine. Two folds are only comparable when they run
/// the same `VmVersion` — the bytecode semantics are versioned, never mutated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmVersion(pub u16);

/// A decoded H-VM instruction — the in-memory form of the log bytecode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmInstruction {
    /// `OP_UPSERT_LE` — inject/replace a key/value in the ledger data space.
    Upsert {
        key: Vec<u8>,
        val: Vec<u8>,
        lsn: Lsn,
        ev_id: EventId,
    },
    /// `OP_DELETE_LE` — logically remove a key (obliterate future visibility).
    Delete {
        key: Vec<u8>,
        lsn: Lsn,
        ev_id: EventId,
    },
    /// `OP_SPLIT_LT` — split a logical shard range and update the routing table.
    SplitShard {
        shard_id: usize,
        split_key: Vec<u8>,
        new_shard_id: usize,
        lsn: Lsn,
    },
}

impl VmInstruction {
    /// The LSN this instruction carries — its position in the canonical order.
    pub fn lsn(&self) -> Lsn {
        match self {
            VmInstruction::Upsert { lsn, .. }
            | VmInstruction::Delete { lsn, .. }
            | VmInstruction::SplitShard { lsn, .. } => *lsn,
        }
    }
}

/// The accumulator: the entire physical state is a fold of the instruction log.
/// `BTreeMap`s (not hash maps) keep iteration order canonical for hashing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmState {
    /// LSN of the instruction applied last.
    pub current_lsn: Lsn,
    /// Highest LSN ever applied (monotonic; the consistency point).
    pub max_lsn_applied: Lsn,
    /// The materialized key/value space.
    pub memory_layers: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Stable shard boundaries (range routing), rebuilt deterministically.
    pub active_routing_table: BTreeMap<Vec<u8>, usize>,
}

/// The consistency virtual machine: a versioned, pure reducer. It holds no
/// mutable state of its own — the state lives in [`VmState`] and flows through
/// the fold.
pub struct ConsistencyVirtualMachine {
    pub version: VmVersion,
}

impl ConsistencyVirtualMachine {
    pub fn new(version: VmVersion) -> Self {
        Self { version }
    }

    /// THE CANONICAL REDUCER (R): a pure `(S_t, Inst) -> S_{t+1}` transition.
    /// Deterministic and free of OS/timing effects by construction.
    #[inline]
    pub fn reduce_step(&self, mut state: VmState, instr: VmInstruction) -> VmState {
        match instr {
            VmInstruction::Upsert { key, val, lsn, .. } => {
                state.current_lsn = lsn;
                state.max_lsn_applied = state.max_lsn_applied.max(lsn);
                state.memory_layers.insert(key, val);
            }
            VmInstruction::Delete { key, lsn, .. } => {
                state.current_lsn = lsn;
                state.max_lsn_applied = state.max_lsn_applied.max(lsn);
                state.memory_layers.remove(&key);
            }
            VmInstruction::SplitShard {
                split_key,
                new_shard_id,
                lsn,
                ..
            } => {
                state.current_lsn = lsn;
                state.max_lsn_applied = state.max_lsn_applied.max(lsn);
                // Spatial rebalancing is just an edit to the VM's logical routing
                // registers — reproduced bit-for-bit from the topology log.
                state.active_routing_table.insert(split_key, new_shard_id);
            }
        }
        state
    }

    /// Fold an entire instruction stream from an initial state — convenience
    /// over `stream.into_iter().fold(state, |s, i| vm.reduce_step(s, i))`.
    pub fn run(&self, state: VmState, stream: impl IntoIterator<Item = VmInstruction>) -> VmState {
        stream
            .into_iter()
            .fold(state, |acc, inst| self.reduce_step(acc, inst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a deterministic Upsert with a stable, content-derived ULID so the
    /// test never depends on wall-clock or randomness.
    fn upsert(lsn: Lsn, key_id: u64) -> VmInstruction {
        let mut raw = [0u8; 16];
        raw[8..16].copy_from_slice(&(key_id + 8888).to_be_bytes());
        VmInstruction::Upsert {
            key: format!("cpf_{key_id:011}").into_bytes(),
            val: vec![0x01, 0x02, 0x03],
            lsn,
            ev_id: EventId(ulid::Ulid::from_bytes(raw)),
        }
    }

    /// THE M20.0 GATE (execution-equivalence theorem): a straight sequential
    /// fold and a scrambled-then-canonically-ordered fold land on a bit-for-bit
    /// identical state. The reducer's purity is what makes consistency immune to
    /// transport reordering or local RAM inversions.
    #[test]
    fn vm_execution_equivalence_under_reorder() {
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        let stream: Vec<VmInstruction> = (1..1000u64).map(|i| upsert(i, i)).collect();

        // Alpha: straight sequential fold.
        let alpha = vm.run(VmState::default(), stream.clone());

        // Beta: simulate fragmented concurrent traffic with forced reordering,
        // then apply the ISA's compulsory canonical ordering (by LSN) before the
        // fold. The theorem requires the accumulator to coagulate identically.
        let mut scrambled = stream.clone();
        scrambled.swap(50, 60);
        scrambled.swap(200, 300);
        scrambled.sort_by_key(|i| i.lsn());
        let beta = vm.run(VmState::default(), scrambled);

        assert_eq!(alpha.max_lsn_applied, beta.max_lsn_applied);
        assert_eq!(alpha.current_lsn, beta.current_lsn);
        assert_eq!(
            alpha.memory_layers, beta.memory_layers,
            "the consistency VM diverged between executions"
        );
        assert_eq!(alpha, beta, "full state must be bit-for-bit identical");
    }

    #[test]
    fn upsert_then_delete_removes_key() {
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        let s = vm.run(
            VmState::default(),
            [
                upsert(1, 42),
                VmInstruction::Delete {
                    key: b"cpf_00000000042".to_vec(),
                    lsn: 2,
                    ev_id: EventId::new(),
                },
            ],
        );
        assert!(s.memory_layers.is_empty(), "delete obliterates the key");
        assert_eq!(s.max_lsn_applied, 2);
        assert_eq!(s.current_lsn, 2);
    }

    #[test]
    fn split_updates_routing_table() {
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        let s = vm.reduce_step(
            VmState::default(),
            VmInstruction::SplitShard {
                shard_id: 0,
                split_key: b"m".to_vec(),
                new_shard_id: 1,
                lsn: 7,
            },
        );
        assert_eq!(s.active_routing_table.get(b"m".as_slice()), Some(&1));
        assert_eq!(s.max_lsn_applied, 7);
    }
}
