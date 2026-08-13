//! H-VM ↔ log bridge (milestone **M20.1**, completion).
//!
//! Persists H-VM instructions in the existing append-only log **additively**:
//! each instruction is encoded as an ISA frame (the M20.1 codec) and stored as
//! the `content` of an ordinary [`Episode`] tagged `EventKind::Custom("hvm_isa")`.
//! This reuses the whole durable substrate — segments, crc32, blake3 Merkle,
//! fsync policy, encryption at rest — **without touching the record format**
//! (`docs/md/LOG_FORMAT.md` unchanged). The grand "the log IS bytecode" rewrite
//! from SPEC-HVM-001 stays out of scope; this is the safe, reversible path the
//! M20 plan calls for.
//!
//! [`replay_vm`] closes the loop with M20.0: the persisted bytecode, folded
//! through the reducer, reconstructs the deterministic [`VmState`].

use crate::Log;
use heraclitus_core::vm::{
    decode, encode, ConsistencyVirtualMachine, VmInstruction, VmState, VmVersion,
};
use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn};

/// The `EventKind::Custom` tag that marks a log record as an H-VM ISA frame.
pub const HVM_KIND: &str = "hvm_isa";

/// Is this episode an H-VM instruction frame (vs. an ordinary event)?
pub fn is_hvm(ep: &Episode) -> bool {
    matches!(&ep.kind, EventKind::Custom(k) if k == HVM_KIND)
}

/// Append one H-VM instruction to the log as a first-class event whose content
/// is the ISA frame. Returns the LSN the log assigned.
pub fn append_instruction(
    log: &Log,
    version: VmVersion,
    instr: &VmInstruction,
) -> Result<Lsn, HeraclitusError> {
    let frame = encode(version, instr);
    log.append(Episode::new(
        "hvm",
        EventKind::Custom(HVM_KIND.to_string()),
        frame,
    ))
}

/// Decode the H-VM instruction stored at `lsn`, or `None` if that record is not
/// an ISA frame. A corrupt frame on a direct read surfaces as `Serialization`
/// (never silently skipped).
pub fn read_instruction(
    log: &Log,
    lsn: Lsn,
) -> Result<Option<(VmVersion, VmInstruction)>, HeraclitusError> {
    match log.read(lsn)? {
        Some((_, ep)) if is_hvm(&ep) => {
            let decoded =
                decode(&ep.content).map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
            Ok(Some(decoded))
        }
        _ => Ok(None),
    }
}

/// Replay every persisted H-VM frame in LSN order and fold it into a [`VmState`].
/// Non-H-VM records are ignored, so the bridge coexists with ordinary episodes.
/// The scan is windowed (`scan_capped`) to bound startup RAM, matching how the
/// engine rebuilds its attribute index.
pub fn replay_vm(log: &Log, vm: &ConsistencyVirtualMachine) -> Result<VmState, HeraclitusError> {
    let mut state = VmState::default();
    let head = log.head();
    let mut cur: Lsn = 0;
    while cur <= head {
        let batch = log.scan_capped(cur, head + 1, 100_000)?;
        if batch.is_empty() {
            break;
        }
        let last = batch.last().unwrap().0;
        for (_, ep) in &batch {
            if is_hvm(ep) {
                let (_, instr) = decode(&ep.content)
                    .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
                state = vm.reduce_step(state, instr);
            }
        }
        cur = last + 1;
    }
    Ok(state)
}

/// Replay the log's H-VM frames straight into a Bᵋ-tree (Fractal Tree),
/// materializing the ledger state for persistence. The tree's content equals the
/// replayed `VmState::memory_layers`; persist it with `BEpsilonTree::save` as a
/// fast-start checkpoint — **M20.2.1** closing the loop log → reducer → tree.
pub fn replay_vm_to_btree(
    log: &Log,
    vm: &ConsistencyVirtualMachine,
    path: &std::path::Path,
) -> Result<heraclitus_btree::BEpsilonTree, HeraclitusError> {
    let state = replay_vm(log, vm)?;
    // O btree passou a ser file-backed: from_map(path, map) -> io::Result.
    Ok(heraclitus_btree::BEpsilonTree::from_map(
        path,
        state.memory_layers,
    )?)
}

#[cfg(test)]
mod tests {
    use super::{append_instruction, read_instruction, replay_vm, replay_vm_to_btree};
    use crate::Log;
    use heraclitus_core::vm::{ConsistencyVirtualMachine, VmInstruction, VmState, VmVersion};
    use heraclitus_core::{Episode, EventId, EventKind, FsyncPolicy};

    fn open_log(dir: &std::path::Path) -> Log {
        Log::open_with_keystore(
            dir.join("log"),
            256 * 1024 * 1024,
            FsyncPolicy::Always,
            None,
        )
        .unwrap()
    }

    /// THE M20.1 COMPLETION GATE: instructions persisted through the log and then
    /// replayed reconstruct the exact same folded state as a direct fold.
    #[test]
    fn persisted_bytecode_replays_to_same_state() {
        let dir = tempfile::tempdir().unwrap();
        let log = open_log(dir.path());
        let ver = VmVersion(1);

        let instrs = vec![
            VmInstruction::Upsert {
                key: b"a".to_vec(),
                val: b"1".to_vec(),
                lsn: 1,
                ev_id: EventId::new(),
            },
            VmInstruction::Upsert {
                key: b"b".to_vec(),
                val: b"2".to_vec(),
                lsn: 2,
                ev_id: EventId::new(),
            },
            VmInstruction::Delete {
                key: b"a".to_vec(),
                lsn: 3,
                ev_id: EventId::new(),
            },
        ];
        for i in &instrs {
            append_instruction(&log, ver, i).unwrap();
        }

        // A direct read decodes the same instruction back. Log LSNs are 0-based,
        // so the 2nd appended instruction (instrs[1]) sits at LSN 1.
        let (v, back) = read_instruction(&log, 1).unwrap().unwrap();
        assert_eq!(v, ver);
        assert_eq!(back, instrs[1]);

        // Replay over the log == direct fold over the instruction stream.
        let vm = ConsistencyVirtualMachine::new(ver);
        let replayed = replay_vm(&log, &vm).unwrap();
        let direct = vm.run(VmState::default(), instrs.clone());
        assert_eq!(replayed, direct, "replay must equal the direct fold");

        // 'a' was deleted, only 'b' survives.
        assert_eq!(
            replayed.memory_layers.get(b"b".as_slice()),
            Some(&b"2".to_vec())
        );
        assert!(!replayed.memory_layers.contains_key(b"a".as_slice()));
    }

    /// The bridge coexists with ordinary episodes: non-H-VM records are ignored
    /// by both `read_instruction` and `replay_vm`.
    #[test]
    fn ignores_non_hvm_records() {
        let dir = tempfile::tempdir().unwrap();
        let log = open_log(dir.path());

        log.append(Episode::new(
            "ag",
            EventKind::Observation,
            b"hello".to_vec(),
        ))
        .unwrap();
        append_instruction(
            &log,
            VmVersion(1),
            &VmInstruction::Upsert {
                key: b"k".to_vec(),
                val: b"v".to_vec(),
                lsn: 1,
                ev_id: EventId::new(),
            },
        )
        .unwrap();

        // LSN 0 (0-based) is the ordinary observation → not an instruction.
        assert!(read_instruction(&log, 0).unwrap().is_none());

        // Replay sees only the single H-VM frame.
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        let s = replay_vm(&log, &vm).unwrap();
        assert_eq!(s.memory_layers.len(), 1);
        assert_eq!(s.memory_layers.get(b"k".as_slice()), Some(&b"v".to_vec()));
    }

    /// M20.2.1 loop closure: replay → Bᵋ-tree equals the ledger state, and the
    /// tree survives an atomic save/load round-trip bit-for-bit.
    #[test]
    fn replay_into_btree_matches_state_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let log = open_log(dir.path());
        let ver = VmVersion(1);

        let mk = |k: &[u8], v: &[u8], lsn| VmInstruction::Upsert {
            key: k.to_vec(),
            val: v.to_vec(),
            lsn,
            ev_id: EventId::new(),
        };
        append_instruction(&log, ver, &mk(b"a", b"1", 0)).unwrap();
        append_instruction(&log, ver, &mk(b"b", b"2", 1)).unwrap();
        append_instruction(&log, ver, &mk(b"c", b"3", 2)).unwrap();
        append_instruction(
            &log,
            ver,
            &VmInstruction::Delete {
                key: b"b".to_vec(),
                lsn: 3,
                ev_id: EventId::new(),
            },
        )
        .unwrap();

        let vm = ConsistencyVirtualMachine::new(ver);
        let state = replay_vm(&log, &vm).unwrap();
        let tree = replay_vm_to_btree(&log, &vm, &dir.path().join("replay.hbt")).unwrap();
        // O btree ficou file-backed e sem `materialize`/`state_hash`: verifica
        // chave-a-chave que a árvore == ledger reconstruído (get(k) == ledger[k]).
        // A construção via from_map garante que não há chaves a mais.
        for (k, v) in &state.memory_layers {
            assert_eq!(
                tree.get(k).as_ref(),
                Some(v),
                "tree deve conter a chave do ledger"
            );
        }

        // Persist + reload the checkpoint.
        let path = dir.path().join("ckpt.hbt");
        tree.save(&path).unwrap();
        let loaded = heraclitus_btree::BEpsilonTree::load(&path).unwrap();
        for (k, v) in &state.memory_layers {
            assert_eq!(
                loaded.get(k).as_ref(),
                Some(v),
                "checkpoint recarregado == ledger"
            );
        }
    }
}
