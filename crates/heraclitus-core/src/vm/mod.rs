//! heraclitus-core::vm — the H-VM consistency core (milestone **M20.0**).
//!
//! See [`docs/md/M20_hvm_fractal_gpu.md`] (derived from SPEC-HVM-001). This is
//! the **CPU-only, deterministic foundation** of the Sovereignty Layer:
//!
//! - [`interpreter`] — a pure left-fold reducer `(S_t, Inst) -> S_{t+1}`. The
//!   physical state is the accumulator of a deterministic fold over an immutable
//!   instruction stream; no wall-clock, no RNG, no timing-dependent allocation.
//! - [`quantizer`] — the GPU→integer quantization barrier (`OP_QUANTIZE`) that
//!   makes approximate GPU floats ordinally stable across hardware.
//!
//! No GPU, no disk and no Fractal Tree here — those are M20.2 / M20.3. What
//! exists is verifiable: the execution-equivalence theorem is a unit test.

pub mod codec;
pub mod interpreter;
pub mod quantizer;

pub use codec::{decode, decode_stream, encode, VmCodecError};
pub use interpreter::{ConsistencyVirtualMachine, VmInstruction, VmState, VmVersion};
pub use quantizer::execute_op_quantize;

/// Canonical OpCode table (SPEC-HVM-001 §1): the 16-bit codes that head each
/// fixed-layout bytecode frame. The binary codec (encode/decode of the 8-byte
/// frame) lands in **M20.1**; M20.0 only fixes the numbers. `OP_MERGE_LT` has no
/// reducer arm yet — it is reserved here as part of the full ISA.
pub mod opcode {
    /// Inject/replace a key in the ledger data space.
    pub const OP_UPSERT_LE: u16 = 0x0001;
    /// Logically remove a key (obliterate future visibility).
    pub const OP_DELETE_LE: u16 = 0x0002;
    /// Split a logical shard range and update routing.
    pub const OP_SPLIT_LT: u16 = 0x0101;
    /// Merge two contiguous shards (reserved — no reducer arm in M20.0).
    pub const OP_MERGE_LT: u16 = 0x0102;
    /// Quantize a GPU float to a fixed-point integer (determinism barrier).
    pub const OP_QUANTIZE: u16 = 0x0201;
}
