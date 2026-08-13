//! Binary codec for the H-VM ISA frame (milestone **M20.1**).
//!
//! Layout (SPEC-HVM-001 §1) — a fixed 8-byte header then a contiguous payload:
//!
//! ```text
//! 0x00..0x02  u16   OpCode
//! 0x02..0x04  u16   VM Schema Version
//! 0x04..0x08  u32   Payload length (L)
//! 0x08..0x08+L      Payload (opcode-specific arguments)
//! ```
//!
//! **Every integer is big-endian.** A canonical, platform-independent wire form
//! is the whole point: the same bytes must decode to the same instruction on any
//! CPU, so the H-VM fold ([`super::interpreter`]) stays bit-for-bit reproducible.
//! Length-prefixed (`u32` BE) byte fields make `key`/`val` unambiguous.

use super::interpreter::{VmInstruction, VmVersion};
use super::opcode;
use crate::EventId;

/// Size of the fixed frame header in bytes.
pub const HEADER_LEN: usize = 8;

/// Errors decoding an H-VM bytecode frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VmCodecError {
    /// The buffer is shorter than the frame declares.
    #[error("frame truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    /// The OpCode is not part of the known ISA.
    #[error("unknown opcode 0x{0:04x}")]
    UnknownOpcode(u16),
    /// The decoded instruction did not consume exactly the declared payload.
    #[error(
        "payload length mismatch for opcode 0x{op:04x}: declared {declared}, consumed {consumed}"
    )]
    LengthMismatch {
        op: u16,
        declared: usize,
        consumed: usize,
    },
}

/// Encode one instruction (with its schema version) into a self-describing frame.
pub fn encode(version: VmVersion, instr: &VmInstruction) -> Vec<u8> {
    let (op, payload) = encode_payload(instr);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&op.to_be_bytes());
    out.extend_from_slice(&version.0.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Decode exactly one frame from the front of `bytes`.
pub fn decode(bytes: &[u8]) -> Result<(VmVersion, VmInstruction), VmCodecError> {
    if bytes.len() < HEADER_LEN {
        return Err(VmCodecError::Truncated {
            need: HEADER_LEN,
            have: bytes.len(),
        });
    }
    let op = u16::from_be_bytes([bytes[0], bytes[1]]);
    let ver = u16::from_be_bytes([bytes[2], bytes[3]]);
    let len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let end = HEADER_LEN + len;
    if bytes.len() < end {
        return Err(VmCodecError::Truncated {
            need: end,
            have: bytes.len(),
        });
    }
    let instr = decode_payload(op, &bytes[HEADER_LEN..end])?;
    Ok((VmVersion(ver), instr))
}

/// Decode a contiguous buffer of back-to-back frames into a stream.
pub fn decode_stream(mut bytes: &[u8]) -> Result<Vec<(VmVersion, VmInstruction)>, VmCodecError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < HEADER_LEN {
            return Err(VmCodecError::Truncated {
                need: HEADER_LEN,
                have: bytes.len(),
            });
        }
        let len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let frame_end = HEADER_LEN + len;
        if bytes.len() < frame_end {
            return Err(VmCodecError::Truncated {
                need: frame_end,
                have: bytes.len(),
            });
        }
        out.push(decode(&bytes[..frame_end])?);
        bytes = &bytes[frame_end..];
    }
    Ok(out)
}

// ── payload (de)serialization ────────────────────────────────────────────────

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

fn encode_payload(instr: &VmInstruction) -> (u16, Vec<u8>) {
    let mut p = Vec::new();
    match instr {
        VmInstruction::Upsert {
            key,
            val,
            lsn,
            ev_id,
        } => {
            p.extend_from_slice(&lsn.to_be_bytes());
            p.extend_from_slice(&ev_id.0.to_bytes());
            put_bytes(&mut p, key);
            put_bytes(&mut p, val);
            (opcode::OP_UPSERT_LE, p)
        }
        VmInstruction::Delete { key, lsn, ev_id } => {
            p.extend_from_slice(&lsn.to_be_bytes());
            p.extend_from_slice(&ev_id.0.to_bytes());
            put_bytes(&mut p, key);
            (opcode::OP_DELETE_LE, p)
        }
        VmInstruction::SplitShard {
            shard_id,
            split_key,
            new_shard_id,
            lsn,
        } => {
            p.extend_from_slice(&lsn.to_be_bytes());
            p.extend_from_slice(&(*shard_id as u64).to_be_bytes());
            p.extend_from_slice(&(*new_shard_id as u64).to_be_bytes());
            put_bytes(&mut p, split_key);
            (opcode::OP_SPLIT_LT, p)
        }
    }
}

/// Cursor over a payload that fails closed on any short read.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], VmCodecError> {
        let end = self.pos.checked_add(n).ok_or(VmCodecError::Truncated {
            need: usize::MAX,
            have: self.b.len(),
        })?;
        if end > self.b.len() {
            return Err(VmCodecError::Truncated {
                need: end,
                have: self.b.len(),
            });
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, VmCodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, VmCodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn event_id(&mut self) -> Result<EventId, VmCodecError> {
        let raw: [u8; 16] = self.take(16)?.try_into().unwrap();
        Ok(EventId(ulid::Ulid::from_bytes(raw)))
    }
    fn var_bytes(&mut self) -> Result<Vec<u8>, VmCodecError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

fn decode_payload(op: u16, payload: &[u8]) -> Result<VmInstruction, VmCodecError> {
    let mut r = Reader::new(payload);
    let instr = match op {
        opcode::OP_UPSERT_LE => {
            let lsn = r.u64()?;
            let ev_id = r.event_id()?;
            let key = r.var_bytes()?;
            let val = r.var_bytes()?;
            VmInstruction::Upsert {
                key,
                val,
                lsn,
                ev_id,
            }
        }
        opcode::OP_DELETE_LE => {
            let lsn = r.u64()?;
            let ev_id = r.event_id()?;
            let key = r.var_bytes()?;
            VmInstruction::Delete { key, lsn, ev_id }
        }
        opcode::OP_SPLIT_LT => {
            let lsn = r.u64()?;
            let shard_id = r.u64()? as usize;
            let new_shard_id = r.u64()? as usize;
            let split_key = r.var_bytes()?;
            VmInstruction::SplitShard {
                shard_id,
                split_key,
                new_shard_id,
                lsn,
            }
        }
        other => return Err(VmCodecError::UnknownOpcode(other)),
    };
    if r.pos != payload.len() {
        return Err(VmCodecError::LengthMismatch {
            op,
            declared: payload.len(),
            consumed: r.pos,
        });
    }
    Ok(instr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{ConsistencyVirtualMachine, VmState};

    fn sample() -> Vec<VmInstruction> {
        vec![
            VmInstruction::Upsert {
                key: b"cpf_00000000042".to_vec(),
                val: vec![0xDE, 0xAD, 0xBE, 0xEF],
                lsn: 1,
                ev_id: EventId(ulid::Ulid::from_bytes([7u8; 16])),
            },
            VmInstruction::Delete {
                key: b"cpf_00000000042".to_vec(),
                lsn: 2,
                ev_id: EventId(ulid::Ulid::from_bytes([9u8; 16])),
            },
            VmInstruction::SplitShard {
                shard_id: 3,
                split_key: b"m".to_vec(),
                new_shard_id: 4,
                lsn: 3,
            },
        ]
    }

    #[test]
    fn header_layout_is_canonical() {
        let f = encode(
            VmVersion(0x0102),
            &VmInstruction::Delete {
                key: vec![],
                lsn: 0,
                ev_id: EventId(ulid::Ulid::from_bytes([0u8; 16])),
            },
        );
        // opcode (OP_DELETE_LE = 0x0002), version 0x0102, both big-endian.
        assert_eq!(&f[0..2], &[0x00, 0x02]);
        assert_eq!(&f[2..4], &[0x01, 0x02]);
        // payload len = lsn(8) + ulid(16) + key_len(4) + key(0) = 28.
        assert_eq!(&f[4..8], &28u32.to_be_bytes());
        assert_eq!(f.len(), HEADER_LEN + 28);
    }

    #[test]
    fn roundtrip_each_instruction() {
        for ins in sample() {
            let bytes = encode(VmVersion(1), &ins);
            let (ver, back) = decode(&bytes).unwrap();
            assert_eq!(ver, VmVersion(1));
            assert_eq!(back, ins);
        }
    }

    /// THE M20.1 GATE: encoding a whole stream and decoding it back yields the
    /// same instructions AND the same folded H-VM state — the codec is transparent
    /// to the M20.0 reducer.
    #[test]
    fn codec_roundtrip_preserves_fold() {
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        let stream: Vec<VmInstruction> = (1..200u64)
            .map(|i| VmInstruction::Upsert {
                key: format!("k{i:08}").into_bytes(),
                val: i.to_be_bytes().to_vec(),
                lsn: i,
                ev_id: EventId(ulid::Ulid::from_bytes([(i % 256) as u8; 16])),
            })
            .collect();

        let mut buf = Vec::new();
        for ins in &stream {
            buf.extend_from_slice(&encode(VmVersion(1), ins));
        }
        let decoded: Vec<VmInstruction> = decode_stream(&buf)
            .unwrap()
            .into_iter()
            .map(|(_, i)| i)
            .collect();
        assert_eq!(decoded, stream, "stream must survive the round-trip");

        let direct = vm.run(VmState::default(), stream.clone());
        let via_codec = vm.run(VmState::default(), decoded);
        assert_eq!(direct, via_codec, "fold over decoded == fold over original");
    }

    #[test]
    fn truncated_and_unknown_fail_closed() {
        let f = encode(VmVersion(1), &sample()[0]);
        // Chop the payload: header promises more than is present.
        assert!(matches!(
            decode(&f[..f.len() - 1]),
            Err(VmCodecError::Truncated { .. })
        ));
        // A header shorter than 8 bytes.
        assert!(matches!(
            decode(&[0u8; 4]),
            Err(VmCodecError::Truncated { .. })
        ));
        // Unknown opcode 0xFFFF with zero payload.
        let mut bad = Vec::new();
        bad.extend_from_slice(&0xFFFFu16.to_be_bytes());
        bad.extend_from_slice(&1u16.to_be_bytes());
        bad.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(decode(&bad), Err(VmCodecError::UnknownOpcode(0xFFFF)));
    }
}
