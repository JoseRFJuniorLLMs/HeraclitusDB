use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::evidence::{sha256_file, write_bytes_new, write_json_new};
use crate::manifest::{CorruptionMode, CorruptionRecord};

fn next(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

pub fn inject(
    input: &Path,
    output: &Path,
    mode: CorruptionMode,
    seed: u64,
) -> Result<CorruptionRecord> {
    if output.exists() {
        bail!(
            "refusing to overwrite corruption output {}",
            output.display()
        );
    }
    let mut bytes =
        fs::read(input).with_context(|| format!("read corruption input {}", input.display()))?;
    if bytes.len() < 2 {
        bail!("corruption input must contain at least two bytes");
    }
    let input_size = bytes.len() as u64;
    let input_sha256 = sha256_file(input)?;
    let mut state = seed ^ 0xA076_1D64_78BD_642F;
    let offset = (next(&mut state) as usize) % bytes.len();
    let max_len = (bytes.len() - offset).clamp(1, 64);
    let length = 1 + (next(&mut state) as usize % max_len);

    let (record_offset, record_length) = match mode {
        CorruptionMode::FlipBit => {
            bytes[offset] ^= 1 << (next(&mut state) % 8);
            (Some(offset as u64), Some(1))
        }
        CorruptionMode::Truncate => {
            let new_len = offset.max(1);
            bytes.truncate(new_len);
            (Some(new_len as u64), Some(input_size - new_len as u64))
        }
        CorruptionMode::ZeroRange => {
            bytes[offset..offset + length].fill(0);
            (Some(offset as u64), Some(length as u64))
        }
        CorruptionMode::DuplicateRange => {
            let duplicate = bytes[offset..offset + length].to_vec();
            bytes.splice(offset..offset, duplicate);
            (Some(offset as u64), Some(length as u64))
        }
        CorruptionMode::RemoveRange => {
            bytes.drain(offset..offset + length);
            (Some(offset as u64), Some(length as u64))
        }
    };
    write_bytes_new(output, &bytes)?;
    let record = CorruptionRecord {
        schema_version: 1,
        mode,
        seed,
        input_sha256,
        output_sha256: sha256_file(output)?,
        input_size,
        output_size: bytes.len() as u64,
        offset: record_offset,
        length: record_length,
    };
    let record_path = output.with_extension(format!(
        "{}corruption.json",
        output
            .extension()
            .map(|extension| format!("{}.", extension.to_string_lossy()))
            .unwrap_or_default()
    ));
    write_json_new(&record_path, &record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corruption_is_deterministic_and_never_touches_input() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.bin");
        fs::write(&input, (0_u8..=127).collect::<Vec<_>>()).unwrap();
        let original = fs::read(&input).unwrap();
        let a = temp.path().join("a.bin");
        let b = temp.path().join("b.bin");
        let ra = inject(&input, &a, CorruptionMode::FlipBit, 9).unwrap();
        let rb = inject(&input, &b, CorruptionMode::FlipBit, 9).unwrap();
        assert_eq!(ra.output_sha256, rb.output_sha256);
        assert_eq!(fs::read(&input).unwrap(), original);
        assert_ne!(fs::read(a).unwrap(), original);
    }
}
