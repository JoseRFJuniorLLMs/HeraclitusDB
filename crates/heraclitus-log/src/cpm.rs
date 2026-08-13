//! CPM — Canonical Persistence Model (CPM-100/200/300/500).
//!
//! Physical realization of the `docs/md/pesquisar_FlatBuffers_rkyv.md` (CPM)
//! specification suite. This module is **additive and isolated**: it implements
//! the CPM *record* primitives (Canonical Record Format v2, CRC32C Castagnoli,
//! TLV variable metadata, canonical little-endian encoding and the BLAKE3 Merkle
//! leaf rule) as a self-contained, fully-tested codec. It does **not** touch the
//! live [`crate::format`] write/read path — the crown-jewel append-only log
//! keeps writing FORMAT_VERSION 4 until a deliberate, separately-reviewed v5
//! cutover wires this codec into `LogBackend`.
//!
//! Reuses (unchanged, already spec-compliant): [`crate::format::SegmentHeader`]
//! (CPM-100 §3, 22 B, magic `HRKL`) and [`crate::format::SegmentFooter`]
//! (CPM-100 §3, 60 B, magic `HFTR`, blake3 root). The delta this module adds is
//! strictly the richer **CRF v2 record** layout and the CRC32C lane.
//!
//! ## CRF v2 physical layout (CPM-100 §2)
//!
//! ```text
//! Record Header (32 B)                Fixed Metadata (32 B)
//! 0x00 crc32c        u32              0x20 var_metadata_len u32
//! 0x04 record_size   u32              0x24 payload_len      u32
//! 0x08 lsn           u64              0x28 event_id         [u8;16]
//! 0x10 hlc_timestamp u64              0x38 knowledge_ver    u16
//! 0x18 header_len    u16              0x3A ontology_ver     u16
//! 0x1A reserved      u16              0x3C confidence_raw   u16
//! 0x1C flags         u32              0x3E alignment_pad    u16
//! ── fixed prefix ends at 0x40 (64 B) ──
//! 0x40                 var_metadata   (TLV, var_metadata_len bytes)
//! 0x40+var_len         pristine_payload (payload_len bytes)
//! ```
//!
//! ### Spec deviations (deliberate — the doc contradicts itself)
//! * The prose calls Fixed Metadata "24 B" and `header_len` "56 B", but the
//!   authoritative offset table runs the fixed fields from `0x00`..`0x40`, i.e.
//!   **64 B** (Record Header 32 B + Fixed Metadata 32 B). We follow the offset
//!   table and stamp `header_len = 64`. The "24/56" figures are a spec typo.
//! * The Merkle-leaf formula literally writes `RecordHeader[4..28]`, which would
//!   drop `flags` (0x1C..0x20) from the authenticated region — a retroactive
//!   fraud hole (flip the `deleted` bit without moving the root). CPM-200's own
//!   sentence says to exclude *only* the 4 crc32c bytes, so we authenticate
//!   `record[4..record_size]` (everything but crc32c), matching the existing
//!   v2+ philosophy in [`crate::format`]. `[4..28]` is treated as a typo.

use blake3;

/// Record Header size (CPM-100 §2, offsets `0x00`..`0x20`).
pub const RECORD_HEADER_LEN: usize = 32;
/// Fixed Metadata size (offsets `0x20`..`0x40`).
pub const FIXED_META_LEN: usize = 32;
/// Fixed prefix = Record Header + Fixed Metadata (`0x00`..`0x40`).
pub const FIXED_PREFIX_LEN: usize = RECORD_HEADER_LEN + FIXED_META_LEN; // 64
/// Segments roll at 256 MB (CPM-100 §3); one record can never exceed this.
pub const MAX_RECORD_SIZE: usize = 512 * 1024 * 1024;

// ---- flags bitmask (CPM-300 §1) ---------------------------------------------
pub const FLAG_COMPRESSED: u32 = 1 << 0;
pub const FLAG_ENCRYPTED: u32 = 1 << 1;
pub const FLAG_DELETED: u32 = 1 << 2;
pub const FLAG_CHECKSUM_ALG: u32 = 1 << 4;
pub const FLAG_PAYLOAD_CODEC: u32 = 1 << 5;
pub const FLAG_METADATA_CODEC: u32 = 1 << 6;

// ---- canonical TLV tags (CPM-300 §2) ----------------------------------------
pub const TLV_CAUSAL_PARENTS: u16 = 0x0001;
pub const TLV_GEOMETRIC_EMBEDDINGS: u16 = 0x0002;
pub const TLV_LEGAL_DIGITAL_RECEIPT: u16 = 0x0003;
pub const TLV_ORIGIN_TENANT_ID: u16 = 0x0004;

/// One Type-Length-Value field in the variable-metadata zone (CPM-300 §2).
/// An unknown `tag` is skipped by length on decode, never rejected — this is
/// what gives the format "infinite" forward-compatible extensibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(tag: u16, value: impl Into<Vec<u8>>) -> Self {
        Self { tag, value: value.into() }
    }
}

/// A decoded / to-be-encoded Canonical Record (CRF v2). `event_id` is 16 raw
/// canonical bytes (CPM-500), decoupled from any higher-level id type so the
/// codec stays dependency-light and independently testable.
#[derive(Debug, Clone, PartialEq)]
pub struct CpmRecord {
    pub lsn: u64,
    pub hlc: u64,
    pub flags: u32,
    pub event_id: [u8; 16],
    pub knowledge_ver: u16,
    pub ontology_ver: u16,
    /// Raw semantic precision; normalize with [`CpmRecord::confidence`].
    pub confidence_raw: u16,
    pub tlvs: Vec<Tlv>,
    /// Pristine payload — the original captured log bytes, stored verbatim
    /// (CPM-200-INV-001: never normalized/reordered after ingestion).
    pub payload: Vec<u8>,
}

impl CpmRecord {
    /// `confidence_raw / u16::MAX` (CPM-100, `0x3C`).
    pub fn confidence(&self) -> f32 {
        self.confidence_raw as f32 / u16::MAX as f32
    }

    /// Serialize the TLV zone into its canonical byte form: `tag u16 | len u32 |
    /// value` per field, concatenated in order.
    fn encode_tlvs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for t in &self.tlvs {
            out.extend_from_slice(&t.tag.to_le_bytes());
            out.extend_from_slice(&(t.value.len() as u32).to_le_bytes());
            out.extend_from_slice(&t.value);
        }
        out
    }

    /// Encode a full CRF v2 record. Stamps `record_size`, `header_len` (64) and
    /// the CRC32C over the authenticated region (`record[4..record_size]`).
    pub fn encode(&self) -> Vec<u8> {
        let var = self.encode_tlvs();
        let total = FIXED_PREFIX_LEN + var.len() + self.payload.len();
        let mut buf = vec![0u8; FIXED_PREFIX_LEN];
        // Record Header
        // [0..4] crc32c — filled last
        buf[4..8].copy_from_slice(&(total as u32).to_le_bytes()); // record_size
        buf[8..16].copy_from_slice(&self.lsn.to_le_bytes());
        buf[16..24].copy_from_slice(&self.hlc.to_le_bytes());
        buf[24..26].copy_from_slice(&(FIXED_PREFIX_LEN as u16).to_le_bytes()); // header_len
        // [26..28] reserved = 0
        buf[28..32].copy_from_slice(&self.flags.to_le_bytes());
        // Fixed Metadata
        buf[32..36].copy_from_slice(&(var.len() as u32).to_le_bytes()); // var_metadata_len
        buf[36..40].copy_from_slice(&(self.payload.len() as u32).to_le_bytes()); // payload_len
        buf[40..56].copy_from_slice(&self.event_id);
        buf[56..58].copy_from_slice(&self.knowledge_ver.to_le_bytes());
        buf[58..60].copy_from_slice(&self.ontology_ver.to_le_bytes());
        buf[60..62].copy_from_slice(&self.confidence_raw.to_le_bytes());
        // [62..64] alignment_pad = 0
        buf.extend_from_slice(&var);
        buf.extend_from_slice(&self.payload);
        let crc = crc32c(&buf[4..]); // authenticated region: everything but crc32c
        buf[..4].copy_from_slice(&crc.to_le_bytes());
        buf
    }
}

/// Result of decoding one CRF v2 record from the head of a byte slice.
pub enum CpmDecoded {
    /// A valid record and the total bytes it consumed (`record_size`).
    Record(CpmRecord, usize),
    /// Short buffer, out-of-range length, CRC mismatch or malformed TLV —
    /// caller truncates here (CPM-400 torn-write handling).
    Torn,
}

/// BLAKE3 Merkle leaf for a CRF v2 record (CPM-200 §3): hash over the
/// authenticated region = all record bytes except the 4-byte `crc32c`
/// (`record[4..record_size]`). Writer, recovery and the receipt verifier MUST
/// use this exact definition or segment roots diverge. `record` must be at
/// least `record_size` bytes.
pub fn record_leaf(record: &[u8]) -> [u8; 32] {
    let size = u32::from_le_bytes(record[4..8].try_into().unwrap()) as usize;
    *blake3::hash(&record[4..size]).as_bytes()
}

/// Decode the CRF v2 record starting at `buf[0]`. Pure function (fuzz target).
/// Validates CRC32C over the authenticated region, so a flip in ANY field but
/// the crc yields [`CpmDecoded::Torn`] instead of a silently accepted record.
pub fn decode_record(buf: &[u8]) -> CpmDecoded {
    if buf.len() < FIXED_PREFIX_LEN {
        return CpmDecoded::Torn;
    }
    let stored_crc = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let record_size = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if !(FIXED_PREFIX_LEN..=MAX_RECORD_SIZE).contains(&record_size) {
        return CpmDecoded::Torn;
    }
    let var_len = u32::from_le_bytes(buf[32..36].try_into().unwrap()) as usize;
    let payload_len = u32::from_le_bytes(buf[36..40].try_into().unwrap()) as usize;
    // The three length fields must agree — a mismatch is a torn/forged record.
    if FIXED_PREFIX_LEN + var_len + payload_len != record_size {
        return CpmDecoded::Torn;
    }
    if buf.len() < record_size {
        return CpmDecoded::Torn;
    }
    if crc32c(&buf[4..record_size]) != stored_crc {
        return CpmDecoded::Torn;
    }
    let var_start = FIXED_PREFIX_LEN;
    let payload_start = var_start + var_len;
    let tlvs = match parse_tlvs(&buf[var_start..payload_start]) {
        Some(t) => t,
        None => return CpmDecoded::Torn,
    };
    let rec = CpmRecord {
        lsn: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        hlc: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        flags: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        event_id: buf[40..56].try_into().unwrap(),
        knowledge_ver: u16::from_le_bytes(buf[56..58].try_into().unwrap()),
        ontology_ver: u16::from_le_bytes(buf[58..60].try_into().unwrap()),
        confidence_raw: u16::from_le_bytes(buf[60..62].try_into().unwrap()),
        tlvs,
        payload: buf[payload_start..record_size].to_vec(),
    };
    CpmDecoded::Record(rec, record_size)
}

/// Parse the TLV zone. Returns `None` if any field is truncated (torn write).
/// Unknown tags are preserved verbatim (skipped by length, never rejected).
fn parse_tlvs(mut buf: &[u8]) -> Option<Vec<Tlv>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 6 {
            return None; // partial tag/len header
        }
        let tag = u16::from_le_bytes(buf[..2].try_into().unwrap());
        let len = u32::from_le_bytes(buf[2..6].try_into().unwrap()) as usize;
        let end = 6usize.checked_add(len)?;
        if buf.len() < end {
            return None; // value truncated
        }
        out.push(Tlv { tag, value: buf[6..end].to_vec() });
        buf = &buf[end..];
    }
    Some(out)
}

// ---- CPM-200 §2 physical lane: CRC32C Castagnoli (poly 0x1EDC6F41) ----------

/// Reflected CRC-32C (iSCSI/Castagnoli) lookup table, built at compile time from
/// the reflected polynomial `0x82F63B78`.
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Streaming CRC-32C (Castagnoli) hasher, mirroring `crc32fast::Hasher` so the
/// physical-integrity lane reads symmetrically at the call site and can cover a
/// discontiguous authenticated region without allocating. Feeding several
/// slices with [`Crc32c::update`] yields the same result as hashing their
/// concatenation.
#[derive(Clone)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    pub fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.0;
        for &b in data {
            crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        self.0 = crc;
    }

    pub fn finalize(self) -> u32 {
        !self.0
    }
}

/// CRC-32C (Castagnoli) of a single slice. Standard init/final XOR of
/// `0xFFFF_FFFF`. Check value: `crc32c(b"123456789") == 0xE306_9283`.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut h = Crc32c::new();
    h.update(data);
    h.finalize()
}

// ---- CPM-500 canonical primitive encoding (length-prefixed, UTF-8, LE) ------

/// Canonical `string` (CPM-500): `u32` LE byte-length + UTF-8 bytes, no NUL.
pub fn encode_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

/// Decode a canonical `string`, returning `(value, bytes_consumed)`.
pub fn decode_string(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    let end = 4usize.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    let s = std::str::from_utf8(&buf[4..end]).ok()?.to_owned();
    Some((s, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        // Canonical CRC-32C check value.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0x0000_0000);
    }

    #[test]
    fn crc32c_streaming_equals_oneshot() {
        // Feeding a discontiguous region in pieces == hashing the concatenation
        // (this is what the v5 record CRC relies on: len ‖ lsn+hlc+payload).
        let mut h = Crc32c::new();
        h.update(b"12345");
        h.update(b"6789");
        assert_eq!(h.finalize(), crc32c(b"123456789"));
    }

    fn sample() -> CpmRecord {
        CpmRecord {
            lsn: 14_812_346,
            hlc: 1_782_467_794_979_937,
            flags: FLAG_DELETED | FLAG_PAYLOAD_CODEC,
            event_id: *b"0123456789abcdef",
            knowledge_ver: 7,
            ontology_ver: 9,
            confidence_raw: (0.972 * u16::MAX as f32) as u16,
            tlvs: vec![
                Tlv::new(TLV_CAUSAL_PARENTS, vec![1u8; 16]),
                Tlv::new(TLV_ORIGIN_TENANT_ID, b"tenant-gov-br".to_vec()),
            ],
            payload: b"2026-... FATAL: permission denied for table users".to_vec(),
        }
    }

    #[test]
    fn round_trip_all_fields_and_pristine_payload() {
        let rec = sample();
        let bytes = rec.encode();
        // header_len field stamped to the true fixed prefix (64), not the spec typo.
        assert_eq!(u16::from_le_bytes(bytes[24..26].try_into().unwrap()) as usize, FIXED_PREFIX_LEN);
        match decode_record(&bytes) {
            CpmDecoded::Record(got, consumed) => {
                assert_eq!(consumed, bytes.len());
                assert_eq!(got, rec);
                assert!((got.confidence() - 0.972).abs() < 1e-3);
            }
            CpmDecoded::Torn => panic!("valid record decoded as Torn"),
        }
    }

    #[test]
    fn unknown_tlv_tag_is_preserved_not_rejected() {
        let mut rec = sample();
        rec.tlvs.push(Tlv::new(0xBEEF, b"future dimension".to_vec()));
        let bytes = rec.encode();
        match decode_record(&bytes) {
            CpmDecoded::Record(got, _) => {
                assert!(got.tlvs.iter().any(|t| t.tag == 0xBEEF && t.value == b"future dimension"));
                // pristine payload still readable past the unknown tag
                assert_eq!(got.payload, rec.payload);
            }
            CpmDecoded::Torn => panic!("unknown TLV tag must be skipped, not rejected"),
        }
    }

    #[test]
    fn tamper_any_authenticated_byte_is_caught() {
        let bytes = sample().encode();
        // Flip a bit in every authenticated position (everything but crc32c[0..4]).
        for i in 4..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(
                matches!(decode_record(&t), CpmDecoded::Torn),
                "tamper at offset {i} slipped through CRC32C"
            );
        }
    }

    #[test]
    fn tamper_moves_merkle_leaf() {
        let bytes = sample().encode();
        let leaf0 = record_leaf(&bytes);
        let mut t = bytes.clone();
        t[40] ^= 0x01; // flip a byte of event_id
        // recompute crc so it passes the physical lane, proving the *crypto* lane still catches it
        let size = u32::from_le_bytes(t[4..8].try_into().unwrap()) as usize;
        let crc = crc32c(&t[4..size]);
        t[..4].copy_from_slice(&crc.to_le_bytes());
        assert_ne!(leaf0, record_leaf(&t), "Merkle leaf must change when a field is altered");
    }

    #[test]
    fn truncated_and_length_mismatch_are_torn() {
        let bytes = sample().encode();
        assert!(matches!(decode_record(&bytes[..FIXED_PREFIX_LEN - 1]), CpmDecoded::Torn));
        assert!(matches!(decode_record(&bytes[..bytes.len() - 1]), CpmDecoded::Torn));
        // corrupt payload_len so the three length fields disagree
        let mut t = bytes.clone();
        t[36] ^= 0xFF;
        assert!(matches!(decode_record(&t), CpmDecoded::Torn));
    }

    #[test]
    fn empty_var_and_payload_round_trip() {
        let rec = CpmRecord {
            lsn: 1,
            hlc: 2,
            flags: 0,
            event_id: [0u8; 16],
            knowledge_ver: 0,
            ontology_ver: 0,
            confidence_raw: 0,
            tlvs: vec![],
            payload: vec![],
        };
        let bytes = rec.encode();
        assert_eq!(bytes.len(), FIXED_PREFIX_LEN);
        match decode_record(&bytes) {
            CpmDecoded::Record(got, n) => {
                assert_eq!(n, FIXED_PREFIX_LEN);
                assert_eq!(got, rec);
            }
            CpmDecoded::Torn => panic!("empty record must round-trip"),
        }
    }

    #[test]
    fn canonical_string_round_trips() {
        let enc = encode_string("evidência priscina");
        let (s, n) = decode_string(&enc).unwrap();
        assert_eq!(s, "evidência priscina");
        assert_eq!(n, enc.len());
        assert!(decode_string(&enc[..2]).is_none());
    }
}
