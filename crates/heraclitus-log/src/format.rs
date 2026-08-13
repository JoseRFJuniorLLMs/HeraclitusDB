//! Binary segment format. Spec: `docs/LOG_FORMAT.md`. Version byte mandatory.
//!
//! ```text
//! [Segment Header: magic "HRKL" | format_version u16 | segment_id u64 | created_hlc u64]
//! [Record]* where Record = [len u32][crc32 u32][lsn u64][hlc u64][payload]
//! [Footer on seal: magic "HFTR" | record_count u64 | min_lsn u64 | max_lsn u64 | blake3_root [32]]
//! ```
//!
//! All integers little-endian. `len` is the payload length. A record length
//! can never reach the footer magic value because segments roll at 256 MB.
//!
//! ## Per-record integrity coverage (format versions)
//!
//! The byte layout is identical across versions; only what the CRC and the
//! Merkle leaf are computed *over* changed:
//!
//! - **v1:** `crc32` and the Merkle leaf cover the **payload only**. The header
//!   fields `len`/`lsn`/`hlc` are unprotected — a byte flip there is not caught
//!   by `verify()` and does not move the segment root (a retroactive-fraud hole
//!   for the RFC-3161 timestamp argument).
//! - **v2 (current):** `crc32` and the Merkle leaf cover the **full
//!   authenticated region** — `len + lsn + hlc + payload` (everything but the
//!   `crc32` field itself). A flip in any header field is detected on decode
//!   (CRC mismatch → `Torn`) and changes the sealed segment's Merkle root.
//!
//! Readers pick the rule from the segment header's `format_version`, so v1
//! segments on disk stay readable. New segments are always written at the
//! current version; reopening an older-version unsealed tail seals it and
//! continues in a fresh current-version segment (see `Log::open`).

use heraclitus_core::{HeraclitusError, Lsn, SegmentId};

pub const MAGIC: [u8; 4] = *b"HRKL";
pub const FOOTER_MAGIC: [u8; 4] = *b"HFTR";
/// Bumped 1 → 2: CRC and Merkle leaf now cover the full record header, not
/// just the payload. v1 segments remain readable.
/// Bumped 2 → 3: StoragePayload now persists the full Episode (id, session_id,
/// kind, embedding, attrs, parents) — the log is the complete source of truth.
/// Bumped 3 → 4: native bi-temporal Valid Time — StoragePayload carries the
/// episode's `valid_from`/`valid_to` (world time, SQL:2011-style), orthogonal
/// to the LSN/HLC transaction time. v2 and v3 segments remain readable
/// (per-version payload decode in `decode_episode_payload`).
/// Bumped 4 → 5: the per-record physical-corruption lane switches from
/// CRC-32/ISO-HDLC (`crc32fast`) to **CRC-32C Castagnoli** (poly `0x1EDC6F41`),
/// the CPM-200 §2 mandated checksum. The authenticated region, the payload
/// layout (`StoragePayload`) and the BLAKE3 Merkle leaf are unchanged — only
/// the CRC algorithm differs, dispatched by the segment's `format_version`, so
/// v2–v4 segments (including the live memory log) stay readable under their
/// original crc32fast lane. See `crate::cpm` for the canonical codec.
pub const FORMAT_VERSION: u16 = 5;
pub const HEADER_LEN: usize = 4 + 2 + 8 + 8;
pub const RECORD_HEADER_LEN: usize = 4 + 4 + 8 + 8;
pub const FOOTER_LEN: usize = 4 + 8 + 8 + 8 + 32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SegmentHeader {
    pub version: u16,
    pub segment_id: SegmentId,
    pub created_hlc: u64,
}

impl SegmentHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..14].copy_from_slice(&self.segment_id.to_le_bytes());
        buf[14..22].copy_from_slice(&self.created_hlc.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, HeraclitusError> {
        if buf.len() < HEADER_LEN || buf[..4] != MAGIC {
            return Err(HeraclitusError::Corruption {
                context: "segment header".into(),
                detail: "bad magic or short header".into(),
            });
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        // SPEC-029 wired: a validação passa pelo negociador formal de versões.
        // O u16 do disco mapeia para (major=version, minor=0, flags=0); um
        // major mais novo que o suportado é rejeição dura (nunca interpretar
        // bytes que este binário não entende); minor/flags ficam prontos para
        // quando o header os carregar. Bytes no disco: INTOCADOS.
        use heraclitus_core::format_version::{Compatibility, StorageFormatVersion};
        let on_disk = StorageFormatVersion::new(version, 0, 0);
        let supported = StorageFormatVersion::new(FORMAT_VERSION, 0, 0);
        match on_disk.negotiate(supported, 0) {
            Compatibility::Reject(reason) if version > FORMAT_VERSION => {
                return Err(HeraclitusError::Corruption {
                    context: "segment header".into(),
                    detail: format!("format negotiation failed: {reason}"),
                });
            }
            // Major mais ANTIGO é legível por construção neste log (os decoders
            // v<=N são mantidos), por isso o Reject "needs migration" do
            // negociador genérico não se aplica aqui.
            _ => {}
        }
        Ok(Self {
            version,
            segment_id: u64::from_le_bytes(buf[6..14].try_into().unwrap()),
            created_hlc: u64::from_le_bytes(buf[14..22].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SegmentFooter {
    pub record_count: u64,
    pub min_lsn: Lsn,
    pub max_lsn: Lsn,
    pub blake3_root: [u8; 32],
}

impl SegmentFooter {
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut buf = [0u8; FOOTER_LEN];
        buf[..4].copy_from_slice(&FOOTER_MAGIC);
        buf[4..12].copy_from_slice(&self.record_count.to_le_bytes());
        buf[12..20].copy_from_slice(&self.min_lsn.to_le_bytes());
        buf[20..28].copy_from_slice(&self.max_lsn.to_le_bytes());
        buf[28..60].copy_from_slice(&self.blake3_root);
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < FOOTER_LEN || buf[..4] != FOOTER_MAGIC {
            return None;
        }
        Some(Self {
            record_count: u64::from_le_bytes(buf[4..12].try_into().unwrap()),
            min_lsn: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            max_lsn: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            blake3_root: buf[28..60].try_into().unwrap(),
        })
    }
}

/// Encode one record (header + payload) into a buffer, stamping the CRC for
/// the given format `version`. v1 protects only the payload; v2+ protects the
/// full authenticated region (`len + lsn + hlc + payload`) so a flip in any
/// header field is caught on decode.
pub fn encode_record(version: u16, lsn: Lsn, hlc: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // [0..4]   len
    buf.extend_from_slice(&[0u8; 4]); //                             [4..8]   crc (filled below)
    buf.extend_from_slice(&lsn.to_le_bytes()); //                    [8..16]  lsn
    buf.extend_from_slice(&hlc.to_le_bytes()); //                    [16..24] hlc
    buf.extend_from_slice(payload); //                               [24..]   payload
    let crc = authenticated_crc(version, &buf);
    buf[4..8].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// CRC over a record's authenticated region. The 4-byte CRC field at `[4..8]`
/// is never part of the input (it would be self-referential). v1 covers the
/// payload only (back-compat); v2–v4 cover `len + lsn + hlc + payload` under
/// CRC-32/ISO-HDLC (`crc32fast`); v5+ covers the same region under **CRC-32C
/// Castagnoli** (CPM-200 §2). The algorithm is chosen by the segment's
/// `format_version`, so older segments keep validating under their original
/// lane. `record` must be the full record bytes (`len >= RECORD_HEADER_LEN`).
fn authenticated_crc(version: u16, record: &[u8]) -> u32 {
    if version < 2 {
        crc32fast::hash(&record[RECORD_HEADER_LEN..])
    } else if version < 5 {
        let mut h = crc32fast::Hasher::new();
        h.update(&record[..4]); // len
        h.update(&record[8..]); // lsn + hlc + payload
        h.finalize()
    } else {
        // v5+ (CPM-200 §2): CRC-32C Castagnoli over the authenticated region.
        // The streaming hasher covers the discontiguous region (skipping the
        // crc field at [4..8]) without allocating.
        let mut h = crate::cpm::Crc32c::new();
        h.update(&record[..4]); // len
        h.update(&record[8..]); // lsn + hlc + payload
        h.finalize()
    }
}

/// Blake3 Merkle leaf for one record. This definition is shared by the writer
/// (`Log::append`), recovery (`verify`), and the cold-tier receipt verifier —
/// they MUST agree or roots diverge. v1: `blake3(payload)`. v2+: blake3 over
/// the same authenticated region the CRC covers (`len + lsn + hlc + payload`),
/// so a flip in `lsn`/`hlc`/`len` moves the sealed segment's Merkle root.
/// `record` must be the full record bytes (`len >= RECORD_HEADER_LEN`).
pub fn record_leaf(version: u16, record: &[u8]) -> [u8; 32] {
    if version < 2 {
        *blake3::hash(&record[RECORD_HEADER_LEN..]).as_bytes()
    } else {
        let mut h = blake3::Hasher::new();
        h.update(&record[..4]); // len
        h.update(&record[8..]); // lsn + hlc + payload
        *h.finalize().as_bytes()
    }
}

/// Result of decoding one record from a byte slice.
pub enum Decoded<'a> {
    /// A valid record: (lsn, hlc, payload, total bytes consumed).
    Record(Lsn, u64, &'a [u8], usize),
    /// A sealed-segment footer begins here.
    Footer(SegmentFooter),
    /// Not enough bytes / torn write — caller should truncate here.
    Torn,
}

/// Decode the record starting at `buf[0]` under format `version`. Pure
/// function — fuzz target. The CRC is validated over the version's
/// authenticated region (see [`authenticated_crc`]), so under v2+ a flip in
/// any header field (`len`/`lsn`/`hlc`) yields `Torn` instead of a silently
/// accepted, tampered record.
pub fn decode_record(version: u16, buf: &[u8]) -> Decoded<'_> {
    if buf.len() >= 4 && buf[..4] == FOOTER_MAGIC {
        return match SegmentFooter::decode(buf) {
            Some(f) => Decoded::Footer(f),
            None => Decoded::Torn,
        };
    }
    if buf.len() < RECORD_HEADER_LEN {
        return Decoded::Torn;
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    // Sanity bound: a single record cannot exceed the roll size.
    if len > 512 * 1024 * 1024 {
        return Decoded::Torn;
    }
    let crc = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let lsn = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let hlc = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let total = RECORD_HEADER_LEN + len;
    if buf.len() < total {
        return Decoded::Torn;
    }
    if authenticated_crc(version, &buf[..total]) != crc {
        return Decoded::Torn;
    }
    let payload = &buf[RECORD_HEADER_LEN..total];
    Decoded::Record(lsn, hlc, payload, total)
}
