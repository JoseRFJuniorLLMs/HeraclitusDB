//! CPM-600 — Memory-Mapping Model. A read-only, zero-copy `mmap` view over a
//! sealed `.hrkl` segment, for analytical / query-time scans.
//!
//! CPM-600-DIR-001 (MUST): analytical segment maps are instantiated read-only
//! (`PROT_READ` + `MAP_SHARED`). CPM-600-DIR-002 (SHALL NOT): no write ever
//! touches an active read map — the map borrows an immutable, sealed segment,
//! so I-001 (the log is the single source of truth) cannot be corrupted by a
//! wild user-space pointer.
//!
//! This is **additive and isolated**: it does not touch the append or recovery
//! paths. It gives the read side a zero-copy alternative to the
//! `File`/`seek`/`read_exact` loop — records are yielded as slices straight out
//! of the page cache, with no per-record allocation or copy.
//!
//! ## Kernel hints (CPM-600 "Granularidade" / "NUMA")
//! `madvise` hints — `MADV_SEQUENTIAL`/`MADV_WILLNEED` for cache residency and
//! the spec's **Huge Pages** (`MADV_HUGEPAGE`, 2 MB/1 GB) — plus **NUMA**
//! affinity (binding scan threads to the node backing the file cache) are
//! Linux-only runtime tuning. They need either a newer `memmap2` `advise` API
//! or raw `libc`, so they are left as a documented deployment step rather than
//! pulled into this dependency-light, cross-platform crate. The core CPM-600
//! contract realized here is the read-only (`PROT_READ`/`MAP_SHARED`) zero-copy
//! mapping itself.

use crate::format::{self, Decoded, SegmentHeader, HEADER_LEN};
use heraclitus_core::{HeraclitusError, Lsn};
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

/// A read-only memory-mapped sealed segment (CPM-600).
pub struct MappedSegment {
    mmap: Mmap,
    /// `format_version` from the segment header — drives per-version decode.
    pub version: u16,
}

impl MappedSegment {
    /// Map a sealed segment read-only and validate its header.
    ///
    /// # Safety contract
    /// The caller must map only **sealed** (immutable) segments. `mmap` is
    /// unsafe because another process truncating the file underneath a live map
    /// is UB; sealed `.hrkl` files are never mutated in place by this engine, so
    /// the invariant holds.
    pub fn open(path: &Path) -> Result<Self, HeraclitusError> {
        let file = File::open(path).map_err(|e| HeraclitusError::Corruption {
            context: format!("mmap open {}", path.display()),
            detail: e.to_string(),
        })?;
        // SAFETY: sealed segment, opened read-only, never mutated in place.
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| HeraclitusError::Corruption {
            context: format!("mmap map {}", path.display()),
            detail: e.to_string(),
        })?;
        // NOTE: madvise (SEQUENTIAL/WILLNEED/HUGEPAGE) + NUMA affinity are the
        // Linux runtime tuning of CPM-600 — see the module docs; not wired here.
        let hdr = SegmentHeader::decode(&mmap[..])?;
        Ok(Self { mmap, version: hdr.version })
    }

    /// The raw mapped bytes (including header/footer).
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap
    }

    /// Zero-copy iterator over the records after the segment header, stopping at
    /// the footer or the first torn boundary. Each payload slice borrows the
    /// mapped pages directly — no copy.
    pub fn records(&self) -> RecordIter<'_> {
        RecordIter {
            buf: &self.mmap[HEADER_LEN.min(self.mmap.len())..],
            version: self.version,
        }
    }
}

/// Zero-copy record cursor over a mapped segment body.
pub struct RecordIter<'a> {
    buf: &'a [u8],
    version: u16,
}

impl<'a> Iterator for RecordIter<'a> {
    /// `(lsn, hlc, payload)` — `payload` borrows the mmap.
    type Item = (Lsn, u64, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        match format::decode_record(self.version, self.buf) {
            Decoded::Record(lsn, hlc, payload, consumed) => {
                self.buf = &self.buf[consumed..];
                Some((lsn, hlc, payload))
            }
            // Footer (sealed boundary) or Torn → end of the record stream.
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{encode_record, SegmentFooter};
    use std::io::Write;

    /// Hand-build a sealed v5 segment (header + records + footer), byte-exact to
    /// what the writer produces, then map it and iterate zero-copy.
    #[test]
    fn maps_and_iterates_sealed_v5_segment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{:020}.hrkl", 7));

        let payloads: [&[u8]; 3] = [b"alpha", b"bravo-payload", b"charlie"];
        let mut hashes = Vec::new();
        {
            let mut f = File::create(&path).unwrap();
            let hdr = SegmentHeader { version: format::FORMAT_VERSION, segment_id: 7, created_hlc: 1 };
            f.write_all(&hdr.encode()).unwrap();
            for (i, p) in payloads.iter().enumerate() {
                let rec = encode_record(format::FORMAT_VERSION, 100 + i as u64, 500 + i as u64, p);
                hashes.push(format::record_leaf(format::FORMAT_VERSION, &rec));
                f.write_all(&rec).unwrap();
            }
            // Seal with a footer so records() must stop exactly at it.
            let footer = SegmentFooter {
                record_count: 3,
                min_lsn: 100,
                max_lsn: 102,
                blake3_root: [0u8; 32],
            };
            f.write_all(&footer.encode()).unwrap();
            f.sync_all().unwrap();
        }

        let seg = MappedSegment::open(&path).unwrap();
        assert_eq!(seg.version, format::FORMAT_VERSION);

        let got: Vec<(Lsn, u64, Vec<u8>)> =
            seg.records().map(|(l, h, p)| (l, h, p.to_vec())).collect();
        assert_eq!(got.len(), 3, "iteration must stop at the footer, not read it");
        assert_eq!(got[0], (100, 500, b"alpha".to_vec()));
        assert_eq!(got[1], (101, 501, b"bravo-payload".to_vec()));
        assert_eq!(got[2], (102, 502, b"charlie".to_vec()));

        // The mapped bytes are the whole file (header + 3 records + footer).
        assert!(seg.as_bytes().len() > HEADER_LEN + format::FOOTER_LEN);
    }

    /// A tampered byte in a mapped record halts the zero-copy stream at that
    /// record (CRC mismatch → Torn → iterator ends) instead of yielding it.
    #[test]
    fn tampered_record_halts_iteration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{:020}.hrkl", 0));
        {
            let mut f = File::create(&path).unwrap();
            let hdr = SegmentHeader { version: format::FORMAT_VERSION, segment_id: 0, created_hlc: 1 };
            f.write_all(&hdr.encode()).unwrap();
            let rec0 = encode_record(format::FORMAT_VERSION, 0, 0, b"good");
            let mut rec1 = encode_record(format::FORMAT_VERSION, 1, 0, b"tampered");
            let n = rec1.len();
            rec1[n - 1] ^= 0x01; // flip a payload byte; CRC no longer matches
            f.write_all(&rec0).unwrap();
            f.write_all(&rec1).unwrap();
            f.sync_all().unwrap();
        }
        let seg = MappedSegment::open(&path).unwrap();
        let got: Vec<Lsn> = seg.records().map(|(l, _, _)| l).collect();
        assert_eq!(got, vec![0], "iteration halts at the first tampered record");
    }
}
