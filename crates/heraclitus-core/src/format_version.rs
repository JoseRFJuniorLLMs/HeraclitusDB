//! SPEC-029 — storage-format versioning & capability negotiation.
//!
//! Every self-contained segment / manifest carries a `(major, minor,
//! feature_flags)` stamp. On open, the running binary negotiates: a higher
//! `major` or an unknown feature-flag bit is a hard stop (refuse rather than
//! misread bytes); a higher `minor` with matching `major` is safe forward
//! evolution (ignore unknown secondary metadata, replay the raw log unchanged).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFormatVersion {
    pub major: u16,
    pub minor: u16,
    pub feature_flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// Safe to read as-is.
    Ok,
    /// Same major, older minor on disk — we can read; nothing to do.
    ReadOlderMinor,
    /// Same major, newer minor — read raw log, ignore unknown secondary meta.
    ForwardMinor,
    /// Hard incompatibility (newer major or unknown feature bit) — refuse.
    Reject(String),
}

impl StorageFormatVersion {
    pub fn new(major: u16, minor: u16, feature_flags: u64) -> Self {
        Self { major, minor, feature_flags }
    }

    /// Negotiate an on-disk version against what this binary supports.
    /// `supported_flags` is the OR of every feature bit this build understands.
    pub fn negotiate(&self, running: StorageFormatVersion, supported_flags: u64) -> Compatibility {
        if self.major > running.major {
            return Compatibility::Reject(format!(
                "on-disk major {} > supported {}",
                self.major, running.major
            ));
        }
        if self.major < running.major {
            return Compatibility::Reject(format!(
                "on-disk major {} < supported {} (needs migration)",
                self.major, running.major
            ));
        }
        let unknown = self.feature_flags & !supported_flags;
        if unknown != 0 {
            return Compatibility::Reject(format!("unknown feature-flag bits: {unknown:#x}"));
        }
        match self.minor.cmp(&running.minor) {
            std::cmp::Ordering::Greater => Compatibility::ForwardMinor,
            std::cmp::Ordering::Less => Compatibility::ReadOlderMinor,
            std::cmp::Ordering::Equal => Compatibility::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAG_HYPERSPARSE: u64 = 1 << 0;
    const FLAG_RIBBON: u64 = 1 << 1;

    #[test]
    fn same_version_is_ok() {
        let running = StorageFormatVersion::new(5, 2, FLAG_HYPERSPARSE);
        let disk = StorageFormatVersion::new(5, 2, FLAG_HYPERSPARSE);
        assert_eq!(disk.negotiate(running, FLAG_HYPERSPARSE), Compatibility::Ok);
    }

    #[test]
    fn newer_minor_is_forward_compatible() {
        let running = StorageFormatVersion::new(5, 2, 0);
        let disk = StorageFormatVersion::new(5, 4, 0);
        assert_eq!(disk.negotiate(running, 0), Compatibility::ForwardMinor);
    }

    #[test]
    fn newer_major_is_rejected() {
        let running = StorageFormatVersion::new(5, 0, 0);
        let disk = StorageFormatVersion::new(6, 0, 0);
        assert!(matches!(disk.negotiate(running, 0), Compatibility::Reject(_)));
    }

    #[test]
    fn unknown_feature_bit_is_rejected() {
        let running = StorageFormatVersion::new(5, 0, FLAG_HYPERSPARSE);
        // Disk needs RIBBON, which this build does not understand.
        let disk = StorageFormatVersion::new(5, 0, FLAG_HYPERSPARSE | FLAG_RIBBON);
        assert!(matches!(
            disk.negotiate(running, FLAG_HYPERSPARSE),
            Compatibility::Reject(_)
        ));
    }
}
