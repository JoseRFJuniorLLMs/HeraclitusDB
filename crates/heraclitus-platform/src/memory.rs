//! Memory management, page advice, and cache hinting.
//!
//! Encapsulates platform-specific virtual memory hints (madvise on Linux/POSIX)
//! without dispersing unsafe libc invocations throughout higher-level crates.

use std::io;

/// Virtual memory access hints for the operating system page cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAdvice {
    /// Default kernel page access pattern.
    Normal,
    /// Sequential read expectation (aggressive readahead).
    Sequential,
    /// Random access expectation (minimal readahead).
    Random,
    /// Page will be needed soon (asynchronous prefetch).
    WillNeed,
    /// Page will not be needed soon (can be reclaimed without swap).
    DontNeed,
}

/// Applies memory access advice to a mapped memory range.
///
/// # Safety
/// The caller must ensure that ddr points to a valid mapped memory region
/// of at least len bytes, and that the memory remains mapped for the duration
/// of the call.
pub unsafe fn advise(addr: *const u8, len: usize, advice: MemoryAdvice) -> io::Result<()> {
    if len == 0 || addr.is_null() {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let flag = match advice {
            MemoryAdvice::Normal => libc::MADV_NORMAL,
            MemoryAdvice::Sequential => libc::MADV_SEQUENTIAL,
            MemoryAdvice::Random => libc::MADV_RANDOM,
            MemoryAdvice::WillNeed => libc::MADV_WILLNEED,
            MemoryAdvice::DontNeed => libc::MADV_DONTNEED,
        };

        // SAFETY:
        // - ddr was asserted non-null and is guaranteed valid and mapped by caller.
        // - len matches the mapped extent.
        // - libc::madvise does not mutate memory contents or invalidate pointers;
        //   it merely hints to the kernel page cache.
        let ret = libc::madvise(addr as *mut libc::c_void, len, flag);
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (addr, len, advice);
        // Safe no-op on non-Linux platforms
        Ok(())
    }
}

/// Safely applies memory advice to a byte slice.
pub fn advise_slice(slice: &[u8], advice: MemoryAdvice) -> io::Result<()> {
    if slice.is_empty() {
        return Ok(());
    }
    // SAFETY:
    // A Rust slice &[u8] is always a valid, contiguous, non-null mapped region in memory.
    unsafe { advise(slice.as_ptr(), slice.len(), advice) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advise_slice_safe() {
        let buffer = vec![0u8; 4096];
        assert!(advise_slice(&buffer, MemoryAdvice::Sequential).is_ok());
        assert!(advise_slice(&buffer, MemoryAdvice::Random).is_ok());
        assert!(advise_slice(&buffer, MemoryAdvice::Normal).is_ok());
    }

    #[test]
    fn test_advise_empty_slice() {
        let empty: [u8; 0] = [];
        assert!(advise_slice(&empty, MemoryAdvice::WillNeed).is_ok());
    }
}
