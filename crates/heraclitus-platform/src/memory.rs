//! Memory management, page advice, and cache hinting.
//!
//! Encapsulates platform-specific virtual memory hints (madvise on Linux/POSIX)
//! without dispersing unsafe libc invocations throughout higher-level crates.
//!
//! # Page alignment is not a detail
//!
//! `madvise(2)` fails with `EINVAL` when `addr` is not page-aligned. Rust
//! slices carry no such guarantee: a `Vec<u8>` lands wherever the allocator put
//! it. The first version of this module handed slice pointers straight to the
//! kernel and asserted success — which passed on Windows (where the call is a
//! no-op) and failed on the first Linux runner that ever executed it.
//!
//! So the safe wrapper narrows the requested range to its **page-aligned
//! interior** before advising. Narrowing is the only sound direction: advice is
//! a hint, so covering fewer pages merely hints less, while widening would hand
//! the kernel pages the caller does not own — and for `DontNeed` that is not a
//! hint, it is someone else's data.

use std::io;

/// Fallback page size for targets where the value cannot be queried at runtime.
const DEFAULT_PAGE_SIZE: usize = 4096;

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

impl MemoryAdvice {
    /// Whether the hint can *change what the caller reads back*.
    ///
    /// `MADV_DONTNEED` on a private anonymous mapping discards the pages: the
    /// next read returns zeroes. That is a mutation, so it can never be reached
    /// through a shared `&[u8]` — only through [`advise`], whose caller asserts
    /// ownership of the region.
    pub fn is_destructive(self) -> bool {
        matches!(self, MemoryAdvice::DontNeed)
    }
}

/// The kernel page size in bytes.
///
/// Queried via `sysconf(_SC_PAGESIZE)` on Linux; falls back to 4 KiB when the
/// value is unavailable or not a power of two (the alignment arithmetic below
/// relies on that property).
pub fn page_size() -> usize {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: sysconf with a valid constant name has no preconditions and
        // returns -1 on failure without touching caller memory.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if raw > 0 {
            let size = raw as usize;
            if size.is_power_of_two() {
                return size;
            }
        }
    }
    DEFAULT_PAGE_SIZE
}

/// Narrows `[addr, addr + len)` to the largest page-aligned range it contains.
///
/// Returns `None` when no whole page fits inside — a 4 KiB buffer at an
/// unaligned address contains no complete page, which is exactly the case that
/// used to return `EINVAL`.
///
/// `page` must be a power of two; [`page_size`] guarantees that.
fn aligned_interior(addr: usize, len: usize, page: usize) -> Option<(usize, usize)> {
    debug_assert!(page.is_power_of_two(), "page size must be a power of two");
    let mask = !(page - 1);
    let start = addr.checked_add(page - 1)? & mask;
    let end = addr.checked_add(len)? & mask;
    if end > start {
        Some((start, end - start))
    } else {
        None
    }
}

/// Applies memory access advice to a mapped memory range.
///
/// # Safety
/// The caller must ensure that `addr` points to a valid mapped memory region of
/// at least `len` bytes, that the memory remains mapped for the duration of the
/// call, and — for [`MemoryAdvice::DontNeed`] — that discarding those pages is
/// permitted, since no other reference may observe the contents afterwards.
///
/// `addr` must be page-aligned, or the kernel rejects the call with `EINVAL`.
/// Use [`advise_slice`] to have the range aligned for you.
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
        // - addr was asserted non-null and is guaranteed valid, mapped and
        //   page-aligned by the caller's contract.
        // - len matches the mapped extent.
        // - For every non-destructive flag madvise only hints to the page
        //   cache; DontNeed discards pages, which the caller has asserted is
        //   permitted for this region.
        let ret = unsafe { libc::madvise(addr as *mut libc::c_void, len, flag) };
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

/// Applies memory advice to the page-aligned interior of a byte slice.
///
/// Pages only partially covered by `slice` are left untouched, so this never
/// affects memory the caller does not own. When the slice is too small or too
/// misaligned to contain a whole page, the call succeeds having done nothing.
///
/// # Errors
/// Returns [`io::ErrorKind::InvalidInput`] for destructive advice
/// ([`MemoryAdvice::DontNeed`]), which discards page contents and therefore
/// cannot be reached through a shared reference; use [`advise`] instead.
/// Otherwise returns the underlying `madvise` error.
pub fn advise_slice(slice: &[u8], advice: MemoryAdvice) -> io::Result<()> {
    if advice.is_destructive() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "advice destrutiva nao pode ser aplicada atraves de &[u8]; use advise()",
        ));
    }
    let Some((addr, len)) = aligned_interior(slice.as_ptr() as usize, slice.len(), page_size())
    else {
        return Ok(());
    };
    // SAFETY:
    // - The range is a sub-range of a live Rust slice, hence mapped and valid
    //   for the duration of the borrow.
    // - It was narrowed to page boundaries above, satisfying the alignment
    //   precondition of madvise.
    // - The advice was checked to be non-destructive, so contents are unchanged
    //   and the shared borrow stays sound.
    unsafe { advise(addr as *const u8, len, advice) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc, Layout};

    #[test]
    fn page_size_is_a_usable_power_of_two() {
        let page = page_size();
        assert!(page.is_power_of_two());
        assert!(page >= 4096);
    }

    #[test]
    fn aligned_interior_narrows_to_whole_pages() {
        // Already aligned and page-sized: kept whole.
        assert_eq!(aligned_interior(4096, 8192, 4096), Some((4096, 8192)));
        // Unaligned start: the leading partial page is dropped.
        assert_eq!(aligned_interior(4097, 8192, 4096), Some((8192, 4096)));
        // Unaligned end: the trailing partial page is dropped.
        assert_eq!(aligned_interior(4096, 5000, 4096), Some((4096, 4096)));
    }

    #[test]
    fn aligned_interior_rejects_ranges_holding_no_whole_page() {
        // One page worth of bytes, but straddling a boundary.
        assert_eq!(aligned_interior(4097, 4096, 4096), None);
        assert_eq!(aligned_interior(1, 10, 4096), None);
        assert_eq!(aligned_interior(0, 0, 4096), None);
        // Overflow must not wrap into a bogus range.
        assert_eq!(aligned_interior(usize::MAX - 1, 8192, 4096), None);
    }

    #[test]
    fn advise_slice_accepts_an_unaligned_heap_buffer() {
        // The regression: a plain Vec is not page-aligned, and handing its
        // pointer to madvise returned EINVAL on Linux.
        let buffer = vec![0u8; 4096];
        assert!(advise_slice(&buffer, MemoryAdvice::Sequential).is_ok());
        assert!(advise_slice(&buffer, MemoryAdvice::Random).is_ok());
        assert!(advise_slice(&buffer, MemoryAdvice::Normal).is_ok());
    }

    #[test]
    fn advise_slice_advises_a_page_aligned_region() {
        // Large and aligned: the interior is non-empty, so this really does
        // reach madvise on Linux instead of short-circuiting.
        let page = page_size();
        let layout = Layout::from_size_align(page * 4, page).expect("layout valido");
        // SAFETY: non-zero size, valid layout; freed with the same layout below.
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "alocacao alinhada falhou");
        // SAFETY: `ptr` is a live allocation of exactly `page * 4` zeroed bytes.
        let slice = unsafe { std::slice::from_raw_parts(ptr, page * 4) };

        assert_eq!(
            aligned_interior(ptr as usize, page * 4, page),
            Some((ptr as usize, page * 4)),
            "a regiao alinhada devia ser aproveitada por inteiro"
        );
        let result = advise_slice(slice, MemoryAdvice::WillNeed);

        // SAFETY: same pointer and layout used for the allocation.
        unsafe { dealloc(ptr, layout) };
        assert!(result.is_ok(), "madvise alinhado falhou: {result:?}");
    }

    #[test]
    fn advise_slice_refuses_destructive_advice() {
        let buffer = vec![7u8; 4096];
        let err = advise_slice(&buffer, MemoryAdvice::DontNeed)
            .expect_err("DontNeed atraves de &[u8] tem de ser recusado");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(buffer.iter().all(|&b| b == 7), "conteudo foi descartado");
    }

    #[test]
    fn advise_empty_slice_is_a_noop() {
        let empty: [u8; 0] = [];
        assert!(advise_slice(&empty, MemoryAdvice::WillNeed).is_ok());
    }
}
