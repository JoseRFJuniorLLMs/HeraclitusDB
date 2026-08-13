//! SPEC-034 — concurrent memory-lifetime model (epoch-like reclamation).
//!
//! Analytical readers must be able to scan an old version of a frozen structure
//! while a background Optimize pass publishes a new one, with no torn reads and
//! no use-after-free. [`Versioned<T>`] gives exactly that: `load()` hands a
//! reader an `Arc` to the current version (cheap, lock-free after the pointer
//! read); `store()` swaps in a new version. The previous version stays alive
//! until the last reader holding its `Arc` drops it — reclamation by refcount,
//! the same safety guarantee as epoch-based reclamation.
//!
//! Note: true EBR (`crossbeam-epoch`) removes even the brief swap lock and the
//! atomic refcount traffic on the hot path; that is a performance follow-up. The
//! *safety* contract (readers never see freed memory) holds here already.

use std::sync::{Arc, RwLock};

pub struct Versioned<T> {
    inner: RwLock<Arc<T>>,
}

impl<T> Versioned<T> {
    pub fn new(value: T) -> Self {
        Self { inner: RwLock::new(Arc::new(value)) }
    }

    /// Reader: take a snapshot handle to the current version. Holding it keeps
    /// that version alive even if a writer swaps a newer one in meanwhile.
    pub fn load(&self) -> Arc<T> {
        self.inner.read().unwrap().clone()
    }

    /// Writer: publish a new version. Old readers keep their handle; the old
    /// version is freed when the last such handle drops.
    pub fn store(&self, value: T) {
        *self.inner.write().unwrap() = Arc::new(value);
    }

    /// Strong-count of the *current* version (mostly for tests/introspection).
    pub fn current_refs(&self) -> usize {
        Arc::strong_count(&self.inner.read().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_reader_sees_old_version_after_swap() {
        let v = Versioned::new(vec![1, 2, 3]);
        let old = v.load(); // reader pins version 1
        v.store(vec![9, 9]); // writer publishes version 2
        // The old handle is unchanged — no torn read, no use-after-free.
        assert_eq!(*old, vec![1, 2, 3]);
        // A fresh load sees the new version.
        assert_eq!(*v.load(), vec![9, 9]);
    }

    #[test]
    fn version_is_shared_not_copied() {
        let v = Versioned::new(String::from("hot"));
        let a = v.load();
        let b = v.load();
        // Both readers share one allocation (Arc), no deep copy.
        assert!(Arc::ptr_eq(&a, &b));
    }
}
