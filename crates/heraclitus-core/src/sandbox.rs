//! SPEC-035 — extension crash isolation (stable-ABI boundary).
//!
//! A third-party extension must never take the database down. [`run_sandboxed`]
//! wraps plugin execution in a panic boundary: a panicking or aborting
//! extension is caught and turned into an ordinary `Err`, leaving the immutable
//! log and other queries untouched.
//!
//! Honest scope: this is the in-process crash boundary (real, working). Full
//! *memory* isolation via a WebAssembly runtime (`wasmtime`/`extism`) is the
//! feature-gated upgrade — it also sits in tension with the "intelligence lives
//! in the agent, not the DB" thesis, so it stays deliberately behind a flag.
//!
//! Wiring status (P4, 2026-07-16): **reference — 0 callers.** `run_sandboxed`
//! works but nothing on the live path wraps extension code with it (there is no
//! extension execution site yet). See `docs/md/DECISAO-P4-plugins-wasm.md`.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run untrusted extension code, converting a panic into a handled error so it
/// cannot unwind into (and poison) the engine.
pub fn run_sandboxed<F, R>(name: &str, f: F) -> Result<R, String>
where
    F: FnOnce() -> R,
{
    // Silence the default panic hook's stderr noise for the controlled call.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(prev);

    result.map_err(|payload| {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        format!("sandboxed extension '{name}' faulted: {msg}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_result_passes_through() {
        let r = run_sandboxed("adder", || 2 + 2);
        assert_eq!(r, Ok(4));
    }

    #[test]
    fn panic_is_contained_as_error() {
        let r: Result<(), String> = run_sandboxed("bad", || panic!("boom in plugin"));
        let err = r.unwrap_err();
        assert!(err.contains("bad") && err.contains("boom"), "got: {err}");
        // The engine is still alive: a subsequent call works fine.
        assert_eq!(run_sandboxed("ok", || 1), Ok(1));
    }
}
