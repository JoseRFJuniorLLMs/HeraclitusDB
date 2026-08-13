//! Pretty boot sequence — the server narrates its own startup like a Fedora /
//! systemd boot: a banner, then one `[  OK  ]` line per subsystem as it comes
//! up, with a live braille spinner while the slow phases (log + view replay)
//! run. `πάντα ῥεῖ` — everything flows.
//!
//! It writes straight to stdout (not through `tracing`) when stdout is a TTY, so
//! the boot reads like a console boot with colour and motion. When stdout is
//! redirected (a pipe, or the Windows service's daily log file), it degrades to
//! plain `tracing` events — no ANSI, no spinner — so logs stay clean and
//! grep-able. The literal `"heraclitus-server up"` line is preserved in that
//! path so existing log scrapers keep matching.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// ── braille spinner (the "something moving" the boot is named for) ───────────
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// ── ANSI styles ──────────────────────────────────────────────────────────────
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[97m";
/// Clear the whole current line, then return the cursor to column 0. Used to
/// overwrite an animated spinner frame with its final `[  OK  ]` line.
const CLR: &str = "\r\x1b[2K";

/// How the boot narrates: a rich TTY console, plain `tracing` events, or nothing.
#[derive(Clone, Copy)]
enum Mode {
    Console { color: bool },
    Log,
    Silent,
}

/// The boot narrator. Construct once at startup; hand `&Boot` to the engine so
/// each index can announce itself as it warms up.
pub struct Boot {
    mode: Mode,
    start: Instant,
}

impl Boot {
    /// Pick the right mode automatically:
    /// - `HERACLITUS_PLAIN_BOOT=1` (or any truthy) forces plain `tracing` output
    ///   — the Windows service uses this so its file log stays structured.
    /// - otherwise, an interactive TTY gets the full console boot (colour unless
    ///   `NO_COLOR` is set); a redirected stdout falls back to `tracing`.
    pub fn auto() -> Self {
        let mode = if env_truthy("HERACLITUS_PLAIN_BOOT") {
            Mode::Log
        } else if std::io::stdout().is_terminal() {
            // `enable_ansi` also switches the Windows console to UTF-8 so the
            // Greek motto, braille spinner and box glyphs render correctly.
            let ansi_ok = enable_ansi();
            let color = ansi_ok && std::env::var_os("NO_COLOR").is_none();
            Mode::Console { color }
        } else {
            Mode::Log
        };
        Self {
            mode,
            start: Instant::now(),
        }
    }

    /// A no-op narrator (tests, the CLI, embedded use): builds nothing, prints
    /// nothing. `Engine::open` uses this so non-server callers stay silent.
    pub fn silent() -> Self {
        Self {
            mode: Mode::Silent,
            start: Instant::now(),
        }
    }

    /// The flowing-river banner. In log mode this is a single structured line.
    pub fn banner(&self, version: &str) {
        match self.mode {
            Mode::Console { color } => {
                let (b, d, cy, bl, wh, rs) = styles(color);
                let mut o = std::io::stdout().lock();
                let _ = writeln!(o);
                let _ = writeln!(
                    o,
                    "  {bl}≈∿≈{cy}∿≈∿{rs}  {b}{wh}HERACLITUS{rs}{b}{cy}DB{rs}"
                );
                let _ = writeln!(
                    o,
                    "  {d}πάντα ῥεῖ — tudo flui · substrato de memória event-sourced · v{version}{rs}"
                );
                let _ = writeln!(
                    o,
                    "  {d}log imutável append-only  ·  grafo temporal AS OF  ·  geometria hiperbólica{rs}"
                );
                let _ = writeln!(o);
            }
            Mode::Log => tracing::info!(version, "HeraclitusDB a arrancar — πάντα ῥεῖ"),
            Mode::Silent => {}
        }
    }

    /// Begin a phase. Returns a guard; call `.ok(detail)` (or `.fail(..)`) when
    /// it finishes. In console mode a spinner animates the phase line until then.
    pub fn phase(&self, label: &str) -> Phase {
        match self.mode {
            Mode::Console { color } => {
                let stop = Arc::new(AtomicBool::new(false));
                let handle = {
                    let stop = stop.clone();
                    let label = label.to_string();
                    std::thread::Builder::new()
                        .name("boot-spinner".into())
                        .spawn(move || spin(label, color, stop))
                        .ok()
                };
                Phase {
                    label: label.to_string(),
                    start: Instant::now(),
                    kind: PhaseKind::Console {
                        color,
                        stop,
                        handle,
                    },
                }
            }
            Mode::Log => Phase {
                label: label.to_string(),
                start: Instant::now(),
                kind: PhaseKind::Log,
            },
            Mode::Silent => Phase {
                label: label.to_string(),
                start: Instant::now(),
                kind: PhaseKind::Silent,
            },
        }
    }

    /// A one-shot `[  OK  ]` line with no spinner/timing (for things that are
    /// simply true, like a bound listen address).
    pub fn ok_line(&self, label: &str, detail: &str) {
        self.write_line("[  OK  ]", GREEN, label, detail);
    }

    /// A `[ INFO ]` line (configuration summary, addresses).
    pub fn info_line(&self, label: &str, detail: &str) {
        self.write_line("[ INFO ]", CYAN, label, detail);
    }

    /// A `[ WARN ]` line (auth enabled, compliance daemon, etc.).
    pub fn warn_line(&self, label: &str, detail: &str) {
        self.write_line("[ WARN ]", YELLOW, label, detail);
    }

    fn write_line(&self, tag: &str, tag_color: &str, label: &str, detail: &str) {
        match self.mode {
            Mode::Console { color } => {
                let mut o = std::io::stdout().lock();
                if color {
                    if detail.is_empty() {
                        let _ = writeln!(o, "{tag_color}{tag}{RESET} {label}");
                    } else {
                        let _ =
                            writeln!(o, "{tag_color}{tag}{RESET} {label}  {DIM}{detail}{RESET}");
                    }
                } else if detail.is_empty() {
                    let _ = writeln!(o, "{tag} {label}");
                } else {
                    let _ = writeln!(o, "{tag} {label}  {detail}");
                }
            }
            Mode::Log => tracing::info!(detail = %detail, "{}", label),
            Mode::Silent => {}
        }
    }

    /// The closing flourish: total boot time and where to reach the server. Keeps
    /// the literal `"heraclitus-server up"` in the log path for compatibility.
    pub fn ready(&self, grpc: &str, rest: &str) {
        let total = fmt_dur(self.start.elapsed());
        match self.mode {
            Mode::Console { color } => {
                let (b, d, _cy, _bl, _wh, rs) = styles(color);
                let g = if color { GREEN } else { "" };
                let mut o = std::io::stdout().lock();
                let _ = writeln!(o);
                let _ = writeln!(o, "  {g}{b}✔ HeraclitusDB pronto{rs} {d}em {total}{rs}");
                let _ = writeln!(
                    o,
                    "  {d}gRPC {grpc} · REST http://{rest} · Ctrl-C para parar · πάντα ῥεῖ{rs}"
                );
                let _ = writeln!(o);
                let _ = o.flush();
            }
            Mode::Log => {
                tracing::info!(grpc_addr = %grpc, rest_addr = %rest, elapsed = %total, "heraclitus-server up")
            }
            Mode::Silent => {}
        }
    }
}

/// A running boot phase. Drop (or `.ok`/`.fail`) stops the spinner thread.
pub struct Phase {
    label: String,
    start: Instant,
    kind: PhaseKind,
}

enum PhaseKind {
    Console {
        color: bool,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    },
    Log,
    Silent,
}

impl Phase {
    /// Complete the phase successfully, printing `[  OK  ] <label> <detail> (t)`.
    pub fn ok(mut self, detail: impl AsRef<str>) {
        self.finish("[  OK  ]", GREEN, detail.as_ref());
    }

    /// Complete the phase as failed, printing `[ FAIL ] <label> <detail> (t)`.
    pub fn fail(mut self, detail: impl AsRef<str>) {
        self.finish("[ FAIL ]", RED, detail.as_ref());
    }

    fn finish(&mut self, tag: &str, color: &str, detail: &str) {
        let el = fmt_dur(self.start.elapsed());
        let label = std::mem::take(&mut self.label);
        match &mut self.kind {
            PhaseKind::Console {
                color: col,
                stop,
                handle,
            } => {
                stop.store(true, Ordering::Relaxed);
                if let Some(h) = handle.take() {
                    let _ = h.join();
                }
                let mut o = std::io::stdout().lock();
                if *col {
                    if detail.is_empty() {
                        let _ = writeln!(o, "{CLR}{color}{tag}{RESET} {label}  {DIM}{el}{RESET}");
                    } else {
                        let _ = writeln!(
                            o,
                            "{CLR}{color}{tag}{RESET} {label}  {DIM}{detail} · {el}{RESET}"
                        );
                    }
                } else if detail.is_empty() {
                    let _ = writeln!(o, "\r{tag} {label}  ({el})");
                } else {
                    let _ = writeln!(o, "\r{tag} {label}  {detail} ({el})");
                }
                let _ = o.flush();
            }
            PhaseKind::Log => {
                tracing::info!(detail = %detail, elapsed = %el, "{label}")
            }
            PhaseKind::Silent => {}
        }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        // If the phase was abandoned (early `?` return) rather than completed,
        // still stop and reap the spinner thread so it can't keep painting.
        if let PhaseKind::Console { stop, handle, .. } = &mut self.kind {
            stop.store(true, Ordering::Relaxed);
            if let Some(h) = handle.take() {
                let _ = h.join();
            }
        }
    }
}

/// The spinner thread body: paint a frame on the phase line every ~80 ms until
/// signalled to stop. The initial wait means phases that finish near-instantly
/// (e.g. an empty index) never flash a frame — only the truly slow phases move.
fn spin(label: String, color: bool, stop: Arc<AtomicBool>) {
    let mut i = 0usize;
    loop {
        // Wait ~80 ms in 10 ms steps so `.ok()` joins us promptly on stop.
        for _ in 0..8 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let frame = SPINNER[i % SPINNER.len()];
        let mut o = std::io::stdout().lock();
        if color {
            let _ = write!(o, "{CLR}  {CYAN}{frame}{RESET} {DIM}{label}{RESET}…");
        } else {
            let _ = write!(o, "{CLR}  {frame} {label}…");
        }
        let _ = o.flush();
        i += 1;
    }
}

// ── small helpers (shared with the engine narration) ─────────────────────────

/// Return the style codes, or empty strings when colour is off.
fn styles(
    color: bool,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if color {
        (BOLD, DIM, CYAN, BLUE, WHITE, RESET)
    } else {
        ("", "", "", "", "", "")
    }
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

/// `4612883` → `4.612.883` (PT thousands grouping) for human-sized counts.
pub(crate) fn group(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(ch);
    }
    out
}

/// `268435456` → `256 MB`.
pub(crate) fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v.fract() == 0.0 {
        format!("{v:.0} {}", U[i])
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Render a small non-negative integer as Unicode superscript (`32` → `³²`),
/// for the geometry signature `H³² ⊗ S⁸ ⊗ E⁸`.
pub(crate) fn sup(n: usize) -> String {
    const S: [char; 10] = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹'];
    n.to_string()
        .chars()
        .map(|c| S[(c as u8 - b'0') as usize])
        .collect()
}

fn fmt_dur(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        let s = d.as_secs();
        format!("{}m{:02}s", s / 60, s % 60)
    }
}

/// Enable ANSI virtual-terminal processing and UTF-8 output on the Windows
/// console so colours, the braille spinner and the Greek motto render in the
/// classic conhost (where they otherwise show up as raw `←[2m…` escapes and
/// mojibake). Returns whether ANSI is usable. No-op (always `true`) elsewhere.
#[cfg(windows)]
pub fn enable_ansi() -> bool {
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const CP_UTF8: u32 = 65001;
    type Handle = isize;
    extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> Handle;
        fn GetConsoleMode(h: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: Handle, mode: u32) -> i32;
        fn SetConsoleOutputCP(cp: u32) -> i32;
    }
    unsafe {
        // UTF-8 first, so even if VT can't be enabled the glyphs are correct.
        SetConsoleOutputCP(CP_UTF8);
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h == 0 || h == -1 {
            return false;
        }
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) == 0 {
            // Not a real console (redirected) — caller already gated on is_terminal.
            return false;
        }
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
pub fn enable_ansi() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_thousands() {
        assert_eq!(group(0), "0");
        assert_eq!(group(42), "42");
        assert_eq!(group(1000), "1.000");
        assert_eq!(group(4_612_883), "4.612.883");
    }

    #[test]
    fn bytes_human() {
        assert_eq!(fmt_bytes(256 * 1024 * 1024), "256 MB");
        assert_eq!(fmt_bytes(1024), "1 KB");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
    }

    #[test]
    fn superscript() {
        assert_eq!(sup(32), "³²");
        assert_eq!(sup(8), "⁸");
        assert_eq!(sup(0), "⁰");
    }

    #[test]
    fn duration_scales() {
        assert_eq!(fmt_dur(Duration::from_millis(12)), "12ms");
        assert_eq!(fmt_dur(Duration::from_millis(1200)), "1.2s");
        assert_eq!(fmt_dur(Duration::from_secs(161)), "2m41s");
    }

    #[test]
    fn silent_and_log_modes_do_not_panic() {
        let b = Boot::silent();
        b.banner("0.0.0");
        b.info_line("x", "y");
        b.phase("z").ok("done");
        b.ready("127.0.0.1:1", "127.0.0.1:2");
    }
}
