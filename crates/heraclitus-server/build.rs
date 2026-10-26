use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=HERACLITUS_BUILD_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-changed=../../crates");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed=../../.git/{head}");
    }
    let sha = git(&["rev-parse", "HEAD"])
        .or_else(|| std::env::var("HERACLITUS_BUILD_SHA").ok())
        .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".into());
    let dirty = git(&["status", "--porcelain", "--untracked-files=normal"])
        .map(|s| if s.is_empty() { "clean" } else { "dirty" })
        .unwrap_or("unknown");
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .or_else(|| git(&["log", "-1", "--format=%ct"]))
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=HERACLITUS_GIT_SHA={sha}");
    println!("cargo:rustc-env=HERACLITUS_GIT_STATE={dirty}");
    println!("cargo:rustc-env=HERACLITUS_SOURCE_EPOCH={epoch}");
}
