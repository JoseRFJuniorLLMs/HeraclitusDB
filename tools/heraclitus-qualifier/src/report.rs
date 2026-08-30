use std::fmt::Write as _;

use crate::manifest::{QualificationManifest, QualificationResult};

fn cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

pub fn render(manifest: &QualificationManifest, result: &QualificationResult) -> String {
    let mut report = String::new();
    writeln!(report, "# HeraclitusDB Qualification Report").unwrap();
    writeln!(report).unwrap();
    writeln!(
        report,
        "- Qualification ID: `{}`",
        manifest.qualification_id
    )
    .unwrap();
    writeln!(report, "- Release: `{}`", manifest.release_version).unwrap();
    writeln!(report, "- Git commit: `{}`", manifest.git_commit).unwrap();
    writeln!(report, "- Source SHA-256: `{}`", manifest.source_digest).unwrap();
    writeln!(
        report,
        "- Binary SHA-256: `{}`",
        manifest.binary_digest.as_deref().unwrap_or("NOT PROVIDED")
    )
    .unwrap();
    writeln!(report, "- Level: `{:?}`", manifest.qualification_level).unwrap();
    writeln!(report, "- Status: `{:?}`", result.status).unwrap();
    writeln!(
        report,
        "- Production qualified: `{}`",
        result.production_qualified
    )
    .unwrap();
    writeln!(
        report,
        "- Repository dirty: `{}`",
        manifest.repository_dirty
    )
    .unwrap();
    writeln!(report).unwrap();

    writeln!(report, "## Environment").unwrap();
    writeln!(report).unwrap();
    writeln!(report, "| Field | Value |").unwrap();
    writeln!(report, "|---|---|").unwrap();
    writeln!(
        report,
        "| CPU | {} |",
        cell(&manifest.environment.cpu_model)
    )
    .unwrap();
    writeln!(
        report,
        "| Logical CPUs | {} |",
        manifest.environment.cpu_count
    )
    .unwrap();
    writeln!(
        report,
        "| Memory bytes | {} |",
        manifest.environment.memory_bytes
    )
    .unwrap();
    writeln!(
        report,
        "| Storage | {} |",
        cell(&manifest.environment.storage_model)
    )
    .unwrap();
    writeln!(
        report,
        "| Filesystem | {} |",
        cell(&manifest.environment.filesystem)
    )
    .unwrap();
    writeln!(report, "| OS | {} |", cell(&manifest.environment.os)).unwrap();
    writeln!(
        report,
        "| Kernel | {} |",
        cell(&manifest.environment.kernel)
    )
    .unwrap();
    writeln!(
        report,
        "| Network | {} |",
        cell(&manifest.environment.network)
    )
    .unwrap();
    writeln!(report).unwrap();

    writeln!(report, "## Gates").unwrap();
    writeln!(report).unwrap();
    writeln!(
        report,
        "| Gate | Status | Assurance | Duration (ms) | Evidence | Failures |"
    )
    .unwrap();
    writeln!(report, "|---|---|---|---:|---|---|").unwrap();
    for trial in &result.trials {
        writeln!(
            report,
            "| {} | {:?} | {:?} | {} | {} | {} |",
            cell(&trial.trial),
            trial.status,
            trial.assurance,
            trial.duration_ms,
            cell(&trial.evidence.join(", ")),
            cell(&trial.failures.join("; "))
        )
        .unwrap();
    }
    writeln!(report).unwrap();

    writeln!(report, "## Known limitations").unwrap();
    writeln!(report).unwrap();
    if result.known_limitations.is_empty() {
        writeln!(report, "None recorded.").unwrap();
    } else {
        for limitation in &result.known_limitations {
            writeln!(report, "- {}", limitation).unwrap();
        }
    }
    writeln!(report).unwrap();
    writeln!(report, "## Integrity").unwrap();
    writeln!(report).unwrap();
    writeln!(
        report,
        "`evidence-index.json` seals this report and every accompanying artifact. "
    )
    .unwrap();
    writeln!(
        report,
        "A Passed result is valid only for the exact source, binary digest, environment and plan above."
    )
    .unwrap();
    report
}
