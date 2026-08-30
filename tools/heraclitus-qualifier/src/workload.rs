use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::evidence::{sha256_file, write_json_new};
use crate::manifest::{DatasetManifest, WorkloadProfile};

const EVENT_CLASSES: &[&str] = &[
    "authentication",
    "network",
    "dns",
    "http",
    "process",
    "endpoint",
    "iam",
    "kubernetes",
    "cloud_audit",
    "database_audit",
    "application_log",
];

#[derive(Debug, Serialize)]
struct SyntheticEvent<'a> {
    sequence: u64,
    ts_offset_ms: u64,
    event_class: &'a str,
    tenant: String,
    actor: String,
    source_ip: String,
    entity: String,
    severity: u8,
    content: String,
    attributes: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, upper: u64) -> u64 {
        if upper == 0 {
            0
        } else {
            self.next() % upper
        }
    }
}

fn operation_mix(profile: WorkloadProfile) -> BTreeMap<String, u64> {
    let pairs: &[(&str, u64)] = match profile {
        WorkloadProfile::WriteHeavy => &[("ingest", 90), ("attribute_query", 10)],
        WorkloadProfile::ReadHeavy => &[
            ("ingest", 20),
            ("attribute_query", 40),
            ("text", 20),
            ("graph", 20),
        ],
        WorkloadProfile::Mixed => &[
            ("ingest", 70),
            ("attribute_query", 10),
            ("text", 5),
            ("vector", 5),
            ("graph", 5),
            ("as_of_analytics", 5),
        ],
        WorkloadProfile::SocIngestion => &[("ingest", 95), ("attribute_query", 5)],
        WorkloadProfile::SocInvestigation => &[
            ("ingest", 20),
            ("attribute_query", 25),
            ("text", 20),
            ("vector", 10),
            ("graph", 15),
            ("as_of_analytics", 10),
        ],
        WorkloadProfile::Burst => &[("ingest", 85), ("attribute_query", 15)],
        WorkloadProfile::AdversarialCardinality => &[("ingest", 70), ("attribute_query", 30)],
    };
    pairs
        .iter()
        .map(|(name, weight)| ((*name).to_owned(), *weight))
        .collect()
}

pub fn generate(
    profile: WorkloadProfile,
    seed: u64,
    events: u64,
    output: &Path,
) -> Result<DatasetManifest> {
    if events == 0 {
        bail!("--events must be greater than zero");
    }
    if output.exists() {
        bail!("refusing to overwrite workload {}", output.display());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .with_context(|| format!("create workload {}", output.display()))?;
    let mut writer = BufWriter::new(file);
    let mut rng = DeterministicRng::new(seed);
    let mut event_classes = BTreeMap::<String, u64>::new();

    for sequence in 0..events {
        let class = EVENT_CLASSES[rng.below(EVENT_CLASSES.len() as u64) as usize];
        *event_classes.entry(class.to_owned()).or_default() += 1;
        let cardinality = match profile {
            WorkloadProfile::AdversarialCardinality => events.max(1),
            _ => 4_096,
        };
        let actor_id = rng.below(cardinality);
        let source = rng.next();
        let payload_size = match profile {
            WorkloadProfile::Burst => 64 + rng.below(2_048),
            _ => 96 + rng.below(768),
        } as usize;
        let mut attributes = BTreeMap::new();
        attributes.insert("region".to_owned(), format!("r{}", rng.below(8)));
        attributes.insert("sensor".to_owned(), format!("s{}", rng.below(512)));
        attributes.insert(
            "outcome".to_owned(),
            if rng.below(10) < 8 {
                "success"
            } else {
                "failure"
            }
            .to_owned(),
        );
        if matches!(profile, WorkloadProfile::AdversarialCardinality) {
            attributes.insert("unique_key".to_owned(), format!("u{sequence:016x}"));
        }
        let event = SyntheticEvent {
            sequence,
            ts_offset_ms: if matches!(profile, WorkloadProfile::Burst) {
                sequence / 100
            } else {
                sequence.saturating_mul(10)
            },
            event_class: class,
            tenant: format!("tenant-{}", rng.below(32)),
            actor: format!("actor-{actor_id}"),
            source_ip: format!(
                "10.{}.{}.{}",
                (source >> 16) & 0xff,
                (source >> 8) & 0xff,
                source & 0xff
            ),
            entity: format!("entity-{}", rng.below(cardinality)),
            severity: (rng.below(10) + 1) as u8,
            content: format!("synthetic-{class}-{}", "x".repeat(payload_size)),
            attributes,
        };
        serde_json::to_writer(&mut writer, &event)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;

    let manifest = DatasetManifest {
        schema_version: 1,
        provenance: "synthetic".to_owned(),
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        profile,
        seed,
        events,
        sha256: sha256_file(output)?,
        event_classes,
        operation_mix: operation_mix(profile),
    };
    let manifest_path = output.with_extension(format!(
        "{}manifest.json",
        output
            .extension()
            .map(|extension| format!("{}.", extension.to_string_lossy()))
            .unwrap_or_default()
    ));
    write_json_new(&manifest_path, &manifest)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_identical_dataset() {
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("a.jsonl");
        let b = temp.path().join("b.jsonl");
        let first = generate(WorkloadProfile::Mixed, 42, 100, &a).unwrap();
        let second = generate(WorkloadProfile::Mixed, 42, 100, &b).unwrap();
        assert_eq!(first.sha256, second.sha256);
        assert_eq!(first.operation_mix.get("ingest"), Some(&70));
    }

    #[test]
    fn output_is_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        generate(WorkloadProfile::Mixed, 1, 1, &path).unwrap();
        assert!(generate(WorkloadProfile::Mixed, 1, 1, &path).is_err());
    }
}
