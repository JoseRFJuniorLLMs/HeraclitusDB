use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use toml::Value as TomlValue;

use crate::evidence::{repository_root, sha256_file, write_bytes_new, write_json_new};

#[derive(Debug, Clone, Serialize)]
pub struct SbomSummary {
    pub format: &'static str,
    pub spec_version: &'static str,
    pub components: usize,
    pub sha256: String,
    pub source: &'static str,
}

fn string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(ToOwned::to_owned)
}

fn metadata_bom(metadata: &Value) -> Result<(Value, usize)> {
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no packages")?;
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();

    let mut components = Vec::with_capacity(packages.len());
    let mut id_to_ref = BTreeMap::new();
    for package in packages {
        let id = string(package.get("id")).context("Cargo package without id")?;
        let name = string(package.get("name")).context("Cargo package without name")?;
        let version = string(package.get("version")).context("Cargo package without version")?;
        let bom_ref = format!("pkg:cargo/{name}@{version}?cargo_id={}", url_escape(&id));
        id_to_ref.insert(id.clone(), bom_ref.clone());
        let mut component = json!({
            "type": if workspace_members.contains(id.as_str()) { "application" } else { "library" },
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "purl": format!("pkg:cargo/{name}@{version}")
        });
        if let Some(description) = string(package.get("description")) {
            component["description"] = Value::String(description);
        }
        if let Some(license) = string(package.get("license")) {
            component["licenses"] = json!([{ "expression": license }]);
        }
        if let Some(checksum) = string(package.get("checksum")) {
            component["hashes"] = json!([{ "alg": "SHA-256", "content": checksum }]);
        }
        if let Some(source) = string(package.get("source")) {
            component["properties"] = json!([{ "name": "cargo:source", "value": source }]);
        }
        components.push(component);
    }
    components.sort_by(|left, right| left["bom-ref"].as_str().cmp(&right["bom-ref"].as_str()));

    let mut dependencies = Vec::new();
    if let Some(nodes) = metadata["resolve"]["nodes"].as_array() {
        for node in nodes {
            let Some(id) = node["id"].as_str() else {
                continue;
            };
            let Some(reference) = id_to_ref.get(id) else {
                continue;
            };
            let mut depends_on = node["deps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|dependency| dependency["pkg"].as_str())
                .filter_map(|dependency_id| id_to_ref.get(dependency_id))
                .cloned()
                .collect::<Vec<_>>();
            depends_on.sort();
            depends_on.dedup();
            dependencies.push(json!({ "ref": reference, "dependsOn": depends_on }));
        }
    }
    dependencies.sort_by(|left, right| left["ref"].as_str().cmp(&right["ref"].as_str()));

    Ok((
        base_bom(
            components,
            dependencies,
            "Cargo.lock + cargo metadata --locked --offline",
        ),
        packages.len(),
    ))
}

fn lock_string<'a>(package: &'a TomlValue, key: &str) -> Option<&'a str> {
    package.get(key).and_then(TomlValue::as_str)
}

fn lock_bom(repo: &Path) -> Result<(Value, usize)> {
    let lock_path = repo.join("Cargo.lock");
    let lock_text =
        fs::read_to_string(&lock_path).with_context(|| format!("read {}", lock_path.display()))?;
    let lock: TomlValue = toml::from_str(&lock_text).context("parse Cargo.lock for SBOM")?;
    let packages = lock
        .get("package")
        .and_then(TomlValue::as_array)
        .context("Cargo.lock has no package entries")?;

    let mut components = Vec::with_capacity(packages.len());
    let mut by_name = BTreeMap::<String, Vec<(String, String)>>::new();
    let mut package_refs = Vec::with_capacity(packages.len());
    for package in packages {
        let name = lock_string(package, "name").context("lock package without name")?;
        let version = lock_string(package, "version").context("lock package without version")?;
        let source = lock_string(package, "source");
        let bom_ref = match source {
            Some(source) => format!("pkg:cargo/{name}@{version}?source={}", url_escape(source)),
            None => format!("pkg:cargo/{name}@{version}?workspace=true"),
        };
        by_name
            .entry(name.to_owned())
            .or_default()
            .push((version.to_owned(), bom_ref.clone()));
        package_refs.push(bom_ref.clone());
        let mut component = json!({
            "type": if source.is_none() { "application" } else { "library" },
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "purl": format!("pkg:cargo/{name}@{version}")
        });
        if let Some(checksum) = lock_string(package, "checksum") {
            component["hashes"] = json!([{ "alg": "SHA-256", "content": checksum }]);
        }
        if let Some(source) = source {
            component["properties"] = json!([{ "name": "cargo:source", "value": source }]);
        }
        components.push(component);
    }
    components.sort_by(|left, right| left["bom-ref"].as_str().cmp(&right["bom-ref"].as_str()));

    let mut dependencies = Vec::with_capacity(packages.len());
    for (index, package) in packages.iter().enumerate() {
        let mut depends_on = Vec::new();
        if let Some(entries) = package.get("dependencies").and_then(TomlValue::as_array) {
            for entry in entries.iter().filter_map(TomlValue::as_str) {
                let (name, version) = parse_lock_dependency(entry);
                if let Some(candidates) = by_name.get(name) {
                    depends_on.extend(
                        candidates
                            .iter()
                            .filter(|(candidate_version, _)| {
                                version.is_none_or(|version| version == candidate_version)
                            })
                            .map(|(_, reference)| reference.clone()),
                    );
                }
            }
        }
        depends_on.sort();
        depends_on.dedup();
        dependencies.push(json!({
            "ref": package_refs[index],
            "dependsOn": depends_on
        }));
    }
    dependencies.sort_by(|left, right| left["ref"].as_str().cmp(&right["ref"].as_str()));
    Ok((
        base_bom(
            components,
            dependencies,
            "Cargo.lock deterministic fallback; registry metadata unavailable",
        ),
        packages.len(),
    ))
}

fn parse_lock_dependency(dependency: &str) -> (&str, Option<&str>) {
    let mut parts = dependency.split_whitespace();
    let name = parts.next().unwrap_or(dependency);
    let version = parts
        .next()
        .filter(|candidate| candidate.as_bytes().first().is_some_and(u8::is_ascii_digit));
    (name, version)
}

fn base_bom(components: Vec<Value>, dependencies: Vec<Value>, source: &str) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "heraclitus-qualifier",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            },
            "properties": [{
                "name": "heraclitus:source",
                "value": source
            }]
        },
        "components": components,
        "dependencies": dependencies
    })
}

fn finish(
    output: &Path,
    bom: &Value,
    components: usize,
    source: &'static str,
) -> Result<SbomSummary> {
    write_json_new(output, bom)?;
    let sha256 = sha256_file(output)?;
    let sidecar = output.with_extension(format!(
        "{}sha256",
        output
            .extension()
            .map(|extension| format!("{}.", extension.to_string_lossy()))
            .unwrap_or_default()
    ));
    let filename = output
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    write_bytes_new(&sidecar, format!("{sha256}  {filename}\n").as_bytes())?;
    Ok(SbomSummary {
        format: "CycloneDX",
        spec_version: "1.5",
        components,
        sha256,
        source,
    })
}

pub fn generate(output: &Path) -> Result<SbomSummary> {
    if output.exists() {
        bail!("refusing to overwrite SBOM {}", output.display());
    }
    let current = std::env::current_dir()?;
    let repo = repository_root(&current)?;
    let metadata_output = Command::new("cargo")
        .args(["metadata", "--locked", "--offline", "--format-version", "1"])
        .current_dir(&repo)
        .output()
        .context("execute cargo metadata for SBOM")?;
    if metadata_output.status.success() {
        let metadata: Value =
            serde_json::from_slice(&metadata_output.stdout).context("parse cargo metadata")?;
        let (bom, components) = metadata_bom(&metadata)?;
        finish(output, &bom, components, "cargo-metadata")
    } else {
        let (bom, components) = lock_bom(&repo)?;
        finish(output, &bom, components, "cargo-lock-fallback")
    }
}

fn url_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(byte as char);
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_ids_are_escaped_for_bom_refs() {
        assert_eq!(url_escape("a b#c"), "a%20b%23c");
    }

    #[test]
    fn lock_dependency_version_is_optional() {
        assert_eq!(
            parse_lock_dependency("serde 1.0.0"),
            ("serde", Some("1.0.0"))
        );
        assert_eq!(parse_lock_dependency("local-crate"), ("local-crate", None));
        assert_eq!(
            parse_lock_dependency("serde 1.0.0 (registry+https://example.invalid)"),
            ("serde", Some("1.0.0"))
        );
    }
}
