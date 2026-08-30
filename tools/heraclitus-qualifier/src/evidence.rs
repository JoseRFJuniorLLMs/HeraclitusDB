use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::manifest::{EvidenceIndex, QualificationArtifact};

pub const INDEX_FILE: &str = "evidence-index.json";
pub const INDEX_DIGEST_FILE: &str = "evidence-index.sha256";

pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open {} for hashing", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create evidence directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite evidence {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write evidence {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync evidence {}", path.display()))?;
    Ok(())
}

pub fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).context("serialize evidence JSON")?;
    bytes.push(b'\n');
    write_bytes_new(path, &bytes)
}

pub fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create evidence directory {}", parent.display()))?;
    }
    let mut input =
        File::open(source).with_context(|| format!("open evidence source {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("refusing to overwrite evidence {}", destination.display()))?;
    std::io::copy(&mut input, &mut output).with_context(|| {
        format!(
            "copy evidence {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    output.sync_all()?;
    Ok(())
}

pub fn command_text(program: &str, args: &[&str], cwd: &Path) -> String {
    Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

pub fn repository_root(start: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start)
        .output()
        .context("execute git rev-parse --show-toplevel")?;
    if !output.status.success() {
        bail!(
            "qualification must run inside a Git checkout: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let root = String::from_utf8(output.stdout)
        .context("git root is not UTF-8")?
        .trim()
        .to_owned();
    fs::canonicalize(&root).with_context(|| format!("canonicalize repository root {root}"))
}

pub fn git_commit(repo: &Path) -> String {
    command_text("git", &["rev-parse", "HEAD"], repo)
}

pub fn repository_dirty(repo: &Path) -> bool {
    !command_text("git", &["status", "--porcelain"], repo).is_empty()
}

/// Number of untracked, non-ignored files in the checkout.
///
/// Recorded alongside the digest so a littered tree cannot pass as a clean one.
/// It is a count and not a hash on purpose: these files are *not* part of what
/// the digest covers, and the manifest has to say so rather than imply it.
pub fn untracked_file_count(repo: &Path) -> u64 {
    Command::new("git")
        .args(["ls-files", "-z", "--others", "--exclude-standard"])
        .current_dir(repo)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
                .count() as u64
        })
        .unwrap_or(0)
}

/// Hash the exact **tracked** source tree, including names and file lengths.
///
/// Tracked-only is the whole point. §111 requires another laboratory to
/// reproduce the run from the repository, and a clone of the commit contains
/// exactly the tracked files — never the untracked ones. Folding untracked
/// paths in produced a digest that no third party could ever recompute, and in
/// a checkout carrying a stray build directory it also meant hashing tens of
/// thousands of object files before the first trial could start.
///
/// The untracked state is not ignored, it is reported: `repository_dirty` and
/// [`untracked_file_count`] carry it into the manifest, and the runner turns a
/// dirty tree into a release limitation.
pub fn source_digest(repo: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--cached"])
        .current_dir(repo)
        .output()
        .context("list tracked source files")?;
    if !output.status.success() {
        bail!("git ls-files failed");
    }
    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8(path.to_vec()).context("tracked source path is not UTF-8"))
        .collect::<Result<Vec<_>>>()?;
    paths.sort();

    let mut tree = Sha256::new();
    for relative in paths {
        let path = repo.join(&relative);
        // Git may temporarily report a deleted tracked path in a dirty tree.
        // Record that state rather than silently hashing a different tree.
        tree.update((relative.len() as u64).to_le_bytes());
        tree.update(relative.as_bytes());
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                tree.update(metadata.len().to_le_bytes());
                let digest = sha256_file(&path)?;
                tree.update(digest.as_bytes());
            }
            Ok(_) => tree.update(b"NON_FILE"),
            Err(_) => tree.update(b"MISSING"),
        }
    }
    Ok(format!("{:x}", tree.finalize()))
}

pub fn relative_safe(root: &Path, child: &Path) -> Result<String> {
    let relative = child.strip_prefix(root).with_context(|| {
        format!(
            "artifact {} is outside evidence root {}",
            child.display(),
            root.display()
        )
    })?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("unsafe evidence path {}", relative.display());
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current)
        .with_context(|| format!("read evidence directory {}", current.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            bail!(
                "symbolic links are forbidden in evidence: {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            collect_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = relative_safe(root, &path)?;
            if relative != INDEX_FILE && relative != INDEX_DIGEST_FILE {
                files.push(path);
            }
        }
    }
    Ok(())
}

pub fn inventory(root: &Path) -> Result<Vec<QualificationArtifact>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by_key(|path| relative_safe(root, path).unwrap_or_default());
    files
        .into_iter()
        .map(|path| {
            let metadata = fs::metadata(&path)?;
            Ok(QualificationArtifact {
                path: relative_safe(root, &path)?,
                sha256: sha256_file(&path)?,
                size: metadata.len(),
            })
        })
        .collect()
}

pub fn merkle_root(artifacts: &[QualificationArtifact]) -> String {
    if artifacts.is_empty() {
        return sha256_bytes(b"HERACLITUS_EMPTY_EVIDENCE_V1");
    }
    let mut level = artifacts
        .iter()
        .map(|artifact| {
            let mut leaf = Sha256::new();
            leaf.update(b"HERACLITUS_EVIDENCE_LEAF_V1\0");
            leaf.update(artifact.path.as_bytes());
            leaf.update([0]);
            leaf.update(artifact.sha256.as_bytes());
            leaf.update(artifact.size.to_le_bytes());
            leaf.finalize().to_vec()
        })
        .collect::<Vec<_>>();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut node = Sha256::new();
            node.update(b"HERACLITUS_EVIDENCE_NODE_V1\0");
            node.update(left);
            node.update(right);
            next.push(node.finalize().to_vec());
        }
        level = next;
    }
    level[0].iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn seal(root: &Path, qualification_id: &str) -> Result<EvidenceIndex> {
    let artifacts = inventory(root)?;
    let index = EvidenceIndex {
        schema_version: 1,
        qualification_id: qualification_id.to_owned(),
        algorithm: "sha256-merkle-v1".to_owned(),
        merkle_root: merkle_root(&artifacts),
        artifacts,
    };
    let index_path = root.join(INDEX_FILE);
    write_json_new(&index_path, &index)?;
    let digest = sha256_file(&index_path)?;
    write_bytes_new(
        &root.join(INDEX_DIGEST_FILE),
        format!("{digest}  {INDEX_FILE}\n").as_bytes(),
    )?;
    Ok(index)
}

pub fn verify_inventory(root: &Path, index: &EvidenceIndex) -> Result<()> {
    let actual = inventory(root)?;
    let expected_paths = index
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    let actual_paths = actual
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    if expected_paths != actual_paths {
        bail!("evidence file set differs from the sealed index");
    }
    for (expected, observed) in index.artifacts.iter().zip(actual.iter()) {
        if expected.path != observed.path
            || expected.size != observed.size
            || expected.sha256 != observed.sha256
        {
            bail!("evidence artifact changed: {}", expected.path);
        }
    }
    let root_hash = merkle_root(&actual);
    if root_hash != index.merkle_root {
        bail!("evidence Merkle root mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_detects_later_mutation_and_extra_files() {
        let temp = tempfile::tempdir().unwrap();
        write_bytes_new(&temp.path().join("a.txt"), b"alpha").unwrap();
        let index = seal(temp.path(), "q-1").unwrap();
        verify_inventory(temp.path(), &index).unwrap();

        fs::write(temp.path().join("a.txt"), b"changed").unwrap();
        assert!(verify_inventory(temp.path(), &index).is_err());
    }

    #[test]
    fn the_source_digest_covers_only_what_a_clone_reproduces() {
        // A stray untracked file must not move the digest, or no second
        // laboratory could ever recompute it (§111).
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let before = source_digest(&repo).unwrap();
        let stray = repo.join("qualifier-source-digest-probe.tmp");
        fs::write(&stray, b"untracked").unwrap();
        let after = source_digest(&repo);
        let _ = fs::remove_file(&stray);
        assert_eq!(before, after.unwrap());
    }

    #[test]
    fn output_writes_are_create_new() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("immutable");
        write_bytes_new(&path, b"one").unwrap();
        assert!(write_bytes_new(&path, b"two").is_err());
        assert_eq!(fs::read(path).unwrap(), b"one");
    }
}
