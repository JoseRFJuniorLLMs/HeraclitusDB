//! Supervision of a real `heraclitus-server` process for the trials that must
//! own its lifecycle (SPEC-0049 §22 crash injection, §18 soak).
//!
//! The qualifier launches the *release binary under qualification*, not an
//! embedded engine. A test that links the library into the harness proves the
//! library recovers; it does not prove the shipped process recovers, and §7
//! binds every result to a binary digest.

use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::evidence::write_bytes_new;

/// How the append path is configured for the run. Recorded in every report:
/// §9 forbids publishing a durability result without the durability mode, and
/// §24 measures acknowledgements against the *declared* contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityMode {
    /// `fsync` on every append.
    Always,
    /// Group commit at most once per interval.
    GroupCommit,
}

impl DurabilityMode {
    fn toml(self) -> String {
        match self {
            Self::Always => "[fsync]\nmode = \"always\"\n".to_owned(),
            Self::GroupCommit => "[fsync]\nmode = \"group_commit\"\ninterval_ms = 5\n".to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerSpec {
    pub binary: PathBuf,
    pub root: PathBuf,
    pub durability: DurabilityMode,
    pub segment_max_bytes: u64,
    pub storage_format: String,
    pub extra_config: BTreeMap<String, String>,
}

/// A running server plus the endpoints and log files bound to it.
#[derive(Debug)]
pub struct Supervised {
    child: Option<Child>,
    spec: ServerSpec,
    grpc_addr: String,
    rest_addr: String,
    config_path: PathBuf,
    generation: u32,
}

/// Reserve two distinct ephemeral ports.
///
/// Both listeners are held open at the same time before either is released, so
/// the OS cannot hand out the same port twice. There is still a window between
/// releasing them and the server binding — another process can take one — which
/// is why [`Supervised::start`] retries rather than trusting a single attempt.
/// Silently reusing a busy port would make a crash trial measure the wrong
/// process, so the failure is handled, never ignored.
fn free_port_pair() -> Result<(u16, u16)> {
    let first = TcpListener::bind("127.0.0.1:0").context("reserve a local port")?;
    let second = TcpListener::bind("127.0.0.1:0").context("reserve a local port")?;
    let ports = (first.local_addr()?.port(), second.local_addr()?.port());
    drop(first);
    drop(second);
    Ok(ports)
}

/// How many times to re-pick ports before giving up.
const START_ATTEMPTS: u32 = 5;

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\")
}

impl Supervised {
    /// Write the config once and start the first generation.
    pub fn start(mut spec: ServerSpec) -> Result<Self> {
        if !spec.binary.is_file() {
            bail!(
                "server binary under qualification does not exist: {}",
                spec.binary.display()
            );
        }
        // Every path written into the config must be absolute. The child runs
        // with its working directory set to the root, so a relative `data_dir`
        // would resolve a second time against the root and land in
        // `<root>/<root>/data` — which the server reports only as a NotFound
        // that looks like a permissions problem.
        spec.root = std::path::absolute(&spec.root)
            .with_context(|| format!("resolve qualification root {}", spec.root.display()))?;
        spec.binary = std::path::absolute(&spec.binary)
            .with_context(|| format!("resolve server binary {}", spec.binary.display()))?;
        let data_dir = spec.root.join("data");
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("create data directory {}", data_dir.display()))?;

        let mut last_failure = String::from("no attempt was made");
        for attempt in 1..=START_ATTEMPTS {
            let (grpc_port, rest_port) = free_port_pair()?;
            let grpc_addr = format!("127.0.0.1:{grpc_port}");
            let rest_addr = format!("127.0.0.1:{rest_port}");
            let mut config = String::new();
            config.push_str(&format!("data_dir = \"{}\"\n", toml_path(&data_dir)));
            config.push_str(&format!(
                "storage_format = \"{}\"\n",
                spec.storage_format.replace('"', "")
            ));
            config.push_str(&format!("grpc_addr = \"{grpc_addr}\"\n"));
            config.push_str(&format!("rest_addr = \"{rest_addr}\"\n"));
            config.push_str(&format!(
                "segment_max_bytes = {}\n",
                spec.segment_max_bytes.max(4096)
            ));
            for (key, value) in &spec.extra_config {
                config.push_str(&format!("{key} = {value}\n"));
            }
            config.push_str(&spec.durability.toml());
            // One config file per attempt: the evidence keeps every address the
            // campaign tried, and `write_bytes_new` never overwrites.
            let config_path = spec.root.join(format!("heraclitus-attempt-{attempt}.toml"));
            write_bytes_new(&config_path, config.as_bytes())?;

            let mut supervised = Self {
                child: None,
                spec: spec.clone(),
                grpc_addr,
                rest_addr,
                config_path,
                generation: 0,
            };
            supervised.spawn()?;

            // A port taken between reservation and bind shows up as an
            // immediate exit. Distinguish that from a slow start rather than
            // waiting out the readiness timeout on a process that is gone.
            std::thread::sleep(Duration::from_millis(600));
            match supervised.exited()? {
                None => return Ok(supervised),
                Some(code) => {
                    last_failure = format!(
                        "attempt {attempt} exited with code {code}; see {}",
                        supervised
                            .spec
                            .root
                            .join("logs")
                            .join(format!(
                                "heraclitus-attempt-{attempt}-generation-0001.stderr.log"
                            ))
                            .display()
                    );
                    // Drop the failed supervisor before the next attempt so its
                    // handles are released.
                    drop(supervised);
                }
            }
        }
        bail!("server did not stay up after {START_ATTEMPTS} attempts: {last_failure}")
    }

    fn spawn(&mut self) -> Result<()> {
        if self.child.is_some() {
            bail!("a server generation is already running");
        }
        self.generation += 1;
        // Prefixed by the config in use, so a retried start does not overwrite
        // the log that explains why the previous attempt died.
        let prefix = self
            .config_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "heraclitus".to_owned());
        let logs = self.spec.root.join("logs");
        let stdout_path = logs.join(format!(
            "{prefix}-generation-{:04}.stdout.log",
            self.generation
        ));
        let stderr_path = logs.join(format!(
            "{prefix}-generation-{:04}.stderr.log",
            self.generation
        ));
        if let Some(parent) = stdout_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let stdout = fs::File::create(&stdout_path)?;
        let stderr = fs::File::create(&stderr_path)?;
        let mut command = Command::new(&self.spec.binary);
        command
            .arg(&self.config_path)
            .current_dir(&self.spec.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // Strip every HERACLITUS_* variable the qualifier inherited.
        //
        // `HeraclitusConfig::load` applies environment overrides *after* the
        // file, so an inherited variable silently wins over the config this
        // harness just wrote. That is not a theoretical risk: on an operator
        // workstation that runs the service, the machine environment carries
        // `HERACLITUS_DATA_DIR` pointing at the **live database** and
        // `HERACLITUS_GRPC_ADDR` at the running port. Without this, a crash
        // trial would have abruptly killed a server attached to production
        // data, and the evidence would have recorded the configuration it
        // wrote rather than the one that ran — which §7 and §9 forbid.
        for (key, _) in std::env::vars() {
            if key.to_ascii_uppercase().starts_with("HERACLITUS_") {
                command.env_remove(&key);
            }
        }
        let child = command.spawn().with_context(|| {
            format!(
                "spawn server under qualification {}",
                self.spec.binary.display()
            )
        })?;
        self.child = Some(child);
        Ok(())
    }

    /// The `HERACLITUS_*` variables this process inherited, which the child
    /// does **not** see. Recorded in the report so the evidence states that the
    /// configuration under test was the file and nothing else.
    pub fn neutralised_environment() -> Vec<String> {
        let mut names = std::env::vars()
            .map(|(key, _)| key)
            .filter(|key| key.to_ascii_uppercase().starts_with("HERACLITUS_"))
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn grpc_endpoint(&self) -> String {
        format!("http://{}", self.grpc_addr)
    }

    pub fn rest_endpoint(&self) -> String {
        format!("http://{}", self.rest_addr)
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Has the process exited on its own? A crash trial must be able to tell an
    /// injected kill apart from a server that fell over by itself.
    pub fn exited(&mut self) -> Result<Option<i32>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        Ok(child.try_wait()?.and_then(|status| status.code()))
    }

    /// Terminate without any chance to flush, close or run shutdown hooks —
    /// `SIGKILL` on Unix, `TerminateProcess` on Windows.
    ///
    /// §25 is explicit that this is **not** equivalent to power loss: the OS
    /// page cache survives the process. The power-loss gate is a separate,
    /// externally attested trial and this call never stands in for it.
    pub fn kill_abruptly(&mut self) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            bail!("no server generation is running");
        };
        // An already-exited child makes `kill` fail on some platforms; that is
        // a self-inflicted crash, which the caller detects through `exited`.
        let _ = child.kill();
        child.wait().context("reap abruptly terminated server")?;
        Ok(())
    }

    /// Start the next generation over the same data directory.
    pub fn restart(&mut self) -> Result<()> {
        if self.child.is_some() {
            bail!("refusing to restart over a running generation");
        }
        self.spawn()
    }

    pub fn data_dir(&self) -> PathBuf {
        self.spec.root.join("data")
    }

    pub fn durability(&self) -> DurabilityMode {
        self.spec.durability
    }
}

impl Drop for Supervised {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Wait until the endpoint answers a snapshot call, or give up.
pub async fn wait_ready(endpoint: &str, timeout: Duration) -> Result<u64> {
    let deadline = Instant::now() + timeout;
    let mut last_error = String::from("never attempted");
    while Instant::now() < deadline {
        match heraclitus_client::Client::connect_with(endpoint, Duration::from_secs(2)).await {
            Ok(mut client) => match client.snapshot().await {
                Ok(head) => return Ok(head),
                Err(error) => last_error = error.to_string(),
            },
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    bail!("server did not become ready at {endpoint}: {last_error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durability_mode_is_written_as_the_engine_spells_it() {
        assert!(DurabilityMode::Always.toml().contains("mode = \"always\""));
        assert!(DurabilityMode::GroupCommit
            .toml()
            .contains("mode = \"group_commit\""));
    }

    #[test]
    fn windows_paths_survive_toml_quoting() {
        assert_eq!(
            toml_path(Path::new(r"D:\evidence\data")),
            r"D:\\evidence\\data"
        );
    }

    #[test]
    fn a_missing_binary_fails_before_any_directory_is_created() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("run");
        let error = Supervised::start(ServerSpec {
            binary: temp.path().join("does-not-exist"),
            root: root.clone(),
            durability: DurabilityMode::Always,
            segment_max_bytes: 8 * 1024 * 1024,
            storage_format: "v6".to_owned(),
            extra_config: BTreeMap::new(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("does not exist"));
        assert!(!root.exists());
    }
}
