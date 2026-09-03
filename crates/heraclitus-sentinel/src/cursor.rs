//! Durable LSN cursor for replayable Sentinel processing.

use crate::error::SentinelError;
use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelCursor {
    pub next_lsn: Lsn,
    pub pipeline_version: u32,
}

impl SentinelCursor {
    pub const fn new(pipeline_version: u32) -> Self {
        Self {
            next_lsn: 0,
            pipeline_version,
        }
    }
}

/// Atomic cursor persistence.  A missing cursor is a clean first boot; a
/// malformed one is an error rather than silently replaying from zero.
#[derive(Debug, Clone)]
pub struct CursorStore {
    path: PathBuf,
}

impl CursorStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self, pipeline_version: u32) -> Result<SentinelCursor, SentinelError> {
        if !self.path.exists() {
            return Ok(SentinelCursor::new(pipeline_version));
        }
        let bytes = std::fs::read(&self.path)?;
        let cursor: SentinelCursor = serde_json::from_slice(&bytes)
            .map_err(|error| SentinelError::Cursor(format!("{}: {error}", self.path.display())))?;
        if cursor.pipeline_version != pipeline_version {
            return Err(SentinelError::Cursor(format!(
                "pipeline version mismatch: cursor={} configured={}",
                cursor.pipeline_version, pipeline_version
            )));
        }
        Ok(cursor)
    }

    pub fn commit(&self, cursor: SentinelCursor) -> Result<(), SentinelError> {
        let parent = self.path.parent().ok_or_else(|| {
            SentinelError::Cursor("cursor path must have an explicit parent".into())
        })?;
        std::fs::create_dir_all(parent)?;
        let temp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&cursor)
            .map_err(|error| SentinelError::Cursor(error.to_string()))?;
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        // POSIX rename replaces atomically.  Windows refuses replacement, so
        // retry with the documented remove+rename fallback; the temporary file
        // is always complete and durable before this point.
        //
        // O fallback TEM de ser exclusivo do Windows. Não estava gated, e em
        // Linux isso era destrutivo: aqui o `rename` substitui sempre, logo só
        // falha por uma razão real — ENOSPC, EACCES, EIO. Nessas condições o
        // ramo apagava o cursor VIVO e tentava outra vez, falhando pelo mesmo
        // motivo. Um erro de I/O transitório passava a perda do cursor, e com
        // ele o Sentinel perde a posição e reprocessa a base do início.
        match std::fs::rename(&temp, &self.path) {
            Ok(()) => {}
            Err(error) => {
                #[cfg(windows)]
                {
                    if self.path.exists() {
                        std::fs::remove_file(&self.path)?;
                        std::fs::rename(&temp, &self.path)?;
                    } else {
                        return Err(error.into());
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = std::fs::remove_file(&temp);
                    return Err(error.into());
                }
            }
        }
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_and_version_guard() {
        let temp = tempfile::tempdir().unwrap();
        let store = CursorStore::new(temp.path().join("sentinel/cursor.json"));
        assert_eq!(store.load(3).unwrap(), SentinelCursor::new(3));
        store
            .commit(SentinelCursor {
                next_lsn: 42,
                pipeline_version: 3,
            })
            .unwrap();
        assert_eq!(store.load(3).unwrap().next_lsn, 42);
        assert!(store.load(4).is_err());
    }
}
