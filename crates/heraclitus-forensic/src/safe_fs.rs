//! Open package paths without following links. Hold every ancestor until use.
use std::fs::File;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

pub(crate) fn valid(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(':')
        && !path.contains('\\')
        && !path.chars().any(|c| c.is_ascii_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && !part.ends_with(['.', ' ']))
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(windows)]
fn open_directory(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x02000000 | 0x00200000)
        .open(path)?;
    if !f.metadata()?.is_dir() || f.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("package directory is a reparse point"));
    }
    Ok(f)
}

/// Windows denies write/delete sharing on pinned ancestors and opens the final
/// component with OPEN_REPARSE_POINT. Unix uses openat/O_NOFOLLOW at each step.
pub(crate) fn open(root: &Path, relative: &str, write: bool) -> io::Result<File> {
    if !valid(relative) {
        return Err(io::Error::other("unsafe package path"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let mut pins = vec![open_directory(root)?];
        let mut path = root.to_path_buf();
        let parts: Vec<_> = relative.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            path.push(part);
            if write && !path.exists() {
                std::fs::create_dir(&path)?;
            }
            pins.push(open_directory(&path)?);
        }
        path.push(parts[parts.len() - 1]);
        let f = OpenOptions::new()
            .read(!write)
            .write(write)
            .create_new(write)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)?;
        if !f.metadata()?.is_file() || f.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("package object is a reparse point"));
        }
        if write {
            f.set_len(0)?;
        }
        Ok(f)
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let root = CString::new(root.as_os_str().as_bytes()).map_err(io::Error::other)?;
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut directory = unsafe { File::from_raw_fd(fd) };
        let parts: Vec<_> = relative.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            let name = CString::new(*part).map_err(io::Error::other)?;
            if write {
                let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io::Error::last_os_error());
                }
            }
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            directory = unsafe { File::from_raw_fd(fd) };
        }
        let name = CString::new(parts[parts.len() - 1]).map_err(io::Error::other)?;
        let flags = libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if write {
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
            } else {
                libc::O_RDONLY
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("object is not a regular file"));
        }
        if write {
            file.set_len(0)?;
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::other(
            "confined package IO unsupported on this platform",
        ))
    }
}

pub(crate) fn read(root: &Path, path: &str, limit: u64) -> io::Result<Vec<u8>> {
    let file = open(root, path, false)?;
    if file.metadata()?.len() > limit {
        return Err(io::Error::other("package file budget exceeded"));
    }
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(io::Error::other("package file budget exceeded"));
    }
    Ok(data)
}

pub(crate) fn write(root: &Path, path: &str, data: &[u8]) -> io::Result<()> {
    let mut f = open(root, path, true)?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    #[test]
    fn win32_normalization_cannot_turn_a_valid_component_into_parent_traversal() {
        for path in [
            "objects/.. /outside",
            "objects/.../outside",
            "objects/file.",
            "objects/file ",
            "objects//file",
            "objects/\0file",
        ] {
            assert!(!super::valid(path), "accepted {path:?}");
        }
        assert!(super::valid("objects/evidence.bin"));
    }
}
