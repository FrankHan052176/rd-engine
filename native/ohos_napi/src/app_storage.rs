//! Shared app-private store helpers for bridge-owned settings and directories.
//!
//! A store lives only under the fixed private root reserved by `appInit`; the
//! directory is resolved on the worker thread so no caller-supplied path and no
//! app metadata lock is involved. Writes use a private-mode temporary file that
//! is renamed over the destination, so a failed write cannot leave a half store
//! behind, and a read reports a missing file separately from a read failure.
use super::app_context::AppScope;
use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// The private directory these stores live in.
///
/// It is the same `rustdesk` directory the official configuration bootstrap
/// created under the reserved root, so it is resolved and verified here rather
/// than assumed from a caller string.
pub(super) fn store_dir(scope: &AppScope) -> Result<PathBuf, String> {
    let root = scope
        .root()
        .canonicalize()
        .map_err(|error| format!("cannot resolve the private root: {error}"))?;
    if !root.is_dir() {
        return Err("the private root is not a directory".to_string());
    }
    let dir = root
        .join("rustdesk")
        .canonicalize()
        .map_err(|error| format!("cannot resolve the private configuration directory: {error}"))?;
    if dir.parent() != Some(root.as_path()) {
        return Err(
            "the private configuration directory leaves the fixed private root".to_string(),
        );
    }
    Ok(dir)
}

/// Reads one store file, bounded before it is loaded.
///
/// `Ok(None)` means the file does not exist: "no store yet", which is a
/// successful observation of no data and not the same thing as a read failure.
pub(super) fn read_private(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect the private store: {error}")),
    };
    if !metadata.is_file() {
        return Err("the private store is not a file".to_string());
    }
    if metadata.len() > max_bytes {
        return Err("the private store is larger than this layer accepts".to_string());
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|error| format!("cannot read the private store: {error}"))
}

/// Writes one store file atomically: private temporary file, then rename.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut temporary_name = path.as_os_str().to_owned();
    temporary_name.push(".tmp");
    let temporary = PathBuf::from(temporary_name);
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("cannot write the private store: {error}"));
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("cannot commit the private store: {error}"));
    }
    Ok(())
}
