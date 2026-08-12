//! The one way this crate flushes a directory.
//!
//! Atomic replacement is not durability. A `rename` either happens or does not,
//! but neither it nor the bytes before it are on disk until they are flushed,
//! and the entry a rename creates lives in a *directory* that has to be flushed
//! in its own right. Every staged write this crate publishes and later reads
//! back to resume from — a trust generation read at every start, an artifact
//! read at every boot, whatever the root daemon lands — therefore calls
//! [`sync_dir`] after the rename that made the entry appear.
//!
//! It lives here rather than being open-coded at each site so there is one
//! spelling of it to read and to get right.

use std::path::Path;

/// Flushes the directory at `path`, so the entries in it — the new name a
/// `rename` created, a file's creation — survive a crash or a power loss.
///
/// Call it **after** the rename it makes durable, never before: flushing a
/// directory says what is in it right now is on disk, so a flush that precedes
/// the entry it is meant to protect protects nothing.
///
/// `File::sync_all` is `fsync(2)` on Linux, which is the deployment target and
/// where the guarantee has to hold, and `fcntl(fd, F_FULLFSYNC)` on Apple
/// targets, so a developer machine gets the stronger call rather than a weaker
/// one.
///
/// No context is attached to the returned error. The modules that call this do
/// not agree on how an I/O error carries its path — two have a path-carrying
/// variant and one converts bare — so each names the flushed path the way its
/// neighbouring `std::fs` calls already do rather than fighting a decision made
/// here.
///
/// # Errors
///
/// Returns the [`std::io::Error`] from opening `path` or from flushing it: a
/// path that does not exist or is not readable by this process fails here
/// rather than succeeding silently.
pub(crate) fn sync_dir(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::sync_dir;

    #[test]
    fn flushes_an_existing_directory() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("landed"), b"bytes").unwrap();
        sync_dir(dir.path()).unwrap();
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let dir = tempdir().unwrap();
        let err = sync_dir(&dir.path().join("absent")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
