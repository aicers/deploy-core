//! Opening a caller-configured directory through held, no-follow handles.
//!
//! The staging parent and every publication destination parent are trusted
//! caller configuration. What this module adds is that the directory the
//! library ends up holding is the one the policy was judged against: the walk
//! opens `/` and then each component relative to the handle before it, with
//! `O_NOFOLLOW`, so no pathname is resolved a second time between the check
//! and the use. The policy stops unrelated users from redirecting or replacing
//! that storage. It does not defend against root, against other processes of
//! the effective user, or against a malicious filesystem.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};

use crate::package::DirectoryTrustReason;

/// Group- and other-write bits.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const STICKY: u32 = 0o1000;
/// Owner write and search bits.
const OWNER_WRITE_SEARCH: u32 = 0o300;
const ROOT_UID: u32 = 0;

/// The flags every directory in this module is opened with.
pub(crate) fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// A directory opened and judged by [`open_trusted_dir`].
#[derive(Debug)]
pub(crate) struct TrustedDir {
    file: File,
    /// The path the directory was opened by, for diagnostics only.
    path: PathBuf,
}

impl TrustedDir {
    /// Wraps a directory this crate created and opened itself, so it can be
    /// handled like one that passed the walk.
    pub(crate) fn from_parts(fd: OwnedFd, path: PathBuf) -> Self {
        Self {
            file: File::from(fd),
            path,
        }
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// Why [`open_trusted_dir`] refused or failed; `path` is the directory or
/// component where the check stopped.
#[derive(Debug)]
pub(crate) enum TrustedDirError {
    Unsafe {
        path: PathBuf,
        reason: DirectoryTrustReason,
    },
    Io {
        path: PathBuf,
        source: io::Error,
    },
}

/// The ownership and mode of one directory, as the policy sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirFacts {
    pub(crate) uid: u32,
    pub(crate) mode: u32,
}

impl DirFacts {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            uid: stat.st_uid,
            mode: widen_mode(stat.st_mode),
        }
    }
}

/// Widens a platform `mode_t` (`u16` on macOS, `u32` on Linux) to `u32`.
///
/// Generic so the same line compiles on both without an identity conversion.
pub(crate) fn widen_mode<M: Into<u32>>(mode: M) -> u32 {
    mode.into()
}

/// Opens the directory at `path` after checking its syntax, walking to it
/// through held no-follow handles, and judging every ancestor and the
/// directory itself.
///
/// The syntax rule runs on the raw bytes before any system call: the path is
/// absolute, and is either exactly `/` or has no empty, `.` or `..` segment
/// and no trailing `/`. Nothing here canonicalizes.
///
/// # Errors
///
/// Returns [`TrustedDirError::Unsafe`] with the first policy refusal, and
/// [`TrustedDirError::Io`] with the original error for an open or `fstat`
/// that fails for any other reason.
pub(crate) fn open_trusted_dir(path: &Path) -> Result<TrustedDir, TrustedDirError> {
    let components = canonical_components(path).map_err(|reason| TrustedDirError::Unsafe {
        path: path.to_owned(),
        reason,
    })?;
    let euid = rustix::process::geteuid().as_raw();

    let mut current_path = PathBuf::from("/");
    let mut current: OwnedFd = step!(
        OpenComponent,
        rustix::fs::open("/", dir_flags(), Mode::empty()).map_err(io::Error::from)
    )
    .map_err(|source| TrustedDirError::Io {
        path: current_path.clone(),
        source,
    })?;
    let mut facts = dir_facts(&current, &current_path)?;

    for component in components {
        let child_path = current_path.join(component);
        let child = match step!(
            OpenComponent,
            rustix::fs::openat(&current, component, dir_flags(), Mode::empty())
                .map_err(io::Error::from)
        ) {
            Ok(child) => child,
            Err(source) => {
                return Err(classify_open_failure(
                    &current, component, child_path, source,
                ));
            }
        };
        let child_facts = dir_facts(&child, &child_path)?;
        judge_ancestor(facts, child_facts, euid).map_err(|reason| TrustedDirError::Unsafe {
            path: current_path,
            reason,
        })?;
        current = child;
        current_path = child_path;
        facts = child_facts;
    }

    judge_selected(facts, euid).map_err(|reason| TrustedDirError::Unsafe {
        path: current_path.clone(),
        reason,
    })?;
    Ok(TrustedDir {
        file: File::from(current),
        path: current_path,
    })
}

/// Splits `path` into its components, or says why its syntax is refused.
///
/// `/` yields no component at all.
pub(crate) fn canonical_components(path: &Path) -> Result<Vec<&OsStr>, DirectoryTrustReason> {
    let bytes = path.as_os_str().as_bytes();
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return Err(DirectoryTrustReason::NotAbsolute);
    };
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    rest.split(|&b| b == b'/')
        .map(|segment| match segment {
            b"" | b"." | b".." => Err(DirectoryTrustReason::NotCanonical),
            segment => Ok(OsStr::from_bytes(segment)),
        })
        .collect()
}

fn dir_facts(fd: &OwnedFd, path: &Path) -> Result<DirFacts, TrustedDirError> {
    rustix::fs::fstat(fd)
        .map(|stat| DirFacts::from_stat(&stat))
        .map_err(|errno| TrustedDirError::Io {
            path: path.to_owned(),
            source: errno.into(),
        })
}

/// Names a failed component open for diagnostics. The `statat` here confers
/// nothing: the refusal already happened on the held-handle open.
fn classify_open_failure(
    parent: &OwnedFd,
    component: &OsStr,
    path: PathBuf,
    source: io::Error,
) -> TrustedDirError {
    match rustix::fs::statat(parent, component, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => TrustedDirError::Unsafe {
                path,
                reason: DirectoryTrustReason::SymlinkComponent,
            },
            FileType::Directory => TrustedDirError::Io { path, source },
            _ => TrustedDirError::Unsafe {
                path,
                reason: DirectoryTrustReason::NotDirectory,
            },
        },
        Err(_) => TrustedDirError::Io { path, source },
    }
}

/// Judges an ancestor `dir` of the selected directory, once its child `child`
/// on the walk is open.
///
/// `dir` is owned by root or by `euid`; and if it is group- or
/// other-writable, it is a root-owned sticky directory whose `child` is owned
/// by `euid` or by root — the `/tmp/<private>` shape.
pub(crate) fn judge_ancestor(
    dir: DirFacts,
    child: DirFacts,
    euid: u32,
) -> Result<(), DirectoryTrustReason> {
    let owner_trusted = dir.uid == ROOT_UID || dir.uid == euid;
    let writable_safely = dir.mode & GROUP_OR_OTHER_WRITE == 0
        || (dir.mode & STICKY != 0
            && dir.uid == ROOT_UID
            && (child.uid == euid || child.uid == ROOT_UID));
    if owner_trusted && writable_safely {
        Ok(())
    } else {
        Err(DirectoryTrustReason::UntrustedAncestor)
    }
}

/// Judges the selected directory itself; the first failing rule wins.
pub(crate) fn judge_selected(dir: DirFacts, euid: u32) -> Result<(), DirectoryTrustReason> {
    if dir.uid != euid && dir.uid != ROOT_UID {
        return Err(DirectoryTrustReason::UntrustedOwner);
    }
    if dir.mode & GROUP_OR_OTHER_WRITE != 0 {
        return Err(DirectoryTrustReason::GroupOrOtherWritable);
    }
    if euid == ROOT_UID || (dir.uid == euid && dir.mode & OWNER_WRITE_SEARCH == OWNER_WRITE_SEARCH)
    {
        Ok(())
    } else {
        Err(DirectoryTrustReason::NotWritableByEffectiveUser)
    }
}
