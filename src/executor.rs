//! Executor abstraction backing the install phases.
//!
//! `bootler-core`'s phase code is written against an [`Executor`] so the
//! identical checks run against the seat (the [`LocalExecutor`]), a remote
//! target (the [`SshExecutor`]), or a root daemon that runs `bootler-core`
//! in-process (the [`InDaemonExecutor`], RFC 0001 §5) without change.
//!
//! The contract is split along two orthogonal axes (RFC 0003 §10):
//!
//! ```text
//! identity:  Operator | Root | Service(<account>)
//! transport: Local    | Ssh(<host>) | InDaemon
//! ```
//!
//! **The axes are deliberately asymmetric in the API.** Identity is a per-call
//! parameter: every primitive takes an [`Identity`], so a phase names the
//! identity it needs. Transport is a property of the executor *instance* — the
//! concrete type, constructed once per host and handed to phase code as a trait
//! object — so it appears in no call signature and phase code stays
//! transport-agnostic. That agnosticism is what RFC 0001 §5 relies on for
//! single-host/multi-host parity, and threading transport through call
//! signatures would destroy it.
//!
//! Resolving an `(identity, transport)` pair into a concrete invocation —
//! `sudo`, `sudo -u`, or no prefix at all — is the executor implementation's
//! business alone, and happens at exactly one site per transport.
//!
//! Elevation is settled on the trait before the SSH transport (RFC 0001 §4):
//! the elevating transports reuse a single sudo credential across the many
//! commands one run issues — prompted once per host in interactive mode, or
//! `sudo -n` (NOPASSWD) under `--non-interactive`, where a command that would
//! still prompt fails with a host-named [`ExecutorError::Elevation`].
//! [`SudoAuth`] does not apply to [`InDaemonExecutor`]: descending from root
//! never raises a password prompt, so there is nothing for it to answer.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::durability::sync_dir;
use crate::transport::{HostKeyPolicy, Ssh};

/// The `sudo` binary name used unless a test overrides it.
const SUDO: &str = "sudo";
/// Number of times a spawn is retried when the target reports `ETXTBSY`
/// ("Text file busy"). A binary that was just written (staged, or a test
/// script) can transiently be flagged busy when a concurrent `fork` in the
/// same process momentarily inherits a writable descriptor to it; the flag
/// clears the instant that child `execve`s and its close-on-exec descriptor
/// is dropped, so a handful of brief retries resolves the race without
/// masking a genuinely unrunnable binary.
const SPAWN_TEXT_BUSY_RETRIES: u32 = 8;
/// Backoff between `ETXTBSY` spawn retries.
const SPAWN_TEXT_BUSY_BACKOFF: Duration = Duration::from_millis(25);
/// The `ssh` binary name used unless the environment overrides it.
const SSH: &str = "ssh";
/// The `cat` binary used by the elevated read helper to slurp a root-owned
/// file back through the executor's elevation path.
const CAT: &str = "cat";
/// The `sh` binary used to run a command with a pinned working directory.
const SH: &str = "sh";
/// The `test` builtin used by [`file_present`] to probe for a regular file.
pub const TEST: &str = "test";
/// The `id` binary used to read the uid the current process runs as, for the
/// staging-directory ownership check in the native landing sequence.
const ID: &str = "id";
/// The `chown` binary used by [`Executor::chown_no_deref`] to hand an already
/// root-populated path to a service account without following a symlink at its
/// final component (RFC 0003 §11.3).
const CHOWN: &str = "chown";
/// The `stat` binary used by [`Executor::owner_of`] to read a path's owner and
/// group. GNU `stat` does not dereference a symlink at the named path (it is
/// `lstat`-like without `-L`), so a planted symlink reports its own ownership
/// rather than its target's — the property the ownership assertion depends on.
const STAT: &str = "stat";
/// The `sh -c` script that lands one file, run as a single elevated invocation
/// on the shell transports (RFC 0003 §9.2). Invoked as
/// `sh -c SCRIPT _ <dest> <owner> <group> <mode>`, so every value arrives
/// positionally and is never spliced into the script text.
///
/// The sequence is create-in-staging → write → chown/chmod → flush → rename →
/// flush:
///
/// - `mktemp` in the staging directory opens with `O_CREAT|O_EXCL` at mode
///   `0600`, so the temporary file is never readable by another account and
///   never adopts a file an attacker pre-created.
/// - The staging directory is the nearest ancestor **above the destination's
///   own directory** that the writing identity owns, no one else can write, and
///   that sits on the destination's own filesystem. Under `sudo` that identity
///   is root, so this is the root-only staging location §9.2 requires; skipping
///   the destination's own directory is what closes the TOCTOU, because that
///   directory may be service-writable. The predicate rejects a candidate
///   carrying *either* write bit — `-perm -0022` matches all-of, so the
///   single-predicate spelling would admit `0775`.
/// - **The filesystem is compared before anything is written.** The walk climbs
///   until it finds a root-only ancestor, and nothing stops it from climbing
///   past a mount point to get there. `mv` across a mount boundary is not a
///   `rename`: it degrades to copy-then-unlink, which is the non-atomic landing
///   §9.2 exists to rule out, and a copy that fails partway can leave a partial
///   destination behind. So each candidate's filesystem is compared to the
///   destination directory's — by `df -P`'s device *and* mount point, since
///   either alone can repeat — and the walk stops at the first boundary,
///   because every ancestor above one is on some other filesystem too. No
///   staging directory on the destination's filesystem is a refusal *before*
///   the temporary is created, not a failure discovered at the move.
/// - Owner, group and mode are applied to the temporary file, so the
///   destination name never resolves to a file with the wrong owner or a wider
///   mode. The shell cannot express descriptor-based metadata, so here the
///   guarantee is carried by the staging directory being unreachable to anyone
///   but the writer — nothing an unprivileged account can touch is ever named.
/// - `mv` renames over the destination, which replaces a symlink rather than
///   following it — except for one case `mv` does not share with `rename(2)`:
///   an existing *directory* at the destination is a target directory to `mv`,
///   which moves the temporary inside it and exits `0`. `rename(2)` fails
///   there, so the native path already refuses it; the script has to refuse it
///   explicitly or the shell transports would report a success that wrote to a
///   path the caller never named. A guard before the write refuses the ordinary
///   case, so contents never land inside a directory bootler was not asked to
///   write into; it follows symlinks, so a symlink pointing at a directory is
///   refused on the same terms.
/// - **The write is confirmed by identity, not by the absence of a directory.**
///   A directory appearing between that guard and the `mv` cannot be caught by
///   re-testing `[ -d "$dest" ]` afterwards: an account able to write the
///   destination's own directory can rename the directory away again before the
///   re-test runs, and the script would then report success for contents that
///   landed under a path the caller never named. So the check after the `mv` is
///   positive — the destination must *be* the object just staged, matched by
///   inode together with the owner, group and mode applied to it. Nothing an
///   attacker can put at the destination satisfies that: only one file carries
///   that inode, and an unprivileged account cannot produce a root-owned one.
///   Any bypass would have to hard-link the staged file to the destination,
///   which is the write succeeding. This confirms *what landed*; it is not what
///   keeps the landing atomic, since it runs after the `mv` and an inode number
///   is only unique within one device. The same-filesystem guarantee is the
///   staging-selection rule above, which acts before the move.
/// - **Both halves of the landing are flushed**, so a destination this script
///   reported written is durable as well as atomic — the promise
///   [`put_file_natively`] makes in process, made here too rather than left to
///   differ by transport for the same file. `flush "$tmp"` sits *after* the
///   `chown` and the `chmod` and before the `mv`, because what it protects is
///   the temporary's bytes together with the owner and mode just applied to it;
///   a flush placed above those two calls would leave what they set unflushed.
///   `flush "$(dirname "$dest")"` runs after the `mv`, because the entry a
///   rename creates lives in the destination's own directory and has to be
///   flushed in its own right, and does not exist yet at the first point — the
///   ordering rule [`crate::durability`] states for the native paths. Both
///   halves are reachable through `sync` because GNU coreutils' `sync` takes
///   operands and `fsync`s each one, and an operand may be a *directory*; it is
///   the operand that is the extension there, not the directory.
/// - **Which `sync` runs is settled by what it does, never by probing for the
///   name.** `sync "$1" 2>/dev/null || sync` is correct against all three
///   implementations a target can carry, and a `command -v sync` probe would be
///   worse than useless because the name is present in every one of them:
///   coreutils flushes the named object; macOS's `sync` and a busybox built
///   without `FEATURE_SYNC_FANCY` accept the operand, ignore it, flush every
///   filesystem on the host and exit `0` — which has already done everything
///   the fallback would; and an implementation that refuses the operand exits
///   non-zero, so the bare `sync` runs. POSIX `sync` takes no operands, so that
///   third outcome is the standard-conforming one and not an edge case. The
///   shells this has to survive `set -e` under — dash, bash and busybox ash —
///   carry no `sync` builtin, so the resolution is `PATH`'s in each, and the
///   `||` list is one whose left operands `set -e` exempts. `dd` is not the
///   alternative: the idiom that reads like a flush,
///   `dd if="$tmp" of=/dev/null conv=fsync`, flushes the *output* file and so
///   `fsync`s `/dev/null` while merely reading the temporary into the page
///   cache, and the form that works — `of="$tmp" conv=notrunc,fsync` — destroys
///   the file it was called to flush the moment `notrunc` is dropped, all while
///   still leaving the directory half to the floor.
/// - **The floor's cost is its breadth, and it is paid on every write that
///   reaches it.** A bare `sync` flushes every filesystem on the host, so on a
///   target already running services it can block for seconds on another
///   workload's dirty pages, and that is what a target without coreutils gets
///   for both halves of every landing. It is the fallback rather than the first
///   choice for exactly that reason. POSIX allows `sync` to return before the
///   writeback it scheduled has completed; Linux is the deployment target and
///   its `sync` waits for the writeback, so the floor is a real flush where the
///   guarantee has to hold and only a scheduling hint on a host that takes the
///   latitude. A target with no working `sync` at all does not fail the install
///   over it — the write goes through and the missing flush is said on stderr,
///   because an artifact the caller asked for is worth more than a guarantee it
///   never had, and silence is the one outcome that would let the write pass
///   for durable when it is not.
///
/// The `EXIT` trap is the cleanup path: any failure removes the temporary file
/// rather than leaving one behind for the caller to reason about. In the raced
/// case the misplaced file is removed when the directory `mv` moved it into is
/// still at the destination; when it is not, the write is reported failed and
/// what remains carries the requested owner and mode — for a secret, `0600`
/// root-owned — inside a directory the attacker already controlled.
const PUT_FILE_SCRIPT: &str = r#"set -e
dest=$1; owner=$2; group=$3; mode=$4
if [ -d "$dest" ]; then
  echo "destination $dest is a directory" >&2
  exit 1
fi
uid=$(id -u)
fsid() {
  df -P "$1" 2>/dev/null | awk 'NR==2 {mp=$6; for (i=7; i<=NF; i++) mp=mp" "$i; print $1"\t"mp}'
}
flush() {
  sync "$1" 2>/dev/null || sync || echo "warning: $1 was not flushed: no working sync" >&2
}
destfs=$(fsid "$(dirname "$dest")")
if [ -z "$destfs" ]; then
  echo "cannot determine the filesystem holding $dest" >&2
  exit 1
fi
stage=
dir=$(dirname "$(dirname "$dest")")
while :; do
  if [ -d "$dir" ]; then
    if [ "$(fsid "$dir")" != "$destfs" ]; then break; fi
    if [ -n "$(find "$dir" -maxdepth 0 -user "$uid" ! -perm -0002 ! -perm -0020 2>/dev/null)" ]; then
      stage=$dir; break
    fi
  fi
  up=$(dirname "$dir")
  if [ "$up" = "$dir" ]; then break; fi
  dir=$up
done
if [ -z "$stage" ]; then
  echo "no staging directory only the writer can write on the filesystem holding $dest" >&2
  exit 1
fi
tmp=$(mktemp "$stage/.bootler.XXXXXX")
trap 'rm -f "$tmp"' EXIT INT TERM
cat > "$tmp"
chown "$owner:$group" "$tmp"
chmod "$mode" "$tmp"
flush "$tmp"
ino=$(ls -di "$tmp" | awk '{print $1}')
mv -f "$tmp" "$dest"
flush "$(dirname "$dest")"
if [ -z "$(find "$dest" -maxdepth 0 -inum "$ino" -user "$owner" -group "$group" -perm "$mode" 2>/dev/null)" ]; then
  if [ -d "$dest" ]; then rm -f "$dest/${tmp##*/}"; fi
  echo "destination $dest is not the file just written" >&2
  exit 1
fi
trap - EXIT INT TERM"#;
/// The `sh -c` script that creates or reconciles one host directory. Invoked as
/// `sh -c SCRIPT _ <dir> <owner> <group> <mode> <policy>`, where `policy` is
/// [`DIR_POLICY_CORRECT`] or [`DIR_POLICY_VERIFY`].
///
/// An absent directory is created with explicit owner, group and mode — never a
/// bare `mkdir -p`, which would land it at the umask. An existing directory is
/// handled by who can write it (§9.2): a root-owned one is corrected, because
/// nothing unprivileged could have interfered with it; a service-writable one
/// is only verified, because repairing it means running a privileged operation
/// over entries a lower-privileged account controls.
///
/// The outcome is printed on stdout as one of [`DIR_CREATED`], [`DIR_MATCHED`]
/// or [`DIR_CORRECTED`]; a verify-policy mismatch exits [`DIR_MISMATCH_CODE`]
/// with the observed state on stderr.
const MAKE_DIR_SCRIPT: &str = r#"set -e
dir=$1; owner=$2; group=$3; mode=$4; policy=$5
if [ ! -d "$dir" ]; then
  install -d -o "$owner" -g "$group" -m "$mode" "$dir"
  echo created
  exit 0
fi
if [ -n "$(find "$dir" -maxdepth 0 -user "$owner" -group "$group" -perm "$mode" 2>/dev/null)" ]; then
  echo matched
  exit 0
fi
if [ "$policy" != correct ]; then
  echo "$(ls -ld "$dir")" >&2
  exit 3
fi
chown "$owner:$group" "$dir"
chmod "$mode" "$dir"
echo corrected"#;
/// [`MAKE_DIR_SCRIPT`] policy: reconcile an existing directory to the requested
/// metadata. Used where the directory is root-owned.
const DIR_POLICY_CORRECT: &str = "correct";
/// [`MAKE_DIR_SCRIPT`] policy: report a mismatch rather than repairing it. Used
/// where the directory is service-writable.
const DIR_POLICY_VERIFY: &str = "verify";
/// [`MAKE_DIR_SCRIPT`] stdout for a directory that did not exist.
const DIR_CREATED: &str = "created";
/// [`MAKE_DIR_SCRIPT`] stdout for a directory that already matched.
const DIR_MATCHED: &str = "matched";
/// [`MAKE_DIR_SCRIPT`] stdout for a directory reconciled under `correct`.
const DIR_CORRECTED: &str = "corrected";
/// [`MAKE_DIR_SCRIPT`] exit status for a `verify`-policy mismatch, kept distinct
/// from the shell's generic failure so it classifies as
/// [`ExecutorError::DirectoryMismatch`] rather than a transfer failure.
const DIR_MISMATCH_CODE: i32 = 3;
/// Mode the landing sequence's temporary file is created with, before the
/// requested mode is applied. Owner-only from the instant the file exists, so
/// secret-bearing contents are never briefly readable even in the temporary.
#[cfg(unix)]
const STAGING_TEMP_MODE: u32 = 0o600;
/// `root`'s uid and gid, which are fixed by the system rather than looked up.
#[cfg(unix)]
const ROOT_ID: u32 = 0;
/// Disambiguates concurrent native writes from one process, whose pid alone
/// would collide. `O_EXCL` makes a collision an error rather than a silent
/// overwrite, so this only avoids spurious failures.
#[cfg(unix)]
static NATIVE_TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// The `sh -c` script that runs a command with a caller-chosen working
/// directory: invoked as `sh -c SCRIPT _ <dir> <command> <args…>`, so `$1` is
/// the directory and the wrapped command/args follow after a `shift`. The
/// directory and every argument are passed positionally — never spliced into the
/// script text — so a path or argument with shell metacharacters is treated
/// strictly as data.
const CD_EXEC_SCRIPT: &str = r#"cd "$1"; shift; exec "$@""#;
/// Environment variable overriding the `ssh` program (the injectable seam that
/// lets preflight and the CLI e2e tests run without a live remote).
const SSH_BIN_ENV: &str = "BOOTLER_SSH_BIN";
/// Marker the remote wrapper prints on stderr to carry the remote command's own
/// exit status back separately from OpenSSH's process exit. OpenSSH exits `255`
/// for both a transport failure and a remote command that genuinely exits `255`,
/// so the status alone is ambiguous; the wrapper runs the command, captures
/// `$?`, and always exits `0` itself, printing `<marker><code>` here. Its
/// presence means the command ran (and this is the true remote code); its
/// absence means the transport failed before the command started.
const RC_MARKER: &str = "__BOOTLER_RC__:";
/// Marker the sudo wrapper prints on stderr the instant `sudo` has elevated and
/// begun running the wrapped command. It lets an elevation failure (sudo refused
/// before the command ran, so the marker is absent) be told apart from a wrapped
/// command that merely exited non-zero — even one whose own stderr mentions a
/// password — rather than classifying by scanning combined stderr afterwards.
const SUDO_OK_SENTINEL: &str = "__BOOTLER_SUDO_OK__";

/// Errors raised by an executor primitive.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// A command could not be spawned (for example the binary was not found).
    #[error("failed to spawn `{command}`: {source}")]
    Spawn {
        /// The command that could not be spawned.
        command: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A file transfer failed.
    #[error("i/o error on `{path}`: {source}")]
    Io {
        /// Path involved in the failed transfer.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A file transfer exited non-zero after the transport itself succeeded.
    #[error("transfer of `{path}` failed: {reason}")]
    Transfer {
        /// Path involved in the failed transfer.
        path: PathBuf,
        /// Why the transfer failed.
        reason: String,
    },
    /// The SSH transport itself failed — connection refused, authentication
    /// rejected, or host-key verification failed — rather than the remote
    /// command exiting non-zero. Detected because the remote wrapper never ran,
    /// so its exit-status marker is absent; a remote command that ran and
    /// returned any exit code (including `255`) is a [`CommandOutput`], not this
    /// error.
    #[error("host `{host}`: SSH connection failed: {reason}")]
    Connection {
        /// The host that could not be reached.
        host: String,
        /// Diagnostic text `ssh` wrote to stderr.
        reason: String,
    },
    /// A caller asked for [`Identity::Operator`] on a transport that has no
    /// operator identity to offer — the root daemon ([`InDaemonExecutor`]),
    /// which runs with no operator session to descend to.
    ///
    /// This is an explicit refusal rather than a silent fallback on purpose. A
    /// root daemon *could* just run the command, but that would execute an
    /// operator request as root: the identity contract inverted into a
    /// privilege escalation, and invisibly. There is no correct command here,
    /// so there must not be a guessed one.
    #[error("host `{host}`: no operator identity is available inside the root daemon")]
    NoOperatorIdentity {
        /// The host whose daemon was asked for an operator identity.
        host: String,
    },
    /// A directory bootler must create already exists with different ownership
    /// or mode, and is one a service account can write — so it is verified and
    /// never repaired (RFC 0003 §9.2, §11.3).
    ///
    /// Correcting a directory a lower-privileged account controls means running
    /// a privileged operation over entries that account can manipulate, which is
    /// the race the write contract exists to avoid, and no ordering makes it
    /// safe. A mismatch is therefore a hard error naming the path rather than
    /// something bootler fixes. Root-owned directories are corrected instead,
    /// because nothing unprivileged could have interfered with them.
    #[error("directory `{path}` has unexpected ownership or mode: {reason}")]
    DirectoryMismatch {
        /// The directory whose ownership or mode did not match.
        path: PathBuf,
        /// The observed state, as the target reported it.
        reason: String,
    },
    /// Elevated execution was required but the SSH user has no NOPASSWD and
    /// the run is non-interactive, so `sudo` cannot elevate without a prompt.
    #[error(
        "host `{host}`: sudo requires a password but the run is non-interactive; \
         configure NOPASSWD for the SSH user"
    )]
    Elevation {
        /// The host on which elevation could not proceed.
        host: String,
    },
    /// `sudo` refused to elevate before the wrapped command could start — the
    /// elevation sentinel never appeared — for a reason a password prompt cannot
    /// cure (for example the SSH user is not in the sudoers file, a sudo policy
    /// or plugin denied the request, or an interactive password was rejected).
    /// Told apart from the wrapped command's own non-zero exit by the sentinel's
    /// absence, so it is never mistaken for the requested command's result.
    #[error("host `{host}`: sudo could not elevate: {reason}")]
    SudoRefused {
        /// The host on which elevation could not proceed.
        host: String,
        /// The diagnostic `sudo` wrote before refusing.
        reason: String,
    },
}

/// The captured result of running a command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Exit code, or `None` when the process was terminated by a signal.
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    /// Reports whether the command exited with status 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// A service account bootler creates and runs components under (RFC 0003 §6).
///
/// This is a closed enum rather than a wrapped string, and that is the whole
/// point: the three accounts are fixed by the RFC and are bootler's own, never
/// operator configuration. Because there is no variant carrying a runtime
/// value, and no `FromStr`/`Deserialize`/`From<String>` on this type or on
/// [`Identity`], an account name read from operator input or off the host
/// **cannot be turned into an identity at all**. Elevation-by-injection
/// (RFC 0003 §9.2) is excluded by construction, not merely left untested.
///
/// §11.4 later validates these accounts against the host; that validation reads
/// host state to *check* an account, and still names the account itself with one
/// of these compile-time constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccount {
    /// `clumit-security` — runs `review` and its `bootroot-agent`.
    Security,
    /// `clumit-insight` — runs `aimer` and its `bootroot-agent`.
    Insight,
    /// `clumit-roxyd` — runs `roxyd`'s `bootroot-agent`.
    Roxyd,
    /// A test-only account, so the quoting tests can push a name the three real
    /// accounts cannot express.
    ///
    /// `&'static str` rather than `String` deliberately: even this escape hatch
    /// takes only a compile-time value, so it widens what a *test* can name
    /// without opening a runtime path into [`Identity`].
    #[cfg(any(test, feature = "test-support"))]
    Fixture(&'static str),
}

impl ServiceAccount {
    /// Returns the account's system user name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceAccount::Security => "clumit-security",
            ServiceAccount::Insight => "clumit-insight",
            ServiceAccount::Roxyd => "clumit-roxyd",
            #[cfg(any(test, feature = "test-support"))]
            ServiceAccount::Fixture(name) => name,
        }
    }
}

/// A host account naming the owner or the group of an artifact bootler writes
/// (RFC 0003 §9.1).
///
/// Closed on the same terms as [`ServiceAccount`], and for the same reason on a
/// second axis. [`Identity`] cannot be built from a runtime string, so an
/// account name read off the host or out of operator input cannot become an
/// identity commands run under; typing an owner as `String` would reopen
/// exactly that hole for the account artifacts are *owned by*. In production an
/// owner is `root` or one of the closed [`ServiceAccount`] set — never free
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// `root`, which owns every artifact bootler writes today.
    Root,
    /// One of the bootler-managed service accounts.
    Service(ServiceAccount),
    /// A numeric uid or gid, so the unprivileged tests can name the id the test
    /// process already runs as.
    ///
    /// **The test-only gate is the whole of the guarantee here, not a
    /// convenience.** [`ServiceAccount::Fixture`] takes a `&'static str` and so
    /// opens nothing at all; this variant cannot do the same, because a uid
    /// fixture reads `getuid()` at runtime by definition. What keeps it from
    /// widening the production type is that it does not exist in a release
    /// build — a non-test constructor would remove the property this variant
    /// was gated to establish.
    ///
    /// The gate is `any(test, feature = "test-support")` rather than bare
    /// `test` only so a dependent crate's *tests* can construct fixtures across
    /// the crate boundary (`test` is invisible to dependents). The property is
    /// preserved because `test-support` is enabled **only** as a
    /// `[dev-dependencies]` feature: no release build — of this crate or any
    /// consumer — turns it on, so the variant is still absent from every shipped
    /// artifact. Never list `test-support` under normal `[dependencies]`.
    #[cfg(any(test, feature = "test-support"))]
    Fixture(u32),
}

impl Principal {
    /// Returns the account as `chown`/`install` name it: a user or group name in
    /// production, a numeric id under the test fixture.
    ///
    /// Public because it is also how an owner or group is named to the operator
    /// — the reported form and the applied form are the same string, so there is
    /// no second rendering to keep in step.
    #[must_use]
    pub fn as_arg(self) -> String {
        match self {
            Principal::Root => "root".to_string(),
            Principal::Service(account) => account.as_str().to_string(),
            #[cfg(any(test, feature = "test-support"))]
            Principal::Fixture(id) => id.to_string(),
        }
    }
}

/// The owner, group and mode an artifact is created with (RFC 0003 §9.2).
///
/// **There is no `Default`, and that is deliberate**: a call site that has not
/// decided the ownership of what it writes has not finished. The named
/// constants below are the artifact classes bootler actually writes, so a call
/// site names a class rather than restating three fields — and a class that
/// does not exist yet is a decision to make, not a value to infer.
///
/// A `FileMeta` is fixed by the phase code and is never derived from operator
/// input or from a value read off the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    /// The account that owns the artifact.
    pub owner: Principal,
    /// The group that owns the artifact.
    pub group: Principal,
    /// The permission bits, as an octal literal (`0o644`).
    pub mode: u32,
}

impl FileMeta {
    /// A native binary under `bin/`: executable, world-readable.
    pub const ROOT_BINARY: Self = Self::new(Principal::Root, Principal::Root, 0o755);
    /// A rendered config or systemd unit: world-readable.
    pub const ROOT_CONFIG: Self = Self::new(Principal::Root, Principal::Root, 0o644);
    /// Secret-bearing material — rotation secrets, remote-bootstrap files:
    /// owner-only.
    pub const ROOT_SECRET: Self = Self::new(Principal::Root, Principal::Root, 0o600);
    /// A root-owned directory in the installed namespace.
    pub const ROOT_DIR: Self = Self::new(Principal::Root, Principal::Root, 0o755);
    /// A root-owned directory holding secret-bearing material: owner-only, so
    /// nothing inside is reachable by another account even transiently.
    pub const ROOT_SECRET_DIR: Self = Self::new(Principal::Root, Principal::Root, 0o700);
    /// A root-owned, group-restricted directory whose writer is root but which is
    /// closed to *others* — `bootroot/` and `module-store/` under a product's
    /// `/var/lib` (RFC 0003 §7.1). Both are written by root (the `bootroot` binary
    /// and bootler), so they stay root-owned rather than service-owned, but sit at
    /// `0750` so no account outside the namespace can list or traverse them.
    pub const ROOT_RESTRICTED_DIR: Self = Self::new(Principal::Root, Principal::Root, 0o750);

    /// A service-owned directory — the per-service `agent/<svc>/` root, and the
    /// service data directories: owned `<account>:<account>`, `0750`, closed to
    /// others (RFC 0003 §7.1). Its mode inside `agent/<svc>/` is partly bootroot's
    /// once `--cert-group` is in play (§7.1.1); verify asserts ownership there,
    /// not the exact mode.
    #[must_use]
    pub const fn service_dir(account: ServiceAccount) -> Self {
        Self::new(
            Principal::Service(account),
            Principal::Service(account),
            0o750,
        )
    }

    /// Service-owned secret-bearing material — `agent.toml`, `role_id`,
    /// `secret_id`, the private key, the fast-poll state file: owner-only `0600`.
    #[must_use]
    pub const fn service_secret(account: ServiceAccount) -> Self {
        Self::new(
            Principal::Service(account),
            Principal::Service(account),
            0o600,
        )
    }

    /// Service-owned world-readable material — the leaf certificate and the CA
    /// bundle: `0644`, so a peer or a bind-mounting container can read it.
    #[must_use]
    pub const fn service_readable(account: ServiceAccount) -> Self {
        Self::new(
            Principal::Service(account),
            Principal::Service(account),
            0o644,
        )
    }

    /// A namespace root (`/opt`, `/etc`, `/var/lib` under `clumit-<product>`):
    /// root-owned, group-owned by the product account, group-restricted so no
    /// other account can list or write it. `/opt` and `/etc` are `0751` so
    /// `clumit-roxyd` can *traverse* to its own directory and execute
    /// `bootroot-agent` without membership; `/var/lib` needs no such traversal
    /// and is `0750` (RFC 0003 §7).
    #[must_use]
    pub const fn namespace_root(account: ServiceAccount, mode: u32) -> Self {
        Self::new(Principal::Root, Principal::Service(account), mode)
    }

    /// A root-written config a service must read but never write — `review.toml`,
    /// `aimer.toml` (which embeds LLM API keys), the operator `ip2location.bin`:
    /// root-owned, group the product account, `0640` so it is not world-readable
    /// (RFC 0003 §7.1, §9.1). R1 and R2 both hold: bootler is the sole writer and
    /// the file is root-owned, while the account gets read via the group.
    #[must_use]
    pub const fn service_config(account: ServiceAccount) -> Self {
        Self::new(Principal::Root, Principal::Service(account), 0o640)
    }

    /// Creates a `FileMeta` from an explicit owner, group and mode.
    #[must_use]
    pub const fn new(owner: Principal, group: Principal, mode: u32) -> Self {
        Self { owner, group, mode }
    }

    /// Returns the mode as the four-digit octal string `chmod` and `install`
    /// take.
    fn mode_arg(self) -> String {
        format!("{:04o}", self.mode)
    }

    /// Returns whether the metadata describes a service-writable artifact, which
    /// is verified rather than repaired when it already exists (§9.2).
    fn is_service_writable(self) -> bool {
        matches!(self.owner, Principal::Service(_))
    }
}

/// What [`Executor::make_dir`] found and did.
///
/// Returned rather than logged because `bootler-core` has no output channel of
/// its own; a correction is the caller's to surface, and §9.2 requires that it
/// be surfaceable rather than silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirOutcome {
    /// The directory did not exist and was created with the requested metadata.
    Created,
    /// The directory existed and already carried the requested metadata.
    Matched,
    /// The directory existed with different metadata and was reconciled. Only
    /// root-owned directories reach this; a service-writable mismatch is
    /// [`ExecutorError::DirectoryMismatch`].
    Corrected,
}

/// Who a primitive runs as.
///
/// Named by the phase code on every call, and resolved into a concrete
/// invocation by the executor alone. The variants are not a privilege ladder:
/// [`Identity::Root`] is reached by *elevation* (`sudo`) while
/// [`Identity::Service`] is reached by *descent* (`sudo -u`), traversing root
/// rather than acquiring it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// The operator account the CLI itself runs as; no `sudo`.
    Operator,
    /// `root`, for the root-owned namespace paths (`/opt`, `/etc`, `/var/lib`,
    /// `/var/log` under `clumit-<product>`).
    Root,
    /// A bootler-managed service account, reached by descent.
    Service(ServiceAccount),
}

/// How elevating (`sudo`) operations authenticate, prompted once per host and
/// reused across every elevated command that host's run issues.
///
/// This governs [`Identity::Root`] and [`Identity::Service`] on the elevating
/// transports only. It does not apply to [`InDaemonExecutor`], where the caller
/// is already root and `sudo -u` never prompts. It is also independent of
/// [`SshPrompt`], which governs the transport's own authentication.
#[derive(Debug, Clone)]
pub enum SudoAuth {
    /// Interactive: feed this cached password to `sudo -S` (the password is
    /// obtained once, then reused).
    Password(String),
    /// Non-interactive: use `sudo -n`; an elevated command that would prompt
    /// is a host-named [`ExecutorError::Elevation`] error.
    NonInteractive,
}

/// Whether the SSH transport may prompt on the terminal for its own
/// authentication — a password, keyboard-interactive challenge, or key
/// passphrase.
///
/// This is a distinct axis from [`SudoAuth`]: SSH-level authentication is
/// negotiated before any remote `sudo` runs, so a run can allow an SSH
/// passphrase prompt while still elevating through `sudo -n`. A non-interactive
/// run forbids every transport prompt via `-o BatchMode=yes` so a would-be
/// prompt fails fast instead of hanging on `/dev/tty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshPrompt {
    /// The transport may prompt (an interactive run).
    Allow,
    /// The transport must never prompt (`-o BatchMode=yes`).
    Deny,
}

/// Runs commands and transfers files on one host.
///
/// The trait is object-safe so a single code path can dispatch across a mix of
/// local and remote executors.
pub trait Executor {
    /// Runs `command` with `args` as `identity`, capturing its output.
    ///
    /// `args` are discrete: each is preserved verbatim across the transport and
    /// is never re-split by an intermediate shell. How `identity` resolves into a
    /// concrete invocation — `sudo`, `sudo -u`, or no prefix — is this
    /// implementation's business alone; the caller only names who it needs to be.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the command cannot be spawned or the
    /// transport fails. A non-zero exit is reported through [`CommandOutput`],
    /// not as an error. When `identity` resolves through `sudo`, returns
    /// [`ExecutorError::Elevation`] when a non-interactive `sudo` needs a
    /// password the run cannot supply and [`ExecutorError::SudoRefused`] when
    /// `sudo` refuses for any other reason; a non-zero exit of the *elevated*
    /// command is still a [`CommandOutput`]. Returns
    /// [`ExecutorError::NoOperatorIdentity`] when `identity` is
    /// [`Identity::Operator`] on a transport that has none.
    fn run(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ExecutorError>;

    /// Writes `contents` to `dest` on the target with the owner, group and mode
    /// `meta` names (RFC 0003 §9.2).
    ///
    /// **This is the one primitive that takes no [`Identity`], and the asymmetry
    /// is the signal.** Writing installation artifacts is something the
    /// installer does, and the installer is root; the [`Identity::Service`]
    /// identity exists so *commands* can run as a service account, not so files
    /// can be written as one. A `Service`-identity write is therefore excluded
    /// by construction rather than rejected at runtime — the same discipline
    /// that leaves [`ServiceAccount`] without a runtime constructor. It is also
    /// what makes the sequence below implementable at all: a non-root account
    /// could neither create a temporary file in a root-only staging directory
    /// nor rename out of one, so restricting the primitive removes the case
    /// instead of splitting the algorithm.
    ///
    /// Every transport runs the same sequence: create the temporary file in a
    /// staging directory only the writer can write and on the destination's
    /// filesystem, write it, apply `meta` **before the file is reachable under
    /// its final name**, then `rename` over the destination. So the destination
    /// never exists with the wrong owner or a wider mode, and a symlink at the
    /// destination is replaced rather than followed. A failure at any step
    /// leaves no temporary file behind.
    ///
    /// The transports differ only in step 3's mechanism, and neither substitutes
    /// for the other: [`InDaemonExecutor`] applies metadata through the open
    /// descriptor (`fchown`/`fchmod`), never by pathname, so no path component
    /// changing mid-sequence can redirect it; [`LocalExecutor`] and
    /// [`SshExecutor`] run the sequence as a single `sudo sh -c` script, where
    /// the shell cannot express descriptor-based metadata and the guarantee is
    /// carried instead by the staging directory being unreachable to anyone but
    /// the writer.
    ///
    /// The landing is durable as well as atomic on **every** transport, so a
    /// destination this primitive reported written survives a crash or a power
    /// loss immediately after: the bytes together with the owner and mode are
    /// flushed before the rename, and the entry the rename created in the
    /// destination's directory is flushed after it. [`InDaemonExecutor`] gets
    /// that from `fsync` on the descriptors it already holds; the shell
    /// transports get it from the target's `sync`, which is the one place the
    /// guarantee rests on something the target supplies rather than on this
    /// crate — a host carrying no working `sync` still lands the file and says
    /// on stderr that it was not flushed.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the write fails, or the elevation errors
    /// of [`Executor::run`], since the write elevates on every transport that
    /// is not already root.
    fn put_file(&self, dest: &Path, contents: &[u8], meta: FileMeta) -> Result<(), ExecutorError>;

    /// Creates the directory `dest` on the target with the owner, group and mode
    /// `meta` names, reconciling one that already exists.
    ///
    /// Bare `mkdir -p` leaves a host directory at the umask, which is the same
    /// gap [`Executor::put_file`] closes for files, so directories are created
    /// through `install -d -o … -g … -m …` instead (§9.2).
    ///
    /// An existing directory is handled by who can write it, and the asymmetry
    /// is the point — correction is a privilege bootler may exercise only where
    /// nothing else could have interfered:
    ///
    /// - **Root-owned** directories are corrected, and the correction is
    ///   returned as [`DirOutcome::Corrected`]. Silently accepting one is how a
    ///   re-install inherits a weakened tree from a failed earlier attempt.
    ///
    ///   RFC 0003 §9.2 asks for that correction to be *reported to the
    ///   operator*, and this method carries it as far as its return value. Each
    ///   install call site funnels the outcome into the phase's
    ///   `CorrectionReport`, which the phase
    ///   hands back alongside its own outcome — on the failure path through
    ///   `InstallFailure` — and the CLI renders
    ///   through `Messages` in both locales.
    /// - **Service-writable** directories — those whose `meta.owner` is a
    ///   [`Principal::Service`] — are verified only. A mismatch is
    ///   [`ExecutorError::DirectoryMismatch`] naming the path, which *is*
    ///   operator-facing and is rendered through `Messages` in both locales.
    ///
    /// The default runs the reconciliation as one elevated script, which every
    /// transport can serve through [`Executor::run`] with [`Identity::Root`].
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::DirectoryMismatch`] when a service-writable
    /// directory does not match, [`ExecutorError::Transfer`] when the
    /// reconciliation itself fails, or the elevation errors of
    /// [`Executor::run`].
    fn make_dir(&self, dest: &Path, meta: FileMeta) -> Result<DirOutcome, ExecutorError> {
        make_dir_through_install(self, dest, meta)
    }

    /// Reads the file at `src` from the target as `identity`.
    ///
    /// [`Identity::Operator`] cannot read the root-owned `0600` files the install
    /// phases must fetch back — the persisted `secrets.json` on the idempotent
    /// re-run path, and bootroot's `secrets/` bootstrap bundle on the control
    /// node — so those callers name [`Identity::Root`].
    ///
    /// The default slurps the bytes through `cat` as `identity`, reusing
    /// whatever [`Executor::run`] resolves that identity to, so a transport
    /// needs no separate read channel and an elevated read costs no extra
    /// plumbing. A transport overrides this only where it has a cheaper native
    /// read for the identity in question — both shipped transports override it
    /// for [`Identity::Operator`] and fall back to this path otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Transfer`] when the read exits non-zero (a
    /// missing or unreadable file), or the elevation errors of
    /// [`Executor::run`] when `identity` resolves through `sudo`.
    fn fetch_file(&self, identity: Identity, src: &Path) -> Result<Vec<u8>, ExecutorError> {
        fetch_through_cat(self, identity, src)
    }

    /// Runs `command` with `args` as `identity` from the working directory `dir`.
    ///
    /// bootroot resolves its `state.json` and `secrets/` tree relative to the
    /// process working directory (its CLI exposes no global `--state-file`, and
    /// `--secrets-dir` is accepted only by a few subcommands), so bootler pins the
    /// directory here rather than by flag. The wrapped command runs exactly as it
    /// would under [`Executor::run`], only with `dir` as its cwd — including when
    /// `identity` elevates, so a root-owned state root such as
    /// `/var/lib/clumit-<product>` is reachable. The default wraps through
    /// `sh -c`, passing the directory and every argument positionally so a
    /// metacharacter-laden path is never re-parsed.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Executor::run`].
    fn run_in(
        &self,
        identity: Identity,
        dir: &Path,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ExecutorError> {
        let wrapped = wrap_in_dir(dir, command, args);
        let borrowed: Vec<&str> = wrapped.iter().map(String::as_str).collect();
        self.run(identity, SH, &borrowed)
    }

    /// Hands an already-populated path to the account `meta` names, changing only
    /// its owner and group and **never** following a symlink at the final path
    /// component (`chown --no-dereference`).
    ///
    /// This is the ownership half of the RFC 0003 §11.3 handoff: `bootroot service
    /// add` creates `agent.toml` and the `AppRole` credentials root-owned before the
    /// agent's unit exists, so ownership cannot come from agent identity alone and
    /// a first install chowns the enumerated set to the account. It is enumerated,
    /// per-path, and never recursive — a privileged recursive walk into a tree a
    /// service account controls is exactly the race the RFC exists to close. Mode
    /// is left untouched, since inside `agent/<svc>/` it is partly bootroot's
    /// (§7.1.1).
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Transfer`] when the `chown` exits non-zero, or the
    /// elevation errors of [`Executor::run`].
    fn chown_no_deref(&self, path: &Path, meta: FileMeta) -> Result<(), ExecutorError> {
        let spec = format!("{}:{}", meta.owner.as_arg(), meta.group.as_arg());
        let output = self.run(
            Identity::Root,
            CHOWN,
            &["--no-dereference", &spec, &path.to_string_lossy()],
        )?;
        if output.success() {
            Ok(())
        } else {
            Err(ExecutorError::Transfer {
                path: path.to_path_buf(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }

    /// Reads a path's owner and group as `(user, group)` names, via a root-identity
    /// `stat -c %U:%G`.
    ///
    /// GNU `stat` does not dereference a symlink at the named path, so a symlink
    /// planted at a final component reports its own ownership, not its target's —
    /// which is what lets the ownership assertion (RFC 0003 §11.3, §11.7) detect a
    /// swap rather than be fooled by one. A numeric id the host cannot resolve to a
    /// name is returned verbatim (`stat` prints the number), which compares equal
    /// only to a like-numbered expectation.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Transfer`] when the path is missing or the `stat`
    /// output is malformed, or the elevation errors of [`Executor::run`].
    fn owner_of(&self, path: &Path) -> Result<(String, String), ExecutorError> {
        let output = self.run(
            Identity::Root,
            STAT,
            &["-c", "%U:%G", &path.to_string_lossy()],
        )?;
        if !output.success() {
            return Err(ExecutorError::Transfer {
                path: path.to_path_buf(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text.trim();
        match line.split_once(':') {
            Some((user, group)) => Ok((user.to_string(), group.to_string())),
            None => Err(ExecutorError::Transfer {
                path: path.to_path_buf(),
                reason: format!("unexpected stat output: {line}"),
            }),
        }
    }
}

/// Reports whether `path` is a regular file on the executor's host, via a
/// root-identity `test -f`.
///
/// This is the shared existence probe for the callers that need to tell "the
/// file is not there" from "the read failed" — a distinction
/// [`Executor::fetch_file`] deliberately collapses, since its contract returns
/// [`ExecutorError::Transfer`] for both and only one transport can ever produce
/// an `Io { NotFound }`. A plain non-zero `test` means absent, not a failure;
/// only a transport error propagates.
///
/// Deliberately `test -f` rather than `test -e`: every caller here is asking
/// about a regular file it intends to read. `crate::uninstall` keeps its own
/// `test -e` predicate because it gates directories and symlinks too, and
/// folding the two together would silently narrow that check.
///
/// # Errors
///
/// Returns the errors of [`Executor::run`].
pub fn file_present(executor: &dyn Executor, path: &Path) -> Result<bool, ExecutorError> {
    let output = executor.run(Identity::Root, TEST, &["-f", &path.to_string_lossy()])?;
    Ok(output.success())
}

/// Reports whether `path` exists at all (a regular file, directory, or symlink),
/// via a root-identity `test -e`. Unlike [`file_present`] this does not narrow to
/// regular files, so the §11.3 handoff can tell an already-created agent
/// directory from an absent one.
/// # Errors
///
/// Returns [`ExecutorError`] if the probe cannot be run at all. A probe that
/// runs and finds nothing is `Ok(false)`, not an error.
pub fn path_present(executor: &dyn Executor, path: &Path) -> Result<bool, ExecutorError> {
    let output = executor.run(Identity::Root, TEST, &["-e", &path.to_string_lossy()])?;
    Ok(output.success())
}

/// Compares `path`'s on-disk owner and group against what `meta` names, returning
/// `Some((expected, actual))` on a mismatch and `None` when they match. Both
/// sides render as `owner:group` name strings.
///
/// This is the shared ownership check behind three call sites (RFC 0003 §11.3,
/// §11.7): the handoff's re-install branch (which verifies rather than re-chowns),
/// the update path's stop-agent-then-verify step, and `verify`. A missing path is
/// propagated as [`ExecutorError::Transfer`] from [`Executor::owner_of`], so an
/// absent enumerated artifact is a checkable condition rather than a silent pass.
/// # Errors
///
/// Returns whatever [`Executor::owner_of`] reports, which includes
/// [`ExecutorError::Transfer`] for a path that is not there — an absent
/// artifact is a condition to be checked, not a silent match.
pub fn ownership_mismatch(
    executor: &dyn Executor,
    path: &Path,
    meta: FileMeta,
) -> Result<Option<(String, String)>, ExecutorError> {
    let (actual_owner, actual_group) = executor.owner_of(path)?;
    let expected = format!("{}:{}", meta.owner.as_arg(), meta.group.as_arg());
    let actual = format!("{actual_owner}:{actual_group}");
    Ok(if expected == actual {
        None
    } else {
        Some((expected, actual))
    })
}

/// Reads `src` by slurping it through [`CAT`] as `identity`, for the transports
/// whose native read primitive runs only as the operator.
///
/// A non-zero exit (a missing or unreadable file) is an
/// [`ExecutorError::Transfer`]; an elevation failure surfaces as the executor's
/// own host-named error, propagated unchanged.
fn fetch_through_cat<E: Executor + ?Sized>(
    executor: &E,
    identity: Identity,
    src: &Path,
) -> Result<Vec<u8>, ExecutorError> {
    let output = executor.run(identity, CAT, &[&src.to_string_lossy()])?;
    if output.success() {
        Ok(output.stdout)
    } else {
        Err(ExecutorError::Transfer {
            path: src.to_path_buf(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// Builds the `sh` argument vector that runs [`PUT_FILE_SCRIPT`] for one write.
///
/// This is the single place the shell transports' landing sequence is
/// constructed, so [`LocalExecutor`] and [`SshExecutor`] emit an identical
/// script and the shape can be asserted once.
fn landing_argv(dest: &Path, meta: FileMeta) -> Vec<String> {
    vec![
        "-c".to_string(),
        PUT_FILE_SCRIPT.to_string(),
        "_".to_string(),
        dest.to_string_lossy().into_owned(),
        meta.owner.as_arg(),
        meta.group.as_arg(),
        meta.mode_arg(),
    ]
}

/// Reconciles `dest` to `meta` by running [`MAKE_DIR_SCRIPT`] as root, for the
/// transports that have no cheaper native path.
///
/// The policy the script runs under is derived from `meta` rather than passed
/// separately: an owner that is a service account *is* the statement that the
/// directory is service-writable, so there is no way to ask for a
/// service-writable directory to be repaired.
fn make_dir_through_install<E: Executor + ?Sized>(
    executor: &E,
    dest: &Path,
    meta: FileMeta,
) -> Result<DirOutcome, ExecutorError> {
    let policy = if meta.is_service_writable() {
        DIR_POLICY_VERIFY
    } else {
        DIR_POLICY_CORRECT
    };
    let output = executor.run(
        Identity::Root,
        SH,
        &[
            "-c",
            MAKE_DIR_SCRIPT,
            "_",
            &dest.to_string_lossy(),
            &meta.owner.as_arg(),
            &meta.group.as_arg(),
            &meta.mode_arg(),
            policy,
        ],
    )?;
    if output.code == Some(DIR_MISMATCH_CODE) {
        return Err(ExecutorError::DirectoryMismatch {
            path: dest.to_path_buf(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    if !output.success() {
        return Err(ExecutorError::Transfer {
            path: dest.to_path_buf(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        DIR_CREATED => Ok(DirOutcome::Created),
        DIR_CORRECTED => Ok(DirOutcome::Corrected),
        DIR_MATCHED => Ok(DirOutcome::Matched),
        other => Err(ExecutorError::Transfer {
            path: dest.to_path_buf(),
            reason: format!("unrecognised directory outcome `{other}`"),
        }),
    }
}

/// The landing sequence run with direct syscalls, for the transport that is
/// already root and needs neither a shell nor `sudo` (RFC 0003 §9.2).
///
/// This is the descriptor-based half of step 3 and is not interchangeable with
/// the script the shell transports run: owner and mode are applied to the
/// object already held open, so no path component changing between the write
/// and the `chown` can redirect them. The shell cannot express that, which is
/// why the two mechanisms both exist rather than one standing in for the other.
///
/// The landing is durable as well as atomic: on return the file's bytes, its
/// owner and its mode are on disk, and so is the destination directory's entry
/// naming it, so a crash or a power loss immediately after cannot leave the
/// destination empty or absent.
#[cfg(unix)]
fn put_file_natively<E: Executor + ?Sized>(
    executor: &E,
    dest: &Path,
    contents: &[u8],
    meta: FileMeta,
) -> Result<(), ExecutorError> {
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, fchown};

    let stage = staging_dir(dest)?;
    // The directory the rename's new entry appears in, bound here because the
    // call above is what makes it infallible: `select_staging_dir` opens with
    // `dest.parent()?`, and `staging_dir` turns that `None` into a `Transfer`
    // error, so a parentless destination never reaches this line.
    let dest_dir = dest
        .parent()
        .expect("staging_dir has already refused a destination with no parent");
    let uid = numeric_id(executor, meta.owner, IdKind::User)?;
    let gid = numeric_id(executor, meta.group, IdKind::Group)?;
    let temp = stage.join(format!(
        ".bootler.{}.{}.tmp",
        std::process::id(),
        NATIVE_TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));

    // `create_new` is `O_CREAT|O_EXCL`, so an entry an attacker pre-created is
    // never adopted, and `mode` makes the file owner-only from the instant it
    // exists rather than at the umask.
    let landed = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(STAGING_TEMP_MODE)
            .open(&temp)?;
        file.write_all(contents)?;
        // Metadata goes on before the file is reachable under its final name,
        // and through the descriptor rather than the path, so the destination
        // never resolves to a file with the wrong owner or a wider mode and
        // nothing renaming a path component can redirect either call.
        fchown(&file, Some(uid), Some(gid))?;
        file.set_permissions(Permissions::from_mode(meta.mode))?;
        // Flushed here rather than straight after the write: `sync_all` covers
        // metadata as well as data, and the owner and the mode this function
        // exists to get right are precisely that metadata, so a flush placed
        // above the two calls would leave what they set unflushed. What it
        // protects is a destination that survives a crash holding the bytes and
        // the ownership this call promised.
        file.sync_all()?;
        // `rename` replaces whatever is at the destination — including a
        // symlink, which it does not follow — atomically.
        std::fs::rename(&temp, dest)
    })();
    if landed.is_err() {
        // The cleanup path belongs to the primitive, not to its callers: a
        // failure at any step leaves no temporary file behind.
        let _ = std::fs::remove_file(&temp);
    }
    landed.map_err(|source| ExecutorError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    // The entry the rename created lives in the destination's own directory, so
    // that is what has to be flushed for the landing to survive a crash — not
    // the staging directory, which is somewhere else entirely and whose lost
    // temporary entry would be inert anyway.
    sync_dir(dest_dir).map_err(|source| ExecutorError::Io {
        path: dest_dir.to_path_buf(),
        source,
    })
}

/// What the staging walk needs to know about one candidate directory.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirFacts {
    /// The owning uid, which must be the writer's.
    uid: u32,
    /// The permission bits, which must carry neither the group nor the other
    /// write bit.
    mode: u32,
    /// The device the directory lives on, which must be the destination's.
    dev: u64,
}

/// Returns the staging directory for a native write: the nearest ancestor
/// **above the destination's own directory** that the writing process owns,
/// no one else can write, and that sits on the destination's own filesystem.
///
/// Skipping the destination's own directory is what closes the TOCTOU that
/// `O_EXCL` alone does not — under `agent/<svc>/` that directory is
/// service-writable, so an account could replace the temporary file between the
/// open and the `rename`.
///
/// The device check is the other half, and it is not a formality the installed
/// layout makes redundant: the walk climbs until it finds a root-only ancestor,
/// and nothing stops it from climbing *past a mount point* to get there. §9.2
/// requires staging on the destination's filesystem so the landing is a
/// `rename` rather than a copy, so a candidate above a mount boundary is
/// refused here — before anything is written — rather than discovered when the
/// move is attempted. The walk stops at the first boundary it meets, because
/// every ancestor above one is on some other filesystem too.
#[cfg(unix)]
fn staging_dir(dest: &Path) -> Result<PathBuf, ExecutorError> {
    use std::os::unix::fs::MetadataExt;

    let uid = current_uid()?;
    // A destination directory that cannot be stat'd is reported as the I/O
    // error it is — the walk would refuse it too, having no filesystem to match
    // against, but "no such directory" is the useful thing to say.
    if let Some(dest_dir) = dest.parent() {
        std::fs::metadata(dest_dir).map_err(|source| ExecutorError::Io {
            path: dest.to_path_buf(),
            source,
        })?;
    }
    select_staging_dir(dest, uid, |dir| {
        let meta = std::fs::metadata(dir).ok()?;
        meta.is_dir().then(|| DirFacts {
            uid: meta.uid(),
            mode: meta.mode(),
            dev: meta.dev(),
        })
    })
    .ok_or_else(|| ExecutorError::Transfer {
        path: dest.to_path_buf(),
        reason: "no staging directory only the writer can write on the destination's filesystem \
                 above the destination"
            .to_string(),
    })
}

/// The staging walk itself, over a caller-supplied view of the filesystem.
///
/// [`staging_dir`] supplies the real `stat`; a test supplies a synthetic one, so
/// the selection rule — including the mount boundary, which an unprivileged CI
/// cannot construct for real — is exercised rather than assumed.
#[cfg(unix)]
fn select_staging_dir<F>(dest: &Path, uid: u32, probe: F) -> Option<PathBuf>
where
    F: Fn(&Path) -> Option<DirFacts>,
{
    let dest_dir = dest.parent()?;
    // Without the destination's own device there is nothing to compare an
    // ancestor against, so there is no way to promise the landing is a rename.
    let dest_dev = probe(dest_dir)?.dev;
    let mut candidate = dest_dir.parent();
    while let Some(dir) = candidate {
        // An unreadable ancestor is stepped over, as it always was; a readable
        // one on another device ends the walk, since so is everything above it.
        if let Some(facts) = probe(dir) {
            if facts.dev != dest_dev {
                return None;
            }
            if facts.uid == uid && facts.mode & 0o022 == 0 {
                return Some(dir.to_path_buf());
            }
        }
        candidate = dir.parent();
    }
    None
}

/// Which of `id`'s two numeric outputs a [`Principal`] is being resolved to.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum IdKind {
    /// A uid, read with `id -u`.
    User,
    /// A gid, read with `id -g`.
    Group,
}

#[cfg(unix)]
impl IdKind {
    /// Returns the `id` flag selecting this kind.
    fn flag(self) -> &'static str {
        match self {
            IdKind::User => "-u",
            IdKind::Group => "-g",
        }
    }
}

/// Resolves a [`Principal`] to the numeric id `fchown` takes.
///
/// `root` and the test fixture are numeric by construction; only a service
/// account needs the host consulted, and it is named by a compile-time constant
/// even then.
///
/// In the group position this resolves `id -g <account>` — the *user*'s primary
/// group — whereas the shell transports pass the same [`Principal`] to
/// `chown owner:group`, where it names a *group*. The two agree only while a
/// service account's primary group is the like-named group RFC 0003 §7.1 has
/// bootroot create alongside it. That is no longer relied on: `crate::accounts`
/// creates every account with `useradd --user-group` and asserts `id -gn` equals
/// the account name at Phase 0, on creation and on reuse alike, so an account
/// whose primary group diverges aborts the install before any write reaches
/// here. Nothing exercises the difference today in any case, since every
/// production [`FileMeta`] is still `root:root`.
#[cfg(unix)]
fn numeric_id<E: Executor + ?Sized>(
    executor: &E,
    principal: Principal,
    kind: IdKind,
) -> Result<u32, ExecutorError> {
    let account = match principal {
        Principal::Root => return Ok(ROOT_ID),
        #[cfg(any(test, feature = "test-support"))]
        Principal::Fixture(id) => return Ok(id),
        Principal::Service(account) => account,
    };
    let output = executor.run(Identity::Root, ID, &[kind.flag(), account.as_str()])?;
    parse_id(&output, account.as_str())
}

/// Returns the uid the current process runs as, read once through `id -u`.
///
/// `std` exposes no `getuid`, and the staging check needs the uid on every
/// write, so the answer is cached: it cannot change for a running process.
#[cfg(unix)]
fn current_uid() -> Result<u32, ExecutorError> {
    static CURRENT_UID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    CURRENT_UID
        .get_or_init(|| {
            let output = Command::new(ID).arg("-u").output().ok()?;
            String::from_utf8_lossy(&output.stdout).trim().parse().ok()
        })
        .ok_or_else(|| ExecutorError::Transfer {
            path: PathBuf::from(ID),
            reason: "could not read the current uid".to_string(),
        })
}

/// Parses the numeric id `id` printed, naming `account` when it did not print
/// one (an account the host does not know).
#[cfg(unix)]
fn parse_id(output: &CommandOutput, account: &str) -> Result<u32, ExecutorError> {
    let id = String::from_utf8_lossy(&output.stdout).trim().parse().ok();
    match id.filter(|_| output.success()) {
        Some(id) => Ok(id),
        // A non-zero exit and unparsable output mean the same thing — the host
        // does not know this account — so they report the same way.
        None => Err(ExecutorError::Transfer {
            path: PathBuf::from(account),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }),
    }
}

/// Builds the `sh` argument vector that runs `command`/`args` from `dir` via
/// [`CD_EXEC_SCRIPT`]. Returns the arguments for `sh` (the program itself is
/// [`SH`]); the directory and each wrapped argument are discrete words, so they
/// survive verbatim across either transport.
fn wrap_in_dir(dir: &Path, command: &str, args: &[&str]) -> Vec<String> {
    let mut wrapped = vec![
        "-c".to_string(),
        CD_EXEC_SCRIPT.to_string(),
        "_".to_string(),
        dir.to_string_lossy().into_owned(),
        command.to_string(),
    ];
    wrapped.extend(args.iter().map(|arg| (*arg).to_string()));
    wrapped
}

/// Spawns `command`, retrying briefly while the target reports `ETXTBSY`.
///
/// A freshly written binary can momentarily read as "Text file busy" when a
/// concurrent `fork` elsewhere in the process transiently holds a writable
/// descriptor to it. The condition is self-clearing, so this retries a bounded
/// number of times with a short backoff before surfacing any other spawn error
/// (or a persistent busy state) unchanged.
fn spawn_retrying_text_busy(command: &mut Command) -> std::io::Result<std::process::Child> {
    for _ in 0..SPAWN_TEXT_BUSY_RETRIES {
        match command.spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(SPAWN_TEXT_BUSY_BACKOFF);
            }
            result => return result,
        }
    }
    command.spawn()
}

/// Spawns `command`, optionally feeding `stdin`, and captures its output.
///
/// `program` names the binary for error reporting. When `stdin` is `None` the
/// child's standard input is `/dev/null` so a command that reads stdin (such as
/// `ssh`) never consumes the parent's.
fn spawn_capturing(
    mut command: Command,
    program: &str,
    stdin: Option<&[u8]>,
) -> Result<CommandOutput, ExecutorError> {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child =
        spawn_retrying_text_busy(&mut command).map_err(|source| ExecutorError::Spawn {
            command: program.to_string(),
            source,
        })?;
    // Feed stdin on a separate thread so the child's stdout/stderr are drained
    // concurrently. Writing the whole input before reading any output would
    // deadlock once the child fills its output pipe buffer — `tee`, which echoes
    // the file contents back to stdout, does exactly that on a large payload.
    let stdin_handle = child.stdin.take();
    let (output, write_result) = std::thread::scope(|scope| {
        let writer = match (stdin, stdin_handle) {
            (Some(bytes), Some(mut handle)) => {
                // Dropping `handle` when the closure ends closes the pipe so the
                // child sees EOF.
                Some(scope.spawn(move || handle.write_all(bytes)))
            }
            _ => None,
        };
        let output = child.wait_with_output();
        let write_result =
            writer.map(|writer| writer.join().expect("stdin writer thread panicked"));
        (output, write_result)
    });
    // A broken pipe means the child closed stdin early (for example `sudo`
    // rejecting a password); its captured output carries the real story, so it
    // is not itself a spawn failure.
    if let Some(Err(source)) = write_result
        && source.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(ExecutorError::Spawn {
            command: program.to_string(),
            source,
        });
    }
    let output = output.map_err(|source| ExecutorError::Spawn {
        command: program.to_string(),
        source,
    })?;
    Ok(CommandOutput {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// Quotes one argument for a POSIX shell by single-quoting it, so a remote
/// login shell re-parses it as exactly one word regardless of the
/// metacharacters it contains.
fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Joins pre-tokenised words into one shell-safe command line.
fn shell_join<'a>(words: impl IntoIterator<Item = &'a str>) -> String {
    words
        .into_iter()
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Reports whether `sudo` refused because it needs a password or a terminal.
#[must_use]
pub fn sudo_needs_password(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.contains("a password is required")
        || text.contains("a terminal is required")
        || text.contains("no askpass")
        || text.contains("no tty present")
}

/// The remote command line that runs `remote`, then reports its own exit status
/// through [`RC_MARKER`] on stderr while the wrapper itself exits `0`. This keeps
/// the remote command's status distinct from OpenSSH's transport status (both of
/// which can be `255`).
fn wrap_with_rc_marker(remote: &str) -> String {
    format!("{remote}; printf '\\n{RC_MARKER}%d\\n' \"$?\" >&2")
}

/// Recovers the remote command's exit code emitted by [`wrap_with_rc_marker`],
/// returning the byte offset of the marker line and the parsed code. `None`
/// means the wrapper never ran, i.e. the SSH transport failed.
fn extract_remote_code(stderr: &[u8]) -> Option<(usize, i32)> {
    let marker = RC_MARKER.as_bytes();
    let pos = stderr.windows(marker.len()).rposition(|w| w == marker)?;
    let after = stderr.get(pos + marker.len()..)?;
    let digits: Vec<u8> = after.iter().copied().take_while(|&b| b != b'\n').collect();
    let code = std::str::from_utf8(&digits).ok()?.parse::<i32>().ok()?;
    Some((pos, code))
}

/// The `sh -c` script `sudo` runs under [`SudoAuth`]: it emits
/// [`SUDO_OK_SENTINEL`] the instant `sudo` has elevated, then `exec`s the real
/// command passed as `$0`/`$@`, preserving each argument as a discrete word. The
/// sentinel proves elevation began, so a later non-zero exit is attributed to
/// the command, never mistaken for a sudo refusal.
fn sudo_sentinel_script() -> String {
    format!("printf '%s' '{SUDO_OK_SENTINEL}' >&2; exec \"$0\" \"$@\"")
}

/// Removes the first [`SUDO_OK_SENTINEL`] from `stderr`, reporting whether it was
/// present (i.e. whether `sudo` elevated and started the wrapped command).
fn take_sudo_sentinel(stderr: &mut Vec<u8>) -> bool {
    let token = SUDO_OK_SENTINEL.as_bytes();
    match stderr.windows(token.len()).position(|w| w == token) {
        Some(pos) => {
            stderr.drain(pos..pos + token.len());
            true
        }
        None => false,
    }
}

/// Finalises an invocation that went through `sudo`: strips the sudo sentinel
/// and, when it is absent, raises a host-named elevation error rather than
/// passing `sudo`'s own exit off as the wrapped command's result.
///
/// This follows `sudo`, not the transport: every arm that invokes `sudo` or
/// `sudo -u` settles here, including [`Identity::Service`] on
/// [`InDaemonExecutor`], where an unknown or non-descendable account is a
/// refusal that must classify rather than read as a command failure.
/// [`Identity::Operator`], and [`Identity::Root`] inside the daemon, invoke no
/// `sudo` and so never reach this.
///
/// The sentinel is emitted the instant `sudo` has elevated and begun running the
/// wrapped command, so its absence proves the command never started — the run
/// failed *at elevation*. That is reported as a host-named error: the clearer
/// [`ExecutorError::Elevation`] when a non-interactive `sudo` merely wanted a
/// password (the fix is NOPASSWD), and [`ExecutorError::SudoRefused`] carrying
/// `sudo`'s diagnostic for any other refusal (not in sudoers, a policy denial,
/// a rejected interactive password). When the sentinel *is* present the command
/// ran, so its exit — even non-zero — is returned verbatim as a
/// [`CommandOutput`] and never mistaken for an elevation failure. The sentinel's
/// absence also means the remaining stderr is `sudo`'s alone and safe to match.
///
/// `auth` is `None` where no [`SudoAuth`] governs the invocation — descent from
/// root inside the daemon, which never prompts — so the "wanted a password"
/// arm cannot apply and every refusal is a [`ExecutorError::SudoRefused`].
fn classify_elevation(
    mut output: CommandOutput,
    auth: Option<&SudoAuth>,
    host: &str,
) -> Result<CommandOutput, ExecutorError> {
    let granted = take_sudo_sentinel(&mut output.stderr);
    if granted {
        return Ok(output);
    }
    if matches!(auth, Some(SudoAuth::NonInteractive)) && sudo_needs_password(&output.stderr) {
        return Err(ExecutorError::Elevation {
            host: host.to_string(),
        });
    }
    Err(ExecutorError::SudoRefused {
        host: host.to_string(),
        reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// An [`Executor`] that acts on the local (seat) machine.
#[derive(Debug, Clone)]
pub struct LocalExecutor {
    host: String,
    sudo_bin: PathBuf,
    auth: SudoAuth,
}

impl LocalExecutor {
    /// Creates a local executor for `host`, elevating via `auth`.
    #[must_use]
    pub fn new(host: impl Into<String>, auth: SudoAuth) -> Self {
        Self {
            host: host.into(),
            sudo_bin: PathBuf::from(SUDO),
            auth,
        }
    }

    /// Overrides the `sudo` binary, for tests that must not invoke real `sudo`.
    #[cfg(test)]
    fn with_sudo_bin(mut self, bin: PathBuf) -> Self {
        self.sudo_bin = bin;
        self
    }

    /// Resolves an `(identity, Local)` pair into a concrete invocation.
    ///
    /// This is the one site where the local transport decides whether `sudo` is
    /// involved at all, so every primitive elevates identically:
    ///
    /// - [`Identity::Operator`] spawns `command` directly, with no prefix.
    /// - [`Identity::Root`] prefixes `sudo`, authenticating per [`SudoAuth`].
    /// - [`Identity::Service`] prefixes `sudo -u <account>`, descending rather
    ///   than elevating. The account name is passed as a discrete `Command`
    ///   argument, so it reaches `sudo` as exactly one word whatever it contains.
    fn resolve(&self, identity: Identity, command: &str, args: &[&str]) -> Resolved {
        let Some(elevation) = Elevation::of(identity) else {
            let mut cmd = Command::new(command);
            cmd.args(args);
            return Resolved {
                command: cmd,
                password_line: None,
                elevated: false,
            };
        };
        let mut cmd = Command::new(&self.sudo_bin);
        let password_line = match &self.auth {
            SudoAuth::NonInteractive => {
                cmd.arg("-n");
                None
            }
            SudoAuth::Password(password) => {
                cmd.args(["-S", "-p", ""]);
                Some(format!("{password}\n").into_bytes())
            }
        };
        if let Elevation::Descend(account) = elevation {
            cmd.arg("-u").arg(account.as_str());
        }
        cmd.arg("sh")
            .arg("-c")
            .arg(sudo_sentinel_script())
            .arg(command)
            .args(args);
        Resolved {
            command: cmd,
            password_line,
            elevated: true,
        }
    }

    /// Spawns a [`Resolved`] invocation, feeding `payload` after any password
    /// line and settling the sudo sentinel when the invocation elevated.
    fn spawn_resolved(
        &self,
        resolved: Resolved,
        payload: Option<&[u8]>,
    ) -> Result<CommandOutput, ExecutorError> {
        let Resolved {
            command,
            password_line,
            elevated,
        } = resolved;
        let program = command.get_program().to_string_lossy().into_owned();
        let feed = match (password_line, payload) {
            (Some(mut line), Some(bytes)) => {
                line.extend_from_slice(bytes);
                Some(line)
            }
            (Some(line), None) => Some(line),
            (None, Some(bytes)) => Some(bytes.to_vec()),
            (None, None) => None,
        };
        let output = spawn_capturing(command, &program, feed.as_deref())?;
        if elevated {
            classify_elevation(output, Some(&self.auth), &self.host)
        } else {
            Ok(output)
        }
    }
}

/// A local invocation resolved from an identity: the command to spawn, the
/// password line to feed ahead of any payload, and whether the sudo sentinel
/// must be settled afterwards.
struct Resolved {
    command: Command,
    password_line: Option<Vec<u8>>,
    elevated: bool,
}

/// How an identity reaches its account when the transport is not already root.
///
/// [`Elevation::of`] returning `None` is the "runs as the caller, no `sudo`"
/// case; the two variants are the two shapes of `sudo` invocation, and every
/// transport maps them onto its own command construction at a single site.
#[derive(Debug, Clone, Copy)]
enum Elevation {
    /// Acquire root: bare `sudo`.
    Elevate,
    /// Traverse root down to a service account: `sudo -u <account>`.
    Descend(ServiceAccount),
}

impl Elevation {
    /// Returns how `identity` reaches its account, or `None` when it is the
    /// caller's own identity and no `sudo` is involved.
    fn of(identity: Identity) -> Option<Self> {
        match identity {
            Identity::Operator => None,
            Identity::Root => Some(Elevation::Elevate),
            Identity::Service(account) => Some(Elevation::Descend(account)),
        }
    }
}

impl Default for LocalExecutor {
    fn default() -> Self {
        Self::new("seat", SudoAuth::NonInteractive)
    }
}

impl Executor for LocalExecutor {
    fn run(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ExecutorError> {
        self.spawn_resolved(self.resolve(identity, command, args), None)
    }

    fn put_file(&self, dest: &Path, contents: &[u8], meta: FileMeta) -> Result<(), ExecutorError> {
        // One elevated `sh -c`, so the sequence cannot be interleaved with
        // another elevation; the payload is fed on the script's stdin.
        let argv = landing_argv(dest, meta);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let resolved = self.resolve(Identity::Root, SH, &borrowed);
        let output = self.spawn_resolved(resolved, Some(contents))?;
        if !output.success() {
            return Err(ExecutorError::Transfer {
                path: dest.to_path_buf(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(())
    }

    fn fetch_file(&self, identity: Identity, src: &Path) -> Result<Vec<u8>, ExecutorError> {
        if matches!(identity, Identity::Operator) {
            return std::fs::read(src).map_err(|source| ExecutorError::Io {
                path: src.to_path_buf(),
                source,
            });
        }
        fetch_through_cat(self, identity, src)
    }
}

/// An [`Executor`] that acts on a remote host over the system `ssh`.
///
/// It drives the OpenSSH client so `~/.ssh/config`, agents, and jump hosts keep
/// working, building the invocation from the host's `[hosts.*].ssh` block. The
/// remote command runs through the target's login shell, so every argument is
/// shell-quoted before transmission; file transfers pipe through `ssh … cat`
/// over the same connection.
#[derive(Debug, Clone)]
pub struct SshExecutor {
    host: String,
    target: String,
    port: u16,
    key: PathBuf,
    host_key: HostKeyPolicy,
    ssh_bin: PathBuf,
    remote_sudo: String,
    auth: SudoAuth,
    prompt: SshPrompt,
}

impl SshExecutor {
    /// Builds an executor for `host` from its parsed `ssh` block, taking the
    /// `ssh` program from `BOOTLER_SSH_BIN` when set (the injectable seam).
    ///
    /// `auth` governs remote `sudo`; `prompt` governs whether the SSH transport
    /// itself may prompt for authentication — the two are independent, so an
    /// interactive run can allow an SSH passphrase prompt while still elevating
    /// through `sudo -n`.
    #[must_use]
    pub fn from_config(
        host: impl Into<String>,
        ssh: &Ssh,
        address: &str,
        auth: SudoAuth,
        prompt: SshPrompt,
    ) -> Self {
        let ssh_bin =
            std::env::var_os(SSH_BIN_ENV).map_or_else(|| PathBuf::from(SSH), PathBuf::from);
        Self {
            host: host.into(),
            target: format!("{}@{address}", ssh.user),
            port: ssh.port,
            key: ssh.key.clone(),
            host_key: ssh.host_key,
            ssh_bin,
            remote_sudo: SUDO.to_string(),
            auth,
            prompt,
        }
    }

    /// Overrides the `ssh` program, for tests that inject a stub transport.
    #[cfg(test)]
    fn with_ssh_bin(mut self, bin: PathBuf) -> Self {
        self.ssh_bin = bin;
        self
    }

    /// Overrides the remote `sudo` program, for tests that must not invoke real
    /// `sudo` on the machine running the stub transport.
    #[cfg(test)]
    fn with_remote_sudo(mut self, sudo: impl Into<String>) -> Self {
        self.remote_sudo = sudo.into();
        self
    }

    /// Builds the base `ssh` invocation with connection options but no remote
    /// command.
    ///
    /// A [`SshPrompt::Deny`] run adds `-o BatchMode=yes` so OpenSSH never falls
    /// back to a `/dev/tty` prompt for a password, keyboard-interactive auth, or
    /// a key passphrase — it fails fast instead, letting bootler report a clear
    /// host-named error rather than hanging on a prompt. This is driven by the
    /// run's interactivity, not by [`SudoAuth`]: an interactive run may still
    /// satisfy an SSH passphrase prompt even while remote `sudo` uses `-n`.
    fn ssh_command(&self) -> Command {
        let mut cmd = Command::new(&self.ssh_bin);
        cmd.arg("-i")
            .arg(&self.key)
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg(format!(
                "StrictHostKeyChecking={}",
                self.host_key.strict_host_key_checking()
            ));
        if matches!(self.prompt, SshPrompt::Deny) {
            cmd.arg("-o").arg("BatchMode=yes");
        }
        cmd.arg(&self.target);
        cmd
    }

    /// Runs `remote` (a complete shell command line) over `ssh`, feeding
    /// `stdin` when supplied.
    ///
    /// The remote is wrapped so it reports its own exit status through
    /// [`RC_MARKER`]; a present marker yields a [`CommandOutput`] carrying the
    /// true remote code (even `255`), while its absence means the transport
    /// failed before the command ran and is an [`ExecutorError::Connection`].
    fn ssh_run(&self, remote: &str, stdin: Option<&[u8]>) -> Result<CommandOutput, ExecutorError> {
        let mut cmd = self.ssh_command();
        cmd.arg(wrap_with_rc_marker(remote));
        let program = self.ssh_bin.to_string_lossy().into_owned();
        let mut output = spawn_capturing(cmd, &program, stdin)?;
        let Some((pos, code)) = extract_remote_code(&output.stderr) else {
            return Err(ExecutorError::Connection {
                host: self.host.clone(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        };
        // Drop the marker line, including the newline the wrapper printed ahead
        // of it, so callers see only the remote command's own stderr.
        let cut = if pos > 0 && output.stderr.get(pos - 1) == Some(&b'\n') {
            pos - 1
        } else {
            pos
        };
        output.stderr.truncate(cut);
        output.code = Some(code);
        Ok(output)
    }

    /// Resolves an `(identity, Ssh)` pair into a remote command line, returning
    /// it with the stdin to feed and whether the sudo sentinel must be settled.
    ///
    /// This is the one site where the SSH transport decides whether `sudo` is
    /// involved, mirroring [`LocalExecutor::resolve`]:
    ///
    /// - [`Identity::Operator`] sends the bare command line, with no prefix.
    /// - [`Identity::Root`] prefixes `sudo`, authenticating per [`SudoAuth`].
    /// - [`Identity::Service`] prefixes `sudo -u <account>`.
    ///
    /// Every word — the account name included — goes through [`shell_join`], so
    /// the target's login shell re-parses each as exactly one word without
    /// re-splitting argument boundaries.
    fn resolve(&self, identity: Identity, command: &str, args: &[&str]) -> ResolvedRemote {
        let payload = std::iter::once(command).chain(args.iter().copied());
        let Some(elevation) = Elevation::of(identity) else {
            return ResolvedRemote {
                remote: shell_join(payload),
                password_line: None,
                elevated: false,
            };
        };
        let script = sudo_sentinel_script();
        let wrapped = ["sh", "-c", script.as_str(), command]
            .into_iter()
            .chain(args.iter().copied())
            .collect::<Vec<_>>();
        let descent = match elevation {
            Elevation::Elevate => String::new(),
            Elevation::Descend(account) => format!(" -u {}", shell_quote(account.as_str())),
        };
        let (flags, password_line) = match &self.auth {
            SudoAuth::NonInteractive => ("-n", None),
            SudoAuth::Password(password) => {
                ("-S -p ''", Some(format!("{password}\n").into_bytes()))
            }
        };
        ResolvedRemote {
            remote: format!(
                "{} {flags}{descent} {}",
                self.remote_sudo,
                shell_join(wrapped)
            ),
            password_line,
            elevated: true,
        }
    }

    /// Runs a [`ResolvedRemote`] invocation, feeding `payload` after any
    /// password line and settling the sudo sentinel when it elevated.
    fn run_resolved(
        &self,
        resolved: ResolvedRemote,
        payload: Option<&[u8]>,
    ) -> Result<CommandOutput, ExecutorError> {
        let ResolvedRemote {
            remote,
            password_line,
            elevated,
        } = resolved;
        let feed = match (password_line, payload) {
            (Some(mut line), Some(bytes)) => {
                line.extend_from_slice(bytes);
                Some(line)
            }
            (Some(line), None) => Some(line),
            (None, Some(bytes)) => Some(bytes.to_vec()),
            (None, None) => None,
        };
        let output = self.ssh_run(&remote, feed.as_deref())?;
        if elevated {
            classify_elevation(output, Some(&self.auth), &self.host)
        } else {
            Ok(output)
        }
    }
}

/// A remote invocation resolved from an identity: the complete remote command
/// line, the password line to feed ahead of any payload, and whether the sudo
/// sentinel must be settled afterwards.
struct ResolvedRemote {
    remote: String,
    password_line: Option<Vec<u8>>,
    elevated: bool,
}

impl Executor for SshExecutor {
    fn run(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ExecutorError> {
        self.run_resolved(self.resolve(identity, command, args), None)
    }

    fn put_file(&self, dest: &Path, contents: &[u8], meta: FileMeta) -> Result<(), ExecutorError> {
        // The identical script the local transport runs, shell-quoted word by
        // word so the remote login shell re-parses each as exactly one word.
        let argv = landing_argv(dest, meta);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let resolved = self.resolve(Identity::Root, SH, &borrowed);
        let output = self.run_resolved(resolved, Some(contents))?;
        if output.success() {
            Ok(())
        } else {
            Err(ExecutorError::Transfer {
                path: dest.to_path_buf(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }

    fn fetch_file(&self, identity: Identity, src: &Path) -> Result<Vec<u8>, ExecutorError> {
        if !matches!(identity, Identity::Operator) {
            return fetch_through_cat(self, identity, src);
        }
        let remote = format!("cat {}", shell_quote(&src.to_string_lossy()));
        let output = self.ssh_run(&remote, None)?;
        if output.success() {
            Ok(output.stdout)
        } else {
            Err(ExecutorError::Transfer {
                path: src.to_path_buf(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }
}

/// An [`Executor`] that acts on the local machine from inside a root daemon
/// (Roxyd running `bootler-core` in-process, RFC 0001 §5, RFC 0003 §10).
///
/// The daemon already *is* root, so this transport resolves each identity
/// differently from [`LocalExecutor`] — and per identity, never uniformly:
///
/// | identity | resolution |
/// | --- | --- |
/// | [`Identity::Root`] | no prefix; the daemon already is root |
/// | [`Identity::Service`] | `sudo -u <account>` — descent from root, which never prompts |
/// | [`Identity::Operator`] | [`ExecutorError::NoOperatorIdentity`] |
///
/// "Already root, so no prefix" is true only of [`Identity::Root`]. Applying it
/// to the whole transport would run an [`Identity::Operator`] request as root:
/// the identity contract inverted into a silent privilege escalation. There is
/// no operator session to descend to inside a daemon and so no correct command,
/// which is why that arm refuses rather than guesses.
///
/// [`SudoAuth`] does not apply here. It exists to answer a password prompt, and
/// descent from root raises none: the `sudo -u` invocation carries neither `-n`
/// nor `-S -p ""` and is fed no password line, so a write under this transport
/// sends payload bytes alone where the elevating transports prepend a password
/// line. The sudo sentinel still wraps the invocation, because `sudo -u` can
/// still refuse — an unknown or non-descendable account — and that refusal must
/// classify as an elevation failure rather than a command failure.
#[derive(Debug, Clone)]
pub struct InDaemonExecutor {
    host: String,
    sudo_bin: PathBuf,
}

impl InDaemonExecutor {
    /// Creates an executor for `host` that runs inside that host's root daemon.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            sudo_bin: PathBuf::from(SUDO),
        }
    }

    /// Overrides the `sudo` binary, for tests that must not invoke real `sudo`.
    #[cfg(test)]
    fn with_sudo_bin(mut self, bin: PathBuf) -> Self {
        self.sudo_bin = bin;
        self
    }

    /// Resolves an `(identity, InDaemon)` pair into a concrete invocation, or
    /// refuses when the identity has no meaning inside a root daemon.
    ///
    /// This is the one site where this transport decides whether `sudo` is
    /// involved. The account name is a discrete `Command` argument, so it
    /// reaches `sudo -u` as exactly one word whatever it contains.
    fn resolve(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
    ) -> Result<(Command, bool), ExecutorError> {
        match identity {
            Identity::Operator => Err(ExecutorError::NoOperatorIdentity {
                host: self.host.clone(),
            }),
            Identity::Root => {
                let mut cmd = Command::new(command);
                cmd.args(args);
                Ok((cmd, false))
            }
            Identity::Service(account) => {
                let mut cmd = Command::new(&self.sudo_bin);
                cmd.arg("-u")
                    .arg(account.as_str())
                    .arg("sh")
                    .arg("-c")
                    .arg(sudo_sentinel_script())
                    .arg(command)
                    .args(args);
                Ok((cmd, true))
            }
        }
    }

    /// Spawns a resolved invocation, feeding `payload` verbatim — there is no
    /// password line to prepend — and settling the sudo sentinel on descent.
    fn spawn_resolved(
        &self,
        command: Command,
        elevated: bool,
        payload: Option<&[u8]>,
    ) -> Result<CommandOutput, ExecutorError> {
        let program = command.get_program().to_string_lossy().into_owned();
        let output = spawn_capturing(command, &program, payload)?;
        if elevated {
            classify_elevation(output, None, &self.host)
        } else {
            Ok(output)
        }
    }
}

impl Executor for InDaemonExecutor {
    fn run(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ExecutorError> {
        let (cmd, elevated) = self.resolve(identity, command, args)?;
        self.spawn_resolved(cmd, elevated, None)
    }

    fn put_file(&self, dest: &Path, contents: &[u8], meta: FileMeta) -> Result<(), ExecutorError> {
        // The daemon already is root, so the sequence runs as direct syscalls:
        // no shell, no `sudo`, and metadata applied through the open descriptor
        // rather than by pathname.
        #[cfg(unix)]
        {
            put_file_natively(self, dest, contents, meta)
        }
        #[cfg(not(unix))]
        {
            let argv = landing_argv(dest, meta);
            let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
            let (cmd, elevated) = self.resolve(Identity::Root, SH, &borrowed)?;
            let output = self.spawn_resolved(cmd, elevated, Some(contents))?;
            if output.success() {
                Ok(())
            } else {
                Err(ExecutorError::Transfer {
                    path: dest.to_path_buf(),
                    reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                })
            }
        }
    }

    fn fetch_file(&self, identity: Identity, src: &Path) -> Result<Vec<u8>, ExecutorError> {
        if matches!(identity, Identity::Root) {
            return std::fs::read(src).map_err(|source| ExecutorError::Io {
                path: src.to_path_buf(),
                source,
            });
        }
        fetch_through_cat(self, identity, src)
    }
}

#[cfg(test)]
mod tests {
    use super::{Executor, ExecutorError, Identity, LocalExecutor, shell_quote};

    #[test]
    fn shell_quote_wraps_and_escapes() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn local_executor_runs_a_command_and_captures_output() {
        let output = LocalExecutor::default()
            .run(Identity::Operator, "true", &[])
            .expect("`true` should be runnable");
        assert!(output.success());
    }

    #[test]
    fn local_executor_reports_a_nonzero_exit_without_erroring() {
        let output = LocalExecutor::default()
            .run(Identity::Operator, "false", &[])
            .expect("`false` should be runnable");
        assert!(!output.success());
    }

    #[test]
    fn local_executor_reports_a_missing_binary_as_spawn_error() {
        let error = LocalExecutor::default()
            .run(Identity::Operator, "bootler-no-such-binary-xyz", &[])
            .expect_err("missing binary should be a spawn error");
        assert!(
            matches!(error, ExecutorError::Spawn { .. }),
            "got: {error:?}"
        );
    }

    #[cfg(unix)]
    mod conformance {
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};

        use tempfile::TempDir;

        use super::super::{
            Executor, ExecutorError, FileMeta, Identity, LocalExecutor, Principal, SshExecutor,
            SshPrompt, SudoAuth,
        };

        /// An argument carrying the metacharacters the SSH transport must not
        /// let a remote shell re-split.
        const TRICKY_ARG: &str = "a b\"c'd$e;f|g&h`i(j)";

        /// Writes `body` to an executable script and returns its path.
        fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, body).expect("write script");
            let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
            path
        }

        /// A stub `ssh` that strips the connection options and target, then runs
        /// the remaining remote command through a real shell — reproducing the
        /// remote login shell so per-argument quoting is what survives.
        fn fake_ssh(dir: &Path) -> PathBuf {
            write_script(
                dir,
                "fake-ssh",
                r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -i|-p|-o) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
shift
exec /bin/sh -c "$*"
"#,
            )
        }

        /// A stub `ssh` that prints each argument it received on its own line,
        /// so a test can assert the connection options bootler built (before
        /// they would be stripped by [`fake_ssh`]). It also emits the wrapper's
        /// exit-status marker so `ssh_run` treats the invocation as a completed
        /// remote command rather than a transport failure.
        fn recording_ssh(dir: &Path) -> PathBuf {
            write_script(
                dir,
                "recording-ssh",
                &format!(
                    "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n\
                     printf '\\n{}0\\n' >&2\n",
                    super::super::RC_MARKER
                ),
            )
        }

        /// A stub `ssh` that fails the way OpenSSH does when it cannot reach the
        /// host: a diagnostic on stderr and exit status 255, without ever running
        /// a remote command.
        fn failing_ssh(dir: &Path) -> PathBuf {
            write_script(
                dir,
                "failing-ssh",
                "#!/bin/sh\necho 'ssh: connect to host 10.0.0.10 port 22: Connection refused' >&2\nexit 255\n",
            )
        }

        /// A stub `sudo` that drops its own flags and execs the wrapped command,
        /// so elevation conformance never invokes real `sudo`.
        fn fake_sudo(dir: &Path) -> PathBuf {
            write_script(
                dir,
                "fake-sudo",
                r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p) shift 2 ;;
    -n|-S) shift ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
"#,
            )
        }

        /// Returns a [`FileMeta`] naming the uid/gid the test process already
        /// runs as, at `mode`.
        ///
        /// This is the whole reason [`Principal::Fixture`] exists. `fchown` to a
        /// *different* uid needs `CAP_CHOWN` and CI is unprivileged, so naming
        /// the current ids makes the owner-change a kernel no-op — while still
        /// issuing every call in the sequence. What is under test is therefore
        /// the sequence and its ordering, which are uid-independent; the real
        /// owner-change is observed in E2E, against a real filesystem with real
        /// elevation. No test here skips when non-root, because none needs root.
        fn current_meta(mode: u32) -> FileMeta {
            FileMeta::new(
                Principal::Fixture(id_now("-u")),
                Principal::Fixture(id_now("-g")),
                mode,
            )
        }

        /// Reads the current process's uid (`-u`) or gid (`-g`) through `id`.
        fn id_now(flag: &str) -> u32 {
            let output = std::process::Command::new("id")
                .arg(flag)
                .output()
                .expect("id should be runnable");
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .expect("id prints a number")
        }

        /// Returns `path`'s permission bits.
        fn mode_of(path: &Path) -> u32 {
            std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
        }

        /// Builds a destination two levels below `root`, so the staging walk has
        /// somewhere above the destination's own directory to land.
        ///
        /// `root` is the tempdir itself (0700, owned by the test process), which
        /// is what makes it a legal staging directory under the same rule that
        /// makes a root-owned `agent/` one in production: owned by the writer,
        /// writable by nobody else.
        fn dest_under(root: &Path, name: &str) -> PathBuf {
            let dir = root.join("namespace");
            std::fs::create_dir_all(&dir).expect("dest dir");
            dir.join(name)
        }

        /// Exercises the primitive contract that every executor must satisfy.
        fn assert_primitive_contract(exec: &dyn Executor, dir: &Path) {
            assert!(
                exec.run(Identity::Operator, "true", &[])
                    .expect("run true")
                    .success(),
                "`true` should succeed"
            );
            assert!(
                !exec
                    .run(Identity::Operator, "false", &[])
                    .expect("run false")
                    .success(),
                "`false` should report a non-zero exit, not an error"
            );

            // Argument boundaries survive verbatim: `printf %s <arg>` echoes the
            // single argument the transport delivered.
            let output = exec
                .run(Identity::Operator, "printf", &["%s", TRICKY_ARG])
                .expect("run printf");
            assert!(output.success(), "printf should succeed");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                TRICKY_ARG,
                "the metacharacter-laden argument must arrive unsplit"
            );

            // Files read back through the transport. There is no operator *write*
            // to pair this with — `put_file` is root-only by signature — so the
            // fixture is seeded directly and the read is what is under test.
            let path = dir.join("round-trip.bin");
            std::fs::write(&path, b"payload-bytes").expect("seed");
            assert_eq!(
                exec.fetch_file(Identity::Operator, &path)
                    .expect("fetch_file"),
                b"payload-bytes"
            );

            // A pinned working directory resolves a relative path against `dir`:
            // reading `marker` by its bare name only succeeds from that cwd.
            std::fs::write(dir.join("marker"), b"in-dir").expect("seed marker");
            let output = exec
                .run_in(Identity::Operator, dir, "cat", &["marker"])
                .expect("run_in cat marker");
            assert!(output.success(), "run_in should resolve cwd-relative paths");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "in-dir",
                "run_in must execute from the pinned directory"
            );
        }

        /// Exercises the elevation contract: elevated commands preserve
        /// argument boundaries and elevated writes land.
        fn assert_elevation_contract(exec: &dyn Executor, dir: &Path) {
            let output = exec
                .run(Identity::Root, "printf", &["%s", TRICKY_ARG])
                .expect("elevated printf");
            assert!(output.success(), "the elevated printf should succeed");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                TRICKY_ARG,
                "elevated argument boundaries must survive too"
            );

            // The write names the current uid/gid through the test fixture, so
            // the `chown` is a kernel no-op while still being *issued* — the
            // sequence and its ordering are what is under test, not the ability
            // to change owner, which needs CAP_CHOWN and belongs in E2E.
            //
            // The destination sits a level below `dir` so the staging walk has
            // `dir` — the 0700 tempdir the test process owns — to land on. A
            // destination directly in `dir` would send the walk to the tempdir's
            // own parent, which on Linux is the world-writable `/tmp`.
            let path = dest_under(dir, "root-owned.bin");
            exec.put_file(&path, b"root-owned", current_meta(0o640))
                .expect("elevated put_file");
            assert_eq!(
                exec.fetch_file(Identity::Operator, &path)
                    .expect("fetch_file"),
                b"root-owned"
            );
            assert_eq!(
                mode_of(&path),
                0o640,
                "the write must land the mode it asked for, with no follow-up chmod"
            );

            // An elevated command also honours the pinned working directory, so
            // bootroot's root-owned state root is reachable by cwd rather than flag.
            let marker = dest_under(dir, "priv-marker");
            exec.put_file(&marker, b"priv-in-dir", current_meta(0o644))
                .expect("put priv marker");
            let marker_dir = marker.parent().expect("marker has a parent");
            let output = exec
                .run_in(Identity::Root, marker_dir, "cat", &["priv-marker"])
                .expect("elevated run_in cat priv-marker");
            assert!(output.success(), "an elevated run_in should resolve cwd");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "priv-in-dir",
                "an elevated run_in must execute from the pinned directory"
            );

            // A root-owned file round-trips through the elevated read too — the
            // seam Phase 3 uses to slurp `secrets.json` and the bootstrap bundle.
            assert_eq!(
                exec.fetch_file(Identity::Root, &path)
                    .expect("elevated fetch_file"),
                b"root-owned"
            );

            // An elevated command that elevates fine but then exits non-zero is
            // a CommandOutput, never mistaken for an elevation failure — even
            // when its own stderr echoes the sudo password phrase.
            let output = exec
                .run(
                    Identity::Root,
                    "sh",
                    &["-c", "echo 'sudo: a password is required' >&2; exit 7"],
                )
                .expect("a failing elevated command is a CommandOutput, not an Elevation error");
            assert_eq!(output.code, Some(7), "the command's own exit must survive");
        }

        /// Covers the resolution of every `(identity, transport)` pair — all
        /// nine, none left implicit.
        ///
        /// Each transport is given a `sudo` stub that dumps its own argv, so a
        /// test can see exactly what the resolution site built: whether `sudo`
        /// was invoked at all, and whether it carried `-u <account>`. The stub
        /// also emits the elevation sentinel, so an invocation that *did* go
        /// through `sudo` still classifies as granted rather than as a refusal.
        mod resolution {
            use std::path::{Path, PathBuf};

            use tempfile::TempDir;

            use super::super::super::{
                Executor, ExecutorError, Identity, InDaemonExecutor, LocalExecutor, ServiceAccount,
                SshExecutor, SshPrompt, SudoAuth,
            };
            use super::{fake_ssh, write_script};

            /// An account name carrying the metacharacters `sudo -u` must
            /// receive as exactly one word on every transport.
            const TRICKY_ACCOUNT: &str = "acct b\"c'd$e;f|g&h`i(j)";

            /// A `sudo` stub that prints each argument it received on its own
            /// line and then emits the elevation sentinel, so the invocation
            /// classifies as granted while the test reads back the resolved
            /// argv.
            fn recording_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "recording-sudo",
                    &format!(
                        "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n\
                         printf '%s' '{}' >&2\n",
                        super::super::super::SUDO_OK_SENTINEL
                    ),
                )
            }

            fn local(dir: &TempDir) -> LocalExecutor {
                LocalExecutor::new("seat", SudoAuth::NonInteractive)
                    .with_sudo_bin(recording_sudo(dir.path()))
            }

            fn ssh(dir: &TempDir) -> SshExecutor {
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                SshExecutor::from_config(
                    "target",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(fake_ssh(dir.path()))
                .with_remote_sudo(recording_sudo(dir.path()).to_string_lossy().into_owned())
            }

            fn in_daemon(dir: &TempDir) -> InDaemonExecutor {
                InDaemonExecutor::new("seat").with_sudo_bin(recording_sudo(dir.path()))
            }

            /// Runs `printf %s marker` as `identity` and returns what the stub
            /// wrote: the resolved `sudo` argv when `sudo` ran, or `marker`
            /// when the command ran directly with no prefix.
            fn resolved(exec: &dyn Executor, identity: Identity) -> String {
                let output = exec
                    .run(identity, "printf", &["%s", "marker"])
                    .expect("the invocation should resolve");
                String::from_utf8_lossy(&output.stdout).into_owned()
            }

            /// Asserts `argv` shows `sudo` descending to `account` — the `-u`
            /// flag immediately followed by the account name as one whole word.
            ///
            /// `transport` names which executor produced `argv`, so a failure
            /// says which of the three arms broke.
            fn assert_descends_to(transport: &str, argv: &str, account: &str) {
                let words: Vec<&str> = argv.lines().collect();
                let flag = words
                    .iter()
                    .position(|word| *word == "-u")
                    .unwrap_or_else(|| panic!("{transport}: `-u` should be present: {argv:?}"));
                assert_eq!(
                    words.get(flag + 1),
                    Some(&account),
                    "{transport}: the account must arrive as exactly one word: {argv:?}"
                );
            }

            #[test]
            fn operator_runs_with_no_prefix_on_the_elevating_transports() {
                let dir = tempfile::tempdir().expect("tempdir");
                assert_eq!(
                    resolved(&local(&dir), Identity::Operator),
                    "marker",
                    "a local operator command must not go through sudo"
                );
                assert_eq!(
                    resolved(&ssh(&dir), Identity::Operator),
                    "marker",
                    "a remote operator command must not go through sudo"
                );
            }

            #[test]
            fn root_elevates_without_descending_on_the_elevating_transports() {
                let dir = tempfile::tempdir().expect("tempdir");
                for (transport, argv) in [
                    ("local", resolved(&local(&dir), Identity::Root)),
                    ("ssh", resolved(&ssh(&dir), Identity::Root)),
                ] {
                    assert!(
                        argv.lines().any(|word| word == "-n"),
                        "{transport}: SudoAuth must still govern root: {argv:?}"
                    );
                    assert!(
                        !argv.lines().any(|word| word == "-u"),
                        "{transport}: root elevates, it does not descend: {argv:?}"
                    );
                }
            }

            #[test]
            fn service_descends_on_every_transport() {
                let dir = tempfile::tempdir().expect("tempdir");
                let identity = Identity::Service(ServiceAccount::Security);
                for (transport, argv) in [
                    ("local", resolved(&local(&dir), identity)),
                    ("ssh", resolved(&ssh(&dir), identity)),
                    ("in-daemon", resolved(&in_daemon(&dir), identity)),
                ] {
                    assert_descends_to(transport, &argv, "clumit-security");
                }
            }

            #[test]
            fn a_metacharacter_laden_account_survives_sudo_u_verbatim() {
                let dir = tempfile::tempdir().expect("tempdir");
                let identity = Identity::Service(ServiceAccount::Fixture(TRICKY_ACCOUNT));
                for (transport, argv) in [
                    ("local", resolved(&local(&dir), identity)),
                    ("ssh", resolved(&ssh(&dir), identity)),
                    ("in-daemon", resolved(&in_daemon(&dir), identity)),
                ] {
                    assert_descends_to(transport, &argv, TRICKY_ACCOUNT);
                }
            }

            #[test]
            fn root_inside_the_daemon_invokes_no_sudo() {
                let dir = tempfile::tempdir().expect("tempdir");
                assert_eq!(
                    resolved(&in_daemon(&dir), Identity::Root),
                    "marker",
                    "the daemon already is root, so nothing may prefix the command"
                );
            }

            #[test]
            fn service_inside_the_daemon_carries_no_sudo_auth_flags() {
                // SudoAuth exists to answer a password prompt, and descent from
                // root never raises one — so neither `-n` nor `-S -p ''`.
                let dir = tempfile::tempdir().expect("tempdir");
                let argv = resolved(
                    &in_daemon(&dir),
                    Identity::Service(ServiceAccount::Security),
                );
                for flag in ["-n", "-S", "-p"] {
                    assert!(
                        !argv.lines().any(|word| word == flag),
                        "descent from root must not carry `{flag}`: {argv:?}"
                    );
                }
            }

            #[test]
            fn operator_inside_the_daemon_refuses_and_runs_nothing() {
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = in_daemon(&dir);
                let marker = dir.path().join("must-not-exist");
                let error = exec
                    .run(Identity::Operator, "touch", &[&marker.to_string_lossy()])
                    .expect_err("a root daemon has no operator identity to descend to");
                match error {
                    ExecutorError::NoOperatorIdentity { host } => assert_eq!(host, "seat"),
                    other => panic!("expected NoOperatorIdentity naming the host, got: {other:?}"),
                }
                assert!(
                    !marker.exists(),
                    "the refusal must run nothing, not fall back to running as root"
                );

                // The refusal holds for the read primitive too, so no path
                // silently treats `Operator` as `Root`. There is no write arm to
                // check: `put_file` takes no identity at all, so an operator —
                // or service — write is not a call that can be made.
                let error = exec
                    .fetch_file(Identity::Operator, &marker)
                    .expect_err("an operator read inside the daemon must refuse");
                assert!(
                    matches!(error, ExecutorError::NoOperatorIdentity { .. }),
                    "got: {error:?}"
                );
            }

            #[test]
            fn a_refused_descent_inside_the_daemon_classifies_as_elevation() {
                // `sudo -u` can still refuse — an unknown or non-descendable
                // account — and that is an elevation failure, not the wrapped
                // command exiting non-zero. No SudoAuth governs this transport,
                // so every refusal is a SudoRefused rather than an Elevation.
                let dir = tempfile::tempdir().expect("tempdir");
                let refusing = write_script(
                    dir.path(),
                    "refusing-sudo",
                    "#!/bin/sh\necho 'sudo: unknown user clumit-roxyd' >&2\nexit 1\n",
                );
                let exec = InDaemonExecutor::new("mgmt").with_sudo_bin(refusing);
                let error = exec
                    .run(Identity::Service(ServiceAccount::Roxyd), "true", &[])
                    .expect_err("a refused descent must not read as a command failure");
                match error {
                    ExecutorError::SudoRefused { host, reason } => {
                        assert_eq!(host, "mgmt");
                        assert!(reason.contains("unknown user"), "reason: {reason}");
                    }
                    other => panic!("expected SudoRefused naming the host, got: {other:?}"),
                }
            }
        }

        fn ssh_executor(bin_dir: &TempDir, auth: SudoAuth) -> SshExecutor {
            let ssh = crate::transport::Ssh {
                user: "ops".to_string(),
                port: 22,
                key: PathBuf::from("/dev/null"),
                host_key: crate::transport::HostKeyPolicy::Strict,
            };
            SshExecutor::from_config("target", &ssh, "10.0.0.10", auth, SshPrompt::Deny)
                .with_ssh_bin(fake_ssh(bin_dir.path()))
                .with_remote_sudo(fake_sudo(bin_dir.path()).to_string_lossy().into_owned())
        }

        #[test]
        fn local_executor_satisfies_the_primitive_contract() {
            let dir = tempfile::tempdir().expect("tempdir");
            assert_primitive_contract(&LocalExecutor::default(), dir.path());
        }

        #[test]
        fn local_executor_satisfies_the_elevation_contract() {
            let dir = tempfile::tempdir().expect("tempdir");
            let sudo = fake_sudo(dir.path());
            let exec = LocalExecutor::new("seat", SudoAuth::NonInteractive).with_sudo_bin(sudo);
            assert_elevation_contract(&exec, dir.path());
        }

        #[test]
        fn ssh_executor_satisfies_the_primitive_contract() {
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let work = tempfile::tempdir().expect("tempdir");
            let exec = ssh_executor(&bin_dir, SudoAuth::NonInteractive);
            assert_primitive_contract(&exec, work.path());
        }

        #[test]
        fn ssh_executor_satisfies_the_elevation_contract() {
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let work = tempfile::tempdir().expect("tempdir");
            let exec = ssh_executor(&bin_dir, SudoAuth::NonInteractive);
            assert_elevation_contract(&exec, work.path());
        }

        #[test]
        fn an_elevated_put_file_handles_a_payload_larger_than_the_pipe_buffer() {
            // The landing script reads the payload from stdin; a payload past the
            // pipe buffer would deadlock if stdin were written before the child's
            // output is drained. 512 KiB comfortably exceeds a 64 KiB pipe buffer.
            let dir = tempfile::tempdir().expect("tempdir");
            let sudo = fake_sudo(dir.path());
            let exec = LocalExecutor::new("seat", SudoAuth::NonInteractive).with_sudo_bin(sudo);
            let payload = vec![b'x'; 512 * 1024];
            let dest_dir = dir.path().join("dest");
            std::fs::create_dir(&dest_dir).expect("dest dir");
            let path = dest_dir.join("large.bin");
            exec.put_file(&path, &payload, current_meta(0o644))
                .expect("a large elevated write should not deadlock");
            assert_eq!(
                exec.fetch_file(Identity::Operator, &path)
                    .expect("fetch_file"),
                payload
            );
        }

        #[test]
        fn non_interactive_without_nopasswd_is_a_host_named_error() {
            let dir = tempfile::tempdir().expect("tempdir");
            // A sudo stub that refuses like real `sudo -n` without NOPASSWD.
            let sudo = write_script(
                dir.path(),
                "refusing-sudo",
                "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n",
            );
            let exec = LocalExecutor::new("mgmt", SudoAuth::NonInteractive).with_sudo_bin(sudo);
            let error = exec
                .run(Identity::Root, "true", &[])
                .expect_err("elevation without NOPASSWD should error");
            match error {
                ExecutorError::Elevation { host } => assert_eq!(host, "mgmt"),
                other => panic!("expected Elevation naming the host, got: {other:?}"),
            }
        }

        #[test]
        fn sudo_refusal_before_the_command_runs_is_a_host_named_error() {
            let dir = tempfile::tempdir().expect("tempdir");
            // A sudo stub that refuses for a reason a password cannot cure and
            // exits before the sentinel is ever emitted — the requested command
            // never starts. Its non-zero exit must not pass as the command's own
            // result; the sentinel's absence proves elevation failed.
            let sudo = write_script(
                dir.path(),
                "sudoers-refusing-sudo",
                "#!/bin/sh\necho 'sudo: user ops is not in the sudoers file' >&2\nexit 1\n",
            );
            let exec = LocalExecutor::new("mgmt", SudoAuth::NonInteractive).with_sudo_bin(sudo);
            let error = exec
                .run(Identity::Root, "true", &[])
                .expect_err("a sudo refusal before the command runs is an elevation error");
            match error {
                ExecutorError::SudoRefused { host, reason } => {
                    assert_eq!(host, "mgmt");
                    assert!(
                        reason.contains("sudoers"),
                        "reason should surface: {reason}"
                    );
                }
                other => panic!("expected SudoRefused naming the host, got: {other:?}"),
            }

            // The same refusal on an elevated write is an elevation error too,
            // not a generic transfer failure.
            let path = dir.path().join("root-owned.bin");
            let error = exec
                .put_file(&path, b"data", current_meta(0o644))
                .expect_err("a sudo refusal on an elevated write is an elevation error");
            assert!(
                matches!(error, ExecutorError::SudoRefused { .. }),
                "got: {error:?}"
            );
        }

        #[test]
        fn interactive_password_is_fed_to_sudo() {
            let dir = tempfile::tempdir().expect("tempdir");
            // A sudo stub that echoes the password line it reads from stdin (so
            // the test can confirm `-S` received the cached credential), then
            // drops its flags and execs the wrapped command like real `sudo` —
            // which emits the elevation sentinel, so the run is not misread as a
            // refusal.
            let sudo = write_script(
                dir.path(),
                "echo-sudo",
                r#"#!/bin/sh
read line
printf '%s' "$line"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p) shift 2 ;;
    -n|-S) shift ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
"#,
            );
            let exec = LocalExecutor::new("seat", SudoAuth::Password("s3cret".to_string()))
                .with_sudo_bin(sudo);
            let output = exec
                .run(Identity::Root, "true", &[])
                .expect("an elevated run");
            assert_eq!(String::from_utf8_lossy(&output.stdout), "s3cret");
        }

        #[test]
        fn ssh_transport_failure_is_an_error_not_a_command_output() {
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let ssh = crate::transport::Ssh {
                user: "ops".to_string(),
                port: 22,
                key: PathBuf::from("/dev/null"),
                host_key: crate::transport::HostKeyPolicy::Strict,
            };
            let exec = SshExecutor::from_config(
                "mgmt",
                &ssh,
                "10.0.0.10",
                SudoAuth::NonInteractive,
                SshPrompt::Deny,
            )
            .with_ssh_bin(failing_ssh(bin_dir.path()));
            let error = exec
                .run(Identity::Operator, "true", &[])
                .expect_err("an unreachable host is a transport error, not a 255 exit");
            match error {
                ExecutorError::Connection { host, reason } => {
                    assert_eq!(host, "mgmt");
                    assert!(reason.contains("Connection refused"), "reason: {reason}");
                }
                other => panic!("expected Connection naming the host, got: {other:?}"),
            }
        }

        #[test]
        fn ssh_executor_reports_remote_exit_255_as_command_output() {
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let exec = ssh_executor(&bin_dir, SudoAuth::NonInteractive);
            // OpenSSH also exits 255 for its own transport failures, so a remote
            // command that genuinely exits 255 must still be reported verbatim.
            let output = exec
                .run(Identity::Operator, "sh", &["-c", "exit 255"])
                .expect("remote exit 255 is a CommandOutput, not a transport error");
            assert_eq!(output.code, Some(255));
            assert!(!output.success());
        }

        #[test]
        fn ssh_prompt_deny_sets_batch_mode() {
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let ssh = crate::transport::Ssh {
                user: "ops".to_string(),
                port: 22,
                key: PathBuf::from("/dev/null"),
                host_key: crate::transport::HostKeyPolicy::Strict,
            };
            let exec = SshExecutor::from_config(
                "target",
                &ssh,
                "10.0.0.10",
                SudoAuth::NonInteractive,
                SshPrompt::Deny,
            )
            .with_ssh_bin(recording_ssh(bin_dir.path()));
            let output = exec
                .run(Identity::Operator, "true", &[])
                .expect("run over recording ssh");
            let argv = String::from_utf8_lossy(&output.stdout);
            assert!(
                argv.contains("BatchMode=yes\n"),
                "a non-interactive run must never prompt: {argv}"
            );
        }

        #[test]
        fn ssh_prompt_allow_omits_batch_mode_even_with_noninteractive_sudo() {
            // The regression guard: preflight builds SSH executors with
            // `SudoAuth::NonInteractive` (it probes sudo via `sudo -n`), but an
            // interactive run must still let the transport satisfy an SSH
            // passphrase or auth prompt. BatchMode is driven by `SshPrompt`, not
            // by the sudo auth, so `Allow` omits it regardless of the auth mode.
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let ssh = crate::transport::Ssh {
                user: "ops".to_string(),
                port: 22,
                key: PathBuf::from("/dev/null"),
                host_key: crate::transport::HostKeyPolicy::Strict,
            };
            let exec = SshExecutor::from_config(
                "target",
                &ssh,
                "10.0.0.10",
                SudoAuth::NonInteractive,
                SshPrompt::Allow,
            )
            .with_ssh_bin(recording_ssh(bin_dir.path()));
            let output = exec
                .run(Identity::Operator, "true", &[])
                .expect("run over recording ssh");
            let argv = String::from_utf8_lossy(&output.stdout);
            assert!(
                !argv.contains("BatchMode"),
                "an interactive run may still satisfy a prompt: {argv}"
            );
        }

        #[test]
        fn ssh_invocation_carries_key_port_and_host_key_policy() {
            let bin_dir = tempfile::tempdir().expect("tempdir");
            let ssh = crate::transport::Ssh {
                user: "ops".to_string(),
                port: 2222,
                key: PathBuf::from("/keys/id_ed25519"),
                host_key: crate::transport::HostKeyPolicy::AcceptNew,
            };
            let exec = SshExecutor::from_config(
                "target",
                &ssh,
                "10.0.0.10",
                SudoAuth::NonInteractive,
                SshPrompt::Deny,
            )
            .with_ssh_bin(recording_ssh(bin_dir.path()));
            let output = exec
                .run(Identity::Operator, "true", &[])
                .expect("run over recording ssh");
            let argv = String::from_utf8_lossy(&output.stdout);
            assert!(argv.contains("-i\n/keys/id_ed25519\n"), "key: {argv}");
            assert!(argv.contains("-p\n2222\n"), "port: {argv}");
            assert!(
                argv.contains("StrictHostKeyChecking=accept-new\n"),
                "host-key policy: {argv}"
            );
            assert!(argv.contains("ops@10.0.0.10\n"), "target: {argv}");
        }

        /// The landing sequence [`Executor::put_file`] runs (RFC 0003 §9.2).
        ///
        /// The coverage is deliberately split, because `fchown` to a *different*
        /// uid needs `CAP_CHOWN` and CI is unprivileged:
        ///
        /// - The **algorithm** — staging location, `O_EXCL`, metadata before
        ///   `rename`, symlink replacement, no temporary left behind — is
        ///   uid-independent, so it runs for real under [`InDaemonExecutor`]
        ///   with a `FileMeta` naming the current uid/gid. Every call in the
        ///   sequence executes; only the owner-change is a kernel no-op.
        /// - The **shell transports** cannot run `sudo sh -c` under a non-root
        ///   CI either, so they are covered by capturing the emitted script and
        ///   asserting its shape.
        /// - The **real owner-change** lands in E2E, against a real filesystem
        ///   with real elevation.
        ///
        /// No test here requires root, and none silently skips when non-root —
        /// a test that no-ops off-root would report coverage it does not have.
        mod landing {
            use std::io::Write;
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            use std::path::{Path, PathBuf};

            use super::super::super::{
                DirOutcome, Executor, ExecutorError, FileMeta, InDaemonExecutor, LocalExecutor,
                Principal, SshExecutor, SshPrompt, SudoAuth,
            };
            use super::{current_meta, dest_under, id_now, mode_of, write_script};

            /// How many times [`await_staging`] looks for the landing script's
            /// temporary file, and how long it waits between looks. Generous
            /// enough that a loaded CI runner cannot fail the wait, and never
            /// reached in the ordinary case.
            const STAGING_POLLS: u32 = 1_000;
            const STAGING_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

            /// The daemon transport, which runs the sequence as direct syscalls.
            fn daemon() -> InDaemonExecutor {
                InDaemonExecutor::new("seat")
            }

            /// Runs [`PUT_FILE_SCRIPT`](super::super::super::PUT_FILE_SCRIPT)
            /// the way the shell transports do, minus the `sudo` a non-root CI
            /// cannot use: the same constant script text, the same positional
            /// arguments, the contents on stdin.
            ///
            /// Naming the current ids as owner and group is what keeps this
            /// runnable unprivileged — the `chown` is a no-op the kernel
            /// permits — on exactly the terms [`current_meta`] uses for the
            /// native path. They are passed numerically so the script needs no
            /// passwd entry for the account CI happens to run as.
            ///
            /// A refused destination is refused before `cat > "$tmp"` — a
            /// directory at the destination in the script's first four lines —
            /// so on those paths the shell exits without ever reading stdin.
            /// Whether these bytes reach the pipe buffer before that happens is
            /// a race, and `BrokenPipe` is the side of it that says the script
            /// refused early rather than that anything went wrong. The verdict
            /// is the exit status and the stderr the caller asserts on, so it
            /// is taken as one outcome of a run; every other write error still
            /// panics.
            fn run_landing_script(dest: &Path, contents: &[u8], mode: u32) -> std::process::Output {
                run_landing_script_with_stubs(dest, contents, mode, None)
            }

            /// [`run_landing_script`] with `stubs`, when given, prepended to the
            /// script's `PATH`, so a utility written there is what the script
            /// resolves that name to.
            ///
            /// The directory is prepended rather than replacing `PATH`, because
            /// the script reaches for a dozen other utilities that must keep
            /// resolving to the host's. Only the child's environment is set;
            /// this process's is never touched.
            fn run_landing_script_with_stubs(
                dest: &Path,
                contents: &[u8],
                mode: u32,
                stubs: Option<&Path>,
            ) -> std::process::Output {
                let mut child = spawn_landing_script_with_stubs(dest, mode, stubs);
                let mut stdin = child.stdin.take().expect("stdin is piped");
                match stdin.write_all(contents) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Err(error) => panic!("write contents: {error}"),
                }
                // Explicitly, and before the wait: the paths that do read stdin
                // sit in `cat` until they see EOF, and holding this open past
                // here would hang them.
                drop(stdin);
                child.wait_with_output().expect("the script should finish")
            }

            /// Spawns [`run_landing_script`]'s invocation with the contents left
            /// to the caller, so a test can hold the script at `cat > "$tmp"` —
            /// past the pre-write guard, before the rename — and act on the
            /// destination while it is blocked there.
            fn spawn_landing_script(dest: &Path, mode: u32) -> std::process::Child {
                spawn_landing_script_with_stubs(dest, mode, None)
            }

            /// [`spawn_landing_script`] with the `PATH` prefix
            /// [`run_landing_script_with_stubs`] describes.
            fn spawn_landing_script_with_stubs(
                dest: &Path,
                mode: u32,
                stubs: Option<&Path>,
            ) -> std::process::Child {
                let args = [
                    "-c".to_string(),
                    super::super::super::PUT_FILE_SCRIPT.to_string(),
                    "_".to_string(),
                    dest.to_string_lossy().into_owned(),
                    id_now("-u").to_string(),
                    id_now("-g").to_string(),
                    format!("{mode:04o}"),
                ];
                let mut command = std::process::Command::new("sh");
                command.args(args);
                if let Some(stubs) = stubs {
                    let mut path = std::ffi::OsString::from(stubs);
                    path.push(":");
                    path.push(std::env::var_os("PATH").unwrap_or_default());
                    command.env("PATH", path);
                }
                command
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("sh should be runnable")
            }

            /// Blocks until the landing script has created its temporary file
            /// under `root`, which it does only after the pre-write guard and
            /// the staging walk have both run.
            ///
            /// This is a synchronisation point, not a timing guess: the script
            /// is blocked reading stdin the caller still holds open, so the
            /// state being waited for is reached and then stays.
            fn await_staging(root: &Path) {
                for _ in 0..STAGING_POLLS {
                    if !strays(root).is_empty() {
                        return;
                    }
                    std::thread::sleep(STAGING_POLL_INTERVAL);
                }
                panic!("the landing script never created its temporary file under {root:?}");
            }

            /// Returns the temporary files the landing sequence left anywhere
            /// under `root`.
            fn strays(root: &Path) -> Vec<PathBuf> {
                fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
                    let Ok(entries) = std::fs::read_dir(dir) else {
                        return;
                    };
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            walk(&path, out);
                        } else if path
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with(".bootler."))
                        {
                            out.push(path);
                        }
                    }
                }
                let mut out = Vec::new();
                walk(root, &mut out);
                out
            }

            #[test]
            fn the_staging_directory_is_never_the_destinations_own_directory() {
                // The destination's own directory may be service-writable, so an
                // account could replace the temporary between the open and the
                // rename — a TOCTOU `O_EXCL` alone does not close, because the
                // attacker can act after the descriptor is open. Staging above
                // that directory removes the window, so *where* the temporary
                // goes is the property, not an implementation detail.
                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "config.toml");
                let dest_dir = dest.parent().expect("dest dir");

                let stage = super::super::super::staging_dir(&dest).expect("a staging directory");
                assert_ne!(
                    stage, dest_dir,
                    "the temporary must not be created in the destination's own directory"
                );
                assert!(
                    dest_dir.starts_with(&stage),
                    "the staging directory must be an ancestor, so the rename stays on one \
                     filesystem: {stage:?} vs {dest_dir:?}"
                );

                // And the write itself lands, leaving nothing behind anywhere.
                daemon()
                    .put_file(&dest, b"contents", current_meta(0o644))
                    .expect("write");
                assert_eq!(std::fs::read(&dest).expect("read back"), b"contents");
                assert!(
                    strays(root.path()).is_empty(),
                    "a successful write leaves no temporary behind"
                );
            }

            #[test]
            fn a_symlink_at_the_destination_is_replaced_not_followed() {
                // `tee` follows a symlink at the destination, which would let any
                // account able to create one in a directory bootler writes to as
                // root redirect a root write anywhere on the filesystem.
                // `rename` replaces it instead. This is the concrete reason the
                // write primitive may never be `tee` or a shell redirection.
                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "unit.service");
                let elsewhere = root.path().join("must-not-be-written");
                std::fs::write(&elsewhere, b"untouched").expect("seed victim");
                std::os::unix::fs::symlink(&elsewhere, &dest).expect("plant symlink");

                daemon()
                    .put_file(&dest, b"new-contents", current_meta(0o644))
                    .expect("a symlinked destination is replaced");

                assert_eq!(
                    std::fs::read(&elsewhere).expect("read victim"),
                    b"untouched",
                    "the write must not have followed the symlink to its target"
                );
                assert!(
                    !std::fs::symlink_metadata(&dest)
                        .expect("stat dest")
                        .is_symlink(),
                    "the symlink must have been replaced by the real file"
                );
                assert_eq!(std::fs::read(&dest).expect("read dest"), b"new-contents");
            }

            #[test]
            fn a_hostile_entry_in_the_destination_directory_cannot_capture_the_write() {
                // An attacker who can write the destination's directory can plant
                // anything they like there — a file, a symlink, a directory — and
                // none of it is on the path the write takes, because the write
                // never names anything in that directory except the destination
                // itself, and only to rename over it.
                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "secrets.json");
                let dest_dir = dest.parent().expect("dest dir");
                let victim = root.path().join("must-not-be-written");
                std::fs::write(&victim, b"untouched").expect("seed victim");

                // Pre-plant every name the sequence could plausibly reach for,
                // each pointing somewhere the write must not land.
                for name in [".secrets.json.tmp", ".bootler.tmp", "secrets.json.tmp"] {
                    std::os::unix::fs::symlink(&victim, dest_dir.join(name)).expect("plant");
                }

                daemon()
                    .put_file(&dest, b"secret-bytes", current_meta(0o600))
                    .expect("planted entries do not obstruct the write");

                assert_eq!(
                    std::fs::read(&victim).expect("read victim"),
                    b"untouched",
                    "no planted name may have captured the write"
                );
                assert_eq!(std::fs::read(&dest).expect("read dest"), b"secret-bytes");
                assert_eq!(mode_of(&dest), 0o600);
            }

            #[test]
            fn a_directory_at_the_destination_fails_the_native_write() {
                // `rename(2)` refuses to replace a directory, so the native path
                // fails here for free — but the property is worth pinning,
                // because it is the behaviour the shell script has to be held to
                // and a regression on either side is a divergence between the
                // two step-3 mechanisms rather than a local bug.
                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "config.toml");
                std::fs::create_dir(&dest).expect("plant a directory at the destination");

                daemon()
                    .put_file(&dest, b"contents", current_meta(0o644))
                    .expect_err("a directory at the destination is not a writable destination");

                assert!(
                    std::fs::read_dir(&dest)
                        .expect("read the planted directory")
                        .next()
                        .is_none(),
                    "nothing may be written inside a directory standing at the destination"
                );
                assert!(
                    strays(root.path()).is_empty(),
                    "the failed write leaves no temporary behind"
                );
            }

            #[test]
            fn a_directory_at_the_destination_fails_the_shell_write() {
                // `mv` and `rename(2)` part company here: to `mv`, an existing
                // directory at the destination is a *target directory*, so it
                // moves the temporary inside and exits 0. Left unchecked the
                // shell transports would report success for a write that landed
                // at a path the caller never named, under a directory an
                // attacker may control, and then disarm the cleanup trap on the
                // way out — leaving the staged contents there.
                //
                // Unlike the transports' other coverage this runs the script for
                // real rather than asserting its shape, because the failure mode
                // is `mv`'s behaviour and not the script's text: no reading of
                // `mv -f "$tmp" "$dest"` reveals it.
                let root = tempfile::tempdir().expect("tempdir");

                // First a plain write, so the failure below is the destination
                // being a directory and not the script failing to run at all.
                let ordinary = dest_under(root.path(), "unit.service");
                let output = run_landing_script(&ordinary, b"contents", 0o640);
                assert!(
                    output.status.success(),
                    "the landing script should run unprivileged against its own uid: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(std::fs::read(&ordinary).expect("read back"), b"contents");
                assert_eq!(mode_of(&ordinary), 0o640);

                let dest = dest_under(root.path(), "config.toml");
                std::fs::create_dir(&dest).expect("plant a directory at the destination");
                let output = run_landing_script(&dest, b"contents", 0o644);

                assert!(
                    !output.status.success(),
                    "a directory at the destination must not report a successful write"
                );
                assert!(
                    std::fs::read_dir(&dest)
                        .expect("read the planted directory")
                        .next()
                        .is_none(),
                    "the temporary must not be left inside the directory `mv` would move it into"
                );
                assert!(
                    strays(root.path()).is_empty(),
                    "the failed write leaves no temporary behind anywhere"
                );
            }

            #[test]
            fn a_directory_planted_after_the_pre_write_guard_fails_the_shell_write() {
                // The case above stops at the pre-write guard and never reaches
                // the `mv`. This one gets past that guard and *does*: the script
                // is held at `cat > "$tmp"` — stdin stays open until the
                // temporary exists, which is proof the guard and the staging
                // walk are already behind it — and the directory is planted
                // there. So `mv` really does move the staged file inside a
                // directory the script was not asked to write into, and what is
                // under test is what the script does about it afterwards.
                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "config.toml");

                let mut child = spawn_landing_script(&dest, 0o644);
                let mut stdin = child.stdin.take().expect("stdin is piped");
                stdin.write_all(b"cont").expect("write the first half");
                await_staging(root.path());
                std::fs::create_dir(&dest).expect("plant a directory mid-write");
                stdin.write_all(b"ents").expect("write the second half");
                drop(stdin);
                let output = child.wait_with_output().expect("the script should finish");

                assert!(
                    !output.status.success(),
                    "a directory appearing between the guard and the rename must not report a \
                     successful write"
                );
                assert!(
                    std::fs::read_dir(&dest)
                        .expect("read the planted directory")
                        .next()
                        .is_none(),
                    "the file `mv` misplaced must be removed while it is still reachable"
                );
                assert!(
                    strays(root.path()).is_empty(),
                    "the failed write leaves no temporary behind anywhere"
                );
            }

            #[test]
            fn the_landing_confirmation_accepts_only_the_file_just_written() {
                // The interleaving the check above cannot stage is the one where
                // the directory is *also* renamed away before the script looks
                // again — an account that can write the destination's own
                // directory can do that, and no test can win that race on
                // demand. That is exactly why the post-rename check is positive:
                // it does not ask whether a directory is standing at the
                // destination, it asks whether the destination *is* the object
                // just staged. Whatever an attacker leaves behind, it is not
                // that object.
                //
                // Asserting the spelling would not establish it, so this runs
                // the predicate the script actually uses against real files, the
                // way the staging-predicate test does.
                let script = super::super::super::PUT_FILE_SCRIPT;
                let start = script.find("-inum").expect("an identity predicate");
                let end = script[start..].find(" 2>/dev/null").expect("predicate end");
                let predicate = &script[start..start + end];

                let root = tempfile::tempdir().expect("tempdir");
                let written = root.path().join("written");
                std::fs::write(&written, b"contents").expect("the file just staged");
                std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o644))
                    .expect("mode");
                let ino = std::fs::metadata(&written).expect("stat").ino();

                let decoy = root.path().join("decoy");
                std::fs::write(&decoy, b"contents").expect("an impostor at the destination");
                std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o644))
                    .expect("mode");
                let widened = root.path().join("widened");
                std::fs::write(&widened, b"contents").expect("the same contents, wider");
                std::fs::set_permissions(&widened, std::fs::Permissions::from_mode(0o666))
                    .expect("mode");
                let directory = root.path().join("directory");
                std::fs::create_dir(&directory).expect("a directory standing at the destination");
                let link = root.path().join("link");
                std::os::unix::fs::symlink(&written, &link).expect("a symlink to the real file");

                for (path, confirmed, why) in [
                    (&written, true, "the file the script staged"),
                    (
                        &decoy,
                        false,
                        "a different file, however identical it looks",
                    ),
                    (
                        &widened,
                        false,
                        "the same contents at a mode the script did not apply",
                    ),
                    (
                        &directory,
                        false,
                        "a directory `mv` would have moved the file into",
                    ),
                    (&link, false, "a symlink pointing at the real file"),
                ] {
                    let output = std::process::Command::new("sh")
                        .args([
                            "-c",
                            &format!(
                                r#"ino=$2; owner=$3; group=$4; mode=$5
find "$1" -maxdepth 0 {predicate}"#
                            ),
                            "_",
                            &path.to_string_lossy(),
                            &ino.to_string(),
                            &id_now("-u").to_string(),
                            &id_now("-g").to_string(),
                            "0644",
                        ])
                        .output()
                        .expect("find should be runnable");
                    assert_eq!(
                        !output.stdout.is_empty(),
                        confirmed,
                        "{why} should be confirmed={confirmed}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }

            #[test]
            fn a_failed_write_leaves_no_temporary_file() {
                // Cleanup belongs to the primitive, not to its callers: a caller
                // that has just been told the write failed cannot be expected to
                // know a staging path it never named.
                let root = tempfile::tempdir().expect("tempdir");
                // The destination's parent does not exist, so the `rename` fails
                // *after* the temporary has been created and written.
                let dest = root.path().join("namespace").join("absent").join("file");
                std::fs::create_dir(root.path().join("namespace")).expect("namespace");

                let error = daemon()
                    .put_file(&dest, b"contents", current_meta(0o644))
                    .expect_err("a write into a missing directory fails");
                assert!(matches!(error, ExecutorError::Io { .. }), "got: {error:?}");
                assert!(
                    strays(root.path()).is_empty(),
                    "the failed write must have removed its temporary: {:?}",
                    strays(root.path())
                );
            }

            #[test]
            fn metadata_is_applied_before_the_destination_name_is_reachable() {
                // The mode is on the file the instant the destination resolves to
                // it, so there is no window at which a secret-bearing artifact is
                // readable by another account. Under the current uid the owner
                // half is a no-op at the kernel, but `fchown` is still issued.
                //
                // What an unprivileged test can and cannot separate is worth
                // being exact about, because the test name claims an ordering.
                // The final mode plus the inode swap below rule out the failure
                // this sequence replaced — opening the destination in place and
                // chmod'ing it afterwards, which is what leaves the window. They
                // do *not* distinguish a rename-then-chmod-by-path variant,
                // whose window is only observable from a concurrent attacker; on
                // this transport that ordering is carried by construction, since
                // `put_file_natively` has nothing but the descriptor to name
                // before the `rename`. The byte-offset assertion in
                // `the_landing_script_stages_outside_the_destination_and_never_uses_tee`
                // is where the ordering itself is pinned, because a script is
                // text that can be read.
                use std::os::unix::fs::MetadataExt;

                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "aimer.toml");
                daemon()
                    .put_file(&dest, b"key = \"secret\"", current_meta(0o600))
                    .expect("write");
                assert_eq!(
                    mode_of(&dest),
                    0o600,
                    "the destination must never have existed at a wider mode"
                );

                // Re-writing over an existing wider file narrows it atomically,
                // rather than leaving the old inode to be chmod'ed in place.
                let wide = dest_under(root.path(), "wide.toml");
                std::fs::write(&wide, b"old").expect("seed");
                std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o666))
                    .expect("widen");
                let stale = std::fs::metadata(&wide).expect("stat").ino();
                daemon()
                    .put_file(&wide, b"new", current_meta(0o600))
                    .expect("write");
                assert_eq!(mode_of(&wide), 0o600);
                assert_eq!(std::fs::read(&wide).expect("read"), b"new");
                assert_ne!(
                    std::fs::metadata(&wide).expect("stat").ino(),
                    stale,
                    "the destination must be a different object, landed by rename — the same \
                     inode would mean the old file was opened in place and narrowed afterwards, \
                     which is the window this sequence exists to close"
                );
            }

            #[test]
            fn a_pre_created_staging_name_is_never_adopted() {
                // `O_CREAT|O_EXCL` is what stops the open from adopting an entry
                // that is already there. In production the staging directory is
                // root-only, so this is the half of the guarantee that does not
                // depend on the walk having chosen correctly — worth pinning on
                // its own, because a `create(true)` typo would leave every other
                // assertion in this module passing.
                //
                // The temporary's name is derived from the pid and a counter, so
                // the test can name it. The window covers a counter another test
                // took between the load and the open; a collision only matters
                // within one staging directory, and every test stages into its
                // own `tempdir`.
                let root = tempfile::tempdir().expect("tempdir");
                let dest = dest_under(root.path(), "config.toml");

                let victim = root.path().join("victim");
                std::fs::write(&victim, b"untouched").expect("victim");

                let next = super::super::super::NATIVE_TEMP_COUNTER
                    .load(std::sync::atomic::Ordering::Relaxed);
                for n in next..next + 256 {
                    let planted = root
                        .path()
                        .join(format!(".bootler.{}.{n}.tmp", std::process::id()));
                    // A symlink rather than a plain file, so that an open which
                    // *did* adopt the entry would write through to the victim and
                    // be caught below rather than silently passing.
                    std::os::unix::fs::symlink(&victim, &planted).expect("plant");
                }

                let error = daemon()
                    .put_file(&dest, b"contents", current_meta(0o600))
                    .expect_err("an occupied staging name must not be adopted");
                assert!(matches!(error, ExecutorError::Io { .. }), "got: {error:?}");
                assert_eq!(
                    std::fs::read(&victim).expect("victim").as_slice(),
                    b"untouched",
                    "adopting the planted entry would have written through the symlink"
                );
                assert!(
                    !dest.exists(),
                    "a write that could not stage must not reach the destination"
                );
            }

            #[test]
            fn a_world_writable_ancestor_is_never_chosen_for_staging() {
                // "Root-only" is the point, not "root-owned": a directory anyone
                // can write is a directory an attacker can plant a temporary in,
                // which is the whole window the sequence exists to close. The
                // walk must step over it rather than stop at the first ancestor
                // the writer happens to own.
                let root = tempfile::tempdir().expect("tempdir");
                let open = root.path().join("open");
                let dest_dir = open.join("inner");
                std::fs::create_dir_all(&dest_dir).expect("dirs");
                std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))
                    .expect("world-writable");

                let dest = dest_dir.join("file");
                let stage = super::super::super::staging_dir(&dest).expect("a staging directory");
                assert_ne!(stage, open, "a world-writable ancestor must be skipped");
                assert_eq!(
                    stage,
                    root.path(),
                    "the walk must continue to the first ancestor nobody else can write"
                );

                daemon()
                    .put_file(&dest, b"x", current_meta(0o644))
                    .expect("the write still lands");
                assert!(strays(root.path()).is_empty());
            }

            /// Facts for a directory the synthetic staging walk should accept:
            /// owned by the writer, writable by nobody else.
            fn writer_owned(dev: u64) -> super::super::super::DirFacts {
                super::super::super::DirFacts {
                    uid: FIXTURE_UID,
                    mode: 0o755,
                    dev,
                }
            }

            /// The uid the synthetic walk treats as the writer's. Any value does,
            /// since the probe is supplied by the test rather than the kernel.
            const FIXTURE_UID: u32 = 4242;
            /// Two distinct device numbers, standing for a mount boundary an
            /// unprivileged CI cannot create for real.
            const DEST_DEV: u64 = 1;
            const OTHER_DEV: u64 = 2;

            #[test]
            fn staging_stops_at_a_mount_boundary_rather_than_crossing_it() {
                // The walk climbs until it finds a root-only ancestor, and the
                // installed layout does not stop it from climbing past a mount
                // point to get one. Staging there would make the landing a
                // cross-device `mv` — copy-then-unlink, not `rename` — which is
                // exactly the non-atomic write §9.2 rules out, and a copy that
                // fails partway can leave a partial destination behind. So the
                // refusal has to happen at selection, before anything is
                // written, not be inferred afterwards from the landed inode.
                //
                // Here the destination's own directory and its parent are on the
                // destination's device but group-writable, so the walk wants to
                // keep climbing; the only root-only ancestor is above the
                // boundary. Selection must fail rather than reach for it.
                let dest = Path::new("/mnt/data/svc/config.toml");
                let facts = |dir: &Path| {
                    let dir = dir.to_string_lossy().into_owned();
                    Some(match dir.as_str() {
                        "/mnt/data/svc" | "/mnt/data" => super::super::super::DirFacts {
                            mode: 0o775,
                            ..writer_owned(DEST_DEV)
                        },
                        // `/mnt` is where the mounted filesystem ends: by path it
                        // still resolves through the mount, but its parent is the
                        // filesystem underneath.
                        "/mnt" => writer_owned(DEST_DEV),
                        _ => writer_owned(OTHER_DEV),
                    })
                };
                assert_eq!(
                    super::super::super::select_staging_dir(dest, FIXTURE_UID, facts),
                    Some(PathBuf::from("/mnt")),
                    "the mount point itself is on the destination's filesystem and is usable"
                );

                // Same tree, but now the mount point is group-writable too, so
                // the only candidate the ownership rule would accept is `/`,
                // which is on the other side of the boundary.
                let across = |dir: &Path| {
                    let dir = dir.to_string_lossy().into_owned();
                    Some(match dir.as_str() {
                        "/mnt/data/svc" | "/mnt/data" | "/mnt" => super::super::super::DirFacts {
                            mode: 0o775,
                            ..writer_owned(DEST_DEV)
                        },
                        _ => writer_owned(OTHER_DEV),
                    })
                };
                assert_eq!(
                    super::super::super::select_staging_dir(dest, FIXTURE_UID, across),
                    None,
                    "an ancestor across a mount boundary must not be chosen for staging"
                );
            }

            #[test]
            fn staging_selection_needs_the_destinations_own_filesystem() {
                // Nothing can be promised about the move if the destination
                // directory itself cannot be stat'd, so the walk refuses rather
                // than falling back on an ancestor that may be elsewhere.
                let dest = Path::new("/srv/app/config.toml");
                let absent_dest_dir =
                    |dir: &Path| (dir != Path::new("/srv/app")).then(|| writer_owned(DEST_DEV));
                assert_eq!(
                    super::super::super::select_staging_dir(dest, FIXTURE_UID, absent_dest_dir),
                    None,
                    "an unreadable destination directory leaves no filesystem to match"
                );
            }

            #[test]
            fn the_shell_walk_refuses_a_staging_directory_on_another_filesystem() {
                // The script's half of the same rule. A non-root CI cannot mount
                // anything, so the boundary is introduced where the script reads
                // it: `df` is stubbed on `PATH` to report a different filesystem
                // for every ancestor above the destination's own directory. The
                // script must then fail *before* `mv` — no temporary anywhere,
                // nothing at the destination.
                let root = tempfile::tempdir().expect("tempdir");
                let bin = root.path().join("bin");
                std::fs::create_dir(&bin).expect("bin");
                let dest = dest_under(root.path(), "config.toml");
                let dest_dir = dest.parent().expect("dest dir").to_path_buf();
                // Only the destination's own directory reports the destination's
                // filesystem; every ancestor the walk would consider reports
                // another one.
                write_script(
                    &bin,
                    "df",
                    &format!(
                        "#!/bin/sh\n\
                         printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\n\
                         if [ \"$2\" = '{}' ]; then\n\
                           printf '/dev/dest 1 1 1 1%% /dest\\n'\n\
                         else\n\
                           printf '/dev/other 1 1 1 1%% /other\\n'\n\
                         fi\n",
                        dest_dir.display()
                    ),
                );

                let path = format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                );
                let mut child = std::process::Command::new("sh")
                    .args([
                        "-c".to_string(),
                        super::super::super::PUT_FILE_SCRIPT.to_string(),
                        "_".to_string(),
                        dest.to_string_lossy().into_owned(),
                        id_now("-u").to_string(),
                        id_now("-g").to_string(),
                        "0644".to_string(),
                    ])
                    .env("PATH", path)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("sh should be runnable");
                child
                    .stdin
                    .take()
                    .expect("stdin is piped")
                    .write_all(b"contents")
                    .expect("write contents");
                let output = child.wait_with_output().expect("the script should finish");

                assert!(
                    !output.status.success(),
                    "staging across a filesystem boundary must be refused"
                );
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("no staging directory"),
                    "the refusal must name the selection rule: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    !dest.exists(),
                    "a write that could not stage must not reach the destination"
                );
                assert!(
                    strays(root.path()).is_empty(),
                    "a refusal before the move leaves no temporary behind"
                );
            }

            /// A `sudo`/`ssh` stub that dumps the argv it was handed into
            /// `<dir>/argv` and drains stdin, so a write's payload does not
            /// deadlock against an unread pipe.
            ///
            /// A non-root CI can no more run `sudo sh -c` than it can `fchown`,
            /// so the shell transports are covered by capturing the script they
            /// emit and asserting its shape — the same way the old tests
            /// asserted the `chmod 0755 …` a write used to be followed by.
            fn dumping_stub(dir: &Path, name: &str, trailer: &str) -> PathBuf {
                let argv = dir.join("argv");
                write_script(
                    dir,
                    name,
                    &format!(
                        "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done > {}\n\
                         cat > /dev/null\n{trailer}",
                        argv.display()
                    ),
                )
            }

            /// The argv [`dumping_stub`] recorded, one word per line.
            fn dumped(dir: &Path) -> Vec<String> {
                std::fs::read_to_string(dir.join("argv"))
                    .expect("the stub must have run")
                    .lines()
                    .map(str::to_string)
                    .collect()
            }

            #[test]
            fn both_shell_transports_emit_the_same_landing_script() {
                // Phase code is transport-agnostic, which only holds if the
                // transports do the same thing. One quietly diverging is how a
                // guarantee that holds single-host stops holding multi-host, so
                // the two are compared against each other, not just each checked.
                let dest = Path::new("/opt/clumit-security/bin/review");
                let meta = FileMeta::ROOT_BINARY;

                let local_dir = tempfile::tempdir().expect("tempdir");
                let sudo = dumping_stub(
                    local_dir.path(),
                    "dumping-sudo",
                    &format!(
                        "printf '%s' '{}' >&2\n",
                        super::super::super::SUDO_OK_SENTINEL
                    ),
                );
                LocalExecutor::new("seat", SudoAuth::NonInteractive)
                    .with_sudo_bin(sudo)
                    .put_file(dest, b"payload", meta)
                    .expect("the stub reports success");
                let local_argv = dumped(local_dir.path());

                let ssh_dir = tempfile::tempdir().expect("tempdir");
                let ssh_stub = dumping_stub(
                    ssh_dir.path(),
                    "dumping-ssh",
                    &format!(
                        "printf '%s' '{}' >&2\nprintf '\\n{}0\\n' >&2\n",
                        super::super::super::SUDO_OK_SENTINEL,
                        super::super::super::RC_MARKER
                    ),
                );
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                SshExecutor::from_config(
                    "target",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(ssh_stub)
                .with_remote_sudo("sudo".to_string())
                .put_file(dest, b"payload", meta)
                .expect("the stub reports success");
                // The remote command line is a single argument spanning many
                // lines, so it is read out of the joined text rather than off
                // one line.
                let remote_line = dumped(ssh_dir.path()).join("\n");

                // The local transport hands `sh` the script as one discrete
                // argument; the SSH transport shell-quotes the same script into
                // one remote word. Both must carry the identical script text and
                // the identical positional values.
                // The stub prints one argument per line, so the multi-line
                // script reassembles verbatim in the joined text.
                assert!(
                    local_argv
                        .join("\n")
                        .contains(super::super::super::PUT_FILE_SCRIPT),
                    "the local transport must spawn the landing script verbatim: {local_argv:?}"
                );
                // Asserting a couple of landmarks here would let a materially
                // different remote script pass — including one whose staging
                // predicate differs, which is the whole guarantee on this
                // transport. So the remote side is held to the same verbatim
                // bar as the local one.
                assert!(
                    remote_line.contains(&super::super::super::shell_quote(
                        super::super::super::PUT_FILE_SCRIPT
                    )),
                    "the SSH transport must carry the identical script, quoted so the remote \
                     login shell re-parses it as exactly one word: {remote_line}"
                );
                for value in [dest.to_string_lossy().as_ref(), "root", "0755"] {
                    assert!(
                        local_argv.iter().any(|word| word == value),
                        "the local argv must carry `{value}`: {local_argv:?}"
                    );
                    assert!(
                        remote_line.contains(value),
                        "the remote line must carry `{value}`: {remote_line}"
                    );
                }
                assert!(
                    !local_argv.iter().any(|word| word == "tee") && !remote_line.contains(" tee "),
                    "neither transport may resolve to `tee`"
                );
            }

            #[test]
            fn the_landing_script_stages_outside_the_destination_and_never_uses_tee() {
                // The script's shape *is* the guarantee on the shell transports,
                // where the shell cannot express descriptor-based metadata. Four
                // things must hold, and each is a separate way the sequence could
                // silently regress into the write it replaced.
                let script = super::super::super::PUT_FILE_SCRIPT;
                assert!(
                    !script.contains("tee"),
                    "no writer may resolve to `tee`: {script}"
                );
                assert!(
                    script.contains("mktemp"),
                    "the temporary must be created O_EXCL at 0600: {script}"
                );
                assert!(
                    script.contains(r#"dirname "$(dirname "$dest")""#),
                    "staging must start above the destination's own directory: {script}"
                );
                let chown_at = script.find("chown").expect("chown");
                let chmod_at = script.find("chmod").expect("chmod");
                let rename_at = script.find("mv -f").expect("rename");
                assert!(
                    chown_at < rename_at && chmod_at < rename_at,
                    "metadata must be applied before the rename: {script}"
                );
                assert!(
                    script.contains(r#"trap 'rm -f "$tmp"' EXIT"#),
                    "a failure must leave no temporary behind: {script}"
                );
                // The pre-write guard is one thing; what the write actually
                // rests on is the check *after* the rename being positive. A
                // second `[ -d "$dest" ]` would be bypassable — an account able
                // to write the destination's own directory can rename the
                // directory away between the `mv` and the re-test — so the
                // destination has to be identified as the object just staged.
                let confirm_at = script.find("-inum").expect("an identity check");
                assert!(
                    confirm_at > rename_at,
                    "the destination must be confirmed after the rename: {script}"
                );
                assert!(
                    script[confirm_at..]
                        .contains(r#"-user "$owner" -group "$group" -perm "$mode""#),
                    "identity is inode plus the metadata just applied, so no file an \
                     unprivileged account can create satisfies it: {script}"
                );
                assert!(
                    script[confirm_at..].contains(r#"rm -f "$dest/"#),
                    "the file `mv` misplaced must be removed when it is still reachable: \
                     {script}"
                );
            }

            #[test]
            fn the_landing_script_flushes_the_temporary_and_the_destinations_directory() {
                // Two flushes, because they protect different things and neither
                // placement serves the other: the temporary's bytes with the
                // owner and mode just applied to them, and the directory entry
                // the rename created, which does not exist at the first point.
                // Where each sits *is* the guarantee, so the positions are what
                // is asserted.
                let script = super::super::super::PUT_FILE_SCRIPT;
                let chmod_at = script.find(r#"chmod "$mode""#).expect("chmod");
                let rename_at = script.find("mv -f").expect("rename");
                let temp_flush = script
                    .find(r#"flush "$tmp""#)
                    .expect("the temporary is flushed");
                let dir_flush = script
                    .find(r#"flush "$(dirname "$dest")""#)
                    .expect("the destination's directory is flushed");
                assert!(
                    chmod_at < temp_flush && temp_flush < rename_at,
                    "the temporary must be flushed after its owner and mode are applied and \
                     before the rename: {script}"
                );
                assert!(
                    dir_flush > rename_at,
                    "the directory must be flushed after the rename that created the entry, \
                     since flushing it earlier protects nothing: {script}"
                );

                // The floor is reached by what the targeted form *does*, not by
                // asking whether a name is there: `sync` is present on every one
                // of the three implementations, so a probe cannot tell the one
                // that honours the operand from the one that ignores it.
                assert!(
                    script.contains(r#"sync "$1" 2>/dev/null || sync"#),
                    "the targeted flush must fall back to the host-wide one on failure: {script}"
                );
                assert!(
                    !script.contains("command -v"),
                    "selection must not be a name probe: {script}"
                );
                assert!(
                    !script.split_whitespace().any(|word| word == "dd"),
                    "`dd` flushes its output file, so the idiom that reads like a flush syncs \
                     /dev/null, and the form that works destroys the file without `notrunc`: \
                     {script}"
                );
            }

            #[test]
            fn the_flush_survives_every_sync_a_target_can_carry() {
                // The three run-time behaviours the fallback is selected against,
                // plus the absence the floor itself can meet. None of them may
                // fail the write: an install that cannot land an artifact because
                // the host's `sync` refuses an operand is worse than one whose
                // flush was broader than it needed to be.
                //
                // Each stub records how it was called, so the assertion is what
                // the script actually reached for rather than what its text
                // says — the rejecting case in particular has to be seen to run
                // the bare `sync` rather than to give up.
                const HONOURS: &str = r#"#!/bin/sh
if [ "$#" -eq 0 ]; then echo bare >>"LOG"; else echo "operand $1" >>"LOG"; fi
exit 0
"#;
                const REJECTS: &str = r#"#!/bin/sh
if [ "$#" -eq 0 ]; then echo bare >>"LOG"; exit 0; fi
echo "refused $1" >>"LOG"
echo "sync: extra operand '$1'" >&2
exit 1
"#;
                const IGNORES: &str = r#"#!/bin/sh
echo "host-wide $*" >>"LOG"
exit 0
"#;
                const ABSENT: &str = r#"#!/bin/sh
if [ "$#" -eq 0 ]; then echo bare >>"LOG"; else echo "refused $1" >>"LOG"; fi
echo "sync: not found" >&2
exit 127
"#;

                for (what, body, falls_back, warns) in [
                    (
                        "coreutils, which flushes the operand",
                        HONOURS,
                        false,
                        false,
                    ),
                    (
                        "an implementation that refuses the operand",
                        REJECTS,
                        true,
                        false,
                    ),
                    (
                        "macOS or busybox, which ignore the operand",
                        IGNORES,
                        false,
                        false,
                    ),
                    ("a host with no working sync at all", ABSENT, true, true),
                ] {
                    let root = tempfile::tempdir().expect("tempdir");
                    let stubs = root.path().join("stubs");
                    std::fs::create_dir(&stubs).expect("stub directory");
                    let log = root.path().join("sync.log");
                    write_script(&stubs, "sync", &body.replace("LOG", &log.to_string_lossy()));

                    let dest = dest_under(root.path(), "secrets.json");
                    let output = run_landing_script_with_stubs(
                        &dest,
                        b"secret-bytes",
                        0o600,
                        Some(stubs.as_path()),
                    );

                    assert!(
                        output.status.success(),
                        "{what} must not fail the write: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert_eq!(std::fs::read(&dest).expect("read back"), b"secret-bytes");
                    assert_eq!(mode_of(&dest), 0o600, "{what}");
                    assert!(
                        strays(root.path()).is_empty(),
                        "{what}: a successful write leaves no temporary behind"
                    );

                    let calls = std::fs::read_to_string(&log).expect("the stub was called");
                    let calls: Vec<&str> = calls.lines().collect();
                    let dest_dir = dest.parent().expect("dest dir").to_string_lossy();
                    let (first, rest) = calls.split_first().expect("the stub was called");
                    assert!(
                        first.contains(".bootler."),
                        "{what}: the first flush must name the temporary, which is the half the \
                         owner and mode were just applied to, got {calls:?}"
                    );
                    assert!(
                        rest.iter().any(|call| call.ends_with(dest_dir.as_ref())),
                        "{what}: the directory holding the destination must be flushed, and only \
                         after the temporary the rename moved into it, got {calls:?}"
                    );
                    assert_eq!(
                        calls.iter().filter(|call| call.starts_with("bare")).count(),
                        if falls_back { 2 } else { 0 },
                        "{what}: the host-wide flush runs for both halves exactly when the \
                         targeted form failed, got {calls:?}"
                    );
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert_eq!(
                        stderr.contains("was not flushed"),
                        warns,
                        "{what}: a flush that did not happen must be said rather than passed \
                         over in silence, and one that did must say nothing: {stderr}"
                    );
                }
            }

            #[test]
            fn the_shell_staging_predicate_rejects_either_write_bit() {
                // On the shell transports the staging directory being writable
                // by nobody but the writer *is* the whole guarantee, because the
                // shell applies metadata by pathname: an account able to write
                // the staging directory can swap the temporary for a symlink
                // between the write and the `chown`, and redirect a root
                // chown/chmod anywhere. So the predicate must reject a directory
                // carrying *either* write bit, not only one carrying both —
                // `! -perm -0022` matches all-of, which lets 0775 through.
                //
                // Asserting the spelling would not catch that; this runs the
                // predicate the script actually uses against real directories,
                // and pins it to the same rule the native path applies as
                // `mode & 0o022 == 0`.
                let script = super::super::super::PUT_FILE_SCRIPT;
                let start = script.find("! -perm").expect("a write-bit predicate");
                let end = script[start..].find(" 2>/dev/null").expect("predicate end");
                let predicate = &script[start..start + end];

                let root = tempfile::tempdir().expect("tempdir");
                for (mode, staging_is_legal) in [
                    (0o700, true),
                    (0o755, true),
                    (0o775, false),
                    (0o757, false),
                    (0o777, false),
                ] {
                    let dir = root.path().join(format!("{mode:04o}"));
                    std::fs::create_dir(&dir).expect("candidate");
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
                        .expect("mode");

                    let output = std::process::Command::new("sh")
                        .args([
                            "-c",
                            &format!(r#"find "$1" -maxdepth 0 -user "$(id -u)" {predicate}"#),
                            "_",
                            &dir.to_string_lossy(),
                        ])
                        .output()
                        .expect("find should be runnable");
                    assert_eq!(
                        !output.stdout.is_empty(),
                        staging_is_legal,
                        "mode {mode:04o} staging-legal should be {staging_is_legal}, and the \
                         native path agrees: mode & 0o022 == 0 is {}",
                        mode & 0o022 == 0,
                    );
                }
            }

            #[test]
            fn the_landing_argv_passes_every_value_positionally() {
                // A destination or account spliced into the script text would be
                // re-parsed by the shell; passing them positionally means a path
                // with metacharacters is treated strictly as data.
                let argv = super::super::super::landing_argv(
                    Path::new("/opt/a b;rm -rf /"),
                    FileMeta::ROOT_SECRET,
                );
                assert_eq!(argv.first().map(String::as_str), Some("-c"));
                assert_eq!(
                    argv.get(1).map(String::as_str),
                    Some(super::super::super::PUT_FILE_SCRIPT),
                    "the script text is a constant, never interpolated"
                );
                assert_eq!(
                    &argv[2..],
                    &["_", "/opt/a b;rm -rf /", "root", "root", "0600"],
                    "dest, owner, group and mode arrive as discrete words"
                );
            }

            #[test]
            fn a_service_owned_directory_is_verified_and_never_repaired() {
                // Correcting a directory a lower-privileged account controls means
                // running a privileged operation over entries that account can
                // manipulate — the race the whole contract exists to avoid, which
                // no ordering makes safe. So the mismatch is a hard error naming
                // the path, and the directory is left exactly as it was.
                let root = tempfile::tempdir().expect("tempdir");
                let dir = root.path().join("agent").join("aice-web-next");
                std::fs::create_dir_all(&dir).expect("create");
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
                    .expect("mode");

                let meta = FileMeta::new(
                    Principal::Service(crate::executor::ServiceAccount::Security),
                    Principal::Service(crate::executor::ServiceAccount::Security),
                    0o700,
                );
                let error = daemon()
                    .make_dir(&dir, meta)
                    .expect_err("a service-writable mismatch is a hard error");
                match error {
                    ExecutorError::DirectoryMismatch { path, .. } => assert_eq!(path, dir),
                    other => panic!("expected DirectoryMismatch naming the path, got: {other:?}"),
                }
                assert_eq!(
                    mode_of(&dir),
                    0o755,
                    "a verified directory must be left exactly as it was found"
                );
            }

            #[test]
            fn a_root_owned_directory_is_created_then_corrected_and_the_correction_reported() {
                // A re-install must not inherit a weakened tree from a failed
                // earlier attempt, and correcting a directory nothing
                // unprivileged can write is safe — so this half of the asymmetry
                // repairs, and says so.
                let root = tempfile::tempdir().expect("tempdir");
                let dir = root.path().join("namespace");
                let meta = current_meta(0o755);

                assert_eq!(
                    daemon().make_dir(&dir, meta).expect("create"),
                    DirOutcome::Created,
                    "an absent directory is created with explicit metadata"
                );
                assert_eq!(mode_of(&dir), 0o755, "never at the umask");
                assert_eq!(
                    daemon().make_dir(&dir, meta).expect("re-run"),
                    DirOutcome::Matched,
                    "a matching directory is left alone"
                );

                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
                    .expect("weaken");
                assert_eq!(
                    daemon().make_dir(&dir, meta).expect("correct"),
                    DirOutcome::Corrected,
                    "a weakened root-owned directory is repaired, and the repair reported"
                );
                assert_eq!(mode_of(&dir), 0o755);
            }

            #[test]
            fn a_directory_is_never_created_by_a_bare_mkdir() {
                // `mkdir -p` lands a host directory at the umask, which is the
                // same gap the write primitive closes for files.
                let script = super::super::super::MAKE_DIR_SCRIPT;
                assert!(
                    !script.contains("mkdir"),
                    "host directories must not be created by mkdir: {script}"
                );
                assert!(
                    script.contains(r#"install -d -o "$owner" -g "$group" -m "$mode""#),
                    "owner, group and mode must all be explicit: {script}"
                );
            }
        }
    }
}
