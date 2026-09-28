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

pub use self::channel::{Channel, ChannelError, ChannelExit, ChannelLimits};
use crate::durability::sync_dir;
use crate::transport::{HostKeyPolicy, Ssh};

// The bounded, killable run behind `Executor::run_with_input`, shared by every
// transport.
mod bounded;
// The long-lived channel behind `Executor::open_channel`.
mod channel;
// A scriptable, recording executor, for this crate's tests and for dependents
// that enable `test-support` under `[dev-dependencies]`.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

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
///   for durable when it is not. What reaches a caller from that line is a
///   transport question, settled at [`Executor::put_file`], which surfaces this
///   script's stderr only on a write that failed.
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
/// The `sh -c` script that links one file aside, run as a single elevated
/// invocation on the shell transports. Invoked as
/// `sh -c SCRIPT _ <source> <dest>`, so both paths arrive positionally and are
/// never spliced into the script text.
///
/// The sequence is refuse-a-non-regular-source → `link` to a temporary sibling
/// → `rename` over the destination → flush the directory:
///
/// - **A link, not a copy.** An interrupted `cp` leaves a *truncated*
///   destination, which a later reader succeeds onto; an interrupted link
///   leaves *no* destination, which fails where anyone looking can see it. The
///   link also subsumes what `cp -p` preserves: sharing an inode makes the mode
///   and the timestamps identical rather than copied.
/// - **A regular file only.** `ln` without `-L` captures a *symlink* itself, so
///   linking one would leave a destination pointing wherever the operator
///   pointed it — and POSIX leaves it implementation-defined whether `ln`
///   dereferences at all, so which of the two happens is not the target's to
///   decide. A symlink is refused before the link, and what the link produced
///   is checked again afterwards: the temporary shares the source's inode, so
///   its own type is the type of the object actually linked, whatever `ln`
///   resolved and whatever raced the guard. A directory or any other
///   non-regular file is refused on the same terms.
/// - **Not `ln -f`.** `link(2)` fails with `EEXIST`, so `ln -f` *unlinks the
///   destination and then links* — a window in which the destination does not
///   exist at all. Link-to-temporary then `rename` is atomic and never exposes
///   an absent destination, which is the same idiom [`PUT_FILE_SCRIPT`] lands
///   the artifact itself with. An entry already sitting at the temporary name
///   is never cleared away either, for the same reason: the link fails on it,
///   and that refusal is what the recovery below is built on rather than
///   something to work around.
/// - **The temporary name is chosen, not assumed free.** An attempt
///   interrupted between the `ln` and the `trap` on the line after it leaves a
///   completed link behind — an ordinary `TERM` is enough, the trap not being
///   registered yet — and the caller's journal correctly records no backup, so
///   a resumed apply must be able to take one. `$$` alone cannot tell this run
///   apart from the one that left the leftover, because pids are reused, and
///   under `sudo sh -c` in a container they are reused quickly. So the name
///   carries an attempt number as well, and an occupied candidate is stepped
///   over rather than adopted, unlinked or resolved through: only a failure
///   that left the name taken advances to the next candidate. Every other
///   failure is reported with the diagnostic the link attempt gave, and a
///   directory in which [`LINK_TEMP_ATTEMPTS`] consecutive candidates are
///   taken is reported too rather than being retried forever. [`link_aside`]
///   chooses the native side's name on the same terms.
///
///   **The link is made by `link`, and by nothing else.** `ln` is the one step
///   here that does not fail on an occupied name: given a *directory*, or a
///   symlink to one, it links the source *inside* it and exits `0`, which
///   would both write through a planted entry and leave the link behind under
///   a path nobody named. No option suppresses that portably — `-T` is GNU's,
///   `-h` and `-n` are the BSDs' and cover only the symlink — and no test run
///   ahead of it closes it either, since an entry appearing between the test
///   and the `ln` is followed exactly as one that was already there. `link` is
///   a different utility rather than another spelling of that one: it passes
///   the two names it was given to `link(2)` and does nothing else, so an
///   occupied candidate is `EEXIST` there whatever kind of entry sits at it,
///   with no name resolved and so no window to race. That is the same refusal
///   [`link_aside`] gets from the same syscall.
///
///   `link` is not POSIX, so a host could in principle carry none. That is
///   refused before the walk begins rather than degraded onto `ln`: the
///   refusal of a planted entry is what this recovery is *for*, and an `ln`
///   path would give it up on exactly the hosts nobody checked. What such a
///   host loses is the backup, reported as [`ExecutorError::Transfer`] naming
///   the destination like every other on-host failure here, which is a
///   diagnosable stop rather than a link made through somebody else's
///   directory. The set is close to empty in practice — coreutils, busybox,
///   toybox and the BSDs all ship `link` — and the check is a `command -v`,
///   not a probe run against the candidate.
///
///   The trap stays *below the walk* rather than being hoisted above it. `$tmp`
///   names whichever candidate is in hand, so a trap armed inside the walk
///   would fire on a *refused* one and `rm -f` a leftover this sequence is
///   required to leave standing. Below it, `$tmp` is the entry `link(2)` just
///   created and nothing else can be: the walk breaks only on a link this
///   script made. So it is armed there, before the temporary's own type is
///   checked, and that guard needs no cleanup of its own — what it refuses is
///   still this script's own entry, unlinked by the name it was given.
/// - **Not a bare `link`.** A directory entry is not durable until its
///   directory is flushed, and a backup is precisely the thing that must
///   survive a power loss. The flush runs after the rename, per the ordering
///   rule [`crate::durability`] states.
///
///   It selects a `sync` the way [`PUT_FILE_SCRIPT`] does — the targeted form
///   first, the host-wide one where an implementation refuses the operand,
///   because which of the two a target carries cannot be told from the name.
///   Where the two *end* differs, and deliberately: a host on which both fail
///   carries no working `sync` at all, and this script fails there rather than
///   warning and standing, so the failure arrives as
///   [`ExecutorError::Transfer`] exactly as [`hard_link_over_natively`]'s
///   `fsync` failure does. [`PUT_FILE_SCRIPT`] lets that case stand because
///   the caller still holds the bytes and can write them again; nothing holds
///   the artifact's pre-apply inode once the backup is the only other name for
///   it, and the caller records the backup as taken from this call's success.
///   A success reported over a flush that never ran would let that record
///   suppress the retake the un-flushed entry is precisely what needs.
/// - **The landing is confirmed by inode**, exactly as [`PUT_FILE_SCRIPT`]
///   confirms its own: a directory appearing at the destination between the
///   guard and the `mv` would otherwise take the temporary *inside* it and exit
///   `0`, reporting success for a file that landed under a path the caller
///   never named. `find` does not follow a symlink at the named path, so a
///   symlink planted there fails the match rather than being resolved through.
/// - **The rename is skipped where it would be a no-op.** `rename(2)` returns
///   success and does nothing when both names already refer to one inode,
///   which is what a second backup of an unchanged artifact asks for, but `mv`
///   does not pass that case through to it: GNU's refuses it outright with
///   `are the same file` and exits non-zero. The inode the confirmation below
///   needs anyway is therefore compared against the destination first, and the
///   `mv` runs only where the two differ. The final `rm -f "$tmp"` is not the
///   cleanup path — the trap is — but that skip's last step, since a rename
///   that never ran leaves the temporary standing.
const LINK_ASIDE_SCRIPT: &str = r#"set -e
source=$1; dest=$2
if [ -h "$source" ]; then
  echo "$source is a symbolic link, not a regular file" >&2
  exit 1
fi
if [ ! -f "$source" ]; then
  echo "$source is not a regular file" >&2
  exit 1
fi
if [ -d "$dest" ]; then
  echo "destination $dest is a directory" >&2
  exit 1
fi
flush() {
  sync "$1" 2>/dev/null || sync || {
    echo "$1 was not flushed: no working sync" >&2
    return 1
  }
}
dir=$(dirname "$dest")
if ! command -v link >/dev/null 2>&1; then
  echo "no link utility: a temporary beside $dest cannot be claimed without following it" >&2
  exit 1
fi
attempt=0
while :; do
  tmp=$dir/.bootler.link.$$.$attempt
  if err=$(link "$source" "$tmp" 2>&1); then
    break
  elif [ -e "$tmp" ] || [ -h "$tmp" ]; then
    taken=$err
  else
    echo "$err" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 64 ]; then
    echo "no free temporary name beside $dest: $taken" >&2
    exit 1
  fi
done
trap 'rm -f "$tmp"' EXIT INT TERM
if [ -h "$tmp" ] || [ ! -f "$tmp" ]; then
  echo "$source is not a regular file" >&2
  exit 1
fi
ino=$(ls -di "$tmp" | awk '{print $1}')
if [ -z "$(find "$dest" -maxdepth 0 -inum "$ino" 2>/dev/null)" ]; then
  mv -f "$tmp" "$dest"
fi
flush "$dir"
if [ -z "$(find "$dest" -maxdepth 0 -inum "$ino" 2>/dev/null)" ]; then
  if [ -d "$dest" ]; then rm -f "$dest/${tmp##*/}"; fi
  echo "destination $dest is not the file just linked" >&2
  exit 1
fi
rm -f "$tmp"
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
/// How many temporary names [`link_aside`] tries beside one destination before
/// reporting that none is free, mirrored by the same bound in
/// [`LINK_ASIDE_SCRIPT`].
///
/// Each name past the first is one an interrupted attempt under this pid left
/// behind, or one a concurrent link into the same directory holds; both are
/// exhausted long before this, and a directory that really does hold this many
/// is one to report rather than to keep walking.
#[cfg(unix)]
const LINK_TEMP_ATTEMPTS: u32 = 64;
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
/// Marker the descent script prints on stderr, in place of
/// [`SUDO_OK_SENTINEL`], when the target identity cannot enter the profile's
/// working directory: `sudo` descended, but the command was never started.
const NO_WORKING_DIRECTORY_MARKER: &str = "__BOOTLER_NO_WORKING_DIRECTORY__";
/// The `$0` the descent script runs under, so a shell diagnostic — `cd`'s,
/// above all — names what printed it.
const DESCENT_ARG0: &str = "bootler-descent";

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

/// The bounds one [`Executor::run_with_input`] call runs under.
///
/// There is no `Default`: how much output a command may write and how long it
/// may take are the caller's decisions about that command, not the executor's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    /// The most bytes the command may write to standard output.
    pub max_stdout: usize,
    /// The most bytes the command may write to standard error.
    pub max_stderr: usize,
    /// How long the command may run before it is killed.
    pub timeout: Duration,
}

/// One of a command's two output streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl std::fmt::Display for OutputStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        })
    }
}

/// Errors raised by [`Executor::run_with_input`].
///
/// A type of its own rather than more [`ExecutorError`] variants, because the
/// variants below arise from this one method alone: a caller of
/// [`Executor::run`] or any other primitive never has to consider them, and an
/// exhaustive match over [`ExecutorError`] elsewhere stays exhaustive.
#[derive(Debug, thiserror::Error)]
pub enum RunWithInputError {
    /// `command` is not an absolute path, or contains `=`, and was refused
    /// before anything was spawned.
    ///
    /// The command runs with no `PATH`, so only an absolute path names one
    /// binary. `=` is refused because the command is started through
    /// `env -i` wherever a supervisor runs it, and `env` reads an operand
    /// containing `=` as a variable assignment rather than the utility.
    #[error("command `{command}` is not an absolute path free of `=`")]
    InvalidCommand {
        /// The command as the caller named it.
        command: String,
    },
    /// The command wrote more than `limit` bytes to `stream`. It was killed
    /// and waited for, or had already exited.
    #[error("`{command}` wrote more than {limit} bytes to {stream}")]
    OutputLimit {
        /// The command that was run.
        command: String,
        /// The stream that passed its limit.
        stream: OutputStream,
        /// The limit it passed.
        limit: usize,
    },
    /// The command was still running when `timeout` passed. It was killed
    /// and waited for.
    #[error("`{command}` did not finish within {timeout:?}")]
    TimedOut {
        /// The command that was run.
        command: String,
        /// The timeout it outlived.
        timeout: Duration,
    },
    /// The executor does not implement [`Executor::run_with_input`].
    ///
    /// Only the trait's default body returns this. [`LocalExecutor`],
    /// [`SshExecutor`] and [`InDaemonExecutor`] each implement the method, as
    /// does the `RecordingExecutor` the `test-support` feature exposes.
    #[error("this executor cannot run a command with bounded input")]
    Unsupported,
    /// Spawning, the transport or elevation failed, exactly as
    /// [`Executor::run`] reports it.
    #[error(transparent)]
    Executor(#[from] ExecutorError),
}

/// Reports whether `command` is an absolute path free of `=`: the one form
/// that names a single binary with no `PATH`, and that `env` cannot read as an
/// assignment.
fn is_absolute_and_plain(command: &str) -> bool {
    Path::new(command).is_absolute() && !command.contains('=')
}

/// Refuses a command [`Executor::run_with_input`] cannot run as named.
fn check_bounded_command(command: &str) -> Result<(), RunWithInputError> {
    if is_absolute_and_plain(command) {
        Ok(())
    } else {
        Err(RunWithInputError::InvalidCommand {
            command: command.to_string(),
        })
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

    /// Runs `command` with `args` as `identity`, feeding it `input` on
    /// standard input and holding it to `limits`.
    ///
    /// This is [`Executor::run`] for a command that is handed a request and
    /// must answer within bounds:
    ///
    /// - **`command` must be an absolute path**, free of `=`. Anything else is
    ///   [`RunWithInputError::InvalidCommand`], refused before anything is
    ///   spawned.
    /// - **`input` is written to the command's standard input**, which is then
    ///   closed; an empty `input` closes it at once. The bytes pass through
    ///   every transport verbatim.
    /// - **The command runs with an empty environment** — no inherited
    ///   variable, and so no `PATH` lookup. Where `sudo` or an SSH session
    ///   stands between this process and the command, the environment either
    ///   of them sets up is cleared again before the command starts.
    /// - **Standard output and standard error are each read up to their
    ///   limit.** One byte past either, or the command outliving
    ///   `limits.timeout`, kills the command and waits for it, and is reported
    ///   as [`RunWithInputError::OutputLimit`] or
    ///   [`RunWithInputError::TimedOut`] — never as a [`CommandOutput`].
    ///   The limits bound the command's own bytes: what `sudo` or `ssh`
    ///   writes before the command starts is neither counted nor returned,
    ///   so a refusal or a failed connection is reported as the error
    ///   [`Executor::run`] reports for it however small `max_stderr` is.
    ///   Where a supervising shell or the SSH exit-status line shares
    ///   standard error with the command, a byte past `max_stderr` that could
    ///   still be the start of that framing is given a second to become it
    ///   before it counts, so a command that stops on such a byte is killed
    ///   up to a second after it passed its limit.
    /// - **A non-zero exit is a [`CommandOutput`]**, as it is from
    ///   [`Executor::run`].
    ///
    /// `identity` resolves exactly as it does for [`Executor::run`], at the
    /// same resolution site: no prefix for [`Identity::Operator`], `sudo` for
    /// [`Identity::Root`] and `sudo -u <account>` for [`Identity::Service`] on
    /// the elevating transports, with [`SudoAuth`] governing both; and inside
    /// the root daemon, no prefix for root, a `sudo -u` descent that never
    /// prompts for a service account, and a refusal for the operator.
    ///
    /// **What "killed" reaches depends on who may signal whom**, so the
    /// transports get there differently:
    ///
    /// - A command this process spawns directly — [`Identity::Operator`] on
    ///   [`LocalExecutor`], [`Identity::Root`] on [`InDaemonExecutor`] — runs
    ///   in a process group of its own, which is killed with `SIGKILL`. Every
    ///   descendant that stayed in the group dies with it.
    /// - Where `sudo` stands in between, the command runs under a supervising
    ///   shell that kills the command's process group from the inside, on the
    ///   `SIGTERM` `sudo` relays to it and on a deadline of its own, so a
    ///   command that ignores `SIGTERM` still dies even where this process may
    ///   not signal it. Only after that is `sudo`'s own group killed.
    /// - Over [`SshExecutor`], the local `ssh` process is killed at the
    ///   deadline. No signal crosses the connection, so the remote command is
    ///   ended by the same supervising shell on the remote host, at its own
    ///   deadline — `limits.timeout` rounded up to a whole second, counted
    ///   from when the remote side started — and this call does not wait to
    ///   see it happen. A command whose stream passes its limit is ended the
    ///   same way on the remote side: once `ssh` is gone its output pipes are
    ///   closed, and the supervisor's deadline ends it if writing does not.
    ///
    /// A descendant that leaves the process group — a daemon that calls
    /// `setsid` — is out of reach on every transport. A supervised command
    /// that a signal kills reports `128 + signal` as its exit code rather than
    /// none, and starts with `SIGINT` and `SIGQUIT` ignored, as any command a
    /// shell runs in the background does.
    ///
    /// The command's process group is also not the caller's, so a signal the
    /// caller's terminal generates does not reach the command; `limits` is
    /// what bounds it.
    ///
    /// The default body refuses with [`RunWithInputError::Unsupported`], so an
    /// existing implementation of this trait keeps compiling; every executor
    /// this crate ships overrides it.
    ///
    /// # Errors
    ///
    /// Returns [`RunWithInputError::InvalidCommand`] for a command that is not
    /// an absolute path free of `=`, [`RunWithInputError::OutputLimit`] or
    /// [`RunWithInputError::TimedOut`] for a command that was stopped, and
    /// [`RunWithInputError::Executor`] carrying whatever [`Executor::run`]
    /// would report for a spawn, transport or elevation failure.
    fn run_with_input(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        let _ = (identity, command, args, input, limits);
        Err(RunWithInputError::Unsupported)
    }

    /// Starts `command` with `args` as `identity` and returns a [`Channel`]
    /// to it that lives until the caller ends it.
    ///
    /// This is the long-lived counterpart of [`Executor::run_with_input`]:
    /// where that call feeds a request and collects an answer within bounds,
    /// this one hands the caller the command's standard input and standard
    /// output for as long as it runs, with no size or time bound from this
    /// crate.
    ///
    /// - **`command` must be an absolute path**, free of `=`. Anything else is
    ///   [`ChannelError::InvalidCommand`], refused before anything is spawned.
    ///   `args` stay discrete words on every transport.
    /// - **The command runs with an empty environment** — no inherited
    ///   variable, and so no `PATH` lookup. Where `sudo` or an SSH session
    ///   stands between this process and the command, the environment either
    ///   of them sets up is cleared again with `env -i` as the command starts.
    /// - **The start is proven before this returns.** Where `sudo` or SSH
    ///   stands in between — [`Identity::Root`] and [`Identity::Service`] on
    ///   [`LocalExecutor`], every identity on [`SshExecutor`] — the command
    ///   starts under a fixed `sh -c` script that announces the start on
    ///   standard error, reads standard input up to a line written after the
    ///   announcement, and then replaces itself with the command. Under
    ///   [`SudoAuth::Password`] the password line is written first; a `sudo`
    ///   that does not ask for it — a `NOPASSWD` rule, or credentials it still
    ///   has cached — leaves it for the script, which discards it. Either way
    ///   standard input then stays open for the caller, and the command's
    ///   first byte of input is the caller's first byte. Standard error is
    ///   read until the announcement, and standard output not at all. A
    ///   transport that ends first, or writes more than 64 KiB ahead of the
    ///   announcement, is killed and classified as [`Executor::run`]
    ///   classifies that output; one that does neither within
    ///   `limits.elevation_timeout` is killed and reaped. The operator on
    ///   [`LocalExecutor`] is spawned directly, and this returns at once.
    /// - **Standard error stays with the channel**, drained for its whole
    ///   life so the command never blocks on it: the first
    ///   `limits.max_stderr` bytes of the command's own standard error are
    ///   kept for [`Channel::wait`], the rest discarded and noted. Over SSH the
    ///   wrapper's trailing exit-status line is removed and supplies the exit
    ///   code, so a remote `255` is the command's.
    ///
    /// `identity` resolves exactly as it does for [`Executor::run`], at the
    /// same resolution site: no prefix for [`Identity::Operator`], `sudo` for
    /// [`Identity::Root`] and `sudo -u <account>` for [`Identity::Service`],
    /// with [`SudoAuth`] choosing `-n` or `-S -p ""`; over SSH, the same `ssh`
    /// invocation — key, port, host-key policy, and `BatchMode=yes` under
    /// [`SshPrompt::Deny`] — with no terminal requested. The transport is
    /// spawned in the caller's process group, as [`Executor::run`] spawns it,
    /// so a passphrase prompt [`SshPrompt::Allow`] permits still reaches the
    /// terminal.
    ///
    /// [`Channel`] states what ending the channel reaches: the local
    /// transport process, not a command started through `sudo` or over SSH,
    /// and never a descendant.
    ///
    /// The default body refuses with [`ChannelError::Unsupported`], so an
    /// existing implementation of this trait keeps compiling. [`LocalExecutor`]
    /// and [`SshExecutor`] override it; [`InDaemonExecutor`] does not.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::InvalidCommand`] for a command that is not an
    /// absolute path free of `=`, [`ChannelError::ElevationTimedOut`] for a
    /// start not proven within `limits.elevation_timeout`, and
    /// [`ChannelError::Executor`] carrying whatever [`Executor::run`] would
    /// report for a spawn, transport or elevation failure —
    /// [`ExecutorError::Connection`], [`ExecutorError::Elevation`] or
    /// [`ExecutorError::SudoRefused`]. An SSH transport whose remote shell
    /// ran but did not start the command is reported as
    /// [`ExecutorError::SudoRefused`] carrying the remote diagnostic, for the
    /// operator too.
    fn open_channel(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        limits: ChannelLimits,
    ) -> Result<Channel, ChannelError> {
        let _ = (identity, command, args, limits);
        Err(ChannelError::Unsupported)
    }

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
    /// crate — a host carrying no working `sync` still lands the file rather
    /// than failing the install, and the script says on its own stderr that the
    /// flush did not happen. That stderr is what [`ExecutorError::Transfer`]
    /// carries, so the line reaches a caller only when the write itself failed
    /// too: a `put_file` that returned `Ok` on such a host reports nothing about
    /// the flush it could not perform, and this crate has no logging facade to
    /// raise it through.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the write fails, or the elevation errors
    /// of [`Executor::run`], since the write elevates on every transport that
    /// is not already root.
    fn put_file(&self, dest: &Path, contents: &[u8], meta: FileMeta) -> Result<(), ExecutorError>;

    /// Hard-links the regular file `source` to `dest` on the target, replacing
    /// whatever `dest` named, and flushes the directory the new entry appears
    /// in.
    ///
    /// This is the preservation primitive [`crate::apply::backup_previous_artifact`]
    /// takes a `.previous` backup with, and it takes no [`Identity`] for the
    /// same reason [`Executor::put_file`] does not: the paths it acts on are
    /// root-owned, so the operation is root's or it is nothing.
    ///
    /// **A link rather than a copy, and the difference is the guarantee.** An
    /// interrupted copy leaves a *truncated* `dest` that a later reader
    /// succeeds onto; an interrupted link leaves no `dest` at all, which fails
    /// where anyone looking can see it. Sharing an inode also makes the mode
    /// and the timestamps identical rather than copied, so nothing preserves
    /// them separately — and an in-place write to `source` afterwards would
    /// destroy the linked copy, which is exactly why [`Executor::put_file`]
    /// replaces a directory entry rather than writing through one.
    ///
    /// Every transport runs the same sequence: refuse a `source` that is not a
    /// regular file, `link` it to a temporary sibling of `dest`, `rename` that
    /// over `dest`, then flush `dest`'s directory. The rename is what keeps a
    /// `dest` that already existed continuously present — `link(2)` fails with
    /// `EEXIST`, so linking onto the name directly would mean unlinking it
    /// first and exposing a window with no backup — and the flush is what makes
    /// the new entry durable, since a directory entry is not on disk until its
    /// directory is.
    ///
    /// **A symlink at `source` is refused, not followed**, and so is a
    /// directory or any other non-regular file. Following one would leave a
    /// `dest` pointing wherever the symlink pointed, and linking one without
    /// following would capture the symlink itself; neither is a backup of the
    /// artifact. The refusal is re-checked against what the link actually
    /// produced, so a path swapped under the guard is caught rather than
    /// linked.
    ///
    /// A symlink at `dest` is neither refused nor followed but **replaced**:
    /// the publish renames over the name it was given, so an entry planted
    /// there is displaced rather than written through, and whatever it pointed
    /// at is left alone. A copy would have opened it and landed the artifact's
    /// bytes on the pointed-at file instead of at `dest`.
    ///
    /// The two fault models the sequence answers differ, and only one of them
    /// is a claim about `dest`:
    ///
    /// - **Process interruption**, where the filesystem holds whatever the last
    ///   completed call left: a `dest` that already existed is either the old
    ///   file or the new one at every point, never a partial or absent one,
    ///   because the old entry is never unlinked and the `rename` is atomic.
    /// - **Power loss**, where a completed call whose entry has not been
    ///   flushed may or may not survive: nothing above the flush is claimed. A
    ///   caller that must know whether the backup was taken keeps its own
    ///   record of having taken it and re-takes it when that record is absent.
    ///
    /// [`InDaemonExecutor`] runs the sequence as direct syscalls, being root
    /// already; the shell transports run it as a single elevated `sh -c`
    /// script. Both report every on-host failure — of the link, the rename, the
    /// flush and the confirmation — as [`ExecutorError::Transfer`] naming
    /// `dest`, so a caller need not tell the two mechanisms apart.
    ///
    /// The flush is the step whose *mechanism* differs most, and it is still
    /// held to that contract. Natively it is `fsync` on an open descriptor. On
    /// the shell transports it is the `sync` utility, which some hosts do not
    /// accept an operand for; the script falls back to the host-wide `sync`,
    /// and a host on which that fails too — one carrying no working `sync` at
    /// all — fails the backup rather than reporting one it could not make
    /// durable. What is disclaimed above is a fault *between* the rename and a
    /// flush that ran, not a flush that never ran: this call returning `Ok` is
    /// what a caller writes its backup-taken record from, and a record written
    /// over a skipped flush would suppress the retake the missing entry needs.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Transfer`] when `source` is not a regular file,
    /// when the link, the rename or the flush fails, or when what landed at
    /// `dest` is not the file that was just linked, and the elevation errors of
    /// [`Executor::run`], since the sequence elevates on every transport that
    /// is not already root.
    fn hard_link_over(&self, source: &Path, dest: &Path) -> Result<(), ExecutorError> {
        hard_link_over_through_shell(self, source, dest)
    }

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

/// Links `source` aside to `dest` by running [`LINK_ASIDE_SCRIPT`] as root, for
/// the transports that have no cheaper native path.
///
/// The whole sequence is one elevated invocation, so nothing can be interleaved
/// between the link and the rename by another elevation, and the script's own
/// stderr is what reaches the caller as the failure reason.
fn hard_link_over_through_shell<E: Executor + ?Sized>(
    executor: &E,
    source: &Path,
    dest: &Path,
) -> Result<(), ExecutorError> {
    let output = executor.run(
        Identity::Root,
        SH,
        &[
            "-c",
            LINK_ASIDE_SCRIPT,
            "_",
            &source.to_string_lossy(),
            &dest.to_string_lossy(),
        ],
    )?;
    if output.success() {
        Ok(())
    } else {
        Err(ExecutorError::Transfer {
            path: dest.to_path_buf(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// Step 1 of the link-based backup: `link(2)` `source` to a temporary sibling
/// in `dir`, refusing a `source` that is not a regular file, and returning the
/// name the link was made under.
///
/// The refusal is made twice, and the second one is the one that holds.
/// `std::fs::hard_link` is `linkat(…, 0)`, which does not follow a symlink at
/// `source`, so a symlink swapped in after the first check would be captured
/// rather than followed; the temporary shares the linked inode, so its own type
/// reports what was actually linked and a wrong one is unlinked again before
/// anything is published. The first check exists to say *which* wrong kind of
/// file was named, which the second cannot.
///
/// **The name is chosen rather than assumed free.** An earlier attempt
/// interrupted between the link and the publish leaves a completed link at the
/// name it drew, and the pid the name carries does not distinguish this process
/// from the one that left it: pids are reused, and [`NATIVE_TEMP_COUNTER`]
/// would be no help here even where it is used, since it restarts at 0 in every
/// process. So the attempt number is walked upwards until a name is free, and
/// an occupied one is stepped over rather than adopted, unlinked or resolved
/// through — `link(2)` returning `EEXIST` is what says the name is taken, and
/// every other failure is reported as itself. That refusal covers every kind of
/// entry: the new name is never resolved, so a directory or a symlink to one
/// sitting at a candidate is `EEXIST` like anything else, where an `ln` handed
/// the same name would have linked the source *inside* it.
/// [`LINK_ASIDE_SCRIPT`] walks the same candidates under the same bound, and
/// reaches this same syscall through `link(1)` for exactly that reason, on a
/// host carrying no `link` refusing the backup rather than linking with `ln`.
///
/// The candidates are siblings of the destination, because `link(2)` cannot
/// cross a filesystem and only the destination's own directory is guaranteed to
/// be on the source's.
///
/// On return, the returned name exists as a second name for `source`'s inode
/// and nothing else on the filesystem has changed — an interruption here leaves
/// the destination the caller was going to publish over exactly as it was.
#[cfg(unix)]
fn link_aside(source: &Path, dir: &Path, dest: &Path) -> Result<PathBuf, ExecutorError> {
    let refuse = |reason: String| ExecutorError::Transfer {
        path: dest.to_path_buf(),
        reason,
    };
    let found =
        std::fs::symlink_metadata(source).map_err(|error| refuse(link_reason(source, &error)))?;
    if found.file_type().is_symlink() {
        return Err(refuse(format!(
            "{} is a symbolic link, not a regular file",
            source.display()
        )));
    }
    if !found.is_file() {
        return Err(refuse(format!(
            "{} is not a regular file",
            source.display()
        )));
    }
    let mut occupied = None;
    for attempt in 0..LINK_TEMP_ATTEMPTS {
        let temp = dir.join(format!(".bootler.link.{}.{attempt}", std::process::id()));
        // `link(2)` fails with `EEXIST` rather than adopting an entry already
        // at the temporary name, so a stale or planted one is left standing and
        // the next candidate is tried.
        match std::fs::hard_link(source, &temp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                occupied = Some(link_reason(&temp, &error));
                continue;
            }
            Err(error) => return Err(refuse(link_reason(&temp, &error))),
        }
        let linked = std::fs::symlink_metadata(&temp).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            refuse(link_reason(&temp, &error))
        })?;
        if linked.file_type().is_symlink() || !linked.is_file() {
            let _ = std::fs::remove_file(&temp);
            return Err(refuse(format!(
                "{} is not a regular file",
                source.display()
            )));
        }
        return Ok(temp);
    }
    Err(refuse(format!(
        "no free temporary name beside {}: {}",
        dest.display(),
        occupied.expect("the loop falls through only after a candidate was refused as occupied")
    )))
}

/// Renders one failed syscall of the link sequence as a reason string naming
/// the path it happened on.
///
/// The variant carrying it names the *destination*, which is what the caller
/// asked for and what the shell transports name too; the path here is whichever
/// intermediate the call touched, and would otherwise be lost.
#[cfg(unix)]
fn link_reason(path: &Path, error: &std::io::Error) -> String {
    format!("{}: {error}", path.display())
}

/// Step 2: `rename(2)` `temp` over `dest`, which replaces the entry atomically
/// and never leaves `dest` absent.
///
/// The `remove_file` afterwards is not a cleanup path — a rename that moved the
/// entry leaves nothing at `temp` — but the one case where the rename is a
/// no-op: POSIX has it return success and do nothing when both names already
/// refer to a single inode, which is what re-linking an unchanged artifact
/// asks for.
#[cfg(unix)]
fn publish_link(temp: &Path, dest: &Path) -> Result<(), ExecutorError> {
    let renamed = std::fs::rename(temp, dest);
    // Either way the temporary name is not left behind: on failure it is the
    // cleanup, and on the no-op rename it is the whole of the work.
    let _ = std::fs::remove_file(temp);
    renamed.map_err(|error| ExecutorError::Transfer {
        path: dest.to_path_buf(),
        reason: link_reason(temp, &error),
    })
}

/// The link-based backup run with direct syscalls, for the transport that is
/// already root and needs neither a shell nor `sudo`.
///
/// The three steps are the three functions the issue's sequence names —
/// [`link_aside`], [`publish_link`], [`sync_dir`] — composed in that order and
/// in no other, so what a caller reads is the fault model: after the first,
/// `dest` is untouched; after the second, `dest` is the new file; after the
/// third, that is true of the disk and not only of the page cache.
#[cfg(unix)]
fn hard_link_over_natively(source: &Path, dest: &Path) -> Result<(), ExecutorError> {
    let dir = dest.parent().ok_or_else(|| ExecutorError::Transfer {
        path: dest.to_path_buf(),
        reason: "the destination has no directory to link into".to_string(),
    })?;
    let temp = link_aside(source, dir, dest)?;
    publish_link(&temp, dest)?;
    sync_dir(dir).map_err(|error| ExecutorError::Transfer {
        path: dest.to_path_buf(),
        reason: link_reason(dir, &error),
    })
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

/// The `sh -c` script [`InDaemonExecutor::descent_command`] descends through,
/// run as the target identity.
///
/// Invoked as `sh -c SCRIPT <arg0> <cwd> <K=V>… <command> <args…>`: it enters
/// `<cwd>` or prints [`NO_WORKING_DIRECTORY_MARKER`] and exits `1`, then
/// announces the start with [`SUDO_OK_SENTINEL`] and replaces itself with
/// `env -i`, which takes the `K=V` words as the whole environment and the first
/// word without `=` as the utility. Every value is a positional word, never
/// spliced into the script text.
fn descent_script() -> String {
    format!(
        "cd -- \"$1\" || {{ printf '%s' '{NO_WORKING_DIRECTORY_MARKER}' >&2; exit 1; }}; \
         shift; printf '%s' '{SUDO_OK_SENTINEL}' >&2; exec {env} -i \"$@\"",
        env = bounded::ENV,
    )
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
    Err(elevation_refusal(&output.stderr, auth, host))
}

/// Classifies what `sudo` wrote on `stderr` when the sentinel never arrived,
/// as [`classify_elevation`] reports it: [`ExecutorError::Elevation`] for a
/// non-interactive `sudo` that wanted a password, [`ExecutorError::SudoRefused`]
/// carrying the diagnostic otherwise.
fn elevation_refusal(stderr: &[u8], auth: Option<&SudoAuth>, host: &str) -> ExecutorError {
    if matches!(auth, Some(SudoAuth::NonInteractive)) && sudo_needs_password(stderr) {
        return ExecutorError::Elevation {
            host: host.to_string(),
        };
    }
    ExecutorError::SudoRefused {
        host: host.to_string(),
        reason: String::from_utf8_lossy(stderr).trim().to_string(),
    }
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
        self.resolve_through(identity, SH, &sudo_sentinel_script(), command, args)
    }

    /// Resolves an `(identity, Local)` pair as [`LocalExecutor::resolve`]
    /// does, with an elevated command run under `shell -c script` rather than
    /// the sentinel script — the one knob [`Executor::run_with_input`] turns.
    /// Whether `sudo` is involved, and with which flags and descent, is decided
    /// here for both methods.
    fn resolve_through(
        &self,
        identity: Identity,
        shell: &str,
        script: &str,
        command: &str,
        args: &[&str],
    ) -> Resolved {
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
        cmd.arg(shell).arg("-c").arg(script).arg(command).args(args);
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

impl LocalExecutor {
    /// The local half of [`Executor::run_with_input`]: the command itself for
    /// the operator, the supervisor under `sudo` otherwise.
    fn run_bounded(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        let supervisor = bounded::Supervisor::new(limits.timeout)?;
        let Resolved {
            command: mut cmd,
            password_line,
            elevated,
        } = self.resolve_through(
            identity,
            bounded::SUPERVISOR_SHELL,
            supervisor.script(),
            command,
            args,
        );
        // A command spawned directly has its environment cleared here. `sudo`
        // keeps the caller's, so it is found exactly as `run` finds it; the
        // supervisor clears the command's after `sudo` has set up its own.
        if !elevated {
            cmd.env_clear();
        }
        let program = cmd.get_program().to_string_lossy().into_owned();
        let (framing, kill) = if elevated {
            (supervisor.framing(false), bounded::Kill::Relay)
        } else {
            (bounded::Framing::DIRECT, bounded::Kill::Group)
        };
        let feed = match password_line {
            Some(mut line) => {
                line.extend_from_slice(input);
                line
            }
            None => input.to_vec(),
        };
        let ended = bounded::run(cmd, &program, &feed, limits, framing, kill)?;
        bounded::finish(ended, command, limits, framing, |output| {
            if elevated {
                classify_elevation(output, Some(&self.auth), &self.host)
            } else {
                Ok(output)
            }
        })
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

    fn run_with_input(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        check_bounded_command(command)?;
        self.run_bounded(identity, command, args, input, limits)
    }

    fn open_channel(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        limits: ChannelLimits,
    ) -> Result<Channel, ChannelError> {
        channel::check_command(command)?;
        let script = channel::StartScript::new()?;
        let Resolved {
            command: mut cmd,
            password_line,
            elevated,
        } = self.resolve_through(
            identity,
            channel::START_SHELL,
            script.script(),
            command,
            args,
        );
        // A command spawned directly has its environment cleared here. `sudo`
        // keeps the caller's, so it is found exactly as `run` finds it; the
        // start script clears the command's after `sudo` has set up its own.
        if !elevated {
            cmd.env_clear();
            return channel::open_direct(cmd, limits.max_stderr);
        }
        let start = channel::Start {
            script: &script,
            host: &self.host,
            password_line,
            remote_code: false,
            limits,
        };
        channel::open_started(cmd, &start, |output| {
            elevation_refusal(&output.stderr, Some(&self.auth), &self.host)
        })
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
        let output = spawn_capturing(cmd, &program, stdin)?;
        self.settle_remote_code(output)
    }

    /// Replaces `output`'s exit code with the remote command's own, read from
    /// the [`RC_MARKER`] line, and removes that line from its stderr.
    ///
    /// A missing marker means the wrapper never ran — the transport failed
    /// before the command started — and is an [`ExecutorError::Connection`].
    fn settle_remote_code(
        &self,
        mut output: CommandOutput,
    ) -> Result<CommandOutput, ExecutorError> {
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
        self.resolve_through(identity, SH, &sudo_sentinel_script(), None, command, args)
    }

    /// Resolves an `(identity, Ssh)` pair as [`SshExecutor::resolve`] does,
    /// with an elevated command run under `shell -c script` rather than the
    /// sentinel script, and — where `operator_script` is given — the
    /// operator's command run under `shell -c operator_script` rather than
    /// bare. Those are the knobs [`Executor::run_with_input`] turns; whether
    /// `sudo` is involved, and with which flags and descent, is decided here
    /// for both methods.
    fn resolve_through(
        &self,
        identity: Identity,
        shell: &str,
        script: &str,
        operator_script: Option<&str>,
        command: &str,
        args: &[&str],
    ) -> ResolvedRemote {
        let Some(elevation) = Elevation::of(identity) else {
            let remote = match operator_script {
                Some(wrapper) => shell_join(
                    [shell, "-c", wrapper, command]
                        .into_iter()
                        .chain(args.iter().copied()),
                ),
                None => shell_join(std::iter::once(command).chain(args.iter().copied())),
            };
            return ResolvedRemote {
                remote,
                password_line: None,
                elevated: false,
            };
        };
        let wrapped = [shell, "-c", script, command]
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

impl SshExecutor {
    /// The SSH half of [`Executor::run_with_input`]: the supervisor on the
    /// remote host for every identity, since no signal to the local `ssh`
    /// reaches the remote command.
    fn run_bounded(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        let supervisor = bounded::Supervisor::new(limits.timeout)?;
        let ResolvedRemote {
            remote,
            password_line,
            elevated,
        } = self.resolve_through(
            identity,
            bounded::SUPERVISOR_SHELL,
            supervisor.script(),
            Some(supervisor.script()),
            command,
            args,
        );
        let feed = match password_line {
            Some(mut line) => {
                line.extend_from_slice(input);
                line
            }
            None => input.to_vec(),
        };
        let framing = supervisor.framing(true);
        // `ssh` keeps the caller's environment: it needs `HOME` for its
        // configuration and `SSH_AUTH_SOCK` for the agent. The remote
        // supervisor clears the command's.
        let mut cmd = self.ssh_command();
        cmd.arg(wrap_with_rc_marker(&remote));
        let program = self.ssh_bin.to_string_lossy().into_owned();
        let ended = bounded::run(cmd, &program, &feed, limits, framing, bounded::Kill::Group)?;
        bounded::finish(ended, command, limits, framing, |output| {
            let mut output = self.settle_remote_code(output)?;
            if elevated {
                classify_elevation(output, Some(&self.auth), &self.host)
            } else {
                // The operator's supervisor announces itself too; with no
                // `sudo` to have refused, its absence is only a supervisor
                // that never ran, and the exit status says why.
                take_sudo_sentinel(&mut output.stderr);
                Ok(output)
            }
        })
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

    fn run_with_input(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        check_bounded_command(command)?;
        self.run_bounded(identity, command, args, input, limits)
    }

    fn open_channel(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        limits: ChannelLimits,
    ) -> Result<Channel, ChannelError> {
        channel::check_command(command)?;
        let script = channel::StartScript::new()?;
        let ResolvedRemote {
            remote,
            password_line,
            elevated,
        } = self.resolve_through(
            identity,
            channel::START_SHELL,
            script.script(),
            Some(script.script()),
            command,
            args,
        );
        // `ssh` keeps the caller's environment, as it does for `run`; the
        // remote start script clears the command's.
        let mut cmd = self.ssh_command();
        cmd.arg(wrap_with_rc_marker(&remote));
        let start = channel::Start {
            script: &script,
            host: &self.host,
            password_line,
            remote_code: true,
            limits,
        };
        channel::open_started(cmd, &start, |output| {
            match self.settle_remote_code(output) {
                Err(connection) => connection,
                // The remote shell ran and the command did not start: `sudo`
                // refused it, or, for the operator, the shell could not.
                Ok(output) => {
                    elevation_refusal(&output.stderr, elevated.then_some(&self.auth), &self.host)
                }
            }
        })
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
///
/// It does not implement [`Executor::open_channel`]: that call returns the
/// trait default's [`ChannelError::Unsupported`] here.
///
/// A root caller that spawns, bounds and kills its own children — and knows
/// an operator's ids from a session it authenticated itself — builds its
/// descents with [`InDaemonExecutor::descent_command`] instead, which applies
/// an execution profile after `sudo` has selected the identity. That is not an
/// [`Identity`], and does not change what [`Identity::Operator`] does here.
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
        self.resolve_through(identity, SH, &sudo_sentinel_script(), command, args)
    }

    /// Resolves an `(identity, InDaemon)` pair as [`InDaemonExecutor::resolve`]
    /// does, with a descended command run under `shell -c script` rather than
    /// the sentinel script — the one knob [`Executor::run_with_input`] turns.
    /// Which identities refuse, run bare or descend is decided here for both
    /// methods.
    fn resolve_through(
        &self,
        identity: Identity,
        shell: &str,
        script: &str,
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
                let mut cmd = self.sudo_descent(Descent::Service(account));
                cmd.arg(shell).arg("-c").arg(script).arg(command).args(args);
                Ok((cmd, true))
            }
        }
    }

    /// Returns `sudo` with the words that select `who` and nothing after them:
    /// the one site building a descent from root, for [`Executor::run`] and its
    /// siblings on [`Identity::Service`] and for
    /// [`InDaemonExecutor::descent_command`] alike.
    ///
    /// A service account is `-u <account>`, one word whatever it contains. An
    /// operator is `-u #<uid> -g #<gid>`, the numeric forms `sudo` reads as ids
    /// rather than names.
    fn sudo_descent(&self, who: Descent) -> Command {
        let mut cmd = Command::new(&self.sudo_bin);
        match who {
            Descent::Service(account) => {
                cmd.arg("-u").arg(account.as_str());
            }
            Descent::Operator(ids) => {
                cmd.arg("-u")
                    .arg(format!("#{}", ids.uid))
                    .arg("-g")
                    .arg(format!("#{}", ids.gid));
            }
        }
        cmd
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

impl InDaemonExecutor {
    /// The in-daemon half of [`Executor::run_with_input`]: the command itself
    /// for root, the supervisor under a `sudo -u` descent for a service
    /// account.
    fn run_bounded(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        let supervisor = bounded::Supervisor::new(limits.timeout)?;
        let (mut cmd, elevated) = self.resolve_through(
            identity,
            bounded::SUPERVISOR_SHELL,
            supervisor.script(),
            command,
            args,
        )?;
        // As on the local transport: root's command is cleared here, and a
        // descended one by the supervisor, after `sudo` has run as it does
        // for `run`.
        if !elevated {
            cmd.env_clear();
        }
        let program = cmd.get_program().to_string_lossy().into_owned();
        let (framing, kill) = if elevated {
            (supervisor.framing(false), bounded::Kill::Relay)
        } else {
            (bounded::Framing::DIRECT, bounded::Kill::Group)
        };
        // No password line: descent from root never prompts.
        let ended = bounded::run(cmd, &program, input, limits, framing, kill)?;
        bounded::finish(ended, command, limits, framing, |output| {
            if elevated {
                classify_elevation(output, None, &self.host)
            } else {
                Ok(output)
            }
        })
    }
}

/// Who a root process descends to through
/// [`InDaemonExecutor::descent_command`].
///
/// Not an [`Identity`]: [`Identity::Root`] has no place here, because a root
/// caller spawns its own root children, and [`Descent::Operator`] names an
/// operator by the ids a session already authenticated, where
/// [`Identity::Operator`] inside the daemon has none to name and refuses.
///
/// Like [`Identity`], it has no `FromStr`, `Deserialize` or `From` impl:
/// a service account is still one of the closed [`ServiceAccount`] set, so a
/// configured account name cannot become a descent (RFC 0003 §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Descent {
    /// A bootler-managed service account, reached by `sudo -u <account>`
    /// exactly as [`Identity::Service`] is inside the daemon.
    Service(ServiceAccount),
    /// An already-authenticated operator, reached by
    /// `sudo -u #<uid> -g #<gid>` — never root.
    Operator(OperatorIds),
}

/// An already-authenticated operator's numeric user and group ids.
///
/// Built only by [`OperatorIds::new`], which refuses the ids that would not
/// descend: `0`, root's, and `u32::MAX`, `(uid_t)-1`, which the kernel reads
/// as "leave unchanged". There is no `From<(u32, u32)>`, so every pair goes
/// through that check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorIds {
    uid: u32,
    gid: u32,
}

impl OperatorIds {
    /// Creates the ids of an operator whose session authenticated `uid` and
    /// `gid`.
    ///
    /// # Errors
    ///
    /// Returns [`DescentError::InvalidOperator`] when either id is `0` or
    /// `u32::MAX`.
    pub fn new(uid: u32, gid: u32) -> Result<Self, DescentError> {
        let descendable = |id: u32| id != 0 && id != u32::MAX;
        if descendable(uid) && descendable(gid) {
            Ok(Self { uid, gid })
        } else {
            Err(DescentError::InvalidOperator { uid, gid })
        }
    }

    /// Returns the operator's user id.
    #[must_use]
    pub fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the operator's primary group id.
    #[must_use]
    pub fn gid(self) -> u32 {
        self.gid
    }
}

/// The execution profile [`InDaemonExecutor::descent_command`] applies to the
/// command after `sudo` has selected the identity.
///
/// **No secret belongs in `env`.** Each pair travels as a `K=V` argument word
/// of `sudo` and of the shell it starts, so it is readable in the process
/// table by any local user until the command replaces them.
#[derive(Clone, Copy)]
pub struct DescentProfile<'a> {
    /// The command's whole environment, as `(name, value)` pairs. Each name
    /// matches `[A-Za-z_][A-Za-z0-9_]*` and appears once; no value contains
    /// a NUL byte.
    pub env: &'a [(&'a str, &'a str)],
    /// The command's working directory: absolute, with no NUL byte.
    pub cwd: &'a Path,
}

/// Errors raised building a descent, before anything is built.
///
/// No variant carries an environment value, so none can reach a log through
/// this error.
#[derive(Debug, thiserror::Error)]
pub enum DescentError {
    /// `command` is not an absolute path, or contains `=`.
    ///
    /// The command runs with only the profile's environment, and is started
    /// through `env -i`, which reads an operand containing `=` as an
    /// assignment rather than the utility.
    #[error("command `{command}` is not an absolute path free of `=`")]
    InvalidCommand {
        /// The command as the caller named it.
        command: String,
    },
    /// An entry of [`DescentProfile::env`] was refused: its name is not
    /// `[A-Za-z_][A-Za-z0-9_]*`, it is given twice, or its value contains a
    /// NUL byte. The value is never carried.
    #[error("environment variable `{name}` {reason}")]
    InvalidEnvironment {
        /// The variable's name.
        name: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// [`DescentProfile::cwd`] is not absolute, or contains a NUL byte.
    #[error("working directory `{}` is not an absolute path free of NUL", cwd.display())]
    InvalidWorkingDirectory {
        /// The directory as the caller named it.
        cwd: PathBuf,
    },
    /// An operator's uid or gid is `0` or `u32::MAX`.
    #[error("operator uid {uid} and gid {gid} cannot be descended to: neither may be 0 or {max}", max = u32::MAX)]
    InvalidOperator {
        /// The uid given.
        uid: u32,
        /// The gid given.
        gid: u32,
    },
}

/// What [`InDaemonExecutor::settle_descent`] reads in the standard error a
/// descent has written so far.
#[derive(Debug)]
pub enum DescentSettle {
    /// Undecided: read more, and ask again.
    Pending,
    /// `sudo` descended and the command has been started in the profile's
    /// directory. Standard error from `command_stderr_from` on is the
    /// command's; everything before it is not.
    Started {
        /// The offset just past the start announcement.
        command_stderr_from: usize,
    },
    /// `sudo` descended, but the target identity could not enter the
    /// profile's working directory, so the command was never started.
    NoWorkingDirectory {
        /// What the shell wrote on failing to enter it, trimmed.
        reason: String,
    },
    /// `sudo` refused before the command could start — or wrote more than
    /// 64 KiB before announcing a start, which is treated the same way — with
    /// the error [`Executor::run`] reports for that refusal. The caller kills
    /// the child.
    Refused(ExecutorError),
}

/// Refuses a descent [`InDaemonExecutor::descent_command`] cannot build as
/// asked.
fn check_descent(command: &str, profile: &DescentProfile<'_>) -> Result<(), DescentError> {
    if !is_absolute_and_plain(command) {
        return Err(DescentError::InvalidCommand {
            command: command.to_string(),
        });
    }
    let mut seen = std::collections::HashSet::new();
    for &(name, value) in profile.env {
        let refuse = |reason| DescentError::InvalidEnvironment {
            name: name.to_string(),
            reason,
        };
        if !is_env_name(name) {
            return Err(refuse("is not a name of the form [A-Za-z_][A-Za-z0-9_]*"));
        }
        if !seen.insert(name) {
            return Err(refuse("is given more than once"));
        }
        if value.contains('\0') {
            return Err(refuse("has a value containing a NUL byte"));
        }
    }
    let cwd = profile.cwd;
    if !cwd.is_absolute() || cwd.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(DescentError::InvalidWorkingDirectory {
            cwd: cwd.to_path_buf(),
        });
    }
    Ok(())
}

/// Reports whether `name` matches `[A-Za-z_][A-Za-z0-9_]*`, the portable form
/// of an environment variable name.
fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl InDaemonExecutor {
    /// Builds, without spawning, the command that descends from this root
    /// process to `who` and runs `command` with `args` under `profile`.
    ///
    /// The command is
    /// `sudo <selection> /bin/sh -c <script> <arg0> <cwd> <K=V>… <command> <args…>`,
    /// where `<selection>` is `-u <account>` for [`Descent::Service`] — the
    /// same words [`Executor::run`] descends with for that account — and
    /// `-u #<uid> -g #<gid>` for [`Descent::Operator`]. There is no `-n`, no
    /// `-S` and no password line: descent from root never prompts. `sudo`
    /// sets the target's uid, primary gid and group-database groups, as a
    /// login would. The fixed script, run as the target identity, enters
    /// `profile.cwd`, announces the start on standard error, and `exec`s
    /// `env -i` with the `K=V` words and the command. So the command sees
    /// exactly `profile.env`, runs in `profile.cwd`, and receives every
    /// argument as one word; no value is ever spliced into the script.
    ///
    /// The returned [`Command`] has its program, its arguments and the working
    /// directory `/` set — so `sudo` never depends on the caller's — and
    /// nothing else: no stdio, process group, session, uid, gid, `pre_exec`
    /// or environment change. The caller sets stdio and its process group,
    /// spawns it, and reads its standard error through
    /// [`InDaemonExecutor::settle_descent`] until that settles.
    ///
    /// **What the command gets besides the profile.** Umask and resource
    /// limits are not set here: they are what the caller passes on and what
    /// `sudo` and its PAM session leave (a sudoers `umask` is unioned with the
    /// caller's). `sudo` closes descriptors above 2, so only stdio reaches the
    /// command. With no controlling terminal, as in a systemd service, `sudo`
    /// allocates no pty and runs the command without a new session; that is
    /// the condition under which `sudo` and the command stay in the process
    /// group the caller spawned it into. Under a terminal, `sudo` may move the
    /// command into a session of its own.
    ///
    /// **No secret belongs in `profile.env`.** The `K=V` words are visible in
    /// the process table, as arguments of `sudo` and of the shell, until the
    /// script `exec`s the command.
    ///
    /// A host whose sudoers does not let root run as the account, or as the
    /// operator's uid and gid, refuses; that settles as
    /// [`DescentSettle::Refused`], and nothing falls back.
    ///
    /// # Errors
    ///
    /// Refuses before anything is built with
    /// [`DescentError::InvalidCommand`] when `command` is not an absolute path
    /// free of `=`, [`DescentError::InvalidEnvironment`] for a profile entry
    /// whose name is malformed or repeated or whose value holds a NUL byte, and
    /// [`DescentError::InvalidWorkingDirectory`] when `profile.cwd` is relative
    /// or holds a NUL byte.
    pub fn descent_command(
        &self,
        who: Descent,
        command: &str,
        args: &[&str],
        profile: &DescentProfile<'_>,
    ) -> Result<Command, DescentError> {
        check_descent(command, profile)?;
        let mut cmd = self.sudo_descent(who);
        cmd.arg(bounded::SUPERVISOR_SHELL)
            .arg("-c")
            .arg(descent_script())
            .arg(DESCENT_ARG0)
            .arg(profile.cwd)
            .args(
                profile
                    .env
                    .iter()
                    .map(|(name, value)| format!("{name}={value}")),
            )
            .arg(command)
            .args(args)
            .current_dir("/");
        Ok(cmd)
    }

    /// Classifies what a child spawned from
    /// [`InDaemonExecutor::descent_command`] has written on standard error so
    /// far. `ended` is whether that stream reached end of file, or the child
    /// exited.
    ///
    /// - The start announced within the first 64 KiB is
    ///   [`DescentSettle::Started`]; the bytes after it are the command's.
    /// - The working directory the target could not enter is
    ///   [`DescentSettle::NoWorkingDirectory`].
    /// - A stream that ended with neither is [`DescentSettle::Refused`],
    ///   carrying the [`ExecutorError::SudoRefused`] that [`Executor::run`]
    ///   reports for the same standard error.
    /// - More than 64 KiB ahead of any announcement — not counting a trailing
    ///   fragment that may still grow into one — is
    ///   [`DescentSettle::Refused`] too, ended or not, with the first 64 KiB
    ///   as its reason; the caller then kills the child. An announcement that
    ///   arrives only past the limit does not excuse what precedes it.
    /// - Anything else is [`DescentSettle::Pending`]. A fragment of the
    ///   announcement is never taken for it.
    ///
    /// The announcement and the limit are judged exactly as
    /// [`Executor::open_channel`] judges a channel's start.
    #[must_use]
    pub fn settle_descent(&self, stderr: &[u8], ended: bool) -> DescentSettle {
        let limit = bounded::TRANSPORT_STDERR_LIMIT;
        let capped = |end: usize| stderr.get(..end.min(limit)).unwrap_or_default();
        match channel::announcement(stderr) {
            channel::Announcement::Started(from) => DescentSettle::Started {
                command_stderr_from: from,
            },
            channel::Announcement::Overran(transport) => {
                DescentSettle::Refused(elevation_refusal(capped(transport), None, &self.host))
            }
            channel::Announcement::Undecided => {
                let marker = NO_WORKING_DIRECTORY_MARKER.as_bytes();
                if let Some(at) = bounded::find(stderr, marker) {
                    DescentSettle::NoWorkingDirectory {
                        reason: String::from_utf8_lossy(capped(at)).trim().to_string(),
                    }
                } else if ended {
                    DescentSettle::Refused(elevation_refusal(stderr, None, &self.host))
                } else {
                    DescentSettle::Pending
                }
            }
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

    fn run_with_input(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        check_bounded_command(command)?;
        self.run_bounded(identity, command, args, input, limits)
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

    fn hard_link_over(&self, source: &Path, dest: &Path) -> Result<(), ExecutorError> {
        // As with the write, the daemon already is root: the link, the rename
        // and the flush are direct syscalls, with no shell to re-parse a path
        // and no `sudo` to acquire what this process already holds.
        #[cfg(unix)]
        {
            hard_link_over_natively(source, dest)
        }
        #[cfg(not(unix))]
        {
            hard_link_over_through_shell(self, source, dest)
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
            use std::os::unix::fs::MetadataExt;

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

            // The link-based backup lands the same way on every transport: a
            // second name for the artifact's inode, published by a rename so
            // the backup is never absent, and refused outright for a source
            // that is not a regular file. Elevated like the write, since the
            // paths it acts on are root-owned.
            let previous = path.with_extension("previous");
            exec.hard_link_over(&path, &previous)
                .expect("elevated hard_link_over");
            assert_eq!(
                std::fs::symlink_metadata(&previous).expect("stat").ino(),
                std::fs::symlink_metadata(&path).expect("stat").ino(),
                "the backup must share the artifact's inode rather than copy its bytes"
            );
            assert_eq!(
                mode_of(&previous),
                0o640,
                "and its mode, which the shared inode carries rather than preserves"
            );

            let symlink = path.with_extension("link");
            std::os::unix::fs::symlink(&path, &symlink).expect("plant a symlink");
            let error = exec
                .hard_link_over(&symlink, &symlink.with_extension("previous"))
                .expect_err("a symlink is refused, not followed");
            assert!(
                matches!(&error, ExecutorError::Transfer { reason, .. }
                    if reason.contains("is a symbolic link")),
                "got: {error:?}"
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

        /// The link-based backup: the sequence
        /// `apply::backup_previous_artifact` preserves an artifact with, and
        /// the two fault models it answers.
        ///
        /// Nothing here needs root either. `link`, `rename` and `fsync` are
        /// ordinary calls in a directory the test process owns, so the native
        /// transport runs the production sequence for real, and the script the
        /// shell transports elevate is run as the same text minus the `sudo` a
        /// non-root CI cannot use.
        ///
        /// **Interruption is injected, never waited for.** The native side
        /// composes the sequence's own steps and stops after one, which is
        /// exactly what a process killed between two of them leaves behind; the
        /// shell side has a stub kill the script from inside the step, which is
        /// the real thing rather than a model of it. What is asserted is the
        /// backup, because that is what a later revert reads.
        mod linking {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            use std::path::{Path, PathBuf};

            use super::super::super::{
                CommandOutput, Executor, ExecutorError, FileMeta, Identity, InDaemonExecutor,
                LINK_ASIDE_SCRIPT, LINK_TEMP_ATTEMPTS, link_aside, publish_link,
            };
            use super::{dest_under, write_script};

            /// The artifact that was running, and the one replacing it — chosen
            /// to differ in length, so a truncated backup could not pass for
            /// either.
            const RUNNING: &[u8] = b"the-generation-that-was-running";
            const INCOMING: &[u8] = b"incoming";
            /// The mode a native binary is installed with.
            const BINARY_MODE: u32 = 0o755;
            /// Builds the temporary name both transports draw for `attempt`
            /// beside a destination in `dir`, under `pid`. The tests that stage
            /// a stale candidate need the production spelling exactly: a name
            /// of their own invention would collide with nothing.
            fn candidate(dir: &Path, pid: u32, attempt: u32) -> PathBuf {
                dir.join(format!(".bootler.link.{pid}.{attempt}"))
            }

            /// Seeds a regular file two levels below `root` at a binary's mode.
            fn seed(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
                let path = dest_under(root, name);
                std::fs::write(&path, bytes).expect("seed");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(BINARY_MODE))
                    .expect("mode");
                path
            }

            /// Returns `path`'s inode without following a symlink at it.
            fn inode(path: &Path) -> u64 {
                std::fs::symlink_metadata(path).expect("stat").ino()
            }

            /// Returns the temporary names left in `dir`.
            fn strays(dir: &Path) -> Vec<PathBuf> {
                std::fs::read_dir(dir)
                    .expect("read the directory")
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with(".bootler."))
                    })
                    .collect()
            }

            /// Resolves `name` against this process's `PATH` the way a shell
            /// does, so a stub directory can be populated with the host's own
            /// utilities.
            fn on_path(name: &str) -> PathBuf {
                std::env::var_os("PATH")
                    .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|dir| dir.join(name))
                    .find(|candidate| {
                        std::fs::metadata(candidate).is_ok_and(|meta| {
                            meta.is_file() && meta.permissions().mode() & 0o111 != 0
                        })
                    })
                    .unwrap_or_else(|| panic!("{name} is on the PATH of any host running these"))
            }

            /// Builds a directory that resolves every utility
            /// [`LINK_ASIDE_SCRIPT`] reaches for *except* `link`, to be used as
            /// the script's whole `PATH`.
            ///
            /// `link` is not POSIX, so a host could carry none, and the script
            /// refuses the backup there rather than reaching for `ln`. That
            /// host cannot be staged by prepending a stub — `command -v` would
            /// find the stub, and a stub that exits non-zero is a `link` that
            /// failed rather than one that is absent — so it is staged by
            /// handing the script a `PATH` on which no `link` exists at all,
            /// which is what such a host is. `ln` is deliberately not on it
            /// either: the script must not be able to reach one.
            fn path_without_link(root: &Path) -> PathBuf {
                const NEEDED: [&str; 8] =
                    ["sh", "dirname", "ls", "awk", "find", "mv", "rm", "sync"];
                let farm = root.join("no-link");
                std::fs::create_dir_all(&farm).expect("the stand-in PATH");
                for name in NEEDED {
                    std::os::unix::fs::symlink(on_path(name), farm.join(name))
                        .expect("the host's own utility");
                }
                assert!(
                    !farm.join("link").exists(),
                    "the point of this PATH is that `link` is not on it"
                );
                farm
            }

            /// Runs [`LINK_ASIDE_SCRIPT`] the way the shell transports do, minus
            /// the `sudo` a non-root CI cannot use: the same constant text and
            /// the same positional arguments.
            ///
            /// `stubs`, when given, is prepended to the script's `PATH` — never
            /// replacing it, since the script reaches for a dozen other
            /// utilities that must keep resolving to the host's. Only the
            /// child's environment is set; this process's is never touched.
            fn run_link_script(
                source: &Path,
                dest: &Path,
                stubs: Option<&Path>,
            ) -> std::process::Output {
                let mut command = std::process::Command::new("sh");
                command.args([
                    "-c".to_string(),
                    LINK_ASIDE_SCRIPT.to_string(),
                    "_".to_string(),
                    source.to_string_lossy().into_owned(),
                    dest.to_string_lossy().into_owned(),
                ]);
                if let Some(stubs) = stubs {
                    let mut path = std::ffi::OsString::from(stubs);
                    path.push(":");
                    path.push(std::env::var_os("PATH").unwrap_or_default());
                    command.env("PATH", path);
                }
                command.output().expect("sh should be runnable")
            }

            /// What one staged candidate is occupied by. The walk draws them in
            /// order, so a plan is read as the sequence of entries a resumed
            /// attempt meets before it reaches a free name.
            #[derive(Clone, Copy)]
            enum Stale {
                /// A completed link, which is what an attempt interrupted
                /// between the link and the publish strands.
                Link,
                /// A symlink to the operator's own file.
                SymlinkToFile,
                /// A directory.
                Directory,
                /// A symlink to the operator's own directory.
                SymlinkToDirectory,
            }

            impl Stale {
                /// The word the wrapper's `case` plants this kind from.
                fn word(self) -> &'static str {
                    match self {
                        Self::Link => "link",
                        Self::SymlinkToFile => "symlink",
                        Self::Directory => "dir",
                        Self::SymlinkToDirectory => "dirlink",
                    }
                }
            }

            /// Runs [`LINK_ASIDE_SCRIPT`] with `plan`'s entries already
            /// occupying the very candidate names it is about to draw, pointing
            /// the symlinked kinds at `victim` and `victim_dir`. Returns the pid
            /// those names carry alongside the script's output.
            ///
            /// The leftovers an interrupted attempt strands are named from the
            /// shell's own pid, which nothing outside the shell can predict —
            /// so they are planted from *inside* a wrapper that uses its `$$`
            /// and then `exec`s the script. `exec` replaces the process image
            /// without forking, so the script runs under that same pid: exactly
            /// what a resumed apply meets when the kernel hands its shell a
            /// reused one. The pid is printed before the exec, and the script
            /// itself writes nothing to stdout.
            fn run_link_script_over_stale_candidates(
                source: &Path,
                dest: &Path,
                plan: &[Stale],
                victim: Option<&Path>,
                victim_dir: Option<&Path>,
            ) -> (u32, std::process::Output) {
                run_link_script_over_stale_candidates_on_path(
                    source, dest, plan, victim, victim_dir, None,
                )
            }

            /// [`run_link_script_over_stale_candidates`], with `path` replacing
            /// the script's `PATH` outright where it is given.
            ///
            /// The replacement happens inside the wrapper, after the leftovers
            /// are planted and immediately before the `exec`, so only the
            /// script under test runs under it; the staging keeps the host's
            /// own. Nothing here touches this process's environment.
            fn run_link_script_over_stale_candidates_on_path(
                source: &Path,
                dest: &Path,
                plan: &[Stale],
                victim: Option<&Path>,
                victim_dir: Option<&Path>,
                path: Option<&Path>,
            ) -> (u32, std::process::Output) {
                const WRAPPER: &str = r#"set -e
source=$1; dest=$2; plan=$3; victim=$4; victimdir=$5; path=$6; script=$7
dir=$(dirname "$dest")
echo "$$"
n=0
for kind in $plan; do
  tmp=$dir/.bootler.link.$$.$n
  case $kind in
    link) ln "$source" "$tmp" ;;
    symlink) ln -s "$victim" "$tmp" ;;
    dir) mkdir "$tmp" ;;
    dirlink) ln -s "$victimdir" "$tmp" ;;
  esac
  n=$((n + 1))
done
if [ -n "$path" ]; then PATH=$path; export PATH; fi
exec sh -c "$script" _ "$source" "$dest""#;
                // The wrapper spells the candidate name a second time, and a
                // staged collision the script does not actually meet would let
                // every assertion downstream pass without recovery ever having
                // happened. So the script's own line is what the wrapper is
                // held to.
                assert!(
                    LINK_ASIDE_SCRIPT.contains("tmp=$dir/.bootler.link.$$.$attempt"),
                    "the wrapper plants at the name the script draws, or this stages a \
                     collision with nothing"
                );
                let output = std::process::Command::new("sh")
                    .args([
                        "-c".to_string(),
                        WRAPPER.to_string(),
                        "_".to_string(),
                        source.to_string_lossy().into_owned(),
                        dest.to_string_lossy().into_owned(),
                        plan.iter()
                            .map(|kind| kind.word())
                            .collect::<Vec<_>>()
                            .join(" "),
                        victim
                            .map(|entry| entry.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        victim_dir
                            .map(|entry| entry.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        path.map(|entry| entry.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        LINK_ASIDE_SCRIPT.to_string(),
                    ])
                    .output()
                    .expect("sh should be runnable");
                let pid = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .expect("the wrapper prints its pid before the exec")
                    .trim()
                    .parse()
                    .expect("the pid is a number");
                (pid, output)
            }

            /// An [`Executor`] that reaches [`LINK_ASIDE_SCRIPT`] the way the
            /// shell transports do — through the default
            /// [`Executor::hard_link_over`] body — with `stubs` prepended to
            /// the child's `PATH`.
            ///
            /// [`run_link_script`] asserts on the script's exit status; this
            /// asserts on what a caller actually acts on, which is the
            /// [`ExecutorError`] the transport turns that status into. `run`
            /// spawns directly, minus the `sudo` a non-root CI cannot use, and
            /// sets only the child's environment; this process's is never
            /// touched.
            struct StubbedPath {
                stubs: PathBuf,
            }

            impl StubbedPath {
                fn new(stubs: &Path) -> Self {
                    Self {
                        stubs: stubs.to_path_buf(),
                    }
                }
            }

            impl Executor for StubbedPath {
                fn run(
                    &self,
                    _identity: Identity,
                    command: &str,
                    args: &[&str],
                ) -> Result<CommandOutput, ExecutorError> {
                    let mut path = std::ffi::OsString::from(&self.stubs);
                    path.push(":");
                    path.push(std::env::var_os("PATH").unwrap_or_default());
                    let output = std::process::Command::new(command)
                        .args(args)
                        .env("PATH", path)
                        .output()
                        .expect("the command should be runnable");
                    Ok(CommandOutput {
                        code: output.status.code(),
                        stdout: output.stdout,
                        stderr: output.stderr,
                    })
                }

                fn put_file(
                    &self,
                    _dest: &Path,
                    _contents: &[u8],
                    _meta: FileMeta,
                ) -> Result<(), ExecutorError> {
                    unimplemented!("only the link sequence is driven through this executor")
                }
            }

            /// Writes a stub for `name` that kills the shell running the script
            /// the instant that step is reached, and returns the directory to
            /// put on `PATH`.
            ///
            /// `SIGKILL` rather than a non-zero exit, and rather than the
            /// script's own error paths: an interrupted apply does not get to
            /// run its `EXIT` trap, so what the filesystem holds afterwards is
            /// whatever the last completed call left — which is the fault model
            /// under test.
            fn kill_at(root: &Path, name: &str) -> PathBuf {
                let stubs = root.join("stubs");
                std::fs::create_dir_all(&stubs).expect("stub directory");
                write_script(&stubs, name, "#!/bin/sh\nkill -KILL $PPID\n");
                stubs
            }

            #[test]
            fn the_backup_is_a_second_name_for_the_artifacts_inode() {
                // The property the whole change rests on: no bytes are copied,
                // so there is no partial copy to be interrupted, and the mode
                // and timestamps are the artifact's own rather than preserved
                // alongside it.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");

                InDaemonExecutor::new("seat")
                    .hard_link_over(&artifact, &previous)
                    .expect("link the artifact aside");

                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), RUNNING);
                assert_eq!(
                    std::fs::metadata(&previous)
                        .expect("stat")
                        .permissions()
                        .mode()
                        & 0o777,
                    BINARY_MODE
                );
                assert!(strays(artifact.parent().expect("dir")).is_empty());
            }

            #[test]
            fn a_symlink_at_the_destination_is_replaced_rather_than_written_through() {
                // The publish is a rename, which replaces whatever entry sits
                // at the destination without resolving it. A copy would have
                // opened a symlink planted there and written *through* it,
                // landing the artifact's bytes on whatever the operator
                // pointed it at and still leaving no backup for a revert to
                // read. The source guard cannot cover this: the symlink is at
                // the destination, which is the crate's own name and not a
                // path the caller was asked about.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let elsewhere = seed(root.path(), "the-operators-own-file", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::os::unix::fs::symlink(&elsewhere, &previous).expect("plant the symlink");
                let pointed_at = inode(&elsewhere);

                InDaemonExecutor::new("seat")
                    .hard_link_over(&artifact, &previous)
                    .expect("link the artifact aside");

                assert_eq!(
                    inode(&previous),
                    inode(&artifact),
                    "the destination is the artifact itself now, not a pointer to something else"
                );
                assert_eq!(inode(&elsewhere), pointed_at);
                assert_eq!(
                    std::fs::read(&elsewhere).expect("read"),
                    INCOMING,
                    "and what the symlink pointed at is untouched"
                );
                assert!(strays(artifact.parent().expect("dir")).is_empty());
            }

            #[test]
            fn an_interruption_between_the_link_and_the_rename_leaves_the_old_backup() {
                // Replacing an existing backup is a process-interruption
                // guarantee: the old entry is never unlinked, so a fault here
                // leaves the old backup whole rather than a partial or absent
                // one. Stopping after the first step *is* that fault.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::write(&previous, RUNNING).expect("seed the existing backup");
                let old = inode(&previous);
                let dir = previous.parent().expect("dir").to_path_buf();

                let temp = link_aside(&artifact, &dir, &previous).expect("step one links aside");

                assert_eq!(inode(&previous), old, "the old backup is still the old one");
                assert_eq!(
                    std::fs::read(&previous).expect("read"),
                    RUNNING,
                    "and it is whole: nothing was written through it"
                );
                assert_eq!(
                    inode(&temp),
                    inode(&artifact),
                    "the temporary is the link that was not published"
                );
            }

            #[test]
            fn an_interruption_between_the_rename_and_the_flush_leaves_the_new_backup() {
                // The other half of the same guarantee, and the reason the
                // publish is a rename: at no point is the backup absent, so the
                // second fault point holds the new backup rather than nothing.
                // Durability is not claimed here — that is what the flush is
                // for, and it has deliberately not run.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::write(&previous, RUNNING).expect("seed the existing backup");
                let dir = previous.parent().expect("dir").to_path_buf();

                let temp = link_aside(&artifact, &dir, &previous).expect("step one");
                publish_link(&temp, &previous).expect("step two renames over the old backup");

                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), INCOMING);
                assert!(
                    strays(previous.parent().expect("dir")).is_empty(),
                    "the rename consumed the temporary rather than leaving it beside the backup"
                );
            }

            #[test]
            fn an_interruption_before_a_first_backup_lands_leaves_none_and_the_artifact_live() {
                // Creating the first backup has nothing to preserve, so absence
                // is the correct intermediate state and the criterion is
                // recovery instead: the caller's journal records no
                // backup-taken, and the resumed apply re-takes it. That is only
                // sound because this runs before the swap, so what a retry
                // links is still the live artifact — which is what is asserted
                // here, since the journal is the caller's.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();

                let temp = link_aside(&artifact, &dir, &previous).expect("step one");

                assert!(
                    !previous.exists(),
                    "an unpublished link is not a backup, and must not look like one"
                );
                assert_eq!(std::fs::read(&artifact).expect("read"), RUNNING);
                assert_eq!(
                    std::fs::metadata(&artifact)
                        .expect("stat")
                        .permissions()
                        .mode()
                        & 0o777,
                    BINARY_MODE,
                    "the artifact a retry will link is untouched"
                );

                // The retry itself, with the temporary of the interrupted
                // attempt still lying there. It is the *first* candidate a
                // retry draws — same pid, same attempt number — so the retry
                // steps over it onto the next one rather than being blocked by
                // it, and leaves it exactly where the interruption did.
                let left = inode(&temp);
                InDaemonExecutor::new("seat")
                    .hard_link_over(&artifact, &previous)
                    .expect("the resumed apply re-takes the backup");
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(
                    inode(&temp),
                    left,
                    "the leftover is stepped over, never consumed by the retry"
                );
            }

            #[test]
            fn a_stale_native_candidate_is_stepped_over_rather_than_reused() {
                // The recovery the criterion names, staged rather than waited
                // for: an interrupted attempt's completed link sits at the
                // first candidate a retry draws, and a pid reused by the
                // resuming process is what makes the two names identical. The
                // retry must publish the backup anyway, out of a sibling none
                // of the leftovers occupies — and must not clear, adopt or
                // resolve through any of them on the way, which is why one of
                // them is a symlink to a file that would show the write, and
                // two more are the entries `ln` links *into* rather than
                // refuses. `link(2)` refuses all four alike, and this is what
                // holds it to that.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let victim = seed(root.path(), "the-operators-own-file", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();
                let victim_dir = dir.join("the-operators-own-directory");
                std::fs::create_dir(&victim_dir).expect("the operator's directory");
                let pid = std::process::id();
                // The leftovers are made by step one itself, twice, which is
                // exactly what two attempts interrupted between the link and
                // the publish leave — and their names are then pinned against
                // the spelling the staging below shares. A leftover planted at
                // a name of the test's own invention would collide with
                // nothing, and every assertion here would still pass.
                let stranded: Vec<PathBuf> = (0..2)
                    .map(|_| {
                        link_aside(&artifact, &dir, &previous).expect("strand a completed link")
                    })
                    .collect();
                assert_eq!(
                    stranded,
                    vec![candidate(&dir, pid, 0), candidate(&dir, pid, 1)],
                    "the walk starts at the first candidate and steps one at a time"
                );
                let planted = candidate(&dir, pid, 2);
                std::os::unix::fs::symlink(&victim, &planted).expect("plant a symlink");
                let planted_dir = candidate(&dir, pid, 3);
                std::fs::create_dir(&planted_dir).expect("plant a directory");
                let planted_dir_link = candidate(&dir, pid, 4);
                std::os::unix::fs::symlink(&victim_dir, &planted_dir_link)
                    .expect("plant a symlink to a directory");

                InDaemonExecutor::new("seat")
                    .hard_link_over(&artifact, &previous)
                    .expect("the resumed apply re-takes the backup");

                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), RUNNING);
                for path in &stranded {
                    assert_eq!(
                        inode(path),
                        inode(&artifact),
                        "a leftover is left standing, not unlinked or renamed away: {path:?}"
                    );
                }
                assert!(
                    std::fs::symlink_metadata(&planted)
                        .expect("stat")
                        .file_type()
                        .is_symlink(),
                    "the planted entry is still the symlink it was"
                );
                assert_eq!(
                    std::fs::read(&victim).expect("read"),
                    INCOMING,
                    "and nothing was resolved through it"
                );
                assert!(
                    planted_dir.is_dir(),
                    "the planted directory is still there: {planted_dir:?}"
                );
                assert_eq!(
                    std::fs::read_dir(&planted_dir).expect("read").count(),
                    0,
                    "and nothing was linked into it"
                );
                assert!(
                    std::fs::symlink_metadata(&planted_dir_link)
                        .expect("stat")
                        .file_type()
                        .is_symlink(),
                    "the symlink to it is still the symlink it was"
                );
                assert_eq!(
                    std::fs::read_dir(&victim_dir).expect("read").count(),
                    0,
                    "and nothing was linked through it into the operator's directory"
                );
                assert!(
                    !candidate(&dir, pid, 5).exists(),
                    "the first free candidate is the one the publish renamed away, so the \
                     retry leaves no temporary of its own behind"
                );
                assert_eq!(
                    strays(&dir).len(),
                    stranded.len() + 3,
                    "what is beside the backup is what was already there: {:?}",
                    strays(&dir)
                );
            }

            #[test]
            fn a_directory_with_no_free_candidate_fails_rather_than_walking_forever() {
                // The walk is bounded, and the bound is reported rather than
                // spun on. What reaches the caller is the same
                // `ExecutorError::Transfer` naming the destination that every
                // other on-host failure of the sequence reports, so
                // `backup_previous_artifact` folds it into its
                // subject-labelled `CoreError::Command` unchanged.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();
                let pid = std::process::id();
                let taken = usize::try_from(LINK_TEMP_ATTEMPTS).expect("the bound fits a usize");
                for n in 0..LINK_TEMP_ATTEMPTS {
                    std::fs::hard_link(&artifact, candidate(&dir, pid, n)).expect("occupy");
                }

                let error = InDaemonExecutor::new("seat")
                    .hard_link_over(&artifact, &previous)
                    .expect_err("a backup that could not be linked must not be reported taken");

                assert!(
                    matches!(&error, ExecutorError::Transfer { path, reason }
                        if path == &previous && reason.contains("no free temporary name")),
                    "got: {error:?}"
                );
                assert!(
                    !previous.exists(),
                    "and no backup was published from a name it could not take"
                );
                assert_eq!(
                    strays(&dir).len(),
                    taken,
                    "nor was any of the occupied candidates cleared away"
                );
            }

            #[test]
            fn the_shell_sequence_killed_before_the_rename_leaves_the_old_backup() {
                // The same fault model on the transports that run the sequence
                // as a script, injected where it really happens: the process is
                // killed inside the step, so not even the `EXIT` trap runs.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::write(&previous, RUNNING).expect("seed the existing backup");
                let old = inode(&previous);
                let stubs = kill_at(root.path(), "mv");

                let output = run_link_script(&artifact, &previous, Some(stubs.as_path()));

                assert!(
                    !output.status.success(),
                    "a killed script cannot report a backup it did not take"
                );
                assert_eq!(inode(&previous), old);
                assert_eq!(std::fs::read(&previous).expect("read"), RUNNING);
            }

            #[test]
            fn the_shell_sequence_killed_before_the_flush_leaves_the_new_backup() {
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::write(&previous, RUNNING).expect("seed the existing backup");
                let stubs = kill_at(root.path(), "sync");

                let output = run_link_script(&artifact, &previous, Some(stubs.as_path()));

                assert!(!output.status.success(), "the flush never completed");
                assert_eq!(
                    inode(&previous),
                    inode(&artifact),
                    "the rename had already published the new backup"
                );
                assert_eq!(std::fs::read(&previous).expect("read"), INCOMING);
            }

            #[test]
            fn the_shell_sequence_killed_before_a_first_backup_lands_leaves_none() {
                // The other half of the fault model on the transports that run
                // the sequence as a script: with no backup to preserve, absence
                // is the correct intermediate state, so the criterion is
                // recovery rather than the file. The caller's journal records no
                // backup-taken and the resumed apply re-takes it, which is sound
                // only because this runs before the swap — so what is asserted
                // here is that the artifact a retry will link is still the live
                // one, and that the retry then lands.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let stubs = kill_at(root.path(), "mv");

                let output = run_link_script(&artifact, &previous, Some(stubs.as_path()));

                assert!(!output.status.success(), "the rename never ran");
                assert!(
                    !previous.exists(),
                    "an unpublished link is not a backup, and must not look like one"
                );
                assert_eq!(std::fs::read(&artifact).expect("read"), RUNNING);
                assert_eq!(
                    std::fs::metadata(&artifact)
                        .expect("stat")
                        .permissions()
                        .mode()
                        & 0o777,
                    BINARY_MODE,
                    "the artifact a retry will link is untouched"
                );
                // A kill runs no `EXIT` trap, so the temporary link survives.
                // It is a whole second name for the artifact's inode and never
                // a partial file — the point of linking rather than copying.
                // What it is *named* is the shell's pid, which this test cannot
                // predict and a retry cannot be relied on to avoid; the retry
                // here runs under a fresh shell and merely happens not to
                // collide, and the test below is the one that stages the
                // collision on purpose.
                let left = strays(artifact.parent().expect("dir"));
                assert_eq!(left.len(), 1, "one temporary, unremoved: {left:?}");
                assert_eq!(
                    inode(left.first().expect("the temporary")),
                    inode(&artifact),
                    "even the leftover is a link, not truncated bytes"
                );

                let retry = run_link_script(&artifact, &previous, None);

                assert!(
                    retry.status.success(),
                    "the resumed apply re-takes the backup: {}",
                    String::from_utf8_lossy(&retry.stderr)
                );
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), RUNNING);
            }

            #[test]
            fn a_stale_shell_candidate_is_stepped_over_rather_than_reused() {
                // The native recovery test's counterpart, with the collision
                // staged rather than hoped for: the leftovers are planted under
                // the pid the script itself runs as, which is what a resumed
                // apply meets when the kernel reuses one. The retry must
                // publish the backup out of a candidate none of them occupies,
                // and must not clear, adopt or resolve through any of them —
                // hence the symlink to a file a write would show.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let victim = seed(root.path(), "the-operators-own-file", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();

                let (pid, output) = run_link_script_over_stale_candidates(
                    &artifact,
                    &previous,
                    &[Stale::Link, Stale::Link, Stale::SymlinkToFile],
                    Some(&victim),
                    None,
                );

                assert!(
                    output.status.success(),
                    "the resumed apply re-takes the backup: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), RUNNING);
                for n in 0..2 {
                    let stranded = candidate(&dir, pid, n);
                    assert_eq!(
                        inode(&stranded),
                        inode(&artifact),
                        "a leftover is left standing, not unlinked or renamed away: {stranded:?}"
                    );
                }
                let planted = candidate(&dir, pid, 2);
                assert!(
                    std::fs::symlink_metadata(&planted)
                        .expect("stat")
                        .file_type()
                        .is_symlink(),
                    "the planted entry is still the symlink it was"
                );
                assert_eq!(
                    std::fs::read(&victim).expect("read"),
                    INCOMING,
                    "and nothing was resolved through it"
                );
                assert!(
                    !candidate(&dir, pid, 3).exists(),
                    "the first free candidate is the one the `mv` consumed, so the retry \
                     leaves no temporary of its own behind"
                );
                assert_eq!(
                    strays(&dir).len(),
                    3,
                    "what is beside the backup is what was already there: {:?}",
                    strays(&dir)
                );
            }

            #[test]
            fn a_shell_candidate_that_is_a_directory_is_neither_followed_nor_removed() {
                // The one occupied candidate `ln` does not refuse. Handed a
                // directory, or a symlink to one, it links the source *inside*
                // it and exits 0 — so a walk that left the refusal to `ln`
                // would write through a planted entry, publish nothing from the
                // name it thought it had taken, and, on the symlink, delete the
                // entry on its way out while leaving the stray link it made
                // behind. Both spellings are staged at once, and the two
                // directories are empty precisely so that a link landing in
                // either one shows up as an entry that should not be there.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();
                let victim_dir = dir.join("the-operators-own-directory");
                std::fs::create_dir(&victim_dir).expect("the operator's directory");

                let (pid, output) = run_link_script_over_stale_candidates(
                    &artifact,
                    &previous,
                    &[Stale::Directory, Stale::SymlinkToDirectory],
                    None,
                    Some(&victim_dir),
                );

                assert!(
                    output.status.success(),
                    "the backup is taken out of a free sibling: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), RUNNING);
                let planted = candidate(&dir, pid, 0);
                assert!(
                    planted.is_dir(),
                    "the planted directory is still there: {planted:?}"
                );
                assert_eq!(
                    std::fs::read_dir(&planted).expect("read").count(),
                    0,
                    "and nothing was linked into it"
                );
                let pointer = candidate(&dir, pid, 1);
                assert!(
                    std::fs::symlink_metadata(&pointer)
                        .expect("stat")
                        .file_type()
                        .is_symlink(),
                    "the planted symlink is still the symlink it was"
                );
                assert_eq!(
                    std::fs::read_dir(&victim_dir).expect("read").count(),
                    0,
                    "and nothing was linked through it into the operator's directory"
                );
                assert!(
                    !candidate(&dir, pid, 2).exists(),
                    "the first free candidate is the one the `mv` consumed, so the retry \
                     leaves no temporary of its own behind"
                );
                assert_eq!(
                    strays(&dir).len(),
                    2,
                    "what is beside the backup is what was already there: {:?}",
                    strays(&dir)
                );
            }

            #[test]
            fn a_shell_host_without_link_refuses_the_backup_rather_than_linking_with_ln() {
                // The other end of the same requirement. `link` is not POSIX,
                // so a host may carry none — and the only other way to make a
                // hard link from a shell is `ln`, which cannot be stopped from
                // linking the source *into* a directory sitting at the
                // candidate: no portable option suppresses it, and a test run
                // ahead of it is a window an entry can be created inside. So
                // that host is refused before the walk starts, and this pins
                // the refusal against the same two entries an `ln` would have
                // been diverted into. Handing the script a `PATH` with neither
                // `link` nor `ln` on it is what makes it such a host; every
                // other test here runs on the host's own, where `link` is.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();
                let victim_dir = dir.join("the-operators-own-directory");
                std::fs::create_dir(&victim_dir).expect("the operator's directory");
                let path = path_without_link(root.path());

                let (pid, output) = run_link_script_over_stale_candidates_on_path(
                    &artifact,
                    &previous,
                    &[Stale::Directory, Stale::SymlinkToDirectory],
                    None,
                    Some(&victim_dir),
                    Some(&path),
                );

                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    !output.status.success(),
                    "a host that cannot claim a name without following it must not report a \
                     backup: {stderr}"
                );
                assert!(
                    stderr.contains("no link utility"),
                    "and it must say which utility it could not find, since the failure is \
                     reported to an operator as a transfer failure: {stderr}"
                );
                assert!(
                    !previous.exists(),
                    "no backup was published by a sequence that could not take one"
                );
                let planted = candidate(&dir, pid, 0);
                assert!(
                    planted.is_dir(),
                    "the planted directory is still there: {planted:?}"
                );
                assert_eq!(
                    std::fs::read_dir(&planted).expect("read").count(),
                    0,
                    "and nothing was linked into it"
                );
                let pointer = candidate(&dir, pid, 1);
                assert!(
                    std::fs::symlink_metadata(&pointer)
                        .expect("stat")
                        .file_type()
                        .is_symlink(),
                    "the planted symlink is still the symlink it was"
                );
                assert_eq!(
                    std::fs::read_dir(&victim_dir).expect("read").count(),
                    0,
                    "and nothing was linked through it into the operator's directory"
                );
                assert_eq!(
                    strays(&dir).len(),
                    2,
                    "nor was anything else left beside the artifact: {:?}",
                    strays(&dir)
                );
            }

            #[test]
            fn the_shell_sequence_with_no_free_candidate_fails_rather_than_walking_forever() {
                // The shell half of the bound, held to the same number the
                // native side walks: a script that kept trying would hang the
                // apply instead of failing it, and one that gave up quietly
                // would report a backup it never took.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();
                let taken = usize::try_from(LINK_TEMP_ATTEMPTS).expect("the bound fits a usize");
                assert!(
                    LINK_ASIDE_SCRIPT.contains(&format!("-ge {LINK_TEMP_ATTEMPTS} ]")),
                    "the script walks the number the native side does, or this test stages \
                     the wrong count and stops saying anything about the bound"
                );

                let (_, output) = run_link_script_over_stale_candidates(
                    &artifact,
                    &previous,
                    &vec![Stale::Link; taken],
                    None,
                    None,
                );

                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success(), "a backup was not taken: {stderr}");
                assert!(
                    stderr.contains("no free temporary name"),
                    "unexpected failure: {stderr}"
                );
                assert!(
                    !previous.exists(),
                    "and no backup was published from a name it could not take"
                );
                assert_eq!(
                    strays(&dir).len(),
                    taken,
                    "nor was any of the occupied candidates cleared away"
                );
            }

            #[test]
            fn a_link_failure_that_is_not_occupancy_is_reported_as_itself() {
                // Only an occupied candidate advances the walk. A link that
                // fails for any other reason — a directory that cannot be
                // written, a filesystem boundary — leaves nothing at the
                // candidate, and walking past it would spend the whole bound to
                // report the same failure under "no free temporary name", which
                // names the wrong problem entirely. So the diagnostic the
                // linker gave is what the caller is handed, and it runs once.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let dir = previous.parent().expect("dir").to_path_buf();
                let stubs = root.path().join("stubs");
                std::fs::create_dir_all(&stubs).expect("stub directory");
                let calls = root.path().join("link-calls");
                let body = format!(
                    "#!/bin/sh\necho called >> {}\necho \"a diagnostic only the linker could \
                     give\" >&2\nexit 1\n",
                    calls.display()
                );
                write_script(&stubs, "link", &body);

                let error = StubbedPath::new(&stubs)
                    .hard_link_over(&artifact, &previous)
                    .expect_err("a link that could not be made must not pass for one that was");

                assert!(
                    matches!(&error, ExecutorError::Transfer { path, reason }
                        if path == &previous
                            && reason.contains("a diagnostic only the linker could give")
                            && !reason.contains("no free temporary name")),
                    "the failure carries the linker's own words, not the bound's: {error:?}"
                );
                assert_eq!(
                    std::fs::read_to_string(&calls)
                        .expect("the stub ran")
                        .lines()
                        .count(),
                    1,
                    "and it was reported on the first attempt rather than walked over"
                );
                assert!(
                    !previous.exists(),
                    "no backup was published from a link that never happened"
                );
                assert!(strays(&dir).is_empty(), "and nothing was left beside it");
            }

            #[test]
            fn a_host_with_no_working_sync_fails_the_backup_rather_than_claiming_one() {
                // The flush is a required step, not a best effort, and this is
                // the only way it can fail on the shell transports: a `sync`
                // that fails both with the operand and without it is a host
                // carrying no working one. Reporting `Ok` there would be the
                // whole problem — the caller writes its backup-taken record
                // from this call's success, and a record standing over an entry
                // that was never flushed suppresses the retake the missing
                // entry needs. So it fails, exactly as the native `fsync`
                // failure does, and it is asserted through the executor-facing
                // path rather than off the script's exit status, since what the
                // caller acts on is the `ExecutorError`.
                //
                // This is the flush *failing*, distinct from the flush never
                // running, which the kill-at-`sync` test above covers.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                let stubs = root.path().join("stubs");
                std::fs::create_dir_all(&stubs).expect("stub directory");
                write_script(
                    &stubs,
                    "sync",
                    "#!/bin/sh\necho \"sync: not found\" >&2\nexit 127\n",
                );

                let error = StubbedPath::new(&stubs)
                    .hard_link_over(&artifact, &previous)
                    .expect_err("a flush that cannot run must not pass for one that did");

                assert!(
                    matches!(&error, ExecutorError::Transfer { path, reason }
                        if path == &previous && reason.contains("was not flushed")),
                    "the failure must name the destination and say which flush did not \
                     happen, so `backup_previous_artifact` can fold it into the \
                     subject-labelled `CoreError::Command`: {error:?}"
                );
                // The rename ran before the flush did, so the entry is on the
                // filesystem — it is simply not *claimed*. The retry the caller
                // makes re-links the same artifact, which is still live because
                // the backup runs before the swap.
                assert_eq!(
                    inode(&previous),
                    inode(&artifact),
                    "and what it left behind is a link, never truncated bytes"
                );
                assert!(
                    strays(artifact.parent().expect("dir")).is_empty(),
                    "and the failure still cleans up after itself"
                );
            }

            #[test]
            fn the_shell_sequence_refuses_a_directory_at_the_destination() {
                // `mv` would move the temporary *inside* a directory sitting at
                // the destination and exit `0`, so the backup would be reported
                // taken under a path nobody named. It is refused before the link
                // instead, and nothing is left behind by the refusal.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::create_dir(&previous).expect("plant a directory at the destination");

                let output = run_link_script(&artifact, &previous, None);

                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success(), "a directory must be refused");
                assert!(
                    stderr.contains("is a directory"),
                    "unexpected refusal: {stderr}"
                );
                assert!(
                    std::fs::read_dir(&previous)
                        .expect("read the destination")
                        .next()
                        .is_none(),
                    "the refusal must not leave the link inside the directory"
                );
                assert_eq!(
                    std::fs::metadata(&artifact).expect("stat").nlink(),
                    1,
                    "and must not have linked the artifact at all"
                );
                assert!(strays(artifact.parent().expect("dir")).is_empty());
            }

            #[test]
            fn the_shell_sequence_replaces_a_symlink_at_the_destination() {
                // The same on the transports that run the sequence as a
                // script: `mv` renames over the symlink rather than following
                // it, so the operator's file keeps its own inode and its own
                // bytes, and the confirmation by inode still matches because
                // `find` does not resolve the name it is given either.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let elsewhere = seed(root.path(), "the-operators-own-file", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::os::unix::fs::symlink(&elsewhere, &previous).expect("plant the symlink");
                let pointed_at = inode(&elsewhere);

                let output = run_link_script(&artifact, &previous, None);

                assert!(
                    output.status.success(),
                    "the script should succeed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(inode(&elsewhere), pointed_at);
                assert_eq!(std::fs::read(&elsewhere).expect("read"), INCOMING);
                assert!(strays(artifact.parent().expect("dir")).is_empty());
            }

            #[test]
            fn the_shell_sequence_links_the_artifact_and_replaces_an_older_backup() {
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", INCOMING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::write(&previous, RUNNING).expect("seed the existing backup");

                let output = run_link_script(&artifact, &previous, None);

                assert!(
                    output.status.success(),
                    "the script should succeed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(std::fs::read(&previous).expect("read"), INCOMING);
                assert!(
                    strays(previous.parent().expect("dir")).is_empty(),
                    "a successful link leaves no temporary behind, including where the rename \
                     was skipped"
                );

                // Re-run against the artifact it already names: the rename is
                // skipped, and the temporary must not survive that.
                let again = run_link_script(&artifact, &previous, None);
                assert!(
                    again.status.success(),
                    "re-linking an unchanged artifact is not a failure: {}",
                    String::from_utf8_lossy(&again.stderr)
                );
                assert_eq!(
                    std::fs::metadata(&previous).expect("stat").nlink(),
                    2,
                    "two names for one inode, not three"
                );
                assert!(strays(previous.parent().expect("dir")).is_empty());
            }

            #[test]
            fn re_linking_an_unchanged_artifact_never_reaches_mv() {
                // GNU `mv` refuses two names for one inode with `are the same
                // file` instead of passing POSIX's no-op rename through to
                // `rename(2)`, so the script must not hand it that pair at all.
                // The stub fails however it is called, which is what makes the
                // skip the thing under test: on a host whose own `mv` tolerates
                // the pair, the sequence would otherwise pass here while being
                // broken everywhere the crate ships.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");

                let first = run_link_script(&artifact, &previous, None);
                assert!(
                    first.status.success(),
                    "the first backup should succeed: {}",
                    String::from_utf8_lossy(&first.stderr)
                );

                let stubs = root.path().join("stubs");
                std::fs::create_dir_all(&stubs).expect("stub directory");
                write_script(
                    &stubs,
                    "mv",
                    "#!/bin/sh\necho \"mv: refused: $*\" >&2\nexit 1\n",
                );

                let again = run_link_script(&artifact, &previous, Some(&stubs));

                assert!(
                    again.status.success(),
                    "the rename the artifact already satisfies must not be attempted: {}",
                    String::from_utf8_lossy(&again.stderr)
                );
                assert_eq!(inode(&previous), inode(&artifact));
                assert_eq!(
                    std::fs::metadata(&previous).expect("stat").nlink(),
                    2,
                    "two names for one inode, not three"
                );
                assert!(strays(previous.parent().expect("dir")).is_empty());
            }

            #[test]
            fn the_shell_sequence_refuses_every_source_that_is_not_a_regular_file() {
                let root = tempfile::tempdir().expect("tempdir");
                let target = seed(root.path(), "roxyd", RUNNING);

                let symlink = target.with_file_name("linked");
                std::os::unix::fs::symlink(&target, &symlink).expect("plant the symlink");
                // A symlink is refused for what it is, not for what it resolves
                // to, so one resolving to nothing is refused on the same terms
                // rather than read as an absent source.
                let dangling = target.with_file_name("linked-nowhere");
                std::os::unix::fs::symlink(target.with_file_name("gone"), &dangling)
                    .expect("plant the dangling symlink");
                let directory = target.with_file_name("bundle");
                std::fs::create_dir(&directory).expect("plant the directory");

                for (source, expected) in [
                    (&symlink, "is a symbolic link"),
                    (&dangling, "is a symbolic link"),
                    (&directory, "is not a regular file"),
                ] {
                    let dest = source.with_extension("previous");
                    let output = run_link_script(source, &dest, None);

                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(
                        !output.status.success(),
                        "{source:?} must be refused, not linked"
                    );
                    assert!(stderr.contains(expected), "unexpected refusal: {stderr}");
                    assert!(
                        !dest.exists(),
                        "a refusal writes nothing, of the source or of what it points at"
                    );
                }
                assert_eq!(
                    std::fs::metadata(&target).expect("stat").nlink(),
                    1,
                    "the symlink's target was never linked either"
                );
                assert!(strays(target.parent().expect("dir")).is_empty());
            }

            #[test]
            fn the_link_script_never_leaves_the_destination_absent() {
                // The script's shape is the guarantee on the shell transports,
                // and each of these is a way it could silently regress into the
                // sequence it replaced.
                let script = LINK_ASIDE_SCRIPT;
                assert!(
                    !script.split_whitespace().any(|word| word == "cp"),
                    "a copy is what leaves a truncated backup: {script}"
                );
                assert!(
                    !script.contains("ln -f") && !script.contains("ln -s"),
                    "`ln -f` unlinks the destination before linking, and a symbolic link is not \
                     a backup at all: {script}"
                );
                let link_at = script.find(r#"link "$source" "$tmp""#).expect("the link");
                let rename_at = script.find("mv -f").expect("the rename");
                let flush_at = script
                    .find(r#"flush "$dir""#)
                    .expect("the directory is flushed");
                let symlink_guard = script.find(r#"[ -h "$source" ]"#).expect("symlink guard");
                let regular_guard = script.find(r#"[ ! -f "$source" ]"#).expect("regular guard");
                assert!(
                    symlink_guard < link_at && regular_guard < link_at,
                    "a source that is not a regular file is refused before anything is linked: \
                     {script}"
                );
                assert!(
                    link_at < rename_at && rename_at < flush_at,
                    "link, then rename over the destination, then flush the directory the entry \
                     appeared in — flushing earlier protects nothing: {script}"
                );
                assert!(
                    script[link_at..].contains(r#"[ -h "$tmp" ]"#),
                    "what the link produced is checked again, since POSIX leaves it to `ln` \
                     whether a symlink is followed: {script}"
                );
                assert!(
                    !script.split_whitespace().any(|word| word == "ln"),
                    "the link goes through `link`, which hands `link(2)` the name it was given, \
                     and through nothing else: `ln` links the source *into* a directory sitting \
                     at the name instead of failing on it, and a test run ahead of it only \
                     narrows the window an entry can appear in: {script}"
                );
                let requires_at = script
                    .find("command -v link")
                    .expect("the linker's presence is established");
                assert!(
                    requires_at < link_at
                        && script[requires_at..link_at].contains("no link utility"),
                    "a host carrying no `link` is refused before the walk begins rather than \
                     degraded onto something that follows a planted entry: {script}"
                );
                let trap_at = script
                    .find(r#"trap 'rm -f "$tmp"' EXIT"#)
                    .expect("a failure must leave no temporary behind");
                let temp_guard = script
                    .find(r#"[ -h "$tmp" ] || [ ! -f "$tmp" ]"#)
                    .expect("the temporary's own type is checked");
                assert!(
                    link_at < trap_at && trap_at < temp_guard,
                    "the trap is armed below the walk, where `$tmp` is the entry `link(2)` just \
                     made rather than a refused leftover this script must leave standing — and \
                     above the type guard, whose refusal that same `rm -f` then cleans up: \
                     {script}"
                );
                assert!(
                    script[..flush_at].contains("no working sync")
                        && script[..flush_at].contains("return 1"),
                    "a flush neither `sync` form could perform must fail the script rather than \
                     warn and let the backup stand, since the caller writes its backup-taken \
                     record from this script's success: {script}"
                );
                // `-inum` appears twice: the skip that keeps `mv` from being
                // handed two names for one inode comes before the rename, and
                // the confirmation of what landed comes after it.
                let skip_at = script.find("-inum").expect("the no-op skip");
                let confirm_at = script.rfind("-inum").expect("an identity check");
                assert!(
                    skip_at < rename_at,
                    "a rename handed two names for one inode is skipped rather than run, since \
                     `mv` refuses it instead of passing POSIX's no-op through: {script}"
                );
                assert!(
                    confirm_at > rename_at,
                    "the destination must be confirmed to be the file just linked, after the \
                     rename: {script}"
                );
            }

            #[test]
            fn the_native_sequence_reports_every_on_host_failure_as_a_transfer() {
                // One error shape across the transports, because the caller
                // folds it into one subject-labelled failure and cannot be
                // asked which mechanism ran.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let daemon = InDaemonExecutor::new("seat");

                let absent = root.path().join("nowhere").join("roxyd.previous");
                let error = daemon
                    .hard_link_over(&artifact, &absent)
                    .expect_err("a destination directory that is not there fails");
                match error {
                    ExecutorError::Transfer { path, .. } => assert_eq!(path, absent),
                    other => panic!("expected Transfer naming the destination, got {other:?}"),
                }

                let directory = artifact.with_file_name("bundle");
                std::fs::create_dir(&directory).expect("plant the directory");
                let error = daemon
                    .hard_link_over(&directory, &directory.with_extension("previous"))
                    .expect_err("a directory is refused");
                match error {
                    ExecutorError::Transfer { reason, .. } => assert!(
                        reason.contains("is not a regular file"),
                        "unexpected reason: {reason}"
                    ),
                    other => panic!("expected Transfer, got {other:?}"),
                }
                assert!(strays(artifact.parent().expect("dir")).is_empty());
            }

            #[test]
            fn the_native_sequence_refuses_a_directory_at_the_destination() {
                // The shell transports guard this before the link because `mv`
                // would move the temporary *inside* the directory and exit `0`.
                // The native sequence needs no guard — `rename(2)` cannot move
                // a file into a directory, so it fails instead — but the
                // outcome must be the same one on both: a failure, nothing
                // taken inside the directory, and no temporary left beside it.
                let root = tempfile::tempdir().expect("tempdir");
                let artifact = seed(root.path(), "roxyd", RUNNING);
                let previous = artifact.with_file_name("roxyd.previous");
                std::fs::create_dir(&previous).expect("plant a directory at the destination");

                let error = InDaemonExecutor::new("seat")
                    .hard_link_over(&artifact, &previous)
                    .expect_err("a directory at the destination must be refused");

                match error {
                    ExecutorError::Transfer { path, .. } => assert_eq!(path, previous),
                    other => panic!("expected Transfer naming the destination, got {other:?}"),
                }
                assert!(
                    std::fs::read_dir(&previous)
                        .expect("read the destination")
                        .next()
                        .is_none(),
                    "the refusal must not leave the link inside the directory"
                );
                assert_eq!(
                    std::fs::metadata(&artifact).expect("stat").nlink(),
                    1,
                    "and the temporary link must be cleaned up again"
                );
                assert!(strays(artifact.parent().expect("dir")).is_empty());
            }
        }

        /// [`Executor::run_with_input`] on every `(identity, transport)` pair
        /// that runs a command, against stub `sudo` and `ssh` programs.
        ///
        /// The stubs keep elevation and the connection out of the picture
        /// while leaving everything this method adds in it: the supervisor
        /// really runs under the `sudo` stub and on the far side of the `ssh`
        /// stub, so the empty environment, the verbatim stdin, the stream
        /// accounting around the transport's markers and the kill are all
        /// exercised on each path.
        mod bounded_runs {
            use std::path::{Path, PathBuf};
            use std::process::{Command, Stdio};
            use std::time::{Duration, Instant};

            use rustix::process::Pid;
            use tempfile::TempDir;

            use super::super::super::bounded::Supervisor;
            use super::super::super::{
                CommandOutput, Executor, ExecutorError, FileMeta, Identity, InDaemonExecutor,
                LocalExecutor, OutputStream, RunLimits, RunWithInputError, ServiceAccount,
                SshExecutor, SshPrompt, SudoAuth,
            };
            use super::{failing_ssh, fake_ssh, write_script};

            /// Limits roomy enough for every test that is not about them.
            const ROOMY: RunLimits = RunLimits {
                max_stdout: 1 << 20,
                max_stderr: 1 << 20,
                timeout: Duration::from_secs(30),
            };
            /// The largest request the first consumer sends.
            const REQUEST_MAX: usize = 65_536;
            /// A command that ignores `SIGTERM`, records its own pid and a
            /// `SIGTERM`-ignoring child's in the file named by `$1`, writes
            /// `$2` bytes of stdout, and then waits on the child forever.
            const STUBBORN: &str = r#"trap '' TERM
/bin/sleep 300 &
echo "$!" > "$1.tmp"
echo "$$" >> "$1.tmp"
/bin/mv "$1.tmp" "$1"
/usr/bin/head -c "$2" /dev/zero
wait"#;
            /// How long a killed process may take to disappear from the
            /// process table, reaped by whoever inherited it.
            const REAP_WAIT: Duration = Duration::from_secs(10);

            /// A `sudo` stub that drops its own flags, `-u <account>`
            /// included, and execs the wrapped command.
            pub(super) fn descending_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "descending-sudo",
                    r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|-u) shift 2 ;;
    -n|-S) shift ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
"#,
                )
            }

            /// A `sudo` stub that insists on reading `s3cret` as its first
            /// line of stdin, as `sudo -S` does, before execing the wrapped
            /// command with the rest of the stream.
            pub(super) fn password_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "password-sudo",
                    r#"#!/bin/sh
IFS= read -r line
[ "$line" = s3cret ] || { echo "sudo: wrong password: $line" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|-u) shift 2 ;;
    -n|-S) shift ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
"#,
                )
            }

            pub(super) fn ssh_with(dir: &Path, sudo: &Path, auth: SudoAuth) -> SshExecutor {
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                SshExecutor::from_config("target", &config, "10.0.0.10", auth, SshPrompt::Deny)
                    .with_ssh_bin(fake_ssh(dir))
                    .with_remote_sudo(sudo.to_string_lossy().into_owned())
            }

            /// Every pair that runs a command, labelled for failure messages.
            fn every_pair(dir: &TempDir) -> Vec<(&'static str, Box<dyn Executor>, Identity)> {
                let sudo = descending_sudo(dir.path());
                let service = Identity::Service(ServiceAccount::Security);
                let local = || {
                    LocalExecutor::new("seat", SudoAuth::NonInteractive).with_sudo_bin(sudo.clone())
                };
                let ssh = || ssh_with(dir.path(), &sudo, SudoAuth::NonInteractive);
                let daemon = || InDaemonExecutor::new("seat").with_sudo_bin(sudo.clone());
                vec![
                    ("local operator", Box::new(local()), Identity::Operator),
                    ("local root", Box::new(local()), Identity::Root),
                    ("local service", Box::new(local()), service),
                    ("ssh operator", Box::new(ssh()), Identity::Operator),
                    ("ssh root", Box::new(ssh()), Identity::Root),
                    ("ssh service", Box::new(ssh()), service),
                    ("daemon root", Box::new(daemon()), Identity::Root),
                    ("daemon service", Box::new(daemon()), service),
                ]
            }

            /// Every byte value, repeated out to `len` bytes.
            fn pattern(len: usize) -> Vec<u8> {
                (0..=u8::MAX).cycle().take(len).collect()
            }

            /// Reads the pids [`STUBBORN`] recorded.
            fn recorded_pids(path: &Path) -> Vec<Pid> {
                let text = std::fs::read_to_string(path).expect("the command recorded its pids");
                text.lines()
                    .map(|line| {
                        let raw: i32 = line.trim().parse().expect("a pid");
                        Pid::from_raw(raw).expect("a positive pid")
                    })
                    .collect()
            }

            /// Waits until no process with any of `pids` exists any more.
            ///
            /// A killed process lingers as a zombie until whoever inherited it
            /// reaps it, and `kill(pid, 0)` still finds a zombie, so this
            /// awaits the condition rather than checking it once.
            fn assert_gone(label: &str, pids: &[Pid]) {
                let deadline = Instant::now() + REAP_WAIT;
                for &pid in pids {
                    while rustix::process::test_kill_process(pid).is_ok() {
                        assert!(
                            Instant::now() < deadline,
                            "{label}: process {pid:?} survived the kill"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }

            #[test]
            fn stdin_arrives_exactly_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                for input in [
                    Vec::new(),
                    pattern(REQUEST_MAX),
                    b"{\"op\":\"snapshot\"}\n".to_vec(),
                ] {
                    for (label, exec, identity) in every_pair(&dir) {
                        let output = exec
                            .run_with_input(identity, "/bin/cat", &[], &input, ROOMY)
                            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                        assert_eq!(output.code, Some(0), "{label}");
                        assert!(
                            output.stdout == input,
                            "{label}: {} bytes in, {} bytes out",
                            input.len(),
                            output.stdout.len()
                        );
                        assert!(output.stderr.is_empty(), "{label}: {:?}", output.stderr);
                    }
                }
            }

            #[test]
            fn a_password_line_is_consumed_before_the_input_on_the_elevating_transports() {
                let dir = tempfile::tempdir().expect("tempdir");
                let sudo = password_sudo(dir.path());
                let auth = || SudoAuth::Password("s3cret".to_string());
                let input = pattern(REQUEST_MAX);
                let pairs: Vec<(&str, Box<dyn Executor>)> = vec![
                    (
                        "local",
                        Box::new(LocalExecutor::new("seat", auth()).with_sudo_bin(sudo.clone())),
                    ),
                    ("ssh", Box::new(ssh_with(dir.path(), &sudo, auth()))),
                ];
                for (label, exec) in pairs {
                    for identity in [Identity::Root, Identity::Service(ServiceAccount::Roxyd)] {
                        let output = exec
                            .run_with_input(identity, "/bin/cat", &[], &input, ROOMY)
                            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                        assert!(
                            output.stdout == input,
                            "{label}: the input must follow intact"
                        );
                    }
                }
            }

            #[test]
            fn the_command_sees_an_empty_environment_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                assert!(
                    std::env::var_os("PATH").is_some(),
                    "the test process must have an environment to withhold"
                );
                for (label, exec, identity) in every_pair(&dir) {
                    let output = exec
                        .run_with_input(identity, "/usr/bin/env", &[], b"", ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(output.code, Some(0), "{label}");
                    assert_eq!(
                        String::from_utf8_lossy(&output.stdout),
                        "",
                        "{label}: no variable may reach the command"
                    );
                }
            }

            #[test]
            fn a_command_that_is_not_an_absolute_path_is_refused_before_spawning() {
                let dir = tempfile::tempdir().expect("tempdir");
                let marker = dir.path().join("spawned");
                let marker_arg = marker.to_string_lossy().into_owned();
                for command in ["touch", "./touch", "/usr/bin/touch=x"] {
                    for (label, exec, identity) in every_pair(&dir) {
                        let error = exec
                            .run_with_input(identity, command, &[&marker_arg], b"", ROOMY)
                            .expect_err("the command must be refused");
                        assert!(
                            matches!(&error, RunWithInputError::InvalidCommand { command: named }
                                if named == command),
                            "{label}: got {error:?}"
                        );
                        assert!(!marker.exists(), "{label}: nothing may have run");
                    }
                }
                // The refusal comes before the identity is looked at too.
                let error = InDaemonExecutor::new("seat")
                    .run_with_input(Identity::Operator, "cat", &[], b"", ROOMY)
                    .expect_err("refused");
                assert!(
                    matches!(error, RunWithInputError::InvalidCommand { .. }),
                    "{error:?}"
                );
            }

            #[test]
            fn a_nonzero_exit_is_a_command_output_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                for (label, exec, identity) in every_pair(&dir) {
                    let output = exec
                        .run_with_input(
                            identity,
                            "/bin/sh",
                            &["-c", "printf out; printf err >&2; exit 7"],
                            b"",
                            ROOMY,
                        )
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(output.code, Some(7), "{label}");
                    assert_eq!(output.stdout, b"out", "{label}");
                    assert_eq!(output.stderr, b"err", "{label}: only the command's stderr");
                }
            }

            #[test]
            fn a_command_that_prints_a_timeout_marker_still_exits_on_every_pair() {
                // The fixed marker earlier revisions announced a timeout with,
                // and one shaped like the current marker with another run's
                // nonce: a command that prints either and exits has exited,
                // and each byte counts against its stderr limit.
                let printed = "__BOOTLER_TIMEOUT__\
                               __BOOTLER_TIMEOUT_00112233445566778899aabbccddeeff__";
                let exact = RunLimits {
                    max_stderr: printed.len(),
                    ..ROOMY
                };
                let under = RunLimits {
                    max_stderr: printed.len() - 1,
                    ..ROOMY
                };
                let dir = tempfile::tempdir().expect("tempdir");
                for (label, exec, identity) in every_pair(&dir) {
                    let args = ["-c", "printf '%s' \"$0\" >&2", printed];
                    let output = exec
                        .run_with_input(identity, "/bin/sh", &args, b"", exact)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(output.code, Some(0), "{label}");
                    assert_eq!(output.stderr, printed.as_bytes(), "{label}");
                    let error = exec
                        .run_with_input(identity, "/bin/sh", &args, b"", under)
                        .expect_err("one byte over");
                    assert!(
                        matches!(
                            error,
                            RunWithInputError::OutputLimit {
                                stream: OutputStream::Stderr,
                                ..
                            }
                        ),
                        "{label}: {error:?}"
                    );
                }
            }

            #[test]
            fn a_byte_over_the_limit_that_could_open_a_marker_kills_a_running_command_on_every_pair()
             {
                // `_` could open the timeout marker and a newline the SSH
                // exit-status line, but a command still running after either
                // wrote it itself, and one byte over is one byte over.
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = RunLimits {
                    max_stderr: 0,
                    ..ROOMY
                };
                // Written only once the pids are recorded, since a direct
                // run is stopped at the byte.
                let flood = "/usr/bin/head -c \"$2\" /dev/zero";
                assert!(STUBBORN.contains(flood));
                let script = STUBBORN.replace(flood, "printf '%s' \"$3\" >&2");
                for (fragment, name) in [("_", "underscore"), ("\n", "newline")] {
                    for (index, (label, exec, identity)) in every_pair(&dir).into_iter().enumerate()
                    {
                        let pids = dir.path().join(format!("{name}-{index}"));
                        let started = Instant::now();
                        let error = exec
                            .run_with_input(
                                identity,
                                "/bin/sh",
                                &["-c", &script, "sh", &pids.to_string_lossy(), "0", fragment],
                                b"",
                                limits,
                            )
                            .expect_err("the byte must be counted");
                        assert!(
                            matches!(
                                error,
                                RunWithInputError::OutputLimit {
                                    stream: OutputStream::Stderr,
                                    limit: 0,
                                    ..
                                }
                            ),
                            "{label} {name}: got {error:?}"
                        );
                        assert!(
                            started.elapsed() < limits.timeout,
                            "{label} {name}: the breach, not the timeout, must end the run"
                        );
                        assert_gone(label, &recorded_pids(&pids));
                    }
                }
            }

            #[test]
            fn a_command_that_leaves_its_input_unread_still_reports_its_exit_on_every_pair() {
                // More than a pipe buffer holds, so feeding it cannot finish
                // before the command exits and the write meets a closed pipe.
                let input = pattern(4 * REQUEST_MAX);
                let dir = tempfile::tempdir().expect("tempdir");
                for (label, exec, identity) in every_pair(&dir) {
                    let output = exec
                        .run_with_input(
                            identity,
                            "/bin/sh",
                            &["-c", "printf done; exit 3"],
                            &input,
                            ROOMY,
                        )
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(output.code, Some(3), "{label}");
                    assert_eq!(output.stdout, b"done", "{label}");
                    assert!(output.stderr.is_empty(), "{label}: {:?}", output.stderr);
                }
            }

            #[test]
            fn an_executor_that_does_not_implement_it_refuses_as_unsupported() {
                struct RunOnly;
                impl Executor for RunOnly {
                    fn run(
                        &self,
                        _identity: Identity,
                        command: &str,
                        _args: &[&str],
                    ) -> Result<CommandOutput, ExecutorError> {
                        panic!("`{command}` must not be run through `run`")
                    }
                    fn put_file(
                        &self,
                        dest: &Path,
                        _contents: &[u8],
                        _meta: FileMeta,
                    ) -> Result<(), ExecutorError> {
                        panic!("`{}` must not be written", dest.display())
                    }
                }
                let error = RunOnly
                    .run_with_input(Identity::Root, "/bin/cat", &[], b"{}", ROOMY)
                    .expect_err("the default body refuses");
                assert!(
                    matches!(error, RunWithInputError::Unsupported),
                    "got {error:?}"
                );
            }

            #[test]
            fn each_stream_may_reach_its_limit_but_not_pass_it_on_every_pair() {
                const LIMIT: usize = 7;
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = RunLimits {
                    max_stdout: LIMIT,
                    max_stderr: LIMIT,
                    timeout: ROOMY.timeout,
                };
                for (stream, script) in [
                    (OutputStream::Stdout, "/bin/cat"),
                    (OutputStream::Stderr, "/bin/cat >&2"),
                ] {
                    for (label, exec, identity) in every_pair(&dir) {
                        let at_limit = pattern(LIMIT);
                        let output = exec
                            .run_with_input(identity, "/bin/sh", &["-c", script], &at_limit, limits)
                            .unwrap_or_else(|error| panic!("{label} {stream}: {error:?}"));
                        let captured = match stream {
                            OutputStream::Stdout => &output.stdout,
                            OutputStream::Stderr => &output.stderr,
                        };
                        assert_eq!(captured, &at_limit, "{label} {stream}");

                        let error = exec
                            .run_with_input(
                                identity,
                                "/bin/sh",
                                &["-c", script],
                                &pattern(LIMIT + 1),
                                limits,
                            )
                            .expect_err("one byte over the limit is an error");
                        match error {
                            RunWithInputError::OutputLimit {
                                command,
                                stream: over,
                                limit,
                            } => {
                                assert_eq!(command, "/bin/sh", "{label}");
                                assert_eq!(over, stream, "{label}");
                                assert_eq!(limit, LIMIT, "{label}");
                            }
                            other => {
                                panic!("{label} {stream}: expected OutputLimit, got {other:?}")
                            }
                        }
                    }
                }
            }

            #[test]
            fn a_breach_kills_a_command_that_ignores_sigterm_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = RunLimits {
                    max_stdout: 16,
                    ..ROOMY
                };
                for (index, (label, exec, identity)) in every_pair(&dir).into_iter().enumerate() {
                    let pids = dir.path().join(format!("breach-{index}"));
                    let started = Instant::now();
                    let error = exec
                        .run_with_input(
                            identity,
                            "/bin/sh",
                            &["-c", STUBBORN, "sh", &pids.to_string_lossy(), "4096"],
                            b"",
                            limits,
                        )
                        .expect_err("the flood must be stopped");
                    assert!(
                        matches!(
                            error,
                            RunWithInputError::OutputLimit {
                                stream: OutputStream::Stdout,
                                ..
                            }
                        ),
                        "{label}: got {error:?}"
                    );
                    assert!(
                        started.elapsed() < limits.timeout,
                        "{label}: the breach, not the timeout, must end the run"
                    );
                    assert_gone(label, &recorded_pids(&pids));
                }
            }

            #[test]
            fn a_timeout_kills_a_command_that_ignores_sigterm_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = RunLimits {
                    timeout: Duration::from_secs(2),
                    ..ROOMY
                };
                for (index, (label, exec, identity)) in every_pair(&dir).into_iter().enumerate() {
                    let pids = dir.path().join(format!("timeout-{index}"));
                    let error = exec
                        .run_with_input(
                            identity,
                            "/bin/sh",
                            &["-c", STUBBORN, "sh", &pids.to_string_lossy(), "0"],
                            b"",
                            limits,
                        )
                        .expect_err("the command outlives its timeout");
                    match error {
                        RunWithInputError::TimedOut { command, timeout } => {
                            assert_eq!(command, "/bin/sh", "{label}");
                            assert_eq!(timeout, limits.timeout, "{label}");
                        }
                        other => panic!("{label}: expected TimedOut, got {other:?}"),
                    }
                    assert_gone(label, &recorded_pids(&pids));
                }
            }

            #[test]
            fn an_unbounded_timeout_runs_the_command_to_completion_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = RunLimits {
                    timeout: Duration::MAX,
                    ..ROOMY
                };
                for (label, exec, identity) in every_pair(&dir) {
                    let output = exec
                        .run_with_input(identity, "/bin/cat", &[], b"{}", limits)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(output.code, Some(0), "{label}");
                    assert_eq!(output.stdout, b"{}", "{label}");
                    assert!(output.stderr.is_empty(), "{label}: {:?}", output.stderr);
                }
            }

            #[test]
            fn a_command_that_closes_its_streams_is_still_held_to_the_timeout() {
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = RunLimits {
                    timeout: Duration::from_millis(500),
                    ..ROOMY
                };
                let pids = dir.path().join("closed");
                let script = format!(
                    "exec >/dev/null 2>&1 </dev/null; {}",
                    STUBBORN.replace("\"$2\"", "0")
                );
                let error = LocalExecutor::default()
                    .run_with_input(
                        Identity::Operator,
                        "/bin/sh",
                        &["-c", &script, "sh", &pids.to_string_lossy()],
                        b"",
                        limits,
                    )
                    .expect_err("closing its pipes does not end the command");
                assert!(
                    matches!(error, RunWithInputError::TimedOut { .. }),
                    "got {error:?}"
                );
                assert_gone("closed streams", &recorded_pids(&pids));
            }

            // One table of failures across every transport, each checked under
            // both limits; split up, the shared stubs would be built per part.
            #[allow(clippy::too_many_lines)]
            #[test]
            fn elevation_and_transport_failures_are_reported_as_run_reports_them() {
                // Under no stderr allowance at all, too: what `sudo` or `ssh`
                // writes when it fails is not the command's output, so it
                // cannot pass the command's limit before it is classified.
                let tight = RunLimits {
                    max_stdout: 0,
                    max_stderr: 0,
                    ..ROOMY
                };
                let dir = tempfile::tempdir().expect("tempdir");
                let refusing = write_script(
                    dir.path(),
                    "refusing-sudo",
                    "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n",
                );
                let denying = write_script(
                    dir.path(),
                    "denying-sudo",
                    "#!/bin/sh\necho 'ops is not in the sudoers file.' >&2\nexit 1\n",
                );
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                let unreachable = SshExecutor::from_config(
                    "mgmt",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(failing_ssh(dir.path()));
                let remote_refusing = SshExecutor::from_config(
                    "mgmt",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(fake_ssh(dir.path()))
                .with_remote_sudo(refusing.to_string_lossy().into_owned());
                let password = password_sudo(dir.path());
                let wrong_password =
                    LocalExecutor::new("mgmt", SudoAuth::Password("wrong".to_string()))
                        .with_sudo_bin(password);
                for limits in [ROOMY, tight] {
                    let error = LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                        .with_sudo_bin(refusing.clone())
                        .run_with_input(Identity::Root, "/bin/cat", &[], b"{}", limits)
                        .expect_err("sudo refused");
                    assert!(
                        matches!(&error, RunWithInputError::Executor(ExecutorError::Elevation { host })
                            if host == "mgmt"),
                        "{limits:?}: got {error:?}"
                    );
                    let error = wrong_password
                        .run_with_input(Identity::Root, "/bin/cat", &[], b"{}", limits)
                        .expect_err("sudo rejected the password");
                    assert!(
                        matches!(&error, RunWithInputError::Executor(ExecutorError::SudoRefused { reason, .. })
                            if reason.contains("wrong password")),
                        "{limits:?}: got {error:?}"
                    );
                    let error = InDaemonExecutor::new("mgmt")
                        .with_sudo_bin(denying.clone())
                        .run_with_input(
                            Identity::Service(ServiceAccount::Security),
                            "/bin/cat",
                            &[],
                            b"{}",
                            limits,
                        )
                        .expect_err("sudo refused");
                    assert!(
                        matches!(&error, RunWithInputError::Executor(ExecutorError::SudoRefused { reason, .. })
                            if reason.contains("sudoers")),
                        "{limits:?}: got {error:?}"
                    );
                    let error = unreachable
                        .run_with_input(Identity::Operator, "/bin/cat", &[], b"{}", limits)
                        .expect_err("the host is unreachable");
                    assert!(
                        matches!(&error, RunWithInputError::Executor(ExecutorError::Connection { host, reason })
                            if host == "mgmt" && reason.contains("Connection refused")),
                        "{limits:?}: got {error:?}"
                    );
                    let error = unreachable
                        .run_with_input(Identity::Root, "/bin/cat", &[], b"{}", limits)
                        .expect_err("the host is unreachable");
                    assert!(
                        matches!(
                            &error,
                            RunWithInputError::Executor(ExecutorError::Connection { .. })
                        ),
                        "{limits:?}: got {error:?}"
                    );
                    let error = remote_refusing
                        .run_with_input(Identity::Root, "/bin/cat", &[], b"{}", limits)
                        .expect_err("the remote sudo refused");
                    assert!(
                        matches!(&error, RunWithInputError::Executor(ExecutorError::Elevation { host })
                            if host == "mgmt"),
                        "{limits:?}: got {error:?}"
                    );
                }

                let error = InDaemonExecutor::new("mgmt")
                    .run_with_input(Identity::Operator, "/bin/cat", &[], b"{}", ROOMY)
                    .expect_err("no operator inside the daemon");
                assert!(
                    matches!(
                        error,
                        RunWithInputError::Executor(ExecutorError::NoOperatorIdentity { .. })
                    ),
                    "got {error:?}"
                );
            }

            #[test]
            fn a_transport_that_floods_stderr_before_the_command_starts_is_refused() {
                // A `sudo` that never grants, writes far more than any real
                // diagnostic, and then hangs: the run is abandoned well before
                // the timeout, and still classifies as the refusal it is.
                let dir = tempfile::tempdir().expect("tempdir");
                let flooding = write_script(
                    dir.path(),
                    "flooding-sudo",
                    "#!/bin/sh\n/usr/bin/head -c 1048576 /dev/zero | /usr/bin/tr '\\0' x >&2\n\
                     exec /bin/sleep 300\n",
                );
                let started = Instant::now();
                let error = LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                    .with_sudo_bin(flooding)
                    .run_with_input(Identity::Root, "/bin/cat", &[], b"", ROOMY)
                    .expect_err("sudo never granted");
                assert!(
                    matches!(
                        error,
                        RunWithInputError::Executor(ExecutorError::SudoRefused { .. })
                    ),
                    "got {error:?}"
                );
                assert!(
                    started.elapsed() < ROOMY.timeout,
                    "abandoned, not timed out"
                );
            }

            /// Spawns the supervisor the way a transport this process cannot
            /// signal through would run it, in a process group of its own so
            /// its `kill 0` stays inside it, over [`STUBBORN`]. Its `PATH`
            /// names only the directory holding `pids`, where no utility lives,
            /// so its deadline is shown to depend on no `PATH` lookup — an empty
            /// environment would not show it, since a shell then falls back to
            /// a default `PATH` of its own.
            fn spawn_supervised(supervisor: &Supervisor, pids: &Path) -> std::process::Child {
                use std::os::unix::process::CommandExt;

                Command::new("/bin/sh")
                    .env_clear()
                    .env("PATH", pids.parent().expect("pids lives in a directory"))
                    .arg("-c")
                    .arg(supervisor.script())
                    .args(["/bin/sh", "-c", STUBBORN, "sh"])
                    .arg(pids)
                    .arg("0")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .process_group(0)
                    .spawn()
                    .expect("spawn the supervisor")
            }

            #[test]
            fn the_supervisor_kills_the_command_at_its_own_deadline() {
                // What ends a command on the far side of an SSH connection,
                // where no signal from here arrives: nothing signals the
                // supervisor, and its own deadline still kills everything.
                let dir = tempfile::tempdir().expect("tempdir");
                let pids = dir.path().join("pids");
                let supervisor = Supervisor::new(Duration::from_millis(200)).expect("a supervisor");
                let child = spawn_supervised(&supervisor, &pids);
                let output = child.wait_with_output().expect("the supervisor ends");
                assert!(!output.status.success());
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains(supervisor.timeout_marker()),
                    "the deadline announces itself: {:?}",
                    output.stderr
                );
                assert_gone("remote deadline", &recorded_pids(&pids));
            }

            #[test]
            fn a_relayed_sigterm_makes_the_supervisor_kill_the_command() {
                // What `sudo` relays when this process terminates it: a
                // SIGTERM to the supervisor alone, which the command ignores,
                // and which must still end the command.
                let dir = tempfile::tempdir().expect("tempdir");
                let pids = dir.path().join("pids");
                let supervisor = Supervisor::new(Duration::from_mins(5)).expect("a supervisor");
                let mut child = spawn_supervised(&supervisor, &pids);
                let deadline = Instant::now() + REAP_WAIT;
                while !pids.exists() {
                    assert!(Instant::now() < deadline, "the command never started");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let supervisor = Pid::from_child(&child);
                rustix::process::kill_process(supervisor, rustix::process::Signal::TERM)
                    .expect("signal the supervisor");
                let status = child.wait().expect("the supervisor ends");
                assert!(!status.success());
                assert_gone("relayed SIGTERM", &recorded_pids(&pids));
            }

            #[test]
            fn identities_resolve_through_sudo_exactly_as_run_resolves_them() {
                // A stub `sudo` that prints its argv and grants, so the words
                // ahead of the shell — the flags and the descent — can be
                // compared between the two methods on each transport.
                let dir = tempfile::tempdir().expect("tempdir");
                let recording = write_script(
                    dir.path(),
                    "recording-sudo",
                    &format!(
                        "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n\
                         printf '%s' '{}' >&2\n",
                        super::super::super::SUDO_OK_SENTINEL
                    ),
                );
                let local = LocalExecutor::new("seat", SudoAuth::NonInteractive)
                    .with_sudo_bin(recording.clone());
                let ssh = ssh_with(dir.path(), &recording, SudoAuth::NonInteractive);
                let daemon = InDaemonExecutor::new("seat").with_sudo_bin(recording.clone());
                let prefix = |argv: &[u8], shell: &str| -> Vec<String> {
                    String::from_utf8_lossy(argv)
                        .lines()
                        .take_while(|word| *word != shell)
                        .map(str::to_string)
                        .collect()
                };
                let pairs: Vec<(&str, &dyn Executor, Identity)> = vec![
                    ("local root", &local, Identity::Root),
                    (
                        "local service",
                        &local,
                        Identity::Service(ServiceAccount::Insight),
                    ),
                    ("ssh root", &ssh, Identity::Root),
                    (
                        "ssh service",
                        &ssh,
                        Identity::Service(ServiceAccount::Insight),
                    ),
                    (
                        "daemon service",
                        &daemon,
                        Identity::Service(ServiceAccount::Insight),
                    ),
                ];
                for (label, exec, identity) in pairs {
                    let run = exec
                        .run(identity, "/usr/bin/printf", &["%s", "marker"])
                        .expect("run");
                    let bounded = exec
                        .run_with_input(identity, "/usr/bin/printf", &["%s", "marker"], b"", ROOMY)
                        .expect("run_with_input");
                    let run_prefix = prefix(&run.stdout, "sh");
                    assert!(!run_prefix.is_empty(), "{label}: sudo must be involved");
                    assert_eq!(
                        prefix(&bounded.stdout, "/bin/sh"),
                        run_prefix,
                        "{label}: the elevation must match run's"
                    );
                }
                // The identities that involve no `sudo` run the command bare.
                for (label, exec, identity) in [
                    (
                        "local operator",
                        &local as &dyn Executor,
                        Identity::Operator,
                    ),
                    ("ssh operator", &ssh, Identity::Operator),
                    ("daemon root", &daemon, Identity::Root),
                ] {
                    let bounded = exec
                        .run_with_input(identity, "/usr/bin/printf", &["%s", "marker"], b"", ROOMY)
                        .expect("run_with_input");
                    assert_eq!(
                        bounded.stdout, b"marker",
                        "{label}: no sudo may be involved"
                    );
                }
            }
        }

        /// [`Executor::open_channel`] on every pair that implements it.
        mod channels {
            use std::io::{Read, Write};
            use std::path::{Path, PathBuf};
            use std::time::{Duration, Instant};

            use rustix::process::Pid;
            use tempfile::TempDir;

            use super::super::super::bounded::TRANSPORT_STDERR_LIMIT;
            use super::super::super::{
                Channel, ChannelError, ChannelLimits, CommandOutput, Executor, ExecutorError,
                FileMeta, Identity, InDaemonExecutor, LocalExecutor, RC_MARKER, SUDO_OK_SENTINEL,
                ServiceAccount, SshExecutor, SshPrompt, SudoAuth, spawn_retrying_text_busy,
            };
            use super::bounded_runs::{descending_sudo, password_sudo, ssh_with};
            use super::{failing_ssh, fake_ssh, write_script};

            /// Limits roomy enough for every test that is not about them.
            const ROOMY: ChannelLimits = ChannelLimits {
                elevation_timeout: Duration::from_secs(30),
                max_stderr: 1 << 20,
            };
            /// More than any pipe buffer holds, so an echo of it cannot
            /// complete unless both directions move at once.
            const ECHO_LEN: usize = 256 * 1024;
            /// How long a killed process may take to disappear from the
            /// process table, reaped by whoever inherited it.
            const REAP_WAIT: Duration = Duration::from_secs(10);

            /// Every pair that implements the channel, labelled for failure
            /// messages.
            fn every_pair(dir: &TempDir) -> Vec<(&'static str, Box<dyn Executor>, Identity)> {
                let sudo = descending_sudo(dir.path());
                let service = Identity::Service(ServiceAccount::Security);
                let local = || {
                    LocalExecutor::new("seat", SudoAuth::NonInteractive).with_sudo_bin(sudo.clone())
                };
                let ssh = || ssh_with(dir.path(), &sudo, SudoAuth::NonInteractive);
                vec![
                    ("local operator", Box::new(local()), Identity::Operator),
                    ("local root", Box::new(local()), Identity::Root),
                    ("local service", Box::new(local()), service),
                    ("ssh operator", Box::new(ssh()), Identity::Operator),
                    ("ssh root", Box::new(ssh()), Identity::Root),
                    ("ssh service", Box::new(ssh()), service),
                ]
            }

            /// Every byte value, repeated out to `len` bytes.
            fn pattern(len: usize) -> Vec<u8> {
                (0..=u8::MAX).cycle().take(len).collect()
            }

            /// Writes `input` to the channel's standard input and closes it,
            /// while reading its standard output to the end.
            fn echo(channel: &mut Channel, input: &[u8]) -> Vec<u8> {
                let mut stdin = channel.take_stdin().expect("stdin is the caller's");
                let mut stdout = channel.take_stdout().expect("stdout is the caller's");
                std::thread::scope(|scope| {
                    let writer = scope.spawn(move || stdin.write_all(input));
                    let mut echoed = Vec::new();
                    stdout.read_to_end(&mut echoed).expect("read stdout");
                    writer
                        .join()
                        .expect("the writer does not panic")
                        .expect("write stdin");
                    echoed
                })
            }

            /// Reads a channel's standard output to the end, closing its
            /// standard input first.
            fn read_out(channel: &mut Channel) -> Vec<u8> {
                echo(channel, b"")
            }

            /// Waits until `path` exists, then reads the pid written in it.
            fn recorded_pid(path: &Path) -> Pid {
                let deadline = Instant::now() + REAP_WAIT;
                while !path.exists() {
                    assert!(Instant::now() < deadline, "the command never started");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let text = std::fs::read_to_string(path).expect("the recorded pid");
                pid(text.trim())
            }

            fn pid(text: &str) -> Pid {
                Pid::from_raw(text.parse().expect("a pid")).expect("a positive pid")
            }

            /// Waits until no process with `pid` exists any more.
            fn assert_gone(label: &str, pid: Pid) {
                let deadline = Instant::now() + REAP_WAIT;
                while rustix::process::test_kill_process(pid).is_ok() {
                    assert!(
                        Instant::now() < deadline,
                        "{label}: process {pid:?} survived"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            #[test]
            fn bytes_pass_verbatim_both_ways_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                let input = pattern(ECHO_LEN);
                for (label, exec, identity) in every_pair(&dir) {
                    let mut channel = exec
                        .open_channel(identity, "/bin/cat", &[], ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    let echoed = echo(&mut channel, &input);
                    assert!(
                        echoed == input,
                        "{label}: {} bytes in, {} bytes out",
                        input.len(),
                        echoed.len()
                    );
                    let exit = channel
                        .wait()
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(exit.code, Some(0), "{label}");
                    assert!(exit.stderr.is_empty(), "{label}: {:?}", exit.stderr);
                    assert!(!exit.stderr_truncated, "{label}");
                }
            }

            #[test]
            fn stderr_is_drained_and_held_to_its_limit_while_the_echo_runs_on_every_pair() {
                const KEPT: usize = 1000;
                let dir = tempfile::tempdir().expect("tempdir");
                let limits = ChannelLimits {
                    max_stderr: KEPT,
                    ..ROOMY
                };
                let input = pattern(ECHO_LEN);
                let flood = "/usr/bin/head -c 1048576 /dev/zero >&2 & /bin/cat; wait";
                for (label, exec, identity) in every_pair(&dir) {
                    let mut channel = exec
                        .open_channel(identity, "/bin/sh", &["-c", flood], limits)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    let echoed = echo(&mut channel, &input);
                    assert!(echoed == input, "{label}: the echo must complete intact");
                    let exit = channel
                        .wait()
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(exit.code, Some(0), "{label}");
                    assert_eq!(exit.stderr, vec![0; KEPT], "{label}");
                    assert!(exit.stderr_truncated, "{label}");
                }
            }

            #[test]
            fn the_commands_own_code_and_stderr_come_back_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                for code in [0, 3, 255] {
                    let script = format!("printf err >&2; exit {code}");
                    for (label, exec, identity) in every_pair(&dir) {
                        let mut channel = exec
                            .open_channel(identity, "/bin/sh", &["-c", &script], ROOMY)
                            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                        assert!(read_out(&mut channel).is_empty(), "{label}");
                        let exit = channel
                            .wait()
                            .unwrap_or_else(|error| panic!("{label} {code}: {error:?}"));
                        assert_eq!(exit.code, Some(code), "{label}");
                        assert_eq!(
                            exit.stderr, b"err",
                            "{label}: neither the sentinel nor the exit-status line"
                        );
                        assert!(!exit.stderr_truncated, "{label}");
                    }
                }
            }

            #[test]
            fn wait_closes_standard_input_that_was_never_taken_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                for (label, exec, identity) in every_pair(&dir) {
                    let channel = exec
                        .open_channel(identity, "/bin/cat", &[], ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    let exit = channel
                        .wait()
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(exit.code, Some(0), "{label}: `cat` saw end of input");
                }
            }

            #[test]
            fn a_local_transport_ended_by_a_signal_has_no_code() {
                // Locally the stub `sudo` execs its way to the command, so the
                // signal ends the local transport process itself. Over SSH the
                // remote shell reports the signalled command's status as a code.
                let dir = tempfile::tempdir().expect("tempdir");
                for (label, exec, identity) in every_pair(&dir) {
                    let mut channel = exec
                        .open_channel(identity, "/bin/sh", &["-c", "kill -9 $$"], ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert!(read_out(&mut channel).is_empty(), "{label}");
                    let exit = channel
                        .wait()
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    let expected = if label.starts_with("local") {
                        None
                    } else {
                        Some(128 + 9)
                    };
                    assert_eq!(exit.code, expected, "{label}");
                }
            }

            #[test]
            fn the_command_sees_an_empty_environment_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                assert!(
                    std::env::var_os("PATH").is_some(),
                    "the test process must have an environment to withhold"
                );
                for (label, exec, identity) in every_pair(&dir) {
                    let mut channel = exec
                        .open_channel(identity, "/usr/bin/env", &[], ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    let printed = read_out(&mut channel);
                    assert_eq!(
                        String::from_utf8_lossy(&printed),
                        "",
                        "{label}: no variable may reach the command"
                    );
                    let exit = channel
                        .wait()
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(exit.code, Some(0), "{label}");
                }
            }

            #[test]
            fn the_start_consumes_no_standard_output() {
                // A transport that writes on stdout before the command starts:
                // every byte of it is still there for the caller.
                let dir = tempfile::tempdir().expect("tempdir");
                let early = write_script(
                    dir.path(),
                    "early-sudo",
                    &format!(
                        "#!/bin/sh\nprintf early\n{}",
                        std::fs::read_to_string(descending_sudo(dir.path()))
                            .expect("the stub")
                            .trim_start_matches("#!/bin/sh\n")
                    ),
                );
                let pairs: Vec<(&str, Box<dyn Executor>)> = vec![
                    (
                        "local",
                        Box::new(
                            LocalExecutor::new("seat", SudoAuth::NonInteractive)
                                .with_sudo_bin(early.clone()),
                        ),
                    ),
                    (
                        "ssh",
                        Box::new(ssh_with(dir.path(), &early, SudoAuth::NonInteractive)),
                    ),
                ];
                for (label, exec) in pairs {
                    let mut channel = exec
                        .open_channel(Identity::Root, "/bin/cat", &[], ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(echo(&mut channel, b"-late"), b"early-late", "{label}");
                    assert_eq!(channel.wait().expect("wait").code, Some(0), "{label}");
                }
            }

            #[test]
            fn identities_resolve_exactly_as_run_resolves_them() {
                // A stub `sudo` that prints its argv and grants, so the words
                // ahead of the shell — the flags and the descent — can be
                // compared between the two methods on each transport.
                let dir = tempfile::tempdir().expect("tempdir");
                let recording = write_script(
                    dir.path(),
                    "recording-sudo",
                    &format!(
                        "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n\
                         printf '%s' '{SUDO_OK_SENTINEL}' >&2\n"
                    ),
                );
                let local = LocalExecutor::new("seat", SudoAuth::NonInteractive)
                    .with_sudo_bin(recording.clone());
                let ssh = ssh_with(dir.path(), &recording, SudoAuth::NonInteractive);
                let password = LocalExecutor::new("seat", SudoAuth::Password("pw".to_string()))
                    .with_sudo_bin(recording.clone());
                let prefix = |argv: &[u8], shell: &str| -> Vec<String> {
                    String::from_utf8_lossy(argv)
                        .lines()
                        .take_while(|word| *word != shell)
                        .map(str::to_string)
                        .collect()
                };
                let service = Identity::Service(ServiceAccount::Insight);
                let pairs: Vec<(&str, &dyn Executor, Identity)> = vec![
                    ("local root", &local, Identity::Root),
                    ("local service", &local, service),
                    ("local root, password", &password, Identity::Root),
                    ("local service, password", &password, service),
                    ("ssh root", &ssh, Identity::Root),
                    ("ssh service", &ssh, service),
                ];
                for (label, exec, identity) in pairs {
                    let run = exec
                        .run(identity, "/usr/bin/printf", &["%s", "marker"])
                        .expect("run");
                    let mut channel = exec
                        .open_channel(identity, "/usr/bin/printf", &["%s", "marker"], ROOMY)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    let argv = read_out(&mut channel);
                    assert_eq!(channel.wait().expect("wait").code, Some(0), "{label}");
                    let run_prefix = prefix(&run.stdout, "sh");
                    assert!(!run_prefix.is_empty(), "{label}: sudo must be involved");
                    assert_eq!(
                        prefix(&argv, "/bin/sh"),
                        run_prefix,
                        "{label}: the elevation must match run's"
                    );
                    let words: Vec<&str> =
                        std::str::from_utf8(&argv).expect("utf-8").lines().collect();
                    let shell = words.iter().position(|word| *word == "/bin/sh");
                    assert_eq!(
                        shell.and_then(|at| words.get(at + 1..at + 2)),
                        Some(&["-c"][..]),
                        "{label}: {words:?}"
                    );
                    assert!(
                        words.ends_with(&["/usr/bin/printf", "%s", "marker"]),
                        "{label}: the command and its arguments stay discrete words: {words:?}"
                    );
                }
                // The identity that involves no `sudo` runs the command bare.
                for (label, exec) in [("local", &local as &dyn Executor), ("ssh", &ssh)] {
                    let mut channel = exec
                        .open_channel(
                            Identity::Operator,
                            "/usr/bin/printf",
                            &["%s", "marker"],
                            ROOMY,
                        )
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(
                        read_out(&mut channel),
                        b"marker",
                        "{label}: no sudo may be involved"
                    );
                    assert_eq!(channel.wait().expect("wait").code, Some(0), "{label}");
                }
            }

            #[test]
            fn the_ssh_invocation_is_run_s_with_no_terminal() {
                // A stub `ssh` that prints its argv and answers as the remote
                // start script and wrapper would, so both methods complete.
                let dir = tempfile::tempdir().expect("tempdir");
                let recording = write_script(
                    dir.path(),
                    "channel-recording-ssh",
                    &format!(
                        "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n\
                         printf '%s\\n{RC_MARKER}0\\n' '{SUDO_OK_SENTINEL}' >&2\n"
                    ),
                );
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 2222,
                    key: PathBuf::from("/keys/id_ed25519"),
                    host_key: crate::transport::HostKeyPolicy::AcceptNew,
                };
                for prompt in [SshPrompt::Deny, SshPrompt::Allow] {
                    for identity in [
                        Identity::Operator,
                        Identity::Root,
                        Identity::Service(ServiceAccount::Roxyd),
                    ] {
                        let exec = |bin: &Path| {
                            SshExecutor::from_config(
                                "target",
                                &config,
                                "10.0.0.10",
                                SudoAuth::NonInteractive,
                                prompt,
                            )
                            .with_ssh_bin(bin.to_path_buf())
                        };
                        let run = exec(&recording)
                            .run(identity, "/bin/cat", &[])
                            .expect("run over recording ssh");
                        let mut channel = exec(&recording)
                            .open_channel(identity, "/bin/cat", &[], ROOMY)
                            .unwrap_or_else(|error| panic!("{prompt:?} {identity:?}: {error:?}"));
                        let argv = read_out(&mut channel);
                        assert_eq!(channel.wait().expect("wait").code, Some(0));
                        let words = |argv: &[u8]| -> Vec<String> {
                            let mut words: Vec<String> = String::from_utf8_lossy(argv)
                                .lines()
                                .map(str::to_string)
                                .collect();
                            // The remote command line, which differs by design,
                            // spans the lines after the target.
                            let target = words
                                .iter()
                                .position(|word| word == "ops@10.0.0.10")
                                .expect("the target");
                            words.truncate(target + 1);
                            words
                        };
                        let channel_words = words(&argv);
                        assert_eq!(
                            channel_words,
                            words(&run.stdout),
                            "{prompt:?} {identity:?}: the ssh prefix must match run's"
                        );
                        assert_eq!(
                            channel_words.iter().any(|word| word == "BatchMode=yes"),
                            prompt == SshPrompt::Deny,
                            "{prompt:?}: {channel_words:?}"
                        );
                        assert!(
                            !channel_words
                                .iter()
                                .any(|word| word == "-t" || word == "-tt"),
                            "no terminal is requested: {channel_words:?}"
                        );
                    }
                }
            }

            #[test]
            fn a_password_line_is_consumed_before_the_callers_bytes() {
                let dir = tempfile::tempdir().expect("tempdir");
                let asking = password_sudo(dir.path());
                // A `NOPASSWD` rule, or cached credentials: `sudo` leaves the
                // password line unread.
                let not_asking = descending_sudo(dir.path());
                let auth = || SudoAuth::Password("s3cret".to_string());
                let input = pattern(ECHO_LEN);
                let mut pairs: Vec<(String, Box<dyn Executor>)> = Vec::new();
                for (how, sudo) in [("asking", &asking), ("not asking", &not_asking)] {
                    pairs.push((
                        format!("local, {how}"),
                        Box::new(LocalExecutor::new("seat", auth()).with_sudo_bin(sudo.clone())),
                    ));
                    pairs.push((
                        format!("ssh, {how}"),
                        Box::new(ssh_with(dir.path(), sudo, auth())),
                    ));
                }
                for (label, exec) in pairs {
                    for identity in [Identity::Root, Identity::Service(ServiceAccount::Roxyd)] {
                        let mut channel = exec
                            .open_channel(identity, "/bin/cat", &[], ROOMY)
                            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                        let echoed = echo(&mut channel, &input);
                        assert!(
                            echoed == input,
                            "{label}: the caller's first byte must be the command's first"
                        );
                        assert_eq!(channel.wait().expect("wait").code, Some(0), "{label}");
                    }
                }
            }

            #[test]
            fn failures_before_the_start_are_reported_as_run_reports_them() {
                let dir = tempfile::tempdir().expect("tempdir");
                let refusing = write_script(
                    dir.path(),
                    "refusing-sudo",
                    "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n",
                );
                let denying = write_script(
                    dir.path(),
                    "denying-sudo",
                    "#!/bin/sh\necho 'ops is not in the sudoers file.' >&2\nexit 1\n",
                );
                let open = |exec: &dyn Executor, identity| {
                    exec.open_channel(identity, "/bin/cat", &[], ROOMY)
                        .expect_err("the start fails")
                };

                let error = open(
                    &LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                        .with_sudo_bin(refusing.clone()),
                    Identity::Root,
                );
                assert!(
                    matches!(&error, ChannelError::Executor(ExecutorError::Elevation { host })
                        if host == "mgmt"),
                    "got {error:?}"
                );
                let error = open(
                    &LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                        .with_sudo_bin(denying.clone()),
                    Identity::Service(ServiceAccount::Security),
                );
                assert!(
                    matches!(&error, ChannelError::Executor(ExecutorError::SudoRefused { host, reason })
                        if host == "mgmt" && reason.contains("sudoers")),
                    "got {error:?}"
                );

                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                let ssh = || {
                    SshExecutor::from_config(
                        "mgmt",
                        &config,
                        "10.0.0.10",
                        SudoAuth::NonInteractive,
                        SshPrompt::Deny,
                    )
                };
                let unreachable = ssh().with_ssh_bin(failing_ssh(dir.path()));
                for identity in [Identity::Operator, Identity::Root] {
                    let error = open(&unreachable, identity);
                    assert!(
                        matches!(&error, ChannelError::Executor(ExecutorError::Connection { host, reason })
                            if host == "mgmt" && reason.contains("Connection refused")),
                        "{identity:?}: got {error:?}"
                    );
                }
                let remote_refusing = ssh()
                    .with_ssh_bin(fake_ssh(dir.path()))
                    .with_remote_sudo(refusing.to_string_lossy().into_owned());
                let error = open(&remote_refusing, Identity::Root);
                assert!(
                    matches!(&error, ChannelError::Executor(ExecutorError::Elevation { host })
                        if host == "mgmt"),
                    "got {error:?}"
                );
                let remote_denying = ssh()
                    .with_ssh_bin(fake_ssh(dir.path()))
                    .with_remote_sudo(denying.to_string_lossy().into_owned());
                let error = open(&remote_denying, Identity::Root);
                assert!(
                    matches!(&error, ChannelError::Executor(ExecutorError::SudoRefused { reason, .. })
                        if reason.contains("sudoers")),
                    "got {error:?}"
                );
            }

            #[test]
            fn a_start_not_proven_in_time_is_killed_and_reaped() {
                let dir = tempfile::tempdir().expect("tempdir");
                let silent = write_script(
                    dir.path(),
                    "silent-sudo",
                    "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n\
                     printf 'sudo: pid %s\\n' \"$$\" >&2\nexec /bin/sleep 300\n",
                );
                // Run once first, so the first run of a fresh executable —
                // which macOS scans — is not what the short timeout measures.
                let warmed =
                    spawn_retrying_text_busy(std::process::Command::new(&silent).arg("warm"))
                        .and_then(|mut child| child.wait())
                        .expect("warm the stub");
                assert!(warmed.success());
                let limits = ChannelLimits {
                    elevation_timeout: Duration::from_millis(200),
                    ..ROOMY
                };
                let started = Instant::now();
                let error = LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                    .with_sudo_bin(silent)
                    .open_channel(Identity::Root, "/bin/cat", &[], limits)
                    .expect_err("the sentinel never arrives");
                assert!(
                    started.elapsed() < REAP_WAIT,
                    "took {:?}",
                    started.elapsed()
                );
                let ChannelError::ElevationTimedOut {
                    host,
                    timeout,
                    diagnostic,
                } = error
                else {
                    panic!("expected ElevationTimedOut, got {error:?}");
                };
                assert_eq!(host, "mgmt");
                assert_eq!(timeout, limits.elevation_timeout);
                let transport = diagnostic
                    .strip_prefix("sudo: pid ")
                    .unwrap_or_else(|| panic!("the preamble read so far: {diagnostic:?}"));
                let transport = pid(transport);
                assert!(
                    rustix::process::test_kill_process(transport).is_err(),
                    "the transport was reaped before the error returned"
                );
            }

            #[test]
            fn a_rejected_password_times_out_with_sudos_complaint() {
                // `sudo -S` asks again rather than exiting on a wrong password.
                let dir = tempfile::tempdir().expect("tempdir");
                let asking = write_script(
                    dir.path(),
                    "asking-sudo",
                    "#!/bin/sh\nwhile IFS= read -r line; do\n  \
                     [ \"$line\" = s3cret ] && exit 0\n  \
                     echo 'Sorry, try again.' >&2\ndone\n",
                );
                let limits = ChannelLimits {
                    elevation_timeout: Duration::from_millis(500),
                    ..ROOMY
                };
                let error = LocalExecutor::new("mgmt", SudoAuth::Password("wrong".to_string()))
                    .with_sudo_bin(asking)
                    .open_channel(Identity::Root, "/bin/cat", &[], limits)
                    .expect_err("the password was rejected");
                assert!(
                    matches!(&error, ChannelError::ElevationTimedOut { diagnostic, .. }
                        if diagnostic.contains("Sorry, try again")),
                    "got {error:?}"
                );
            }

            #[test]
            fn a_transport_that_floods_stderr_before_the_start_is_killed_and_classified() {
                let dir = tempfile::tempdir().expect("tempdir");
                let flooding = write_script(
                    dir.path(),
                    "flooding-sudo",
                    "#!/bin/sh\n/usr/bin/head -c 1048576 /dev/zero | /usr/bin/tr '\\0' x >&2\n\
                     exec /bin/sleep 300\n",
                );
                let started = Instant::now();
                let error = LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                    .with_sudo_bin(flooding)
                    .open_channel(Identity::Root, "/bin/cat", &[], ROOMY)
                    .expect_err("sudo never granted");
                assert!(
                    matches!(
                        error,
                        ChannelError::Executor(ExecutorError::SudoRefused { .. })
                    ),
                    "got {error:?}"
                );
                assert!(
                    started.elapsed() < ROOMY.elevation_timeout,
                    "abandoned, not timed out"
                );
            }

            #[test]
            fn a_start_at_the_transport_limit_opens_and_one_past_it_is_refused() {
                let dir = tempfile::tempdir().expect("tempdir");
                // Writes `$FLOOD` bytes, drops `-n`, and execs the start
                // script, whose sentinel follows them directly.
                let flooding_then_granting = |name: &str, flood: usize| {
                    write_script(
                        dir.path(),
                        name,
                        &format!(
                            "#!/bin/sh\n/usr/bin/head -c {flood} /dev/zero | \
                             /usr/bin/tr '\\0' x >&2\nshift\nexec \"$@\"\n"
                        ),
                    )
                };
                let at_limit = flooding_then_granting("at-limit-sudo", TRANSPORT_STDERR_LIMIT);
                let mut channel = LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                    .with_sudo_bin(at_limit)
                    .open_channel(Identity::Root, "/bin/cat", &[], ROOMY)
                    .expect("the limit itself is not passed");
                assert_eq!(echo(&mut channel, b"frame"), b"frame");
                let exit = channel.wait().expect("wait");
                assert_eq!(exit.code, Some(0));
                assert!(exit.stderr.is_empty(), "{:?}", exit.stderr.len());

                let past_limit =
                    flooding_then_granting("past-limit-sudo", TRANSPORT_STDERR_LIMIT + 1);
                let error = LocalExecutor::new("mgmt", SudoAuth::NonInteractive)
                    .with_sudo_bin(past_limit)
                    .open_channel(Identity::Root, "/bin/cat", &[], ROOMY)
                    .expect_err("the sentinel came one byte past the limit");
                let ChannelError::Executor(ExecutorError::SudoRefused { reason, .. }) = &error
                else {
                    panic!("expected SudoRefused, got {error:?}");
                };
                assert!(
                    !reason.contains(SUDO_OK_SENTINEL),
                    "only the transport's own bytes are classified"
                );
            }

            #[test]
            fn an_ssh_channel_that_loses_its_exit_status_has_no_code() {
                let dir = tempfile::tempdir().expect("tempdir");
                let lossy = write_script(
                    dir.path(),
                    "lossy-ssh",
                    &format!(
                        "#!/bin/sh\nprintf '%s' '{SUDO_OK_SENTINEL}' >&2\n\
                         IFS= read -r handoff\n\
                         /bin/cat\necho 'Connection to 10.0.0.10 closed.' >&2\nexit 255\n"
                    ),
                );
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                let exec = SshExecutor::from_config(
                    "mgmt",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(lossy);
                let mut channel = exec
                    .open_channel(Identity::Root, "/bin/cat", &[], ROOMY)
                    .expect("the start was announced");
                assert_eq!(echo(&mut channel, b"frame"), b"frame");
                let error = channel.wait().expect_err("no exit-status line");
                assert!(
                    matches!(&error, ChannelError::ExitUnknown { host, reason }
                        if host == "mgmt" && reason.contains("closed")),
                    "got {error:?}"
                );
            }

            #[test]
            fn a_failed_ssh_is_not_trusted_for_a_status_line_the_command_forged() {
                let dir = tempfile::tempdir().expect("tempdir");
                // The command's own stderr ends in a well-formed exit-status
                // line; the connection then drops before the wrapper reports.
                let forging = write_script(
                    dir.path(),
                    "forging-ssh",
                    &format!(
                        "#!/bin/sh\nprintf '%s' '{SUDO_OK_SENTINEL}' >&2\n\
                         IFS= read -r handoff\n\
                         /bin/cat\nprintf '\\n{RC_MARKER}0\\n' >&2\nexit 255\n"
                    ),
                );
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                let exec = SshExecutor::from_config(
                    "mgmt",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(forging);
                let mut channel = exec
                    .open_channel(Identity::Root, "/bin/cat", &[], ROOMY)
                    .expect("the start was announced");
                assert_eq!(echo(&mut channel, b"frame"), b"frame");
                let error = channel
                    .wait()
                    .expect_err("a failed ssh delivered no exit-status line");
                assert!(
                    matches!(&error, ChannelError::ExitUnknown { host, reason }
                        if host == "mgmt" && reason.contains("255")),
                    "got {error:?}"
                );
            }

            /// A command that records its pid in the file named by `$1`, then
            /// blocks on standard input.
            const BLOCKING: &str =
                "echo \"$$\" > \"$1.tmp\"; /bin/mv \"$1.tmp\" \"$1\"; exec /bin/cat";

            #[test]
            fn kill_and_drop_end_the_transport_and_the_command_sees_eof_on_every_pair() {
                let dir = tempfile::tempdir().expect("tempdir");
                for how in ["kill", "drop"] {
                    for (index, (label, exec, identity)) in every_pair(&dir).into_iter().enumerate()
                    {
                        let pid_file = dir.path().join(format!("{how}-{index}"));
                        let channel = exec
                            .open_channel(
                                identity,
                                "/bin/sh",
                                &["-c", BLOCKING, "sh", &pid_file.to_string_lossy()],
                                ROOMY,
                            )
                            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                        let command = recorded_pid(&pid_file);
                        let transport = pid(&channel.transport_pid().to_string());
                        match how {
                            "kill" => channel
                                .kill()
                                .unwrap_or_else(|error| panic!("{label}: {error:?}")),
                            _ => drop(channel),
                        }
                        assert!(
                            rustix::process::test_kill_process(transport).is_err(),
                            "{label} {how}: the transport was reaped"
                        );
                        assert_gone(&format!("{label} {how}"), command);
                    }
                }
            }

            #[test]
            fn wait_gives_stderr_a_grace_when_a_descendant_holds_it() {
                // A descendant that outlives the command keeps stderr open;
                // `wait` returns once the grace passes, and says so.
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = LocalExecutor::new("seat", SudoAuth::NonInteractive)
                    .with_sudo_bin(descending_sudo(dir.path()));
                let pid_file = dir.path().join("descendant");
                let started = Instant::now();
                let channel = exec
                    .open_channel(
                        Identity::Operator,
                        "/bin/sh",
                        &[
                            "-c",
                            "printf err >&2; /bin/sleep 8 >/dev/null & echo \"$!\" > \"$1\"; exit 4",
                            "sh",
                            &pid_file.to_string_lossy(),
                        ],
                        ROOMY,
                    )
                    .expect("open");
                let exit = channel.wait().expect("wait");
                let elapsed = started.elapsed();
                // The descendant is this test's to stop, not left to run out.
                let descendant = recorded_pid(&pid_file);
                let _ = rustix::process::kill_process(descendant, rustix::process::Signal::KILL);
                assert_gone("the descendant", descendant);
                assert_eq!(exit.code, Some(4));
                assert_eq!(exit.stderr, b"err");
                assert!(exit.stderr_truncated, "the stream had not ended");
                assert!(
                    elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(8),
                    "waited {elapsed:?}"
                );
            }

            #[test]
            fn a_command_that_is_not_an_absolute_path_is_refused_before_spawning() {
                let dir = tempfile::tempdir().expect("tempdir");
                let marker = dir.path().join("spawned");
                let marking = write_script(
                    dir.path(),
                    "marking-stub",
                    &format!("#!/bin/sh\n: > '{}'\nexit 1\n", marker.display()),
                );
                let config = crate::transport::Ssh {
                    user: "ops".to_string(),
                    port: 22,
                    key: PathBuf::from("/dev/null"),
                    host_key: crate::transport::HostKeyPolicy::Strict,
                };
                let local = LocalExecutor::new("seat", SudoAuth::NonInteractive)
                    .with_sudo_bin(marking.clone());
                let ssh = SshExecutor::from_config(
                    "target",
                    &config,
                    "10.0.0.10",
                    SudoAuth::NonInteractive,
                    SshPrompt::Deny,
                )
                .with_ssh_bin(marking);
                for command in ["cat", "/bin/a=b"] {
                    for exec in [&local as &dyn Executor, &ssh] {
                        for identity in [
                            Identity::Operator,
                            Identity::Root,
                            Identity::Service(ServiceAccount::Security),
                        ] {
                            let error = exec
                                .open_channel(identity, command, &[], ROOMY)
                                .expect_err("the command must be refused");
                            assert!(
                                matches!(&error, ChannelError::InvalidCommand { command: named }
                                    if named == command),
                                "{identity:?}: got {error:?}"
                            );
                            assert!(!marker.exists(), "nothing may have been spawned");
                        }
                    }
                }
            }

            #[test]
            fn the_default_body_and_the_daemon_are_unsupported() {
                struct RunOnly;
                impl Executor for RunOnly {
                    fn run(
                        &self,
                        _identity: Identity,
                        command: &str,
                        _args: &[&str],
                    ) -> Result<CommandOutput, ExecutorError> {
                        panic!("`{command}` must not be run through `run`")
                    }
                    fn put_file(
                        &self,
                        dest: &Path,
                        _contents: &[u8],
                        _meta: FileMeta,
                    ) -> Result<(), ExecutorError> {
                        panic!("`{}` must not be written", dest.display())
                    }
                }
                for (label, exec) in [
                    ("default", &RunOnly as &dyn Executor),
                    ("daemon", &InDaemonExecutor::new("seat")),
                ] {
                    for identity in [Identity::Root, Identity::Service(ServiceAccount::Roxyd)] {
                        let error = exec
                            .open_channel(identity, "/bin/cat", &[], ROOMY)
                            .expect_err("unsupported");
                        assert!(
                            matches!(error, ChannelError::Unsupported),
                            "{label}: got {error:?}"
                        );
                    }
                }
            }
        }

        /// [`InDaemonExecutor::descent_command`] and
        /// [`InDaemonExecutor::settle_descent`], against stub `sudo` programs:
        /// the returned `Command` is spawned exactly as a root caller spawns
        /// it, and the stub stands in for `sudo` alone, so the descent script,
        /// `env -i` and the command all really run.
        mod descents {
            use std::path::{Path, PathBuf};
            use std::process::{Command, Output, Stdio};

            use tempfile::TempDir;

            use super::super::super::bounded::TRANSPORT_STDERR_LIMIT;
            use super::super::super::{
                CommandOutput, Descent, DescentError, DescentProfile, DescentSettle, Executor,
                ExecutorError, Identity, InDaemonExecutor, NO_WORKING_DIRECTORY_MARKER,
                OperatorIds, SUDO_OK_SENTINEL, ServiceAccount, classify_elevation,
                spawn_retrying_text_busy,
            };
            use super::write_script;

            /// The pinned execution profile's variables.
            const PROFILE_ENV: &[(&str, &str)] = &[
                ("PATH", "/usr/local/bin:/usr/bin:/bin"),
                ("HOME", "/home/operator"),
                ("USER", "operator"),
                ("LOGNAME", "operator"),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
            ];
            /// Arguments a shell would split, expand or read as options.
            const AWKWARD_ARGS: &[&str] = &[
                "two words",
                "\"double\" and 'single' quotes",
                "$(echo expanded)",
                "`echo expanded`",
                "line\nbreak",
                "-n",
                "-leading-dash",
                "K=V",
                "",
                "*",
            ];
            /// Parses the flags a `sudo` stub drops — `-u` and `-g` with their
            /// values, any other flag alone — leaving the wrapped command in
            /// `$@`.
            const SKIP_SUDO_FLAGS: &str = r#"while [ "$#" -gt 0 ]; do
  case "$1" in
    -u|-g) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
"#;

            /// A `sudo` stub that prints its arguments, each ended by a NUL.
            fn recording_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "recording-sudo",
                    &format!(
                        "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\0' \"$arg\"; done\n\
                         printf '%s' '{SUDO_OK_SENTINEL}' >&2\n"
                    ),
                )
            }

            /// A `sudo` stub that drops its flags and replaces itself with the
            /// wrapped command.
            fn descending_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "descending-sudo",
                    &format!("#!/bin/sh\n{SKIP_SUDO_FLAGS}exec \"$@\"\n"),
                )
            }

            /// A `sudo` stub that drops its flags and runs the wrapped command
            /// as its child, staying alive beside it as `sudo` does.
            #[cfg(target_os = "linux")]
            fn staying_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "staying-sudo",
                    &format!("#!/bin/sh\n{SKIP_SUDO_FLAGS}\"$@\"\nexit \"$?\"\n"),
                )
            }

            /// A `sudo` stub that refuses an unknown account.
            fn refusing_sudo(dir: &Path) -> PathBuf {
                write_script(
                    dir,
                    "refusing-sudo",
                    "#!/bin/sh\necho 'sudo: unknown user clumit-insight' >&2\nexit 1\n",
                )
            }

            fn daemon(sudo: PathBuf) -> InDaemonExecutor {
                InDaemonExecutor::new("mgmt").with_sudo_bin(sudo)
            }

            /// Returns `dir` with every symlink resolved, as `/bin/pwd` prints
            /// it.
            fn real(dir: &TempDir) -> PathBuf {
                std::fs::canonicalize(dir.path()).expect("canonicalize the tempdir")
            }

            /// Spawns `cmd` with standard input closed and both output streams
            /// captured, and waits for it.
            fn output(mut cmd: Command) -> Output {
                cmd.stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                spawn_retrying_text_busy(&mut cmd)
                    .expect("spawn the descent")
                    .wait_with_output()
                    .expect("wait for the descent")
            }

            /// Runs `command` through a descent to `who` and returns its
            /// standard output, once standard error has settled as started.
            fn descended_stdout(
                exec: &InDaemonExecutor,
                who: Descent,
                command: &str,
                args: &[&str],
                profile: &DescentProfile<'_>,
            ) -> Vec<u8> {
                let cmd = exec
                    .descent_command(who, command, args, profile)
                    .expect("a valid descent");
                let out = output(cmd);
                match exec.settle_descent(&out.stderr, true) {
                    DescentSettle::Started {
                        command_stderr_from,
                    } => assert_eq!(
                        out.stderr.get(command_stderr_from..),
                        Some(&b""[..]),
                        "the command wrote nothing on stderr"
                    ),
                    other => panic!("{who:?}: expected a start, got {other:?}"),
                }
                assert!(out.status.success(), "{who:?}: {out:?}");
                out.stdout
            }

            fn operator() -> OperatorIds {
                OperatorIds::new(1000, 1000).expect("1000 is an operator id")
            }

            fn both_descents() -> [Descent; 2] {
                [
                    Descent::Service(ServiceAccount::Insight),
                    Descent::Operator(operator()),
                ]
            }

            /// Splits NUL-ended words.
            fn words(bytes: &[u8]) -> Vec<String> {
                bytes
                    .split(|&byte| byte == 0)
                    .map(|word| String::from_utf8_lossy(word).into_owned())
                    .collect::<Vec<_>>()
                    .split_last()
                    .map(|(_, words)| words.to_vec())
                    .unwrap_or_default()
            }

            /// Returns the words before `shell`.
            fn prefix<'w>(words: &'w [String], shell: &str) -> &'w [String] {
                let at = words
                    .iter()
                    .position(|word| word == shell)
                    .unwrap_or_else(|| panic!("`{shell}` should be present: {words:?}"));
                words.get(..at).expect("the position is within the words")
            }

            #[test]
            fn a_service_descends_as_run_does_and_an_operator_by_id() {
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = daemon(recording_sudo(dir.path()));
                let cwd = real(&dir);
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: &cwd,
                };

                let run = exec
                    .run(Identity::Service(ServiceAccount::Insight), "printf", &[])
                    .expect("the recording stub runs");
                let run_words = words(&run.stdout);
                let run_prefix = prefix(&run_words, super::super::super::SH);
                assert_eq!(run_prefix, ["-u", "clumit-insight"]);

                for (who, expected) in [
                    (
                        Descent::Service(ServiceAccount::Insight),
                        run_prefix.to_vec(),
                    ),
                    (
                        Descent::Operator(operator()),
                        ["-u", "#1000", "-g", "#1000"].map(String::from).to_vec(),
                    ),
                ] {
                    let cmd = exec
                        .descent_command(who, "/usr/bin/printf", &["%s", "a b"], &profile)
                        .expect("a valid descent");
                    let out = output(cmd);
                    let argv = words(&out.stdout);
                    assert_eq!(prefix(&argv, "/bin/sh"), expected, "{who:?}");
                    for flag in ["-n", "-S", "-p"] {
                        assert!(
                            !argv.iter().any(|word| word == flag),
                            "{who:?}: descent from root must not carry `{flag}`: {argv:?}"
                        );
                    }
                    let mut tail = vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        super::super::super::descent_script(),
                        "bootler-descent".to_string(),
                        cwd.to_string_lossy().into_owned(),
                    ];
                    tail.extend(
                        PROFILE_ENV
                            .iter()
                            .map(|(name, value)| format!("{name}={value}")),
                    );
                    tail.extend(["/usr/bin/printf", "%s", "a b"].map(String::from));
                    assert_eq!(
                        argv.get(expected.len()..),
                        Some(tail.as_slice()),
                        "{who:?}: every value is a word of its own"
                    );
                }
            }

            #[test]
            fn the_command_is_built_and_not_spawned() {
                let dir = tempfile::tempdir().expect("tempdir");
                let marker = dir.path().join("spawned");
                let sudo = write_script(
                    dir.path(),
                    "touching-sudo",
                    &format!("#!/bin/sh\n: > '{}'\n", marker.display()),
                );
                let exec = daemon(sudo.clone());
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: Path::new("/"),
                };
                for who in both_descents() {
                    let cmd = exec
                        .descent_command(who, "/bin/cat", &[], &profile)
                        .expect("a valid descent");
                    assert_eq!(cmd.get_program(), sudo.as_os_str(), "{who:?}");
                    assert_eq!(cmd.get_current_dir(), Some(Path::new("/")), "{who:?}");
                    assert_eq!(cmd.get_envs().count(), 0, "{who:?}: no environment change");
                }
                assert!(!marker.exists(), "building a descent must spawn nothing");
            }

            #[test]
            fn the_command_sees_exactly_the_profile_in_its_directory() {
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = daemon(descending_sudo(dir.path()));
                let cwd = real(&dir);
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: &cwd,
                };
                let mut expected: Vec<String> = PROFILE_ENV
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect();
                expected.sort_unstable();

                for who in both_descents() {
                    let mut cmd = exec
                        .descent_command(who, "/usr/bin/env", &[], &profile)
                        .expect("a valid descent");
                    // Reaches the stub standing in for `sudo`, and must stop
                    // there.
                    cmd.env("BOOTLER_OUTER_ONLY", "leaked");
                    let out = output(cmd);
                    assert!(
                        matches!(
                            exec.settle_descent(&out.stderr, true),
                            DescentSettle::Started { .. }
                        ),
                        "{who:?}: {out:?}"
                    );
                    let stdout = String::from_utf8(out.stdout).expect("utf-8");
                    let mut seen: Vec<String> = stdout.lines().map(String::from).collect();
                    seen.sort_unstable();
                    assert_eq!(seen, expected, "{who:?}: exactly the profile");

                    let pwd = descended_stdout(&exec, who, "/bin/pwd", &[], &profile);
                    assert_eq!(
                        pwd,
                        format!("{}\n", cwd.display()).into_bytes(),
                        "{who:?}: the profile's directory"
                    );
                }
            }

            #[test]
            fn every_argument_and_value_arrives_intact() {
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = daemon(descending_sudo(dir.path()));
                let cwd = real(&dir);
                let mut args = vec!["%s\n"];
                args.extend_from_slice(AWKWARD_ARGS);
                let expected: String = AWKWARD_ARGS.iter().flat_map(|arg| [*arg, "\n"]).collect();
                let awkward_value = "a value with \"double\", 'single', $(x) and\nnewline";
                let env = [("PATH", "/usr/bin:/bin"), ("AWKWARD", awkward_value)];
                let profile = DescentProfile {
                    env: &env,
                    cwd: &cwd,
                };

                for who in both_descents() {
                    let printed = descended_stdout(&exec, who, "/usr/bin/printf", &args, &profile);
                    assert_eq!(
                        String::from_utf8_lossy(&printed),
                        expected,
                        "{who:?}: every argument is one word, unchanged"
                    );

                    let printed = descended_stdout(
                        &exec,
                        who,
                        "/usr/bin/printf",
                        &["%s", "$AWKWARD"],
                        &profile,
                    );
                    assert_eq!(printed, b"$AWKWARD", "{who:?}: no argument is expanded");

                    let printed = descended_stdout(&exec, who, "/usr/bin/env", &[], &profile);
                    assert!(
                        String::from_utf8_lossy(&printed)
                            .contains(&format!("AWKWARD={awkward_value}\n")),
                        "{who:?}: the value arrives unchanged: {printed:?}"
                    );
                }
            }

            #[test]
            fn a_missing_directory_starts_nothing_and_settles_as_such() {
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = daemon(descending_sudo(dir.path()));
                let missing = real(&dir).join("missing");
                let marker = real(&dir).join("ran");
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: &missing,
                };
                for who in both_descents() {
                    let cmd = exec
                        .descent_command(
                            who,
                            "/usr/bin/touch",
                            &[&marker.to_string_lossy()],
                            &profile,
                        )
                        .expect("a valid descent");
                    let out = output(cmd);
                    assert!(!out.status.success(), "{who:?}");
                    assert!(!marker.exists(), "{who:?}: the command must not run");
                    match exec.settle_descent(&out.stderr, true) {
                        DescentSettle::NoWorkingDirectory { reason } => {
                            assert!(reason.contains("missing"), "{who:?}: reason: {reason}");
                            assert!(!reason.contains(NO_WORKING_DIRECTORY_MARKER));
                        }
                        other => panic!("{who:?}: expected no directory, got {other:?}"),
                    }
                }
            }

            #[test]
            fn a_refusal_settles_as_run_classifies_it() {
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = daemon(refusing_sudo(dir.path()));
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: Path::new("/"),
                };
                for who in both_descents() {
                    let cmd = exec
                        .descent_command(who, "/bin/cat", &[], &profile)
                        .expect("a valid descent");
                    let out = output(cmd);
                    let run = classify_elevation(
                        CommandOutput {
                            code: out.status.code(),
                            stdout: Vec::new(),
                            stderr: out.stderr.clone(),
                        },
                        None,
                        "mgmt",
                    )
                    .expect_err("run refuses too");
                    let ExecutorError::SudoRefused {
                        host: run_host,
                        reason: run_reason,
                    } = run
                    else {
                        panic!("run classifies a refusal as SudoRefused, got {run:?}");
                    };
                    assert!(
                        matches!(
                            exec.settle_descent(&out.stderr, false),
                            DescentSettle::Pending
                        ),
                        "{who:?}: a stream still open may yet announce a start"
                    );
                    match exec.settle_descent(&out.stderr, true) {
                        DescentSettle::Refused(ExecutorError::SudoRefused { host, reason }) => {
                            assert_eq!(host, run_host);
                            assert_eq!(reason, run_reason);
                            assert_eq!(reason, "sudo: unknown user clumit-insight");
                        }
                        other => panic!("{who:?}: expected a refusal, got {other:?}"),
                    }
                }
            }

            #[test]
            fn settling_follows_the_sentinel_and_the_transport_limit() {
                let exec = InDaemonExecutor::new("mgmt");
                let sentinel = SUDO_OK_SENTINEL.as_bytes();
                let (head, rest) = sentinel.split_at(sentinel.len() / 2);

                // A sentinel split across two reads.
                let mut read = b"sudo: note\n".to_vec();
                read.extend_from_slice(head);
                assert!(matches!(
                    exec.settle_descent(&read, false),
                    DescentSettle::Pending
                ));
                read.extend_from_slice(rest);
                read.extend_from_slice(b"own");
                assert!(matches!(
                    exec.settle_descent(&read, false),
                    DescentSettle::Started { command_stderr_from } if command_stderr_from == 11 + sentinel.len()
                ));

                // Once started, a marker in the command's own stderr is its own.
                let mut read = sentinel.to_vec();
                read.extend_from_slice(NO_WORKING_DIRECTORY_MARKER.as_bytes());
                assert!(matches!(
                    exec.settle_descent(&read, true),
                    DescentSettle::Started { command_stderr_from } if command_stderr_from == sentinel.len()
                ));

                // The limit itself is not passed.
                let mut read = vec![b'x'; TRANSPORT_STDERR_LIMIT];
                read.extend_from_slice(sentinel);
                assert!(matches!(
                    exec.settle_descent(&read, false),
                    DescentSettle::Started { command_stderr_from }
                        if command_stderr_from == TRANSPORT_STDERR_LIMIT + sentinel.len()
                ));

                // Past the limit with no sentinel, while the stream is open.
                let read = vec![b'x'; TRANSPORT_STDERR_LIMIT + 1];
                assert_refused_with_the_limit(exec.settle_descent(&read, false));

                // A fragment that may still become the sentinel is not counted,
                // and is not the sentinel.
                let mut read = vec![b'x'; TRANSPORT_STDERR_LIMIT];
                read.extend_from_slice(
                    sentinel
                        .get(..sentinel.len() - 1)
                        .expect("the sentinel is longer than one byte"),
                );
                assert!(matches!(
                    exec.settle_descent(&read, false),
                    DescentSettle::Pending
                ));

                // A sentinel arriving past the limit does not excuse what
                // precedes it.
                let mut read = vec![b'x'; TRANSPORT_STDERR_LIMIT + 1];
                read.extend_from_slice(sentinel);
                assert_refused_with_the_limit(exec.settle_descent(&read, false));
            }

            /// Asserts a refusal whose reason is the first
            /// [`TRANSPORT_STDERR_LIMIT`] bytes of a run of `x`.
            fn assert_refused_with_the_limit(settled: DescentSettle) {
                match settled {
                    DescentSettle::Refused(ExecutorError::SudoRefused { host, reason }) => {
                        assert_eq!(host, "mgmt");
                        assert_eq!(reason, "x".repeat(TRANSPORT_STDERR_LIMIT));
                    }
                    other => panic!("expected a refusal, got {other:?}"),
                }
            }

            #[test]
            fn an_invalid_descent_is_refused_before_building() {
                const SECRET: &str = "s3cret-value";
                let dir = tempfile::tempdir().expect("tempdir");
                let exec = daemon(descending_sudo(dir.path()));
                let valid = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: Path::new("/"),
                };
                let who = Descent::Operator(operator());

                for command in ["cat", "bin/cat", "/usr/bin/env=x", ""] {
                    let error = exec
                        .descent_command(who, command, &[], &valid)
                        .expect_err("the command is refused");
                    assert!(
                        matches!(&error, DescentError::InvalidCommand { command: named } if named == command),
                        "{command:?}: got {error:?}"
                    );
                }

                let nul_value = format!("{SECRET}\0{SECRET}");
                let cases: [(&[(&str, &str)], &str); 7] = [
                    (&[("1PATH", SECRET)], "1PATH"),
                    (&[("A-B", SECRET)], "A-B"),
                    (&[("", SECRET)], ""),
                    (&[("A=B", SECRET)], "A=B"),
                    (&[("PÄTH", SECRET)], "PÄTH"),
                    (&[("DUP", SECRET), ("OTHER", "x"), ("DUP", SECRET)], "DUP"),
                    (&[("NUL", nul_value.as_str())], "NUL"),
                ];
                for (env, name) in cases {
                    let profile = DescentProfile {
                        env,
                        cwd: Path::new("/"),
                    };
                    let error = exec
                        .descent_command(who, "/bin/cat", &[], &profile)
                        .expect_err("the environment is refused");
                    assert!(
                        matches!(&error, DescentError::InvalidEnvironment { name: named, .. } if named == name),
                        "{name:?}: got {error:?}"
                    );
                    for text in [error.to_string(), format!("{error:?}")] {
                        assert!(!text.contains(SECRET), "{name:?}: a value leaked: {text}");
                    }
                }

                for cwd in [Path::new("tmp"), Path::new(""), Path::new("/tmp/a\0b")] {
                    let profile = DescentProfile {
                        env: PROFILE_ENV,
                        cwd,
                    };
                    let error = exec
                        .descent_command(who, "/bin/cat", &[], &profile)
                        .expect_err("the directory is refused");
                    assert!(
                        matches!(&error, DescentError::InvalidWorkingDirectory { cwd: named } if named == cwd),
                        "{cwd:?}: got {error:?}"
                    );
                }

                for (uid, gid) in [
                    (0, 1000),
                    (1000, 0),
                    (u32::MAX, 1000),
                    (1000, u32::MAX),
                    (0, 0),
                ] {
                    let error = OperatorIds::new(uid, gid).expect_err("the ids are refused");
                    assert!(
                        matches!(error, DescentError::InvalidOperator { uid: u, gid: g } if u == uid && g == gid),
                        "{uid}:{gid}: got {error:?}"
                    );
                }
                let ids = OperatorIds::new(1000, 1001).expect("valid ids");
                assert_eq!((ids.uid(), ids.gid()), (1000, 1001));
            }

            /// `/proc/<pid>/stat`'s command name, parent pid and process group.
            #[cfg(target_os = "linux")]
            fn stat(pid: u32) -> Option<(String, u32, u32)> {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
                let open = stat.find('(')?;
                let close = stat.rfind(')')?;
                let comm = stat.get(open + 1..close)?.to_string();
                let mut fields = stat.get(close + 1..)?.split_whitespace().skip(1);
                let parent = fields.next()?.parse().ok()?;
                let group = fields.next()?.parse().ok()?;
                Some((comm, parent, group))
            }

            /// Waits for a process named `name` to be `root` or one of its
            /// descendants, and returns its pid.
            ///
            /// Only called while that process blocks reading standard input
            /// the test still holds open, so the state waited for is reached
            /// and then stays.
            #[cfg(target_os = "linux")]
            fn await_descendant(root: u32, name: &str) -> u32 {
                const POLLS: u32 = 1000;
                const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
                let descends = |mut pid: u32| {
                    while pid > 1 {
                        if pid == root {
                            return true;
                        }
                        match stat(pid) {
                            Some((_, ppid, _)) => pid = ppid,
                            None => return false,
                        }
                    }
                    false
                };
                for _ in 0..POLLS {
                    let found = std::fs::read_dir("/proc")
                        .expect("read /proc")
                        .flatten()
                        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
                        .find(|&pid| {
                            stat(pid).is_some_and(|(comm, _, _)| comm == name) && descends(pid)
                        });
                    if let Some(pid) = found {
                        return pid;
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                panic!("no `{name}` appeared under pid {root}");
            }

            /// Spawns `cmd` in a new process group of its own, as the root
            /// caller spawns it into its anchored group, and asserts that the
            /// spawned process — `sudo`, here its stub — and `/bin/cat` beneath
            /// it both report that group, then ends `cat` by closing its
            /// standard input.
            #[cfg(target_os = "linux")]
            fn assert_one_process_group(mut cmd: Command) {
                use std::os::unix::process::CommandExt;

                cmd.process_group(0)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let mut child = spawn_retrying_text_busy(&mut cmd).expect("spawn the descent");
                let group = child.id();
                let cat = await_descendant(group, "cat");
                for pid in [group, cat] {
                    let (comm, _, pgrp) = stat(pid).expect("the process is alive");
                    assert_eq!(pgrp, group, "`{comm}` ({pid}) is in the caller's group");
                }
                drop(child.stdin.take());
                let status = child.wait().expect("wait for the descent");
                assert!(status.success(), "{status:?}");
            }

            #[cfg(target_os = "linux")]
            #[test]
            fn the_descent_stays_in_the_group_it_is_spawned_into() {
                let dir = tempfile::tempdir().expect("tempdir");
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: Path::new("/"),
                };
                for sudo in [staying_sudo(dir.path()), descending_sudo(dir.path())] {
                    let exec = daemon(sudo);
                    for who in both_descents() {
                        assert_one_process_group(
                            exec.descent_command(who, "/bin/cat", &[], &profile)
                                .expect("a valid descent"),
                        );
                    }
                }
            }

            /// Runs the real `sudo`, as root, down to the `nobody` account —
            /// once named as a service account, once by its ids as an
            /// operator — and checks the identity, the environment, the
            /// directory and the process group the command gets.
            ///
            /// Needs root, `sudo`, and a `nobody` account that root may run
            /// as, with its group; CI runs none of that. It also needs no
            /// controlling terminal, as in the systemd service the caller
            /// runs in: under one, `sudo` with `use_pty` — Debian's and
            /// Ubuntu's default — moves the command into a session of its
            /// own. From a terminal, run it as
            /// `setsid -w cargo test -- --ignored descent_through_the_real_sudo`.
            ///
            /// The groups check tells `sudo`'s group-database groups apart
            /// from none at all only when `nobody` belongs to a supplementary
            /// group: stock `nobody` has only its primary group, which a
            /// descent that dropped every supplementary group reports too.
            /// Add one first (`usermod -aG users nobody`) for a run that
            /// shows them arriving.
            #[cfg(target_os = "linux")]
            #[test]
            #[ignore = "runs the real sudo as root to a real account"]
            fn descent_through_the_real_sudo() {
                use std::os::unix::fs::PermissionsExt;

                const ACCOUNT: &str = "nobody";
                assert!(
                    rustix::process::geteuid().is_root(),
                    "this test runs `sudo` as root"
                );
                assert!(
                    std::fs::File::open("/dev/tty").is_err(),
                    "this test runs without a controlling terminal; start it under `setsid -w`"
                );
                let id = |flag: &str| {
                    let out = Command::new("/usr/bin/id")
                        .args([flag, ACCOUNT])
                        .output()
                        .expect("run id");
                    assert!(out.status.success(), "{out:?}");
                    String::from_utf8(out.stdout).expect("utf-8")
                };
                let uid: u32 = id("-u").trim().parse().expect("a uid");
                let gid: u32 = id("-g").trim().parse().expect("a gid");
                let groups = id("-G");
                let dir = tempfile::tempdir().expect("tempdir");
                std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
                    .expect("let the account enter the directory");
                let cwd = real(&dir);
                let profile = DescentProfile {
                    env: PROFILE_ENV,
                    cwd: &cwd,
                };
                let mut expected_env: Vec<String> = PROFILE_ENV
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect();
                expected_env.sort_unstable();
                let exec = InDaemonExecutor::new("real");

                for who in [
                    Descent::Service(ServiceAccount::Fixture(ACCOUNT)),
                    Descent::Operator(OperatorIds::new(uid, gid).expect("nobody is not root")),
                ] {
                    let text = |args: &[&str]| {
                        let (command, args) = args.split_first().expect("a command");
                        String::from_utf8(descended_stdout(&exec, who, command, args, &profile))
                            .expect("utf-8")
                    };
                    assert_eq!(
                        text(&["/usr/bin/id", "-u"]).trim(),
                        uid.to_string(),
                        "{who:?}"
                    );
                    assert_eq!(
                        text(&["/usr/bin/id", "-g"]).trim(),
                        gid.to_string(),
                        "{who:?}"
                    );
                    assert_eq!(text(&["/usr/bin/id", "-G"]), groups, "{who:?}");
                    let mut env: Vec<String> =
                        text(&["/usr/bin/env"]).lines().map(String::from).collect();
                    env.sort_unstable();
                    assert_eq!(env, expected_env, "{who:?}");
                    assert_eq!(
                        text(&["/bin/pwd"]),
                        format!("{}\n", cwd.display()),
                        "{who:?}"
                    );
                    let printed = text(&["/usr/bin/printf", "%s\n", "a b", "$(x)", "-n"]);
                    assert_eq!(printed, "a b\n$(x)\n-n\n", "{who:?}");
                    assert_one_process_group(
                        exec.descent_command(who, "/bin/cat", &[], &profile)
                            .expect("a valid descent"),
                    );
                    eprintln!("{who:?}: uid {uid}, gid {gid}, groups {}", groups.trim());
                }
            }
        }
    }
}
