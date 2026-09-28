//! The long-lived channel behind [`Executor::open_channel`].
//!
//! [`open_started`] spawns a transport — `sudo`, or `ssh` — that runs the
//! command under a [`StartScript`], and returns only once that script has
//! announced the command's start with [`SUDO_OK_SENTINEL`] and been handed
//! standard input. [`open_direct`]
//! spawns a command with nothing in between and returns at once. Either way
//! the caller then owns standard input and standard output, while standard
//! error stays with the [`Channel`] and is drained on a thread of its own for
//! the channel's whole life, so the command never blocks on a full pipe.
//!
//! That thread cannot sit in a blocking `read`: a thread blocked there
//! cannot be cancelled, and a pipe some descendant of the command still holds
//! open would pin it past the channel's end. So, as in [`bounded`], the pipe
//! is non-blocking and waited on with `poll(2)`, together with a wake pipe
//! whose closing tells the thread to stop.
//!
//! [`Executor::open_channel`]: super::Executor::open_channel
//! [`bounded`]: super::bounded

use std::io::{ErrorKind, PipeReader, PipeWriter, Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use aws_lc_rs::rand::SecureRandom;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;

use super::bounded::{
    Deadline, ENV, KILL_GRACE, SUPERVISOR_SHELL, TRANSPORT_STDERR_LIMIT, find, partial_suffix,
    reap_within,
};
use super::{CommandOutput, ExecutorError, RC_MARKER, SUDO_OK_SENTINEL, spawn_retrying_text_busy};

/// How long [`Channel::wait`] waits for standard error to end once the local
/// transport process has exited. A descendant of the command can hold the
/// pipe open indefinitely; past this, what was read is what is returned, and
/// the rest is noted as truncated.
const STDERR_GRACE: Duration = Duration::from_secs(5);
/// The shell a [`StartScript`] runs under, named absolutely so the start
/// depends on no `PATH`.
pub(super) const START_SHELL: &str = SUPERVISOR_SHELL;
/// What opens every [`StartScript`]'s handoff line; the start's own random
/// nonce follows it.
const HANDOFF_PREFIX: &str = "__BOOTLER_STDIN_";
/// What closes every [`StartScript`]'s handoff line.
const HANDOFF_SUFFIX: &str = "__";
/// Random bytes in a handoff line's nonce.
const HANDOFF_NONCE_LEN: usize = 16;
/// Bytes read from standard error per readiness.
const READ_CHUNK: usize = 8192;
/// Bytes at the end of an SSH channel's standard error held back from the
/// command's until the stream ends, because they may be — or hold — the
/// wrapper's exit-status line. Far more than the line itself needs, so that
/// the end of the stream can also explain a missing line.
const STATUS_HOLD: usize = 512;

/// The bounds one [`Executor::open_channel`](super::Executor::open_channel)
/// call opens under.
///
/// There is no `Default`: how long elevation may take and how much of the
/// command's standard error is worth keeping are the caller's decisions about
/// that command, not the executor's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelLimits {
    /// How long the start may take to prove — from spawning the transport to
    /// reading its announcement that the command has started. Where nothing
    /// stands between this process and the command, the start is proven by
    /// the spawn itself and this is unused.
    pub elevation_timeout: Duration,
    /// How many bytes of the command's own standard error are kept for
    /// [`ChannelExit::stderr`]. The rest is read and discarded.
    pub max_stderr: usize,
}

/// How a [`Channel`]'s command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelExit {
    /// The command's own exit code. `None` only where the local transport
    /// process — the command itself for [`Identity::Operator`] on
    /// [`LocalExecutor`], else `sudo` — was ended by a signal; over
    /// [`SshExecutor`] an exit code that did not arrive is
    /// [`ChannelError::ExitUnknown`] instead.
    ///
    /// [`Identity::Operator`]: super::Identity::Operator
    /// [`LocalExecutor`]: super::LocalExecutor
    /// [`SshExecutor`]: super::SshExecutor
    pub code: Option<i32>,
    /// At most [`ChannelLimits::max_stderr`] bytes of the command's own
    /// standard error, from its start: nothing the transport wrote before the
    /// command started, and not the SSH exit-status line.
    pub stderr: Vec<u8>,
    /// Whether standard error held more than [`ChannelExit::stderr`] keeps —
    /// bytes past [`ChannelLimits::max_stderr`] were discarded, or the stream
    /// had not ended within 5 seconds of the transport exiting.
    pub stderr_truncated: bool,
}

/// Errors raised by [`Executor::open_channel`](super::Executor::open_channel)
/// and by the [`Channel`] it returns.
///
/// A type of its own rather than more [`ExecutorError`] variants, for the
/// reason [`RunWithInputError`](super::RunWithInputError) is one: these arise
/// from the channel alone.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// `command` is not an absolute path, or contains `=`, and was refused
    /// before anything was spawned.
    ///
    /// The command runs with an empty environment, so with no `PATH`, and is
    /// started through `env -i` wherever `sudo` or SSH stands in between —
    /// where an operand containing `=` would be read as an assignment.
    #[error("command `{command}` is not an absolute path free of `=`")]
    InvalidCommand {
        /// The command as the caller named it.
        command: String,
    },
    /// The transport had not announced the command's start within
    /// [`ChannelLimits::elevation_timeout`]. It was killed and reaped.
    ///
    /// A `sudo -S` that rejected the password waits for another line rather
    /// than exiting, so a wrong password ends here, its `Sorry, try again.`
    /// in `diagnostic`.
    #[error("host `{host}`: the channel did not start within {timeout:?}: {diagnostic}")]
    ElevationTimedOut {
        /// The host whose transport did not start the command.
        host: String,
        /// The timeout it outlived.
        timeout: Duration,
        /// What the transport wrote on standard error before it was killed.
        diagnostic: String,
    },
    /// The SSH transport ended without reporting the remote command's exit
    /// status, so the command's outcome is not known — the connection was
    /// lost, or `ssh` was ended some other way. An `ssh` that exits
    /// unsuccessfully is this too, whatever its standard error ends with.
    /// Never a guessed code.
    #[error("host `{host}`: the channel's exit status is unknown: {reason}")]
    ExitUnknown {
        /// The host whose command's outcome is unknown.
        host: String,
        /// Why, with the end of what the transport wrote on standard error.
        reason: String,
    },
    /// The executor does not implement
    /// [`Executor::open_channel`](super::Executor::open_channel).
    ///
    /// The trait's default body returns this, and so does
    /// [`InDaemonExecutor`](super::InDaemonExecutor), which keeps it.
    #[error("this executor cannot open a channel")]
    Unsupported,
    /// Spawning, the transport or elevation failed, exactly as
    /// [`Executor::run`](super::Executor::run) reports it.
    #[error(transparent)]
    Executor(#[from] ExecutorError),
}

/// Refuses a command a channel cannot start as named.
pub(super) fn check_command(command: &str) -> Result<(), ChannelError> {
    if super::is_absolute_and_plain(command) {
        Ok(())
    } else {
        Err(ChannelError::InvalidCommand {
            command: command.to_string(),
        })
    }
}

/// The `sh -c` script a channel's command starts under wherever `sudo` or SSH
/// stands in between, with the handoff line of its one start.
///
/// Invoked as `sh -c SCRIPT <command> <args…>`, so the command and every
/// argument arrive positionally and are never spliced into the script text.
///
/// - **It first announces the start** on standard error with
///   [`SUDO_OK_SENTINEL`]: `sudo` has granted it, and has read standard input
///   for the last time.
/// - **It then takes standard input up to its handoff line**, which
///   [`open_started`] writes only once the announcement has arrived, and
///   discards it. Under [`SudoAuth::Password`] the password line comes first
///   on standard input, and a `sudo` that did not ask for it — a `NOPASSWD`
///   rule, or credentials it still has cached — leaves it unread; this is
///   where it goes instead of to the command. A `sudo` that did ask has
///   consumed it, and only the handoff line is left. A shell reads a pipe a
///   byte at a time, so the command's standard input begins exactly after
///   the handoff line, at the caller's first byte.
/// - **It replaces itself with the command**, run through `env -i` with an
///   empty environment. Standard input that ends before the handoff line
///   means the transport broke, and the script exits `1` without starting it.
///
/// The handoff line shares standard input with what precedes it, so it is not
/// a fixed string a password could happen to equal: it carries a nonce of
/// [`HANDOFF_NONCE_LEN`] bytes drawn from the system's secure random source
/// for this start alone.
///
/// [`SudoAuth::Password`]: super::SudoAuth::Password
pub(super) struct StartScript {
    script: String,
    handoff: String,
}

impl StartScript {
    /// Creates the script of one start, with a handoff line of its own.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Spawn`] when the system's random source fails
    /// to draw the handoff line's nonce: without it, nothing can be started
    /// under this script.
    pub(super) fn new() -> Result<Self, ExecutorError> {
        let mut nonce = [0u8; HANDOFF_NONCE_LEN];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ExecutorError::Spawn {
                command: START_SHELL.to_string(),
                source: std::io::Error::other("system random source failed"),
            })?;
        let hex = crate::payload::to_hex(&nonce);
        let handoff = format!("{HANDOFF_PREFIX}{hex}{HANDOFF_SUFFIX}");
        let script = format!(
            "printf '%s' '{SUDO_OK_SENTINEL}' >&2; \
             while IFS= read -r line; do \
             [ \"$line\" = '{handoff}' ] && exec {ENV} -i \"$0\" \"$@\"; \
             done; exit 1"
        );
        Ok(Self { script, handoff })
    }

    /// Returns the script to run as `sh -c SCRIPT <command> <args…>`.
    pub(super) fn script(&self) -> &str {
        &self.script
    }

    /// Returns the line [`open_started`] writes once the start is announced,
    /// newline included.
    fn handoff_line(&self) -> Vec<u8> {
        format!("{}\n", self.handoff).into_bytes()
    }
}

/// What [`open_started`] needs to know beyond the command it spawns.
pub(super) struct Start<'a> {
    /// The script the transport runs the command under.
    pub(super) script: &'a StartScript,
    /// The host the transport reaches, for the errors that name it.
    pub(super) host: &'a str,
    /// The line to write on standard input before anything else — `sudo -S`'s
    /// password — or `None`.
    pub(super) password_line: Option<Vec<u8>>,
    /// Whether the transport appends the SSH wrapper's exit-status line.
    pub(super) remote_code: bool,
    /// The caller's limits.
    pub(super) limits: ChannelLimits,
}

/// Spawns `command` — a transport running the command under `start.script` —
/// and returns the channel once the start is proven.
///
/// The password line, if any, is written first. Standard error is then read,
/// and standard output never, until [`SUDO_OK_SENTINEL`] arrives; what follows
/// it is the command's. The script's handoff line is written then, so that
/// standard input passes to the caller with nothing ahead of the caller's
/// bytes. A transport that ends first, or writes more than
/// [`TRANSPORT_STDERR_LIMIT`] ahead of the sentinel, is killed and reaped,
/// and what it wrote ahead of the sentinel is handed to `refusal` to be
/// classified as [`Executor::run`](super::Executor::run) classifies it. One
/// that does neither within the elevation timeout is killed and reaped too.
///
/// # Errors
///
/// Returns [`ChannelError::ElevationTimedOut`] for a start that did not prove
/// itself in time, [`ChannelError::Executor`] carrying `refusal`'s error for
/// one that failed, and [`ExecutorError::Spawn`] when the transport cannot be
/// spawned or its pipes fail.
pub(super) fn open_started(
    mut command: Command,
    start: &Start<'_>,
    refusal: impl FnOnce(CommandOutput) -> ExecutorError,
) -> Result<Channel, ChannelError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut spawned = spawn(&mut command, &program)?;
    let settled = settle_start(
        &mut spawned.stdin,
        &mut spawned.stderr,
        start.password_line.as_deref(),
        start.limits.elevation_timeout,
    )
    .and_then(|settled| {
        if matches!(settled, Settled::Started(_)) {
            hand_off(&mut spawned.stdin, &start.script.handoff_line())?;
        }
        Ok(settled)
    });
    let started = match settled {
        Ok(Settled::Started(started)) => started,
        Ok(Settled::Ended(stderr)) => {
            let _ = kill_and_reap(&mut spawned.child);
            return Err(refusal(CommandOutput {
                code: None,
                stdout: Vec::new(),
                stderr,
            })
            .into());
        }
        Ok(Settled::TimedOut(stderr)) => {
            let _ = kill_and_reap(&mut spawned.child);
            return Err(ChannelError::ElevationTimedOut {
                host: start.host.to_string(),
                timeout: start.limits.elevation_timeout,
                diagnostic: String::from_utf8_lossy(&stderr).trim().to_string(),
            });
        }
        Err(source) => {
            let _ = kill_and_reap(&mut spawned.child);
            return Err(spawn_failed(&program, source));
        }
    };
    Channel::assemble(
        spawned,
        started,
        start.limits.max_stderr,
        start.remote_code.then(|| start.host.to_string()),
        program,
    )
}

/// Spawns `command` with nothing standing between this process and it, and
/// returns its channel at once: the spawn is the start.
///
/// The caller has already set the command's environment.
///
/// # Errors
///
/// Returns [`ExecutorError::Spawn`] when the command cannot be spawned or its
/// standard error cannot be drained.
pub(super) fn open_direct(
    mut command: Command,
    max_stderr: usize,
) -> Result<Channel, ChannelError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let spawned = spawn(&mut command, &program)?;
    Channel::assemble(spawned, Vec::new(), max_stderr, None, program)
}

/// A spawned transport and its three pipes.
struct Spawned {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

/// Spawns `command` with all three streams piped, in the caller's process
/// group, and takes the pipes.
fn spawn(command: &mut Command, program: &str) -> Result<Spawned, ChannelError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child =
        spawn_retrying_text_busy(command).map_err(|source| spawn_failed(program, source))?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = kill_and_reap(&mut child);
        return Err(spawn_failed(
            program,
            std::io::Error::other("a standard stream was not piped"),
        ));
    };
    Ok(Spawned {
        child,
        stdin,
        stdout,
        stderr,
    })
}

fn spawn_failed(program: &str, source: std::io::Error) -> ChannelError {
    ChannelError::Executor(ExecutorError::Spawn {
        command: program.to_string(),
        source,
    })
}

/// How the start of a channel settled.
enum Settled {
    /// The start was announced; these bytes followed the announcement and are
    /// the command's.
    Started(Vec<u8>),
    /// The transport's standard error ended, or passed
    /// [`TRANSPORT_STDERR_LIMIT`], before the announcement: all of it up to
    /// the announcement.
    Ended(Vec<u8>),
    /// The elevation timeout passed first, with what had been written by then.
    TimedOut(Vec<u8>),
}

/// Writes `password` and reads standard error until the start is announced,
/// the transport gives up, or `timeout` passes. Standard output is not read.
///
/// Standard input is non-blocking only while the password is written, so a
/// transport that never reads it cannot hold the start past `timeout`; the
/// caller writes to it with ordinary blocking writes afterwards.
fn settle_start(
    stdin: &mut ChildStdin,
    stderr: &mut ChildStderr,
    password: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<Settled> {
    rustix::io::ioctl_fionbio(&*stderr, true)?;
    let Some(password) = password else {
        return feed_and_settle(stdin, stderr, b"", timeout);
    };
    rustix::io::ioctl_fionbio(&*stdin, true)?;
    let settled = feed_and_settle(stdin, stderr, password, timeout)?;
    rustix::io::ioctl_fionbio(&*stdin, false)?;
    Ok(settled)
}

/// [`settle_start`]'s loop, over pipes already made non-blocking.
fn feed_and_settle(
    stdin: &mut ChildStdin,
    stderr: &mut ChildStderr,
    unwritten: &[u8],
    timeout: Duration,
) -> std::io::Result<Settled> {
    let deadline = Deadline::after(timeout);
    let mut written = 0;
    let mut read = Vec::new();
    let mut chunk = vec![0; READ_CHUNK];
    loop {
        if let Some(settled) = judge(&mut read, written >= unwritten.len()) {
            return Ok(settled);
        }
        let Some(left) = deadline.remaining() else {
            return Ok(Settled::TimedOut(read));
        };
        // A time left too large for a `timespec` is no bound at all.
        let wait = Timespec::try_from(left).ok();
        let feeding = written < unwritten.len();
        let (err_ready, in_ready) = {
            let mut fds = vec![PollFd::new(&*stderr, PollFlags::IN)];
            if feeding {
                fds.push(PollFd::new(&*stdin, PollFlags::OUT));
            }
            match rustix::event::poll(&mut fds, wait.as_ref()) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(errno.into()),
            }
            // A hang-up or an error is readiness too: the read or write it
            // wakes reports what happened.
            let ready = |index: usize| fds.get(index).is_some_and(|fd| !fd.revents().is_empty());
            (ready(0), ready(1))
        };
        if in_ready {
            match stdin.write(unwritten.get(written..).unwrap_or_default()) {
                Ok(count) => written += count,
                Err(error) if is_transient(&error) => {}
                // The transport closed its standard input without reading
                // the password; what it wrote on standard error says why.
                Err(error) if error.kind() == ErrorKind::BrokenPipe => written = unwritten.len(),
                Err(error) => return Err(error),
            }
        }
        if err_ready {
            match stderr.read(&mut chunk) {
                Ok(0) => return Ok(Settled::Ended(read)),
                Ok(count) => read.extend_from_slice(chunk.get(..count).unwrap_or_default()),
                Err(error) if is_transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// Returns what the standard error `read` so far says of the start, or `None`
/// while it is still undecided. `fed` is whether the password line, if any,
/// has been written in full.
///
/// What precedes the sentinel is the transport's, and is held to
/// [`TRANSPORT_STDERR_LIMIT`] wherever the sentinel lands — in the same read
/// that passes the limit included. Before the sentinel has arrived, only a
/// trailing fragment that may still grow into it is not yet counted.
fn judge(read: &mut Vec<u8>, fed: bool) -> Option<Settled> {
    match announcement(read) {
        Announcement::Overran(transport) => {
            read.truncate(transport);
            Some(Settled::Ended(std::mem::take(read)))
        }
        // A password `sudo` did not read is still written in full first, so
        // that the start script can discard it as one whole line.
        Announcement::Started(from) if fed => Some(Settled::Started(read.split_off(from))),
        Announcement::Started(_) | Announcement::Undecided => None,
    }
}

/// Where standard error read so far places a start's [`SUDO_OK_SENTINEL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Announcement {
    /// The sentinel arrived within [`TRANSPORT_STDERR_LIMIT`]; the command's
    /// own bytes begin at this offset, just past it.
    Started(usize),
    /// The transport wrote more than [`TRANSPORT_STDERR_LIMIT`] ahead of the
    /// sentinel, whether or not the sentinel has arrived since. The
    /// transport's bytes are the first this many.
    Overran(usize),
    /// Neither yet.
    Undecided,
}

/// Returns what the standard error `read` so far says of a start announced
/// with [`SUDO_OK_SENTINEL`]: the one rule every start through `sudo` or SSH
/// is settled by, whoever reads the stream.
///
/// What precedes the sentinel is the transport's, and is held to
/// [`TRANSPORT_STDERR_LIMIT`] wherever the sentinel lands — in the same read
/// that passes the limit included. Before the sentinel has arrived, only a
/// trailing fragment that may still grow into it is not yet counted, and such
/// a fragment is never taken for the sentinel itself.
pub(super) fn announcement(read: &[u8]) -> Announcement {
    let sentinel = SUDO_OK_SENTINEL.as_bytes();
    match find(read, sentinel) {
        Some(at) if at > TRANSPORT_STDERR_LIMIT => Announcement::Overran(at),
        Some(at) => Announcement::Started(at + sentinel.len()),
        None if read.len() - partial_suffix(read, sentinel) > TRANSPORT_STDERR_LIMIT => {
            Announcement::Overran(read.len())
        }
        None => Announcement::Undecided,
    }
}

/// Writes the start script's handoff line, after which standard input is the
/// caller's.
///
/// Nothing is left in the pipe but, at most, a password line `sudo` did not
/// read, so the line fits and the write does not block. A transport that has
/// closed standard input since announcing the start is not a failure here:
/// [`Channel::wait`] reports how it ended.
fn hand_off(stdin: &mut ChildStdin, line: &[u8]) -> std::io::Result<()> {
    match stdin.write_all(line) {
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(()),
        written => written,
    }
}

/// Reports whether an I/O error only means "not now".
fn is_transient(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

/// `SIGKILL`s `child` — the process alone, never its group, which is the
/// caller's — and reaps it. A child this process may not signal is given
/// [`KILL_GRACE`] to exit on its own rather than waited on without bound.
fn kill_and_reap(child: &mut Child) -> std::io::Result<()> {
    match child.kill() {
        Ok(()) => child.wait().map(drop),
        Err(error) => {
            reap_within(child, KILL_GRACE);
            Err(error)
        }
    }
}

/// A long-lived command started by
/// [`Executor::open_channel`](super::Executor::open_channel), with its
/// standard input and standard output for the caller to take and standard
/// error drained for it.
///
/// Bytes pass verbatim both ways, with no size or time bound from this crate.
/// The channel ends by [`Channel::wait`] or [`Channel::kill`]; one dropped
/// without either is killed as [`Channel::kill`] kills it.
///
/// **What a kill reaches is limited.** It `SIGKILL`s the local transport
/// process — the command itself for [`Identity::Operator`] on
/// [`LocalExecutor`], else `sudo` or `ssh` — and reaps it. A command started
/// through `sudo` or over SSH is not signalled: it learns of the end only by
/// end of file on its standard input and `EPIPE` on its standard output.
/// Descendants of the command are not tracked on any transport. Whatever
/// survives is the caller's to contain.
///
/// [`Identity::Operator`]: super::Identity::Operator
/// [`LocalExecutor`]: super::LocalExecutor
#[derive(Debug)]
pub struct Channel {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    drain: Option<Drain>,
    /// The host an SSH channel reaches, whose exit code arrives in the
    /// exit-status line; `None` where the local transport's status is the
    /// code.
    remote_host: Option<String>,
    program: String,
    /// Whether [`Channel::wait`] or [`Channel::kill`] has ended the channel,
    /// so dropping it has nothing left to do.
    ended: bool,
}

impl Channel {
    /// Starts draining the spawned transport's standard error, whose first
    /// bytes past the start are `first`, and assembles the channel. The
    /// transport is killed and reaped if the drain cannot start.
    fn assemble(
        spawned: Spawned,
        first: Vec<u8>,
        max_stderr: usize,
        remote_host: Option<String>,
        program: String,
    ) -> Result<Self, ChannelError> {
        let Spawned {
            mut child,
            stdin,
            stdout,
            stderr,
        } = spawned;
        let hold = if remote_host.is_some() {
            STATUS_HOLD
        } else {
            0
        };
        match Drain::start(stderr, first, Sink::new(max_stderr, hold)) {
            Ok(drain) => Ok(Self {
                child,
                stdin: Some(stdin),
                stdout: Some(stdout),
                drain: Some(drain),
                remote_host,
                program,
                ended: false,
            }),
            Err(source) => {
                let _ = kill_and_reap(&mut child);
                Err(spawn_failed(&program, source))
            }
        }
    }

    /// Takes the command's standard input. Returns `None` once taken.
    ///
    /// Dropping it closes the pipe, which is how the command learns its input
    /// has ended.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    /// Takes the command's standard output. Returns `None` once taken.
    ///
    /// Until it is taken the channel holds it open and nothing reads it, so a
    /// command that writes more than a pipe holds blocks.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// Waits for the command to end and returns how it ended.
    ///
    /// Standard input is closed first if it was never taken. The local
    /// transport process is then waited for with no time bound, and standard
    /// error for at most 5 seconds more, since a descendant of the command
    /// can hold it open; past that, [`ChannelExit::stderr_truncated`] is set.
    ///
    /// On [`LocalExecutor`](super::LocalExecutor) the code is the local
    /// process's own status, which `sudo` passes the command's through. Over
    /// [`SshExecutor`](super::SshExecutor) it is the remote command's own, read
    /// from the wrapper's exit-status line — a remote `255` included, which
    /// is the command's and never the transport's.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ExitUnknown`] when an SSH channel ended without
    /// its exit-status line, or when `ssh` itself exited unsuccessfully — the
    /// wrapper exits zero once it reports, so a line then is not its — and [`ExecutorError::Spawn`] when waiting for the
    /// transport or reading standard error fails.
    pub fn wait(mut self) -> Result<ChannelExit, ChannelError> {
        self.stdin = None;
        let status = match self.child.wait() {
            Ok(status) => status,
            // Dropping `self` kills and reaps what may still be running.
            Err(source) => return Err(spawn_failed(&self.program, source)),
        };
        self.ended = true;
        let drained = self
            .stop_drain(STDERR_GRACE)
            .map_err(|source| spawn_failed(&self.program, source))?;
        let code = match (&self.remote_host, drained.remote_code) {
            (None, _) => status.code(),
            // The wrapper's last act is printing the line, which exits the
            // remote shell zero, so only a successful `ssh` delivered it: a
            // failed one leaves marker-shaped text the command wrote itself.
            (Some(_), Some(code)) if status.success() => Some(code),
            (Some(host), remote_code) => {
                let ending = if drained.ended {
                    "standard error ended"
                } else {
                    "standard error had not ended 5 seconds later"
                };
                let missing = if remote_code.is_some() {
                    "after standard error ended on an exit-status line the wrapper did not \
                     deliver"
                } else {
                    "without reporting the remote exit status"
                };
                return Err(ChannelError::ExitUnknown {
                    host: host.clone(),
                    reason: format!(
                        "`{}` exited ({status}) {missing}; {ending} with: {}",
                        self.program,
                        String::from_utf8_lossy(&drained.tail).trim()
                    ),
                });
            }
        };
        Ok(ChannelExit {
            code,
            stderr: drained.stderr,
            stderr_truncated: drained.truncated || !drained.ended,
        })
    }

    /// Ends the channel at once: closes the pipe ends it still holds,
    /// `SIGKILL`s the local transport process and reaps it, and stops
    /// draining standard error.
    ///
    /// See the type's documentation for what this does not reach.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Spawn`] when the transport cannot be killed or
    /// reaped — a `sudo` this process may not signal. The drain is stopped
    /// either way.
    pub fn kill(mut self) -> Result<(), ChannelError> {
        self.ended = true;
        self.shut_down()
            .map_err(|source| spawn_failed(&self.program, source))
    }

    /// Closes the held pipes, kills and reaps the transport, and stops and
    /// joins the drain.
    fn shut_down(&mut self) -> std::io::Result<()> {
        self.stdin = None;
        self.stdout = None;
        let killed = kill_and_reap(&mut self.child);
        // Stopped rather than waited for: nothing more is wanted from it,
        // and a drain that panicked has nothing to report here either.
        if let Some(mut drain) = self.drain.take() {
            drain.wake = None;
            let _ = drain.handle.join();
        }
        killed
    }

    /// Gives the drain up to `grace` to reach the end of standard error, then
    /// stops it and joins it.
    fn stop_drain(&mut self, grace: Duration) -> std::io::Result<Drained> {
        let Some(mut drain) = self.drain.take() else {
            return Err(std::io::Error::other("standard error was already drained"));
        };
        // The drain never sends; it hangs up by ending.
        let _: Result<(), RecvTimeoutError> = drain.done.recv_timeout(grace);
        drain.wake = None;
        match drain.handle.join() {
            Ok(drained) => drained,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// Returns the local transport process's id.
    #[cfg(test)]
    pub(super) fn transport_pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.shut_down();
        }
    }
}

/// The thread draining a channel's standard error, and what stops it.
#[derive(Debug)]
struct Drain {
    handle: JoinHandle<std::io::Result<Drained>>,
    /// Dropping this wakes the thread and stops it.
    wake: Option<PipeWriter>,
    /// Hangs up when the thread ends.
    done: mpsc::Receiver<()>,
}

impl Drain {
    fn start(stderr: ChildStderr, first: Vec<u8>, mut sink: Sink) -> std::io::Result<Self> {
        rustix::io::ioctl_fionbio(&stderr, true)?;
        let (asleep, wake) = std::io::pipe()?;
        let (done_tx, done) = mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("channel-stderr".to_string())
            .spawn(move || {
                let _done = done_tx;
                sink.push(&first);
                drain(stderr, &asleep, sink)
            })?;
        Ok(Self {
            handle,
            wake: Some(wake),
            done,
        })
    }
}

/// What a drain read.
#[derive(Debug)]
struct Drained {
    /// The command's own standard error, held to its limit.
    stderr: Vec<u8>,
    /// Whether bytes past the limit were discarded.
    truncated: bool,
    /// Whether standard error reached its end, rather than the drain being
    /// stopped first.
    ended: bool,
    /// The remote exit code, where the stream ended on the exit-status line.
    remote_code: Option<i32>,
    /// The last bytes of the stream, to explain a missing exit-status line.
    tail: Vec<u8>,
}

/// Reads `stderr` into `sink` until it ends or `asleep` is woken.
fn drain(mut stderr: ChildStderr, asleep: &PipeReader, mut sink: Sink) -> std::io::Result<Drained> {
    let mut chunk = vec![0; READ_CHUNK];
    loop {
        let (stop, ready) = {
            let mut fds = [
                PollFd::new(asleep, PollFlags::IN),
                PollFd::new(&stderr, PollFlags::IN),
            ];
            match rustix::event::poll(&mut fds, None) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(errno.into()),
            }
            let [woken, readable] = &fds;
            (!woken.revents().is_empty(), !readable.revents().is_empty())
        };
        // Woken before reading, so a stream that never stops cannot keep the
        // drain from stopping.
        if stop {
            return Ok(sink.finish(false));
        }
        if ready {
            match stderr.read(&mut chunk) {
                Ok(0) => return Ok(sink.finish(true)),
                Ok(count) => sink.push(chunk.get(..count).unwrap_or_default()),
                Err(error) if is_transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// Where the command's standard error goes: kept up to its limit, with a
/// trailing window held back where the exit-status line may end the stream.
struct Sink {
    max: usize,
    kept: Vec<u8>,
    truncated: bool,
    hold: usize,
    held: Vec<u8>,
}

impl Sink {
    fn new(max: usize, hold: usize) -> Self {
        Self {
            max,
            kept: Vec::new(),
            truncated: false,
            hold,
            held: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.hold == 0 {
            self.keep_bytes(bytes);
            return;
        }
        self.held.extend_from_slice(bytes);
        let excess = self.held.len().saturating_sub(self.hold);
        if excess > 0 {
            let rest = self.held.split_off(excess);
            let committed = std::mem::replace(&mut self.held, rest);
            self.keep_bytes(&committed);
        }
    }

    fn keep_bytes(&mut self, bytes: &[u8]) {
        let room = self.max.saturating_sub(self.kept.len());
        let (kept, discarded) = bytes.split_at(room.min(bytes.len()));
        self.kept.extend_from_slice(kept);
        self.truncated |= !discarded.is_empty();
    }

    /// Settles what was held: the exit-status line, where the stream ends on
    /// one, is removed and read; everything else is the command's.
    fn finish(mut self, ended: bool) -> Drained {
        let held = std::mem::take(&mut self.held);
        let (own, remote_code) = match split_status_line(&held) {
            Some((cut, code)) => (held.get(..cut).unwrap_or_default(), Some(code)),
            None => (held.as_slice(), None),
        };
        self.keep_bytes(own);
        Drained {
            stderr: self.kept,
            truncated: self.truncated,
            ended,
            remote_code,
            tail: held,
        }
    }
}

/// Finds the SSH wrapper's exit-status line — an optional newline,
/// [`RC_MARKER`], the code, a newline — at the very end of `tail`, returning
/// where the line starts and the code.
fn split_status_line(tail: &[u8]) -> Option<(usize, i32)> {
    let body = tail.strip_suffix(b"\n")?;
    let marker = RC_MARKER.as_bytes();
    let at = body
        .windows(marker.len())
        .rposition(|window| window == marker)?;
    let digits = body.get(at + marker.len()..)?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let code = std::str::from_utf8(digits).ok()?.parse::<i32>().ok()?;
    let cut = match at.checked_sub(1) {
        Some(before) if body.get(before) == Some(&b'\n') => before,
        _ => at,
    };
    Some((cut, code))
}

#[cfg(test)]
mod tests {
    use super::{
        RC_MARKER, SUDO_OK_SENTINEL, Settled, Sink, TRANSPORT_STDERR_LIMIT, judge,
        split_status_line,
    };

    /// `before` bytes of the transport's, then `after`.
    fn preamble(before: usize, after: &str) -> Vec<u8> {
        let mut read = vec![b'x'; before];
        read.extend_from_slice(after.as_bytes());
        read
    }

    #[test]
    fn the_transport_limit_holds_wherever_the_sentinel_lands() {
        let mut read = preamble(TRANSPORT_STDERR_LIMIT, &format!("{SUDO_OK_SENTINEL}own"));
        assert!(
            matches!(judge(&mut read, true), Some(Settled::Started(own)) if own == b"own"),
            "the limit itself is not passed"
        );

        // The sentinel arriving in the read that passes the limit does not
        // excuse what precedes it.
        let mut read = preamble(
            TRANSPORT_STDERR_LIMIT + 1,
            &format!("{SUDO_OK_SENTINEL}own"),
        );
        assert!(
            matches!(judge(&mut read, true),
                Some(Settled::Ended(ended)) if ended == vec![b'x'; TRANSPORT_STDERR_LIMIT + 1]),
            "only the transport's bytes are kept for classification"
        );

        let mut read = preamble(TRANSPORT_STDERR_LIMIT + 1, "");
        assert!(matches!(judge(&mut read, true), Some(Settled::Ended(_))));

        // A fragment that may still become the sentinel is not yet counted.
        let fragment = SUDO_OK_SENTINEL
            .get(..SUDO_OK_SENTINEL.len() - 1)
            .expect("the sentinel is longer than one byte");
        let mut read = preamble(TRANSPORT_STDERR_LIMIT, fragment);
        assert!(judge(&mut read, true).is_none());
    }

    #[test]
    fn the_start_waits_for_the_password_to_be_written_in_full() {
        let mut read = preamble(0, SUDO_OK_SENTINEL);
        assert!(judge(&mut read, false).is_none());
        assert!(matches!(judge(&mut read, true), Some(Settled::Started(own)) if own.is_empty()));
    }

    #[test]
    fn the_status_line_is_read_only_at_the_end_of_the_stream() {
        let line = format!("own\n{RC_MARKER}255\n");
        assert_eq!(split_status_line(line.as_bytes()), Some((3, 255)));
        let line = format!("{RC_MARKER}0\n");
        assert_eq!(split_status_line(line.as_bytes()), Some((0, 0)));
        let line = format!("\n{RC_MARKER}3\nmore");
        assert_eq!(split_status_line(line.as_bytes()), None);
        let line = format!("\n{RC_MARKER}\n");
        assert_eq!(split_status_line(line.as_bytes()), None);
        let line = format!("\n{RC_MARKER}3");
        assert_eq!(split_status_line(line.as_bytes()), None);
    }

    #[test]
    fn a_sink_keeps_its_limit_and_removes_the_status_line() {
        let mut sink = Sink::new(4, 32);
        sink.push(b"abcdefghabcdefghabcdefghabcdefgh");
        sink.push(format!("ij\n{RC_MARKER}7\n").as_bytes());
        let drained = sink.finish(true);
        assert_eq!(drained.stderr, b"abcd");
        assert!(drained.truncated);
        assert_eq!(drained.remote_code, Some(7));

        let mut sink = Sink::new(16, 64);
        sink.push(format!("ab\n{RC_MARKER}1").as_bytes());
        sink.push(b"2\n");
        let drained = sink.finish(true);
        assert_eq!(drained.stderr, b"ab");
        assert!(!drained.truncated);
        assert_eq!(drained.remote_code, Some(12));

        let mut sink = Sink::new(2, 0);
        sink.push(b"ab");
        let drained = sink.finish(true);
        assert_eq!(drained.stderr, b"ab");
        assert!(!drained.truncated, "reaching the limit is not passing it");
    }
}
