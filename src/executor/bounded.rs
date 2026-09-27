//! The bounded, killable run behind [`Executor::run_with_input`].
//!
//! [`run`] is the engine every transport drives: it feeds the child's standard
//! input, reads its standard output and standard error each up to a limit, and
//! kills the child at a deadline. It is one thread multiplexing three pipes
//! through `poll(2)` rather than a thread per pipe, because a thread blocked in
//! `read` cannot be cancelled: a pipe some descendant of a killed child still
//! holds open would pin that thread, and the caller's scope with it. Here the
//! pipes are non-blocking and are simply dropped once the run is decided.
//!
//! What the engine cannot do by itself is reach a process it may not signal —
//! a command `sudo` started as root, or one running on the far side of an SSH
//! connection. Those transports run the command under a [`Supervisor`], which
//! kills the command's process group from inside, on the relayed signal and on
//! a deadline of its own.
//!
//! [`Executor::run_with_input`]: super::Executor::run_with_input

use std::io::{ErrorKind, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aws_lc_rs::rand::SecureRandom;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

use super::{
    CommandOutput, ExecutorError, OutputStream, RC_MARKER, RunLimits, RunWithInputError,
    SUDO_OK_SENTINEL, spawn_retrying_text_busy,
};

/// Bytes read from one output pipe per readiness.
const READ_CHUNK: usize = 8192;
/// Interval at which the exit of a child whose pipes have all closed is polled.
/// `std` offers no timed wait on a child, and the pipes, the only thing
/// `poll(2)` can wait on, are gone by then.
const EXIT_POLL: Duration = Duration::from_millis(5);
/// How long a supervised child is given to die after the terminating signal
/// is relayed to it, before its process group is killed outright.
const RELAY_GRACE: Duration = Duration::from_secs(5);
/// How long a child is given to be reaped after `SIGKILL` reached its group.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// What opens every [`Supervisor`]'s timeout marker; the run's own random
/// nonce follows it.
const TIMEOUT_MARKER_PREFIX: &str = "__BOOTLER_TIMEOUT_";
/// What closes every [`Supervisor`]'s timeout marker.
const TIMEOUT_MARKER_SUFFIX: &str = "__";
/// Random bytes in a timeout marker's nonce.
const TIMEOUT_NONCE_LEN: usize = 16;
/// The most stderr a supervised run's transport may write before the command
/// starts — `sudo`'s refusal, `ssh`'s connection diagnostic. None of it is the
/// command's, so `max_stderr` does not bound it; this does, so that memory
/// stays bounded while the transport fails. Real diagnostics are a line or
/// two.
const TRANSPORT_STDERR_LIMIT: usize = 64 * 1024;
/// The shell a [`Supervisor`] script runs under, named absolutely so the
/// invocation depends on no `PATH`.
pub(super) const SUPERVISOR_SHELL: &str = "/bin/sh";
/// The `env` the supervisor clears the command's environment with. Its path is
/// the one fixed location both Linux and macOS guarantee.
const ENV: &str = "/usr/bin/env";
/// The `sleep` the supervisor's deadline runs, named absolutely for the same
/// reason: one `PATH` could not resolve would exit at once, and the script
/// would lose its deadline exactly as it would to a `sleep` that refused it.
const SLEEP: &str = "/bin/sleep";
/// The longest deadline a [`Supervisor`] script hands `sleep`, `i32::MAX`
/// seconds — some 68 years, which is no bound in practice. macOS's `sleep`
/// refuses anything longer and exits at once, which the script would read as
/// the command's deadline never arriving: the backstop would be gone, and the
/// cancelling `kill` would be sent to a pid already reaped and free for reuse.
const MAX_SLEEP_SECS: u64 = 2_147_483_647;

/// How a run that must stop early stops its child.
#[derive(Debug, Clone, Copy)]
pub(super) enum Kill {
    /// `SIGKILL` the child's process group at once. Right where every process
    /// in the group is this process's to signal: a command spawned directly,
    /// and the local half of an SSH connection.
    Group,
    /// `SIGTERM` the child alone, give it [`RELAY_GRACE`] to die, then
    /// `SIGKILL` its group. Right where the child is `sudo`: `sudo` relays the
    /// `SIGTERM` to the [`Supervisor`], which kills the command from the
    /// inside, and this process may not be able to signal the command at all.
    Relay,
}

/// What the invocation itself writes on stderr around the command's own
/// bytes, so the stderr limit is held against the command and not against the
/// transport.
#[derive(Debug, Clone, Copy)]
pub(super) struct Framing<'a> {
    /// The run's timeout marker where a [`Supervisor`] runs the command. The
    /// supervisor prints [`SUDO_OK_SENTINEL`] before it starts the command,
    /// so whatever precedes the sentinel is the transport's, and the marker
    /// may follow the command's bytes.
    pub(super) timeout_marker: Option<&'a str>,
    /// The SSH wrapper appends the remote exit status after [`RC_MARKER`].
    pub(super) remote_code: bool,
}

/// Whose stderr a supervised run has written so far.
#[derive(Debug, PartialEq, Eq)]
enum Attributed {
    /// The command has not started; this many bytes are the transport's.
    Transport(usize),
    /// The command has started and has written this many bytes of its own.
    Command(usize),
}

impl Framing<'static> {
    /// A command spawned directly: every byte on stderr is its own.
    pub(super) const DIRECT: Self = Self {
        timeout_marker: None,
        remote_code: false,
    };
}

impl Framing<'_> {
    /// Attributes the bytes of `stderr` read so far.
    ///
    /// Until [`SUDO_OK_SENTINEL`] has arrived, nothing on a supervised run's
    /// stderr is the command's: it is `sudo` refusing, `ssh` failing to
    /// connect, or the sentinel itself still arriving, and it is left for the
    /// transport's failure to be classified exactly as
    /// [`Executor::run`](super::Executor::run) classifies it. After the
    /// sentinel, a timeout marker already seen in full is discounted, and so
    /// is a trailing fragment that may still grow into it or into the
    /// exit-status line — a stream is read in chunks, and a marker split
    /// across two of them must not count against the limit while only its
    /// first half has arrived. Nothing else is discounted, so a command that
    /// writes one byte past its limit is caught at that byte.
    fn attribute(self, stderr: &[u8]) -> Attributed {
        let Some(marker) = self.timeout_marker else {
            return Attributed::Command(stderr.len());
        };
        let Some(at) = find(stderr, SUDO_OK_SENTINEL.as_bytes()) else {
            return Attributed::Transport(stderr.len());
        };
        let tail = stderr
            .get(at + SUDO_OK_SENTINEL.len()..)
            .unwrap_or_default();
        let mut framing = 0;
        let mut pending = 0;
        if find(tail, marker.as_bytes()).is_some() {
            framing += marker.len();
        } else {
            pending = partial_suffix(tail, marker.as_bytes());
        }
        if self.remote_code {
            pending = pending.max(remote_code_suffix(tail));
        }
        Attributed::Command(tail.len().saturating_sub(framing + pending))
    }
}

/// How the engine's run ended.
#[derive(Debug)]
pub(super) enum Ended {
    /// The child exited, or was killed by something other than this run, with
    /// its output captured raw — any transport framing is still in it.
    Exited(CommandOutput),
    /// The transport wrote more than [`TRANSPORT_STDERR_LIMIT`] before the
    /// command started, and the child was killed. What it wrote is kept raw,
    /// so the failure is classified as an exit would be.
    Abandoned(CommandOutput),
    /// A stream passed its limit and the child was killed.
    Breach(OutputStream),
    /// The deadline passed and the child was killed.
    TimedOut,
}

/// The `sh -c` script that supervises a command on a transport this process
/// cannot signal the command through, with the timeout marker of its one run.
///
/// Invoked as `sh -c SCRIPT <command> <args…>`, so the command and every
/// argument arrive positionally and are never spliced into the script text.
///
/// - **It first prints [`SUDO_OK_SENTINEL`]**, so a `sudo` that refused is
///   told apart from a command that failed exactly as
///   [`Executor::run`](super::Executor::run) tells them apart, and so what the
///   transport wrote before the command started is never counted as the
///   command's. It prints it on every transport, `sudo` or not: over SSH it
///   is also where `ssh`'s own diagnostics end.
///
/// - **The environment is cleared.** The command is started through
///   `env -i`, so nothing `sudo`'s environment reset or the SSH session put
///   back reaches it — no variable at all, and so no `PATH` either.
/// - **Only the command writes to standard error.** The script keeps the
///   real standard error aside for the command and for its timeout marker,
///   and points its own at `/dev/null`: a shell reports a job a signal killed
///   — bash prints `Killed: 9` for the cancelled `sleep` below — and that
///   report is not the command's output.
/// - **Standard input is handed to the command.** A shell gives a command it
///   runs in the background `/dev/null` unless told otherwise, so the script
///   moves its standard input aside and redirects it back onto the command
///   explicitly.
/// - **The command runs in the background of the script**, because a shell
///   runs a trap only once the foreground command it is waiting on returns,
///   and a command that ignores `SIGTERM` never would. `wait` is interrupted
///   by a trapped signal, so the trap fires at once.
/// - **`SIGTERM`, `SIGHUP` and `SIGINT` kill the whole process group** with
///   `SIGKILL`. This is what `sudo` relays [`Kill::Relay`]'s `SIGTERM` to, and
///   the group is the command and all of its descendants that did not leave
///   it.
/// - **The deadline is enforced from the inside too**: a `sleep` of
///   `timeout`, rounded up to a whole second, started before the command.
///   The script waits on it; the subshell running the command kills it with
///   `SIGKILL` the moment the command exits. A `sleep` that ran out means the
///   deadline passed first, and the script prints its timeout marker and
///   kills the group. This is what ends the command on the far side of an SSH
///   connection, which a signal to the local `ssh` never reaches, and it is
///   the backstop wherever the relay fails to arrive.
///
///   The cancellation is `SIGKILL` to a process that is nothing but `sleep`
///   deliberately. A cancelling `SIGTERM` to a subshell can be lost: one that
///   arrives after the fork but before the subshell has installed its own
///   trap is dropped by some shells, dash among them, and the deadline would
///   then fire over a command that finished long before. `SIGKILL` passes
///   through no trap, and `sleep`'s pid cannot be reused while it waits
///   unreaped for the script's `wait`.
///
/// The timeout marker shares standard error with the command, so it is not a
/// fixed string a command could happen to print: it carries a nonce of
/// [`TIMEOUT_NONCE_LEN`] bytes drawn from the system's secure random source
/// for this run alone. A command could find it only by reading its
/// supervisor's arguments on purpose, and all that would win it is being
/// reported as timed out — which it could as well have had by not exiting.
///
/// Two things differ from a command run directly. A command a signal killed
/// reports `128 + signal` rather than no exit code, since the script exits
/// with the status its subshell returned; and a command started in the
/// background of a shell without job control starts with `SIGINT` and
/// `SIGQUIT` ignored.
pub(super) struct Supervisor {
    script: String,
    timeout_marker: String,
}

impl Supervisor {
    /// Creates the supervisor of one run held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Spawn`] when the system's random source fails
    /// to draw the timeout marker's nonce: without it, nothing can be spawned
    /// under this supervisor.
    pub(super) fn new(timeout: Duration) -> Result<Self, ExecutorError> {
        let mut nonce = [0u8; TIMEOUT_NONCE_LEN];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ExecutorError::Spawn {
                command: SUPERVISOR_SHELL.to_string(),
                source: std::io::Error::other("system random source failed"),
            })?;
        let hex = crate::payload::to_hex(&nonce);
        let timeout_marker = format!("{TIMEOUT_MARKER_PREFIX}{hex}{TIMEOUT_MARKER_SUFFIX}");
        Ok(Self {
            script: script(&timeout_marker, timeout),
            timeout_marker,
        })
    }

    /// Returns the script to run as `sh -c SCRIPT <command> <args…>`.
    pub(super) fn script(&self) -> &str {
        &self.script
    }

    /// Returns the marker this supervisor prints at its own deadline.
    #[cfg(test)]
    pub(super) fn timeout_marker(&self) -> &str {
        &self.timeout_marker
    }

    /// Returns the stderr framing of a run under this supervisor, with the
    /// SSH wrapper's exit-status line after it where `remote_code`.
    pub(super) fn framing(&self, remote_code: bool) -> Framing<'_> {
        Framing {
            timeout_marker: Some(&self.timeout_marker),
            remote_code,
        }
    }
}

/// Returns a [`Supervisor`]'s script, printing `timeout_marker` at a deadline
/// of `timeout` rounded up to a whole second.
fn script(timeout_marker: &str, timeout: Duration) -> String {
    let seconds = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0))
        .min(MAX_SLEEP_SECS);
    format!(
        r#"trap 'kill -KILL 0' TERM HUP INT
printf '%s' '{SUDO_OK_SENTINEL}' >&2
exec 3<&0 0</dev/null 4>&2 2>/dev/null
{SLEEP} {seconds} </dev/null >/dev/null 3<&- 4>&- &
nap=$!
{{
  {ENV} -i "$0" "$@" 2>&4 4>&-
  status=$?
  kill -KILL "$nap"
  exit "$status"
}} 0<&3 3<&- &
run=$!
exec 3<&-
if wait "$nap"; then
  printf '%s' '{timeout_marker}' >&4
  kill -KILL 0
fi
wait "$run""#
    )
}

/// Runs `command` to completion under `limits`, feeding it `feed` on stdin.
///
/// The child is placed in a process group of its own, so that killing it
/// reaches every descendant that did not leave the group, and so that a
/// supervisor's `kill 0` can never reach this process. `program` names the
/// binary for error reporting.
///
/// A stream passing its limit — stderr attributed by `framing` — or the deadline
/// passing kills the child by `kill` and waits for it; neither is an error
/// here, but an [`Ended`] the caller turns into one.
///
/// # Errors
///
/// Returns [`ExecutorError::Spawn`] when the child cannot be spawned, or when
/// feeding or reading it fails for a reason other than the child going away;
/// the child is killed first.
pub(super) fn run(
    mut command: Command,
    program: &str,
    feed: &[u8],
    limits: RunLimits,
    framing: Framing<'_>,
    kill: Kill,
) -> Result<Ended, ExecutorError> {
    let failed = |source: std::io::Error| ExecutorError::Spawn {
        command: program.to_string(),
        source,
    };
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = spawn_retrying_text_busy(&mut command).map_err(failed)?;
    let deadline = Deadline::after(limits.timeout);
    let mut pipes = Pipes {
        stdin: child.stdin.take(),
        stdout: child.stdout.take(),
        stderr: child.stderr.take(),
    };
    if let Err(source) = pipes.set_nonblocking() {
        terminate(&mut child, kill);
        return Err(failed(source));
    }
    if feed.is_empty() {
        pipes.stdin = None;
    }
    let pumped = pump(&mut pipes, feed, limits, framing, &deadline);
    drop(pipes);
    match pumped {
        Ok(Pumped::Closed { stdout, stderr }) => {
            await_exit(child, kill, &deadline, stdout, stderr).map_err(failed)
        }
        Ok(Pumped::Stopped(ended)) => {
            terminate(&mut child, kill);
            Ok(ended)
        }
        Err(source) => {
            terminate(&mut child, kill);
            Err(failed(source))
        }
    }
}

/// The child's three pipes, each dropped — closed — once it is finished with.
struct Pipes {
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
}

impl Pipes {
    /// Makes every pipe non-blocking, so a read or a write never waits past
    /// what `poll(2)` reported ready and the deadline is always observed.
    fn set_nonblocking(&self) -> std::io::Result<()> {
        if let Some(pipe) = &self.stdin {
            rustix::io::ioctl_fionbio(pipe, true)?;
        }
        if let Some(pipe) = &self.stdout {
            rustix::io::ioctl_fionbio(pipe, true)?;
        }
        if let Some(pipe) = &self.stderr {
            rustix::io::ioctl_fionbio(pipe, true)?;
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.stdin.is_none() && self.stdout.is_none() && self.stderr.is_none()
    }
}

/// What [`pump`] stopped on.
enum Pumped {
    /// Every pipe closed, with what the child wrote on the two it reads.
    Closed { stdout: Vec<u8>, stderr: Vec<u8> },
    /// The run must stop early; only an [`Ended::Abandoned`] returns what it
    /// captured.
    Stopped(Ended),
}

/// Moves bytes until every pipe has closed or the run must stop early.
///
/// The stderr limit is held against what [`Framing::attribute`] credits to the
/// command; what the transport writes before the command starts is held to
/// [`TRANSPORT_STDERR_LIMIT`] instead, and passing that abandons the run with
/// the transport's output kept for classification.
fn pump(
    pipes: &mut Pipes,
    feed: &[u8],
    limits: RunLimits,
    framing: Framing<'_>,
    deadline: &Deadline,
) -> std::io::Result<Pumped> {
    let mut written = 0;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut chunk = vec![0; READ_CHUNK];
    while !pipes.is_empty() {
        let Some(left) = deadline.remaining() else {
            return Ok(Pumped::Stopped(Ended::TimedOut));
        };
        // A time left too large for a `timespec` is no bound at all.
        let timeout = Timespec::try_from(left).ok();
        let ready = match wait_ready(pipes, timeout.as_ref()) {
            Ok(ready) => ready,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno.into()),
        };
        if ready.stdin
            && let Some(pipe) = &mut pipes.stdin
        {
            match pipe.write(feed.get(written..).unwrap_or_default()) {
                Ok(count) => {
                    written += count;
                    if written >= feed.len() {
                        pipes.stdin = None;
                    }
                }
                Err(error) if is_transient(&error) => {}
                // The child closed its stdin without reading all of it —
                // `sudo` refusing, or a command that needed less. What it
                // wrote carries the story, so this is not a failure.
                Err(error) if error.kind() == ErrorKind::BrokenPipe => pipes.stdin = None,
                Err(error) => return Err(error),
            }
        }
        if ready.stdout && drain(&mut pipes.stdout, &mut stdout, &mut chunk)? {
            pipes.stdout = None;
        }
        if stdout.len() > limits.max_stdout {
            return Ok(Pumped::Stopped(Ended::Breach(OutputStream::Stdout)));
        }
        if ready.stderr && drain(&mut pipes.stderr, &mut stderr, &mut chunk)? {
            pipes.stderr = None;
        }
        match framing.attribute(&stderr) {
            Attributed::Command(len) if len > limits.max_stderr => {
                return Ok(Pumped::Stopped(Ended::Breach(OutputStream::Stderr)));
            }
            Attributed::Transport(len) if len > TRANSPORT_STDERR_LIMIT => {
                return Ok(Pumped::Stopped(Ended::Abandoned(CommandOutput {
                    code: None,
                    stdout,
                    stderr,
                })));
            }
            Attributed::Command(_) | Attributed::Transport(_) => {}
        }
    }
    Ok(Pumped::Closed { stdout, stderr })
}

/// Which pipes `poll(2)` reported ready.
struct Ready {
    stdin: bool,
    stdout: bool,
    stderr: bool,
}

/// Waits until at least one open pipe is ready or `timeout` passes.
fn wait_ready(pipes: &Pipes, timeout: Option<&Timespec>) -> Result<Ready, Errno> {
    let mut fds = Vec::with_capacity(3);
    let mut slots = [None; 3];
    if let Some(pipe) = &pipes.stdin {
        slots[0] = Some(fds.len());
        fds.push(PollFd::new(pipe, PollFlags::OUT));
    }
    if let Some(pipe) = &pipes.stdout {
        slots[1] = Some(fds.len());
        fds.push(PollFd::new(pipe, PollFlags::IN));
    }
    if let Some(pipe) = &pipes.stderr {
        slots[2] = Some(fds.len());
        fds.push(PollFd::new(pipe, PollFlags::IN));
    }
    rustix::event::poll(&mut fds, timeout)?;
    // A hang-up or an error is readiness too: the read or write it wakes
    // reports what happened, and a pipe that only ever reported those would
    // otherwise be polled forever.
    let ready = |slot: Option<usize>| {
        slot.and_then(|index| fds.get(index))
            .is_some_and(|fd| !fd.revents().is_empty())
    };
    Ok(Ready {
        stdin: ready(slots[0]),
        stdout: ready(slots[1]),
        stderr: ready(slots[2]),
    })
}

/// Reads what one ready output pipe holds into `into`, returning whether the
/// pipe reached end of file.
fn drain<R: Read>(
    pipe: &mut Option<R>,
    into: &mut Vec<u8>,
    chunk: &mut [u8],
) -> std::io::Result<bool> {
    let Some(reader) = pipe else {
        return Ok(false);
    };
    match reader.read(chunk) {
        Ok(0) => Ok(true),
        Ok(count) => {
            into.extend_from_slice(chunk.get(..count).unwrap_or_default());
            Ok(false)
        }
        Err(error) if is_transient(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Reports whether an I/O error only means "not now".
fn is_transient(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

/// Waits for a child whose pipes have all closed to exit, killing it at the
/// deadline.
///
/// The pipes closing is not the child exiting: a command can close its
/// standard streams and keep running, and nothing then remains to `poll(2)`
/// on, so the exit is polled.
fn await_exit(
    mut child: Child,
    kill: Kill,
    deadline: &Deadline,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> std::io::Result<Ended> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Ended::Exited(CommandOutput {
                code: status.code(),
                stdout,
                stderr,
            }));
        }
        let Some(timeout) = deadline.remaining() else {
            terminate(&mut child, kill);
            return Ok(Ended::TimedOut);
        };
        std::thread::sleep(timeout.min(EXIT_POLL));
    }
}

/// Kills `child` and everything left in its process group, and reaps it.
///
/// The group is killed even where the child has already exited, since a
/// descendant can outlive it; a group already empty is `ESRCH`, which is the
/// outcome wanted. The group is always killed **before** the child is reaped:
/// until then the child's pid, and so the group's id, cannot be reused, so the
/// `SIGKILL` cannot reach an unrelated group that took the number over. A
/// child this process may not signal — `sudo` running as root under an
/// unprivileged caller, whose relay did not end it within [`RELAY_GRACE`] — is
/// left unreaped after [`KILL_GRACE`] rather than waited on without bound.
fn terminate(child: &mut Child, kill: Kill) {
    let pid = Pid::from_child(child);
    if matches!(kill, Kill::Relay) {
        let _ = rustix::process::kill_process(pid, Signal::TERM);
        await_unreaped(pid, RELAY_GRACE);
    }
    let _ = rustix::process::kill_process_group(pid, Signal::KILL);
    reap_within(child, KILL_GRACE);
}

/// Waits up to `grace` for the child `pid` to exit, leaving it unreaped.
fn await_unreaped(pid: Pid, grace: Duration) {
    let deadline = Deadline::after(grace);
    loop {
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        match rustix::process::waitid(WaitId::Pid(pid), options) {
            Ok(None) | Err(Errno::INTR) => {}
            // Exited and waiting to be reaped, or not a child to wait on.
            Ok(Some(_)) | Err(_) => return,
        }
        let Some(left) = deadline.remaining() else {
            return;
        };
        std::thread::sleep(left.min(EXIT_POLL));
    }
}

/// Waits up to `grace` for `child` to exit and reaps it.
fn reap_within(child: &mut Child, grace: Duration) {
    let deadline = Deadline::after(grace);
    // An error is a child already reaped, or not ours to reap: nothing more
    // to wait for.
    while let Ok(None) = child.try_wait() {
        let Some(left) = deadline.remaining() else {
            return;
        };
        std::thread::sleep(left.min(EXIT_POLL));
    }
}

/// When a run must end. `None` is a timeout too large to represent as an
/// instant, which never passes.
struct Deadline(Option<Instant>);

impl Deadline {
    fn after(timeout: Duration) -> Self {
        Self(Instant::now().checked_add(timeout))
    }

    /// Returns the time left, or `None` once the deadline has passed.
    fn remaining(&self) -> Option<Duration> {
        match self.0 {
            Some(at) => at
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero()),
            None => Some(Duration::MAX),
        }
    }
}

/// Returns the position of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reports whether `haystack` contains `needle`.
pub(super) fn contains(haystack: &[u8], needle: &str) -> bool {
    find(haystack, needle.as_bytes()).is_some()
}

/// Returns the length of the longest proper prefix of `marker` that `bytes`
/// ends with: a marker that may still be arriving.
fn partial_suffix(bytes: &[u8], marker: &[u8]) -> usize {
    let longest = bytes.len().min(marker.len().saturating_sub(1));
    (1..=longest)
        .rev()
        .find(|&len| bytes.ends_with(marker.get(..len).unwrap_or_default()))
        .unwrap_or(0)
}

/// Returns the length of the trailing bytes of `bytes` that are, or may still
/// grow into, the SSH wrapper's exit-status line: a newline, [`RC_MARKER`], up
/// to three digits, and a newline.
fn remote_code_suffix(bytes: &[u8]) -> usize {
    /// Digits in the largest exit status a shell reports, `255`.
    const MAX_DIGITS: usize = 3;
    let head_len = 1 + RC_MARKER.len();
    let longest = bytes.len().min(head_len + MAX_DIGITS + 1);
    (1..=longest)
        .rev()
        .find(|&len| {
            let tail = bytes.get(bytes.len() - len..).unwrap_or_default();
            is_remote_code_prefix(tail, MAX_DIGITS)
        })
        .unwrap_or(0)
}

/// Reports whether `tail` is a prefix of an exit-status line.
fn is_remote_code_prefix(tail: &[u8], max_digits: usize) -> bool {
    let Some((&first, rest)) = tail.split_first() else {
        return false;
    };
    if first != b'\n' {
        return false;
    }
    let marker = RC_MARKER.as_bytes();
    if rest.len() <= marker.len() {
        return marker.starts_with(rest);
    }
    let Some(code) = rest.strip_prefix(marker) else {
        return false;
    };
    let digits = code.strip_suffix(b"\n").unwrap_or(code);
    !digits.is_empty()
        && digits.len() <= max_digits
        && digits.iter().all(u8::is_ascii_digit)
        && (digits.len() == code.len() || digits.len() + 1 == code.len())
}

/// Settles how the engine's run ended into the result
/// [`Executor::run_with_input`](super::Executor::run_with_input) returns.
///
/// A run that exited is first checked for its supervisor's own deadline
/// having ended it, and stripped of whatever the transport wrote before the
/// command started. It is then handed to `settle` — the transport's framing,
/// removed exactly as [`Executor::run`](super::Executor::run) removes it, and
/// its failure classified the same way — and what is left is held against the
/// limits once more, now with nothing but the command's own bytes in it. The
/// transport's bytes are kept where [`SUDO_OK_SENTINEL`] never arrived: the
/// command did not start, and they are the diagnostic `settle` reports.
pub(super) fn finish(
    ended: Ended,
    command: &str,
    limits: RunLimits,
    framing: Framing<'_>,
    settle: impl FnOnce(CommandOutput) -> Result<CommandOutput, ExecutorError>,
) -> Result<CommandOutput, RunWithInputError> {
    let mut output = match ended {
        Ended::Exited(output) | Ended::Abandoned(output) => output,
        Ended::Breach(stream) => return Err(breach(command, stream, limits)),
        Ended::TimedOut => return Err(timed_out(command, limits)),
    };
    if let Some(marker) = framing.timeout_marker {
        if contains(&output.stderr, marker) {
            return Err(timed_out(command, limits));
        }
        if let Some(at) = find(&output.stderr, SUDO_OK_SENTINEL.as_bytes()) {
            output.stderr.drain(..at);
        }
    }
    let output = settle(output)?;
    if output.stdout.len() > limits.max_stdout {
        return Err(breach(command, OutputStream::Stdout, limits));
    }
    if output.stderr.len() > limits.max_stderr {
        return Err(breach(command, OutputStream::Stderr, limits));
    }
    Ok(output)
}

fn breach(command: &str, stream: OutputStream, limits: RunLimits) -> RunWithInputError {
    RunWithInputError::OutputLimit {
        command: command.to_string(),
        stream,
        limit: match stream {
            OutputStream::Stdout => limits.max_stdout,
            OutputStream::Stderr => limits.max_stderr,
        },
    }
}

fn timed_out(command: &str, limits: RunLimits) -> RunWithInputError {
    RunWithInputError::TimedOut {
        command: command.to_string(),
        timeout: limits.timeout,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        Attributed, CommandOutput, Ended, Framing, MAX_SLEEP_SECS, SLEEP, Supervisor,
        TIMEOUT_MARKER_PREFIX, TIMEOUT_MARKER_SUFFIX, finish, partial_suffix, remote_code_suffix,
    };
    use crate::executor::{RC_MARKER, RunLimits, RunWithInputError, SUDO_OK_SENTINEL};

    const MARKER: &str = "__BOOTLER_TIMEOUT_00112233445566778899aabbccddeeff__";
    const SUDO_SSH: Framing<'static> = Framing {
        timeout_marker: Some(MARKER),
        remote_code: true,
    };
    const LIMITS: RunLimits = RunLimits {
        max_stdout: 16,
        max_stderr: 16,
        timeout: Duration::from_secs(5),
    };

    fn exited(stderr: &[u8]) -> Ended {
        Ended::Exited(CommandOutput {
            code: Some(0),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        })
    }

    /// What `settle` does for a `sudo` that granted: strip the sentinel.
    fn strip_sentinel(
        mut output: CommandOutput,
    ) -> Result<CommandOutput, crate::executor::ExecutorError> {
        let at = super::find(&output.stderr, SUDO_OK_SENTINEL.as_bytes()).ok_or_else(|| {
            crate::executor::ExecutorError::SudoRefused {
                host: "test".to_string(),
                reason: "no sentinel".to_string(),
            }
        })?;
        output.stderr.drain(at..at + SUDO_OK_SENTINEL.len());
        Ok(output)
    }

    #[test]
    fn a_direct_run_counts_every_stderr_byte() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}0\n");
        assert_eq!(
            Framing::DIRECT.attribute(stderr.as_bytes()),
            Attributed::Command(stderr.len())
        );
    }

    #[test]
    fn the_sentinel_and_the_exit_status_line_are_not_the_commands() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}255\n");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
    }

    #[test]
    fn what_precedes_the_sentinel_is_the_transports() {
        // `sudo` refusing, or `ssh` failing to connect: however long, none of
        // it is held against the command's limit.
        let refusal = "sudo: a password is required\n";
        assert_eq!(
            SUDO_SSH.attribute(refusal.as_bytes()),
            Attributed::Transport(refusal.len())
        );
        // Half a sentinel is the transport's too, until the rest arrives.
        let half = format!("{refusal}{}", &SUDO_OK_SENTINEL[..7]);
        assert_eq!(
            SUDO_SSH.attribute(half.as_bytes()),
            Attributed::Transport(half.len())
        );
        // Once it has arrived, a warning ahead of it is still not counted.
        let stderr = format!("Warning: added host key\n{SUDO_OK_SENTINEL}abc");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
    }

    #[test]
    fn the_runs_own_timeout_marker_is_not_the_commands() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc{MARKER}");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
        let stderr = format!("{SUDO_OK_SENTINEL}abc{MARKER}\n{RC_MARKER}124\n");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
    }

    #[test]
    fn another_runs_timeout_marker_is_the_commands() {
        // The fixed marker earlier revisions used, and one well formed with
        // another nonce: both are bytes the command wrote, and count.
        for other in [
            "__BOOTLER_TIMEOUT__".to_string(),
            format!(
                "{TIMEOUT_MARKER_PREFIX}ffeeddccbbaa99887766554433221100{TIMEOUT_MARKER_SUFFIX}"
            ),
        ] {
            // A trailing byte, since a trailing `_` may still grow into
            // this run's marker and is not counted until it cannot.
            let stderr = format!("{SUDO_OK_SENTINEL}{other}.");
            assert_eq!(
                SUDO_SSH.attribute(stderr.as_bytes()),
                Attributed::Command(other.len() + 1),
                "{other}"
            );
        }
    }

    #[test]
    fn a_marker_still_arriving_is_not_counted_yet() {
        // Half an exit-status line after the command's own bytes.
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{}", &RC_MARKER[..4]);
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}2");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
        let stderr = format!("{SUDO_OK_SENTINEL}abc{}", &MARKER[..5]);
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(3)
        );
    }

    #[test]
    fn bytes_that_cannot_become_a_marker_are_counted() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}2x");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(stderr.len() - SUDO_OK_SENTINEL.len())
        );
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}2555");
        assert_eq!(
            SUDO_SSH.attribute(stderr.as_bytes()),
            Attributed::Command(stderr.len() - SUDO_OK_SENTINEL.len())
        );
    }

    #[test]
    fn only_the_runs_own_marker_settles_as_a_timeout() {
        let framing = Framing {
            timeout_marker: Some(MARKER),
            remote_code: false,
        };
        let stderr = format!("{SUDO_OK_SENTINEL}{MARKER}");
        let error = finish(
            exited(stderr.as_bytes()),
            "/bin/x",
            LIMITS,
            framing,
            strip_sentinel,
        )
        .expect_err("the supervisor's deadline ended it");
        assert!(
            matches!(error, RunWithInputError::TimedOut { .. }),
            "{error:?}"
        );
        // A command that printed the fixed marker of earlier revisions and
        // exited is a command that exited.
        let stderr = format!("{SUDO_OK_SENTINEL}__BOOTLER_TIMEOUT__");
        let output = finish(
            exited(stderr.as_bytes()),
            "/bin/x",
            RunLimits {
                max_stderr: 19,
                ..LIMITS
            },
            framing,
            strip_sentinel,
        )
        .expect("the command's own output");
        assert_eq!(output.code, Some(0));
        assert_eq!(output.stderr, b"__BOOTLER_TIMEOUT__");
    }

    #[test]
    fn what_the_transport_wrote_before_the_command_is_not_returned() {
        let framing = Framing {
            timeout_marker: Some(MARKER),
            remote_code: false,
        };
        let stderr = format!("Warning: added host key\n{SUDO_OK_SENTINEL}abc");
        let output = finish(
            exited(stderr.as_bytes()),
            "/bin/x",
            RunLimits {
                max_stderr: 3,
                ..LIMITS
            },
            framing,
            strip_sentinel,
        )
        .expect("the command's own output");
        assert_eq!(output.stderr, b"abc");
    }

    #[test]
    fn each_supervisor_draws_its_own_marker() {
        let first = Supervisor::new(Duration::from_secs(1)).expect("a supervisor");
        let second = Supervisor::new(Duration::from_secs(1)).expect("a supervisor");
        assert_ne!(first.timeout_marker(), second.timeout_marker());
        for supervisor in [&first, &second] {
            let marker = supervisor.timeout_marker();
            let nonce = marker
                .strip_prefix(TIMEOUT_MARKER_PREFIX)
                .and_then(|rest| rest.strip_suffix(TIMEOUT_MARKER_SUFFIX))
                .expect("prefix, nonce, suffix");
            assert_eq!(nonce.len(), 32);
            assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(supervisor.script().contains(marker));
        }
    }

    #[test]
    fn the_supervisor_deadline_is_whole_seconds_rounded_up_and_capped() {
        let sleeps = |timeout| {
            let supervisor = Supervisor::new(timeout).expect("a supervisor");
            let line = supervisor
                .script()
                .lines()
                .find(|line| line.starts_with(&format!("{SLEEP} ")))
                .expect("the deadline's sleep")
                .to_string();
            line.split_whitespace()
                .nth(1)
                .expect("a duration")
                .parse::<u64>()
                .expect("whole seconds")
        };
        assert_eq!(sleeps(Duration::from_secs(2)), 2);
        assert_eq!(sleeps(Duration::from_millis(2001)), 3);
        assert_eq!(sleeps(Duration::from_millis(1)), 1);
        // A timeout past what every `sleep` accepts is held to the cap rather
        // than handed on and refused.
        assert_eq!(
            sleeps(Duration::from_secs(MAX_SLEEP_SECS + 1)),
            MAX_SLEEP_SECS
        );
        assert_eq!(sleeps(Duration::MAX), MAX_SLEEP_SECS);
    }

    #[test]
    fn suffix_helpers_find_the_longest_candidate() {
        assert_eq!(partial_suffix(b"xx__BOOT", b"__BOOTLER"), 6);
        assert_eq!(partial_suffix(b"__BOOTLER", b"__BOOTLER"), 0);
        assert_eq!(remote_code_suffix(b"abc\n"), 1);
        assert_eq!(remote_code_suffix(b"abc"), 0);
    }
}
