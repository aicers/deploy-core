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
//! connection. Those transports run the command under [`supervisor_script`],
//! which kills the command's process group from inside, on the relayed signal
//! and on a deadline of its own.
//!
//! [`Executor::run_with_input`]: super::Executor::run_with_input

use std::io::{ErrorKind, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
/// Marker [`supervisor_script`]'s own deadline prints on stderr before it kills
/// the command, so a run the supervisor ended is reported as a timeout rather
/// than read as the command dying of a signal.
pub(super) const TIMEOUT_MARKER: &str = "__BOOTLER_TIMEOUT__";
/// The shell [`supervisor_script`] runs under, named absolutely so the
/// invocation depends on no `PATH`.
pub(super) const SUPERVISOR_SHELL: &str = "/bin/sh";
/// The `env` the supervisor clears the command's environment with. Its path is
/// the one fixed location both Linux and macOS guarantee.
const ENV: &str = "/usr/bin/env";
/// The `sleep` the supervisor's deadline runs, named absolutely for the same
/// reason: one `PATH` could not resolve would exit at once, and the script
/// would lose its deadline exactly as it would to a `sleep` that refused it.
const SLEEP: &str = "/bin/sleep";
/// The longest deadline [`supervisor_script`] hands `sleep`, `i32::MAX`
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
    /// `SIGTERM` to [`supervisor_script`], which kills the command from the
    /// inside, and this process may not be able to signal the command at all.
    Relay,
}

/// What the invocation itself writes on stderr around the command's own
/// bytes, so the stderr limit is held against the command and not against the
/// transport's markers.
#[derive(Debug, Clone, Copy)]
pub(super) struct Framing {
    /// [`supervisor_script`] runs the command, so [`TIMEOUT_MARKER`] may
    /// appear.
    pub(super) supervised: bool,
    /// `sudo` runs the supervisor, which prints [`SUDO_OK_SENTINEL`] first.
    pub(super) sentinel: bool,
    /// The SSH wrapper appends the remote exit status after [`RC_MARKER`].
    pub(super) remote_code: bool,
}

impl Framing {
    /// A command spawned directly: every byte on stderr is its own.
    pub(super) const DIRECT: Self = Self {
        supervised: false,
        sentinel: false,
        remote_code: false,
    };

    /// Returns how many bytes of `stderr` the command itself wrote.
    ///
    /// A marker already seen in full is discounted, and so is a trailing
    /// fragment that may still grow into one — a stream is read in chunks, and
    /// a marker split across two of them must not count against the limit
    /// while only its first half has arrived. Nothing else is discounted, so a
    /// command that writes one byte past its limit is caught at that byte.
    fn command_len(self, stderr: &[u8]) -> usize {
        let mut framing = 0;
        let mut tail = stderr;
        let mut pending = 0;
        if self.sentinel {
            match find(stderr, SUDO_OK_SENTINEL.as_bytes()) {
                Some(at) => {
                    framing += SUDO_OK_SENTINEL.len();
                    tail = stderr
                        .get(at + SUDO_OK_SENTINEL.len()..)
                        .unwrap_or_default();
                }
                None => pending = partial_suffix(stderr, SUDO_OK_SENTINEL.as_bytes()),
            }
        }
        if self.supervised {
            if find(tail, TIMEOUT_MARKER.as_bytes()).is_some() {
                framing += TIMEOUT_MARKER.len();
            } else {
                pending = pending.max(partial_suffix(tail, TIMEOUT_MARKER.as_bytes()));
            }
        }
        if self.remote_code {
            pending = pending.max(remote_code_suffix(tail));
        }
        stderr.len().saturating_sub(framing + pending)
    }
}

/// How the engine's run ended.
#[derive(Debug)]
pub(super) enum Ended {
    /// The child exited, or was killed by something other than this run, with
    /// its output captured raw — any transport framing is still in it.
    Exited(CommandOutput),
    /// A stream passed its limit and the child was killed.
    Breach(OutputStream),
    /// The deadline passed and the child was killed.
    TimedOut,
}

/// Returns the `sh -c` script that supervises a command on a transport this
/// process cannot signal the command through.
///
/// Invoked as `sh -c SCRIPT <command> <args…>`, so the command and every
/// argument arrive positionally and are never spliced into the script text.
/// With `sentinel`, it first prints [`SUDO_OK_SENTINEL`], so a `sudo` that
/// refused is told apart from a command that failed exactly as
/// [`Executor::run`](super::Executor::run) tells them apart.
///
/// - **The environment is cleared.** The command is started through
///   `env -i`, so nothing `sudo`'s environment reset or the SSH session put
///   back reaches it — no variable at all, and so no `PATH` either.
/// - **Only the command writes to standard error.** The script keeps the
///   real standard error aside for the command and for [`TIMEOUT_MARKER`],
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
///   deadline passed first, and the script prints [`TIMEOUT_MARKER`] and kills
///   the group. This is what ends the command on the far side of an SSH
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
/// Two things differ from a command run directly. A command a signal killed
/// reports `128 + signal` rather than no exit code, since the script exits
/// with the status its subshell returned; and a command started in the
/// background of a shell without job control starts with `SIGINT` and
/// `SIGQUIT` ignored.
pub(super) fn supervisor_script(sentinel: bool, timeout: Duration) -> String {
    let seconds = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0))
        .min(MAX_SLEEP_SECS);
    let announce = if sentinel {
        format!("printf '%s' '{SUDO_OK_SENTINEL}' >&2\n")
    } else {
        String::new()
    };
    format!(
        r#"trap 'kill -KILL 0' TERM HUP INT
{announce}exec 3<&0 0</dev/null 4>&2 2>/dev/null
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
  printf '%s' '{TIMEOUT_MARKER}' >&4
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
/// A stream passing its limit — stderr measured by `framing` — or the deadline
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
    framing: Framing,
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
    /// The run must stop early; nothing it captured is returned.
    Stopped(Ended),
}

/// Moves bytes until every pipe has closed or the run must stop early.
fn pump(
    pipes: &mut Pipes,
    feed: &[u8],
    limits: RunLimits,
    framing: Framing,
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
        if framing.command_len(&stderr) > limits.max_stderr {
            return Ok(Pumped::Stopped(Ended::Breach(OutputStream::Stderr)));
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
/// A run that exited is first checked for the supervisor's own deadline
/// having ended it, then handed to `settle` — the transport's framing, removed
/// exactly as [`Executor::run`](super::Executor::run) removes it — and what is
/// left is held against the limits once more, now with nothing but the
/// command's own bytes in it.
pub(super) fn finish(
    ended: Ended,
    command: &str,
    limits: RunLimits,
    framing: Framing,
    settle: impl FnOnce(CommandOutput) -> Result<CommandOutput, ExecutorError>,
) -> Result<CommandOutput, RunWithInputError> {
    let output = match ended {
        Ended::Exited(output) => output,
        Ended::Breach(stream) => return Err(breach(command, stream, limits)),
        Ended::TimedOut => return Err(timed_out(command, limits)),
    };
    if framing.supervised && contains(&output.stderr, TIMEOUT_MARKER) {
        return Err(timed_out(command, limits));
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
        Framing, MAX_SLEEP_SECS, SLEEP, TIMEOUT_MARKER, partial_suffix, remote_code_suffix,
        supervisor_script,
    };
    use crate::executor::{RC_MARKER, SUDO_OK_SENTINEL};

    const SUDO_SSH: Framing = Framing {
        supervised: true,
        sentinel: true,
        remote_code: true,
    };

    #[test]
    fn a_direct_run_counts_every_stderr_byte() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}0\n");
        assert_eq!(Framing::DIRECT.command_len(stderr.as_bytes()), stderr.len());
    }

    #[test]
    fn the_sentinel_and_the_exit_status_line_are_not_the_commands() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}255\n");
        assert_eq!(SUDO_SSH.command_len(stderr.as_bytes()), 3);
    }

    #[test]
    fn a_marker_still_arriving_is_not_counted_yet() {
        // Half a sentinel, before the command has written anything.
        let half = &SUDO_OK_SENTINEL[..7];
        assert_eq!(SUDO_SSH.command_len(half.as_bytes()), 0);
        // Half an exit-status line after the command's own bytes.
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{}", &RC_MARKER[..4]);
        assert_eq!(SUDO_SSH.command_len(stderr.as_bytes()), 3);
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}2");
        assert_eq!(SUDO_SSH.command_len(stderr.as_bytes()), 3);
        let stderr = format!("{SUDO_OK_SENTINEL}abc{}", &TIMEOUT_MARKER[..5]);
        assert_eq!(SUDO_SSH.command_len(stderr.as_bytes()), 3);
    }

    #[test]
    fn bytes_that_cannot_become_a_marker_are_counted() {
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}2x");
        assert_eq!(
            SUDO_SSH.command_len(stderr.as_bytes()),
            stderr.len() - SUDO_OK_SENTINEL.len()
        );
        let stderr = format!("{SUDO_OK_SENTINEL}abc\n{RC_MARKER}2555");
        assert_eq!(
            SUDO_SSH.command_len(stderr.as_bytes()),
            stderr.len() - SUDO_OK_SENTINEL.len()
        );
    }

    #[test]
    fn the_supervisor_deadline_is_whole_seconds_rounded_up_and_capped() {
        let sleeps = |timeout| {
            let script = supervisor_script(false, timeout);
            let line = script
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
