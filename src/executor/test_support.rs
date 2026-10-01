//! A recording, scriptable [`Executor`] for tests.
//!
//! [`RecordingExecutor`] runs nothing. It records every call made to it —
//! the identity, the argument vector and, for
//! [`Executor::run_with_input`], the exact standard-input bytes and the
//! [`RunLimits`] — and answers each call with the next outcome a test
//! scripted for that method. A test of code built on the executor can then
//! assert what was asked for and drive every outcome the real transports
//! produce, including a stream passing its limit and a timeout, without a
//! process being spawned.
//!
//! It holds commands to the same rule the real transports do: a
//! [`Executor::run_with_input`] or [`Executor::open_channel`] call naming a
//! command that is not an absolute path free of `=` is recorded and refused
//! with [`RunWithInputError::InvalidCommand`] or
//! [`ChannelError::InvalidCommand`], and consumes no scripted outcome.
//!
//! [`Executor::open_channel`] is the one call that can start a process: a
//! scripted [`ScriptedChannel::Spawn`] runs the program it names, so a test can
//! drive a real [`Channel`] without any transport in between.
//!
//! This module is compiled only for this crate's tests and under the
//! `test-support` feature. Enable that feature in a dependent's
//! `[dev-dependencies]` only — never under `[dependencies]` — so none of it
//! reaches a release build.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{
    Channel, ChannelError, ChannelLimits, CommandOutput, Executor, ExecutorError, FileMeta,
    Identity, OutputStream, RunLimits, RunWithInputError, channel, check_bounded_command,
};

/// One call a [`RecordingExecutor`] received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedCall {
    /// [`Executor::run`], including the calls the trait's default methods
    /// make through it.
    Run {
        /// Who the command was to run as.
        identity: Identity,
        /// The command.
        command: String,
        /// Every argument, in order.
        args: Vec<String>,
    },
    /// [`Executor::run_with_input`].
    RunWithInput {
        /// Who the command was to run as.
        identity: Identity,
        /// The command.
        command: String,
        /// Every argument, in order.
        args: Vec<String>,
        /// The bytes to be fed on standard input, exactly.
        input: Vec<u8>,
        /// The limits the command was to run under.
        limits: RunLimits,
    },
    /// [`Executor::open_channel`].
    OpenChannel {
        /// Who the command was to run as.
        identity: Identity,
        /// The command.
        command: String,
        /// Every argument, in order.
        args: Vec<String>,
        /// The limits the channel was to open under.
        limits: ChannelLimits,
    },
    /// [`Executor::put_file`].
    PutFile {
        /// The destination.
        dest: PathBuf,
        /// The contents, exactly.
        contents: Vec<u8>,
        /// The owner, group and mode.
        meta: FileMeta,
    },
}

/// The outcome a test scripts for one [`Executor::run_with_input`] call.
#[derive(Debug)]
pub enum ScriptedRun {
    /// The command ran and exited, with this output — a non-zero exit
    /// included, as the real transports report one.
    Output(CommandOutput),
    /// The command wrote past its limit on this stream. Answered with
    /// [`RunWithInputError::OutputLimit`] naming the call's command and the
    /// call's limit for the stream.
    OutputLimit(OutputStream),
    /// The command outlived its timeout. Answered with
    /// [`RunWithInputError::TimedOut`] naming the call's command and the
    /// call's timeout.
    TimedOut,
    /// Any other error, returned as it is.
    Error(RunWithInputError),
}

/// The outcome a test scripts for one [`Executor::open_channel`] call.
#[derive(Debug)]
pub enum ScriptedChannel {
    /// Spawns `program` with `args` directly — no `sudo`, piped standard
    /// streams, an empty environment — and returns it as the [`Channel`], in
    /// place of the command the call named.
    Spawn {
        /// The program to spawn.
        program: PathBuf,
        /// Its arguments, in order.
        args: Vec<String>,
    },
    /// Returns this error as it is.
    Fail(ChannelError),
}

/// An [`Executor`] that records every call and answers from a script.
///
/// Scripted outcomes are consumed first in, first out, one queue per method.
/// [`Executor::put_file`] needs no script and always succeeds.
#[derive(Debug, Default)]
pub struct RecordingExecutor {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    calls: Vec<RecordedCall>,
    runs: VecDeque<Result<CommandOutput, ExecutorError>>,
    bounded_runs: VecDeque<ScriptedRun>,
    channels: VecDeque<ScriptedChannel>,
}

impl RecordingExecutor {
    /// Creates an executor with nothing recorded and nothing scripted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues the outcome of the next unanswered [`Executor::run`] call.
    pub fn script_run(&self, outcome: Result<CommandOutput, ExecutorError>) {
        self.state().runs.push_back(outcome);
    }

    /// Queues the outcome of the next unanswered
    /// [`Executor::run_with_input`] call.
    pub fn script_run_with_input(&self, outcome: ScriptedRun) {
        self.state().bounded_runs.push_back(outcome);
    }

    /// Queues the outcome of the next unanswered [`Executor::open_channel`]
    /// call.
    pub fn script_open_channel(&self, outcome: ScriptedChannel) {
        self.state().channels.push_back(outcome);
    }

    /// Returns every call received so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.state().calls.clone()
    }

    /// A poisoned lock means a test already panicked while holding it; the
    /// record is still the best account of what happened.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Copies an argument vector into the owned form a record keeps.
fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

impl Executor for RecordingExecutor {
    /// Records the call and returns the next scripted [`Executor::run`]
    /// outcome.
    ///
    /// # Panics
    ///
    /// Panics when no outcome is scripted: the test did not anticipate the
    /// call, and inventing an answer would hide that.
    fn run(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ExecutorError> {
        let mut state = self.state();
        state.calls.push(RecordedCall::Run {
            identity,
            command: command.to_string(),
            args: owned(args),
        });
        match state.runs.pop_front() {
            Some(outcome) => outcome,
            None => panic!("RecordingExecutor: no outcome scripted for run `{command}` {args:?}"),
        }
    }

    /// Records the call and returns the next scripted
    /// [`Executor::run_with_input`] outcome, after refusing a command the real
    /// transports would refuse.
    ///
    /// # Panics
    ///
    /// Panics when no outcome is scripted for a command that is not refused:
    /// the test did not anticipate the call, and inventing an answer would
    /// hide that.
    fn run_with_input(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        input: &[u8],
        limits: RunLimits,
    ) -> Result<CommandOutput, RunWithInputError> {
        let mut state = self.state();
        state.calls.push(RecordedCall::RunWithInput {
            identity,
            command: command.to_string(),
            args: owned(args),
            input: input.to_vec(),
            limits,
        });
        check_bounded_command(command)?;
        let Some(outcome) = state.bounded_runs.pop_front() else {
            panic!("RecordingExecutor: no outcome scripted for run_with_input `{command}` {args:?}")
        };
        match outcome {
            ScriptedRun::Output(output) => Ok(output),
            ScriptedRun::OutputLimit(stream) => Err(RunWithInputError::OutputLimit {
                command: command.to_string(),
                stream,
                limit: match stream {
                    OutputStream::Stdout => limits.max_stdout,
                    OutputStream::Stderr => limits.max_stderr,
                },
            }),
            ScriptedRun::TimedOut => Err(RunWithInputError::TimedOut {
                command: command.to_string(),
                timeout: limits.timeout,
            }),
            ScriptedRun::Error(error) => Err(error),
        }
    }

    /// Records the call and answers it with the next scripted
    /// [`ScriptedChannel`], after refusing a command the real transports
    /// would refuse.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::InvalidCommand`] for a command that is not an
    /// absolute path free of `=`, the scripted error for
    /// [`ScriptedChannel::Fail`], and [`ExecutorError::Spawn`] when a
    /// [`ScriptedChannel::Spawn`] program cannot be spawned.
    ///
    /// # Panics
    ///
    /// Panics when no outcome is scripted for a command that is not refused:
    /// the test did not anticipate the call, and inventing an answer would
    /// hide that.
    fn open_channel(
        &self,
        identity: Identity,
        command: &str,
        args: &[&str],
        limits: ChannelLimits,
    ) -> Result<Channel, ChannelError> {
        let outcome = {
            let mut state = self.state();
            state.calls.push(RecordedCall::OpenChannel {
                identity,
                command: command.to_string(),
                args: owned(args),
                limits,
            });
            channel::check_command(command)?;
            let Some(outcome) = state.channels.pop_front() else {
                panic!(
                    "RecordingExecutor: no outcome scripted for open_channel `{command}` {args:?}"
                )
            };
            outcome
        };
        match outcome {
            ScriptedChannel::Spawn { program, args } => {
                let mut spawned = Command::new(program);
                spawned.args(args).env_clear();
                channel::open_direct(spawned, limits.max_stderr)
            }
            ScriptedChannel::Fail(error) => Err(error),
        }
    }

    fn put_file(&self, dest: &Path, contents: &[u8], meta: FileMeta) -> Result<(), ExecutorError> {
        self.state().calls.push(RecordedCall::PutFile {
            dest: dest.to_path_buf(),
            contents: contents.to_vec(),
            meta,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{RecordedCall, RecordingExecutor, ScriptedChannel, ScriptedRun};
    use crate::executor::{
        ChannelError, ChannelLimits, CommandOutput, Executor, ExecutorError, Identity,
        OutputStream, RunLimits, RunWithInputError, ServiceAccount,
    };

    const LIMITS: RunLimits = RunLimits {
        max_stdout: 65_536,
        max_stderr: 4_096,
        timeout: Duration::from_secs(30),
    };
    const CHANNEL: ChannelLimits = ChannelLimits {
        elevation_timeout: Duration::from_secs(10),
        max_stderr: 4_096,
    };

    fn output(code: i32, stdout: &[u8]) -> CommandOutput {
        CommandOutput {
            code: Some(code),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn every_argument_of_a_bounded_run_is_recorded() {
        let exec = RecordingExecutor::new();
        exec.script_run_with_input(ScriptedRun::Output(output(0, b"{}")));
        let input = vec![0xA5; 65_536];
        let identity = Identity::Service(ServiceAccount::Security);
        let result = exec
            .run_with_input(
                identity,
                "/usr/lib/review/review",
                &["core-update", "restore"],
                &input,
                LIMITS,
            )
            .expect("the scripted output");
        assert_eq!(result.stdout, b"{}");
        assert_eq!(
            exec.calls(),
            vec![RecordedCall::RunWithInput {
                identity,
                command: "/usr/lib/review/review".to_string(),
                args: vec!["core-update".to_string(), "restore".to_string()],
                input,
                limits: LIMITS,
            }]
        );
    }

    #[test]
    fn each_outcome_can_be_scripted() {
        let exec = RecordingExecutor::new();
        exec.script_run_with_input(ScriptedRun::Output(output(3, b"")));
        exec.script_run_with_input(ScriptedRun::OutputLimit(OutputStream::Stderr));
        exec.script_run_with_input(ScriptedRun::TimedOut);
        exec.script_run_with_input(ScriptedRun::Error(RunWithInputError::Executor(
            ExecutorError::Elevation {
                host: "seat".to_string(),
            },
        )));
        let call = || exec.run_with_input(Identity::Root, "/bin/snapshot", &[], b"", LIMITS);

        assert_eq!(call().expect("non-zero exit is an output").code, Some(3));
        match call() {
            Err(RunWithInputError::OutputLimit {
                command,
                stream,
                limit,
            }) => {
                assert_eq!(command, "/bin/snapshot");
                assert_eq!(stream, OutputStream::Stderr);
                assert_eq!(limit, LIMITS.max_stderr);
            }
            other => panic!("expected OutputLimit, got {other:?}"),
        }
        match call() {
            Err(RunWithInputError::TimedOut { command, timeout }) => {
                assert_eq!(command, "/bin/snapshot");
                assert_eq!(timeout, LIMITS.timeout);
            }
            other => panic!("expected TimedOut, got {other:?}"),
        }
        assert!(matches!(
            call(),
            Err(RunWithInputError::Executor(ExecutorError::Elevation { .. }))
        ));
    }

    #[test]
    fn a_relative_command_is_refused_without_consuming_the_script() {
        let exec = RecordingExecutor::new();
        exec.script_run_with_input(ScriptedRun::TimedOut);
        let error = exec
            .run_with_input(Identity::Root, "review", &[], b"", LIMITS)
            .expect_err("a relative command is refused");
        assert!(
            matches!(error, RunWithInputError::InvalidCommand { ref command } if command == "review"),
            "got: {error:?}"
        );
        assert_eq!(exec.calls().len(), 1, "the refused call is still recorded");
        assert!(matches!(
            exec.run_with_input(Identity::Root, "/bin/review", &[], b"", LIMITS),
            Err(RunWithInputError::TimedOut { .. })
        ));
    }

    #[test]
    fn run_and_the_default_methods_are_recorded_and_scripted() {
        let exec = RecordingExecutor::new();
        exec.script_run(Ok(output(0, b"bytes")));
        let read = exec
            .fetch_file(Identity::Root, std::path::Path::new("/etc/x"))
            .expect("the scripted read");
        assert_eq!(read, b"bytes");
        assert_eq!(
            exec.calls(),
            vec![RecordedCall::Run {
                identity: Identity::Root,
                command: "cat".to_string(),
                args: vec!["/etc/x".to_string()],
            }]
        );
    }

    #[test]
    fn a_scripted_spawn_is_a_channel_to_that_program() {
        let exec = RecordingExecutor::new();
        exec.script_open_channel(ScriptedChannel::Spawn {
            program: PathBuf::from("/bin/cat"),
            args: Vec::new(),
        });
        let identity = Identity::Service(ServiceAccount::Roxyd);
        let mut channel = exec
            .open_channel(identity, "/usr/lib/helper", &["__attempt-launch"], CHANNEL)
            .expect("the scripted spawn");
        let mut stdin = channel.take_stdin().expect("stdin");
        let mut stdout = channel.take_stdout().expect("stdout");
        stdin.write_all(b"frame").expect("write");
        drop(stdin);
        let mut echoed = Vec::new();
        stdout.read_to_end(&mut echoed).expect("read");
        assert_eq!(echoed, b"frame");
        let exit = channel.wait().expect("wait");
        assert_eq!(exit.code, Some(0));
        assert_eq!(exit.stderr, [] as [u8; 0]);
        assert_eq!(
            exec.calls(),
            vec![RecordedCall::OpenChannel {
                identity,
                command: "/usr/lib/helper".to_string(),
                args: vec!["__attempt-launch".to_string()],
                limits: CHANNEL,
            }]
        );
    }

    #[test]
    fn a_scripted_failure_is_returned_and_an_invalid_command_consumes_nothing() {
        let exec = RecordingExecutor::new();
        exec.script_open_channel(ScriptedChannel::Fail(ChannelError::Executor(
            ExecutorError::Elevation {
                host: "seat".to_string(),
            },
        )));
        let error = exec
            .open_channel(Identity::Root, "helper", &[], CHANNEL)
            .expect_err("a relative command is refused");
        assert!(
            matches!(error, ChannelError::InvalidCommand { ref command } if command == "helper"),
            "got: {error:?}"
        );
        assert_eq!(exec.calls().len(), 1, "the refused call is still recorded");
        let error = exec
            .open_channel(Identity::Root, "/usr/lib/helper", &[], CHANNEL)
            .expect_err("the scripted failure");
        assert!(
            matches!(
                error,
                ChannelError::Executor(ExecutorError::Elevation { .. })
            ),
            "got: {error:?}"
        );
        assert_eq!(exec.calls().len(), 2);
    }
}
