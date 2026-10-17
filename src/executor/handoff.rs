//! The handoff line a script run under `sudo -S` discards standard input up
//! to.
//!
//! Under [`SudoAuth::Password`] the password line goes on `sudo`'s standard
//! input ahead of everything else, and a `sudo` that does not ask for it — a
//! `NOPASSWD` rule, or credentials it still has cached — leaves it there for
//! whatever it starts. Every script an elevating transport runs under
//! `sudo -S` therefore reads standard input a line at a time once `sudo` has
//! granted it, and discards it up to a [`Handoff`] line: the password line if
//! `sudo` left it, then the handoff line itself. A shell reads a pipe a byte at
//! a time, so the `read` builtin stops exactly at the handoff line's newline
//! and the command's standard input begins at the caller's first byte, whether
//! or not `sudo` read the password.
//!
//! The handoff line shares standard input with the password, so it is not a
//! fixed string a password could happen to equal: it carries a nonce of
//! [`HANDOFF_NONCE_LEN`] bytes drawn from the system's secure random source for
//! one invocation alone.
//!
//! [`SudoAuth::Password`]: super::SudoAuth::Password

use aws_lc_rs::rand::SecureRandom;

use super::ExecutorError;

/// What opens every handoff line; the invocation's own random nonce follows
/// it.
const HANDOFF_PREFIX: &str = "__BOOTLER_STDIN_";
/// What closes every handoff line.
const HANDOFF_SUFFIX: &str = "__";
/// Random bytes in a handoff line's nonce.
const HANDOFF_NONCE_LEN: usize = 16;

/// The handoff line of one invocation.
pub(super) struct Handoff {
    line: String,
}

impl Handoff {
    /// Creates the handoff line of one invocation of `shell`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Spawn`] naming `shell` when the system's random
    /// source fails to draw the nonce: without it, nothing can be started
    /// under a script that discards up to the line.
    pub(super) fn new(shell: &str) -> Result<Self, ExecutorError> {
        let mut nonce = [0u8; HANDOFF_NONCE_LEN];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ExecutorError::Spawn {
                command: shell.to_string(),
                source: std::io::Error::other("system random source failed"),
            })?;
        let hex = crate::payload::to_hex(&nonce);
        Ok(Self {
            line: format!("{HANDOFF_PREFIX}{hex}{HANDOFF_SUFFIX}"),
        })
    }

    /// Returns the line to write on standard input, newline included.
    pub(super) fn line(&self) -> Vec<u8> {
        format!("{}\n", self.line).into_bytes()
    }

    /// Returns the shell fragment that reads standard input up to this
    /// handoff line and discards it, exiting `1` where standard input ends
    /// first.
    ///
    /// A stream that ends before the line arrived in full — `sudo` consumed
    /// more than its own line, or the transport broke — must not start the
    /// command, since what it would read is not the caller's input from its
    /// first byte.
    pub(super) fn discard(&self) -> String {
        format!(
            "while :; do IFS= read -r line || exit 1; [ \"$line\" = '{}' ] && break; done",
            self.line
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::*;

    /// Runs `script` under `/bin/sh` with `/bin/cat` as `$0`, feeding `input`.
    fn run(script: &str, input: &[u8]) -> std::process::Output {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .arg("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let mut stdin = child.stdin.take().expect("piped stdin");
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
        let output = child.wait_with_output().expect("wait for sh");
        writer.join().expect("writer thread");
        output
    }

    #[test]
    fn two_handoffs_differ() {
        let first = Handoff::new("/bin/sh").expect("a handoff");
        let second = Handoff::new("/bin/sh").expect("a handoff");
        assert_ne!(first.line(), second.line());
        let text = String::from_utf8(first.line()).expect("ASCII");
        assert!(text.starts_with(HANDOFF_PREFIX), "{text}");
        assert!(text.ends_with(&format!("{HANDOFF_SUFFIX}\n")), "{text}");
        assert_eq!(
            text.len(),
            HANDOFF_PREFIX.len() + 2 * HANDOFF_NONCE_LEN + HANDOFF_SUFFIX.len() + 1
        );
    }

    #[test]
    fn everything_up_to_the_line_is_discarded_and_nothing_after_it() {
        let handoff = Handoff::new("/bin/sh").expect("a handoff");
        let script = format!("{}; exec \"$0\" \"$@\"", handoff.discard());
        let decoy = format!("{HANDOFF_PREFIX}{}{HANDOFF_SUFFIX}\n", "0".repeat(32));
        for preamble in [&b""[..], b"\n", b"s3cret\n", b"two\nlines\n"] {
            for payload in [&b""[..], b"no newline", decoy.as_bytes(), b"\0\xff\n\n"] {
                let mut input = preamble.to_vec();
                input.extend_from_slice(&handoff.line());
                input.extend_from_slice(payload);
                let output = run(&script, &input);
                assert_eq!(output.status.code(), Some(0), "{preamble:?} {payload:?}");
                assert_eq!(output.stdout, payload, "{preamble:?} {payload:?}");
            }
        }
    }

    #[test]
    fn a_stream_without_the_line_starts_nothing() {
        let handoff = Handoff::new("/bin/sh").expect("a handoff");
        let script = format!("{}; exec \"$0\" \"$@\"", handoff.discard());
        let line = handoff.line();
        let unterminated = line.strip_suffix(b"\n").expect("a newline");
        for input in [&b""[..], b"s3cret\n", b"s3cret\npayload", unterminated] {
            let output = run(&script, input);
            assert_eq!(output.status.code(), Some(1), "{input:?}");
            assert!(output.stdout.is_empty(), "{input:?}");
        }
    }
}
