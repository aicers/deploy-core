//! Generic SSH-transport types shared by the executor.
//!
//! These describe *how to reach a host* — an address and an optional `ssh`
//! block with its host-key policy — independent of any product or component.
//! They are consumed by [`crate::executor`] to build an SSH invocation and are
//! deliberately free of product concepts (no `Component`), so the execution
//! primitives that use them carry no product-specific knowledge. The install
//! configuration schema in `crate::config` re-exports them for its own
//! `[hosts]` parsing.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// SSH port used when a host's `ssh` block omits `port`.
const DEFAULT_SSH_PORT: u16 = 22;

/// One `[hosts.<name>]` entry.
///
/// A host without an `ssh` block refers to the seat and is reached by the local
/// executor; a host with one is remote (reached over SSH in slice 3).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Reachable IP or host for connecting. This is not the FQDN; the effective
    /// FQDN is derived from the host key and `network.domain`.
    pub address: String,
    /// SSH access details; absent for the seat.
    #[serde(default)]
    pub ssh: Option<Ssh>,
}

/// The `ssh = { user, port, key, host_key }` block on a remote host.
///
/// The SSH executor (slice 3) consumes this to build its `ssh` invocation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    /// SSH login user.
    pub user: String,
    /// SSH port.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Path to the private key.
    pub key: PathBuf,
    /// Host-key checking policy; defaults to strict (RFC 0001 §4).
    #[serde(default)]
    pub host_key: HostKeyPolicy,
}

/// SSH host-key checking policy for a remote host (RFC 0001 §4).
///
/// Maps to OpenSSH's `StrictHostKeyChecking`. Strict is the default; the
/// `accept-new` escape trusts a host's key on first contact but still refuses a
/// key that later changes. There is deliberately no global disable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyPolicy {
    /// `StrictHostKeyChecking=yes`: the host key must already be known.
    #[default]
    Strict,
    /// `StrictHostKeyChecking=accept-new`: trust a new key on first contact,
    /// still refuse a key that changes afterward.
    AcceptNew,
}

impl HostKeyPolicy {
    /// Returns the OpenSSH `StrictHostKeyChecking` value for this policy.
    #[must_use]
    pub fn strict_host_key_checking(self) -> &'static str {
        match self {
            HostKeyPolicy::Strict => "yes",
            HostKeyPolicy::AcceptNew => "accept-new",
        }
    }
}

/// Returns the default SSH port.
fn default_ssh_port() -> u16 {
    DEFAULT_SSH_PORT
}
