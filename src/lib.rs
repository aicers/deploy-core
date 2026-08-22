//! Product-neutral deploy primitives shared by the installer and the on-host agent.
//!
//! `deploy-core` is the slim, component-agnostic core of the deploy stack: the
//! transport and execution vocabulary, the on-host directory layout, the payload
//! and manifest formats — one container whether it rides on a base executable or
//! stands alone as a `.pkg` module package — the declarative per-module install
//! spec a package carries in its manifest with the systemd serialization rule its
//! strings are held to, the generic renderer that turns such a spec into a systemd
//! unit, the one package verifier both the control plane and the root daemon reach
//! a verdict through, the trust-set generation document that verifier's material
//! is delivered as together with the reader that refuses a malformed one, the
//! on-host release-trust tree that document is installed into and the constructor
//! that turns its active generation back into the verifier's injected trust set,
//! the install/update diff engine, the apply primitives, the canonical
//! self-update rollback supervisor unit text both installers embed rather than
//! each carrying a copy, the
//! bootroot command wrapper, service registration, and the on-host trust-material
//! activation. It carries **no** product concept — no component catalog, no
//! per-component renderers — so both the installer and the per-machine root daemon
//! depend on it and share a single implementation rather than shelling out to a
//! CLI.
//!
//! The product-specific install/update orchestration, the component catalog, and
//! the per-component rendering stay in the installer crate, which depends on this
//! one.

pub mod apply;
pub mod bootroot_cmd;
// The one directory flush every staged write in this crate publishes through.
// Crate-private: it is an implementation detail of those writes, not vocabulary
// a dependent has any reason to name.
pub(crate) mod durability;
pub mod engine;
pub mod exec;
pub mod executor;
// The tree-neutral trust-generation engine. Crate-private: every caller — the roxyd
// mTLS adapter and the release-trust tree's — is in this crate, and each exports its
// own entry point, so nothing outside needs to name the engine or its types.
pub(crate) mod generation;
pub mod layout;
pub mod manifest;
pub mod module_spec;
pub mod payload;
pub mod registration;
pub mod release_trust;
pub mod render;
pub mod roxyd_selfupdate;
pub mod roxyd_trust;
pub mod systemd;
pub mod transport;
// The signed single-member trust-container fixture, shared by every test module
// that mints one. Test-only, so minting a generation stays impossible in a
// release build.
#[cfg(test)]
pub(crate) mod trust_fixture;
pub mod trust_set;
pub mod verify;
