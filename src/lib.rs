//! Product-neutral deploy primitives shared by the installer and the on-host agent.
//!
//! `deploy-core` is the slim, component-agnostic core of the deploy stack: the
//! transport and execution vocabulary, the on-host directory layout, the payload
//! and manifest formats — one container whether it rides on a base executable or
//! stands alone as a `.pkg` module package — the declarative per-module install
//! spec a package carries in its manifest with the systemd serialization rule its
//! strings are held to, the generic renderer that turns such a spec into a systemd
//! unit, the one package verifier both the control plane and the root daemon reach
//! a verdict through, the install/update diff engine, the apply primitives, the
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
pub mod engine;
pub mod exec;
pub mod executor;
pub mod layout;
pub mod manifest;
pub mod module_spec;
pub mod payload;
pub mod registration;
pub mod render;
pub mod roxyd_trust;
pub mod systemd;
pub mod transport;
pub mod verify;
