//! Product-neutral on-host directory layout.
//!
//! Every install tree is rooted at a single **namespace** (`clumit-security`,
//! `clumit-insight`, …) under the fixed `/opt`, `/etc`, `/var/lib` prefixes.
//! [`Layout`] derives every managed path from that namespace alone — the
//! software, config, and variable-data directories, the module store, and the
//! bootroot-state, roxyd-trust and release-trust subtrees. It carries **no**
//! product concept (no component catalog, no ports), so an external consumer
//! such as the on-host agent can resolve the same paths without the installer's
//! `ProductManifest`.
//!
//! The installer's `ProductManifest` embeds a `Layout` and delegates its path
//! accessors to it, so existing callers are unchanged while the generic paths
//! are reusable on their own.

use std::path::{Path, PathBuf};

/// Mode of the `/opt` and `/etc` namespace roots (RFC 0003 §7.1): root-owned,
/// group the product account, `0751` so `clumit-roxyd` — deliberately not a member
/// of the product group — can *traverse* to `agent/roxyd/` and execute
/// `bootroot-agent` from `<opt>/bin` without gaining list or read on the tree.
///
/// A structural namespace-root fact (no component concept), so it lives with the
/// other namespace layout here; the installer's `product` module re-exports it for
/// existing callers.
pub const NAMESPACE_ROOT_TRAVERSE_MODE: u32 = 0o751;
/// Mode of the `/var/lib` namespace root (RFC 0003 §7.1): `0750`, since nothing
/// outside the namespace needs to traverse it.
pub const NAMESPACE_ROOT_DATA_MODE: u32 = 0o750;

/// The variable-data subdirectory holding the REview-accessible module store.
pub(crate) const MODULE_STORE_SUBDIR: &str = "module-store";
/// The variable-data subdirectory bootroot's state tree resolves under.
const BOOTROOT_STATE_SUBDIR: &str = "bootroot";
/// The bootroot-state subdirectory bootroot's secrets tree resolves under.
const BOOTROOT_SECRETS_SUBDIR: &str = "secrets";
/// The bootroot-secrets subdirectory `step ca init` writes CA material under.
const BOOTROOT_CA_CERTS_SUBDIR: &str = "certs";
/// bootroot's internal CA root certificate basename.
const BOOTROOT_CA_ROOT_FILE: &str = "root_ca.crt";
/// The config subdirectory holding roxyd's root-owned validated trust root.
const ROXYD_TLS_SUBDIR: &str = "roxyd-tls";
/// The config subdirectory holding the root-owned release-signing trust root — a
/// **sibling** of `roxyd-tls/`, never inside it, since the two carry different trust
/// (release provenance rather than PKI) and share no generation index or `active`
/// link.
const RELEASE_TRUST_SUBDIR: &str = "release-trust";
/// The fixed `active` symlink at the root of a trust tree, which its readers resolve
/// their material through. Tree-neutral: every root-owned trust tree the generation
/// engine drives uses this one name, so no two trees can drift apart on it.
pub(crate) const ACTIVE_LINK: &str = "active";
/// The `gen-<n>/` generation-directory prefix inside a trust tree. Tree-neutral for
/// the same reason as [`ACTIVE_LINK`]: it is a name the engine parses, and only this
/// crate parses it.
pub(crate) const GENERATION_PREFIX: &str = "gen-";
/// roxyd's client-identity trust-anchor snapshot basename.
const ROXYD_CLIENT_ANCHOR_FILE: &str = "client-anchor.pem";
/// roxyd's client certificate basename inside a trust directory.
const ROXYD_CERT_BASENAME: &str = "roxyd-cert.pem";
/// roxyd's client private-key basename inside a trust directory.
const ROXYD_KEY_BASENAME: &str = "roxyd-key.pem";
/// The internal CA bundle basename a bootroot agent writes beside a cert.
pub const CA_BUNDLE_FILE: &str = "ca-bundle.pem";
/// The basename of the host-side marker whose presence demands an out-of-band
/// fingerprint pin before a host may be re-bootstrapped past the retention floor.
///
/// The installer that creates the marker and the runtime that gates on it live in
/// different repositories, and two sides that each join their own path do not fail
/// loudly when they drift — they leave the gate off on a host that asked for it. So
/// this constant is the **single declaration** of the name, and every side resolves
/// the file by joining it rather than by spelling it: a caller holding a namespace
/// through [`Layout::require_pin_marker`], and
/// [`crate::release_trust::rebootstrap_generation`], which is handed the
/// already-resolved tree root, through that module's own root-based helper. Two
/// resolutions of one name, never two names.
pub const REQUIRE_TRUST_PIN_MARKER: &str = "require-trust-pin";

/// The basename of the operator-delivered generation a host with no prior
/// release-trust generation is bootstrapped from.
///
/// Written at the root of the release-trust tree by the operator-mediated join
/// channel — the same out-of-band delivery that carries the mTLS CA anchor — and
/// read by [`crate::release_trust::bootstrap_from_join_material`], for which **the
/// location is the enforcement**: that entry point accepts no caller-supplied
/// generation bytes at all.
///
/// Declared and resolved exactly as [`REQUIRE_TRUST_PIN_MARKER`] is: this constant
/// is the single declaration, [`Layout::join_generation_path`] resolves it for a
/// caller holding a namespace, and the release-trust module's own root-based helper
/// resolves it for the reader holding a tree root.
pub const JOIN_GENERATION_FILE: &str = "join-generation.pkg";

/// The on-host directory layout for one namespaced install tree.
///
/// Cheap to construct and copy; every accessor returns an owned [`PathBuf`]
/// derived from the namespace, so it borrows nothing beyond the namespace
/// string itself.
#[derive(Debug, Clone, Copy)]
pub struct Layout<'a> {
    namespace: &'a str,
}

impl<'a> Layout<'a> {
    /// Builds a layout rooted at `namespace` (e.g. `clumit-security`).
    #[must_use]
    pub fn new(namespace: &'a str) -> Self {
        Self { namespace }
    }

    /// Returns the namespace this layout is rooted at.
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.namespace
    }

    /// Returns the default software directory (`/opt/clumit-<product>`).
    #[must_use]
    pub fn opt_dir(&self) -> PathBuf {
        PathBuf::from("/opt").join(self.namespace)
    }

    /// Returns the default configuration directory (`/etc/clumit-<product>`),
    /// home of the root-owned `secrets.json` (RFC 0001 §4/§7).
    #[must_use]
    pub fn etc_dir(&self) -> PathBuf {
        PathBuf::from("/etc").join(self.namespace)
    }

    /// Returns the default variable-data directory (`/var/lib/clumit-<product>`).
    #[must_use]
    pub fn var_dir(&self) -> PathBuf {
        PathBuf::from("/var/lib").join(self.namespace)
    }

    /// Returns the REview-accessible module-store directory
    /// (`/var/lib/clumit-<product>/module-store/`) baseline packages are written
    /// into (RFC 0001 §3 / §6 Phase 4).
    #[must_use]
    pub fn module_store_dir(&self) -> PathBuf {
        self.var_dir().join(MODULE_STORE_SUBDIR)
    }

    /// Returns bootroot's state directory under the variable-data tree.
    #[must_use]
    pub fn bootroot_state_dir(&self) -> PathBuf {
        self.var_dir().join(BOOTROOT_STATE_SUBDIR)
    }

    /// Returns the absolute directory bootroot's secrets tree resolves to under
    /// the pinned working directory, where `init`/`service add` write bootroot's
    /// secrets and where Phase 3 fetches the remote-bootstrap bundle from.
    #[must_use]
    pub fn bootroot_secrets_dir(&self) -> PathBuf {
        self.bootroot_state_dir().join(BOOTROOT_SECRETS_SUBDIR)
    }

    /// Returns the path to bootroot's internal CA **root** certificate on the
    /// bootroot host (`<bootroot-secrets>/certs/root_ca.crt`) — the self-signed
    /// root `step ca init` writes (RFC 0003 §8.3).
    #[must_use]
    pub fn bootroot_ca_root_path(&self) -> PathBuf {
        self.bootroot_secrets_dir()
            .join(BOOTROOT_CA_CERTS_SUBDIR)
            .join(BOOTROOT_CA_ROOT_FILE)
    }

    /// Returns roxyd's root-owned validated trust root, `<etc>/roxyd-tls/`
    /// (root:root 0700). The accessor is unconditional so callers derive the
    /// path uniformly even for a product that ships no roxyd (RFC 0003 §8.3).
    #[must_use]
    pub fn roxyd_tls_dir(&self) -> PathBuf {
        self.etc_dir().join(ROXYD_TLS_SUBDIR)
    }

    /// Returns the fixed `active` symlink inside [`roxyd_tls_dir`] that roxyd's
    /// `ExecStart` reads its cert/key/CA through; the activation helper repoints
    /// it atomically at the current [`roxyd_generation_dir`].
    ///
    /// [`roxyd_tls_dir`]: Layout::roxyd_tls_dir
    /// [`roxyd_generation_dir`]: Layout::roxyd_generation_dir
    #[must_use]
    pub fn roxyd_active_dir(&self) -> PathBuf {
        self.roxyd_tls_dir().join(ACTIVE_LINK)
    }

    /// Returns the generation directory `roxyd-tls/gen-<generation>/` a validated
    /// snapshot is installed into before [`roxyd_active_dir`] is repointed at it.
    ///
    /// [`roxyd_active_dir`]: Layout::roxyd_active_dir
    #[must_use]
    pub fn roxyd_generation_dir(&self, generation: u64) -> PathBuf {
        self.roxyd_tls_dir()
            .join(format!("{GENERATION_PREFIX}{generation}"))
    }

    /// Returns the root-owned release-signing trust root, `<etc>/release-trust/`
    /// (root:root 0700) — a **sibling** of [`roxyd_tls_dir`], never inside it. It
    /// carries release-provenance trust rather than PKI, and shares no directory, no
    /// generation index and no `active` link with the mTLS tree, so the two can
    /// never be conflated.
    ///
    /// [`roxyd_tls_dir`]: Layout::roxyd_tls_dir
    #[must_use]
    pub fn release_trust_dir(&self) -> PathBuf {
        self.etc_dir().join(RELEASE_TRUST_SUBDIR)
    }

    /// Returns the fixed `active` symlink inside [`release_trust_dir`], which a
    /// reader resolves the current release-signing trust set through; the activation
    /// helper repoints it atomically at the current
    /// [`release_trust_generation_dir`].
    ///
    /// [`release_trust_dir`]: Layout::release_trust_dir
    /// [`release_trust_generation_dir`]: Layout::release_trust_generation_dir
    #[must_use]
    pub fn release_trust_active_dir(&self) -> PathBuf {
        self.release_trust_dir().join(ACTIVE_LINK)
    }

    /// Returns the generation directory `release-trust/gen-<generation>/` a validated
    /// release-signing trust set is installed into before
    /// [`release_trust_active_dir`] is repointed at it. Its generation index is the
    /// release-trust tree's own and is unrelated to the mTLS tree's.
    ///
    /// [`release_trust_active_dir`]: Layout::release_trust_active_dir
    #[must_use]
    pub fn release_trust_generation_dir(&self, generation: u64) -> PathBuf {
        self.release_trust_dir()
            .join(format!("{GENERATION_PREFIX}{generation}"))
    }

    /// Returns the host-side re-bootstrap pin marker — [`REQUIRE_TRUST_PIN_MARKER`]
    /// inside [`release_trust_dir`] — for a caller that holds a namespace, such as
    /// the installer that creates it.
    ///
    /// The name is declared once, in that constant, and this is one of its two
    /// resolutions. The other is the release-trust module's root-based helper,
    /// which is what the runtime gate reads the marker through: that path is handed
    /// the already-resolved tree root and cannot reconstruct a namespace to call
    /// this accessor with. Both join the same constant onto the same directory, so
    /// they cannot drift.
    ///
    /// It sits at the **root** of the release-trust tree, beside `active` and the
    /// generation directories and never inside a generation: the generation engine
    /// enumerates only `active` and `gen-<n>` there, so an activation leaves the
    /// marker byte-identical and a prune never removes it. The root-owned tree
    /// directory is also exactly what makes the marker unclearable by the control
    /// plane the gate defends against.
    ///
    /// [`release_trust_dir`]: Layout::release_trust_dir
    #[must_use]
    pub fn require_pin_marker(&self) -> PathBuf {
        self.release_trust_dir().join(REQUIRE_TRUST_PIN_MARKER)
    }

    /// Returns the operator-delivered join generation — [`JOIN_GENERATION_FILE`]
    /// inside [`release_trust_dir`] — for a caller that holds a namespace, such as
    /// the provisioning side that writes the file.
    ///
    /// The name is declared once, in that constant, and this is one of its two
    /// resolutions; the release-trust module's root-based helper is the other, for
    /// [`crate::release_trust::bootstrap_from_join_material`], which is handed the
    /// tree root alone.
    ///
    /// It sits at the **root** of the release-trust tree for the same reason the pin
    /// marker does: the generation engine enumerates only `active` and `gen-<n>`
    /// there, so a file at this path is never staged, activated or pruned, and the
    /// root-owned directory is what makes the location itself the enforcement.
    ///
    /// [`release_trust_dir`]: Layout::release_trust_dir
    #[must_use]
    pub fn join_generation_path(&self) -> PathBuf {
        self.release_trust_dir().join(JOIN_GENERATION_FILE)
    }

    /// Returns roxyd's client-identity trust-anchor snapshot,
    /// `roxyd-tls/client-anchor.pem` (root:root 0644) — the internal CA root the
    /// activation helper requires roxyd's staged leaf to chain to (RFC 0003 §8.3).
    #[must_use]
    pub fn roxyd_client_anchor_path(&self) -> PathBuf {
        self.roxyd_tls_dir().join(ROXYD_CLIENT_ANCHOR_FILE)
    }

    /// Returns the cert/key/CA-bundle triple inside a given roxyd trust directory
    /// (an `active` symlink or a `gen-<n>/`). The basenames match what the
    /// bootroot agent writes into `agent/roxyd/`, so a generation is a like-named
    /// copy of the staged material.
    #[must_use]
    pub fn roxyd_material_in(&self, dir: &Path) -> RoxydMaterialPaths {
        RoxydMaterialPaths {
            cert: dir.join(ROXYD_CERT_BASENAME),
            key: dir.join(ROXYD_KEY_BASENAME),
            ca_bundle: dir.join(CA_BUNDLE_FILE),
        }
    }
}

/// Returns the Roxyd unit name (`<namespace>-roxyd.service`), the single source of
/// truth shared by the install path, the uninstall teardown, and the trust-material
/// activation reload. A namespace-derived name, so it lives with the other
/// namespace layout in this product-neutral module.
#[must_use]
pub fn roxyd_unit_name(namespace: &str) -> String {
    format!("{namespace}-roxyd.service")
}

/// The cert/key/CA-bundle file triple inside one roxyd trust directory, returned
/// by [`Layout::roxyd_material_in`].
#[derive(Debug, Clone)]
pub struct RoxydMaterialPaths {
    /// roxyd's client certificate PEM.
    pub cert: PathBuf,
    /// roxyd's client private key PEM.
    pub key: PathBuf,
    /// The internal CA bundle roxyd hands to `.root_certs()` to verify the Manager.
    pub ca_bundle: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::{JOIN_GENERATION_FILE, Layout, RELEASE_TRUST_SUBDIR, REQUIRE_TRUST_PIN_MARKER};

    #[test]
    fn the_release_trust_tree_is_a_sibling_of_the_mtls_tree() {
        let layout = Layout::new("clumit-security");
        let release = layout.release_trust_dir();
        assert_eq!(release, layout.etc_dir().join(RELEASE_TRUST_SUBDIR));
        assert_eq!(release, layout.etc_dir().join("release-trust"));

        let mtls = layout.roxyd_tls_dir();
        for path in [
            release.clone(),
            layout.release_trust_active_dir(),
            layout.release_trust_generation_dir(7),
            layout.require_pin_marker(),
            layout.join_generation_path(),
        ] {
            assert!(
                path.starts_with(&release),
                "{} must resolve under the release-trust tree",
                path.display(),
            );
            assert!(
                !path.starts_with(&mtls),
                "{} must not resolve inside the mTLS tree",
                path.display(),
            );
        }

        // Each tree carries its own `active` and its own generation index, under its
        // own root.
        assert_ne!(layout.release_trust_active_dir(), layout.roxyd_active_dir());
        assert_ne!(
            layout.release_trust_generation_dir(1),
            layout.roxyd_generation_dir(1),
        );
        assert_eq!(
            layout.release_trust_generation_dir(3),
            release.join("gen-3"),
        );
    }

    #[test]
    fn the_pin_marker_resolves_through_the_shared_constant() {
        let layout = Layout::new("clumit-security");
        assert_eq!(
            layout.require_pin_marker(),
            layout.release_trust_dir().join(REQUIRE_TRUST_PIN_MARKER),
        );
    }

    #[test]
    fn the_join_generation_resolves_through_the_shared_constant() {
        let layout = Layout::new("clumit-security");
        assert_eq!(
            layout.join_generation_path(),
            layout.release_trust_dir().join(JOIN_GENERATION_FILE),
        );
    }
}
