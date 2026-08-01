//! Product-neutral on-host directory layout.
//!
//! Every install tree is rooted at a single **namespace** (`clumit-security`,
//! `clumit-insight`, …) under the fixed `/opt`, `/etc`, `/var/lib` prefixes.
//! [`Layout`] derives every managed path from that namespace alone — the
//! software, config, and variable-data directories, the module store, and the
//! bootroot-state and roxyd-trust subtrees. It carries **no** product concept
//! (no component catalog, no ports), so an external consumer such as the
//! on-host agent can resolve the same paths without the installer's
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
/// The fixed `active` symlink inside `roxyd-tls/` roxyd reads its material through.
pub(crate) const ROXYD_ACTIVE_LINK: &str = "active";
/// The `gen-<n>/` generation-directory prefix inside `roxyd-tls/`.
pub(crate) const ROXYD_GENERATION_PREFIX: &str = "gen-";
/// roxyd's client-identity trust-anchor snapshot basename.
const ROXYD_CLIENT_ANCHOR_FILE: &str = "client-anchor.pem";
/// roxyd's client certificate basename inside a trust directory.
const ROXYD_CERT_BASENAME: &str = "roxyd-cert.pem";
/// roxyd's client private-key basename inside a trust directory.
const ROXYD_KEY_BASENAME: &str = "roxyd-key.pem";
/// The internal CA bundle basename a bootroot agent writes beside a cert.
pub const CA_BUNDLE_FILE: &str = "ca-bundle.pem";

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
        self.roxyd_tls_dir().join(ROXYD_ACTIVE_LINK)
    }

    /// Returns the generation directory `roxyd-tls/gen-<generation>/` a validated
    /// snapshot is installed into before [`roxyd_active_dir`] is repointed at it.
    ///
    /// [`roxyd_active_dir`]: Layout::roxyd_active_dir
    #[must_use]
    pub fn roxyd_generation_dir(&self, generation: u64) -> PathBuf {
        self.roxyd_tls_dir()
            .join(format!("{ROXYD_GENERATION_PREFIX}{generation}"))
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
