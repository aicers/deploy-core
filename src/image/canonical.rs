//! The canonical OCI image manifest: the one manifest an image archive may
//! carry for a given config.
//!
//! Many manifests can describe one config — gzip or uncompressed layers,
//! different gzip bytes, annotations, key order, whitespace — and a runtime
//! that names an image by its manifest digest would see each as a different
//! image. The profile removes that freedom. The config's digest and length
//! fix its descriptor; its `rootfs.diff_ids` fix every layer's uncompressed
//! bytes, and so their lengths; and the canonical manifest is those values
//! written in one fixed byte form. Its digest is therefore a pure function of
//! the config.
//!
//! [`canonical_image_manifest`] is the single definition of that form.
//! Producers call it when they normalize an archive, and the archive
//! validator compares every manifest blob with its output byte for byte.

use super::{SHA256_DIGEST_PREFIX, is_lower_hex};
use crate::manifest::IMAGE_DIGEST_HEX_LEN;

/// The OCI image manifest media type.
pub(super) const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// The OCI image config media type.
pub(super) const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
/// The uncompressed OCI layer media type, the only one a canonical manifest
/// names.
pub(super) const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// Everything ahead of the config descriptor.
const MANIFEST_HEAD: &str = r#"{"schemaVersion":2,"mediaType":"#;
const CONFIG_KEY: &str = r#","config":"#;
const LAYERS_KEY: &str = r#","layers":["#;
const MANIFEST_TAIL: &str = "]}";

const DESCRIPTOR_MEDIA_TYPE: &str = r#"{"mediaType":""#;
const DESCRIPTOR_DIGEST: &str = r#"","digest":""#;
const DESCRIPTOR_SIZE: &str = r#"","size":"#;
const DESCRIPTOR_TAIL: &str = "}";

/// The most decimal digits a `u64` takes.
const MAX_U64_DIGITS: usize = 20;

/// Why [`canonical_image_manifest`] could not render a manifest. No variant
/// echoes an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalManifestError {
    /// The config digest is not `sha256:` and 64 lowercase hex characters.
    #[error("the config digest is not `sha256:` and 64 lowercase hex characters")]
    InvalidConfigDigest,
    /// The config length is zero; a config is a nonempty JSON object.
    #[error("the config is empty")]
    EmptyConfig,
    /// A diff ID is not `sha256:` and 64 lowercase hex characters.
    #[error("the diff id of layer {position} is not `sha256:` and 64 lowercase hex characters")]
    InvalidDiffId {
        /// The layer's zero-based position.
        position: usize,
    },
    /// The manifest's length overflows, or memory for it cannot be reserved.
    #[error("the canonical manifest is too large to render")]
    TooLarge,
}

/// Renders the canonical image manifest of a config, as the exact bytes an
/// image archive must store.
///
/// `config_digest` and `config_size` are the config blob's `sha256:` digest
/// and byte length. `layers` holds, for each position of the config's
/// `rootfs.diff_ids` in order, that diff ID and the byte length of the
/// uncompressed layer tar it names. A repeated diff ID keeps one entry per
/// position, and a config with no diff IDs renders `"layers":[]`.
///
/// The output is compact JSON with no whitespace and no trailing newline,
/// keys in exactly this order and integers in plain decimal:
///
/// ```text
/// {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
///  "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"<config_digest>","size":<config_size>},
///  "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"<diff ID>","size":<size>},…]}
/// ```
///
/// (shown wrapped; the bytes carry no line break). Every layer is
/// uncompressed, so its blob digest is its diff ID. Nothing else is written:
/// no `annotations`, `artifactType`, `subject`, `urls` or `data`.
///
/// ```
/// use deploy_core::image::canonical_image_manifest;
///
/// let config = format!("sha256:{}", "c".repeat(64));
/// let layer = format!("sha256:{}", "1".repeat(64));
/// let manifest = canonical_image_manifest(&config, 7, &[(&layer, 2048)]).unwrap();
/// assert!(manifest.starts_with(br#"{"schemaVersion":2,"mediaType":"#));
/// assert!(manifest.ends_with(b"\"size\":2048}]}"));
/// ```
///
/// # Errors
///
/// Checked in this order, the first failure winning:
/// [`CanonicalManifestError::InvalidConfigDigest`] for a malformed config
/// digest, [`CanonicalManifestError::EmptyConfig`] for a zero config length,
/// [`CanonicalManifestError::InvalidDiffId`] for the first malformed diff ID,
/// and [`CanonicalManifestError::TooLarge`] when the output's length
/// overflows or cannot be reserved.
pub fn canonical_image_manifest(
    config_digest: &str,
    config_size: u64,
    layers: &[(&str, u64)],
) -> Result<Vec<u8>, CanonicalManifestError> {
    if !is_digest(config_digest) {
        return Err(CanonicalManifestError::InvalidConfigDigest);
    }
    if config_size == 0 {
        return Err(CanonicalManifestError::EmptyConfig);
    }
    if let Some(position) = layers.iter().position(|(diff_id, _)| !is_digest(diff_id)) {
        return Err(CanonicalManifestError::InvalidDiffId { position });
    }

    let fixed = [
        MANIFEST_HEAD.len() + OCI_MANIFEST_MEDIA_TYPE.len() + 2,
        CONFIG_KEY.len(),
        descriptor_max_len(OCI_CONFIG_MEDIA_TYPE),
        LAYERS_KEY.len(),
        MANIFEST_TAIL.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add);
    // One comma ahead of every layer but the first.
    let per_layer = descriptor_max_len(OCI_LAYER_MEDIA_TYPE).checked_add(1);
    let capacity = per_layer
        .and_then(|per_layer| per_layer.checked_mul(layers.len()))
        .zip(fixed)
        .and_then(|(layers, fixed)| layers.checked_add(fixed))
        .ok_or(CanonicalManifestError::TooLarge)?;
    let mut out = String::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| CanonicalManifestError::TooLarge)?;

    out.push_str(MANIFEST_HEAD);
    out.push('"');
    out.push_str(OCI_MANIFEST_MEDIA_TYPE);
    out.push('"');
    out.push_str(CONFIG_KEY);
    push_descriptor(&mut out, OCI_CONFIG_MEDIA_TYPE, config_digest, config_size);
    out.push_str(LAYERS_KEY);
    for (position, (diff_id, size)) in layers.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        push_descriptor(&mut out, OCI_LAYER_MEDIA_TYPE, diff_id, *size);
    }
    out.push_str(MANIFEST_TAIL);
    Ok(out.into_bytes())
}

/// Whether `value` is `sha256:` and 64 lowercase hex characters.
fn is_digest(value: &str) -> bool {
    value
        .strip_prefix(SHA256_DIGEST_PREFIX)
        .is_some_and(|hex| hex.len() == IMAGE_DIGEST_HEX_LEN && is_lower_hex(hex))
}

/// The longest a descriptor of `media_type` can render.
const fn descriptor_max_len(media_type: &str) -> usize {
    DESCRIPTOR_MEDIA_TYPE.len()
        + media_type.len()
        + DESCRIPTOR_DIGEST.len()
        + SHA256_DIGEST_PREFIX.len()
        + IMAGE_DIGEST_HEX_LEN
        + DESCRIPTOR_SIZE.len()
        + MAX_U64_DIGITS
        + DESCRIPTOR_TAIL.len()
}

/// Appends one descriptor. The digest has been checked, and the media types
/// are constants, so nothing needs escaping.
fn push_descriptor(out: &mut String, media_type: &str, digest: &str, size: u64) {
    out.push_str(DESCRIPTOR_MEDIA_TYPE);
    out.push_str(media_type);
    out.push_str(DESCRIPTOR_DIGEST);
    out.push_str(digest);
    out.push_str(DESCRIPTOR_SIZE);
    out.push_str(&size.to_string());
    out.push_str(DESCRIPTOR_TAIL);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

    const CONFIG_HEAD: &str = concat!(
        r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
        r#""config":{"mediaType":"application/vnd.oci.image.config.v1+json","#,
    );

    fn render(config_size: u64, layers: &[(&str, u64)]) -> String {
        String::from_utf8(canonical_image_manifest(&digest('c'), config_size, layers).unwrap())
            .unwrap()
    }

    #[test]
    fn zero_layers_render_an_empty_array() {
        assert_eq!(
            render(1, &[]),
            format!(
                "{CONFIG_HEAD}\"digest\":\"sha256:{}\",\"size\":1}},\"layers\":[]}}",
                "c".repeat(64)
            )
        );
        // The same bytes, spelled out.
        assert_eq!(
            render(1, &[]),
            concat!(
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                r#""config":{"mediaType":"application/vnd.oci.image.config.v1+json","#,
                r#""digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","#,
                r#""size":1},"layers":[]}"#,
            )
        );
    }

    #[test]
    fn one_layer_renders_exactly() {
        let one = digest('1');
        assert_eq!(
            render(1234, &[(&one, 2048)]),
            concat!(
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                r#""config":{"mediaType":"application/vnd.oci.image.config.v1+json","#,
                r#""digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","#,
                r#""size":1234},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
                r#""size":2048}]}"#,
            )
        );
    }

    #[test]
    fn several_layers_render_in_order() {
        let (one, two, three) = (digest('1'), digest('2'), digest('3'));
        assert_eq!(
            render(
                u64::MAX,
                &[
                    (&three, 0),
                    (&one, 1024),
                    (&two, 18_446_744_073_709_551_615)
                ]
            ),
            concat!(
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                r#""config":{"mediaType":"application/vnd.oci.image.config.v1+json","#,
                r#""digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","#,
                r#""size":18446744073709551615},"layers":["#,
                r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","#,
                r#""size":0},"#,
                r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
                r#""size":1024},"#,
                r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","#,
                r#""size":18446744073709551615}]}"#,
            )
        );
    }

    #[test]
    fn a_repeated_diff_id_keeps_one_entry_per_position() {
        let (one, two) = (digest('1'), digest('2'));
        assert_eq!(
            render(9, &[(&one, 3072), (&two, 1536), (&one, 3072)]),
            concat!(
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                r#""config":{"mediaType":"application/vnd.oci.image.config.v1+json","#,
                r#""digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","#,
                r#""size":9},"layers":["#,
                r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
                r#""size":3072},"#,
                r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","#,
                r#""size":1536},"#,
                r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar","#,
                r#""digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
                r#""size":3072}]}"#,
            )
        );
    }

    #[test]
    fn the_capacity_bound_covers_every_render() {
        let one = digest('1');
        let layers = vec![(one.as_str(), u64::MAX); 3];
        let rendered = canonical_image_manifest(&digest('c'), u64::MAX, &layers).unwrap();
        let fixed = MANIFEST_HEAD.len()
            + OCI_MANIFEST_MEDIA_TYPE.len()
            + 2
            + CONFIG_KEY.len()
            + descriptor_max_len(OCI_CONFIG_MEDIA_TYPE)
            + LAYERS_KEY.len()
            + MANIFEST_TAIL.len();
        // At the maximum size every descriptor reaches its bound, and every
        // layer but the first carries its comma.
        assert_eq!(
            rendered.len(),
            fixed + 3 * descriptor_max_len(OCI_LAYER_MEDIA_TYPE) + 2
        );
    }

    #[test]
    fn every_input_is_validated_in_order() {
        let good = digest('1');
        for bad in [
            String::new(),
            "sha256:".to_string(),
            "c".repeat(64),
            format!("sha256:{}", "C".repeat(64)),
            format!("sha256:{}", "c".repeat(63)),
            format!("sha256:{}", "c".repeat(65)),
            format!("sha512:{}", "c".repeat(64)),
            format!("sha256:{}g", "c".repeat(63)),
            format!(" sha256:{}", "c".repeat(64)),
        ] {
            assert_eq!(
                canonical_image_manifest(&bad, 0, &[("bad", 1)]),
                Err(CanonicalManifestError::InvalidConfigDigest)
            );
            assert_eq!(
                canonical_image_manifest(&digest('c'), 1, &[(&good, 1), (&bad, 1)]),
                Err(CanonicalManifestError::InvalidDiffId { position: 1 })
            );
        }
        assert_eq!(
            canonical_image_manifest(&digest('c'), 0, &[("bad", 1)]),
            Err(CanonicalManifestError::EmptyConfig)
        );
    }

    #[test]
    fn the_error_messages_are_fixed_lowercase_phrases() {
        for error in [
            CanonicalManifestError::InvalidConfigDigest,
            CanonicalManifestError::EmptyConfig,
            CanonicalManifestError::InvalidDiffId { position: 3 },
            CanonicalManifestError::TooLarge,
        ] {
            let message = error.to_string();
            assert_eq!(message, message.to_lowercase());
        }
        assert!(
            CanonicalManifestError::InvalidDiffId { position: 3 }
                .to_string()
                .contains("layer 3")
        );
    }
}
