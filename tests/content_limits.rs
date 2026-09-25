//! The public `package::ContentLimits` policy, exercised from outside the
//! crate the way a consumer sees it.

use std::collections::HashSet;

use deploy_core::package::{ContentLimits, ContentLimitsError, LimitResource};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// A hard-coded copy of the default table, in table order.
const TABLE: &[(LimitResource, u64)] = &[
    (LimitResource::RawManifest, 16 * MIB),
    (LimitResource::CompressedArchive, 64 * GIB),
    (LimitResource::Package, 64 * GIB + 16 * MIB + 201),
    (LimitResource::OuterMembers, 1024),
    (LimitResource::OuterUncompressedTotal, 128 * GIB),
    (LimitResource::ImageArchive, 32 * GIB),
    (LimitResource::StoredLayerBlob, 16 * GIB),
    (LimitResource::DecodedLayer, 16 * GIB),
    (LimitResource::DecodedLayersPerImage, 128 * GIB),
    (LimitResource::DecodedLayersPerOperation, 256 * GIB),
    (LimitResource::GzipHeader, 64 * KIB),
    (LimitResource::ImageEntries, 4096),
    (LimitResource::ImagePathBytes, 255),
    (LimitResource::LayersPerImage, 256),
    (LimitResource::TagsPerImage, 256),
    (LimitResource::IndexJson, MIB),
    (LimitResource::ImageManifestJson, MIB),
    (LimitResource::CompatibilityJson, MIB),
    (LimitResource::ConfigJson, 4 * MIB),
    (LimitResource::OciLayout, KIB),
    (LimitResource::ImageJsonTotal, 16 * MIB),
    (LimitResource::JsonDepth, 64),
    (LimitResource::LayerEntries, 1_000_000),
    (LimitResource::LayerPathBytes, 4096),
    (LimitResource::LayerLinkTargetBytes, 4096),
    (LimitResource::LayerExtension, 64 * KIB),
    (LimitResource::LayerExtensionTotal, 64 * MIB),
    (LimitResource::RetainedDisk, 512 * GIB),
    (LimitResource::CopyBuffer, MIB),
    (LimitResource::ZstdWindow, 64 * MIB),
    (LimitResource::PreparationRecord, 64 * KIB),
];

/// Every variant, spelled out so a new one fails to compile here until the
/// table above is extended.
fn in_table(resource: LimitResource) -> bool {
    match resource {
        LimitResource::RawManifest
        | LimitResource::CompressedArchive
        | LimitResource::Package
        | LimitResource::OuterMembers
        | LimitResource::OuterUncompressedTotal
        | LimitResource::ImageArchive
        | LimitResource::StoredLayerBlob
        | LimitResource::DecodedLayer
        | LimitResource::DecodedLayersPerImage
        | LimitResource::DecodedLayersPerOperation
        | LimitResource::GzipHeader
        | LimitResource::ImageEntries
        | LimitResource::ImagePathBytes
        | LimitResource::LayersPerImage
        | LimitResource::TagsPerImage
        | LimitResource::IndexJson
        | LimitResource::ImageManifestJson
        | LimitResource::CompatibilityJson
        | LimitResource::ConfigJson
        | LimitResource::OciLayout
        | LimitResource::ImageJsonTotal
        | LimitResource::JsonDepth
        | LimitResource::LayerEntries
        | LimitResource::LayerPathBytes
        | LimitResource::LayerLinkTargetBytes
        | LimitResource::LayerExtension
        | LimitResource::LayerExtensionTotal
        | LimitResource::RetainedDisk
        | LimitResource::CopyBuffer
        | LimitResource::ZstdWindow
        | LimitResource::PreparationRecord => true,
    }
}

#[test]
fn defaults_match_the_table() {
    let limits = ContentLimits::default();
    let table: Vec<LimitResource> = TABLE.iter().map(|(resource, _)| *resource).collect();
    assert_eq!(LimitResource::ALL, table.as_slice());
    for (resource, default) in TABLE {
        assert!(in_table(*resource));
        assert_eq!(limits.get(*resource), *default, "{resource}");
        assert_eq!(resource.default_limit(), *default, "{resource}");
    }
    let unique: HashSet<LimitResource> = LimitResource::ALL.iter().copied().collect();
    assert_eq!(unique.len(), LimitResource::ALL.len());
}

#[test]
fn labels_are_fixed_and_lowercase() {
    assert_eq!(LimitResource::DecodedLayer.to_string(), "decoded layer");
    assert_eq!(
        LimitResource::ImageJsonTotal.to_string(),
        "image json total"
    );
    let labels: HashSet<String> = LimitResource::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(labels.len(), LimitResource::ALL.len());
    assert!(labels.iter().all(|label| label == &label.to_lowercase()));
}

fn refuses_zero(resource: LimitResource) -> bool {
    matches!(
        resource,
        LimitResource::CopyBuffer | LimitResource::JsonDepth | LimitResource::ZstdWindow
    )
}

#[test]
fn every_resource_accepts_its_default_and_one_below() {
    for resource in LimitResource::ALL {
        let default = resource.default_limit();
        let at = ContentLimits::default()
            .with_limit(*resource, default)
            .expect("the default is accepted");
        assert_eq!(at.get(*resource), default);
        let below = ContentLimits::default()
            .with_limit(*resource, default - 1)
            .expect("one below the default is accepted");
        let expected = if *resource == LimitResource::ZstdWindow {
            32 * MIB
        } else {
            default - 1
        };
        assert_eq!(below.get(*resource), expected, "{resource}");
    }
}

#[test]
fn no_resource_accepts_more_than_its_default() {
    for resource in LimitResource::ALL {
        let default = resource.default_limit();
        for requested in [default + 1, u64::MAX] {
            let err = ContentLimits::default()
                .with_limit(*resource, requested)
                .unwrap_err();
            match err {
                ContentLimitsError::AboveDefault {
                    resource: refused,
                    requested: reported,
                    default: ceiling,
                } => {
                    assert_eq!(refused, *resource);
                    assert_eq!(reported, requested);
                    assert_eq!(ceiling, default);
                }
                ContentLimitsError::Zero { .. } | ContentLimitsError::BelowMinimum { .. } => {
                    panic!("{resource} at {requested}: {err}")
                }
            }
        }
    }
}

#[test]
fn the_ceiling_is_the_default_not_the_current_value() {
    let limits = ContentLimits::default()
        .with_limit(LimitResource::JsonDepth, 10)
        .unwrap()
        .with_limit(LimitResource::JsonDepth, 20)
        .unwrap();
    assert_eq!(limits.get(LimitResource::JsonDepth), 20);
    assert_eq!(
        limits.clone().with_limit(LimitResource::JsonDepth, 65),
        Err(ContentLimitsError::AboveDefault {
            resource: LimitResource::JsonDepth,
            requested: 65,
            default: 64,
        })
    );
    assert_eq!(limits.get(LimitResource::JsonDepth), 20);
}

#[test]
fn lowering_one_resource_leaves_the_others_alone() {
    let limits = ContentLimits::default()
        .with_limit(LimitResource::DecodedLayersPerImage, 10)
        .unwrap();
    assert_eq!(limits.get(LimitResource::DecodedLayersPerImage), 10);
    assert_eq!(limits.get(LimitResource::DecodedLayer), 16 * GIB);
    for resource in LimitResource::ALL {
        if *resource != LimitResource::DecodedLayersPerImage {
            assert_eq!(limits.get(*resource), resource.default_limit());
        }
    }
}

#[test]
fn zero_is_refused_only_where_nothing_could_work() {
    let limits = ContentLimits::default()
        .with_limit(LimitResource::OuterMembers, 0)
        .unwrap();
    assert_eq!(limits.get(LimitResource::OuterMembers), 0);
    for resource in LimitResource::ALL {
        let result = ContentLimits::default().with_limit(*resource, 0);
        if refuses_zero(*resource) {
            match result.unwrap_err() {
                ContentLimitsError::Zero { resource: refused } => assert_eq!(refused, *resource),
                other => panic!("{resource}: {other}"),
            }
        } else {
            assert_eq!(result.unwrap().get(*resource), 0);
        }
    }
}

#[test]
fn the_zstd_window_has_a_minimum_and_is_a_power_of_two() {
    match ContentLimits::default()
        .with_limit(LimitResource::ZstdWindow, 1023)
        .unwrap_err()
    {
        ContentLimitsError::BelowMinimum {
            resource,
            requested,
            minimum,
        } => {
            assert_eq!(resource, LimitResource::ZstdWindow);
            assert_eq!(requested, 1023);
            assert_eq!(minimum, 1024);
        }
        other => panic!("{other}"),
    }
    let window = |value: u64| {
        ContentLimits::default()
            .with_limit(LimitResource::ZstdWindow, value)
            .unwrap()
            .get(LimitResource::ZstdWindow)
    };
    assert_eq!(window(1024), 1024);
    assert_eq!(window(3 * MIB), 2 * MIB);
    assert_eq!(window(64 * MIB - 1), 32 * MIB);
    assert_eq!(window(64 * MIB), 64 * MIB);
}

#[test]
fn errors_are_checked_above_default_then_zero_then_minimum() {
    // Zero is below the zstd minimum too, but is reported as zero.
    assert_eq!(
        ContentLimits::default().with_limit(LimitResource::ZstdWindow, 0),
        Err(ContentLimitsError::Zero {
            resource: LimitResource::ZstdWindow,
        })
    );
    assert!(matches!(
        ContentLimits::default().with_limit(LimitResource::ZstdWindow, u64::MAX),
        Err(ContentLimitsError::AboveDefault { .. })
    ));
}

#[test]
fn errors_describe_the_refusal() {
    let err = ContentLimits::default()
        .with_limit(LimitResource::DecodedLayer, u64::MAX)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "the decoded layer limit {} is above its default of {}",
            u64::MAX,
            16 * GIB
        )
    );
}
