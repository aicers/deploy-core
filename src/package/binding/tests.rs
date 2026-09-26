use serde_json::{Value, json};

use super::*;

/// The illustrative record: a namespace and no epoch.
const GOLDEN: &str = concat!(
    r#"{"schema":1,"#,
    r#""manifest_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
    r#""manifest_length":4096,"#,
    r#""archive_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
    r#""archive_length":1048576,"#,
    r#""target":"example-app","version":"1.0.0","#,
    r#""commit":"1111111111111111111111111111111111111111","#,
    r#""target_arch":"x86_64","namespace":"example-product","trust_epoch":null}"#,
    "\n",
);

fn golden() -> Value {
    serde_json::from_str(GOLDEN).unwrap()
}

/// Renders `value` as compact JSON, keys in the order `serde_json` holds them.
fn render(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn edited(edit: impl FnOnce(&mut Map<String, Value>)) -> Vec<u8> {
    let mut value = golden();
    edit(value.as_object_mut().unwrap());
    render(&value)
}

#[track_caller]
fn fault(bytes: &[u8]) -> RecordFault {
    match PreparationBinding::from_record_bytes(bytes) {
        Err(PackageWriteError::InvalidPreparation {
            reason: PreparationFault::RecordInvalid(fault),
        }) => fault,
        other => panic!("expected a record fault, got {other:?}"),
    }
}

#[track_caller]
fn limit(result: Result<PreparationBinding, PackageWriteError>) -> (LimitResource, u64) {
    match result {
        Err(PackageWriteError::Content(ContentError::LimitExceeded { resource, limit })) => {
            (resource, limit)
        }
        other => panic!("expected a limit, got {other:?}"),
    }
}

#[test]
fn the_canonical_record_matches_its_golden_form_and_round_trips() {
    let binding = PreparationBinding::from_record_bytes(GOLDEN.as_bytes()).expect("parses");
    assert_eq!(binding.schema(), 1);
    assert_eq!(binding.manifest_sha256(), &[0xaa; 32]);
    assert_eq!(binding.manifest_length(), 4096);
    assert_eq!(binding.archive_sha256(), &[0xbb; 32]);
    assert_eq!(binding.archive_length(), 1_048_576);
    assert_eq!(binding.target(), "example-app");
    assert_eq!(binding.version(), "1.0.0");
    assert_eq!(binding.commit(), "1111111111111111111111111111111111111111");
    assert_eq!(binding.target_arch(), TargetArch::X86_64);
    assert_eq!(binding.namespace(), Some("example-product"));
    assert_eq!(binding.trust_epoch(), None);
    assert_eq!(binding.to_record_bytes(), GOLDEN.as_bytes());
    assert_eq!(binding.record_len(), GOLDEN.len() as u64);
    let again =
        PreparationBinding::from_record_bytes(&binding.to_record_bytes()).expect("round trips");
    assert_eq!(again, binding);
}

#[test]
fn every_nullable_combination_has_its_computed_length() {
    for namespace in [json!(null), json!("example-product")] {
        for epoch in [json!(null), json!(0), json!(u64::MAX)] {
            for arch in ["x86_64", "aarch64"] {
                let bytes = edited(|object| {
                    object.insert("namespace".into(), namespace.clone());
                    object.insert("trust_epoch".into(), epoch.clone());
                    object.insert("target_arch".into(), json!(arch));
                });
                let binding = PreparationBinding::from_record_bytes(&bytes).expect("parses");
                let record = binding.to_record_bytes();
                assert_eq!(binding.record_len(), record.len() as u64);
                assert!(record.ends_with(b"}\n"));
                assert!(!record.contains(&b' '));
                assert_eq!(
                    PreparationBinding::from_record_bytes(&record).expect("round trips"),
                    binding
                );
            }
        }
    }
}

#[test]
fn the_record_is_written_in_field_order() {
    let binding = PreparationBinding::from_record_bytes(GOLDEN.as_bytes()).expect("parses");
    let record = String::from_utf8(binding.to_record_bytes()).unwrap();
    let mut last = 0;
    for (_, name) in FIELDS {
        let at = record.find(&format!("\"{name}\":")).expect("present");
        assert!(at >= last, "{name} out of order");
        last = at;
    }
    let mut streamed = Vec::new();
    binding.write_record(&mut streamed).expect("streams");
    assert_eq!(streamed, record.as_bytes());
}

#[test]
fn malformed_records() {
    assert_eq!(fault(b""), RecordFault::Malformed);
    assert_eq!(fault(b"{\"schema\":1,\xff}"), RecordFault::Malformed);
    let mut trailing = GOLDEN.as_bytes().to_vec();
    trailing.extend_from_slice(b"{}");
    assert_eq!(fault(&trailing), RecordFault::Malformed);
    assert_eq!(fault(b"{\"schema\":"), RecordFault::Malformed);
}

#[test]
fn a_repeated_key_is_a_duplicate() {
    let record = GOLDEN.replace(
        r#""archive_length""#,
        r#""archive_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","archive_length""#,
    );
    assert_eq!(fault(record.as_bytes()), RecordFault::DuplicateKey);
}

#[test]
fn a_root_that_is_not_an_object() {
    assert_eq!(fault(b"[1]"), RecordFault::NotObject);
    assert_eq!(fault(b"1"), RecordFault::NotObject);
}

#[test]
fn the_schema_is_checked_first() {
    let without = edited(|object| {
        object.remove("schema");
    });
    assert_eq!(
        fault(&without),
        RecordFault::MissingField {
            field: BindingField::Schema
        }
    );
    for schema in ["1.0", "\"1\"", "-1", "1e0"] {
        let record = GOLDEN.replacen("\"schema\":1", &format!("\"schema\":{schema}"), 1);
        assert_eq!(
            fault(record.as_bytes()),
            RecordFault::FieldType {
                field: BindingField::Schema
            },
            "{schema}"
        );
    }
    let record = GOLDEN.replacen("\"schema\":1", "\"schema\":2", 1);
    assert_eq!(fault(record.as_bytes()), RecordFault::UnsupportedSchema);
}

#[test]
fn an_unknown_field() {
    let bytes = edited(|object| {
        object.insert("path".into(), json!("/tmp/x"));
    });
    assert_eq!(fault(&bytes), RecordFault::UnknownField);
}

#[test]
fn an_absent_nullable_field_is_missing_not_null() {
    for (key, field) in [
        ("namespace", BindingField::Namespace),
        ("trust_epoch", BindingField::TrustEpoch),
    ] {
        let bytes = edited(|object| {
            object.remove(key);
        });
        assert_eq!(fault(&bytes), RecordFault::MissingField { field });
    }
}

#[test]
fn every_field_reports_its_own_absence() {
    for (field, key) in FIELDS {
        let bytes = edited(|object| {
            object.remove(key);
        });
        assert_eq!(fault(&bytes), RecordFault::MissingField { field }, "{key}");
    }
}

#[test]
fn lengths_must_be_unsigned_integers() {
    for value in ["-1", "1.5", "18446744073709551616", "\"4096\""] {
        let record = GOLDEN.replacen(
            "\"manifest_length\":4096",
            &format!("\"manifest_length\":{value}"),
            1,
        );
        assert_eq!(
            fault(record.as_bytes()),
            RecordFault::FieldType {
                field: BindingField::ManifestLength
            },
            "{value}"
        );
    }
    let bytes = edited(|object| {
        object.insert("trust_epoch".into(), json!(true));
    });
    assert_eq!(
        fault(&bytes),
        RecordFault::FieldType {
            field: BindingField::TrustEpoch
        }
    );
}

#[test]
fn strings_must_be_strings() {
    for (key, field) in [
        ("manifest_sha256", BindingField::ManifestSha256),
        ("archive_sha256", BindingField::ArchiveSha256),
        ("target", BindingField::Target),
        ("version", BindingField::Version),
        ("commit", BindingField::Commit),
        ("target_arch", BindingField::TargetArch),
        ("namespace", BindingField::Namespace),
    ] {
        let bytes = edited(|object| {
            object.insert(key.into(), json!(7));
        });
        assert_eq!(fault(&bytes), RecordFault::FieldType { field }, "{key}");
    }
}

#[test]
fn digests_must_be_prefixed_lowercase_sha256() {
    for digest in [
        format!("sha256:{}", "B".repeat(64)),
        "b".repeat(64),
        format!("sha256:{}", "b".repeat(63)),
    ] {
        let bytes = edited(|object| {
            object.insert("archive_sha256".into(), json!(digest));
        });
        assert_eq!(
            fault(&bytes),
            RecordFault::InvalidDigest {
                field: BindingField::ArchiveSha256
            },
            "{digest}"
        );
    }
}

#[test]
fn values_break_their_rules() {
    let bytes = edited(|object| {
        object.insert("target_arch".into(), json!("amd64"));
    });
    assert_eq!(fault(&bytes), RecordFault::InvalidTargetArch);
    for (key, value, field) in [
        ("target", "../app", BindingField::Target),
        ("version", "-1", BindingField::Version),
        ("commit", "not-a-commit", BindingField::Commit),
        ("namespace", "Example", BindingField::Namespace),
    ] {
        let bytes = edited(|object| {
            object.insert(key.into(), json!(value));
        });
        assert_eq!(
            fault(&bytes),
            RecordFault::InvalidIdentifier { field },
            "{key}"
        );
    }
}

/// Pads the golden record with spaces after its opening brace to `len`
/// bytes.
fn padded(len: usize) -> Vec<u8> {
    let mut bytes = b"{".to_vec();
    bytes.extend(std::iter::repeat_n(b' ', len - GOLDEN.len()));
    bytes.extend_from_slice(&GOLDEN.as_bytes()[1..]);
    assert_eq!(bytes.len(), len);
    bytes
}

#[test]
fn the_default_limit_admits_64_kib_and_no_more() {
    PreparationBinding::from_record_bytes(&padded(65_536)).expect("at the limit");
    assert_eq!(
        limit(PreparationBinding::from_record_bytes(&padded(65_537))),
        (LimitResource::PreparationRecord, 65_536)
    );
}

#[test]
fn excess_nesting_is_the_depth_limit() {
    let nested = format!("{}{}", "[".repeat(65), "]".repeat(65));
    let record = GOLDEN.replacen('{', &format!("{{\"deep\":{nested},"), 1);
    assert_eq!(
        limit(PreparationBinding::from_record_bytes(record.as_bytes())),
        (LimitResource::JsonDepth, 64)
    );
}

#[test]
fn a_caller_limit_replaces_the_default() {
    let limits = ContentLimits::default()
        .with_limit(LimitResource::PreparationRecord, 100)
        .unwrap();
    assert_eq!(
        limit(parse_record(GOLDEN.as_bytes(), &limits)),
        (LimitResource::PreparationRecord, 100)
    );
}

#[test]
fn paired_faults_resolve_in_check_order() {
    // Oversize and malformed: the size, before any scan.
    let mut oversize = vec![b'{'; 65_537];
    oversize[0] = b'x';
    assert_eq!(
        limit(PreparationBinding::from_record_bytes(&oversize)),
        (LimitResource::PreparationRecord, 65_536)
    );

    // A duplicate key, then a syntax error: byte order.
    let record = GOLDEN.replace(
        r#""archive_length""#,
        r#""archive_sha256":"x","archive_length""#,
    );
    let broken = format!("{}}}", record.trim_end());
    assert_eq!(fault(broken.as_bytes()), RecordFault::DuplicateKey);

    // No schema and an unknown field: the schema.
    let bytes = edited(|object| {
        object.remove("schema");
        object.insert("path".into(), json!("x"));
    });
    assert_eq!(
        fault(&bytes),
        RecordFault::MissingField {
            field: BindingField::Schema
        }
    );

    // An unsupported schema and an unknown field: the schema.
    let bytes = edited(|object| {
        object.insert("schema".into(), json!(2));
        object.insert("path".into(), json!("x"));
    });
    assert_eq!(fault(&bytes), RecordFault::UnsupportedSchema);

    // An unknown field and a bad digest: the unknown field.
    let bytes = edited(|object| {
        object.insert("path".into(), json!("x"));
        object.insert("archive_sha256".into(), json!("nope"));
    });
    assert_eq!(fault(&bytes), RecordFault::UnknownField);

    // A bad manifest digest and a bad commit: field order.
    let bytes = edited(|object| {
        object.insert("manifest_sha256".into(), json!("nope"));
        object.insert("commit".into(), json!("nope"));
    });
    assert_eq!(
        fault(&bytes),
        RecordFault::InvalidDigest {
            field: BindingField::ManifestSha256
        }
    );

    // A mistyped manifest length and a bad archive digest: field order.
    let bytes = edited(|object| {
        object.insert("manifest_length".into(), json!("4096"));
        object.insert("archive_sha256".into(), json!("nope"));
    });
    assert_eq!(
        fault(&bytes),
        RecordFault::FieldType {
            field: BindingField::ManifestLength
        }
    );
}

#[test]
fn differences_are_reported_in_field_order() {
    let binding = PreparationBinding::from_record_bytes(GOLDEN.as_bytes()).unwrap();
    let other = PreparationBinding::from_record_bytes(&edited(|object| {
        object.insert("commit".into(), json!("2".repeat(40)));
        object.insert("trust_epoch".into(), json!(4));
    }))
    .unwrap();
    assert_eq!(binding.first_difference(&binding), None);
    assert_eq!(binding.first_difference(&other), Some(BindingField::Commit));

    let request = VerifyRequest::for_namespaced_package(
        "example-app",
        "1.0.0",
        &"1".repeat(40),
        "example-product",
    )
    .unwrap();
    assert_eq!(
        binding.request_difference(&request, TargetArch::X86_64),
        None
    );
    assert_eq!(
        binding.request_difference(&request, TargetArch::Aarch64),
        Some(BindingField::TargetArch)
    );
    let plain = VerifyRequest::for_package("example-app", "1.0.0", &"1".repeat(40)).unwrap();
    assert_eq!(
        binding.request_difference(&plain, TargetArch::Aarch64),
        Some(BindingField::TargetArch)
    );
    assert_eq!(
        binding.request_difference(&plain, TargetArch::X86_64),
        Some(BindingField::Namespace)
    );
    let trust = VerifyRequest::for_trust("1.0.0", &"1".repeat(40), 3).unwrap();
    assert_eq!(
        binding.request_difference(&trust, TargetArch::X86_64),
        Some(BindingField::Target)
    );
}

#[test]
fn fields_and_faults_display_in_lowercase() {
    for (field, key) in FIELDS {
        assert_eq!(field.to_string(), key);
    }
    for fault in [
        RecordFault::Malformed,
        RecordFault::DuplicateKey,
        RecordFault::NotObject,
        RecordFault::MissingField {
            field: BindingField::Schema,
        },
        RecordFault::FieldType {
            field: BindingField::TrustEpoch,
        },
        RecordFault::UnsupportedSchema,
        RecordFault::UnknownField,
        RecordFault::InvalidDigest {
            field: BindingField::ManifestSha256,
        },
        RecordFault::InvalidTargetArch,
        RecordFault::InvalidIdentifier {
            field: BindingField::Namespace,
        },
    ] {
        let text = fault.to_string();
        assert_eq!(text, text.to_lowercase(), "{text}");
    }
}
