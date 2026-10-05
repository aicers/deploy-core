//! Named first-install configuration templates shared by the manager and host agent.
//!
//! This compile-time catalog is interim, until a UI policy for reconverge's
//! `[[detectors]]` settings is decided. The manager reads ids, names, descriptions
//! and the set of components that require a template; it never renders, sends,
//! logs or exposes a template body. The host agent looks up a template by the
//! install target and id, renders it with its host values, and writes the returned
//! TOML verbatim as the instance's configuration file.
//!
//! To add an entry, add one TOML file at `templates/<component>/<id>.toml` and one
//! element of `CATALOG`, with its body compiled in using
//! `include_str!("../templates/<component>/<id>.toml")`; nothing else is needed.
//! Catalog order is presentation order. The catalog is initially empty, while
//! reconverge requires a template, so the manager refuses its first installs.
//!
//! Templates can name `${cert_path}`, `${key_path}`, `${ca_bundle_path}`,
//! `${manager_address}` and `${manager_server_name}`. Rendering parses a TOML
//! table and walks every value recursively, including nested and inline tables,
//! arrays of strings and arrays of tables. Only a string exactly equal to one
//! token is substituted. A key containing `${` is refused at any depth, as is
//! any other string containing `${`; there is no partial interpolation. Token
//! recognition operates on parsed strings, regardless of TOML quoting style.
//! A named token with no supplied value is an error, never an empty string,
//! default or remaining placeholder. Strings without `${` and all non-string
//! values pass through unchanged.
//!
//! Host values are substituted verbatim without validation or re-scanning: a
//! host value containing a token stays literal. The substituted table is
//! serialized with `toml::to_string`, which escapes host strings as necessary.
//! The returned text is exactly that serialization, with no added header or
//! trailing text. Comments and source formatting are discarded; key order is
//! the TOML map's deterministic order. The first violation in table iteration
//! order is returned, and identical inputs produce byte-identical output.
//! Rendering reads no environment, touches no host and writes no file.
//!
//! Two policies are enforced by review rather than code:
//!
//! - A template holds **no secret**: it is compiled into every manager and host
//!   binary, and its id and texts are shown to operators.
//! - A template's content **never changes under an existing id**. Changed
//!   content gets a new id, and a retired id is never reused for other content.
//!   Managers and hosts linking different deploy-core versions must never
//!   render different files for one id.

use std::fmt;

const CATALOG: &[ConfigTemplate] = &[];
const REQUIRES_TEMPLATE: &[&str] = &["reconverge"];

/// An operator-facing text in English and Korean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalizedText {
    /// The English text.
    pub en: &'static str,
    /// The Korean text.
    pub ko: &'static str,
}

/// A named configuration template belonging to one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigTemplate {
    /// The package id carried by the install request's target.
    pub component: &'static str,
    /// The template id within its component.
    pub id: &'static str,
    /// The operator-facing name.
    pub name: LocalizedText,
    /// The operator-facing description.
    pub description: LocalizedText,
    /// The template's TOML document.
    pub body: &'static str,
}

/// A host-value token accepted in a template's string values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateToken {
    /// The instance's issued certificate path.
    CertPath,
    /// The instance's private key path.
    KeyPath,
    /// The instance's trusted CA bundle path.
    CaBundlePath,
    /// The manager's numeric address and port.
    ManagerAddress,
    /// The manager's certificate identity.
    ManagerServerName,
}

impl TemplateToken {
    /// All supported host-value tokens.
    pub const ALL: [TemplateToken; 5] = [
        Self::CertPath,
        Self::KeyPath,
        Self::CaBundlePath,
        Self::ManagerAddress,
        Self::ManagerServerName,
    ];

    /// Returns the literal token text accepted in a template.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CertPath => "${cert_path}",
            Self::KeyPath => "${key_path}",
            Self::CaBundlePath => "${ca_bundle_path}",
            Self::ManagerAddress => "${manager_address}",
            Self::ManagerServerName => "${manager_server_name}",
        }
    }
}

impl fmt::Display for TemplateToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The caller's host values, substituted verbatim without validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostValues<'a> {
    /// Path of the instance's issued enrollment certificate, also supplied to
    /// its unit as [`crate::module_spec::RenderVar::CertPath`].
    pub cert_path: Option<&'a str>,
    /// Path of the instance's enrollment private key, also supplied to its unit
    /// as [`crate::module_spec::RenderVar::KeyPath`].
    pub key_path: Option<&'a str>,
    /// Path of the enrollment CA bundle the instance trusts, also supplied to
    /// its unit as [`crate::module_spec::RenderVar::CaBundlePath`].
    pub ca_bundle_path: Option<&'a str>,
    /// The `<ip>:<port>` of the manager the host agent is pointed at, spelled
    /// as [`std::net::SocketAddr`]'s `Display` (an IPv6 address is bracketed).
    pub manager_address: Option<&'a str>,
    /// The manager's server name (its certificate identity).
    pub manager_server_name: Option<&'a str>,
}

/// Errors raised while rendering a configuration template.
#[derive(Debug, thiserror::Error)]
pub enum ConfigTemplateError {
    /// The body is not a TOML document.
    #[error("the template is not a TOML document: {0}")]
    InvalidToml(#[source] toml::de::Error),
    /// A key contains placeholder syntax, which is only accepted in values.
    #[error("the template key contains a placeholder: {key:?}")]
    PlaceholderInKey {
        /// The rejected template key.
        key: String,
    },
    /// A string contains placeholder syntax without being exactly a known token.
    #[error("the template contains an unknown placeholder: {value:?}")]
    UnknownPlaceholder {
        /// The rejected template string, before host-value substitution.
        value: String,
    },
    /// A token has no corresponding host value.
    #[error("the template names `{token}`, for which no host value was supplied")]
    UnresolvedToken {
        /// The token whose host value is absent.
        token: TemplateToken,
    },
    /// The substituted table could not be serialized.
    #[error("serializing the substituted template failed: {0}")]
    Serialize(#[source] toml::ser::Error),
}

/// Returns whether the component requires a configuration template.
#[must_use]
pub fn requires_template(component: &str) -> bool {
    requires_template_in(REQUIRES_TEMPLATE, component)
}

fn requires_template_in(required: &[&str], component: &str) -> bool {
    required.contains(&component)
}

/// Returns the component's templates in their declared presentation order.
#[must_use = "the returned iterator must be consumed to read the templates"]
pub fn templates_for(component: &str) -> impl Iterator<Item = &'static ConfigTemplate> {
    templates_in(CATALOG, component)
}

fn templates_in<'a>(
    catalog: &'static [ConfigTemplate],
    component: &'a str,
) -> impl Iterator<Item = &'static ConfigTemplate> + 'a {
    catalog
        .iter()
        .filter(move |entry| entry.component == component)
}

/// Returns a template matching the component and id exactly and case-sensitively.
#[must_use]
pub fn find(component: &str, id: &str) -> Option<&'static ConfigTemplate> {
    find_in(CATALOG, component, id)
}

fn find_in(
    catalog: &'static [ConfigTemplate],
    component: &str,
    id: &str,
) -> Option<&'static ConfigTemplate> {
    templates_in(catalog, component).find(|entry| entry.id == id)
}

/// Renders a TOML template by substituting its tokens with the supplied host values.
///
/// Returns exactly the substituted table's TOML serialization. See the module
/// documentation for token recognition, traversal and single-pass semantics.
///
/// # Errors
///
/// Returns an error if the body is not TOML, a key contains `${`, a string
/// contains an unknown placeholder, a named token has no host value, or the
/// substituted table cannot be serialized.
pub fn render(body: &str, values: &HostValues<'_>) -> Result<String, ConfigTemplateError> {
    let mut table = body
        .parse::<toml::Table>()
        .map_err(ConfigTemplateError::InvalidToml)?;
    substitute_table(&mut table, values)?;
    toml::to_string(&table).map_err(ConfigTemplateError::Serialize)
}

fn substitute_table(
    table: &mut toml::Table,
    values: &HostValues<'_>,
) -> Result<(), ConfigTemplateError> {
    for (key, value) in table {
        if key.contains("${") {
            return Err(ConfigTemplateError::PlaceholderInKey { key: key.clone() });
        }
        substitute_value(value, values)?;
    }
    Ok(())
}

fn substitute_value(
    value: &mut toml::Value,
    values: &HostValues<'_>,
) -> Result<(), ConfigTemplateError> {
    match value {
        toml::Value::String(text) => {
            if let Some(token) = TemplateToken::ALL
                .into_iter()
                .find(|token| text == token.as_str())
            {
                let resolved = match token {
                    TemplateToken::CertPath => values.cert_path,
                    TemplateToken::KeyPath => values.key_path,
                    TemplateToken::CaBundlePath => values.ca_bundle_path,
                    TemplateToken::ManagerAddress => values.manager_address,
                    TemplateToken::ManagerServerName => values.manager_server_name,
                }
                .ok_or(ConfigTemplateError::UnresolvedToken { token })?;
                resolved.clone_into(text);
            } else if text.contains("${") {
                return Err(ConfigTemplateError::UnknownPlaceholder {
                    value: text.clone(),
                });
            }
        }
        toml::Value::Table(table) => substitute_table(table, values)?,
        toml::Value::Array(array) => {
            for element in array {
                substitute_value(element, values)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use super::*;

    const VALUES: HostValues<'static> = HostValues {
        cert_path: Some("/enrollment/cert.pem"),
        key_path: Some("/enrollment/key.pem"),
        ca_bundle_path: Some("/enrollment/ca.pem"),
        manager_address: Some("[::1]:8443"),
        manager_server_name: Some("manager.example"),
    };
    const PLAIN_BODY: &str = "value = 'unchanged'";
    const ENTRY: ConfigTemplate = ConfigTemplate {
        component: "reconverge",
        id: "default",
        name: LocalizedText {
            en: "Default",
            ko: "기본",
        },
        description: LocalizedText {
            en: "Default configuration",
            ko: "기본 설정",
        },
        body: PLAIN_BODY,
    };
    const FIXTURE_CATALOG: &[ConfigTemplate] = &[
        ConfigTemplate { id: "z", ..ENTRY },
        ConfigTemplate {
            component: "hog",
            id: "z",
            ..ENTRY
        },
        ConfigTemplate { id: "a", ..ENTRY },
    ];

    fn check_catalog(catalog: &[ConfigTemplate]) -> Result<(), String> {
        let mut identities = HashSet::new();
        for entry in catalog {
            let id = entry.id.as_bytes();
            if !(1..=63).contains(&id.len())
                || !id
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                || !id
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            {
                return Err(format!("invalid template id: {}", entry.id));
            }
            if !identities.insert((entry.component, entry.id)) {
                return Err(format!(
                    "duplicate template: {}/{}",
                    entry.component, entry.id
                ));
            }
            if !requires_template(entry.component) {
                return Err(format!(
                    "component does not require a template: {}",
                    entry.component
                ));
            }
            render(entry.body, &VALUES).map_err(|error| error.to_string())?;
            if [
                entry.name.en,
                entry.name.ko,
                entry.description.en,
                entry.description.ko,
            ]
            .iter()
            .any(|text| text.trim().is_empty())
            {
                return Err(format!(
                    "empty operator text: {}/{}",
                    entry.component, entry.id
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn substitutes_everywhere_and_emits_only_serialized_table() {
        const BODY: &str = r#"
# Comments are not emitted.
cert = "${cert_path}"
key = '${key_path}'
ca = """${ca_bundle_path}"""
manager = '''${manager_address}'''
server = "\u0024{manager_server_name}"
strings = ["${cert_path}", "${key_path}", "${ca_bundle_path}", "${manager_address}", "${manager_server_name}", "untouched"]
arrays = [["${cert_path}"], ["${manager_server_name}"]]
inline = { cert = "${cert_path}", nested = { key = "${key_path}" } }
text = "unchanged"
integer = 42
float = 1.25
boolean = true
datetime = 2026-10-05T01:02:03Z

[nested.deeper]
ca = "${ca_bundle_path}"

[[services]]
address = "${manager_address}"
server = "${manager_server_name}"

[[services]]
cert = "${cert_path}"
"#;
        const EXPECTED: &str = r#"
cert = "/enrollment/cert.pem"
key = "/enrollment/key.pem"
ca = "/enrollment/ca.pem"
manager = "[::1]:8443"
server = "manager.example"
strings = ["/enrollment/cert.pem", "/enrollment/key.pem", "/enrollment/ca.pem", "[::1]:8443", "manager.example", "untouched"]
arrays = [["/enrollment/cert.pem"], ["manager.example"]]
inline = { cert = "/enrollment/cert.pem", nested = { key = "/enrollment/key.pem" } }
text = "unchanged"
integer = 42
float = 1.25
boolean = true
datetime = 2026-10-05T01:02:03Z

[nested.deeper]
ca = "/enrollment/ca.pem"

[[services]]
address = "[::1]:8443"
server = "manager.example"

[[services]]
cert = "/enrollment/cert.pem"
"#;
        let expected = EXPECTED.parse::<toml::Table>().unwrap();
        let output = render(BODY, &VALUES).unwrap();
        assert_eq!(output.parse::<toml::Table>().unwrap(), expected);
        assert_eq!(output, toml::to_string(&expected).unwrap());
    }

    #[test]
    fn refuses_each_absent_host_value() {
        for token in TemplateToken::ALL {
            let mut values = VALUES;
            match token {
                TemplateToken::CertPath => values.cert_path = None,
                TemplateToken::KeyPath => values.key_path = None,
                TemplateToken::CaBundlePath => values.ca_bundle_path = None,
                TemplateToken::ManagerAddress => values.manager_address = None,
                TemplateToken::ManagerServerName => values.manager_server_name = None,
            }
            let body = format!("value = '{}'", token.as_str());
            assert!(matches!(
                render(&body, &values),
                Err(ConfigTemplateError::UnresolvedToken { token: found }) if found == token
            ));
        }
    }

    #[test]
    fn renders_without_host_values_when_no_token_is_named() {
        let expected = PLAIN_BODY.parse::<toml::Table>().unwrap();
        assert_eq!(
            render(PLAIN_BODY, &HostValues::default()).unwrap(),
            toml::to_string(&expected).unwrap()
        );
        assert_eq!(
            render("", &HostValues::default()).unwrap(),
            toml::to_string(&toml::Table::new()).unwrap()
        );
    }

    #[test]
    fn refuses_unknown_placeholders_at_every_depth() {
        const UNKNOWN: &[&str] = &[
            "${cert_path}/x",
            " ${cert_path}",
            "${CERT_PATH}",
            "${unknown}",
            "${",
        ];
        for text in UNKNOWN {
            for body in [
                format!("value = '{text}'"),
                format!("values = ['{text}']"),
                format!("[nested]\nvalue = '{text}'"),
                format!("inline = {{ value = '{text}' }}"),
                format!("[[tables]]\nvalue = '{text}'"),
            ] {
                assert!(
                    matches!(
                        render(&body, &VALUES),
                        Err(ConfigTemplateError::UnknownPlaceholder { value }) if value == *text
                    ),
                    "body: {body}"
                );
            }
        }
    }

    #[test]
    fn leaves_strings_without_placeholder_syntax_unchanged() {
        const BODY: &str = "values = ['$cert_path', '{cert_path}']";
        assert_eq!(
            render(BODY, &HostValues::default())
                .unwrap()
                .parse::<toml::Table>()
                .unwrap(),
            BODY.parse::<toml::Table>().unwrap()
        );
    }

    #[test]
    fn refuses_placeholders_in_keys_at_every_depth() {
        const BODIES: &[(&str, &str)] = &[
            ("'prefix${suffix' = 1", "prefix${suffix"),
            ("[nested.'${table']\nvalue = 1", "${table"),
            ("[[tables]]\n'${key' = 1", "${key"),
            ("'${cert_path}' = 1", "${cert_path}"),
            ("inline = { '${key' = 1 }", "${key"),
        ];
        for (body, expected) in BODIES {
            assert!(matches!(
                render(body, &VALUES),
                Err(ConfigTemplateError::PlaceholderInKey { key }) if key == *expected
            ));
        }
    }

    #[test]
    fn refuses_invalid_toml() {
        const BODY: &str = "value = [";
        assert!(matches!(
            render(BODY, &VALUES),
            Err(ConfigTemplateError::InvalidToml(_))
        ));
    }

    #[test]
    fn host_values_round_trip_verbatim() {
        const BODY: &str = r#"
cert = "${cert_path}"
key = "${key_path}"
ca = "${ca_bundle_path}"
manager = "${manager_address}"
server = "${manager_server_name}"
"#;
        const VALUE: &str = "quote\" backslash\\ newline\n${cert_path}";
        let values = HostValues {
            cert_path: Some(VALUE),
            key_path: Some(VALUE),
            ca_bundle_path: Some(VALUE),
            manager_address: Some(VALUE),
            manager_server_name: Some(VALUE),
        };
        let output = render(BODY, &values)
            .unwrap()
            .parse::<toml::Table>()
            .unwrap();
        assert_eq!(output.len(), 5);
        for value in output.values() {
            assert_eq!(value.as_str(), Some(VALUE));
        }
    }

    #[test]
    fn supplied_empty_values_are_not_treated_as_absent() {
        const BODY: &str = "values = ['${cert_path}', '${key_path}', '${ca_bundle_path}', '${manager_address}', '${manager_server_name}']";
        const EXPECTED: &str = "values = ['', '', '', '', '']";
        let values = HostValues {
            cert_path: Some(""),
            key_path: Some(""),
            ca_bundle_path: Some(""),
            manager_address: Some(""),
            manager_server_name: Some(""),
        };
        assert_eq!(
            render(BODY, &values)
                .unwrap()
                .parse::<toml::Table>()
                .unwrap(),
            EXPECTED.parse::<toml::Table>().unwrap()
        );
    }

    #[test]
    fn errors_do_not_expose_previously_substituted_host_values() {
        const BODIES: &[&str] = &[
            "a = '${cert_path}'\nz = '${key_path}'",
            "a = '${cert_path}'\nz = '${unknown}'",
            "a = '${cert_path}'\n'z${key}' = 1",
        ];
        const HOST_VALUE: &str = "host-value-that-must-not-appear-in-an-error";
        let values = HostValues {
            cert_path: Some(HOST_VALUE),
            ..HostValues::default()
        };
        for body in BODIES {
            let error = render(body, &values).unwrap_err();
            assert!(!error.to_string().contains(HOST_VALUE));
            assert!(!format!("{error:?}").contains(HOST_VALUE));
        }
    }

    #[test]
    fn substitutes_in_a_single_pass() {
        const BODY: &str = "cert = '${cert_path}'";
        let values = HostValues {
            cert_path: Some("${key_path}"),
            ..HostValues::default()
        };
        let output = render(BODY, &values)
            .unwrap()
            .parse::<toml::Table>()
            .unwrap();
        assert_eq!(
            output.get("cert").and_then(toml::Value::as_str),
            Some("${key_path}")
        );
    }

    #[test]
    fn rendering_is_deterministic() {
        const BODY: &str =
            "z = '${key_path}'\na = '${cert_path}'\n[nested]\nserver = '${manager_server_name}'";
        assert_eq!(
            render(BODY, &VALUES).unwrap(),
            render(BODY, &VALUES).unwrap()
        );
    }

    #[test]
    fn returns_first_violation_in_table_iteration_order() {
        const BODY: &str = "z = '${unknown}'\na = '${cert_path}'";
        const NESTED: &str = "z = '${unknown}'\na = [{ value = '${key_path}' }]";
        let table = BODY.parse::<toml::Table>().unwrap();
        assert_eq!(table.keys().next().map(String::as_str), Some("a"));
        assert!(matches!(
            render(BODY, &HostValues::default()),
            Err(ConfigTemplateError::UnresolvedToken {
                token: TemplateToken::CertPath
            })
        ));
        assert!(matches!(
            render(NESTED, &HostValues::default()),
            Err(ConfigTemplateError::UnresolvedToken {
                token: TemplateToken::KeyPath
            })
        ));
    }

    #[test]
    fn token_text_and_display_cover_the_closed_set() {
        const TEXTS: [&str; 5] = [
            "${cert_path}",
            "${key_path}",
            "${ca_bundle_path}",
            "${manager_address}",
            "${manager_server_name}",
        ];
        assert_eq!(
            TemplateToken::ALL.into_iter().collect::<HashSet<_>>().len(),
            5
        );
        for (token, text) in TemplateToken::ALL.into_iter().zip(TEXTS) {
            assert_eq!(token.as_str(), text);
            assert_eq!(token.to_string(), text);
        }
    }

    #[test]
    fn fixture_lookups_are_exact_and_preserve_declared_order() {
        assert_eq!(
            templates_in(FIXTURE_CATALOG, "reconverge")
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            ["z", "a"]
        );
        let entry = find_in(FIXTURE_CATALOG, "reconverge", "z").unwrap();
        assert_eq!(entry.component, "reconverge");
        assert_eq!(entry.id, "z");
        assert_eq!(
            find_in(FIXTURE_CATALOG, "hog", "z").unwrap().component,
            "hog"
        );
        for (component, id) in [
            ("reconverge", "unknown"),
            ("piglet", "z"),
            ("reconverge", ""),
            ("reconverge", "Z"),
            ("Reconverge", "z"),
        ] {
            assert!(find_in(FIXTURE_CATALOG, component, id).is_none());
        }
        assert_eq!(templates_in(FIXTURE_CATALOG, "Reconverge").count(), 0);
        assert_eq!(templates_in(FIXTURE_CATALOG, "piglet").count(), 0);
        assert!(requires_template_in(&["fixture"], "fixture"));
        assert!(!requires_template_in(&["fixture"], "Fixture"));
    }

    #[test]
    fn real_catalog_is_empty_and_only_reconverge_requires_a_template() {
        assert_eq!(CATALOG, []);
        assert!(requires_template("reconverge"));
        assert_eq!(templates_for("reconverge").count(), 0);
        assert!(find("reconverge", "default").is_none());
        for component in ["piglet", "giganto", "hog", "crusher", "Reconverge", ""] {
            assert!(!requires_template(component));
            assert_eq!(templates_for(component).count(), 0);
            assert!(find(component, "default").is_none());
        }
    }

    #[test]
    fn real_catalog_satisfies_invariants() {
        check_catalog(CATALOG).unwrap();
    }

    #[test]
    fn real_catalog_bodies_match_the_named_files() {
        for entry in CATALOG {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join(entry.component)
                .join(format!("{}.toml", entry.id));
            assert_eq!(
                entry.body,
                std::fs::read_to_string(&path).unwrap(),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn invariants_reject_invalid_ids_and_accept_boundaries() {
        const TOO_LONG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const LONGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(TOO_LONG.len(), 64);
        assert_eq!(LONGEST.len(), 63);
        for id in ["", "Default", "-a", "a_b", TOO_LONG, "한글", "a\n"] {
            assert!(
                check_catalog(&[ConfigTemplate { id, ..ENTRY }]).is_err(),
                "id: {id:?}"
            );
        }
        for id in [LONGEST, "a-", "0", "a"] {
            check_catalog(&[ConfigTemplate { id, ..ENTRY }]).unwrap();
        }
    }

    #[test]
    fn invariants_reject_duplicates_and_components_that_do_not_require_templates() {
        assert!(check_catalog(&[ENTRY, ENTRY]).is_err());
        assert!(
            check_catalog(&[ConfigTemplate {
                component: "hog",
                ..ENTRY
            }])
            .is_err()
        );
        check_catalog(&[
            ENTRY,
            ConfigTemplate {
                id: "other",
                ..ENTRY
            },
        ])
        .unwrap();
    }

    #[test]
    fn invariants_reject_invalid_bodies() {
        const BODIES: &[&str] = &["value = '${unknown}'", "'${key}' = 1", "not TOML"];
        const BODY: &str = "values = ['${cert_path}', '${key_path}', '${ca_bundle_path}', '${manager_address}', '${manager_server_name}']";
        for body in BODIES {
            assert!(check_catalog(&[ConfigTemplate { body, ..ENTRY }]).is_err());
        }
        check_catalog(&[ConfigTemplate {
            body: BODY,
            ..ENTRY
        }])
        .unwrap();
    }

    #[test]
    fn invariants_reject_each_empty_or_whitespace_only_operator_text() {
        for text in ["", " \t\n "] {
            for entry in [
                ConfigTemplate {
                    name: LocalizedText {
                        en: text,
                        ..ENTRY.name
                    },
                    ..ENTRY
                },
                ConfigTemplate {
                    name: LocalizedText {
                        ko: text,
                        ..ENTRY.name
                    },
                    ..ENTRY
                },
                ConfigTemplate {
                    description: LocalizedText {
                        en: text,
                        ..ENTRY.description
                    },
                    ..ENTRY
                },
                ConfigTemplate {
                    description: LocalizedText {
                        ko: text,
                        ..ENTRY.description
                    },
                    ..ENTRY
                },
            ] {
                assert!(check_catalog(&[entry]).is_err());
            }
        }
    }
}
