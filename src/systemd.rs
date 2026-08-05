//! The one systemd serialization and rejection rule this crate holds.
//!
//! A [`crate::module_spec::UnitTemplate`] is a closed structured record rather
//! than templated text, which removes placeholder substitution but not
//! systemd's own parsing of a unit file. So the escaping rule lives here, once,
//! with two entry points:
//!
//! - [`is_representable`] is the **rejection** half. It answers the narrow
//!   question *can this byte sequence appear in a unit file at all?* and is
//!   what the spec validator applies to package-declared strings. It is not a
//!   command-safety check and says nothing about what a string means to a
//!   program that later receives it — a value that becomes an argument of a
//!   root-run command carries its own domain grammar instead (see
//!   [`crate::module_spec::ReloadSpec`]).
//! - [`render`] is the **serialization** half. It turns an already
//!   host-resolved value into the directive text a unit file carries. Its only
//!   production caller is the renderer, which is not in this crate yet.
//!
//! Exactly one copy of these rules exists, because two repositories render
//! bytes from the same record and any second copy is a silent divergence.

/// A resolved value about to become unit-file directive text.
///
/// Every variant carries a value that has already been resolved host-side: this
/// type knows nothing about [`crate::module_spec::RenderVar`] and resolves
/// nothing. [`UnitValue::MainPid`] is the one exception and exists because
/// `$MAINPID` is systemd's own expansion rather than a value anybody resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitValue<'a> {
    /// One element of `ExecStart=`, `ExecReload=` or `WorkingDirectory=`.
    Argument(&'a str),
    /// The literal `$MAINPID`, which systemd expands itself.
    MainPid,
    /// One `Environment=` entry, rendered as the quoted `KEY=VALUE` body.
    Environment {
        /// Variable name, already validated against the key grammar.
        key: &'a str,
        /// Variable value.
        value: &'a str,
    },
    /// The whole-line body of `Description=`.
    Description(&'a str),
}

/// The text systemd expands to the main process id.
const MAIN_PID: &str = "$MAINPID";

/// Reports whether `value` can be represented in a unit file at all: it is
/// non-empty and carries no control character (which covers NUL, `\n` and
/// `\r`).
///
/// This is the rejection half of the rule [`render`] serializes. Nothing else
/// is claimed: a representable string can still be a nonsensical argument to
/// whatever eventually receives it, which is why the strings that become
/// arguments of a root-run command are validated against their own grammars.
#[must_use]
pub fn is_representable(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

/// Renders one resolved `value` as the directive text it contributes,
/// without its directive name.
///
/// An [`UnitValue::Argument`] is emitted bare when its raw text is bare-safe —
/// every byte in `0x21..=0x7E` and none of `"`, `'` or `\` — and wrapped in
/// double quotes otherwise; either way `%` is doubled to `%%` and `$` to `$$`.
/// The bare-safe test reads the **raw** value while the emitted text is the
/// doubled one, so a value carrying `%` or `$` stays bare and is still doubled.
/// An [`UnitValue::Environment`] entry is always quoted and doubles `%` but
/// **not** `$`, because systemd performs no variable expansion there. An
/// [`UnitValue::Description`] is a whole line, unquoted, with `%` doubled.
///
/// The caller joins argument elements with a single space and prefixes the
/// directive name; the canonical section layout and directive order live with
/// the record this renders from.
#[must_use]
pub fn render(value: UnitValue<'_>) -> String {
    match value {
        UnitValue::Argument(raw) => {
            let doubled = double(raw, true);
            if is_bare_safe(raw) {
                doubled
            } else {
                quote(&doubled)
            }
        }
        UnitValue::MainPid => MAIN_PID.to_string(),
        UnitValue::Environment { key, value } => quote(&double(&format!("{key}={value}"), false)),
        UnitValue::Description(raw) => double(raw, false),
    }
}

/// Doubles `%` to `%%`, and `$` to `$$` when `dollars` is set.
fn double(value: &str, dollars: bool) -> String {
    let percent_doubled = value.replace('%', "%%");
    if dollars {
        percent_doubled.replace('$', "$$")
    } else {
        percent_doubled
    }
}

/// Reports whether `raw` may be emitted without surrounding quotes.
///
/// The empty string is not bare-safe: emitting it bare would contribute no
/// bytes at all rather than an empty argument. It cannot reach here from a
/// validated template — [`is_representable`] rejects it — and this keeps the
/// serializer total anyway.
fn is_bare_safe(raw: &str) -> bool {
    !raw.is_empty()
        && raw
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7E) && !matches!(byte, b'"' | b'\'' | b'\\'))
}

/// Wraps `value` in double quotes, escaping `\` to `\\` and `"` to `\"`.
fn quote(value: &str) -> String {
    let escaped = value.replace('\\', r"\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::{UnitValue, is_representable, render};

    #[test]
    fn the_rejection_half_refuses_the_unrepresentable_classes() {
        for bad in [
            "\0",
            "a\0b",
            "line\nbreak",
            "carriage\rreturn",
            "bell\x07",
            "",
        ] {
            assert!(!is_representable(bad), "{bad:?} must be rejected");
        }
        for good in ["/opt/bin/roxyd", "-c", "a b", "%", "$", "\"", "'", "\\"] {
            assert!(is_representable(good), "{good:?} must be accepted");
        }
    }

    #[test]
    fn a_bare_safe_argument_is_emitted_unquoted() {
        assert_eq!(
            render(UnitValue::Argument("/opt/clumit-security/bin/roxyd")),
            "/opt/clumit-security/bin/roxyd"
        );
        assert_eq!(render(UnitValue::Argument("--ca-certs")), "--ca-certs");
    }

    #[test]
    fn an_argument_doubles_both_percent_and_dollar() {
        assert_eq!(render(UnitValue::Argument("100%done")), "100%%done");
        assert_eq!(render(UnitValue::Argument("$HOME")), "$$HOME");
    }

    #[test]
    fn the_bare_safe_test_reads_the_raw_value_while_the_output_is_the_doubled_one() {
        // `%` and `$` are both inside the bare-safe set, so a value carrying
        // them stays unquoted — and is still doubled. Pinning this keeps an
        // implementation from testing the doubled text and quoting instead.
        for (raw, expected) in [("a%b", "a%%b"), ("a$b", "a$$b"), ("%$", "%%$$")] {
            let rendered = render(UnitValue::Argument(raw));
            assert_eq!(rendered, expected);
            assert!(!rendered.starts_with('"'), "{raw:?} got: {rendered}");
        }
    }

    #[test]
    fn an_argument_leaving_the_bare_safe_set_is_quoted_and_escaped() {
        assert_eq!(render(UnitValue::Argument("a b")), "\"a b\"");
        assert_eq!(render(UnitValue::Argument("it's")), "\"it's\"");
        assert_eq!(render(UnitValue::Argument("say \"hi\"")), r#""say \"hi\"""#);
        assert_eq!(render(UnitValue::Argument(r"a\b")), r#""a\\b""#);
        // Leaving the set does not switch the doubling off.
        assert_eq!(render(UnitValue::Argument("a %$ b")), "\"a %%$$ b\"");
    }

    #[test]
    fn main_pid_renders_bare_and_undoubled() {
        assert_eq!(render(UnitValue::MainPid), "$MAINPID");
    }

    #[test]
    fn an_environment_entry_is_always_quoted_and_leaves_dollar_alone() {
        // systemd performs no variable expansion in `Environment=`, so `$` is
        // not doubled there while `%` still is. The asymmetry is the point.
        assert_eq!(
            render(UnitValue::Environment {
                key: "RUST_LOG",
                value: "info",
            }),
            r#""RUST_LOG=info""#
        );
        assert_eq!(
            render(UnitValue::Environment {
                key: "PROMPT",
                value: "$USER 50%",
            }),
            r#""PROMPT=$USER 50%%""#
        );
        assert_eq!(
            render(UnitValue::Environment {
                key: "Q",
                value: r#"a"b\c"#,
            }),
            r#""Q=a\"b\\c""#
        );
    }

    #[test]
    fn a_description_is_a_whole_unquoted_line_with_percent_doubled() {
        assert_eq!(
            render(UnitValue::Description("Clumit Security review")),
            "Clumit Security review"
        );
        assert_eq!(render(UnitValue::Description("50% done")), "50%% done");
        // `$` is not doubled on a `Description=` line either.
        assert_eq!(render(UnitValue::Description("a $ b")), "a $ b");
    }
}
