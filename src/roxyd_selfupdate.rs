//! The roxyd self-update rollback supervisor units, shipped as data.
//!
//! **This crate is the single owner of this text.** Two consumers install the
//! same supervisor: bootler, the installer, onto the hosts it provisions over
//! SSH, and roxyd's `join`, onto the hosts it onboards itself — where bootler
//! never runs and so cannot place anything. The two host populations must roll back
//! under identical rules, so a consumer **embeds these bytes from its pinned
//! dependency on this crate and never carries a copy of its own**. A copy is not
//! a copy for long: the moment one side edits its own, the two populations
//! diverge silently, and nothing on either host says which rules it is under.
//!
//! The text takes no parameters, and there is deliberately no renderer here —
//! a consumer substitutes nothing. That is possible because the units name no
//! host-varying value: every activation execs the decision subcommand from the
//! `.previous` sibling of the roxyd binary's canonical path, and every one is
//! gated on `ConditionPathExists=` naming the arm record at its canonical path.
//! Should parameterization ever be needed, it is a decision to be taken then,
//! not a hook to leave open now.
//!
//! # The three activations
//!
//! The supervisor's decision logic is a subcommand on the roxyd binary, executed
//! from `.previous` — the known-good slot. The binary being judged is the
//! incoming one; the binary doing the judging is the one that was demonstrably
//! running until the swap. That is also what lets one unit shape serve both host
//! populations: a join-onboarded host has no product CLI and never will, but by
//! definition it has roxyd.
//!
//! The decider decides from durable state, never from which activation woke it —
//! the activation reason is passed only so the journal line and the status record
//! can name what woke it — and it is safe to run at any time, any number of
//! times, **including concurrently**: the three activations are separately named
//! units, so systemd will not serialize them and a timer pass can overlap the
//! boot activation on a host that has just come up. Holding a lock across a
//! revert is the decider's own job; no directive in this text can do it. Three
//! activations reach it:
//!
//! - the **deadline** activation ([`deadline_activation_unit`], driven by
//!   [`deadline_timer_unit`]), which fires on a schedule of its own. It is
//!   required and it cannot be replaced by a `.path` watch: the primary failure
//!   mode is a new binary that starts cleanly, stays up, and never re-establishes
//!   its channel, and nothing on such a host will modify a file to wake a watch.
//! - the **boot** activation ([`boot_activation_unit`]), so a host that was
//!   powered off across the window still reaches a decision.
//! - the **crash** activation ([`crash_activation_unit`]), reached from the roxyd
//!   daemon unit's `OnFailure=`, so a crash-looping build is decided when the
//!   crash threshold is reached rather than at the deadline.
//!
//! # What the consumer still owns
//!
//! The roxyd **daemon** unit is the consumer's, and it is the only side that
//! knows its own name — which is namespaced on an installer-provisioned host and
//! is not on a join-onboarded one. So the two edges that join the daemon to the
//! supervisor are expressed there rather than here, which is also what keeps this
//! text free of a host-varying value:
//!
//! - `OnFailure=` naming [`CRASH_ACTIVATION_SERVICE`], paired with explicit
//!   `StartLimitIntervalSec=`/`StartLimitBurst=` values a crash loop can actually
//!   reach at the daemon's `RestartSec` — `OnFailure=` without that pairing ships
//!   a crash path that silently never fires;
//! - `Before=` naming [`BOOT_ACTIVATION_SERVICE`], so the boot activation is
//!   ordered after the daemon.
//!
//! # The frozen constants
//!
//! The decision subcommand's name, the canonical roxyd binary path whose
//! `.previous` sibling the units exec, and the arm record's path are contract
//! constants, frozen because a rename strands every unit already installed on
//! every host. This text is where they are pinned first: the installer's
//! exported contract module and the checked-in contract document are written
//! against these values, and that document is the tie-breaker should the two
//! ever be found to differ.
//!
//! One of the three is an obligation rather than a name. The units exec
//! `/opt/roxyd/bin/roxyd.previous`, so a consumer installs the roxyd binary at
//! `/opt/roxyd/bin/roxyd` — namespace-free, because a join-onboarded host has no
//! namespace to resolve and a per-product path could not be byte-identical
//! across the two populations. Installing the binary anywhere else and these
//! units alongside it ships a supervisor whose every activation fails to exec,
//! and nothing here catches that: the `ConditionPathExists=` gate names the arm
//! record, not the binary.

/// File name of the boot activation service.
pub const BOOT_ACTIVATION_SERVICE: &str = "roxyd-selfupdate-boot.service";
/// File name of the crash activation service, which the roxyd daemon unit's
/// `OnFailure=` names.
pub const CRASH_ACTIVATION_SERVICE: &str = "roxyd-selfupdate-crash.service";
/// File name of the deadline activation service, which [`DEADLINE_TIMER`] drives.
pub const DEADLINE_ACTIVATION_SERVICE: &str = "roxyd-selfupdate-deadline.service";
/// File name of the timer that drives [`DEADLINE_ACTIVATION_SERVICE`].
pub const DEADLINE_TIMER: &str = "roxyd-selfupdate-deadline.timer";

/// One supervisor unit file: the name it installs under and the text that goes
/// in it, as returned by [`units`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorUnit {
    /// The file name the text installs under, inside the host's system unit
    /// directory.
    pub name: &'static str,
    /// The unit text, verbatim.
    pub text: &'static str,
}

/// Returns every supervisor unit file — the three activation services and the
/// deadline timer — as name/text pairs.
///
/// A consumer installs **all** of them: the activations are not alternatives to
/// one another, and dropping one leaves a failure mode nothing on the host
/// reaches a decision on.
#[must_use]
pub fn units() -> [SupervisorUnit; 4] {
    [
        SupervisorUnit {
            name: BOOT_ACTIVATION_SERVICE,
            text: boot_activation_unit(),
        },
        SupervisorUnit {
            name: CRASH_ACTIVATION_SERVICE,
            text: crash_activation_unit(),
        },
        SupervisorUnit {
            name: DEADLINE_ACTIVATION_SERVICE,
            text: deadline_activation_unit(),
        },
        SupervisorUnit {
            name: DEADLINE_TIMER,
            text: deadline_timer_unit(),
        },
    ]
}

/// Returns the boot activation service text, installed as
/// [`BOOT_ACTIVATION_SERVICE`].
///
/// A oneshot the consumer enables into `multi-user.target`, so a host that was
/// powered off across the arm record's window still reaches a decision on the
/// next boot — the case a power cut between the arm record's fsync and the binary
/// rename lands on.
#[must_use]
pub fn boot_activation_unit() -> &'static str {
    include_str!("../assets/units/roxyd-selfupdate-boot.service")
}

/// Returns the crash activation service text, installed as
/// [`CRASH_ACTIVATION_SERVICE`].
///
/// It carries no `[Install]` section: nothing enables it, and the roxyd daemon
/// unit's `OnFailure=` is what reaches it, so a crash-looping incoming build is
/// decided when the crash threshold is reached instead of waiting out the
/// deadline. A reached crash threshold is a failure condition in its own right,
/// not an early firing of the deadline check.
#[must_use]
pub fn crash_activation_unit() -> &'static str {
    include_str!("../assets/units/roxyd-selfupdate-crash.service")
}

/// Returns the deadline activation service text, installed as
/// [`DEADLINE_ACTIVATION_SERVICE`].
///
/// It carries no `[Install]` section either: [`deadline_timer_unit`] is what
/// reaches it.
#[must_use]
pub fn deadline_activation_unit() -> &'static str {
    include_str!("../assets/units/roxyd-selfupdate-deadline.service")
}

/// Returns the deadline timer text, installed as [`DEADLINE_TIMER`].
///
/// It fires on a schedule of its own, armed independently of roxyd's liveness,
/// and re-runs the decider so the deadline is compared against the host clock on
/// each pass — the deadline itself lives in the arm record, which a timer cannot
/// read.
///
/// The timer carries **no** `ConditionPathExists=` gate, and that asymmetry with
/// the three activation services is deliberate. A condition on a `.timer` is
/// evaluated when the timer is started, which is at boot: an arm record written
/// hours later by a self-update would find the timer already skipped, and the one
/// activation that catches a build which runs but never reconnects would never
/// fire. The gate sits on the service the timer triggers instead, where it is
/// re-evaluated on every pass, so an unarmed host spends nothing beyond a
/// condition check.
#[must_use]
pub fn deadline_timer_unit() -> &'static str {
    include_str!("../assets/units/roxyd-selfupdate-deadline.timer")
}

#[cfg(test)]
mod tests {
    use super::{
        BOOT_ACTIVATION_SERVICE, CRASH_ACTIVATION_SERVICE, DEADLINE_ACTIVATION_SERVICE,
        DEADLINE_TIMER, boot_activation_unit, crash_activation_unit, deadline_activation_unit,
        deadline_timer_unit, units,
    };
    use crate::apply::PREVIOUS_ARTIFACT_SUFFIX;

    /// The arm record gate, verbatim. Its path is a frozen contract constant: the
    /// producer of the record lives in another repository, and a rename strands
    /// every unit already installed.
    const ARM_RECORD_GATE: &str = "ConditionPathExists=/var/lib/roxyd/selfupdate/arm.json";
    /// The canonical roxyd binary path whose `.previous` sibling every activation
    /// execs. Frozen for the same reason as the gate above.
    const ROXYD_BINARY: &str = "/opt/roxyd/bin/roxyd";
    /// The `.previous` invocation each activation execs, verbatim, one per
    /// activation reason. The binary path, the subcommand name and the `--reason`
    /// values are frozen for the same reason as the gate above.
    const BOOT_EXEC_START: &str =
        "ExecStart=/opt/roxyd/bin/roxyd.previous selfupdate-decide --reason boot";
    const CRASH_EXEC_START: &str =
        "ExecStart=/opt/roxyd/bin/roxyd.previous selfupdate-decide --reason crash";
    const DEADLINE_EXEC_START: &str =
        "ExecStart=/opt/roxyd/bin/roxyd.previous selfupdate-decide --reason deadline";

    /// Splits one unit's text into `(section, key, value)` triples, asserting the
    /// section/key *shape* of a systemd unit file as it goes — never its
    /// semantics, which only systemd itself can judge.
    fn parse(name: &str, text: &str) -> Vec<(String, String, String)> {
        assert!(
            text.ends_with('\n'),
            "{name}: a unit file ends with a newline"
        );
        assert!(
            !text.contains('\r'),
            "{name}: a unit file carries no carriage return"
        );

        let mut section: Option<String> = None;
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            assert_eq!(
                line.trim_end(),
                line,
                "{name}:{number}: no trailing whitespace"
            );
            if let Some(header) = line.strip_prefix('[') {
                let header = header
                    .strip_suffix(']')
                    .unwrap_or_else(|| panic!("{name}:{number}: unterminated section header"));
                assert!(
                    !header.is_empty() && header.chars().all(|c| c.is_ascii_alphanumeric()),
                    "{name}:{number}: `{header}` is not a section name"
                );
                section = Some(header.to_string());
                continue;
            }
            let current = section
                .clone()
                .unwrap_or_else(|| panic!("{name}:{number}: an entry before any section header"));
            let (key, value) = line.split_once('=').unwrap_or_else(|| {
                panic!("{name}:{number}: `{line}` is neither section nor entry")
            });
            assert!(
                key.starts_with(|c: char| c.is_ascii_alphabetic())
                    && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "{name}:{number}: `{key}` is not a directive name"
            );
            assert!(!value.is_empty(), "{name}:{number}: `{key}` has no value");
            entries.push((current, key.to_string(), value.to_string()));
        }
        assert!(
            !entries.is_empty(),
            "{name}: a unit file carries directives"
        );
        entries
    }

    /// Returns every value `key` is given inside `section`.
    fn values<'a>(
        entries: &'a [(String, String, String)],
        section: &str,
        key: &str,
    ) -> Vec<&'a str> {
        entries
            .iter()
            .filter(|(s, k, _)| s == section && k == key)
            .map(|(_, _, v)| v.as_str())
            .collect()
    }

    #[test]
    fn every_shipped_unit_parses_as_a_systemd_unit() {
        for unit in units() {
            let entries = parse(unit.name, unit.text);
            let sections: Vec<&str> = entries.iter().map(|(s, _, _)| s.as_str()).collect();
            assert!(
                sections.contains(&"Unit"),
                "{}: every unit opens a [Unit] section",
                unit.name
            );
            // systemd reads a unit's type off its file-name extension, not its
            // body, so a name whose suffix disagrees with the section it carries
            // is loaded as the wrong type or not at all.
            let body = if unit.name == DEADLINE_TIMER {
                "Timer"
            } else {
                "Service"
            };
            assert!(
                sections.contains(&body),
                "{}: every unit carries its [{body}] section",
                unit.name
            );
            assert!(
                unit.name.ends_with(&format!(".{}", body.to_lowercase())),
                "{}: a [{body}] unit installs under a `.{}` name",
                unit.name,
                body.to_lowercase()
            );
        }
    }

    #[test]
    fn each_activation_pins_its_previous_exec_start_and_its_arm_record_gate() {
        for (name, text, exec_start) in [
            (
                BOOT_ACTIVATION_SERVICE,
                boot_activation_unit(),
                BOOT_EXEC_START,
            ),
            (
                CRASH_ACTIVATION_SERVICE,
                crash_activation_unit(),
                CRASH_EXEC_START,
            ),
            (
                DEADLINE_ACTIVATION_SERVICE,
                deadline_activation_unit(),
                DEADLINE_EXEC_START,
            ),
        ] {
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(
                lines.iter().filter(|l| **l == exec_start).count(),
                1,
                "{name}: execs the decision subcommand from `.previous`, exactly once"
            );
            assert_eq!(
                lines.iter().filter(|l| **l == ARM_RECORD_GATE).count(),
                1,
                "{name}: gates on the arm record, exactly once"
            );

            let entries = parse(name, text);
            assert_eq!(
                values(&entries, "Service", "ExecStart").len(),
                1,
                "{name}: carries no second `ExecStart=`"
            );
            assert_eq!(
                values(&entries, "Unit", "ConditionPathExists").len(),
                1,
                "{name}: carries no second `ConditionPathExists=`"
            );
            assert_eq!(
                values(&entries, "Service", "Type"),
                ["oneshot"],
                "{name}: the decider runs to completion and exits"
            );
        }
    }

    #[test]
    fn every_activation_execs_the_sibling_this_crate_writes() {
        // The `.previous` sibling these units exec is the one the apply path
        // copies aside, so the suffix is one decision and not two. Change it
        // there alone and every installed unit execs a path that is never
        // written, with nothing on the host to say why.
        let previous = format!("{ROXYD_BINARY}{PREVIOUS_ARTIFACT_SUFFIX}");
        for exec_start in [BOOT_EXEC_START, CRASH_EXEC_START, DEADLINE_EXEC_START] {
            let binary = exec_start
                .strip_prefix("ExecStart=")
                .and_then(|command| command.split(' ').next());
            assert_eq!(
                binary,
                Some(previous.as_str()),
                "`{exec_start}` execs the backed-up sibling of `{ROXYD_BINARY}`"
            );
        }
    }

    #[test]
    fn the_deadline_timer_drives_the_deadline_service_and_is_itself_ungated() {
        let entries = parse(DEADLINE_TIMER, deadline_timer_unit());
        assert_eq!(
            values(&entries, "Timer", "Unit"),
            [DEADLINE_ACTIVATION_SERVICE],
            "the timer triggers the deadline activation"
        );
        assert!(
            !values(&entries, "Timer", "OnCalendar").is_empty(),
            "the timer fires on a schedule of its own, needing no file to change"
        );
        // A condition on the `.timer` is evaluated when the timer starts, so a
        // record written after boot would find it already skipped. The gate
        // belongs on the service the timer triggers, where every pass re-reads it.
        assert!(
            values(&entries, "Unit", "ConditionPathExists").is_empty(),
            "the timer itself carries no arm-record gate"
        );
    }

    #[test]
    fn only_the_boot_activation_and_the_timer_are_enabled() {
        for unit in units() {
            let entries = parse(unit.name, unit.text);
            let wanted_by = values(&entries, "Install", "WantedBy");
            match unit.name {
                BOOT_ACTIVATION_SERVICE => assert_eq!(wanted_by, ["multi-user.target"]),
                DEADLINE_TIMER => assert_eq!(wanted_by, ["timers.target"]),
                // The crash activation is reached from the daemon unit's
                // `OnFailure=` and the deadline activation from the timer, so
                // neither is enabled and neither carries an `[Install]` section.
                _ => assert!(
                    wanted_by.is_empty(),
                    "{}: is triggered, not enabled",
                    unit.name
                ),
            }
        }
    }

    #[test]
    fn no_shipped_unit_names_a_host_varying_value() {
        for unit in units() {
            // The product namespace is the one value that varies between the two
            // host populations, and an installer-provisioned host resolves it into
            // paths under these roots. None may appear here.
            for varying in ["/opt/clumit-", "/etc/clumit-", "/var/lib/clumit-", "%i"] {
                assert!(
                    !unit.text.contains(varying),
                    "{}: names `{varying}`, which is not the same on every host",
                    unit.name
                );
            }
        }
    }

    #[test]
    fn units_names_every_supervisor_unit_and_pairs_each_with_its_own_accessor() {
        // Without this, an entry dropped from `units()` fails no test: every
        // other test either iterates whatever `units()` happens to return or
        // reaches an accessor directly. A consumer installing three of the four
        // leaves a failure mode nothing on the host reaches a decision on.
        assert_eq!(
            units().map(|unit| unit.name),
            [
                BOOT_ACTIVATION_SERVICE,
                CRASH_ACTIVATION_SERVICE,
                DEADLINE_ACTIVATION_SERVICE,
                DEADLINE_TIMER,
            ]
        );
        assert_eq!(
            units().map(|unit| unit.text),
            [
                boot_activation_unit(),
                crash_activation_unit(),
                deadline_activation_unit(),
                deadline_timer_unit(),
            ]
        );
    }

    #[test]
    fn every_unit_file_name_is_distinct_and_its_text_is_its_own() {
        let units = units();
        for (index, unit) in units.iter().enumerate() {
            for other in &units[index + 1..] {
                assert_ne!(unit.name, other.name, "two units install under one name");
                assert_ne!(unit.text, other.text, "two units ship one text");
            }
        }
    }
}
