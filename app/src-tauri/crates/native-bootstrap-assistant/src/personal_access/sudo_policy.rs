//! Non-secret preflight of the effective remote `sudo` policy.
//!
//! A `sudo` password travels on the standard input of the remote command. If
//! the remote policy logs input, that password lands in `/var/log/sudo-io` in
//! clear text. This module decides, *before* any password exists, whether that
//! outcome can be excluded. Everything it reads is public policy output: it
//! never sees, sends or stores a secret.
//!
//! The decision never relies on `sudo`'s own password redaction. That
//! redaction depends on `passprompt_regex` matching the prompt, and this
//! palier passes its own sentinel prompt, which the default regex does not
//! describe. Input logging is therefore refused outright instead of being
//! trusted to redact.

/// Fixed preflight argument vector. `-N` keeps the timestamp untouched, `-n`
/// forbids any interactive prompt and `-ll` asks for the long listing. No part
/// of it comes from the frontend.
pub const PREFLIGHT_ARGUMENTS: [&str; 4] = ["-N", "-n", "-l", "-l"];

/// Largest accepted preflight output. A real listing is a few hundred bytes.
pub const MAX_PREFLIGHT_OUTPUT_BYTES: usize = 4 * 1024;

/// English anchors of the long listing. The preflight runs under `LC_ALL=C`,
/// so a translated or absent anchor means the output cannot be attested.
const DEFAULTS_ANCHOR: &str = "Matching Defaults entries for";
const COMMANDS_ANCHOR: &str = "may run the following commands";
/// What `sudo` answers instead of a listing. The first three are what it writes
/// when the answer costs a secret or a terminal it has not got; the fourth is
/// the one `requiretty` produces, captured verbatim from `sudo 1.9.16p2` on
/// Debian 13 — that policy refuses even to *list* itself without a terminal,
/// and a refusal that specific must not be read as a merely unrecognised
/// listing.
const AUTHENTICATION_MARKERS: [&str; 4] = [
    "a password is required",
    "a terminal is required",
    "sudo: no tty present",
    "sorry, you must have a tty",
];

/// Boolean sudoers flags that place the standard input in the I/O log.
/// `log_input` implies `log_stdin`; both are refused.
const INPUT_LOGGING_FLAGS: [&str; 2] = ["log_input", "log_stdin"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SudoRefusal {
    /// Listing the policy would itself require authenticating, so the policy
    /// cannot be attested without first sending the secret it should protect.
    AuthenticationRequired,
    OutputTooLarge,
    OutputNotAscii,
    /// Missing, translated or otherwise unrecognised listing.
    Unattestable,
    InputLoggingActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SudoDecision {
    /// True only when input logging is provably excluded.
    pub password_may_be_sent: bool,
    /// Always false. Kept explicit so a later change cannot silently start
    /// depending on `sudo`'s configurable prompt redaction.
    pub relies_on_sudo_redaction: bool,
}

/// Decides whether a `sudo` password may be sent at all.
///
/// `succeeded` is the preflight exit status, `output` its captured bytes and
/// `truncated` whether the capture hit its bound. Any doubt fails closed.
pub fn evaluate(
    succeeded: bool,
    output: &[u8],
    truncated: bool,
) -> Result<SudoDecision, SudoRefusal> {
    if truncated || output.len() > MAX_PREFLIGHT_OUTPUT_BYTES {
        return Err(SudoRefusal::OutputTooLarge);
    }
    if !output.is_ascii() {
        // Under LC_ALL=C the listing is ASCII. Anything else means the locale
        // was not applied, so the anchors below cannot be trusted.
        return Err(SudoRefusal::OutputNotAscii);
    }
    let text = std::str::from_utf8(output).map_err(|_| SudoRefusal::OutputNotAscii)?;
    let lowered = text.to_ascii_lowercase();
    if AUTHENTICATION_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return Err(SudoRefusal::AuthenticationRequired);
    }
    if !succeeded {
        return Err(SudoRefusal::Unattestable);
    }
    if !text.contains(COMMANDS_ANCHOR) {
        return Err(SudoRefusal::Unattestable);
    }

    let tokens = defaults_tokens(text).ok_or(SudoRefusal::Unattestable)?;
    if input_logging_active(&tokens) {
        return Err(SudoRefusal::InputLoggingActive);
    }

    Ok(SudoDecision {
        password_may_be_sent: true,
        relies_on_sudo_redaction: false,
    })
}

/// Collects the comma-separated Defaults entries that follow the anchor.
fn defaults_tokens(text: &str) -> Option<Vec<&str>> {
    let mut lines = text.lines();
    lines.find(|line| line.trim_start().starts_with(DEFAULTS_ANCHOR))?;
    let mut tokens = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        for token in trimmed.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                tokens.push(token);
            }
        }
    }
    Some(tokens)
}

/// A disabled boolean is either absent or printed negated, so only a bare
/// flag name counts as active. An unknown token is ignored here because the
/// anchors above already established that the listing itself is understood.
fn input_logging_active(tokens: &[&str]) -> bool {
    tokens.iter().any(|token| {
        let name = token.split('=').next().unwrap_or(token).trim();
        INPUT_LOGGING_FLAGS.contains(&name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(defaults: &str) -> String {
        format!(
            "Matching Defaults entries for operator on target:\n    \
             {defaults}\n\nUser operator may run the following commands on target:\n\n\
             Sudoers entry:\n    RunAsUsers: root\n    Commands:\n\t/usr/bin/id\n"
        )
    }

    #[test]
    fn a_policy_without_input_logging_allows_sending_the_password_once() {
        let output = listing("env_reset, mail_badpass, secure_path=/usr/bin");
        let decision = evaluate(true, output.as_bytes(), false).expect("attestable policy");
        assert!(decision.password_may_be_sent);
        assert!(
            !decision.relies_on_sudo_redaction,
            "the decision must never depend on sudo's prompt redaction"
        );
    }

    #[test]
    fn input_logging_refuses_before_any_password_exists() {
        for flag in ["log_input", "log_stdin"] {
            let output = listing(&format!("env_reset, {flag}, mail_badpass"));
            assert_eq!(
                evaluate(true, output.as_bytes(), false),
                Err(SudoRefusal::InputLoggingActive),
                "{flag} must fail closed"
            );
        }
    }

    #[test]
    fn a_negated_flag_is_not_read_as_active() {
        let output = listing("env_reset, !log_input, !log_stdin");
        assert!(
            evaluate(true, output.as_bytes(), false)
                .expect("negated flags leave logging off")
                .password_may_be_sent
        );
    }

    #[test]
    fn input_logging_is_detected_anywhere_in_the_entry_list() {
        let output = listing("env_reset, mail_badpass, secure_path=/usr/bin, log_input");
        assert_eq!(
            evaluate(true, output.as_bytes(), false),
            Err(SudoRefusal::InputLoggingActive)
        );
    }

    #[test]
    fn a_policy_that_cannot_be_listed_without_authenticating_is_refused() {
        let output = b"sudo: a password is required\n";
        assert_eq!(
            evaluate(false, output, false),
            Err(SudoRefusal::AuthenticationRequired)
        );
    }

    #[test]
    fn a_missing_tty_is_refused_rather_than_retried() {
        for answer in [
            &b"sudo: no tty present and no askpass program specified\n"[..],
            // What `requiretty` really answers, on the very listing this
            // module was going to judge.
            b"sudo: sorry, you must have a tty to run sudo\n",
        ] {
            assert_eq!(
                evaluate(false, answer, false),
                Err(SudoRefusal::AuthenticationRequired),
                "{:?} must be read as the policy refusing to describe itself",
                String::from_utf8_lossy(answer)
            );
        }
    }

    #[test]
    fn an_unrecognised_or_translated_listing_is_refused() {
        for output in [
            "",
            "Entrees Defaults correspondantes pour operator sur target:\n    env_reset\n",
            "Matching Defaults entries for operator on target:\n    env_reset\n",
            "User operator may run the following commands on target:\n\n    /usr/bin/id\n",
        ] {
            assert!(
                matches!(
                    evaluate(true, output.as_bytes(), false),
                    Err(SudoRefusal::Unattestable)
                ),
                "an unattestable listing must fail closed: {output:?}"
            );
        }
    }

    #[test]
    fn a_non_ascii_listing_means_the_locale_was_not_applied() {
        let output = "Matching Defaults entries for opérateur on target:\n    env_reset\n\n\
                      User may run the following commands on target:\n";
        assert_eq!(
            evaluate(true, output.as_bytes(), false),
            Err(SudoRefusal::OutputNotAscii)
        );
    }

    #[test]
    fn a_truncated_or_oversized_capture_is_refused() {
        let output = listing("env_reset");
        assert_eq!(
            evaluate(true, output.as_bytes(), true),
            Err(SudoRefusal::OutputTooLarge),
            "a capture that hit its bound cannot be attested"
        );

        let oversized = vec![b'A'; MAX_PREFLIGHT_OUTPUT_BYTES + 1];
        assert_eq!(
            evaluate(true, &oversized, false),
            Err(SudoRefusal::OutputTooLarge)
        );
    }

    #[test]
    fn a_failed_preflight_never_yields_a_decision() {
        let output = listing("env_reset");
        assert_eq!(
            evaluate(false, output.as_bytes(), false),
            Err(SudoRefusal::Unattestable)
        );
    }

    #[test]
    fn the_preflight_argument_vector_stays_fixed() {
        assert_eq!(PREFLIGHT_ARGUMENTS, ["-N", "-n", "-l", "-l"]);
    }

    /// Captures taken verbatim from `sudo 1.9.16p2` on Debian 13 under
    /// `LC_ALL=C`, with a synthetic account and synthetic policies. Real sudo
    /// wraps the Defaults entries over several lines, which a listing invented
    /// from the manual page does not show; these fixtures pin the decision to
    /// the format actually emitted.
    mod real_debian_13_captures {
        use super::*;

        const NOMINAL: &str = "Matching Defaults entries for ycoperator on lab-app:\n    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin,\n    use_pty\n\nUser ycoperator may run the following commands on lab-app:\n\nSudoers entry: /etc/sudoers.d/90-lab-ycoperator\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n\t/usr/bin/id\n";

        const LOG_INPUT: &str = "Matching Defaults entries for ycoperator on lab-app:\n    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin,\n    use_pty, log_input\n\nUser ycoperator may run the following commands on lab-app:\n\nSudoers entry: /etc/sudoers.d/90-lab-ycoperator\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n\t/usr/bin/id\n";

        const LOG_STDIN: &str = "Matching Defaults entries for ycoperator on lab-app:\n    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin,\n    use_pty, log_stdin\n\nUser ycoperator may run the following commands on lab-app:\n\nSudoers entry: /etc/sudoers.d/90-lab-ycoperator\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n\t/usr/bin/id\n";

        const NEGATED: &str = "Matching Defaults entries for ycoperator on lab-app:\n    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin,\n    use_pty, !log_input, !log_stdin\n\nUser ycoperator may run the following commands on lab-app:\n\nSudoers entry: /etc/sudoers.d/90-lab-ycoperator\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n\t/usr/bin/id\n";

        const UNLISTED: &str = "sudo: a password is required\n";

        #[test]
        fn a_real_nominal_policy_is_attested_across_wrapped_lines() {
            let decision = evaluate(true, NOMINAL.as_bytes(), false).expect("real nominal policy");
            assert!(decision.password_may_be_sent);
            assert!(!decision.relies_on_sudo_redaction);
        }

        #[test]
        fn real_input_logging_is_detected_on_a_wrapped_continuation_line() {
            for capture in [LOG_INPUT, LOG_STDIN] {
                assert_eq!(
                    evaluate(true, capture.as_bytes(), false),
                    Err(SudoRefusal::InputLoggingActive),
                    "input logging wrapped onto a continuation line must fail closed"
                );
            }
        }

        #[test]
        fn real_negated_flags_leave_the_password_path_open() {
            assert!(
                evaluate(true, NEGATED.as_bytes(), false)
                    .expect("negated flags leave logging off")
                    .password_may_be_sent
            );
        }

        #[test]
        fn a_real_unlisted_account_cannot_attest_its_policy() {
            assert_eq!(
                evaluate(false, UNLISTED.as_bytes(), false),
                Err(SudoRefusal::AuthenticationRequired)
            );
        }

        /// `use_pty` and `secure_path` sit next to the flags that matter and
        /// must never be mistaken for input logging.
        #[test]
        fn neighbouring_default_entries_are_not_read_as_input_logging() {
            let tokens = defaults_tokens(NOMINAL).expect("wrapped defaults");
            assert!(tokens.contains(&"use_pty"));
            assert!(tokens.iter().any(|token| token.starts_with("secure_path=")));
            assert!(!input_logging_active(&tokens));
        }
    }
}
