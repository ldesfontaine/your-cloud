//! Non-secret preflight of the effective remote `sudo` policy.
//!
//! This module judges whether the listing of the remote policy can be trusted.
//! Everything it reads is public policy output: it never sees, sends or stores
//! a secret.
//!
//! **Ce module a porté un refus de plus, et il est tombé le 22 août 2026
//! (#217).** Il refusait une politique portant `log_input` ou `log_stdin`, au
//! motif écrit que « le mot de passe voyage sur l'entrée standard de la
//! commande distante, donc une politique qui journalise l'entrée le pose en
//! clair dans `/var/log/sudo-io` ». **Ce mécanisme a été mesuré, et il est
//! faux pour la forme de commande du produit** : sans PTY et avec `-S`, `sudo`
//! consomme la ligne du secret pendant l'authentification, avant que le
//! journal d'E/S de la commande n'existe. Le journal capte bien l'entrée de la
//! commande — un témoin placé derrière le secret s'y retrouve — mais le secret,
//! lui, n'y est jamais.
//!
//! **Bornes de cette mesure, et ce qui ramènerait le refus.** Elle vaut pour
//! Debian 13, `sudo` 1.9.16p2, sans PTY, et la forme `-S` sans rien piper
//! derrière le secret. Un acte futur qui allouerait un PTY, ou une version de
//! `sudo` qui lirait le secret autrement, rouvrirait la question.
//! Le pilote LAB `sudo-io-logging` rejoue la mesure : c'est lui qui justifie
//! l'absence de ce refus, et qui rougira le jour où elle cessera d'être vraie.
//!
//! **Ce que ce refus ne protégeait pas, et qui a pris sa place.** Il regardait
//! la politique d'une machine distante pour se prémunir d'un défaut qui
//! naîtrait ici. La garde appartient donc à la table des actes, où elle est
//! exerçable : `installation::acts` tient qu'aucun acte ne porte de matériau
//! produit, ni sur son entrée, ni sur sa sortie — et la sortie compte, parce
//! qu'une machine qui journalise capture bien celle des commandes.
//!
//! La décision ne s'appuie jamais sur le masquage de mot de passe de `sudo`.
//! Cette réduction dépend de `passprompt_regex`, que la configuration peut
//! changer, et ce palier passe son propre prompt sentinelle, que la regex par
//! défaut ne décrit pas. Le prompt sentinelle reste : il protège de
//! l'usurpation d'invite, ce qu'aucune regex configurable ne fait.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SudoRefusal {
    /// Listing the policy would itself require authenticating, so the policy
    /// cannot be attested without first sending the secret it should protect.
    AuthenticationRequired,
    OutputTooLarge,
    OutputNotAscii,
    /// Missing, translated or otherwise unrecognised listing.
    Unattestable,
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

    // Le bloc `Defaults` doit être présent et lisible : c'est une moitié de
    // l'attestation du listing, au même titre que l'ancre des commandes. Ce
    // qu'on y lisait — la journalisation d'entrée — a cessé d'être un refus,
    // mais un listing dont ce bloc manque reste un listing qu'on ne comprend
    // pas. Retirer un refus n'autorise pas à emporter ses voisins.
    defaults_tokens(text).ok_or(SudoRefusal::Unattestable)?;

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
    fn a_plain_policy_allows_sending_the_password_once() {
        let output = listing("env_reset, mail_badpass, secure_path=/usr/bin");
        let decision = evaluate(true, output.as_bytes(), false).expect("attestable policy");
        assert!(decision.password_may_be_sent);
        assert!(
            !decision.relies_on_sudo_redaction,
            "the decision must never depend on sudo's prompt redaction"
        );
    }

    /// Une machine qui journalise ses E/S est **servie**, et ce test est la
    /// trace exécutable du refus retiré (#217).
    ///
    /// Le refus supposait que le secret atterrissait dans le journal ; la
    /// mesure a établi le contraire pour la forme de commande du produit. Ce
    /// que la journalisation capte réellement — la sortie des actes — est tenu
    /// là où c'est exerçable : `installation::acts` interdit qu'un acte y porte
    /// du matériau produit.
    #[test]
    fn a_machine_that_logs_its_io_is_served_rather_than_refused() {
        for flag in ["log_input", "log_stdin", "log_input, log_output"] {
            let output = listing(&format!("env_reset, {flag}, mail_badpass"));
            let decision = evaluate(true, output.as_bytes(), false).unwrap_or_else(|refusal| {
                panic!("{flag} doit être servi, refus rendu : {refusal:?}")
            });
            assert!(decision.password_may_be_sent);
        }
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

        /// Les deux captures réelles d'une politique journalisante restent
        /// dans la suite après le retrait du refus : elles prouvent désormais
        /// qu'une telle machine est servie, sur le format exact que Debian 13
        /// émet — repli de ligne compris.
        #[test]
        fn real_io_logging_captures_are_served() {
            for capture in [LOG_INPUT, LOG_STDIN] {
                assert!(
                    evaluate(true, capture.as_bytes(), false)
                        .expect("une politique journalisante est servie")
                        .password_may_be_sent
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

        /// Le bloc `Defaults` reste lu, et son repli de ligne reste compris :
        /// c'est une moitié de l'attestation du listing, et elle survit au
        /// refus retiré. Retirer un refus n'emporte pas ses voisins.
        #[test]
        fn the_wrapped_defaults_block_is_still_parsed() {
            let tokens = defaults_tokens(NOMINAL).expect("wrapped defaults");
            assert!(tokens.contains(&"use_pty"));
            assert!(tokens.iter().any(|token| token.starts_with("secure_path=")));
        }
    }
}
