//! The window a human reads before an approval is signed.
//!
//! It is a separate window of a separate process for one reason: the App
//! renders through a WebView whose paint surface this product does not treat as
//! trustworthy, and what a human accepts must be drawn by something that
//! surface cannot reach. What crosses into it is the consent document — the
//! sentences the App core derived from two documents it had already held
//! against their own digests, beside the two digests themselves. The pair never
//! crosses.
//!
//! **This window is not a second verifier, and it says so by what it cannot
//! do.** It holds no plan grammar, no key and no network. It renders sentences
//! and returns one closed answer. Making it verify would mean two derivations
//! of the same sentences, and every divergence between them would be a window
//! showing something other than what gets signed.
//!
//! **Every sentence is shown whole.** Each is folded to the width this product
//! already folds at, and the document was refused before it arrived if the
//! folded total passed [`MAX_APPROVAL_CONSENT_FOLDED_LINES`]: a window nobody
//! can see the bottom of is a window nobody read. Nothing here truncates, and
//! nothing here scrolls.
//!
//! **The last two sentences are the two digests**, and the answer carries those
//! same two values. That is what makes the echo mean something: what returns is
//! what the human had in front of him on the last two lines he read.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use gtk::{
    glib::{self, ControlFlow},
    prelude::*,
    Dialog, DialogFlags, Label, ResponseType,
};
use your_cloud_bootstrap_protocol::{
    ApprovalConsentOutcomeKind, ApprovalConsentOutcomeV1, ApprovalConsentV1,
    APPROVAL_CONSENT_FOLD_COLUMNS,
};

use crate::lease::LeaseState;

const TIMER_INTERVAL: Duration = Duration::from_millis(25);
const EXPIRED_RESPONSE_ID: u16 = 1_000;
const LEASE_CANCELLED_RESPONSE_ID: u16 = 1_001;
const PROTOCOL_INVALID_RESPONSE_ID: u16 = 1_002;

/// Opens the window and returns the one answer it produced.
///
/// The answer is built here rather than by the caller so that the coupling the
/// document requires — a confirmation names the pair, a refusal names nothing —
/// exists in one place and cannot be assembled differently elsewhere.
pub(crate) fn ask(
    consent: &ApprovalConsentV1,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
) -> ApprovalConsentOutcomeV1 {
    // The document is held against its own grammar before a pixel exists. A
    // consent this window would have to interpret to display is a consent it
    // refuses to display at all, and it says `unavailable` rather than showing
    // a human something it could not itself read.
    let Ok(validated) = consent.clone().validate() else {
        return refusal(consent, ApprovalConsentOutcomeKind::Unavailable);
    };
    if validated != *consent || lease.is_protocol_invalid() || gtk::init().is_err() {
        return refusal(consent, ApprovalConsentOutcomeKind::Unavailable);
    }
    if lease.is_cancelled() {
        return refusal(consent, ApprovalConsentOutcomeKind::Cancelled);
    }
    if expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
        return refusal(consent, ApprovalConsentOutcomeKind::Expired);
    }

    let dialog = Dialog::with_buttons::<gtk::Window>(
        Some("Approuver cette opération"),
        None,
        DialogFlags::MODAL,
        &[
            ("_Refuser", ResponseType::Reject),
            ("_Approuver et signer", ResponseType::Accept),
        ],
    );
    // Refusal is the default: a window closed by a stray key press has refused,
    // never approved.
    dialog.set_default_response(ResponseType::Reject);
    dialog.set_resizable(false);

    let content = dialog.content_area();
    content.set_spacing(8);
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);
    for line in folded_lines(&consent.confirmation_lines) {
        let label = Label::new(Some(&line));
        label.set_xalign(0.0);
        // Selectable so a human can copy what he is reading, never editable:
        // nothing typed here changes a byte of what gets signed.
        label.set_selectable(true);
        content.pack_start(&label, false, false, 0);
    }

    let countdown = Label::new(Some(&countdown_text(deadline)));
    countdown.set_xalign(0.0);
    content.pack_start(&countdown, false, false, 0);

    let timer_dialog = dialog.clone();
    let timer_countdown = countdown.clone();
    let timer_expired = Arc::clone(&expired);
    let timer_lease = lease.clone();
    let timer = glib::source::timeout_add_local(TIMER_INTERVAL, move || {
        if timer_lease.is_protocol_invalid() {
            timer_dialog.response(ResponseType::Other(PROTOCOL_INVALID_RESPONSE_ID));
            return ControlFlow::Break;
        }
        if timer_expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
            timer_dialog.response(ResponseType::Other(EXPIRED_RESPONSE_ID));
            return ControlFlow::Break;
        }
        if timer_lease.is_cancelled() {
            timer_dialog.response(ResponseType::Other(LEASE_CANCELLED_RESPONSE_ID));
            return ControlFlow::Break;
        }
        timer_countdown.set_text(&countdown_text(deadline));
        ControlFlow::Continue
    });

    dialog.show_all();
    let response = dialog.run();
    timer.remove();
    unsafe { dialog.destroy() };
    while gtk::events_pending() {
        gtk::main_iteration_do(false);
    }

    match response {
        ResponseType::Accept => consent.confirmed(),
        ResponseType::Other(PROTOCOL_INVALID_RESPONSE_ID) => {
            refusal(consent, ApprovalConsentOutcomeKind::Unavailable)
        }
        ResponseType::Other(EXPIRED_RESPONSE_ID) => {
            refusal(consent, ApprovalConsentOutcomeKind::Expired)
        }
        ResponseType::Other(LEASE_CANCELLED_RESPONSE_ID) => {
            refusal(consent, ApprovalConsentOutcomeKind::Cancelled)
        }
        // Everything else a window can end with — the refusal button, the close
        // button, the window manager, a delete event — is a refusal. There is no
        // path out of this function that approves without the acceptance
        // response, and that is the property rather than the enumeration.
        _ => refusal(consent, ApprovalConsentOutcomeKind::Refused),
    }
}

/// Every answer that is not a confirmation, built in one place so that none of
/// them can accidentally name a pair.
fn refusal(
    consent: &ApprovalConsentV1,
    kind: ApprovalConsentOutcomeKind,
) -> ApprovalConsentOutcomeV1 {
    ApprovalConsentOutcomeV1::without_confirmation(&consent.request_id, kind)
}

/// Folds each sentence to the product's own display width.
///
/// The width is the one constant the bootstrap window already folds at, taken
/// from the protocol crate rather than repeated here, so the bound that refused
/// an oversized document and the drawing that lays it out can never fold
/// differently. Nothing is dropped: a sentence longer than the width becomes
/// several lines, never a shorter sentence.
fn folded_lines(sentences: &[String]) -> Vec<String> {
    let mut folded = Vec::new();
    for sentence in sentences {
        let mut chunk = String::new();
        let mut characters = 0;
        for character in sentence.chars() {
            if characters == APPROVAL_CONSENT_FOLD_COLUMNS {
                folded.push(std::mem::take(&mut chunk));
                characters = 0;
            }
            chunk.push(character);
            characters += 1;
        }
        folded.push(chunk);
    }
    folded
}

fn countdown_text(deadline: Instant) -> String {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let seconds = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0));
    format!("Cette demande expire dans {seconds} s.")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";

    /// Folding never loses a character and never merges two sentences: what is
    /// laid out is exactly what was carried, cut only at the width.
    #[test]
    fn folding_shows_every_sentence_whole() {
        let sentences = vec![
            "Machine : lab-machine-1".to_owned(),
            "é".repeat(APPROVAL_CONSENT_FOLD_COLUMNS * 2 + 1),
            "Empreinte du plan : ".to_owned() + &"a".repeat(64),
        ];
        let folded = folded_lines(&sentences);
        assert_eq!(folded.concat(), sentences.concat());
        assert!(folded.len() > sentences.len());
        for line in &folded {
            assert!(line.chars().count() <= APPROVAL_CONSENT_FOLD_COLUMNS);
        }
    }

    /// A sentence exactly at the width stays one line, and an empty set folds
    /// to nothing rather than to one empty line.
    #[test]
    fn folding_adds_no_line_of_its_own() {
        assert_eq!(
            folded_lines(&["a".repeat(APPROVAL_CONSENT_FOLD_COLUMNS)]).len(),
            1
        );
        assert!(folded_lines(&[]).is_empty());
    }

    /// Every answer that is not a confirmation names no pair, whichever way the
    /// window ended.
    #[test]
    fn no_refusal_of_any_kind_names_a_pair() {
        let consent = ApprovalConsentV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            infrastructure_id: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2".into(),
            machine_id: "lab-machine-1".into(),
            operation: your_cloud_bootstrap_protocol::ApprovalOperation::DeployOciProbe,
            plan_sha256: "a".repeat(64),
            rollback_sha256: "b".repeat(64),
            confirmation_lines: vec![
                "Machine : lab-machine-1".to_owned(),
                "Empreinte du plan : ".to_owned() + &"a".repeat(64),
                "Empreinte du rollback : ".to_owned() + &"b".repeat(64),
            ],
            issued_at_monotonic_nanos: 1,
            remaining_millis: 120_000,
        };
        for kind in [
            ApprovalConsentOutcomeKind::Refused,
            ApprovalConsentOutcomeKind::Cancelled,
            ApprovalConsentOutcomeKind::Expired,
            ApprovalConsentOutcomeKind::Unavailable,
        ] {
            let answer = refusal(&consent, kind);
            let rendered = serde_json::to_string(&answer).unwrap();
            assert!(!rendered.contains(&consent.plan_sha256));
            assert!(!rendered.contains(&consent.rollback_sha256));
            assert!(answer.clone().validate().is_ok());
        }
        // And a confirmation cannot travel without naming it.
        let confirmed = consent.confirmed();
        let rendered = serde_json::to_string(&confirmed).unwrap();
        assert!(rendered.contains(&consent.plan_sha256));
        assert!(rendered.contains(&consent.rollback_sha256));
    }
}
