//! The Windows half of the approval consent window.
//!
//! **It is not written yet, and this file says so rather than pretending.** The
//! Win32 dialog of the bootstrap window is a full custom implementation — a
//! window class, a message loop, its own layout and its own accessibility — and
//! the approval window owes the same. Until it is written and run on a real
//! Windows machine, this arm answers `unavailable`: the Console on Windows can
//! build a plan and read it, and cannot collect a signature.
//!
//! `unavailable` is the honest answer rather than a refusal, because a refusal
//! would say a human declined and no human was ever asked. It is also the one
//! answer that names no pair, so nothing here can be mistaken for a consent.
//!
//! The honest state, and it is written the same way everywhere: **the Console
//! on Windows observes, it does not approve plans yet.**
//!
//! The named debt — the Win32 dialog, its run in the evaluation VM, and the
//! lifting of this `unavailable` — belongs to the Windows catch-up issue, and
//! is deferred past this palier rather than rushed into code nobody could
//! compile or run. `docs/architecture/TRAJET-DE-COMMANDE.md` carries the
//! decision and its reasons.

use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};

use your_cloud_bootstrap_protocol::{
    ApprovalConsentOutcomeKind, ApprovalConsentOutcomeV1, ApprovalConsentV1,
};

use crate::lease::LeaseState;

pub(crate) fn ask(
    consent: &ApprovalConsentV1,
    _deadline: Instant,
    _expired: Arc<AtomicBool>,
    _lease: LeaseState,
) -> ApprovalConsentOutcomeV1 {
    ApprovalConsentOutcomeV1::without_confirmation(
        &consent.request_id,
        ApprovalConsentOutcomeKind::Unavailable,
    )
}
