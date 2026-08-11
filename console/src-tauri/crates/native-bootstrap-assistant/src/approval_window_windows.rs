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
//! The named debt: `#123` ships the GTK half proven on `lab-console`; the Win32
//! half and its `windows-eval` run remain due before `v0.1.2` can be declared.

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
