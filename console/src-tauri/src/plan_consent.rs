//! The session that carries one plan to the native window and brings back one
//! answer.
//!
//! It is deliberately the same shape as the bootstrap session: one request at a
//! time, named by an identifier the frontend never chooses, bounded by a
//! deadline this side owns, and readable only by naming that identifier. What
//! differs is what travels — a consent rather than a scope — and what comes
//! back: an answer about two digests rather than a proof of access.
//!
//! **Nothing here decides anything about a plan.** The session holds the
//! consent it sent so that the answer can be held against it, and hands both to
//! `publication_plan`, which owns the grammar. A session that judged would be a
//! second place where "this answer is about this pair" is decided, and the two
//! would drift.

use std::time::{Duration, Instant};

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use your_cloud_bootstrap_protocol::{ApprovalConsentV1, MAX_ASSISTANT_REMAINING_MILLIS};

/// How long a human is given to read one plan and answer.
///
/// It is the ceiling the helper's own watchdog enforces, taken from the
/// protocol rather than chosen here, so the window and the process that hosts
/// it cannot disagree about when the session ended. A shorter figure would be a
/// second deadline to keep in step; a longer one would be a lease the watchdog
/// would cut without the Console knowing why.
const CONSENT_LIFETIME: Duration = Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanConsentError {
    /// No plan is being considered, so there is nothing to open a window on.
    NoPlan,
    /// A window is already open, or the identifier names no open session.
    RequestRefused,
    /// The session outlived the time it was given.
    Expired,
    Unavailable,
}

impl PlanConsentError {
    pub fn public_code(self) -> &'static str {
        match self {
            Self::NoPlan => "plan_absent",
            Self::RequestRefused => "plan_consent_request_refused",
            Self::Expired => "plan_consent_expired",
            Self::Unavailable => "plan_consent_unavailable",
        }
    }
}

/// What the frontend reads of an open session: which request it is, and how
/// long is left. It carries no digest and no sentence — those were shown by the
/// window, and repeating them here would be a second place they could differ
/// from what was displayed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanConsentSessionView {
    pub schema_version: u8,
    pub request_id: String,
    pub remaining_millis: u64,
    /// `open` while the window is up, `answered` once it closed with a decision
    /// this Console has held against the pair.
    pub state: &'static str,
    /// Filled only once the session is answered: whether the human confirmed.
    /// A refusal is a refusal whatever ended the window — the button, the close
    /// box, the deadline or a cancellation — because none of them is a consent.
    pub confirmed: bool,
}

struct PlanConsentSession {
    request_id: String,
    consent: ApprovalConsentV1,
    expires_at: Instant,
    answered: Option<bool>,
}

#[derive(Default)]
pub struct PlanConsentState {
    active: Option<PlanConsentSession>,
}

impl PlanConsentState {
    /// Opens a session for one consent, and refuses a second.
    ///
    /// The identifier is drawn here rather than accepted from the caller: a
    /// frontend that named its own request could name one it had already seen
    /// the answer to.
    pub fn start(
        &mut self,
        mut build: impl FnMut(&str, u64) -> Option<ApprovalConsentV1>,
    ) -> Result<(PlanConsentSessionView, ApprovalConsentV1, Instant), PlanConsentError> {
        let now = Instant::now();
        self.clear_if_expired(now);
        if self.active.is_some() {
            return Err(PlanConsentError::RequestRefused);
        }
        let request_id = random_request_id().ok_or(PlanConsentError::Unavailable)?;
        let expires_at = now
            .checked_add(CONSENT_LIFETIME)
            .ok_or(PlanConsentError::Unavailable)?;
        let remaining = u64::try_from(CONSENT_LIFETIME.as_millis())
            .map_err(|_| PlanConsentError::Unavailable)?;
        let consent = build(&request_id, remaining).ok_or(PlanConsentError::NoPlan)?;
        self.active = Some(PlanConsentSession {
            request_id: request_id.clone(),
            consent: consent.clone(),
            expires_at,
            answered: None,
        });
        let view = self.view(now)?;
        Ok((view, consent, expires_at))
    }

    /// The consent this session sent, so an answer can be held against the very
    /// document the window was opened on rather than against a rebuilt one.
    pub fn consent(&mut self, request_id: &str) -> Result<ApprovalConsentV1, PlanConsentError> {
        let now = Instant::now();
        self.require_active(request_id, now)?;
        Ok(self
            .active
            .as_ref()
            .expect("active session checked above")
            .consent
            .clone())
    }

    pub fn status(&mut self, request_id: &str) -> Result<PlanConsentSessionView, PlanConsentError> {
        let now = Instant::now();
        self.require_active(request_id, now)?;
        self.view(now)
    }

    /// Records what the window answered, once and never twice: a session that
    /// already holds its answer is not a session a second answer may reach.
    pub fn answer(
        &mut self,
        request_id: &str,
        confirmed: bool,
    ) -> Result<PlanConsentSessionView, PlanConsentError> {
        let now = Instant::now();
        self.require_active(request_id, now)?;
        let session = self.active.as_mut().expect("active session checked above");
        if session.answered.is_some() {
            return Err(PlanConsentError::RequestRefused);
        }
        session.answered = Some(confirmed);
        self.view(now)
    }

    /// Whether this session was answered by a confirmation, for the one caller
    /// entitled to act on it.
    pub fn confirmed(&self, request_id: &str) -> bool {
        self.active.as_ref().is_some_and(|session| {
            session.request_id == request_id && session.answered == Some(true)
        })
    }

    pub fn cancel(&mut self, request_id: &str) -> Result<(), PlanConsentError> {
        let now = Instant::now();
        self.require_active(request_id, now)?;
        self.active = None;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.active = None;
    }

    fn require_active(&mut self, request_id: &str, now: Instant) -> Result<(), PlanConsentError> {
        self.clear_if_expired(now);
        match self.active.as_ref() {
            Some(session) if session.request_id == request_id => Ok(()),
            Some(_) | None => Err(PlanConsentError::RequestRefused),
        }
    }

    fn view(&self, now: Instant) -> Result<PlanConsentSessionView, PlanConsentError> {
        let session = self.active.as_ref().ok_or(PlanConsentError::Expired)?;
        let remaining = session.expires_at.saturating_duration_since(now);
        Ok(PlanConsentSessionView {
            schema_version: 1,
            request_id: session.request_id.clone(),
            remaining_millis: u64::try_from(remaining.as_millis())
                .map_err(|_| PlanConsentError::Unavailable)?,
            state: if session.answered.is_some() {
                "answered"
            } else {
                "open"
            },
            confirmed: session.answered == Some(true),
        })
    }

    fn clear_if_expired(&mut self, now: Instant) {
        if self
            .active
            .as_ref()
            .is_some_and(|session| now >= session.expires_at)
        {
            self.active = None;
        }
    }
}

/// Sixteen random bytes, hexadecimal, the same shape the bootstrap session
/// draws. It is drawn from the operating system: a request identifier a caller
/// could predict would be a request a caller could claim.
fn random_request_id() -> Option<String> {
    let mut bytes = [0_u8; 16];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use your_cloud_bootstrap_protocol::ApprovalOperation;

    fn consent_for(request_id: &str, remaining: u64) -> Option<ApprovalConsentV1> {
        let plan = "a".repeat(64);
        let rollback = "b".repeat(64);
        Some(ApprovalConsentV1 {
            schema_version: 1,
            request_id: request_id.to_owned(),
            infrastructure_id: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2".into(),
            machine_id: "lab-machine-1".into(),
            operation: ApprovalOperation::DeployOciProbe,
            confirmation_lines: vec![
                "Machine : lab-machine-1".to_owned(),
                format!("Empreinte du plan : {plan}"),
                format!("Empreinte du rollback : {rollback}"),
            ],
            plan_sha256: plan,
            rollback_sha256: rollback,
            issued_at_monotonic_nanos: 1,
            remaining_millis: remaining,
        })
    }

    #[test]
    fn one_window_at_a_time_and_the_identifier_is_never_the_callers() {
        let mut state = PlanConsentState::default();
        let (view, consent, _) = state.start(consent_for).expect("a first session");
        assert_eq!(view.state, "open");
        assert!(!view.confirmed);
        assert_eq!(view.request_id.len(), 32);
        assert_eq!(consent.request_id, view.request_id);

        // A second window is refused while the first is open.
        assert_eq!(
            state.start(consent_for).map(|_| ()),
            Err(PlanConsentError::RequestRefused)
        );
        // And an identifier that names no session reads nothing.
        assert_eq!(
            state.status("00000000000000000000000000000000"),
            Err(PlanConsentError::RequestRefused)
        );
    }

    #[test]
    fn an_answer_is_recorded_once_and_a_refusal_is_a_refusal() {
        let mut state = PlanConsentState::default();
        let (view, _, _) = state.start(consent_for).expect("a session");
        let answered = state.answer(&view.request_id, true).expect("one answer");
        assert_eq!(answered.state, "answered");
        assert!(answered.confirmed);
        assert!(state.confirmed(&view.request_id));

        // Never twice: a session holding its answer is not one a second may
        // reach.
        assert_eq!(
            state.answer(&view.request_id, true),
            Err(PlanConsentError::RequestRefused)
        );

        let mut refused = PlanConsentState::default();
        let (view, _, _) = refused.start(consent_for).expect("a session");
        let answered = refused.answer(&view.request_id, false).expect("one answer");
        assert!(!answered.confirmed);
        assert!(!refused.confirmed(&view.request_id));
    }

    #[test]
    fn a_cancelled_session_leaves_nothing_behind() {
        let mut state = PlanConsentState::default();
        let (view, _, _) = state.start(consent_for).expect("a session");
        state.cancel(&view.request_id).expect("a cancellation");
        assert_eq!(
            state.status(&view.request_id),
            Err(PlanConsentError::RequestRefused)
        );
        assert!(!state.confirmed(&view.request_id));
        // And the seat is free again.
        assert!(state.start(consent_for).is_ok());
    }

    #[test]
    fn a_session_without_a_plan_opens_nothing() {
        let mut state = PlanConsentState::default();
        assert_eq!(
            state.start(|_, _| None).map(|_| ()),
            Err(PlanConsentError::NoPlan)
        );
        // The seat was not taken by the attempt.
        assert!(state.start(consent_for).is_ok());
    }
}
