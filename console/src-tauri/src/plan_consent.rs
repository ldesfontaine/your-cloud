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

/// Le temps donné à un humain pour lire **un** plan et répondre.
///
/// C'est le plafond que la montre du helper applique elle-même, pris du
/// protocole plutôt que choisi ici, pour que la fenêtre et le processus qui la
/// porte ne puissent pas être en désaccord sur le moment où la session a pris
/// fin. Un chiffre plus court serait une seconde échéance à tenir en phase ;
/// un plus long serait un bail que la montre couperait sans que la Console
/// sache pourquoi.
///
/// **Ce chiffre est provisoire** : `#133` demande qu'il soit fixé par un essai
/// humain chronométré sur la fenêtre réelle — 12 phrases, 942 caractères, deux
/// empreintes de 64 caractères à comparer — et non par un avis. Il est laissé
/// tel quel en attendant cette mesure, parce qu'une durée de vie d'autorité se
/// change avec une justification, jamais pour arrondir un angle.
const DELIBERATION_LIFETIME: Duration = Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS);

/// Le temps qu'une **autorité confirmée** reste inutilisée avant de s'éteindre.
///
/// C'est la seconde échéance, et elle ne mesure pas la même chose que la
/// première. Celle-là borne une lecture humaine ; celle-ci borne l'intervalle
/// entre « un humain a confirmé » et « la signature part », qui ne contient
/// aucun geste humain — le sondage voit `answered` et soumet. Les deux étaient
/// une seule échéance courant depuis l'ouverture, si bien que le temps
/// utilisable après l'approbation était ce qui restait des cinq minutes une
/// fois la délibération faite : imprévisible, et potentiellement quasi nul.
///
/// **Ce chiffre est provisoire lui aussi, et délibérément pas un nombre
/// inventé** : il reprend le plafond du protocole faute de mesure. Ce que ce
/// palier livre est la *forme* — deux échéances distinctes, et une borne qui
/// mord réellement sur la signature. Avant ce changement, rien ne balayait la
/// session après une confirmation et l'autorité confirmée ne s'éteignait
/// **jamais** ; toute valeur finie resserre donc, aucune n'élargit. `#133`
/// reste ouverte jusqu'à ce que la mesure fixe les deux.
const CONFIRMED_AUTHORITY_LIFETIME: Duration =
    Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS);

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

pub struct PlanConsentState {
    active: Option<PlanConsentSession>,
    /// Les deux échéances, portées par l'état plutôt que lues des constantes au
    /// point d'usage. C'est ce qui permet à une suite de **laisser la borne
    /// s'écouler pour de vrai** en quelques dizaines de millisecondes : même
    /// horloge, même code, même chemin, une durée plus courte.
    deliberation: Duration,
    confirmed_authority: Duration,
}

impl Default for PlanConsentState {
    fn default() -> Self {
        Self {
            active: None,
            deliberation: DELIBERATION_LIFETIME,
            confirmed_authority: CONFIRMED_AUTHORITY_LIFETIME,
        }
    }
}

impl PlanConsentState {
    #[cfg(test)]
    fn with_lifetimes(deliberation: Duration, confirmed_authority: Duration) -> Self {
        Self {
            active: None,
            deliberation,
            confirmed_authority,
        }
    }

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
            .checked_add(self.deliberation)
            .ok_or(PlanConsentError::Unavailable)?;
        let remaining = u64::try_from(self.deliberation.as_millis())
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
        let confirmed_authority = self.confirmed_authority;
        let session = self.active.as_mut().expect("active session checked above");
        if session.answered.is_some() {
            return Err(PlanConsentError::RequestRefused);
        }
        session.answered = Some(confirmed);
        // La seconde échéance est armée ici, et seulement par une confirmation :
        // un refus ne porte aucune autorité qu'il faudrait borner. Ce qui court
        // à partir de maintenant n'est plus le temps de lire — il a été pris —
        // mais le temps qu'une autorité confirmée reste inutilisée.
        if confirmed {
            session.expires_at = now
                .checked_add(confirmed_authority)
                .ok_or(PlanConsentError::Unavailable)?;
        }
        self.view(now)
    }

    /// Whether this session was answered by a confirmation **whose authority has
    /// not run out**, for the one caller entitled to act on it.
    ///
    /// Le balayage de l'expiration est ici, et il y est parce qu'il y manquait :
    /// cette lecture était un `&self` sans `clear_if_expired`, et l'expiration
    /// n'était balayée que par `require_active`, qu'appellent `status`,
    /// `consent`, `answer` et `cancel`. Or le sondage du frontend s'arrête dès
    /// l'état `answered` : après une confirmation, plus rien n'appelait
    /// `require_active`, la session n'était jamais balayée, et la signature
    /// aboutissait au-delà de la borne. Une durée de vie d'autorité qui ne
    /// s'applique pas au geste qu'elle est censée borner n'est pas une durée de
    /// vie (`#133`).
    ///
    /// Les deux refus sont distincts parce que la suite ne l'est pas : une
    /// autorité échue se rouvre en relisant le plan et en approuvant de nouveau,
    /// une session qui n'a jamais été confirmée n'a rien à rouvrir.
    pub fn confirmed(&mut self, request_id: &str) -> Result<(), PlanConsentError> {
        let now = Instant::now();
        let expired = self
            .active
            .as_ref()
            .is_some_and(|session| session.request_id == request_id && now >= session.expires_at);
        self.clear_if_expired(now);
        if expired {
            return Err(PlanConsentError::Expired);
        }
        match self.active.as_ref() {
            Some(session) if session.request_id == request_id && session.answered == Some(true) => {
                Ok(())
            }
            Some(_) | None => Err(PlanConsentError::RequestRefused),
        }
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
        assert_eq!(state.confirmed(&view.request_id), Ok(()));

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
        assert_eq!(
            refused.confirmed(&view.request_id),
            Err(PlanConsentError::RequestRefused)
        );
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
        assert_eq!(
            state.confirmed(&view.request_id),
            Err(PlanConsentError::RequestRefused)
        );
        // And the seat is free again.
        assert!(state.start(consent_for).is_ok());
    }

    /// Une session confirmée dont la borne a échu **refuse de signer**, et la
    /// borne s'écoule pour de vrai.
    ///
    /// C'est le cas qu'aucune suite ne tenait : elles exercent une session
    /// confirmée immédiatement après sa réponse, et aucune ne laisse la borne
    /// courir entre la confirmation et la signature. Rien n'est simulé ici —
    /// même horloge, même chemin, seules les deux durées sont courtes, portées
    /// par l'état pour que ce test dure des millisecondes et non cinq minutes.
    #[test]
    fn a_confirmed_authority_stops_signing_once_its_own_deadline_has_run() {
        let deliberation = Duration::from_millis(400);
        let confirmed_authority = Duration::from_millis(60);
        let mut state = PlanConsentState::with_lifetimes(deliberation, confirmed_authority);
        let (view, _, _) = state.start(consent_for).expect("a session");

        // Juste après la confirmation, l'autorité est utilisable.
        state.answer(&view.request_id, true).expect("one answer");
        assert_eq!(state.confirmed(&view.request_id), Ok(()));

        // La seconde échéance est bien une seconde échéance : elle court depuis
        // la confirmation, et non depuis l'ouverture.
        std::thread::sleep(confirmed_authority + Duration::from_millis(40));
        assert_eq!(
            state.confirmed(&view.request_id),
            Err(PlanConsentError::Expired)
        );
        // Et la session est réellement partie, pas seulement jugée échue.
        assert_eq!(
            state.status(&view.request_id),
            Err(PlanConsentError::RequestRefused)
        );
        assert!(state.start(consent_for).is_ok());
    }

    /// La borne de délibération, elle, mord toujours fenêtre ouverte — et le
    /// réarmement ne la prolonge pas tant qu'aucune confirmation n'est venue.
    #[test]
    fn an_unanswered_window_still_expires_on_its_own_deadline() {
        let mut state =
            PlanConsentState::with_lifetimes(Duration::from_millis(60), Duration::from_secs(300));
        let (view, _, _) = state.start(consent_for).expect("a session");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            state.confirmed(&view.request_id),
            Err(PlanConsentError::Expired)
        );
        // Balayée par cette lecture même : la session ne survit pas à son constat.
        assert_eq!(
            state.status(&view.request_id),
            Err(PlanConsentError::RequestRefused)
        );
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
