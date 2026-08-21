//! What a human is shown before an approval is signed, and what the window
//! answers.
//!
//! An approval binds two digests (`crate::approval`). Nothing in that envelope
//! says a human ever read what those digests cover, and nothing in it could:
//! the App core verifies the pair, but the core renders through a WebView
//! whose paint surface the product does not treat as trustworthy. The consent
//! below is the missing half — the exact document handed to the separate native
//! window, and the exact document that window hands back.
//!
//! Three decisions shape it, and each of them is a decision about *what the
//! window is for* rather than about bytes.
//!
//! **The window renders sentences, not documents.** The pair itself never
//! crosses this frame. What crosses is [`ApprovalConsentV1::confirmation_lines`]
//! — the sentences the App core derived from the two documents it had
//! already verified against their own digests — beside the two digests
//! themselves. The window is a rendering surface the WebView cannot paint on;
//! it is not a second verifier. Making it one would mean carrying the whole
//! plan grammar into a helper whose Cargo graph is deliberately held to a plain
//! GTK or Win32 program, and it would mean two derivations of the same
//! sentences, whose every divergence is a window showing something other than
//! what gets signed. One derivation, in the process that holds the key, is the
//! property. What this frame therefore proves is exactly this, and the product
//! says so rather than implying more: **the human saw and accepted these
//! sentences.** That the sentences describe the pair is proved elsewhere and
//! twice — by the core, which rebuilt both digests from the fields it parsed
//! before any of this existed, and by the Auxiliary, which re-derives them from
//! the bytes it receives before it touches the machine.
//!
//! **A refusal names no pair, and a confirmation cannot travel without one.**
//! [`ApprovalConsentOutcomeV1`] is one closed, flat document whose two digest
//! fields are filled exactly when the outcome confirms; the coupling runs both
//! ways and [`ApprovalConsentOutcomeV1::validate`] refuses either half of it.
//! The App core then holds those two values against the two it computed
//! itself, so a consent collected on one plan can never be presented for
//! another. The shape is flat rather than an enum because serde honours
//! `deny_unknown_fields` on a structure and silently ignores it on an
//! internally tagged enum: a wire enum here would be a document that looks
//! closed and is not.
//!
//! **The last two sentences are the two digests.** [`ApprovalConsentV1::validate`]
//! requires it, without knowing a word of the copy: the last line ends with the
//! rollback digest, the one before it with the plan digest. That is what makes
//! the echo meaningful — the window returns values a human had in front of him
//! on the last two lines he read, rather than values it was handed out of band.
//!
//! There is no signing here and no key. This module turns a validated
//! presentation into a bounded document and back; the App core is the only
//! place that owns a private key.

use crate::{
    approval::{canonical_machine_id, canonical_uuid_v4, decode_digest},
    canonical_request_id, ApprovalOperation, ProtocolError, ASSISTANT_EXIT_ACCESS_VERIFIED,
    ASSISTANT_EXIT_CANCELLED, ASSISTANT_EXIT_REFUSED, ASSISTANT_EXIT_UNAVAILABLE,
    ASSISTANT_EXIT_WATCHDOG_EXPIRED, MAX_ASSISTANT_REMAINING_MILLIS,
};
use serde::{Deserialize, Serialize};

pub const APPROVAL_CONSENT_SCHEMA_VERSION: u8 = 1;

/// Most sentences one consent may carry.
///
/// The widest presentation the product writes today is the private service of
/// schema 2, at sixteen lines: two of heading, eleven of body — profile, image,
/// image digest, local port, origin, persistent volume, three hardening
/// environment lines, the origin variable and the egress confinement — and
/// three of tail. The bound is set above that with room for the paliers still
/// to come, and it is small enough that a window cannot be made to scroll a
/// human past what he is approving.
pub const MAX_APPROVAL_CONSENT_LINES: usize = 24;

/// Longest single sentence, in bytes.
///
/// The widest one the product can write today is the origin of a user service:
/// a host that may reach [`crate::MAX_ROUTE_HOST_BYTES`], inside a sentence that
/// also names [`crate::ORIGIN_HOST_PLACEHOLDER`], which comes to 331 bytes. The
/// bound is that with room to spare, and it is a byte count rather than a
/// character count because it bounds a frame. The test suite of this module
/// rebuilds that widest sentence from the very constants it is formatted from,
/// so a host bound that grew would turn this red rather than produce a plan no
/// window can be opened on.
///
/// It bounds a *logical* sentence. The window wraps each of them to its own
/// display width, as the bootstrap consent window already does, and it owes the
/// human every wrapped line: a window that hid part of one would be a window
/// nobody read.
pub const MAX_APPROVAL_CONSENT_LINE_BYTES: usize = 384;

/// The width the approval window folds a sentence at, in characters.
///
/// It is not a new number: it is the width the bootstrap consent window already
/// folds its own lines at, shipped and measured, and taking a second one would
/// be two windows of the same product disagreeing on what a line is. It is a
/// character count rather than a byte count because folding is a display
/// question, and the copy of this product is accented.
pub const APPROVAL_CONSENT_FOLD_COLUMNS: usize = 72;

/// Most *displayed* lines one consent may reach once folded.
///
/// [`MAX_APPROVAL_CONSENT_LINES`] bounds the number of **logical** sentences,
/// and that is not the number a human scrolls past: twenty-four sentences of
/// 384 bytes would fold into far more than twenty-four lines. What decides
/// whether a window must scroll is the folded count, so that is what is
/// bounded, and it is bounded **here** — a window that refused at the drawing
/// would refuse in front of a human, and one that truncated would show less
/// than what is signed.
///
/// The number is measured rather than chosen. Folded at
/// [`APPROVAL_CONSENT_FOLD_COLUMNS`], the two widest presentations the product
/// writes measure **30** and **25** displayed lines: the private service of
/// schema 2, whose sixteen sentences carry two digests, a long egress sentence
/// and two origins, and the user service, whose origin sentence alone folds into
/// five. Thirty-two is the power of two above that measurement, and the test
/// suite of this module rebuilds both presentations from the very constants they
/// are formatted from, so a host bound or a hardening line that grew turns this
/// red rather than producing a window a human must scroll.
///
/// **The margin is two lines, and that is the decision rather than an
/// oversight.** Adding a sentence to an approval window must be a decision taken
/// against this bound, never a drift discovered in front of a human; a palier
/// that needs a wider presentation must say what it gives up, exactly as the
/// contract already says for the frame. The two bounds bind in different
/// regimes and neither is dead: twenty-four short sentences fold into
/// twenty-four lines and are refused by [`MAX_APPROVAL_CONSENT_LINES`], while
/// sixteen wide ones are refused by this one.
pub const MAX_APPROVAL_CONSENT_FOLDED_LINES: usize = 32;

/// How many displayed lines a set of sentences folds into.
///
/// One sentence is at least one line, even shorter than the width; the count is
/// in characters, and it is the same walk the window performs, kept here so the
/// bound and the drawing cannot fold differently.
pub fn folded_line_count(lines: &[String]) -> usize {
    lines
        .iter()
        .map(|line| {
            let characters = line.chars().count();
            characters.div_ceil(APPROVAL_CONSENT_FOLD_COLUMNS).max(1)
        })
        .sum()
}

/// What one sentence costs in the encoding beyond its own bytes: the two quotes
/// that delimit it and the comma that separates it from the next.
///
/// One byte of sentence costs exactly one encoded byte, and that is a property
/// [`is_refused_display_character`] holds rather than an accident: the two
/// characters the JSON encoding escapes — the quote and the backslash — are
/// refused there, the controls it also escapes are refused with them, and
/// everything else crosses the encoder verbatim.
const APPROVAL_CONSENT_LINE_ENCODING_BYTES: usize = 3;

/// What the consent costs beyond its sentences: the field names, the request
/// identifier, the two identifiers, the operation name, the two digests, the
/// two stamps and the punctuation around them. Rounded up once from the widest
/// each of those can be.
const APPROVAL_CONSENT_FIXED_BYTES: usize = 640;

/// Largest consent frame the native window reads before parsing it.
///
/// It is deliberately *not* [`crate::MAX_ASSISTANT_SCOPE_FRAME_BYTES`]. That
/// bound belongs to the bootstrap scope, which carries a host, an account, a
/// port, a fingerprint and at most eight addresses; raising it to hold a
/// consent would loosen a bound on a document that never needs the room. The
/// two frames carry different documents and each is bounded by what its own
/// fields can reach. This one is derived rather than chosen, so it cannot drift
/// from the fields above, and the test suite of this module serialises a
/// maximal consent against it rather than trusting the arithmetic.
pub const MAX_APPROVAL_CONSENT_FRAME_BYTES: usize = MAX_APPROVAL_CONSENT_LINES
    * (MAX_APPROVAL_CONSENT_LINE_BYTES + APPROVAL_CONSENT_LINE_ENCODING_BYTES)
    + APPROVAL_CONSENT_FIXED_BYTES;

/// Largest outcome frame the App core reads back. The outcome is a version,
/// a request identifier, a closed decision and at most two digests, so this is
/// the size those fields reach, rounded up once.
pub const MAX_APPROVAL_CONSENT_OUTCOME_FRAME_BYTES: usize = 512;

/// What one consent window may ever answer.
///
/// The list is closed and every member names its own exit code below, in the
/// same numbering the bootstrap events use, so the two tables agree on what a
/// code means without either of them restating the other's rows.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalConsentOutcomeKind {
    Confirmed,
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

impl ApprovalConsentOutcomeKind {
    /// The one exit code this outcome may ever be read beside.
    ///
    /// Zero belongs to [`Self::Confirmed`] and to nothing else. The App
    /// core refuses any frame whose code is not the one named here, so a
    /// divergent combination is not a case anybody has to remember to handle:
    /// it has no entry at all.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Confirmed => ASSISTANT_EXIT_ACCESS_VERIFIED,
            Self::Refused => ASSISTANT_EXIT_REFUSED,
            Self::Cancelled => ASSISTANT_EXIT_CANCELLED,
            Self::Expired => ASSISTANT_EXIT_WATCHDOG_EXPIRED,
            Self::Unavailable => ASSISTANT_EXIT_UNAVAILABLE,
        }
    }
}

/// What the window decided, as the App core reads it once the document has
/// been validated.
///
/// This is a view rather than a wire shape, and deliberately so. Serde honours
/// `deny_unknown_fields` on a flat structure and silently ignores it on an
/// internally tagged enum, so an enum on the wire would be a document that
/// looks closed and is not. The document below is therefore flat and closed,
/// and this is what a caller matches on afterwards: the digests exist in the
/// one variant that has any, so a refusal cannot be read as a confirmation of a
/// pair by the code that consumes it either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalConsentDecision {
    Confirmed {
        /// SHA-256 of the plan the last-but-one displayed sentence ended with.
        plan_sha256: String,
        /// SHA-256 of the rollback the last displayed sentence ended with.
        rollback_sha256: String,
    },
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

impl ApprovalConsentDecision {
    pub fn kind(&self) -> ApprovalConsentOutcomeKind {
        match self {
            Self::Confirmed { .. } => ApprovalConsentOutcomeKind::Confirmed,
            Self::Refused => ApprovalConsentOutcomeKind::Refused,
            Self::Cancelled => ApprovalConsentOutcomeKind::Cancelled,
            Self::Expired => ApprovalConsentOutcomeKind::Expired,
            Self::Unavailable => ApprovalConsentOutcomeKind::Unavailable,
        }
    }
}

/// Everything the native consent window is given, and nothing else.
///
/// There is deliberately no plan document, no rollback document and no service
/// definition here. The window renders; it does not verify. What it is given is
/// what a human must read, plus the two values he must be able to compare
/// against what the Auxiliary will later be shown.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConsentV1 {
    pub schema_version: u8,
    /// Correlates this window with the one request the App core opened, and
    /// with the outcome that comes back.
    pub request_id: String,
    /// The infrastructure the association names. It is displayed so a human
    /// with two installations cannot approve inside the wrong one.
    pub infrastructure_id: String,
    /// The one machine the approval will be presented to.
    pub machine_id: String,
    pub operation: ApprovalOperation,
    /// SHA-256 of the plan, lower-case hexadecimal, as the core computed it
    /// from the document it parsed.
    pub plan_sha256: String,
    /// The same, for the rollback of that same plan.
    pub rollback_sha256: String,
    /// The sentences the window renders, in the order it renders them.
    ///
    /// They come from the presentation the App core built out of the two
    /// verified documents. The last two end with the two digests above, which
    /// [`Self::validate`] requires without reading a word of the copy.
    pub confirmation_lines: Vec<String>,
    pub issued_at_monotonic_nanos: u64,
    pub remaining_millis: u64,
}

impl ApprovalConsentV1 {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.schema_version != APPROVAL_CONSENT_SCHEMA_VERSION
            || !canonical_request_id(&self.request_id)
            || !canonical_uuid_v4(&self.infrastructure_id)
            || !canonical_machine_id(&self.machine_id)
            || decode_digest(&self.plan_sha256).is_none()
            || decode_digest(&self.rollback_sha256).is_none()
            || self.plan_sha256 == self.rollback_sha256
            || !(1..=MAX_ASSISTANT_REMAINING_MILLIS).contains(&self.remaining_millis)
            || !valid_confirmation_lines(
                &self.confirmation_lines,
                &self.plan_sha256,
                &self.rollback_sha256,
            )
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The whole document the window writes back when a human accepts these
    /// lines, naming the two digests he had on his last two of them.
    ///
    /// It is built here rather than in the window so that the values echoed
    /// back are, by construction, the ones the consent carried. A window that
    /// answered anything else is answering about another consent, and the
    /// App core refuses it on that ground.
    pub fn confirmed(&self) -> ApprovalConsentOutcomeV1 {
        ApprovalConsentOutcomeV1 {
            schema_version: APPROVAL_CONSENT_SCHEMA_VERSION,
            request_id: self.request_id.clone(),
            outcome: ApprovalConsentOutcomeKind::Confirmed,
            confirmed_plan_sha256: self.plan_sha256.clone(),
            confirmed_rollback_sha256: self.rollback_sha256.clone(),
        }
    }
}

/// The whole document the window writes back, once.
///
/// It is flat and every field is always present, because that is the only
/// shape serde really closes: `deny_unknown_fields` holds here, a missing field
/// is a parse error, and there is no optionality for a transport to exploit.
/// The coupling that matters — digests exactly when the outcome confirms, and
/// never otherwise — is stated by [`Self::validate`] rather than by the
/// encoding, and read back as a typed decision by [`Self::decision`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConsentOutcomeV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub outcome: ApprovalConsentOutcomeKind,
    /// SHA-256 of the plan, lower-case hexadecimal, when the outcome confirms.
    /// Empty on every other outcome, and validation refuses anything else: a
    /// refusal that carried a digest would be a refusal somebody meant to read
    /// as a confirmation.
    pub confirmed_plan_sha256: String,
    /// The same, for the rollback.
    pub confirmed_rollback_sha256: String,
}

impl ApprovalConsentOutcomeV1 {
    /// The document a window writes when it did not confirm.
    ///
    /// The two digest fields are empty here and there is no way to fill them:
    /// the constructor does not take them.
    pub fn without_confirmation(request_id: &str, outcome: ApprovalConsentOutcomeKind) -> Self {
        Self {
            schema_version: APPROVAL_CONSENT_SCHEMA_VERSION,
            request_id: request_id.to_owned(),
            outcome,
            confirmed_plan_sha256: String::new(),
            confirmed_rollback_sha256: String::new(),
        }
    }

    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.schema_version != APPROVAL_CONSENT_SCHEMA_VERSION
            || !canonical_request_id(&self.request_id)
        {
            return Err(ProtocolError::InvalidInput);
        }
        let confirms = self.outcome == ApprovalConsentOutcomeKind::Confirmed;
        let names_a_pair = decode_digest(&self.confirmed_plan_sha256).is_some()
            && decode_digest(&self.confirmed_rollback_sha256).is_some()
            && self.confirmed_plan_sha256 != self.confirmed_rollback_sha256;
        let names_nothing =
            self.confirmed_plan_sha256.is_empty() && self.confirmed_rollback_sha256.is_empty();
        if confirms != names_a_pair || confirms == names_nothing {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The decision this document states, once it has been validated.
    ///
    /// It is `None` on a document that has not been through [`Self::validate`]
    /// and would not survive it, so a caller cannot obtain a `Confirmed`
    /// decision out of a shape the contract refuses.
    pub fn decision(&self) -> Option<ApprovalConsentDecision> {
        if self.clone().validate().is_err() {
            return None;
        }
        Some(match self.outcome {
            ApprovalConsentOutcomeKind::Confirmed => ApprovalConsentDecision::Confirmed {
                plan_sha256: self.confirmed_plan_sha256.clone(),
                rollback_sha256: self.confirmed_rollback_sha256.clone(),
            },
            ApprovalConsentOutcomeKind::Refused => ApprovalConsentDecision::Refused,
            ApprovalConsentOutcomeKind::Cancelled => ApprovalConsentDecision::Cancelled,
            ApprovalConsentOutcomeKind::Expired => ApprovalConsentDecision::Expired,
            ApprovalConsentOutcomeKind::Unavailable => ApprovalConsentDecision::Unavailable,
        })
    }

    /// The one exit code this outcome may be read beside.
    pub fn exit_code(&self) -> u8 {
        self.outcome.exit_code()
    }
}

/// Bounds the sentences, refuses everything that could make a window render
/// something other than what it was given, and holds the last two against the
/// digests they must end with.
///
/// The character refusals are not decoration. A sentence carrying a line break
/// would let a caller add a visual line nobody counted; a sentence carrying a
/// bidirectional override would let it reorder what a human reads without
/// changing a byte of what is signed. Both are refused here, where the document
/// is defined, rather than by whichever toolkit happens to draw it.
fn valid_confirmation_lines(lines: &[String], plan_sha256: &str, rollback_sha256: &str) -> bool {
    // Three is the floor rather than two: the last two sentences are the two
    // digests, so a presentation of exactly two would be a window whose only
    // subject is its own two digests.
    if lines.len() < 3 || lines.len() > MAX_APPROVAL_CONSENT_LINES {
        return false;
    }
    for line in lines {
        if line.is_empty()
            || line.len() > MAX_APPROVAL_CONSENT_LINE_BYTES
            || line.chars().any(is_refused_display_character)
        {
            return false;
        }
    }
    // The second bound, and the one a human actually meets: what the window
    // will display once every sentence is folded to its width. The byte frame
    // bounds what is *read* before parsing; this bounds what is *accepted*, and
    // it is the stricter of the two by construction.
    if folded_line_count(lines) > MAX_APPROVAL_CONSENT_FOLDED_LINES {
        return false;
    }
    let last = &lines[lines.len() - 1];
    let previous = &lines[lines.len() - 2];
    previous.ends_with(plan_sha256) && last.ends_with(rollback_sha256)
}

/// Control characters, the marks that reorder text, the two separators that
/// break a line without being controls, and the two characters the JSON
/// encoding escapes. Everything else a plan sentence is written with — accented
/// letters, typographic quotes, the two guillemets — is left alone, because
/// refusing them would refuse the product's own copy.
fn is_refused_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            // Bidirectional embeddings and overrides.
            '\u{202a}'..='\u{202e}'
            // Bidirectional isolates and the pop that closes them.
            | '\u{2066}'..='\u{2069}'
            // The three invisible marks that flip a run on their own — the
            // Arabic letter mark is the one `is_control` and the ranges above
            // both miss.
            | '\u{200e}' | '\u{200f}' | '\u{061c}'
            // The line and paragraph separators: mandatory breaks that would
            // add a visual line nobody counted, without being controls.
            | '\u{2028}' | '\u{2029}'
            // The two characters the JSON encoding escapes. Refusing them is
            // what keeps the frame bound at one encoded byte per sentence
            // byte, and no sentence of the product ever writes them: its copy
            // quotes with « » and ’.
            | '"' | '\\'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    /// The two digests of the shared probe vector. They are the very ones
    /// `src/probe_plan.rs` displays and `internal/plan/plan_test.go` pins, so a
    /// consent written here is a consent of a pair that really exists.
    const PLAN: &str = "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e";
    const ROLLBACK: &str = "e953fb5f9d8423be61cad4a06d571e200977dd183f53c12d5a897746ad80497a";

    fn lines() -> Vec<String> {
        vec![
            format!("Machine : {MACHINE}"),
            "Opération : déployer la sonde de validation".to_owned(),
            "Image : docker.io/traefik/whoami".to_owned(),
            "Port local : 127.0.0.1:8080".to_owned(),
            "Rollback : retirer la sonde de validation, sur la même machine, la même image et \
             le même port"
                .to_owned(),
            format!("Empreinte du plan : {PLAN}"),
            format!("Empreinte du rollback : {ROLLBACK}"),
        ]
    }

    fn consent() -> ApprovalConsentV1 {
        ApprovalConsentV1 {
            schema_version: APPROVAL_CONSENT_SCHEMA_VERSION,
            request_id: REQUEST_ID.into(),
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: ApprovalOperation::DeployOciProbe,
            plan_sha256: PLAN.into(),
            rollback_sha256: ROLLBACK.into(),
            confirmation_lines: lines(),
            issued_at_monotonic_nanos: 1,
            remaining_millis: MAX_ASSISTANT_REMAINING_MILLIS,
        }
    }

    fn refusal(outcome: ApprovalConsentOutcomeKind) -> ApprovalConsentOutcomeV1 {
        ApprovalConsentOutcomeV1::without_confirmation(REQUEST_ID, outcome)
    }

    #[test]
    fn a_nominal_consent_is_accepted_and_names_its_own_confirmation() {
        let validated = consent().validate().expect("nominal consent");
        let confirmed = validated.confirmed();
        assert_eq!(confirmed.request_id, validated.request_id);
        assert_eq!(
            confirmed.clone().validate().unwrap().decision(),
            Some(ApprovalConsentDecision::Confirmed {
                plan_sha256: PLAN.into(),
                rollback_sha256: ROLLBACK.into(),
            })
        );
        assert_eq!(
            confirmed.decision().unwrap().kind(),
            ApprovalConsentOutcomeKind::Confirmed
        );
    }

    /// The declared ceiling really holds the widest document it bounds.
    ///
    /// The arithmetic above is checked against a serialised maximum rather than
    /// believed: a field added to the consent and forgotten in
    /// `APPROVAL_CONSENT_FIXED_BYTES` fails here rather than producing a frame
    /// the window refuses in the field.
    ///
    /// The document built here is deliberately **not** admissible: twenty-four
    /// sentences at their byte ceiling fold into far more than
    /// [`MAX_APPROVAL_CONSENT_FOLDED_LINES`] displayed lines. That is the whole
    /// distinction between the two bounds — the frame bounds what the window
    /// must be able to *read* before it can parse anything, so a hostile
    /// document of that width has to be readable and then refused, never
    /// unreadable. Both halves are asserted below.
    #[test]
    fn the_declared_frame_ceiling_holds_the_widest_consent() {
        let mut maximal = consent();
        maximal.machine_id = "m".to_owned() + &"a".repeat(62);
        // Every line at its own ceiling, in bytes, with the last two still
        // ending on the two digests the contract requires.
        let filler = "é".repeat((MAX_APPROVAL_CONSENT_LINE_BYTES - 1) / 2);
        let mut widest: Vec<String> = (0..MAX_APPROVAL_CONSENT_LINES - 2)
            .map(|_| filler.clone())
            .collect();
        let padding = "é".repeat((MAX_APPROVAL_CONSENT_LINE_BYTES - PLAN.len() - 1) / 2);
        widest.push(format!("{padding}{PLAN}"));
        widest.push(format!("{padding}{ROLLBACK}"));
        for line in &widest {
            assert!(line.len() <= MAX_APPROVAL_CONSENT_LINE_BYTES);
        }
        maximal.confirmation_lines = widest;

        let encoded = serde_json::to_vec(&maximal).unwrap();
        assert!(
            encoded.len() <= MAX_APPROVAL_CONSENT_FRAME_BYTES,
            "the widest consent is {} bytes, over the declared {MAX_APPROVAL_CONSENT_FRAME_BYTES}",
            encoded.len()
        );
        // Readable, then refused: the frame let it through, the folded bound
        // did not.
        assert!(folded_line_count(&maximal.confirmation_lines) > MAX_APPROVAL_CONSENT_FOLDED_LINES);
        assert!(maximal.validate().is_err());

        assert!(
            serde_json::to_vec(&consent().confirmed()).unwrap().len()
                <= MAX_APPROVAL_CONSENT_OUTCOME_FRAME_BYTES
        );
    }

    /// The folded bound really holds the widest presentations the product
    /// writes, and it is measured rather than believed.
    ///
    /// Both are rebuilt from the very constants they are formatted from — the
    /// route host bound, the origin placeholder, the hardening lines, the data
    /// volume, the egress table — so a constant that grew turns this red rather
    /// than producing a window a human must scroll. What is held is a width,
    /// not a copy: the sentences themselves are pinned where they are written.
    #[test]
    fn the_folded_bound_holds_the_widest_presentations_the_product_writes() {
        let host = "a".repeat(crate::MAX_ROUTE_HOST_BYTES);
        let image = format!("registry.example.test/namespace/service:1.0.0@sha256:{PLAN}");

        // The private service of schema 2: sixteen sentences, the widest
        // presentation of the delivered profiles.
        let mut private_service = vec![
            format!("Machine : {}", "m".repeat(63)),
            "Opération : déployer le service privé".to_owned(),
            "Service : coffre privé".to_owned(),
            format!("Image : {image}"),
            format!("Digest de l’image : sha256:{PLAN}"),
            format!("Port local : {}:65535", crate::SERVICE_LOCAL_ADDRESS),
            format!(
                "Origine : {}://{host}",
                crate::PRIVATE_SERVICE_ORIGIN_SCHEME
            ),
            format!("Volume persistant : {}", crate::PRIVATE_SERVICE_DATA_VOLUME),
        ];
        for hardening in crate::PRIVATE_SERVICE_ENVIRONMENT_HARDENING {
            private_service.push(format!("Ligne d’environnement : {hardening}"));
        }
        private_service.push(format!(
            "Ligne d’environnement : {}={}://{host}",
            crate::PRIVATE_SERVICE_ORIGIN_VARIABLE,
            crate::PRIVATE_SERVICE_ORIGIN_SCHEME
        ));
        private_service.push(format!(
            "Confinement de sortie : table {}, le service ne parle à personne : sortie refusée \
             hors loopback et réponses",
            crate::PRIVATE_SERVICE_EGRESS_TABLE
        ));
        private_service.push(
            "Rollback : retirer le service privé, sur la même machine, la même image et le même \
             port"
                .to_owned(),
        );
        private_service.push(format!("Empreinte du plan : {PLAN}"));
        private_service.push(format!("Empreinte du rollback : {ROLLBACK}"));

        // The user service: fewer sentences, but the widest single one of the
        // product — the origin, which folds into five lines on its own.
        let user_service = vec![
            format!("Machine : {}", "m".repeat(63)),
            "Opération : déployer le service utilisateur".to_owned(),
            format!("Service défini : {}", "s".repeat(32)),
            format!("Révision de la définition : {PLAN}"),
            format!("Image : {image}"),
            format!("Digest de l’image : sha256:{PLAN}"),
            format!("Port local : {}:65535", crate::SERVICE_LOCAL_ADDRESS),
            format!(
                "Origine : {host}, portée par les lignes de la définition qui nomment {}",
                crate::ORIGIN_HOST_PLACEHOLDER
            ),
            "Ce que la révision décide : le compte, le foyer, les volumes, l’environnement et les \
             noms de secrets viennent de la définition gelée sous cette empreinte, et d’aucun \
             champ de ce plan"
                .to_owned(),
            "Rollback : retirer le service utilisateur, sur la même machine et le même slug"
                .to_owned(),
            format!("Empreinte du plan : {PLAN}"),
            format!("Empreinte du rollback : {ROLLBACK}"),
        ];

        for (family, sentences) in [
            ("le service privé", &private_service),
            ("le service utilisateur", &user_service),
        ] {
            assert!(
                sentences.len() <= MAX_APPROVAL_CONSENT_LINES,
                "{family} writes {} sentences, over the declared {MAX_APPROVAL_CONSENT_LINES}",
                sentences.len()
            );
            let folded = folded_line_count(sentences);
            assert!(
                folded <= MAX_APPROVAL_CONSENT_FOLDED_LINES,
                "{family} folds into {folded} lines, over the declared \
                 {MAX_APPROVAL_CONSENT_FOLDED_LINES}"
            );
            // And each is really admissible, rather than merely under a number.
            let mut carried = consent();
            carried.confirmation_lines = sentences.clone();
            assert!(
                carried.validate().is_ok(),
                "{family} is not admissible as a consent"
            );
        }

        // The two measurements, held as numbers so a presentation that grew is
        // read here rather than discovered in front of a human.
        assert_eq!(folded_line_count(&private_service), 30);
        assert_eq!(folded_line_count(&user_service), 25);

        // The bound bites, and it bites on the widest family: one sentence more
        // of the widest kind carries the private service past it, and the
        // document refuses it — not the window.
        let mut overflowing = consent();
        let mut sentences = private_service.clone();
        sentences.insert(
            1,
            format!(
                "Origine : {host}, portée par les lignes de la définition qui nomment {}",
                crate::ORIGIN_HOST_PLACEHOLDER
            ),
        );
        assert!(
            sentences.len() <= MAX_APPROVAL_CONSENT_LINES,
            "the sentence bound is not what refuses it"
        );
        overflowing.confirmation_lines = sentences;
        assert!(overflowing.validate().is_err());
    }

    /// A sentence shorter than the fold width still costs one displayed line,
    /// and the count is in characters rather than bytes — the copy of this
    /// product is accented, and folding is a display question.
    #[test]
    fn folding_counts_characters_and_never_costs_less_than_one_line() {
        assert_eq!(folded_line_count(&["a".to_owned()]), 1);
        assert_eq!(
            folded_line_count(&["a".repeat(APPROVAL_CONSENT_FOLD_COLUMNS)]),
            1
        );
        assert_eq!(
            folded_line_count(&["a".repeat(APPROVAL_CONSENT_FOLD_COLUMNS + 1)]),
            2
        );
        // 72 accented characters are 144 bytes and still one displayed line: a
        // byte count here would have refused a sentence a window renders whole.
        assert_eq!(
            folded_line_count(&["é".repeat(APPROVAL_CONSENT_FOLD_COLUMNS)]),
            1
        );
        assert_eq!(
            folded_line_count(&["a".to_owned(), "b".to_owned()]),
            2,
            "each sentence starts its own line"
        );
    }

    /// The consent frame is its own bound, and a bootstrap scope can never be
    /// given the room this one needs.
    #[test]
    fn the_consent_frame_is_bounded_apart_from_the_bootstrap_scope() {
        assert!(MAX_APPROVAL_CONSENT_FRAME_BYTES > crate::MAX_ASSISTANT_SCOPE_FRAME_BYTES);
        assert!(
            MAX_APPROVAL_CONSENT_OUTCOME_FRAME_BYTES < crate::MAX_ASSISTANT_EVENT_FRAME_BYTES,
            "an outcome says less than a bootstrap event and is bounded to less"
        );
        assert_eq!(MAX_APPROVAL_CONSENT_FRAME_BYTES, 9_928);
    }

    /// The line bound really holds the widest sentence the product writes.
    ///
    /// It is rebuilt here from the two constants the plan module formats it
    /// from, rather than copied as a number: a host bound that grew, or a
    /// placeholder that was renamed to something longer, turns this red instead
    /// of producing a plan on which no window can be opened. The wording is a
    /// width witness rather than a copy assertion — what is held is the length,
    /// and the sentence itself is pinned where it is written.
    #[test]
    fn the_line_bound_holds_the_widest_sentence_the_product_can_write() {
        let host = "a".repeat(crate::MAX_ROUTE_HOST_BYTES);
        let placeholder = crate::ORIGIN_HOST_PLACEHOLDER;
        let widest = format!(
            "Origine : {host}, portée par les lignes de la définition qui nomment {placeholder}"
        );
        assert!(
            widest.len() <= MAX_APPROVAL_CONSENT_LINE_BYTES,
            "the widest sentence is {} bytes, over the declared {MAX_APPROVAL_CONSENT_LINE_BYTES}",
            widest.len()
        );

        // The two runners-up, for the same reason.
        for other in [
            format!("Ligne d’environnement : DOMAIN=https://{host}"),
            format!("Nom publié : {host}"),
        ] {
            assert!(other.len() <= MAX_APPROVAL_CONSENT_LINE_BYTES);
        }

        // And a sentence of that width is really admissible, rather than merely
        // under a number: it goes through the whole validation.
        let mut widened = consent();
        widened.confirmation_lines[0] = widest;
        assert!(widened.validate().is_ok());
    }

    /// The last two sentences are the two digests, and a presentation whose
    /// tail does not say so never reaches a window.
    #[test]
    fn the_last_two_sentences_must_end_with_the_two_digests() {
        for hostile in [
            // The two exchanged: the human would read the rollback where the
            // plan belongs, and confirm a pair the core would then refuse.
            {
                let mut swapped = consent();
                let length = swapped.confirmation_lines.len();
                swapped.confirmation_lines.swap(length - 2, length - 1);
                swapped
            },
            // A tail that names one digest twice.
            {
                let mut duplicated = consent();
                let length = duplicated.confirmation_lines.len();
                duplicated.confirmation_lines[length - 1] =
                    format!("Empreinte du rollback : {PLAN}");
                duplicated
            },
            // A digest line with something appended after it: what the human
            // reads last is no longer the digest.
            {
                let mut trailing = consent();
                let length = trailing.confirmation_lines.len();
                trailing.confirmation_lines[length - 1].push_str(" (approuvé)");
                trailing
            },
            // The tail removed entirely.
            {
                let mut truncated = consent();
                truncated.confirmation_lines.truncate(2);
                truncated
            },
        ] {
            assert_eq!(hostile.validate(), Err(ProtocolError::InvalidInput));
        }
    }

    /// Nothing that could make a window render other than what it was given.
    #[test]
    fn a_sentence_that_could_reorder_or_extend_the_window_is_refused() {
        for hostile in [
            "Machine : lab-machine-1\nOpération : tout autoriser",
            "Machine : lab-machine-1\rOpération : tout autoriser",
            "Machine :\tlab-machine-1",
            "Machine : \u{202e}1-enihcam-bal",
            "Machine : \u{2066}lab-machine-1\u{2069}",
            "Machine : \u{200f}lab-machine-1",
            "Machine : \u{061c}lab-machine-1",
            "Machine : lab\u{2028}machine-1",
            "Machine : lab\u{2029}machine-1",
            "Machine : \"lab-machine-1\"",
            "Machine : lab\\machine-1",
            "Machine : lab-machine-1\u{0}",
        ] {
            let mut invalid = consent();
            invalid.confirmation_lines[0] = hostile.to_owned();
            assert_eq!(
                invalid.validate(),
                Err(ProtocolError::InvalidInput),
                "{hostile:?} must never reach the consent window"
            );
        }

        // The product's own copy is not collateral damage: accents, typographic
        // apostrophes and guillemets stay admissible.
        let mut typographic = consent();
        typographic.confirmation_lines[0] =
            "Opération : « déployer » l’instance approuvée — rien d’autre".to_owned();
        assert!(typographic.validate().is_ok());
    }

    #[test]
    fn a_consent_outside_its_bounds_never_becomes_a_window() {
        let long = "a".repeat(MAX_APPROVAL_CONSENT_LINE_BYTES + 1);
        let mut too_long = consent();
        too_long.confirmation_lines[0] = long;

        let mut too_many = consent();
        let mut overflowing = vec!["Ligne".to_owned(); MAX_APPROVAL_CONSENT_LINES - 1];
        overflowing.push(format!("Empreinte du plan : {PLAN}"));
        overflowing.push(format!("Empreinte du rollback : {ROLLBACK}"));
        too_many.confirmation_lines = overflowing;

        let mut empty_line = consent();
        empty_line.confirmation_lines[0] = String::new();

        for hostile in [
            ApprovalConsentV1 {
                schema_version: 2,
                ..consent()
            },
            ApprovalConsentV1 {
                request_id: "forged".into(),
                ..consent()
            },
            ApprovalConsentV1 {
                request_id: REQUEST_ID.to_ascii_uppercase(),
                ..consent()
            },
            ApprovalConsentV1 {
                infrastructure_id: "8F14E45F-CEEA-4167-A8B1-1F7BD0A0F4C2".into(),
                ..consent()
            },
            ApprovalConsentV1 {
                machine_id: "../../etc/shadow".into(),
                ..consent()
            },
            ApprovalConsentV1 {
                plan_sha256: PLAN.to_ascii_uppercase(),
                ..consent()
            },
            // One pair, two digests: a plan that is its own rollback is not a
            // return path, and the two lines would read the same.
            ApprovalConsentV1 {
                plan_sha256: ROLLBACK.into(),
                confirmation_lines: {
                    let mut same = lines();
                    let length = same.len();
                    same[length - 2] = format!("Empreinte du plan : {ROLLBACK}");
                    same
                },
                ..consent()
            },
            ApprovalConsentV1 {
                remaining_millis: 0,
                ..consent()
            },
            ApprovalConsentV1 {
                remaining_millis: MAX_ASSISTANT_REMAINING_MILLIS + 1,
                ..consent()
            },
            too_long,
            too_many,
            empty_line,
        ] {
            assert_eq!(hostile.validate(), Err(ProtocolError::InvalidInput));
        }
    }

    /// Exactly one outcome carries the successful code, and only that outcome
    /// carries digests.
    #[test]
    fn exactly_one_outcome_confirms_and_only_it_names_a_pair() {
        const REFUSALS: [ApprovalConsentOutcomeKind; 4] = [
            ApprovalConsentOutcomeKind::Refused,
            ApprovalConsentOutcomeKind::Cancelled,
            ApprovalConsentOutcomeKind::Expired,
            ApprovalConsentOutcomeKind::Unavailable,
        ];

        let confirmed = consent().confirmed();
        assert_eq!(confirmed.exit_code(), ASSISTANT_EXIT_ACCESS_VERIFIED);
        assert_eq!(ASSISTANT_EXIT_ACCESS_VERIFIED, 0);
        assert!(confirmed.clone().validate().is_ok());

        let mut codes: Vec<u8> = vec![confirmed.exit_code()];
        for kind in REFUSALS {
            let refused = refusal(kind);
            let code = refused.exit_code();
            assert_ne!(code, 0, "{kind:?} must not share the successful code");
            assert!(!codes.contains(&code), "{kind:?} reuses the code {code}");
            codes.push(code);

            // A refusal names no digest, so it cannot be read as a confirmation
            // of anything — neither on the wire nor by the code that consumes it.
            let rendered = serde_json::to_string(&refused).unwrap();
            assert!(!rendered.contains(PLAN));
            assert!(!rendered.contains(ROLLBACK));
            assert!(matches!(
                refused.decision(),
                Some(
                    ApprovalConsentDecision::Refused
                        | ApprovalConsentDecision::Cancelled
                        | ApprovalConsentDecision::Expired
                        | ApprovalConsentDecision::Unavailable
                )
            ));
            assert!(refused.validate().is_ok());
        }

        // The coupling runs both ways: a confirmation with the digests removed
        // and a refusal with digests added are both outside the contract, and a
        // caller cannot read a decision out of either.
        let mut stripped = consent().confirmed();
        stripped.confirmed_plan_sha256 = String::new();
        stripped.confirmed_rollback_sha256 = String::new();
        assert_eq!(
            stripped.clone().validate(),
            Err(ProtocolError::InvalidInput)
        );
        assert_eq!(stripped.decision(), None);

        let mut dressed = refusal(ApprovalConsentOutcomeKind::Refused);
        dressed.confirmed_plan_sha256 = PLAN.into();
        dressed.confirmed_rollback_sha256 = ROLLBACK.into();
        assert_eq!(dressed.clone().validate(), Err(ProtocolError::InvalidInput));
        assert_eq!(dressed.decision(), None);

        // Half a pair is not a pair either, on either outcome.
        let mut half = refusal(ApprovalConsentOutcomeKind::Cancelled);
        half.confirmed_plan_sha256 = PLAN.into();
        assert_eq!(half.validate(), Err(ProtocolError::InvalidInput));
    }

    #[test]
    fn wire_variants_are_fixed_and_the_documents_are_closed() {
        for (kind, wire_name) in [
            (ApprovalConsentOutcomeKind::Confirmed, "confirmed"),
            (ApprovalConsentOutcomeKind::Refused, "refused"),
            (ApprovalConsentOutcomeKind::Cancelled, "cancelled"),
            (ApprovalConsentOutcomeKind::Expired, "expired"),
            (ApprovalConsentOutcomeKind::Unavailable, "unavailable"),
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::json!(wire_name)
            );
        }

        // The two documents, pinned whole. The window and the App core are
        // built from this module, but the Auxiliary's side of the product is
        // not, so the wire form is written down rather than left to serde's
        // defaults.
        assert_eq!(
            serde_json::to_value(refusal(ApprovalConsentOutcomeKind::Refused)).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "request_id": REQUEST_ID,
                "outcome": "refused",
                "confirmed_plan_sha256": "",
                "confirmed_rollback_sha256": "",
            })
        );
        assert_eq!(
            serde_json::to_value(consent().confirmed()).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "request_id": REQUEST_ID,
                "outcome": "confirmed",
                "confirmed_plan_sha256": PLAN,
                "confirmed_rollback_sha256": ROLLBACK,
            })
        );

        let mut hostile = serde_json::to_value(consent()).unwrap();
        hostile["forged"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<ApprovalConsentV1>(hostile).is_err());

        let mut missing = serde_json::to_value(consent()).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("issued_at_monotonic_nanos");
        assert!(serde_json::from_value::<ApprovalConsentV1>(missing).is_err());

        let mut hostile_outcome =
            serde_json::to_value(refusal(ApprovalConsentOutcomeKind::Refused)).unwrap();
        hostile_outcome["plan_sha256"] = serde_json::json!(PLAN);
        assert!(serde_json::from_value::<ApprovalConsentOutcomeV1>(hostile_outcome).is_err());

        let mut short_outcome =
            serde_json::to_value(refusal(ApprovalConsentOutcomeKind::Refused)).unwrap();
        short_outcome
            .as_object_mut()
            .unwrap()
            .remove("confirmed_plan_sha256");
        assert!(serde_json::from_value::<ApprovalConsentOutcomeV1>(short_outcome).is_err());
    }

    /// An outcome naming a digest that is not one is refused before the App
    /// core ever compares it with what it computed.
    #[test]
    fn a_confirmation_naming_something_other_than_two_digests_is_refused() {
        for (plan_sha256, rollback_sha256) in [
            (PLAN.to_ascii_uppercase(), ROLLBACK.to_owned()),
            (PLAN.to_owned(), String::new()),
            (PLAN.to_owned(), PLAN.to_owned()),
            (format!("{PLAN}00"), ROLLBACK.to_owned()),
        ] {
            assert_eq!(
                ApprovalConsentOutcomeV1 {
                    confirmed_plan_sha256: plan_sha256,
                    confirmed_rollback_sha256: rollback_sha256,
                    ..consent().confirmed()
                }
                .validate(),
                Err(ProtocolError::InvalidInput)
            );
        }

        for hostile in [
            ApprovalConsentOutcomeV1 {
                request_id: "forged".into(),
                ..refusal(ApprovalConsentOutcomeKind::Refused)
            },
            ApprovalConsentOutcomeV1 {
                schema_version: 2,
                ..refusal(ApprovalConsentOutcomeKind::Refused)
            },
        ] {
            assert_eq!(hostile.validate(), Err(ProtocolError::InvalidInput));
        }
    }

    /// Nothing in this module holds, produces or transports key material.
    #[test]
    fn the_consent_surface_carries_no_signature_and_no_key() {
        let rendered = serde_json::to_string(&consent()).unwrap();
        for forbidden in ["signature", "public_key", "seed", "privileges", "sequence"] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} has no place in what a window renders"
            );
        }
    }
}
