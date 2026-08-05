//! A Controller identifier that is new, and an infrastructure identifier that
//! is kept only when independent states agree it is the same infrastructure.
//!
//! The two identifiers are not symmetric and this module exists because they
//! are constantly treated as if they were.
//!
//! **The `controller_id` must be new, always.** It names the authority, and the
//! authority is exactly what is being taken away from the old host. Reusing the
//! identifier would mean that every leaf, manifest and pin that authorised the
//! old Controller keeps authorising the new one — which is the same thing as
//! never having replaced anything. [`succeed`] refuses the old identifier, and
//! refuses any identifier the infrastructure has already seen.
//!
//! **The `infrastructure_id` must be *kept*, but only after concordance.** It
//! names the estate, not the authority, and minting a new one would orphan every
//! enrolled machine, every Daemon certificate and the whole ingestion registry —
//! which the architecture explicitly refuses to do without cause. But keeping it
//! on the old Controller's own word would let a host that is being replaced
//! decide what it is being replaced into. So it is kept only when independent
//! states, none of which is the old Controller, all say the same thing.
//!
//! **Independence is checked, not assumed.** [`concord`] refuses a state whose
//! source is the old Controller or the suspect host, refuses the same source
//! twice, and refuses a set smaller than [`REQUIRED_INDEPENDENT_STATES`]. One
//! state is not a concordance; it is a copy of one opinion.

use crate::installation::association::MAX_IDENTIFIER_BYTES;
use crate::replacement::incident::QualifiedIncident;

/// Independent states that must agree before the infrastructure identifier is
/// carried over.
///
/// Two, for the same reason the incident needs two vantages: one state is one
/// opinion, and the whole question here is whether several things that were
/// never the old Controller believe the same thing.
pub const REQUIRED_INDEPENDENT_STATES: usize = 2;

/// One place that remembers which infrastructure it belongs to, and what it
/// remembers.
///
/// The sources this palier reads are the enrolled machines — whose approval
/// anchor carries the infrastructure — and the Relay, whose reader manifest
/// carries it too. Neither of them was ever written by the Controller being
/// replaced, which is the entire reason they may be asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependentState {
    /// The machine or the Relay this was read from.
    pub source: String,
    /// What it says, or nothing when it could not be read. An unreadable state
    /// is not a state that agrees.
    pub infrastructure_id: Option<String>,
}

/// Why the infrastructure identifier could not be carried over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuityRefusal {
    /// Fewer independent states than [`REQUIRED_INDEPENDENT_STATES`].
    TooFewIndependentStates { count: usize },
    /// A state read from the very Controller being replaced, or from its host.
    /// It is not independent of the thing it is supposed to corroborate.
    SourceIsNotIndependent { source: String },
    /// The same source twice.
    DuplicateSource { source: String },
    /// A source that could not be read. It is refused rather than skipped: a
    /// concordance of "the two that answered" is a concordance of a subset
    /// somebody chose.
    Unreadable { source: String },
    /// Two sources name two infrastructures. The estate does not have one
    /// identity, so nothing is carried over.
    Divergent {
        source: String,
        announced: String,
        other: String,
    },
    /// An identifier this module does not read.
    MalformedIdentifier { source: String },
}

/// The proof that every independent state names one and the same
/// infrastructure.
///
/// It cannot be built by naming its fields and [`concord`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuity {
    infrastructure_id: String,
    sources: Vec<String>,
}

impl Continuity {
    pub fn infrastructure_id(&self) -> &str {
        &self.infrastructure_id
    }

    /// The states that agreed, named, so a report says who was asked rather
    /// than how many were.
    pub fn sources(&self) -> &[String] {
        &self.sources
    }
}

/// The one gate. Nothing else in this crate builds a [`Continuity`].
///
/// The incident is a parameter rather than two strings so that "independent of
/// the old Controller" and "independent of the suspect host" are read off the
/// one qualified statement instead of being passed again — and possibly
/// differently — by every call site.
pub fn concord(
    incident: &QualifiedIncident,
    states: &[IndependentState],
) -> Result<Continuity, ContinuityRefusal> {
    let mut seen: Vec<String> = Vec::with_capacity(states.len());
    let mut agreed: Option<String> = None;
    for state in states {
        if state.source == incident.old_controller_id() || state.source == incident.suspect_host() {
            return Err(ContinuityRefusal::SourceIsNotIndependent {
                source: state.source.clone(),
            });
        }
        if seen.contains(&state.source) {
            return Err(ContinuityRefusal::DuplicateSource {
                source: state.source.clone(),
            });
        }
        let Some(announced) = state.infrastructure_id.clone() else {
            return Err(ContinuityRefusal::Unreadable {
                source: state.source.clone(),
            });
        };
        if !is_identifier(&announced) {
            return Err(ContinuityRefusal::MalformedIdentifier {
                source: state.source.clone(),
            });
        }
        match &agreed {
            None => agreed = Some(announced),
            Some(other) if other != &announced => {
                return Err(ContinuityRefusal::Divergent {
                    source: state.source.clone(),
                    announced,
                    other: other.clone(),
                })
            }
            Some(_) => {}
        }
        seen.push(state.source.clone());
    }
    if seen.len() < REQUIRED_INDEPENDENT_STATES {
        return Err(ContinuityRefusal::TooFewIndependentStates { count: seen.len() });
    }
    Ok(Continuity {
        infrastructure_id: agreed.expect("a non-empty agreed set carries a value"),
        sources: seen,
    })
}

/// Why no succession was established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuccessionRefusal {
    /// An identifier this module does not read.
    MalformedIdentifier { field: &'static str },
    /// The new Controller is the old one. Whatever else changed, the authority
    /// did not.
    ControllerIdIsNotFresh,
    /// The new Controller carries an identifier this infrastructure has already
    /// used. A retired authority's identifier is not a free name: every pin
    /// that ever authorised it would authorise this one.
    ControllerIdAlreadyUsed { controller_id: String },
}

/// One Controller succeeding another, for one infrastructure.
///
/// It cannot be built by naming its fields and [`succeed`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Succession {
    infrastructure_id: String,
    controller_id: String,
    old_controller_id: String,
}

impl Succession {
    /// The infrastructure, carried over from the [`Continuity`] rather than
    /// from an argument: it is kept because the estate agreed, not because a
    /// caller said so.
    pub fn infrastructure_id(&self) -> &str {
        &self.infrastructure_id
    }

    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    pub fn old_controller_id(&self) -> &str {
        &self.old_controller_id
    }
}

/// The one gate. Nothing else in this crate builds a [`Succession`].
///
/// `already_used` is every `controller_id` this infrastructure has ever bound,
/// the old one included; the caller keeps it in the Console's own archive. It is
/// asked for by parameter rather than derived so that a Console which lost its
/// archive has to say so instead of silently accepting any identifier.
pub fn succeed(
    incident: &QualifiedIncident,
    continuity: &Continuity,
    new_controller_id: &str,
    already_used: &[String],
) -> Result<Succession, SuccessionRefusal> {
    if !is_identifier(new_controller_id) {
        return Err(SuccessionRefusal::MalformedIdentifier {
            field: "controller_id",
        });
    }
    if !is_identifier(continuity.infrastructure_id()) {
        return Err(SuccessionRefusal::MalformedIdentifier {
            field: "infrastructure_id",
        });
    }
    if new_controller_id == incident.old_controller_id() {
        return Err(SuccessionRefusal::ControllerIdIsNotFresh);
    }
    if already_used.iter().any(|used| used == new_controller_id) {
        return Err(SuccessionRefusal::ControllerIdAlreadyUsed {
            controller_id: new_controller_id.to_owned(),
        });
    }
    Ok(Succession {
        infrastructure_id: continuity.infrastructure_id().to_owned(),
        controller_id: new_controller_id.to_owned(),
        old_controller_id: incident.old_controller_id().to_owned(),
    })
}

fn is_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replacement::incident::{
        self, Answer, Isolation, NewHost, Probe, Qualification, Request, REQUIRED_SILENCE_SECONDS,
    };

    const OLD: &str = "controller-old";
    const NEW: &str = "controller-new";
    const INFRASTRUCTURE: &str = "infrastructure-1";
    const SUSPECT: &str = "lab-console";

    fn incident() -> QualifiedIncident {
        let probes = ["lab-machine-1", "lab-relay"].map(|vantage| Probe {
            vantage: vantage.into(),
            answer: Answer::Unreachable,
            continuous_seconds: REQUIRED_SILENCE_SECONDS,
        });
        incident::qualify(
            &Request {
                qualification: Qualification::HardwareLoss,
                old_controller_id: OLD.into(),
                suspect_host: SUSPECT.into(),
                new_host: NewHost::Distinct {
                    endpoint: "lab-machine-1".into(),
                },
                isolation: Isolation::Unverified,
                confirmed: true,
            },
            &probes,
        )
        .expect("the incident fixture must qualify")
    }

    fn state(source: &str, infrastructure: Option<&str>) -> IndependentState {
        IndependentState {
            source: source.into(),
            infrastructure_id: infrastructure.map(str::to_owned),
        }
    }

    fn agreeing() -> Vec<IndependentState> {
        vec![
            state("lab-machine-1", Some(INFRASTRUCTURE)),
            state("lab-relay", Some(INFRASTRUCTURE)),
        ]
    }

    fn continuity() -> Continuity {
        concord(&incident(), &agreeing()).expect("the continuity fixture must concur")
    }

    /// The positive control of both halves: two independent states agree, so
    /// the infrastructure is carried over, and a fresh identifier succeeds.
    #[test]
    fn agreeing_independent_states_carry_the_infrastructure_to_a_fresh_controller() {
        let continuity = continuity();
        assert_eq!(continuity.infrastructure_id(), INFRASTRUCTURE);
        assert_eq!(continuity.sources(), ["lab-machine-1", "lab-relay"]);

        let succession = succeed(&incident(), &continuity, NEW, &[OLD.to_owned()])
            .expect("the positive control must succeed");
        assert_eq!(succession.controller_id(), NEW);
        assert_eq!(succession.old_controller_id(), OLD);
        assert_eq!(succession.infrastructure_id(), INFRASTRUCTURE);
    }

    /// **The identifier is fresh or there is no succession.** Reusing the old
    /// one would leave every pin that authorised the old Controller authorising
    /// the new one.
    #[test]
    fn the_old_controller_identifier_is_never_reused() {
        assert_eq!(
            succeed(&incident(), &continuity(), OLD, &[OLD.to_owned()]),
            Err(SuccessionRefusal::ControllerIdIsNotFresh)
        );
    }

    /// A retired identifier is not a free name either.
    #[test]
    fn an_identifier_this_infrastructure_already_bound_is_refused() {
        assert_eq!(
            succeed(
                &incident(),
                &continuity(),
                "controller-2019",
                &[OLD.to_owned(), "controller-2019".to_owned()],
            ),
            Err(SuccessionRefusal::ControllerIdAlreadyUsed {
                controller_id: "controller-2019".into()
            })
        );
    }

    /// **The infrastructure is kept only after concordance.** Two states naming
    /// two infrastructures carry nothing over, and the refusal names both.
    #[test]
    fn divergent_states_carry_nothing_over() {
        assert_eq!(
            concord(
                &incident(),
                &[
                    state("lab-machine-1", Some(INFRASTRUCTURE)),
                    state("lab-relay", Some("infrastructure-2")),
                ]
            ),
            Err(ContinuityRefusal::Divergent {
                source: "lab-relay".into(),
                announced: "infrastructure-2".into(),
                other: INFRASTRUCTURE.into(),
            })
        );
    }

    /// One state is not a concordance, and neither is none.
    #[test]
    fn a_single_state_or_no_state_at_all_concurs_with_nothing() {
        assert_eq!(
            concord(&incident(), &[state("lab-machine-1", Some(INFRASTRUCTURE))]),
            Err(ContinuityRefusal::TooFewIndependentStates { count: 1 })
        );
        assert_eq!(
            concord(&incident(), &[]),
            Err(ContinuityRefusal::TooFewIndependentStates { count: 0 })
        );
    }

    /// **The thing being replaced does not corroborate its own replacement.**
    /// Neither the old Controller nor the host it lived on is an independent
    /// state, and both are refused by name.
    #[test]
    fn neither_the_old_controller_nor_its_host_is_an_independent_state() {
        for source in [OLD, SUSPECT] {
            assert_eq!(
                concord(
                    &incident(),
                    &[
                        state(source, Some(INFRASTRUCTURE)),
                        state("lab-relay", Some(INFRASTRUCTURE)),
                    ]
                ),
                Err(ContinuityRefusal::SourceIsNotIndependent {
                    source: source.into()
                }),
                "{source} must not corroborate its own replacement"
            );
        }
    }

    /// An unreadable state is refused rather than skipped: a concordance of
    /// whoever answered is a concordance of a subset somebody chose.
    #[test]
    fn an_unreadable_state_denies_the_concordance_instead_of_being_skipped() {
        assert_eq!(
            concord(
                &incident(),
                &[
                    state("lab-machine-1", Some(INFRASTRUCTURE)),
                    state("lab-relay", None),
                    state("lab-machine-2", Some(INFRASTRUCTURE)),
                ]
            ),
            Err(ContinuityRefusal::Unreadable {
                source: "lab-relay".into()
            })
        );
    }

    /// The same source twice would let one opinion count as a concordance.
    #[test]
    fn the_same_source_twice_is_one_opinion_not_two() {
        assert_eq!(
            concord(
                &incident(),
                &[
                    state("lab-machine-1", Some(INFRASTRUCTURE)),
                    state("lab-machine-1", Some(INFRASTRUCTURE)),
                ]
            ),
            Err(ContinuityRefusal::DuplicateSource {
                source: "lab-machine-1".into()
            })
        );
    }

    /// Values that are not identifiers are refused before anything is compared.
    #[test]
    fn a_value_this_module_does_not_read_is_refused_by_name() {
        assert_eq!(
            concord(
                &incident(),
                &[
                    state("lab-machine-1", Some("")),
                    state("lab-relay", Some(INFRASTRUCTURE)),
                ]
            ),
            Err(ContinuityRefusal::MalformedIdentifier {
                source: "lab-machine-1".into()
            })
        );
        assert_eq!(
            succeed(&incident(), &continuity(), "", &[]),
            Err(SuccessionRefusal::MalformedIdentifier {
                field: "controller_id"
            })
        );
        assert_eq!(
            succeed(
                &incident(),
                &continuity(),
                &"c".repeat(MAX_IDENTIFIER_BYTES + 1),
                &[]
            ),
            Err(SuccessionRefusal::MalformedIdentifier {
                field: "controller_id"
            })
        );
    }
}
