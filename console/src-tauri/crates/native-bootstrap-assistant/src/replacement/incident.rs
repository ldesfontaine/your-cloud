//! Qualifying the incident, before the word « replacement » may be used.
//!
//! This is the module the whole palier exists to make hard to get past. A
//! Controller that stops answering is not a fact about the Controller: it is a
//! fact about one observer, at one moment, over one network. Turning it into
//! « the Controller is lost » requires more than one observer, more than one
//! moment, and a human who says so.
//!
//! **Nothing here is reached by a timeout.** [`qualify`] takes an explicit
//! [`Request`] with a `confirmed` flag the user sets, and refuses without it by
//! its own name. There is no path from an unavailability to a
//! [`QualifiedIncident`], which is what "no automatic failover" means when it is
//! a property of a signature rather than a promise in a document.
//!
//! **One credible answer stops everything.** [`read`] lets
//! [`Reading::Answering`] dominate every other observation: if a single
//! independent vantage saw the old Controller answer, the fleet does not get
//! replaced, whatever the other vantages think. The asymmetry is deliberate and
//! it is the safe one — overwriting a healthy Controller is unrecoverable, while
//! refusing to replace a dead one costs a second attempt.
//!
//! **The suspect never testifies about itself.** A vantage that *is* the host
//! being replaced is refused: its answers are exactly the answers an adversary
//! holding it would choose. The same rule applies to the isolation, which is why
//! [`Isolation::Verified`] carries the name of who verified it.
//!
//! **A hardware loss and a suspected compromise are different journeys.** They
//! are not a flag on one journey: [`Qualification`] changes what
//! [`qualify`] demands, and it changes the step sequence
//! [`super::plan::ReplacementPlan::steps`] returns. A run cannot drift from one
//! into the other without the refusals of both standing in the way.

/// Independent vantages that must agree before an unavailability may be read as
/// a silence.
///
/// Two is the floor rather than a target: one vantage cannot distinguish "the
/// Controller is down" from "my own link is down", and that single confusion is
/// the whole failure mode this palier is about. It is not raised further because
/// a small infrastructure may genuinely have only two places to look from, and a
/// bound nobody can meet is a bound that gets bypassed.
pub const REQUIRED_INDEPENDENT_VANTAGES: usize = 2;

/// How long every vantage must have been seeing the same silence, in seconds.
///
/// It exists so that a switch cannot be taken on a blip. The value is the order
/// of magnitude of a reboot, a link renegotiation or a DHCP lease — the events
/// that look exactly like a loss for a minute and are not one. A run that has
/// not waited it out has not observed a loss, it has observed a moment.
pub const REQUIRED_SILENCE_SECONDS: u64 = 300;

/// Longest name this module reads for a vantage or an endpoint. Anything longer
/// is not a longer name, it is input this module does not recognise.
pub const MAX_NAME_BYTES: usize = 128;

/// What one attempt on the old Controller produced, from one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The old Controller answered. Whatever else is true, something is serving
    /// its authority.
    Answered,
    /// A definite negative: the host refused the connection, or the network
    /// answered that it is not there.
    Unreachable,
    /// No usable answer — cut, or timed out. It is distinct from
    /// [`Answer::Unreachable`] because "it is not there" and "I do not know" are
    /// different facts, and only the first one says anything.
    NoAnswer,
}

/// One attempt, and where it was made from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    /// The place the attempt was made from. Two probes from the same place are
    /// one observation, not two, and this module says so by name.
    pub vantage: String,
    pub answer: Answer,
    /// How long this vantage has been seeing this same answer, in seconds. It
    /// is carried per vantage rather than globally: a fleet where one machine
    /// has been silent for an hour and another for four seconds has not
    /// observed a silence, it has observed a machine that just lost its link.
    pub continuous_seconds: u64,
}

/// Why the probes could not be read as anything at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ambiguity {
    /// Fewer independent vantages than [`REQUIRED_INDEPENDENT_VANTAGES`].
    TooFewVantages { count: usize },
    /// The same vantage twice. Which of its two answers counted would be
    /// decided by ordering rather than by observation.
    DuplicateVantage { vantage: String },
    /// A vantage that is the very host being replaced. Its answers are the ones
    /// an adversary holding it would choose.
    VantageIsTheSuspectHost { vantage: String },
    /// A name this module does not read.
    MalformedVantage { vantage: String },
    /// One vantage got no usable answer. The fleet does not know, so the fleet
    /// does not act — and the report says which vantage did not know.
    NoAnswerFrom { vantage: String },
    /// The silence is younger than [`REQUIRED_SILENCE_SECONDS`] somewhere.
    SilenceTooYoung { vantage: String, seconds: u64 },
}

/// What the probes, taken together, actually establish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// At least one independent vantage saw the old Controller answer. This
    /// dominates every other observation.
    Answering { vantage: String },
    /// Every independent vantage agreed on a definite negative, for long
    /// enough.
    Silent,
    /// Anything else, with the exact reason.
    Ambiguous(Ambiguity),
}

/// The one function that turns attempts into a fact.
///
/// It is public and total on purpose: a report that says « ambiguous, because
/// `lab-machine-1` gave no answer » is a report a human can act on, whereas a
/// bare refusal is not.
pub fn read(probes: &[Probe], suspect_host: &str) -> Reading {
    // The dominating answer is looked for first, and over the whole set. A
    // Controller that answered one vantage is answering, even if the vantage
    // that saw it is listed last, and even if every other check below would
    // have refused the set for some unrelated reason.
    for probe in probes {
        if probe.answer == Answer::Answered && probe.vantage != suspect_host {
            return Reading::Answering {
                vantage: probe.vantage.clone(),
            };
        }
    }
    let mut seen: Vec<&str> = Vec::with_capacity(probes.len());
    for probe in probes {
        if !is_name(&probe.vantage) {
            return Reading::Ambiguous(Ambiguity::MalformedVantage {
                vantage: probe.vantage.clone(),
            });
        }
        if probe.vantage == suspect_host {
            return Reading::Ambiguous(Ambiguity::VantageIsTheSuspectHost {
                vantage: probe.vantage.clone(),
            });
        }
        if seen.contains(&probe.vantage.as_str()) {
            return Reading::Ambiguous(Ambiguity::DuplicateVantage {
                vantage: probe.vantage.clone(),
            });
        }
        seen.push(&probe.vantage);
        match probe.answer {
            Answer::Answered => unreachable!("an answering vantage returned above"),
            Answer::NoAnswer => {
                return Reading::Ambiguous(Ambiguity::NoAnswerFrom {
                    vantage: probe.vantage.clone(),
                })
            }
            Answer::Unreachable => {
                if probe.continuous_seconds < REQUIRED_SILENCE_SECONDS {
                    return Reading::Ambiguous(Ambiguity::SilenceTooYoung {
                        vantage: probe.vantage.clone(),
                        seconds: probe.continuous_seconds,
                    });
                }
            }
        }
    }
    if seen.len() < REQUIRED_INDEPENDENT_VANTAGES {
        return Reading::Ambiguous(Ambiguity::TooFewVantages { count: seen.len() });
    }
    Reading::Silent
}

/// What the user says happened. It is not a severity and it is not a hint: the
/// two values demand different things and produce different journeys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qualification {
    /// The host is gone — destroyed, stolen as hardware, or its storage is
    /// unrecoverable. Nobody else is holding it.
    HardwareLoss,
    /// Somebody may be holding it. Everything the old Controller could read is
    /// assumed read.
    SuspectedCompromise,
}

impl Qualification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardwareLoss => "hardware-loss",
            Self::SuspectedCompromise => "suspected-compromise",
        }
    }

    /// Whether this qualification may be reached without a verified isolation.
    ///
    /// A hardware loss may: there is no host left to isolate. A suspected
    /// compromise may not, and that difference is the whole point of asking the
    /// user to qualify.
    pub fn requires_isolation(self) -> bool {
        matches!(self, Self::SuspectedCompromise)
    }
}

/// Whether the suspect host has been cut off, and who established it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Isolation {
    /// Cut off, established from somewhere that is not the suspect host — a
    /// switch port that is down, a hypervisor that reports the interface
    /// detached, a physical cable in a hand.
    Verified { by: String },
    /// Not established. It covers "nobody looked" and "the host says it is
    /// isolated" alike, because those are the same amount of evidence.
    Unverified,
}

/// Where the new Controller is going to live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewHost {
    /// A machine that never carried the old Controller.
    Distinct { endpoint: String },
    /// The very host, rebuilt from a trusted base. The architecture allows it
    /// explicitly, for both journeys.
    ReinstalledFromTrustedBase { endpoint: String },
    /// The very host, as it stands. It is a value rather than an absence so
    /// that it can be refused by name.
    SameHostAsItStands { endpoint: String },
}

impl NewHost {
    pub fn endpoint(&self) -> &str {
        match self {
            Self::Distinct { endpoint }
            | Self::ReinstalledFromTrustedBase { endpoint }
            | Self::SameHostAsItStands { endpoint } => endpoint,
        }
    }
}

/// What the user explicitly asked for.
///
/// `confirmed` is not a formality. It is the only way a [`QualifiedIncident`]
/// ever comes into existence, and it is what makes "no automatic failover" a
/// statement about this function rather than about the callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub qualification: Qualification,
    /// The Controller the user is declaring lost, by name. Naming it is what
    /// makes the declaration about one Controller rather than about whatever is
    /// currently failing.
    pub old_controller_id: String,
    /// The host the old Controller lived on.
    pub suspect_host: String,
    pub new_host: NewHost,
    pub isolation: Isolation,
    /// Set by the user, in the Console, on this incident. Nothing else sets it.
    pub confirmed: bool,
}

/// Why no replacement was qualified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IncidentRefusal {
    /// Nobody asked. It is the first refusal and the most important one: an
    /// unavailability, however long and however well observed, arrives here and
    /// stops.
    NotRequestedByTheUser,
    /// A name this module does not read.
    MalformedName { field: &'static str },
    /// The old Controller answered. Whatever the user believes, something is
    /// serving that authority, and it will not be overwritten from here.
    ControllerStillAnswering { vantage: String },
    /// The observations do not establish anything.
    Ambiguous(Ambiguity),
    /// A suspected compromise with no verified isolation. Until the host is cut
    /// off, a new Controller does not restore the authority — it shares it.
    IsolationNotVerified,
    /// The isolation was established by the suspect host itself.
    IsolationVerifiedByTheSuspectHost,
    /// A suspected compromise being reinstalled onto the suspect host as it
    /// stands. The architecture requires a healthy host or one rebuilt from a
    /// trusted base, and "as it stands" is neither.
    SuspectHostIsNotAHealthyHost { endpoint: String },
    /// A hardware loss whose replacement is meant to live on the very host that
    /// was lost, untouched. The two statements cannot both be true.
    LostHostCannotHostTheReplacement { endpoint: String },
}

/// One incident, qualified: the user asked, the observations agreed, and
/// everything this qualification demands is in place.
///
/// It cannot be built by naming its fields and [`qualify`] is the only function
/// that returns one. Holding it is what a caller must be able to show before the
/// replacement has a plan at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedIncident {
    qualification: Qualification,
    old_controller_id: String,
    suspect_host: String,
    new_host: String,
}

impl QualifiedIncident {
    pub fn qualification(&self) -> Qualification {
        self.qualification
    }

    /// The Controller being replaced, taken from the user's declaration rather
    /// than from whatever later answers.
    pub fn old_controller_id(&self) -> &str {
        &self.old_controller_id
    }

    pub fn suspect_host(&self) -> &str {
        &self.suspect_host
    }

    /// The endpoint the new Controller will live on.
    pub fn new_host(&self) -> &str {
        &self.new_host
    }
}

/// The one gate. Nothing else in this crate builds a [`QualifiedIncident`].
///
/// The order of the refusals is itself a decision. The human request is checked
/// first, because a run nobody asked for should not even reveal what the probes
/// saw; the answering Controller is checked before every demand of the
/// qualification, because a live Controller ends the matter regardless of how
/// well the rest of the paperwork is filled in.
pub fn qualify(request: &Request, probes: &[Probe]) -> Result<QualifiedIncident, IncidentRefusal> {
    if !request.confirmed {
        return Err(IncidentRefusal::NotRequestedByTheUser);
    }
    name(&request.old_controller_id, "old_controller_id")?;
    name(&request.suspect_host, "suspect_host")?;
    name(request.new_host.endpoint(), "new_host")?;

    match read(probes, &request.suspect_host) {
        Reading::Answering { vantage } => {
            return Err(IncidentRefusal::ControllerStillAnswering { vantage })
        }
        Reading::Ambiguous(ambiguity) => return Err(IncidentRefusal::Ambiguous(ambiguity)),
        Reading::Silent => {}
    }

    match request.qualification {
        Qualification::SuspectedCompromise => match &request.isolation {
            Isolation::Unverified => return Err(IncidentRefusal::IsolationNotVerified),
            Isolation::Verified { by } => {
                name(by, "isolation")?;
                if by == &request.suspect_host {
                    return Err(IncidentRefusal::IsolationVerifiedByTheSuspectHost);
                }
            }
        },
        Qualification::HardwareLoss => {}
    }

    match (&request.qualification, &request.new_host) {
        (Qualification::SuspectedCompromise, NewHost::SameHostAsItStands { endpoint }) => {
            return Err(IncidentRefusal::SuspectHostIsNotAHealthyHost {
                endpoint: endpoint.clone(),
            })
        }
        (Qualification::HardwareLoss, NewHost::SameHostAsItStands { endpoint }) => {
            return Err(IncidentRefusal::LostHostCannotHostTheReplacement {
                endpoint: endpoint.clone(),
            })
        }
        _ => {}
    }

    Ok(QualifiedIncident {
        qualification: request.qualification,
        old_controller_id: request.old_controller_id.clone(),
        suspect_host: request.suspect_host.clone(),
        new_host: request.new_host.endpoint().to_owned(),
    })
}

fn name(value: &str, field: &'static str) -> Result<(), IncidentRefusal> {
    if is_name(value) {
        return Ok(());
    }
    Err(IncidentRefusal::MalformedName { field })
}

fn is_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_NAME_BYTES
        && !value.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "controller-old";
    const SUSPECT: &str = "lab-console";
    const FRESH: &str = "lab-machine-1";

    fn silent(vantage: &str) -> Probe {
        Probe {
            vantage: vantage.into(),
            answer: Answer::Unreachable,
            continuous_seconds: REQUIRED_SILENCE_SECONDS,
        }
    }

    fn silence() -> Vec<Probe> {
        vec![silent("lab-machine-1"), silent("lab-relay")]
    }

    fn loss() -> Request {
        Request {
            qualification: Qualification::HardwareLoss,
            old_controller_id: OLD.into(),
            suspect_host: SUSPECT.into(),
            new_host: NewHost::Distinct {
                endpoint: FRESH.into(),
            },
            isolation: Isolation::Unverified,
            confirmed: true,
        }
    }

    fn compromise() -> Request {
        Request {
            qualification: Qualification::SuspectedCompromise,
            isolation: Isolation::Verified {
                by: "lab-switch".into(),
            },
            ..loss()
        }
    }

    /// The positive control of the first journey: a confirmed hardware loss,
    /// two independent vantages that have seen the same silence long enough,
    /// and a host that never carried the old Controller.
    #[test]
    fn a_confirmed_hardware_loss_on_an_established_silence_qualifies() {
        let incident = qualify(&loss(), &silence()).expect("the positive control must qualify");

        assert_eq!(incident.qualification(), Qualification::HardwareLoss);
        assert_eq!(incident.old_controller_id(), OLD);
        assert_eq!(incident.suspect_host(), SUSPECT);
        assert_eq!(incident.new_host(), FRESH);
        assert!(!incident.qualification().requires_isolation());
    }

    /// The positive control of the second journey. It differs from the first
    /// one by exactly two things — the qualification and the verified isolation
    /// — and it demands both.
    #[test]
    fn a_confirmed_suspected_compromise_with_a_verified_isolation_qualifies() {
        let incident =
            qualify(&compromise(), &silence()).expect("the positive control must qualify");

        assert_eq!(incident.qualification(), Qualification::SuspectedCompromise);
        assert!(incident.qualification().requires_isolation());
    }

    /// **The refusal the whole palier exists for.** No amount of observed
    /// unavailability produces a replacement: without the user's own request,
    /// the very probes that would otherwise qualify a loss produce nothing.
    #[test]
    fn no_observation_however_conclusive_qualifies_a_replacement_by_itself() {
        let unrequested = Request {
            confirmed: false,
            ..loss()
        };

        assert_eq!(
            qualify(&unrequested, &silence()),
            Err(IncidentRefusal::NotRequestedByTheUser)
        );
        // And the very same probes, with the request, do qualify: the refusal
        // above is about the request and about nothing else.
        assert!(qualify(&loss(), &silence()).is_ok());
    }

    /// **A healthy Controller is never overwritten.** One independent vantage
    /// that saw it answer ends the matter, even when every other vantage has
    /// been seeing silence for longer than the bound, and even when the user
    /// has confirmed.
    #[test]
    fn one_vantage_that_saw_it_answer_denies_the_whole_replacement() {
        let mut probes = silence();
        probes.push(Probe {
            vantage: "lab-relay-2".into(),
            answer: Answer::Answered,
            continuous_seconds: 1,
        });

        assert_eq!(
            qualify(&loss(), &probes),
            Err(IncidentRefusal::ControllerStillAnswering {
                vantage: "lab-relay-2".into()
            })
        );
        // Including on the compromise journey, where every demand is met.
        assert_eq!(
            qualify(&compromise(), &probes),
            Err(IncidentRefusal::ControllerStillAnswering {
                vantage: "lab-relay-2".into()
            })
        );
    }

    /// **No switch on an ambiguous failure.** Each way of not knowing is a
    /// refusal with its own name, so a report says what was not established.
    #[test]
    fn every_shape_of_not_knowing_is_refused_under_its_own_name() {
        let one = vec![silent("lab-machine-1")];
        assert_eq!(
            qualify(&loss(), &one),
            Err(IncidentRefusal::Ambiguous(Ambiguity::TooFewVantages {
                count: 1
            }))
        );

        let cut = vec![
            silent("lab-machine-1"),
            Probe {
                vantage: "lab-relay".into(),
                answer: Answer::NoAnswer,
                continuous_seconds: REQUIRED_SILENCE_SECONDS,
            },
        ];
        assert_eq!(
            qualify(&loss(), &cut),
            Err(IncidentRefusal::Ambiguous(Ambiguity::NoAnswerFrom {
                vantage: "lab-relay".into()
            }))
        );

        let twice = vec![silent("lab-machine-1"), silent("lab-machine-1")];
        assert_eq!(
            qualify(&loss(), &twice),
            Err(IncidentRefusal::Ambiguous(Ambiguity::DuplicateVantage {
                vantage: "lab-machine-1".into()
            }))
        );

        assert_eq!(
            qualify(&loss(), &[]),
            Err(IncidentRefusal::Ambiguous(Ambiguity::TooFewVantages {
                count: 0
            }))
        );
    }

    /// A blip is not a loss, and the boundary is exactly where the constant
    /// says it is.
    #[test]
    fn a_silence_younger_than_the_bound_is_not_a_loss() {
        let mut young = silence();
        young[1].continuous_seconds = REQUIRED_SILENCE_SECONDS - 1;

        assert_eq!(
            qualify(&loss(), &young),
            Err(IncidentRefusal::Ambiguous(Ambiguity::SilenceTooYoung {
                vantage: "lab-relay".into(),
                seconds: REQUIRED_SILENCE_SECONDS - 1,
            }))
        );

        young[1].continuous_seconds = REQUIRED_SILENCE_SECONDS;
        assert!(qualify(&loss(), &young).is_ok());
    }

    /// The suspect host does not testify about its own death, and a probe taken
    /// from it counts for nothing — neither as a silence nor as an answer.
    #[test]
    fn the_suspect_host_is_never_one_of_the_vantages() {
        let mut probes = silence();
        probes.push(silent(SUSPECT));
        assert_eq!(
            qualify(&loss(), &probes),
            Err(IncidentRefusal::Ambiguous(
                Ambiguity::VantageIsTheSuspectHost {
                    vantage: SUSPECT.into()
                }
            ))
        );

        // And an "it answered" coming from the suspect host does not stop the
        // replacement either: it is not an independent observation at all.
        let self_serving = vec![
            silent("lab-machine-1"),
            silent("lab-relay"),
            Probe {
                vantage: SUSPECT.into(),
                answer: Answer::Answered,
                continuous_seconds: 1,
            },
        ];
        assert_eq!(
            read(&self_serving, SUSPECT),
            Reading::Ambiguous(Ambiguity::VantageIsTheSuspectHost {
                vantage: SUSPECT.into()
            })
        );
    }

    /// **The two journeys are not one journey with a flag.** A suspected
    /// compromise demands a verified isolation; the same request qualified as a
    /// hardware loss does not, and that is the difference the user is asked to
    /// state.
    #[test]
    fn a_suspected_compromise_demands_an_isolation_a_hardware_loss_does_not() {
        let unisolated = Request {
            isolation: Isolation::Unverified,
            ..compromise()
        };
        assert_eq!(
            qualify(&unisolated, &silence()),
            Err(IncidentRefusal::IsolationNotVerified)
        );

        // The very same request, qualified as the loss it is not, would pass.
        // That is precisely why the qualification is the user's statement and
        // not an inference.
        assert!(qualify(
            &Request {
                qualification: Qualification::HardwareLoss,
                ..unisolated
            },
            &silence()
        )
        .is_ok());
    }

    /// An isolation the suspect host vouched for is not a verified isolation.
    #[test]
    fn an_isolation_the_suspect_host_established_is_refused() {
        assert_eq!(
            qualify(
                &Request {
                    isolation: Isolation::Verified { by: SUSPECT.into() },
                    ..compromise()
                },
                &silence()
            ),
            Err(IncidentRefusal::IsolationVerifiedByTheSuspectHost)
        );
    }

    /// The new Controller lives on a healthy host, and the two journeys refuse
    /// the suspect host under two different names — a compromise because the
    /// host is not healthy, a loss because a host that is gone cannot serve.
    #[test]
    fn the_suspect_host_as_it_stands_is_refused_by_both_journeys() {
        assert_eq!(
            qualify(
                &Request {
                    new_host: NewHost::SameHostAsItStands {
                        endpoint: SUSPECT.into()
                    },
                    ..compromise()
                },
                &silence()
            ),
            Err(IncidentRefusal::SuspectHostIsNotAHealthyHost {
                endpoint: SUSPECT.into()
            })
        );
        assert_eq!(
            qualify(
                &Request {
                    new_host: NewHost::SameHostAsItStands {
                        endpoint: SUSPECT.into()
                    },
                    ..loss()
                },
                &silence()
            ),
            Err(IncidentRefusal::LostHostCannotHostTheReplacement {
                endpoint: SUSPECT.into()
            })
        );
    }

    /// A host rebuilt from a trusted base is what the architecture allows, and
    /// it is allowed on both journeys.
    #[test]
    fn a_host_rebuilt_from_a_trusted_base_is_accepted_by_both_journeys() {
        let rebuilt = NewHost::ReinstalledFromTrustedBase {
            endpoint: SUSPECT.into(),
        };
        assert_eq!(
            qualify(
                &Request {
                    new_host: rebuilt.clone(),
                    ..compromise()
                },
                &silence()
            )
            .expect("a rebuilt host must be accepted")
            .new_host(),
            SUSPECT
        );
        assert!(qualify(
            &Request {
                new_host: rebuilt,
                ..loss()
            },
            &silence()
        )
        .is_ok());
    }

    /// Names this module does not read are refused before anything is compared,
    /// and the refusal says which field.
    #[test]
    fn a_name_this_module_does_not_read_is_refused_by_field() {
        assert_eq!(
            qualify(
                &Request {
                    old_controller_id: String::new(),
                    ..loss()
                },
                &silence()
            ),
            Err(IncidentRefusal::MalformedName {
                field: "old_controller_id"
            })
        );
        assert_eq!(
            qualify(
                &Request {
                    suspect_host: "a b".into(),
                    ..loss()
                },
                &silence()
            ),
            Err(IncidentRefusal::MalformedName {
                field: "suspect_host"
            })
        );
        assert_eq!(
            read(
                &[
                    Probe {
                        vantage: "x".repeat(MAX_NAME_BYTES + 1),
                        answer: Answer::Unreachable,
                        continuous_seconds: REQUIRED_SILENCE_SECONDS,
                    },
                    silent("lab-relay"),
                ],
                SUSPECT
            ),
            Reading::Ambiguous(Ambiguity::MalformedVantage {
                vantage: "x".repeat(MAX_NAME_BYTES + 1)
            })
        );
    }
}
