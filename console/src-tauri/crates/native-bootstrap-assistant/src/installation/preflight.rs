//! The check that has to pass before any other machine is touched.
//!
//! Step 5 of « Création d'une infrastructure » is the hinge of the whole
//! sequence: the Controller — not the laptop — reaches every declared endpoint
//! and finds the host key that was already confirmed during the audit. Until
//! that holds for *every* endpoint, step 6 must not have begun on *any* of
//! them.
//!
//! **The clearance is all-or-nothing, and that is a type and not a habit.**
//! There is no per-endpoint witness in this module. If there were, a caller
//! could install on the endpoints that answered and leave the one that did not
//! for later, which is precisely the partial success the issue forbids. One
//! [`PreflightCleared`] covers the whole declared set or it does not exist.
//!
//! **A machine reachable from the laptop is not a machine reachable from the
//! Controller.** These answers come from the Controller's own attempts; nothing
//! here may be satisfied by what the Assistant could reach itself. The
//! difference is the whole reason the step exists — the Controller is what will
//! live with these endpoints after the laptop is closed.
//!
//! **A first answer is never a confirmation.** The fingerprint an endpoint
//! presents is compared with the one already confirmed by the declaration and
//! the audit, never recorded because it was the first thing to answer. An
//! endpoint whose key was never confirmed is refused, not trusted.

use crate::personal_access::host_key::HOST_KEY_FINGERPRINT_BYTES;

/// One endpoint as the preflight must find it: what was declared and already
/// confirmed, beside what the Controller actually observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointAttempt {
    /// The declared name, carried verbatim into every refusal so a report says
    /// which endpoint failed rather than how many did.
    pub name: String,
    /// The fingerprint confirmed before this palier, in `SHA256:` form. An
    /// empty value means the endpoint was never confirmed, which is a refusal.
    pub confirmed_fingerprint: String,
    /// What the Controller's attempt answered.
    pub observed: Observation,
}

/// What the Controller's own attempt on one endpoint produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// The Controller opened a transport and the endpoint presented this
    /// fingerprint.
    Presented { fingerprint: String },
    /// The Controller could not reach the endpoint at all.
    Unreachable,
    /// The attempt produced no usable answer — it was cut, or it timed out.
    /// It is distinct from [`Observation::Unreachable`] because "we know it is
    /// not reachable" and "we do not know" are different facts, and only the
    /// second one says nothing about the endpoint.
    NoAnswer,
}

/// Why the preflight refused, and on which endpoint.
///
/// The endpoint name travels inside the refusal rather than beside it, so no
/// call site can report a refusal without saying what it was about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreflightRefusal {
    /// Nothing was declared. An empty set is refused rather than cleared
    /// vacuously: a run that installs on no endpoint has not passed a
    /// preflight, it has skipped one.
    NothingDeclared,
    /// The same endpoint name appears twice. Which of the two answers cleared
    /// it would be decided by ordering rather than by observation.
    DuplicateEndpoint { name: String },
    /// The endpoint carries no confirmed fingerprint to compare against.
    NeverConfirmed { name: String },
    /// The confirmed fingerprint is not a `SHA256:` fingerprint.
    ConfirmedMalformed { name: String },
    /// The Controller could not reach the endpoint.
    Unreachable { name: String },
    /// The attempt gave no usable answer.
    NoAnswer { name: String },
    /// The endpoint answered with a key that is not the confirmed one.
    HostKeyMismatch { name: String },
}

/// The proof that every declared endpoint answered the Controller with the key
/// it was already confirmed to hold.
///
/// Like the other witnesses of this palier it cannot be built by naming its
/// fields, and [`clear`] is the only function that returns one. It carries the
/// endpoint names it covers so that the step which mutates targets can assert
/// it is about to touch exactly the set that was cleared, and no other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightCleared {
    endpoints: Vec<String>,
}

impl PreflightCleared {
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// True when this clearance covers that exact endpoint. The mutating step
    /// asks this rather than trusting its own list.
    pub fn covers(&self, name: &str) -> bool {
        self.endpoints.iter().any(|endpoint| endpoint == name)
    }
}

/// The one gate. Nothing else in this crate builds a [`PreflightCleared`].
///
/// Every attempt is judged; the first refusal is returned. The function is
/// total in the sense that matters here: it never returns a clearance covering
/// a subset of what it was given.
pub fn clear(attempts: &[EndpointAttempt]) -> Result<PreflightCleared, PreflightRefusal> {
    if attempts.is_empty() {
        return Err(PreflightRefusal::NothingDeclared);
    }
    let mut names: Vec<String> = Vec::with_capacity(attempts.len());
    for attempt in attempts {
        if names.contains(&attempt.name) {
            return Err(PreflightRefusal::DuplicateEndpoint {
                name: attempt.name.clone(),
            });
        }
        judge(attempt)?;
        names.push(attempt.name.clone());
    }
    Ok(PreflightCleared { endpoints: names })
}

fn judge(attempt: &EndpointAttempt) -> Result<(), PreflightRefusal> {
    let name = attempt.name.clone();
    if attempt.confirmed_fingerprint.trim().is_empty() {
        return Err(PreflightRefusal::NeverConfirmed { name });
    }
    if attempt.confirmed_fingerprint.len() != HOST_KEY_FINGERPRINT_BYTES
        || !attempt.confirmed_fingerprint.starts_with("SHA256:")
    {
        return Err(PreflightRefusal::ConfirmedMalformed { name });
    }
    match &attempt.observed {
        Observation::Unreachable => Err(PreflightRefusal::Unreachable { name }),
        Observation::NoAnswer => Err(PreflightRefusal::NoAnswer { name }),
        Observation::Presented { fingerprint } => {
            if fingerprint == &attempt.confirmed_fingerprint {
                return Ok(());
            }
            Err(PreflightRefusal::HostKeyMismatch { name })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const KEY_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn answered(name: &str, confirmed: &str, presented: &str) -> EndpointAttempt {
        EndpointAttempt {
            name: name.into(),
            confirmed_fingerprint: confirmed.into(),
            observed: Observation::Presented {
                fingerprint: presented.into(),
            },
        }
    }

    /// The positive control: three endpoints, each answering with the key it
    /// was confirmed to hold.
    #[test]
    fn every_endpoint_answering_its_confirmed_key_clears_the_whole_set() {
        let cleared = clear(&[
            answered("machine-1", KEY_A, KEY_A),
            answered("machine-2", KEY_B, KEY_B),
            answered("machine-3", KEY_A, KEY_A),
        ])
        .expect("the positive control must clear");

        assert_eq!(cleared.endpoints(), ["machine-1", "machine-2", "machine-3"]);
        assert!(cleared.covers("machine-2"));
        assert!(!cleared.covers("machine-4"));
    }

    /// The property the issue asks for: one endpoint failing means no
    /// clearance at all, so nothing downstream can touch the two that answered.
    #[test]
    fn one_endpoint_failing_denies_the_clearance_of_every_other() {
        let refusal = clear(&[
            answered("machine-1", KEY_A, KEY_A),
            EndpointAttempt {
                name: "machine-2".into(),
                confirmed_fingerprint: KEY_B.into(),
                observed: Observation::Unreachable,
            },
            answered("machine-3", KEY_A, KEY_A),
        ])
        .expect_err("one unreachable endpoint must deny the whole clearance");

        assert_eq!(
            refusal,
            PreflightRefusal::Unreachable {
                name: "machine-2".into()
            }
        );
    }

    /// A hostile endpoint presenting a well-formed key that is simply not the
    /// confirmed one is refused as a mismatch, not accepted as a first answer.
    #[test]
    fn a_key_that_is_not_the_confirmed_one_is_refused_however_well_formed() {
        assert_eq!(
            clear(&[answered("machine-1", KEY_A, KEY_B)]),
            Err(PreflightRefusal::HostKeyMismatch {
                name: "machine-1".into()
            })
        );
    }

    /// An endpoint nobody ever confirmed is refused rather than pinned now.
    #[test]
    fn an_endpoint_without_a_confirmed_key_is_refused_not_trusted() {
        assert_eq!(
            clear(&[answered("machine-1", "", KEY_A)]),
            Err(PreflightRefusal::NeverConfirmed {
                name: "machine-1".into()
            })
        );
        assert_eq!(
            clear(&[answered("machine-1", "SHA256:short", KEY_A)]),
            Err(PreflightRefusal::ConfirmedMalformed {
                name: "machine-1".into()
            })
        );
    }

    /// "We could not reach it" and "we do not know" are different facts and
    /// come back as different refusals.
    #[test]
    fn no_answer_is_not_the_same_refusal_as_unreachable() {
        let no_answer = EndpointAttempt {
            name: "machine-1".into(),
            confirmed_fingerprint: KEY_A.into(),
            observed: Observation::NoAnswer,
        };

        assert_eq!(
            clear(&[no_answer]),
            Err(PreflightRefusal::NoAnswer {
                name: "machine-1".into()
            })
        );
    }

    /// An empty declaration does not clear vacuously.
    #[test]
    fn an_empty_declaration_is_refused_rather_than_cleared() {
        assert_eq!(clear(&[]), Err(PreflightRefusal::NothingDeclared));
    }

    /// The same name twice would let ordering decide which answer counted.
    #[test]
    fn the_same_endpoint_declared_twice_is_refused() {
        assert_eq!(
            clear(&[
                answered("machine-1", KEY_A, KEY_A),
                answered("machine-1", KEY_A, KEY_B),
            ]),
            Err(PreflightRefusal::DuplicateEndpoint {
                name: "machine-1".into()
            })
        );
    }
}
