//! What the new Controller may start with, and what the old one may not keep.
//!
//! The two questions are one question asked from both ends, which is why they
//! live in one module: *does anything that belonged to the old authority still
//! carry authority?* At the start of the replacement the answer must be "nothing
//! came in"; at the end it must be "nothing is left".
//!
//! **Starting clean is a refusal, not a habit.** [`admit`] refuses by name any
//! item whose origin is the old association. It is deliberately blunt: there is
//! no "compatible" device, no "still valid" certificate and no "harmless"
//! session. The Daemons and the ingestion Relay are reused — but they are reused
//! because their identities never depended on the Controller in the first place,
//! so they are not inherited from it and never appear here.
//!
//! **The sweep must cover every kind, or it is not a sweep.** [`sweep`] refuses
//! a set that says nothing about one of [`Kind::EVERY`]. A verification that
//! looked at five things out of six and reported success would be exactly the
//! false secured success the palier forbids — and the one that gets written by
//! accident, because the sixth thing is always the one nobody remembered.
//!
//! **Not observed is not refused.** [`Grant::NotObserved`] denies the sweep just
//! as loudly as [`Grant::StillGrantsAuthority`] does. The difference between
//! them is what a human is told, not whether the replacement may be called
//! secured.

/// One kind of thing that could carry a Controller's authority.
///
/// The list is the architecture's own enumeration, and it is closed. A seventh
/// kind is a change to the contract, not a value somebody adds at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A Console device the Controller issued a certificate to.
    Device,
    /// A TLS certificate or the authority that issued it.
    Certificate,
    /// A live session, or a token that reopens one.
    Session,
    /// A credential the old Controller could read.
    Secret,
    /// A network filter that admits the old host or its address.
    NetworkFilter,
    /// A manifest that names the old Controller — the Relay reader's above all.
    Manifest,
}

impl Kind {
    /// Every kind, so a sweep can be checked for coverage against the contract
    /// rather than against whatever a caller happened to pass.
    pub const EVERY: [Kind; 6] = [
        Kind::Device,
        Kind::Certificate,
        Kind::Session,
        Kind::Secret,
        Kind::NetworkFilter,
        Kind::Manifest,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Certificate => "certificate",
            Self::Session => "session",
            Self::Secret => "secret",
            Self::NetworkFilter => "network-filter",
            Self::Manifest => "manifest",
        }
    }
}

/// Where one item the new Controller is starting with came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Made for this Controller, by this replacement.
    MintedForTheNewController,
    /// Carried over from the association being replaced.
    InheritedFromTheOldAssociation,
    /// It never belonged to any Controller: a Daemon's own identity, the
    /// ingestion Relay's. Reusing it is what the architecture asks for, and it
    /// is a third value rather than a shade of the first so that "reused" and
    /// "freshly minted" never read the same in a report.
    IndependentOfEveryController,
}

/// One thing the new Controller is starting with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    pub kind: Kind,
    pub name: String,
    pub origin: Origin,
}

/// Why the new Controller was not allowed to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InheritanceRefusal {
    /// Something came from the old association.
    Inherited { kind: &'static str, name: String },
    /// Nothing at all was declared. A start nobody described is a start nobody
    /// checked.
    NothingDeclared,
}

/// The proof that the new Controller started with nothing of the old one's.
///
/// It cannot be built by naming its fields and [`admit`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartedClean {
    minted: usize,
    reused: usize,
}

impl StartedClean {
    /// How many items were made for this Controller.
    pub fn minted(&self) -> usize {
        self.minted
    }

    /// How many were reused because they never depended on a Controller.
    pub fn reused(&self) -> usize {
        self.reused
    }
}

/// The one gate. Nothing else in this crate builds a [`StartedClean`].
pub fn admit(carried: &[Carried]) -> Result<StartedClean, InheritanceRefusal> {
    if carried.is_empty() {
        return Err(InheritanceRefusal::NothingDeclared);
    }
    let mut minted = 0;
    let mut reused = 0;
    for item in carried {
        match item.origin {
            Origin::InheritedFromTheOldAssociation => {
                return Err(InheritanceRefusal::Inherited {
                    kind: item.kind.as_str(),
                    name: item.name.clone(),
                })
            }
            Origin::MintedForTheNewController => minted += 1,
            Origin::IndependentOfEveryController => reused += 1,
        }
    }
    Ok(StartedClean { minted, reused })
}

/// What one thing the old Controller could use still gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grant {
    /// It was tried, from the old Controller's own position, and it was
    /// refused.
    Refused,
    /// It was tried and it worked. The one fatal answer.
    StillGrantsAuthority,
    /// Nobody tried. It denies the sweep too, and says so under its own name.
    NotObserved,
}

/// One thing the old Controller could use, and what trying it produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Residue {
    pub kind: Kind,
    pub name: String,
    pub grant: Grant,
}

/// Why the old authority could not be declared gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SweepRefusal {
    /// **The fatal one.** Something still works for the old Controller.
    StillGrantsAuthority { kind: &'static str, name: String },
    /// Something was never tried.
    NotObserved { kind: &'static str, name: String },
    /// A whole kind is missing from the sweep. It is refused by the name of the
    /// kind, because "we checked five of the six" is the shape this failure
    /// always takes.
    KindNotSwept { kind: &'static str },
}

/// The proof that nothing the old Controller could use still gives it
/// authority.
///
/// It cannot be built by naming its fields and [`sweep`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swept {
    checked: usize,
}

impl Swept {
    /// How many things were actually tried. A sweep of six and a sweep of
    /// sixty are different reports.
    pub fn checked(&self) -> usize {
        self.checked
    }
}

/// The one gate. Nothing else in this crate builds a [`Swept`].
///
/// The order of the refusals matters: something that still works is reported
/// before something that was not looked at, because the first is a live
/// exposure and the second is an incomplete report.
pub fn sweep(residues: &[Residue]) -> Result<Swept, SweepRefusal> {
    for residue in residues {
        if residue.grant == Grant::StillGrantsAuthority {
            return Err(SweepRefusal::StillGrantsAuthority {
                kind: residue.kind.as_str(),
                name: residue.name.clone(),
            });
        }
    }
    for residue in residues {
        if residue.grant == Grant::NotObserved {
            return Err(SweepRefusal::NotObserved {
                kind: residue.kind.as_str(),
                name: residue.name.clone(),
            });
        }
    }
    for kind in Kind::EVERY {
        if !residues.iter().any(|residue| residue.kind == kind) {
            return Err(SweepRefusal::KindNotSwept {
                kind: kind.as_str(),
            });
        }
    }
    Ok(Swept {
        checked: residues.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minted(kind: Kind, name: &str) -> Carried {
        Carried {
            kind,
            name: name.into(),
            origin: Origin::MintedForTheNewController,
        }
    }

    fn refused(kind: Kind) -> Residue {
        Residue {
            kind,
            name: format!("the old {}", kind.as_str()),
            grant: Grant::Refused,
        }
    }

    fn complete_sweep() -> Vec<Residue> {
        Kind::EVERY.into_iter().map(refused).collect()
    }

    /// The positive control of the start: everything freshly minted, plus the
    /// things that never belonged to a Controller and are reused on purpose.
    #[test]
    fn a_controller_starting_with_its_own_material_and_nothing_else_is_admitted() {
        let clean = admit(&[
            minted(Kind::Certificate, "server authority"),
            minted(Kind::Certificate, "device authority"),
            minted(Kind::Secret, "reader client key"),
            Carried {
                kind: Kind::Certificate,
                name: "daemon authority".into(),
                origin: Origin::IndependentOfEveryController,
            },
        ])
        .expect("the positive control must be admitted");

        assert_eq!(clean.minted(), 3);
        assert_eq!(clean.reused(), 1);
    }

    /// **Nothing old comes in.** Each kind is refused under its own name, one
    /// at a time, so a report says what was inherited rather than that
    /// something was.
    #[test]
    fn anything_inherited_from_the_old_association_is_refused_by_its_own_kind() {
        for kind in Kind::EVERY {
            let carried = vec![
                minted(Kind::Certificate, "server authority"),
                Carried {
                    kind,
                    name: format!("the old {}", kind.as_str()),
                    origin: Origin::InheritedFromTheOldAssociation,
                },
            ];
            assert_eq!(
                admit(&carried),
                Err(InheritanceRefusal::Inherited {
                    kind: kind.as_str(),
                    name: format!("the old {}", kind.as_str()),
                }),
                "an inherited {} must be refused",
                kind.as_str()
            );
        }
    }

    /// A start nobody described is a start nobody checked.
    #[test]
    fn a_controller_starting_with_nothing_declared_is_refused() {
        assert_eq!(admit(&[]), Err(InheritanceRefusal::NothingDeclared));
    }

    /// The positive control of the sweep: every kind tried, every kind refused.
    #[test]
    fn a_sweep_covering_every_kind_and_refusing_every_one_is_accepted() {
        let swept = sweep(&complete_sweep()).expect("the positive control must sweep");
        assert_eq!(swept.checked(), Kind::EVERY.len());
    }

    /// **The fatal answer.** One thing that still works denies the whole sweep,
    /// and names it.
    #[test]
    fn one_thing_that_still_works_denies_the_whole_sweep() {
        for kind in Kind::EVERY {
            let mut residues = complete_sweep();
            let position = residues
                .iter()
                .position(|residue| residue.kind == kind)
                .expect("every kind is in the complete sweep");
            residues[position].grant = Grant::StillGrantsAuthority;

            assert_eq!(
                sweep(&residues),
                Err(SweepRefusal::StillGrantsAuthority {
                    kind: kind.as_str(),
                    name: format!("the old {}", kind.as_str()),
                }),
                "a live {} must deny the sweep",
                kind.as_str()
            );
        }
    }

    /// **A kind nobody swept denies the sweep**, which is the shape this
    /// failure always takes: five of the six checked, and the report clean.
    #[test]
    fn a_kind_missing_from_the_sweep_is_refused_by_the_name_of_the_kind() {
        for kind in Kind::EVERY {
            let residues: Vec<Residue> = complete_sweep()
                .into_iter()
                .filter(|residue| residue.kind != kind)
                .collect();
            assert_eq!(
                sweep(&residues),
                Err(SweepRefusal::KindNotSwept {
                    kind: kind.as_str()
                }),
                "a sweep missing {} must be refused",
                kind.as_str()
            );
        }
        assert_eq!(
            sweep(&[]),
            Err(SweepRefusal::KindNotSwept {
                kind: Kind::Device.as_str()
            })
        );
    }

    /// Something nobody tried denies the sweep too — and a live exposure is
    /// reported before an incomplete report, because they are not equally
    /// urgent.
    #[test]
    fn something_never_tried_denies_the_sweep_and_yields_to_a_live_exposure() {
        let mut residues = complete_sweep();
        residues[2].grant = Grant::NotObserved;
        assert_eq!(
            sweep(&residues),
            Err(SweepRefusal::NotObserved {
                kind: residues[2].kind.as_str(),
                name: residues[2].name.clone(),
            })
        );

        residues[4].grant = Grant::StillGrantsAuthority;
        assert_eq!(
            sweep(&residues),
            Err(SweepRefusal::StillGrantsAuthority {
                kind: residues[4].kind.as_str(),
                name: residues[4].name.clone(),
            })
        );
    }
}
