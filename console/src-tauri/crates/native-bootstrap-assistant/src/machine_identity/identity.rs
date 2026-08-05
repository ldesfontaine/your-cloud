//! One SSH identity per machine, and its refusal on every other machine.
//!
//! This is the central decision of the palier. A single operational key for the
//! whole estate would mean that stealing one machine's access is stealing every
//! machine's access; the architecture therefore requires a different pair per
//! target, and requires that a pair be *unusable* anywhere else. The second
//! half is the one that has to be decided somewhere, because the first half
//! alone is only a habit of whoever generated the keys.
//!
//! [`Enrolled::admits`] is that decision, and it is deliberately the smallest
//! function in the module: given a machine and the fingerprint presented for
//! it, it answers with the identity or with the name of the machine that
//! fingerprint really belongs to. A LAB mutation that makes it answer `Ok` for
//! a foreign owner is what the cross-key proof has to redden.
//!
//! **A fingerprint nobody minted is not a lesser refusal.**
//! [`IdentityRefusal::Unattributed`] and [`IdentityRefusal::ForeignIdentity`]
//! are distinct because a report has to be able to say whether the key that was
//! presented belongs to the estate at all. Collapsing them would make an
//! intrusion and a misconfiguration read the same in a proof.
//!
//! Nothing here generates a key. The private material of the operational
//! identities stays on the Controller, in the root-owned credential sources of
//! #38, and this module only ever sees fingerprints.

use crate::personal_access::host_key::HOST_KEY_FINGERPRINT_BYTES;

/// Most machines one enrolment run may mint identities for.
///
/// It bounds the input rather than expressing a product limit: a declaration
/// naming more machines than an infrastructure of this palier has is a
/// declaration this palier does not recognise, and refusing it early is
/// cheaper than deciding on it.
pub const MAX_ENROLLED_MACHINES: usize = 64;

/// One machine and the fingerprint of the one identity it accepts.
///
/// It cannot be built by naming its fields: [`mint`] is the only function that
/// produces one, so an identity that was never checked for uniqueness cannot be
/// handed to anything downstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintedIdentity {
    machine: String,
    fingerprint: String,
}

impl MintedIdentity {
    pub fn machine(&self) -> &str {
        &self.machine
    }

    /// The `SHA256:…` fingerprint of the public key this machine accepts.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// One machine as the mint receives it: a name and the fingerprint the
/// Controller generated for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    pub machine: String,
    pub fingerprint: String,
}

/// Why an identity was not minted, or not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityRefusal {
    /// Nothing was declared. An empty estate is refused rather than minted
    /// vacuously: a run that enrols no machine has not enrolled one.
    NothingDeclared,
    /// More machines than this palier recognises.
    TooManyMachines { count: usize },
    /// The name is not a machine name this palier reads.
    MalformedMachine { machine: String },
    /// The fingerprint is not a `SHA256:` fingerprint of the expected length.
    MalformedFingerprint { machine: String },
    /// The same machine appears twice, so ordering rather than observation
    /// would decide which of its two identities counted.
    DuplicateMachine { machine: String },
    /// Two machines were given the same identity. This is the refusal that
    /// makes "a different pair per machine" a decision instead of a hope.
    SharedIdentity { machine: String, other: String },
    /// The estate holds no identity for that machine at all.
    UnknownMachine { machine: String },
    /// The key presented for this machine is the identity of another one. It is
    /// the crown refusal of the palier: a stolen identity opens exactly the one
    /// machine it was minted for.
    ForeignIdentity { machine: String, owner: String },
    /// The key presented for this machine belongs to no machine of the estate.
    Unattributed { machine: String },
}

/// Every machine of one infrastructure, each holding an identity no other one
/// holds.
///
/// Like the witnesses of #38 it has exactly one constructor, and nothing in
/// this crate builds one another way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    identities: Vec<MintedIdentity>,
}

/// The one gate. Nothing else in this crate builds an [`Enrolled`].
///
/// It refuses the whole declaration on the first problem rather than minting
/// the machines that happened to be well formed: a partially minted estate
/// would let a caller enrol the machines that passed and leave the collision
/// for later, which is the partial success the palier forbids.
pub fn mint(declared: &[Declared]) -> Result<Enrolled, IdentityRefusal> {
    if declared.is_empty() {
        return Err(IdentityRefusal::NothingDeclared);
    }
    if declared.len() > MAX_ENROLLED_MACHINES {
        return Err(IdentityRefusal::TooManyMachines {
            count: declared.len(),
        });
    }
    let mut identities: Vec<MintedIdentity> = Vec::with_capacity(declared.len());
    for entry in declared {
        if !is_machine_name(&entry.machine) {
            return Err(IdentityRefusal::MalformedMachine {
                machine: entry.machine.clone(),
            });
        }
        if !is_fingerprint(&entry.fingerprint) {
            return Err(IdentityRefusal::MalformedFingerprint {
                machine: entry.machine.clone(),
            });
        }
        if let Some(previous) = identities
            .iter()
            .find(|minted| minted.machine == entry.machine)
        {
            return Err(IdentityRefusal::DuplicateMachine {
                machine: previous.machine.clone(),
            });
        }
        if let Some(previous) = identities
            .iter()
            .find(|minted| minted.fingerprint == entry.fingerprint)
        {
            return Err(IdentityRefusal::SharedIdentity {
                machine: entry.machine.clone(),
                other: previous.machine.clone(),
            });
        }
        identities.push(MintedIdentity {
            machine: entry.machine.clone(),
            fingerprint: entry.fingerprint.clone(),
        });
    }
    Ok(Enrolled { identities })
}

impl Enrolled {
    pub fn machines(&self) -> Vec<&str> {
        self.identities
            .iter()
            .map(|minted| minted.machine.as_str())
            .collect()
    }

    /// The identity one machine was minted, or the refusal that names it.
    pub fn identity_of(&self, machine: &str) -> Result<&MintedIdentity, IdentityRefusal> {
        self.identities
            .iter()
            .find(|minted| minted.machine == machine)
            .ok_or_else(|| IdentityRefusal::UnknownMachine {
                machine: machine.to_owned(),
            })
    }

    /// **The crown decision.** Whether this machine admits the key presented
    /// for it.
    ///
    /// It answers with the machine's own identity, or with the name of the
    /// machine the presented key really belongs to. The second answer is the
    /// whole security property of the palier: a key stolen from one machine
    /// opens that machine and no other, and the refusal says which one it came
    /// from rather than merely that something did not match.
    pub fn admits(
        &self,
        machine: &str,
        presented: &str,
    ) -> Result<&MintedIdentity, IdentityRefusal> {
        let minted = self.identity_of(machine)?;
        if minted.fingerprint == presented {
            return Ok(minted);
        }
        match self
            .identities
            .iter()
            .find(|other| other.fingerprint == presented)
        {
            Some(owner) => Err(IdentityRefusal::ForeignIdentity {
                machine: machine.to_owned(),
                owner: owner.machine.clone(),
            }),
            None => Err(IdentityRefusal::Unattributed {
                machine: machine.to_owned(),
            }),
        }
    }
}

/// The machine names this palier reads, kept identical to the ones the
/// Auxiliary's anchor accepts: lower-case, three to sixty-three characters, no
/// leading separator.
fn is_machine_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A `SHA256:` fingerprint as `ssh-keygen -l` renders one: the prefix, then the
/// unpadded base64 of thirty-two bytes.
fn is_fingerprint(value: &str) -> bool {
    if value.len() != HOST_KEY_FINGERPRINT_BYTES || !value.starts_with("SHA256:") {
        return false;
    }
    value["SHA256:".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const KEY_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const KEY_C: &str = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    fn declared(pairs: &[(&str, &str)]) -> Vec<Declared> {
        pairs
            .iter()
            .map(|(machine, fingerprint)| Declared {
                machine: (*machine).into(),
                fingerprint: (*fingerprint).into(),
            })
            .collect()
    }

    fn estate() -> Enrolled {
        mint(&declared(&[
            ("lab-machine-1", KEY_A),
            ("lab-machine-2", KEY_B),
        ]))
        .expect("the estate fixture must mint")
    }

    /// The positive control: two machines, two identities, each admitted on its
    /// own machine.
    #[test]
    fn each_machine_admits_the_identity_it_was_minted() {
        let estate = estate();
        assert_eq!(estate.machines(), ["lab-machine-1", "lab-machine-2"]);
        assert_eq!(
            estate
                .admits("lab-machine-1", KEY_A)
                .expect("the positive control must be admitted")
                .fingerprint(),
            KEY_A
        );
        assert_eq!(
            estate
                .admits("lab-machine-2", KEY_B)
                .expect("the positive control must be admitted")
                .machine(),
            "lab-machine-2"
        );
    }

    /// **The property the whole palier exists for.** The identity of one
    /// machine, presented to another, is refused — and the refusal names the
    /// machine it was stolen from.
    #[test]
    fn the_identity_of_one_machine_is_refused_on_every_other_machine() {
        let estate = estate();
        assert_eq!(
            estate.admits("lab-machine-2", KEY_A),
            Err(IdentityRefusal::ForeignIdentity {
                machine: "lab-machine-2".into(),
                owner: "lab-machine-1".into(),
            })
        );
        assert_eq!(
            estate.admits("lab-machine-1", KEY_B),
            Err(IdentityRefusal::ForeignIdentity {
                machine: "lab-machine-1".into(),
                owner: "lab-machine-2".into(),
            })
        );
    }

    /// A key that belongs to no machine of the estate is a different fact from
    /// a key stolen from one of them, and comes back as a different refusal.
    #[test]
    fn a_key_belonging_to_no_machine_is_not_reported_as_a_stolen_one() {
        assert_eq!(
            estate().admits("lab-machine-1", KEY_C),
            Err(IdentityRefusal::Unattributed {
                machine: "lab-machine-1".into()
            })
        );
    }

    /// Handing two machines the same pair is refused at the mint, so no
    /// downstream step can be given an estate where one key opens two machines.
    #[test]
    fn two_machines_are_never_minted_the_same_identity() {
        assert_eq!(
            mint(&declared(&[
                ("lab-machine-1", KEY_A),
                ("lab-machine-2", KEY_A)
            ])),
            Err(IdentityRefusal::SharedIdentity {
                machine: "lab-machine-2".into(),
                other: "lab-machine-1".into(),
            })
        );
    }

    /// The same machine twice would let ordering decide which identity counted.
    #[test]
    fn the_same_machine_declared_twice_is_refused() {
        assert_eq!(
            mint(&declared(&[
                ("lab-machine-1", KEY_A),
                ("lab-machine-1", KEY_B)
            ])),
            Err(IdentityRefusal::DuplicateMachine {
                machine: "lab-machine-1".into()
            })
        );
    }

    /// A machine nobody enrolled admits nothing, rather than admitting the
    /// first key that is offered for it.
    #[test]
    fn an_unenrolled_machine_admits_nothing() {
        assert_eq!(
            estate().admits("lab-machine-9", KEY_A),
            Err(IdentityRefusal::UnknownMachine {
                machine: "lab-machine-9".into()
            })
        );
    }

    /// Shapes that are not fingerprints are refused before anything compares
    /// them, so a truncated or empty value never matches by accident.
    #[test]
    fn a_value_that_is_not_a_fingerprint_never_reaches_a_comparison() {
        for hostile in ["", "SHA256:short", KEY_A.trim_end_matches('A'), "MD5:aa:bb"] {
            assert_eq!(
                mint(&declared(&[("lab-machine-1", hostile)])),
                Err(IdentityRefusal::MalformedFingerprint {
                    machine: "lab-machine-1".into()
                }),
                "{hostile:?} must not be read as a fingerprint"
            );
        }
    }

    /// An empty estate is refused rather than minted vacuously, and an estate
    /// longer than this palier reads is refused before it is judged.
    #[test]
    fn an_empty_or_oversized_estate_is_refused() {
        assert_eq!(mint(&[]), Err(IdentityRefusal::NothingDeclared));
        let many: Vec<Declared> = (0..=MAX_ENROLLED_MACHINES)
            .map(|index| Declared {
                machine: format!("lab-machine-{index}"),
                fingerprint: KEY_A.into(),
            })
            .collect();
        assert_eq!(
            mint(&many),
            Err(IdentityRefusal::TooManyMachines {
                count: MAX_ENROLLED_MACHINES + 1
            })
        );
    }

    /// A machine name this palier does not read is refused before it is minted.
    #[test]
    fn a_machine_name_this_palier_does_not_read_is_refused() {
        for hostile in [
            "",
            "ab",
            "-machine",
            "Lab-Machine-1",
            "lab machine",
            "lab.1",
        ] {
            assert_eq!(
                mint(&declared(&[(hostile, KEY_A)])),
                Err(IdentityRefusal::MalformedMachine {
                    machine: hostile.into()
                }),
                "{hostile:?} must not be read as a machine name"
            );
        }
    }
}
