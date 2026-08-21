//! The Relay reader: closed across the switch, and never open to two
//! Controllers.
//!
//! The reader is the one place in the product where a Controller's authority is
//! *served to it* rather than held by it. It is therefore the place where two
//! Controllers would overlap most quietly: an old process and a new one, both
//! holding a client certificate the Relay still accepts, and nothing in either
//! of them able to notice.
//!
//! **The Relay refuses to change identity in place, and this module relies on
//! that rather than on a promise.** `internal/readeridentity` holds one
//! manifest, with one `controller_id`, and its reload refuses a document naming
//! another one. So the reader cannot be *moved* from the old Controller to the
//! new one — it can only be closed and reopened. That is not an inconvenience
//! this module works around; it is the mechanism it proves, because a reader
//! that could be swapped live is a reader that is open to both for the duration
//! of the swap.
//!
//! **A manifest names exactly one Controller.** [`read`] refuses a document
//! naming two by its own name, refuses a document naming none, and refuses a
//! `uri` that does not derive from the pair it claims. A reader authority is not
//! a list.
//!
//! **The closure is sampled, not asserted.** [`rotate`] wants the states
//! observed *during* the switch, not a caller's word that it closed something.
//! An empty sample set is refused: a switch nobody looked at is a switch nobody
//! can say was closed.

use crate::installation::association::MAX_IDENTIFIER_BYTES;

/// The one port the reader is served on. It is named here so a harness can
/// assert the socket it sampled is the socket the product means, rather than
/// whichever port happened to be free.
pub const READER_PORT: u16 = 8444;

/// The scheme every reader URI derives from. A manifest whose `uri` is not
/// exactly this prefix followed by the pair it declares is refused: an
/// authority whose name and whose claim can drift apart has two identities.
pub const READER_URI_PREFIX: &str = "urn:your-cloud:controller-reader:";

/// The reader URI one infrastructure and one Controller derive.
pub fn reader_uri(infrastructure_id: &str, controller_id: &str) -> String {
    format!("{READER_URI_PREFIX}{infrastructure_id}:{controller_id}")
}

/// What a reader manifest says, as it stands on the Relay.
///
/// `authorized_controller_ids` is a list even though exactly one is ever
/// acceptable. Modelling it as a single value would make "two Controllers are
/// never accepted" unrepresentable rather than refused, and an unrepresentable
/// state is one no proof can exercise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderManifest {
    pub infrastructure_id: String,
    pub authorized_controller_ids: Vec<String>,
    pub uri: String,
    /// The one exact source address the listener admits. It is one address and
    /// not a range, exactly as `relay::NewReaderListener` requires.
    pub source_address: String,
    /// `active` or `revoked`, as the product's own closed set writes it.
    pub status: String,
    pub port: u16,
}

/// The status values the product recognises. Anything else is a manifest this
/// module does not read, rather than a status it tolerates.
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_REVOKED: &str = "revoked";

/// What the reader is, once its manifest and its socket have been read
/// together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderState {
    /// Nothing is served. Either the socket is not listening, or the manifest
    /// revokes the only identity it knows.
    Closed,
    /// Exactly one Controller is served, from exactly one source address.
    OpenTo {
        controller_id: String,
        source_address: String,
    },
}

/// Whether the socket was found listening, observed rather than assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socket {
    Listening,
    NotListening,
    /// The sample failed. It is neither of the two above, and it is never read
    /// as a closure.
    NotObserved,
}

/// Why a manifest or a rotation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderRefusal {
    /// **The crown refusal.** The manifest authorises two Controllers.
    TwoControllers { first: String, second: String },
    /// The manifest authorises none, so there is nothing to be open to and
    /// nothing to be closed against.
    NoController,
    /// A status outside the product's closed set.
    UnknownStatus { status: String },
    /// A port that is not the reader's.
    WrongPort { port: u16 },
    /// The `uri` does not derive from the pair the manifest declares.
    UriDoesNotDeriveFromThePair { uri: String },
    /// A source address that is not one exact address.
    SourceAddressNotExact { source_address: String },
    /// An identifier this module does not read.
    MalformedIdentifier { field: &'static str },
    /// The socket sample failed, so nothing may be read from it.
    SocketNotObserved,
    /// Nobody sampled the reader during the switch.
    NeverSampledDuringTheSwitch,
    /// The reader was open at some point during the switch.
    OpenDuringTheSwitch { controller_id: String },
    /// The reader is still open to the Controller being replaced.
    StillOpenToTheOldController,
    /// The reader came back open to somebody who is neither of the two.
    OpenToAnotherController { controller_id: String },
    /// The reader never came back open to the new Controller.
    NeverReopened,
    /// The reader came back on the old source address. The client identity and
    /// its address are reprovisioned together, or the old host keeps a route
    /// the manifest still admits.
    SourceAddressNotReprovisioned { source_address: String },
}

/// Reads one manifest and one socket sample into one state.
///
/// It is the only way a [`ReaderState`] is produced, so "the reader is closed"
/// is always a statement about a document *and* a socket, never about one of
/// them.
pub fn read(manifest: &ReaderManifest, socket: Socket) -> Result<ReaderState, ReaderRefusal> {
    identifier(&manifest.infrastructure_id, "infrastructure_id")?;
    if manifest.port != READER_PORT {
        return Err(ReaderRefusal::WrongPort {
            port: manifest.port,
        });
    }
    if manifest.status != STATUS_ACTIVE && manifest.status != STATUS_REVOKED {
        return Err(ReaderRefusal::UnknownStatus {
            status: manifest.status.clone(),
        });
    }
    match manifest.authorized_controller_ids.as_slice() {
        [] => return Err(ReaderRefusal::NoController),
        [_] => {}
        [first, second, ..] => {
            return Err(ReaderRefusal::TwoControllers {
                first: first.clone(),
                second: second.clone(),
            })
        }
    }
    let controller_id = &manifest.authorized_controller_ids[0];
    identifier(controller_id, "controller_id")?;
    if manifest.uri != reader_uri(&manifest.infrastructure_id, controller_id) {
        return Err(ReaderRefusal::UriDoesNotDeriveFromThePair {
            uri: manifest.uri.clone(),
        });
    }
    if !is_exact_address(&manifest.source_address) {
        return Err(ReaderRefusal::SourceAddressNotExact {
            source_address: manifest.source_address.clone(),
        });
    }
    match socket {
        Socket::NotObserved => Err(ReaderRefusal::SocketNotObserved),
        Socket::NotListening => Ok(ReaderState::Closed),
        Socket::Listening => {
            if manifest.status == STATUS_REVOKED {
                // The socket is up and the only identity it knows is revoked:
                // nothing is served. It is a closure, and it is the closure the
                // product reaches without restarting the Relay.
                return Ok(ReaderState::Closed);
            }
            Ok(ReaderState::OpenTo {
                controller_id: controller_id.clone(),
                source_address: manifest.source_address.clone(),
            })
        }
    }
}

/// The proof that the reader was closed across the whole switch and came back
/// open to the new Controller alone, on a reprovisioned address.
///
/// It cannot be built by naming its fields and [`rotate`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderRotation {
    controller_id: String,
    samples: usize,
}

impl ReaderRotation {
    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    /// How many times the reader was actually looked at while it was supposed
    /// to be closed. A report that says "closed" over one sample and a report
    /// that says it over nine are different reports.
    pub fn samples(&self) -> usize {
        self.samples
    }
}

/// The one gate. Nothing else in this crate builds a [`ReaderRotation`].
///
/// `during` is every state sampled between the moment the old reader was closed
/// and the moment the new one was opened — one per transition of the plan. An
/// empty slice is refused rather than read as "it was never open".
pub fn rotate(
    during: &[ReaderState],
    after: &ReaderState,
    old_controller_id: &str,
    new_controller_id: &str,
    old_source_address: &str,
) -> Result<ReaderRotation, ReaderRefusal> {
    identifier(old_controller_id, "old_controller_id")?;
    identifier(new_controller_id, "new_controller_id")?;
    if during.is_empty() {
        return Err(ReaderRefusal::NeverSampledDuringTheSwitch);
    }
    for state in during {
        if let ReaderState::OpenTo { controller_id, .. } = state {
            return Err(ReaderRefusal::OpenDuringTheSwitch {
                controller_id: controller_id.clone(),
            });
        }
    }
    let ReaderState::OpenTo {
        controller_id,
        source_address,
    } = after
    else {
        return Err(ReaderRefusal::NeverReopened);
    };
    if controller_id.as_str() == old_controller_id {
        return Err(ReaderRefusal::StillOpenToTheOldController);
    }
    if controller_id.as_str() != new_controller_id {
        return Err(ReaderRefusal::OpenToAnotherController {
            controller_id: controller_id.clone(),
        });
    }
    if source_address.as_str() == old_source_address {
        return Err(ReaderRefusal::SourceAddressNotReprovisioned {
            source_address: source_address.clone(),
        });
    }
    Ok(ReaderRotation {
        controller_id: controller_id.clone(),
        samples: during.len(),
    })
}

fn identifier(value: &str, field: &'static str) -> Result<(), ReaderRefusal> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.contains(char::is_whitespace)
        || value.contains(':')
    {
        return Err(ReaderRefusal::MalformedIdentifier { field });
    }
    Ok(())
}

/// One exact IPv4 address, the way the listener wants it: four decimal octets,
/// no prefix length, no range, no name.
fn is_exact_address(value: &str) -> bool {
    let mut octets = 0;
    for part in value.split('.') {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u8>().is_err() {
            return false;
        }
        octets += 1;
    }
    octets == 4
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFRASTRUCTURE: &str = "infrastructure-1";
    const OLD: &str = "controller-old";
    const NEW: &str = "controller-new";
    const OLD_ADDRESS: &str = "192.0.2.10";
    const NEW_ADDRESS: &str = "192.0.2.11";

    fn manifest(controller_id: &str, source_address: &str) -> ReaderManifest {
        ReaderManifest {
            infrastructure_id: INFRASTRUCTURE.into(),
            authorized_controller_ids: vec![controller_id.into()],
            uri: reader_uri(INFRASTRUCTURE, controller_id),
            source_address: source_address.into(),
            status: STATUS_ACTIVE.into(),
            port: READER_PORT,
        }
    }

    fn open(controller_id: &str, source_address: &str) -> ReaderState {
        read(&manifest(controller_id, source_address), Socket::Listening)
            .expect("the open fixture must read")
    }

    fn closed() -> ReaderState {
        read(&manifest(OLD, OLD_ADDRESS), Socket::NotListening)
            .expect("the closed fixture must read")
    }

    /// The positive control: a manifest naming one Controller, on a listening
    /// socket, is open to that Controller and to nobody else.
    #[test]
    fn one_manifest_and_one_listening_socket_open_the_reader_to_one_controller() {
        assert_eq!(
            open(NEW, NEW_ADDRESS),
            ReaderState::OpenTo {
                controller_id: NEW.into(),
                source_address: NEW_ADDRESS.into(),
            }
        );
    }

    /// **The crown refusal.** A manifest naming two Controllers is refused
    /// outright — not resolved to the first, not resolved to the last.
    #[test]
    fn a_manifest_naming_two_controllers_is_refused_rather_than_resolved() {
        let mut both = manifest(NEW, NEW_ADDRESS);
        both.authorized_controller_ids = vec![OLD.into(), NEW.into()];

        assert_eq!(
            read(&both, Socket::Listening),
            Err(ReaderRefusal::TwoControllers {
                first: OLD.into(),
                second: NEW.into(),
            })
        );
        // And a socket that is down does not make it acceptable either: the
        // document is refused before the socket is consulted.
        assert_eq!(
            read(&both, Socket::NotListening),
            Err(ReaderRefusal::TwoControllers {
                first: OLD.into(),
                second: NEW.into(),
            })
        );
    }

    /// **The property the switch rests on.** Every sample taken while the
    /// switch was running must be a closure; one open sample denies the whole
    /// rotation and names who it was open to.
    #[test]
    fn one_open_sample_during_the_switch_denies_the_rotation() {
        assert_eq!(
            rotate(
                &[closed(), open(OLD, OLD_ADDRESS), closed()],
                &open(NEW, NEW_ADDRESS),
                OLD,
                NEW,
                OLD_ADDRESS,
            ),
            Err(ReaderRefusal::OpenDuringTheSwitch {
                controller_id: OLD.into()
            })
        );
        // The positive control differs by exactly that one sample.
        let rotation = rotate(
            &[closed(), closed(), closed()],
            &open(NEW, NEW_ADDRESS),
            OLD,
            NEW,
            OLD_ADDRESS,
        )
        .expect("the positive control must rotate");
        assert_eq!(rotation.controller_id(), NEW);
        assert_eq!(rotation.samples(), 3);
    }

    /// A switch nobody looked at is not a switch anybody can call closed.
    #[test]
    fn a_switch_that_was_never_sampled_is_refused() {
        assert_eq!(
            rotate(&[], &open(NEW, NEW_ADDRESS), OLD, NEW, OLD_ADDRESS),
            Err(ReaderRefusal::NeverSampledDuringTheSwitch)
        );
    }

    /// A failed sample is not a closure. It is the same distinction the
    /// preflight makes between "unreachable" and "no answer".
    #[test]
    fn a_sample_that_failed_is_never_read_as_a_closure() {
        assert_eq!(
            read(&manifest(OLD, OLD_ADDRESS), Socket::NotObserved),
            Err(ReaderRefusal::SocketNotObserved)
        );
    }

    /// The reader coming back to the old Controller, or to a third one, is
    /// refused under two different names.
    #[test]
    fn the_reader_never_comes_back_to_the_old_controller_or_to_a_stranger() {
        assert_eq!(
            rotate(&[closed()], &open(OLD, NEW_ADDRESS), OLD, NEW, OLD_ADDRESS),
            Err(ReaderRefusal::StillOpenToTheOldController)
        );
        assert_eq!(
            rotate(
                &[closed()],
                &open("controller-third", NEW_ADDRESS),
                OLD,
                NEW,
                OLD_ADDRESS,
            ),
            Err(ReaderRefusal::OpenToAnotherController {
                controller_id: "controller-third".into()
            })
        );
        assert_eq!(
            rotate(&[closed()], &closed(), OLD, NEW, OLD_ADDRESS),
            Err(ReaderRefusal::NeverReopened)
        );
    }

    /// The client identity and its source address are reprovisioned together.
    /// A reader that came back on the old address still admits a route the old
    /// host holds.
    #[test]
    fn the_reader_never_comes_back_on_the_old_source_address() {
        assert_eq!(
            rotate(&[closed()], &open(NEW, OLD_ADDRESS), OLD, NEW, OLD_ADDRESS),
            Err(ReaderRefusal::SourceAddressNotReprovisioned {
                source_address: OLD_ADDRESS.into()
            })
        );
    }

    /// A revoked manifest closes the reader even while the socket is up. It is
    /// the closure the product reaches without stopping the Relay, and it is a
    /// closure and not a half-measure.
    #[test]
    fn a_revoked_manifest_closes_the_reader_on_a_listening_socket() {
        let revoked = ReaderManifest {
            status: STATUS_REVOKED.into(),
            ..manifest(OLD, OLD_ADDRESS)
        };
        assert_eq!(read(&revoked, Socket::Listening), Ok(ReaderState::Closed));
    }

    /// A manifest with no Controller at all is refused rather than read as a
    /// closure: an empty authority is not a revoked one.
    #[test]
    fn a_manifest_naming_no_controller_is_refused_rather_than_read_as_closed() {
        let mut empty = manifest(NEW, NEW_ADDRESS);
        empty.authorized_controller_ids.clear();
        assert_eq!(
            read(&empty, Socket::NotListening),
            Err(ReaderRefusal::NoController)
        );
    }

    /// The name and the claim cannot drift apart: a `uri` that does not derive
    /// from the declared pair is a second identity.
    #[test]
    fn a_uri_that_does_not_derive_from_the_pair_is_refused() {
        let mut drifted = manifest(NEW, NEW_ADDRESS);
        drifted.uri = reader_uri(INFRASTRUCTURE, OLD);
        assert_eq!(
            read(&drifted, Socket::Listening),
            Err(ReaderRefusal::UriDoesNotDeriveFromThePair {
                uri: reader_uri(INFRASTRUCTURE, OLD)
            })
        );
        assert!(reader_uri(INFRASTRUCTURE, NEW).starts_with(READER_URI_PREFIX));
    }

    /// The port is the reader's, and the source is one exact address rather
    /// than a range a whole subnet could answer from.
    #[test]
    fn a_wrong_port_or_a_range_instead_of_one_address_is_refused() {
        assert_eq!(
            read(
                &ReaderManifest {
                    port: 8443,
                    ..manifest(NEW, NEW_ADDRESS)
                },
                Socket::Listening
            ),
            Err(ReaderRefusal::WrongPort { port: 8443 })
        );
        for hostile in [
            "192.0.2.0/24",
            "",
            "relay.example",
            "192.0.2",
            "192.0.2.256",
        ] {
            assert_eq!(
                read(&manifest(NEW, hostile), Socket::Listening),
                Err(ReaderRefusal::SourceAddressNotExact {
                    source_address: hostile.into()
                }),
                "{hostile:?} must not pass for one exact address"
            );
        }
    }

    /// A status outside the product's closed set is a manifest this module does
    /// not read, not a status it tolerates.
    #[test]
    fn a_status_outside_the_closed_set_is_refused() {
        assert_eq!(
            read(
                &ReaderManifest {
                    status: "pending".into(),
                    ..manifest(NEW, NEW_ADDRESS)
                },
                Socket::Listening
            ),
            Err(ReaderRefusal::UnknownStatus {
                status: "pending".into()
            })
        );
    }
}
