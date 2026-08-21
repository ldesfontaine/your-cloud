//! Binding this App to this Controller, freshly and for one infrastructure.
//!
//! The Controller is the thing that outlives the laptop. What ties the two
//! together therefore has to be narrow in two directions at once: it must be
//! *fresh*, so a sheet observed once cannot be presented again later, and it
//! must be *bounded to the infrastructure*, so an association obtained for one
//! infrastructure never speaks for another.
//!
//! **Freshness is a window and a single use, not one or the other.** A window
//! alone would let the same sheet be presented twice inside it; a single use
//! alone would let a sheet kept for a month still work. [`bind`] requires both,
//! and the caller passes the offers already consumed so the second presentation
//! of the same sheet is refused by this module rather than by whatever happens
//! to notice first.
//!
//! **The clock is an input, never a reading.** This module takes `now` as an
//! argument. It has no business deciding what time it is, and a test that could
//! not choose the instant could not exercise the boundary at all.

/// The longest an offer may claim to live. The window exists so a human can
/// answer a prompt, not so a sheet can be filed away: an offer asking for more
/// is refused rather than silently clamped, because a clamp would let a
/// Controller ask for a month and receive ten minutes without ever being told.
pub const MAX_LIFETIME_SECONDS: u64 = 600;

/// Identifiers are opaque here, but they are not unbounded: a value longer than
/// this is refused before it is compared or reported.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// What the Controller offered the App.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssociationOffer {
    /// The infrastructure the Controller was just initialised for.
    pub infrastructure_id: String,
    /// The Controller itself.
    pub controller_id: String,
    /// The one-time value of this offer. Two offers never share one.
    pub sheet_id: String,
    pub issued_at_unix_seconds: u64,
    pub lifetime_seconds: u64,
}

/// Why an association was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssociationRefusal {
    /// An identifier is empty or longer than [`MAX_IDENTIFIER_BYTES`].
    IdentifierMalformed { field: &'static str },
    /// The offer claims to live longer than an offer may.
    LifetimeTooLong,
    /// The offer has no lifetime at all, so it is either already over or
    /// unbounded depending on who reads it.
    LifetimeMissing,
    /// The window has closed.
    Expired,
    /// The offer is stamped in the future. It is refused rather than tolerated:
    /// accepting it would make the window longer than it claims to be.
    NotYetValid,
    /// This sheet has already been used.
    AlreadyUsed,
    /// The offer names an infrastructure other than the one being created.
    ForeignInfrastructure { announced: String },
}

/// The proof that one App was bound to one Controller for one
/// infrastructure, inside the window and for the first time.
///
/// It cannot be built by naming its fields and [`bind`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Association {
    infrastructure_id: String,
    controller_id: String,
    sheet_id: String,
}

impl Association {
    pub fn infrastructure_id(&self) -> &str {
        &self.infrastructure_id
    }

    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    /// The sheet this association consumed. The caller adds it to the used set
    /// so the next call refuses it.
    pub fn sheet_id(&self) -> &str {
        &self.sheet_id
    }
}

/// The one gate. Nothing else in this crate builds an [`Association`].
///
/// `expected_infrastructure` is the infrastructure the Assistant is creating,
/// known from the Controller's own initialisation. An offer that authenticates
/// but names another infrastructure is a valid offer about something else.
pub fn bind(
    offer: &AssociationOffer,
    expected_infrastructure: &str,
    already_used: &[String],
    now_unix_seconds: u64,
) -> Result<Association, AssociationRefusal> {
    identifier(&offer.infrastructure_id, "infrastructure_id")?;
    identifier(&offer.controller_id, "controller_id")?;
    identifier(&offer.sheet_id, "sheet_id")?;
    identifier(expected_infrastructure, "expected_infrastructure")?;

    if offer.lifetime_seconds == 0 {
        return Err(AssociationRefusal::LifetimeMissing);
    }
    if offer.lifetime_seconds > MAX_LIFETIME_SECONDS {
        return Err(AssociationRefusal::LifetimeTooLong);
    }
    if offer.infrastructure_id != expected_infrastructure {
        return Err(AssociationRefusal::ForeignInfrastructure {
            announced: offer.infrastructure_id.clone(),
        });
    }
    if now_unix_seconds < offer.issued_at_unix_seconds {
        return Err(AssociationRefusal::NotYetValid);
    }
    // Saturating rather than wrapping: an offer stamped near the end of the
    // representable range must expire, not wrap around into the distant past
    // and become eternally valid.
    let expires_at = offer
        .issued_at_unix_seconds
        .saturating_add(offer.lifetime_seconds);
    if now_unix_seconds >= expires_at {
        return Err(AssociationRefusal::Expired);
    }
    if already_used.iter().any(|used| used == &offer.sheet_id) {
        return Err(AssociationRefusal::AlreadyUsed);
    }
    Ok(Association {
        infrastructure_id: offer.infrastructure_id.clone(),
        controller_id: offer.controller_id.clone(),
        sheet_id: offer.sheet_id.clone(),
    })
}

fn identifier(value: &str, field: &'static str) -> Result<(), AssociationRefusal> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(AssociationRefusal::IdentifierMalformed { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFRASTRUCTURE: &str = "infrastructure-1";

    fn offer() -> AssociationOffer {
        AssociationOffer {
            infrastructure_id: INFRASTRUCTURE.into(),
            controller_id: "controller-1".into(),
            sheet_id: "sheet-1".into(),
            issued_at_unix_seconds: 1_000,
            lifetime_seconds: 300,
        }
    }

    /// The positive control.
    #[test]
    fn a_fresh_offer_for_this_infrastructure_binds() {
        let association =
            bind(&offer(), INFRASTRUCTURE, &[], 1_100).expect("the positive control must bind");

        assert_eq!(association.infrastructure_id(), INFRASTRUCTURE);
        assert_eq!(association.controller_id(), "controller-1");
        assert_eq!(association.sheet_id(), "sheet-1");
    }

    /// Freshness is a window: the same offer stops binding once it closes, and
    /// the boundary is exclusive.
    #[test]
    fn the_window_closes_exactly_when_it_says_it_does() {
        assert!(bind(&offer(), INFRASTRUCTURE, &[], 1_299).is_ok());
        assert_eq!(
            bind(&offer(), INFRASTRUCTURE, &[], 1_300),
            Err(AssociationRefusal::Expired)
        );
    }

    /// Freshness is also a single use: inside the window, the second
    /// presentation of the same sheet is refused.
    #[test]
    fn a_sheet_already_used_does_not_bind_again_inside_its_own_window() {
        let used = vec!["sheet-1".to_owned()];

        assert_eq!(
            bind(&offer(), INFRASTRUCTURE, &used, 1_100),
            Err(AssociationRefusal::AlreadyUsed)
        );
    }

    /// The bound half: a perfectly fresh offer for another infrastructure is
    /// a valid offer about something else.
    #[test]
    fn an_offer_for_another_infrastructure_is_refused() {
        assert_eq!(
            bind(&offer(), "infrastructure-2", &[], 1_100),
            Err(AssociationRefusal::ForeignInfrastructure {
                announced: INFRASTRUCTURE.into()
            })
        );
    }

    /// An offer stamped in the future would stretch its own window.
    #[test]
    fn an_offer_from_the_future_is_refused_rather_than_tolerated() {
        assert_eq!(
            bind(&offer(), INFRASTRUCTURE, &[], 999),
            Err(AssociationRefusal::NotYetValid)
        );
    }

    /// A lifetime past the bound is refused, not silently clamped.
    #[test]
    fn a_lifetime_longer_than_the_bound_is_refused_not_clamped() {
        let mut greedy = offer();
        greedy.lifetime_seconds = MAX_LIFETIME_SECONDS + 1;

        assert_eq!(
            bind(&greedy, INFRASTRUCTURE, &[], 1_100),
            Err(AssociationRefusal::LifetimeTooLong)
        );

        let mut none = offer();
        none.lifetime_seconds = 0;
        assert_eq!(
            bind(&none, INFRASTRUCTURE, &[], 1_100),
            Err(AssociationRefusal::LifetimeMissing)
        );
    }

    /// An offer stamped at the end of the representable range expires rather
    /// than wrapping into eternal validity.
    #[test]
    fn an_offer_at_the_end_of_time_expires_rather_than_wrapping() {
        let mut extreme = offer();
        extreme.issued_at_unix_seconds = u64::MAX - 1;
        extreme.lifetime_seconds = 300;

        assert_eq!(
            bind(&extreme, INFRASTRUCTURE, &[], u64::MAX),
            Err(AssociationRefusal::Expired)
        );
    }

    #[test]
    fn an_empty_or_oversized_identifier_is_refused_by_name() {
        let mut nameless = offer();
        nameless.controller_id = String::new();
        assert_eq!(
            bind(&nameless, INFRASTRUCTURE, &[], 1_100),
            Err(AssociationRefusal::IdentifierMalformed {
                field: "controller_id"
            })
        );

        let mut oversized = offer();
        oversized.sheet_id = "s".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert_eq!(
            bind(&oversized, INFRASTRUCTURE, &[], 1_100),
            Err(AssociationRefusal::IdentifierMalformed { field: "sheet_id" })
        );
    }
}
