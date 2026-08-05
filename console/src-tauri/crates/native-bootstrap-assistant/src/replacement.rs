//! Replacing one Controller explicitly, and leaving the old one no exposed
//! authority.
//!
//! Every palier before this one acted on something that was true. This one acts
//! on something nobody knows: a Controller that does not answer may be a
//! Controller that is off, a network that is lying, or a host somebody else is
//! holding. The modules here are therefore organised around the one question
//! that decides whether anything may happen at all — *what do we actually know,
//! and who told us?*
//!
//! The split of [`super::installation`] and [`super::machine_identity`] is kept,
//! and for the same reason. [`incident`], [`succession`], [`inheritance`],
//! [`reader`], [`withdrawal`] and [`transition`] decide on values already in
//! hand and act on nothing; [`plan`] is the one place where the decisions are
//! required together before a privileged command may run. Nothing in this module
//! opens a file, spawns a process or dials an address.
//!
//! ## The danger is not failing the replacement
//!
//! The danger is succeeding at it too quickly. A healthy Controller silently
//! overwritten, or a switch taken on an ambiguous failure, are worse outcomes
//! than a refusal — the refusal costs an evening, the other two cost the
//! infrastructure. Three separate things therefore have to happen before the
//! first mutation, and none of them is a check a caller could forget:
//!
//! | Fact | Witness | Built by |
//! |------|---------|----------|
//! | the user asked for this, on a failure that is not ambiguous | [`incident::QualifiedIncident`] | [`incident::qualify`] |
//! | the new Controller is new, and the infrastructure is the same one | [`succession::Succession`] | [`succession::succeed`] |
//! | one Console is bound to it, freshly | `installation::association::Association` | #38 |
//! | root was really reached | `personal_access::elevation::Elevation` | #54 |
//! | every endpoint answered the new Controller | `installation::preflight::PreflightCleared` | #38 |
//!
//! [`plan::authorize`] asks for all five by type and re-derives none of them.
//!
//! ## What is reused, and why nothing is re-decided
//!
//! The registry of #38 — `installation::rollback::Ledger`, its three provenances
//! and its refusal to remove what it did not create — is the registry a cut
//! replacement is undone by. There is no second ledger here, because a second
//! ledger is a second set of rules to be wrong in. The proof that a machine
//! really answered its new identity is #39's `machine_identity::plan::PathVerified`,
//! and [`withdrawal::withdraw`] asks for it by type: "could an old key be
//! removed before the new one was verified" is answered by reading one
//! signature. The one-time, window-bounded binding of a Console to a Controller
//! is #38's `installation::association::bind`, used here exactly as the creation
//! uses it.
//!
//! ## What this palier does not do
//!
//! It never fails over. Nothing in [`plan::STEPS`] is reached without
//! [`incident::qualify`] having been handed an explicit human request, and no
//! amount of unavailability produces one. It does not restore service data, it
//! does not rebuild an inventory, and it does not offer a third SSH authority or
//! an offline escrow: those are named as absent in the architecture, and adding
//! one here would be adding an authority the replacement is supposed to remove.

/// What the user asked for, on which incident, and everything that must be true
/// before the word « replacement » may be used at all.
pub mod incident;
/// What the new Controller may start with, and what the old one may not keep.
pub mod inheritance;
/// The ordered replacement, its witnesses, and the one gate a secured outcome
/// may ever be announced through.
pub mod plan;
/// The Relay reader: closed across the switch, and never open to two
/// Controllers.
pub mod reader;
/// A fresh Controller identifier, and the infrastructure identifier that is
/// kept only after independent states concur.
pub mod succession;
/// The four states a target may be left in, rebuilt from the machine after a
/// cut rather than replayed from what the run believed.
pub mod transition;
/// What may be taken away once the new authority answered — and everything that
/// may not be, whoever asks.
pub mod withdrawal;
