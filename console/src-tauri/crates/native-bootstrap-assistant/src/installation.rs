//! Installing one Controller from the embedded bundle.
//!
//! Every palier before this one observed, judged or refused. This one is the
//! first that mutates a machine, so the modules here are organised around the
//! single question that matters when it goes wrong: *what is true, and what is
//! merely hoped, at the instant the sequence stops?*
//!
//! The split of [`super::personal_access`] is kept, and for the same reason.
//! [`bundle`], [`preflight`], [`association`] and [`rollback`] decide on values
//! already in hand and act on nothing; [`plan`] is the one place where the four
//! decisions are required together before a privileged command may run. Nothing
//! in this module opens a file, spawns a process or dials an address — the
//! session of the previous paliers already owns those, and adding a second
//! actor here would give the installation two places to be interrupted in.
//!
//! ## The witnesses, and why they are types
//!
//! Four things must be true before the first privileged act:
//!
//! | Fact | Witness | Built by |
//! |------|---------|----------|
//! | the bundle is the bundle | [`bundle::VerifiedBundle`] | [`bundle::verify`] |
//! | root was really reached | `personal_access::elevation::Elevation` | `elevation::elevated` (#54) |
//! | the placement is private, approved, normally on | `personal_access::placement::ApprovedPlacement` | `placement::approve` (#36) |
//! | every endpoint answered the Controller | [`preflight::PreflightCleared`] | [`preflight::clear`] |
//!
//! None of the four can be built by naming its fields, and each has exactly one
//! constructor. [`plan::authorize`] asks for all four by type. That is the whole
//! mechanism: "could something privileged happen without X" is answered by
//! reading one function signature, not by auditing every call site.
//!
//! ## What this palier does not do
//!
//! It does not touch the other machines. The scope of #38 stops at the
//! preflight, and [`plan::STEPS`] has no step past it — installing the artefact,
//! the technical account and the forced command on each target belongs to the
//! next palier, which will have to be handed a [`preflight::PreflightCleared`]
//! to get there. It does not replace an existing Controller either, and it
//! never transfers authority: [`rollback::Ledger::authority_transferred`] exists
//! to mark the boundary past which this module stops answering, not to cross it.

/// Les octets de ce qui agit, et le témoin sans lequel aucun ne part.
pub mod acts;
/// L'ancre de release, scellée dans ce binaire à la compilation.
pub mod anchor;
/// Binding one Console to one Controller, freshly and for one infrastructure.
pub mod association;
/// Judging the embedded `.deb` and its signed manifest before any privilege.
pub mod bundle;
/// La configuration propre à la machine, produite ici et jugée comme le lot.
pub mod configuration;
/// La résolution du lot embarqué depuis la position attestée, et depuis rien
/// d'autre.
pub mod embedded;
/// Ce que la machine dit des nœuds que l'Assistant possède, hors inventaire
/// `dpkg`.
pub mod nodes;
/// Ce que la machine dit du paquet, avant l'acte et après lui.
pub mod package;
/// The ordered sequence, and the four witnesses it may not be built without.
pub mod plan;
/// Reaching every declared endpoint from the Controller, before any other
/// machine is touched.
pub mod preflight;
/// What a failure may take back, and what it must leave visible.
pub mod rollback;
/// L'ordonnanceur : il enchaîne, il n'invente rien.
pub mod sequence;
/// Le lot posé sur la cible, sous le seul accès personnel, et son empreinte
/// relue là-bas.
pub mod transfer;
/// Ce que la machine dit de l'unité activée : elle tourne, et elle est
/// confinée.
pub mod unit;
