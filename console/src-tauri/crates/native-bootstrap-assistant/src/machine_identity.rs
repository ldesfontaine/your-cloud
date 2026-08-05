//! Enrolling one approved machine with an SSH identity that is bounded to it.
//!
//! This is the palier where the user's personal SSH access stops being the
//! administration path. The Controller acquires an identity of its own on every
//! machine, and the whole value of the module is in what that identity *cannot*
//! do: it opens no shell, no PTY, no SFTP, no forwarding, it carries no
//! environment, it runs one absolute command with no free argument, and — the
//! property everything else is built around — **it is refused on every machine
//! but its own**.
//!
//! The split of [`super::installation`] is kept, and for the same reason. Every
//! module here decides on values already in hand and acts on nothing: no file
//! is opened, no process is spawned, no address is dialled. The session of the
//! earlier paliers owns those, and a second actor here would give the enrolment
//! a second place to be interrupted in.
//!
//! ## What is reused, and why nothing is re-decided
//!
//! | Fact | Witness | Built by |
//! |------|---------|----------|
//! | every endpoint answered the Controller | `installation::preflight::PreflightCleared` | #38 |
//! | root was really reached | `personal_access::elevation::Elevation` | #54 |
//! | this machine's roles were approved | `personal_access::placement::ApprovedPlacement` | #36 |
//! | this machine has an identity nobody else has | [`identity::Enrolled`] | this module |
//!
//! An interrupted enrolment is undone by the very ledger of #38 —
//! `installation::rollback::Ledger` — with the same three provenances and the
//! same refusal to remove what it did not create. There is no second rollback
//! here, because a second rollback is a second set of rules to be wrong in.
//!
//! ## The order is the security property
//!
//! [`plan::STEPS`] installs the artefact before the forced key is reachable and
//! verifies the new path before any role is activated. Both are asserted on the
//! shape of the sequence rather than on a check somebody remembered to write:
//! "could a key be activated with no binary behind it" is answered by reading
//! one constant.
//!
//! ## What this palier does not do
//!
//! It performs no mutation on the enrolled machine beyond its own enrolment.
//! The Auxiliary it makes reachable is the read-only protocol diagnostic of
//! #37, and [`plan::verify`] refuses a report that claims otherwise. The first
//! OCI mutation, the general shell and the free SSH primitive belong to no
//! palier this module prepares.

/// The locked technical account the bounded identity is tied to.
pub mod account;
/// Ownership and modes of the key file, of its parents and of the binary.
pub mod custody;
/// The `sudo` rule, bounded to one exact invocation.
pub mod elevation_rule;
/// The `authorized_keys` entry: its forced command and its refusals.
pub mod entry;
/// One identity per machine, and its refusal on every other one.
pub mod identity;
/// The ordered enrolment, its witnesses, and the activation of approved roles.
pub mod plan;
