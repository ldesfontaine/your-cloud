//! Bounds and transport of the personal SSH access.
//!
//! The module is split in two halves that must not blur into one another.
//!
//! The **deciding** half — [`algorithms`], [`host_key`], [`openssh_key`],
//! [`signature_budget`], [`ssh_algorithms`], [`sudo_policy`], [`target`] —
//! never acts. Its only inputs are bytes already in hand and its only outputs
//! are accept/refuse decisions with an explicit reason, which is what makes
//! every bound testable without a live agent or a live server.
//!
//! The **observing and acting** half — [`local_addresses`], [`resolver`],
//! [`agent_endpoint`]'s system read, `agent_pipe`, [`agent_client`],
//! [`session`] — performs the exact operations the decisions were written for,
//! and nothing else: one interface enumeration, one name resolution, one
//! `stat` or one pipe attestation, one agent connection, one transport, one
//! channel. Each of them hands its observation back to the deciding half
//! rather than judging it on the spot.
//!
//! The fallback of #53 — [`key_file`], [`key_unlock`], [`key_signer`] — follows
//! the same split, and joins the acting half rather than doubling it: the key it
//! opens becomes a signer for the very transport, the very probe and the very
//! signature budget the agent path already uses. Any elevation belongs to #54.

pub mod agent_client;
pub mod agent_endpoint;
/// The Windows endpoint: the fixed OpenSSH pipe, and the attestation of the
/// process serving it. It has no Linux counterpart because a Unix socket
/// carries its own owner and mode, which [`agent_endpoint`] reads directly.
#[cfg(target_os = "windows")]
pub mod agent_pipe;
pub mod algorithms;
pub mod host_key;
/// Opening the personal key file the native selector answered, on the system
/// that carries `O_NOFOLLOW` and an inode. It is the observing half of
/// [`openssh_key`], which decides on bytes already in hand.
#[cfg(target_os = "linux")]
pub mod key_file;
/// Turning the opened key into a signer that spends the budget of #52. It is
/// compiled beside the file it serves, and for the same reason.
#[cfg(target_os = "linux")]
pub mod key_signer;
/// Paying for the key derivation under the session's own deadline.
#[cfg(target_os = "linux")]
pub mod key_unlock;
pub mod local_addresses;
pub mod openssh_key;
pub mod resolver;
/// The acting half, on both platforms the palier targets. The session is one
/// sequence — local addresses, one resolution, one agent endpoint, one
/// transport, one probe — and only the endpoint differs: a Unix socket the
/// Linux rule judges, or the attested OpenSSH pipe `agent_pipe` opens. What
/// the two share is everything after it, so a bound proved on one is the bound
/// the other runs.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod session;
pub mod signature_budget;
pub mod ssh_algorithms;
pub mod sudo_policy;
pub mod target;
