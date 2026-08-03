//! Pure policy of the personal SSH access.
//!
//! This module decides; it never acts. It opens no connection, spawns no
//! process, reads no key material and collects no secret. Its only inputs are
//! bytes already in hand — a key file envelope, a public `sudo` listing — and
//! its only outputs are accept/refuse decisions with an explicit reason.
//!
//! It exists so the bounds of the personal access are fixed and testable
//! before anything privileged happens. The connection belongs to #52, the
//! encrypted key opening to #53 and the elevation to #54.

pub mod agent_endpoint;
pub mod algorithms;
pub mod openssh_key;
pub mod signature_budget;
pub mod ssh_algorithms;
pub mod sudo_policy;
pub mod target;
