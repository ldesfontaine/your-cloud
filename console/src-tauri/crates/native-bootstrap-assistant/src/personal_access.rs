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
//! [`agent_endpoint`]'s system read, [`agent_client`], [`session`] — performs
//! the exact operations the decisions were written for, and nothing else: one
//! interface enumeration, one name resolution, one `stat`, one agent
//! connection, one transport, one channel. Each of them hands its observation
//! back to the deciding half rather than judging it on the spot.
//!
//! Opening an encrypted key file belongs to #53 and any elevation to #54.

pub mod agent_client;
pub mod agent_endpoint;
pub mod algorithms;
pub mod host_key;
pub mod local_addresses;
pub mod openssh_key;
pub mod resolver;
/// The acting half is wired to Linux only for now: it connects to the agent
/// through a Unix socket and reads the endpoint the Linux rule judges. The
/// Windows pass of this palier brings its own named pipe endpoint, and until
/// it exists nothing here may pretend to be portable.
#[cfg(target_os = "linux")]
pub mod session;
pub mod signature_budget;
pub mod ssh_algorithms;
pub mod sudo_policy;
pub mod target;
