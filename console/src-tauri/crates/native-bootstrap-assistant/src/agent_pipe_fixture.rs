//! The two halves of the Windows agent pipe contract that need a process of
//! their own.
//!
//! It carries no logic of its own: everything it does lives behind
//! [`your_cloud_native_bootstrap_assistant::personal_access::agent_pipe::hostile_agent_pipe_fixture_main`]
//! and its attesting counterpart, so what the suite confronts the helper with
//! is one separate process holding the OpenSSH pipe name — and, when asked, one
//! separate process running the real attestation under whatever identity it was
//! started with, with nothing this file could quietly add to either.
//!
//! Without an argument it serves the hostile pipe; with `attest` it attests.
//! Anything else is refused rather than guessed at.

use std::process;

use your_cloud_native_bootstrap_assistant::personal_access::agent_pipe::{
    attesting_agent_pipe_fixture_main, hostile_agent_pipe_fixture_main,
};

/// What an unusable invocation returns, distinct from the fixture's own failure
/// so a mistyped role can never read as a fixture that merely did badly.
const UNKNOWN_ROLE: u8 = 2;

fn main() {
    let mut arguments = std::env::args().skip(1);
    let role = arguments.next();
    let code = match (role.as_deref(), arguments.next()) {
        (None, _) => hostile_agent_pipe_fixture_main(),
        (Some("attest"), None) => attesting_agent_pipe_fixture_main(),
        _ => UNKNOWN_ROLE,
    };
    process::exit(code.into());
}
