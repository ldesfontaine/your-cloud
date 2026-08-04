//! Hostile pipe server of the Windows agent pipe contract.
//!
//! It carries no logic of its own: everything it does lives behind
//! [`your_cloud_native_bootstrap_assistant::personal_access::agent_pipe::hostile_agent_pipe_fixture_main`],
//! so what the suite confronts the helper with is one separate process holding
//! the OpenSSH pipe name, and nothing this file could quietly add to it.

use std::process;

use your_cloud_native_bootstrap_assistant::personal_access::agent_pipe::hostile_agent_pipe_fixture_main;

fn main() {
    process::exit(hostile_agent_pipe_fixture_main().into());
}
