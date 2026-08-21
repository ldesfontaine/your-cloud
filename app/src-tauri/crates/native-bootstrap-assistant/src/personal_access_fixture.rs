//! Hardened fixture process of the personal access contract.
//!
//! It carries no logic of its own: everything it does lives behind
//! [`your_cloud_native_bootstrap_assistant::personal_access_contract_main`],
//! so the process the suite kills, searches and dumps is hardened exactly as
//! the helper is rather than approximately like it.

use std::process;

use your_cloud_native_bootstrap_assistant::personal_access_contract_main;

fn main() {
    process::exit(personal_access_contract_main().into());
}
