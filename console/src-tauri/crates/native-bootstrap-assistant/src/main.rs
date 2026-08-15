use std::{ffi::OsStr, process::ExitCode};

use your_cloud_native_bootstrap_assistant as assistant;

/// The three modes this process answers to, chosen by the invocation and never
/// by a document. A mode a document decided would be a process whose behaviour
/// the document decides; a mode the invocation decides is a process whose
/// behaviour the invoker decides — and what attests the invoker is the parent
/// contract for the two dialoguing modes, the position contract for the third,
/// which dialogues with nobody and derives everything from `/proc/self/exe`.
///
/// Anything that is not a named mode falls to the bootstrap session, which
/// holds its own invocation to exactly one argument and refuses everything else.
fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next();
    let code = if mode.as_deref() == Some(OsStr::new(assistant::REQUIRED_APPROVAL_MODE_ARGUMENT)) {
        assistant::approval_consent_main()
    } else if mode.as_deref()
        == Some(OsStr::new(
            assistant::REQUIRED_VERIFY_EMBEDDED_MODE_ARGUMENT,
        ))
    {
        assistant::verify_embedded_main()
    } else {
        assistant::process_main()
    };
    ExitCode::from(code)
}
