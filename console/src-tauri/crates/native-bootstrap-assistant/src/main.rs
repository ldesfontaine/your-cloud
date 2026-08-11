use std::{ffi::OsStr, process::ExitCode};

use your_cloud_native_bootstrap_assistant as assistant;

/// The two modes this process answers to, chosen by the invocation and never by
/// a document. A mode a document decided would be a process whose behaviour the
/// document decides; a mode the invocation decides is a process whose behaviour
/// the parent decides, and the parent is attested.
///
/// Anything that is not the approval mode falls to the bootstrap session, which
/// holds its own invocation to exactly one argument and refuses everything else.
fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let approval =
        arguments.next().as_deref() == Some(OsStr::new(assistant::REQUIRED_APPROVAL_MODE_ARGUMENT));
    let code = if approval {
        assistant::approval_consent_main()
    } else {
        assistant::process_main()
    };
    ExitCode::from(code)
}
