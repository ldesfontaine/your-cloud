mod framing;
mod hardening;
#[cfg(target_os = "linux")]
mod native_prompt;
mod watchdog;

use std::{
    ffi::{OsStr, OsString},
    io,
    time::{Duration, Instant},
};

use framing::ReadFrameError;
use your_cloud_bootstrap_protocol::{
    AssistantEventKind, AssistantEventV1, AssistantScopeV1, ASSISTANT_EXIT_CANCELLED,
    ASSISTANT_EXIT_INTERNAL_FAILURE, ASSISTANT_EXIT_INVALID_INVOCATION, ASSISTANT_EXIT_IO_FAILURE,
    ASSISTANT_EXIT_PROTOCOL_REFUSED, ASSISTANT_EXIT_REFUSED, ASSISTANT_EXIT_UNAVAILABLE,
    ASSISTANT_EXIT_WATCHDOG_EXPIRED,
};

pub const REQUIRED_MODE_ARGUMENT: &str = "--native-bootstrap-assistant";
pub const EXIT_INVALID_INVOCATION: u8 = ASSISTANT_EXIT_INVALID_INVOCATION;
pub const EXIT_PROTOCOL_REFUSED: u8 = ASSISTANT_EXIT_PROTOCOL_REFUSED;
pub const EXIT_REFUSED: u8 = ASSISTANT_EXIT_REFUSED;
pub const EXIT_CANCELLED: u8 = ASSISTANT_EXIT_CANCELLED;
pub const EXIT_UNAVAILABLE: u8 = ASSISTANT_EXIT_UNAVAILABLE;
pub const EXIT_INTERNAL_FAILURE: u8 = ASSISTANT_EXIT_INTERNAL_FAILURE;
pub const EXIT_IO_FAILURE: u8 = ASSISTANT_EXIT_IO_FAILURE;
pub const EXIT_WATCHDOG_EXPIRED: u8 = ASSISTANT_EXIT_WATCHDOG_EXPIRED;

pub fn process_main() -> u8 {
    if hardening::apply().is_err() {
        return EXIT_INTERNAL_FAILURE;
    }
    std::panic::set_hook(Box::new(|_| {}));

    if !valid_arguments(std::env::args_os()) {
        return EXIT_INVALID_INVOCATION;
    }

    let watchdog = match watchdog::Watchdog::start() {
        Ok(watchdog) => watchdog,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    match serve_once(&mut reader, &mut writer, &watchdog) {
        Ok(terminal) => terminal.exit_code(),
        Err(SessionError::Protocol) => EXIT_PROTOCOL_REFUSED,
        Err(SessionError::Io) => EXIT_IO_FAILURE,
        Err(SessionError::Internal) => EXIT_INTERNAL_FAILURE,
    }
}

fn valid_arguments(arguments: impl IntoIterator<Item = OsString>) -> bool {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    arguments.next().as_deref() == Some(OsStr::new(REQUIRED_MODE_ARGUMENT))
        && arguments.next().is_none()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionError {
    Protocol,
    Io,
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionTerminal {
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

impl SessionTerminal {
    fn event(self) -> AssistantEventKind {
        match self {
            Self::Refused => AssistantEventKind::Refused,
            Self::Cancelled => AssistantEventKind::Cancelled,
            Self::Expired => AssistantEventKind::Expired,
            Self::Unavailable => AssistantEventKind::Unavailable,
        }
    }

    fn exit_code(self) -> u8 {
        match self {
            Self::Refused => EXIT_REFUSED,
            Self::Cancelled => EXIT_CANCELLED,
            Self::Expired => EXIT_WATCHDOG_EXPIRED,
            Self::Unavailable => EXIT_UNAVAILABLE,
        }
    }
}

fn serve_once(
    reader: &mut impl io::Read,
    writer: &mut impl io::Write,
    watchdog: &watchdog::Watchdog,
) -> Result<SessionTerminal, SessionError> {
    // Receiving and parsing the parent's frame consumes, and never renews, its remaining TTL.
    let session_started_at = Instant::now();
    let scope = framing::read_scope(reader).map_err(map_read_error)?;
    let deadline = deadline_from_start(session_started_at, scope.remaining_millis)
        .ok_or(SessionError::Protocol)?;
    watchdog
        .tighten_to(deadline)
        .map_err(|_| SessionError::Internal)?;
    if Instant::now() >= deadline {
        return write_terminal(writer, &scope, SessionTerminal::Expired);
    }

    framing::require_eof(reader).map_err(map_read_error)?;
    if Instant::now() >= deadline {
        return write_terminal(writer, &scope, SessionTerminal::Expired);
    }

    let terminal = show_prompt(&scope, deadline, watchdog.expiration_flag());
    let terminal = if Instant::now() >= deadline {
        SessionTerminal::Expired
    } else {
        terminal
    };
    write_terminal(writer, &scope, terminal)
}

fn write_terminal(
    writer: &mut impl io::Write,
    scope: &AssistantScopeV1,
    terminal: SessionTerminal,
) -> Result<SessionTerminal, SessionError> {
    let event = AssistantEventV1 {
        schema_version: 1,
        request_id: scope.request_id.clone(),
        event: terminal.event(),
    }
    .validate()
    .map_err(|_| SessionError::Internal)?;
    framing::write_event(writer, &event).map_err(|_| SessionError::Io)?;
    Ok(terminal)
}

#[cfg(target_os = "linux")]
fn show_prompt(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> SessionTerminal {
    native_prompt::confirm_personal_access(scope, deadline, expired)
}

#[cfg(not(target_os = "linux"))]
fn show_prompt(
    _scope: &AssistantScopeV1,
    _deadline: Instant,
    _expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> SessionTerminal {
    SessionTerminal::Unavailable
}

fn deadline_from_start(started_at: Instant, remaining_millis: u64) -> Option<Instant> {
    started_at.checked_add(Duration::from_millis(remaining_millis))
}

fn map_read_error(error: ReadFrameError) -> SessionError {
    match error {
        ReadFrameError::Invalid => SessionError::Protocol,
        ReadFrameError::Io => SessionError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_requires_exactly_one_fixed_argument() {
        assert!(valid_arguments([
            OsString::from("assistant"),
            OsString::from(REQUIRED_MODE_ARGUMENT),
        ]));
        for arguments in [
            vec![OsString::from("assistant")],
            vec![OsString::from("assistant"), OsString::from("--other")],
            vec![
                OsString::from("assistant"),
                OsString::from(REQUIRED_MODE_ARGUMENT),
                OsString::from("extra"),
            ],
        ] {
            assert!(!valid_arguments(arguments));
        }
    }

    #[test]
    fn ipc_read_time_is_deducted_instead_of_extending_the_deadline() {
        let started_at = Instant::now();
        let after_slow_read = started_at + Duration::from_millis(90);
        let deadline = deadline_from_start(started_at, 100).unwrap();

        assert_eq!(deadline, started_at + Duration::from_millis(100));
        assert_eq!(
            deadline.duration_since(after_slow_read),
            Duration::from_millis(10)
        );
    }
}
