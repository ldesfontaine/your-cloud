use std::{
    ffi::CStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use gtk::{
    glib::{self, translate::ToGlibPtr, ControlFlow},
    prelude::*,
    Dialog, DialogFlags, Entry, InputPurpose, Label, ResponseType,
};
use your_cloud_bootstrap_protocol::{
    AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
    NativePromptKind,
};

use crate::{lease::LeaseState, secret::ProtectedSecret, PromptOutcome};

const TIMER_INTERVAL: Duration = Duration::from_millis(25);
#[cfg(test)]
const AUTOMATIC_RESPONSE_DELAY: Duration = Duration::from_millis(50);
const EXPIRED_RESPONSE_ID: u16 = 1_000;
const LEASE_CANCELLED_RESPONSE_ID: u16 = 1_001;
const PROTOCOL_INVALID_RESPONSE_ID: u16 = 1_002;
const MAX_SECRET_CHARACTERS: i32 = 1_024;
const MAX_PUBLIC_LINE_CHARACTERS: usize = 72;

pub(crate) fn prompt(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    #[cfg(test)]
    {
        run_dialog(scope, deadline, expired, lease, None)
    }
    #[cfg(not(test))]
    {
        run_dialog(scope, deadline, expired, lease)
    }
}

fn run_dialog(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
    #[cfg(test)] automatic_action: Option<AutomaticAction>,
) -> PromptOutcome {
    let Ok(validated_scope) = scope.clone().validate() else {
        return PromptOutcome::Unavailable;
    };
    if validated_scope != *scope || lease.is_protocol_invalid() || gtk::init().is_err() {
        return PromptOutcome::Unavailable;
    }
    if lease.is_cancelled() {
        return PromptOutcome::Cancelled;
    }
    if expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
        return PromptOutcome::Expired;
    }

    let copy = prompt_copy(scope.prompt);
    let dialog = Dialog::with_buttons::<gtk::Window>(
        Some(copy.title),
        None,
        DialogFlags::MODAL,
        &[
            ("_Refuser", ResponseType::Reject),
            (copy.accept, ResponseType::Accept),
        ],
    );
    dialog.set_default_response(ResponseType::Reject);
    dialog.set_resizable(false);

    let content = dialog.content_area();
    content.set_spacing(8);
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);
    for line in scope_lines(scope) {
        let label = Label::new(Some(&line));
        label.set_xalign(0.0);
        label.set_selectable(true);
        content.pack_start(&label, false, false, 0);
    }

    let countdown = Label::new(Some(&countdown_text(deadline)));
    countdown.set_xalign(0.0);
    content.pack_start(&countdown, false, false, 0);

    let secret_entry = copy.secret_label.map(|secret_label| {
        let label = Label::new(Some(secret_label));
        label.set_xalign(0.0);
        content.pack_start(&label, false, false, 0);
        let entry = new_secret_entry();
        content.pack_start(&entry, false, false, 0);
        entry
    });

    let timer_dialog = dialog.clone();
    let timer_countdown = countdown.clone();
    let timer_expired = Arc::clone(&expired);
    let timer_lease = lease.clone();
    let timer = glib::source::timeout_add_local(TIMER_INTERVAL, move || {
        if timer_lease.is_protocol_invalid() {
            timer_dialog.response(ResponseType::Other(PROTOCOL_INVALID_RESPONSE_ID));
            return ControlFlow::Break;
        }
        if timer_expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
            timer_dialog.response(ResponseType::Other(EXPIRED_RESPONSE_ID));
            return ControlFlow::Break;
        }
        if timer_lease.is_cancelled() {
            timer_dialog.response(ResponseType::Other(LEASE_CANCELLED_RESPONSE_ID));
            return ControlFlow::Break;
        }
        timer_countdown.set_text(&countdown_text(deadline));
        ControlFlow::Continue
    });

    #[cfg(test)]
    schedule_automatic_action(
        &dialog,
        secret_entry.as_ref(),
        lease.clone(),
        automatic_action,
    );

    dialog.show_all();
    let response = dialog.run();
    if !timer_stopped_itself(response) {
        timer.remove();
    }

    let outcome = if lease.is_protocol_invalid()
        || response == ResponseType::Other(PROTOCOL_INVALID_RESPONSE_ID)
    {
        PromptOutcome::Unavailable
    } else if expired.load(Ordering::SeqCst)
        || Instant::now() >= deadline
        || response == ResponseType::Other(EXPIRED_RESPONSE_ID)
    {
        PromptOutcome::Expired
    } else if lease.is_cancelled() || response == ResponseType::Other(LEASE_CANCELLED_RESPONSE_ID) {
        PromptOutcome::Cancelled
    } else {
        outcome_from_response(scope.prompt, response, secret_entry.as_ref())
    };

    if let Some(entry) = secret_entry.as_ref() {
        entry.set_text("");
        #[cfg(test)]
        assert_eq!(entry.text_length(), 0);
    }
    dialog.hide();
    outcome
}

fn outcome_from_response(
    prompt: NativePromptKind,
    response: ResponseType,
    secret_entry: Option<&Entry>,
) -> PromptOutcome {
    match response {
        ResponseType::Reject => PromptOutcome::Refused,
        ResponseType::Accept => match prompt {
            NativePromptKind::ConfirmPersonalAccess | NativePromptKind::ConfirmRootAccess => {
                // Consent is internal to the helper. The caller maps it to an
                // expurgated Unavailable terminal until the next issue consumes it.
                PromptOutcome::Consent
            }
            NativePromptKind::KeyPassphrase | NativePromptKind::SudoPassword => {
                let Some(entry) = secret_entry else {
                    return PromptOutcome::Unavailable;
                };
                match capture_secret(entry) {
                    Ok(secret) => PromptOutcome::Secret(secret),
                    Err(CaptureSecretError::Empty) => PromptOutcome::Refused,
                    Err(CaptureSecretError::Unavailable) => PromptOutcome::Unavailable,
                }
            }
        },
        ResponseType::Cancel
        | ResponseType::Close
        | ResponseType::DeleteEvent
        | ResponseType::None => PromptOutcome::Cancelled,
        _ => PromptOutcome::Cancelled,
    }
}

fn new_secret_entry() -> Entry {
    let entry = Entry::new();
    entry.set_visibility(false);
    entry.set_input_purpose(InputPurpose::Password);
    entry.set_max_length(MAX_SECRET_CHARACTERS);
    entry
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureSecretError {
    Empty,
    Unavailable,
}

fn capture_secret(entry: &Entry) -> Result<ProtectedSecret, CaptureSecretError> {
    let captured = (|| {
        let text = unsafe {
            // gtk_entry_get_text returns a pointer borrowed from the Entry. CStr
            // exposes those bytes without allocating a String or GString.
            gtk::ffi::gtk_entry_get_text(entry.to_glib_none().0)
        };
        if text.is_null() {
            return Err(CaptureSecretError::Unavailable);
        }
        let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
        if bytes.is_empty() {
            return Err(CaptureSecretError::Empty);
        }
        let mut secret = ProtectedSecret::new().map_err(|_| CaptureSecretError::Unavailable)?;
        secret
            .copy_from(bytes)
            .map_err(|_| CaptureSecretError::Unavailable)?;
        Ok(secret)
    })();

    // Clear the widget's logical value while the Entry is alive, regardless of
    // whether protected allocation or bounded copying succeeded. GTK owns its
    // backing allocation, so only ProtectedSecret can promise a physical wipe.
    entry.set_text("");
    captured
}

fn timer_stopped_itself(response: ResponseType) -> bool {
    matches!(
        response,
        ResponseType::Other(
            EXPIRED_RESPONSE_ID | LEASE_CANCELLED_RESPONSE_ID | PROTOCOL_INVALID_RESPONSE_ID
        )
    )
}

struct PromptCopy {
    title: &'static str,
    secret_label: Option<&'static str>,
    accept: &'static str,
}

fn prompt_copy(prompt: NativePromptKind) -> PromptCopy {
    match prompt {
        NativePromptKind::ConfirmPersonalAccess => PromptCopy {
            title: "Your Cloud — autoriser l’accès personnel",
            secret_label: None,
            accept: "_Autoriser l’audit",
        },
        NativePromptKind::KeyPassphrase => PromptCopy {
            title: "Your Cloud — passphrase de la clé SSH",
            secret_label: Some("Passphrase de la clé SSH :"),
            accept: "_Continuer",
        },
        NativePromptKind::SudoPassword => PromptCopy {
            title: "Your Cloud — mot de passe sudo",
            secret_label: Some("Mot de passe sudo :"),
            accept: "_Continuer",
        },
        NativePromptKind::ConfirmRootAccess => PromptCopy {
            title: "Your Cloud — confirmer l’accès root",
            secret_label: None,
            accept: "_Confirmer root",
        },
    }
}

fn scope_lines(scope: &AssistantScopeV1) -> Vec<String> {
    logical_scope_lines(scope)
        .into_iter()
        .flat_map(|line| wrap_public_line(&line))
        .collect()
}

fn logical_scope_lines(scope: &AssistantScopeV1) -> Vec<String> {
    let mode = match scope.mode {
        BootstrapMode::Create => "création",
        BootstrapMode::Replace => "remplacement",
    };
    let access = match scope.target.access_kind {
        BootstrapAccessKind::Administrator => "administrateur",
        BootstrapAccessKind::Root => "root",
    };
    let step = match scope.step {
        BootstrapStep::PersonalAccess => "accès personnel",
        BootstrapStep::UnlockPersonalKey => "déverrouillage de la clé personnelle",
        BootstrapStep::PrivilegeEscalation => "élévation sudo",
        BootstrapStep::RootAccess => "accès root",
    };
    let action = match scope.actions {
        [BootstrapAction::AuditTargetReadOnly] => "audit de la cible en lecture seule",
    };
    vec![
        format!("Parcours : {mode}"),
        format!(
            "Cible : {}@{}:{}",
            scope.target.username, scope.target.host, scope.target.port
        ),
        format!("Route d’accès : {access}"),
        format!("Empreinte hôte : {}", scope.target.host_key_sha256),
        format!("Étape : {step}"),
        format!("Action : {action}"),
    ]
}

fn wrap_public_line(line: &str) -> Vec<String> {
    let mut wrapped = Vec::new();
    let mut chunk = String::new();
    let mut characters = 0;
    for character in line.chars() {
        if characters == MAX_PUBLIC_LINE_CHARACTERS {
            wrapped.push(std::mem::take(&mut chunk));
            characters = 0;
        }
        chunk.push(character);
        characters += 1;
    }
    if !chunk.is_empty() {
        wrapped.push(chunk);
    }
    wrapped
}

fn countdown_text(deadline: Instant) -> String {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let seconds = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0));
    format!("Expiration : {seconds} s")
}

#[cfg(test)]
enum AutomaticAction {
    Respond(ResponseType),
    EnterSecretAndAccept(&'static str),
    EnterSecret(&'static str),
    EnterSecretThenRespond(&'static str, ResponseType),
    EnterSecretThenCancelLease(&'static str),
    EnterSecretThenInvalidateLease(&'static str),
}

#[cfg(test)]
fn schedule_automatic_action(
    dialog: &Dialog,
    secret_entry: Option<&Entry>,
    lease: LeaseState,
    action: Option<AutomaticAction>,
) {
    let Some(action) = action else {
        return;
    };
    let automatic_dialog = dialog.clone();
    let automatic_entry = secret_entry.cloned();
    glib::source::timeout_add_local_once(AUTOMATIC_RESPONSE_DELAY, move || match action {
        AutomaticAction::Respond(response) => automatic_dialog.response(response),
        AutomaticAction::EnterSecretAndAccept(value) => {
            if let Some(entry) = automatic_entry.as_ref() {
                entry.set_text(value);
            }
            automatic_dialog.response(ResponseType::Accept);
        }
        AutomaticAction::EnterSecret(value) => {
            if let Some(entry) = automatic_entry.as_ref() {
                entry.set_text(value);
            }
        }
        AutomaticAction::EnterSecretThenRespond(value, response) => {
            if let Some(entry) = automatic_entry.as_ref() {
                entry.set_text(value);
            }
            automatic_dialog.response(response);
        }
        AutomaticAction::EnterSecretThenCancelLease(value) => {
            if let Some(entry) = automatic_entry.as_ref() {
                entry.set_text(value);
            }
            lease.cancel_for_test();
        }
        AutomaticAction::EnterSecretThenInvalidateLease(value) => {
            if let Some(entry) = automatic_entry.as_ref() {
                entry.set_text(value);
            }
            lease.invalidate_for_test();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use your_cloud_bootstrap_protocol::{BootstrapTarget, MAX_HOST_BYTES, MAX_USERNAME_BYTES};

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn scope(prompt: NativePromptKind) -> AssistantScopeV1 {
        let (step, access_kind) = match prompt {
            NativePromptKind::ConfirmPersonalAccess => (
                BootstrapStep::PersonalAccess,
                BootstrapAccessKind::Administrator,
            ),
            NativePromptKind::KeyPassphrase => (
                BootstrapStep::UnlockPersonalKey,
                BootstrapAccessKind::Administrator,
            ),
            NativePromptKind::SudoPassword => (
                BootstrapStep::PrivilegeEscalation,
                BootstrapAccessKind::Administrator,
            ),
            NativePromptKind::ConfirmRootAccess => {
                (BootstrapStep::RootAccess, BootstrapAccessKind::Root)
            }
        };
        AssistantScopeV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            mode: BootstrapMode::Create,
            target: BootstrapTarget {
                host: "controller.example.test".into(),
                port: 22,
                username: match access_kind {
                    BootstrapAccessKind::Administrator => "infra_admin".into(),
                    BootstrapAccessKind::Root => "root".into(),
                },
                host_key_sha256: HOST_KEY.into(),
                access_kind,
            },
            step,
            actions: [BootstrapAction::AuditTargetReadOnly],
            prompt,
            issued_at_monotonic_nanos: 1,
            remaining_millis: 5_000,
        }
    }

    fn maximal_scope(prompt: NativePromptKind) -> AssistantScopeV1 {
        let host = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(host.len(), MAX_HOST_BYTES);
        let mut maximal = scope(prompt);
        maximal.target.host = host;
        maximal.target.username = "u".repeat(MAX_USERNAME_BYTES);
        maximal.target.port = u16::MAX;
        assert_eq!(maximal.clone().validate().unwrap(), maximal);
        maximal
    }

    fn run_test_dialog(scope: &AssistantScopeV1, action: Option<AutomaticAction>) -> PromptOutcome {
        run_dialog(
            scope,
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            LeaseState::active_for_test(),
            action,
        )
    }

    #[test]
    fn public_copy_names_all_four_validated_steps_exactly() {
        for (prompt, expected_lines) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                vec![
                    "Parcours : création",
                    "Cible : infra_admin@controller.example.test:22",
                    "Route d’accès : administrateur",
                    "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "Étape : accès personnel",
                    "Action : audit de la cible en lecture seule",
                ],
            ),
            (
                NativePromptKind::KeyPassphrase,
                vec![
                    "Parcours : création",
                    "Cible : infra_admin@controller.example.test:22",
                    "Route d’accès : administrateur",
                    "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "Étape : déverrouillage de la clé personnelle",
                    "Action : audit de la cible en lecture seule",
                ],
            ),
            (
                NativePromptKind::SudoPassword,
                vec![
                    "Parcours : création",
                    "Cible : infra_admin@controller.example.test:22",
                    "Route d’accès : administrateur",
                    "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "Étape : élévation sudo",
                    "Action : audit de la cible en lecture seule",
                ],
            ),
            (
                NativePromptKind::ConfirmRootAccess,
                vec![
                    "Parcours : création",
                    "Cible : root@controller.example.test:22",
                    "Route d’accès : root",
                    "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "Étape : accès root",
                    "Action : audit de la cible en lecture seule",
                ],
            ),
        ] {
            let lines = logical_scope_lines(&scope(prompt));
            assert_eq!(lines, expected_lines);
        }
    }

    #[test]
    fn maximal_canonical_target_and_fingerprint_are_split_without_truncation() {
        let maximal = maximal_scope(NativePromptKind::KeyPassphrase);

        let logical = logical_scope_lines(&maximal);
        let wrapped = scope_lines(&maximal);
        assert!(wrapped.len() > logical.len());
        assert!(wrapped
            .iter()
            .all(|line| line.chars().count() <= MAX_PUBLIC_LINE_CHARACTERS));
        assert_eq!(wrapped.concat(), logical.concat());
        let rendered = wrapped.concat();
        assert!(rendered.contains(&format!(
            "Cible : {}@{}:{}",
            maximal.target.username, maximal.target.host, maximal.target.port
        )));
        assert!(rendered.contains(&format!(
            "Empreinte hôte : {}",
            maximal.target.host_key_sha256
        )));
    }

    #[test]
    fn root_confirmation_is_dedicated_and_has_no_secret_field() {
        let copy = prompt_copy(NativePromptKind::ConfirmRootAccess);
        assert_eq!(copy.title, "Your Cloud — confirmer l’accès root");
        assert_eq!(copy.accept, "_Confirmer root");
        assert!(copy.secret_label.is_none());
        assert!(prompt_copy(NativePromptKind::ConfirmPersonalAccess)
            .secret_label
            .is_none());
        assert!(prompt_copy(NativePromptKind::KeyPassphrase)
            .secret_label
            .is_some());
        assert!(prompt_copy(NativePromptKind::SudoPassword)
            .secret_label
            .is_some());
    }

    #[test]
    fn mismatched_step_is_unavailable_before_gtk_initialization() {
        let mut invalid = scope(NativePromptKind::SudoPassword);
        invalid.step = BootstrapStep::PersonalAccess;
        let outcome = prompt(
            &invalid,
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            LeaseState::active_for_test(),
        );
        assert!(matches!(outcome, PromptOutcome::Unavailable));
    }

    #[test]
    #[ignore = "requires isolated Xvfb"]
    fn gtk_dialog_handles_consent_secret_and_lease_states() {
        gtk::init().expect("isolated GTK display");

        assert!(matches!(
            run_test_dialog(
                &maximal_scope(NativePromptKind::KeyPassphrase),
                Some(AutomaticAction::Respond(ResponseType::Reject)),
            ),
            PromptOutcome::Refused
        ));

        let entry = new_secret_entry();
        assert!(!gtk::prelude::EntryExt::is_visible(&entry));
        assert_eq!(entry.input_purpose(), InputPurpose::Password);
        assert_eq!(entry.max_length(), MAX_SECRET_CHARACTERS);
        entry.set_text("synthetic-canary");
        let secret = capture_secret(&entry).expect("protected secret capture");
        let secret_matches = secret.bytes() == b"synthetic-canary";
        assert!(secret_matches);
        assert_eq!(entry.text_length(), 0);
        drop(secret);

        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::ConfirmPersonalAccess),
                Some(AutomaticAction::Respond(ResponseType::Reject)),
            ),
            PromptOutcome::Refused
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::ConfirmPersonalAccess),
                Some(AutomaticAction::Respond(ResponseType::DeleteEvent)),
            ),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::ConfirmPersonalAccess),
                Some(AutomaticAction::Respond(ResponseType::Accept)),
            ),
            PromptOutcome::Consent
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::ConfirmRootAccess),
                Some(AutomaticAction::Respond(ResponseType::Accept)),
            ),
            PromptOutcome::Consent
        ));

        for prompt in [
            NativePromptKind::KeyPassphrase,
            NativePromptKind::SudoPassword,
        ] {
            let outcome = run_test_dialog(
                &scope(prompt),
                Some(AutomaticAction::EnterSecretAndAccept("synthetic-canary")),
            );
            let PromptOutcome::Secret(secret) = outcome else {
                panic!("secret prompt did not return its internal protected outcome");
            };
            let secret_matches = secret.bytes() == b"synthetic-canary";
            assert!(secret_matches);
            drop(secret);
        }
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::KeyPassphrase),
                Some(AutomaticAction::Respond(ResponseType::Accept)),
            ),
            PromptOutcome::Refused
        ));

        let expiring_scope = scope(NativePromptKind::KeyPassphrase);
        assert!(matches!(
            run_dialog(
                &expiring_scope,
                Instant::now() + Duration::from_millis(100),
                Arc::new(AtomicBool::new(false)),
                LeaseState::active_for_test(),
                Some(AutomaticAction::EnterSecret("synthetic-canary")),
            ),
            PromptOutcome::Expired
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::KeyPassphrase),
                Some(AutomaticAction::EnterSecretThenCancelLease(
                    "synthetic-canary",
                )),
            ),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::SudoPassword),
                Some(AutomaticAction::EnterSecretThenInvalidateLease(
                    "synthetic-canary",
                )),
            ),
            PromptOutcome::Unavailable
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(NativePromptKind::KeyPassphrase),
                Some(AutomaticAction::EnterSecretThenRespond(
                    "synthetic-canary",
                    ResponseType::DeleteEvent,
                )),
            ),
            PromptOutcome::Cancelled
        ));
    }
}
