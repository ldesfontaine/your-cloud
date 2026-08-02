use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use gtk::{
    glib::{self, ControlFlow},
    prelude::*,
    Dialog, DialogFlags, Label, ResponseType,
};
use your_cloud_bootstrap_protocol::{
    AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
    NativePromptKind,
};

use crate::SessionTerminal;

const TIMER_INTERVAL: Duration = Duration::from_millis(25);
const EXPIRED_RESPONSE_ID: u16 = 1000;

pub(crate) fn confirm_personal_access(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: Arc<AtomicBool>,
) -> SessionTerminal {
    #[cfg(test)]
    {
        run_dialog(scope, deadline, expired, None)
    }
    #[cfg(not(test))]
    {
        run_dialog(scope, deadline, expired)
    }
}

fn run_dialog(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    #[cfg(test)] automatic_response: Option<ResponseType>,
) -> SessionTerminal {
    if scope.prompt != NativePromptKind::ConfirmPersonalAccess || gtk::init().is_err() {
        return SessionTerminal::Unavailable;
    }

    let dialog = Dialog::with_buttons::<gtk::Window>(
        Some("Your Cloud — autoriser l’accès personnel"),
        None,
        DialogFlags::MODAL,
        &[
            ("_Refuser", ResponseType::Reject),
            ("_Autoriser l’audit", ResponseType::Accept),
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

    let timer_dialog = dialog.clone();
    let timer_countdown = countdown.clone();
    let timer_expired = Arc::clone(&expired);
    let timer = glib::source::timeout_add_local(TIMER_INTERVAL, move || {
        if timer_expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
            timer_dialog.response(ResponseType::Other(EXPIRED_RESPONSE_ID));
            return ControlFlow::Break;
        }
        timer_countdown.set_text(&countdown_text(deadline));
        ControlFlow::Continue
    });

    #[cfg(test)]
    if let Some(response) = automatic_response {
        let automatic_dialog = dialog.clone();
        glib::source::timeout_add_local_once(Duration::from_millis(50), move || {
            automatic_dialog.response(response);
        });
    }

    dialog.show_all();
    let response = dialog.run();
    dialog.hide();
    if response != ResponseType::Other(EXPIRED_RESPONSE_ID) {
        timer.remove();
    }

    if expired.load(Ordering::SeqCst)
        || Instant::now() >= deadline
        || response == ResponseType::Other(EXPIRED_RESPONSE_ID)
    {
        return SessionTerminal::Expired;
    }
    match response {
        ResponseType::Reject => SessionTerminal::Refused,
        ResponseType::Accept => {
            // This first native prompt only records consent. The read-only target audit remains
            // a separate phase, so acceptance can never be reported as bootstrap success here.
            SessionTerminal::Unavailable
        }
        ResponseType::Cancel
        | ResponseType::Close
        | ResponseType::DeleteEvent
        | ResponseType::None => SessionTerminal::Cancelled,
        _ => SessionTerminal::Cancelled,
    }
}

fn scope_lines(scope: &AssistantScopeV1) -> Vec<String> {
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
        format!("Demande : {}", scope.request_id),
    ]
}

fn countdown_text(deadline: Instant) -> String {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let seconds = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0));
    format!("Expiration : {seconds} s")
}

#[cfg(test)]
mod tests {
    use super::*;
    use your_cloud_bootstrap_protocol::{BootstrapTarget, MAX_ASSISTANT_REMAINING_MILLIS};

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn scope() -> AssistantScopeV1 {
        AssistantScopeV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            mode: BootstrapMode::Create,
            target: BootstrapTarget {
                host: "controller.example.test".into(),
                port: 22,
                username: "infra_admin".into(),
                host_key_sha256: HOST_KEY.into(),
                access_kind: BootstrapAccessKind::Administrator,
            },
            step: BootstrapStep::PersonalAccess,
            actions: [BootstrapAction::AuditTargetReadOnly],
            prompt: NativePromptKind::ConfirmPersonalAccess,
            remaining_millis: MAX_ASSISTANT_REMAINING_MILLIS,
        }
    }

    #[test]
    fn prompt_copy_repeats_only_the_validated_public_scope() {
        assert_eq!(
            scope_lines(&scope()),
            [
                "Parcours : création",
                "Cible : infra_admin@controller.example.test:22",
                "Route d’accès : administrateur",
                "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "Étape : accès personnel",
                "Action : audit de la cible en lecture seule",
                "Demande : 00112233445566778899aabbccddeeff",
            ]
        );
    }

    #[test]
    #[ignore = "requires isolated Xvfb"]
    fn gtk_dialog_maps_consent_without_collecting_a_secret() {
        assert_eq!(
            run_dialog(
                &scope(),
                Instant::now() + Duration::from_secs(5),
                Arc::new(AtomicBool::new(false)),
                Some(ResponseType::Reject),
            ),
            SessionTerminal::Refused
        );
        assert_eq!(
            run_dialog(
                &scope(),
                Instant::now() + Duration::from_secs(5),
                Arc::new(AtomicBool::new(false)),
                Some(ResponseType::DeleteEvent),
            ),
            SessionTerminal::Cancelled
        );
        assert_eq!(
            run_dialog(
                &scope(),
                Instant::now() + Duration::from_secs(5),
                Arc::new(AtomicBool::new(false)),
                Some(ResponseType::Accept),
            ),
            SessionTerminal::Unavailable
        );
        assert_eq!(
            run_dialog(
                &scope(),
                Instant::now() + Duration::from_millis(50),
                Arc::new(AtomicBool::new(false)),
                None,
            ),
            SessionTerminal::Expired
        );
    }
}
