use std::{
    cell::RefCell,
    ffi::CStr,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use gtk::{
    glib::{self, translate::ToGlibPtr, ControlFlow},
    prelude::*,
    Button, ComboBoxText, Dialog, DialogFlags, Entry, FileChooserAction, FileChooserDialog,
    InputPurpose, Label, ResponseType,
};
use your_cloud_bootstrap_protocol::{
    AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
    NativePromptKind,
};

use crate::{
    lease::LeaseState, personal_access::signature_budget::OfferedIdentity, secret::ProtectedSecret,
    PromptOutcome,
};

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
        run_dialog(scope, &[], deadline, expired, lease, None)
    }
    #[cfg(not(test))]
    {
        run_dialog(scope, &[], deadline, expired, lease)
    }
}

/// The personal access window: the same public scope, plus the selection of
/// exactly one credential — an identity the agent holds, or an encrypted key
/// file chosen through this process's own native selector.
///
/// The acceptance button stays insensitive until one of the two is named, and
/// naming one clears the other, so a consent can never be given without saying
/// which key it applies to and can never apply to two.
pub(crate) fn prompt_with_identities(
    scope: &AssistantScopeV1,
    identities: &[OfferedIdentity],
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    #[cfg(test)]
    {
        run_dialog(scope, identities, deadline, expired, lease, None)
    }
    #[cfg(not(test))]
    {
        run_dialog(scope, identities, deadline, expired, lease)
    }
}

fn run_dialog(
    scope: &AssistantScopeV1,
    identities: &[OfferedIdentity],
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

    let identity_chooser = build_identity_chooser(&dialog, &content, identities);
    // The fallback of #53. The path is chosen here, by a selector this process
    // owns, and never arrives from the WebView: the frontend can open this
    // named journey, it cannot name a file inside it.
    let key_file = build_key_file_chooser(
        &dialog,
        &content,
        scope.prompt,
        identity_chooser.as_ref(),
        deadline,
        Arc::clone(&expired),
        lease.clone(),
    );

    let countdown = Label::new(Some(&countdown_text(deadline)));
    countdown.set_xalign(0.0);
    content.pack_start(&countdown, false, false, 0);

    let secret_entry = copy.secret_label.map(|secret_label| {
        // The label carries the field's accelerator and points at it, which is
        // what GTK expects of a labelled entry: without it the only way to the
        // field is a walk through every selectable line of the scope above.
        let label = Label::with_mnemonic(secret_label);
        label.set_xalign(0.0);
        content.pack_start(&label, false, false, 0);
        let entry = new_secret_entry();
        label.set_mnemonic_widget(Some(&entry));
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
        outcome_from_response(
            scope.prompt,
            response,
            secret_entry.as_ref(),
            identity_chooser.as_ref(),
            key_file.and_then(|chosen| chosen.borrow_mut().take()),
        )
    };

    if let Some(entry) = secret_entry.as_ref() {
        entry.set_text("");
        #[cfg(test)]
        assert_eq!(entry.text_length(), 0);
    }
    dialog.hide();
    outcome
}

/// The rows a user may actually pick, each as its identifying fingerprint and
/// the line displayed for it.
///
/// A certificate is dropped rather than shown: this palier refuses to sign
/// with one, and offering it would let the user pick something the signature
/// budget is going to refuse anyway.
fn selectable_identities(identities: &[OfferedIdentity]) -> Vec<(String, String)> {
    identities
        .iter()
        .filter(|identity| !identity.is_certificate)
        .map(|identity| {
            (
                identity.fingerprint.clone(),
                format!("{} {}", identity.algorithm, identity.fingerprint),
            )
        })
        .collect()
}

/// Builds the identity list, or nothing at all when there is none to choose.
///
/// Each row is named by its own SHA-256 fingerprint, which is also the value
/// the transport later binds its signature budget to, so what the user reads
/// and what gets signed cannot drift apart.
fn build_identity_chooser(
    dialog: &Dialog,
    content: &gtk::Box,
    identities: &[OfferedIdentity],
) -> Option<ComboBoxText> {
    if identities.is_empty() {
        return None;
    }
    let label = Label::new(Some("Identité de l’agent à utiliser :"));
    label.set_xalign(0.0);
    content.pack_start(&label, false, false, 0);

    let chooser = ComboBoxText::new();
    for (fingerprint, line) in selectable_identities(identities) {
        chooser.append(Some(&fingerprint), &line);
    }
    content.pack_start(&chooser, false, false, 0);

    // Nothing is preselected, and acceptance stays unavailable until the user
    // has named exactly one identity.
    dialog.set_response_sensitive(ResponseType::Accept, false);
    let sensitivity_dialog = dialog.clone();
    chooser.connect_changed(move |chooser| {
        sensitivity_dialog
            .set_response_sensitive(ResponseType::Accept, chooser.active_id().is_some());
    });
    Some(chooser)
}

/// Adds the encrypted key file row to the personal access window.
///
/// It is offered whether or not the agent holds anything, because "the agent is
/// not retained" covers both an agent that offers nothing and a user who would
/// rather open their own file. What it never does is accept a path from
/// anywhere but this selector: the WebView opens a named journey, it does not
/// name files inside it.
///
/// Exactly one credential leaves this window. Choosing a file clears the
/// identity list, choosing an identity clears the file, and acceptance stays
/// unavailable until one of the two is named.
fn build_key_file_chooser(
    dialog: &Dialog,
    content: &gtk::Box,
    prompt: NativePromptKind,
    identity_chooser: Option<&ComboBoxText>,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
) -> Option<Rc<RefCell<Option<PathBuf>>>> {
    if prompt != NativePromptKind::ConfirmPersonalAccess {
        return None;
    }
    // Nothing is named yet, whatever the agent offered.
    dialog.set_response_sensitive(ResponseType::Accept, false);

    // The accelerator sits on the label and points at the button rather than
    // on the button itself, which is what GTK expects and what keeps the two
    // concerns apart: the button's own text becomes the chosen path, and a
    // path holding an underscore must render as itself rather than as an
    // accelerator. Every other control of this window already answers to one.
    let label = Label::with_mnemonic(KEY_FILE_LABEL);
    label.set_xalign(0.0);
    content.pack_start(&label, false, false, 0);

    let button = Button::with_label(NO_KEY_FILE_CHOSEN);
    label.set_mnemonic_widget(Some(&button));
    content.pack_start(&button, false, false, 0);

    let chosen: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let click_dialog = dialog.clone();
    let click_chosen = Rc::clone(&chosen);
    let click_identities = identity_chooser.cloned();
    button.connect_clicked(move |button| {
        let Some(path) = run_key_file_chooser(&click_dialog, deadline, &expired, &lease) else {
            return;
        };
        if let Some(chooser) = click_identities.as_ref() {
            chooser.set_active_id(None);
        }
        button.set_label(&rendered_path(&path));
        click_chosen.replace(Some(path));
        click_dialog.set_response_sensitive(ResponseType::Accept, true);
    });

    if let Some(chooser) = identity_chooser {
        let changed_button = button.clone();
        let changed_chosen = Rc::clone(&chosen);
        chooser.connect_changed(move |chooser| {
            if chooser.active_id().is_some() {
                changed_chosen.replace(None);
                changed_button.set_label(NO_KEY_FILE_CHOSEN);
            }
        });
    }
    Some(chosen)
}

/// Runs the native selector under the same three bounds the window itself has.
///
/// A modal child dialog runs its own loop, so the parent's countdown cannot end
/// it: the expiry, the released lease and the violated protocol are watched
/// here as well, and each closes the selector with nothing chosen.
///
/// Each of the three answers the selector with its *own* identifier rather than
/// with a plain cancellation, and the reason is not cosmetic. A GLib source
/// that breaks has already removed itself, so removing it a second time is a
/// fatal error and not a no-operation; the only way this function can know
/// whether the source is still there is to be able to tell the response its own
/// timer wrote from the one the user's button writes, and a timer answering
/// `Cancel` is indistinguishable from that button. Answering with the same
/// identifiers the window above uses makes the two loops read alike, and
/// [`timer_stopped_itself`] answers for both.
///
/// Which of the three fired is deliberately not returned. This function only
/// ever answers a path or nothing, and the terminal that the session ends on is
/// decided by the window underneath, whose own timer observes the very same
/// three conditions.
fn run_key_file_chooser(
    parent: &Dialog,
    deadline: Instant,
    expired: &Arc<AtomicBool>,
    lease: &LeaseState,
) -> Option<PathBuf> {
    let chooser = FileChooserDialog::new(
        Some("Your Cloud — choisir la clé OpenSSH chiffrée"),
        Some(parent),
        FileChooserAction::Open,
    );
    chooser.add_button("_Annuler", ResponseType::Cancel);
    chooser.add_button("_Ouvrir", ResponseType::Accept);
    chooser.set_modal(true);
    chooser.set_select_multiple(false);
    // Only what this machine's own file system holds: a remote location would
    // be fetched into a temporary file, which is exactly what nothing here may
    // create.
    chooser.set_local_only(true);
    chooser.set_create_folders(false);
    chooser.set_show_hidden(true);

    let timer_chooser = chooser.clone();
    let timer_expired = Arc::clone(expired);
    let timer_lease = lease.clone();
    let timer = glib::source::timeout_add_local(TIMER_INTERVAL, move || {
        let stopped = if timer_lease.is_protocol_invalid() {
            PROTOCOL_INVALID_RESPONSE_ID
        } else if timer_expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
            EXPIRED_RESPONSE_ID
        } else if timer_lease.is_cancelled() {
            LEASE_CANCELLED_RESPONSE_ID
        } else {
            return ControlFlow::Continue;
        };
        timer_chooser.response(ResponseType::Other(stopped));
        ControlFlow::Break
    });

    chooser.show_all();
    let response = chooser.run();
    // A source that broke removed itself; removing it again aborts the process.
    if !timer_stopped_itself(response) {
        timer.remove();
    }
    let chosen = (response == ResponseType::Accept)
        .then(|| chooser.filename())
        .flatten();
    chooser.hide();
    // Nothing is opened here. The path is only a name until `key_file` opens it
    // once, without following a link, and confirms what it opened.
    chosen.filter(|path| path.is_absolute())
}

/// The row that offers the encrypted key file, and the accelerator that opens
/// its selector.
const KEY_FILE_LABEL: &str = "_Ou clé OpenSSH chiffrée :";
const NO_KEY_FILE_CHOSEN: &str = "Choisir un fichier de clé…";

/// The tail of a path, bounded like every other public line of this window.
fn rendered_path(path: &std::path::Path) -> String {
    let rendered = path.to_string_lossy();
    let characters: Vec<char> = rendered.chars().collect();
    if characters.len() <= MAX_PUBLIC_LINE_CHARACTERS {
        return rendered.into_owned();
    }
    let tail: String = characters[characters.len() - (MAX_PUBLIC_LINE_CHARACTERS - 1)..]
        .iter()
        .collect();
    format!("…{tail}")
}

fn outcome_from_response(
    prompt: NativePromptKind,
    response: ResponseType,
    secret_entry: Option<&Entry>,
    identity_chooser: Option<&ComboBoxText>,
    key_file: Option<PathBuf>,
) -> PromptOutcome {
    match response {
        ResponseType::Reject => PromptOutcome::Refused,
        ResponseType::Accept => match prompt {
            // A chosen file wins over a chosen identity, and the window makes
            // choosing one clear the other, so the two can never both be set.
            NativePromptKind::ConfirmPersonalAccess if key_file.is_some() => {
                match key_file.filter(|path| path.is_absolute()) {
                    Some(path) => PromptOutcome::ConsentWithKeyFile(path),
                    // A selector that answered something relative answered
                    // nothing this process will open.
                    None => PromptOutcome::Refused,
                }
            }
            // The root window offers the same list for the same reason: the
            // session it consents to still has to authenticate with one named
            // identity, and a consent that did not say which would be leaving
            // that choice to something downstream.
            NativePromptKind::ConfirmPersonalAccess | NativePromptKind::ConfirmRootAccess
                if identity_chooser.is_some() =>
            {
                match identity_chooser.and_then(ComboBoxExt::active_id) {
                    // The selected identity travels with the consent: nothing
                    // downstream may choose a key on the user's behalf.
                    Some(fingerprint) => {
                        PromptOutcome::ConsentWithIdentity(fingerprint.to_string())
                    }
                    None => PromptOutcome::Refused,
                }
            }
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
            secret_label: Some("_Passphrase de la clé SSH :"),
            accept: "_Continuer",
        },
        NativePromptKind::SudoPassword => PromptCopy {
            title: "Your Cloud — mot de passe sudo",
            secret_label: Some("_Mot de passe sudo :"),
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
    let mut lines = vec![
        format!("Parcours : {mode}"),
        format!(
            "Cible : {}@{}:{}",
            scope.target.username, scope.target.host, scope.target.port
        ),
    ];
    // The name is what the user recognises; the frozen addresses are what the
    // transport will actually dial. Showing both is the only way consent can
    // cover the peer rather than the label.
    if !scope.target_addresses.is_empty() {
        lines.push(format!("Adresses : {}", scope.target_addresses.join(", ")));
    }
    lines.extend([
        format!("Route d’accès : {access}"),
        format!("Empreinte hôte : {}", scope.target.host_key_sha256),
        format!("Étape : {step}"),
        format!("Action : {action}"),
    ]);
    lines
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
            target_addresses: Vec::new(),
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
            &[],
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            LeaseState::active_for_test(),
            action,
        )
    }

    fn ed25519_identity(fingerprint: &str) -> OfferedIdentity {
        OfferedIdentity {
            algorithm: russh::keys::Algorithm::Ed25519,
            fingerprint: fingerprint.into(),
            is_certificate: false,
        }
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

    /// What the transport will dial must be readable before consent, next to
    /// the name it came from. An unresolved scope shows no address line at all
    /// rather than an empty or invented one.
    #[test]
    fn the_frozen_addresses_are_displayed_beside_the_name() {
        let mut resolved = scope(NativePromptKind::ConfirmPersonalAccess);
        resolved.target_addresses = vec!["192.168.1.10".into(), "2001:db8::1".into()];
        let resolved = resolved.validate().expect("a bounded frozen set");

        let lines = logical_scope_lines(&resolved);
        assert_eq!(
            lines,
            vec![
                "Parcours : création",
                "Cible : infra_admin@controller.example.test:22",
                "Adresses : 192.168.1.10, 2001:db8::1",
                "Route d’accès : administrateur",
                "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "Étape : accès personnel",
                "Action : audit de la cible en lecture seule",
            ]
        );

        let unresolved = scope(NativePromptKind::ConfirmPersonalAccess);
        assert!(
            !logical_scope_lines(&unresolved)
                .iter()
                .any(|line| line.starts_with("Adresses")),
            "nothing frozen yet means nothing to display"
        );
    }

    /// Eight IPv6 addresses is the widest set the perimeter accepts; it must
    /// still be shown whole, wrapped rather than cut.
    #[test]
    fn a_maximal_frozen_set_is_wrapped_without_truncation() {
        let mut maximal = scope(NativePromptKind::ConfirmPersonalAccess);
        maximal.target_addresses = (1..=8)
            .map(|last| format!("2001:db8:aaaa:bbbb:cccc:dddd:eeee:{last:x}"))
            .collect();
        let maximal = maximal.validate().expect("eight canonical addresses");

        let logical = logical_scope_lines(&maximal);
        let wrapped = scope_lines(&maximal);
        assert!(wrapped
            .iter()
            .all(|line| line.chars().count() <= MAX_PUBLIC_LINE_CHARACTERS));
        assert_eq!(wrapped.concat(), logical.concat());
        for address in &maximal.target_addresses {
            assert!(
                wrapped.concat().contains(address.as_str()),
                "{address} must stay readable in the consent window"
            );
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

    /// The character GTK reads as an accelerator out of one label, if any.
    fn accelerator(label: &str) -> Option<char> {
        let mut characters = label.chars();
        while let Some(character) = characters.next() {
            if character == '_' {
                return characters.next().map(|marked| {
                    marked
                        .to_lowercase()
                        .next()
                        .expect("a character lowercases to at least one")
                });
            }
        }
        None
    }

    /// Every control of every window answers to an accelerator, and no two
    /// controls of the same window answer to the same one.
    ///
    /// It is not a cosmetic rule. These windows carry a countdown, and the
    /// controls that end them must be reachable without a pointing device;
    /// two controls sharing a letter would make one of them unreachable, which
    /// on a window with a deadline means unreachable in time.
    #[test]
    fn each_window_names_its_controls_by_a_distinct_accelerator() {
        for prompt in [
            NativePromptKind::ConfirmPersonalAccess,
            NativePromptKind::ConfirmRootAccess,
            NativePromptKind::KeyPassphrase,
            NativePromptKind::SudoPassword,
        ] {
            let copy = prompt_copy(prompt);
            let mut labels = vec!["_Refuser", copy.accept];
            labels.extend(copy.secret_label);
            if prompt == NativePromptKind::ConfirmPersonalAccess {
                labels.push(KEY_FILE_LABEL);
            }

            let mut marked = Vec::new();
            for label in &labels {
                let letter = accelerator(label)
                    .unwrap_or_else(|| panic!("{label:?} carries no accelerator at all"));
                assert!(
                    !marked.contains(&letter),
                    "two controls of {prompt:?} answer to the same accelerator {letter:?}"
                );
                marked.push(letter);
            }
        }

        // The reader itself, on the two shapes that must not be confused.
        assert_eq!(accelerator("_Refuser"), Some('r'));
        assert_eq!(accelerator("Refuser"), None);
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

    /// Each row is named by the exact fingerprint the budget will be bound to,
    /// and a certificate is never offered as a choice.
    #[test]
    fn only_plain_identities_are_offered_and_each_row_names_its_own_fingerprint() {
        const FIRST: &str = "SHA256:0ur4Vv8h1nRhKZ9lPqYq2sBvXwGx7cJd1KfE0mTnRbA";
        const SECOND: &str = "SHA256:Zz9QaWxLm4Tn2VkJhRfCg7BdY6sXeUo1PtNvHcMi3Ek";

        let rows = selectable_identities(&[
            ed25519_identity(FIRST),
            OfferedIdentity {
                is_certificate: true,
                ..ed25519_identity(SECOND)
            },
        ]);
        assert_eq!(
            rows,
            vec![(
                FIRST.to_string(),
                format!("{} {FIRST}", russh::keys::Algorithm::Ed25519)
            )],
            "a certificate must never be selectable at this palier"
        );
        assert!(rows[0].1.contains(FIRST));
        assert!(selectable_identities(&[]).is_empty());
    }

    /// Without any identity list the window keeps its plain consent, which is
    /// what the other three prompts of this palier rely on.
    #[test]
    fn a_window_without_an_identity_list_keeps_the_plain_consent() {
        assert!(matches!(
            outcome_from_response(
                NativePromptKind::ConfirmPersonalAccess,
                ResponseType::Accept,
                None,
                None,
                None,
            ),
            PromptOutcome::Consent
        ));
        assert!(matches!(
            outcome_from_response(
                NativePromptKind::ConfirmPersonalAccess,
                ResponseType::Reject,
                None,
                None,
                None,
            ),
            PromptOutcome::Refused
        ));
    }

    /// A chosen key file travels with the consent, exactly as a chosen identity
    /// does, and it is the *path* that travels: nothing is opened by the window.
    #[test]
    fn a_chosen_key_file_travels_with_the_consent_and_only_when_absolute() {
        let outcome = outcome_from_response(
            NativePromptKind::ConfirmPersonalAccess,
            ResponseType::Accept,
            None,
            None,
            Some(PathBuf::from("/home/synthetic/.ssh/id_ed25519")),
        );
        let PromptOutcome::ConsentWithKeyFile(path) = outcome else {
            panic!("an absolute selection must reach the consent");
        };
        assert_eq!(path, PathBuf::from("/home/synthetic/.ssh/id_ed25519"));

        assert!(
            matches!(
                outcome_from_response(
                    NativePromptKind::ConfirmPersonalAccess,
                    ResponseType::Accept,
                    None,
                    None,
                    Some(PathBuf::from("relative/id_ed25519")),
                ),
                PromptOutcome::Refused
            ),
            "a selector that answered something relative answered nothing"
        );
        assert!(
            matches!(
                outcome_from_response(
                    NativePromptKind::ConfirmPersonalAccess,
                    ResponseType::Reject,
                    None,
                    None,
                    Some(PathBuf::from("/home/synthetic/.ssh/id_ed25519")),
                ),
                PromptOutcome::Refused
            ),
            "a refusal stays a refusal whatever was chosen before it"
        );
    }

    /// The displayed path is bounded like every other public line, and keeps
    /// the end — which is what tells two keys of the same user apart.
    #[test]
    fn a_displayed_path_is_bounded_and_keeps_its_tail() {
        let short = std::path::Path::new("/home/synthetic/.ssh/id_ed25519");
        assert_eq!(rendered_path(short), "/home/synthetic/.ssh/id_ed25519");

        let long = PathBuf::from(format!("/{}/id_ed25519", "d".repeat(200)));
        let rendered = rendered_path(&long);
        assert_eq!(rendered.chars().count(), MAX_PUBLIC_LINE_CHARACTERS);
        assert!(rendered.starts_with('…'));
        assert!(rendered.ends_with("/id_ed25519"));
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
                &[],
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
