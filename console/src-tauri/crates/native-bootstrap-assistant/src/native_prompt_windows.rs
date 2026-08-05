use std::{
    mem::size_of,
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[cfg(test)]
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, CB_SETCURSEL};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, HWND, LPARAM, RECT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Input::KeyboardAndMouse::{EnableWindow, GetFocus, IsWindowEnabled, SetFocus},
        WindowsAndMessaging::{
            CreateWindowExW, DialogBoxIndirectParamW, EndDialog, GetClassNameW, GetWindowLongPtrW,
            GetWindowTextLengthW, GetWindowTextW, KillTimer, MapDialogRect, SendMessageW, SetTimer,
            SetWindowLongPtrW, SetWindowTextW, BN_CLICKED, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
            CBN_SELCHANGE, CBS_DROPDOWNLIST, CBS_HASSTRINGS, CB_ADDSTRING, CB_ERR, CB_GETCOUNT,
            CB_GETCURSEL, CB_GETLBTEXT, CB_GETLBTEXTLEN, DC_HASDEFID, DM_GETDEFID, DM_SETDEFID,
            DS_CENTER, DS_MODALFRAME, ES_AUTOHSCROLL, ES_PASSWORD, GWL_STYLE, IDCANCEL, IDOK,
            WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_INITDIALOG, WM_TIMER, WS_BORDER, WS_CAPTION,
            WS_CHILD, WS_EX_CLIENTEDGE, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
        },
    },
};
use your_cloud_bootstrap_protocol::{
    AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
    NativePromptKind,
};

use crate::{
    personal_access::signature_budget::OfferedIdentity, secret::ProtectedSecret, LeaseState,
    PromptOutcome,
};

const TIMER_INTERVAL: Duration = Duration::from_millis(25);
const TIMER_ID: usize = 1;
const MAX_SECRET_UNITS: usize = 1_024;
// Winuser.h defines DWLP_USER after two pointer-sized dialog slots. windows-sys 0.61.2 does not
// project that architecture-dependent macro.
const DWLP_USER: i32 = (size_of::<isize>() * 2) as i32;
// These stable edit-control messages live behind Win32_UI_Controls in windows-sys 0.61.2. Keep
// this helper's narrower feature set while using the exact Winuser.h message identifiers.
const EM_GETLIMITTEXT: u32 = 0x00d5;
const EM_SETLIMITTEXT: u32 = 0x00c5;
const MAX_PUBLIC_LINE_CHARACTERS: usize = 72;
const SCOPE_LINE_HEIGHT_DLU: i32 = 13;
const SCOPE_VERTICAL_PADDING_DLU: i32 = 4;
const BASE_SCOPE_HEIGHT_DLU: i32 = 112;
const BASE_COUNTDOWN_Y_DLU: i32 = 126;
// The lower block is the secret entry or the identity chooser. A prompt never
// carries both — the personal access window asks for no secret, and no secret
// window selects a key — so the two share one set of slots.
const BASE_LOWER_LABEL_Y_DLU: i32 = 146;
const BASE_LOWER_CONTROL_Y_DLU: i32 = 162;
const BASE_LOWER_BUTTON_Y_DLU: i32 = 198;
const BASE_CONSENT_BUTTON_Y_DLU: i32 = 166;
const BASE_DIALOG_HEIGHT_DLU: i32 = 235;
// A combo box is created with the height of its dropped list; Windows resizes
// the control itself to one item, so this is what the list may show at once
// rather than what the closed field occupies.
const IDENTITY_LIST_HEIGHT_DLU: i32 = 60;

const SCOPE_CONTROL_ID: i32 = 1_001;
const COUNTDOWN_CONTROL_ID: i32 = 1_002;
const SECRET_LABEL_CONTROL_ID: i32 = 1_003;
const SECRET_EDIT_CONTROL_ID: i32 = 1_004;
const REFUSE_CONTROL_ID: i32 = 1_005;
const IDENTITY_LABEL_CONTROL_ID: i32 = 1_006;
const IDENTITY_CONTROL_ID: i32 = 1_007;

const IDENTITY_LABEL: &str = "Identité de l’agent à utiliser :";

const DIALOG_RESULT_DONE: isize = 1;

const STATIC_CLASS: [u16; 7] = [
    b'S' as u16,
    b'T' as u16,
    b'A' as u16,
    b'T' as u16,
    b'I' as u16,
    b'C' as u16,
    0,
];
const EDIT_CLASS: [u16; 5] = [b'E' as u16, b'D' as u16, b'I' as u16, b'T' as u16, 0];
const EDIT_CLASS_NAME: [u16; 4] = [b'E' as u16, b'd' as u16, b'i' as u16, b't' as u16];
const COMBOBOX_CLASS: [u16; 9] = [
    b'C' as u16,
    b'O' as u16,
    b'M' as u16,
    b'B' as u16,
    b'O' as u16,
    b'B' as u16,
    b'O' as u16,
    b'X' as u16,
    0,
];
const COMBOBOX_CLASS_NAME: [u16; 8] = [
    b'C' as u16,
    b'o' as u16,
    b'm' as u16,
    b'b' as u16,
    b'o' as u16,
    b'B' as u16,
    b'o' as u16,
    b'x' as u16,
];
const BUTTON_CLASS: [u16; 7] = [
    b'B' as u16,
    b'U' as u16,
    b'T' as u16,
    b'T' as u16,
    b'O' as u16,
    b'N' as u16,
    0,
];

// DialogBoxIndirectParamW consumes the variable-length DLGTEMPLATE wire representation, not the
// padded Rust size of DLGTEMPLATE. This aligned twelve-WORD form is: fixed 18-byte header, then
// empty menu, default dialog class and empty title.
#[repr(C, align(4))]
struct EmptyDialogTemplate([u16; 12]);

impl EmptyDialogTemplate {
    fn new(height: u16) -> Self {
        let style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME as u32 | DS_CENTER as u32;
        let mut words = [0_u16; 12];
        put_u32(&mut words, 0, style);
        put_u32(&mut words, 2, 0); // dwExtendedStyle
        words[4] = 0; // cdit: controls are created from validated native state in WM_INITDIALOG.
        words[5] = 0; // x
        words[6] = 0; // y
        words[7] = 340; // cx, dialog units
        words[8] = height; // cy, dialog units
        words[9] = 0; // no menu
        words[10] = 0; // default dialog class
        words[11] = 0; // empty template title; SetWindowTextW supplies the validated title.
        Self(words)
    }
}

#[derive(Clone, Copy)]
struct DialogLayout {
    scope_height: i32,
    countdown_y: i32,
    lower_label_y: i32,
    lower_control_y: i32,
    button_y: i32,
    dialog_height: u16,
}

impl DialogLayout {
    fn new(scope_line_count: usize, has_lower_block: bool) -> Option<Self> {
        let required_scope_height = i32::try_from(scope_line_count)
            .ok()?
            .checked_mul(SCOPE_LINE_HEIGHT_DLU)?
            .checked_add(SCOPE_VERTICAL_PADDING_DLU)?;
        let scope_height = BASE_SCOPE_HEIGHT_DLU.max(required_scope_height);
        let additional_height = scope_height.checked_sub(BASE_SCOPE_HEIGHT_DLU)?;
        let countdown_y = BASE_COUNTDOWN_Y_DLU.checked_add(additional_height)?;
        let lower_label_y = BASE_LOWER_LABEL_Y_DLU.checked_add(additional_height)?;
        let lower_control_y = BASE_LOWER_CONTROL_Y_DLU.checked_add(additional_height)?;
        let button_y = if has_lower_block {
            BASE_LOWER_BUTTON_Y_DLU
        } else {
            BASE_CONSENT_BUTTON_Y_DLU
        }
        .checked_add(additional_height)?;
        let dialog_height =
            u16::try_from(BASE_DIALOG_HEIGHT_DLU.checked_add(additional_height)?).ok()?;
        Some(Self {
            scope_height,
            countdown_y,
            lower_label_y,
            lower_control_y,
            button_y,
            dialog_height,
        })
    }
}

fn put_u32(words: &mut [u16], index: usize, value: u32) {
    words[index] = value as u16;
    words[index + 1] = (value >> 16) as u16;
}

pub(crate) fn prompt(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    #[cfg(test)]
    {
        run_dialog(scope, &[], deadline, expired, lease, None, None)
    }
    #[cfg(not(test))]
    {
        run_dialog(scope, &[], deadline, expired, lease)
    }
}

/// The personal access window: the same public scope, plus the selection of
/// exactly one identity among those the agent holds.
///
/// The acceptance button stays disabled until an identity is selected, so a
/// consent can never be given without naming which key it applies to.
pub(crate) fn prompt_with_identities(
    scope: &AssistantScopeV1,
    identities: &[OfferedIdentity],
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    #[cfg(test)]
    {
        run_dialog(scope, identities, deadline, expired, lease, None, None)
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
    #[cfg(test)] observed: Option<&mut IdentityObservation>,
) -> PromptOutcome {
    let Ok(validated_scope) = scope.clone().validate() else {
        return PromptOutcome::Unavailable;
    };
    if validated_scope != *scope || lease.is_protocol_invalid() {
        return PromptOutcome::Unavailable;
    }
    if expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
        return PromptOutcome::Expired;
    }
    if lease.is_cancelled() {
        return PromptOutcome::Cancelled;
    }

    let Some(mut state) = DialogState::new(
        scope,
        identities,
        deadline,
        expired,
        lease,
        #[cfg(test)]
        automatic_action,
    ) else {
        return PromptOutcome::Unavailable;
    };
    let template = EmptyDialogTemplate::new(state.layout.dialog_height);
    let instance = unsafe { GetModuleHandleW(null()) };
    if instance.is_null() {
        return PromptOutcome::Unavailable;
    }
    // SAFETY: template is DWORD-aligned and contains the complete empty DLGTEMPLATE wire form.
    // state remains at a stable stack address for this synchronous modal call, and dialog_proc
    // stores its pointer only for the lifetime of that call.
    let result = unsafe {
        DialogBoxIndirectParamW(
            instance,
            template.0.as_ptr().cast(),
            null_mut(),
            Some(dialog_proc),
            (&mut state as *mut DialogState) as LPARAM,
        )
    };

    #[cfg(test)]
    if let Some(slot) = observed {
        *slot = state.observation.clone();
    }
    if result != DIALOG_RESULT_DONE {
        return PromptOutcome::Unavailable;
    }
    state.outcome.take().unwrap_or(PromptOutcome::Unavailable)
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

struct DialogState {
    prompt: NativePromptKind,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    lease: LeaseState,
    title: Vec<u16>,
    scope_text: Vec<u16>,
    countdown_text: Vec<u16>,
    secret_label_text: Option<Vec<u16>>,
    identity_label_text: Option<Vec<u16>>,
    /// The rows the window offers, each as its fingerprint and its line. The
    /// consent names one of these, never a string read back from the control.
    identity_rows: Vec<(String, String)>,
    accept_text: Vec<u16>,
    refuse_text: Vec<u16>,
    scope_control: HWND,
    countdown_control: HWND,
    secret_label_control: HWND,
    secret_edit_control: HWND,
    identity_label_control: HWND,
    identity_control: HWND,
    accept_control: HWND,
    refuse_control: HWND,
    layout: DialogLayout,
    outcome: Option<PromptOutcome>,
    #[cfg(test)]
    automatic_action: Option<AutomaticAction>,
    #[cfg(test)]
    observation: IdentityObservation,
}

impl DialogState {
    fn new(
        scope: &AssistantScopeV1,
        identities: &[OfferedIdentity],
        deadline: Instant,
        expired: Arc<AtomicBool>,
        lease: LeaseState,
        #[cfg(test)] automatic_action: Option<AutomaticAction>,
    ) -> Option<Self> {
        let (title, secret_label, accept) = prompt_copy(scope.prompt);
        let rendered_scope = scope_text(scope);
        let scope_line_count = rendered_scope.split("\r\n").count();
        let has_secret_entry = matches!(
            scope.prompt,
            NativePromptKind::KeyPassphrase | NativePromptKind::SudoPassword
        );
        // An agent that holds only certificates still gets a chooser, empty:
        // the window must show that there is nothing this palier may sign
        // with, and acceptance stays out of reach rather than falling back on
        // a consent that names no key.
        let has_identity_chooser = !identities.is_empty();
        let layout = DialogLayout::new(scope_line_count, has_secret_entry || has_identity_chooser)?;
        Some(Self {
            prompt: scope.prompt,
            deadline,
            expired,
            lease,
            title: wide(title),
            scope_text: wide(&rendered_scope),
            countdown_text: wide(&countdown_text(deadline)),
            secret_label_text: secret_label.map(wide),
            identity_label_text: has_identity_chooser.then(|| wide(IDENTITY_LABEL)),
            identity_rows: selectable_identities(identities),
            accept_text: wide(accept),
            refuse_text: wide("&Refuser"),
            scope_control: null_mut(),
            countdown_control: null_mut(),
            secret_label_control: null_mut(),
            secret_edit_control: null_mut(),
            identity_label_control: null_mut(),
            identity_control: null_mut(),
            accept_control: null_mut(),
            refuse_control: null_mut(),
            layout,
            outcome: None,
            #[cfg(test)]
            automatic_action,
            #[cfg(test)]
            observation: IdentityObservation::default(),
        })
    }

    fn has_secret_entry(&self) -> bool {
        matches!(
            self.prompt,
            NativePromptKind::KeyPassphrase | NativePromptKind::SudoPassword
        )
    }

    fn has_identity_chooser(&self) -> bool {
        self.identity_label_text.is_some()
    }
}

/// What an in-process run read back from the live identity chooser.
///
/// It exists so a case can name what the window really offered, and whether
/// acceptance was reachable, without any of it travelling through an outcome.
#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct IdentityObservation {
    /// The rows read back from the control itself, in order.
    rows: Vec<String>,
    /// Whether the acceptance button was enabled before anything was named.
    accept_enabled_before_selection: bool,
    /// Whether it was enabled when the acceptance was finally acted upon.
    accept_enabled_at_acceptance: bool,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum AutomaticAction {
    Refuse,
    Cancel,
    Close,
    ActivateDefault,
    Accept,
    EnterSecretAndAccept(&'static str),
    EnterSecretAndRefuse(&'static str),
    EnterSecretAndCancel(&'static str),
    EnterSecretAndClose(&'static str),
    EnterSecretThenCancelLease(&'static str),
    EnterSecretThenInvalidateLease(&'static str),
    EnterSecret(&'static str),
    TamperSecretControlAndAccept,
    TamperPublicScope,
    /// Read the offered rows back, then accept without naming anything.
    AcceptWithoutSelection,
    /// Read the offered rows back, name one exactly as the control would, then
    /// accept.
    SelectIdentityAndAccept(usize),
    /// Add a row this window never offered, and let the next tick judge it.
    TamperIdentityList,
}

unsafe extern "system" fn dialog_proc(
    dialog: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match message {
        WM_INITDIALOG => {
            let state = lparam as *mut DialogState;
            if state.is_null() {
                // No state means no trusted native scope from which to construct the surface.
                let _ = EndDialog(dialog, DIALOG_RESULT_DONE);
                return 1;
            }
            let _ = SetWindowLongPtrW(dialog, DWLP_USER, lparam);
            let state = &mut *state;
            if GetWindowLongPtrW(dialog, DWLP_USER) != lparam {
                state.outcome = Some(PromptOutcome::Unavailable);
                let _ = EndDialog(dialog, DIALOG_RESULT_DONE);
                return 1;
            }
            if !initialize_dialog(dialog, state) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return 1;
            }
            if !focus_initial_control(state) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return 1;
            }
            // WM_INITDIALOG must return FALSE after the application explicitly sets focus.
            0
        }
        WM_TIMER => {
            let state = state_pointer(dialog);
            if state.is_null() {
                return 0;
            }
            let state = &mut *state;
            #[cfg(test)]
            if perform_automatic_action(dialog, state) {
                return 1;
            }
            if state.lease.is_protocol_invalid() {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
            } else if state.expired.load(Ordering::SeqCst) || Instant::now() >= state.deadline {
                finish_dialog(dialog, state, PromptOutcome::Expired);
            } else if state.lease.is_cancelled() {
                finish_dialog(dialog, state, PromptOutcome::Cancelled);
            } else if !public_surface_is_intact(dialog, state) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
            } else if !refresh_countdown(state) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
            }
            1
        }
        WM_COMMAND => {
            let control_id = (wparam & 0xffff) as i32;
            let notification_code = ((wparam >> 16) & 0xffff) as u32;
            if control_id == IDENTITY_CONTROL_ID && notification_code == CBN_SELCHANGE {
                let state = state_pointer(dialog);
                if state.is_null() {
                    return 0;
                }
                let state = &*state;
                // Only the chooser this window created may move acceptance.
                if lparam == state.identity_control as LPARAM {
                    refresh_accept_availability(state);
                }
                return 1;
            }
            if !matches!(control_id, REFUSE_CONTROL_ID | IDOK | IDCANCEL)
                || notification_code != BN_CLICKED
            {
                // In particular, SetWindowTextW on the EDIT can synchronously notify its parent.
                // Focus notifications can also re-enter here during WM_INITDIALOG. Ignore every
                // non-click notification without re-borrowing DialogState.
                return 0;
            }
            let state = state_pointer(dialog);
            if state.is_null() {
                return 0;
            }
            let state = &mut *state;
            match control_id {
                REFUSE_CONTROL_ID => {
                    finish_dialog(dialog, state, PromptOutcome::Refused);
                    1
                }
                IDOK => {
                    accept_dialog(dialog, state);
                    1
                }
                // Escape is deliberately distinct from the visible refusal action.
                IDCANCEL => {
                    finish_dialog(dialog, state, PromptOutcome::Cancelled);
                    1
                }
                _ => 0,
            }
        }
        WM_CLOSE => {
            let state = state_pointer(dialog);
            if state.is_null() {
                return 0;
            }
            finish_dialog(dialog, &mut *state, PromptOutcome::Cancelled);
            1
        }
        WM_DESTROY => {
            let _ = KillTimer(dialog, TIMER_ID);
            0
        }
        _ => 0,
    }
}

#[cfg(test)]
unsafe fn perform_automatic_action(dialog: HWND, state: &mut DialogState) -> bool {
    let Some(action) = state.automatic_action.take() else {
        return false;
    };
    match action {
        AutomaticAction::Refuse => {
            post_command(dialog, REFUSE_CONTROL_ID, state.refuse_control, state)
        }
        AutomaticAction::Cancel => post_command(dialog, IDCANCEL, null_mut(), state),
        AutomaticAction::Close => post_dialog_message(dialog, state, WM_CLOSE, 0, 0),
        AutomaticAction::ActivateDefault => {
            let Some(control_id) = default_control_id(dialog) else {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            };
            let control = match control_id {
                REFUSE_CONTROL_ID => state.refuse_control,
                IDOK => state.accept_control,
                _ => null_mut(),
            };
            post_command(dialog, control_id, control, state)
        }
        AutomaticAction::Accept => post_command(dialog, IDOK, state.accept_control, state),
        AutomaticAction::EnterSecretAndAccept(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            post_command(dialog, IDOK, state.accept_control, state)
        }
        AutomaticAction::EnterSecretAndRefuse(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            post_command(dialog, REFUSE_CONTROL_ID, state.refuse_control, state)
        }
        AutomaticAction::EnterSecretAndCancel(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            post_command(dialog, IDCANCEL, null_mut(), state)
        }
        AutomaticAction::EnterSecretAndClose(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            post_dialog_message(dialog, state, WM_CLOSE, 0, 0)
        }
        AutomaticAction::EnterSecretThenCancelLease(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            state.lease.cancel_for_test();
            false
        }
        AutomaticAction::EnterSecretThenInvalidateLease(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            state.lease.invalidate_for_test();
            false
        }
        AutomaticAction::EnterSecret(value) => {
            if !preload_test_secret(state, value) {
                finish_dialog(dialog, state, PromptOutcome::Unavailable);
                return true;
            }
            false
        }
        AutomaticAction::TamperSecretControlAndAccept => {
            let _ = SendMessageW(
                state.secret_edit_control,
                EM_SETLIMITTEXT,
                MAX_SECRET_UNITS + 1,
                0,
            );
            post_command(dialog, IDOK, state.accept_control, state)
        }
        AutomaticAction::TamperPublicScope => {
            let _ = SetWindowTextW(state.scope_control, wide("scope altered").as_ptr());
            false
        }
        AutomaticAction::AcceptWithoutSelection => {
            observe_identity_chooser(state);
            post_command(dialog, IDOK, state.accept_control, state)
        }
        AutomaticAction::SelectIdentityAndAccept(index) => {
            observe_identity_chooser(state);
            let _ = SendMessageW(state.identity_control, CB_SETCURSEL, index, 0);
            // `CB_SETCURSEL` deliberately notifies nobody, so the notification a
            // real selection sends is emitted here too: what is under test is
            // the path the control itself takes, not a shortcut into it.
            post_notification(
                dialog,
                IDENTITY_CONTROL_ID,
                CBN_SELCHANGE,
                state.identity_control,
                state,
            ) && post_command(dialog, IDOK, state.accept_control, state)
        }
        AutomaticAction::TamperIdentityList => {
            let row = wide("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            let _ = SendMessageW(
                state.identity_control,
                CB_ADDSTRING,
                0,
                row.as_ptr() as LPARAM,
            );
            false
        }
    }
}

/// Record what the live chooser offers and whether acceptance is reachable.
#[cfg(test)]
unsafe fn observe_identity_chooser(state: &mut DialogState) {
    state.observation.accept_enabled_before_selection = IsWindowEnabled(state.accept_control) != 0;
    state.observation.rows = read_combo_rows(state.identity_control);
}

/// The rows as the control itself holds them, read back one by one.
#[cfg(test)]
unsafe fn read_combo_rows(chooser: HWND) -> Vec<String> {
    if chooser.is_null() {
        return Vec::new();
    }
    let Ok(count) = usize::try_from(SendMessageW(chooser, CB_GETCOUNT, 0, 0)) else {
        return Vec::new();
    };
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let Ok(units) = usize::try_from(SendMessageW(chooser, CB_GETLBTEXTLEN, index, 0)) else {
            return Vec::new();
        };
        let mut text = vec![0_u16; units + 1];
        let copied = SendMessageW(chooser, CB_GETLBTEXT, index, text.as_mut_ptr() as LPARAM);
        if usize::try_from(copied).ok() != Some(units) {
            return Vec::new();
        }
        rows.push(String::from_utf16_lossy(&text[..units]));
    }
    rows
}

#[cfg(test)]
unsafe fn preload_test_secret(state: &DialogState, value: &str) -> bool {
    !state.secret_edit_control.is_null()
        && SetWindowTextW(state.secret_edit_control, wide(value).as_ptr()) != 0
}

#[cfg(test)]
unsafe fn post_command(
    dialog: HWND,
    control_id: i32,
    control: HWND,
    state: &mut DialogState,
) -> bool {
    post_dialog_message(
        dialog,
        state,
        WM_COMMAND,
        control_id as WPARAM,
        control as LPARAM,
    )
}

#[cfg(test)]
unsafe fn post_notification(
    dialog: HWND,
    control_id: i32,
    notification: u32,
    control: HWND,
    state: &mut DialogState,
) -> bool {
    let wparam = (control_id as usize & 0xffff) | ((notification as usize) << 16);
    post_dialog_message(dialog, state, WM_COMMAND, wparam, control as LPARAM)
}

#[cfg(test)]
unsafe fn post_dialog_message(
    dialog: HWND,
    state: &mut DialogState,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> bool {
    // Posting avoids synchronously re-entering dialog_proc while the timer handler owns state.
    if PostMessageW(dialog, message, wparam, lparam) == 0 {
        finish_dialog(dialog, state, PromptOutcome::Unavailable);
    }
    true
}

unsafe fn state_pointer(dialog: HWND) -> *mut DialogState {
    GetWindowLongPtrW(dialog, DWLP_USER) as *mut DialogState
}

unsafe fn focus_initial_control(state: &DialogState) -> bool {
    let control = if state.has_secret_entry() {
        state.secret_edit_control
    } else {
        state.refuse_control
    };
    if control.is_null() {
        return false;
    }
    let _ = SetFocus(control);
    GetFocus() == control
}

unsafe fn initialize_dialog(dialog: HWND, state: &mut DialogState) -> bool {
    if SetWindowTextW(dialog, state.title.as_ptr()) == 0 {
        return false;
    }

    state.scope_control = create_control(
        dialog,
        STATIC_CLASS.as_ptr(),
        state.scope_text.as_ptr(),
        WS_CHILD | WS_VISIBLE,
        0,
        SCOPE_CONTROL_ID,
        DialogRect::new(12, 10, 316, state.layout.scope_height),
    );
    state.countdown_control = create_control(
        dialog,
        STATIC_CLASS.as_ptr(),
        state.countdown_text.as_ptr(),
        WS_CHILD | WS_VISIBLE,
        0,
        COUNTDOWN_CONTROL_ID,
        DialogRect::new(12, state.layout.countdown_y, 316, 14),
    );

    if state.has_secret_entry() {
        let Some(secret_label_text) = state.secret_label_text.as_ref() else {
            return false;
        };
        state.secret_label_control = create_control(
            dialog,
            STATIC_CLASS.as_ptr(),
            secret_label_text.as_ptr(),
            WS_CHILD | WS_VISIBLE,
            0,
            SECRET_LABEL_CONTROL_ID,
            DialogRect::new(12, state.layout.lower_label_y, 316, 13),
        );
        state.secret_edit_control = create_control(
            dialog,
            EDIT_CLASS.as_ptr(),
            wide_empty().as_ptr(),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_BORDER
                | ES_AUTOHSCROLL as u32
                | ES_PASSWORD as u32,
            WS_EX_CLIENTEDGE,
            SECRET_EDIT_CONTROL_ID,
            DialogRect::new(12, state.layout.lower_control_y, 316, 17),
        );
        if state.secret_edit_control.is_null() {
            return false;
        }
        let _ = SendMessageW(
            state.secret_edit_control,
            EM_SETLIMITTEXT,
            MAX_SECRET_UNITS,
            0,
        );
    }

    if state.has_identity_chooser() {
        let Some(identity_label_text) = state.identity_label_text.as_ref() else {
            return false;
        };
        state.identity_label_control = create_control(
            dialog,
            STATIC_CLASS.as_ptr(),
            identity_label_text.as_ptr(),
            WS_CHILD | WS_VISIBLE,
            0,
            IDENTITY_LABEL_CONTROL_ID,
            DialogRect::new(12, state.layout.lower_label_y, 316, 13),
        );
        state.identity_control = create_control(
            dialog,
            COMBOBOX_CLASS.as_ptr(),
            wide_empty().as_ptr(),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_VSCROLL
                | CBS_DROPDOWNLIST as u32
                | CBS_HASSTRINGS as u32,
            0,
            IDENTITY_CONTROL_ID,
            DialogRect::new(
                12,
                state.layout.lower_control_y,
                316,
                IDENTITY_LIST_HEIGHT_DLU,
            ),
        );
        if state.identity_label_control.is_null() || state.identity_control.is_null() {
            return false;
        }
        // Each row is named by its own SHA-256 fingerprint, which is also the
        // value the transport later binds its signature budget to, so what the
        // user reads and what gets signed cannot drift apart.
        for (_, line) in &state.identity_rows {
            let row = wide(line);
            if SendMessageW(
                state.identity_control,
                CB_ADDSTRING,
                0,
                row.as_ptr() as LPARAM,
            ) < 0
            {
                return false;
            }
        }
        if SendMessageW(state.identity_control, CB_GETCOUNT, 0, 0)
            != state.identity_rows.len() as isize
        {
            return false;
        }
        // Nothing is preselected, so acceptance starts out of reach and only a
        // named identity may bring it back.
        if SendMessageW(state.identity_control, CB_GETCURSEL, 0, 0) != CB_ERR as isize {
            return false;
        }
    }

    // Creation order keeps the secret entry first in the tab order when present. Otherwise the
    // refusal button is the first focusable control and remains the explicit default.
    state.refuse_control = create_control(
        dialog,
        BUTTON_CLASS.as_ptr(),
        state.refuse_text.as_ptr(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
        0,
        REFUSE_CONTROL_ID,
        DialogRect::new(166, state.layout.button_y, 78, 22),
    );
    state.accept_control = create_control(
        dialog,
        BUTTON_CLASS.as_ptr(),
        state.accept_text.as_ptr(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
        0,
        IDOK,
        DialogRect::new(250, state.layout.button_y, 78, 22),
    );

    if [
        state.scope_control,
        state.countdown_control,
        state.refuse_control,
        state.accept_control,
    ]
    .iter()
    .any(|handle| handle.is_null())
        || (state.has_secret_entry() && state.secret_label_control.is_null())
    {
        return false;
    }

    // A consent cannot be given without saying which key it applies to: while
    // the chooser names nothing, the acceptance button is not available at all.
    if state.has_identity_chooser() {
        refresh_accept_availability(state);
        if IsWindowEnabled(state.accept_control) != 0 {
            return false;
        }
    }

    let _ = SendMessageW(dialog, DM_SETDEFID, REFUSE_CONTROL_ID as usize, 0);
    if default_control_id(dialog) != Some(REFUSE_CONTROL_ID) {
        return false;
    }
    SetTimer(
        dialog,
        TIMER_ID,
        u32::try_from(TIMER_INTERVAL.as_millis()).unwrap_or(25),
        None,
    ) != 0
}

unsafe fn default_control_id(dialog: HWND) -> Option<i32> {
    let result = SendMessageW(dialog, DM_GETDEFID, 0, 0) as usize;
    if ((result >> 16) & 0xffff) as u32 != DC_HASDEFID {
        return None;
    }
    Some((result & 0xffff) as i32)
}

#[derive(Clone, Copy)]
struct DialogRect {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

impl DialogRect {
    const fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

unsafe fn create_control(
    dialog: HWND,
    class: *const u16,
    text: *const u16,
    style: u32,
    extended_style: u32,
    identifier: i32,
    rect: DialogRect,
) -> HWND {
    let mut pixels = RECT {
        left: rect.x,
        top: rect.y,
        right: rect.x + rect.width,
        bottom: rect.y + rect.height,
    };
    if MapDialogRect(dialog, &mut pixels) == 0 {
        return null_mut();
    }
    CreateWindowExW(
        extended_style,
        class,
        text,
        style,
        pixels.left,
        pixels.top,
        pixels.right - pixels.left,
        pixels.bottom - pixels.top,
        dialog,
        identifier as usize as _,
        null_mut(),
        null(),
    )
}

unsafe fn accept_dialog(dialog: HWND, state: &mut DialogState) {
    #[cfg(test)]
    {
        state.observation.accept_enabled_at_acceptance = IsWindowEnabled(state.accept_control) != 0;
    }
    if state.lease.is_protocol_invalid() || !public_surface_is_intact(dialog, state) {
        finish_dialog(dialog, state, PromptOutcome::Unavailable);
        return;
    }
    if state.expired.load(Ordering::SeqCst) || Instant::now() >= state.deadline {
        finish_dialog(dialog, state, PromptOutcome::Expired);
        return;
    }
    if state.lease.is_cancelled() {
        finish_dialog(dialog, state, PromptOutcome::Cancelled);
        return;
    }

    match state.prompt {
        // The root window offers the same list for the same reason: the session
        // it consents to still has to authenticate with one named identity, and
        // a consent that did not say which would be leaving that choice to
        // something downstream.
        NativePromptKind::ConfirmPersonalAccess | NativePromptKind::ConfirmRootAccess
            if state.has_identity_chooser() =>
        {
            // The selected identity travels with the consent: nothing
            // downstream may choose a key on the user's behalf.
            match selected_fingerprint(state) {
                Some(fingerprint) => finish_dialog(
                    dialog,
                    state,
                    PromptOutcome::ConsentWithIdentity(fingerprint),
                ),
                None => finish_dialog(dialog, state, PromptOutcome::Refused),
            }
        }
        NativePromptKind::ConfirmPersonalAccess | NativePromptKind::ConfirmRootAccess => {
            finish_dialog(dialog, state, PromptOutcome::Consent);
        }
        NativePromptKind::KeyPassphrase | NativePromptKind::SudoPassword => {
            match capture_secret(state.secret_edit_control) {
                Ok(secret) => finish_dialog(dialog, state, PromptOutcome::Secret(secret)),
                Err(CaptureSecretError::Empty) => {
                    finish_dialog(dialog, state, PromptOutcome::Refused)
                }
                Err(CaptureSecretError::Unavailable) => {
                    finish_dialog(dialog, state, PromptOutcome::Unavailable)
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureSecretError {
    Empty,
    Unavailable,
}

fn classify_secret_units(units: i32, last_error: u32) -> Result<usize, CaptureSecretError> {
    if units == 0 {
        return if last_error == 0 {
            Err(CaptureSecretError::Empty)
        } else {
            Err(CaptureSecretError::Unavailable)
        };
    }
    usize::try_from(units)
        .ok()
        .filter(|units| *units <= MAX_SECRET_UNITS)
        .ok_or(CaptureSecretError::Unavailable)
}

unsafe fn capture_secret(edit: HWND) -> Result<ProtectedSecret, CaptureSecretError> {
    if edit.is_null() || !secret_control_is_intact(edit) {
        return Err(CaptureSecretError::Unavailable);
    }
    SetLastError(0);
    let units = GetWindowTextLengthW(edit);
    let expected_units = classify_secret_units(units, GetLastError())?;

    let mut secret = ProtectedSecret::new().map_err(|_| CaptureSecretError::Unavailable)?;
    let storage = secret.raw_mut();
    let capacity_with_nul = storage.len() / size_of::<u16>();
    if capacity_with_nul < expected_units + 1 {
        return Err(CaptureSecretError::Unavailable);
    }
    // VirtualAlloc/mmap returns page-aligned storage, so this u16 view is aligned. GetWindowTextW
    // copies directly from the Win32 control into the locked and dump-excluded allocation; no
    // String or ordinary Vec ever owns the secret. The committed representation is native UTF-16
    // without its trailing NUL and remains opaque until the future bounded SSH consumer uses it.
    let destination = storage.as_mut_ptr().cast::<u16>();
    let copied = GetWindowTextW(
        edit,
        destination,
        i32::try_from(capacity_with_nul).map_err(|_| CaptureSecretError::Unavailable)?,
    );
    let copied = usize::try_from(copied).map_err(|_| CaptureSecretError::Unavailable)?;
    if copied == 0 || copied != expected_units {
        return Err(CaptureSecretError::Unavailable);
    }
    let bytes = copied
        .checked_mul(size_of::<u16>())
        .ok_or(CaptureSecretError::Unavailable)?;
    secret
        .set_len(bytes)
        .map_err(|_| CaptureSecretError::Unavailable)?;
    Ok(secret)
}

unsafe fn finish_dialog(dialog: HWND, state: &mut DialogState, mut outcome: PromptOutcome) {
    let _ = KillTimer(dialog, TIMER_ID);
    if !clear_edit_control(state.secret_edit_control) {
        // Dropping a captured secret here invokes ProtectedSecret's controlled zeroization.
        outcome = PromptOutcome::Unavailable;
    }
    state.outcome = Some(outcome);
    let _ = SetWindowLongPtrW(dialog, DWLP_USER, 0);
    let _ = EndDialog(dialog, DIALOG_RESULT_DONE);
}

unsafe fn clear_edit_control(edit: HWND) -> bool {
    edit.is_null()
        || (SetWindowTextW(edit, wide_empty().as_ptr()) != 0 && GetWindowTextLengthW(edit) == 0)
}

unsafe fn public_surface_is_intact(dialog: HWND, state: &DialogState) -> bool {
    window_text_equals(dialog, &state.title)
        && window_text_equals(state.scope_control, &state.scope_text)
        && window_text_equals(state.countdown_control, &state.countdown_text)
        && window_text_equals(state.refuse_control, &state.refuse_text)
        && window_text_equals(state.accept_control, &state.accept_text)
        && match state.secret_label_text.as_ref() {
            Some(expected) => {
                window_text_equals(state.secret_label_control, expected)
                    && secret_control_is_intact(state.secret_edit_control)
            }
            None => state.secret_label_control.is_null() && state.secret_edit_control.is_null(),
        }
        && match state.identity_label_text.as_ref() {
            Some(expected) => {
                window_text_equals(state.identity_label_control, expected)
                    && identity_chooser_is_intact(state)
            }
            None => state.identity_label_control.is_null() && state.identity_control.is_null(),
        }
}

unsafe fn secret_control_is_intact(edit: HWND) -> bool {
    if edit.is_null() || !class_name_is(edit, &EDIT_CLASS_NAME) {
        return false;
    }
    let style = GetWindowLongPtrW(edit, GWL_STYLE) as u32;
    style & ES_PASSWORD as u32 != 0
        && SendMessageW(edit, EM_GETLIMITTEXT, 0, 0) == MAX_SECRET_UNITS as isize
        && GetWindowTextLengthW(edit) <= MAX_SECRET_UNITS as i32
}

/// The chooser still offers exactly the rows this window put in it, and
/// acceptance is still out of reach while nothing is named.
///
/// Reading the rows back rather than trusting the insertion is what ties the
/// displayed line to the fingerprint the budget will be bound to: a row whose
/// text was altered no longer names what would be signed, and the window fails
/// closed instead of collecting a consent for something else.
unsafe fn identity_chooser_is_intact(state: &DialogState) -> bool {
    let chooser = state.identity_control;
    if chooser.is_null() || !class_name_is(chooser, &COMBOBOX_CLASS_NAME) {
        return false;
    }
    if isize::try_from(state.identity_rows.len()).ok()
        != Some(SendMessageW(chooser, CB_GETCOUNT, 0, 0))
    {
        return false;
    }
    for (index, (_, line)) in state.identity_rows.iter().enumerate() {
        if !combo_item_text_equals(chooser, index, line) {
            return false;
        }
    }
    IsWindowEnabled(state.accept_control) == 0 || selected_index(state).is_some()
}

unsafe fn class_name_is(window: HWND, expected: &[u16]) -> bool {
    let mut class = [0_u16; 32];
    if expected.len() >= class.len() {
        return false;
    }
    let class_units = GetClassNameW(window, class.as_mut_ptr(), class.len() as i32);
    usize::try_from(class_units).ok() == Some(expected.len())
        && class[..expected.len()] == *expected
}

unsafe fn combo_item_text_equals(chooser: HWND, index: usize, expected: &str) -> bool {
    let expected: Vec<u16> = expected.encode_utf16().collect();
    let units = SendMessageW(chooser, CB_GETLBTEXTLEN, index, 0);
    if usize::try_from(units).ok() != Some(expected.len()) {
        return false;
    }
    let mut actual = vec![0_u16; expected.len() + 1];
    let copied = SendMessageW(chooser, CB_GETLBTEXT, index, actual.as_mut_ptr() as LPARAM);
    usize::try_from(copied).ok() == Some(expected.len()) && actual[..expected.len()] == expected[..]
}

/// The row the user named, or nothing at all.
///
/// `CB_ERR` is negative and every index beyond the rows this window inserted is
/// refused, so an index is only ever resolved against the list this process
/// built itself.
unsafe fn selected_index(state: &DialogState) -> Option<usize> {
    if state.identity_control.is_null() {
        return None;
    }
    let index = usize::try_from(SendMessageW(state.identity_control, CB_GETCURSEL, 0, 0)).ok()?;
    (index < state.identity_rows.len()).then_some(index)
}

/// The fingerprint of the named row, taken from this process's own list rather
/// than from the control, so no text the control holds can become a consent.
unsafe fn selected_fingerprint(state: &DialogState) -> Option<String> {
    let index = selected_index(state)?;
    state
        .identity_rows
        .get(index)
        .map(|(fingerprint, _)| fingerprint.clone())
}

unsafe fn refresh_accept_availability(state: &DialogState) {
    if !state.has_identity_chooser() || state.accept_control.is_null() {
        return;
    }
    let _ = EnableWindow(
        state.accept_control,
        i32::from(selected_index(state).is_some()),
    );
}

unsafe fn window_text_equals(window: HWND, expected_with_nul: &[u16]) -> bool {
    if window.is_null() || expected_with_nul.last() != Some(&0) {
        return false;
    }
    let expected = &expected_with_nul[..expected_with_nul.len() - 1];
    let length = GetWindowTextLengthW(window);
    if length < 0 || usize::try_from(length).ok() != Some(expected.len()) {
        return false;
    }
    let mut actual = vec![0_u16; expected.len() + 1];
    let copied = GetWindowTextW(
        window,
        actual.as_mut_ptr(),
        i32::try_from(actual.len()).unwrap_or(i32::MAX),
    );
    usize::try_from(copied).ok() == Some(expected.len()) && actual[..expected.len()] == expected[..]
}

unsafe fn refresh_countdown(state: &mut DialogState) -> bool {
    let next = wide(&countdown_text(state.deadline));
    if next == state.countdown_text {
        return true;
    }
    if SetWindowTextW(state.countdown_control, next.as_ptr()) == 0 {
        return false;
    }
    state.countdown_text = next;
    true
}

fn prompt_copy(prompt: NativePromptKind) -> (&'static str, Option<&'static str>, &'static str) {
    match prompt {
        NativePromptKind::ConfirmPersonalAccess => (
            "Your Cloud — autoriser l’accès personnel",
            None,
            "&Autoriser l’audit",
        ),
        NativePromptKind::ConfirmRootAccess => (
            "Your Cloud — confirmer l’accès root",
            None,
            "&Confirmer root",
        ),
        NativePromptKind::KeyPassphrase => (
            "Your Cloud — passphrase de la clé SSH",
            Some("Passphrase de la clé SSH :"),
            "&Continuer",
        ),
        NativePromptKind::SudoPassword => (
            "Your Cloud — mot de passe sudo",
            Some("Mot de passe sudo :"),
            "&Continuer",
        ),
    }
}

fn scope_text(scope: &AssistantScopeV1) -> String {
    logical_scope_lines(scope)
        .into_iter()
        .flat_map(|line| wrap_public_line(&line))
        .collect::<Vec<_>>()
        .join("\r\n")
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

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn wide_empty() -> [u16; 1] {
    [0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use your_cloud_bootstrap_protocol::{BootstrapTarget, MAX_HOST_BYTES, MAX_USERNAME_BYTES};

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SYNTHETIC_SECRET: &str = "synthetic-\u{1f512}-canary";

    fn scope(prompt: NativePromptKind, access_kind: BootstrapAccessKind) -> AssistantScopeV1 {
        let step = match prompt {
            NativePromptKind::ConfirmPersonalAccess => BootstrapStep::PersonalAccess,
            NativePromptKind::KeyPassphrase => BootstrapStep::UnlockPersonalKey,
            NativePromptKind::SudoPassword => BootstrapStep::PrivilegeEscalation,
            NativePromptKind::ConfirmRootAccess => BootstrapStep::RootAccess,
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
        let mut maximal = scope(prompt, BootstrapAccessKind::Administrator);
        maximal.target.host = host;
        maximal.target.username = "u".repeat(MAX_USERNAME_BYTES);
        maximal.target.port = u16::MAX;
        assert_eq!(maximal.clone().validate().unwrap(), maximal);
        maximal
    }

    #[test]
    fn public_copy_is_derived_only_from_the_validated_scope() {
        let scope = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        assert_eq!(
            logical_scope_lines(&scope),
            vec![
                "Parcours : création",
                "Cible : infra_admin@controller.example.test:22",
                "Route d’accès : administrateur",
                "Empreinte hôte : SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "Étape : accès personnel",
                "Action : audit de la cible en lecture seule",
            ]
        );
        let rendered = scope_text(&scope);
        assert!(rendered
            .split("\r\n")
            .all(|line| line.chars().count() <= MAX_PUBLIC_LINE_CHARACTERS));
        assert_eq!(
            rendered.replace("\r\n", ""),
            logical_scope_lines(&scope).concat()
        );
    }

    #[test]
    fn maximal_canonical_target_and_fingerprint_fit_the_computed_dialog() {
        let maximal = maximal_scope(NativePromptKind::KeyPassphrase);

        let logical = logical_scope_lines(&maximal);
        let rendered = scope_text(&maximal);
        let physical = rendered.split("\r\n").collect::<Vec<_>>();
        assert!(physical.len() > logical.len());
        assert!(physical
            .iter()
            .all(|line| line.chars().count() <= MAX_PUBLIC_LINE_CHARACTERS));
        assert_eq!(physical.concat(), logical.concat());
        let compact = physical.concat();
        assert!(compact.contains(&format!(
            "Cible : {}@{}:{}",
            maximal.target.username, maximal.target.host, maximal.target.port
        )));
        assert!(compact.contains(&format!(
            "Empreinte hôte : {}",
            maximal.target.host_key_sha256
        )));

        let layout = DialogLayout::new(physical.len(), true).unwrap();
        assert!(
            layout.scope_height
                >= i32::try_from(physical.len()).unwrap() * SCOPE_LINE_HEIGHT_DLU
                    + SCOPE_VERTICAL_PADDING_DLU
        );
        assert_eq!(i32::from(layout.dialog_height), layout.button_y + 22 + 15);
        assert_eq!(
            EmptyDialogTemplate::new(layout.dialog_height).0[8],
            layout.dialog_height
        );
    }

    #[test]
    fn invalid_secret_control_is_unavailable_not_an_empty_refusal() {
        assert_eq!(classify_secret_units(0, 0), Err(CaptureSecretError::Empty));
        assert_eq!(
            classify_secret_units(0, 5),
            Err(CaptureSecretError::Unavailable)
        );
        assert_eq!(
            classify_secret_units(-1, 0),
            Err(CaptureSecretError::Unavailable)
        );
        assert_eq!(
            classify_secret_units(MAX_SECRET_UNITS as i32 + 1, 0),
            Err(CaptureSecretError::Unavailable)
        );
        assert!(matches!(
            unsafe { capture_secret(null_mut()) },
            Err(CaptureSecretError::Unavailable)
        ));
    }

    #[test]
    fn root_and_sudo_prompts_are_never_interchangeable() {
        assert!(scope(
            NativePromptKind::ConfirmRootAccess,
            BootstrapAccessKind::Root,
        )
        .validate()
        .is_ok());
        assert!(scope(
            NativePromptKind::ConfirmRootAccess,
            BootstrapAccessKind::Administrator,
        )
        .validate()
        .is_err());
        assert!(scope(
            NativePromptKind::SudoPassword,
            BootstrapAccessKind::Administrator,
        )
        .validate()
        .is_ok());
        assert!(
            scope(NativePromptKind::SudoPassword, BootstrapAccessKind::Root,)
                .validate()
                .is_err()
        );
        assert!(prompt_copy(NativePromptKind::ConfirmRootAccess).1.is_none());
        assert!(prompt_copy(NativePromptKind::SudoPassword).1.is_some());
    }

    fn run_test_dialog(scope: &AssistantScopeV1, action: Option<AutomaticAction>) -> PromptOutcome {
        run_dialog(
            scope,
            &[],
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            LeaseState::active_for_test(),
            action,
            None,
        )
    }

    fn ed25519_identity(fingerprint: &str) -> OfferedIdentity {
        OfferedIdentity {
            algorithm: russh::keys::Algorithm::Ed25519,
            fingerprint: fingerprint.into(),
            is_certificate: false,
        }
    }

    /// One personal access window, driven with the identities the agent holds.
    fn run_identity_dialog(
        identities: &[OfferedIdentity],
        action: Option<AutomaticAction>,
    ) -> (PromptOutcome, IdentityObservation) {
        let mut observed = IdentityObservation::default();
        let outcome = run_dialog(
            &scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            ),
            identities,
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            LeaseState::active_for_test(),
            action,
            Some(&mut observed),
        );
        (outcome, observed)
    }

    fn protected_secret_equals_utf16(secret: &ProtectedSecret, expected: &str) -> bool {
        let bytes = secret.bytes();
        bytes.len() % size_of::<u16>() == 0
            && bytes
                .chunks_exact(size_of::<u16>())
                .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
                .eq(expected.encode_utf16())
    }

    #[test]
    #[ignore = "requires an isolated Windows desktop"]
    fn win32_dialog_handles_consent_secret_tamper_and_lease_states() {
        assert!(matches!(
            run_test_dialog(
                &maximal_scope(NativePromptKind::KeyPassphrase),
                Some(AutomaticAction::Refuse),
            ),
            PromptOutcome::Refused
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::Refuse),
            ),
            PromptOutcome::Refused
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::TamperSecretControlAndAccept),
            ),
            PromptOutcome::Unavailable
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::ActivateDefault),
            ),
            PromptOutcome::Refused
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::Cancel),
            ),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::Close),
            ),
            PromptOutcome::Cancelled
        ));
        for (prompt, access_kind) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            ),
            (
                NativePromptKind::ConfirmRootAccess,
                BootstrapAccessKind::Root,
            ),
        ] {
            assert!(matches!(
                run_test_dialog(&scope(prompt, access_kind), Some(AutomaticAction::Accept)),
                PromptOutcome::Consent
            ));
        }
        for prompt in [
            NativePromptKind::KeyPassphrase,
            NativePromptKind::SudoPassword,
        ] {
            let outcome = run_test_dialog(
                &scope(prompt, BootstrapAccessKind::Administrator),
                Some(AutomaticAction::EnterSecretAndAccept(SYNTHETIC_SECRET)),
            );
            let PromptOutcome::Secret(secret) = outcome else {
                panic!("Win32 secret prompt did not return protected memory");
            };
            // Boolean equality deliberately avoids formatting either byte sequence on failure.
            assert!(protected_secret_equals_utf16(&secret, SYNTHETIC_SECRET));
            drop(secret);
        }
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::Accept),
            ),
            PromptOutcome::Refused
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::EnterSecretAndRefuse(SYNTHETIC_SECRET)),
            ),
            PromptOutcome::Refused
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::EnterSecretAndCancel(SYNTHETIC_SECRET)),
            ),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::EnterSecretAndClose(SYNTHETIC_SECRET)),
            ),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::TamperPublicScope),
            ),
            PromptOutcome::Unavailable
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::EnterSecretThenCancelLease(
                    SYNTHETIC_SECRET,
                )),
            ),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            run_test_dialog(
                &scope(
                    NativePromptKind::SudoPassword,
                    BootstrapAccessKind::Administrator,
                ),
                Some(AutomaticAction::EnterSecretThenInvalidateLease(
                    SYNTHETIC_SECRET,
                )),
            ),
            PromptOutcome::Unavailable
        ));
        assert!(matches!(
            run_dialog(
                &scope(
                    NativePromptKind::KeyPassphrase,
                    BootstrapAccessKind::Administrator,
                ),
                &[],
                Instant::now() + Duration::from_millis(100),
                Arc::new(AtomicBool::new(false)),
                LeaseState::active_for_test(),
                Some(AutomaticAction::EnterSecret(SYNTHETIC_SECRET)),
                None,
            ),
            PromptOutcome::Expired
        ));
    }

    const FIRST_IDENTITY: &str = "SHA256:0ur4Vv8h1nRhKZ9lPqYq2sBvXwGx7cJd1KfE0mTnRbA";
    const SECOND_IDENTITY: &str = "SHA256:Zz9QaWxLm4Tn2VkJhRfCg7BdY6sXeUo1PtNvHcMi3Ek";
    const CERTIFICATE_IDENTITY: &str = "SHA256:Qq1WwEeRrTtYyUuIiOoPpAaSsDdFfGgHhJjKkLlZzX";

    fn offered_identities() -> Vec<OfferedIdentity> {
        vec![
            ed25519_identity(FIRST_IDENTITY),
            OfferedIdentity {
                is_certificate: true,
                ..ed25519_identity(CERTIFICATE_IDENTITY)
            },
            ed25519_identity(SECOND_IDENTITY),
        ]
    }

    fn offered_rows() -> Vec<String> {
        vec![
            format!("{} {FIRST_IDENTITY}", russh::keys::Algorithm::Ed25519),
            format!("{} {SECOND_IDENTITY}", russh::keys::Algorithm::Ed25519),
        ]
    }

    /// Each row is named by the exact fingerprint the budget will be bound to,
    /// and a certificate is never offered as a choice.
    #[test]
    fn only_plain_identities_are_offered_and_each_row_names_its_own_fingerprint() {
        let rows = selectable_identities(&offered_identities());
        assert_eq!(
            rows,
            vec![
                (FIRST_IDENTITY.to_string(), offered_rows()[0].clone()),
                (SECOND_IDENTITY.to_string(), offered_rows()[1].clone()),
            ],
            "a certificate must never be selectable at this palier"
        );
        assert!(rows[0].1.contains(FIRST_IDENTITY));
        assert!(selectable_identities(&[]).is_empty());
    }

    /// What the transport will dial must be readable before consent, next to
    /// the name it came from. An unresolved scope shows no address line at all
    /// rather than an empty or invented one.
    #[test]
    fn the_frozen_addresses_are_displayed_beside_the_name() {
        let mut resolved = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        resolved.target_addresses = vec!["192.168.1.10".into(), "2001:db8::1".into()];
        let resolved = resolved.validate().expect("a bounded frozen set");

        assert_eq!(
            logical_scope_lines(&resolved),
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
        assert!(
            !logical_scope_lines(&scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            ))
            .iter()
            .any(|line| line.starts_with("Adresses")),
            "nothing frozen yet means nothing to display"
        );
    }

    /// Eight IPv6 addresses is the widest set the perimeter accepts; it must
    /// still be shown whole, wrapped rather than cut, and the window must grow
    /// to hold it.
    #[test]
    fn a_maximal_frozen_set_is_wrapped_without_truncation() {
        let mut maximal = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        maximal.target_addresses = (1..=8)
            .map(|last| format!("2001:db8:aaaa:bbbb:cccc:dddd:eeee:{last:x}"))
            .collect();
        let maximal = maximal.validate().expect("eight canonical addresses");

        let logical = logical_scope_lines(&maximal);
        let rendered = scope_text(&maximal);
        let physical = rendered.split("\r\n").collect::<Vec<_>>();
        assert!(physical
            .iter()
            .all(|line| line.chars().count() <= MAX_PUBLIC_LINE_CHARACTERS));
        assert_eq!(physical.concat(), logical.concat());
        for address in &maximal.target_addresses {
            assert!(
                physical.concat().contains(address.as_str()),
                "{address} must stay readable in the consent window"
            );
        }
        let layout = DialogLayout::new(physical.len(), true).expect("a computable layout");
        assert!(
            layout.scope_height
                >= i32::try_from(physical.len()).unwrap() * SCOPE_LINE_HEIGHT_DLU
                    + SCOPE_VERTICAL_PADDING_DLU
        );
    }

    /// The identity selection of the personal access window, driven inside this
    /// process.
    ///
    /// It proves what the dialogue decides — the rows it really offers, the
    /// acceptance it withholds while nothing is named, the fingerprint a
    /// consent carries, the refusals it leaves untouched. It proves nothing
    /// about a *visible* window: this run never asks whether the dialog gained
    /// `WS_VISIBLE`, because the only session this LAB can open is session 0,
    /// whose window station is not interactive.
    #[test]
    #[ignore = "requires an isolated Windows desktop"]
    fn win32_identity_selection_binds_one_consent_to_one_chosen_fingerprint() {
        let identities = offered_identities();

        // What the window offers is read back from the control itself: the
        // certificate is absent, and each row names its own fingerprint.
        let (outcome, observed) =
            run_identity_dialog(&identities, Some(AutomaticAction::AcceptWithoutSelection));
        assert_eq!(observed.rows, offered_rows());
        assert!(
            !observed
                .rows
                .iter()
                .any(|row| row.contains(CERTIFICATE_IDENTITY)),
            "a certificate must never be offered at this palier"
        );
        // Acceptance is out of reach while nothing is named, and accepting
        // anyway can only refuse — never consent to an unnamed key.
        assert!(!observed.accept_enabled_before_selection);
        assert!(!observed.accept_enabled_at_acceptance);
        assert!(matches!(outcome, PromptOutcome::Refused));

        // Naming a row makes acceptance available, and the consent carries that
        // row's fingerprint and no other.
        for (index, expected) in [(0_usize, FIRST_IDENTITY), (1, SECOND_IDENTITY)] {
            let (outcome, observed) = run_identity_dialog(
                &identities,
                Some(AutomaticAction::SelectIdentityAndAccept(index)),
            );
            assert!(!observed.accept_enabled_before_selection);
            assert!(observed.accept_enabled_at_acceptance);
            let PromptOutcome::ConsentWithIdentity(fingerprint) = outcome else {
                panic!("a named identity did not produce a consent that carries it");
            };
            assert_eq!(fingerprint, expected);
        }

        // An agent holding nothing this palier may sign with still gets a
        // window, and it can only be refused.
        let (outcome, observed) = run_identity_dialog(
            &[OfferedIdentity {
                is_certificate: true,
                ..ed25519_identity(CERTIFICATE_IDENTITY)
            }],
            Some(AutomaticAction::AcceptWithoutSelection),
        );
        assert!(observed.rows.is_empty());
        assert!(!observed.accept_enabled_at_acceptance);
        assert!(matches!(outcome, PromptOutcome::Refused));

        // A row this window never offered makes the whole surface untrusted.
        let (outcome, _) =
            run_identity_dialog(&identities, Some(AutomaticAction::TamperIdentityList));
        assert!(matches!(outcome, PromptOutcome::Unavailable));

        // Refusal, escape and closing keep the meaning they have everywhere
        // else, chooser or not.
        for (action, expected_refusal) in [
            (AutomaticAction::Refuse, true),
            (AutomaticAction::ActivateDefault, true),
            (AutomaticAction::Cancel, false),
            (AutomaticAction::Close, false),
        ] {
            let (outcome, _) = run_identity_dialog(&identities, Some(action));
            if expected_refusal {
                assert!(matches!(outcome, PromptOutcome::Refused));
            } else {
                assert!(matches!(outcome, PromptOutcome::Cancelled));
            }
        }
    }
}
