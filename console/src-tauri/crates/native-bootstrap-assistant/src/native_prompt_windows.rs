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
use windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW;
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, HWND, LPARAM, RECT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Input::KeyboardAndMouse::{GetFocus, SetFocus},
        WindowsAndMessaging::{
            CreateWindowExW, DialogBoxIndirectParamW, EndDialog, GetClassNameW, GetWindowLongPtrW,
            GetWindowTextLengthW, GetWindowTextW, KillTimer, MapDialogRect, SendMessageW, SetTimer,
            SetWindowLongPtrW, SetWindowTextW, BN_CLICKED, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
            DC_HASDEFID, DM_GETDEFID, DM_SETDEFID, DS_CENTER, DS_MODALFRAME, ES_AUTOHSCROLL,
            ES_PASSWORD, GWL_STYLE, IDCANCEL, IDOK, WM_CLOSE, WM_COMMAND, WM_DESTROY,
            WM_INITDIALOG, WM_TIMER, WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE, WS_POPUP,
            WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
        },
    },
};
use your_cloud_bootstrap_protocol::{
    AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
    NativePromptKind,
};

use crate::{secret::ProtectedSecret, LeaseState, PromptOutcome};

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
const BASE_SECRET_LABEL_Y_DLU: i32 = 146;
const BASE_SECRET_EDIT_Y_DLU: i32 = 162;
const BASE_SECRET_BUTTON_Y_DLU: i32 = 198;
const BASE_CONSENT_BUTTON_Y_DLU: i32 = 166;
const BASE_DIALOG_HEIGHT_DLU: i32 = 235;

const SCOPE_CONTROL_ID: i32 = 1_001;
const COUNTDOWN_CONTROL_ID: i32 = 1_002;
const SECRET_LABEL_CONTROL_ID: i32 = 1_003;
const SECRET_EDIT_CONTROL_ID: i32 = 1_004;
const REFUSE_CONTROL_ID: i32 = 1_005;

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
    secret_label_y: i32,
    secret_edit_y: i32,
    button_y: i32,
    dialog_height: u16,
}

impl DialogLayout {
    fn new(scope_line_count: usize, has_secret_entry: bool) -> Option<Self> {
        let required_scope_height = i32::try_from(scope_line_count)
            .ok()?
            .checked_mul(SCOPE_LINE_HEIGHT_DLU)?
            .checked_add(SCOPE_VERTICAL_PADDING_DLU)?;
        let scope_height = BASE_SCOPE_HEIGHT_DLU.max(required_scope_height);
        let additional_height = scope_height.checked_sub(BASE_SCOPE_HEIGHT_DLU)?;
        let countdown_y = BASE_COUNTDOWN_Y_DLU.checked_add(additional_height)?;
        let secret_label_y = BASE_SECRET_LABEL_Y_DLU.checked_add(additional_height)?;
        let secret_edit_y = BASE_SECRET_EDIT_Y_DLU.checked_add(additional_height)?;
        let button_y = if has_secret_entry {
            BASE_SECRET_BUTTON_Y_DLU
        } else {
            BASE_CONSENT_BUTTON_Y_DLU
        }
        .checked_add(additional_height)?;
        let dialog_height =
            u16::try_from(BASE_DIALOG_HEIGHT_DLU.checked_add(additional_height)?).ok()?;
        Some(Self {
            scope_height,
            countdown_y,
            secret_label_y,
            secret_edit_y,
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

    if result != DIALOG_RESULT_DONE {
        return PromptOutcome::Unavailable;
    }
    state.outcome.take().unwrap_or(PromptOutcome::Unavailable)
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
    accept_text: Vec<u16>,
    refuse_text: Vec<u16>,
    scope_control: HWND,
    countdown_control: HWND,
    secret_label_control: HWND,
    secret_edit_control: HWND,
    accept_control: HWND,
    refuse_control: HWND,
    layout: DialogLayout,
    outcome: Option<PromptOutcome>,
    #[cfg(test)]
    automatic_action: Option<AutomaticAction>,
}

impl DialogState {
    fn new(
        scope: &AssistantScopeV1,
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
        let layout = DialogLayout::new(scope_line_count, has_secret_entry)?;
        Some(Self {
            prompt: scope.prompt,
            deadline,
            expired,
            lease,
            title: wide(title),
            scope_text: wide(&rendered_scope),
            countdown_text: wide(&countdown_text(deadline)),
            secret_label_text: secret_label.map(wide),
            accept_text: wide(accept),
            refuse_text: wide("&Refuser"),
            scope_control: null_mut(),
            countdown_control: null_mut(),
            secret_label_control: null_mut(),
            secret_edit_control: null_mut(),
            accept_control: null_mut(),
            refuse_control: null_mut(),
            layout,
            outcome: None,
            #[cfg(test)]
            automatic_action,
        })
    }

    fn has_secret_entry(&self) -> bool {
        matches!(
            self.prompt,
            NativePromptKind::KeyPassphrase | NativePromptKind::SudoPassword
        )
    }
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
    }
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
            DialogRect::new(12, state.layout.secret_label_y, 316, 13),
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
            DialogRect::new(12, state.layout.secret_edit_y, 316, 17),
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
}

unsafe fn secret_control_is_intact(edit: HWND) -> bool {
    if edit.is_null() {
        return false;
    }
    let mut class = [0_u16; 16];
    let class_units = GetClassNameW(edit, class.as_mut_ptr(), class.len() as i32);
    if class_units != 4 || class[..4] != EDIT_CLASS_NAME {
        return false;
    }
    let style = GetWindowLongPtrW(edit, GWL_STYLE) as u32;
    style & ES_PASSWORD as u32 != 0
        && SendMessageW(edit, EM_GETLIMITTEXT, 0, 0) == MAX_SECRET_UNITS as isize
        && GetWindowTextLengthW(edit) <= MAX_SECRET_UNITS as i32
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
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            LeaseState::active_for_test(),
            action,
        )
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
                Instant::now() + Duration::from_millis(100),
                Arc::new(AtomicBool::new(false)),
                LeaseState::active_for_test(),
                Some(AutomaticAction::EnterSecret(SYNTHETIC_SECRET)),
            ),
            PromptOutcome::Expired
        ));
    }
}
