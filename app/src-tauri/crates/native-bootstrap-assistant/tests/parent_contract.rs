#[allow(dead_code)]
#[path = "../../../src/native_helper.rs"]
mod native_helper;

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use native_helper::{HelperInvocation, NativeHelperError, NativeHelperSupervisor};
// Ce que rend une attente qui n'a pas encore conclu. Les trois emplois vivent
// dans les cas `cfg(target_os = "linux")` de ce fichier, et l'import suit la
// même borne : sous Windows, ces cas ne sont pas compilés et le nom n'aurait
// personne pour l'employer.
#[cfg(target_os = "linux")]
use native_helper::NativeHelperPoll;
use your_cloud_bootstrap_protocol::{
    AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
    BootstrapTarget, NativePromptKind,
};

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
        target_addresses: Vec::new(),
        machine_configuration: None,
        declared_target: None,
        issued_at_monotonic_nanos: 0,
        remaining_millis: 5_000,
    }
}

/// The scope used when the helper must really hold a window open.
///
/// `ConfirmPersonalAccess` no longer opens one by itself: it resolves the
/// target, freezes its addresses and reads the agent first, and against a
/// synthetic unreachable host it never reaches a window. What is proven below
/// is that the parent bounds a live helper until it cancels it, so the scope
/// carries the escalation couple, which still goes straight to the native
/// prompt with the same administrator target.
#[cfg(target_os = "linux")]
fn windowed_scope() -> AssistantScopeV1 {
    AssistantScopeV1 {
        step: BootstrapStep::PrivilegeEscalation,
        prompt: NativePromptKind::SudoPassword,
        ..scope()
    }
}

#[cfg(target_os = "linux")]
#[test]
fn app_parent_launches_the_exact_helper_and_refuses_to_invent_success() {
    let path = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let expected_name = path.file_name().unwrap();
    let mut supervisor = NativeHelperSupervisor::default();
    supervisor
        .start_with_path(
            path,
            expected_name,
            HelperInvocation::Bootstrap(scope()),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

    assert_eq!(
        supervisor.poll("ffeeddccbbaa99887766554433221100"),
        Err(NativeHelperError::RequestRefused)
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match supervisor.poll(REQUEST_ID) {
            Ok(NativeHelperPoll::Running) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(NativeHelperPoll::Unavailable) => break,
            outcome => panic!("unexpected native assistant outcome: {outcome:?}"),
        }
    }
}

#[cfg(target_os = "windows")]
#[test]
fn app_parent_closes_one_job_before_reusing_the_boundary() {
    let path = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let expected_name = path.file_name().unwrap();
    let mut supervisor = NativeHelperSupervisor::default();
    supervisor
        .start_with_path(
            path,
            expected_name,
            HelperInvocation::Bootstrap(scope()),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

    supervisor.cancel(REQUEST_ID).unwrap();
    assert_eq!(
        supervisor.poll(REQUEST_ID),
        Err(NativeHelperError::RequestRefused)
    );

    let mut second_scope = scope();
    second_scope.request_id = "ffeeddccbbaa99887766554433221100".into();
    supervisor
        .start_with_path(
            path,
            expected_name,
            HelperInvocation::Bootstrap(second_scope),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    supervisor
        .cancel("ffeeddccbbaa99887766554433221100")
        .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Xvfb"]
fn app_parent_keeps_the_gtk_helper_bounded_until_cancelled() {
    let path = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let expected_name = path.file_name().unwrap();
    let mut supervisor = NativeHelperSupervisor::default();
    supervisor
        .start_with_path(
            path,
            expected_name,
            HelperInvocation::Bootstrap(windowed_scope()),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

    thread::sleep(Duration::from_millis(250));
    assert_eq!(supervisor.poll(REQUEST_ID), Ok(NativeHelperPoll::Running));
    supervisor.cancel(REQUEST_ID).unwrap();
    assert_eq!(
        supervisor.poll(REQUEST_ID),
        Err(NativeHelperError::RequestRefused)
    );
}
