#[allow(dead_code)]
#[path = "../../../src/native_assistant.rs"]
mod native_assistant;

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use native_assistant::{NativeAssistantError, NativeAssistantPoll, NativeAssistantSupervisor};
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
        issued_at_monotonic_nanos: 0,
        remaining_millis: 5_000,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn console_parent_launches_the_exact_helper_and_refuses_to_invent_success() {
    let path = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let expected_name = path.file_name().unwrap();
    let mut supervisor = NativeAssistantSupervisor::default();
    supervisor
        .start_with_path(
            path,
            expected_name,
            scope(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

    assert_eq!(
        supervisor.poll("ffeeddccbbaa99887766554433221100"),
        Err(NativeAssistantError::RequestRefused)
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match supervisor.poll(REQUEST_ID) {
            Ok(NativeAssistantPoll::Running) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(NativeAssistantPoll::Unavailable) => break,
            outcome => panic!("unexpected native assistant outcome: {outcome:?}"),
        }
    }
}

#[cfg(target_os = "windows")]
#[test]
fn console_parent_closes_one_job_before_reusing_the_boundary() {
    let path = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let expected_name = path.file_name().unwrap();
    let mut supervisor = NativeAssistantSupervisor::default();
    supervisor
        .start_with_path(
            path,
            expected_name,
            scope(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

    supervisor.cancel(REQUEST_ID).unwrap();
    assert_eq!(
        supervisor.poll(REQUEST_ID),
        Err(NativeAssistantError::RequestRefused)
    );

    let mut second_scope = scope();
    second_scope.request_id = "ffeeddccbbaa99887766554433221100".into();
    supervisor
        .start_with_path(
            path,
            expected_name,
            second_scope,
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
fn console_parent_keeps_the_gtk_helper_bounded_until_cancelled() {
    let path = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let expected_name = path.file_name().unwrap();
    let mut supervisor = NativeAssistantSupervisor::default();
    supervisor
        .start_with_path(
            path,
            expected_name,
            scope(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

    thread::sleep(Duration::from_millis(250));
    assert_eq!(
        supervisor.poll(REQUEST_ID),
        Ok(NativeAssistantPoll::Running)
    );
    supervisor.cancel(REQUEST_ID).unwrap();
    assert_eq!(
        supervisor.poll(REQUEST_ID),
        Err(NativeAssistantError::RequestRefused)
    );
}
