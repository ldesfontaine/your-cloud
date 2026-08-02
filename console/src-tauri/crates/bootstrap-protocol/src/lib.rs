use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

pub const REQUEST_ID_BYTES: usize = 16;
pub const MAX_HOST_BYTES: usize = 253;
pub const MAX_USERNAME_BYTES: usize = 32;
pub const HOST_KEY_BYTES: usize = 32;
pub const HOST_KEY_ENCODED_BYTES: usize = 43;
pub const MAX_ASSISTANT_REMAINING_MILLIS: u64 = 300_000;
pub const MAX_ASSISTANT_SCOPE_FRAME_BYTES: usize = 4_096;
pub const MAX_ASSISTANT_EVENT_FRAME_BYTES: usize = 1_024;
pub const ASSISTANT_EXIT_INVALID_INVOCATION: u8 = 64;
pub const ASSISTANT_EXIT_PROTOCOL_REFUSED: u8 = 65;
pub const ASSISTANT_EXIT_REFUSED: u8 = 66;
pub const ASSISTANT_EXIT_CANCELLED: u8 = 67;
pub const ASSISTANT_EXIT_UNAVAILABLE: u8 = 69;
pub const ASSISTANT_EXIT_INTERNAL_FAILURE: u8 = 70;
pub const ASSISTANT_EXIT_IO_FAILURE: u8 = 74;
pub const ASSISTANT_EXIT_WATCHDOG_EXPIRED: u8 = 124;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidInput,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid public bootstrap protocol input")
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMode {
    Create,
    Replace,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapAccessKind {
    Administrator,
    // This selects the requested route. Only the separate native consent flow may authorize it.
    Root,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_sha256: String,
    pub access_kind: BootstrapAccessKind,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapStartInput {
    pub mode: BootstrapMode,
    pub target: BootstrapTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapStep {
    PersonalAccess,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapAction {
    AuditTargetReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapLifecycle {
    AwaitingNativeAssistant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootstrapSessionView {
    pub schema_version: u8,
    pub request_id: String,
    pub mode: BootstrapMode,
    pub target: BootstrapTarget,
    pub step: BootstrapStep,
    pub actions: [BootstrapAction; 1],
    pub lifecycle: BootstrapLifecycle,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePromptKind {
    ConfirmPersonalAccess,
    KeyPassphrase,
    SudoPassword,
    ConfirmRootAccess,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantScopeV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub mode: BootstrapMode,
    pub target: BootstrapTarget,
    pub step: BootstrapStep,
    pub actions: [BootstrapAction; 1],
    pub prompt: NativePromptKind,
    pub remaining_millis: u64,
}

impl AssistantScopeV1 {
    pub fn validate(mut self) -> Result<Self, ProtocolError> {
        if self.schema_version != 1
            || !canonical_request_id(&self.request_id)
            || !(1..=MAX_ASSISTANT_REMAINING_MILLIS).contains(&self.remaining_millis)
            || !prompt_matches_access(self.prompt, self.target.access_kind)
        {
            return Err(ProtocolError::InvalidInput);
        }
        self.target = validate_target(self.target)?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantEventKind {
    PromptOpen,
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantEventV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub event: AssistantEventKind,
}

impl AssistantEventV1 {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.schema_version != 1 || !canonical_request_id(&self.request_id) {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }
}

pub fn validate_target(mut target: BootstrapTarget) -> Result<BootstrapTarget, ProtocolError> {
    target.host = canonical_host(&target.host)?;
    if target.port == 0 || !valid_username(&target.username, target.access_kind) {
        return Err(ProtocolError::InvalidInput);
    }
    validate_host_key(&target.host_key_sha256)?;
    Ok(target)
}

pub fn canonical_request_id(request_id: &str) -> bool {
    request_id.len() == REQUEST_ID_BYTES * 2
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prompt_matches_access(prompt: NativePromptKind, access_kind: BootstrapAccessKind) -> bool {
    match prompt {
        NativePromptKind::ConfirmRootAccess => access_kind == BootstrapAccessKind::Root,
        NativePromptKind::SudoPassword => access_kind == BootstrapAccessKind::Administrator,
        NativePromptKind::ConfirmPersonalAccess | NativePromptKind::KeyPassphrase => true,
    }
}

fn canonical_host(host: &str) -> Result<String, ProtocolError> {
    if host.is_empty() || host.len() > MAX_HOST_BYTES || host.trim() != host || !host.is_ascii() {
        return Err(ProtocolError::InvalidInput);
    }
    if let Ok(address) = IpAddr::from_str(host) {
        if !valid_target_address(address) {
            return Err(ProtocolError::InvalidInput);
        }
        return Ok(address.to_string());
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(ProtocolError::InvalidInput);
    }
    if host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.ends_with('.')
        || host
            .split('.')
            .any(|label| !valid_dns_label(label.as_bytes()))
    {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(host.to_ascii_lowercase())
}

fn valid_target_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => valid_target_ipv4(address),
        IpAddr::V6(address) => valid_target_ipv6(address),
    }
}

fn valid_target_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
}

fn valid_target_ipv6(address: Ipv6Addr) -> bool {
    if let Some(address) = address.to_ipv4_mapped() {
        return valid_target_ipv4(address);
    }
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_unicast_link_local()
        && !address.is_multicast()
}

fn valid_dns_label(label: &[u8]) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    let is_alphanumeric = |byte: u8| byte.is_ascii_alphanumeric();
    is_alphanumeric(label[0])
        && is_alphanumeric(label[label.len() - 1])
        && label
            .iter()
            .all(|byte| is_alphanumeric(*byte) || *byte == b'-')
}

fn valid_username(username: &str, access_kind: BootstrapAccessKind) -> bool {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_USERNAME_BYTES || !username.is_ascii() {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first == b'_')
        || !bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'_' | b'-')
        })
    {
        return false;
    }
    match access_kind {
        BootstrapAccessKind::Administrator => username != "root",
        BootstrapAccessKind::Root => username == "root",
    }
}

fn validate_host_key(host_key_sha256: &str) -> Result<(), ProtocolError> {
    let encoded = host_key_sha256
        .strip_prefix("SHA256:")
        .ok_or(ProtocolError::InvalidInput)?;
    if encoded.len() != HOST_KEY_ENCODED_BYTES || !encoded.is_ascii() {
        return Err(ProtocolError::InvalidInput);
    }
    let mut decoded = [0_u8; HOST_KEY_BYTES];
    let decoded_bytes = STANDARD_NO_PAD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_| ProtocolError::InvalidInput)?;
    if decoded_bytes != HOST_KEY_BYTES || STANDARD_NO_PAD.encode(decoded) != encoded {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn target(access_kind: BootstrapAccessKind) -> BootstrapTarget {
        BootstrapTarget {
            host: "Controller.Example.test".into(),
            port: 22,
            username: match access_kind {
                BootstrapAccessKind::Administrator => "infra_admin".into(),
                BootstrapAccessKind::Root => "root".into(),
            },
            host_key_sha256: HOST_KEY.into(),
            access_kind,
        }
    }

    fn scope(prompt: NativePromptKind, access_kind: BootstrapAccessKind) -> AssistantScopeV1 {
        AssistantScopeV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            mode: BootstrapMode::Create,
            target: target(access_kind),
            step: BootstrapStep::PersonalAccess,
            actions: [BootstrapAction::AuditTargetReadOnly],
            prompt,
            remaining_millis: MAX_ASSISTANT_REMAINING_MILLIS,
        }
    }

    #[test]
    fn target_validation_canonicalizes_the_public_scope() {
        let target = validate_target(target(BootstrapAccessKind::Administrator)).unwrap();
        assert_eq!(target.host, "controller.example.test");
    }

    #[test]
    fn target_validation_refuses_local_and_mapped_addresses() {
        for host in [
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.1.1",
            "::ffff:224.0.0.1",
            "localhost",
            "machine.localhost",
        ] {
            assert_eq!(
                validate_target(BootstrapTarget {
                    host: host.into(),
                    ..target(BootstrapAccessKind::Administrator)
                }),
                Err(ProtocolError::InvalidInput)
            );
        }
    }

    #[test]
    fn request_id_is_exact_and_canonical() {
        assert!(canonical_request_id(REQUEST_ID));
        assert!(!canonical_request_id("00112233445566778899AABBCCDDEEFF"));
        assert!(!canonical_request_id("../../forged"));
    }

    #[test]
    fn assistant_scope_accepts_only_positive_bounded_combinations() {
        for (prompt, access_kind) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            ),
            (
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Root,
            ),
            (
                NativePromptKind::KeyPassphrase,
                BootstrapAccessKind::Administrator,
            ),
            (NativePromptKind::KeyPassphrase, BootstrapAccessKind::Root),
            (
                NativePromptKind::SudoPassword,
                BootstrapAccessKind::Administrator,
            ),
            (
                NativePromptKind::ConfirmRootAccess,
                BootstrapAccessKind::Root,
            ),
        ] {
            assert!(scope(prompt, access_kind).validate().is_ok());
        }

        for (prompt, access_kind) in [
            (NativePromptKind::SudoPassword, BootstrapAccessKind::Root),
            (
                NativePromptKind::ConfirmRootAccess,
                BootstrapAccessKind::Administrator,
            ),
        ] {
            assert_eq!(
                scope(prompt, access_kind).validate(),
                Err(ProtocolError::InvalidInput)
            );
        }
    }

    #[test]
    fn assistant_wire_variants_are_fixed() {
        for (prompt, wire_name) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                "confirm_personal_access",
            ),
            (NativePromptKind::KeyPassphrase, "key_passphrase"),
            (NativePromptKind::SudoPassword, "sudo_password"),
            (NativePromptKind::ConfirmRootAccess, "confirm_root_access"),
        ] {
            assert_eq!(
                serde_json::to_value(prompt).unwrap(),
                serde_json::json!(wire_name)
            );
        }

        for (event, wire_name) in [
            (AssistantEventKind::PromptOpen, "prompt_open"),
            (AssistantEventKind::Refused, "refused"),
            (AssistantEventKind::Cancelled, "cancelled"),
            (AssistantEventKind::Expired, "expired"),
            (AssistantEventKind::Unavailable, "unavailable"),
        ] {
            assert_eq!(
                serde_json::to_value(event).unwrap(),
                serde_json::json!(wire_name)
            );
        }
    }

    #[test]
    fn assistant_scope_refuses_wrong_schema_identifier_or_expiration() {
        let mut wrong_schema = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        wrong_schema.schema_version = 2;
        assert_eq!(wrong_schema.validate(), Err(ProtocolError::InvalidInput));

        let mut wrong_request = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        wrong_request.request_id = "forged".into();
        assert_eq!(wrong_request.validate(), Err(ProtocolError::InvalidInput));

        for remaining_millis in [0, MAX_ASSISTANT_REMAINING_MILLIS + 1] {
            let mut invalid = scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            );
            invalid.remaining_millis = remaining_millis;
            assert_eq!(invalid.validate(), Err(ProtocolError::InvalidInput));
        }
    }

    #[test]
    fn assistant_event_is_closed_and_correlated() {
        let event = AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::PromptOpen,
        };
        assert!(event.clone().validate().is_ok());

        let hostile = serde_json::json!({
            "schema_version": 1,
            "request_id": REQUEST_ID,
            "event": "prompt_open",
            "secret": "forbidden"
        });
        assert!(serde_json::from_value::<AssistantEventV1>(hostile).is_err());

        let mut wrong_request = event;
        wrong_request.request_id = "forged".into();
        assert_eq!(wrong_request.validate(), Err(ProtocolError::InvalidInput));

        let wrong_schema = AssistantEventV1 {
            schema_version: 2,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
        };
        assert_eq!(wrong_schema.validate(), Err(ProtocolError::InvalidInput));
    }

    #[test]
    fn assistant_scope_serde_refuses_unknown_fields() {
        let mut document = serde_json::to_value(scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        ))
        .unwrap();
        document["secret"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<AssistantScopeV1>(document).is_err());
    }
}
