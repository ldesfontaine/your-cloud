use std::io::{self, Read, Write};

use your_cloud_bootstrap_protocol::{
    AssistantEventV1, AssistantScopeV1, MAX_ASSISTANT_EVENT_FRAME_BYTES,
    MAX_ASSISTANT_SCOPE_FRAME_BYTES,
};

const FRAME_HEADER_BYTES: usize = 4;

#[derive(Debug)]
pub(crate) enum ReadFrameError {
    Invalid,
    Io,
}

/// Reads exactly the single public scope frame. Production transfers the same
/// unbuffered reader to the stdin lease afterwards; substituting a buffered
/// reader and probing only its underlying handle would strand prefetched bytes.
pub(crate) fn read_scope(reader: &mut impl Read) -> Result<AssistantScopeV1, ReadFrameError> {
    let payload = read_payload(reader, MAX_ASSISTANT_SCOPE_FRAME_BYTES)?;
    serde_json::from_slice::<AssistantScopeV1>(&payload)
        .map_err(|_| ReadFrameError::Invalid)?
        .validate()
        .map_err(|_| ReadFrameError::Invalid)
}

pub(crate) fn write_event(writer: &mut impl Write, event: &AssistantEventV1) -> Result<(), ()> {
    let payload = serde_json::to_vec(event).map_err(|_| ())?;
    if payload.is_empty() || payload.len() > MAX_ASSISTANT_EVENT_FRAME_BYTES {
        return Err(());
    }
    let length = u32::try_from(payload.len()).map_err(|_| ())?;
    writer.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    writer.write_all(&payload).map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}

fn read_payload(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, ReadFrameError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact(reader, &mut header)?;
    let length =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| ReadFrameError::Invalid)?;
    if length == 0 || length > maximum {
        return Err(ReadFrameError::Invalid);
    }
    let mut payload = vec![0_u8; length];
    read_exact(reader, &mut payload)?;
    Ok(payload)
}

fn read_exact(reader: &mut impl Read, mut buffer: &mut [u8]) -> Result<(), ReadFrameError> {
    while !buffer.is_empty() {
        match reader.read(buffer) {
            Ok(0) => return Err(ReadFrameError::Invalid),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ReadFrameError::Io),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use your_cloud_bootstrap_protocol::{
        AssistantEventKind, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
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
            issued_at_monotonic_nanos: 1,
            remaining_millis: 1_000,
        }
    }

    fn framed(value: &AssistantScopeV1) -> Vec<u8> {
        let payload = serde_json::to_vec(value).unwrap();
        let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn reads_one_bounded_validated_scope_and_leaves_the_lease_byte() {
        let mut bytes = framed(&scope());
        bytes.push(0xa5);
        let mut input = Cursor::new(bytes);
        let received = read_scope(&mut input).unwrap();
        assert_eq!(received.request_id, REQUEST_ID);
        let mut lease_byte = [0_u8; 1];
        input.read_exact(&mut lease_byte).unwrap();
        assert_eq!(lease_byte, [0xa5]);
    }

    #[test]
    fn refuses_empty_oversized_and_truncated_frames() {
        for input in [
            0_u32.to_be_bytes().to_vec(),
            u32::try_from(MAX_ASSISTANT_SCOPE_FRAME_BYTES + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            [10_u32.to_be_bytes().as_slice(), b"{}"].concat(),
        ] {
            assert!(read_scope(&mut Cursor::new(input)).is_err());
        }

        // Bytes after this single scope are observed by the separate stdin lease
        // and can never be interpreted as a second scope or an update.
    }

    #[test]
    fn writes_one_bounded_expurgated_event() {
        let event = AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
        };
        let mut output = Vec::new();
        write_event(&mut output, &event).unwrap();

        let length = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(length, output.len() - 4);
        let decoded = serde_json::from_slice::<AssistantEventV1>(&output[4..])
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(decoded, event);
    }
}
