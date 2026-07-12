import base64
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from your_cloud_console.errors import TelemetryError
from your_cloud_console.protocol import telemetrie_pb2
from your_cloud_console.telemetry import IdentityStore, SIGNATURE_DOMAIN, verify_event, verify_state


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = IdentityStore(Path(self.temporary.name))
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        import hashlib
        self.key_id = hashlib.sha256(public).hexdigest()
        self.store.approve(
            "machine-1",
            key_id=self.key_id,
            algorithm="Ed25519",
            public_key=base64.b64encode(public).decode("ascii"),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def envelope(self, sequence=1, *, private=None, key_id=None):
        private = private or self.private
        key_id = key_id or self.key_id
        state = telemetrie_pb2.MachineState(
            schema_version=1,
            machine_id="machine-1",
            daemon_version="test",
            sequence=sequence,
            observed_at_unix=1,
            debian_version="13",
            memory_total_bytes=2,
            memory_available_bytes=1,
            root_total_bytes=2,
            root_free_bytes=1,
        )
        payload = state.SerializeToString(deterministic=True)
        stream = telemetrie_pb2.TELEMETRY_STREAM_STATE
        signature = private.sign(SIGNATURE_DOMAIN + bytes((stream,)) + payload)
        return telemetrie_pb2.SignedEnvelope(
            schema_version=1,
            key_id=key_id,
            stream=stream,
            payload=payload,
            signature=signature,
        )

    def test_accepts_signed_state_then_rejects_replay(self):
        encoded = self.envelope().SerializeToString(deterministic=True)
        self.assertEqual(verify_state("machine-1", encoded, self.store).sequence, 1)
        with self.assertRaisesRegex(TelemetryError, "rejouée"):
            verify_state("machine-1", encoded, self.store)

    def test_rejects_modified_payload(self):
        envelope = self.envelope()
        envelope.payload = envelope.payload + b"\x08\x01"
        with self.assertRaisesRegex(TelemetryError, "signature"):
            verify_state("machine-1", envelope.SerializeToString(), self.store)

    def test_rejects_revoked_identity(self):
        encoded = self.envelope().SerializeToString(deterministic=True)
        self.store.revoke("machine-1")
        with self.assertRaisesRegex(TelemetryError, "révoquée"):
            verify_state("machine-1", encoded, self.store)

    def test_accepts_signed_event(self):
        event = telemetrie_pb2.MachineEvent(
            schema_version=1,
            machine_id="machine-1",
            sequence=1,
            observed_at_unix=1,
            kind="observer-started",
            detail="test",
        )
        payload = event.SerializeToString(deterministic=True)
        stream = telemetrie_pb2.TELEMETRY_STREAM_EVENT
        envelope = telemetrie_pb2.SignedEnvelope(
            schema_version=1,
            key_id=self.key_id,
            stream=stream,
            payload=payload,
            signature=self.private.sign(SIGNATURE_DOMAIN + bytes((stream,)) + payload),
        )
        verified = verify_event(
            "machine-1", envelope.SerializeToString(deterministic=True), self.store
        )
        self.assertEqual(verified.kind, "observer-started")

    def test_renewal_accepts_only_prepared_candidate_then_archives_previous(self):
        candidate = Ed25519PrivateKey.generate()
        public = candidate.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        import hashlib
        key_id = hashlib.sha256(public).hexdigest()
        candidate_envelope = self.envelope(
            sequence=2, private=candidate, key_id=key_id
        ).SerializeToString(deterministic=True)
        with self.assertRaisesRegex(TelemetryError, "inconnue"):
            verify_state("machine-1", candidate_envelope, self.store)
        self.store.prepare_renewal(
            "machine-1",
            key_id=key_id,
            algorithm="Ed25519",
            public_key=base64.b64encode(public).decode("ascii"),
        )
        self.assertEqual(
            verify_state("machine-1", candidate_envelope, self.store).sequence, 2
        )
        self.store.finalize_renewal("machine-1", key_id)
        raw = self.store.load()
        self.assertEqual(self.store.get("machine-1").key_id, key_id)
        self.assertEqual(raw["history"]["machine-1"][0]["status"], "replaced")
        with self.assertRaisesRegex(TelemetryError, "inconnue|remplacée"):
            verify_state(
                "machine-1",
                self.envelope(sequence=3).SerializeToString(deterministic=True),
                self.store,
            )


if __name__ == "__main__":
    unittest.main()
