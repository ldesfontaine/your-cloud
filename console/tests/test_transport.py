from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from your_cloud_console.transport import TransportStore
from your_cloud_console.errors import CoordinationError


class TransportStoreTests(unittest.TestCase):
    def test_creates_distinct_encrypted_identities_and_materializes_one(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TransportStore(Path(directory))
            passphrase = b"synthetic-lab-passphrase"
            store.ensure(passphrase, "machine-1", "192.0.2.10", ("machine-1",))
            coordinator = x509.load_pem_x509_certificate(
                store.certificate_path("coordinator", "machine-1").read_bytes()
            )
            daemon = x509.load_pem_x509_certificate(
                store.certificate_path("daemon", "machine-1").read_bytes()
            )
            console = x509.load_pem_x509_certificate(
                store.certificate_path("console", "local").read_bytes()
            )
            self.assertEqual(coordinator.subject.rfc4514_string(), "CN=coordinator:machine-1")
            self.assertEqual(daemon.subject.rfc4514_string(), "CN=daemon:machine-1")
            self.assertEqual(console.subject.rfc4514_string(), "CN=console:local")
            self.assertNotEqual(daemon.serial_number, console.serial_number)
            with store.materialize_private("console", "local", passphrase) as clear:
                private = serialization.load_pem_private_key(clear.read_bytes(), password=None)
                self.assertIsNotNone(private)
            self.assertFalse(clear.exists())

    def test_existing_server_identity_cannot_silently_change_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TransportStore(Path(directory))
            passphrase = b"synthetic-lab-passphrase"
            store.ensure(passphrase, "coordinator-1", "192.0.2.10", ())
            with self.assertRaisesRegex(CoordinationError, "incompatible"):
                store.ensure(passphrase, "coordinator-1", "coordinator.example", ())

    def test_dns_endpoint_is_bound_in_server_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TransportStore(Path(directory))
            store.ensure(
                b"synthetic-lab-passphrase",
                "coordinator-1",
                "coordinator.example",
                (),
            )
            certificate = x509.load_pem_x509_certificate(
                store.certificate_path("coordinator", "coordinator-1").read_bytes()
            )
            names = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertEqual(names.get_values_for_type(x509.DNSName), ["coordinator.example"])


if __name__ == "__main__":
    unittest.main()
