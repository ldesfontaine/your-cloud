from pathlib import Path
import tempfile
import unittest

from your_cloud_console.errors import SecurityError
from your_cloud_console.secrets import AdminKeyStore, read_passphrase


class AdminKeyStoreTests(unittest.TestCase):
    def test_encrypted_key_and_recovery_kit_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            declaration = root / "declaration.json"
            declaration.write_text('{"schema_version":1,"machines":[],"infrastructures":[]}\n')
            kit = root / "recovery" / "kit.json"
            password = b"synthetic-password-for-tests"
            store = AdminKeyStore(state)
            public = store.create_with_recovery_kit("machine-1", declaration, kit, password)
            self.assertEqual(store.verify_recovery_kit(kit, password), public)
            self.assertNotIn(password, kit.read_bytes())
            self.assertEqual(store.private_path("machine-1").stat().st_mode & 0o777, 0o600)
            self.assertEqual(kit.stat().st_mode & 0o777, 0o600)
            with store.materialize("machine-1", password) as clear:
                self.assertTrue(clear.exists())
                self.assertEqual(clear.stat().st_mode & 0o777, 0o600)
            self.assertFalse(clear.exists())

    def test_wrong_password_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            declaration = root / "declaration.json"
            declaration.write_text('{"schema_version":1,"machines":[],"infrastructures":[]}\n')
            kit = root / "kit.json"
            store = AdminKeyStore(state)
            store.create_with_recovery_kit(
                "machine-1", declaration, kit, b"synthetic-password-for-tests"
            )
            with self.assertRaisesRegex(SecurityError, "mot de passe"):
                store.verify_recovery_kit(kit, b"another-wrong-password")

    def test_passphrase_file_must_be_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "passphrase"
            path.write_text("synthetic-password-for-tests")
            path.chmod(0o644)
            with self.assertRaisesRegex(SecurityError, "privé"):
                read_passphrase(path, confirm=False)


if __name__ == "__main__":
    unittest.main()
