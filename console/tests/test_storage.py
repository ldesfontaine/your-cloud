import os
import json
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.errors import HostKeyError
from your_cloud_console.storage import HostKeyStore, PinnedHostKey


class HostKeyStoreTests(unittest.TestCase):
    def test_registry_and_known_hosts_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary) / "state")
            key = PinnedHostKey.accepted(
                endpoint="example.test",
                key_type="ssh-ed25519",
                key="AAAA",
                fingerprint="SHA256:test",
                source="tofu-visible",
            )
            store.pin("machine-1", key)
            self.assertEqual(store.get("machine-1"), key)
            self.assertEqual(store.known_hosts_path.read_text(), "example.test ssh-ed25519 AAAA\n")
            self.assertEqual(os.stat(store.registry_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(store.known_hosts_path).st_mode & 0o777, 0o600)

    def test_corrupt_entry_is_refused_before_known_hosts_render(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary) / "state")
            store.state_dir.mkdir()
            store.registry_path.write_text(
                json.dumps({"schema_version": 1, "host_keys": {"machine-1": {"key": "AAAA"}}})
            )
            with self.assertRaisesRegex(HostKeyError, "entrée de clé d'hôte invalide"):
                store.render_known_hosts()
            self.assertFalse(store.known_hosts_path.exists())


if __name__ == "__main__":
    unittest.main()
