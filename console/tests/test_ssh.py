from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from your_cloud_console.errors import HostKeyError
from your_cloud_console.model import Machine
from your_cloud_console.ssh import ScannedHostKey, verify_or_pin_host_key
from your_cloud_console.storage import HostKeyStore


class HostTrustTests(unittest.TestCase):
    def setUp(self):
        self.machine = Machine("machine-1", "192.0.2.10", 22, "root", "/tmp/key")
        self.scan = ScannedHostKey(
            "192.0.2.10", "ssh-ed25519", "AAAA", "SHA256:first"
        )

    def test_first_contact_requires_explicit_choice(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary))
            with patch("your_cloud_console.ssh.scan_host_key", return_value=self.scan):
                with self.assertRaisesRegex(HostKeyError, "premier contact"):
                    verify_or_pin_host_key(self.machine, store)
                self.assertIsNone(store.get(self.machine.id))

    def test_visible_tofu_is_pinned_then_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary))
            with patch("your_cloud_console.ssh.scan_host_key", return_value=self.scan):
                pinned = verify_or_pin_host_key(self.machine, store, accept_tofu=True)
                self.assertEqual(pinned.source, "tofu-visible")
                self.assertEqual(verify_or_pin_host_key(self.machine, store), pinned)

    def test_changed_key_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary))
            with patch("your_cloud_console.ssh.scan_host_key", return_value=self.scan):
                verify_or_pin_host_key(self.machine, store, accept_tofu=True)
            changed = ScannedHostKey("192.0.2.10", "ssh-ed25519", "BBBB", "SHA256:changed")
            with patch("your_cloud_console.ssh.scan_host_key", return_value=changed):
                with self.assertRaisesRegex(HostKeyError, "clé d'hôte changée"):
                    verify_or_pin_host_key(self.machine, store)


if __name__ == "__main__":
    unittest.main()
