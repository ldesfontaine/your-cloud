import subprocess
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.audit import run_audit
from your_cloud_console.model import Machine
from your_cloud_console.storage import HostKeyStore, PinnedHostKey


def remote_output(**overrides):
    fields = {
        "os_id": "debian",
        "os_version_id": "13",
        "os_codename": "trixie",
        "architecture": "amd64",
        "kernel_machine": "x86_64",
        "hostname": "target",
        "free_kib": "8388608",
        "epoch": "0",
        "sudo_present": "yes",
        "privilege_non_interactive": "yes",
        "systemd_present": "yes",
        "ssh_config_sources": "/etc/ssh/sshd_config",
        "nft_config_sources": "",
        "sysctl_config_sources": "/etc/sysctl.conf",
        "config_managers": "",
        "listening_sockets": "tcp 0.0.0.0:22",
        "nft_rule_lines": "0",
    }
    fields.update(overrides)
    payload = bytearray()
    for key, value in fields.items():
        payload.extend(key.encode("ascii") + b"\0" + value.encode("utf-8") + b"\0")
    return bytes(payload)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.machine = Machine("machine-1", "192.0.2.10", 22, "root", "/tmp/key")
        self.host_key = PinnedHostKey.accepted(
            endpoint="192.0.2.10",
            key_type="ssh-ed25519",
            key="AAAA",
            fingerprint="SHA256:test",
            source="tofu-visible",
        )

    def test_compatible_target_is_eligible(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary))
            store.pin(self.machine.id, self.host_key)
            completed = subprocess.CompletedProcess([], 0, stdout=remote_output(epoch="1"), stderr=b"")
            with patch("your_cloud_console.audit.ssh_command", return_value=["ssh"]), patch(
                "your_cloud_console.audit.subprocess.run", return_value=completed
            ), patch("your_cloud_console.audit.time.time", return_value=1):
                result = run_audit(self.machine, store, self.host_key)
            self.assertEqual(result.decision, "eligible")
            self.assertEqual(result.mutation_count, 0)

    def test_incompatible_target_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = HostKeyStore(Path(temporary))
            store.pin(self.machine.id, self.host_key)
            completed = subprocess.CompletedProcess(
                [], 0, stdout=remote_output(os_version_id="12", epoch="1"), stderr=b""
            )
            with patch("your_cloud_console.audit.ssh_command", return_value=["ssh"]), patch(
                "your_cloud_console.audit.subprocess.run", return_value=completed
            ), patch("your_cloud_console.audit.time.time", return_value=1):
                result = run_audit(self.machine, store, self.host_key)
            self.assertEqual(result.decision, "refused")
            self.assertIn("Debian 13", result.refusals[0])


if __name__ == "__main__":
    unittest.main()
