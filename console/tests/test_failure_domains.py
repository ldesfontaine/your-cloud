import os
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.failure_domains import (
    DetectedFailureDomain,
    FailureDomainStore,
    failure_domain_view,
)
from your_cloud_console.errors import FailureDomainError
from your_cloud_console.model import Infrastructure


class FailureDomainTests(unittest.TestCase):
    def test_unknown_declared_detected_confirmed_and_conflict_are_distinct(self):
        unknown = Infrastructure("site-a", "Site A")
        declared = Infrastructure("site-a", "Site A", "zone-a")
        detected_a = DetectedFailureDomain(
            "site-a", "zone-a", "labctl:metadata", "réseau vérifié", "2026-07-12T00:00:00+00:00"
        )
        detected_b = DetectedFailureDomain(
            "site-a", "zone-b", "labctl:metadata", "réseau vérifié", "2026-07-12T00:00:00+00:00"
        )
        self.assertEqual(failure_domain_view(unknown, None)["status"], "unknown")
        self.assertEqual(failure_domain_view(declared, None)["status"], "declared")
        self.assertEqual(failure_domain_view(unknown, detected_a)["status"], "detected")
        self.assertEqual(failure_domain_view(declared, detected_a)["status"], "confirmed")
        self.assertEqual(failure_domain_view(declared, detected_b)["status"], "conflict")
        with self.assertRaisesRegex(FailureDomainError, "autre infrastructure"):
            failure_domain_view(
                Infrastructure("site-b", "Site B"),
                detected_a,
            )

    def test_runtime_detection_is_private_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = FailureDomainStore(Path(temporary) / "state")
            recorded = store.record(
                "site-a",
                "lab-site-private",
                "labctl:metadata",
                "topologie v1-full, réseau lab-site-private",
            )
            self.assertEqual(store.get("site-a"), recorded)
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(store.state_dir).st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
