from pathlib import Path
import tempfile
import unittest

from your_cloud_console.errors import ConsoleError
from your_cloud_console.updates import UpdateStore


class UpdateStoreTests(unittest.TestCase):
    def test_observer_requires_coordinator_at_same_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = UpdateStore(Path(temporary))
            with self.assertRaisesRegex(ConsoleError, "coordinateur"):
                store.require_coordinator_version("1.0.0-rc.1")
            store.record("coordinator", "coord-1", "1.0.0-rc.1")
            store.require_coordinator_version("1.0.0-rc.1")
            store.record("observer", "machine-1", "1.0.0-rc.1")
            self.assertEqual(
                store.load()["observers"]["machine-1"], "1.0.0-rc.1"
            )


if __name__ == "__main__":
    unittest.main()
