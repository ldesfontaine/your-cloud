import unittest

from your_cloud_console.model import Machine
from your_cloud_console.security import security_plan


class SecurityPlanTests(unittest.TestCase):
    def test_coordinator_sources_are_distinct_from_ssh_sources(self):
        plan = security_plan(
            Machine("coordinator", "192.0.2.10", 22, "admin", "/tmp/key"),
            "clean",
            "192.0.2.0/24",
            "2001:db8:1::/64",
            "console fournisseur",
            8443,
            "0.0.0.0/0",
            "::/0",
        )
        self.assertIn("SSH depuis 192.0.2.0/24 et 2001:db8:1::/64", plan)
        self.assertIn("TCP 8443 depuis 0.0.0.0/0 et ::/0, sans élargir SSH", plan)


if __name__ == "__main__":
    unittest.main()
