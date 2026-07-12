import json
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.errors import DeclarationError
from your_cloud_console.model import (
    Declaration,
    Infrastructure,
    Machine,
    SCHEMA_VERSION,
    add_machine,
    assign_machine,
    empty_declaration,
    load_declaration,
    migration_candidate,
    parse_declaration,
    save_declaration,
    set_failure_domain,
)


class DeclarationTests(unittest.TestCase):
    def test_empty_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "declaration.json"
            save_declaration(path, empty_declaration())
            self.assertEqual(load_declaration(path), empty_declaration())

    def test_duplicate_endpoint_is_refused(self):
        first = Machine("one", "192.0.2.1", 22, "root", "/tmp/key")
        second = Machine("two", "192.0.2.1", 22, "admin", "/tmp/other-key")
        declaration = add_machine(empty_declaration(), first)
        with self.assertRaisesRegex(DeclarationError, "cible SSH ambigu"):
            add_machine(declaration, second)

    def test_unknown_schema_is_refused(self):
        with self.assertRaisesRegex(DeclarationError, "schéma 3"):
            parse_declaration({"schema_version": 3, "machines": [], "infrastructures": []})

    def test_schema_one_requires_explicit_migration(self):
        previous = {
            "schema_version": 1,
            "machines": [],
            "infrastructures": [{"id": "site-a", "name": "Site A"}],
        }
        with self.assertRaisesRegex(DeclarationError, "migrer explicitement"):
            parse_declaration(previous)
        migrated = migration_candidate(previous)
        self.assertEqual(migrated.schema_version, SCHEMA_VERSION)
        self.assertIsNone(migrated.infrastructures[0].failure_domain)

    def test_unknown_field_is_refused(self):
        raw = json.loads(json.dumps(empty_declaration().to_dict()))
        raw["surprise"] = True
        with self.assertRaisesRegex(DeclarationError, "champs inconnus"):
            parse_declaration(raw)

    def test_assignment_preserves_machine_identity_and_supports_movement(self):
        infrastructure_a = Infrastructure("site-a", "Site A")
        infrastructure_b = Infrastructure("site-b", "Site B")
        machine = Machine("machine-1", "192.0.2.1", 22, "admin", "/tmp/key", "site-a")
        declaration = Declaration(
            SCHEMA_VERSION,
            (machine,),
            (infrastructure_a, infrastructure_b),
        )
        moved = assign_machine(declaration, "machine-1", "site-b")
        self.assertEqual(moved.machine("machine-1").infrastructure_id, "site-b")
        self.assertEqual(moved.machine("machine-1").endpoint, machine.endpoint)
        available = assign_machine(moved, "machine-1", None)
        self.assertIsNone(available.machine("machine-1").infrastructure_id)

    def test_assignment_to_unknown_infrastructure_is_refused(self):
        declaration = add_machine(
            empty_declaration(),
            Machine("machine-1", "192.0.2.1", 22, "admin", "/tmp/key"),
        )
        with self.assertRaisesRegex(DeclarationError, "infrastructure inconnue"):
            assign_machine(declaration, "machine-1", "absent")

    def test_failure_domain_is_declared_without_changing_assignment(self):
        infrastructure = Infrastructure("site-a", "Site A")
        machine = Machine(
            "machine-1", "192.0.2.1", 22, "admin", "/tmp/key", "site-a"
        )
        declaration = Declaration(SCHEMA_VERSION, (machine,), (infrastructure,))
        updated = set_failure_domain(declaration, "site-a", "provider:region-a")
        self.assertEqual(updated.infrastructures[0].failure_domain, "provider:region-a")
        self.assertEqual(updated.machine("machine-1"), machine)


if __name__ == "__main__":
    unittest.main()
