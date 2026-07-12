import json
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.errors import DeclarationError
from your_cloud_console.model import Machine, add_machine, empty_declaration, load_declaration, parse_declaration, save_declaration


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
        with self.assertRaisesRegex(DeclarationError, "schéma 2"):
            parse_declaration({"schema_version": 2, "machines": [], "infrastructures": []})

    def test_unknown_field_is_refused(self):
        raw = json.loads(json.dumps(empty_declaration().to_dict()))
        raw["surprise"] = True
        with self.assertRaisesRegex(DeclarationError, "champs inconnus"):
            parse_declaration(raw)


if __name__ == "__main__":
    unittest.main()
