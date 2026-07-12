from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.cli import build_parser, run
from your_cloud_console.model import Declaration, Infrastructure, SCHEMA_VERSION, save_declaration


class CliTests(unittest.TestCase):
    def test_declaration_migration_requires_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "declaration.json"
            original = (
                '{"schema_version":1,"machines":[],"infrastructures":'
                '[{"id":"site-a","name":"Site A"}]}\n'
            )
            path.write_text(original, encoding="utf-8")
            parser = build_parser()
            arguments = ["--declaration", str(path), "declaration", "migrate"]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run(parser.parse_args(arguments)), 3)
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run(parser.parse_args([*arguments, "--approve"])), 0)
            migrated = path.read_text(encoding="utf-8")
            self.assertIn('"schema_version": 2', migrated)
            self.assertIn('"failure_domain": null', migrated)

    def test_unknown_failure_domain_renders_without_runtime_detection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            declaration = root / "declaration.json"
            save_declaration(
                declaration,
                Declaration(SCHEMA_VERSION, (), (Infrastructure("site-a", "Site A"),)),
            )
            args = build_parser().parse_args([
                "--declaration", str(declaration),
                "--state-dir", str(root / "state"),
                "infrastructure", "status", "site-a",
            ])
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(run(args), 0)
            self.assertIn("inconnu : aucune déclaration ni détection", output.getvalue())


if __name__ == "__main__":
    unittest.main()
