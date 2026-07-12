from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from your_cloud_console.cli import build_parser, run
from your_cloud_console.errors import ConsoleError
from your_cloud_console.model import (
    Declaration, Infrastructure, Machine, SCHEMA_VERSION, save_declaration,
)


class CliTests(unittest.TestCase):
    def test_distant_colocation_requires_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            declaration = root / "declaration.json"
            save_declaration(
                declaration,
                Declaration(
                    SCHEMA_VERSION,
                    (Machine("vps", "192.0.2.10", 22, "operator", "/tmp/key"),),
                    (),
                ),
            )
            base = [
                "--declaration", str(declaration),
                "--state-dir", str(root / "state"),
                "coordination", "migrate-pilot", "vps",
                "--coordinator", "vps", "--endpoint", "192.0.2.10",
                "--engine-dir", str(root / "engine"),
            ]
            parser = build_parser()
            with self.assertRaisesRegex(ConsoleError, "--colocated"):
                run(parser.parse_args(base))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(run(parser.parse_args([*base, "--colocated"])), 3)
            self.assertIn("Plan non appliqué", output.getvalue())

    def test_recovery_restore_requires_approval_before_reading_the_kit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = build_parser().parse_args([
                "--declaration", str(root / "declaration.json"),
                "--state-dir", str(root / "state"),
                "recovery", "restore", "--kit", str(root / "missing-kit.json"),
            ])
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(run(arguments), 3)
            self.assertIn("Plan non appliqué", output.getvalue())
            self.assertFalse((root / "declaration.json").exists())

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
