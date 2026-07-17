#!/usr/bin/env python3
"""Hostile stdlib-only checks for the fixed v0.0.1 proof-result boundary."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
RENDERER = Path(__file__).resolve().parents[1] / "lab" / "v0.0.1" / "report" / "renderer.py"
SPEC = importlib.util.spec_from_file_location("your_cloud_v001_renderer", RENDERER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load v0.0.1 proof renderer")
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


def valid_p1() -> dict[str, object]:
    return {
        "schema": 1,
        "proof": "your-cloud-v0.0.1",
        "automation_scope": "P1",
        "outcome": "passed",
        "failure_class": None,
        "source_revision": "9ecfe643cd85b84e1901814bc8c273758442825d+worktree",
        "source_lot_sha256": "1" * 64,
        "artifact_sha256": "2" * 64,
        "topology": "v1-full",
        "targets": list(renderer.EXPECTED_TARGETS),
        "relay_window": {
            "started_at": "2026-07-17T05:05:32Z",
            "finished_at": "2026-07-17T05:07:09Z",
        },
        "cleanup": {
            "status": "passed",
            "failure_state": "not-required",
            "success_state": "documented-final",
            "clock_restored": True,
        },
        "redaction": {
            "policy": "fixed-field-allowlist",
            "sensitive_data_included": False,
        },
        "steps": [
            {"id": identifier, "category": category, "title": title, "status": "passed"}
            for identifier, category, title in renderer.EXPECTED_STEPS
        ],
    }


class P1SchemaTests(unittest.TestCase):
    def assert_refused(self, data: object) -> None:
        with self.assertRaises(ValueError):
            renderer.validate(data)

    def test_exact_manifest_is_accepted(self) -> None:
        self.assertEqual(renderer.validate(valid_p1())["outcome"], "passed")

    def test_missing_reordered_or_renamed_step_is_refused(self) -> None:
        missing = valid_p1()
        missing["steps"].pop()
        self.assert_refused(missing)

        reordered = valid_p1()
        reordered["steps"][0], reordered["steps"][1] = reordered["steps"][1], reordered["steps"][0]
        self.assert_refused(reordered)

        renamed = valid_p1()
        renamed["steps"][0]["title"] = "looks harmless but is outside the manifest"
        self.assert_refused(renamed)

    def test_extra_sensitive_or_unknown_field_is_refused(self) -> None:
        data = valid_p1()
        data["raw_logs"] = "forbidden"
        self.assert_refused(data)

        wrong_type = valid_p1()
        wrong_type["steps"][0]["category"] = ["infrastructure"]
        self.assert_refused(wrong_type)

    def test_success_requires_exact_cleanup_and_time_order(self) -> None:
        cleanup = valid_p1()
        cleanup["cleanup"]["failure_state"] = "absent"
        self.assert_refused(cleanup)

        reversed_window = valid_p1()
        reversed_window["relay_window"] = {
            "started_at": "2026-07-17T05:07:09Z",
            "finished_at": "2026-07-17T05:05:32Z",
        }
        self.assert_refused(reversed_window)

    def test_failure_cleanup_state_machine_is_fixed(self) -> None:
        for cleanup in (
            {
                "status": "passed",
                "failure_state": "not-mutated",
                "success_state": "not-reached",
                "clock_restored": True,
            },
            {
                "status": "passed",
                "failure_state": "absent",
                "success_state": "not-reached",
                "clock_restored": True,
            },
            {
                "status": "failed",
                "failure_state": "unknown",
                "success_state": "not-reached",
                "clock_restored": False,
            },
            {
                "status": "failed",
                "failure_state": "not-mutated",
                "success_state": "not-reached",
                "clock_restored": True,
            },
            {
                "status": "failed",
                "failure_state": "absent",
                "success_state": "not-reached",
                "clock_restored": False,
            },
            {
                "status": "failed",
                "failure_state": "not-required",
                "success_state": "documented-final",
                "clock_restored": True,
            },
        ):
            renderer.validate_cleanup_state(cleanup, "failed")

        with self.assertRaises(ValueError):
            renderer.validate_cleanup_state(
                {
                    "status": "passed",
                    "failure_state": "unknown",
                    "success_state": "documented-final",
                    "clock_restored": True,
                },
                "failed",
            )
        with self.assertRaises(ValueError):
            renderer.validate_cleanup_state(
                {
                    "status": "failed",
                    "failure_state": "not-mutated",
                    "success_state": "not-reached",
                    "clock_restored": False,
                },
                "failed",
            )
        with self.assertRaises(ValueError):
            renderer.validate_cleanup_state(
                {
                    "status": "failed",
                    "failure_state": "not-required",
                    "success_state": "documented-final",
                    "clock_restored": False,
                },
                "failed",
            )

    def test_duplicate_top_level_and_nested_keys_are_refused(self) -> None:
        raw = json.dumps(valid_p1(), separators=(",", ":"))
        duplicate_top = raw[:-1] + ',"proof":"your-cloud-v0.0.1"}'
        duplicate_nested = raw.replace('"status":"passed"', '"status":"passed","status":"passed"', 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            for hostile in (duplicate_top, duplicate_nested):
                path.write_text(hostile, encoding="utf-8")
                with self.assertRaises(ValueError):
                    renderer.load_exact_json(path)

    def test_unbounded_input_is_refused_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_bytes(b" " * (renderer.MAX_RESULT_BYTES + 1))
            with self.assertRaises(ValueError):
                renderer.load_exact_json(path)

    def test_both_projections_contain_the_exact_step_manifest(self) -> None:
        data = valid_p1()
        markdown = renderer.render_markdown(data)
        html = renderer.render_html(data)
        self.assertEqual(len(renderer.EXPECTED_STEPS), 20)
        for identifier, _, _ in renderer.EXPECTED_STEPS:
            self.assertEqual(markdown.count(f"`{identifier}`"), 1)
            self.assertEqual(html.count(f"<code>{identifier}</code>"), 1)


class P2SchemaTests(unittest.TestCase):
    def test_success_is_bound_to_source_and_capture_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.png"
            capture.write_bytes(renderer.PNG_SIGNATURE + b"\x00" * renderer.MIN_CAPTURE_BYTES)
            capture_sha = hashlib.sha256(capture.read_bytes()).hexdigest()
            data = {
                "schema": 1,
                "automation_scope": "P2",
                "outcome": "passed",
                "source": {"name": "result.json", "sha256": "3" * 64},
                "machine_assertions_authority": True,
                "server": {
                    "status": "passed",
                    "identity": "nobody",
                    "uid": 65534,
                    "listen": "127.0.0.1:18080",
                    "cleanup": "passed",
                },
                "content_check": "passed",
                "capture": {"status": "passed", "sha256": capture_sha},
                "diagnostic": {"class": None, "detail": None},
            }
            renderer.validate_render_result(data, "passed", "3" * 64, capture)

            wrong_source = copy.deepcopy(data)
            wrong_source["source"]["sha256"] = "4" * 64
            with self.assertRaises(ValueError):
                renderer.validate_render_result(wrong_source, "passed", "3" * 64, capture)

            no_authority = copy.deepcopy(data)
            no_authority["machine_assertions_authority"] = False
            with self.assertRaises(ValueError):
                renderer.validate_render_result(no_authority, "passed", "3" * 64, capture)

            extra = copy.deepcopy(data)
            extra["raw_browser_log"] = "forbidden"
            with self.assertRaises(ValueError):
                renderer.validate_render_result(extra, "passed", "3" * 64, capture)

            capture.write_bytes(b"changed-after-render")
            with self.assertRaises(ValueError):
                renderer.validate_render_result(data, "passed", "3" * 64, capture)

            capture.write_bytes(renderer.PNG_SIGNATURE + b"\x00" * (renderer.MAX_CAPTURE_BYTES + 1))
            data["capture"]["sha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                renderer.validate_render_result(data, "passed", "3" * 64, capture)

    def test_injected_failure_contract_is_exact(self) -> None:
        data = {
            "schema": 1,
            "automation_scope": "P2",
            "outcome": "failed",
            "source": {"name": "result.json", "sha256": "3" * 64},
            "machine_assertions_authority": True,
            "server": {
                "status": "passed",
                "identity": "nobody",
                "uid": 65534,
                "listen": "127.0.0.1:18080",
                "cleanup": "passed",
            },
            "content_check": "passed",
            "capture": {"status": "failed", "sha256": None},
            "diagnostic": {
                "class": "injected_capture_failure",
                "detail": "capture failure injected after a real Chromium execution",
            },
        }
        renderer.validate_render_result(data, "failed", "3" * 64, None)

        forged = copy.deepcopy(data)
        forged["diagnostic"]["class"] = "capture_failed"
        with self.assertRaises(ValueError):
            renderer.validate_render_result(forged, "failed", "3" * 64, None)

    def test_runtime_failure_diagnostic_is_bounded_by_fixed_values(self) -> None:
        data = {
            "schema": 1,
            "automation_scope": "P2",
            "outcome": "failed",
            "source": {"name": "result.json", "sha256": "3" * 64},
            "machine_assertions_authority": True,
            "server": {
                "status": "passed",
                "identity": "nobody",
                "uid": 65534,
                "listen": "127.0.0.1:18080",
                "cleanup": "passed",
            },
            "content_check": "passed",
            "capture": {"status": "failed", "sha256": None},
            "diagnostic": {
                "class": "capture_failed",
                "detail": "Chromium capture failed or exceeded 45 seconds",
            },
        }
        renderer.validate_failure_diagnostic(data, "3" * 64)

        unbounded = copy.deepcopy(data)
        unbounded["diagnostic"]["detail"] = "raw log: " + "x" * 1000
        with self.assertRaises(ValueError):
            renderer.validate_failure_diagnostic(unbounded, "3" * 64)

        wrong_type = copy.deepcopy(data)
        wrong_type["diagnostic"]["detail"] = {"raw": "forbidden"}
        with self.assertRaises(ValueError):
            renderer.validate_failure_diagnostic(wrong_type, "3" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
