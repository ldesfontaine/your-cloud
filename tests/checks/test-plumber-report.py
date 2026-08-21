#!/usr/bin/env python3
"""Cas hostiles du garde indépendant placé après l'action Plumber."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("plumber-report.py")
MODULE_SPEC = importlib.util.spec_from_file_location("plumber_report", MODULE_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("impossible de charger plumber-report.py")
PLUMBER_REPORT = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(PLUMBER_REPORT)
TEST_SOURCE_IDENTITY = "a" * 40
TEST_PROJECT = "ldesfontaine/your-cloud"


class PlumberReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.report = Path(self.temporary_directory.name) / "plumber-report.json"

    def clean_report(self) -> dict[str, object]:
        report: dict[str, object] = {
            "ciValid": True,
            "ciMissing": False,
            "minPoints": 100,
            "passed": True,
            "headCommitSha": TEST_SOURCE_IDENTITY,
            "projectPath": TEST_PROJECT,
            "plumberConfig": {
                "source": ".plumber.yaml",
                "hash": PLUMBER_REPORT.EXPECTED_POLICY_HASH,
            },
            "pipelineOriginMetrics": {"jobTotal": 4},
            "plumberScore": {
                "finalPoints": 100,
                "score": "A",
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "losses": [],
                "codeLosses": [],
            },
        }
        for field in PLUMBER_REPORT.REQUIRED_CONTROL_RESULTS:
            report[field] = {
                "ciValid": True,
                "ciMissing": False,
                "skipped": False,
                "issues": [],
                "metrics": {},
            }
        report["securityJobsWeakenedResult"]["metrics"] = {
            "securityJobsFound": 4,
            "weakenedJobs": 0,
        }
        report["authorizedActionSourcesResult"]["metrics"] = {
            "actionRefsTotal": 13,
            "actionRefsUnauthorized": 0,
        }
        report["permissionsResult"]["metrics"] = {
            "workflowsTotal": 1,
            "workflowsMissingPermissions": 0,
        }
        return report

    def hostile_report(self) -> dict[str, object]:
        report = self.clean_report()
        report["passed"] = False
        report["plumberScore"]["finalPoints"] = 77.5
        report["plumberScore"]["score"] = "B"
        report["plumberScore"]["counts"]["high"] = 3
        report["actionPinningResult"]["issues"] = [
            {
                "code": "ISSUE-701",
                "docUrl": "https://getplumber.io/docs/cli/issues/ISSUE-701",
                "jobName": job,
            }
            for job in ("ci/plumber_policy", "ci/app_platforms", "ci/source")
        ]
        return report

    def write_json(self, value: object) -> None:
        self.report.write_text(json.dumps(value), encoding="utf-8")

    def validate(self, outcome: str = "success", passed: str = "true") -> None:
        PLUMBER_REPORT.validate(
            self.report,
            outcome,
            passed,
            TEST_SOURCE_IDENTITY,
            TEST_PROJECT,
            PLUMBER_REPORT.EXPECTED_POLICY_HASH,
        )

    def validate_hostile(self) -> None:
        PLUMBER_REPORT.validate_action_pinning_failure(
            self.report,
            3,
            TEST_SOURCE_IDENTITY,
            TEST_PROJECT,
            PLUMBER_REPORT.EXPECTED_POLICY_HASH,
        )

    def assert_refused(self, expected_message: str) -> None:
        with self.assertRaisesRegex(PLUMBER_REPORT.ValidationError, expected_message):
            self.validate()

    def test_accepts_clean_known_fields_and_unknown_extensions(self) -> None:
        report = self.clean_report()
        report.update(
            {
                "partialControls": [],
                "warnings": [],
                "dataCollectionDegraded": False,
                "futureExtension": {"kept": True},
            }
        )
        self.write_json(report)
        self.validate()

    def test_accepts_report_when_optional_known_fields_are_absent(self) -> None:
        report = self.clean_report()
        report["futureExtension"] = "accepted"
        self.write_json(report)
        self.validate()

    def test_refuses_report_when_required_contract_is_absent(self) -> None:
        self.write_json({"futureExtension": "insufficient"})
        self.assert_refused("ciValid.*absent")

    def test_refuses_missing_report(self) -> None:
        self.assert_refused("absent")

    def test_refuses_oversized_report(self) -> None:
        with self.report.open("wb") as report_file:
            report_file.truncate(PLUMBER_REPORT.MAX_REPORT_BYTES + 1)
        self.assert_refused("taille autorisée")

    def test_refuses_symbolic_link(self) -> None:
        target = Path(self.temporary_directory.name) / "target.json"
        target.write_text("{}", encoding="utf-8")
        self.report.symlink_to(target)
        self.assert_refused("lien symbolique")

    def test_refuses_duplicate_json_key_at_any_depth(self) -> None:
        self.report.write_text(
            '{"future":{"same":1,"same":2}}', encoding="utf-8"
        )
        self.assert_refused("clé dupliquée")

    def test_refuses_nonempty_partial_controls(self) -> None:
        report = self.clean_report()
        report["partialControls"] = [{"control": "not-evaluated"}]
        self.write_json(report)
        self.assert_refused("partialControls.*incomplet")

    def test_refuses_nonempty_warnings(self) -> None:
        report = self.clean_report()
        report["warnings"] = ["could not verify"]
        self.write_json(report)
        self.assert_refused("warnings.*incomplet")

    def test_refuses_degraded_data_collection(self) -> None:
        report = self.clean_report()
        report["dataCollectionDegraded"] = True
        self.write_json(report)
        self.assert_refused("dataCollectionDegraded.*dégradé")

    def test_refuses_invalid_ci(self) -> None:
        report = self.clean_report()
        report["ciValid"] = False
        self.write_json(report)
        self.assert_refused("ciValid.*valeur refusée")

    def test_refuses_missing_ci(self) -> None:
        report = self.clean_report()
        report["ciMissing"] = True
        self.write_json(report)
        self.assert_refused("ciMissing.*valeur refusée")

    def test_refuses_malformed_known_fields(self) -> None:
        malformed_values = {
            "partialControls": None,
            "warnings": {},
            "dataCollectionDegraded": 0,
            "ciValid": "true",
            "ciMissing": [],
        }
        for field, value in malformed_values.items():
            with self.subTest(field=field):
                report = self.clean_report()
                report[field] = value
                self.write_json(report)
                self.assert_refused(f"{field}.*(liste|booléen)")

    def test_refuses_unsuccessful_action_outcome(self) -> None:
        self.write_json(self.clean_report())
        with self.assertRaisesRegex(
            PLUMBER_REPORT.ValidationError, "ne s'est pas terminée avec succès"
        ):
            self.validate(outcome="failure")

    def test_refuses_action_passed_output_other_than_exact_true(self) -> None:
        self.write_json(self.clean_report())
        for passed in ("", "false", "TRUE", "1"):
            with self.subTest(passed=passed):
                with self.assertRaisesRegex(
                    PLUMBER_REPORT.ValidationError, "sortie passed"
                ):
                    self.validate(passed=passed)

    def test_refuses_non_object_json_root(self) -> None:
        self.write_json([])
        self.assert_refused("racine.*objet JSON")

    def test_refuses_non_standard_json_numbers(self) -> None:
        self.report.write_text('{"score":NaN}', encoding="utf-8")
        self.assert_refused("nombre non conforme")

    def test_refuses_failed_or_incomplete_score(self) -> None:
        cases = (
            ("passed", False, "passed.*valeur refusée"),
            ("minPoints", 99, "minPoints.*valeur refusée"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                report = self.clean_report()
                report[field] = value
                self.write_json(report)
                self.assert_refused(message)

        report = self.clean_report()
        report["plumberScore"]["codeLosses"] = [{"code": "ISSUE-701"}]
        self.write_json(report)
        self.assert_refused("codeLosses")

    def test_refuses_missing_skipped_or_failing_required_control(self) -> None:
        for mutation, message in (
            ("missing", "actionPinningResult.*objet"),
            ("skipped", "skipped.*valeur refusée"),
            ("issues", "actionPinningResult.*constats"),
        ):
            with self.subTest(mutation=mutation):
                report = self.clean_report()
                if mutation == "missing":
                    del report["actionPinningResult"]
                elif mutation == "skipped":
                    report["actionPinningResult"]["skipped"] = True
                else:
                    report["actionPinningResult"]["issues"] = [
                        {"code": "ISSUE-701"}
                    ]
                self.write_json(report)
                self.assert_refused(message)

    def test_refuses_vacuous_security_job_control(self) -> None:
        report = self.clean_report()
        report["securityJobsWeakenedResult"]["metrics"]["securityJobsFound"] = 0
        self.write_json(report)
        self.assert_refused("securityJobsFound.*valeur refusée")

    def test_refuses_wrong_source_policy_or_denominator(self) -> None:
        mutations = (
            ("source", "lot source"),
            ("policy", "politique attendue"),
            ("jobs", "jobTotal.*valeur refusée"),
            ("actions", "actionRefsTotal.*valeur refusée"),
            ("workflows", "workflowsTotal.*valeur refusée"),
        )
        for mutation, message in mutations:
            with self.subTest(mutation=mutation):
                report = self.clean_report()
                if mutation == "source":
                    report["headCommitSha"] = "b" * 40
                elif mutation == "policy":
                    report["plumberConfig"]["hash"] = "sha256:" + "0" * 64
                elif mutation == "jobs":
                    report["pipelineOriginMetrics"]["jobTotal"] = 1
                elif mutation == "actions":
                    report["authorizedActionSourcesResult"]["metrics"][
                        "actionRefsTotal"
                    ] = 4
                else:
                    report["permissionsResult"]["metrics"]["workflowsTotal"] = 2
                self.write_json(report)
                self.assert_refused(message)

    def test_accepts_exact_hostile_action_pinning_result(self) -> None:
        self.write_json(self.hostile_report())
        self.validate_hostile()

    def test_refuses_hostile_result_with_wrong_issue_or_job(self) -> None:
        report = self.hostile_report()
        report["actionPinningResult"]["issues"][0]["code"] = "ISSUE-999"
        self.write_json(report)
        with self.assertRaisesRegex(
            PLUMBER_REPORT.ValidationError, "constat inattendu"
        ):
            self.validate_hostile()

        report = self.hostile_report()
        report["actionPinningResult"]["issues"][0]["jobName"] = "ci/other"
        self.write_json(report)
        with self.assertRaisesRegex(
            PLUMBER_REPORT.ValidationError, "trois jobs CI"
        ):
            self.validate_hostile()


if __name__ == "__main__":
    unittest.main()
