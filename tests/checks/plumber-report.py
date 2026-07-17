#!/usr/bin/env python3
"""Refuse un résultat Plumber absent, ambigu, incomplet ou dégradé."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


MAX_REPORT_BYTES = 8 * 1024 * 1024

EXPECTED_MIN_POINTS = 100
EXPECTED_POLICY_HASH = (
    "sha256:3891f8bcecc443b540a388f08144496d86d613c4721cc4ca8edccb1dcf53707f"
)
REQUIRED_CONTROL_RESULTS = (
    "actionPinningResult",
    "authorizedActionSourcesResult",
    "debugTraceResult",
    "dockerInDockerResult",
    "reusableSecretsResult",
    "overprovisionedSecretsResult",
    "securityJobsWeakenedResult",
    "unverifiedScriptsResult",
    "templateInjectionResult",
    "githubEnvInjectionResult",
    "dangerousTriggersResult",
    "pullRequestTargetHeadCheckoutResult",
    "permissionsResult",
    "excessivePermissionsResult",
)


class ValidationError(Exception):
    """Erreur attendue qui doit rendre le contrôle CI bloquant."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("le rapport JSON contient une clé dupliquée")
        result[key] = value
    return result


def _reject_non_standard_number(_value: str) -> None:
    raise ValidationError("le rapport contient un nombre non conforme à JSON")


def _load_report(path: Path, max_bytes: int = MAX_REPORT_BYTES) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValidationError("le rapport Plumber est absent") from error
    except OSError as error:
        raise ValidationError("les métadonnées du rapport sont illisibles") from error

    if stat.S_ISLNK(metadata.st_mode):
        raise ValidationError("le rapport Plumber ne doit pas être un lien symbolique")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("le rapport Plumber doit être un fichier régulier")
    if metadata.st_size > max_bytes:
        raise ValidationError("le rapport Plumber dépasse la taille autorisée")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ValidationError("le rapport Plumber a disparu pendant sa lecture") from error
    except OSError as error:
        raise ValidationError("le rapport Plumber ne peut pas être ouvert sûrement") from error

    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise ValidationError("le rapport ouvert n'est pas un fichier régulier")
        if opened_metadata.st_size > max_bytes:
            raise ValidationError("le rapport Plumber dépasse la taille autorisée")

        with os.fdopen(descriptor, "rb", closefd=False) as report_file:
            raw_report = report_file.read(max_bytes + 1)
    finally:
        os.close(descriptor)

    if len(raw_report) > max_bytes:
        raise ValidationError("le rapport Plumber dépasse la taille autorisée")

    try:
        parsed = json.loads(
            raw_report.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_non_standard_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("le rapport Plumber n'est pas un objet JSON UTF-8 valide") from error

    if not isinstance(parsed, dict):
        raise ValidationError("la racine du rapport Plumber doit être un objet JSON")
    return parsed


def _require_optional_list(report: dict[str, Any], field: str) -> None:
    if field not in report:
        return
    value = report[field]
    if not isinstance(value, list):
        raise ValidationError(f"le champ connu {field} doit être une liste")
    if value:
        raise ValidationError(f"le champ connu {field} signale un résultat incomplet")


def _require_optional_boolean(
    report: dict[str, Any], field: str, accepted_value: bool
) -> None:
    if field not in report:
        return
    value = report[field]
    if type(value) is not bool:
        raise ValidationError(f"le champ connu {field} doit être un booléen")
    if value is not accepted_value:
        raise ValidationError(f"le champ connu {field} signale un résultat dégradé")


def _require_exact_boolean(
    report: dict[str, Any], field: str, accepted_value: bool
) -> None:
    if field not in report:
        raise ValidationError(f"le champ obligatoire {field} est absent")
    value = report[field]
    if type(value) is not bool:
        raise ValidationError(f"le champ obligatoire {field} doit être un booléen")
    if value is not accepted_value:
        raise ValidationError(f"le champ obligatoire {field} a une valeur refusée")


def _require_object(report: dict[str, Any], field: str) -> dict[str, Any]:
    value = report.get(field)
    if not isinstance(value, dict):
        raise ValidationError(f"le champ obligatoire {field} doit être un objet")
    return value


def _require_exact_integer(report: dict[str, Any], field: str, expected: int) -> None:
    value = report.get(field)
    if type(value) is not int:
        raise ValidationError(f"le champ obligatoire {field} doit être un entier")
    if value != expected:
        raise ValidationError(f"le champ obligatoire {field} a une valeur refusée")


def _require_report_identity(
    report: dict[str, Any],
    expected_source_identity: str,
    expected_project: str,
    expected_policy_hash: str,
) -> None:
    if (
        len(expected_source_identity) != 40
        or any(
            character not in "0123456789abcdef"
            for character in expected_source_identity
        )
    ):
        raise ValidationError(
            "l'identité source attendue n'est pas un hexadécimal de 40 caractères"
        )
    if report.get("headCommitSha") != expected_source_identity:
        raise ValidationError("le rapport Plumber ne correspond pas au lot source attendu")
    if not expected_project or report.get("projectPath") != expected_project:
        raise ValidationError("le rapport Plumber ne correspond pas au dépôt attendu")

    config = _require_object(report, "plumberConfig")
    if config.get("source") != ".plumber.yaml":
        raise ValidationError("le rapport Plumber ne nomme pas la politique attendue")
    if expected_policy_hash != EXPECTED_POLICY_HASH:
        raise ValidationError("le hash de politique attendu n'est pas celui du garde")
    if config.get("hash") != expected_policy_hash:
        raise ValidationError("le rapport Plumber ne correspond pas à la politique attendue")


def _require_common_report_contract(report: dict[str, Any]) -> None:
    _require_exact_boolean(report, "ciValid", True)
    _require_exact_boolean(report, "ciMissing", False)
    _require_exact_integer(report, "minPoints", EXPECTED_MIN_POINTS)
    _require_optional_list(report, "partialControls")
    _require_optional_list(report, "warnings")
    _require_optional_boolean(report, "dataCollectionDegraded", False)


def _require_clean_score(report: dict[str, Any]) -> None:
    score = _require_object(report, "plumberScore")
    final_points = score.get("finalPoints")
    if type(final_points) not in (int, float) or final_points != EXPECTED_MIN_POINTS:
        raise ValidationError("le score Plumber final n'atteint pas exactement 100")
    if score.get("score") != "A":
        raise ValidationError("la lettre du score Plumber n'est pas A")

    counts = _require_object(score, "counts")
    for severity in ("critical", "high", "medium", "low"):
        _require_exact_integer(counts, severity, 0)
    for field in ("losses", "codeLosses"):
        value = score.get(field)
        if not isinstance(value, list) or value:
            raise ValidationError(f"le score Plumber contient des {field}")


def _require_clean_control(report: dict[str, Any], field: str) -> None:
    control = _require_object(report, field)
    _require_exact_boolean(control, "ciValid", True)
    _require_exact_boolean(control, "ciMissing", False)
    _require_exact_boolean(control, "skipped", False)
    issues = control.get("issues")
    if not isinstance(issues, list) or issues:
        raise ValidationError(f"le contrôle obligatoire {field} contient des constats")


def validate(
    report_path: Path,
    action_outcome: str,
    action_passed: str,
    expected_source_identity: str,
    expected_project: str,
    expected_policy_hash: str,
    max_bytes: int = MAX_REPORT_BYTES,
) -> None:
    """Valide les signaux stables sans rejeter les extensions de schéma."""

    if action_outcome != "success":
        raise ValidationError("l'action Plumber ne s'est pas terminée avec succès")
    if action_passed != "true":
        raise ValidationError("la sortie passed de Plumber n'est pas vraie")

    report = _load_report(report_path, max_bytes=max_bytes)
    _require_common_report_contract(report)
    _require_report_identity(
        report, expected_source_identity, expected_project, expected_policy_hash
    )
    _require_optional_list(report, "findings")
    _require_exact_boolean(report, "passed", True)
    _require_clean_score(report)
    for field in REQUIRED_CONTROL_RESULTS:
        _require_clean_control(report, field)
    security_metrics = _require_object(
        _require_object(report, "securityJobsWeakenedResult"), "metrics"
    )
    _require_exact_integer(security_metrics, "securityJobsFound", 2)
    _require_exact_integer(security_metrics, "weakenedJobs", 0)
    pipeline_metrics = _require_object(report, "pipelineOriginMetrics")
    _require_exact_integer(pipeline_metrics, "jobTotal", 2)
    authorized_metrics = _require_object(
        _require_object(report, "authorizedActionSourcesResult"), "metrics"
    )
    _require_exact_integer(authorized_metrics, "actionRefsTotal", 5)
    permissions_metrics = _require_object(
        _require_object(report, "permissionsResult"), "metrics"
    )
    _require_exact_integer(permissions_metrics, "workflowsTotal", 1)


def validate_action_pinning_failure(
    report_path: Path,
    expected_issues: int,
    expected_source_identity: str,
    expected_project: str,
    expected_policy_hash: str,
    max_bytes: int = MAX_REPORT_BYTES,
) -> None:
    """Prouve qu'un tag mutable précis est refusé pour les deux jobs CI."""

    if expected_issues != 2:
        raise ValidationError("le scénario hostile doit attendre exactement deux constats")
    report = _load_report(report_path, max_bytes=max_bytes)
    _require_common_report_contract(report)
    _require_report_identity(
        report, expected_source_identity, expected_project, expected_policy_hash
    )
    if "findings" in report and not isinstance(report["findings"], list):
        raise ValidationError("le champ connu findings doit être une liste")
    _require_exact_boolean(report, "passed", False)

    score = _require_object(report, "plumberScore")
    final_points = score.get("finalPoints")
    if (
        type(final_points) not in (int, float)
        or not 0 <= final_points < EXPECTED_MIN_POINTS
    ):
        raise ValidationError("le scénario hostile n'a pas abaissé le score sous 100")

    action_pinning = _require_object(report, "actionPinningResult")
    _require_exact_boolean(action_pinning, "ciValid", True)
    _require_exact_boolean(action_pinning, "ciMissing", False)
    _require_exact_boolean(action_pinning, "skipped", False)
    issues = action_pinning.get("issues")
    if not isinstance(issues, list) or len(issues) != expected_issues:
        raise ValidationError("le nombre de constats ISSUE-701 est inattendu")

    expected_jobs = {"ci/source", "ci/plumber_policy"}
    observed_jobs: set[str] = set()
    for issue in issues:
        if not isinstance(issue, dict) or issue.get("code") != "ISSUE-701":
            raise ValidationError("le scénario hostile contient un constat inattendu")
        if issue.get("docUrl") != "https://getplumber.io/docs/cli/issues/ISSUE-701":
            raise ValidationError("le constat ISSUE-701 ne porte pas sa référence attendue")
        job_name = issue.get("jobName")
        if not isinstance(job_name, str):
            raise ValidationError("le constat ISSUE-701 ne nomme pas son job")
        observed_jobs.add(job_name)
    if observed_jobs != expected_jobs:
        raise ValidationError("les constats ISSUE-701 ne couvrent pas les deux jobs CI")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Valide sans l'afficher le résultat structuré de Plumber."
    )
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument(
        "--mode", choices=("clean", "action-pinning-failure"), default="clean"
    )
    parser.add_argument("--action-outcome", default="")
    parser.add_argument("--action-passed", default="")
    parser.add_argument("--expected-action-pinning-issues", type=int, default=2)
    parser.add_argument("--expected-source-identity", required=True)
    parser.add_argument("--expected-project", required=True)
    parser.add_argument("--expected-policy-hash", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        if arguments.mode == "clean":
            validate(
                arguments.report,
                action_outcome=arguments.action_outcome,
                action_passed=arguments.action_passed,
                expected_source_identity=arguments.expected_source_identity,
                expected_project=arguments.expected_project,
                expected_policy_hash=arguments.expected_policy_hash,
            )
        else:
            validate_action_pinning_failure(
                arguments.report,
                expected_issues=arguments.expected_action_pinning_issues,
                expected_source_identity=arguments.expected_source_identity,
                expected_project=arguments.expected_project,
                expected_policy_hash=arguments.expected_policy_hash,
            )
    except ValidationError as error:
        print(f"REFUS plumber-report: {error}", file=sys.stderr)
        return 1

    print(f"OK plumber-report: contrat structuré {arguments.mode} vérifié")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
