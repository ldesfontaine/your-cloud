#!/usr/bin/env python3
"""Render P1's allowlisted machine result into Markdown and standalone HTML."""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import os
import re
import socket
import sys
from pathlib import Path


EXPECTED_TOP_LEVEL = {
    "schema",
    "proof",
    "automation_scope",
    "outcome",
    "failure_class",
    "source_revision",
    "source_lot_sha256",
    "artifact_sha256",
    "topology",
    "targets",
    "relay_window",
    "cleanup",
    "redaction",
    "steps",
}
EXPECTED_STEP = {"id", "category", "title", "status"}
EXPECTED_TARGETS = ["lab-app", "lab-coordinateur", "lab-machine-1", "lab-machine-2"]
ALLOWED_CATEGORIES = {"infrastructure", "assertion", "expected_refusal", "cleanup"}
EXPECTED_STEPS = (
    ("inventory", "infrastructure", "Read-only LAB inventory guard"),
    (
        "package",
        "infrastructure",
        "Lock the LAB workspace and package the complete non-sensitive source lot",
    ),
    ("source-gate", "assertion", "Single source-side gate and build in lab-app"),
    (
        "prepare-targets",
        "infrastructure",
        "Transfer the LAB artifact with the managed labctl host-key observation pinned on direct SSH",
    ),
    ("absent-start", "cleanup", "Known absent starting state"),
    ("invalid-first-artifact", "expected_refusal", "Transactional refusal of an invalid first artifact"),
    ("host-identity-matrix", "expected_refusal", "Host and allowed-identity mismatch matrix"),
    ("install-roles", "assertion", "Install one artifact with isolated parallel roles and managed metadata"),
    ("non-candidate-relay", "expected_refusal", "Reject Relay activation on the non-candidate machine"),
    ("listen-address-matrix", "expected_refusal", "Reject every declared forbidden Relay listen-address class"),
    ("start-limit-recovery", "expected_refusal", "Reach start-limit-hit and recover only after reset-failed"),
    ("unmanaged-processes", "expected_refusal", "Refuse deletion around Daemon and Relay processes outside their units"),
    ("controlled-clock-skew", "assertion", "Skew emitter and Relay wall clocks while keeping freshness reception-owned"),
    ("journal-transitions", "assertion", "Count success, prolonged outage and recovery log transitions"),
    ("hostile-http", "expected_refusal", "Live hostile POST and QUERY matrix"),
    ("presence-transitions", "assertion", "Presence transitions and independent restarts"),
    ("replacement-rollback", "expected_refusal", "Transactional rollback after an invalid shared artifact"),
    ("relay-lifecycle", "assertion", "Independent Relay disable and re-enable"),
    ("complete-removal", "cleanup", "Complete removal and verified absence"),
    ("final-state", "assertion", "Reinstall the documented final state"),
)
EXPECTED_RENDER_TOP_LEVEL = {
    "schema",
    "automation_scope",
    "outcome",
    "source",
    "machine_assertions_authority",
    "server",
    "content_check",
    "capture",
    "diagnostic",
}
DIAGNOSTIC_DETAILS = {
    "render_refused": {"structured P1 result was refused by the renderer"},
    "server_start_failed": {
        "temporary proof port is already in use",
        "temporary proof server did not start",
    },
    "server_identity_failed": {
        "temporary proof server identity is not nobody with cleared groups",
    },
    "server_listener_failed": {
        "temporary proof server listener is not the expected loopback process",
    },
    "content_check_failed": {
        "temporary proof page request failed",
        "temporary proof page did not return HTTP 200",
        "machine-assertion authority warning is missing",
        "P1 fingerprints could not be read strictly",
        "P1 fingerprint list is not exact",
        "P1 fingerprint value is invalid",
        "served proof page omitted a P1 fingerprint",
        "P1 step identifier list could not be read strictly",
        "P1 step identifier list is not exact",
        "generated proof projections omitted a P1 step identifier",
    },
    "capture_failed": {
        "Chromium capture failed or exceeded 45 seconds",
        "Chromium capture size is outside fixed bounds",
        "Chromium capture is not a PNG",
        "captured PNG SHA-256 is invalid",
    },
    "injected_capture_failure": {
        "capture failure injected after a real Chromium execution",
    },
    "cleanup_failed": {
        "temporary proof process or listener cleanup failed",
    },
    "unexpected_worker_failure": {
        "worker exited without all restitution assertions",
        "worker stopped outside an allowlisted failure point",
    },
}
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}(?:\+worktree)?$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MAX_RESULT_BYTES = 65536
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MIN_CAPTURE_BYTES = 10000
MAX_CAPTURE_BYTES = 16 * 1024 * 1024


def refuse(message: str) -> None:
    raise ValueError(message)


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON key refused")
        result[key] = value
    return result


def load_exact_json(source: Path) -> object:
    if not source.is_file() or source.is_symlink():
        refuse("structured result must be a regular non-symlink file")
    size = source.stat().st_size
    if size <= 0 or size > MAX_RESULT_BYTES:
        refuse("structured result size is empty or exceeds the fixed limit")
    return json.loads(
        source.read_text(encoding="utf-8"),
        object_pairs_hook=no_duplicate_keys,
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc(value: object, name: str) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        refuse(f"{name} must be a bounded UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} is not a valid timestamp") from error
    return parsed


def validate_cleanup_state(cleanup: object, outcome: str) -> dict[str, object]:
    if not isinstance(cleanup, dict) \
            or set(cleanup) != {"status", "failure_state", "success_state", "clock_restored"}:
        refuse("P1 cleanup schema is not exact")
    if type(cleanup["clock_restored"]) is not bool:
        refuse("P1 cleanup clock-restoration status is invalid")
    if not all(
        isinstance(cleanup[field], str)
        for field in ("status", "failure_state", "success_state")
    ):
        refuse("P1 cleanup state values must be strings")
    observed = (
        cleanup["status"],
        cleanup["failure_state"],
        cleanup["success_state"],
    )
    if outcome == "passed":
        if observed != ("passed", "not-required", "documented-final") \
                or cleanup["clock_restored"] is not True:
            refuse("successful P1 cleanup is not the exact documented-final state")
    elif outcome == "failed":
        clean_failure_states = {
            ("passed", "not-mutated", "not-reached"),
            ("passed", "absent", "not-reached"),
        }
        failed_temporary_cleanup_states = {
            ("failed", "not-mutated", "not-reached"),
            ("failed", "absent", "not-reached"),
            ("failed", "unknown", "not-reached"),
            ("failed", "not-required", "documented-final"),
        }
        if observed not in clean_failure_states | failed_temporary_cleanup_states:
            refuse("failed P1 cleanup state is outside the fixed state machine")
        if observed in clean_failure_states and cleanup["clock_restored"] is not True:
            refuse("successful failure cleanup did not restore the controlled clock")
        if observed in {
            ("failed", "not-mutated", "not-reached"),
            ("failed", "not-required", "documented-final"),
        } and cleanup["clock_restored"] is not True:
            refuse("P1 reported an impossible dirty clock for the known produced state")
    else:
        refuse("P1 outcome is invalid for cleanup validation")
    return cleanup


def validate(data: object) -> dict[str, object]:
    if not isinstance(data, dict) or set(data) != EXPECTED_TOP_LEVEL:
        refuse("result top-level schema is not exact")
    if type(data["schema"]) is not int or data["schema"] != 1 or data["proof"] != "your-cloud-v0.0.1":
        refuse("result identity is not v0.0.1 schema 1")
    if data["automation_scope"] != "P1" or data["outcome"] != "passed":
        refuse("only a successful P1 machine result can be rendered")
    if data["failure_class"] is not None:
        refuse("successful result cannot contain a failure class")
    if not isinstance(data["source_revision"], str) or not REVISION.fullmatch(data["source_revision"]):
        refuse("source revision is invalid")
    for field in ("source_lot_sha256", "artifact_sha256"):
        if not isinstance(data[field], str) or not HEX_64.fullmatch(data[field]):
            refuse(f"{field} is invalid")
    if data["topology"] != "v1-full" or data["targets"] != EXPECTED_TARGETS:
        refuse("topology or target allowlist changed")

    relay_window = data["relay_window"]
    if not isinstance(relay_window, dict) or set(relay_window) != {"started_at", "finished_at"}:
        refuse("Relay window schema is not exact")
    started_at = parse_utc(relay_window["started_at"], "relay_window.started_at")
    finished_at = parse_utc(relay_window["finished_at"], "relay_window.finished_at")
    if finished_at < started_at:
        refuse("Relay window finishes before it starts")

    cleanup = validate_cleanup_state(data["cleanup"], "passed")
    redaction = data["redaction"]
    if redaction != {"policy": "fixed-field-allowlist", "sensitive_data_included": False}:
        refuse("redaction contract changed")

    steps = data["steps"]
    if not isinstance(steps, list) or len(steps) != len(EXPECTED_STEPS):
        refuse("step list does not contain the exact v0.0.1 manifest")
    seen: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) != EXPECTED_STEP:
            refuse("step schema is not exact")
        identifier = step["id"]
        title = step["title"]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier) or identifier in seen:
            refuse("step identifier is invalid or duplicated")
        if not isinstance(step["category"], str) or step["category"] not in ALLOWED_CATEGORIES \
                or step["status"] != "passed":
            refuse("step category or status is invalid")
        if not isinstance(title, str) or not (1 <= len(title) <= 160) or any(ord(char) < 32 for char in title):
            refuse("step title is invalid")
        expected_id, expected_category, expected_title = EXPECTED_STEPS[index]
        if (identifier, step["category"], title) != (
            expected_id,
            expected_category,
            expected_title,
        ):
            refuse("step manifest changed, is incomplete or is out of order")
        seen.add(identifier)
    return data


def validate_render_result(
    data: object,
    expected_outcome: str,
    expected_source_sha: str,
    capture_path: Path | None,
) -> dict[str, object]:
    if not isinstance(data, dict) or set(data) != EXPECTED_RENDER_TOP_LEVEL:
        refuse("P2 result top-level schema is not exact")
    if type(data["schema"]) is not int or data["schema"] != 1 or data["automation_scope"] != "P2":
        refuse("P2 result identity is invalid")
    if expected_outcome not in {"passed", "failed"} or data["outcome"] != expected_outcome:
        refuse("P2 result outcome is unexpected")
    if data["machine_assertions_authority"] is not True:
        refuse("P2 result lost machine assertion authority")
    if data["source"] != {"name": "result.json", "sha256": expected_source_sha}:
        refuse("P2 result is not bound to the expected P1 result")
    if data["server"] != {
        "status": "passed",
        "identity": "nobody",
        "uid": 65534,
        "listen": "127.0.0.1:18080",
        "cleanup": "passed",
    }:
        refuse("P2 server identity, listener or cleanup is not exact")
    if data["content_check"] != "passed":
        refuse("P2 served-content check did not pass")

    capture = data["capture"]
    if not isinstance(capture, dict) or set(capture) != {"status", "sha256"}:
        refuse("P2 capture schema is not exact")
    diagnostic = data["diagnostic"]
    if not isinstance(diagnostic, dict) or set(diagnostic) != {"class", "detail"}:
        refuse("P2 diagnostic schema is not exact")
    if expected_outcome == "passed":
        if capture["status"] != "passed" or not isinstance(capture["sha256"], str) \
                or not HEX_64.fullmatch(capture["sha256"]):
            refuse("successful P2 capture metadata is invalid")
        if capture_path is None or not capture_path.is_file() or capture_path.is_symlink():
            refuse("P2 capture is not a regular non-symlink file")
        capture_size = capture_path.stat().st_size
        if not MIN_CAPTURE_BYTES < capture_size <= MAX_CAPTURE_BYTES:
            refuse("P2 capture size is outside the fixed bounds")
        with capture_path.open("rb") as stream:
            if stream.read(len(PNG_SIGNATURE)) != PNG_SIGNATURE:
                refuse("P2 capture does not carry the PNG signature")
        if file_sha256(capture_path) != capture["sha256"]:
            refuse("P2 capture bytes do not match their structured SHA-256")
        if diagnostic != {"class": None, "detail": None}:
            refuse("successful P2 result contains a diagnostic")
    else:
        if capture != {"status": "failed", "sha256": None}:
            refuse("expected P2 capture failure is not exact")
        if diagnostic["class"] != "injected_capture_failure":
            refuse("expected P2 injected-failure diagnostic is not exact")
        detail = diagnostic["detail"]
        if detail != "capture failure injected after a real Chromium execution":
            refuse("expected P2 injected-failure detail is not exact")
    return data


def validate_failure_diagnostic(data: object, expected_source_sha: str) -> dict[str, object]:
    if not isinstance(data, dict) or set(data) != EXPECTED_RENDER_TOP_LEVEL:
        refuse("P2 diagnostic top-level schema is not exact")
    if type(data["schema"]) is not int or data["schema"] != 1 \
            or data["automation_scope"] != "P2" or data["outcome"] != "failed":
        refuse("P2 diagnostic identity or outcome is invalid")
    if data["machine_assertions_authority"] is not True:
        refuse("P2 diagnostic lost machine assertion authority")
    if data["source"] != {"name": "result.json", "sha256": expected_source_sha}:
        refuse("P2 diagnostic is not bound to the expected P1 result")
    server = data["server"]
    if not isinstance(server, dict) \
            or set(server) != {"status", "identity", "uid", "listen", "cleanup"}:
        refuse("P2 diagnostic server schema is not exact")
    if not isinstance(server["status"], str) \
            or server["status"] not in {"not_run", "failed", "passed"} \
            or server["identity"] != "nobody" or server["uid"] != 65534 \
            or server["listen"] != "127.0.0.1:18080" \
            or not isinstance(server["cleanup"], str) \
            or server["cleanup"] not in {"passed", "failed"}:
        refuse("P2 diagnostic server values are invalid")
    if not isinstance(data["content_check"], str) \
            or data["content_check"] not in {"not_run", "passed", "failed"}:
        refuse("P2 diagnostic content status is invalid")
    capture = data["capture"]
    if not isinstance(capture, dict) or set(capture) != {"status", "sha256"} \
            or not isinstance(capture["status"], str) \
            or capture["status"] not in {"not_run", "failed"} or capture["sha256"] is not None:
        refuse("P2 diagnostic capture status is invalid")
    diagnostic = data["diagnostic"]
    if not isinstance(diagnostic, dict) or set(diagnostic) != {"class", "detail"}:
        refuse("P2 diagnostic schema is not exact")
    diagnostic_class = diagnostic["class"]
    diagnostic_detail = diagnostic["detail"]
    if not isinstance(diagnostic_class, str) or diagnostic_class not in DIAGNOSTIC_DETAILS \
            or not isinstance(diagnostic_detail, str) \
            or diagnostic_detail not in DIAGNOSTIC_DETAILS[diagnostic_class]:
        refuse("P2 diagnostic contains a non-allowlisted class or detail")
    return data


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(data: dict[str, object]) -> str:
    window = data["relay_window"]
    cleanup = data["cleanup"]
    lines = [
        "# Restitution automatique v0.0.1",
        "",
        "> Projection P2 du résultat structuré P1. Les assertions machine restent",
        "> l'autorité ; cette page et sa capture ne prouvent pas le produit.",
        "",
        "## Lot exécuté",
        "",
        "| Champ | Valeur |",
        "|---|---|",
        f"| Révision source | `{markdown_cell(data['source_revision'])}` |",
        f"| Empreinte du lot source | `{markdown_cell(data['source_lot_sha256'])}` |",
        f"| Empreinte de l'artefact | `{markdown_cell(data['artifact_sha256'])}` |",
        f"| Topologie | `{markdown_cell(data['topology'])}` |",
        f"| Fenêtre Relay | `{markdown_cell(window['started_at'])}` → `{markdown_cell(window['finished_at'])}` |",
        f"| Nettoyage P1 | `{markdown_cell(cleanup['status'])}` |",
        "",
        "## Étapes assertées",
        "",
        "| ID | Étape | Catégorie | Statut |",
        "|---|---|---|---|",
    ]
    for step in data["steps"]:
        lines.append(
            f"| `{markdown_cell(step['id'])}` | {markdown_cell(step['title'])} | "
            f"`{markdown_cell(step['category'])}` | "
            f"`{markdown_cell(step['status'])}` |"
        )
    lines.extend(
        [
            "",
            "## Limites",
            "",
            "La capture vérifie seulement le rendu de cette projection. Elle ne remplace ni",
            "les codes de sortie, ni les assertions HTTP/systemd, ni le statut de nettoyage",
            "consignés dans `result.json`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(data: dict[str, object]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    window = data["relay_window"]
    rows = "\n".join(
        "<tr>"
        f"<td><strong>{esc(step['title'])}</strong><code>{esc(step['id'])}</code></td>"
        f"<td><span class='tag'>{esc(step['category'])}</span></td>"
        f"<td><span class='pass'>{esc(step['status'])}</span></td>"
        "</tr>"
        for step in data["steps"]
    )
    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Preuve automatisée v0.0.1</title>
<style>
:root {{ color-scheme: dark; --ink:#edf5ff; --muted:#9fb1c4; --panel:#111d2b; --line:#284059; --cyan:#69d5ff; --green:#74e2a8; --amber:#ffc66d; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:radial-gradient(circle at 80% 0,#163552 0,#09121d 42%,#060b12 100%); color:var(--ink); font:16px/1.5 system-ui,sans-serif; }}
main {{ width:min(1180px,92vw); margin:0 auto; padding:56px 0 72px; }}
.eyebrow {{ color:var(--cyan); font-weight:800; letter-spacing:.14em; text-transform:uppercase; }}
h1 {{ max-width:850px; margin:.25rem 0 1rem; font-size:clamp(2.3rem,5vw,4.8rem); line-height:1; }}
.authority {{ max-width:900px; border-left:4px solid var(--amber); padding:14px 18px; background:#201a10; color:#ffe4b5; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin:28px 0; }}
.card {{ min-height:132px; padding:18px; border:1px solid var(--line); border-radius:14px; background:rgba(17,29,43,.9); }}
.card span {{ color:var(--muted); display:block; font-size:.78rem; letter-spacing:.08em; text-transform:uppercase; }}
.card strong {{ display:block; margin-top:9px; overflow-wrap:anywhere; font-size:1.05rem; }}
section {{ margin-top:36px; }} h2 {{ font-size:1.5rem; }}
table {{ width:100%; border-collapse:collapse; border:1px solid var(--line); background:rgba(9,18,29,.88); }}
th,td {{ padding:12px 14px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
th {{ color:var(--muted); font-size:.76rem; letter-spacing:.08em; text-transform:uppercase; }}
td code {{ display:block; color:var(--muted); font-size:.78rem; }}
.tag,.pass {{ display:inline-block; border-radius:999px; padding:4px 9px; font:700 .76rem/1 system-ui,sans-serif; }}
.tag {{ border:1px solid #426481; color:#b8dcf7; }} .pass {{ background:#123d2c; color:var(--green); }}
.limits {{ color:var(--muted); }}
@media (max-width:760px) {{ .grid {{ grid-template-columns:1fr; }} th:nth-child(2),td:nth-child(2) {{ display:none; }} }}
</style>
</head>
<body><main>
<div class="eyebrow">Your Cloud · v0.0.1 · projection P2</div>
<h1>Une restitution lisible, jamais une nouvelle autorité.</h1>
<p class="authority"><strong>Les assertions machine de result.json restent l’autorité.</strong><br>Cette page et sa capture prouvent uniquement que la projection a été générée et rendue.</p>
<div class="grid">
  <div class="card"><span>Révision source</span><strong>{esc(data['source_revision'])}</strong></div>
  <div class="card"><span>Artefact SHA-256</span><strong>{esc(data['artifact_sha256'])}</strong></div>
  <div class="card"><span>Lot source SHA-256</span><strong>{esc(data['source_lot_sha256'])}</strong></div>
  <div class="card"><span>Topologie</span><strong>{esc(data['topology'])}</strong></div>
  <div class="card"><span>Début Relay</span><strong>{esc(window['started_at'])}</strong></div>
  <div class="card"><span>Fin Relay · nettoyage</span><strong>{esc(window['finished_at'])}<br>{esc(data['cleanup']['status'])}</strong></div>
</div>
<section><h2>{len(data['steps'])} étapes assertées</h2>
<table><thead><tr><th>Étape</th><th>Catégorie</th><th>Statut</th></tr></thead><tbody>{rows}</tbody></table></section>
<section class="limits"><h2>Limites visibles</h2><p>La capture n’atteste ni les processus, ni les unités systemd, ni les refus HTTP. Elle archive le rendu des données déjà validées par P1.</p></section>
</main></body></html>
"""


def main() -> int:
    if socket.gethostname() != "lab-app" or os.geteuid() != 0:
        print("renderer must run as root in lab-app", file=sys.stderr)
        return 1
    if len(sys.argv) == 3 and sys.argv[1] == "--p1-fingerprints":
        source = Path(sys.argv[2])
        if not source.is_file() or source.is_symlink():
            print("P1 result must be a regular file", file=sys.stderr)
            return 1
        try:
            data = validate(load_exact_json(source))
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
            print(f"P1 result refused: {error}", file=sys.stderr)
            return 1
        print(data["source_lot_sha256"])
        print(data["artifact_sha256"])
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--p1-step-identifiers":
        source = Path(sys.argv[2])
        if not source.is_file() or source.is_symlink():
            print("P1 result must be a regular file", file=sys.stderr)
            return 1
        try:
            data = validate(load_exact_json(source))
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
            print(f"P1 result refused: {error}", file=sys.stderr)
            return 1
        for step in data["steps"]:
            print(step["id"])
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "--validate-p2-diagnostic":
        result = Path(sys.argv[2])
        expected_source_sha = sys.argv[3]
        if not result.is_file() or result.is_symlink():
            print("P2 diagnostic must be a regular file", file=sys.stderr)
            return 1
        if not HEX_64.fullmatch(expected_source_sha):
            print("expected P1 SHA-256 is invalid", file=sys.stderr)
            return 1
        try:
            validate_failure_diagnostic(load_exact_json(result), expected_source_sha)
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
            print(f"P2 diagnostic refused: {error}", file=sys.stderr)
            return 1
        print("PASS: bounded and redacted P2 failure diagnostic validated")
        return 0
    if len(sys.argv) == 6 and sys.argv[1] == "--validate-p2-result":
        result = Path(sys.argv[2])
        expected_outcome = sys.argv[3]
        expected_source_sha = sys.argv[4]
        capture = None if sys.argv[5] == "-" else Path(sys.argv[5])
        if not result.is_file() or result.is_symlink():
            print("P2 result must be a regular file", file=sys.stderr)
            return 1
        if not HEX_64.fullmatch(expected_source_sha):
            print("expected P1 SHA-256 is invalid", file=sys.stderr)
            return 1
        if capture is not None and (not capture.is_file() or capture.is_symlink()):
            print("P2 capture must be a regular file", file=sys.stderr)
            return 1
        try:
            validate_render_result(
                load_exact_json(result),
                expected_outcome,
                expected_source_sha,
                capture,
            )
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
            print(f"P2 result refused: {error}", file=sys.stderr)
            return 1
        print(f"PASS: exact P2 {expected_outcome} result validated")
        return 0
    if len(sys.argv) != 3:
        print(
            "usage: renderer.py <result.json> <output-dir>\n"
            "       renderer.py --p1-fingerprints <result.json>\n"
            "       renderer.py --p1-step-identifiers <result.json>\n"
            "       renderer.py --validate-p2-diagnostic "
            "<render-result.json> <result-sha256>\n"
            "       renderer.py --validate-p2-result "
            "<render-result.json> <passed|failed> <result-sha256> <capture.png|->",
            file=sys.stderr,
        )
        return 2
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    if not source.is_file() or source.is_symlink():
        print("structured result must be a regular file", file=sys.stderr)
        return 1
    try:
        data = validate(load_exact_json(source))
        output.mkdir(mode=0o755, parents=True, exist_ok=False)
        (output / "report.md").write_text(render_markdown(data), encoding="utf-8")
        (output / "report.html").write_text(render_html(data), encoding="utf-8")
        os.chmod(output / "report.md", 0o644)
        os.chmod(output / "report.html", 0o644)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"render refused: {error}", file=sys.stderr)
        return 1
    print(f"PASS: generated Markdown and HTML from {len(data['steps'])} machine-asserted steps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
