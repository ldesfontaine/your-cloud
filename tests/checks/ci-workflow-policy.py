#!/usr/bin/env python3
"""Fail closed when the repository CI trigger policy drifts."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
NATIVE_MANIFEST = (
    ROOT
    / "console"
    / "src-tauri"
    / "crates"
    / "native-bootstrap-assistant"
    / "Cargo.toml"
)


class PolicyError(RuntimeError):
    """The workflow no longer matches the repository CI contract."""


def mapping_block(lines: list[str], key: str, indent: int) -> list[str]:
    prefix = " " * indent
    header = f"{prefix}{key}:"
    try:
        start = lines.index(header)
    except ValueError as error:
        raise PolicyError(f"missing {key!r} mapping") from error

    block: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.isspace() and not line.lstrip().startswith("#"):
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent <= indent:
                break
        block.append(line)
    return block


def direct_keys(block: list[str], indent: int) -> list[str]:
    pattern = re.compile(
        rf"^{re.escape(' ' * indent)}([A-Za-z_][A-Za-z0-9_-]*):(?:\s.*)?$"
    )
    return [match.group(1) for line in block if (match := pattern.match(line))]


def direct_values(block: list[str], indent: int) -> dict[str, str]:
    pattern = re.compile(
        rf"^{re.escape(' ' * indent)}([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*$"
    )
    values: dict[str, str] = {}
    for line in block:
        match = pattern.match(line)
        if match:
            if match.group(1) in values:
                raise PolicyError(f"duplicate {match.group(1)!r} mapping key")
            values[match.group(1)] = match.group(2)
    return values


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def declared_native_test_targets() -> list[str]:
    if not NATIVE_MANIFEST.is_file():
        raise PolicyError("missing native assistant manifest")
    section = None
    targets: list[str] = []
    for line in NATIVE_MANIFEST.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[["):
            section = stripped
            continue
        if section == "[[test]]":
            match = re.match(r'name\s*=\s*"([^"]+)"', stripped)
            if match:
                targets.append(match.group(1))
    if not targets:
        raise PolicyError("no [[test]] target found in the native manifest")
    return targets


def validate_native_test_targets(lines: list[str]) -> None:
    """A target no gate builds rots without anyone knowing."""

    workflow_text = "\n".join(lines)
    for target in declared_native_test_targets():
        require(
            f"--test {target}" in workflow_text,
            f"native test target {target!r} must be built or run by the gate",
        )


def validate() -> None:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()

    triggers = direct_keys(mapping_block(lines, "on", 0), 2)
    require(
        triggers == ["pull_request", "workflow_dispatch"],
        "CI triggers must be exactly pull_request then workflow_dispatch",
    )

    permissions = direct_values(mapping_block(lines, "permissions", 0), 2)
    require(
        permissions == {"contents": "read"},
        "top-level permissions must be exactly contents: read",
    )

    concurrency = direct_values(mapping_block(lines, "concurrency", 0), 2)
    require(
        concurrency
        == {
            "group": "${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}",
            "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
        },
        "concurrency must cancel obsolete PR runs without replacing manual native runs",
    )

    jobs = mapping_block(lines, "jobs", 0)
    require(
        direct_keys(jobs, 2)
        == ["source", "server_bundle", "console_platforms", "plumber_policy"],
        "CI must retain the four independently diagnosable job families",
    )

    source_lines = mapping_block(jobs, "source", 2)
    source = direct_values(source_lines, 4)
    bundle_lines = mapping_block(jobs, "server_bundle", 2)
    bundle = direct_values(bundle_lines, 4)
    plumber = direct_values(mapping_block(jobs, "plumber_policy", 2), 4)
    console = direct_values(mapping_block(jobs, "console_platforms", 2), 4)
    require("if" not in source, "source checks must remain automatic")
    require("if" not in plumber, "Plumber policy must remain automatic")
    # Le lot est une porte de reproductibilité : automatique comme les deux
    # autres gates rapides, et construit uniquement dans le conteneur épinglé
    # par digest — l'épinglage lui-même est arbitré par la politique Plumber.
    require("if" not in bundle, "the server bundle gate must remain automatic")
    require(
        any(
            line.strip().startswith("image: debian:13@sha256:")
            for line in bundle_lines
        ),
        "the server bundle must build inside the digest-pinned debian:13 container",
    )
    require(
        "      - name: Vérifier le contrat PowerShell Windows" in source_lines
        and "        shell: pwsh" in source_lines
        and "        run: ./tests/checks/console-windows-ci-contract.ps1"
        in source_lines,
        "the fast gate must parse the Windows proof and exercise its cleanup contract",
    )
    require(
        console.get("needs") == "[source, plumber_policy, server_bundle]",
        "native Console jobs must wait for the three fast gates",
    )
    require(
        console.get("if") == "github.event_name == 'workflow_dispatch'",
        "native Console jobs must require an explicit workflow_dispatch",
    )

    console_lines = mapping_block(jobs, "console_platforms", 2)
    strategy_lines = mapping_block(console_lines, "strategy", 4)
    require(
        direct_values(strategy_lines, 6)
        == {"fail-fast": "false", "max-parallel": "2", "matrix": ""},
        "native matrix strategy must preserve both platform results",
    )
    include_lines = mapping_block(strategy_lines, "include", 8)
    require(
        [line for line in include_lines if line.strip()]
        == [
            "          - label: Linux .deb",
            "            runner: ubuntu-24.04",
            "          - label: Windows .msi",
            "            runner: windows-2025",
        ],
        "native matrix must contain exactly the declared Linux and Windows variants",
    )

    validate_native_test_targets(lines)


def main() -> int:
    validate()
    print("PASS: CI policy keeps PR checks fast and native builds explicitly manual")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
