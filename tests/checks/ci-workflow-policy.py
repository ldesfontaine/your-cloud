#!/usr/bin/env python3
"""Fail closed when the repository CI trigger policy drifts."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


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
        direct_keys(jobs, 2) == ["source", "console_platforms", "plumber_policy"],
        "CI must retain the three independently diagnosable job families",
    )

    source_lines = mapping_block(jobs, "source", 2)
    source = direct_values(source_lines, 4)
    plumber = direct_values(mapping_block(jobs, "plumber_policy", 2), 4)
    console = direct_values(mapping_block(jobs, "console_platforms", 2), 4)
    require("if" not in source, "source checks must remain automatic")
    require("if" not in plumber, "Plumber policy must remain automatic")
    require(
        "      - name: Vérifier le contrat PowerShell Windows" in source_lines
        and "        shell: pwsh" in source_lines
        and "        run: ./tests/checks/console-windows-ci-contract.ps1"
        in source_lines,
        "the fast gate must parse the Windows proof and exercise its cleanup contract",
    )
    require(
        console.get("needs") == "[source, plumber_policy]",
        "native Console jobs must wait for both fast gates",
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


def main() -> int:
    validate()
    print("PASS: CI policy keeps PR checks fast and native builds explicitly manual")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
