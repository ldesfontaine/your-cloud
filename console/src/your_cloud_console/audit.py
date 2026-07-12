from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
import time
from typing import Any

from .errors import AuditError
from .model import Machine
from .ssh import ssh_command
from .storage import HostKeyStore, PinnedHostKey


REMOTE_AUDIT_SCRIPT = r"""
set -eu
field() { printf '%s\000%s\000' "$1" "$2"; }

os_id=unknown
os_version_id=unknown
os_codename=unknown
if [ -r /etc/os-release ]; then
  . /etc/os-release
  os_id=${ID:-unknown}
  os_version_id=${VERSION_ID:-unknown}
  os_codename=${VERSION_CODENAME:-unknown}
fi

architecture=$(dpkg --print-architecture 2>/dev/null || uname -m)
kernel_machine=$(uname -m)
hostname_value=$(hostname 2>/dev/null || printf unknown)
free_kib=$(df -Pk / | awk 'NR == 2 { print $4 }')
epoch=$(date +%s)

if command -v sudo >/dev/null 2>&1; then sudo_present=yes; else sudo_present=no; fi
if [ "$(id -u)" -eq 0 ]; then
  privilege_non_interactive=yes
elif [ "$sudo_present" = yes ] && sudo -n true >/dev/null 2>&1; then
  privilege_non_interactive=yes
else
  privilege_non_interactive=no
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemd_present=yes
else
  systemd_present=no
fi

ssh_sources=$(find /etc/ssh -maxdepth 2 -type f \
  \( -name 'sshd_config' -o -path '/etc/ssh/sshd_config.d/*.conf' \) \
  -print 2>/dev/null | sort || true)
nft_sources=$(find /etc/nftables.conf /etc/nftables.d -maxdepth 2 -type f \
  -print 2>/dev/null | sort || true)
sysctl_sources=$(find /etc/sysctl.conf /etc/sysctl.d -maxdepth 2 -type f \
  -name '*.conf' -print 2>/dev/null | sort || true)

config_managers=''
for manager in puppet salt-call chef-client cf-agent; do
  if command -v "$manager" >/dev/null 2>&1; then
    if [ -n "$config_managers" ]; then
      config_managers="$config_managers
$manager"
    else
      config_managers=$manager
    fi
  fi
done

if command -v ss >/dev/null 2>&1; then
  listening_sockets=$(ss -H -lntu 2>/dev/null | awk '{ print $1 " " $5 }' | sort -u || true)
else
  listening_sockets='outil ss absent'
fi

nft_rule_lines=0
if command -v nft >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    nft_rule_lines=$(nft list ruleset 2>/dev/null | awk 'NF && $1 !~ /^#/ { count++ } END { print count + 0 }')
  elif [ "$privilege_non_interactive" = yes ]; then
    nft_rule_lines=$(sudo -n nft list ruleset 2>/dev/null | awk 'NF && $1 !~ /^#/ { count++ } END { print count + 0 }')
  fi
fi

field os_id "$os_id"
field os_version_id "$os_version_id"
field os_codename "$os_codename"
field architecture "$architecture"
field kernel_machine "$kernel_machine"
field hostname "$hostname_value"
field free_kib "$free_kib"
field epoch "$epoch"
field sudo_present "$sudo_present"
field privilege_non_interactive "$privilege_non_interactive"
field systemd_present "$systemd_present"
field ssh_config_sources "$ssh_sources"
field nft_config_sources "$nft_sources"
field sysctl_config_sources "$sysctl_sources"
field config_managers "$config_managers"
field listening_sockets "$listening_sockets"
field nft_rule_lines "$nft_rule_lines"
"""


@dataclass(frozen=True)
class AuditResult:
    schema_version: int
    machine_id: str
    target: str
    host_key_fingerprint: str
    host_key_source: str
    observed: dict[str, Any]
    compatible: bool
    decision: str
    conflicts: tuple[str, ...]
    limits: tuple[str, ...]
    refusals: tuple[str, ...]
    potential_plan: tuple[dict[str, str], ...]
    mutation_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_remote_fields(output: bytes) -> dict[str, str]:
    parts = output.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) % 2:
        raise AuditError("réponse d'audit tronquée ou ambiguë")
    fields: dict[str, str] = {}
    for index in range(0, len(parts), 2):
        try:
            key = parts[index].decode("ascii")
            value = parts[index + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuditError("réponse d'audit illisible") from error
        if key in fields:
            raise AuditError(f"champ d'audit dupliqué : {key}")
        fields[key] = value
    required = {
        "os_id",
        "os_version_id",
        "os_codename",
        "architecture",
        "kernel_machine",
        "hostname",
        "free_kib",
        "epoch",
        "sudo_present",
        "privilege_non_interactive",
        "systemd_present",
        "ssh_config_sources",
        "nft_config_sources",
        "sysctl_config_sources",
        "config_managers",
        "listening_sockets",
        "nft_rule_lines",
    }
    missing = required - set(fields)
    if missing:
        raise AuditError(f"réponse d'audit incomplète : {', '.join(sorted(missing))}")
    return fields


def _lines(value: str) -> list[str]:
    return [line for line in value.splitlines() if line]


def run_audit(machine: Machine, store: HostKeyStore, host_key: PinnedHostKey) -> AuditResult:
    known_hosts = store.render_known_hosts()
    command = [*ssh_command(machine, known_hosts), "sh", "-s"]
    try:
        completed = subprocess.run(
            command,
            input=REMOTE_AUDIT_SCRIPT.encode("utf-8"),
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise AuditError(f"audit SSH impossible pour {machine.id}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        detail = stderr.splitlines()[-1] if stderr else f"code {completed.returncode}"
        raise AuditError(f"audit SSH refusé pour {machine.id} : {detail}")
    fields = _parse_remote_fields(completed.stdout)

    try:
        free_kib = int(fields["free_kib"])
        remote_epoch = int(fields["epoch"])
        nft_rule_lines = int(fields["nft_rule_lines"])
    except ValueError as error:
        raise AuditError("valeur numérique invalide dans l'audit") from error

    clock_skew_seconds = abs(int(time.time()) - remote_epoch)
    observed: dict[str, Any] = {
        "os": {
            "id": fields["os_id"],
            "version_id": fields["os_version_id"],
            "codename": fields["os_codename"],
        },
        "architecture": fields["architecture"],
        "kernel_machine": fields["kernel_machine"],
        "hostname": fields["hostname"],
        "root_free_kib": free_kib,
        "clock_skew_seconds": clock_skew_seconds,
        "sudo_present": fields["sudo_present"] == "yes",
        "privilege_non_interactive": fields["privilege_non_interactive"] == "yes",
        "systemd_present": fields["systemd_present"] == "yes",
        "configuration_sources": {
            "ssh": _lines(fields["ssh_config_sources"]),
            "nftables": _lines(fields["nft_config_sources"]),
            "sysctl": _lines(fields["sysctl_config_sources"]),
        },
        "configuration_managers": _lines(fields["config_managers"]),
        "listening_sockets": _lines(fields["listening_sockets"]),
        "nft_rule_lines": nft_rule_lines,
    }

    refusals: list[str] = []
    limits: list[str] = []
    conflicts: list[str] = []
    if fields["os_id"] != "debian" or fields["os_version_id"] != "13":
        refusals.append(
            f"système incompatible : {fields['os_id']} {fields['os_version_id']} ; attendu : Debian 13"
        )
    if fields["architecture"] != "amd64" or fields["kernel_machine"] != "x86_64":
        refusals.append(
            f"architecture incompatible : {fields['architecture']}/{fields['kernel_machine']} ; attendu : amd64/x86_64"
        )
    if not observed["systemd_present"]:
        refusals.append("systemd n'est pas le gestionnaire de services actif")
    if observed["configuration_managers"]:
        conflicts.append(
            "autorité de configuration persistante détectée : "
            + ", ".join(observed["configuration_managers"])
        )
    if nft_rule_lines:
        conflicts.append(
            f"ruleset nftables existant ({nft_rule_lines} lignes) : son autorité doit être clarifiée avant P3"
        )
    if not observed["sudo_present"]:
        limits.append("sudo absent : le futur compte d'administration P3 ne pourra pas être prouvé")
    if not observed["privilege_non_interactive"]:
        limits.append("élévation non interactive indisponible pour le chemin de bootstrap")
    if free_kib < 2 * 1024 * 1024:
        limits.append(f"espace libre faible sur / : {free_kib} Kio")
    if clock_skew_seconds > 300:
        limits.append(f"écart d'horloge supérieur à 300 s : {clock_skew_seconds} s")

    compatible = not refusals
    decision = "refused" if refusals or conflicts else "eligible"
    blocker = "none" if decision == "eligible" else "compatibility-or-authority"
    potential_plan = (
        {
            "phase": "P2",
            "action": "enroll-observation-daemon",
            "status": "possible" if decision == "eligible" else "blocked",
            "blocker": blocker,
        },
        {
            "phase": "P3",
            "action": "prepare-dedicated-administration-path",
            "status": "requires-separate-plan",
            "blocker": "limits-and-authorities-must-be-approved",
        },
    )
    return AuditResult(
        schema_version=1,
        machine_id=machine.id,
        target=machine.endpoint,
        host_key_fingerprint=host_key.fingerprint,
        host_key_source=host_key.source,
        observed=observed,
        compatible=compatible,
        decision=decision,
        conflicts=tuple(conflicts),
        limits=tuple(limits),
        refusals=tuple(refusals),
        potential_plan=potential_plan,
    )


def render_human(result: AuditResult) -> str:
    observed = result.observed
    os_data = observed["os"]
    sources = observed["configuration_sources"]
    clock_status = "acceptable" if observed["clock_skew_seconds"] <= 300 else "hors limite"
    lines = [
        f"Machine : {result.machine_id} ({result.target})",
        f"Clé d'hôte : {result.host_key_fingerprint} ({result.host_key_source})",
        f"Système : {os_data['id']} {os_data['version_id']} {os_data['codename']}",
        f"Architecture : {observed['architecture']} / {observed['kernel_machine']}",
        f"Espace libre / : {observed['root_free_kib'] // 1024} Mio",
        f"Horloge : {clock_status}",
        f"Privilèges : sudo={'présent' if observed['sudo_present'] else 'absent'}, "
        f"élévation={'oui' if observed['privilege_non_interactive'] else 'non'}",
        f"Systemd actif : {'oui' if observed['systemd_present'] else 'non'}",
        "Sources de configuration : "
        f"SSH={len(sources['ssh'])}, nftables={len(sources['nftables'])}, "
        f"sysctl={len(sources['sysctl'])}",
        "Sockets écoutés : " + (", ".join(observed["listening_sockets"]) or "aucun"),
        f"Décision : {result.decision}",
        "Mutation distante : 0",
    ]
    for title, values in (
        ("Refus", result.refusals),
        ("Conflits", result.conflicts),
        ("Limites", result.limits),
    ):
        lines.append(f"{title} :")
        lines.extend(f"  - {value}" for value in values) if values else lines.append("  - aucun")
    lines.append("Plan potentiel :")
    for step in result.potential_plan:
        lines.append(f"  - {step['phase']} {step['action']} : {step['status']}")
    return "\n".join(lines)


def render_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
