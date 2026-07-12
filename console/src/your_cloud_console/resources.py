"""Mesure bornée des budgets systemd et SQLite des composants natifs."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any

from .errors import ConsoleError
from .model import Machine
from .ssh import ssh_command
from .storage import HostKeyStore


BUDGETS = {
    "observer": {"memory_max": 64 * 1024 * 1024, "tasks_max": 64, "database_max": 10 * 1024 * 1024},
    "coordinator": {"memory_max": 128 * 1024 * 1024, "tasks_max": 64, "database_max": 64 * 1024 * 1024},
}


def measure_resources(
    component: str, machine: Machine, host_store: HostKeyStore
) -> dict[str, Any]:
    """Lit uniquement les compteurs cgroup et l'occupation SQLite annoncée."""

    if component not in BUDGETS:
        raise ConsoleError(f"composant de ressources inconnu : {component}")
    service = (
        "your-cloud-observer.service"
        if component == "observer"
        else "your-cloud-coordinator.service"
    )
    binary = (
        "/usr/libexec/your-cloud-observer --config /etc/your-cloud/observer.json"
        if component == "observer"
        else "/usr/libexec/your-cloud-coordinator --config /etc/your-cloud/coordinator.json"
    )
    command = (
        f"sudo -n systemctl show {service} "
        "-p MemoryCurrent -p MemoryPeak -p MemoryMax -p TasksCurrent -p TasksMax -p CPUQuotaPerSecUSec; "
        f"sudo -n {binary} db-usage"
    )
    try:
        completed = subprocess.run(
            [*ssh_command(machine, host_store.render_known_hosts()), command],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise ConsoleError("mesure de ressources indisponible ou expirée") from error
    if completed.returncode != 0:
        raise ConsoleError(f"mesure de ressources refusée : {completed.stderr.strip()}")
    lines = [line for line in completed.stdout.splitlines() if line]
    if len(lines) < 7:
        raise ConsoleError("mesure de ressources incomplète")
    values: dict[str, int] = {}
    cpu_quota = ""
    for line in lines[:-1]:
        key, separator, value = line.partition("=")
        if key == "CPUQuotaPerSecUSec" and separator:
            cpu_quota = value
            continue
        if not separator or not value.isdigit():
            raise ConsoleError(f"compteur systemd invalide : {line}")
        values[key] = int(value)
    try:
        database = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise ConsoleError("occupation SQLite invalide") from error
    expected = {"page_count", "page_size", "bytes", "limit_bytes"}
    if not isinstance(database, dict) or set(database) != expected:
        raise ConsoleError("occupation SQLite incomplète")
    budget = BUDGETS[component]
    return {
        "component": component,
        "machine_id": machine.id,
        "memory_current_bytes": values["MemoryCurrent"],
        "memory_peak_bytes": values["MemoryPeak"],
        "memory_max_bytes": values["MemoryMax"],
        "tasks_current": values["TasksCurrent"],
        "tasks_max": values["TasksMax"],
        "cpu_quota_per_second": cpu_quota,
        "database": database,
        "within_budget": (
            values["MemoryPeak"] <= budget["memory_max"]
            and values["TasksCurrent"] <= budget["tasks_max"]
            and database["bytes"] <= budget["database_max"]
            and database["limit_bytes"] == budget["database_max"]
        ),
    }
