"""Mises à jour progressives par artefact exact et rollback préparé."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from .errors import ConsoleError
from .model import Machine
from .storage import HostKeyStore


VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")


class UpdateStore:
    """Conserve les versions prouvées sans devenir une autorité distante."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.path = state_dir / "updates.json"

    def load(self) -> dict[str, Any]:
        """Charge le registre privé en refusant tout schéma ambigu."""

        if not self.path.exists():
            return {"schema_version": 1, "coordinators": {}, "observers": {}}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ConsoleError("registre de mises à jour invalide") from error
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version", "coordinators", "observers"
        }:
            raise ConsoleError("registre de mises à jour incomplet")
        if raw["schema_version"] != 1 or not all(
            isinstance(raw[field], dict) for field in ("coordinators", "observers")
        ):
            raise ConsoleError("registre de mises à jour invalide")
        return raw

    def require_coordinator_version(self, version: str) -> None:
        """Refuse un daemon avant la preuve d'un coordinateur compatible."""

        if version not in set(self.load()["coordinators"].values()):
            raise ConsoleError(
                f"mettre à jour et vérifier un coordinateur en {version} avant les daemons"
            )

    def record(self, component: str, machine_id: str, version: str) -> None:
        """Enregistre une version seulement après le succès distant."""

        raw = self.load()
        section = "coordinators" if component == "coordinator" else "observers"
        raw[section][machine_id] = version
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        temporary.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)


def update_plan(
    component: str, machine: Machine, binary: Path, version: str, sha256: str
) -> str:
    """Présente l'ordre, l'intégrité et le rollback avant toute mutation."""

    label = "coordinateur" if component == "coordinator" else "daemon d'observation"
    return "\n".join((
        f"Plan de mise à jour du {label} sur {machine.id} vers {version} :",
        f"  - vérifier SHA-256 {sha256} pour {binary}",
        "  - conserver le binaire installé sous .previous avant remplacement",
        "  - arrêter et redémarrer uniquement le composant ciblé",
        "  - vérifier la version active et restaurer .previous au premier échec",
        "  - arrêter la propagation ; aucune mise à jour automatique de flotte",
    ))


def apply_update(
    component: str,
    machine: Machine,
    host_store: HostKeyStore,
    store: UpdateStore,
    *,
    binary: Path,
    expected_sha256: str,
    version: str,
    engine_dir: Path,
) -> str:
    """Applique un artefact exact sur une seule machine et vérifie le résultat."""

    if component not in {"coordinator", "observer"}:
        raise ConsoleError(f"composant de mise à jour inconnu : {component}")
    if not VERSION_PATTERN.fullmatch(version):
        raise ConsoleError("version de composant invalide")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ConsoleError("somme SHA-256 attendue invalide")
    if not binary.is_file():
        raise ConsoleError(f"artefact absent : {binary}")
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise ConsoleError("somme SHA-256 de l'artefact différente de la valeur approuvée")
    if component == "observer":
        store.require_coordinator_version(version)
    known_hosts = host_store.render_known_hosts()
    playbook = engine_dir / "ansible" / "update-component.yml"
    unit_name = (
        "your-cloud-coordinator.service"
        if component == "coordinator"
        else "your-cloud-observer.service"
    )
    unit = engine_dir / "ansible" / "files" / unit_name
    if not playbook.is_file() or not unit.is_file():
        raise ConsoleError("playbook ou unité de mise à jour absent")
    command = [
        "ansible-playbook", "-i", f"{machine.address},", "--user", machine.user,
        "--private-key", machine.identity_file, "--extra-vars", f"ansible_port={machine.port}",
        "--extra-vars", f"component={component}",
        "--extra-vars", f"component_binary={binary}",
        "--extra-vars", f"component_unit={unit}",
        "--extra-vars", f"expected_sha256={expected_sha256}",
        "--extra-vars", f"expected_version={version}", str(playbook),
    ]
    env = dict(os.environ)
    env["ANSIBLE_CONFIG"] = str(engine_dir / "ansible" / "ansible.cfg")
    env["ANSIBLE_SSH_COMMON_ARGS"] = " ".join((
        "-F /dev/null", "-o IdentitiesOnly=yes", "-o StrictHostKeyChecking=yes",
        f"-o UserKnownHostsFile={known_hosts}", "-o GlobalKnownHostsFile=/dev/null",
    ))
    for candidate in ([*command[:-1], "--syntax-check", command[-1]], command):
        try:
            completed = subprocess.run(
                candidate, capture_output=True, text=True, check=False, timeout=180, env=env
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise ConsoleError("commande de mise à jour indisponible ou expirée") from error
        if completed.returncode != 0:
            raise ConsoleError(
                f"mise à jour refusée : {completed.stderr.strip() or completed.stdout.strip()}"
            )
    store.record(component, machine.id, version)
    summary = next(
        (line.strip() for line in reversed(completed.stdout.splitlines()) if "changed=" in line),
        "résumé Ansible indisponible",
    )
    return f"{component} {version} vérifié sur {machine.id}. Ansible : {summary}"
