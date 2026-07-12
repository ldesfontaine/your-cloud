"""Enrôlement vérifié du daemon d'observation par le chemin d'administration."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time

from .audit import run_audit
from .errors import EnrollmentError
from .model import Machine
from .ssh import ssh_command
from .storage import HostKeyStore, PinnedHostKey
from .telemetry import IdentityStore, decode_envelope, verify_state


OBSERVER_BINARY = "/usr/libexec/your-cloud-observer"
OBSERVER_USER = "your-cloud-observer"


def enrollment_plan(machine: Machine, daemon_binary: Path, units: tuple[str, ...]) -> str:
    """Décrit les effets attendus avant toute installation du daemon."""

    return "\n".join(
        (
            f"Plan pour rendre {machine.id} observable ({machine.endpoint}) :",
            f"  - installer le binaire natif vérifié depuis {daemon_binary}",
            "  - créer le compte non interactif your-cloud-observer sans sudo",
            "  - créer une identité Ed25519 locale dont la clé privée reste sur la machine",
            "  - activer une file SQLite bornée à 10 Mio et une collecte toutes les 60 s",
            f"  - observer {len(units)} unité(s) systemd explicitement choisie(s)",
            "  - ouvrir 0 port entrant et n'affecter aucun rôle d'infrastructure",
        )
    )


def identity_renewal_plan(machine: Machine) -> str:
    """Décrit le remplacement borné de l'identité d'une machine logique."""

    return "\n".join((
        f"Plan de renouvellement d'identité pour {machine.id} :",
        "  - générer une candidate privée sur la machine sans l'activer",
        "  - conserver l'identité active et son historique dans la console",
        "  - préparer le rollback local avant activation",
        "  - redémarrer uniquement le daemon d'observation",
        "  - vérifier un état signé par la candidate avant de remplacer l'ancienne",
        "  - conserver la même machine logique, adresse, affectation et séquences",
    ))


def observer_uninstall_plan(machine: Machine) -> str:
    """Décrit le retrait du seul daemon sans toucher aux services hébergés."""

    return "\n".join((
        f"Plan de désinstallation du daemon pour {machine.id} :",
        "  - arrêter et désactiver uniquement your-cloud-observer.service",
        "  - retirer son binaire, sa configuration, son compte et son état privé",
        "  - révoquer son identité publique dans la console",
        "  - conserver la machine logique, SSH, les services et leurs données",
    ))


def _run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout, env=env)
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise EnrollmentError(f"commande d'enrôlement indisponible ou expirée : {command[0]}") from error


def _ansible_command(
    machine: Machine,
    host_store: HostKeyStore,
    engine_dir: Path,
    daemon_binary: Path,
    units: tuple[str, ...],
) -> tuple[list[str], dict[str, str]]:
    """Construit une invocation Ansible isolée des fichiers SSH personnels."""

    known_hosts = host_store.render_known_hosts()
    playbook = engine_dir / "ansible" / "enroll-observer.yml"
    if not playbook.is_file() or not daemon_binary.is_file():
        raise EnrollmentError("playbook ou binaire du daemon absent")
    command = [
        "ansible-playbook",
        "-i", f"{machine.address},",
        "--user", machine.user,
        "--private-key", machine.identity_file,
        "--extra-vars", f"ansible_port={machine.port}",
        "--extra-vars", f"machine_id={machine.id}",
        "--extra-vars", f"observer_binary={daemon_binary}",
        "--extra-vars", json.dumps({"observer_units": list(units)}),
        str(playbook),
    ]
    env = dict(os.environ)
    env["ANSIBLE_CONFIG"] = str(engine_dir / "ansible" / "ansible.cfg")
    env["ANSIBLE_SSH_COMMON_ARGS"] = " ".join(
        (
            "-F /dev/null", "-o IdentitiesOnly=yes", "-o StrictHostKeyChecking=yes",
            f"-o UserKnownHostsFile={known_hosts}", "-o GlobalKnownHostsFile=/dev/null",
        )
    )
    return command, env


def enroll(
    machine: Machine,
    host_store: HostKeyStore,
    pinned_host_key: PinnedHostKey,
    identity_store: IdentityStore,
    *,
    engine_dir: Path,
    daemon_binary: Path,
    units: tuple[str, ...],
) -> str:
    """Installe le daemon puis approuve son identité et son premier état signé."""

    audit = run_audit(machine, host_store, pinned_host_key)
    if audit.decision != "eligible":
        raise EnrollmentError("l'audit préalable n'autorise pas l'enrôlement")
    command, env = _ansible_command(machine, host_store, engine_dir, daemon_binary, units)
    syntax = _run([*command[:-1], "--syntax-check", command[-1]], env=env)
    if syntax.returncode != 0:
        raise EnrollmentError(f"syntax-check Ansible refusé : {syntax.stderr.strip() or syntax.stdout.strip()}")
    applied = _run(command, env=env, timeout=180)
    if applied.returncode != 0:
        raise EnrollmentError(f"enrôlement Ansible refusé : {applied.stderr.strip() or applied.stdout.strip()}")
    identity_raw = remote_observer(machine, host_store, "public-identity")
    try:
        public = json.loads(identity_raw)
    except json.JSONDecodeError as error:
        raise EnrollmentError("identité publique distante invalide") from error
    if not isinstance(public, dict) or set(public) != {"algorithm", "key_id", "public_key"}:
        raise EnrollmentError("identité publique distante incomplète")
    identity_store.approve(machine.id, **public)
    last_error: Exception | None = None
    for _ in range(10):
        try:
            encoded = remote_observer(machine, host_store, "export-current")
            state = verify_state(machine.id, decode_envelope(encoded), identity_store, record_sequence=False)
            return f"Enrôlement vérifié : identité {public['key_id']}, état signé séquence {state.sequence}"
        except Exception as error:  # l'unité peut être en cours de premier démarrage
            last_error = error
            time.sleep(1)
    raise EnrollmentError(f"daemon installé mais premier état non vérifié : {last_error}")


def remote_observer(machine: Machine, host_store: HostKeyStore, command: str) -> str:
    """Exécute une commande locale bornée du daemon via le chemin SSH vérifié."""

    if command not in {
        "public-identity", "export-current", "db-usage",
        "prepare-identity-renewal", "finalize-identity-renewal",
    }:
        raise EnrollmentError("commande d'observation distante refusée")
    ssh = ssh_command(machine, host_store.render_known_hosts())
    completed = _run(
        [*ssh, f"sudo -n -u {OBSERVER_USER} {OBSERVER_BINARY} --config /etc/your-cloud/observer.json {command}"],
        timeout=20,
    )
    if completed.returncode != 0:
        raise EnrollmentError(f"inspection distante refusée : {completed.stderr.strip()}")
    output = completed.stdout.strip()
    if not output or len(output) > 512 * 1024:
        raise EnrollmentError("sortie d'observation absente ou trop grande")
    return output


def _lifecycle_command(
    machine: Machine, host_store: HostKeyStore, engine_dir: Path, playbook_name: str
) -> tuple[list[str], dict[str, str]]:
    known_hosts = host_store.render_known_hosts()
    playbook = engine_dir / "ansible" / playbook_name
    if not playbook.is_file():
        raise EnrollmentError(f"playbook de cycle de vie absent : {playbook}")
    command = [
        "ansible-playbook", "-i", f"{machine.address},", "--user", machine.user,
        "--private-key", machine.identity_file, "--extra-vars", f"ansible_port={machine.port}",
        str(playbook),
    ]
    env = dict(os.environ)
    env["ANSIBLE_CONFIG"] = str(engine_dir / "ansible" / "ansible.cfg")
    env["ANSIBLE_SSH_COMMON_ARGS"] = " ".join((
        "-F /dev/null", "-o IdentitiesOnly=yes", "-o StrictHostKeyChecking=yes",
        f"-o UserKnownHostsFile={known_hosts}", "-o GlobalKnownHostsFile=/dev/null",
    ))
    return command, env


def renew_identity(
    machine: Machine,
    host_store: HostKeyStore,
    identity_store: IdentityStore,
    *,
    engine_dir: Path,
) -> str:
    """Renouvelle en deux phases puis vérifie la nouvelle provenance signée."""

    authorization, env = _lifecycle_command(
        machine, host_store, engine_dir, "authorize-observer-lifecycle.yml"
    )
    syntax = _run([*authorization[:-1], "--syntax-check", authorization[-1]], env=env)
    if syntax.returncode != 0:
        raise EnrollmentError(
            f"syntax-check des délégations refusé : {syntax.stderr.strip() or syntax.stdout.strip()}"
        )
    authorized = _run(authorization, env=env, timeout=180)
    if authorized.returncode != 0:
        raise EnrollmentError(
            f"délégations de renouvellement refusées : {authorized.stderr.strip() or authorized.stdout.strip()}"
        )
    candidate_raw = remote_observer(machine, host_store, "prepare-identity-renewal")
    try:
        candidate = json.loads(candidate_raw)
    except json.JSONDecodeError as error:
        raise EnrollmentError("identité candidate distante invalide") from error
    if not isinstance(candidate, dict) or set(candidate) != {
        "algorithm", "key_id", "public_key"
    }:
        raise EnrollmentError("identité candidate distante incomplète")
    identity_store.prepare_renewal(machine.id, **candidate)
    command, env = _lifecycle_command(
        machine, host_store, engine_dir, "renew-observer-identity.yml"
    )
    syntax = _run([*command[:-1], "--syntax-check", command[-1]], env=env)
    if syntax.returncode != 0:
        identity_store.cancel_renewal(machine.id, candidate["key_id"])
        raise EnrollmentError(
            f"syntax-check du renouvellement refusé : {syntax.stderr.strip() or syntax.stdout.strip()}"
        )
    applied = _run(command, env=env, timeout=180)
    if applied.returncode != 0:
        identity_store.cancel_renewal(machine.id, candidate["key_id"])
        raise EnrollmentError(
            f"renouvellement distant refusé : {applied.stderr.strip() or applied.stdout.strip()}"
        )
    public = json.loads(remote_observer(machine, host_store, "public-identity"))
    if public != candidate:
        raise EnrollmentError("l'identité active ne correspond pas à la candidate approuvée")
    last_error: Exception | None = None
    for _ in range(10):
        try:
            encoded = remote_observer(machine, host_store, "export-current")
            state = verify_state(
                machine.id, decode_envelope(encoded), identity_store,
                record_sequence=False,
            )
            remote_observer(machine, host_store, "finalize-identity-renewal")
            active = identity_store.finalize_renewal(machine.id, candidate["key_id"])
            return (
                f"Identité renouvelée : {active.key_id}, machine logique {machine.id}, "
                f"état signé séquence {state.sequence}"
            )
        except Exception as error:
            last_error = error
            time.sleep(1)
    raise EnrollmentError(
        f"candidate activée mais état signé non vérifié ; rollback préparé : {last_error}"
    )


def uninstall_observer(
    machine: Machine, host_store: HostKeyStore, *, engine_dir: Path
) -> str:
    """Retire le daemon et son état privé sans toucher aux services applicatifs."""

    command, env = _lifecycle_command(
        machine, host_store, engine_dir, "uninstall-observer.yml"
    )
    syntax = _run([*command[:-1], "--syntax-check", command[-1]], env=env)
    if syntax.returncode != 0:
        raise EnrollmentError(
            f"syntax-check de désinstallation refusé : {syntax.stderr.strip() or syntax.stdout.strip()}"
        )
    applied = _run(command, env=env, timeout=180)
    if applied.returncode != 0:
        raise EnrollmentError(
            f"désinstallation distante refusée : {applied.stderr.strip() or applied.stdout.strip()}"
        )
    summary = next(
        (line.strip() for line in reversed(applied.stdout.splitlines()) if "changed=" in line),
        "résumé Ansible indisponible",
    )
    return f"Daemon désinstallé de {machine.id}; services hébergés inchangés. Ansible : {summary}"
