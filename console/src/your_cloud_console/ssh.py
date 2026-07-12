from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess

from .errors import AuditError, HostKeyError
from .model import Machine
from .storage import HostKeyStore, PinnedHostKey


@dataclass(frozen=True)
class ScannedHostKey:
    endpoint: str
    key_type: str
    key: str
    fingerprint: str


def known_hosts_endpoint(address: str, port: int) -> str:
    return address if port == 22 else f"[{address}]:{port}"


def fingerprint_public_key(key: str) -> str:
    try:
        decoded = base64.b64decode(key.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise HostKeyError("clé d'hôte SSH illisible") from error
    digest = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def scan_host_key(machine: Machine, timeout: int = 5) -> ScannedHostKey:
    command = [
        "ssh-keyscan",
        "-T",
        str(timeout),
        "-p",
        str(machine.port),
        "-t",
        "ed25519",
        machine.address,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 2, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise HostKeyError(f"clé d'hôte inaccessible pour {machine.endpoint}") from error
    lines = [line for line in completed.stdout.splitlines() if line and not line.startswith("#")]
    if completed.returncode != 0 or len(lines) != 1:
        raise HostKeyError(
            f"réponse SSH absente ou ambiguë pour {machine.endpoint} ; aucune clé n'est enregistrée"
        )
    fields = lines[0].split()
    if len(fields) != 3 or fields[1] != "ssh-ed25519":
        raise HostKeyError(f"clé d'hôte inattendue pour {machine.endpoint}")
    endpoint = known_hosts_endpoint(machine.address, machine.port)
    return ScannedHostKey(endpoint, fields[1], fields[2], fingerprint_public_key(fields[2]))


def verify_or_pin_host_key(
    machine: Machine,
    store: HostKeyStore,
    *,
    accept_tofu: bool = False,
    expected_fingerprint: str | None = None,
) -> PinnedHostKey:
    scanned = scan_host_key(machine)
    pinned = store.get(machine.id)
    if pinned is not None:
        if pinned.endpoint != scanned.endpoint:
            raise HostKeyError(
                f"la cible de {machine.id} a changé de {pinned.endpoint} vers {scanned.endpoint} ; "
                "une rotation explicite est requise"
            )
        if pinned.key_type != scanned.key_type or pinned.key != scanned.key:
            raise HostKeyError(
                f"clé d'hôte changée pour {machine.id} : attendue {pinned.fingerprint}, "
                f"présentée {scanned.fingerprint} ; connexion refusée"
            )
        return pinned

    if expected_fingerprint is not None:
        if expected_fingerprint != scanned.fingerprint:
            raise HostKeyError(
                f"empreinte fournisseur différente pour {machine.id} : attendue {expected_fingerprint}, "
                f"présentée {scanned.fingerprint} ; aucune clé n'est enregistrée"
            )
        source = "provider"
    elif accept_tofu:
        source = "tofu-visible"
    else:
        raise HostKeyError(
            f"premier contact avec {machine.id} : empreinte {scanned.fingerprint}. "
            "Relancer avec --accept-host-key pour un TOFU visible ou "
            "--host-fingerprint SHA256:... pour une preuve fournisseur."
        )
    pinned = PinnedHostKey.accepted(
        endpoint=scanned.endpoint,
        key_type=scanned.key_type,
        key=scanned.key,
        fingerprint=scanned.fingerprint,
        source=source,
    )
    store.pin(machine.id, pinned)
    return pinned


def ssh_command(machine: Machine, known_hosts: Path) -> list[str]:
    identity = Path(machine.identity_file)
    if not identity.is_file():
        raise AuditError(f"clé de bootstrap absente : {identity}")
    return [
        "ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "-i",
        str(identity),
        "-p",
        str(machine.port),
        f"{machine.user}@{machine.address}",
    ]
