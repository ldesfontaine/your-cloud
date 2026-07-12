from __future__ import annotations

from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from google.protobuf.message import DecodeError

from .errors import CoordinationError
from .model import Machine
from .secrets import AdminKeyStore
from .storage import HostKeyStore
from .transport import TransportStore
from .protocol import telemetrie_pb2


def coordination_plan(machine: Machine, address: str, port: int) -> str:
    return "\n".join((
        f"Plan pour conserver l'observation via {machine.id} :",
        "  - installer le coordinateur sous un compte distinct sans sudo",
        "  - créer des identités mTLS distinctes pour le daemon, le coordinateur et la console",
        "  - joindre l'autorité privée chiffrée au kit de récupération vérifié",
        "  - copier uniquement le registre public des machines actives",
        f"  - écouter explicitement sur {address}:{port}, jamais sur toutes les interfaces",
        "  - conserver l'état courant et 30 jours d'événements dans une SQLite bornée à 64 Mio",
        "  - republier l'état courant avant le journal après une coupure",
        "  - ne fournir aucune commande ni secret d'administration au coordinateur",
    ))


def _run(command: list[str], env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise CoordinationError(f"commande de coordination indisponible ou expirée : {command[0]}") from error


def install_local_coordinator(
    machine: Machine,
    host_store: HostKeyStore,
    transport_store: TransportStore,
    passphrase: bytes,
    *,
    state_dir: Path,
    engine_dir: Path,
    coordinator_binary: Path,
    observer_binary: Path,
    recovery_kit: Path,
    address: str,
    port: int,
) -> str:
    if address != machine.address:
        raise CoordinationError("le coordinateur local doit écouter sur l'adresse déclarée de sa machine")
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as error:
        raise CoordinationError("le mode local exige une adresse IP explicite") from error
    if parsed_address.is_unspecified:
        raise CoordinationError("le coordinateur refuse une écoute sur toutes les interfaces")
    if not 1024 <= port <= 65535:
        raise CoordinationError("le port du coordinateur doit être non privilégié")
    for path, label in (
        (coordinator_binary, "binaire du coordinateur"),
        (observer_binary, "binaire du daemon"),
        (engine_dir / "ansible" / "install-local-coordinator.yml", "playbook"),
        (state_dir / "machine_identities.json", "registre public"),
    ):
        if not path.is_file():
            raise CoordinationError(f"{label} absent : {path}")
    transport_store.ensure(passphrase, machine.id, address, (machine.id,))
    AdminKeyStore(state_dir).attach_transport_authority(
        recovery_kit,
        passphrase,
        transport_store.ca_key,
        transport_store.ca_certificate,
    )
    with ExitStack() as stack:
        coordinator_key = stack.enter_context(
            transport_store.materialize_private("coordinator", machine.id, passphrase)
        )
        daemon_key = stack.enter_context(
            transport_store.materialize_private("daemon", machine.id, passphrase)
        )
        command = [
            "ansible-playbook", "-i", f"{machine.address},", "--user", machine.user,
            "--private-key", machine.identity_file, "--extra-vars", f"ansible_port={machine.port}",
            "--extra-vars", json.dumps({
                "machine_id": machine.id,
                "coordinator_address": address,
                "coordinator_port": port,
                "coordinator_binary": str(coordinator_binary),
                "observer_binary": str(observer_binary),
                "transport_ca": str(transport_store.ca_certificate),
                "coordinator_certificate": str(transport_store.certificate_path("coordinator", machine.id)),
                "coordinator_private_key": str(coordinator_key),
                "daemon_certificate": str(transport_store.certificate_path("daemon", machine.id)),
                "daemon_private_key": str(daemon_key),
                "identity_registry": str(state_dir / "machine_identities.json"),
            }),
            str(engine_dir / "ansible" / "install-local-coordinator.yml"),
        ]
        env = dict(os.environ)
        env["ANSIBLE_CONFIG"] = str(engine_dir / "ansible" / "ansible.cfg")
        env["ANSIBLE_SSH_COMMON_ARGS"] = " ".join((
            "-F /dev/null", "-o IdentitiesOnly=yes", "-o StrictHostKeyChecking=yes",
            f"-o UserKnownHostsFile={host_store.render_known_hosts()}",
            "-o GlobalKnownHostsFile=/dev/null",
        ))
        syntax = _run([*command[:-1], "--syntax-check", command[-1]], env, 120)
        if syntax.returncode != 0:
            raise CoordinationError(f"syntax-check coordinateur refusé : {syntax.stderr.strip() or syntax.stdout.strip()}")
        applied = _run(command, env, 300)
        if applied.returncode != 0:
            raise CoordinationError(f"installation du coordinateur refusée : {applied.stderr.strip() or applied.stdout.strip()}")
    recap = next((line for line in reversed(applied.stdout.splitlines()) if "changed=" in line), "récapitulatif absent")
    return f"Coordinateur local installé sur {address}:{port}. Ansible : {' '.join(recap.split())}"


def fetch_current(
    machine_id: str,
    base_url: str,
    transport_store: TransportStore,
    passphrase: bytes,
) -> bytes:
    with transport_store.materialize_private("console", "local", passphrase) as private_key:
        context = ssl.create_default_context(cafile=str(transport_store.ca_certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(transport_store.certificate_path("console", "local")),
            keyfile=str(private_key),
        )
        request = Request(f"{base_url.rstrip('/')}/v1/state/{machine_id}")
        try:
            with urlopen(request, context=context, timeout=10) as response:
                if response.headers.get_content_type() != "application/x-protobuf":
                    raise CoordinationError("type de réponse du coordinateur refusé")
                body = response.read(256 * 1024 + 1)
        except (HTTPError, URLError, TimeoutError, ssl.SSLError) as error:
            raise CoordinationError("lecture mTLS du coordinateur refusée") from error
    if not body or len(body) > 256 * 1024:
        raise CoordinationError("état relayé absent ou trop grand")
    return body


def fetch_events(
    machine_id: str,
    base_url: str,
    transport_store: TransportStore,
    passphrase: bytes,
    *,
    after: int = 0,
    limit: int = 64,
) -> tuple[list[bytes], int, bool]:
    if after < 0 or not 1 <= limit <= 64:
        raise CoordinationError("pagination du journal invalide")
    query = urlencode({"after": after, "limit": limit})
    with transport_store.materialize_private("console", "local", passphrase) as private_key:
        context = ssl.create_default_context(cafile=str(transport_store.ca_certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(transport_store.certificate_path("console", "local")),
            keyfile=str(private_key),
        )
        request = Request(f"{base_url.rstrip('/')}/v1/events/{machine_id}?{query}")
        try:
            with urlopen(request, context=context, timeout=10) as response:
                if response.headers.get_content_type() != "application/x-protobuf":
                    raise CoordinationError("type de réponse du coordinateur refusé")
                body = response.read(1024 * 1024 + 1)
        except (HTTPError, URLError, TimeoutError, ssl.SSLError) as error:
            raise CoordinationError("lecture mTLS du journal refusée") from error
    if not body or len(body) > 1024 * 1024:
        raise CoordinationError("page de journal absente ou trop grande")
    page = telemetrie_pb2.EnvelopePage()
    try:
        page.ParseFromString(body)
    except DecodeError as error:
        raise CoordinationError("page Protobuf du journal invalide") from error
    if page.schema_version != 1 or len(page.envelopes) > limit:
        raise CoordinationError("page de journal incohérente")
    return (
        [envelope.SerializeToString(deterministic=True) for envelope in page.envelopes],
        page.next_after_sequence,
        page.has_more,
    )
