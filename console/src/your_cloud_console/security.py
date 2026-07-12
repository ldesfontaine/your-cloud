from __future__ import annotations

from contextlib import AbstractContextManager
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from .audit import run_audit
from .errors import SecurityError
from .model import Machine
from .secrets import AdminKeyStore
from .ssh import ssh_command
from .storage import HostKeyStore, PinnedHostKey


ADMINISTRATION_USER = "your-cloud-admin"
PROFILE_MANIFEST = "/var/lib/your-cloud/profile/manifest.sha256"
NFTABLES_PACKAGE_VERSION = "1.1.3-1"


def _run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise SecurityError(f"commande de sécurisation indisponible ou expirée : {command[0]}") from error


def administration_plan(machine: Machine, kit_path: Path) -> str:
    return "\n".join(
        (
            f"Plan pour préparer l'administration de {machine.id} ({machine.endpoint}) :",
            "  - générer une clé Ed25519 propre à cette machine",
            "  - conserver la clé privée uniquement sous forme OpenSSH chiffrée",
            f"  - exporter et vérifier le kit de récupération {kit_path}",
            f"  - créer le compte non-root {ADMINISTRATION_USER} avec sudo",
            "  - prouver une nouvelle connexion SSH et une élévation distinctes",
            "  - ne fermer aucun accès existant ; SSH et le pare-feu restent un second plan",
        )
    )


def _ansible_environment(engine_dir: Path, known_hosts: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["ANSIBLE_CONFIG"] = str(engine_dir / "ansible" / "ansible.cfg")
    env["ANSIBLE_SSH_COMMON_ARGS"] = " ".join(
        (
            "-F /dev/null",
            "-o IdentitiesOnly=yes",
            "-o StrictHostKeyChecking=yes",
            f"-o UserKnownHostsFile={known_hosts}",
            "-o GlobalKnownHostsFile=/dev/null",
        )
    )
    return env


def _syntax_checked_apply(command: list[str], env: dict[str, str], label: str) -> str:
    syntax = _run([*command[:-1], "--syntax-check", command[-1]], env=env)
    if syntax.returncode != 0:
        raise SecurityError(f"syntax-check {label} refusé : {syntax.stderr.strip() or syntax.stdout.strip()}")
    applied = _run(command, env=env, timeout=300)
    if applied.returncode != 0:
        raise SecurityError(f"{label} refusé : {applied.stderr.strip() or applied.stdout.strip()}")
    return applied.stdout


def _ansible_recap(output: str) -> str:
    for line in reversed(output.splitlines()):
        if "changed=" in line and "failed=" in line:
            return " ".join(line.split())
    raise SecurityError("récapitulatif Ansible absent")


def _ssh_with_identity(
    machine: Machine,
    known_hosts: Path,
    identity_file: Path,
    command: str,
    *,
    address: str | None = None,
    ipv6: bool = False,
) -> subprocess.CompletedProcess[str]:
    target_address = address or machine.address
    if address is None and not ipv6:
        admin = administration_machine(machine, identity_file)
        return _run([*ssh_command(admin, known_hosts), command], timeout=20)
    options = [
        "ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
        "-i", str(identity_file), "-p", str(machine.port),
    ]
    if target_address != machine.address:
        options.extend(("-o", f"HostKeyAlias={machine.address}"))
    if ipv6:
        options.append("-6")
    options.extend((f"{ADMINISTRATION_USER}@{target_address}", command))
    return _run(options, timeout=20)


def prove_administration(
    machine: Machine,
    host_store: HostKeyStore,
    identity_file: Path,
    *,
    address: str | None = None,
    ipv6: bool = False,
) -> None:
    command = "test \"$(id -u)\" -ne 0 && test \"$(sudo -n id -u)\" = 0"
    completed = _ssh_with_identity(
        machine,
        host_store.render_known_hosts(),
        identity_file,
        command,
        address=address,
        ipv6=ipv6,
    )
    if completed.returncode != 0:
        family = "IPv6" if ipv6 else "IPv4"
        raise SecurityError(f"nouvelle connexion d'administration {family} ou sudo non prouvé")


def prepare_administration(
    machine: Machine,
    declaration_path: Path,
    host_store: HostKeyStore,
    pinned_host_key: PinnedHostKey,
    key_store: AdminKeyStore,
    passphrase: bytes,
    *,
    engine_dir: Path,
    kit_path: Path,
) -> str:
    key_exists = key_store.private_path(machine.id).exists()
    if key_exists:
        public = key_store.public_key(machine.id, passphrase)
        recovered = key_store.verify_recovery_kit(kit_path, passphrase)
        if recovered != public:
            raise SecurityError("le kit existant ne correspond pas à la clé d'administration")
    else:
        initial_audit = run_audit(machine, host_store, pinned_host_key)
        if initial_audit.decision != "eligible":
            raise SecurityError("l'audit préalable n'autorise pas la préparation administrative")
        public = key_store.create_with_recovery_kit(
            machine.id, declaration_path, kit_path, passphrase
        )
    playbook = engine_dir / "ansible" / "prepare-administration.yml"
    if not playbook.is_file():
        raise SecurityError(f"playbook absent : {playbook}")

    def apply_with(access: Machine, proof_identity: Path) -> str:
        audit = run_audit(access, host_store, pinned_host_key)
        if audit.decision != "eligible":
            raise SecurityError("l'audit préalable n'autorise pas la préparation administrative")
        command = [
            "ansible-playbook",
            "-i", f"{machine.address},",
            "--user", access.user,
            "--private-key", access.identity_file,
            "--extra-vars", f"ansible_port={machine.port}",
            "--extra-vars", json.dumps(
                {"machine_id": machine.id, "administration_public_key": public}
            ),
            str(playbook),
        ]
        ansible_output = _syntax_checked_apply(
            command,
            _ansible_environment(engine_dir, host_store.render_known_hosts()),
            "préparation administrative",
        )
        prove_administration(machine, host_store, proof_identity)
        return ansible_output

    if key_exists:
        with key_store.materialize(machine.id, passphrase) as identity_file:
            admin = administration_machine(machine, identity_file)
            probe = _ssh_with_identity(
                machine, host_store.render_known_hosts(), identity_file, "true"
            )
            access = admin if probe.returncode == 0 else machine
            ansible_output = apply_with(access, identity_file)
    else:
        with key_store.materialize(machine.id, passphrase) as identity_file:
            ansible_output = apply_with(machine, identity_file)
    return (
        f"Administration vérifiée : compte {ADMINISTRATION_USER}, nouvelle connexion et sudo prouvés. "
        f"Kit vérifié : {kit_path}. Ansible : {_ansible_recap(ansible_output)}"
    )


def administration_machine(machine: Machine, identity_file: Path) -> Machine:
    return Machine(
        id=machine.id,
        address=machine.address,
        port=machine.port,
        user=ADMINISTRATION_USER,
        identity_file=str(identity_file),
        infrastructure_id=machine.infrastructure_id,
    )


def _remote_admin(
    machine: Machine,
    host_store: HostKeyStore,
    identity_file: Path,
    command: str,
) -> str:
    admin = administration_machine(machine, identity_file)
    completed = _run([*ssh_command(admin, host_store.render_known_hosts()), command], timeout=30)
    if completed.returncode != 0:
        raise SecurityError(f"inspection administrative refusée : {completed.stderr.strip()}")
    output = completed.stdout.strip()
    if len(output) > 64 * 1024:
        raise SecurityError("sortie administrative trop grande")
    return output


def profile_status(
    machine: Machine,
    host_store: HostKeyStore,
    identity_file: Path,
) -> str:
    output = _remote_admin(
        machine,
        host_store,
        identity_file,
        f"sudo -n sh -c 'if [ ! -e {PROFILE_MANIFEST} ]; then echo absent; "
        f"elif sha256sum -c {PROFILE_MANIFEST} >/dev/null 2>&1; "
        "then echo clean; else echo drift; fi'",
    )
    if output not in {"absent", "clean", "drift"}:
        raise SecurityError("état d'autorité du profil invalide")
    return output


def security_plan(
    machine: Machine,
    status: str,
    ipv4_cidr: str,
    ipv6_cidr: str,
    out_of_band: str,
    coordinator_port: int = 0,
) -> str:
    disposition = {
        "absent": "nouveau profil, aucune autorité your-cloud existante",
        "clean": "profil déjà possédé et sans dérive",
        "drift": "REFUS : dérive sur un fichier possédé, aucune correction automatique",
    }[status]
    lines = [
            f"Plan pour sécuriser {machine.id} :",
            f"  - autorité : {disposition}",
            f"  - accès hors bande confirmé : {out_of_band}",
            "  - conserver une session bootstrap et préparer un rollback borné",
            "  - imposer les clés SSH, interdire root et les mots de passe",
            f"  - installer nftables {NFTABLES_PACKAGE_VERSION}, version explicitement épinglée",
            f"  - autoriser SSH depuis {ipv4_cidr} et {ipv6_cidr}",
            "  - fermer par défaut les entrées et le forwarding en IPv4 et IPv6",
            "  - conserver les sorties et ICMP/ICMPv6 nécessaires",
            "  - désactiver les redirections réseau par sysctl",
            "  - proposer les correctifs de sécurité sans les activer ni redémarrer",
    ]
    if coordinator_port:
        lines.append(
            f"  - autoriser le coordinateur local sur TCP {coordinator_port} depuis les mêmes réseaux d'administration"
        )
    return "\n".join(lines)


class BootstrapControl(AbstractContextManager["BootstrapControl"]):
    def __init__(
        self,
        machine: Machine,
        host_store: HostKeyStore,
        state_dir: Path,
        *,
        rollback_with_sudo: bool = False,
    ):
        self.machine = machine
        self.base = ssh_command(machine, host_store.render_known_hosts())
        self.temporary = tempfile.TemporaryDirectory(prefix="bootstrap-", dir=state_dir)
        self.socket = Path(self.temporary.name) / "control.sock"
        self.process: subprocess.Popen[str] | None = None
        self.rollback_with_sudo = rollback_with_sudo

    def __enter__(self) -> "BootstrapControl":
        command = [*self.base[:-1], "-M", "-S", str(self.socket), "-N", self.base[-1]]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.socket.exists():
                return self
            if self.process.poll() is not None:
                detail = self.process.stderr.read().strip() if self.process.stderr else ""
                raise SecurityError(f"session bootstrap non conservée : {detail}")
            time.sleep(0.1)
        self.close()
        raise SecurityError("session bootstrap non établie dans le délai")

    def rollback(self, rollback_id: str) -> None:
        rollback = f"sh /var/lib/your-cloud/profile/rollback/{rollback_id}/rollback.sh"
        if self.rollback_with_sudo:
            rollback = "sudo -n " + rollback
        command = [
            *self.base[:-1], "-S", str(self.socket), self.base[-1],
            rollback,
        ]
        completed = _run(command, timeout=60)
        if completed.returncode != 0:
            raise SecurityError(f"rollback par la session conservée en échec : {completed.stderr.strip()}")

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            _run(["ssh", "-F", "/dev/null", "-S", str(self.socket), "-O", "exit", self.base[-1]])
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
        self.temporary.cleanup()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def apply_security_profile(
    machine: Machine,
    host_store: HostKeyStore,
    key_store: AdminKeyStore,
    passphrase: bytes,
    *,
    engine_dir: Path,
    state_dir: Path,
    ipv4_cidr: str,
    ipv6_cidr: str,
    ipv6_address: str,
    coordinator_port: int = 0,
) -> str:
    rollback_id = "initial-profile" if coordinator_port == 0 else f"coordinator-{coordinator_port}"
    playbook = engine_dir / "ansible" / "apply-linux-profile.yml"
    if not playbook.is_file():
        raise SecurityError(f"playbook absent : {playbook}")
    with key_store.materialize(machine.id, passphrase) as identity_file:
        status = profile_status(machine, host_store, identity_file)
        if status == "drift":
            raise SecurityError("dérive détectée : le plan refuse tout écrasement")
        admin = administration_machine(machine, identity_file)
        pinned_host_key = host_store.get(machine.id)
        if pinned_host_key is None:
            raise SecurityError(f"clé d'hôte non épinglée pour {machine.id}")
        audit = run_audit(admin, host_store, pinned_host_key)
        if audit.decision != "eligible":
            raise SecurityError("l'audit préalable n'autorise pas le profil Linux")
        command = [
            "ansible-playbook",
            "-i", f"{machine.address},",
            "--user", ADMINISTRATION_USER,
            "--private-key", str(identity_file),
            "--extra-vars", f"ansible_port={machine.port}",
            "--extra-vars", json.dumps(
                {
                    "machine_id": machine.id,
                    "administration_ipv4_cidr": ipv4_cidr,
                    "administration_ipv6_cidr": ipv6_cidr,
                    "nftables_package_version": NFTABLES_PACKAGE_VERSION,
                    "rollback_id": rollback_id,
                    "coordinator_port": coordinator_port,
                }
            ),
            str(playbook),
        ]
        env = _ansible_environment(engine_dir, host_store.render_known_hosts())
        syntax = _run([*command[:-1], "--syntax-check", command[-1]], env=env)
        if syntax.returncode != 0:
            raise SecurityError(f"syntax-check du profil refusé : {syntax.stderr.strip() or syntax.stdout.strip()}")
        control_machine = machine if status == "absent" else admin
        with BootstrapControl(
            control_machine,
            host_store,
            state_dir,
            rollback_with_sudo=status != "absent",
        ) as bootstrap:
            applied = _run(command, env=env, timeout=600)
            if applied.returncode != 0:
                bootstrap.rollback(rollback_id)
                raise SecurityError(
                    f"profil refusé puis rollback exécuté : {applied.stderr.strip() or applied.stdout.strip()}"
                )
            try:
                prove_administration(machine, host_store, identity_file)
                prove_administration(
                    machine,
                    host_store,
                    identity_file,
                    address=ipv6_address,
                    ipv6=True,
                )
            except Exception:
                bootstrap.rollback(rollback_id)
                raise
    return (
        "Profil vérifié : nouvelles connexions IPv4 et IPv6, sudo, SSH key-only, "
        f"pare-feu dual-stack et rollback préparé. Ansible : {_ansible_recap(applied.stdout)}"
    )
