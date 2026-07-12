from __future__ import annotations

import argparse
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import sys
from typing import Iterator

from .api import serve
from .audit import render_human, render_json, run_audit
from .errors import ConsoleError
from .enrollment import enroll, enrollment_plan, remote_observer
from .model import (
    Declaration,
    Infrastructure,
    Machine,
    add_machine,
    empty_declaration,
    load_declaration,
    parse_declaration,
    save_declaration,
)
from .secrets import AdminKeyStore, read_passphrase
from .security import (
    administration_plan,
    administration_machine,
    apply_security_profile,
    prepare_administration,
    profile_status,
    security_plan,
)
from .ssh import verify_or_pin_host_key
from .storage import HostKeyStore
from .telemetry import IdentityStore, decode_envelope, state_to_dict, verify_state


def default_declaration_path() -> Path:
    return Path(
        os.environ.get(
            "YOUR_CLOUD_DECLARATION",
            Path.home() / ".config" / "your-cloud" / "declaration.json",
        )
    )


def default_state_dir() -> Path:
    return Path(
        os.environ.get(
            "YOUR_CLOUD_STATE_DIR",
            Path.home() / ".local" / "state" / "your-cloud",
        )
    )


@contextmanager
def machine_access(
    machine: Machine,
    state_dir: Path,
    passphrase_file: Path | None,
) -> Iterator[Machine]:
    key_store = AdminKeyStore(state_dir)
    if not key_store.private_path(machine.id).exists():
        yield machine
        return
    passphrase = read_passphrase(passphrase_file, confirm=False)
    with key_store.materialize(machine.id, passphrase) as identity_file:
        yield administration_machine(machine, identity_file)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="your-cloud", description="Console d'infrastructure your-cloud")
    parser.add_argument("--declaration", type=Path, default=default_declaration_path())
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("init", help="créer une déclaration vide au schéma courant")

    infrastructure = subcommands.add_parser("infrastructure", help="gérer les infrastructures déclarées")
    infrastructure_commands = infrastructure.add_subparsers(dest="infrastructure_command", required=True)
    infrastructure_add = infrastructure_commands.add_parser("add")
    infrastructure_add.add_argument("id")
    infrastructure_add.add_argument("--name", required=True)

    machine = subcommands.add_parser("machine", help="gérer et auditer les machines")
    machine_commands = machine.add_subparsers(dest="machine_command", required=True)
    machine_add = machine_commands.add_parser("add")
    machine_add.add_argument("id")
    machine_add.add_argument("--address", required=True)
    machine_add.add_argument("--port", type=int, default=22)
    machine_add.add_argument("--user", required=True)
    machine_add.add_argument("--identity-file", type=Path, required=True)
    machine_add.add_argument("--infrastructure")

    machine_audit = machine_commands.add_parser("audit")
    machine_audit.add_argument("id")
    trust = machine_audit.add_mutually_exclusive_group()
    trust.add_argument("--accept-host-key", action="store_true")
    trust.add_argument("--host-fingerprint")
    machine_audit.add_argument("--json", action="store_true")
    machine_audit.add_argument("--passphrase-file", type=Path)

    machine_enroll = machine_commands.add_parser("enroll", help="enrôler le daemon d'observation")
    machine_enroll.add_argument("id")
    machine_enroll.add_argument("--daemon-binary", type=Path, required=True)
    machine_enroll.add_argument("--engine-dir", type=Path, required=True)
    machine_enroll.add_argument("--unit", action="append", default=[])
    machine_enroll.add_argument("--approve", action="store_true")

    machine_inspect = machine_commands.add_parser("inspect", help="vérifier l'état signé courant")
    machine_inspect.add_argument("id")
    machine_inspect.add_argument("--json", action="store_true")
    machine_inspect.add_argument("--passphrase-file", type=Path)

    machine_disenroll = machine_commands.add_parser("disenroll", help="révoquer le suivi sans désinstaller")
    machine_disenroll.add_argument("id")
    machine_disenroll.add_argument("--approve", action="store_true")

    administration = machine_commands.add_parser(
        "administration", help="préparer un accès d'administration séparé"
    )
    administration_commands = administration.add_subparsers(
        dest="administration_command", required=True
    )
    administration_prepare = administration_commands.add_parser("prepare")
    administration_prepare.add_argument("id")
    administration_prepare.add_argument("--engine-dir", type=Path, required=True)
    administration_prepare.add_argument("--recovery-kit", type=Path, required=True)
    administration_prepare.add_argument("--passphrase-file", type=Path)
    administration_prepare.add_argument("--approve", action="store_true")

    machine_secure = machine_commands.add_parser(
        "secure", help="appliquer le profil Linux après preuve du nouvel accès"
    )
    machine_secure.add_argument("id")
    machine_secure.add_argument("--engine-dir", type=Path, required=True)
    machine_secure.add_argument("--passphrase-file", type=Path)
    machine_secure.add_argument("--admin-ipv4-cidr", required=True)
    machine_secure.add_argument("--admin-ipv6-cidr", required=True)
    machine_secure.add_argument("--ipv6-address", required=True)
    machine_secure.add_argument("--dedicated", action="store_true")
    machine_secure.add_argument("--out-of-band", required=True)
    machine_secure.add_argument("--approve", action="store_true")

    serve_parser = subcommands.add_parser("serve", help="servir l'API locale en lecture seule")
    serve_parser.add_argument("--socket", type=Path, required=True)
    return parser


def _add_infrastructure(path: Path, infrastructure_id: str, name: str) -> None:
    declaration = load_declaration(path)
    candidate = Declaration(
        declaration.schema_version,
        declaration.machines,
        (*declaration.infrastructures, Infrastructure(infrastructure_id, name)),
    )
    save_declaration(path, parse_declaration(candidate.to_dict()))


def run(args: argparse.Namespace) -> int:
    if args.command == "init":
        save_declaration(args.declaration, empty_declaration(), refuse_existing=True)
        print(f"Déclaration créée : {args.declaration}")
        return 0
    if args.command == "infrastructure" and args.infrastructure_command == "add":
        _add_infrastructure(args.declaration, args.id, args.name)
        print(f"Infrastructure déclarée : {args.id}")
        return 0
    if args.command == "machine" and args.machine_command == "add":
        declaration = load_declaration(args.declaration)
        machine = Machine(
            id=args.id,
            address=args.address,
            port=args.port,
            user=args.user,
            identity_file=str(args.identity_file),
            infrastructure_id=args.infrastructure,
        )
        save_declaration(args.declaration, add_machine(declaration, machine))
        print(f"Machine déclarée : {args.id} ({machine.endpoint})")
        return 0
    if args.command == "machine" and args.machine_command == "audit":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        store = HostKeyStore(args.state_dir)
        host_key = verify_or_pin_host_key(
            machine,
            store,
            accept_tofu=args.accept_host_key,
            expected_fingerprint=args.host_fingerprint,
        )
        with machine_access(machine, args.state_dir, args.passphrase_file) as access:
            result = run_audit(access, store, host_key)
        print(render_json(result) if args.json else render_human(result))
        return 0 if result.decision == "eligible" else 3
    if args.command == "machine" and args.machine_command == "enroll":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        units = tuple(args.unit)
        plan = enrollment_plan(machine, args.daemon_binary, units)
        print(plan)
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        host_store = HostKeyStore(args.state_dir)
        host_key = verify_or_pin_host_key(machine, host_store)
        result = enroll(
            machine,
            host_store,
            host_key,
            IdentityStore(args.state_dir),
            engine_dir=args.engine_dir,
            daemon_binary=args.daemon_binary,
            units=units,
        )
        print(result)
        return 0
    if args.command == "machine" and args.machine_command == "inspect":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        host_store = HostKeyStore(args.state_dir)
        verify_or_pin_host_key(machine, host_store)
        with machine_access(machine, args.state_dir, args.passphrase_file) as access:
            encoded = remote_observer(access, host_store, "export-current")
        state = verify_state(machine.id, decode_envelope(encoded), IdentityStore(args.state_dir))
        rendered = state_to_dict(state, machine.infrastructure_id)
        if args.json:
            print(json.dumps(rendered, ensure_ascii=False, indent=2))
        else:
            print(
                f"Machine : {rendered['machine_id']}\n"
                f"Affectation : {rendered['assignment']}\n"
                f"Provenance : {rendered['provenance']}\n"
                f"État : {rendered['freshness']} (séquence {rendered['sequence']}, "
                f"observé {rendered['observed_at']})\n"
                f"Système : Debian {rendered['system']['debian_version']}, "
                f"noyau {rendered['system']['kernel']}\n"
                f"Daemon : {rendered['daemon_version']}"
            )
        return 0
    if args.command == "machine" and args.machine_command == "disenroll":
        declaration = load_declaration(args.declaration)
        declaration.machine(args.id)
        if not args.approve:
            print(
                f"Plan de désenrôlement pour {args.id} : révoquer l'identité dans la console ; "
                "ne modifier ni le daemon ni les services de la machine."
            )
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        revoked = IdentityStore(args.state_dir).revoke(args.id)
        print(f"Identité révoquée : {revoked.key_id}. Aucune mutation distante effectuée.")
        return 0
    if args.command == "machine" and args.machine_command == "administration":
        if args.administration_command != "prepare":
            raise ConsoleError("commande d'administration inconnue")
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        print(administration_plan(machine, args.recovery_kit))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        passphrase = read_passphrase(args.passphrase_file, confirm=True)
        host_store = HostKeyStore(args.state_dir)
        host_key = verify_or_pin_host_key(machine, host_store)
        result = prepare_administration(
            machine,
            args.declaration,
            host_store,
            host_key,
            AdminKeyStore(args.state_dir),
            passphrase,
            engine_dir=args.engine_dir,
            kit_path=args.recovery_kit,
        )
        print(result)
        return 0
    if args.command == "machine" and args.machine_command == "secure":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        if not args.dedicated:
            raise ConsoleError("la sécurisation exige la confirmation explicite --dedicated")
        if not args.out_of_band.strip():
            raise ConsoleError("un accès hors bande explicite est requis")
        try:
            ipv4_cidr = str(ipaddress.IPv4Network(args.admin_ipv4_cidr, strict=False))
            ipv6_cidr = str(ipaddress.IPv6Network(args.admin_ipv6_cidr, strict=False))
            ipaddress.IPv6Address(args.ipv6_address.split("%", 1)[0])
        except ValueError as error:
            raise ConsoleError(f"adresse ou réseau d'administration invalide : {error}") from error
        if "%" not in args.ipv6_address:
            raise ConsoleError("l'adresse IPv6 link-local doit préciser son interface avec %")
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        host_store = HostKeyStore(args.state_dir)
        key_store = AdminKeyStore(args.state_dir)
        with key_store.materialize(machine.id, passphrase) as identity_file:
            status = profile_status(machine, host_store, identity_file)
        print(security_plan(
            machine,
            status,
            ipv4_cidr,
            ipv6_cidr,
            args.out_of_band,
        ))
        if status == "drift":
            return 3
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        result = apply_security_profile(
            machine,
            host_store,
            key_store,
            passphrase,
            engine_dir=args.engine_dir,
            state_dir=args.state_dir,
            ipv4_cidr=ipv4_cidr,
            ipv6_cidr=ipv6_cidr,
            ipv6_address=args.ipv6_address,
        )
        print(result)
        return 0
    if args.command == "serve":
        serve(args.socket, args.declaration)
        return 0
    raise ConsoleError("commande non prise en charge")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        return run(parser.parse_args(argv))
    except ConsoleError as error:
        print(f"REFUS : {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"REFUS : erreur système bornée : {error}", file=sys.stderr)
        return 2
