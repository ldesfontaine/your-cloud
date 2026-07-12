"""Interface en ligne de commande qui orchestre les plans et leurs preuves."""

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
from .coordination import (
    authorize_pilot_coordinator,
    coordination_plan,
    distant_coordination_plan,
    fetch_current,
    fetch_events,
    install_distant_coordinator,
    install_local_coordinator,
    pilot_migration_plan,
    point_retirement_plan,
    retire_coordinator_point,
)
from .errors import ConsoleError
from .enrollment import (
    enroll,
    enrollment_plan,
    identity_renewal_plan,
    observer_uninstall_plan,
    remote_observer,
    renew_identity,
    uninstall_observer,
)
from .failure_domains import FailureDomainStore, failure_domain_view
from .model import (
    Declaration,
    Infrastructure,
    Machine,
    add_machine,
    assign_machine,
    empty_declaration,
    load_declaration,
    load_migration_candidate,
    parse_declaration,
    save_declaration,
    set_failure_domain,
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
from .resources import measure_resources
from .ssh import verify_or_pin_host_key
from .storage import HostKeyStore
from .telemetry import IdentityStore, decode_envelope, state_to_dict, verify_event, verify_state
from .transport import TransportStore
from .updates import UpdateStore, apply_update, update_plan


def default_declaration_path() -> Path:
    """Retourne le chemin déclaré ou l'emplacement XDG par défaut."""

    return Path(
        os.environ.get(
            "YOUR_CLOUD_DECLARATION",
            Path.home() / ".config" / "your-cloud" / "declaration.json",
        )
    )


def default_state_dir() -> Path:
    """Retourne le stockage runtime déclaré ou l'emplacement XDG par défaut."""

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
    """Matérialise temporairement la clé d'administration lorsqu'elle existe."""

    key_store = AdminKeyStore(state_dir)
    if not key_store.private_path(machine.id).exists():
        yield machine
        return
    passphrase = read_passphrase(passphrase_file, confirm=False)
    with key_store.materialize(machine.id, passphrase) as identity_file:
        yield administration_machine(machine, identity_file)


def build_parser() -> argparse.ArgumentParser:
    """Construit la grammaire complète de la CLI et ses validations de forme."""

    parser = argparse.ArgumentParser(prog="your-cloud", description="Console d'infrastructure your-cloud")
    parser.add_argument("--declaration", type=Path, default=default_declaration_path())
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("init", help="créer une déclaration vide au schéma courant")

    recovery = subcommands.add_parser(
        "recovery", help="actualiser ou restaurer le kit de récupération de la console"
    )
    recovery_commands = recovery.add_subparsers(dest="recovery_command", required=True)
    for command, help_text in (
        ("refresh", "capturer l'état complet courant dans un kit existant"),
        ("restore", "restaurer une console neuve depuis un kit complet"),
    ):
        recovery_command = recovery_commands.add_parser(command, help=help_text)
        recovery_command.add_argument("--kit", type=Path, required=True)
        recovery_command.add_argument("--passphrase-file", type=Path)
        recovery_command.add_argument("--approve", action="store_true")

    declaration = subcommands.add_parser("declaration", help="gérer le schéma de déclaration")
    declaration_commands = declaration.add_subparsers(
        dest="declaration_command", required=True
    )
    declaration_migrate = declaration_commands.add_parser(
        "migrate", help="migrer explicitement la déclaration vers le schéma courant"
    )
    declaration_migrate.add_argument("--approve", action="store_true")

    infrastructure = subcommands.add_parser("infrastructure", help="gérer les infrastructures déclarées")
    infrastructure_commands = infrastructure.add_subparsers(dest="infrastructure_command", required=True)
    infrastructure_add = infrastructure_commands.add_parser("add")
    infrastructure_add.add_argument("id")
    infrastructure_add.add_argument("--name", required=True)
    infrastructure_add.add_argument("--failure-domain")

    infrastructure_status = infrastructure_commands.add_parser(
        "status", help="distinguer domaine déclaré, détecté ou inconnu"
    )
    infrastructure_status.add_argument("id", nargs="?")
    infrastructure_status.add_argument("--json", action="store_true")

    infrastructure_domain = infrastructure_commands.add_parser(
        "set-failure-domain", help="déclarer ou oublier un domaine de panne"
    )
    infrastructure_domain.add_argument("id")
    domain_value = infrastructure_domain.add_mutually_exclusive_group(required=True)
    domain_value.add_argument("--domain")
    domain_value.add_argument("--unknown", action="store_true")
    infrastructure_domain.add_argument("--approve", action="store_true")

    machine = subcommands.add_parser("machine", help="gérer et auditer les machines")
    machine_commands = machine.add_subparsers(dest="machine_command", required=True)
    machine_add = machine_commands.add_parser("add")
    machine_add.add_argument("id")
    machine_add.add_argument("--address", required=True)
    machine_add.add_argument("--port", type=int, default=22)
    machine_add.add_argument("--user", required=True)
    machine_add.add_argument("--identity-file", type=Path, required=True)
    machine_add.add_argument("--infrastructure")

    machine_assign = machine_commands.add_parser(
        "assign", help="affecter ou rendre disponible une machine"
    )
    machine_assign.add_argument("id")
    assignment = machine_assign.add_mutually_exclusive_group(required=True)
    assignment.add_argument("--infrastructure")
    assignment.add_argument("--available", action="store_true")
    machine_assign.add_argument("--approve", action="store_true")

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

    machine_renew = machine_commands.add_parser(
        "renew-identity", help="remplacer l'identité sans changer la machine logique"
    )
    machine_renew.add_argument("id")
    machine_renew.add_argument("--engine-dir", type=Path, required=True)
    machine_renew.add_argument("--passphrase-file", type=Path)
    machine_renew.add_argument("--approve", action="store_true")

    machine_uninstall = machine_commands.add_parser(
        "uninstall-observer", help="retirer le daemon sans toucher aux services"
    )
    machine_uninstall.add_argument("id")
    machine_uninstall.add_argument("--engine-dir", type=Path, required=True)
    machine_uninstall.add_argument("--passphrase-file", type=Path)
    machine_uninstall.add_argument("--approve", action="store_true")

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
    machine_secure.add_argument("--coordinator-port", type=int, default=0)
    machine_secure.add_argument("--coordinator-ipv4-cidr")
    machine_secure.add_argument("--coordinator-ipv6-cidr")
    machine_secure.add_argument("--approve", action="store_true")

    coordination = subcommands.add_parser("coordination", help="conserver l'observation sans la console")
    coordination_commands = coordination.add_subparsers(dest="coordination_command", required=True)
    coordination_install = coordination_commands.add_parser("install-local")
    coordination_install.add_argument("id")
    coordination_install.add_argument("--address", required=True)
    coordination_install.add_argument("--port", type=int, default=8443)
    coordination_install.add_argument("--coordinator-binary", type=Path, required=True)
    coordination_install.add_argument("--daemon-binary", type=Path, required=True)
    coordination_install.add_argument("--engine-dir", type=Path, required=True)
    coordination_install.add_argument("--recovery-kit", type=Path, required=True)
    coordination_install.add_argument("--passphrase-file", type=Path)
    coordination_install.add_argument("--approve", action="store_true")

    coordination_distant = coordination_commands.add_parser(
        "install-distant", help="préparer le même coordinateur sur un point public"
    )
    coordination_distant.add_argument("id")
    coordination_distant.add_argument("--endpoint", required=True)
    coordination_distant.add_argument("--listen-address", required=True)
    coordination_distant.add_argument("--port", type=int, default=8443)
    coordination_distant.add_argument("--coordinator-binary", type=Path, required=True)
    coordination_distant.add_argument("--engine-dir", type=Path, required=True)
    coordination_distant.add_argument("--recovery-kit", type=Path, required=True)
    coordination_distant.add_argument("--passphrase-file", type=Path)
    coordination_distant.add_argument("--approve", action="store_true")

    coordination_pilot = coordination_commands.add_parser(
        "migrate-pilot", help="autoriser le point distant sur une seule machine"
    )
    coordination_pilot.add_argument("id")
    coordination_pilot.add_argument("--coordinator", required=True)
    coordination_pilot.add_argument("--endpoint", required=True)
    coordination_pilot.add_argument("--port", type=int, default=8443)
    coordination_pilot.add_argument("--engine-dir", type=Path, required=True)
    coordination_pilot.add_argument("--passphrase-file", type=Path)
    coordination_pilot.add_argument("--approve", action="store_true")

    coordination_retire = coordination_commands.add_parser(
        "retire-point", help="retirer un ancien point dans un plan séparé"
    )
    coordination_retire.add_argument("id")
    coordination_retire.add_argument("--endpoint", required=True)
    coordination_retire.add_argument("--port", type=int, default=8443)
    coordination_retire.add_argument("--engine-dir", type=Path, required=True)
    coordination_retire.add_argument("--passphrase-file", type=Path)
    coordination_retire.add_argument("--approve", action="store_true")

    coordination_inspect = coordination_commands.add_parser("inspect")
    coordination_inspect.add_argument("id")
    coordination_inspect.add_argument("--url", required=True)
    coordination_inspect.add_argument("--passphrase-file", type=Path)
    coordination_inspect.add_argument("--json", action="store_true")

    coordination_journal = coordination_commands.add_parser("journal")
    coordination_journal.add_argument("id")
    coordination_journal.add_argument("--url", required=True)
    coordination_journal.add_argument("--after", type=int, default=0)
    coordination_journal.add_argument("--limit", type=int, default=64)
    coordination_journal.add_argument("--passphrase-file", type=Path)
    coordination_journal.add_argument("--json", action="store_true")

    component = subcommands.add_parser(
        "component", help="mettre à jour progressivement les composants natifs"
    )
    component_commands = component.add_subparsers(dest="component_command", required=True)
    component_update = component_commands.add_parser("update")
    component_update.add_argument("kind", choices=("coordinator", "observer"))
    component_update.add_argument("id")
    component_update.add_argument("--binary", type=Path, required=True)
    component_update.add_argument("--sha256", required=True)
    component_update.add_argument("--version", required=True)
    component_update.add_argument("--engine-dir", type=Path, required=True)
    component_update.add_argument("--passphrase-file", type=Path)
    component_update.add_argument("--pilot", action="store_true")
    component_update.add_argument("--approve", action="store_true")
    component_resources = component_commands.add_parser(
        "resources", help="mesurer les budgets systemd et SQLite"
    )
    component_resources.add_argument("kind", choices=("coordinator", "observer"))
    component_resources.add_argument("id")
    component_resources.add_argument("--passphrase-file", type=Path)
    component_resources.add_argument("--json", action="store_true")

    serve_parser = subcommands.add_parser("serve", help="servir l'API locale en lecture seule")
    serve_parser.add_argument("--socket", type=Path, required=True)
    return parser


def _add_infrastructure(
    path: Path,
    infrastructure_id: str,
    name: str,
    failure_domain: str | None,
) -> None:
    declaration = load_declaration(path)
    candidate = Declaration(
        declaration.schema_version,
        declaration.machines,
        (*declaration.infrastructures, Infrastructure(infrastructure_id, name, failure_domain)),
    )
    save_declaration(path, parse_declaration(candidate.to_dict()))


def run(args: argparse.Namespace) -> int:
    """Exécute une commande déjà analysée en conservant plan et mutation séparés."""

    if args.command == "init":
        save_declaration(args.declaration, empty_declaration(), refuse_existing=True)
        print(f"Déclaration créée : {args.declaration}")
        return 0
    if args.command == "recovery":
        plan_title = (
            "Plan d'actualisation"
            if args.recovery_command == "refresh"
            else "Plan de restauration"
        )
        if args.recovery_command == "refresh":
            effects = (
                "  - remplacer le kit par l'état complet courant de la console\n"
                "  - conserver les clés d'administration et l'autorité de transport chiffrées\n"
                "  - inclure la déclaration et les registres publics à leur version courante"
            )
        elif args.recovery_command == "restore":
            effects = (
                "  - exiger une déclaration absente et un répertoire d'état vierge\n"
                "  - restaurer les autorités chiffrées sans contacter ni réenrôler les machines\n"
                "  - restaurer la déclaration et les registres publics sans écrasement"
            )
        else:
            raise ConsoleError("commande de récupération inconnue")
        print(f"{plan_title} de la console depuis {args.kit} :\n{effects}")
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        store = AdminKeyStore(args.state_dir)
        if args.recovery_command == "refresh":
            count = store.refresh_recovery_kit(args.declaration, args.kit, passphrase)
            print(f"Kit complet actualisé : {count} clé(s) d'administration chiffrée(s).")
        else:
            count = store.restore_recovery_kit(args.declaration, args.kit, passphrase)
            load_declaration(args.declaration)
            IdentityStore(args.state_dir).load()
            print(
                f"Console restaurée : {count} clé(s) d'administration, déclaration et "
                "registre d'identités vérifiés. Aucun réenrôlement effectué."
            )
        return 0
    if args.command == "declaration" and args.declaration_command == "migrate":
        candidate = load_migration_candidate(args.declaration)
        print(
            f"Plan de migration de la déclaration : schéma 1 -> {candidate.schema_version}.\n"
            f"  - conserver {len(candidate.machines)} machine(s) et "
            f"{len(candidate.infrastructures)} infrastructure(s)\n"
            "  - ajouter failure_domain=null à chaque infrastructure\n"
            "  - ne créer aucune détection ni déduire un domaine depuis une adresse\n"
            "  - ne modifier aucune machine, identité ou donnée runtime"
        )
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        save_declaration(args.declaration, candidate)
        print(f"Déclaration migrée explicitement au schéma {candidate.schema_version}.")
        return 0
    if args.command == "infrastructure" and args.infrastructure_command == "add":
        _add_infrastructure(
            args.declaration,
            args.id,
            args.name,
            args.failure_domain,
        )
        print(f"Infrastructure déclarée : {args.id}")
        return 0
    if args.command == "infrastructure" and args.infrastructure_command == "status":
        declaration = load_declaration(args.declaration)
        if args.id is None:
            infrastructures = declaration.infrastructures
        else:
            infrastructures = tuple(
                item for item in declaration.infrastructures if item.id == args.id
            )
            if not infrastructures:
                raise ConsoleError(f"infrastructure inconnue : {args.id}")
        store = FailureDomainStore(args.state_dir)
        rendered = []
        for infrastructure in infrastructures:
            view = failure_domain_view(infrastructure, store.get(infrastructure.id))
            rendered.append({
                "id": infrastructure.id,
                "name": infrastructure.name,
                "machines": [
                    machine.id
                    for machine in declaration.machines
                    if machine.infrastructure_id == infrastructure.id
                ],
                "failure_domain": view,
            })
        if args.json:
            print(json.dumps({"infrastructures": rendered}, ensure_ascii=False, indent=2))
        else:
            for item in rendered:
                domain = item["failure_domain"]
                if domain["status"] == "unknown":
                    detail = "inconnu : aucune déclaration ni détection"
                elif domain["status"] == "declared":
                    detail = f"déclaré : {domain['declared']}"
                elif domain["status"] == "detected":
                    detail = f"détecté : {domain['detected']['name']}"
                elif domain["status"] == "confirmed":
                    detail = f"confirmé déclaré + détecté : {domain['declared']}"
                else:
                    detail = (
                        f"CONFLIT : déclaré {domain['declared']}, "
                        f"détecté {domain['detected']['name']}"
                    )
                print(
                    f"Infrastructure {item['id']} ({item['name']}) — "
                    f"domaine de panne {detail} — {len(item['machines'])} machine(s)"
                )
        return 0
    if (
        args.command == "infrastructure"
        and args.infrastructure_command == "set-failure-domain"
    ):
        declaration = load_declaration(args.declaration)
        current = next(
            (item for item in declaration.infrastructures if item.id == args.id),
            None,
        )
        if current is None:
            raise ConsoleError(f"infrastructure inconnue : {args.id}")
        target = None if args.unknown else args.domain
        if current.failure_domain == target:
            print(f"Domaine déjà conforme pour {args.id} : {target or 'inconnu'}")
            return 0
        print(
            f"Plan pour le domaine de panne de {args.id} : "
            f"{current.failure_domain or 'inconnu'} -> {target or 'inconnu'}.\n"
            "  - modifier uniquement l'intention déclarée\n"
            "  - conserver séparément toute détection et sa preuve\n"
            "  - ne déplacer aucune machine ni aucun service"
        )
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        save_declaration(
            args.declaration,
            set_failure_domain(declaration, args.id, target),
        )
        print(f"Domaine déclaré pour {args.id} : {target or 'inconnu'}")
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
    if args.command == "machine" and args.machine_command == "assign":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        target = None if args.available else args.infrastructure
        if target == machine.infrastructure_id:
            destination = target or "disponible"
            print(f"Affectation déjà conforme pour {machine.id} : {destination}")
            return 0
        if target is not None and target not in {
            infrastructure.id for infrastructure in declaration.infrastructures
        }:
            raise ConsoleError(f"infrastructure inconnue : {target}")
        source = machine.infrastructure_id or "disponible"
        destination = target or "disponible"
        print(
            f"Plan d'affectation pour {machine.id} : {source} -> {destination}.\n"
            "  - conserver l'identité, l'historique et les accès de la machine\n"
            "  - ne déplacer ni service ni donnée et n'attribuer aucun rôle automatiquement"
        )
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        save_declaration(
            args.declaration,
            assign_machine(declaration, machine.id, target),
        )
        print(f"Machine {machine.id} affectée à : {destination}")
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
    if args.command == "machine" and args.machine_command == "renew-identity":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        print(identity_renewal_plan(machine))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        host_store = HostKeyStore(args.state_dir)
        verify_or_pin_host_key(machine, host_store)
        with machine_access(
            machine, args.state_dir, args.passphrase_file
        ) as access:
            print(renew_identity(
                access,
                host_store,
                IdentityStore(args.state_dir),
                engine_dir=args.engine_dir,
            ))
        return 0
    if args.command == "machine" and args.machine_command == "uninstall-observer":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        print(observer_uninstall_plan(machine))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        host_store = HostKeyStore(args.state_dir)
        verify_or_pin_host_key(machine, host_store)
        with machine_access(
            machine, args.state_dir, args.passphrase_file
        ) as access:
            result = uninstall_observer(access, host_store, engine_dir=args.engine_dir)
        revoked = IdentityStore(args.state_dir).revoke(machine.id)
        print(f"{result} Identité révoquée : {revoked.key_id}.")
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
        if args.coordinator_port != 0 and not 1024 <= args.coordinator_port <= 65535:
            raise ConsoleError("le port du coordinateur doit être nul ou non privilégié")
        try:
            ipv4_cidr = str(ipaddress.IPv4Network(args.admin_ipv4_cidr, strict=False))
            ipv6_cidr = str(ipaddress.IPv6Network(args.admin_ipv6_cidr, strict=False))
            coordinator_ipv4_cidr = str(ipaddress.IPv4Network(
                args.coordinator_ipv4_cidr or args.admin_ipv4_cidr,
                strict=False,
            ))
            coordinator_ipv6_cidr = str(ipaddress.IPv6Network(
                args.coordinator_ipv6_cidr or args.admin_ipv6_cidr,
                strict=False,
            ))
            ipv6_address = ipaddress.IPv6Address(args.ipv6_address.split("%", 1)[0])
        except ValueError as error:
            raise ConsoleError(f"adresse ou réseau d'administration invalide : {error}") from error
        if ipv6_address.is_link_local and "%" not in args.ipv6_address:
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
            args.coordinator_port,
            coordinator_ipv4_cidr,
            coordinator_ipv6_cidr,
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
            coordinator_port=args.coordinator_port,
            coordinator_ipv4_cidr=coordinator_ipv4_cidr,
            coordinator_ipv6_cidr=coordinator_ipv6_cidr,
        )
        print(result)
        return 0
    if args.command == "coordination" and args.coordination_command == "install-local":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        print(coordination_plan(machine, args.address, args.port))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après préparation du pare-feu.")
            return 3
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        key_store = AdminKeyStore(args.state_dir)
        with key_store.materialize(machine.id, passphrase) as identity_file:
            admin = administration_machine(machine, identity_file)
            result = install_local_coordinator(
                admin,
                HostKeyStore(args.state_dir),
                TransportStore(args.state_dir),
                passphrase,
                state_dir=args.state_dir,
                engine_dir=args.engine_dir,
                coordinator_binary=args.coordinator_binary,
                observer_binary=args.daemon_binary,
                recovery_kit=args.recovery_kit,
                address=args.address,
                port=args.port,
            )
        print(result)
        return 0
    if args.command == "coordination" and args.coordination_command == "install-distant":
        declaration = load_declaration(args.declaration)
        coordinator = declaration.machine(args.id)
        print(distant_coordination_plan(
            coordinator,
            args.endpoint,
            args.listen_address,
            args.port,
        ))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après préparation du pare-feu.")
            return 3
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        key_store = AdminKeyStore(args.state_dir)
        with key_store.materialize(coordinator.id, passphrase) as identity_file:
            admin = administration_machine(coordinator, identity_file)
            result = install_distant_coordinator(
                admin,
                HostKeyStore(args.state_dir),
                TransportStore(args.state_dir),
                passphrase,
                state_dir=args.state_dir,
                engine_dir=args.engine_dir,
                coordinator_binary=args.coordinator_binary,
                recovery_kit=args.recovery_kit,
                endpoint=args.endpoint,
                listen_address=args.listen_address,
                port=args.port,
            )
        print(result)
        return 0
    if args.command == "coordination" and args.coordination_command == "migrate-pilot":
        declaration = load_declaration(args.declaration)
        pilot = declaration.machine(args.id)
        coordinator = declaration.machine(args.coordinator)
        if pilot.id == coordinator.id:
            raise ConsoleError("le pilote distant doit être distinct du coordinateur")
        print(pilot_migration_plan(pilot, coordinator.id, args.endpoint, args.port))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification du pilote.")
            return 3
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        key_store = AdminKeyStore(args.state_dir)
        with key_store.materialize(pilot.id, passphrase) as identity_file:
            admin = administration_machine(pilot, identity_file)
            result = authorize_pilot_coordinator(
                admin,
                coordinator.id,
                args.endpoint,
                args.port,
                HostKeyStore(args.state_dir),
                TransportStore(args.state_dir),
                passphrase,
                engine_dir=args.engine_dir,
            )
        print(result)
        return 0
    if args.command == "coordination" and args.coordination_command == "retire-point":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        print(point_retirement_plan(machine, args.endpoint, args.port))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après preuve du nouveau point.")
            return 3
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        key_store = AdminKeyStore(args.state_dir)
        with key_store.materialize(machine.id, passphrase) as identity_file:
            admin = administration_machine(machine, identity_file)
            result = retire_coordinator_point(
                admin,
                args.endpoint,
                args.port,
                HostKeyStore(args.state_dir),
                engine_dir=args.engine_dir,
            )
        print(result)
        return 0
    if args.command == "coordination" and args.coordination_command == "inspect":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        encoded = fetch_current(
            machine.id, args.url, TransportStore(args.state_dir), passphrase
        )
        state = verify_state(machine.id, encoded, IdentityStore(args.state_dir))
        rendered = state_to_dict(state, machine.infrastructure_id)
        if args.json:
            print(json.dumps(rendered, ensure_ascii=False, indent=2))
        else:
            print(
                f"Machine : {rendered['machine_id']}\n"
                f"Provenance : coordinateur-mtls + {rendered['provenance']}\n"
                f"État : {rendered['freshness']} (séquence {rendered['sequence']}, "
                f"observé {rendered['observed_at']})"
            )
        return 0
    if args.command == "coordination" and args.coordination_command == "journal":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        passphrase = read_passphrase(args.passphrase_file, confirm=False)
        encoded, next_sequence, has_more = fetch_events(
            machine.id,
            args.url,
            TransportStore(args.state_dir),
            passphrase,
            after=args.after,
            limit=args.limit,
        )
        identity_store = IdentityStore(args.state_dir)
        events = [verify_event(machine.id, item, identity_store) for item in encoded]
        rendered = {
            "machine_id": machine.id,
            "events": [
                {
                    "sequence": event.sequence,
                    "observed_at_unix": event.observed_at_unix,
                    "kind": event.kind,
                    "detail": event.detail,
                    "gap_from_sequence": event.gap_from_sequence,
                    "gap_to_sequence": event.gap_to_sequence,
                    "provenance": "signature-ed25519-verified",
                }
                for event in events
            ],
            "next_after_sequence": next_sequence,
            "has_more": has_more,
        }
        if args.json:
            print(json.dumps(rendered, ensure_ascii=False, indent=2))
        else:
            print(
                f"Journal de {machine.id} : {len(events)} événement(s) signé(s), "
                f"suite après {next_sequence}, autre page : {'oui' if has_more else 'non'}"
            )
        return 0
    if args.command == "component" and args.component_command == "update":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        if not args.pilot:
            raise ConsoleError("la mise à jour exige une machine pilote explicite avec --pilot")
        print(update_plan(args.kind, machine, args.binary, args.version, args.sha256))
        if not args.approve:
            print("Plan non appliqué : relancer avec --approve après vérification.")
            return 3
        host_store = HostKeyStore(args.state_dir)
        verify_or_pin_host_key(machine, host_store)
        with machine_access(
            machine, args.state_dir, args.passphrase_file
        ) as access:
            print(apply_update(
                args.kind,
                access,
                host_store,
                UpdateStore(args.state_dir),
                binary=args.binary,
                expected_sha256=args.sha256,
                version=args.version,
                engine_dir=args.engine_dir,
            ))
        return 0
    if args.command == "component" and args.component_command == "resources":
        declaration = load_declaration(args.declaration)
        machine = declaration.machine(args.id)
        host_store = HostKeyStore(args.state_dir)
        verify_or_pin_host_key(machine, host_store)
        with machine_access(
            machine, args.state_dir, args.passphrase_file
        ) as access:
            measured = measure_resources(args.kind, access, host_store)
        if args.json:
            print(json.dumps(measured, ensure_ascii=False, indent=2))
        else:
            database = measured["database"]
            print(
                f"Ressources {args.kind} sur {args.id} : "
                f"mémoire {measured['memory_current_bytes']} octets "
                f"(pic {measured['memory_peak_bytes']}, plafond {measured['memory_max_bytes']}), "
                f"tâches {measured['tasks_current']}/{measured['tasks_max']}, "
                f"SQLite {database['bytes']}/{database['limit_bytes']} octets, "
                f"budget {'respecté' if measured['within_budget'] else 'DÉPASSÉ'}"
            )
        return 0 if measured["within_budget"] else 3
    if args.command == "serve":
        serve(args.socket, args.declaration)
        return 0
    raise ConsoleError("commande non prise en charge")


def main(argv: list[str] | None = None) -> int:
    """Traduit les refus attendus en messages courts et codes de sortie stables."""

    parser = build_parser()
    try:
        return run(parser.parse_args(argv))
    except ConsoleError as error:
        print(f"REFUS : {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"REFUS : erreur système bornée : {error}", file=sys.stderr)
        return 2
