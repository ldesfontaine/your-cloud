"""Modèle strict de la déclaration durable des machines et infrastructures."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import json
from pathlib import Path
import re
from typing import Any

from .errors import DeclarationError


SCHEMA_VERSION = 1
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
DNS_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


@dataclass(frozen=True)
class Infrastructure:
    """Regroupement logique auquel une machine peut être affectée."""

    id: str
    name: str


@dataclass(frozen=True)
class Machine:
    """Machine logique et chemin SSH déclaré pour l'administration."""

    id: str
    address: str
    port: int
    user: str
    identity_file: str
    infrastructure_id: str | None = None

    @property
    def endpoint(self) -> str:
        """Retourne la cible SSH sous une forme stable et comparable."""

        return f"{self.address}:{self.port}"


@dataclass(frozen=True)
class Declaration:
    """Déclaration versionnée, lisible et indépendante de l'état runtime."""

    schema_version: int
    machines: tuple[Machine, ...]
    infrastructures: tuple[Infrastructure, ...]

    def machine(self, machine_id: str) -> Machine:
        """Retourne une machine connue ou refuse un identifiant inconnu."""

        for machine in self.machines:
            if machine.id == machine_id:
                return machine
        raise DeclarationError(f"machine inconnue : {machine_id}")

    def to_dict(self) -> dict[str, Any]:
        """Produit la représentation JSON canonique de la déclaration."""

        return {
            "schema_version": self.schema_version,
            "machines": [asdict(machine) for machine in self.machines],
            "infrastructures": [asdict(infrastructure) for infrastructure in self.infrastructures],
        }


def empty_declaration() -> Declaration:
    """Crée une déclaration vide au schéma actuellement pris en charge."""

    return Declaration(SCHEMA_VERSION, (), ())


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeclarationError(f"{label} doit être un objet JSON")
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        raise DeclarationError(f"{label} contient des champs inconnus : {', '.join(sorted(unknown))}")
    if missing:
        raise DeclarationError(f"{label} omet des champs requis : {', '.join(sorted(missing))}")


def _validate_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise DeclarationError(f"{label} doit respecter {ID_PATTERN.pattern}")
    return value


def _parse_infrastructure(raw: Any, index: int) -> Infrastructure:
    item = _require_object(raw, f"infrastructures[{index}]")
    _require_exact_keys(item, {"id", "name"}, f"infrastructures[{index}]")
    infrastructure_id = _validate_id(item["id"], f"infrastructures[{index}].id")
    name = item["name"]
    if not isinstance(name, str) or not name.strip():
        raise DeclarationError(f"infrastructures[{index}].name doit être un texte non vide")
    return Infrastructure(infrastructure_id, name.strip())


def _parse_machine(raw: Any, index: int) -> Machine:
    item = _require_object(raw, f"machines[{index}]")
    expected = {"id", "address", "port", "user", "identity_file", "infrastructure_id"}
    _require_exact_keys(item, expected, f"machines[{index}]")
    machine_id = _validate_id(item["id"], f"machines[{index}].id")
    address = item["address"]
    if not isinstance(address, str) or not address.strip() or any(char.isspace() for char in address):
        raise DeclarationError(f"machines[{index}].address doit être une adresse ou un nom sans espace")
    address = address.strip()
    try:
        ipaddress.ip_address(address)
    except ValueError:
        if not DNS_PATTERN.fullmatch(address):
            raise DeclarationError(f"machines[{index}].address est invalide") from None
    port = item["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise DeclarationError(f"machines[{index}].port doit être compris entre 1 et 65535")
    user = item["user"]
    if not isinstance(user, str) or not ID_PATTERN.fullmatch(user):
        raise DeclarationError(f"machines[{index}].user est invalide")
    identity_file = item["identity_file"]
    if not isinstance(identity_file, str) or not identity_file.startswith("/"):
        raise DeclarationError(f"machines[{index}].identity_file doit être un chemin absolu")
    infrastructure_id = item["infrastructure_id"]
    if infrastructure_id is not None:
        infrastructure_id = _validate_id(infrastructure_id, f"machines[{index}].infrastructure_id")
    return Machine(machine_id, address, port, user, identity_file, infrastructure_id)


def parse_declaration(raw: Any) -> Declaration:
    """Valide entièrement une déclaration avant de construire son modèle."""

    root = _require_object(raw, "déclaration")
    _require_exact_keys(root, {"schema_version", "machines", "infrastructures"}, "déclaration")
    if root["schema_version"] != SCHEMA_VERSION:
        raise DeclarationError(
            f"schéma {root['schema_version']!r} non pris en charge ; attendu : {SCHEMA_VERSION}"
        )
    if not isinstance(root["machines"], list) or not isinstance(root["infrastructures"], list):
        raise DeclarationError("machines et infrastructures doivent être des listes")
    infrastructures = tuple(
        _parse_infrastructure(item, index) for index, item in enumerate(root["infrastructures"])
    )
    machines = tuple(_parse_machine(item, index) for index, item in enumerate(root["machines"]))

    infrastructure_ids = [item.id for item in infrastructures]
    machine_ids = [item.id for item in machines]
    endpoints = [item.endpoint for item in machines]
    for values, label in (
        (infrastructure_ids, "identifiant d'infrastructure"),
        (machine_ids, "identifiant de machine"),
        (endpoints, "cible SSH"),
    ):
        duplicate = next((value for value in values if values.count(value) > 1), None)
        if duplicate:
            raise DeclarationError(f"{label} ambigu ou dupliqué : {duplicate}")
    known_infrastructures = set(infrastructure_ids)
    for machine in machines:
        if machine.infrastructure_id is not None and machine.infrastructure_id not in known_infrastructures:
            raise DeclarationError(
                f"machine {machine.id} liée à une infrastructure inconnue : {machine.infrastructure_id}"
            )
    return Declaration(SCHEMA_VERSION, machines, infrastructures)


def load_declaration(path: Path) -> Declaration:
    """Charge puis valide une déclaration JSON depuis un chemin explicite."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DeclarationError(f"déclaration absente : {path}") from error
    except json.JSONDecodeError as error:
        raise DeclarationError(f"JSON invalide dans {path} : ligne {error.lineno}, colonne {error.colno}") from error
    return parse_declaration(raw)


def save_declaration(path: Path, declaration: Declaration, *, refuse_existing: bool = False) -> None:
    """Écrit atomiquement une déclaration, avec refus optionnel d'écrasement."""

    if refuse_existing and path.exists():
        raise DeclarationError(f"refus d'écraser la déclaration existante : {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(declaration.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def add_machine(declaration: Declaration, machine: Machine) -> Declaration:
    """Ajoute une machine en repassant par toutes les validations du schéma."""

    candidate = Declaration(
        declaration.schema_version,
        (*declaration.machines, machine),
        declaration.infrastructures,
    )
    return parse_declaration(candidate.to_dict())
