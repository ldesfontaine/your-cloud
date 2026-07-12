"""Registre d'identités et vérification indépendante de la télémétrie signée."""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from google.protobuf.message import DecodeError

from .errors import TelemetryError
from .protocol import telemetrie_pb2


IDENTITY_SCHEMA_VERSION = 2
MAX_ENVELOPE_BYTES = 256 * 1024
SIGNATURE_DOMAIN = b"your-cloud.telemetry.v1\x00"


@dataclass(frozen=True)
class MachineIdentity:
    """Identité publique approuvée et dernières séquences acceptées d'une machine."""

    key_id: str
    algorithm: str
    public_key: str
    status: str
    approved_at: str
    revoked_at: str | None
    state_sequence: int
    event_sequence: int


class IdentityStore:
    """Autorité locale sur les identités actives, remplacées et révoquées."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.path = state_dir / "machine_identities.json"

    def _empty(self) -> dict[str, Any]:
        return {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "identities": {},
            "pending": {},
            "history": {},
        }

    def load(self) -> dict[str, Any]:
        """Charge le registre et valide chaque identité avant utilisation."""

        if not self.path.exists():
            return self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise TelemetryError(
                f"registre d'identités invalide : ligne {error.lineno}, colonne {error.colno}"
            ) from error
        if not isinstance(raw, dict) or raw.get("schema_version") not in {1, 2}:
            raise TelemetryError("registre d'identités incomplet")
        if raw["schema_version"] == 1:
            if set(raw) != {"schema_version", "identities"}:
                raise TelemetryError("registre d'identités incomplet")
            raw = {
                "schema_version": 2,
                "identities": raw["identities"],
                "pending": {},
                "history": {},
            }
        if set(raw) != {"schema_version", "identities", "pending", "history"}:
            raise TelemetryError("registre d'identités incomplet")
        if not all(isinstance(raw[field], dict) for field in ("identities", "pending", "history")):
            raise TelemetryError("version inconnue du registre d'identités")
        for machine_id, item in raw["identities"].items():
            self._parse(machine_id, item)
        for machine_id, item in raw["pending"].items():
            identity = self._parse(machine_id, item)
            if identity.status != "pending":
                raise TelemetryError(f"identité candidate invalide pour {machine_id}")
        for machine_id, items in raw["history"].items():
            if not isinstance(items, list):
                raise TelemetryError(f"historique d'identités invalide pour {machine_id}")
            for item in items:
                identity = self._parse(machine_id, item)
                if identity.status not in {"replaced", "revoked"}:
                    raise TelemetryError(f"historique d'identités invalide pour {machine_id}")
        return raw

    def _parse(self, machine_id: str, item: Any) -> MachineIdentity:
        expected = {
            "key_id", "algorithm", "public_key", "status", "approved_at", "revoked_at",
            "state_sequence", "event_sequence",
        }
        if not isinstance(item, dict) or set(item) != expected:
            raise TelemetryError(f"identité invalide pour {machine_id}")
        if item["algorithm"] != "Ed25519" or item["status"] not in {
            "active", "pending", "replaced", "revoked"
        }:
            raise TelemetryError(f"identité invalide pour {machine_id}")
        if not all(isinstance(item[field], str) and item[field] for field in ("key_id", "public_key", "approved_at")):
            raise TelemetryError(f"identité invalide pour {machine_id}")
        if item["revoked_at"] is not None and not isinstance(item["revoked_at"], str):
            raise TelemetryError(f"identité invalide pour {machine_id}")
        if any(isinstance(item[field], bool) or not isinstance(item[field], int) or item[field] < 0 for field in ("state_sequence", "event_sequence")):
            raise TelemetryError(f"séquence invalide pour {machine_id}")
        return MachineIdentity(**item)

    def get(self, machine_id: str, *, require_active: bool = True) -> MachineIdentity:
        """Retourne l'identité connue en refusant par défaut toute révocation."""

        item = self.load()["identities"].get(machine_id)
        if item is None:
            raise TelemetryError(f"machine non enrôlée : {machine_id}")
        identity = self._parse(machine_id, item)
        if require_active and identity.status != "active":
            raise TelemetryError(f"identité révoquée pour {machine_id}")
        return identity

    def approve(self, machine_id: str, *, key_id: str, algorithm: str, public_key: str) -> MachineIdentity:
        """Approuve une première identité sans permettre son remplacement implicite."""

        if algorithm != "Ed25519":
            raise TelemetryError(f"algorithme d'identité refusé : {algorithm}")
        public = _decode_public_key(public_key)
        expected_key_id = hashlib.sha256(public).hexdigest()
        if key_id != expected_key_id:
            raise TelemetryError("identifiant de clé incohérent avec la clé publique")
        raw = self.load()
        existing = raw["identities"].get(machine_id)
        if existing is not None:
            current = self._parse(machine_id, existing)
            if current.status == "active" and current.key_id != key_id:
                raise TelemetryError("une autre identité active existe ; renouvellement explicite requis")
            if current.status == "revoked":
                raise TelemetryError("identité révoquée ; renouvellement explicite requis")
            return current
        identity = MachineIdentity(
            key_id=key_id,
            algorithm=algorithm,
            public_key=public_key,
            status="active",
            approved_at=datetime.now(timezone.utc).isoformat(),
            revoked_at=None,
            state_sequence=0,
            event_sequence=0,
        )
        raw["identities"][machine_id] = asdict(identity)
        self._write(raw)
        return identity

    def revoke(self, machine_id: str) -> MachineIdentity:
        """Révoque localement une identité sans muter la machine distante."""

        raw = self.load()
        current = self.get(machine_id, require_active=False)
        if current.status == "revoked":
            return current
        revoked = MachineIdentity(**{
            **asdict(current), "status": "revoked", "revoked_at": datetime.now(timezone.utc).isoformat()
        })
        raw["identities"][machine_id] = asdict(revoked)
        self._write(raw)
        return revoked

    def prepare_renewal(
        self, machine_id: str, *, key_id: str, algorithm: str, public_key: str
    ) -> MachineIdentity:
        """Enregistre une candidate distincte sans remplacer l'identité active."""

        current = self.get(machine_id)
        if algorithm != "Ed25519":
            raise TelemetryError(f"algorithme d'identité refusé : {algorithm}")
        public = _decode_public_key(public_key)
        if hashlib.sha256(public).hexdigest() != key_id:
            raise TelemetryError("identifiant de clé incohérent avec la clé publique")
        if current.key_id == key_id:
            raise TelemetryError("la candidate est identique à l'identité active")
        raw = self.load()
        existing = raw["pending"].get(machine_id)
        if existing is not None:
            pending = self._parse(machine_id, existing)
            if pending.key_id != key_id:
                raise TelemetryError("une autre identité candidate existe déjà")
            return pending
        pending = MachineIdentity(
            key_id=key_id,
            algorithm=algorithm,
            public_key=public_key,
            status="pending",
            approved_at=datetime.now(timezone.utc).isoformat(),
            revoked_at=None,
            state_sequence=current.state_sequence,
            event_sequence=current.event_sequence,
        )
        raw["pending"][machine_id] = asdict(pending)
        self._write(raw)
        return pending

    def finalize_renewal(self, machine_id: str, key_id: str) -> MachineIdentity:
        """Active la candidate vérifiée et archive l'ancienne identité."""

        raw = self.load()
        current = self.get(machine_id)
        item = raw["pending"].get(machine_id)
        if item is None:
            raise TelemetryError("aucune identité candidate à finaliser")
        pending = self._parse(machine_id, item)
        if pending.key_id != key_id:
            raise TelemetryError("identité candidate inattendue")
        ended_at = datetime.now(timezone.utc).isoformat()
        replaced = MachineIdentity(**{
            **asdict(current), "status": "replaced", "revoked_at": ended_at,
        })
        active = MachineIdentity(**{
            **asdict(pending), "status": "active", "revoked_at": None,
        })
        raw["history"].setdefault(machine_id, []).append(asdict(replaced))
        raw["identities"][machine_id] = asdict(active)
        del raw["pending"][machine_id]
        self._write(raw)
        return active

    def cancel_renewal(self, machine_id: str, key_id: str) -> None:
        """Oublie une candidate refusée sans modifier l'identité active."""

        raw = self.load()
        item = raw["pending"].get(machine_id)
        if item is None:
            return
        pending = self._parse(machine_id, item)
        if pending.key_id != key_id:
            raise TelemetryError("identité candidate inattendue")
        del raw["pending"][machine_id]
        self._write(raw)

    def for_envelope(self, machine_id: str, key_id: str) -> MachineIdentity:
        """Retourne l'identité active ou la candidate explicitement préparée."""

        raw = self.load()
        current = self.get(machine_id)
        if current.key_id == key_id:
            return current
        pending = raw["pending"].get(machine_id)
        if pending is not None:
            candidate = self._parse(machine_id, pending)
            if candidate.key_id == key_id:
                return candidate
        raise TelemetryError("identité d'enveloppe inconnue ou remplacée")

    def accept_sequence(
        self, machine_id: str, stream: int, sequence: int, *, key_id: str | None = None
    ) -> None:
        """Avance une séquence persistante et refuse rejeu ou retour arrière."""

        raw = self.load()
        current = self.get(machine_id) if key_id is None else self.for_envelope(machine_id, key_id)
        field = {
            telemetrie_pb2.TELEMETRY_STREAM_STATE: "state_sequence",
            telemetrie_pb2.TELEMETRY_STREAM_EVENT: "event_sequence",
        }.get(stream)
        if field is None:
            raise TelemetryError("flux de télémétrie inconnu")
        previous = getattr(current, field)
        if sequence <= previous:
            raise TelemetryError(
                f"enveloppe rejouée ou en retour arrière : séquence {sequence}, dernière acceptée {previous}"
            )
        item = asdict(current)
        item[field] = sequence
        target = "pending" if current.status == "pending" else "identities"
        raw[target][machine_id] = item
        self._write(raw)

    def _write(self, value: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)


def _decode_public_key(value: str) -> bytes:
    try:
        public = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise TelemetryError("clé publique illisible") from error
    if len(public) != 32:
        raise TelemetryError("clé publique Ed25519 invalide")
    return public


def decode_envelope(value: str | bytes) -> bytes:
    """Décode une enveloppe base64 bornée issue de l'inspection ponctuelle."""

    encoded = value.encode("ascii") if isinstance(value, str) else value
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise TelemetryError("enveloppe base64 illisible") from error
    if not raw or len(raw) > MAX_ENVELOPE_BYTES:
        raise TelemetryError("taille d'enveloppe invalide")
    return raw


def verify_state(
    machine_id: str,
    envelope_bytes: bytes,
    store: IdentityStore,
    *,
    record_sequence: bool = True,
) -> telemetrie_pb2.MachineState:
    """Vérifie identité, signature, contenu et séquence d'un état machine."""

    if not envelope_bytes or len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        raise TelemetryError("taille d'enveloppe invalide")
    envelope = telemetrie_pb2.SignedEnvelope()
    try:
        envelope.ParseFromString(envelope_bytes)
    except DecodeError as error:
        raise TelemetryError("enveloppe Protobuf invalide") from error
    if envelope.schema_version != 1 or envelope.stream != telemetrie_pb2.TELEMETRY_STREAM_STATE:
        raise TelemetryError("version ou flux d'enveloppe refusé")
    identity = store.for_envelope(machine_id, envelope.key_id)
    public = Ed25519PublicKey.from_public_bytes(_decode_public_key(identity.public_key))
    try:
        public.verify(
            envelope.signature,
            SIGNATURE_DOMAIN + bytes((envelope.stream,)) + envelope.payload,
        )
    except InvalidSignature as error:
        raise TelemetryError("signature de télémétrie invalide") from error
    state = telemetrie_pb2.MachineState()
    try:
        state.ParseFromString(envelope.payload)
    except DecodeError as error:
        raise TelemetryError("état Protobuf invalide") from error
    if state.schema_version != 1 or state.machine_id != machine_id or state.sequence < 1:
        raise TelemetryError("contenu signé incohérent avec la machine")
    if state.memory_available_bytes > state.memory_total_bytes or state.root_free_bytes > state.root_total_bytes:
        raise TelemetryError("valeurs de télémétrie incohérentes")
    if len(state.units) > 32:
        raise TelemetryError("trop d'unités dans la télémétrie")
    if record_sequence:
        store.accept_sequence(
            machine_id, envelope.stream, state.sequence, key_id=envelope.key_id
        )
    return state


def verify_event(
    machine_id: str,
    envelope_bytes: bytes,
    store: IdentityStore,
    *,
    record_sequence: bool = True,
) -> telemetrie_pb2.MachineEvent:
    """Vérifie un événement signé et la cohérence d'un éventuel marqueur de lacune."""

    if not envelope_bytes or len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        raise TelemetryError("taille d'enveloppe invalide")
    envelope = telemetrie_pb2.SignedEnvelope()
    try:
        envelope.ParseFromString(envelope_bytes)
    except DecodeError as error:
        raise TelemetryError("enveloppe Protobuf invalide") from error
    if envelope.schema_version != 1 or envelope.stream != telemetrie_pb2.TELEMETRY_STREAM_EVENT:
        raise TelemetryError("version ou flux d'enveloppe refusé")
    identity = store.for_envelope(machine_id, envelope.key_id)
    public = Ed25519PublicKey.from_public_bytes(_decode_public_key(identity.public_key))
    try:
        public.verify(
            envelope.signature,
            SIGNATURE_DOMAIN + bytes((envelope.stream,)) + envelope.payload,
        )
    except InvalidSignature as error:
        raise TelemetryError("signature de télémétrie invalide") from error
    event = telemetrie_pb2.MachineEvent()
    try:
        event.ParseFromString(envelope.payload)
    except DecodeError as error:
        raise TelemetryError("événement Protobuf invalide") from error
    if (
        event.schema_version != 1
        or event.machine_id != machine_id
        or event.sequence < 1
        or not event.kind
        or len(event.kind) > 128
        or len(event.detail) > 1024
    ):
        raise TelemetryError("événement signé incohérent avec la machine")
    if event.kind == "telemetry-gap" and (
        event.gap_from_sequence < 1 or event.gap_to_sequence < event.gap_from_sequence
    ):
        raise TelemetryError("marqueur de lacune incohérent")
    if record_sequence:
        store.accept_sequence(
            machine_id, envelope.stream, event.sequence, key_id=envelope.key_id
        )
    return event


def state_to_dict(state: telemetrie_pb2.MachineState, infrastructure_id: str | None) -> dict[str, Any]:
    """Produit la vue lisible d'un état déjà authentifié par la console."""

    age = max(0, int(datetime.now(timezone.utc).timestamp()) - state.observed_at_unix)
    return {
        "machine_id": state.machine_id,
        "assignment": infrastructure_id or "available",
        "provenance": "signature-ed25519-verified",
        "sequence": state.sequence,
        "observed_at": datetime.fromtimestamp(state.observed_at_unix, timezone.utc).isoformat(),
        "freshness": "delayed" if age > 180 else "recent",
        "age_seconds": age,
        "daemon_version": state.daemon_version,
        "system": {
            "debian_version": state.debian_version,
            "kernel": state.kernel_release,
            "boot_id": state.boot_id,
            "booted_at": datetime.fromtimestamp(state.booted_at_unix, timezone.utc).isoformat(),
            "uptime_seconds": state.uptime_seconds,
        },
        "load_1": state.load_1,
        "memory": {
            "total_bytes": state.memory_total_bytes,
            "available_bytes": state.memory_available_bytes,
            "used_bytes": state.memory_used_bytes,
        },
        "root_filesystem": {
            "total_bytes": state.root_total_bytes,
            "free_bytes": state.root_free_bytes,
            "used_bytes": state.root_used_bytes,
        },
        "security_reboot_required": state.security_reboot_required,
        "units": [{"name": unit.name, "active_state": unit.active_state} for unit in state.units],
    }
