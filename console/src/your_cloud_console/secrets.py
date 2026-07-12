"""Secrets chiffrés de la console et kit de récupération vérifiable."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterator

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import SecurityError


RECOVERY_SCHEMA_VERSION = 1
MIN_PASSPHRASE_BYTES = 16
MAX_PASSPHRASE_BYTES = 1024
MACHINE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
TRANSPORT_FILE_PATTERN = re.compile(
    r"^(?:console|coordinator|daemon)-[a-z0-9][a-z0-9-]{0,62}\.(?:key|crt)$"
)


def read_passphrase(path: Path | None, *, confirm: bool) -> bytes:
    """Lit un mot de passe interactif ou un fichier local strictement privé."""

    if path is None:
        first = getpass.getpass("Mot de passe du stockage chiffré : ").encode("utf-8")
        if confirm:
            second = getpass.getpass("Confirmer le mot de passe : ").encode("utf-8")
            if first != second:
                raise SecurityError("les mots de passe ne correspondent pas")
        value = first
    else:
        try:
            metadata = path.stat()
        except FileNotFoundError as error:
            raise SecurityError(f"fichier de mot de passe absent : {path}") from error
        if not path.is_file() or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
            raise SecurityError(
                "le fichier de mot de passe doit être régulier, privé et possédé par l'opérateur"
            )
        if metadata.st_size > MAX_PASSPHRASE_BYTES:
            raise SecurityError("fichier de mot de passe trop grand")
        value = path.read_bytes().rstrip(b"\r\n")
    if not MIN_PASSPHRASE_BYTES <= len(value) <= MAX_PASSPHRASE_BYTES:
        raise SecurityError(f"le mot de passe doit contenir au moins {MIN_PASSPHRASE_BYTES} octets")
    return value


class AdminKeyStore:
    """Conserve les clés d'administration chiffrées hors de la déclaration."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.keys_dir = state_dir / "admin_keys"

    def private_path(self, machine_id: str) -> Path:
        """Retourne le chemin durable de la clé chiffrée d'une machine."""

        return self.keys_dir / f"{machine_id}.key"

    def _protect_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        self.keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.keys_dir, 0o700)

    def create_with_recovery_kit(
        self,
        machine_id: str,
        declaration_path: Path,
        kit_path: Path,
        passphrase: bytes,
    ) -> str:
        """Crée une clé dédiée et un kit vérifié avant de publier la clé."""

        self._protect_dirs()
        private_path = self.private_path(machine_id)
        if private_path.exists():
            raise SecurityError(f"clé d'administration déjà présente pour {machine_id}")
        if kit_path.exists():
            raise SecurityError(f"refus d'écraser le kit existant : {kit_path}")
        private = Ed25519PrivateKey.generate()
        encrypted = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.BestAvailableEncryption(passphrase),
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("ascii")
        temporary = private_path.with_name(f".{private_path.name}.tmp")
        temporary.write_bytes(encrypted)
        os.chmod(temporary, 0o600)
        temporary.replace(private_path)
        try:
            kit = {
                "schema_version": RECOVERY_SCHEMA_VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "machine_id": machine_id,
                "encrypted_admin_key": base64.b64encode(encrypted).decode("ascii"),
                "admin_public_key": public,
                "declaration": self._load_public_json(declaration_path, "déclaration"),
                "host_keys": self._load_optional_public_json(self.state_dir / "host_keys.json"),
                "machine_identities": self._load_optional_public_json(
                    self.state_dir / "machine_identities.json"
                ),
            }
            kit_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            kit_parent = kit_path.parent.stat()
            if kit_parent.st_mode & 0o077 or kit_parent.st_uid != os.geteuid():
                raise SecurityError("le répertoire du kit doit être privé et possédé par l'opérateur")
            kit_temporary = kit_path.with_name(f".{kit_path.name}.tmp")
            kit_temporary.write_text(json.dumps(kit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.chmod(kit_temporary, 0o600)
            kit_temporary.replace(kit_path)
            self.verify_recovery_kit(kit_path, passphrase)
        except Exception:
            private_path.unlink(missing_ok=True)
            kit_path.unlink(missing_ok=True)
            raise
        return public

    def _load_public_json(self, path: Path, label: str) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise SecurityError(f"{label} absente : {path}") from error
        except json.JSONDecodeError as error:
            raise SecurityError(f"{label} JSON invalide : {path}") from error

    def _load_optional_public_json(self, path: Path) -> Any:
        if not path.exists():
            return None
        return self._load_public_json(path, "registre public")

    def verify_recovery_kit(self, kit_path: Path, passphrase: bytes) -> str:
        """Prouve que le kit peut restaurer ses clés et certificats chiffrés."""

        try:
            raw = json.loads(kit_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as error:
            raise SecurityError(f"kit de récupération illisible : {kit_path}") from error
        expected_v1 = {
            "schema_version", "created_at", "machine_id", "encrypted_admin_key",
            "admin_public_key", "declaration", "host_keys", "machine_identities",
        }
        expected_v2 = {*expected_v1, "transport_authority"}
        expected_v3 = {
            "schema_version", "created_at", "refreshed_at", "encrypted_admin_keys",
            "declaration", "host_keys", "machine_identities",
        }
        if not isinstance(raw, dict) or raw.get("schema_version") not in {1, 2, 3}:
            raise SecurityError("kit de récupération incomplet ou de version inconnue")
        expected = expected_v1 if raw["schema_version"] == 1 else expected_v2
        if raw["schema_version"] == 3:
            optional = {
                "transport_authority", "transport_identities", "runtime_registries"
            } & set(raw)
            expected = expected_v3 | optional
        if set(raw) != expected:
            raise SecurityError("kit de récupération incomplet ou de version inconnue")
        if raw["schema_version"] == 3:
            keys = raw["encrypted_admin_keys"]
            if not isinstance(keys, dict) or not keys:
                raise SecurityError("kit de récupération sans clé d'administration")
            first_public: str | None = None
            for machine_id, encoded in keys.items():
                if not isinstance(machine_id, str) or not MACHINE_ID_PATTERN.fullmatch(machine_id):
                    raise SecurityError("identifiant de machine invalide dans le kit")
                try:
                    encrypted = base64.b64decode(encoded, validate=True)
                    private = serialization.load_ssh_private_key(encrypted, password=passphrase)
                except (ValueError, TypeError) as error:
                    raise SecurityError("mot de passe ou clé du kit invalide") from error
                if not isinstance(private, Ed25519PrivateKey):
                    raise SecurityError("algorithme de clé du kit refusé")
                public = private.public_key().public_bytes(
                    serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
                ).decode("ascii")
                first_public = first_public or public
            if "transport_authority" in raw:
                self._verify_transport_authority(raw["transport_authority"], passphrase)
            if "transport_identities" in raw:
                self._decode_transport_identities(raw["transport_identities"], passphrase)
            if "runtime_registries" in raw and not isinstance(
                raw["runtime_registries"], dict
            ):
                raise SecurityError("registres runtime invalides dans le kit")
            return first_public or ""
        try:
            encrypted = base64.b64decode(raw["encrypted_admin_key"], validate=True)
            private = serialization.load_ssh_private_key(encrypted, password=passphrase)
        except (ValueError, TypeError) as error:
            raise SecurityError("mot de passe ou clé du kit invalide") from error
        if not isinstance(private, Ed25519PrivateKey):
            raise SecurityError("algorithme de clé du kit refusé")
        public = private.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("ascii")
        if public != raw["admin_public_key"]:
            raise SecurityError("clé publique incohérente dans le kit")
        if raw["schema_version"] == 2:
            self._verify_transport_authority(raw["transport_authority"], passphrase)
        return public

    def _verify_transport_authority(self, authority: Any, passphrase: bytes) -> None:
        if not isinstance(authority, dict) or set(authority) != {
            "encrypted_private_key", "certificate_pem"
        }:
            raise SecurityError("autorité de transport invalide dans le kit")
        try:
            authority_private = serialization.load_pem_private_key(
                base64.b64decode(authority["encrypted_private_key"], validate=True),
                password=passphrase,
            )
            authority_certificate = x509.load_pem_x509_certificate(
                authority["certificate_pem"].encode("ascii")
            )
        except (ValueError, TypeError, UnicodeError) as error:
            raise SecurityError("autorité de transport illisible dans le kit") from error
        if not isinstance(authority_private, Ed25519PrivateKey):
            raise SecurityError("algorithme de l'autorité de transport refusé")
        private_public = authority_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        certificate_public = authority_certificate.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if private_public != certificate_public:
            raise SecurityError("certificat incohérent avec l'autorité de transport")

    def _decode_transport_identities(
        self, identities: Any, passphrase: bytes
    ) -> dict[str, bytes]:
        """Valide les identités de rôle sauvegardées sans les exposer en clair."""

        if not isinstance(identities, dict) or not identities:
            raise SecurityError("identités de transport absentes ou invalides dans le kit")
        decoded: dict[str, bytes] = {}
        for name, encoded in identities.items():
            if not isinstance(name, str) or not TRANSPORT_FILE_PATTERN.fullmatch(name):
                raise SecurityError("nom d'identité de transport invalide dans le kit")
            try:
                value = base64.b64decode(encoded, validate=True)
                if name.endswith(".key"):
                    private = serialization.load_pem_private_key(value, password=passphrase)
                    if not isinstance(private, Ed25519PrivateKey):
                        raise SecurityError("algorithme d'identité de transport refusé")
                else:
                    x509.load_pem_x509_certificate(value)
            except (ValueError, TypeError) as error:
                raise SecurityError(f"identité de transport illisible : {name}") from error
            decoded[name] = value
        stems = {name.rsplit(".", 1)[0] for name in decoded}
        if any(
            f"{stem}.key" not in decoded or f"{stem}.crt" not in decoded
            for stem in stems
        ):
            raise SecurityError("paire d'identité de transport incomplète dans le kit")
        if "console-local.key" not in decoded:
            raise SecurityError("identité de transport de la console absente du kit")
        return decoded

    def refresh_recovery_kit(
        self,
        declaration_path: Path,
        kit_path: Path,
        passphrase: bytes,
    ) -> int:
        """Remplace un kit vérifié par un instantané complet de la console."""

        self.verify_recovery_kit(kit_path, passphrase)
        try:
            current = json.loads(kit_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as error:
            raise SecurityError(f"kit de récupération illisible : {kit_path}") from error
        encrypted_admin_keys: dict[str, str] = {}
        if self.keys_dir.exists():
            for path in sorted(self.keys_dir.glob("*.key")):
                machine_id = path.stem
                if not MACHINE_ID_PATTERN.fullmatch(machine_id) or not path.is_file():
                    raise SecurityError(f"clé d'administration au nom invalide : {path.name}")
                encrypted = path.read_bytes()
                try:
                    private = serialization.load_ssh_private_key(encrypted, password=passphrase)
                except (ValueError, TypeError) as error:
                    raise SecurityError(
                        f"clé d'administration illisible pour {machine_id}"
                    ) from error
                if not isinstance(private, Ed25519PrivateKey):
                    raise SecurityError(
                        f"algorithme de clé d'administration refusé pour {machine_id}"
                    )
                encrypted_admin_keys[machine_id] = base64.b64encode(encrypted).decode("ascii")
        if not encrypted_admin_keys:
            raise SecurityError("aucune clé d'administration à placer dans le kit")
        refreshed: dict[str, Any] = {
            "schema_version": 3,
            "created_at": current["created_at"],
            "refreshed_at": datetime.now(timezone.utc).isoformat(),
            "encrypted_admin_keys": encrypted_admin_keys,
            "declaration": self._load_public_json(declaration_path, "déclaration"),
            "host_keys": self._load_optional_public_json(self.state_dir / "host_keys.json"),
            "machine_identities": self._load_optional_public_json(
                self.state_dir / "machine_identities.json"
            ),
            "runtime_registries": {
                name: value
                for name in ("failure_domains", "updates")
                if (value := self._load_optional_public_json(
                    self.state_dir / f"{name}.json"
                )) is not None
            },
        }
        transport_key = self.state_dir / "transport" / "ca.key"
        transport_certificate = self.state_dir / "transport" / "ca.crt"
        if transport_key.exists() != transport_certificate.exists():
            raise SecurityError("autorité de transport incomplète")
        if transport_key.exists():
            encrypted = transport_key.read_bytes()
            certificate_pem = transport_certificate.read_text(encoding="ascii")
            try:
                private = serialization.load_pem_private_key(encrypted, password=passphrase)
                certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
            except (ValueError, TypeError, UnicodeError) as error:
                raise SecurityError("autorité de transport illisible") from error
            if not isinstance(private, Ed25519PrivateKey):
                raise SecurityError("algorithme de l'autorité de transport refusé")
            if private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ) != certificate.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ):
                raise SecurityError("certificat incohérent avec l'autorité de transport")
            refreshed["transport_authority"] = {
                "encrypted_private_key": base64.b64encode(encrypted).decode("ascii"),
                "certificate_pem": certificate_pem,
            }
            leaves_dir = self.state_dir / "transport" / "leaves"
            transport_identities: dict[str, str] = {}
            if leaves_dir.is_dir():
                for path in sorted(leaves_dir.iterdir()):
                    if path.is_dir() and path.name == ".runtime":
                        continue
                    if not path.is_file() or not TRANSPORT_FILE_PATTERN.fullmatch(path.name):
                        raise SecurityError(
                            f"fichier d'identité de transport invalide : {path.name}"
                        )
                    transport_identities[path.name] = base64.b64encode(
                        path.read_bytes()
                    ).decode("ascii")
            self._decode_transport_identities(transport_identities, passphrase)
            refreshed["transport_identities"] = transport_identities
        temporary = kit_path.with_name(f".{kit_path.name}.tmp")
        temporary.write_text(
            json.dumps(refreshed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(kit_path)
        self.verify_recovery_kit(kit_path, passphrase)
        return len(encrypted_admin_keys)

    def restore_recovery_kit(
        self,
        declaration_path: Path,
        kit_path: Path,
        passphrase: bytes,
    ) -> int:
        """Restaure un kit complet dans des emplacements console encore vierges."""

        self.verify_recovery_kit(kit_path, passphrase)
        try:
            raw = json.loads(kit_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as error:
            raise SecurityError(f"kit de récupération illisible : {kit_path}") from error
        if raw.get("schema_version") != 3:
            raise SecurityError("actualiser le kit au schéma 3 avant une restauration complète")
        destinations = [
            declaration_path,
            self.state_dir / "host_keys.json",
            self.state_dir / "machine_identities.json",
            self.state_dir / "transport" / "ca.key",
            self.state_dir / "transport" / "ca.crt",
        ]
        destinations.extend(
            self.state_dir / f"{name}.json"
            for name in raw.get("runtime_registries", {})
        )
        destinations.extend(self.private_path(machine_id) for machine_id in raw["encrypted_admin_keys"])
        if self.state_dir.exists() and any(self.state_dir.iterdir()):
            raise SecurityError(f"répertoire d'état non vierge : {self.state_dir}")
        if declaration_path.exists() or any(path.exists() for path in destinations[1:]):
            raise SecurityError("refus d'écraser un état console existant")
        decoded_keys: dict[str, bytes] = {}
        for machine_id, encoded in raw["encrypted_admin_keys"].items():
            if not MACHINE_ID_PATTERN.fullmatch(machine_id):
                raise SecurityError(f"identifiant de machine invalide dans le kit : {machine_id}")
            try:
                encrypted = base64.b64decode(encoded, validate=True)
                private = serialization.load_ssh_private_key(encrypted, password=passphrase)
            except (ValueError, TypeError) as error:
                raise SecurityError(f"clé restaurée invalide pour {machine_id}") from error
            if not isinstance(private, Ed25519PrivateKey):
                raise SecurityError(f"algorithme restauré refusé pour {machine_id}")
            decoded_keys[machine_id] = encrypted
        from .model import parse_declaration
        from .storage import HostKeyStore

        declaration = parse_declaration(raw["declaration"])
        declared_ids = {machine.id for machine in declaration.machines}
        if not set(decoded_keys) <= declared_ids:
            raise SecurityError("le kit contient une clé pour une machine non déclarée")
        if raw["host_keys"] is not None:
            host_keys = raw["host_keys"]
            if not isinstance(host_keys, dict) or set(host_keys) != {"schema_version", "host_keys"}:
                raise SecurityError("registre de clés d'hôte invalide dans le kit")
            if host_keys["schema_version"] != 1 or not isinstance(host_keys["host_keys"], dict):
                raise SecurityError("registre de clés d'hôte invalide dans le kit")
            validator = HostKeyStore(self.state_dir)
            for machine_id, item in host_keys["host_keys"].items():
                if machine_id not in declared_ids:
                    raise SecurityError("clé d'hôte liée à une machine non déclarée")
                validator._parse_item(machine_id, item)
        if raw["machine_identities"] is not None:
            identities = raw["machine_identities"]
            if not isinstance(identities, dict) or identities.get("schema_version") not in {1, 2}:
                raise SecurityError("registre d'identités invalide dans le kit")
            expected_root = {"schema_version", "identities"}
            if identities["schema_version"] == 2:
                expected_root |= {"pending", "history"}
            if set(identities) != expected_root or not isinstance(
                identities["identities"], dict
            ):
                raise SecurityError("registre d'identités invalide dans le kit")
            sections: list[tuple[str, Any]] = [("identities", identities["identities"])]
            if identities["schema_version"] == 2:
                if not isinstance(identities["pending"], dict) or not isinstance(
                    identities["history"], dict
                ):
                    raise SecurityError("registre d'identités invalide dans le kit")
                sections.append(("pending", identities["pending"]))
                sections.append(("history", identities["history"]))
            for section, values in sections:
                for machine_id, value in values.items():
                    if machine_id not in declared_ids:
                        raise SecurityError("identité liée à une machine non déclarée")
                    items = value if section == "history" else [value]
                    if not isinstance(items, list):
                        raise SecurityError(f"historique d'identités invalide pour {machine_id}")
                    for item in items:
                        self._validate_recovery_identity(machine_id, item, section)
        runtime_registries = raw.get("runtime_registries", {})
        if not isinstance(runtime_registries, dict) or not set(runtime_registries) <= {
            "failure_domains", "updates"
        }:
            raise SecurityError("registres runtime invalides dans le kit")
        if not all(isinstance(value, dict) for value in runtime_registries.values()):
            raise SecurityError("registre runtime invalide dans le kit")
        decoded_transport: dict[str, bytes] = {}
        if "transport_authority" in raw:
            if "transport_identities" not in raw:
                raise SecurityError(
                    "actualiser le kit avant restauration pour inclure l'identité de console"
                )
            decoded_transport = self._decode_transport_identities(
                raw["transport_identities"], passphrase
            )
        self._protect_dirs()
        declaration_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._write_json_private(declaration_path, raw["declaration"])
        for name in ("host_keys", "machine_identities"):
            if raw[name] is not None:
                self._write_json_private(self.state_dir / f"{name}.json", raw[name])
        for name, value in runtime_registries.items():
            self._write_json_private(self.state_dir / f"{name}.json", value)
        for machine_id, encrypted in decoded_keys.items():
            self._write_private_bytes(self.private_path(machine_id), encrypted)
        authority = raw.get("transport_authority")
        if authority is not None:
            transport = self.state_dir / "transport"
            transport.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(transport, 0o700)
            self._write_private_bytes(
                transport / "ca.key",
                base64.b64decode(authority["encrypted_private_key"], validate=True),
            )
            self._write_private_bytes(
                transport / "ca.crt", authority["certificate_pem"].encode("ascii")
            )
            leaves = transport / "leaves"
            leaves.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(leaves, 0o700)
            for name, value in decoded_transport.items():
                self._write_private_bytes(leaves / name, value)
        return len(decoded_keys)

    def _validate_recovery_identity(
        self, machine_id: str, item: Any, section: str
    ) -> None:
        """Valide une entrée du registre sans importer la pile Protobuf."""

        expected_identity = {
            "key_id", "algorithm", "public_key", "status", "approved_at",
            "revoked_at", "state_sequence", "event_sequence",
        }
        if not isinstance(item, dict) or set(item) != expected_identity:
            raise SecurityError(f"identité invalide pour {machine_id}")
        allowed = {
            "identities": {"active", "revoked"},
            "pending": {"pending"},
            "history": {"replaced", "revoked"},
        }[section]
        if item["algorithm"] != "Ed25519" or item["status"] not in allowed:
            raise SecurityError(f"identité invalide pour {machine_id}")
        if not all(
            isinstance(item[field], str) and item[field]
            for field in ("key_id", "public_key", "approved_at")
        ):
            raise SecurityError(f"identité invalide pour {machine_id}")
        if item["revoked_at"] is not None and not isinstance(
            item["revoked_at"], str
        ):
            raise SecurityError(f"identité invalide pour {machine_id}")
        if any(
            isinstance(item[field], bool)
            or not isinstance(item[field], int)
            or item[field] < 0
            for field in ("state_sequence", "event_sequence")
        ):
            raise SecurityError(f"séquence invalide pour {machine_id}")

    def _write_json_private(self, path: Path, value: Any) -> None:
        self._write_private_bytes(
            path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )

    def _write_private_bytes(self, path: Path, value: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(value)
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    def attach_transport_authority(
        self,
        kit_path: Path,
        passphrase: bytes,
        encrypted_private_key: Path,
        certificate_path: Path,
    ) -> None:
        """Migre le kit pour y joindre l'autorité mTLS encore chiffrée."""

        self.verify_recovery_kit(kit_path, passphrase)
        try:
            raw = json.loads(kit_path.read_text(encoding="utf-8"))
            encrypted = encrypted_private_key.read_bytes()
            certificate_pem = certificate_path.read_text(encoding="ascii")
            private = serialization.load_pem_private_key(encrypted, password=passphrase)
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        except (FileNotFoundError, json.JSONDecodeError, ValueError, TypeError) as error:
            raise SecurityError("autorité de transport impossible à joindre au kit") from error
        if not isinstance(private, Ed25519PrivateKey):
            raise SecurityError("algorithme de l'autorité de transport refusé")
        attachment = {
            "encrypted_private_key": base64.b64encode(encrypted).decode("ascii"),
            "certificate_pem": certificate_pem,
        }
        if raw["schema_version"] in {2, 3} and "transport_authority" in raw:
            if raw["transport_authority"] != attachment:
                raise SecurityError("le kit contient une autre autorité de transport")
            return
        if raw["schema_version"] == 1:
            raw["schema_version"] = 2
        raw["transport_authority"] = attachment
        temporary = kit_path.with_name(f".{kit_path.name}.tmp")
        temporary.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(kit_path)
        self.verify_recovery_kit(kit_path, passphrase)

    def public_key(self, machine_id: str, passphrase: bytes) -> str:
        """Dérive la clé publique depuis le secret chiffré vérifié."""

        private = self._load_private(machine_id, passphrase)
        return private.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("ascii")

    def _load_private(self, machine_id: str, passphrase: bytes) -> Ed25519PrivateKey:
        try:
            encrypted = self.private_path(machine_id).read_bytes()
            private = serialization.load_ssh_private_key(encrypted, password=passphrase)
        except FileNotFoundError as error:
            raise SecurityError(f"clé d'administration absente pour {machine_id}") from error
        except (ValueError, TypeError) as error:
            raise SecurityError("mot de passe de la clé d'administration invalide") from error
        if not isinstance(private, Ed25519PrivateKey):
            raise SecurityError("algorithme de clé d'administration refusé")
        return private

    @contextmanager
    def materialize(self, machine_id: str, passphrase: bytes) -> Iterator[Path]:
        """Expose brièvement une clé SSH claire puis détruit son fichier temporaire."""

        private = self._load_private(machine_id, passphrase)
        clear = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        runtime_dir = self.keys_dir / ".runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(runtime_dir, 0o700)
        descriptor, name = tempfile.mkstemp(prefix=f"{machine_id}-", dir=runtime_dir)
        path = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(clear)
                handle.flush()
                os.fsync(handle.fileno())
            yield path
        finally:
            path.unlink(missing_ok=True)
