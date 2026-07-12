from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import SecurityError


RECOVERY_SCHEMA_VERSION = 1
MIN_PASSPHRASE_BYTES = 16
MAX_PASSPHRASE_BYTES = 1024


def read_passphrase(path: Path | None, *, confirm: bool) -> bytes:
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
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.keys_dir = state_dir / "admin_keys"

    def private_path(self, machine_id: str) -> Path:
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
        try:
            raw = json.loads(kit_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as error:
            raise SecurityError(f"kit de récupération illisible : {kit_path}") from error
        expected = {
            "schema_version", "created_at", "machine_id", "encrypted_admin_key",
            "admin_public_key", "declaration", "host_keys", "machine_identities",
        }
        if not isinstance(raw, dict) or set(raw) != expected or raw["schema_version"] != 1:
            raise SecurityError("kit de récupération incomplet ou de version inconnue")
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
        return public

    def public_key(self, machine_id: str, passphrase: bytes) -> str:
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
