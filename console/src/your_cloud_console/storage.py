from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

from .errors import HostKeyError


RUNTIME_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PinnedHostKey:
    endpoint: str
    key_type: str
    key: str
    fingerprint: str
    accepted_at: str
    source: str

    @classmethod
    def accepted(
        cls,
        *,
        endpoint: str,
        key_type: str,
        key: str,
        fingerprint: str,
        source: str,
    ) -> "PinnedHostKey":
        return cls(
            endpoint=endpoint,
            key_type=key_type,
            key=key,
            fingerprint=fingerprint,
            accepted_at=datetime.now(timezone.utc).isoformat(),
            source=source,
        )


class HostKeyStore:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.registry_path = state_dir / "host_keys.json"
        self.known_hosts_path = state_dir / "known_hosts"

    def _empty(self) -> dict[str, Any]:
        return {"schema_version": RUNTIME_SCHEMA_VERSION, "host_keys": {}}

    def load(self) -> dict[str, Any]:
        if not self.registry_path.exists():
            return self._empty()
        try:
            raw = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise HostKeyError(
                f"registre de clés d'hôte invalide : ligne {error.lineno}, colonne {error.colno}"
            ) from error
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "host_keys"}:
            raise HostKeyError("registre de clés d'hôte incomplet")
        if raw.get("schema_version") != RUNTIME_SCHEMA_VERSION:
            raise HostKeyError("version inconnue du registre de clés d'hôte")
        keys = raw.get("host_keys")
        if not isinstance(keys, dict):
            raise HostKeyError("registre de clés d'hôte incomplet")
        return raw

    def _parse_item(self, machine_id: str, item: Any) -> PinnedHostKey:
        expected = {"endpoint", "key_type", "key", "fingerprint", "accepted_at", "source"}
        if not isinstance(item, dict) or set(item) != expected:
            raise HostKeyError(f"entrée de clé d'hôte invalide pour {machine_id}")
        if not all(isinstance(item[field], str) and item[field] for field in expected):
            raise HostKeyError(f"entrée de clé d'hôte invalide pour {machine_id}")
        try:
            return PinnedHostKey(**item)
        except TypeError as error:
            raise HostKeyError(f"entrée de clé d'hôte invalide pour {machine_id}") from error

    def get(self, machine_id: str) -> PinnedHostKey | None:
        item = self.load()["host_keys"].get(machine_id)
        if item is None:
            return None
        return self._parse_item(machine_id, item)

    def pin(self, machine_id: str, host_key: PinnedHostKey) -> None:
        raw = self.load()
        raw["host_keys"][machine_id] = asdict(host_key)
        self._write_json(self.registry_path, raw)
        self.render_known_hosts()

    def render_known_hosts(self) -> Path:
        raw = self.load()
        lines = []
        for machine_id in sorted(raw["host_keys"]):
            item = self._parse_item(machine_id, raw["host_keys"][machine_id])
            lines.append(f"{item.endpoint} {item.key_type} {item.key}")
        self._write_text(self.known_hosts_path, "\n".join(lines) + ("\n" if lines else ""))
        return self.known_hosts_path

    def _write_json(self, path: Path, value: dict[str, Any]) -> None:
        self._write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def _write_text(self, path: Path, value: str) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(value, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
