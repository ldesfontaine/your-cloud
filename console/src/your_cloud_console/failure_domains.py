"""État runtime des domaines de panne détectés, séparé de la déclaration."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any

from .errors import FailureDomainError
from .model import FAILURE_DOMAIN_PATTERN, ID_PATTERN, Infrastructure


RUNTIME_SCHEMA_VERSION = 1
SOURCE_PATTERN = FAILURE_DOMAIN_PATTERN


@dataclass(frozen=True)
class DetectedFailureDomain:
    """Constat runtime lié à sa source et à une preuve non sensible."""

    infrastructure_id: str
    name: str
    source: str
    evidence: str
    observed_at: str


class FailureDomainStore:
    """Conserve les détections sans les transformer en intention déclarée."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.path = state_dir / "failure_domains.json"

    def _empty(self) -> dict[str, Any]:
        return {"schema_version": RUNTIME_SCHEMA_VERSION, "detections": {}}

    def load(self) -> dict[str, Any]:
        """Charge le registre strict ou retourne un registre vide."""

        if not self.path.exists():
            return self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise FailureDomainError("registre des domaines détectés invalide") from error
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "detections"}
            or raw.get("schema_version") != RUNTIME_SCHEMA_VERSION
            or not isinstance(raw.get("detections"), dict)
        ):
            raise FailureDomainError("registre des domaines détectés incomplet")
        for infrastructure_id, item in raw["detections"].items():
            self._parse(infrastructure_id, item)
        return raw

    def _parse(self, infrastructure_id: str, item: Any) -> DetectedFailureDomain:
        expected = {"infrastructure_id", "name", "source", "evidence", "observed_at"}
        if (
            not ID_PATTERN.fullmatch(infrastructure_id)
            or not isinstance(item, dict)
            or set(item) != expected
            or item.get("infrastructure_id") != infrastructure_id
            or not isinstance(item.get("name"), str)
            or not FAILURE_DOMAIN_PATTERN.fullmatch(item["name"])
            or not isinstance(item.get("source"), str)
            or not SOURCE_PATTERN.fullmatch(item["source"])
            or not isinstance(item.get("evidence"), str)
            or not item["evidence"].strip()
            or len(item["evidence"]) > 512
            or not isinstance(item.get("observed_at"), str)
            or not item["observed_at"]
        ):
            raise FailureDomainError(
                f"détection de domaine invalide pour {infrastructure_id}"
            )
        try:
            observed_at = datetime.fromisoformat(item["observed_at"])
        except ValueError as error:
            raise FailureDomainError(
                f"horodatage de détection invalide pour {infrastructure_id}"
            ) from error
        if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
            raise FailureDomainError(
                f"horodatage de détection non UTC pour {infrastructure_id}"
            )
        return DetectedFailureDomain(**item)

    def get(self, infrastructure_id: str) -> DetectedFailureDomain | None:
        """Retourne la dernière détection vérifiée d'une infrastructure."""

        item = self.load()["detections"].get(infrastructure_id)
        return None if item is None else self._parse(infrastructure_id, item)

    def record(
        self,
        infrastructure_id: str,
        name: str,
        source: str,
        evidence: str,
    ) -> DetectedFailureDomain:
        """Enregistre le résultat d'un détecteur avec sa preuve non sensible."""

        item = DetectedFailureDomain(
            infrastructure_id=infrastructure_id,
            name=name,
            source=source,
            evidence=evidence.strip(),
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
        parsed = self._parse(infrastructure_id, asdict(item))
        raw = self.load()
        raw["detections"][infrastructure_id] = asdict(parsed)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        temporary.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)
        return parsed


def failure_domain_view(
    infrastructure: Infrastructure,
    detected: DetectedFailureDomain | None,
) -> dict[str, Any]:
    """Distingue déclaré, détecté, cohérent, conflictuel et inconnu."""

    if detected is not None and detected.infrastructure_id != infrastructure.id:
        raise FailureDomainError("détection associée à une autre infrastructure")
    declared = infrastructure.failure_domain
    detected_name = detected.name if detected is not None else None
    if declared is not None and detected_name is not None:
        status = "confirmed" if declared == detected_name else "conflict"
    elif declared is not None:
        status = "declared"
    elif detected_name is not None:
        status = "detected"
    else:
        status = "unknown"
    return {
        "status": status,
        "declared": declared,
        "detected": None if detected is None else asdict(detected),
    }
