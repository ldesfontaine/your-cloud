from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import tempfile
from typing import Iterator

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import CoordinationError


class TransportStore:
    def __init__(self, state_dir: Path):
        self.root = state_dir / "transport"
        self.leaves = self.root / "leaves"
        self.ca_key = self.root / "ca.key"
        self.ca_certificate = self.root / "ca.crt"

    def _protect(self) -> None:
        for directory in (self.root, self.leaves):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)

    def _private_path(self, role: str, identity: str) -> Path:
        return self.leaves / f"{role}-{identity}.key"

    def certificate_path(self, role: str, identity: str) -> Path:
        return self.leaves / f"{role}-{identity}.crt"

    def ensure(self, passphrase: bytes, coordinator_id: str, address: str, machine_ids: tuple[str, ...]) -> None:
        self._protect()
        if not self.ca_key.exists() and not self.ca_certificate.exists():
            self._create_ca(passphrase)
        elif not self.ca_key.exists() or not self.ca_certificate.exists():
            raise CoordinationError("autorité de transport incomplète")
        ca_private, ca_certificate = self._load_ca(passphrase)
        self._ensure_leaf(
            passphrase, ca_private, ca_certificate, "coordinator", coordinator_id,
            f"coordinator:{coordinator_id}", server_address=address,
        )
        self._ensure_leaf(
            passphrase, ca_private, ca_certificate, "console", "local", "console:local"
        )
        for machine_id in machine_ids:
            self._ensure_leaf(
                passphrase, ca_private, ca_certificate, "daemon", machine_id,
                f"daemon:{machine_id}",
            )

    def _create_ca(self, passphrase: bytes) -> None:
        private = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "your-cloud transport CA")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=False, key_cert_sign=True,
                    key_agreement=False, content_commitment=False, data_encipherment=False,
                    encipher_only=False, decipher_only=False, crl_sign=True,
                ),
                critical=True,
            )
            .sign(private, algorithm=None)
        )
        self._write_private(self.ca_key, private, passphrase)
        self._write_public(self.ca_certificate, certificate.public_bytes(serialization.Encoding.PEM))

    def _load_ca(self, passphrase: bytes) -> tuple[Ed25519PrivateKey, x509.Certificate]:
        try:
            private = serialization.load_pem_private_key(self.ca_key.read_bytes(), password=passphrase)
            certificate = x509.load_pem_x509_certificate(self.ca_certificate.read_bytes())
        except (FileNotFoundError, ValueError, TypeError) as error:
            raise CoordinationError("mot de passe ou autorité de transport invalide") from error
        if not isinstance(private, Ed25519PrivateKey):
            raise CoordinationError("algorithme de l'autorité de transport refusé")
        return private, certificate

    def _ensure_leaf(
        self,
        passphrase: bytes,
        ca_private: Ed25519PrivateKey,
        ca_certificate: x509.Certificate,
        role: str,
        identity: str,
        common_name: str,
        *,
        server_address: str | None = None,
    ) -> None:
        private_path = self._private_path(role, identity)
        certificate_path = self.certificate_path(role, identity)
        if private_path.exists() and certificate_path.exists():
            return
        if private_path.exists() or certificate_path.exists():
            raise CoordinationError(f"identité de transport incomplète : {role}:{identity}")
        private = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_certificate.subject)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private.public_key()),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH if server_address else ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=True,
            )
        )
        if server_address:
            try:
                name = x509.IPAddress(ipaddress.ip_address(server_address))
            except ValueError:
                name = x509.DNSName(server_address)
            builder = builder.add_extension(x509.SubjectAlternativeName([name]), critical=False)
        certificate = builder.sign(ca_private, algorithm=None)
        self._write_private(private_path, private, passphrase)
        self._write_public(certificate_path, certificate.public_bytes(serialization.Encoding.PEM))

    def _write_private(self, path: Path, private: Ed25519PrivateKey, passphrase: bytes) -> None:
        value = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        )
        self._write(path, value)

    def _write_public(self, path: Path, value: bytes) -> None:
        self._write(path, value)

    def _write(self, path: Path, value: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(value)
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    @contextmanager
    def materialize_private(self, role: str, identity: str, passphrase: bytes) -> Iterator[Path]:
        path = self._private_path(role, identity)
        try:
            private = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
        except (FileNotFoundError, ValueError, TypeError) as error:
            raise CoordinationError(f"identité de transport illisible : {role}:{identity}") from error
        runtime = self.root / ".runtime"
        runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(runtime, 0o700)
        descriptor, name = tempfile.mkstemp(prefix=f"{role}-{identity}-", dir=runtime)
        clear_path = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
                handle.flush()
                os.fsync(handle.fileno())
            yield clear_path
        finally:
            clear_path.unlink(missing_ok=True)
