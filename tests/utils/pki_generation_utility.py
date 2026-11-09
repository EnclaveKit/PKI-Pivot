"""Generate a throw-away PKI (CA, server, client, rogue client) for mTLS tests."""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CLIENT_COMMON_NAME = "pki-pivot-proxy-client"
ROGUE_CLIENT_COMMON_NAME = "rogue-client"


@dataclass(frozen=True, slots=True)
class PkiBundle:
    """Paths to the generated PEM files."""

    ca_cert: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    rogue_ca_cert: Path
    rogue_client_cert: Path
    rogue_client_key: Path


_Issued = tuple[x509.Certificate, ec.EllipticCurvePrivateKey]


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _validity() -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.UTC)
    return now - dt.timedelta(minutes=5), now + dt.timedelta(days=1)


def _make_ca(common_name: str) -> _Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    not_before, not_after = _validity()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_leaf(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    *,
    server: bool,
) -> _Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    not_before, not_after = _validity()
    usage = (
        ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256()), key


def _write_cert(path: Path, cert: x509.Certificate) -> Path:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path


def generate_pki(directory: Path) -> PkiBundle:
    """Create the CA, issuer-server cert, proxy-client cert and a rogue client."""
    directory.mkdir(parents=True, exist_ok=True)

    ca_cert, ca_key = _make_ca("pki-pivot-test-ca")
    server_cert, server_key = _make_leaf(ca_cert, ca_key, "localhost", server=True)
    client_cert, client_key = _make_leaf(
        ca_cert, ca_key, CLIENT_COMMON_NAME, server=False
    )

    rogue_ca_cert, rogue_ca_key = _make_ca("rogue-test-ca")
    rogue_cert, rogue_key = _make_leaf(
        rogue_ca_cert, rogue_ca_key, ROGUE_CLIENT_COMMON_NAME, server=False
    )

    return PkiBundle(
        ca_cert=_write_cert(directory / "ca.crt", ca_cert),
        server_cert=_write_cert(directory / "server.crt", server_cert),
        server_key=_write_key(directory / "server.key", server_key),
        client_cert=_write_cert(directory / "client.crt", client_cert),
        client_key=_write_key(directory / "client.key", client_key),
        rogue_ca_cert=_write_cert(directory / "rogue-ca.crt", rogue_ca_cert),
        rogue_client_cert=_write_cert(directory / "rogue-client.crt", rogue_cert),
        rogue_client_key=_write_key(directory / "rogue-client.key", rogue_key),
    )
