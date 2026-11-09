"""Shared fixtures and testing utilities for pki-pivot test suite."""

from __future__ import annotations

import os
import socket
from collections.abc import AsyncIterator, Generator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

import aiohttp
import pytest

from pki_pivot.csp_token_requester import Supported_CSP_Tokens, base
from pki_pivot.csp_token_requester.base import CspConfig
from pki_pivot.http_proxy import ProxyConfig


class EnvSetter(Protocol):
    """Protocol for the mock_env fixture."""

    def __call__(self, env_dict: Mapping[str, str], clear: bool = False) -> None: ...


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Automatically assign unit and integration markers based on directory path."""
    for item in items:
        parts = item.path.relative_to(config.rootpath).parts
        if parts[:2] == ("tests", "unit"):
            item.add_marker(pytest.mark.unit)
        elif parts[:2] == ("tests", "integration"):
            item.add_marker(pytest.mark.integration)


@contextmanager
def _provider_registry_snapshot() -> Generator[None]:
    """Restore the provider registry to its current state on context exit."""
    original = dict(base._PROVIDERS)
    try:
        yield
    finally:
        base._PROVIDERS.clear()
        base._PROVIDERS.update(original)


@pytest.fixture(autouse=True)
def restore_providers_registry() -> Generator[None]:
    """Preserve the CSP provider registry and restore after each test."""
    with _provider_registry_snapshot():
        yield


@pytest.fixture
def free_tcp_port() -> int:
    """Allocate an ephemeral free TCP port for test servers."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


@pytest.fixture
def mock_env(
    monkeypatch: pytest.MonkeyPatch,
) -> EnvSetter:
    """Set or clear environment variables using monkeypatch without leaking changes."""

    def _set_env(env_dict: Mapping[str, str], clear: bool = False) -> None:
        if clear:
            for key in list(os.environ.keys()):
                monkeypatch.delenv(key, raising=False)
        for key, value in env_dict.items():
            monkeypatch.setenv(key, value)

    return _set_env


@pytest.fixture
def dummy_tls_files(tmp_path: Path) -> dict[str, Path]:
    """Create dummy cert, key, and CA files in temporary directory for config tests."""
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)

    cert_path = tls_dir / "client.crt"
    cert_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----\n"
    )

    key_path = tls_dir / "client.key"
    key_path.write_text(
        "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----\n"
    )

    ca_path = tls_dir / "ca.crt"
    ca_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMOCK_CA\n-----END CERTIFICATE-----\n"
    )

    return {
        "cert": cert_path,
        "key": key_path,
        "ca": ca_path,
        "dir": tls_dir,
    }


@pytest.fixture
def sample_csp_config(dummy_tls_files: dict[str, Path]) -> CspConfig:
    """Return a valid CspConfig for AWS."""
    return CspConfig(
        csp=Supported_CSP_Tokens.AWS,
        organization="test-org",
        account_id="123456789012",
        iam_role_name="test-role",
        issuer_url="https://issuer.internal.test:8443",
        issuer_path_template="/{organization}/{account_id}/{iam_role_name}",
        issuer_timeout_ms=5000,
        tls_cert_file=str(dummy_tls_files["cert"]),
        tls_key_file=str(dummy_tls_files["key"]),
        tls_ca_file=str(dummy_tls_files["ca"]),
    )


@pytest.fixture
def sample_aws_env(
    dummy_tls_files: dict[str, Path], tmp_path: Path, free_tcp_port: int
) -> dict[str, str]:
    """Return a complete, valid environment dictionary for AWS CSP configuration."""
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    return {
        "HTTP_BIND_HOST": "127.0.0.1",
        "HTTP_PORT": str(free_tcp_port),
        "SHARED_DIR": str(shared_dir),
        "EXIT_FILE_NAME": "EXIT",
        "EXIT_CHECK_INTERVAL": "100",
        "EXIT_CHECK_DISABLED": "false",
        "LOG_LEVEL": "INFO",
        "TARGET_CSPS": "AWS",
        "AWS_ORGANIZATION": "test-org",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_IAM_ROLE_NAME": "test-role",
        "AWS_ISSUER_URL": "https://issuer.internal.test:8443",
        "AWS_ISSUER_PATH_TEMPLATE": "/{organization}/{account_id}/{iam_role_name}",
        "AWS_ISSUER_TIMEOUT": "5000",
        "AWS_TLS_CERT_FILE": str(dummy_tls_files["cert"]),
        "AWS_TLS_KEY_FILE": str(dummy_tls_files["key"]),
        "AWS_TLS_CA_FILE": str(dummy_tls_files["ca"]),
    }


@pytest.fixture
def sample_proxy_config(
    sample_csp_config: CspConfig, tmp_path: Path, free_tcp_port: int
) -> ProxyConfig:
    """Return a valid ProxyConfig containing sample_csp_config."""
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    return ProxyConfig(
        http_bind_host="127.0.0.1",
        http_port=free_tcp_port,
        shared_dir=str(shared_dir),
        exit_file_name="EXIT",
        exit_check_interval_ms=100,
        exit_check_disabled=False,
        csps=(sample_csp_config,),
        log_level="INFO",
    )


@pytest.fixture
async def client_session() -> AsyncIterator[aiohttp.ClientSession]:
    """Provide a managed aiohttp.ClientSession that automatically closes after test."""
    session = aiohttp.ClientSession()
    try:
        yield session
    finally:
        await session.close()
