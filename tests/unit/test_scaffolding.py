"""Scaffolding tests to verify pytest configuration, fixtures, and markers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp
import pytest

from pki_pivot.csp_token_requester import Supported_CSP_Tokens, base
from pki_pivot.csp_token_requester.base import CspConfig
from pki_pivot.http_proxy import ProxyConfig, load_config
from tests.conftest import _provider_registry_snapshot

if TYPE_CHECKING:
    from tests.conftest import EnvSetter


@pytest.mark.unit
def test_free_tcp_port_fixture(free_tcp_port: int) -> None:
    assert isinstance(free_tcp_port, int)
    assert 1024 <= free_tcp_port <= 65535


@pytest.mark.unit
def test_mock_env_fixture(
    mock_env: EnvSetter,
) -> None:
    test_key = "PKI_PIVOT_MOCK_ENV_TEST_KEY"
    assert test_key not in os.environ

    mock_env({test_key: "value1"})
    assert os.environ.get(test_key) == "value1"

    # Test clear=True removes other environment variables within the isolated test
    mock_env({"NEW_KEY": "new_value"}, clear=True)
    assert os.environ.get("NEW_KEY") == "new_value"
    assert test_key not in os.environ


@pytest.mark.unit
def test_restore_providers_registry_isolation() -> None:
    original = dict(base._PROVIDERS)
    assert Supported_CSP_Tokens.AWS in base.registered_csps()

    with _provider_registry_snapshot():
        base._PROVIDERS.clear()
        assert not base._PROVIDERS

    assert original == base._PROVIDERS


@pytest.mark.unit
def test_dummy_tls_files_fixture(dummy_tls_files: dict[str, Path]) -> None:
    assert dummy_tls_files["cert"].is_file()
    assert dummy_tls_files["key"].is_file()
    assert dummy_tls_files["ca"].is_file()
    assert dummy_tls_files["cert"].read_text().startswith("-----BEGIN CERTIFICATE-----")


@pytest.mark.unit
def test_sample_aws_env_and_proxy_config_sync(
    sample_aws_env: dict[str, str], sample_proxy_config: ProxyConfig
) -> None:
    assert sample_aws_env["TARGET_CSPS"] == "AWS"
    assert sample_aws_env["AWS_ORGANIZATION"] == "test-org"
    assert sample_aws_env["AWS_ACCOUNT_ID"] == "123456789012"
    assert sample_aws_env["AWS_IAM_ROLE_NAME"] == "test-role"

    loaded_config = load_config(sample_aws_env)
    assert loaded_config == sample_proxy_config
    assert loaded_config.http_port == sample_proxy_config.http_port
    assert loaded_config.for_csp(Supported_CSP_Tokens.AWS) is not None


@pytest.mark.unit
def test_sample_csp_config_fixture(sample_csp_config: CspConfig) -> None:
    assert sample_csp_config.csp is Supported_CSP_Tokens.AWS
    assert sample_csp_config.prefix == "AWS"
    assert sample_csp_config.issuer_path() == "/test-org/123456789012/test-role"


@pytest.mark.unit
async def test_client_session_fixture(client_session: aiohttp.ClientSession) -> None:
    assert not client_session.closed
