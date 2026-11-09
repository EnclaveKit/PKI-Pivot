"""Unit tests for pki_pivot.csp_token_requester.aws."""

from __future__ import annotations

import ssl
from collections.abc import Hashable, Mapping
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from pki_pivot.csp_token_requester.aws import (
    CREDENTIALS_PREFIX,
    IMDS_V2_TOKEN,
    AwsCredentialProvider,
)
from pki_pivot.csp_token_requester.base import (
    DEFAULT_ORGANIZATION_LABEL,
    CspConfig,
    ProviderError,
    ProxyRuntime,
)
from pki_pivot.csp_token_requester.csp import Supported_CSP_Tokens


class MockProxyRuntime(ProxyRuntime):
    """Mock ProxyRuntime for testing AwsCredentialProvider routes."""

    def __init__(self, config: CspConfig) -> None:
        self._config = config
        self._ssl_context = None
        self.mock_issuer_get = AsyncMock()

    @property
    def config(self) -> CspConfig:
        return self._config

    @property
    def ssl_context(self) -> ssl.SSLContext | None:
        return self._ssl_context

    async def issuer_get(
        self,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return await self.mock_issuer_get(path, headers=headers, params=params)

    async def fetch_credentials(
        self,
        path: str,
        *,
        key: Hashable | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        # The provider calls fetch_credentials; route it to the same mock so the
        # existing assertions on ``mock_issuer_get`` keep working.
        return await self.mock_issuer_get(path, headers=headers, params=params)


@pytest.fixture
def aws_provider_app(
    sample_csp_config: CspConfig,
) -> tuple[web.Application, MockProxyRuntime, AwsCredentialProvider]:
    """Create a test web.Application with AwsCredentialProvider routes registered."""
    provider = AwsCredentialProvider()
    runtime = MockProxyRuntime(sample_csp_config)
    app = web.Application()
    provider.register_routes(app, runtime)
    return app, runtime, provider


def test_aws_provider_attributes() -> None:
    """Verify AwsCredentialProvider class attributes and constants."""
    assert AwsCredentialProvider.csp == Supported_CSP_Tokens.AWS
    assert IMDS_V2_TOKEN == "pki-pivot-imds-v2-token"
    assert CREDENTIALS_PREFIX == "/latest/meta-data/iam/security-credentials"


async def test_aws_token_endpoint(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
) -> None:
    """Verify PUT /latest/api/token returns IMDSv2 token."""
    app, _, _ = aws_provider_app
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.put("/latest/api/token")
        assert response.status == 200
        assert response.content_type == "text/plain"
        text = await response.text()
        assert text == IMDS_V2_TOKEN
    finally:
        await client.close()


async def test_aws_role_list_endpoint(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
    sample_csp_config: CspConfig,
) -> None:
    """Verify role-list endpoint returns the configured IAM role name."""
    app, _, _ = aws_provider_app
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get(f"{CREDENTIALS_PREFIX}/")
        assert response.status == 200
        assert response.content_type == "text/plain"
        text = await response.text()
        assert text == sample_csp_config.iam_role_name
    finally:
        await client.close()


async def test_aws_credentials_unknown_role(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
) -> None:
    """Verify requesting an unknown role returns HTTP 404."""
    app, runtime, _ = aws_provider_app
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get(f"{CREDENTIALS_PREFIX}/unconfigured-role")
        assert response.status == 404
        text = await response.text()
        assert text == "Unknown role"
        runtime.mock_issuer_get.assert_not_called()
    finally:
        await client.close()


async def test_aws_credentials_nested_payload(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
    sample_csp_config: CspConfig,
) -> None:
    """Verify matching role extracts nested credentials and shapes response."""
    app, runtime, _ = aws_provider_app
    runtime.mock_issuer_get.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA_NESTED",
            "SecretAccessKey": "SECRET_NESTED",
            "SessionToken": "TOKEN_NESTED",
            "Expiration": "2026-10-18T22:00:00Z",
        }
    }
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get(
            f"{CREDENTIALS_PREFIX}/{sample_csp_config.iam_role_name}"
        )
        assert response.status == 200
        data = await response.json()
        assert data == {
            "AccessKeyId": "AKIA_NESTED",
            "SecretAccessKey": "SECRET_NESTED",
            "Token": "TOKEN_NESTED",
            "Expiration": "2026-10-18T22:00:00Z",
        }
        runtime.mock_issuer_get.assert_called_once_with(
            sample_csp_config.issuer_path(),
            headers=None,
            params={DEFAULT_ORGANIZATION_LABEL: sample_csp_config.organization},
        )
    finally:
        await client.close()


@pytest.mark.parametrize(
    ("label", "expected_params"),
    [
        ("org", {"org": "test-org"}),
        ("tenant_id", {"tenant_id": "test-org"}),
        (None, None),
    ],
)
async def test_aws_credentials_forwards_issuer_params(
    sample_csp_config: CspConfig,
    label: str | None,
    expected_params: dict[str, str] | None,
) -> None:
    """Verify the provider forwards the configured organization label (or none)."""
    config = replace(sample_csp_config, organization_label=label)
    provider = AwsCredentialProvider()
    runtime = MockProxyRuntime(config)
    runtime.mock_issuer_get.return_value = {"AccessKeyId": "AKIA"}
    app = web.Application()
    provider.register_routes(app, runtime)

    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        response = await client.get(f"{CREDENTIALS_PREFIX}/{config.iam_role_name}")
        assert response.status == 200
        runtime.mock_issuer_get.assert_called_once_with(
            config.issuer_path(), headers=None, params=expected_params
        )
        assert expected_params == config.issuer_params()
    finally:
        await client.close()


async def test_aws_credentials_flat_payload(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
    sample_csp_config: CspConfig,
) -> None:
    """Verify matching role extracts flat credential dictionary and shapes response."""
    app, runtime, _ = aws_provider_app
    runtime.mock_issuer_get.return_value = {
        "AccessKeyId": "AKIA_FLAT",
        "SecretAccessKey": "SECRET_FLAT",
        "SessionToken": "TOKEN_FLAT",
        "Expiration": "2026-10-18T23:00:00Z",
    }
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get(
            f"{CREDENTIALS_PREFIX}/{sample_csp_config.iam_role_name}"
        )
        assert response.status == 200
        data = await response.json()
        assert data == {
            "AccessKeyId": "AKIA_FLAT",
            "SecretAccessKey": "SECRET_FLAT",
            "Token": "TOKEN_FLAT",
            "Expiration": "2026-10-18T23:00:00Z",
        }
    finally:
        await client.close()


async def test_aws_credentials_missing_fields_fallback(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
    sample_csp_config: CspConfig,
) -> None:
    """Verify missing credential fields fall back to empty strings."""
    app, runtime, _ = aws_provider_app
    runtime.mock_issuer_get.return_value = {}
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get(
            f"{CREDENTIALS_PREFIX}/{sample_csp_config.iam_role_name}"
        )
        assert response.status == 200
        data = await response.json()
        assert data == {
            "AccessKeyId": "",
            "SecretAccessKey": "",
            "Token": "",
            "Expiration": "",
        }
    finally:
        await client.close()


@pytest.mark.parametrize(
    "error",
    [
        aiohttp.ClientConnectionError("Connection failed"),
        TimeoutError("Request timed out"),
        OSError("Socket failure"),
        ValueError("JSON parse error"),
        ProviderError("Invalid issuer payload"),
    ],
)
async def test_aws_credentials_upstream_errors(
    aws_provider_app: tuple[web.Application, MockProxyRuntime, AwsCredentialProvider],
    sample_csp_config: CspConfig,
    error: Exception,
) -> None:
    """Verify upstream errors during credential fetch return HTTP 502."""
    app, runtime, _ = aws_provider_app
    runtime.mock_issuer_get.side_effect = error
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get(
            f"{CREDENTIALS_PREFIX}/{sample_csp_config.iam_role_name}"
        )
        assert response.status == 502
        text = await response.text()
        assert text == "Upstream credential provider error"
    finally:
        await client.close()
