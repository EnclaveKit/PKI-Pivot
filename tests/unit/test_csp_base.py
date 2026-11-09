"""Unit tests for pki_pivot.csp_token_requester.base."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from typing import Any, ClassVar
from unittest.mock import AsyncMock

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from pki_pivot.csp_token_requester.base import (
    DEFAULT_ORGANIZATION_LABEL,
    CredentialProvider,
    CspConfig,
    CspRuntime,
    ProviderError,
    ProxyRuntime,
    get_provider,
    register_provider,
    registered_csps,
)
from pki_pivot.csp_token_requester.csp import Supported_CSP_Tokens


def test_csp_config_prefix_and_issuer_path(sample_csp_config: CspConfig) -> None:
    """Verify CspConfig properties and issuer_path generation."""
    assert sample_csp_config.prefix == "AWS"
    assert sample_csp_config.issuer_path() == "/test-org/123456789012/test-role"


def test_csp_config_issuer_path_without_leading_slash(
    sample_csp_config: CspConfig,
) -> None:
    """Verify issuer_path prepends slash if template lacks leading slash."""
    custom_config = CspConfig(
        csp=sample_csp_config.csp,
        organization=sample_csp_config.organization,
        account_id=sample_csp_config.account_id,
        iam_role_name=sample_csp_config.iam_role_name,
        issuer_url=sample_csp_config.issuer_url,
        issuer_path_template="{organization}/{account_id}/{iam_role_name}",
        issuer_timeout_ms=sample_csp_config.issuer_timeout_ms,
        tls_cert_file=sample_csp_config.tls_cert_file,
        tls_key_file=sample_csp_config.tls_key_file,
        tls_ca_file=sample_csp_config.tls_ca_file,
    )
    assert custom_config.issuer_path() == "/test-org/123456789012/test-role"


# ============================================================================
# CspConfig.organization_label / issuer_params tests
# ============================================================================
def test_csp_config_organization_label_defaults(sample_csp_config: CspConfig) -> None:
    """Verify an omitted organization_label falls back to the default label."""
    assert DEFAULT_ORGANIZATION_LABEL == "organization"
    assert sample_csp_config.organization_label == DEFAULT_ORGANIZATION_LABEL
    assert sample_csp_config.issuer_params() == {"organization": "test-org"}


@pytest.mark.parametrize("label", ["org", "tenant_id", "org.name", "org-name", "_org"])
def test_issuer_params_uses_custom_label(
    sample_csp_config: CspConfig, label: str
) -> None:
    """Verify issuer_params keys the organization by the configured label."""
    config = replace(sample_csp_config, organization_label=label)
    assert config.issuer_params() == {label: "test-org"}


@pytest.mark.parametrize("label", [None, ""])
def test_issuer_params_disabled(
    sample_csp_config: CspConfig, label: str | None
) -> None:
    """Verify a None or empty label disables the organization parameter."""
    config = replace(sample_csp_config, organization_label=label)
    assert config.issuer_params() is None


def test_issuer_params_preserves_organization_value(
    sample_csp_config: CspConfig,
) -> None:
    """Verify the organization value is passed through unmodified."""
    config = replace(sample_csp_config, organization="Acme Corp & Co=EU/1")
    assert config.issuer_params() == {"organization": "Acme Corp & Co=EU/1"}


def test_issuer_params_returns_independent_dict(sample_csp_config: CspConfig) -> None:
    """Verify mutating a returned dict cannot leak into later calls."""
    first = sample_csp_config.issuer_params()
    assert first is not None
    first["organization"] = "tampered"
    first["extra"] = "value"

    assert sample_csp_config.issuer_params() == {"organization": "test-org"}


def test_issuer_params_does_not_affect_issuer_path(
    sample_csp_config: CspConfig,
) -> None:
    """Verify the organization label only affects parameters, not the path."""
    disabled = replace(sample_csp_config, organization_label=None)
    custom = replace(sample_csp_config, organization_label="org")
    expected = "/test-org/123456789012/test-role"

    assert sample_csp_config.issuer_path() == expected
    assert disabled.issuer_path() == expected
    assert custom.issuer_path() == expected


def test_csp_config_organization_label_is_frozen(sample_csp_config: CspConfig) -> None:
    """Verify organization_label cannot be reassigned on the frozen dataclass."""
    with pytest.raises(FrozenInstanceError):
        sample_csp_config.organization_label = "org"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("label", "organization", "expected_query"),
    [
        ("organization", "test-org", {"organization": "test-org"}),
        ("org", "test-org", {"org": "test-org"}),
        ("org", "Acme Corp & Co=EU", {"org": "Acme Corp & Co=EU"}),
        (None, "test-org", {}),
    ],
)
async def test_csp_runtime_issuer_get_sends_issuer_params(
    client_session: aiohttp.ClientSession,
    sample_csp_config: CspConfig,
    label: str | None,
    organization: str,
    expected_query: dict[str, str],
) -> None:
    """Verify issuer_params reach the issuer as (correctly encoded) query params."""
    received: list[dict[str, str]] = []

    async def mock_handler(request: web.Request) -> web.Response:
        received.append(dict(request.query))
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/creds", mock_handler)
    server = TestServer(app)
    await server.start_server()

    try:
        config = replace(
            sample_csp_config,
            organization=organization,
            organization_label=label,
            issuer_url=f"http://127.0.0.1:{server.port}",
            issuer_path_template="/creds",
        )
        runtime = CspRuntime(client_session, config)
        result = await runtime.issuer_get(
            config.issuer_path(), params=config.issuer_params()
        )
        assert result == {"ok": True}
        assert received == [expected_query]
    finally:
        await server.close()


async def test_csp_runtime_fetch_credentials_caches_per_issuer_params(
    monkeypatch: pytest.MonkeyPatch,
    client_session: aiohttp.ClientSession,
    sample_csp_config: CspConfig,
) -> None:
    """Verify each distinct issuer_params value gets its own cache entry."""
    runtime = CspRuntime(client_session, sample_csp_config)
    issuer_get = AsyncMock(return_value={"AccessKeyId": "AKIA123"})
    monkeypatch.setattr(runtime, "issuer_get", issuer_get)

    path = sample_csp_config.issuer_path()
    default_params = sample_csp_config.issuer_params()
    custom_params = replace(sample_csp_config, organization_label="org").issuer_params()

    try:
        await runtime.fetch_credentials(path, params=default_params)
        await runtime.fetch_credentials(path, params=default_params)
        assert issuer_get.await_count == 1

        await runtime.fetch_credentials(path, params=custom_params)
        await runtime.fetch_credentials(path, params=None)
        assert issuer_get.await_count == 3
        assert [call.kwargs["params"] for call in issuer_get.await_args_list] == [
            default_params,
            custom_params,
            None,
        ]
    finally:
        await runtime.close()


def test_provider_registration_and_lookup() -> None:
    """Verify provider registration, duplicate protection, and lookup."""
    # Lookup for registered AWS provider
    provider = get_provider(Supported_CSP_Tokens.AWS)
    assert isinstance(provider, CredentialProvider)
    assert Supported_CSP_Tokens.AWS in registered_csps()

    # Re-registering the exact same class should be idempotent
    provider_cls = type(provider)
    assert register_provider(provider_cls) is provider_cls

    # Registering a different class for an existing CSP raises ProviderError
    class DuplicateProvider(CredentialProvider):
        csp: ClassVar[Supported_CSP_Tokens] = Supported_CSP_Tokens.AWS

        def register_routes(self, app: web.Application, runtime: ProxyRuntime) -> None:
            pass

    with pytest.raises(
        ProviderError, match="A provider for CSP 'aws' is already registered"
    ):
        register_provider(DuplicateProvider)


def test_get_unregistered_provider_raises() -> None:
    """Verify getting a provider for an unregistered CSP raises ProviderError."""
    # Temporarily remove all providers to test missing lookup
    from pki_pivot.csp_token_requester.base import _PROVIDERS

    _PROVIDERS.clear()
    with pytest.raises(
        ProviderError, match="No credential provider registered for CSP 'aws'"
    ):
        get_provider(Supported_CSP_Tokens.AWS)


async def test_csp_runtime_properties(
    client_session: aiohttp.ClientSession, sample_csp_config: CspConfig
) -> None:
    """Verify CspRuntime exposes config and ssl_context."""
    dummy_ssl = ssl.create_default_context()
    runtime = CspRuntime(client_session, sample_csp_config, dummy_ssl)
    assert runtime.config is sample_csp_config
    assert runtime.ssl_context is dummy_ssl


async def test_csp_runtime_issuer_get_success(
    client_session: aiohttp.ClientSession, sample_csp_config: CspConfig
) -> None:
    """Verify CspRuntime.issuer_get successful JSON request and response mapping."""
    received_headers: dict[str, str] = {}
    received_params: dict[str, str] = {}

    async def mock_handler(request: web.Request) -> web.Response:
        received_headers.update(dict(request.headers))
        received_params.update(dict(request.query))
        return web.json_response({"AccessKeyId": "AKIA123", "SessionToken": "tok-abc"})

    app = web.Application()
    app.router.add_get("/test-org/123456789012/test-role", mock_handler)
    server = TestServer(app)
    await server.start_server()

    try:
        config = CspConfig(
            csp=sample_csp_config.csp,
            organization=sample_csp_config.organization,
            account_id=sample_csp_config.account_id,
            iam_role_name=sample_csp_config.iam_role_name,
            issuer_url=f"http://127.0.0.1:{server.port}/",
            issuer_path_template=sample_csp_config.issuer_path_template,
            issuer_timeout_ms=5000,
            tls_cert_file=sample_csp_config.tls_cert_file,
            tls_key_file=sample_csp_config.tls_key_file,
            tls_ca_file=sample_csp_config.tls_ca_file,
        )
        runtime = CspRuntime(client_session, config, ssl_context=None)
        res = await runtime.issuer_get(
            config.issuer_path(),
            headers={"X-Custom": "header-val"},
            params={"param1": "val1"},
        )
        assert res == {"AccessKeyId": "AKIA123", "SessionToken": "tok-abc"}
        assert received_headers.get("X-Custom") == "header-val"
        assert received_params.get("param1") == "val1"
    finally:
        await server.close()


async def test_csp_runtime_issuer_get_with_ssl_context(
    monkeypatch: pytest.MonkeyPatch,
    client_session: aiohttp.ClientSession,
    sample_csp_config: CspConfig,
) -> None:
    """Verify CspRuntime.issuer_get passes SSL context when provided."""
    dummy_ssl = ssl.create_default_context()
    passed_ssl = None

    original_get = client_session.get

    def fake_get(url: str, **kwargs: Any) -> aiohttp.client._RequestContextManager:
        nonlocal passed_ssl
        passed_ssl = kwargs.get("ssl")
        return original_get(url, **kwargs)

    monkeypatch.setattr(client_session, "get", fake_get)

    async def mock_handler(_request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/test-path", mock_handler)
    server = TestServer(app)
    await server.start_server()

    try:
        config = CspConfig(
            csp=sample_csp_config.csp,
            organization=sample_csp_config.organization,
            account_id=sample_csp_config.account_id,
            iam_role_name=sample_csp_config.iam_role_name,
            issuer_url=f"http://127.0.0.1:{server.port}",
            issuer_path_template="/test-path",
            issuer_timeout_ms=5000,
            tls_cert_file=sample_csp_config.tls_cert_file,
            tls_key_file=sample_csp_config.tls_key_file,
            tls_ca_file=sample_csp_config.tls_ca_file,
        )
        runtime = CspRuntime(client_session, config, ssl_context=dummy_ssl)
        await runtime.issuer_get("/test-path")
        assert passed_ssl is dummy_ssl
    finally:
        await server.close()


async def test_csp_runtime_issuer_get_http_error(
    client_session: aiohttp.ClientSession, sample_csp_config: CspConfig
) -> None:
    """Verify CspRuntime.issuer_get raises ClientResponseError on non-200 responses."""

    async def mock_handler(_request: web.Request) -> web.Response:
        return web.Response(status=500, text="Internal Server Error")

    app = web.Application()
    app.router.add_get("/error-path", mock_handler)
    server = TestServer(app)
    await server.start_server()

    try:
        config = CspConfig(
            csp=sample_csp_config.csp,
            organization=sample_csp_config.organization,
            account_id=sample_csp_config.account_id,
            iam_role_name=sample_csp_config.iam_role_name,
            issuer_url=f"http://127.0.0.1:{server.port}",
            issuer_path_template="/error-path",
            issuer_timeout_ms=5000,
            tls_cert_file=sample_csp_config.tls_cert_file,
            tls_key_file=sample_csp_config.tls_key_file,
            tls_ca_file=sample_csp_config.tls_ca_file,
        )
        runtime = CspRuntime(client_session, config)
        with pytest.raises(aiohttp.ClientResponseError) as exc_info:
            await runtime.issuer_get("/error-path")
        assert exc_info.value.status == 500
    finally:
        await server.close()


async def test_csp_runtime_issuer_get_non_dict_json(
    client_session: aiohttp.ClientSession, sample_csp_config: CspConfig
) -> None:
    """Verify CspRuntime.issuer_get raises ProviderError for non-dict JSON."""

    async def mock_handler(_request: web.Request) -> web.Response:
        return web.json_response(["item1", "item2"])

    app = web.Application()
    app.router.add_get("/list-path", mock_handler)
    server = TestServer(app)
    await server.start_server()

    try:
        config = CspConfig(
            csp=sample_csp_config.csp,
            organization=sample_csp_config.organization,
            account_id=sample_csp_config.account_id,
            iam_role_name=sample_csp_config.iam_role_name,
            issuer_url=f"http://127.0.0.1:{server.port}",
            issuer_path_template="/list-path",
            issuer_timeout_ms=5000,
            tls_cert_file=sample_csp_config.tls_cert_file,
            tls_key_file=sample_csp_config.tls_key_file,
            tls_ca_file=sample_csp_config.tls_ca_file,
        )
        runtime = CspRuntime(client_session, config)
        with pytest.raises(
            ProviderError, match="Issuer response was not a JSON object"
        ):
            await runtime.issuer_get("/list-path")
    finally:
        await server.close()


async def test_csp_runtime_issuer_get_timeout(
    client_session: aiohttp.ClientSession, sample_csp_config: CspConfig
) -> None:
    """Verify CspRuntime.issuer_get raises TimeoutError when issuer times out."""

    async def slow_handler(_request: web.Request) -> web.Response:
        await asyncio.sleep(0.5)
        return web.json_response({"status": "ok"})

    app = web.Application()
    app.router.add_get("/slow-path", slow_handler)
    server = TestServer(app)
    await server.start_server()

    try:
        config = CspConfig(
            csp=sample_csp_config.csp,
            organization=sample_csp_config.organization,
            account_id=sample_csp_config.account_id,
            iam_role_name=sample_csp_config.iam_role_name,
            issuer_url=f"http://127.0.0.1:{server.port}",
            issuer_path_template="/slow-path",
            issuer_timeout_ms=50,  # 50 ms timeout
            tls_cert_file=sample_csp_config.tls_cert_file,
            tls_key_file=sample_csp_config.tls_key_file,
            tls_ca_file=sample_csp_config.tls_ca_file,
        )
        runtime = CspRuntime(client_session, config)
        with pytest.raises(TimeoutError):
            await runtime.issuer_get("/slow-path")
    finally:
        await server.close()


def test_provider_expiration_field_is_configurable() -> None:
    """A provider can name its own expiry field without overriding the method."""

    class EpochProvider(CredentialProvider):
        csp: ClassVar[Supported_CSP_Tokens] = Supported_CSP_Tokens.AWS
        expiration_field: ClassVar[str] = "expires_at"

        def register_routes(self, app: web.Application, runtime: ProxyRuntime) -> None:
            pass

    provider = EpochProvider()  # instantiated only; deliberately not registered
    expected = datetime(2099, 1, 1, tzinfo=UTC)

    assert (
        provider.credential_expiration({"expires_at": "2099-01-01T00:00:00Z"})
        == expected
    )
    assert (
        provider.credential_expiration(
            {"Credentials": {"expires_at": expected.timestamp()}}
        )
        == expected
    )
    assert (
        provider.credential_expiration({"Expiration": "2099-01-01T00:00:00Z"}) is None
    )
