"""End-to-end tests: real proxy process <-> local fake issuer (HTTP and mTLS)."""

from __future__ import annotations

import asyncio
import signal
import sys
from pathlib import Path

import aiohttp
import pytest

from pki_pivot.csp_token_requester.aws import CREDENTIALS_PREFIX, IMDS_V2_TOKEN
from tests.utils.fake_credential_issuer import (
    ACCESS_KEY_ID,
    EXPIRATION,
    SECRET_ACCESS_KEY,
    SESSION_TOKEN,
    Behavior,
    FakeIssuer,
)
from tests.utils.pki_generation_utility import CLIENT_COMMON_NAME, PkiBundle
from tests.utils.proxy_process_manager import (
    ACCOUNT_ID,
    ORGANIZATION,
    REQUIRED_ENV_VARS,
    ROLE,
    ProxyProcess,
    StartProxy,
    build_proxy_env,
)

EXPECTED_CREDENTIALS = {
    "AccessKeyId": ACCESS_KEY_ID,
    "SecretAccessKey": SECRET_ACCESS_KEY,
    "Token": SESSION_TOKEN,
    "Expiration": EXPIRATION,
}
ISSUER_PATH = f"/{ORGANIZATION}/{ACCOUNT_ID}/{ROLE}"
UNREACHABLE_HTTPS_ISSUER = "https://127.0.0.1:1"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
async def _health_status(client: aiohttp.ClientSession, proxy: ProxyProcess) -> int:
    async with client.get(f"{proxy.base_url}/health") as response:
        return response.status


async def _credentials(
    client: aiohttp.ClientSession, proxy: ProxyProcess, role: str = ROLE
) -> tuple[int, str]:
    async with client.get(f"{proxy.base_url}{CREDENTIALS_PREFIX}/{role}") as response:
        return response.status, await response.text()


async def _imds_exchange(client: aiohttp.ClientSession, proxy: ProxyProcess) -> None:
    """Full IMDSv2 exchange: token, role discovery, credentials."""
    async with client.put(f"{proxy.base_url}/latest/api/token") as response:
        assert response.status == 200
        assert await response.text() == IMDS_V2_TOKEN
    async with client.get(f"{proxy.base_url}{CREDENTIALS_PREFIX}/") as response:
        assert response.status == 200
        assert await response.text() == ROLE
    async with client.get(f"{proxy.base_url}{CREDENTIALS_PREFIX}/{ROLE}") as response:
        assert response.status == 200
        assert await response.json() == EXPECTED_CREDENTIALS


async def _expect_config_failure(
    start_proxy: StartProxy, env: dict[str, str], *fragments: str
) -> None:
    proxy = await start_proxy(env, wait_ready=False)
    code = await proxy.wait_exit(10)
    assert code != 0, proxy.output
    assert "Configuration error" in proxy.output
    for fragment in fragments:
        assert fragment in proxy.output


# --------------------------------------------------------------------------
# Credential flow: HTTP issuer
# --------------------------------------------------------------------------
async def test_http_issuer_credential_flow(
    http_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    env = build_proxy_env(issuer_url=http_issuer.url, pki=pki, shared_dir=shared_dir)
    proxy = await start_proxy(env)

    await _imds_exchange(http_client, proxy)

    assert [r.path for r in http_issuer.requests] == [ISSUER_PATH]
    # Plain HTTP issuer: the proxy presents no client certificate.
    assert http_issuer.requests[0].client_cn is None


async def test_http_issuer_flat_payload(
    http_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    http_issuer.behavior = Behavior.OK_FLAT
    proxy = await start_proxy(
        build_proxy_env(issuer_url=http_issuer.url, pki=pki, shared_dir=shared_dir)
    )
    await _imds_exchange(http_client, proxy)


async def test_unknown_role_returns_404_without_issuer_call(
    http_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=http_issuer.url, pki=pki, shared_dir=shared_dir)
    )
    status, body = await _credentials(http_client, proxy, role="other-role")
    assert status == 404
    assert body == "Unknown role"
    assert http_issuer.requests == []


async def test_custom_issuer_path_template(
    http_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    env = build_proxy_env(
        issuer_url=http_issuer.url,
        pki=pki,
        shared_dir=shared_dir,
        overrides={
            "AWS_ISSUER_PATH_TEMPLATE": "/{organization}/{account_id}/{iam_role_name}"
        },
    )
    proxy = await start_proxy(env)
    status, _ = await _credentials(http_client, proxy)
    assert status == 200
    assert http_issuer.requests[0].path == ISSUER_PATH


# --------------------------------------------------------------------------
# Credential flow: HTTPS issuer with mutual TLS
# --------------------------------------------------------------------------
async def test_mtls_issuer_credential_flow(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir)
    )

    await _imds_exchange(http_client, proxy)

    assert len(mtls_issuer.requests) == 1
    request = mtls_issuer.requests[0]
    assert request.path == ISSUER_PATH
    assert request.client_cn == CLIENT_COMMON_NAME


async def test_mtls_issuer_rejects_untrusted_client_certificate(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    env = build_proxy_env(
        issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir, identity="rogue"
    )
    proxy = await start_proxy(env)

    status, body = await _credentials(http_client, proxy)

    assert status == 502
    assert body == "Upstream credential provider error"
    assert mtls_issuer.requests == []
    assert await _health_status(http_client, proxy) == 200


async def test_proxy_without_ca_file_does_not_trust_issuer(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    """Without AWS_TLS_CA_FILE only system CAs are trusted, so the test CA fails."""
    env = build_proxy_env(
        issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir, with_ca=False
    )
    proxy = await start_proxy(env)

    status, _ = await _credentials(http_client, proxy)

    assert status == 502
    assert mtls_issuer.requests == []
    assert await _health_status(http_client, proxy) == 200


# --------------------------------------------------------------------------
# Credential caching
# --------------------------------------------------------------------------
async def test_repeated_credential_requests_hit_issuer_once(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir)
    )

    results = await asyncio.gather(
        *(_credentials(http_client, proxy) for _ in range(5))
    )
    await _credentials(http_client, proxy)

    assert all(status == 200 for status, _ in results)
    assert len(mtls_issuer.requests) == 1


async def test_failed_issuer_call_is_not_cached(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir)
    )

    mtls_issuer.behavior = Behavior.HTTP_500
    assert (await _credentials(http_client, proxy))[0] == 502

    mtls_issuer.behavior = Behavior.OK_NESTED
    assert (await _credentials(http_client, proxy))[0] == 200
    assert len(mtls_issuer.requests) == 2


@pytest.mark.parametrize("value", ["0", "-5", "abc", "99999"])
async def test_invalid_cache_ttl_stops_startup(
    value: str,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
) -> None:
    env = build_proxy_env(
        issuer_url=UNREACHABLE_HTTPS_ISSUER,
        pki=pki,
        shared_dir=shared_dir,
        overrides={"CREDENTIAL_CACHE_TTL_MINUTES": value},
    )
    await _expect_config_failure(start_proxy, env, "CREDENTIAL_CACHE_TTL_MINUTES")


# --------------------------------------------------------------------------
# Fault handling
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "behavior",
    [
        Behavior.HTTP_500,
        Behavior.MALFORMED_JSON,
        Behavior.NON_DICT_JSON,
        Behavior.DELAY,
    ],
)
async def test_issuer_faults_map_to_502_and_proxy_recovers(
    behavior: Behavior,
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir)
    )

    mtls_issuer.behavior = behavior
    status, body = await _credentials(http_client, proxy)
    assert status == 502
    assert body == "Upstream credential provider error"
    assert await _health_status(http_client, proxy) == 200

    mtls_issuer.behavior = Behavior.OK_NESTED
    await _imds_exchange(http_client, proxy)


# --------------------------------------------------------------------------
# Environment-variable configuration
# --------------------------------------------------------------------------
@pytest.mark.parametrize("missing", REQUIRED_ENV_VARS)
async def test_missing_required_env_var_stops_startup(
    missing: str, pki: PkiBundle, shared_dir: Path, start_proxy: StartProxy
) -> None:
    env = build_proxy_env(
        issuer_url=UNREACHABLE_HTTPS_ISSUER,
        pki=pki,
        shared_dir=shared_dir,
        overrides={missing: None},
    )
    await _expect_config_failure(start_proxy, env, missing)


async def test_unsupported_target_csp_stops_startup(
    pki: PkiBundle, shared_dir: Path, start_proxy: StartProxy
) -> None:
    env = build_proxy_env(
        issuer_url=UNREACHABLE_HTTPS_ISSUER,
        pki=pki,
        shared_dir=shared_dir,
        overrides={"TARGET_CSPS": "NOPE"},
    )
    await _expect_config_failure(start_proxy, env, "TARGET_CSPS")


async def test_non_http_issuer_url_stops_startup(
    pki: PkiBundle, shared_dir: Path, start_proxy: StartProxy
) -> None:
    env = build_proxy_env(
        issuer_url="ftp://127.0.0.1:21", pki=pki, shared_dir=shared_dir
    )
    await _expect_config_failure(start_proxy, env, "AWS_ISSUER_URL")


async def test_unreadable_tls_cert_file_stops_startup(
    pki: PkiBundle, shared_dir: Path, tmp_path: Path, start_proxy: StartProxy
) -> None:
    env = build_proxy_env(
        issuer_url=UNREACHABLE_HTTPS_ISSUER,
        pki=pki,
        shared_dir=shared_dir,
        overrides={"AWS_TLS_CERT_FILE": str(tmp_path / "missing.crt")},
    )
    await _expect_config_failure(start_proxy, env, "AWS_TLS_CERT_FILE")


async def test_unparsable_tls_key_stops_https_startup(
    pki: PkiBundle, shared_dir: Path, tmp_path: Path, start_proxy: StartProxy
) -> None:
    bad_key = tmp_path / "bad.key"
    bad_key.write_text("this is not a private key\n")
    env = build_proxy_env(
        issuer_url=UNREACHABLE_HTTPS_ISSUER,
        pki=pki,
        shared_dir=shared_dir,
        overrides={"AWS_TLS_KEY_FILE": str(bad_key)},
    )
    await _expect_config_failure(start_proxy, env, "Failed to load TLS certificate/key")


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------
async def test_exit_file_stops_proxy_with_code_zero(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=mtls_issuer.url, pki=pki, shared_dir=shared_dir)
    )
    await _imds_exchange(http_client, proxy)

    (shared_dir / "EXIT").touch()

    assert await proxy.wait_exit(5) == 0, proxy.output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals only")
async def test_sigterm_stops_proxy_with_code_zero(
    http_issuer: FakeIssuer, pki: PkiBundle, shared_dir: Path, start_proxy: StartProxy
) -> None:
    proxy = await start_proxy(
        build_proxy_env(issuer_url=http_issuer.url, pki=pki, shared_dir=shared_dir)
    )

    proxy.send_signal(signal.SIGTERM)

    assert await proxy.wait_exit(5) == 0, proxy.output


async def test_missing_shared_dir_keeps_serving_then_exits(
    mtls_issuer: FakeIssuer,
    pki: PkiBundle,
    tmp_path: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    later = tmp_path / "created-later"
    proxy = await start_proxy(
        build_proxy_env(issuer_url=mtls_issuer.url, pki=pki, shared_dir=later)
    )

    await _imds_exchange(http_client, proxy)
    assert proxy.returncode is None

    later.mkdir()
    (later / "EXIT").touch()

    assert await proxy.wait_exit(5) == 0, proxy.output


async def test_exit_check_disabled_ignores_exit_file(
    http_issuer: FakeIssuer,
    pki: PkiBundle,
    shared_dir: Path,
    start_proxy: StartProxy,
    http_client: aiohttp.ClientSession,
) -> None:
    env = build_proxy_env(
        issuer_url=http_issuer.url,
        pki=pki,
        shared_dir=shared_dir,
        overrides={"EXIT_CHECK_DISABLED": "true"},
    )
    proxy = await start_proxy(env)

    (shared_dir / "EXIT").touch()
    await asyncio.sleep(0.6)  # several 100 ms polling intervals

    assert proxy.returncode is None
    assert await _health_status(http_client, proxy) == 200

    if sys.platform != "win32":
        proxy.send_signal(signal.SIGTERM)
        assert await proxy.wait_exit(5) == 0, proxy.output
