"""Unit tests for the credential cache and CspRuntime.fetch_credentials."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest

from pki_pivot.csp_token_requester.base import (
    CacheClosedError,
    CredentialCache,
    CspConfig,
    CspRuntime,
    payload_expiration,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _iso(delta_seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=delta_seconds)).isoformat()


class Counter:
    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        self.calls = 0
        self.payload = payload if payload is not None else {"AccessKeyId": "A"}

    async def __call__(self) -> dict[str, Any]:
        self.calls += 1
        return dict(self.payload)


async def test_hit_then_ttl_expiry() -> None:
    clock = FakeClock()
    cache = CredentialCache(100, monotonic=clock)
    fetch = Counter()

    await cache.get_or_fetch("k", fetch)
    await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 1

    clock.now = 101
    await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 2


async def test_entry_expires_before_ttl_when_credentials_expire_sooner() -> None:
    clock = FakeClock()
    cache = CredentialCache(3600, expiry_margin_seconds=60, monotonic=clock)
    fetch = Counter({"Expiration": _iso(120)})  # usable for ~60 s after margin

    await cache.get_or_fetch("k", fetch)
    clock.now = 40
    await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 1

    clock.now = 80
    await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 2


async def test_credentials_inside_margin_are_not_cached() -> None:
    cache = CredentialCache(3600, expiry_margin_seconds=60)
    fetch = Counter({"Credentials": {"Expiration": _iso(30)}})

    await cache.get_or_fetch("k", fetch)
    await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 2


async def test_concurrent_callers_share_one_retrieval() -> None:
    cache = CredentialCache(100)
    gate = asyncio.Event()
    calls = 0

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        await gate.wait()
        return {"AccessKeyId": "A"}

    tasks = [asyncio.create_task(cache.get_or_fetch("k", fetch)) for _ in range(5)]
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(*tasks)

    assert calls == 1
    assert all(r == {"AccessKeyId": "A"} for r in results)


async def test_failure_is_not_cached_and_reaches_all_waiters() -> None:
    cache = CredentialCache(100)
    gate = asyncio.Event()
    calls = 0

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            await gate.wait()
            raise aiohttp.ClientConnectionError("boom")
        return {"AccessKeyId": "A"}

    waiters = [asyncio.create_task(cache.get_or_fetch("k", fetch)) for _ in range(3)]
    await asyncio.sleep(0)
    gate.set()
    outcomes = await asyncio.gather(*waiters, return_exceptions=True)
    assert all(isinstance(o, aiohttp.ClientConnectionError) for o in outcomes)

    assert await cache.get_or_fetch("k", fetch) == {"AccessKeyId": "A"}
    assert calls == 2


async def test_cancelled_waiter_does_not_cancel_shared_retrieval() -> None:
    cache = CredentialCache(100)
    gate = asyncio.Event()
    calls = 0

    async def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        await gate.wait()
        return {"AccessKeyId": "A"}

    first = asyncio.create_task(cache.get_or_fetch("k", fetch))
    await asyncio.sleep(0)
    second = asyncio.create_task(cache.get_or_fetch("k", fetch))
    await asyncio.sleep(0)
    first.cancel()
    gate.set()

    assert await second == {"AccessKeyId": "A"}
    assert calls == 1


async def test_returned_payload_is_isolated_from_cache() -> None:
    cache = CredentialCache(100)
    fetch = Counter({"Credentials": {"AccessKeyId": "A"}})

    first = await cache.get_or_fetch("k", fetch)
    first["Credentials"]["AccessKeyId"] = "tampered"

    assert (await cache.get_or_fetch("k", fetch))["Credentials"]["AccessKeyId"] == "A"


async def test_invalidate() -> None:
    cache = CredentialCache(100)
    fetch = Counter()
    await cache.get_or_fetch("k", fetch)
    cache.invalidate("k")
    await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 2


def test_rejects_non_positive_ttl() -> None:
    with pytest.raises(ValueError, match="positive"):
        CredentialCache(0)


@pytest.mark.parametrize(
    "payload",
    [{}, {"Expiration": ""}, {"Expiration": 5}, {"Expiration": "not-a-date"}],
)
def test_payload_expiration_unparsable_is_none(payload: dict[str, Any]) -> None:
    assert payload_expiration(payload) is None


def test_payload_expiration_nested_and_naive_is_utc() -> None:
    parsed = payload_expiration({"Credentials": {"Expiration": "2099-01-01T00:00:00"}})
    assert parsed == datetime(2099, 1, 1, tzinfo=UTC)


async def test_runtime_fetch_credentials_uses_cache(
    sample_csp_config: CspConfig, client_session: aiohttp.ClientSession
) -> None:
    runtime = CspRuntime(client_session, sample_csp_config)
    issuer = AsyncMock(return_value={"AccessKeyId": "A"})
    runtime.issuer_get = issuer  # type: ignore[method-assign]

    await runtime.fetch_credentials("/p")
    await runtime.fetch_credentials("/p")
    assert issuer.await_count == 1

    await runtime.fetch_credentials("/other")  # different path -> different key
    assert issuer.await_count == 2


async def test_close_clears_entries_and_rejects_new_requests() -> None:
    cache = CredentialCache(100)
    fetch = Counter()
    await cache.get_or_fetch("k", fetch)

    await cache.close()

    assert cache._entries == {}
    assert cache._inflight == {}
    with pytest.raises(CacheClosedError):
        await cache.get_or_fetch("k", fetch)
    assert fetch.calls == 1


async def test_close_cancels_inflight_and_fails_waiters() -> None:
    cache = CredentialCache(100)
    started = asyncio.Event()
    fetch_cancelled = False

    async def fetch() -> dict[str, Any]:
        nonlocal fetch_cancelled
        started.set()
        try:
            await asyncio.Event().wait()  # never completes on its own
        except asyncio.CancelledError:
            fetch_cancelled = True
            raise
        return {}

    waiters = [asyncio.create_task(cache.get_or_fetch("k", fetch)) for _ in range(3)]
    await started.wait()

    await cache.close()

    outcomes = await asyncio.gather(*waiters, return_exceptions=True)
    assert fetch_cancelled
    assert all(isinstance(o, CacheClosedError) for o in outcomes)
    assert cache._inflight == {}
    assert cache._entries == {}


async def test_close_is_idempotent() -> None:
    cache = CredentialCache(100)
    await cache.close()
    await cache.close()


async def test_retrieval_finishing_during_close_is_not_cached() -> None:
    cache = CredentialCache(100)
    gate = asyncio.Event()

    async def fetch() -> dict[str, Any]:
        await gate.wait()
        return {"AccessKeyId": "A"}

    waiter = asyncio.create_task(cache.get_or_fetch("k", fetch))
    await asyncio.sleep(0)
    cache._closed = True  # simulate the window between "closed" and task cancel
    gate.set()
    await asyncio.gather(waiter, return_exceptions=True)

    assert cache._entries == {}


async def test_runtime_close_rejects_fetch_credentials(
    sample_csp_config: CspConfig, client_session: aiohttp.ClientSession
) -> None:
    runtime = CspRuntime(client_session, sample_csp_config)
    issuer = AsyncMock(return_value={"AccessKeyId": "A"})
    runtime.issuer_get = issuer  # type: ignore[method-assign]
    await runtime.fetch_credentials("/p")

    await runtime.close()

    with pytest.raises(CacheClosedError):
        await runtime.fetch_credentials("/p")
    assert issuer.await_count == 1
