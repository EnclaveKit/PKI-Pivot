"""Fixtures for the integration suite."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import aiohttp
import pytest

from tests.utils.fake_credential_issuer import FakeIssuer
from tests.utils.pki_generation_utility import PkiBundle, generate_pki
from tests.utils.proxy_process_manager import ProxyProcess, StartProxy


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PkiBundle:
    return generate_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def shared_dir(tmp_path: Path) -> Path:
    path = tmp_path / "shared"
    path.mkdir()
    return path


@pytest.fixture
async def http_issuer() -> AsyncIterator[FakeIssuer]:
    async with FakeIssuer() as issuer:
        yield issuer


@pytest.fixture
async def mtls_issuer(pki: PkiBundle) -> AsyncIterator[FakeIssuer]:
    async with FakeIssuer(pki) as issuer:
        yield issuer


@pytest.fixture
async def start_proxy() -> AsyncIterator[StartProxy]:
    """Start proxies; every one is terminated on teardown."""
    started: list[ProxyProcess] = []

    async def _start(
        env: Mapping[str, str], *, wait_ready: bool = True
    ) -> ProxyProcess:
        proxy = ProxyProcess(env)
        started.append(proxy)
        await proxy.start()
        if wait_ready:
            await proxy.wait_ready()
        return proxy

    try:
        yield _start
    finally:
        for proxy in reversed(started):
            await proxy.stop()


@pytest.fixture
async def http_client() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10)
    ) as session:
        yield session
