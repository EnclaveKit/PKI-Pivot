"""Run the real proxy entry point as a subprocess and configure it via env vars."""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path

import aiohttp

from tests.utils.pki_generation_utility import PkiBundle

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"

ORGANIZATION = "it-org"
ACCOUNT_ID = "123456789012"
ROLE = "it-role"

# Variables the proxy refuses to start without (see docs/architecture.md).
REQUIRED_ENV_VARS = (
    "TARGET_CSPS",
    "AWS_ORGANIZATION",
    "AWS_ACCOUNT_ID",
    "AWS_IAM_ROLE_NAME",
    "AWS_ISSUER_URL",
    "AWS_TLS_CERT_FILE",
    "AWS_TLS_KEY_FILE",
)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_proxy_env(
    *,
    issuer_url: str,
    pki: PkiBundle,
    shared_dir: Path,
    identity: str = "valid",
    with_ca: bool = True,
    overrides: Mapping[str, str | None] | None = None,
) -> dict[str, str]:
    """Build the complete environment for one proxy.

    ``identity`` selects the client certificate (``"valid"`` or ``"rogue"``).
    ``with_ca=False`` leaves ``AWS_TLS_CA_FILE`` unset. A ``None`` override
    removes that variable.
    """
    if identity == "rogue":
        cert, key = pki.rogue_client_cert, pki.rogue_client_key
    else:
        cert, key = pki.client_cert, pki.client_key

    env: dict[str, str] = {
        "TARGET_CSPS": "AWS",
        "HTTP_BIND_HOST": "127.0.0.1",
        "HTTP_PORT": str(find_free_port()),
        "SHARED_DIR": str(shared_dir),
        "EXIT_FILE_NAME": "EXIT",
        "EXIT_CHECK_INTERVAL": "100",
        "EXIT_CHECK_DISABLED": "false",
        "LOG_LEVEL": "DEBUG",
        "AWS_ORGANIZATION": ORGANIZATION,
        "AWS_ACCOUNT_ID": ACCOUNT_ID,
        "AWS_IAM_ROLE_NAME": ROLE,
        "AWS_ISSUER_URL": issuer_url,
        "AWS_ISSUER_TIMEOUT": "1000",
        "AWS_TLS_CERT_FILE": str(cert),
        "AWS_TLS_KEY_FILE": str(key),
    }
    if with_ca:
        env["AWS_TLS_CA_FILE"] = str(pki.ca_cert)

    for name, value in (overrides or {}).items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


class ProxyProcess:
    """The proxy running as ``python -m pki_pivot.http_proxy``."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = dict(env)
        self._proc: asyncio.subprocess.Process | None = None
        self._pump_task: asyncio.Task[None] | None = None
        self._chunks: list[bytes] = []

    @property
    def base_url(self) -> str:
        host = self.env.get("HTTP_BIND_HOST", "127.0.0.1")
        return f"http://{host}:{self.env['HTTP_PORT']}"

    @property
    def output(self) -> str:
        return b"".join(self._chunks).decode(errors="replace")

    @property
    def returncode(self) -> int | None:
        return None if self._proc is None else self._proc.returncode

    async def start(self) -> None:
        # Deliberately not inheriting os.environ: only the variables the test
        # supplies may configure the proxy.
        child_env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(SRC_DIR),
            "PYTHONUNBUFFERED": "1",
            **self.env,
        }
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "pki_pivot.http_proxy",
            env=child_env,
            cwd=REPO_ROOT,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._pump_task = asyncio.create_task(self._pump())

    async def _pump(self) -> None:
        assert self._proc is not None
        assert self._proc.stdout is not None
        while chunk := await self._proc.stdout.read(4096):
            self._chunks.append(chunk)

    async def wait_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        async with aiohttp.ClientSession() as session:
            while time.monotonic() < deadline:
                if self.returncode is not None:
                    raise RuntimeError(
                        f"Proxy exited with {self.returncode} before becoming "
                        f"ready:\n{self.output}"
                    )
                try:
                    async with session.get(
                        f"{self.base_url}/health",
                        timeout=aiohttp.ClientTimeout(total=1),
                    ) as response:
                        if response.status == 200:
                            return
                except (aiohttp.ClientError, TimeoutError):
                    pass
                await asyncio.sleep(0.05)
        raise TimeoutError(f"Proxy not ready after {timeout}s:\n{self.output}")

    async def wait_exit(self, timeout: float = 5.0) -> int:
        assert self._proc is not None
        code = await asyncio.wait_for(self._proc.wait(), timeout)
        if self._pump_task is not None:
            await asyncio.wait_for(self._pump_task, 5)
        return code

    def send_signal(self, sig: int) -> None:
        assert self._proc is not None
        self._proc.send_signal(sig)

    async def stop(self) -> None:
        proc = self._proc
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
        if self._pump_task is not None:
            with contextlib.suppress(asyncio.CancelledError, TimeoutError):
                await asyncio.wait_for(self._pump_task, 5)


StartProxy = Callable[..., Awaitable[ProxyProcess]]
