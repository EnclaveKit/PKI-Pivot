"""Local fake credential issuer: plain HTTP or HTTPS with required client certs."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from aiohttp import web

from tests.utils.pki_generation_utility import PkiBundle

ACCESS_KEY_ID = "AKIAIT0000000000000"
SECRET_ACCESS_KEY = "it-secret-access-key"
SESSION_TOKEN = "it-session-token"
EXPIRATION = "2099-01-01T00:00:00Z"

_CREDENTIALS = {
    "AccessKeyId": ACCESS_KEY_ID,
    "SecretAccessKey": SECRET_ACCESS_KEY,
    "SessionToken": SESSION_TOKEN,
    "Expiration": EXPIRATION,
}


class Behavior(StrEnum):
    OK_NESTED = "ok_nested"
    OK_FLAT = "ok_flat"
    HTTP_500 = "http_500"
    MALFORMED_JSON = "malformed_json"
    NON_DICT_JSON = "non_dict_json"
    DELAY = "delay"


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    path: str
    client_cn: str | None


def _peer_common_name(request: web.Request) -> str | None:
    transport = request.transport
    if transport is None:
        return None
    peercert = transport.get_extra_info("peercert")
    if not peercert:
        return None
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return None


class FakeIssuer:
    """Credential issuer bound to an ephemeral loopback port.

    Pass a :class:`PkiBundle` to serve HTTPS and *require* a client certificate
    signed by the bundle's CA; omit it to serve plain HTTP.
    """

    def __init__(self, pki: PkiBundle | None = None, *, delay_seconds: float = 3.0):
        self.behavior = Behavior.OK_NESTED
        self.delay_seconds = delay_seconds
        self.requests: list[RecordedRequest] = []
        self._pki = pki
        self._runner: web.AppRunner | None = None
        self._port = 0

    @property
    def url(self) -> str:
        scheme = "http" if self._pki is None else "https"
        return f"{scheme}://127.0.0.1:{self._port}"

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self._pki is None:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(self._pki.server_cert, self._pki.server_key)
        context.load_verify_locations(cafile=str(self._pki.ca_cert))
        return context

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/{organization}/{account_id}/{role}", self._handle)
        self._runner = web.AppRunner(app, shutdown_timeout=1.0)
        await self._runner.setup()
        site = web.TCPSite(
            self._runner, "127.0.0.1", 0, ssl_context=self._ssl_context()
        )
        await site.start()
        self._port = int(self._runner.addresses[0][1])

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        self.requests.append(RecordedRequest(request.path, _peer_common_name(request)))
        behavior = self.behavior
        if behavior is Behavior.HTTP_500:
            return web.Response(status=500, text="issuer failure")
        if behavior is Behavior.MALFORMED_JSON:
            return web.Response(text="{not json", content_type="application/json")
        if behavior is Behavior.NON_DICT_JSON:
            return web.json_response(["not", "an", "object"])
        if behavior is Behavior.DELAY:
            await asyncio.sleep(self.delay_seconds)
        if behavior is Behavior.OK_FLAT:
            return web.json_response(_CREDENTIALS)
        return web.json_response({"Credentials": _CREDENTIALS})
