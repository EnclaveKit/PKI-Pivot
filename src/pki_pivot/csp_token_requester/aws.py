"""AWS credential provider.

Serves the subset of the EC2 instance metadata service (IMDS) that AWS SDKs
call to obtain instance-role credentials and forwards the credential request to
the configured token issuer over the shared mutual-TLS client.

All AWS-specific routes, handlers, and response shaping live here so the
provider can be tested and maintained independently of the HTTP server.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import aiohttp
from aiohttp import web

from pki_pivot.csp_token_requester.base import (
    CredentialProvider,
    ProviderError,
    ProxyRuntime,
    register_provider,
)
from pki_pivot.csp_token_requester.csp import Supported_CSP_Tokens

logger = logging.getLogger(__name__)

IMDS_V2_TOKEN = "pki-pivot-imds-v2-token"  # noqa: S105
CREDENTIALS_PREFIX = "/latest/meta-data/iam/security-credentials"


@register_provider
class AwsCredentialProvider(CredentialProvider):
    """EC2 IMDS-compatible credential provider."""

    csp = Supported_CSP_Tokens.AWS
    expiration_field = "Expiration"

    _runtime: ProxyRuntime

    def register_routes(self, app: web.Application, runtime: ProxyRuntime) -> None:
        self._runtime = runtime
        app.router.add_put("/latest/api/token", self._handle_token)
        app.router.add_get(f"{CREDENTIALS_PREFIX}/", self._handle_role_list)
        app.router.add_get(f"{CREDENTIALS_PREFIX}/{{role}}", self._handle_credentials)

    async def _handle_token(self, _request: web.Request) -> web.Response:
        return web.Response(text=IMDS_V2_TOKEN, content_type="text/plain")

    async def _handle_role_list(self, _request: web.Request) -> web.Response:
        return web.Response(
            text=self._runtime.config.iam_role_name, content_type="text/plain"
        )

    async def _handle_credentials(self, request: web.Request) -> web.Response:
        config = self._runtime.config
        requested_role = request.match_info.get("role", "")
        if requested_role != config.iam_role_name:
            logger.info("Request for unknown role %r", requested_role)
            return web.Response(status=404, text="Unknown role")

        try:
            credentials = await self._fetch_credentials(self._runtime)
        except (
            aiohttp.ClientError,
            TimeoutError,
            OSError,
            ValueError,
            ProviderError,
        ) as exc:
            logger.warning("Issuer request error: %s", exc)
            return web.Response(status=502, text="Upstream credential provider error")

        issuer_credentials = credentials.get("Credentials")
        if not isinstance(issuer_credentials, Mapping):
            issuer_credentials = credentials

        return web.json_response(
            {
                "AccessKeyId": issuer_credentials.get("AccessKeyId", ""),
                "SecretAccessKey": issuer_credentials.get("SecretAccessKey", ""),
                "Token": issuer_credentials.get("SessionToken", ""),
                "Expiration": issuer_credentials.get("Expiration", ""),
            }
        )

    async def _fetch_credentials(self, runtime: ProxyRuntime) -> Mapping[str, Any]:
        config = runtime.config
        return await runtime.fetch_credentials(
            config.issuer_path(), params=config.issuer_params()
        )
