"""CSP credential provider abstraction.

Each supported cloud is implemented as a :class:`CredentialProvider` that owns
its metadata routes, request handling, and response shaping. The HTTP server
stays CSP-agnostic, validates one :class:`CspConfig` per target CSP and wires
each provider to its own :class:`CspRuntime`, which performs the actual
mutual-TLS issuer call over the shared client session.

This module must never import :mod:`pki_pivot.http_proxy`: providers must
be importable (and registrable) without pulling in the HTTP server layer.
"""

from __future__ import annotations

import abc
import asyncio
import copy
import logging
import ssl
from collections.abc import Awaitable, Callable, Hashable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic as _default_monotonic
from typing import Any, ClassVar, Protocol, runtime_checkable

import aiohttp
from aiohttp import web

from pki_pivot.csp_token_requester.csp import Supported_CSP_Tokens

logger = logging.getLogger(__name__)

DEFAULT_CREDENTIAL_CACHE_TTL_MINUTES = 55
# Credentials are treated as expired this long before their stated expiry.
CACHE_EXPIRY_MARGIN_SECONDS = 60.0
# Parameter name used to send the organization to the issuer, overridable
# through ``ORGANIZATION_LABEL`` / ``<CSP>_ORGANIZATION_LABEL``.
DEFAULT_ORGANIZATION_LABEL = "organization"


class ProviderError(RuntimeError):
    """Raised when a credential issuer response is unusable."""


class CacheClosedError(ProviderError):
    """Raised when the credential cache is used after (or during) shutdown."""


@dataclass(frozen=True, slots=True)
class CspConfig:
    """Validated issuer configuration for a single target CSP.

    Every value is sourced from an environment variable prefixed with the
    upper-cased CSP name, e.g. ``AWS_ISSUER_URL`` for the ``aws`` CSP, so each
    CSP can target its own token issuer with its own client certificate.
    ``organization_label`` may also come from the global ``ORGANIZATION_LABEL``.
    """

    csp: Supported_CSP_Tokens
    organization: str
    account_id: str
    iam_role_name: str
    issuer_url: str
    issuer_path_template: str
    issuer_timeout_ms: int
    tls_cert_file: str
    tls_key_file: str
    tls_ca_file: str | None
    organization_label: str | None = DEFAULT_ORGANIZATION_LABEL

    @property
    def prefix(self) -> str:
        """Upper-cased CSP name used to prefix this CSP's environment variables."""
        return self.csp.value.upper()

    def issuer_params(self) -> dict[str, str] | None:
        """Query parameters identifying this CSP's organization to the issuer."""
        if not self.organization_label:
            return None
        return {self.organization_label: self.organization}

    def issuer_path(self) -> str:
        path = self.issuer_path_template.format(
            organization=self.organization,
            account_id=self.account_id,
            iam_role_name=self.iam_role_name,
        )
        return path if path.startswith("/") else f"/{path}"


def parse_expiration(raw: Any) -> datetime | None:
    """Parse a credential expiry into an aware UTC datetime, or ``None``.

    Accepts ISO-8601 strings, ``datetime`` objects and epoch seconds (int/float).
    Anything else, or an unparsable value, yields ``None``.
    """
    parsed: datetime
    if isinstance(raw, bool):
        return None
    if isinstance(raw, datetime):
        parsed = raw
    elif isinstance(raw, int | float):
        try:
            parsed = datetime.fromtimestamp(raw, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(raw, str) and raw.strip():
        try:
            parsed = datetime.fromisoformat(raw.strip())
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def payload_expiration(
    payload: Mapping[str, Any], expiration_parameter: str = "Expiration"
) -> datetime | None:
    """Generic best-effort expiry lookup used when a provider does not override it.

    Looks at expiration parameter inside a nested ``Credentials`` object first, then at
    the top level. Providers whose payloads differ should override
    :meth:`CredentialProvider.credential_expiration`.
    """
    nested = payload.get("Credentials")
    source: Mapping[str, Any] = nested if isinstance(nested, Mapping) else payload
    return parse_expiration(source.get(expiration_parameter))


@dataclass(slots=True)
class _CacheEntry:
    payload: dict[str, Any]
    deadline: float  # monotonic clock value
    expires_at: datetime | None  # wall-clock credential expiry, if known


class CredentialCache:
    """TTL cache with in-flight coalescing and no caching of failures."""

    def __init__(
        self,
        ttl_seconds: float,
        *,
        expiry_margin_seconds: float = CACHE_EXPIRY_MARGIN_SECONDS,
        expiry_of: Callable[[Mapping[str, Any]], datetime | None] = payload_expiration,
        monotonic: Callable[[], float] = _default_monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._margin = expiry_margin_seconds
        self._expiry_of = expiry_of
        self._monotonic = monotonic
        self._entries: dict[Hashable, _CacheEntry] = {}
        self._inflight: dict[Hashable, asyncio.Task[dict[str, Any]]] = {}
        self._closed = False

    def _is_fresh(self, entry: _CacheEntry) -> bool:
        if entry.deadline <= self._monotonic():
            return False
        # The monotonic clock can stall (VM pause/suspend), so also honor the
        # credentials' own expiry on the wall clock.
        if entry.expires_at is not None:
            cutoff = entry.expires_at - timedelta(seconds=self._margin)
            if datetime.now(UTC) >= cutoff:
                return False
        return True

    async def get_or_fetch(
        self,
        key: Hashable,
        fetch: Callable[[], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        if self._closed:
            raise CacheClosedError("Credential cache is closed")

        entry = self._entries.get(key)
        if entry is not None:
            if self._is_fresh(entry):
                logger.debug("Credential cache hit")
                return copy.deepcopy(entry.payload)
            del self._entries[key]

        task = self._inflight.get(key)
        if task is None:
            logger.debug("Credential cache miss; requesting from issuer")
            task = asyncio.create_task(self._load(key, fetch))
            # Consume the exception if every waiter was cancelled, so asyncio
            # does not log "exception was never retrieved".
            task.add_done_callback(lambda t: t.cancelled() or t.exception())
            self._inflight[key] = task
        try:
            # shield: cancelling one waiter must not cancel the shared retrieval.
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            # The shared retrieval itself was cancelled by close(), as opposed to
            # this waiter being cancelled: report it as a provider error.
            if self._closed and task.cancelled():
                raise CacheClosedError(
                    "Credential cache closed during retrieval"
                ) from None
            raise
        return copy.deepcopy(result)

    def invalidate(self, key: Hashable | None = None) -> None:
        """Drop one cached entry, or all of them when *key* is ``None``."""
        if key is None:
            self._entries.clear()
        else:
            self._entries.pop(key, None)

    async def close(self) -> None:
        """Cancel in-flight retrievals and drop every cached credential.

        Idempotent. After this call the cache rejects new requests.
        """
        self._closed = True
        tasks = list(self._inflight.values())
        for task in tasks:
            task.cancel()
        if tasks:
            # Wait for cancellation to finish so no retrieval outlives the cache.
            await asyncio.gather(*tasks, return_exceptions=True)
        self._inflight.clear()
        self._entries.clear()

    async def _load(
        self,
        key: Hashable,
        fetch: Callable[[], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        try:
            payload = await fetch()
            expires_at = self._expiry_of(payload)
            deadline = self._deadline_for(expires_at)
            if deadline is not None and not self._closed:
                self._entries[key] = _CacheEntry(
                    copy.deepcopy(payload), deadline, expires_at
                )
            else:
                logger.warning(
                    "Credentials not cached: expire at %s, inside the %.0fs margin",
                    expires_at.isoformat() if expires_at else "an unknown time",
                    self._margin,
                )
            return payload
        finally:
            # Success or failure, the in-flight marker is always removed and
            # failures are never stored.
            self._inflight.pop(key, None)

    def _deadline_for(self, expires_at: datetime | None) -> float | None:
        lifetime = self._ttl
        if expires_at is not None:
            remaining = (expires_at - datetime.now(UTC)).total_seconds()
            lifetime = min(lifetime, remaining - self._margin)
        if lifetime <= 0:
            return None
        return self._monotonic() + lifetime


@runtime_checkable
class ProxyRuntime(Protocol):
    """Services the HTTP server exposes to a single CSP provider."""

    @property
    def config(self) -> CspConfig: ...

    @property
    def ssl_context(self) -> ssl.SSLContext | None: ...

    async def issuer_get(
        self,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]: ...

    async def fetch_credentials(
        self,
        path: str,
        *,
        key: Hashable | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]: ...


class CredentialProvider(abc.ABC):
    """Base class for a CSP-specific metadata/credential provider."""

    csp: ClassVar[Supported_CSP_Tokens]
    # Name of the payload field holding the credentials' expiry. Override per
    # provider (e.g. "expires_at"); override credential_expiration() instead if
    # the payload shape differs more than that.
    expiration_field: ClassVar[str] = "Expiration"

    @abc.abstractmethod
    def register_routes(self, app: web.Application, runtime: ProxyRuntime) -> None:
        """Register this provider's routes on *app* using *runtime*."""

    def credential_expiration(self, payload: Mapping[str, Any]) -> datetime | None:
        """Return when the credentials in an issuer *payload* expire.

        Looks for :attr:`expiration_field`, nested under ``Credentials`` or at the
        top level. Return ``None`` if unknown; the cache then uses its TTL alone.
        """
        return payload_expiration(payload, self.expiration_field)


_PROVIDERS: dict[Supported_CSP_Tokens, CredentialProvider] = {}


def register_provider(
    provider_cls: type[CredentialProvider],
) -> type[CredentialProvider]:
    """Class decorator that registers a provider for its CSP."""
    existing = _PROVIDERS.get(provider_cls.csp)
    if existing is not None and type(existing) is not provider_cls:
        raise ProviderError(
            f"A provider for CSP {provider_cls.csp.value!r} is already registered"
        )
    _PROVIDERS[provider_cls.csp] = provider_cls()
    return provider_cls


def get_provider(csp: Supported_CSP_Tokens) -> CredentialProvider:
    try:
        return _PROVIDERS[csp]
    except KeyError as exc:
        raise ProviderError(
            f"No credential provider registered for CSP {csp.value!r}"
        ) from exc


def registered_csps() -> tuple[Supported_CSP_Tokens, ...]:
    return tuple(_PROVIDERS)


class CspRuntime:
    """CSP-scoped view of the server, handed to that CSP's provider.

    Implements :class:`ProxyRuntime` for a single CSP: the shared client session
    is reused, while the issuer URL, credentials and mutual-TLS context come
    from the matching :class:`CspConfig`. This is what lets two CSPs talk to
    different issuers with different client certificates on one server.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        config: CspConfig,
        ssl_context: ssl.SSLContext | None = None,
        cache_ttl_seconds: float = DEFAULT_CREDENTIAL_CACHE_TTL_MINUTES * 60,
        expiry_of: Callable[[Mapping[str, Any]], datetime | None] | None = None,
    ) -> None:
        self._session = session
        self._config = config
        self._ssl_context = ssl_context
        self._cache = CredentialCache(
            cache_ttl_seconds, expiry_of=expiry_of or payload_expiration
        )

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
        """Call this CSP's token issuer over its own mutual-TLS client."""
        url = f"{self._config.issuer_url.rstrip('/')}{path}"
        timeout = aiohttp.ClientTimeout(total=self._config.issuer_timeout_ms / 1000.0)
        request_kwargs: dict[str, Any] = {
            "headers": headers,
            "params": params,
            "timeout": timeout,
        }
        # ``ssl`` is omitted for http:// issuers, where no client context was
        # built; aiohttp's stubs reject ``ssl=None`` even though it is accepted
        # at runtime and means "use the default context".
        if self._ssl_context is not None:
            request_kwargs["ssl"] = self._ssl_context
        async with self._session.get(url, **request_kwargs) as response:
            response.raise_for_status()
            payload: Any = await response.json(content_type=None)
        if not isinstance(payload, dict):
            raise ProviderError("Issuer response was not a JSON object")
        return {str(key): value for key, value in payload.items()}

    async def fetch_credentials(
        self,
        path: str,
        *,
        key: Hashable | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Return credentials from the cache, calling the issuer only when needed.

        *key* identifies the credential identity. When omitted it is built from the
        CSP, organization, account, role, path and request headers/params, so
        requests that can select different credentials never share an entry.
        """
        cache_key = key if key is not None else self._default_key(path, headers, params)
        return await self._cache.get_or_fetch(
            cache_key,
            lambda: self.issuer_get(path, headers=headers, params=params),
        )

    def _default_key(
        self,
        path: str,
        headers: Mapping[str, str] | None,
        params: Mapping[str, str] | None,
    ) -> Hashable:
        cfg = self._config
        return (
            cfg.csp.value,
            cfg.organization,
            cfg.account_id,
            cfg.iam_role_name,
            path,
            tuple(sorted((headers or {}).items())),
            tuple(sorted((params or {}).items())),
        )

    async def close(self) -> None:
        """Release this runtime's cache, cancelling any in-flight issuer calls."""
        await self._cache.close()
