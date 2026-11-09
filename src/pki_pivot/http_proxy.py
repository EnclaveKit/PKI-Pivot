"""PKI Pivot - HTTP metadata server.

A CSP-agnostic asynchronous HTTP server exposing the instance metadata
endpoints cloud SDKs call to obtain role credentials, plus a ``/health``
endpoint. Each CSP listed in the comma-separated ``TARGET_CSPS`` environment
variable gets its own provider, routes, issuer URL and client certificate,
sourced from CSP-prefixed environment variables (e.g. ``AWS_ISSUER_URL``). The
server itself only validates the shared settings and wires the providers
together.

The server is fully asynchronous: a single event loop serves HTTP, watches
for the exit file, and reacts to SIGINT/SIGTERM, so no worker thread is ever
blocked.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import signal
import ssl
import string
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

import aiohttp
from aiohttp import web

from pki_pivot.csp_token_requester import Supported_CSP_Tokens
from pki_pivot.csp_token_requester.base import (
    DEFAULT_CREDENTIAL_CACHE_TTL_MINUTES,
    DEFAULT_ORGANIZATION_LABEL,
    CspConfig,
    CspRuntime,
    get_provider,
    registered_csps,
)

logger = logging.getLogger(__name__)


DEFAULT_HTTP_BIND_HOST = "localhost"
DEFAULT_HTTP_PORT = 8080
DEFAULT_SHARED_DIR = "/shared"
DEFAULT_EXIT_FILE_NAME = "EXIT"
DEFAULT_EXIT_CHECK_INTERVAL_MS = 500
DEFAULT_ISSUER_PATH_TEMPLATE = "/{organization}/{account_id}/{iam_role_name}"
DEFAULT_ISSUER_TIMEOUT_MS = 10_000
DEFAULT_LOG_LEVEL = "INFO"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})
_TEMPLATE_FIELDS = frozenset({"organization", "account_id", "iam_role_name"})

# Suffixes every CSP listed in TARGET_CSPS must define as ``<CSP>_<SUFFIX>``.
_REQUIRED_CSP_SUFFIXES = (
    "ORGANIZATION",
    "ACCOUNT_ID",
    "IAM_ROLE_NAME",
    "ISSUER_URL",
    "TLS_CERT_FILE",
    "TLS_KEY_FILE",
)
# Lower-case issuer parameter names, e.g. ``org`` or ``organization``.
_PARAMETER_NAME_RE = re.compile(r"[a-z_][a-z0-9_.\-]*")
# ORGANIZATION_LABEL values that disable sending the organization parameter.
_DISABLED_LABEL_VALUES = frozenset({"none", "null", "-"})


class ConfigError(ValueError):
    """Raised when an environment variable is missing or invalid."""


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """Validated configuration for the HTTP server itself.

    Settings that vary per CSP (issuer URL, credentials, client certificate)
    live in the matching :class:`CspConfig` entry in ``csps``.
    """

    http_bind_host: str
    http_port: int
    shared_dir: str
    exit_file_name: str
    exit_check_interval_ms: int
    exit_check_disabled: bool
    csps: tuple[CspConfig, ...]
    log_level: str
    credential_cache_ttl_minutes: int = DEFAULT_CREDENTIAL_CACHE_TTL_MINUTES

    @property
    def exit_file_path(self) -> str:
        return os.path.join(self.shared_dir, self.exit_file_name)

    def for_csp(self, csp: Supported_CSP_Tokens) -> CspConfig:
        """Return the validated configuration for *csp*."""
        for csp_config in self.csps:
            if csp_config.csp is csp:
                return csp_config
        raise ConfigError(f"CSP {csp.value!r} is not configured")


# --------------------------------------------------------------------------
# Environment parsing helpers
# --------------------------------------------------------------------------
def _optional_string(env: Mapping[str, str], name: str, default: str) -> str:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip()


def _required_string(env: Mapping[str, str], name: str) -> str:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        raise ConfigError(
            f"Environment variable {name} is required and must be non-empty"
        )
    return raw.strip()


def _prefixed(prefix: str, suffix: str) -> str:
    """Build a CSP-scoped environment variable name, e.g. ``AWS_ISSUER_URL``."""
    return f"{prefix}_{suffix}"


def _is_blank(env: Mapping[str, str], name: str) -> bool:
    raw = env.get(name)
    return raw is None or raw.strip() == ""


def _parse_target_csps(env: Mapping[str, str]) -> tuple[Supported_CSP_Tokens, ...]:
    """Parse and validate the ``TARGET_CSPS`` environment variable.

    The value is a comma-separated list of CSP names (e.g. ``"AWS"`` or
    ``"AZURE,AWS"``). Every entry is stripped and upper-cased before being
    matched against :class:`Supported_CSP_Tokens`; order is preserved and
    duplicates are dropped.
    """
    valid = ", ".join(member.value.upper() for member in Supported_CSP_Tokens)
    if _is_blank(env, "TARGET_CSPS"):
        raise ConfigError(
            "Environment variable TARGET_CSPS is not defined or empty; set it to a "
            f"comma-separated list of CSPs to activate (supported: {valid})"
        )
    raw = env["TARGET_CSPS"].strip()

    selected: list[Supported_CSP_Tokens] = []
    for entry in raw.split(","):
        name = entry.strip().upper()
        if name == "":
            raise ConfigError(
                "TARGET_CSPS must be a comma-separated list of CSPs without "
                f"empty entries, got {raw!r}"
            )
        try:
            csp = Supported_CSP_Tokens(name.lower())
        except ValueError as exc:
            raise ConfigError(
                f"TARGET_CSPS entry {name!r} is not a supported CSP; "
                f"expected one of: {valid}"
            ) from exc
        if csp not in selected:
            selected.append(csp)
    return tuple(selected)


def _require_csp_variables(
    env: Mapping[str, str], csps: tuple[Supported_CSP_Tokens, ...]
) -> None:
    """Fail with every missing ``<CSP>_<SUFFIX>`` pairing across all target CSPs.

       All target CSPs are checked before failing, so a single fatal error lists
    every missing parameter/CSP pairing instead of only the first one.
    """
    missing: list[tuple[str, str]] = []
    for csp in csps:
        prefix = csp.value.upper()
        for suffix in _REQUIRED_CSP_SUFFIXES:
            name = _prefixed(prefix, suffix)
            if _is_blank(env, name):
                missing.append((prefix, name))
    if missing:
        details = "; ".join(f"CSP {csp}: {name}" for csp, name in missing)
        raise ConfigError(
            "Missing required environment variable(s) for target CSP(s): " + details
        )


def _parse_organization_label(env: Mapping[str, str], prefix: str) -> str | None:
    """Resolve the issuer parameter name carrying the organization.

    ``<CSP>_ORGANIZATION_LABEL`` overrides the global ``ORGANIZATION_LABEL``;
    when both are unset/empty the default ``"organization"`` is used. The
    values ``none``/``null``/``-`` disable sending the parameter.
    """
    name = _prefixed(prefix, "ORGANIZATION_LABEL")
    if _is_blank(env, name):
        name = "ORGANIZATION_LABEL"
    label = _optional_string(env, name, DEFAULT_ORGANIZATION_LABEL).lower()
    if label in _DISABLED_LABEL_VALUES:
        return None
    if not _PARAMETER_NAME_RE.fullmatch(label):
        raise ConfigError(
            f"{name} must be a parameter name (letters, digits, '_', '.', '-'), "
            f"got {label!r}"
        )
    return label


def _parse_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    return value


def _parse_int_with_guard(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(
            f"{name} must be between {minimum} and {maximum}, got {value}"
        )
    return value


def _parse_bool_flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    token = raw.strip().lower()
    if token in _TRUE_VALUES:
        return True
    if token in _FALSE_VALUES:
        return False
    allowed = sorted(_TRUE_VALUES | _FALSE_VALUES - {""})
    raise ConfigError(
        f"{name} must be a boolean (one of {allowed} or empty), got {raw!r}"
    )


def _parse_log_level(env: Mapping[str, str]) -> str:
    raw = env.get("LOG_LEVEL")
    if raw is None or raw.strip() == "":
        return DEFAULT_LOG_LEVEL
    name = raw.strip().upper()
    if name not in logging.getLevelNamesMapping():
        raise ConfigError(f"LOG_LEVEL {raw!r} is not a valid logging level name")
    return name


def _validate_path_segment(name: str, value: str) -> None:
    if value == "":
        raise ConfigError(f"{name} must not be empty")
    if "/" in value or "\\" in value:
        raise ConfigError(f"{name} must be a single path segment, got {value!r}")
    if value in {".", ".."}:
        raise ConfigError(f"{name} must not be {value!r}")


def _validate_path_template(name: str, template: str) -> None:
    try:
        for _, field_name, _, _ in string.Formatter().parse(template):
            if field_name is None:
                continue
            if field_name not in _TEMPLATE_FIELDS:
                raise ConfigError(
                    f"{name} may only use the placeholders "
                    f"{sorted(_TEMPLATE_FIELDS)}; found {field_name!r}"
                )
        template.format(organization="org", account_id="acct", iam_role_name="role")
    except (KeyError, IndexError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"{name} is not a valid format template") from exc


def _assert_readable_file(name: str, raw_path: str) -> str:
    """Return the normalized path if it is a readable file, else raise."""
    path = raw_path.strip()
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        raise ConfigError(f"{name} {path!r} is not a readable file")
    return path


def _optional_readable_file(env: Mapping[str, str], name: str) -> str | None:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return None
    return _assert_readable_file(name, raw)


def _required_readable_file(env: Mapping[str, str], name: str) -> str:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        raise ConfigError(
            f"Environment variable {name} is required and must be non-empty"
        )
    return _assert_readable_file(name, raw)


def _load_csp_config(env: Mapping[str, str], csp: Supported_CSP_Tokens) -> CspConfig:
    """Build and validate the :class:`CspConfig` for a single target CSP.

    All issuer settings are read from environment variables prefixed with the
    upper-cased CSP name, e.g. ``AWS_ISSUER_URL`` for the ``aws`` CSP, so each
    CSP can target a distinct issuer with its own client certificate.
    """
    prefix = csp.value.upper()

    organization = _required_string(env, _prefixed(prefix, "ORGANIZATION"))
    account_id = _required_string(env, _prefixed(prefix, "ACCOUNT_ID"))

    role_var = _prefixed(prefix, "IAM_ROLE_NAME")
    iam_role_name = _required_string(env, role_var)
    _validate_path_segment(role_var, iam_role_name)

    url_var = _prefixed(prefix, "ISSUER_URL")
    issuer_url = _required_string(env, url_var)
    parsed = urlparse(issuer_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(
            f"{url_var} must be an http:// or https:// URL, got {issuer_url!r}"
        )

    template_var = _prefixed(prefix, "ISSUER_PATH_TEMPLATE")
    issuer_path_template = _optional_string(
        env, template_var, DEFAULT_ISSUER_PATH_TEMPLATE
    )
    _validate_path_template(template_var, issuer_path_template)

    issuer_timeout = _parse_int(
        env=env,
        name=_prefixed(prefix, "ISSUER_TIMEOUT"),
        default=DEFAULT_ISSUER_TIMEOUT_MS,
    )

    tls_cert_file = _required_readable_file(env, _prefixed(prefix, "TLS_CERT_FILE"))
    tls_key_file = _required_readable_file(env, _prefixed(prefix, "TLS_KEY_FILE"))
    tls_ca_file = _optional_readable_file(env, _prefixed(prefix, "TLS_CA_FILE"))
    organization_label = _parse_organization_label(env, prefix)

    return CspConfig(
        csp=csp,
        organization=organization,
        account_id=account_id,
        iam_role_name=iam_role_name,
        issuer_url=issuer_url,
        issuer_path_template=issuer_path_template,
        issuer_timeout_ms=issuer_timeout,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
        tls_ca_file=tls_ca_file,
        organization_label=organization_label,
    )


def load_config(environ: Mapping[str, str] | None = None) -> ProxyConfig:
    """Build and validate a :class:`ProxyConfig` from environment variables."""
    env = os.environ if environ is None else environ

    http_bind_host = _optional_string(env, "HTTP_BIND_HOST", DEFAULT_HTTP_BIND_HOST)
    http_port = _parse_int_with_guard(env, "HTTP_PORT", DEFAULT_HTTP_PORT, 1, 65535)

    shared_dir = _optional_string(env, "SHARED_DIR", DEFAULT_SHARED_DIR)

    raw_exit_file = env.get("EXIT_FILE_NAME")
    exit_file_name = (
        DEFAULT_EXIT_FILE_NAME if raw_exit_file is None else raw_exit_file.strip()
    )
    _validate_path_segment("EXIT_FILE_NAME", exit_file_name)

    exit_check_interval = _parse_int_with_guard(
        env=env,
        name="EXIT_CHECK_INTERVAL",
        default=DEFAULT_EXIT_CHECK_INTERVAL_MS,
        minimum=1,
        maximum=60000,
    )
    exit_check_disabled = _parse_bool_flag(env, "EXIT_CHECK_DISABLED", False)

    target_csps = _parse_target_csps(env)
    registered = registered_csps()
    for csp in target_csps:
        if csp not in registered:
            raise ConfigError(
                f"No credential provider is registered for CSP {csp.value.upper()}"
            )
    _require_csp_variables(env, target_csps)
    csps = tuple(_load_csp_config(env, csp) for csp in target_csps)

    log_level = _parse_log_level(env)
    credential_cache_ttl = _parse_int_with_guard(
        env,
        "CREDENTIAL_CACHE_TTL_MINUTES",
        DEFAULT_CREDENTIAL_CACHE_TTL_MINUTES,
        1,
        1440,
    )

    return ProxyConfig(
        http_bind_host=http_bind_host,
        http_port=http_port,
        shared_dir=shared_dir,
        exit_file_name=exit_file_name,
        exit_check_interval_ms=exit_check_interval,
        exit_check_disabled=exit_check_disabled,
        csps=csps,
        log_level=log_level,
        credential_cache_ttl_minutes=credential_cache_ttl,
    )


def configure_logging(level_name: str) -> None:
    """Apply the log level and a stream handler to the whole logging tree.

    ``level_name`` is the validated, upper-cased name (e.g. ``"INFO"``) which
    is resolved to the corresponding ``logging`` level constant.
    """
    log_level = getattr(logging, level_name)
    root = logging.getLogger()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    for existing in root.handlers[:]:
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(log_level)


def build_issuer_ssl_context(config: CspConfig) -> ssl.SSLContext | None:
    """Build the client TLS context used to reach one CSP's issuer.

    Returns ``None`` for plain ``http://`` issuers, where the mutually
    authenticated TLS client is not used. Fails fast if the required
    certificate/key cannot be loaded.
    """
    if urlparse(config.issuer_url).scheme != "https":
        return None

    context = ssl.create_default_context(cafile=config.tls_ca_file)
    # TLS_CERT_FILE/TLS_KEY_FILE are required by load_config for every CSP, so
    # both are guaranteed to be present here.
    try:
        context.load_cert_chain(
            certfile=config.tls_cert_file, keyfile=config.tls_key_file
        )
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError(f"Failed to load TLS certificate/key: {exc}") from exc
    return context


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------
class CredentialProxy:
    """Asynchronous metadata/credential proxy server."""

    def __init__(
        self,
        config: ProxyConfig,
        ssl_contexts: Mapping[Supported_CSP_Tokens, ssl.SSLContext | None]
        | None = None,
    ) -> None:
        self._config = config
        self._ssl_contexts: dict[Supported_CSP_Tokens, ssl.SSLContext | None] = dict(
            ssl_contexts or {}
        )
        self._session: aiohttp.ClientSession | None = None
        self._runner: web.AppRunner | None = None
        self._stop_event = asyncio.Event()
        self._watcher_task: asyncio.Task[None] | None = None
        self._runtimes: dict[Supported_CSP_Tokens, CspRuntime] = {}

    # -- runtime services --------------------------------------------------
    @property
    def session(self) -> aiohttp.ClientSession:
        """The shared client session used by every CSP runtime."""
        if self._session is None:
            raise RuntimeError("Client session is not started")
        return self._session

    def runtime_for(self, csp: Supported_CSP_Tokens) -> CspRuntime:
        """Return the CSP-scoped runtime (one per CSP, so one shared cache)."""
        runtime = self._runtimes.get(csp)
        if runtime is None:
            runtime = CspRuntime(
                session=self.session,
                config=self._config.for_csp(csp),
                ssl_context=self._ssl_contexts.get(csp),
                cache_ttl_seconds=self._config.credential_cache_ttl_minutes * 60,
                expiry_of=get_provider(csp).credential_expiration,
            )
            self._runtimes[csp] = runtime
        return runtime

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        self._session = aiohttp.ClientSession()
        self._runner = web.AppRunner(self._build_app())
        await self._runner.setup()
        site = web.TCPSite(
            self._runner, self._config.http_bind_host, self._config.http_port
        )
        await site.start()
        logger.info(
            "HTTP server listening on %s:%d",
            self._config.http_bind_host,
            self._config.http_port,
        )

        if self._config.exit_check_disabled:
            logger.info("Exit-file monitoring is disabled")
        else:
            if not os.path.isdir(self._config.shared_dir):
                logger.warning(
                    "Shared directory %r does not exist; continuing to run "
                    "without exit-file monitoring",
                    self._config.shared_dir,
                )
            self._watcher_task = asyncio.create_task(
                self._watch_exit_file(), name="exit-file-watcher"
            )

    async def stop(self) -> None:
        self._stop_event.set()
        if self._watcher_task is not None:
            self._watcher_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watcher_task
            self._watcher_task = None
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

        # Wipe cached credentials and cancel in-flight issuer calls before the
        # shared client session they use is closed.
        runtimes = list(self._runtimes.values())
        self._runtimes.clear()
        try:
            await asyncio.gather(*(runtime.close() for runtime in runtimes))
        finally:
            if self._session is not None:
                await self._session.close()
                self._session = None

    async def serve_until_stopped(self) -> None:
        """Run until SIGINT/SIGTERM or the exit file appears."""
        await self.start()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._request_shutdown)
            except (NotImplementedError, RuntimeError, ValueError):
                logger.warning("Cannot install signal handler for %s", sig.name)
        try:
            await self._stop_event.wait()
        finally:
            logger.info("Shutting down")
            await self.stop()

    def _request_shutdown(self) -> None:
        logger.info("Shutdown requested")
        self._stop_event.set()

    async def _watch_exit_file(self) -> None:
        interval = self._config.exit_check_interval_ms / 1000.0
        path = self._config.exit_file_path
        missing_warned = False
        while not self._stop_event.is_set():
            if not os.path.isdir(self._config.shared_dir):
                if not missing_warned:
                    logger.warning(
                        "Shared directory %r is missing; skipping exit-file check",
                        self._config.shared_dir,
                    )
                    missing_warned = True
            else:
                missing_warned = False
                if os.path.exists(path):
                    logger.info("Exit file %s detected; shutting down", path)
                    self._stop_event.set()
                    return
            await asyncio.sleep(interval)

    # -- HTTP wiring -------------------------------------------------------
    def _build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/health", self._handle_health)

        for csp_config in self._config.csps:
            provider = get_provider(csp_config.csp)
            provider.register_routes(app, self.runtime_for(csp_config.csp))
            logger.info("Routing configured for CSP %s", csp_config.prefix)
        return app

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.Response(status=200, text="ok")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main_entry() -> None:
    """Load configuration and run the proxy until shutdown."""
    try:
        config = load_config()
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc

    configure_logging(config.log_level)
    try:
        ssl_contexts = {
            csp_config.csp: build_issuer_ssl_context(csp_config)
            for csp_config in config.csps
        }
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc

    proxy = CredentialProxy(config, ssl_contexts)
    try:
        asyncio.run(proxy.serve_until_stopped())
    except KeyboardInterrupt:
        logger.info("Interrupted")


if __name__ == "__main__":
    main_entry()
