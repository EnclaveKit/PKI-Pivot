"""Unit tests for pki_pivot.http_proxy."""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import re
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pki_pivot.csp_token_requester.base import (
    DEFAULT_ORGANIZATION_LABEL,
    CacheClosedError,
    CspConfig,
)
from pki_pivot.csp_token_requester.csp import Supported_CSP_Tokens
from pki_pivot.http_proxy import (
    _REQUIRED_CSP_SUFFIXES,
    DEFAULT_EXIT_CHECK_INTERVAL_MS,
    DEFAULT_EXIT_FILE_NAME,
    DEFAULT_HTTP_BIND_HOST,
    DEFAULT_HTTP_PORT,
    DEFAULT_ISSUER_PATH_TEMPLATE,
    DEFAULT_ISSUER_TIMEOUT_MS,
    DEFAULT_LOG_LEVEL,
    DEFAULT_SHARED_DIR,
    ConfigError,
    CredentialProxy,
    ProxyConfig,
    _assert_readable_file,
    _is_blank,
    _load_csp_config,
    _optional_readable_file,
    _optional_string,
    _parse_bool_flag,
    _parse_int,
    _parse_int_with_guard,
    _parse_log_level,
    _parse_organization_label,
    _parse_target_csps,
    _prefixed,
    _require_csp_variables,
    _required_readable_file,
    _required_string,
    _validate_path_segment,
    _validate_path_template,
    build_issuer_ssl_context,
    configure_logging,
    load_config,
    main_entry,
)


@pytest.fixture
def real_pki_files(tmp_path: Path) -> dict[str, Path]:
    """Generate valid X.509 certificate, key, and CA files using cryptography."""
    pki_dir = tmp_path / "real_pki"
    pki_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Generate Client cert
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Client")])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = pki_dir / "ca.crt"
    cert_path = pki_dir / "client.crt"
    key_path = pki_dir / "client.key"

    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return {
        "ca": ca_path,
        "cert": cert_path,
        "key": key_path,
    }


# ============================================================================
# ProxyConfig tests
# ============================================================================
def test_proxy_config_properties(sample_proxy_config: ProxyConfig) -> None:
    """Verify ProxyConfig.exit_file_path and for_csp lookup."""
    expected_exit = os.path.join(
        sample_proxy_config.shared_dir, sample_proxy_config.exit_file_name
    )
    assert sample_proxy_config.exit_file_path == expected_exit

    csp_cfg = sample_proxy_config.for_csp(Supported_CSP_Tokens.AWS)
    assert csp_cfg.csp is Supported_CSP_Tokens.AWS


def test_proxy_config_for_csp_unconfigured(sample_proxy_config: ProxyConfig) -> None:
    """Verify for_csp raises ConfigError when CSP is not in config."""
    empty_config = ProxyConfig(
        http_bind_host="127.0.0.1",
        http_port=8080,
        shared_dir="/shared",
        exit_file_name="EXIT",
        exit_check_interval_ms=500,
        exit_check_disabled=False,
        csps=(),
        log_level="INFO",
    )
    with pytest.raises(ConfigError, match="CSP 'aws' is not configured"):
        empty_config.for_csp(Supported_CSP_Tokens.AWS)


# ============================================================================
# Parsing helper tests
# ============================================================================
def test_optional_string() -> None:
    assert _optional_string({"K": "value"}, "K", "default") == "value"
    assert _optional_string({"K": "   "}, "K", "default") == "default"
    assert _optional_string({}, "K", "default") == "default"


def test_required_string() -> None:
    assert _required_string({"K": "value"}, "K") == "value"
    with pytest.raises(
        ConfigError,
        match="Environment variable K is required and must be non-empty",
    ):
        _required_string({"K": "   "}, "K")
    with pytest.raises(
        ConfigError,
        match="Environment variable K is required and must be non-empty",
    ):
        _required_string({}, "K")


def test_prefixed() -> None:
    assert _prefixed("AWS", "ISSUER_URL") == "AWS_ISSUER_URL"


def test_parse_target_csps() -> None:
    # Valid CSPs are case-insensitive, whitespace-trimmed, and deduplicated.
    assert _parse_target_csps({"TARGET_CSPS": "AWS"}) == (Supported_CSP_Tokens.AWS,)
    assert _parse_target_csps({"TARGET_CSPS": " aws , AWS "}) == (
        Supported_CSP_Tokens.AWS,
    )

    # Empty entries
    with pytest.raises(
        ConfigError,
        match="must be a comma-separated list of CSPs without empty entries",
    ):
        _parse_target_csps({"TARGET_CSPS": "AWS,"})
    with pytest.raises(
        ConfigError,
        match="must be a comma-separated list of CSPs without empty entries",
    ):
        _parse_target_csps({"TARGET_CSPS": ",AWS"})

    # Unsupported CSP
    with pytest.raises(
        ConfigError, match="TARGET_CSPS entry 'GCP' is not a supported CSP"
    ):
        _parse_target_csps({"TARGET_CSPS": "GCP"})


def test_is_blank() -> None:
    assert _is_blank({}, "K")
    assert _is_blank({"K": ""}, "K")
    assert _is_blank({"K": " \t\n"}, "K")
    assert not _is_blank({"K": "v"}, "K")
    assert not _is_blank({"K": "  v  "}, "K")


@pytest.mark.parametrize("value", [None, "", "   "])
def test_parse_target_csps_not_defined(value: str | None) -> None:
    """Verify a missing/empty TARGET_CSPS is a fatal 'not defined' error."""
    env = {} if value is None else {"TARGET_CSPS": value}
    with pytest.raises(
        ConfigError, match="TARGET_CSPS is not defined or empty"
    ) as exc_info:
        _parse_target_csps(env)
    assert "supported:" in str(exc_info.value)
    assert "AWS" in str(exc_info.value)


# ============================================================================
# Organization label tests
# ============================================================================
def test_parse_organization_label_default() -> None:
    assert _parse_organization_label({}, "AWS") == DEFAULT_ORGANIZATION_LABEL


@pytest.mark.parametrize(
    "env",
    [
        {"ORGANIZATION_LABEL": ""},
        {"ORGANIZATION_LABEL": "   "},
        {"AWS_ORGANIZATION_LABEL": "", "ORGANIZATION_LABEL": " "},
    ],
)
def test_parse_organization_label_blank_uses_default(env: dict[str, str]) -> None:
    assert _parse_organization_label(env, "AWS") == DEFAULT_ORGANIZATION_LABEL


def test_parse_organization_label_global() -> None:
    assert _parse_organization_label({"ORGANIZATION_LABEL": "org"}, "AWS") == "org"


def test_parse_organization_label_prefixed_only() -> None:
    env = {"AWS_ORGANIZATION_LABEL": "tenant"}
    assert _parse_organization_label(env, "AWS") == "tenant"


def test_parse_organization_label_prefixed_overrides_global() -> None:
    env = {"ORGANIZATION_LABEL": "org", "AWS_ORGANIZATION_LABEL": "tenant"}
    assert _parse_organization_label(env, "AWS") == "tenant"


def test_parse_organization_label_blank_prefixed_falls_back_to_global() -> None:
    env = {"AWS_ORGANIZATION_LABEL": "   ", "ORGANIZATION_LABEL": "org"}
    assert _parse_organization_label(env, "AWS") == "org"


def test_parse_organization_label_ignores_other_csp_prefix() -> None:
    env = {"AZURE_ORGANIZATION_LABEL": "tenant"}
    assert _parse_organization_label(env, "AWS") == DEFAULT_ORGANIZATION_LABEL


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ORG", "org"),
        ("  Org_Id  ", "org_id"),
        ("Org.Name", "org.name"),
        ("ORG-NAME", "org-name"),
        ("_org", "_org"),
        ("org2", "org2"),
    ],
)
def test_parse_organization_label_normalized(raw: str, expected: str) -> None:
    assert _parse_organization_label({"ORGANIZATION_LABEL": raw}, "AWS") == expected


@pytest.mark.parametrize("raw", ["none", "None", "NULL", "null", "-", " - "])
def test_parse_organization_label_disabled(raw: str) -> None:
    assert _parse_organization_label({"ORGANIZATION_LABEL": raw}, "AWS") is None


def test_parse_organization_label_prefixed_disable_overrides_global() -> None:
    env = {"ORGANIZATION_LABEL": "org", "AWS_ORGANIZATION_LABEL": "none"}
    assert _parse_organization_label(env, "AWS") is None


def test_parse_organization_label_prefixed_enables_over_global_disable() -> None:
    env = {"ORGANIZATION_LABEL": "none", "AWS_ORGANIZATION_LABEL": "org"}
    assert _parse_organization_label(env, "AWS") == "org"


@pytest.mark.parametrize(
    "raw",
    ["has space", "a&b", "1org", "x=y", "org/name", "org?", "-org", "org#1", "örg"],
)
def test_parse_organization_label_invalid_global(raw: str) -> None:
    with pytest.raises(
        ConfigError, match=r"^ORGANIZATION_LABEL must be a parameter name"
    ) as exc_info:
        _parse_organization_label({"ORGANIZATION_LABEL": raw}, "AWS")
    assert repr(raw.strip().lower()) in str(exc_info.value)


def test_parse_organization_label_invalid_prefixed_names_prefixed_var() -> None:
    env = {"ORGANIZATION_LABEL": "org", "AWS_ORGANIZATION_LABEL": "bad label"}
    with pytest.raises(
        ConfigError, match=r"^AWS_ORGANIZATION_LABEL must be a parameter name"
    ):
        _parse_organization_label(env, "AWS")


def test_parse_organization_label_invalid_global_ignored_when_prefixed_set() -> None:
    """Only the variable that is actually used is validated."""
    env = {"ORGANIZATION_LABEL": "bad label", "AWS_ORGANIZATION_LABEL": "org"}
    assert _parse_organization_label(env, "AWS") == "org"


# ============================================================================
# Required CSP variable tests
# ============================================================================
def test_required_csp_suffixes_contract() -> None:
    """Pin the required per-CSP variables; optional ones must not be listed."""
    assert _REQUIRED_CSP_SUFFIXES == (
        "ORGANIZATION",
        "ACCOUNT_ID",
        "IAM_ROLE_NAME",
        "ISSUER_URL",
        "TLS_CERT_FILE",
        "TLS_KEY_FILE",
    )
    for optional in (
        "ORGANIZATION_LABEL",
        "ISSUER_PATH_TEMPLATE",
        "ISSUER_TIMEOUT",
        "TLS_CA_FILE",
    ):
        assert optional not in _REQUIRED_CSP_SUFFIXES


def test_require_csp_variables_complete_env(sample_aws_env: dict[str, str]) -> None:
    _require_csp_variables(sample_aws_env, (Supported_CSP_Tokens.AWS,))


def test_require_csp_variables_no_csps() -> None:
    _require_csp_variables({}, ())


def test_require_csp_variables_optional_not_required() -> None:
    env = {f"AWS_{suffix}": "value" for suffix in _REQUIRED_CSP_SUFFIXES}
    _require_csp_variables(env, (Supported_CSP_Tokens.AWS,))


@pytest.mark.parametrize("suffix", _REQUIRED_CSP_SUFFIXES)
@pytest.mark.parametrize("blank", [None, "", "   "])
def test_require_csp_variables_reports_single_missing(
    sample_aws_env: dict[str, str], suffix: str, blank: str | None
) -> None:
    env = dict(sample_aws_env)
    if blank is None:
        del env[f"AWS_{suffix}"]
    else:
        env[f"AWS_{suffix}"] = blank
    with pytest.raises(ConfigError) as exc_info:
        _require_csp_variables(env, (Supported_CSP_Tokens.AWS,))
    message = str(exc_info.value)
    assert f"CSP AWS: AWS_{suffix}" in message
    assert message.count("CSP AWS:") == 1


def test_require_csp_variables_lists_all_missing_in_order() -> None:
    with pytest.raises(ConfigError) as exc_info:
        _require_csp_variables({}, (Supported_CSP_Tokens.AWS,))
    expected = "; ".join(f"CSP AWS: AWS_{s}" for s in _REQUIRED_CSP_SUFFIXES)
    assert str(exc_info.value) == (
        "Missing required environment variable(s) for target CSP(s): " + expected
    )


# ============================================================================
# CspConfig and ProxyConfig loading tests
# ============================================================================
def test_load_csp_config_valid(sample_aws_env: dict[str, str]) -> None:
    """Verify _load_csp_config parses all prefixed variables correctly."""
    csp_config = _load_csp_config(sample_aws_env, Supported_CSP_Tokens.AWS)
    assert csp_config.csp is Supported_CSP_Tokens.AWS
    assert csp_config.organization == sample_aws_env["AWS_ORGANIZATION"]
    assert csp_config.account_id == sample_aws_env["AWS_ACCOUNT_ID"]
    assert csp_config.iam_role_name == sample_aws_env["AWS_IAM_ROLE_NAME"]
    assert csp_config.issuer_url == sample_aws_env["AWS_ISSUER_URL"]
    assert csp_config.issuer_path_template == sample_aws_env["AWS_ISSUER_PATH_TEMPLATE"]
    assert csp_config.issuer_timeout_ms == int(sample_aws_env["AWS_ISSUER_TIMEOUT"])
    assert csp_config.tls_cert_file == sample_aws_env["AWS_TLS_CERT_FILE"]
    assert csp_config.tls_key_file == sample_aws_env["AWS_TLS_KEY_FILE"]
    assert csp_config.tls_ca_file == sample_aws_env["AWS_TLS_CA_FILE"]
    assert csp_config.organization_label == DEFAULT_ORGANIZATION_LABEL
    assert csp_config.issuer_params() == {
        DEFAULT_ORGANIZATION_LABEL: sample_aws_env["AWS_ORGANIZATION"]
    }


@pytest.mark.parametrize(
    ("overrides", "expected_label", "expected_params"),
    [
        ({"ORGANIZATION_LABEL": "org"}, "org", {"org": "test-org"}),
        ({"ORGANIZATION_LABEL": "ORG"}, "org", {"org": "test-org"}),
        ({"AWS_ORGANIZATION_LABEL": "tenant"}, "tenant", {"tenant": "test-org"}),
        (
            {"ORGANIZATION_LABEL": "org", "AWS_ORGANIZATION_LABEL": "tenant"},
            "tenant",
            {"tenant": "test-org"},
        ),
        ({"ORGANIZATION_LABEL": "none"}, None, None),
    ],
)
def test_load_csp_config_organization_label(
    sample_aws_env: dict[str, str],
    overrides: dict[str, str],
    expected_label: str | None,
    expected_params: dict[str, str] | None,
) -> None:
    """Verify _load_csp_config resolves the organization label into CspConfig."""
    env = {**sample_aws_env, **overrides}
    csp_config = _load_csp_config(env, Supported_CSP_Tokens.AWS)
    assert csp_config.organization_label == expected_label
    assert csp_config.issuer_params() == expected_params


def test_load_csp_config_invalid_organization_label(
    sample_aws_env: dict[str, str],
) -> None:
    env = {**sample_aws_env, "AWS_ORGANIZATION_LABEL": "a&b"}
    with pytest.raises(ConfigError, match="AWS_ORGANIZATION_LABEL must be a parameter"):
        _load_csp_config(env, Supported_CSP_Tokens.AWS)


def test_load_config_defaults(dummy_tls_files: dict[str, Path], tmp_path: Path) -> None:
    """Verify load_config populates default values when optional vars are missing."""
    env = {
        "TARGET_CSPS": "AWS",
        "AWS_ORGANIZATION": "org",
        "AWS_ACCOUNT_ID": "123456",
        "AWS_IAM_ROLE_NAME": "role",
        "AWS_ISSUER_URL": "http://issuer.internal",
        "AWS_TLS_CERT_FILE": str(dummy_tls_files["cert"]),
        "AWS_TLS_KEY_FILE": str(dummy_tls_files["key"]),
    }
    config = load_config(env)
    assert config.http_bind_host == DEFAULT_HTTP_BIND_HOST
    assert config.http_port == DEFAULT_HTTP_PORT
    assert config.shared_dir == DEFAULT_SHARED_DIR
    assert config.exit_file_name == DEFAULT_EXIT_FILE_NAME
    assert config.exit_check_interval_ms == DEFAULT_EXIT_CHECK_INTERVAL_MS
    assert config.exit_check_disabled is False
    assert config.log_level == DEFAULT_LOG_LEVEL

    csp = config.for_csp(Supported_CSP_Tokens.AWS)
    assert csp.issuer_path_template == DEFAULT_ISSUER_PATH_TEMPLATE
    assert csp.issuer_timeout_ms == DEFAULT_ISSUER_TIMEOUT_MS
    assert csp.tls_ca_file is None
    assert csp.organization_label == DEFAULT_ORGANIZATION_LABEL
    assert csp.issuer_params() == {"organization": "org"}


def test_load_config_unregistered_csp(sample_aws_env: dict[str, str]) -> None:
    """Verify load_config raises if target CSP has no registered provider."""
    from pki_pivot.csp_token_requester.base import _PROVIDERS

    _PROVIDERS.clear()
    with pytest.raises(
        ConfigError, match="No credential provider is registered for CSP AWS"
    ):
        load_config(sample_aws_env)


def test_load_config_organization_label_override(
    sample_aws_env: dict[str, str],
) -> None:
    """Verify ORGANIZATION_LABEL flows through load_config into the CSP config."""
    config = load_config({**sample_aws_env, "ORGANIZATION_LABEL": "ORG"})
    csp = config.for_csp(Supported_CSP_Tokens.AWS)
    assert csp.organization_label == "org"
    assert csp.issuer_params() == {"org": "test-org"}


def test_load_config_organization_label_from_os_environ(
    monkeypatch: pytest.MonkeyPatch, sample_aws_env: dict[str, str]
) -> None:
    """Verify the label is read from os.environ when no mapping is passed."""
    for key, value in sample_aws_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_ORGANIZATION_LABEL", raising=False)
    monkeypatch.setenv("ORGANIZATION_LABEL", "tenant")

    csp = load_config().for_csp(Supported_CSP_Tokens.AWS)
    assert csp.issuer_params() == {"tenant": "test-org"}


def test_load_config_invalid_organization_label(sample_aws_env: dict[str, str]) -> None:
    with pytest.raises(ConfigError, match="ORGANIZATION_LABEL must be a parameter"):
        load_config({**sample_aws_env, "ORGANIZATION_LABEL": "has space"})


@pytest.mark.parametrize("value", [None, "", "   "])
def test_load_config_target_csps_not_defined(
    sample_aws_env: dict[str, str], value: str | None
) -> None:
    env = dict(sample_aws_env)
    if value is None:
        del env["TARGET_CSPS"]
    else:
        env["TARGET_CSPS"] = value
    with pytest.raises(ConfigError, match="TARGET_CSPS is not defined or empty"):
        load_config(env)


def test_load_config_reports_missing_before_validating_values(
    sample_aws_env: dict[str, str], tmp_path: Path
) -> None:
    """Missing variables are reported before invalid (present) values."""
    env = dict(sample_aws_env)
    del env["AWS_ACCOUNT_ID"]
    env["AWS_TLS_CERT_FILE"] = str(tmp_path / "does-not-exist.crt")
    with pytest.raises(ConfigError) as exc_info:
        load_config(env)
    message = str(exc_info.value)
    assert "CSP AWS: AWS_ACCOUNT_ID" in message
    assert "not a readable file" not in message


def test_load_config_unregistered_provider_before_missing_vars(
    sample_aws_env: dict[str, str],
) -> None:
    """An unregistered provider is reported before missing per-CSP variables."""
    from pki_pivot.csp_token_requester.base import _PROVIDERS

    _PROVIDERS.clear()
    env = dict(sample_aws_env)
    del env["AWS_ACCOUNT_ID"]
    with pytest.raises(
        ConfigError, match="No credential provider is registered for CSP AWS"
    ):
        load_config(env)


def test_load_config_lists_all_missing_csp_variables(
    sample_aws_env: dict[str, str],
) -> None:
    env = {k: v for k, v in sample_aws_env.items() if not k.startswith("AWS_")}
    with pytest.raises(ConfigError) as exc_info:
        load_config(env)
    for suffix in _REQUIRED_CSP_SUFFIXES:
        assert re.search(re.escape(f"CSP AWS: AWS_{suffix}"), str(exc_info.value))


def test_main_entry_invalid_organization_label_is_fatal(
    monkeypatch: pytest.MonkeyPatch, sample_aws_env: dict[str, str]
) -> None:
    """Verify an invalid ORGANIZATION_LABEL stops startup with SystemExit."""
    for key, value in sample_aws_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_ORGANIZATION_LABEL", raising=False)
    monkeypatch.setenv("ORGANIZATION_LABEL", "bad label")
    with pytest.raises(
        SystemExit, match="Configuration error: ORGANIZATION_LABEL must be"
    ):
        main_entry()


def test_load_csp_config_invalid_url(sample_aws_env: dict[str, str]) -> None:
    """Verify _load_csp_config raises on non-HTTP/HTTPS URLs."""
    env = dict(sample_aws_env)
    env["AWS_ISSUER_URL"] = "ftp://issuer.internal.test"
    with pytest.raises(ConfigError, match="must be an http:// or https:// URL"):
        _load_csp_config(env, Supported_CSP_Tokens.AWS)

    env["AWS_ISSUER_URL"] = "https://"
    with pytest.raises(ConfigError, match="must be an http:// or https:// URL"):
        _load_csp_config(env, Supported_CSP_Tokens.AWS)


def test_load_config_uses_environ_when_none(
    monkeypatch: pytest.MonkeyPatch, sample_aws_env: dict[str, str]
) -> None:
    """Verify load_config reads os.environ when environ argument is omitted."""
    for k, v in sample_aws_env.items():
        monkeypatch.setenv(k, v)
    config = load_config()
    assert config.http_bind_host == sample_aws_env["HTTP_BIND_HOST"]


def test_parse_int() -> None:
    assert _parse_int({"INT_VAR": "42"}, "INT_VAR", 10) == 42
    assert _parse_int({"INT_VAR": "  "}, "INT_VAR", 10) == 10
    assert _parse_int({}, "INT_VAR", 10) == 10
    with pytest.raises(ConfigError, match="INT_VAR must be an integer, got 'abc'"):
        _parse_int({"INT_VAR": "abc"}, "INT_VAR", 10)


def test_parse_int_with_guard() -> None:
    assert _parse_int_with_guard({"PORT": "8080"}, "PORT", 80, 1, 65535) == 8080
    assert _parse_int_with_guard({}, "PORT", 80, 1, 65535) == 80
    assert _parse_int_with_guard({"PORT": ""}, "PORT", 80, 1, 65535) == 80
    with pytest.raises(ConfigError, match="PORT must be an integer, got 'bad'"):
        _parse_int_with_guard({"PORT": "bad"}, "PORT", 80, 1, 65535)
    with pytest.raises(ConfigError, match="PORT must be between 1 and 65535, got 0"):
        _parse_int_with_guard({"PORT": "0"}, "PORT", 80, 1, 65535)
    with pytest.raises(
        ConfigError, match="PORT must be between 1 and 65535, got 70000"
    ):
        _parse_int_with_guard({"PORT": "70000"}, "PORT", 80, 1, 65535)


def test_parse_bool_flag() -> None:
    assert _parse_bool_flag({}, "FLAG", True) is True
    assert _parse_bool_flag({}, "FLAG", False) is False

    for val in ("1", "true", "True", "YES", "on"):
        assert _parse_bool_flag({"FLAG": val}, "FLAG", False) is True

    for val in ("0", "false", "False", "NO", "off", ""):
        assert _parse_bool_flag({"FLAG": val}, "FLAG", True) is False

    with pytest.raises(ConfigError, match="FLAG must be a boolean"):
        _parse_bool_flag({"FLAG": "invalid_bool"}, "FLAG", False)


def test_parse_log_level() -> None:
    assert _parse_log_level({}) == DEFAULT_LOG_LEVEL
    assert _parse_log_level({"LOG_LEVEL": ""}) == DEFAULT_LOG_LEVEL
    assert _parse_log_level({"LOG_LEVEL": "debug"}) == "DEBUG"
    assert _parse_log_level({"LOG_LEVEL": "WARNING"}) == "WARNING"
    with pytest.raises(
        ConfigError, match="LOG_LEVEL 'INVALID' is not a valid logging level"
    ):
        _parse_log_level({"LOG_LEVEL": "INVALID"})


def test_validate_path_segment() -> None:
    _validate_path_segment("ROLE", "valid-role_123")
    with pytest.raises(ConfigError, match="ROLE must not be empty"):
        _validate_path_segment("ROLE", "")
    with pytest.raises(
        ConfigError, match="ROLE must be a single path segment, got 'foo/bar'"
    ):
        _validate_path_segment("ROLE", "foo/bar")
    with pytest.raises(
        ConfigError, match=r"ROLE must be a single path segment, got 'foo\\\\bar'"
    ):
        _validate_path_segment("ROLE", "foo\\bar")
    with pytest.raises(ConfigError, match=r"ROLE must not be '\.'"):
        _validate_path_segment("ROLE", ".")
    with pytest.raises(ConfigError, match=r"ROLE must not be '\.\.'"):
        _validate_path_segment("ROLE", "..")


def test_validate_path_template() -> None:
    _validate_path_template("TMPL", "/{organization}/{account_id}/{iam_role_name}")
    _validate_path_template("TMPL", "/constant/path")
    with pytest.raises(ConfigError, match="may only use the placeholders"):
        _validate_path_template("TMPL", "/{organization}/{unsupported_placeholder}")
    with pytest.raises(ConfigError, match="is not a valid format template"):
        _validate_path_template("TMPL", "/{organization/{unclosed")


def test_file_assertion_helpers(tmp_path: Path) -> None:
    test_file = tmp_path / "readable.txt"
    test_file.write_text("content")

    # _assert_readable_file
    assert _assert_readable_file("FILE", str(test_file)) == str(test_file)
    with pytest.raises(ConfigError, match="is not a readable file"):
        _assert_readable_file("FILE", str(tmp_path / "nonexistent.txt"))
    with pytest.raises(ConfigError, match="is not a readable file"):
        _assert_readable_file("FILE", str(tmp_path))  # directory, not file

    # _optional_readable_file
    assert _optional_readable_file({}, "OPT_FILE") is None
    assert _optional_readable_file({"OPT_FILE": "  "}, "OPT_FILE") is None
    assert _optional_readable_file({"OPT_FILE": str(test_file)}, "OPT_FILE") == str(
        test_file
    )

    # _required_readable_file
    assert _required_readable_file({"REQ_FILE": str(test_file)}, "REQ_FILE") == str(
        test_file
    )
    with pytest.raises(ConfigError, match="REQ_FILE is required and must be non-empty"):
        _required_readable_file({}, "REQ_FILE")
    with pytest.raises(ConfigError, match="REQ_FILE is required and must be non-empty"):
        _required_readable_file({"REQ_FILE": ""}, "REQ_FILE")


# ============================================================================
# Logging configuration tests
# ============================================================================
def test_configure_logging() -> None:
    """Verify configure_logging applies formatting and level to root logger."""
    configure_logging("DEBUG")
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0], logging.StreamHandler)


# ============================================================================
# SSL context builder tests
# ============================================================================
def test_build_issuer_ssl_context_http(sample_csp_config: CspConfig) -> None:
    """Verify build_issuer_ssl_context returns None for http:// URLs."""
    http_config = CspConfig(
        csp=sample_csp_config.csp,
        organization=sample_csp_config.organization,
        account_id=sample_csp_config.account_id,
        iam_role_name=sample_csp_config.iam_role_name,
        issuer_url="http://issuer.local:8080",
        issuer_path_template=sample_csp_config.issuer_path_template,
        issuer_timeout_ms=sample_csp_config.issuer_timeout_ms,
        tls_cert_file=sample_csp_config.tls_cert_file,
        tls_key_file=sample_csp_config.tls_key_file,
        tls_ca_file=None,
    )
    assert build_issuer_ssl_context(http_config) is None


def test_build_issuer_ssl_context_valid_https(
    real_pki_files: dict[str, Path], sample_csp_config: CspConfig
) -> None:
    """Verify build_issuer_ssl_context creates SSLContext for valid cert/key/CA."""
    https_config = CspConfig(
        csp=sample_csp_config.csp,
        organization=sample_csp_config.organization,
        account_id=sample_csp_config.account_id,
        iam_role_name=sample_csp_config.iam_role_name,
        issuer_url="https://issuer.internal.test:8443",
        issuer_path_template=sample_csp_config.issuer_path_template,
        issuer_timeout_ms=sample_csp_config.issuer_timeout_ms,
        tls_cert_file=str(real_pki_files["cert"]),
        tls_key_file=str(real_pki_files["key"]),
        tls_ca_file=str(real_pki_files["ca"]),
    )
    context = build_issuer_ssl_context(https_config)
    assert isinstance(context, ssl.SSLContext)


def test_build_issuer_ssl_context_invalid_cert(
    dummy_tls_files: dict[str, Path], sample_csp_config: CspConfig
) -> None:
    """Verify build_issuer_ssl_context raises ConfigError on corrupt cert files."""
    # dummy_tls_files contains unparsable text
    https_config = CspConfig(
        csp=sample_csp_config.csp,
        organization=sample_csp_config.organization,
        account_id=sample_csp_config.account_id,
        iam_role_name=sample_csp_config.iam_role_name,
        issuer_url="https://issuer.internal.test:8443",
        issuer_path_template=sample_csp_config.issuer_path_template,
        issuer_timeout_ms=sample_csp_config.issuer_timeout_ms,
        tls_cert_file=str(dummy_tls_files["cert"]),
        tls_key_file=str(dummy_tls_files["key"]),
        tls_ca_file=None,
    )
    with pytest.raises(ConfigError, match="Failed to load TLS certificate/key"):
        build_issuer_ssl_context(https_config)


# ============================================================================
# CredentialProxy server tests
# ============================================================================
def test_credential_proxy_session_before_start(
    sample_proxy_config: ProxyConfig,
) -> None:
    """Verify accessing proxy.session before start raises RuntimeError."""
    proxy = CredentialProxy(sample_proxy_config)
    with pytest.raises(RuntimeError, match="Client session is not started"):
        _ = proxy.session


async def test_credential_proxy_health_route(
    sample_proxy_config: ProxyConfig,
    client_session: aiohttp.ClientSession,
) -> None:
    """Verify GET /health returns HTTP 200 'ok'."""
    proxy = CredentialProxy(sample_proxy_config)
    proxy._session = client_session
    app = proxy._build_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        response = await client.get("/health")
        assert response.status == 200
        assert await response.text() == "ok"
    finally:
        await client.close()


async def test_credential_proxy_lifecycle(
    sample_proxy_config: ProxyConfig,
) -> None:
    """Verify CredentialProxy start, runtime access, and stop lifecycle."""
    proxy = CredentialProxy(sample_proxy_config)
    await proxy.start()
    try:
        assert isinstance(proxy.session, aiohttp.ClientSession)
        runtime = proxy.runtime_for(Supported_CSP_Tokens.AWS)
        assert runtime.config.csp is Supported_CSP_Tokens.AWS
        assert proxy._watcher_task is not None
    finally:
        await proxy.stop()
    assert proxy._session is None
    assert proxy._runner is None
    assert proxy._watcher_task is None


async def test_credential_proxy_disabled_watcher(
    sample_csp_config: CspConfig, free_tcp_port: int, tmp_path: Path
) -> None:
    """Verify exit file watcher task is not created when exit_check_disabled=True."""
    config = ProxyConfig(
        http_bind_host="127.0.0.1",
        http_port=free_tcp_port,
        shared_dir=str(tmp_path / "shared"),
        exit_file_name="EXIT",
        exit_check_interval_ms=100,
        exit_check_disabled=True,
        csps=(sample_csp_config,),
        log_level="INFO",
    )
    proxy = CredentialProxy(config)
    await proxy.start()
    try:
        assert proxy._watcher_task is None
    finally:
        await proxy.stop()


async def test_credential_proxy_missing_shared_dir_on_start(
    sample_csp_config: CspConfig, free_tcp_port: int, tmp_path: Path
) -> None:
    """Verify proxy starts even if shared_dir does not initially exist."""
    missing_dir = tmp_path / "nonexistent_shared"
    config = ProxyConfig(
        http_bind_host="127.0.0.1",
        http_port=free_tcp_port,
        shared_dir=str(missing_dir),
        exit_file_name="EXIT",
        exit_check_interval_ms=50,
        exit_check_disabled=False,
        csps=(sample_csp_config,),
        log_level="INFO",
    )
    proxy = CredentialProxy(config)
    await proxy.start()
    try:
        assert proxy._watcher_task is not None
    finally:
        await proxy.stop()


async def test_exit_file_detection(
    sample_proxy_config: ProxyConfig, tmp_path: Path
) -> None:
    """Verify creating the exit file signals stop event in _watch_exit_file."""
    proxy = CredentialProxy(sample_proxy_config)
    await proxy.start()
    try:
        assert not proxy._stop_event.is_set()
        exit_file = Path(sample_proxy_config.exit_file_path)
        exit_file.write_text("shutdown")
        # Wait for watcher to detect exit file
        await asyncio.wait_for(proxy._stop_event.wait(), timeout=1.0)
        assert proxy._stop_event.is_set()
    finally:
        await proxy.stop()


async def test_watch_exit_file_missing_dir_then_created(
    sample_csp_config: CspConfig, free_tcp_port: int, tmp_path: Path
) -> None:
    """Verify watcher handles missing directory, then detects created exit file."""
    shared_dir = tmp_path / "dynamic_shared"
    config = ProxyConfig(
        http_bind_host="127.0.0.1",
        http_port=free_tcp_port,
        shared_dir=str(shared_dir),
        exit_file_name="EXIT",
        exit_check_interval_ms=20,
        exit_check_disabled=False,
        csps=(sample_csp_config,),
        log_level="INFO",
    )
    proxy = CredentialProxy(config)
    await proxy.start()
    try:
        # Give watcher one iteration with missing dir
        await asyncio.sleep(0.05)
        assert not proxy._stop_event.is_set()

        # Create directory and exit file
        shared_dir.mkdir(parents=True, exist_ok=True)
        (shared_dir / "EXIT").write_text("stop")

        await asyncio.wait_for(proxy._stop_event.wait(), timeout=1.0)
        assert proxy._stop_event.is_set()
    finally:
        await proxy.stop()


async def test_serve_until_stopped(sample_proxy_config: ProxyConfig) -> None:
    """Verify serve_until_stopped runs until _request_shutdown is called."""
    proxy = CredentialProxy(sample_proxy_config)

    async def trigger_shutdown() -> None:
        await asyncio.sleep(0.05)
        proxy._request_shutdown()

    shutdown_task = asyncio.create_task(trigger_shutdown())
    await asyncio.wait_for(proxy.serve_until_stopped(), timeout=1.0)
    await shutdown_task
    assert proxy._stop_event.is_set()


async def test_serve_until_stopped_signal_failure_fallback(
    monkeypatch: pytest.MonkeyPatch, sample_proxy_config: ProxyConfig
) -> None:
    """Verify serve_until_stopped logs and continues if signal registration fails."""
    proxy = CredentialProxy(sample_proxy_config)
    loop = asyncio.get_running_loop()

    def mock_add_signal_handler(sig: int, callback: object) -> None:
        raise NotImplementedError("Signal handler not supported")

    monkeypatch.setattr(loop, "add_signal_handler", mock_add_signal_handler)

    async def trigger_shutdown() -> None:
        await asyncio.sleep(0.05)
        proxy._request_shutdown()

    shutdown_task = asyncio.create_task(trigger_shutdown())
    await asyncio.wait_for(proxy.serve_until_stopped(), timeout=1.0)
    await shutdown_task
    assert proxy._stop_event.is_set()


async def test_credential_proxy_stop_closes_runtime_caches(
    sample_proxy_config: ProxyConfig,
) -> None:
    """Verify stop() closes every CSP runtime's credential cache."""
    proxy = CredentialProxy(sample_proxy_config)
    await proxy.start()
    runtime = proxy.runtime_for(Supported_CSP_Tokens.AWS)

    await proxy.stop()

    with pytest.raises(CacheClosedError):
        await runtime.fetch_credentials("/anything")
    assert proxy._runtimes == {}


# ============================================================================
# main_entry tests
# ============================================================================
def test_main_entry_success(
    sample_proxy_config: ProxyConfig, sample_aws_env: dict[str, str]
) -> None:
    """Verify main_entry executes cleanly when configuration is valid."""
    with (
        patch("pki_pivot.http_proxy.load_config", return_value=sample_proxy_config),
        patch("pki_pivot.http_proxy.build_issuer_ssl_context", return_value=None),
        patch.object(
            CredentialProxy, "serve_until_stopped", new_callable=AsyncMock
        ) as mock_serve,
    ):
        main_entry()
        mock_serve.assert_called_once()


def test_main_entry_config_error() -> None:
    """Verify main_entry raises SystemExit when load_config fails."""
    with (
        patch(
            "pki_pivot.http_proxy.load_config",
            side_effect=ConfigError("Invalid config"),
        ),
        pytest.raises(SystemExit, match="Configuration error: Invalid config"),
    ):
        main_entry()


def test_main_entry_ssl_config_error(sample_proxy_config: ProxyConfig) -> None:
    """Verify main_entry raises SystemExit when build_issuer_ssl_context fails."""
    with (
        patch("pki_pivot.http_proxy.load_config", return_value=sample_proxy_config),
        patch(
            "pki_pivot.http_proxy.build_issuer_ssl_context",
            side_effect=ConfigError("SSL cert error"),
        ),
        pytest.raises(SystemExit, match="Configuration error: SSL cert error"),
    ):
        main_entry()


def test_main_entry_keyboard_interrupt(sample_proxy_config: ProxyConfig) -> None:
    """Verify main_entry catches KeyboardInterrupt cleanly."""
    with (
        patch("pki_pivot.http_proxy.load_config", return_value=sample_proxy_config),
        patch("pki_pivot.http_proxy.build_issuer_ssl_context", return_value=None),
        patch.object(
            CredentialProxy, "serve_until_stopped", side_effect=KeyboardInterrupt()
        ),
    ):
        main_entry()  # Should not raise exception
