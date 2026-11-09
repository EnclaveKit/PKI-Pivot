"""Unit tests for Supported_CSP_Tokens enum and CSP registration invariants."""

from __future__ import annotations

import pytest

from pki_pivot.csp_token_requester.csp import Supported_CSP_Tokens


def test_supported_csp_tokens_enum_values() -> None:
    """Verify Supported_CSP_Tokens enum values and string representation."""
    assert Supported_CSP_Tokens.AWS == "aws"
    assert Supported_CSP_Tokens.AWS.value == "aws"
    assert str(Supported_CSP_Tokens.AWS) == "aws"
    assert Supported_CSP_Tokens("aws") is Supported_CSP_Tokens.AWS


def test_supported_csp_tokens_invalid_value() -> None:
    """Verify that unknown CSP names raise ValueError on instantiation."""
    with pytest.raises(ValueError):
        Supported_CSP_Tokens("gcp")
    with pytest.raises(ValueError):
        Supported_CSP_Tokens("azure")
