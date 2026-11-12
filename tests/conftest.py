#!/usr/bin/env python3
"""
Pytest Global Isolation & Network Guard for DeepfakeShield

Guarantees:
1. All tests run deterministically in PAYPAL_PROVIDER_MODE=SIMULATOR by default,
   isolated from project-root .env SANDBOX_API settings without mutating .env on disk.
2. Explicit SANDBOX_API tests must deliberately override mode or env vars inside the test.
3. Unmocked HTTP calls to PayPal endpoints are strictly blocked at requests.Session.request
   so placeholder recipients (e.g. @example.com) can never receive a real API call.
4. Process-wide PayPal OAuth token cache and simulator registry are cleared per test.
"""

import os
import sys
import pytest
import requests

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.test_fixtures import (
    TEST_ATTESTATION_SECRET_HEX,
    TEST_AUTH_ASSERTION_KEY_HEX,
    TEST_BLIND_INDEX_KEY_HEX,
)

# Inject test-only cryptographic keys before importing application modules in pytest
os.environ.setdefault("ATTESTATION_SECRET", TEST_ATTESTATION_SECRET_HEX)
os.environ.setdefault("BLIND_INDEX_KEY", TEST_BLIND_INDEX_KEY_HEX)
os.environ.setdefault("AUTH_ASSERTION_KEY", TEST_AUTH_ASSERTION_KEY_HEX)

from backend.paypal_client import clear_paypal_token_cache, reset_paypal_simulator


@pytest.fixture(autouse=True)
def isolate_paypal_test_environment(monkeypatch):
    """Forces deterministic SIMULATOR isolation and blocks unmocked PayPal HTTP traffic."""
    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SIMULATOR")
    monkeypatch.setenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    monkeypatch.delenv("PAYPAL_CLIENT_ID", raising=False)
    monkeypatch.delenv("PAYPAL_CLIENT_SECRET", raising=False)

    clear_paypal_token_cache()
    reset_paypal_simulator()

    orig_session_request = requests.sessions.Session.request

    def guarded_session_request(self, method, url, *args, **kwargs):
        url_str = str(url).lower()
        if "paypal.com" in url_str or "/v1/oauth2/token" in url_str or "/v1/payments/payouts" in url_str:
            raise RuntimeError(
                f"BLOCKED: Unmocked external PayPal HTTP request attempted during test ({method} {url})"
            )
        return orig_session_request(self, method, url, *args, **kwargs)

    monkeypatch.setattr(requests.sessions.Session, "request", guarded_session_request)

    yield

    clear_paypal_token_cache()
    reset_paypal_simulator()
