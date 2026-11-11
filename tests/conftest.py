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

import pytest
import requests
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
