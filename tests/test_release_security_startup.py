#!/usr/bin/env python3
"""
Focused Startup & Security Release Verification Suite for DeepfakeShield.

Verifies without touching the live database:
1. No hardcoded demo passwords, static bearer tokens, or deterministic officer keys active by default.
2. Normal startup requires explicit DB, authentication, and STRICT_CRYPTO_ENFORCEMENT keys.
3. STRICT_CRYPTO_ENFORCEMENT is enabled by default and cannot be disabled outside DEMO_MODE=true.
4. DEMO_MODE=true enables demo fallbacks only when NOT paired with PayPal production endpoints.
5. Explicit env signing keys and operator credentials work outside DEMO_MODE=true.
"""

import os
import sys
import subprocess
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend import database as db_mod
from backend import main as main_mod
from backend.paypal_client import PayPalClient, PayPalClientConfigurationError


def _clear_security_env(monkeypatch):
    for key in (
        "DEMO_MODE",
        "STRICT_CRYPTO_ENFORCEMENT",
        "ATTESTATION_SECRET",
        "BLIND_INDEX_KEY",
        "AUTH_ASSERTION_KEY",
        "PGPASSWORD",
        "APP_PASSWORD",
        "VERIFIER_PASSWORD",
        "WORKER_PASSWORD",
        "AUDITOR_PASSWORD",
        "ALICE_PASSWORD",
        "ALICE_PASSWORD_HASH",
        "BOB_PASSWORD",
        "BOB_PASSWORD_HASH",
        "CAROL_PASSWORD",
        "CAROL_PASSWORD_HASH",
        "DAVE_PASSWORD",
        "DAVE_PASSWORD_HASH",
        "EVE_PASSWORD",
        "EVE_PASSWORD_HASH",
        "OPERATOR_CREDENTIALS",
        "BOB_SIGNING_PRIVATE_KEY_PEM",
        "CAROL_SIGNING_PRIVATE_KEY_PEM",
        "OFFICER_SIGNING_KEYS_JSON",
    ):
        monkeypatch.delenv(key, raising=False)


def _set_valid_non_demo_env(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("STRICT_CRYPTO_ENFORCEMENT", "true")
    monkeypatch.setenv("ATTESTATION_SECRET", "a" * 64)
    monkeypatch.setenv("BLIND_INDEX_KEY", "b" * 64)
    monkeypatch.setenv("AUTH_ASSERTION_KEY", "c" * 64)
    monkeypatch.setenv("PGPASSWORD", "explicit_pg_pass")
    monkeypatch.setenv("APP_PASSWORD", "explicit_app_pass")
    monkeypatch.setenv("VERIFIER_PASSWORD", "explicit_verifier_pass")
    monkeypatch.setenv("WORKER_PASSWORD", "explicit_worker_pass")
    monkeypatch.setenv("AUDITOR_PASSWORD", "explicit_auditor_pass")
    monkeypatch.setenv("ALICE_PASSWORD", "explicit_alice_secret")
    monkeypatch.setenv("BOB_PASSWORD", "explicit_bob_secret")
    monkeypatch.setenv("CAROL_PASSWORD", "explicit_carol_secret")
    monkeypatch.setenv("DAVE_PASSWORD", "explicit_dave_secret")


def test_normal_mode_fails_closed_without_explicit_credentials(monkeypatch):
    _clear_security_env(monkeypatch)
    main_mod.reset_auth_sessions()

    assert db_mod.is_demo_mode() is False
    assert main_mod.AUTH_SESSIONS == {}
    assert db_mod.get_officer_private_keys() == {}

    # Strict crypto enforcement is enabled by default and fails without keys
    with pytest.raises(RuntimeError, match="STRICT_CRYPTO_ENFORCEMENT"):
        main_mod.validate_runtime_security_configuration()

    # Cannot disable STRICT_CRYPTO_ENFORCEMENT outside DEMO_MODE=true
    monkeypatch.setenv("STRICT_CRYPTO_ENFORCEMENT", "false")
    with pytest.raises(RuntimeError, match="cannot be disabled outside DEMO_MODE=true"):
        main_mod.validate_runtime_security_configuration()

    # DB role passwords fail closed outside DEMO_MODE=true
    for db_var in ("APP_PASSWORD", "VERIFIER_PASSWORD", "WORKER_PASSWORD", "AUDITOR_PASSWORD", "PGPASSWORD"):
        with pytest.raises(RuntimeError, match=db_var):
            db_mod._resolve_db_password(db_var)

    # seed_demo_data refuses normal mode
    with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
        db_mod.seed_demo_data()


def test_normal_mode_rejects_missing_db_or_operator_passwords_even_with_crypto_keys(monkeypatch):
    _clear_security_env(monkeypatch)
    # Leave STRICT_CRYPTO_ENFORCEMENT unset to prove default is enabled
    monkeypatch.setenv("ATTESTATION_SECRET", "a" * 64)
    monkeypatch.setenv("BLIND_INDEX_KEY", "b" * 64)
    monkeypatch.setenv("AUTH_ASSERTION_KEY", "c" * 64)

    with pytest.raises(RuntimeError, match="APP_PASSWORD"):
        main_mod.validate_runtime_security_configuration()

    monkeypatch.setenv("APP_PASSWORD", "explicit_app")
    monkeypatch.setenv("VERIFIER_PASSWORD", "explicit_verifier")
    monkeypatch.setenv("WORKER_PASSWORD", "explicit_worker")
    monkeypatch.setenv("AUDITOR_PASSWORD", "explicit_auditor")

    with pytest.raises(RuntimeError, match="Explicit authentication credentials are required"):
        main_mod.validate_runtime_security_configuration()


def test_normal_mode_rejects_legacy_demo_passwords_tokens_and_mock_approvals(monkeypatch):
    _clear_security_env(monkeypatch)
    _set_valid_non_demo_env(monkeypatch)
    main_mod.reset_auth_sessions()

    main_mod.validate_runtime_security_configuration()
    assert main_mod.AUTH_SESSIONS == {}

    client = TestClient(main_mod.app)

    # Static pre-seeded demo bearer token must be rejected
    resp_static = client.get(
        "/api/beneficiaries",
        headers={"Authorization": "Bearer token-alice-maker"},
    )
    assert resp_static.status_code == 401

    # Hardcoded demo default password must fail
    resp_bad_pw = client.post(
        "/api/auth/login",
        json={"username": "alice_ap_maker", "password": "alice_secure_maker_pass_2026"},
    )
    assert resp_bad_pw.status_code == 401

    # Explicit env-configured operator credentials succeed with fresh sess-* token
    resp_login_bob = client.post(
        "/api/auth/login",
        json={"username": "bob_checker", "password": "explicit_bob_secret"},
    )
    assert resp_login_bob.status_code == 200
    bob_token = resp_login_bob.json()["access_token"]
    assert bob_token.startswith("sess-")

    # Simulated approvals are forbidden outside DEMO_MODE=true
    resp_mock = client.post(
        f"/api/batches/{uuid.uuid4()}/approve",
        json={"credential_id": db_mod.BOB_CRED_ID, "mock_simulation": True},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert resp_mock.status_code == 403


def test_explicit_pem_signing_key_loaded_without_demo_mode(monkeypatch):
    _clear_security_env(monkeypatch)
    _set_valid_non_demo_env(monkeypatch)

    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    pem_str = ephemeral_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("utf-8")
    monkeypatch.setenv("BOB_SIGNING_PRIVATE_KEY_PEM", pem_str)

    keys = db_mod.get_officer_private_keys()
    assert db_mod.BOB_CRED_ID in keys
    assert db_mod.CAROL_CRED_ID not in keys
    assert (
        keys[db_mod.BOB_CRED_ID].private_numbers().private_value
        == ephemeral_key.private_numbers().private_value
    )


def test_demo_mode_enables_sandbox_fallbacks_and_blocks_paypal_production(monkeypatch):
    _clear_security_env(monkeypatch)
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SIMULATOR")
    monkeypatch.setenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    monkeypatch.setenv("STRICT_CRYPTO_ENFORCEMENT", "true")
    monkeypatch.setenv("ATTESTATION_SECRET", "a" * 64)
    monkeypatch.setenv("BLIND_INDEX_KEY", "b" * 64)
    monkeypatch.setenv("AUTH_ASSERTION_KEY", "c" * 64)

    db_mod.validate_demo_mode_paypal_safety()
    main_mod.validate_runtime_security_configuration()
    assert db_mod._resolve_db_password("APP_PASSWORD") == "app_secret_pass"
    keys = db_mod.get_officer_private_keys()
    assert db_mod.BOB_CRED_ID in keys and db_mod.CAROL_CRED_ID in keys
    assert main_mod._verify_operator_credential("alice_ap_maker", "alice_secure_maker_pass_2026")

    for prod_url in (
        "https://api-m.paypal.com",
        "https://api.paypal.com",
        "https://www.paypal.com",
    ):
        monkeypatch.setenv("PAYPAL_BASE_URL", prod_url)
        with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
            db_mod.validate_demo_mode_paypal_safety()
        with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
            main_mod.validate_runtime_security_configuration()
        with pytest.raises(PayPalClientConfigurationError, match="DEMO_MODE=true"):
            PayPalClient(base_url=prod_url, mode="SIMULATOR").validate_configuration()
        with pytest.raises(PayPalClientConfigurationError, match="DEMO_MODE=true"):
            PayPalClient(
                client_id="cid",
                client_secret="csec",
                base_url=prod_url,
                mode="SANDBOX_API",
            ).validate_configuration()


def test_subprocess_clean_import_has_empty_demo_tables():
    clean_env = {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "PYTHONPATH", "TEMP", "TMP")}
    clean_env["DEMO_MODE"] = "false"
    code = (
        "import backend.env_loader as el; el.load_env_file = lambda *a, **k: False; "
        "import backend.database as db, backend.main as m; "
        "assert db.OFFICER_PRIVATE_KEYS == {}, db.OFFICER_PRIVATE_KEYS; "
        "assert m.AUTH_SESSIONS == {}, m.AUTH_SESSIONS; "
        "assert db.DB_ADMIN_PASSWORD is None and db.APP_PASS is None; "
        "print('CLEAN_IMPORT_OK')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert "CLEAN_IMPORT_OK" in proc.stdout
