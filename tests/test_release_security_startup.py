#!/usr/bin/env python3
"""
Focused Startup & Security Release Verification Suite for DeepfakeShield.

Verifies without touching the live database:
1. No hardcoded demo passwords, static bearer tokens, sample DEKs, or deterministic officer keys active outside DEMO_MODE=true.
2. Normal startup requires explicit DB, authentication, and STRICT_CRYPTO_ENFORCEMENT 256-bit keys.
3. STRICT_CRYPTO_ENFORCEMENT defaults to true and fails closed on missing, malformed, short, all-zero, or weak keys.
4. DEMO_MODE=true enables demo fallbacks only when NOT paired with PayPal production endpoints.
5. setup_disposable_db rejects unsafe defaults, missing confirmation, and non-disposable/live database names.
6. Test-only deterministic fixture keys and seeds in tests/test_fixtures.py remain reproducible.
"""

import hashlib
import json
import os
import subprocess
import sys
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import crypto_verifier
import setup_disposable_db
from backend import database as db_mod
from backend import main as main_mod
from backend.paypal_client import PayPalClient, PayPalClientConfigurationError
from tests.test_fixtures import (
    TEST_ATTESTATION_SECRET,
    TEST_ATTESTATION_SECRET_HEX,
    TEST_AUTH_ASSERTION_KEY,
    TEST_AUTH_ASSERTION_KEY_HEX,
    TEST_BLIND_INDEX_KEY,
    TEST_BLIND_INDEX_KEY_HEX,
    TEST_BOB_DETERMINISTIC_SEED,
    TEST_CAROL_DETERMINISTIC_SEED,
    TEST_SAMPLE_DEK,
)


def _clear_security_env(monkeypatch):
    for key in (
        "DEMO_MODE",
        "STRICT_CRYPTO_ENFORCEMENT",
        "ATTESTATION_SECRET",
        "BLIND_INDEX_KEY",
        "AUTH_ASSERTION_KEY",
        "PGPASSWORD",
        "PGDATABASE",
        "DISPOSABLE_PGDATABASE",
        "CONFIRM_DISPOSABLE_DB_RESET",
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
    monkeypatch.setenv("ATTESTATION_SECRET", TEST_ATTESTATION_SECRET_HEX)
    monkeypatch.setenv("BLIND_INDEX_KEY", TEST_BLIND_INDEX_KEY_HEX)
    monkeypatch.setenv("AUTH_ASSERTION_KEY", TEST_AUTH_ASSERTION_KEY_HEX)
    monkeypatch.setenv("PGPASSWORD", "explicit_pg_pass")
    monkeypatch.setenv("APP_PASSWORD", "explicit_app_pass")
    monkeypatch.setenv("VERIFIER_PASSWORD", "explicit_verifier_pass")
    monkeypatch.setenv("WORKER_PASSWORD", "explicit_worker_pass")
    monkeypatch.setenv("AUDITOR_PASSWORD", "explicit_auditor_pass")
    monkeypatch.setenv("ALICE_PASSWORD", "explicit_alice_secret")
    monkeypatch.setenv("BOB_PASSWORD", "explicit_bob_secret")
    monkeypatch.setenv("CAROL_PASSWORD", "explicit_carol_secret")
    monkeypatch.setenv("DAVE_PASSWORD", "explicit_dave_secret")


def test_no_hardcoded_fallback_constants_on_crypto_or_database_modules():
    for removed in ("DEFAULT_ATTESTATION_SECRET", "DEFAULT_BLIND_INDEX_KEY", "DEFAULT_AUTH_ASSERTION_KEY"):
        assert not hasattr(crypto_verifier, removed), f"{removed} must not exist on crypto_verifier"
        assert not hasattr(db_mod, removed), f"{removed} must not exist on backend.database"
    for removed_seed in ("BOB_DETERMINISTIC_SEED", "CAROL_DETERMINISTIC_SEED"):
        assert not hasattr(db_mod, removed_seed), f"{removed_seed} must not be exported on backend.database"


def test_normal_mode_fails_closed_without_explicit_credentials(monkeypatch):
    _clear_security_env(monkeypatch)
    main_mod.reset_auth_sessions()

    assert db_mod.is_demo_mode() is False
    assert crypto_verifier.is_strict_crypto_enabled() is True
    assert main_mod.AUTH_SESSIONS == {}
    assert db_mod.get_officer_private_keys() == {}

    # Strict crypto enforcement is enabled by default and fails without keys
    with pytest.raises(RuntimeError, match="STRICT_CRYPTO_ENFORCEMENT|ATTESTATION_SECRET"):
        main_mod.validate_runtime_security_configuration()

    # Cannot disable STRICT_CRYPTO_ENFORCEMENT outside DEMO_MODE=true
    monkeypatch.setenv("STRICT_CRYPTO_ENFORCEMENT", "false")
    with pytest.raises(RuntimeError, match="cannot be disabled outside DEMO_MODE=true"):
        main_mod.validate_runtime_security_configuration()

    # DB role passwords fail closed outside DEMO_MODE=true
    for db_var in ("APP_PASSWORD", "VERIFIER_PASSWORD", "WORKER_PASSWORD", "AUDITOR_PASSWORD", "PGPASSWORD"):
        with pytest.raises(RuntimeError, match=db_var):
            db_mod._resolve_db_password(db_var)

    # Demo secrets, seeds, passwords, and static bearer tokens fail closed outside DEMO_MODE=true
    with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
        db_mod.seed_demo_data()
    with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
        db_mod.get_demo_officer_seed(db_mod.BOB_CRED_ID)
    with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
        db_mod.get_demo_sample_dek()
    with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
        main_mod.get_demo_operator_password("alice_ap_maker")
    with pytest.raises(RuntimeError, match="DEMO_MODE=true"):
        main_mod._build_demo_sessions()


def test_normal_mode_rejects_missing_malformed_and_weak_crypto_keys(monkeypatch):
    _clear_security_env(monkeypatch)
    # Leave STRICT_CRYPTO_ENFORCEMENT unset to prove default is enabled
    assert crypto_verifier.is_strict_crypto_enabled() is True

    monkeypatch.setenv("ATTESTATION_SECRET", "not-valid-hex!")
    monkeypatch.setenv("BLIND_INDEX_KEY", TEST_BLIND_INDEX_KEY_HEX)
    monkeypatch.setenv("AUTH_ASSERTION_KEY", TEST_AUTH_ASSERTION_KEY_HEX)
    with pytest.raises(RuntimeError, match="malformed"):
        main_mod.validate_runtime_security_configuration()

    # Too short (< 32 bytes / 64 hex chars)
    monkeypatch.setenv("ATTESTATION_SECRET", "0123456789abcdef" * 2)
    with pytest.raises(RuntimeError, match="minimum 32 bytes"):
        main_mod.validate_runtime_security_configuration()

    # All-zero key rejected
    monkeypatch.setenv("ATTESTATION_SECRET", "00" * 32)
    with pytest.raises(RuntimeError, match="weak"):
        main_mod.validate_runtime_security_configuration()

    # Low-entropy repeated-byte key rejected (e.g. "aa" * 32)
    monkeypatch.setenv("ATTESTATION_SECRET", "aa" * 32)
    with pytest.raises(RuntimeError, match="weak"):
        main_mod.validate_runtime_security_configuration()

    # Valid keys pass crypto check, then require DB & operator credentials
    monkeypatch.setenv("ATTESTATION_SECRET", TEST_ATTESTATION_SECRET_HEX)
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
    monkeypatch.setenv("ATTESTATION_SECRET", TEST_ATTESTATION_SECRET_HEX)
    monkeypatch.setenv("BLIND_INDEX_KEY", TEST_BLIND_INDEX_KEY_HEX)
    monkeypatch.setenv("AUTH_ASSERTION_KEY", TEST_AUTH_ASSERTION_KEY_HEX)

    db_mod.validate_demo_mode_paypal_safety()
    main_mod.validate_runtime_security_configuration()
    assert db_mod._resolve_db_password("APP_PASSWORD") == "app_secret_pass"
    keys = db_mod.get_officer_private_keys()
    assert db_mod.BOB_CRED_ID in keys and db_mod.CAROL_CRED_ID in keys
    assert len(db_mod.get_demo_sample_dek()) == 32
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


def test_setup_disposable_db_rejects_unsafe_defaults_and_live_databases(monkeypatch):
    _clear_security_env(monkeypatch)

    # Requires explicit confirmation
    with pytest.raises(RuntimeError, match="--confirm-drop"):
        setup_disposable_db.get_env_config(confirm_drop=False)

    # Missing database name rejected (never defaults to deepfakeshield_db)
    with pytest.raises(RuntimeError, match="DISPOSABLE_PGDATABASE"):
        setup_disposable_db.get_env_config(confirm_drop=True)

    # Protected/live database names rejected
    for bad_db in ("deepfakeshield_db", "postgres", "template1", "prod_financials"):
        monkeypatch.setenv("DISPOSABLE_PGDATABASE", bad_db)
        with pytest.raises(RuntimeError, match="Refusing|disposable"):
            setup_disposable_db.get_env_config(confirm_drop=True)

    # Valid disposable name still requires explicit role passwords (no default passwords)
    monkeypatch.setenv("DISPOSABLE_PGDATABASE", "deepfakeshield_disposable_test")
    with pytest.raises(RuntimeError, match="PGPASSWORD"):
        setup_disposable_db.get_env_config(confirm_drop=True)

    monkeypatch.setenv("PGPASSWORD", "test_pg_admin")
    monkeypatch.setenv("APP_PASSWORD", "test_app_pw")
    monkeypatch.setenv("VERIFIER_PASSWORD", "test_verifier_pw")
    monkeypatch.setenv("WORKER_PASSWORD", "test_worker_pw")
    monkeypatch.setenv("AUDITOR_PASSWORD", "test_auditor_pw")
    cfg = setup_disposable_db.get_env_config(confirm_drop=True)
    assert cfg["database"] == "deepfakeshield_disposable_test"
    assert cfg["app_password"] == "test_app_pw"


def test_test_fixtures_deterministic_and_functional(monkeypatch):
    _clear_security_env(monkeypatch)
    _set_valid_non_demo_env(monkeypatch)

    assert len(TEST_ATTESTATION_SECRET) == 32
    assert len(TEST_BLIND_INDEX_KEY) == 32
    assert len(TEST_AUTH_ASSERTION_KEY) == 32
    assert len(TEST_SAMPLE_DEK) == 32
    assert ec.derive_private_key(TEST_BOB_DETERMINISTIC_SEED, ec.SECP256R1())
    assert ec.derive_private_key(TEST_CAROL_DETERMINISTIC_SEED, ec.SECP256R1())

    payload = json.dumps({"sender_batch_header": {"sender_batch_id": "t1"}, "items": []})
    aad = b"DEEPFAKESHIELD-PAYOUT-v1"
    nonce, ct, tag = crypto_verifier.encrypt_payload(TEST_SAMPLE_DEK, payload.encode("utf-8"), aad)
    att, p_digest, _ = crypto_verifier.verify_and_attest_snapshot(
        dek=TEST_SAMPLE_DEK,
        nonce=nonce,
        ciphertext=ct,
        tag=tag,
        aad=aad,
        expected_plaintext_json=payload,
        batch_id=uuid.uuid4(),
        attestation_secret=TEST_ATTESTATION_SECRET,
    )
    assert len(att) == 32
    assert p_digest == hashlib.sha256(payload.encode("utf-8")).hexdigest()
    assert len(crypto_verifier.compute_recipient_blind_index("fixture@example.com")) == 64


@pytest.mark.parametrize(
    "bad_env",
    [
        {},
        {"ATTESTATION_SECRET": "not-hex", "BLIND_INDEX_KEY": TEST_BLIND_INDEX_KEY_HEX, "AUTH_ASSERTION_KEY": TEST_AUTH_ASSERTION_KEY_HEX},
        {"ATTESTATION_SECRET": "00" * 32, "BLIND_INDEX_KEY": TEST_BLIND_INDEX_KEY_HEX, "AUTH_ASSERTION_KEY": TEST_AUTH_ASSERTION_KEY_HEX},
        {"ATTESTATION_SECRET": "aa" * 32, "BLIND_INDEX_KEY": TEST_BLIND_INDEX_KEY_HEX, "AUTH_ASSERTION_KEY": TEST_AUTH_ASSERTION_KEY_HEX},
    ],
)
def test_subprocess_crypto_verifier_defaults_strict_and_fails_closed(bad_env):
    clean_env = {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "PYTHONPATH", "TEMP", "TMP")}
    clean_env.update(bad_env)
    proc = subprocess.run(
        [sys.executable, "-c", "import crypto_verifier"],
        cwd=REPO_ROOT,
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0, f"Expected crypto_verifier import to fail closed! stdout={proc.stdout} stderr={proc.stderr}"


def test_subprocess_clean_import_with_valid_keys_has_empty_demo_tables():
    clean_env = {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "PYTHONPATH", "TEMP", "TMP")}
    clean_env["DEMO_MODE"] = "false"
    clean_env["ATTESTATION_SECRET"] = TEST_ATTESTATION_SECRET_HEX
    clean_env["BLIND_INDEX_KEY"] = TEST_BLIND_INDEX_KEY_HEX
    clean_env["AUTH_ASSERTION_KEY"] = TEST_AUTH_ASSERTION_KEY_HEX
    code = (
        "import backend.env_loader as el; el.load_env_file = lambda *a, **k: False; "
        "import crypto_verifier, backend.database as db, backend.main as m; "
        "assert crypto_verifier.is_strict_crypto_enabled() is True; "
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
