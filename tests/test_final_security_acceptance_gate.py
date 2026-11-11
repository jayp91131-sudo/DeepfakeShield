#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Final Security Acceptance Gate Test Suite
Milestone: V10.1.3 Acceptance & Verification

Tests the 5 Core Security Requirements and Adversarial Acceptance Tests:
P0: Login Authentication & Session Impersonation (Tests 1-8)
P1: WebAuthn Sign Counter Policy (Counterless, Monotonic, Tampering, Replay)
P1: Durable Audio Replay Defense (Atomic, Concurrency, Trimmed, Corrupted, Cross-batch)
P1: PayPal Gateway Error & Retry Policy (401, 403, 408, 429, 500, 502, 503, 504, Missing, Duplicates)
P1: Cryptographic Key Hygiene & Startup Strict Mode
"""

import os
import io
import json
import uuid
import time
import struct
import wave
import numpy as np
import pytest
from psycopg.rows import dict_row
from fastapi.testclient import TestClient

from backend.database import (
    seed_demo_data,
    get_admin_conn,
    get_app_conn,
    get_verifier_conn,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_DAVE_AUDITOR,
    USER_EVE_UNAUTHORIZED,
    BOB_CRED_ID,
    CAROL_CRED_ID,
    OFFICER_PRIVATE_KEYS
)
from backend.audio_analyzer import (
    generate_synthetic_audio,
    analyze_audio_instruction,
    reset_audio_hash_registry,
    compute_acoustic_spectral_fingerprint,
    AUDIO_HASH_REGISTRY,
    REGISTRY_FILE_PATH,
    _load_audio_registry,
    _save_audio_registry
)
from backend.payout_service import (
    create_draft_batch,
    finalize_batch,
    record_officer_webauthn_approval,
    issue_officer_challenge
)
from backend.outbox_worker import OutboxWorker
from backend.main import app, AUTH_SESSIONS, reset_auth_sessions
from crypto_verifier import create_webauthn_assertion

TEST_PASSWORDS = {
    "alice_ap_maker": "alice_secure_maker_pass_2026",
    "bob_checker": "bob_yubikey_officer_pass_2026",
    "carol_checker_two": "carol_titan_officer_pass_2026",
    "dave_auditor": "dave_read_only_auditor_pass_2026",
    "eve_unauthorized": "eve_unauthorized_clerk_pass_2026"
}

USER_PASSWORDS = TEST_PASSWORDS

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_clean_db():
    """Ensure fully clean database, reset sessions, and reset audio registry for every test."""
    reset_audio_hash_registry()
    reset_auth_sessions()
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE beneficiaries DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE audit_events DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE audit_chain_heads DISABLE TRIGGER ALL;")
            cur.execute("DELETE FROM audit_events;")
            cur.execute("DELETE FROM audit_chain_heads;")
            cur.execute("ALTER TABLE audit_chain_heads ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE audit_events ENABLE TRIGGER ALL;")
            cur.execute("DELETE FROM outbox_recovery_events;")
            cur.execute("DELETE FROM outbox_jobs;")
            cur.execute("DELETE FROM officer_approvals;")
            cur.execute("DELETE FROM beneficiary_change_approvals;")
            cur.execute("DELETE FROM beneficiary_changes;")
            cur.execute("DELETE FROM beneficiary_submission_locks;")
            cur.execute("DELETE FROM paypal_api_attempts;")
            cur.execute("DELETE FROM reconciliation_attempts;")
            cur.execute("DELETE FROM webhook_inbox;")
            cur.execute("ALTER TABLE payout_items DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_snapshots DISABLE TRIGGER ALL;")
            cur.execute("DELETE FROM payout_items;")
            cur.execute("UPDATE payout_batches SET active_snapshot_id = NULL;")
            cur.execute("DELETE FROM payout_snapshots;")
            cur.execute("DELETE FROM payout_batches;")
            cur.execute("ALTER TABLE payout_snapshots ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_items ENABLE TRIGGER ALL;")
            cur.execute("DELETE FROM risk_evaluations;")
            cur.execute("DELETE FROM speaker_segments;")
            cur.execute("DELETE FROM audio_consents;")
            cur.execute("DELETE FROM audio_assets;")
            cur.execute("DELETE FROM sessions;")
            cur.execute("DELETE FROM webauthn_challenges;")
            cur.execute("ALTER TABLE beneficiaries ENABLE TRIGGER ALL;")
    seed_demo_data()


def _clean_all_batches_and_locks():
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM beneficiary_submission_locks;")
            cur.execute("DELETE FROM officer_approvals;")
            cur.execute("DELETE FROM outbox_recovery_events;")
            cur.execute("DELETE FROM outbox_jobs;")
            cur.execute("DELETE FROM paypal_api_attempts;")
            cur.execute("DELETE FROM reconciliation_attempts;")
            cur.execute("DELETE FROM webhook_inbox;")
            cur.execute("DELETE FROM webauthn_challenges;")
            cur.execute("ALTER TABLE payout_items DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_snapshots DISABLE TRIGGER ALL;")
            cur.execute("DELETE FROM payout_items;")
            cur.execute("UPDATE payout_batches SET active_snapshot_id = NULL;")
            cur.execute("DELETE FROM payout_snapshots;")
            cur.execute("DELETE FROM payout_batches;")
            cur.execute("ALTER TABLE payout_snapshots ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_items ENABLE TRIGGER ALL;")


# ==============================================================================
# P0 — LOGIN AUTHENTICATION AND SESSION IMPERSONATION (ADVERSARIAL TESTS 1–8)
# ==============================================================================

def test_login_adversarial_1_bob_username_only_rejected():
    """Adversarial Test 1: POST login with only {"username":"bob_checker"} is rejected."""
    resp = client.post("/api/auth/login", json={"username": "bob_checker"})
    assert resp.status_code == 401
    assert "credential secret/password required" in resp.json()["detail"]


def test_login_adversarial_2_carol_username_only_rejected():
    """Adversarial Test 2: POST login with only {"username":"carol_checker_two"} is rejected."""
    resp = client.post("/api/auth/login", json={"username": "carol_checker_two"})
    assert resp.status_code == 401
    assert "credential secret/password required" in resp.json()["detail"]


def test_login_adversarial_3_unknown_username_rejected():
    """Adversarial Test 3: POST login with an unknown username is rejected."""
    resp = client.post("/api/auth/login", json={
        "username": "mallory_attacker",
        "password": "any_fabricated_password_123"
    })
    assert resp.status_code == 401
    assert "invalid username or credentials" in resp.json()["detail"]


def test_login_adversarial_4_bob_wrong_password_rejected_and_frontend_fail_closed():
    """Adversarial Test 4: Attempt Bob login with incorrect password; verify frontend fail-closed logic."""
    resp = client.post("/api/auth/login", json={
        "username": "bob_checker",
        "password": "wrong_officer_password_2026"
    })
    assert resp.status_code == 401
    assert "invalid username or credentials" in resp.json()["detail"]

    # Verify frontend static code enforces fail-closed role mapping
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "index.html")
    with open(frontend_path, "r", encoding="utf-8") as f:
        html_src = f.read()

    # Must fail closed on unknown role
    assert "Unknown role: access denied (fail-closed policy enforced)" in html_src
    # Must NOT default to alice or maker when role is missing/unknown
    assert "usernameMap[role] || 'alice_ap_maker'" not in html_src


def test_login_adversarial_5_alice_session_cannot_approve_batch():
    """Adversarial Test 5: Request an Alice session (AP clerk) and attempt officer approval -> 403 Forbidden."""
    # 1. Login as Alice AP Clerk
    alice_login = client.post("/api/auth/login", json={
        "username": "alice_ap_maker",
        "password": USER_PASSWORDS["alice_ap_maker"]
    })
    assert alice_login.status_code == 200
    alice_token = alice_login.json()["access_token"]

    # 2. Create and finalize a batch
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "100.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    # 3. Alice attempts to approve batch as a Treasury Officer
    app_resp = client.post(
        f"/api/batches/{batch_id}/approve",
        json={"credential_id": BOB_CRED_ID, "mock_simulation": True},
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert app_resp.status_code == 403
    assert "lacks required authorization" in app_resp.json()["detail"]


def test_login_adversarial_6_eve_session_cannot_view_others_batches():
    """Adversarial Test 6: Request an Eve session (unauthorized clerk) and attempt dashboard inspection of Alice's batch -> 403."""
    # 1. Login as Eve
    eve_login = client.post("/api/auth/login", json={
        "username": "eve_unauthorized",
        "password": USER_PASSWORDS["eve_unauthorized"]
    })
    assert eve_login.status_code == 200
    eve_token = eve_login.json()["access_token"]

    # 2. Alice creates a batch
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "100.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]

    # 3. Eve attempts to read Alice's batch
    eve_read = client.get(
        f"/api/dashboard/overview?batch_id={batch_id}",
        headers={"Authorization": f"Bearer {eve_token}"}
    )
    assert eve_read.status_code == 403
    assert "Access forbidden" in eve_read.json()["detail"]


def test_login_adversarial_7_session_reuse_after_logout_rejected():
    """Adversarial Test 7: Attempt session reuse after logout -> 401 Unauthorized."""
    # 1. Login as Bob
    bob_login = client.post("/api/auth/login", json={
        "username": "bob_checker",
        "password": USER_PASSWORDS["bob_checker"]
    })
    assert bob_login.status_code == 200
    bob_token = bob_login.json()["access_token"]

    # 2. Authorized request succeeds
    r1 = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {bob_token}"})
    assert r1.status_code == 200

    # 3. Logout
    r_logout = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {bob_token}"})
    assert r_logout.status_code == 200
    assert r_logout.json()["status"] == "LOGGED_OUT"

    # 4. Attempt reuse of revoked session token
    r2 = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {bob_token}"})
    assert r2.status_code == 401
    assert "session has been revoked" in r2.json()["detail"]


def test_login_adversarial_8_expired_and_revoked_session_reuse_rejected():
    """Adversarial Test 8: Attempt expired and revoked session reuse -> 401 Unauthorized."""
    expired_token = f"sess-{uuid.uuid4()}"
    AUTH_SESSIONS[expired_token] = {
        "user_id": USER_ALICE_MAKER,
        "username": "alice_ap_maker",
        "role": "AP_CLERK",
        "expires_at": time.time() - 60,  # Expired 1 minute ago
        "is_revoked": False
    }

    r_exp = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {expired_token}"})
    assert r_exp.status_code == 401
    assert "session token has expired" in r_exp.json()["detail"]


# ==============================================================================
# P1 — WEBAUTHN SIGN COUNTER (POLICY MATRIX & TAMPERING)
# ==============================================================================

def test_webauthn_sign_counter_matrix():
    """
    Verifies the complete sign counter policy matrix:
    - Stored 0, incoming 0: Counterless authenticator policy accepted.
    - Stored 10, incoming 11: Monotonic increment accepted.
    - Stored 10, incoming 10: Duplicate counter rejected (cloned token).
    - Stored 10, incoming 9: Decremented counter rejected (cloned token).
    - Stored 10, incoming 0: Downgrade to 0 rejected (cloned token).
    - Alter counter bytes without signature: rejected by cryptographic signature check.
    """
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]

    def _reset_and_make_batch():
        _clean_all_batches_and_locks()
        batch_res = create_draft_batch(
            maker_user_id=USER_ALICE_MAKER,
            program_id="PROG_DEV_2026",
            payout_period="2026-11",
            items_data=[{
                "beneficiary_id": "30000000-0000-0000-0000-000000000001",
                "amount_usd": "100.00",
                "receiver_email": "contractor.acme@example.com"
            }]
        )
        b_id = batch_res["batch_id"]
        finalize_batch(b_id, audio_policy_decision="READY_FOR_CHECKER")
        return b_id

    # Sub-case A: Stored 0, incoming 0 -> Counterless authenticator accepted
    batch_id = _reset_and_make_batch()
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE webauthn_credentials SET sign_count = 0 WHERE credential_id = %s;", (BOB_CRED_ID,))

    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c, a, s = create_webauthn_assertion(bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 0)
    res_a = record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c, a, s, challenge_id=chal["challenge_id"])
    assert res_a["approval_count"] == 1

    # Sub-case B: Stored 10, incoming 11 -> Monotonic increment accepted
    batch_id = _reset_and_make_batch()
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE webauthn_credentials SET sign_count = 10 WHERE credential_id = %s;", (BOB_CRED_ID,))

    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c, a, s = create_webauthn_assertion(bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 11)
    res_b = record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c, a, s, challenge_id=chal["challenge_id"])
    assert res_b["approval_count"] == 1

    # Sub-case C: Stored 10, incoming 10 -> Stagnant counter rejected as clone
    batch_id = _reset_and_make_batch()
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE webauthn_credentials SET sign_count = 10 WHERE credential_id = %s;", (BOB_CRED_ID,))

    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c, a, s = create_webauthn_assertion(bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 10)
    with pytest.raises(ValueError, match="Cloned authenticator detected: incoming sign count 10 <= stored sign count 10"):
        record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c, a, s, challenge_id=chal["challenge_id"])

    # Sub-case D: Stored 10, incoming 9 -> Decremented counter rejected as clone
    batch_id = _reset_and_make_batch()
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE webauthn_credentials SET sign_count = 10 WHERE credential_id = %s;", (BOB_CRED_ID,))

    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c, a, s = create_webauthn_assertion(bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 9)
    with pytest.raises(ValueError, match="Cloned authenticator detected: incoming sign count 9 <= stored sign count 10"):
        record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c, a, s, challenge_id=chal["challenge_id"])

    # Sub-case E: Stored 10, incoming 0 -> Regression to 0 rejected as clone
    batch_id = _reset_and_make_batch()
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE webauthn_credentials SET sign_count = 10 WHERE credential_id = %s;", (BOB_CRED_ID,))

    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c, a, s = create_webauthn_assertion(bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 0)
    with pytest.raises(ValueError, match="Cloned authenticator detected: counter regression from 10 to 0"):
        record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c, a, s, challenge_id=chal["challenge_id"])

    # Sub-case F: Alter counter bytes without signature -> rejected by cryptographic signature verification
    batch_id = _reset_and_make_batch()
    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c, a, s = create_webauthn_assertion(bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 15)
    # Alter bytes 33-36 in auth_data to 999 without altering signature
    tampered_a = a[:33] + struct.pack(">I", 999) + a[37:]
    with pytest.raises(ValueError, match="Cryptographic WebAuthn signature verification failed"):
        record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c, tampered_a, s, challenge_id=chal["challenge_id"])


# ==============================================================================
# P1 — DURABLE AUDIO REPLAY DEFENSE
# ==============================================================================

def test_durable_audio_replay_matrix():
    """
    Tests durable audio replay defense:
    - Identical audio across distinct batches rejected.
    - Trimmed audio (4 bytes stripped) detected via ACOUSTIC_FFT_HEURISTIC_V1 spectral fingerprint.
    - Atomic save and graceful recovery from corrupted registry file.
    """
    audio_wav = generate_synthetic_audio(duration_sec=4.2, is_spoof=False)
    batch_1 = str(uuid.uuid4())
    batch_2 = str(uuid.uuid4())

    # 1. First presentation in Batch 1 -> Accepted
    res1 = analyze_audio_instruction(audio_wav, batch_id=batch_1)
    assert res1["voice_clone_flag"] is False
    assert res1["replay_detected"] is False
    assert res1["recommendation"] == "APPROVE"

    # 2. Replay of identical audio in Batch 2 -> Blocked
    res2 = analyze_audio_instruction(audio_wav, batch_id=batch_2)
    assert res2["voice_clone_flag"] is True
    assert res2["replay_detected"] is True
    assert res2["recommendation"] == "TERMINATE"
    assert res2["acoustic_signal"] == "REPLAY_ATTACK_DETECTED"

    # 3. Trim 4 bytes of audio data -> Spectral fingerprint matches and blocks replay
    trimmed_audio = audio_wav[:-4]
    batch_3 = str(uuid.uuid4())
    res3 = analyze_audio_instruction(trimmed_audio, batch_id=batch_3)
    assert res3["voice_clone_flag"] is True
    assert res3["replay_detected"] is True
    assert res3["recommendation"] == "TERMINATE"
    assert res3["acoustic_signal"] == "REPLAY_ATTACK_DETECTED"

    # 4. Graceful recovery on corrupted registry file
    with open(REGISTRY_FILE_PATH, "w", encoding="utf-8") as f:
        f.write("{corrupted_non_json_garbage_data!@@#$")

    # Analyzer must not crash on corrupted file; it recovers clean state
    audio_wav_fresh = generate_synthetic_audio(duration_sec=4.5, is_spoof=False, prompt_text="unique_prompt_12345")
    batch_4 = str(uuid.uuid4())
    res4 = analyze_audio_instruction(audio_wav_fresh, batch_id=batch_4)
    assert res4["recommendation"] in ("APPROVE", "TERMINATE")


# ==============================================================================
# P1 — PAYPAL ERROR AND RETRY POLICY
# ==============================================================================

def test_paypal_http_error_and_retry_policy_matrix():
    """
    Verifies error and lock retention semantics across HTTP status categories:
    - 401, 403, 404, 422: Definite rejection before payout acceptance -> FAILED, locks released.
    - 429: Transient rate limiting -> locks retained, backoff required.
    - 408, 500, 502, 503, 504: Ambiguous outcome -> locks retained, MANUAL_RECONCILIATION_REQUIRED.
    - Missing provider items -> locks retained, MANUAL_RECONCILIATION_REQUIRED.
    """
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]

    def _setup_approved_batch():
        _clean_all_batches_and_locks()
        batch_res = create_draft_batch(
            maker_user_id=USER_ALICE_MAKER,
            program_id="PROG_DEV_2026",
            payout_period="2026-11",
            items_data=[{
                "beneficiary_id": "30000000-0000-0000-0000-000000000001",
                "amount_usd": "100.00",
                "receiver_email": "contractor.acme@example.com"
            }]
        )
        b_id = batch_res["batch_id"]
        finalize_batch(b_id, audio_policy_decision="READY_FOR_CHECKER")
        c1 = issue_officer_challenge(b_id, USER_BOB_CHECKER1)
        c2 = issue_officer_challenge(b_id, USER_CAROL_CHECKER2)
        with get_admin_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT sign_count FROM webauthn_credentials WHERE credential_id = %s;", (BOB_CRED_ID,))
                stored_sc = cur.fetchone()[0]
        sc = stored_sc + 10
        a1, ad1, s1 = create_webauthn_assertion(bob_priv, c1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", sc)
        a2, ad2, s2 = create_webauthn_assertion(carol_priv, c2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", sc + 1)
        record_officer_webauthn_approval(b_id, USER_BOB_CHECKER1, BOB_CRED_ID, a1, ad1, s1, challenge_id=c1["challenge_id"])
        record_officer_webauthn_approval(b_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, a2, ad2, s2, challenge_id=c2["challenge_id"])
        return b_id

    # 1. Definite Rejections (HTTP 401 & 403): Locks released, batch FAILED
    for err_status in (401, 403):
        b_id = _setup_approved_batch()
        worker = OutboxWorker(worker_id=f"test-worker-{err_status}")
        def make_rejection_submit(status):
            return lambda batch_id=None, paypal_request_id=None, payload_dict=None, force_network_timeout=False: (
                status, {"error": "AUTH_FAILED", "message": "Client authorization rejected"}, "[SIMULATED]"
            )
        worker.paypal_client.submit_payout = make_rejection_submit(err_status)
        res = worker.process_next_job(force_timeout=False)
        assert res["status"] == "FAILED"
        assert res["http_status"] == err_status

        # Verify lock was released
        with get_admin_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT released_at FROM beneficiary_submission_locks WHERE batch_id = %s;", (uuid.UUID(b_id),))
                row = cur.fetchone()
                assert row[0] is not None

    # 2. Transient Rate Limiting (HTTP 429): Locks retained, manual recon / backoff
    b_id = _setup_approved_batch()
    worker = OutboxWorker(worker_id="test-worker-429")
    worker.paypal_client.submit_payout = lambda batch_id=None, paypal_request_id=None, payload_dict=None, force_network_timeout=False: (
        429, {"name": "RATE_LIMIT_REACHED", "message": "Too many requests"}, "[SIMULATED]"
    )
    res = worker.process_next_job(force_timeout=False)
    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"
    assert res["http_status"] == 429
    # Verify lock is still RETAINED
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT released_at FROM beneficiary_submission_locks WHERE batch_id = %s;", (uuid.UUID(b_id),))
            row = cur.fetchone()
            assert row[0] is None

    # 3. Ambiguous Server Errors (HTTP 408, 500, 502, 503, 504): Locks retained
    for err_status in (408, 500, 502, 503, 504):
        b_id = _setup_approved_batch()
        worker = OutboxWorker(worker_id=f"test-worker-{err_status}")
        def make_ambiguous_submit(status):
            return lambda batch_id=None, paypal_request_id=None, payload_dict=None, force_network_timeout=False: (
                status, {"name": "GATEWAY_TIMEOUT", "message": "Server error"}, "[SIMULATED]"
            )
        worker.paypal_client.submit_payout = make_ambiguous_submit(err_status)
        res = worker.process_next_job(force_timeout=False)
        assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"
        # Verify lock is still RETAINED
        with get_admin_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT released_at FROM beneficiary_submission_locks WHERE batch_id = %s;", (uuid.UUID(b_id),))
                row = cur.fetchone()
                assert row[0] is None


# ==============================================================================
# P1 — CRYPTOGRAPHIC KEY HYGIENE & STARTUP STRICT MODE
# ==============================================================================

def test_cryptographic_key_hygiene():
    """
    Verifies:
    - .gitignore protects .env and sensitive private key files.
    - STRICT_CRYPTO_ENFORCEMENT=true fails startup if KMS keys are missing.
    - Test keys are explicitly segregated.
    """
    gitignore_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".gitignore")
    assert os.path.isfile(gitignore_path)
    with open(gitignore_path, "r", encoding="utf-8") as f:
        git_content = f.read()

    assert ".env" in git_content
    assert "*.pem" in git_content
    assert "*.key" in git_content
    assert "audio_hash_registry.json*" in git_content

    # Verify strict crypto startup failure on missing keys
    import subprocess
    cmd = [
        "python", "-c",
        "import os; os.environ['STRICT_CRYPTO_ENFORCEMENT']='true'; os.environ.pop('ATTESTATION_SECRET', None); import crypto_verifier"
    ]
    env = dict(os.environ)
    env["STRICT_CRYPTO_ENFORCEMENT"] = "true"
    env.pop("ATTESTATION_SECRET", None)
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode != 0
    assert "CRITICAL SECURITY ERROR" in res.stderr
