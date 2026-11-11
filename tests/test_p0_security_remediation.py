#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — P0 Security Remediation Test Suite
Milestone: V10.1.3 P0 Security Remediation Sprint

Verifies all 14 mandatory security and regression requirements:
1. Forged WebAuthn signature rejected.
2. Genuine registered authenticator assertion accepted.
3. Replayed challenge rejected.
4. Unauthorized API request rejected (401 without token).
5. Authorized user cannot impersonate another officer (403 on role/identity mismatch).
6. Failed PayPal item remains FAILED.
7. Successful PayPal item becomes SETTLED only with provider evidence.
8. Partial batch response reconciled correctly (PARTIALLY_SETTLED).
9. Ambiguous timeout retains beneficiary locks (MANUAL_RECONCILIATION_REQUIRED).
10. Duplicate audio upload detected (replay_detected: true, policy_decision: 'BLOCKED').
11. Missing AASIST checkpoint explicitly labelled, never produces genuine AASIST score.
12. Missing cryptographic environment variables fail safely under STRICT_CRYPTO_ENFORCEMENT=true.
13. Legacy 6-field envelope rejected.
14. Auditor role cannot execute administrative DDL/mutations (least privilege).
"""

import os
import json
import uuid
import hashlib
import subprocess
import sys
import pytest
from psycopg.rows import dict_row
from fastapi.testclient import TestClient

from backend.database import (
    seed_demo_data,
    get_admin_conn,
    get_app_conn,
    get_verifier_conn,
    get_auditor_conn,
    get_worker_conn,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_EVE_UNAUTHORIZED,
    BOB_CRED_ID,
    CAROL_CRED_ID,
    OFFICER_PRIVATE_KEYS
)
from backend.audio_analyzer import (
    generate_synthetic_audio,
    analyze_audio_instruction,
    AUDIO_HASH_REGISTRY
)
from backend.payout_service import (
    create_draft_batch,
    finalize_batch,
    record_officer_webauthn_approval,
    issue_officer_challenge
)
from backend.outbox_worker import OutboxWorker
from backend.main import app, AUTH_SESSIONS
from crypto_verifier import (
    create_webauthn_assertion,
    encrypt_payload,
    verify_and_attest_snapshot,
    verify_envelope_before_submission
)

@pytest.fixture(autouse=True)
def clean_db():
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
    AUDIO_HASH_REGISTRY.clear()
    yield

# ==============================================================================
# REQUIREMENT 1: Forged WebAuthn signature rejected
# ==============================================================================
def test_req01_forged_webauthn_signature_rejected():
    """Negative Test: Corrupted or forged signature bytes must be rejected before state mutation."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "250.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c_data, a_data, valid_sig = create_webauthn_assertion(
        bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )
    forged_sig = b"\x30\x45\x02\x20" + os.urandom(32) + b"\x02\x21\x00" + os.urandom(32)

    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, forged_sig, challenge_id=chal["challenge_id"]
        )
    assert "Cryptographic WebAuthn signature verification failed" in str(exc.value)

    # Verify no approval persisted
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state FROM payout_batches WHERE id = %s;", (batch_id,))
            b = cur.fetchone()
            assert b["gateway_batch_state"] == "READY_FOR_CHECKER"


# ==============================================================================
# REQUIREMENT 2: Genuine registered authenticator assertion accepted
# ==============================================================================
def test_req02_genuine_registered_authenticator_accepted():
    """Positive Test: Genuine ECDSA P-256 WebAuthn assertion from registered key is accepted."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "350.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )
    appr = record_officer_webauthn_approval(
        batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=chal["challenge_id"]
    )
    assert appr["approval_count"] == 1
    assert appr["requires_more_approvals"] is True
    assert appr["gateway_batch_state"] == "READY_FOR_CHECKER"


# ==============================================================================
# REQUIREMENT 3: Replayed challenge rejected
# ==============================================================================
def test_req03_replayed_challenge_rejected():
    """A consumed one-time challenge cannot be reused (replay protection)."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "450.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    chal_bytes = chal["challenge_bytes"]
    chal_id = chal["challenge_id"]

    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, chal_bytes, "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )

    # First consumption succeeds
    appr1 = record_officer_webauthn_approval(
        batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=chal_id
    )
    assert appr1["approval_count"] == 1

    # Second consumption of the exact same assertion/challenge must be rejected as replay
    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=chal_id
        )
    assert "already been consumed" in str(exc.value) or "Officer has already approved" in str(exc.value)


# ==============================================================================
# REQUIREMENT 4: Unauthorized API request rejected (401 without token)
# ==============================================================================
def test_req04_unauthorized_api_request_rejected_401():
    """Unauthenticated calls to protected routes return HTTP 401."""
    client = TestClient(app)
    # 1. Create batch without auth
    res = client.post("/api/batches/create", json={"items": []})
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]

    # 2. Finalize batch without auth
    res = client.post(f"/api/batches/{uuid.uuid4()}/finalize")
    assert res.status_code == 401

    # 3. Approve batch without auth
    res = client.post(f"/api/batches/{uuid.uuid4()}/approve", json={"credential_id": BOB_CRED_ID})
    assert res.status_code == 401


# ==============================================================================
# REQUIREMENT 5: Authorized user cannot impersonate another officer
# ==============================================================================
def test_req05_authorized_user_cannot_impersonate_another_officer():
    """Role enforcement: Eve (AP_CLERK) cannot approve; Bob cannot approve as Carol."""
    client = TestClient(app)

    # Find tokens from server session map
    eve_token = None
    bob_token = None
    for tok, sess in AUTH_SESSIONS.items():
        if sess["username"] == "eve_unauthorized":
            eve_token = tok
        elif sess["username"] == "bob_checker":
            bob_token = tok

    # 1. Eve (AP_CLERK) calls approve endpoint -> 403 Forbidden
    res = client.post(
        f"/api/batches/{uuid.uuid4()}/approve",
        json={"credential_id": BOB_CRED_ID},
        headers={"Authorization": f"Bearer {eve_token}"}
    )
    assert res.status_code == 403
    assert "TREASURY_OFFICER" in res.json()["detail"]

    # 2. Bob (TREASURY_OFFICER) claims Carol's user ID -> 403 Session identity mismatch
    res = client.post(
        f"/api/batches/{uuid.uuid4()}/approve",
        json={
            "credential_id": CAROL_CRED_ID,
            "officer_user_id": USER_CAROL_CHECKER2
        },
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert res.status_code == 403
    assert "Session identity mismatch" in res.json()["detail"]


def approve_both_officers(batch_id):
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]
    chal1 = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    chal2 = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
    c1, a1, s1 = create_webauthn_assertion(bob_priv, chal1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    c2, a2, s2 = create_webauthn_assertion(carol_priv, chal2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c1, a1, s1, challenge_id=chal1["challenge_id"])
    record_officer_webauthn_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c2, a2, s2, challenge_id=chal2["challenge_id"])


# ==============================================================================
# REQUIREMENT 6: Failed PayPal item remains FAILED
# ==============================================================================
def test_req06_failed_paypal_item_remains_failed():
    """Item marked FAILED by PayPal is persisted as FAILED and never SETTLED."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "750.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    approve_both_officers(batch_id)

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, sender_item_id FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm_db = cur.fetchone()

    # Worker processes job with simulated failure for this item
    worker = OutboxWorker(worker_id="test-recon-fail-worker")

    # Mock PayPal fetch_payout_status to return FAILED
    def mock_fetch_fail(p_id):
        return (200, {
            "batch_header": {"payout_batch_id": p_id, "batch_status": "DENIED"},
            "items": [{
                "sender_item_id": itm_db["sender_item_id"],
                "payout_item_id": "SB-FAIL-ITEM-1",
                "transaction_status": "FAILED",
                "activity_id": "ACT-FAIL-1"
            }]
        })
    worker.paypal_client.fetch_payout_status = mock_fetch_fail
    worker.process_next_job(force_timeout=False)

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_item_state, paypal_item_state FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm = cur.fetchone()
            assert itm["gateway_item_state"] == "FAILED"
            assert itm["paypal_item_state"] == "FAILED"


# ==============================================================================
# REQUIREMENT 7: Successful PayPal item becomes SETTLED only with provider evidence
# ==============================================================================
def test_req07_successful_paypal_item_settled_with_evidence():
    """Item becomes SETTLED only when provider explicitly confirms SUCCESS."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "850.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    approve_both_officers(batch_id)

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, sender_item_id FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm_db = cur.fetchone()

    worker = OutboxWorker(worker_id="test-recon-success-worker")
    def mock_fetch_success(p_id):
        return (200, {
            "batch_header": {"payout_batch_id": p_id, "batch_status": "SUCCESS"},
            "items": [{
                "sender_item_id": itm_db["sender_item_id"],
                "payout_item_id": "SB-SUCCESS-ITEM-1",
                "transaction_status": "SUCCESS",
                "activity_id": "ACT-OK-1"
            }]
        })
    worker.paypal_client.fetch_payout_status = mock_fetch_success
    res = worker.process_next_job(force_timeout=False)
    assert res["status"] == "SETTLED"

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_item_state, paypal_item_state FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm = cur.fetchone()
            assert itm["gateway_item_state"] == "SETTLED"
            assert itm["paypal_item_state"] == "SUCCESS"


# ==============================================================================
# REQUIREMENT 8: Partial batch response reconciled correctly
# ==============================================================================
def test_req08_partial_batch_response_reconciled_correctly():
    """Multi-item batch with 1 SUCCESS and 1 FAILED item resolves to PARTIALLY_SETTLED."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[
            {"beneficiary_id": "30000000-0000-0000-0000-000000000001", "amount_usd": "600.00", "receiver_email": "contractor.acme@example.com"},
            {"beneficiary_id": "30000000-0000-0000-0000-000000000001", "amount_usd": "400.00", "receiver_email": "contractor.acme@example.com"}
        ]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    approve_both_officers(batch_id)

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, sender_item_id FROM payout_items WHERE batch_id = %s ORDER BY id ASC;", (batch_id,))
            items = cur.fetchall()

    worker = OutboxWorker(worker_id="test-partial-worker")
    def mock_fetch_partial(p_id):
        return (200, {
            "batch_header": {"payout_batch_id": p_id, "batch_status": "DENIED"},
            "items": [
                {"sender_item_id": items[0]["sender_item_id"], "payout_item_id": "P-OK", "transaction_status": "SUCCESS"},
                {"sender_item_id": items[1]["sender_item_id"], "payout_item_id": "P-FAIL", "transaction_status": "FAILED"}
            ]
        })
    worker.paypal_client.fetch_payout_status = mock_fetch_partial
    res = worker.process_next_job(force_timeout=False)
    assert res["status"] == "PARTIALLY_SETTLED"

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, gateway_item_state FROM payout_items WHERE batch_id = %s ORDER BY id ASC;", (batch_id,))
            res_items = cur.fetchall()
            assert res_items[0]["gateway_item_state"] == "SETTLED"
            assert res_items[1]["gateway_item_state"] == "FAILED"


# ==============================================================================
# REQUIREMENT 9: Ambiguous timeout retains beneficiary locks
# ==============================================================================
def test_req09_ambiguous_timeout_retains_beneficiary_locks():
    """HTTP 504 ambiguous timeout transitions to MANUAL_RECONCILIATION_REQUIRED and keeps locks."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "950.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    approve_both_officers(batch_id)

    worker = OutboxWorker(worker_id="test-timeout-lock-worker")
    res = worker.process_next_job(force_timeout=True)
    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state FROM payout_batches WHERE id = %s;", (batch_id,))
            assert cur.fetchone()["gateway_batch_state"] == "MANUAL_RECONCILIATION_REQUIRED"
            cur.execute("""
                SELECT COUNT(*) FROM beneficiary_submission_locks
                WHERE beneficiary_id = '30000000-0000-0000-0000-000000000001' AND released_at IS NULL;
            """)
            assert cur.fetchone()["count"] == 1  # Lock remains active


# ==============================================================================
# REQUIREMENT 10: Duplicate audio upload detected & blocked
# ==============================================================================
def test_req10_duplicate_audio_upload_detected():
    """Identical audio bytes are detected as replay attack and immediately blocked."""
    audio_bytes = generate_synthetic_audio(duration_sec=3.0, is_spoof=False)
    eval1 = analyze_audio_instruction(audio_bytes)
    assert eval1["replay_detected"] is False
    assert eval1["recommendation"] == "APPROVE"

    eval2 = analyze_audio_instruction(audio_bytes)
    assert eval2["replay_detected"] is True
    assert eval2["policy_decision"] == "BLOCKED"
    assert eval2["recommendation"] == "TERMINATE"
    assert eval2["acoustic_signal"] == "REPLAY_ATTACK_DETECTED"


# ==============================================================================
# REQUIREMENT 11: Missing AASIST checkpoint explicitly labelled
# ==============================================================================
def test_req11_missing_aasist_checkpoint_explicitly_labelled():
    """Audio analyzer explicitly disclaims AASIST and indicates heuristic fallback."""
    audio_bytes = generate_synthetic_audio(duration_sec=2.5, is_spoof=False)
    eval_res = analyze_audio_instruction(audio_bytes)
    assert eval_res["model_version"] == "ACOUSTIC_FFT_HEURISTIC_V1"
    assert eval_res["checkpoint_hash"] is None
    assert eval_res["model_type"] == "SPECTRAL_FFT_HEURISTIC"
    assert eval_res["is_neural_model"] is False
    assert "Heuristic spectral analysis only" in eval_res["notice"]


# ==============================================================================
# REQUIREMENT 12: Missing crypto env vars fail safely under STRICT_CRYPTO_ENFORCEMENT=true
# ==============================================================================
def test_req12_missing_crypto_env_vars_fail_closed():
    """Subprocess test: Importing crypto_verifier with STRICT_CRYPTO_ENFORCEMENT=true fails closed."""
    cmd = [
        sys.executable,
        "-c",
        "import os; os.environ['STRICT_CRYPTO_ENFORCEMENT'] = 'true'; import crypto_verifier"
    ]
    env = os.environ.copy()
    env.pop("ATTESTATION_SECRET", None)
    env.pop("BLIND_INDEX_KEY", None)
    env.pop("AUTH_ASSERTION_KEY", None)
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode != 0
    assert "CRITICAL SECURITY ERROR: Required cryptographic keys missing" in proc.stderr


# ==============================================================================
# REQUIREMENT 13: Legacy 6-field envelope rejected
# ==============================================================================
def test_req13_legacy_6field_envelope_rejected():
    """verify_and_attest_snapshot rejects force_legacy, and verify_envelope_before_submission rejects legacy HMAC."""
    dek = os.urandom(32)
    canonical = '{"test":1}'
    nonce, ct, tag = encrypt_payload(dek, canonical.encode('utf-8'), b'aad')

    # 1. verify_and_attest_snapshot strictly rejects legacy format
    with pytest.raises(ValueError) as exc:
        verify_and_attest_snapshot(
            dek, nonce, ct, tag, b'aad', canonical, force_legacy=True
        )
    assert "Legacy 6-field envelope format is strictly deprecated and rejected" in str(exc.value)

    # 2. verify_envelope_before_submission rejects legacy 6-field HMAC
    fake_legacy_hmac = os.urandom(32)
    with pytest.raises(ValueError) as exc:
        verify_envelope_before_submission(
            dek=dek, nonce=nonce, ciphertext=ct, tag=tag, aad_text="aad",
            expected_plaintext_json=canonical, batch_id=uuid.uuid4(), snapshot_id=uuid.uuid4(),
            key_id=uuid.uuid4(), key_version=1, wrapped_dek=b"dek", attestation=fake_legacy_hmac
        )
    assert "Attestation signature mismatch" in str(exc.value)


# ==============================================================================
# REQUIREMENT 14: Auditor role cannot execute administrative DDL/mutations
# ==============================================================================
def test_req14_auditor_role_cannot_mutate_or_ddl():
    """Least privilege: deepfakeshield_auditor has SELECT only; INSERT, UPDATE, DROP are denied."""
    import psycopg.errors
    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            # 1. SELECT succeeds
            cur.execute("SELECT COUNT(*) FROM payout_batches;")
            assert cur.fetchone()[0] >= 0

            # 2. INSERT fails with InsufficientPrivilege
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("INSERT INTO users (id, username, role) VALUES (%s, 'bad', 'AUDITOR');", (uuid.uuid4(),))

    # Reset connection state after error
    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            # 3. UPDATE fails with InsufficientPrivilege
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("UPDATE payout_batches SET gateway_batch_state = 'BLOCKED';")

    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            # 4. DROP fails with InsufficientPrivilege
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("DROP TABLE users;")
