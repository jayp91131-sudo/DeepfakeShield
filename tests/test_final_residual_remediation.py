#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Final Residual Vulnerability Remediation Test Suite
Milestone: V10.1.3 Acceptance & Verification

Tests 15 Authoritative Security & Functional Acceptance Requirements:
1. Unknown WebAuthn challenge rejected.
2. Self-generated challenge rejected.
3. Cross-batch challenge rejected.
4. Authenticator counter tampering rejected.
5. UV policy enforced.
6. Browser source contains no static Bearer tokens.
7. Anonymous dashboard request rejected.
8. Unauthorized read of another batch rejected.
9. Missing PayPal item never becomes SUCCESS.
10. Unknown provider status enters safe reconciliation.
11. HTTP 401/429/500 handled without crashing.
12. Ambiguous payout retains beneficiary lock.
13. Audio fingerprint persists across restart.
14. Demo startup fails without secure cryptographic keys.
15. Expired and revoked sessions rejected.
"""

import os
import json
import uuid
import time
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
    USER_EVE_UNAUTHORIZED,
    BOB_CRED_ID,
    CAROL_CRED_ID,
    OFFICER_PRIVATE_KEYS
)
from backend.audio_analyzer import (
    generate_synthetic_audio,
    analyze_audio_instruction,
    reset_audio_hash_registry,
    AUDIO_HASH_REGISTRY,
    REGISTRY_FILE_PATH
)
from backend.payout_service import (
    create_draft_batch,
    finalize_batch,
    record_officer_webauthn_approval,
    issue_officer_challenge
)
from backend.outbox_worker import OutboxWorker
from backend.main import app, AUTH_SESSIONS
from crypto_verifier import create_webauthn_assertion

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_state():
    """Ensure clean database and authenticated sessions for each test."""
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


# ==============================================================================
# TEST 1: Unknown WebAuthn challenge rejected
# ==============================================================================
def test_unknown_challenge_rejected():
    """Assertion with an unknown/unregistered challenge ID is rejected."""
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
    unknown_challenge_id = str(uuid.uuid4())
    unknown_challenge_bytes = os.urandom(32)

    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, unknown_challenge_bytes, "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )

    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=unknown_challenge_id
        )
    assert "WebAuthn challenge not found or not issued by server" in str(exc.value)


# ==============================================================================
# TEST 2: Self-generated challenge rejected (No auto-insertion)
# ==============================================================================
def test_self_generated_challenge_rejected():
    """Attacker creates their own challenge without server issuing it; server rejects it."""
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
    self_generated_challenge = os.urandom(32)

    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, self_generated_challenge, "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )

    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig
        )
    assert "self-generated or unregistered challenge rejected" in str(exc.value)


# ==============================================================================
# TEST 3: Cross-batch challenge rejected
# ==============================================================================
def test_cross_batch_challenge_rejected():
    """Challenge issued for Batch A cannot be reused to approve Batch B."""
    b1 = create_draft_batch(USER_ALICE_MAKER, "PROG_DEV_2026", "2026-11", [{
        "beneficiary_id": "30000000-0000-0000-0000-000000000001",
        "amount_usd": "100.00",
        "receiver_email": "contractor.acme@example.com"
    }])
    finalize_batch(b1["batch_id"], audio_policy_decision="READY_FOR_CHECKER")

    b2 = create_draft_batch(USER_ALICE_MAKER, "PROG_DEV_2026", "2026-11", [{
        "beneficiary_id": "30000000-0000-0000-0000-000000000002",
        "amount_usd": "200.00",
        "receiver_email": "billing.infra@example.com"
    }])
    finalize_batch(b2["batch_id"], audio_policy_decision="READY_FOR_CHECKER")

    # Issue challenge for Batch 1
    chal_b1 = issue_officer_challenge(b1["batch_id"], USER_BOB_CHECKER1)
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]

    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, chal_b1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )

    # Attempt to use Batch 1's challenge to approve Batch 2
    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            b2["batch_id"], USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=chal_b1["challenge_id"]
        )
    assert "Challenge target digest mismatch" in str(exc.value)


# ==============================================================================
# TEST 4: Authenticator counter tampering rejected (Cloned authenticator)
# ==============================================================================
def test_authenticator_counter_tampering_rejected():
    """Incoming sign_count <= stored sign_count triggers clone detection."""
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

    # Artificially set stored sign count to 10 in database
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE webauthn_credentials SET sign_count = 10 WHERE credential_id = %s;", (BOB_CRED_ID,))

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)

    # Attempt approval with replayed counter 10 (or decremented 5)
    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", sign_count=5
    )

    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=chal["challenge_id"]
        )
    assert "Cloned authenticator detected: incoming sign count 5 <= stored sign count 10" in str(exc.value)


# ==============================================================================
# TEST 5: UV policy enforced (User Verification flag)
# ==============================================================================
def test_uv_policy_enforced():
    """Assertion with User Present (0x01) but missing User Verification (0x04) is rejected."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "550.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    chal = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)

    # Create assertion with user_verified = False (flags = 0x01 only)
    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal",
        sign_count=1, user_present=True, user_verified=False
    )

    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(
            batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data, a_data, sig, challenge_id=chal["challenge_id"]
        )
    assert "User Verification (UV) flag not set" in str(exc.value)


# ==============================================================================
# TEST 6: Browser source contains no static Bearer tokens
# ==============================================================================
def test_browser_source_contains_no_static_tokens():
    """Verifies that static/index.html does not contain hardcoded bearer tokens."""
    index_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        content = f.read()

    forbidden_tokens = [
        "token-bob-officer",
        "token-carol-officer",
        "token-alice-maker",
        "token-dave-auditor",
        "token-eve-unauthorized"
    ]
    for tok in forbidden_tokens:
        assert tok not in content, f"Hardcoded static token '{tok}' found in browser source code!"


# ==============================================================================
# TEST 7: Anonymous dashboard request rejected (HTTP 401)
# ==============================================================================
def test_anonymous_dashboard_request_rejected():
    """Unauthenticated calls to /api/dashboard/overview return HTTP 401."""
    resp = client.get("/api/dashboard/overview")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


# ==============================================================================
# TEST 8: Unauthorized read of another batch rejected (HTTP 403)
# ==============================================================================
def test_unauthorized_read_of_another_batch_rejected():
    """AP Clerk Eve cannot query the dashboard for a batch created by Maker Alice."""
    # Alice creates and finalizes a batch
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "650.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]

    # Eve attempts to inspect Alice's batch
    resp = client.get(
        f"/api/dashboard/overview?batch_id={batch_id}",
        headers={"Authorization": "Bearer token-eve-unauthorized"}
    )
    assert resp.status_code == 403
    assert "Access forbidden: AP_CLERK 'eve_unauthorized' is not authorized to inspect batch" in resp.json()["detail"]


# ==============================================================================
# TEST 9: Missing PayPal item never becomes SUCCESS
# ==============================================================================
def test_missing_paypal_item_never_becomes_success():
    """An item missing in the PayPal status response is never marked SUCCESS and triggers reconciliation."""
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

    # Approve by both officers
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]
    chal1 = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    chal2 = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
    c1, a1, s1 = create_webauthn_assertion(bob_priv, chal1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    c2, a2, s2 = create_webauthn_assertion(carol_priv, chal2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c1, a1, s1, challenge_id=chal1["challenge_id"])
    record_officer_webauthn_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c2, a2, s2, challenge_id=chal2["challenge_id"])

    worker = OutboxWorker(worker_id="test-missing-item-worker")
    # Provider status returns empty items array (item is completely missing)
    def mock_empty_items(p_id):
        return (200, {
            "batch_header": {"payout_batch_id": p_id, "batch_status": "SUCCESS"},
            "items": []
        })
    worker.paypal_client.fetch_payout_status = mock_empty_items
    res = worker.process_next_job(force_timeout=False)

    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_item_state, paypal_item_state, raw_provider_status_text FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm = cur.fetchone()
            assert itm["paypal_item_state"] != "SUCCESS"
            assert itm["paypal_item_state"] == "PENDING"
            assert "missing" in itm["raw_provider_status_text"].lower()


# ==============================================================================
# TEST 10: Unknown provider status enters safe reconciliation
# ==============================================================================
def test_unknown_provider_status_enters_safe_reconciliation():
    """Unrecognized provider status string maps safely to PENDING and triggers manual reconciliation."""
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

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]
    chal1 = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    chal2 = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
    c1, a1, s1 = create_webauthn_assertion(bob_priv, chal1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    c2, a2, s2 = create_webauthn_assertion(carol_priv, chal2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c1, a1, s1, challenge_id=chal1["challenge_id"])
    record_officer_webauthn_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c2, a2, s2, challenge_id=chal2["challenge_id"])

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, sender_item_id FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm_db = cur.fetchone()

    worker = OutboxWorker(worker_id="test-unknown-status-worker")
    # Provider returns an unknown status string that would violate DB constraints if unmapped
    def mock_unknown_status(p_id):
        return (200, {
            "batch_header": {"payout_batch_id": p_id, "batch_status": "SUCCESS"},
            "items": [{
                "sender_item_id": itm_db["sender_item_id"],
                "payout_item_id": "SB-CUSTOM-ITEM",
                "transaction_status": "CUSTOM_UNRECOGNIZED_STATUS_V2",
                "activity_id": "ACT-CUSTOM"
            }]
        })
    worker.paypal_client.fetch_payout_status = mock_unknown_status
    res = worker.process_next_job(force_timeout=False)

    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_item_state, paypal_item_state, raw_provider_status_text FROM payout_items WHERE batch_id = %s;", (batch_id,))
            itm = cur.fetchone()
            assert itm["paypal_item_state"] == "PENDING"
            assert "CUSTOM_UNRECOGNIZED_STATUS_V2" in itm["raw_provider_status_text"]


# ==============================================================================
# TEST 11: HTTP 401/429/500 handled without crashing
# ==============================================================================
def test_http_provider_errors_handled_without_crash():
    """Provider non-201 HTTP responses (missing batch_header) are handled safely without unhandled KeyError."""
    for idx, (err_code, err_payload) in enumerate([
        (401, {"error": "invalid_client", "error_description": "Client Authentication failed"}),
        (429, {"name": "RATE_LIMIT_REACHED", "message": "Too many requests"}),
        (500, {"name": "INTERNAL_SERVER_ERROR", "message": "PayPal server error"})
    ], start=1):
        with get_admin_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM beneficiary_submission_locks;")
                cur.execute("DELETE FROM officer_approvals;")
                cur.execute("DELETE FROM outbox_jobs;")
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

        bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
        carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]
        chal1 = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
        chal2 = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
        c1, a1, s1 = create_webauthn_assertion(bob_priv, chal1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", idx * 10 + 1)
        c2, a2, s2 = create_webauthn_assertion(carol_priv, chal2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", idx * 10 + 2)
        record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c1, a1, s1, challenge_id=chal1["challenge_id"])
        record_officer_webauthn_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c2, a2, s2, challenge_id=chal2["challenge_id"])

        worker = OutboxWorker(worker_id=f"test-http-{err_code}-worker")
        def mock_error_post(batch_id, paypal_request_id, payload_dict, force_network_timeout=False):
            return (err_code, err_payload, "[PAYPAL_SIMULATED_ERROR]")
        worker.paypal_client.submit_payout = mock_error_post

        # Worker must not crash with KeyError
        res = worker.process_next_job(force_timeout=False)
        assert res is not None
        if err_code in (429, 500, 502, 503, 504):
            assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"
        else:
            assert res["status"] == "FAILED"


# ==============================================================================
# TEST 12: Ambiguous payout retains beneficiary lock
# ==============================================================================
def test_ambiguous_payout_retains_beneficiary_lock():
    """Ambiguous outcome retains locks and moves to manual reconciliation."""
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "1200.00",
            "receiver_email": "contractor.acme@example.com"
        }]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]
    chal1 = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    chal2 = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
    c1, a1, s1 = create_webauthn_assertion(bob_priv, chal1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    c2, a2, s2 = create_webauthn_assertion(carol_priv, chal2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c1, a1, s1, challenge_id=chal1["challenge_id"])
    record_officer_webauthn_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c2, a2, s2, challenge_id=chal2["challenge_id"])

    worker = OutboxWorker(worker_id="test-ambiguous-lock-worker")
    res = worker.process_next_job(force_timeout=True)

    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"

    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT COUNT(*) FROM beneficiary_submission_locks
                WHERE beneficiary_id = '30000000-0000-0000-0000-000000000001' AND released_at IS NULL;
            """)
            assert cur.fetchone()["count"] == 1


# ==============================================================================
# TEST 13: Audio fingerprint persists across restart
# ==============================================================================
def test_audio_fingerprint_persists_across_restart():
    """Audio fingerprint persists to disk and catches replay attacks even after in-memory state is wiped."""
    reset_audio_hash_registry()

    audio_bytes = generate_synthetic_audio(duration_sec=4.0, is_spoof=False)
    session_1 = str(uuid.uuid4())
    batch_1 = str(uuid.uuid4())

    res1 = analyze_audio_instruction(audio_bytes, batch_id=batch_1, session_id=session_1)
    assert res1["replay_detected"] is False

    # Simulate full process restart by wiping in-memory registry
    AUDIO_HASH_REGISTRY.clear()

    # Verify that file exists on disk
    assert os.path.isfile(REGISTRY_FILE_PATH)

    # Re-run with a different batch ID
    session_2 = str(uuid.uuid4())
    batch_2 = str(uuid.uuid4())
    res2 = analyze_audio_instruction(audio_bytes, batch_id=batch_2, session_id=session_2)

    assert res2["replay_detected"] is True
    assert res2["policy_decision"] == "BLOCKED"
    assert res2["acoustic_signal"] == "REPLAY_ATTACK_DETECTED"


# ==============================================================================
# TEST 14: Demo startup fails without secure cryptographic keys
# ==============================================================================
def test_startup_fails_without_secure_crypto_keys(monkeypatch):
    """Enabling STRICT_CRYPTO_ENFORCEMENT without mandatory keys raises RuntimeError."""
    monkeypatch.setenv("STRICT_CRYPTO_ENFORCEMENT", "true")
    monkeypatch.delenv("ATTESTATION_SECRET", raising=False)
    monkeypatch.delenv("BLIND_INDEX_KEY", raising=False)
    monkeypatch.delenv("AUTH_ASSERTION_KEY", raising=False)

    from backend.main import startup_event
    with pytest.raises(RuntimeError) as exc:
        startup_event()
    assert "CRITICAL SECURITY ERROR: Required cryptographic keys missing" in str(exc.value)


# ==============================================================================
# TEST 15: Expired and revoked sessions rejected
# ==============================================================================
def test_expired_and_revoked_sessions_rejected():
    """Expired or revoked tokens return HTTP 401."""
    # 1. Expired session
    expired_token = f"sess-expired-{uuid.uuid4()}"
    AUTH_SESSIONS[expired_token] = {
        "user_id": USER_ALICE_MAKER,
        "username": "alice_ap_maker",
        "role": "AP_CLERK",
        "expires_at": time.time() - 100,  # Expired in past
        "is_revoked": False
    }

    resp1 = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp1.status_code == 401
    assert "session token has expired" in resp1.json()["detail"]

    # 2. Revoked session
    revoked_token = f"sess-revoked-{uuid.uuid4()}"
    AUTH_SESSIONS[revoked_token] = {
        "user_id": USER_ALICE_MAKER,
        "username": "alice_ap_maker",
        "role": "AP_CLERK",
        "expires_at": time.time() + 3600,
        "is_revoked": True  # Explicitly revoked
    }

    resp2 = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {revoked_token}"})
    assert resp2.status_code == 401
    assert "session has been revoked" in resp2.json()["detail"]

    # 3. Test dynamic login & logout flow
    login_resp = client.post("/api/auth/login", json={"username": "alice_ap_maker", "password": "alice_secure_maker_pass_2026"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Valid token can access dashboard
    ok_resp = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {token}"})
    assert ok_resp.status_code == 200

    # Logout revokes the token
    logout_resp = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "LOGGED_OUT"

    # Subsequent access is rejected with 401
    blocked_resp = client.get("/api/dashboard/overview", headers={"Authorization": f"Bearer {token}"})
    assert blocked_resp.status_code == 401
    assert "session has been revoked" in blocked_resp.json()["detail"]
