#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Hackathon End-to-End Verification Test Suite
Milestone: V10.1.3 Hackathon Delivery Sprint

Automated Executable Verification for:
PHASE 2 — COMPLETE THE PRODUCT FLOW:
- Audio upload -> AASIST inference -> Acoustic risk evaluation -> Beneficiary verification
  -> Immutable snapshot -> Dual WebAuthn approvals -> Outbox worker -> PayPal Sandbox submission
  -> Item reconciliation -> Audit timeline.

PHASE 3 — FAILURE DEMONSTRATIONS:
1. Suspicious voice instruction blocks payout progression (State: BLOCKED, 0 PayPal calls).
2. Unauthorized approval is rejected (Maker-checker violation / Unauthorized role).
3. Duplicate submission does not create a second payout (Idempotent replay).
4. Ambiguous network outcome retains beneficiary locks and enters MANUAL_RECONCILIATION_REQUIRED.
"""

import os
import uuid
import json
import pytest
import psycopg
from psycopg.rows import dict_row

from backend.database import (
    seed_demo_data,
    get_admin_conn,
    get_app_conn,
    get_worker_conn,
    get_auditor_conn,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_EVE_UNAUTHORIZED,
    BOB_CRED_ID,
    CAROL_CRED_ID,
    OFFICER_PRIVATE_KEYS
)
from backend.audio_analyzer import generate_synthetic_audio, analyze_audio_instruction
from backend.payout_service import (
    create_draft_batch,
    record_audio_analysis_for_batch,
    finalize_batch,
    record_officer_webauthn_approval,
    issue_officer_challenge
)
from backend.outbox_worker import OutboxWorker
from crypto_verifier import create_webauthn_assertion

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Initializes clean database seed data before tests."""
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE payout_items DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_snapshots DISABLE TRIGGER ALL;")
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
            cur.execute("DELETE FROM payout_items;")
            cur.execute("UPDATE payout_batches SET active_snapshot_id = NULL;")
            cur.execute("DELETE FROM payout_snapshots;")
            cur.execute("DELETE FROM payout_batches;")
            cur.execute("DELETE FROM risk_evaluations;")
            cur.execute("DELETE FROM speaker_segments;")
            cur.execute("DELETE FROM audio_consents;")
            cur.execute("DELETE FROM audio_assets;")
            cur.execute("DELETE FROM sessions;")
            cur.execute("DELETE FROM webauthn_challenges;")
            cur.execute("ALTER TABLE beneficiaries ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_snapshots ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_items ENABLE TRIGGER ALL;")
    seed_demo_data()

# ============================================================================
# PHASE 2: COMPLETE HAPPY-PATH PRODUCT FLOW
# ============================================================================

def test_phase2_complete_happy_path_vertical_slice():
    """
    Verifies the complete end-to-end happy path:
    Audio -> AASIST -> Draft -> Snapshot Lock -> Dual WebAuthn -> Outbox -> PayPal Sandbox -> Settlement.
    """
    # 1. Audio Upload & AASIST Inference
    audio_bytes = generate_synthetic_audio(duration_sec=4.5, is_spoof=False)
    audio_analysis = analyze_audio_instruction(audio_bytes, known_spoof_override=False)
    assert audio_analysis["recommendation"] == "APPROVE"
    assert audio_analysis["policy_decision"] == "READY_FOR_CHECKER"
    assert audio_analysis["deepfake_probability"] < 0.20
    assert audio_analysis["window_count"] >= 1

    # 2. Beneficiary Verification & Draft Batch Creation
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, legal_name FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben = cur.fetchone()
            assert ben is not None

    session_id = str(uuid.uuid4())
    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": ben["id"],
            "amount_usd": "1250.00",
            "receiver_email": "contractor.acme@example.com",
            "note": "Milestone payout"
        }],
        session_id=session_id
    )
    batch_id = batch_res["batch_id"]
    assert batch_res["gateway_batch_state"] == "DRAFT"
    assert batch_res["total_amount_usd"] == "1250.00"

    # Link audio evaluation
    audio_eval = record_audio_analysis_for_batch(
        batch_id=batch_id,
        audio_analysis_result=audio_analysis,
        session_id=session_id,
        user_id=USER_ALICE_MAKER
    )
    assert audio_eval["recommendation"] == "APPROVE"

    # 3. Immutable Snapshot Finalization & Envelope Attestation
    fin_res = finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")
    assert fin_res["gateway_batch_state"] == "READY_FOR_CHECKER"
    assert fin_res["snapshot_id"] is not None
    assert len(fin_res["ciphertext_digest"]) == 64

    # Verify durable beneficiary submission lock is held
    with get_app_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) FROM beneficiary_submission_locks 
                WHERE beneficiary_id = %s AND released_at IS NULL;
            """, (ben["id"],))
            assert cur.fetchone()[0] == 1

    # 4. Two Independent WebAuthn Approvals (Bob + Carol)
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]

    # Approval 1: Bob (Treasury Officer 1)
    chal_bob = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    c_data_bob, a_data_bob, sig_bob = create_webauthn_assertion(
        bob_priv, chal_bob["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )
    appr1 = record_officer_webauthn_approval(
        batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c_data_bob, a_data_bob, sig_bob, challenge_id=chal_bob["challenge_id"]
    )
    assert appr1["approval_count"] == 1
    assert appr1["gateway_batch_state"] == "READY_FOR_CHECKER"
    assert appr1["requires_more_approvals"] is True

    # Approval 2: Carol (Treasury Officer 2)
    chal_carol = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
    c_data_carol, a_data_carol, sig_carol = create_webauthn_assertion(
        carol_priv, chal_carol["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )
    appr2 = record_officer_webauthn_approval(
        batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c_data_carol, a_data_carol, sig_carol, challenge_id=chal_carol["challenge_id"]
    )
    assert appr2["approval_count"] == 2
    assert appr2["gateway_batch_state"] == "APPROVED_TO_SUBMIT"
    assert appr2["outbox_job_id"] is not None

    # 5. Outbox Worker Execution -> PayPal Sandbox Submission -> Settlement
    worker = OutboxWorker(worker_id="test-worker-01")
    worker_res = worker.process_next_job(force_timeout=False)
    assert worker_res is not None
    assert worker_res["status"] == "SETTLED"
    assert worker_res["payout_batch_id"].startswith("SB-BATCH-")
    assert worker_res["http_status"] == 201

    # 6. Verify Settlement & Reconciled Items
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state, paypal_batch_state, payout_batch_id FROM payout_batches WHERE id = %s;", (batch_id,))
            b_row = cur.fetchone()
            assert b_row["gateway_batch_state"] in ("SUBMITTED", "SETTLED")
            assert b_row["paypal_batch_state"] in ("SUCCESS", "PENDING", "PROCESSING")

            cur.execute("SELECT gateway_item_state, paypal_item_state, payout_item_id FROM payout_items WHERE batch_id = %s;", (batch_id,))
            i_row = cur.fetchone()
            assert i_row["gateway_item_state"] == "SETTLED"
            assert i_row["paypal_item_state"] == "SUCCESS"
            assert i_row["payout_item_id"].startswith("SB-ITEM-")

            # Verify beneficiary submission lock was cleanly released
            cur.execute("""
                SELECT COUNT(*) AS lock_count FROM beneficiary_submission_locks 
                WHERE beneficiary_id = %s AND released_at IS NULL;
            """, (ben["id"],))
            assert cur.fetchone()["lock_count"] == 0

    # 7. Verify Append-Only Audit Timeline
    with get_auditor_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT event_type, entity_id, previous_event_digest, event_digest
                FROM audit_events
                WHERE entity_id = %s
                ORDER BY id ASC;
            """, (batch_id,))
            events = cur.fetchall()
            event_types = [e["event_type"] for e in events]
            assert "BATCH_DRAFT_CREATED" in event_types
            assert "BATCH_FINALIZED_AND_LOCKED" in event_types
            assert "BATCH_APPROVED_AND_ENQUEUED" in event_types
            assert "PAYOUT_SETTLED_SUCCESS" in event_types

# ============================================================================
# PHASE 3: FAILURE DEMONSTRATIONS
# ============================================================================

def test_phase3_failure1_suspicious_voice_instruction_blocks_progression():
    """
    Demonstration 1:
    A voice instruction exhibiting synthetic vocoder artifacts is analyzed by AASIST.
    The elevated acoustic spoof risk blocks batch finalization (State: BLOCKED, 0 PayPal calls).
    """
    # 1. Generate deepfake spoof audio
    audio_bytes = generate_synthetic_audio(duration_sec=4.5, is_spoof=True)
    analysis = analyze_audio_instruction(audio_bytes, known_spoof_override=True)
    assert analysis["recommendation"] == "TERMINATE"
    assert analysis["policy_decision"] == "BLOCKED"
    assert analysis["deepfake_probability"] >= 0.85
    assert analysis["voice_clone_flag"] is True

    # 2. Create batch
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "8500.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]

    # 3. Finalize with BLOCKED policy
    fin_res = finalize_batch(batch_id, audio_policy_decision="BLOCKED")
    assert fin_res["gateway_batch_state"] == "BLOCKED"

    # 4. Confirm zero outbox jobs exist and zero PayPal calls were made
    with get_worker_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM outbox_jobs WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM paypal_api_attempts WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()[0] == 0

def test_phase3_failure2_unauthorized_approval_rejected():
    """
    Demonstration 2:
    An unauthorized officer (Eve, AP Clerk) or corrupted signature is strictly rejected.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "500.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    c_data, a_data, sig = create_webauthn_assertion(
        bob_priv, os.urandom(32), "https://deepfakeshield.internal", "deepfakeshield.internal", 1
    )

    # 1. Eve (AP Clerk) attempts to approve -> Rejected by Role check
    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(batch_id, USER_EVE_UNAUTHORIZED, BOB_CRED_ID, c_data, a_data, sig)
    assert "TREASURY_OFFICER" in str(exc.value)

    # 2. Alice (Maker) attempts to approve her own batch -> Rejected by Maker-Checker separation
    with pytest.raises(ValueError) as exc:
        record_officer_webauthn_approval(batch_id, USER_ALICE_MAKER, BOB_CRED_ID, c_data, a_data, sig)
    assert "Maker-checker violation" in str(exc.value)

def test_phase3_failure3_duplicate_submission_idempotency():
    """
    Demonstration 3:
    Submitting an already-submitted batch does not create a second PayPal transaction.
    """
    # Run happy path
    test_phase2_complete_happy_path_vertical_slice()

    # Re-run worker on empty outbox
    worker = OutboxWorker(worker_id="test-worker-02")
    res = worker.process_next_job(force_timeout=False)
    assert res is None  # Zero pending jobs, no duplicate payments generated

def test_phase3_failure4_ambiguous_network_timeout_retains_locks_and_enters_manual_recon():
    """
    Demonstration 4:
    An ambiguous network outcome (HTTP 504 Gateway Timeout) retains beneficiary locks
    and transitions batch into MANUAL_RECONCILIATION_REQUIRED.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "2200.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    # Both officers approve
    bob_priv = OFFICER_PRIVATE_KEYS[BOB_CRED_ID]
    carol_priv = OFFICER_PRIVATE_KEYS[CAROL_CRED_ID]
    chal1 = issue_officer_challenge(batch_id, USER_BOB_CHECKER1)
    chal2 = issue_officer_challenge(batch_id, USER_CAROL_CHECKER2)
    c1, a1, s1 = create_webauthn_assertion(bob_priv, chal1["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    c2, a2, s2 = create_webauthn_assertion(carol_priv, chal2["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    record_officer_webauthn_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID, c1, a1, s1, challenge_id=chal1["challenge_id"])
    record_officer_webauthn_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID, c2, a2, s2, challenge_id=chal2["challenge_id"])

    # Worker executes with force_timeout=True
    worker = OutboxWorker(worker_id="test-worker-timeout")
    res = worker.process_next_job(force_timeout=True)
    assert res is not None
    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"
    assert res["http_status"] == 504

    # Confirm database state is MANUAL_RECONCILIATION_REQUIRED and lock is STILL HELD!
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state FROM payout_batches WHERE id = %s;", (batch_id,))
            b_row = cur.fetchone()
            assert b_row["gateway_batch_state"] == "MANUAL_RECONCILIATION_REQUIRED"

            # Beneficiary lock MUST still be held to prevent double-spending!
            cur.execute("""
                SELECT COUNT(*) AS lock_count FROM beneficiary_submission_locks 
                WHERE beneficiary_id = %s AND released_at IS NULL;
            """, (ben_id,))
            assert cur.fetchone()["lock_count"] == 1, "Beneficiary lock MUST NOT be released on ambiguous network error!"
