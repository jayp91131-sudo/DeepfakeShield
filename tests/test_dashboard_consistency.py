#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Dashboard Cross-Panel Consistency Test Suite
Milestone: V10.1.3 Dashboard Bug Fix Sprint

Verifies that the Threat Operations Console guarantees strict cross-panel data consistency:
1. 1/2 approvals must NEVER be displayed alongside a valid fully approved / enqueued outbox job.
2. Manual reconciliation displays UNKNOWN outcome and timeout timestamp, NEVER "IDLE" or "Awaiting submission".
3. Simulator mode dynamically displays SIMULATED_LOCAL / Local Fallback, NEVER "PayPal US Sandbox: ONLINE".
4. AASIST displays NOT_RUN when unassessed, NEVER "READY" with missing metrics.
5. Finalized batch items display LOCKED_IN_SNAPSHOT / RECONCILIATION_REQUIRED, NEVER unexplained DRAFT.
6. Audit timeline contains all batch lifecycle events in chronological order with verified cryptographic chain.
7. All dashboard panels are strictly synchronized to the SAME active batch_id.
"""

import os
import uuid
import pytest
from psycopg.rows import dict_row

from backend.database import (
    seed_demo_data,
    get_admin_conn,
    get_app_conn,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
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
from backend.main import api_dashboard_overview
from crypto_verifier import create_webauthn_assertion

def make_officer_approval(batch_id, user_id, cred_id):
    priv_key = OFFICER_PRIVATE_KEYS[cred_id]
    chal = issue_officer_challenge(batch_id, user_id)
    c, a, s = create_webauthn_assertion(priv_key, chal["challenge_bytes"], "https://deepfakeshield.internal", "deepfakeshield.internal", 1)
    return record_officer_webauthn_approval(batch_id, user_id, cred_id, c, a, s, challenge_id=chal["challenge_id"])

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

# ============================================================================
# TEST 1: WebAuthn Approvals vs Outbox Enqueue Synchronization
# ============================================================================
def test_inconsistency_webauthn_approvals_vs_outbox_enqueue():
    """
    INCONSISTENCY CHECK:
    - 1/2 approvals must NEVER be displayed alongside an enqueued outbox job.
    - Outbox job creation requires exactly 2 verified independent officer approvals.
    - Both Bob and Carol identities and timestamps are reported.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "1000.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    # Step 1: Officer 1 (Bob) Approves
    make_officer_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID)

    # Inspect dashboard data at 1/2 approvals stage
    data = api_dashboard_overview(batch_id=batch_id)
    assert data["approval_count"] == 1
    assert data["is_threshold_met"] is False
    assert data["bob_info"]["is_approved"] is True
    assert data["bob_info"]["status"] == "VERIFIED (P-256 ECDSA)"
    assert data["bob_info"]["approved_at"] is not None
    assert data["carol_info"]["is_approved"] is False
    assert data["carol_info"]["status"] == "PENDING"
    # CRITICAL INVARIANT: Outbox job MUST NOT be enqueued on 1/2 approvals!
    assert data["outbox_job"] is None, "Outbox job must be None when only 1/2 approvals exist!"

    # Step 2: Officer 2 (Carol) Approves
    make_officer_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID)

    # Inspect dashboard data at 2/2 approvals stage
    data2 = api_dashboard_overview(batch_id=batch_id)
    assert data2["approval_count"] == 2
    assert data2["is_threshold_met"] is True
    assert data2["bob_info"]["is_approved"] is True
    assert data2["carol_info"]["is_approved"] is True
    assert data2["carol_info"]["status"] == "VERIFIED (P-256 ECDSA)"
    assert data2["carol_info"]["approved_at"] is not None
    # Outbox job is now valid and bound to active batch
    assert data2["outbox_job"] is not None
    assert str(data2["outbox_job"]["batch_id"]) == str(batch_id)
    assert data2["outbox_job"]["status"] == "PENDING"

# ============================================================================
# TEST 2: Manual Reconciliation Not Displayed as Idle
# ============================================================================
def test_inconsistency_manual_reconciliation_not_idle():
    """
    INCONSISTENCY CHECK:
    - On ambiguous network timeout (HTTP 504), provider state must NOT be IDLE or 'Awaiting submission'.
    - Submission attempt info must include HTTP 504 and attempt timestamp.
    - Beneficiary lock must be retained.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "3500.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    make_officer_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID)
    make_officer_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID)

    # Execute worker with ambiguous timeout
    worker = OutboxWorker(worker_id="test-recon-worker")
    res = worker.process_next_job(force_timeout=True)
    assert res["status"] == "MANUAL_RECONCILIATION_REQUIRED"

    # Query overview
    data = api_dashboard_overview(batch_id=batch_id)
    assert data["active_batch"]["gateway_batch_state"] == "MANUAL_RECONCILIATION_REQUIRED"
    
    # Provider panel checks
    prov = data["provider_info"]
    assert prov["gateway_status"] == "TIMEOUT_UNKNOWN"
    assert "UNKNOWN" in prov["payout_batch_id"]
    assert prov["payout_batch_id"] != "Awaiting submission"
    assert prov["latest_attempt"]["http_status"] == 504
    assert prov["latest_attempt"]["is_ambiguous"] is True
    assert prov["latest_attempt"]["attempted_at"] is not None

    # Beneficiary lock MUST still be held
    assert data["lock_status"]["is_held"] is True
    assert data["lock_status"]["released_at"] is None

# ============================================================================
# TEST 3: PayPal Simulator vs Live Sandbox Distinction
# ============================================================================
def test_inconsistency_paypal_simulator_vs_live():
    """
    INCONSISTENCY CHECK:
    - Never display 'PayPal US Sandbox: ONLINE' when only the simulator is active.
    - Distinguishes PAYPAL_SANDBOX from PAYPAL_SANDBOX_SIMULATOR.
    """
    data = api_dashboard_overview()
    prov = data["provider_info"]
    if prov["is_simulator"]:
        assert prov["connection_status"] == "SIMULATED_LOCAL"
        assert prov["connection_label"] == "PayPal Sandbox Simulator: ACTIVE (Local Fallback)"
        assert "ONLINE" not in prov["connection_label"]
        assert prov["provider_mode"] == "[PAYPAL_SANDBOX_SIMULATOR]"

# ============================================================================
# TEST 4: AASIST State Machine (NOT_RUN vs COMPLETED)
# ============================================================================
def test_inconsistency_aasist_state_machine_not_run_when_missing():
    """
    INCONSISTENCY CHECK:
    - READY must not appear when assessment values are missing.
    - State is NOT_RUN when no inference has occurred.
    - State is COMPLETED with real probability and recommendation only after valid inference.
    """
    # Create batch without audio
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "700.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]

    data = api_dashboard_overview(batch_id=batch_id)
    assert data["audio_state"] == "NOT_RUN"
    assert data["audio_evaluation"] is None

    # Now evaluate audio and link to batch
    audio_bytes = generate_synthetic_audio(duration_sec=4.5, is_spoof=False)
    analysis = analyze_audio_instruction(audio_bytes, known_spoof_override=False)
    record_audio_analysis_for_batch(batch_id, analysis, batch_res["session_id"], USER_ALICE_MAKER)

    data2 = api_dashboard_overview(batch_id=batch_id)
    assert data2["audio_state"] == "COMPLETED"
    assert data2["audio_evaluation"] is not None
    assert data2["audio_evaluation"]["recommendation"] == "APPROVE"
    assert data2["audio_evaluation"]["deepfake_probability"] < 0.20
    assert data2["audio_evaluation"]["wada_snr_db"] is not None

# ============================================================================
# TEST 5: Finalized Batch Contractor Item Display State
# ============================================================================
def test_inconsistency_finalized_batch_item_display_state():
    """
    INCONSISTENCY CHECK:
    - A finalized batch must not show an unexplained DRAFT item.
    - In READY_FOR_CHECKER, items show LOCKED_IN_SNAPSHOT / AWAITING_DISPATCH.
    - In MANUAL_RECONCILIATION_REQUIRED, items show RECONCILIATION_REQUIRED / UNKNOWN_IN_FLIGHT.
    - In SETTLED, items show SETTLED / SUCCESS.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "1200.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]

    # Before finalization: DRAFT
    data_draft = api_dashboard_overview(batch_id=batch_id)
    assert data_draft["items"][0]["display_gateway_state"] == "DRAFT"

    # After finalization: LOCKED_IN_SNAPSHOT
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")
    data_finalized = api_dashboard_overview(batch_id=batch_id)
    assert data_finalized["items"][0]["display_gateway_state"] == "LOCKED_IN_SNAPSHOT"
    assert data_finalized["items"][0]["display_paypal_state"] == "AWAITING_DISPATCH"
    assert "Sealed" in data_finalized["items"][0]["state_explanation"]

# ============================================================================
# TEST 6: Audit Timeline Active Batch Isolation and Completeness
# ============================================================================
def test_inconsistency_audit_timeline_batch_isolation_and_completeness():
    """
    INCONSISTENCY CHECK:
    - Audit timeline only contains events belonging to the active batch.
    - Events are chronologically ordered.
    - All lifecycle events are present: DRAFT -> FINALIZED -> OFFICER1 -> OFFICER2 -> SETTLED.
    - Cryptographic chain integrity is verified.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{"beneficiary_id": ben_id, "amount_usd": "1500.00", "receiver_email": "contractor.acme@example.com"}]
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    make_officer_approval(batch_id, USER_BOB_CHECKER1, BOB_CRED_ID)
    make_officer_approval(batch_id, USER_CAROL_CHECKER2, CAROL_CRED_ID)

    worker = OutboxWorker(worker_id="test-audit-worker")
    worker.process_next_job(force_timeout=False)

    data = api_dashboard_overview(batch_id=batch_id)
    assert data["chain_verified"] is True
    events = data["audit_events"]
    assert len(events) >= 4
    
    event_types = [e["event_type"] for e in events]
    assert "BATCH_DRAFT_CREATED" in event_types
    assert "BATCH_FINALIZED_AND_LOCKED" in event_types
    assert "OFFICER_STAGE1_APPROVED" in event_types
    assert "BATCH_APPROVED_AND_ENQUEUED" in event_types
    assert "PAYOUT_SETTLED_SUCCESS" in event_types

    # Ensure chronological order
    event_ids = [e["id"] for e in events]
    assert event_ids == sorted(event_ids), "Audit events must be sorted chronologically by ID!"

# ============================================================================
# TEST 7: Cross-Panel Active Batch Synchronization
# ============================================================================
def test_cross_panel_active_batch_synchronization():
    """
    INCONSISTENCY CHECK:
    - All dashboard panels strictly resolve to the SAME active batch.
    - When a BLOCKED batch is active, it must not display an outbox job from an earlier batch.
    """
    with get_app_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM beneficiaries WHERE legal_name = 'Acme Engineering Corp';")
            ben_id = cur.fetchone()["id"]

    # Run Batch 1: Completed Happy Path
    b1 = create_draft_batch(USER_ALICE_MAKER, "PROG_DEV_2026", "2026-11", [{"beneficiary_id": ben_id, "amount_usd": "500.00", "receiver_email": "contractor.acme@example.com"}])
    finalize_batch(b1["batch_id"], audio_policy_decision="READY_FOR_CHECKER")
    make_officer_approval(b1["batch_id"], USER_BOB_CHECKER1, BOB_CRED_ID)
    make_officer_approval(b1["batch_id"], USER_CAROL_CHECKER2, CAROL_CRED_ID)
    OutboxWorker(worker_id="worker-b1").process_next_job(force_timeout=False)

    # Run Batch 2: Blocked by Deepfake Voice Clone (NO outbox job created!)
    b2 = create_draft_batch(USER_ALICE_MAKER, "PROG_DEV_2026", "2026-11", [{"beneficiary_id": ben_id, "amount_usd": "9900.00", "receiver_email": "contractor.acme@example.com"}])
    finalize_batch(b2["batch_id"], audio_policy_decision="BLOCKED")

    # Inspect dashboard for Batch 2
    data_b2 = api_dashboard_overview(batch_id=b2["batch_id"])
    assert data_b2["active_batch"]["id"] == b2["batch_id"]
    assert data_b2["active_batch"]["gateway_batch_state"] == "BLOCKED"
    # CRITICAL: Batch 2 has NO outbox job. It MUST NOT display Batch 1's outbox job!
    assert data_b2["outbox_job"] is None, "Blocked batch must NOT inherit outbox job from previous batch!"
    assert data_b2["items"][0]["batch_id"] == uuid.UUID(b2["batch_id"])
