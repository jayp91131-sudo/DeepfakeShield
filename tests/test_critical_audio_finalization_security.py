"""
DeepfakeShield V10.1.3 — Critical Audio Finalization Security Tests

Strictly non-destructive test suite:
- Never wipes global tables or resets audio_hash_registry.json.
- Never modifies or finalizes batch 00650125-d269-4319-9ec9-1825e106a4b4 or evaluation 25b58cd5-cd6a-4a89-a7c6-8afd94599791.
- Cleans up only synthetic test rows created within each test case.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from backend.database import (
    KEY_ID_ACTIVE,
    USER_ALICE_MAKER,
    get_admin_conn,
    get_app_conn,
    get_auditor_conn,
)
from tests.test_fixtures import TEST_ATTESTATION_SECRET
from backend.main import AUTH_SESSIONS, app, reset_auth_sessions
from backend.payout_service import (
    AudioRiskGateError,
    _verify_server_side_audio_risk_gate,
    create_draft_batch,
    finalize_batch,
    log_audit_event,
    record_audio_analysis_for_batch,
)
from crypto_verifier import encrypt_payload, verify_and_attest_snapshot

client = TestClient(app)

BENEFICIARY_ACME_ID = "30000000-0000-0000-0000-000000000001"
BENEFICIARY_ACME_EMAIL = "contractor.acme@example.com"
TARGET_SANDBOX_BATCH_ID = "00650125-d269-4319-9ec9-1825e106a4b4"
TARGET_SANDBOX_EVAL_ID = "25b58cd5-cd6a-4a89-a7c6-8afd94599791"


def _login(username: str, password: str) -> dict:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _create_synthetic_draft_batch() -> tuple[str, str]:
    session_id = str(uuid.uuid4())
    batch = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_SEC_TEST",
        payout_period="2026-11",
        items_data=[
            {
                "beneficiary_id": BENEFICIARY_ACME_ID,
                "amount_usd": "1.00",
                "receiver_email": BENEFICIARY_ACME_EMAIL,
                "note": "Security gate synthetic test",
            }
        ],
        session_id=session_id,
    )
    return batch["batch_id"], session_id


def _cleanup_synthetic_batch(batch_id: str, session_id: str) -> None:
    if batch_id == TARGET_SANDBOX_BATCH_ID:
        raise RuntimeError("Safety guard triggered: refusing to delete target batch.")
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM outbox_jobs WHERE batch_id = %s;", (batch_id,))
            cur.execute("DELETE FROM officer_approvals WHERE batch_id = %s;", (batch_id,))
            cur.execute("DELETE FROM beneficiary_submission_locks WHERE batch_id = %s;", (batch_id,))
            cur.execute("ALTER TABLE payout_items DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_snapshots DISABLE TRIGGER ALL;")
            try:
                cur.execute("DELETE FROM payout_items WHERE batch_id = %s;", (batch_id,))
                cur.execute("UPDATE payout_batches SET active_snapshot_id = NULL WHERE id = %s;", (batch_id,))
                cur.execute("DELETE FROM payout_snapshots WHERE batch_id = %s;", (batch_id,))
                cur.execute("DELETE FROM payout_batches WHERE id = %s;", (batch_id,))
            finally:
                cur.execute("ALTER TABLE payout_snapshots ENABLE TRIGGER ALL;")
                cur.execute("ALTER TABLE payout_batches ENABLE TRIGGER ALL;")
                cur.execute("ALTER TABLE payout_items ENABLE TRIGGER ALL;")

            cur.execute(
                """
                DELETE FROM risk_evaluations
                WHERE segment_id IN (
                    SELECT ss.id FROM speaker_segments ss
                    JOIN audio_assets aa ON aa.id = ss.audio_asset_id
                    WHERE aa.session_id = %s
                );
                """,
                (session_id,),
            )
            cur.execute(
                """
                DELETE FROM speaker_segments
                WHERE audio_asset_id IN (
                    SELECT id FROM audio_assets WHERE session_id = %s
                );
                """,
                (session_id,),
            )
            cur.execute("DELETE FROM audio_consents WHERE session_id = %s;", (session_id,))
            cur.execute("DELETE FROM audio_assets WHERE session_id = %s;", (session_id,))
            cur.execute("DELETE FROM sessions WHERE id = %s;", (session_id,))


def _assert_batch_untouched_draft(batch_id: str) -> None:
    with get_auditor_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT gateway_batch_state, active_snapshot_id FROM payout_batches WHERE id = %s;",
                (batch_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row["gateway_batch_state"] == "DRAFT"
            assert row["active_snapshot_id"] is None

            cur.execute("SELECT COUNT(*) AS c FROM outbox_jobs WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0

            cur.execute("SELECT COUNT(*) AS c FROM payout_snapshots WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0

            cur.execute("SELECT COUNT(*) AS c FROM officer_approvals WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0

            cur.execute("SELECT COUNT(*) AS c FROM beneficiary_submission_locks WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0


def _sample_eval_payload(
    recommendation: str,
    policy_decision: str,
    deepfake_probability: float,
    voice_clone_flag: bool = False,
    adversarial_noise_detected: bool = False,
) -> dict:
    return {
        "model_version": "ACOUSTIC_FFT_HEURISTIC_V1",
        "duration_ms": 6000,
        "sample_count": 96000,
        "wada_snr_db": 42.69,
        "deepfake_probability": deepfake_probability,
        "acoustic_consistency_score": round(max(0.05, 1.0 - deepfake_probability), 4),
        "voice_clone_flag": voice_clone_flag,
        "adversarial_noise_detected": adversarial_noise_detected,
        "recommendation": recommendation,
        "policy_decision": policy_decision,
    }


@pytest.fixture(autouse=True)
def preserve_auth_sessions():
    yield
    reset_auth_sessions()


def test_01_caller_supplied_ready_for_checker_cannot_bypass_challenge():
    """Caller claiming audio_policy_decision='READY_FOR_CHECKER' must NOT bypass persisted CHALLENGE."""
    batch_id, session_id = _create_synthetic_draft_batch()
    try:
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_sample_eval_payload("CHALLENGE", "NEEDS_REVIEW", 0.3898),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )

        h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")
        resp = client.post(
            f"/api/batches/{batch_id}/finalize",
            json={"audio_policy_decision": "READY_FOR_CHECKER"},
            headers=h_alice,
        )
        assert resp.status_code == 403, f"Expected 403 rejection, got {resp.status_code}: {resp.text}"
        assert "CHALLENGE" in resp.text or "NEEDS_REVIEW" in resp.text

        with pytest.raises(AudioRiskGateError):
            finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

        _assert_batch_untouched_draft(batch_id)
    finally:
        _cleanup_synthetic_batch(batch_id, session_id)


def test_02_needs_review_and_blocked_cannot_be_finalized():
    """Both NEEDS_REVIEW/CHALLENGE and BLOCKED/TERMINATE evaluations must fail closed."""
    batch_nr, sess_nr = _create_synthetic_draft_batch()
    batch_blk, sess_blk = _create_synthetic_draft_batch()
    try:
        record_audio_analysis_for_batch(
            batch_id=batch_nr,
            audio_analysis_result=_sample_eval_payload("APPROVE", "NEEDS_REVIEW", 0.22),
            session_id=sess_nr,
            user_id=USER_ALICE_MAKER,
        )
        record_audio_analysis_for_batch(
            batch_id=batch_blk,
            audio_analysis_result=_sample_eval_payload("TERMINATE", "BLOCKED", 0.89, voice_clone_flag=True),
            session_id=sess_blk,
            user_id=USER_ALICE_MAKER,
        )

        h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")

        r_nr = client.post(
            f"/api/batches/{batch_nr}/finalize",
            json={"audio_policy_decision": "READY_FOR_CHECKER"},
            headers=h_alice,
        )
        assert r_nr.status_code == 403
        assert "NEEDS_REVIEW" in r_nr.text

        r_blk = client.post(
            f"/api/batches/{batch_blk}/finalize",
            json={"audio_policy_decision": "READY_FOR_CHECKER"},
            headers=h_alice,
        )
        assert r_blk.status_code == 403

        # Even sending BLOCKED must not transition state when gate rejects
        r_blk2 = client.post(
            f"/api/batches/{batch_blk}/finalize",
            json={"audio_policy_decision": "BLOCKED"},
            headers=h_alice,
        )
        assert r_blk2.status_code == 403

        _assert_batch_untouched_draft(batch_nr)
        _assert_batch_untouched_draft(batch_blk)
    finally:
        _cleanup_synthetic_batch(batch_nr, sess_nr)
        _cleanup_synthetic_batch(batch_blk, sess_blk)


def test_03_missing_stale_or_unassociated_risk_evaluation_fails_closed():
    """Missing, stale (TTL or superseded asset), or cross-batch evaluations must fail closed; valid APPROVE succeeds."""
    batch_missing, sess_missing = _create_synthetic_draft_batch()
    batch_stale, sess_stale = _create_synthetic_draft_batch()
    batch_superseded, sess_superseded = _create_synthetic_draft_batch()
    batch_wrong_assoc, sess_wrong_assoc = _create_synthetic_draft_batch()
    batch_ok, sess_ok = _create_synthetic_draft_batch()

    try:
        # 3a. Missing risk evaluation
        with pytest.raises(AudioRiskGateError, match="missing audio evidence"):
            finalize_batch(batch_missing)
        _assert_batch_untouched_draft(batch_missing)

        # 3b. Stale evaluation (evaluated_at > TTL ago)
        eval_stale = record_audio_analysis_for_batch(
            batch_id=batch_stale,
            audio_analysis_result=_sample_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=sess_stale,
            user_id=USER_ALICE_MAKER,
        )
        with get_admin_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                old_ts = datetime.now(timezone.utc) - timedelta(hours=2)
                cur.execute(
                    "UPDATE risk_evaluations SET evaluated_at = %s WHERE id = %s;",
                    (old_ts, eval_stale["evaluation_id"]),
                )
        with pytest.raises(AudioRiskGateError, match="stale"):
            finalize_batch(batch_stale, max_eval_age_seconds=3600)
        _assert_batch_untouched_draft(batch_stale)

        # 3c. Superseded by a newer unevaluated audio asset on the same session
        record_audio_analysis_for_batch(
            batch_id=batch_superseded,
            audio_analysis_result=_sample_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=sess_superseded,
            user_id=USER_ALICE_MAKER,
        )
        with get_admin_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                new_asset_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms, recorded_at)
                    VALUES (%s, %s, 16000, 1, 'WAV_PCM16', %s, 5500, %s);
                    """,
                    (
                        new_asset_id,
                        sess_superseded,
                        f"vault://audio/{new_asset_id}.wav",
                        datetime.now(timezone.utc) + timedelta(seconds=2),
                    ),
                )
        with pytest.raises(AudioRiskGateError, match="missing persisted risk evaluation"):
            finalize_batch(batch_superseded)
        _assert_batch_untouched_draft(batch_superseded)

        # 3d. Evaluation audit record bound to a different batch_id
        record_audio_analysis_for_batch(
            batch_id=str(uuid.uuid4()),
            audio_analysis_result=_sample_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=sess_wrong_assoc,
            user_id=USER_ALICE_MAKER,
        )
        with pytest.raises(AudioRiskGateError, match="associated with batch"):
            finalize_batch(batch_wrong_assoc)
        _assert_batch_untouched_draft(batch_wrong_assoc)

        # 3e. Positive control: valid, fresh, batch-associated APPROVE passes gate & finalizes
        record_audio_analysis_for_batch(
            batch_id=batch_ok,
            audio_analysis_result=_sample_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=sess_ok,
            user_id=USER_ALICE_MAKER,
        )
        fin_res = finalize_batch(batch_ok)
        assert fin_res["gateway_batch_state"] == "READY_FOR_CHECKER"
        assert fin_res["snapshot_id"] is not None
    finally:
        for b_id, s_id in [
            (batch_missing, sess_missing),
            (batch_stale, sess_stale),
            (batch_superseded, sess_superseded),
            (batch_wrong_assoc, sess_wrong_assoc),
            (batch_ok, sess_ok),
        ]:
            _cleanup_synthetic_batch(b_id, s_id)


def test_04_direct_db_finalize_cannot_bypass_audio_policy():
    """
    Requires direct SQL invocation of fn_finalize_payout_batch to enforce the audio-risk gate
    and reject a batch whose persisted risk evaluation is CHALLENGE.
    Runs inside a rolled-back transaction so live DB state stays unmodified.
    """
    batch_id, session_id = _create_synthetic_draft_batch()
    try:
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_sample_eval_payload("CHALLENGE", "NEEDS_REVIEW", 0.3898),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )

        with get_app_conn(autocommit=False) as db_conn:
            try:
                with db_conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("SELECT sender_batch_id, payout_period FROM payout_batches WHERE id = %s;", (batch_id,))
                    b_row = cur.fetchone()
                    cur.execute("SELECT sender_item_id, note FROM payout_items WHERE batch_id = %s;", (batch_id,))
                    it_row = cur.fetchone()

                    canonical_payload = {
                        "sender_batch_header": {
                            "sender_batch_id": b_row["sender_batch_id"],
                            "email_subject": f"Disbursement for {b_row['payout_period']}",
                            "recipient_type": "EMAIL",
                        },
                        "items": [
                            {
                                "recipient_type": "EMAIL",
                                "amount": {"value": "1.00", "currency": "USD"},
                                "note": it_row["note"] or "Contractor disbursement",
                                "sender_item_id": it_row["sender_item_id"],
                                "receiver": BENEFICIARY_ACME_EMAIL,
                            }
                        ],
                    }
                    canonical_json = json.dumps(canonical_payload, separators=(",", ":"))
                    p_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
                    dek = os.urandom(32)
                    aad_text = "DEEPFAKESHIELD-PAYOUT-v1"
                    nonce, ciphertext, tag = encrypt_payload(dek, canonical_json.encode("utf-8"), aad_text.encode("utf-8"))
                    snapshot_id = uuid.uuid4()
                    attestation = verify_and_attest_snapshot(
                        dek=dek,
                        nonce=nonce,
                        ciphertext=ciphertext,
                        tag=tag,
                        aad=aad_text.encode("utf-8"),
                        expected_plaintext_json=canonical_json,
                        batch_id=uuid.UUID(batch_id),
                        snapshot_id=snapshot_id,
                        key_id=uuid.UUID(KEY_ID_ACTIVE),
                        attestation_secret=TEST_ATTESTATION_SECRET,
                        wrapped_dek=dek,
                    ).attestation

                    with pytest.raises(Exception):
                        cur.execute(
                            "SELECT fn_finalize_payout_batch(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);",
                            (
                                uuid.UUID(batch_id),
                                canonical_json,
                                ciphertext,
                                p_digest,
                                dek,
                                nonce,
                                tag,
                                aad_text,
                                attestation,
                                snapshot_id,
                            ),
                        )
            finally:
                db_conn.rollback()
    finally:
        _cleanup_synthetic_batch(batch_id, session_id)


def test_05_manual_review_capability_and_auditor_boundaries():
    """
    Verifies AUDITOR read visibility vs strict non-mutation enforcement and confirms
    no unauthorized manual-review override path exists in the frozen V10.1.3 workflow.
    """
    h_dave = _login("dave_auditor", "dave_read_only_auditor_pass_2026")

    # 1. AUDITOR can inspect batch evaluation metadata (read-only) for the real target batch
    dash = client.get(f"/api/dashboard/overview?batch_id={TARGET_SANDBOX_BATCH_ID}", headers=h_dave)
    assert dash.status_code == 200
    body = dash.json()
    assert body["active_batch"]["id"] == TARGET_SANDBOX_BATCH_ID
    assert body["active_batch"]["gateway_batch_state"] == "DRAFT"
    assert str(body["audio_evaluation"]["id"]) == TARGET_SANDBOX_EVAL_ID
    assert body["audio_evaluation"]["recommendation"] == "CHALLENGE"

    # 2. AUDITOR cannot finalize or approve any batch
    r_fin = client.post(
        f"/api/batches/{TARGET_SANDBOX_BATCH_ID}/finalize",
        json={"audio_policy_decision": "READY_FOR_CHECKER"},
        headers=h_dave,
    )
    assert r_fin.status_code == 403

    r_appr = client.post(
        f"/api/batches/{TARGET_SANDBOX_BATCH_ID}/approve",
        json={"credential_id": "cred_bob_yubikey_01", "mock_simulation": True},
        headers=h_dave,
    )
    assert r_appr.status_code == 403

    # 3. No manual-review endpoint or DB write capability for deepfakeshield_auditor exists
    r_rev = client.post(
        f"/api/batches/{TARGET_SANDBOX_BATCH_ID}/review",
        json={"decision": "APPROVE", "reason": "Verified voice"},
        headers=h_dave,
    )
    assert r_rev.status_code == 404

    with get_auditor_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT has_function_privilege(
                    'deepfakeshield_auditor',
                    'fn_append_audit_event(character varying, uuid, character varying, character varying, uuid, character varying, character varying, inet, text, bigint, bytea, jsonb)',
                    'EXECUTE'
                );
                """
            )
            assert cur.fetchone()[0] is False
            cur.execute("SELECT has_table_privilege('deepfakeshield_auditor', 'audio_consents', 'SELECT');")
            assert cur.fetchone()[0] is False
            cur.execute("SELECT has_table_privilege('deepfakeshield_auditor', 'risk_evaluations', 'UPDATE');")
            assert cur.fetchone()[0] is False


def test_06_no_outbox_job_created_on_rejected_finalization():
    """Verifies zero outbox jobs, snapshots, locks, or approvals are created when finalization rejects."""
    batch_id, session_id = _create_synthetic_draft_batch()
    try:
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_sample_eval_payload("CHALLENGE", "NEEDS_REVIEW", 0.3898),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )
        h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")
        for claimed_decision in ("READY_FOR_CHECKER", "NEEDS_REVIEW", "BLOCKED", "APPROVE", ""):
            resp = client.post(
                f"/api/batches/{batch_id}/finalize",
                json={"audio_policy_decision": claimed_decision},
                headers=h_alice,
            )
            assert resp.status_code == 403
            _assert_batch_untouched_draft(batch_id)
    finally:
        _cleanup_synthetic_batch(batch_id, session_id)
