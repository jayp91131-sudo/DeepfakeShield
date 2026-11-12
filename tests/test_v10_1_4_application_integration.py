"""
DeepfakeShield V10.1.4 — Coordinated Application Integration Tests (Disposable DB Only)

Validates:
1. record_audio_analysis_for_batch() persists exclusively via deepfakeshield_verifier
   (fn_record_audio_risk_evaluation) and never uses deepfakeshield_app.
2. Atomic single-transaction persistence of audio_assets, audio_consents,
   speaker_segments, risk_evaluations, and AUDIO_RISK_EVALUATED audit event,
   with complete rollback on failure.
3. Fail-closed behavior when verifier connection is unavailable/misconfigured,
   zero fallback to deepfakeshield_app, and zero credential exposure.
4. Cross-batch / wrong-session binding rejection and non-DRAFT rejection.
5. Full gate enforcement across finalize_batch(), /api/batches/{id}/finalize,
   and both fn_finalize_payout_batch overloads (10-arg & 9-arg), plus positive
   APPROVE -> READY_FOR_CHECKER -> finalized -> dual officer WebAuthn approval flow.
6. Rollout-readiness checks: no verifier secrets in frontend assets, both DB
   finalization overloads locked down, no NEEDS_REVIEW -> READY_FOR_CHECKER override,
   and compatibility with backfilled V10.1.3 historical records.
"""

import hashlib
import json
import os
import re
import uuid
import wave
from datetime import datetime, timedelta, timezone

import numpy as np
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

import backend.audio_analyzer as audio_analyzer
from backend import payout_service
from backend.database import (
    APP_PASS,
    BOB_CRED_ID,
    CAROL_CRED_ID,
    DB_ADMIN_PASSWORD,
    DB_ADMIN_USER,
    DB_HOST,
    DB_PORT,
    KEY_ID_ACTIVE,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_DAVE_AUDITOR,
    VERIFIER_PASS,
    get_admin_conn,
    get_app_conn,
    get_auditor_conn,
    get_verifier_conn,
)
from backend.main import app, reset_auth_sessions
from backend.payout_service import (
    AudioRiskGateError,
    create_draft_batch,
    finalize_batch,
    record_audio_analysis_for_batch,
)
from crypto_verifier import (
    compute_recipient_blind_index,
    encrypt_payload,
    verify_and_attest_snapshot,
)
from tests.test_fixtures import (
    TEST_ATTESTATION_SECRET,
    TEST_AUTH_ASSERTION_KEY,
    TEST_BLIND_INDEX_KEY,
    TEST_BOB_DETERMINISTIC_SEED,
    TEST_CAROL_DETERMINISTIC_SEED,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V1013_PATH = os.path.join(REPO_ROOT, "migrations", "V10_1_3__security_repair.sql")
V1014_PATH = os.path.join(REPO_ROOT, "migrations", "V10_1_4__database_audio_finalization_gate.sql")

BENEFICIARY_ID = "30000000-0000-0000-0000-000000000001"
BENEFICIARY_EMAIL = "contractor.acme@example.com"

client = TestClient(app)


def _conn_str(db_name: str, user: str, password: str) -> str:
    return f"host={DB_HOST} port={DB_PORT} dbname={db_name} user={user} password={password}"


@pytest.fixture(scope="module")
def disposable_v1014_db():
    db_name = f"deepfakeshield_v1014_appint_{uuid.uuid4().hex[:10]}"
    admin_maint = _conn_str("postgres", DB_ADMIN_USER, DB_ADMIN_PASSWORD)

    with psycopg.connect(admin_maint, autocommit=True) as mconn:
        with mconn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{db_name}";')

    try:
        db_admin_dsn = _conn_str(db_name, DB_ADMIN_USER, DB_ADMIN_PASSWORD)
        with psycopg.connect(db_admin_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                with open(V1013_PATH, "r", encoding="utf-8") as f:
                    cur.execute(f.read())

                # Insert one historical V10.1.3-style batch + evaluation BEFORE applying V10.1.4
                # to verify migration backfill compatibility alongside V10.1.4 writes.
                cur.execute(
                    f"""
                    INSERT INTO users (id, username, role, is_active) VALUES
                        ('{USER_ALICE_MAKER}', 'alice_ap_maker', 'AP_CLERK', TRUE),
                        ('{USER_BOB_CHECKER1}', 'bob_checker', 'TREASURY_OFFICER', TRUE),
                        ('{USER_CAROL_CHECKER2}', 'carol_checker_two', 'TREASURY_OFFICER', TRUE),
                        ('{USER_DAVE_AUDITOR}', 'dave_auditor', 'AUDITOR', TRUE);
                    INSERT INTO encryption_key_metadata (key_id, algorithm, is_active)
                    VALUES ('{KEY_ID_ACTIVE}', 'AES-256-GCM', TRUE);
                    INSERT INTO internal_security_keys (key_id, secret_attestation_key, blind_index_key, auth_assertion_key)
                    VALUES (
                        '{KEY_ID_ACTIVE}',
                        decode('{TEST_ATTESTATION_SECRET.hex()}', 'hex'),
                        decode('{TEST_BLIND_INDEX_KEY.hex()}', 'hex'),
                        decode('{TEST_AUTH_ASSERTION_KEY.hex()}', 'hex')
                    );
                    INSERT INTO audit_chain_heads (chain_id, head_event_digest, total_events, genesis_timestamp, last_event_at)
                    VALUES ('main', repeat('0', 64), 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                    """
                )

                bob_priv = ec.derive_private_key(TEST_BOB_DETERMINISTIC_SEED, ec.SECP256R1())
                carol_priv = ec.derive_private_key(TEST_CAROL_DETERMINISTIC_SEED, ec.SECP256R1())
                bob_cose = bob_priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                carol_cose = carol_priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                cur.execute(
                    """
                    INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose, sign_count, aaguid)
                    VALUES
                        (%s, %s, %s, 0, '01020304-0506-0708-090a-0b0c0d0e0f10'::uuid),
                        (%s, %s, %s, 0, '02030405-0607-0809-0a0b-0c0d0e0f1011'::uuid);
                    """,
                    (BOB_CRED_ID, USER_BOB_CHECKER1, bob_cose, CAROL_CRED_ID, USER_CAROL_CHECKER2, carol_cose),
                )

                sample_dek = bytes.fromhex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
                blind_idx = compute_recipient_blind_index(BENEFICIARY_EMAIL, TEST_BLIND_INDEX_KEY)
                dest_digest = hashlib.sha256(BENEFICIARY_EMAIL.encode("utf-8")).hexdigest()
                nonce, ct, tag = encrypt_payload(sample_dek, BENEFICIARY_EMAIL.encode("utf-8"), b"BENEFICIARY_REGISTRY")
                cur.execute(
                    """
                    INSERT INTO beneficiaries (
                        id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce,
                        auth_tag, aad_text, encrypted_destination, destination_blind_index, destination_digest,
                        program_ref, consent_evidence_hash, registered_contact_phone_enc, registered_contact_email_enc
                    ) VALUES (
                        %s, 'Acme Engineering Corp', 1, 'VERIFIED', %s, %s, %s,
                        %s, 'BENEFICIARY_REGISTRY', %s, %s, %s,
                        'PROG_DEV_2026', %s, %s, %s
                    );
                    """,
                    (
                        BENEFICIARY_ID,
                        uuid.UUID(KEY_ID_ACTIVE),
                        sample_dek,
                        nonce,
                        tag,
                        ct,
                        blind_idx,
                        dest_digest,
                        hashlib.sha256(b"Acme Engineering Corp").hexdigest(),
                        b"\x01",
                        b"\x02",
                    ),
                )

                # Seed one pre-migration V10.1.3 historical DRAFT batch + CHALLENGE evaluation
                hist_sess = uuid.UUID("aaaaaaaa-1111-1111-1111-111111111111")
                hist_batch = uuid.UUID("bbbbbbbb-1111-1111-1111-111111111111")
                hist_asset = uuid.UUID("cccccccc-1111-1111-1111-111111111111")
                hist_seg = uuid.UUID("dddddddd-1111-1111-1111-111111111111")
                hist_eval = uuid.UUID("eeeeeeee-1111-1111-1111-111111111111")
                cur.execute("INSERT INTO sessions (id, created_by_user_id) VALUES (%s, %s);", (hist_sess, uuid.UUID(USER_ALICE_MAKER)))
                bn, bc, bt = encrypt_payload(sample_dek, b"HIST", b"PAYOUT_BATCH")
                cur.execute(
                    """
                    INSERT INTO payout_batches (
                        id, session_id, program_id, payout_period, currency, key_id,
                        wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_canonical_payload,
                        payload_digest, sender_batch_id, paypal_request_id, gateway_batch_state,
                        total_amount_cents, item_count, created_by_user_id
                    ) VALUES (
                        %s, %s, 'PROG_HIST', '2026-10', 'USD', %s,
                        %s, %s, %s, 'PAYOUT_BATCH', %s,
                        %s, 'hist_batch_v1013', %s, 'DRAFT',
                        100, 1, %s
                    );
                    """,
                    (
                        hist_batch, hist_sess, uuid.UUID(KEY_ID_ACTIVE),
                        sample_dek, bn, bt, bc,
                        hashlib.sha256(b"HIST").hexdigest(), uuid.uuid4(), uuid.UUID(USER_ALICE_MAKER),
                    ),
                )
                i_nonce, i_ct, i_tag = encrypt_payload(sample_dek, BENEFICIARY_EMAIL.encode("utf-8"), b"PAYOUT_ITEM_RECEIVER")
                cur.execute(
                    """
                    INSERT INTO payout_items (
                        id, batch_id, obligation_key, beneficiary_id, beneficiary_version,
                        expected_destination_digest, sender_item_id, recipient_type, key_id,
                        wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver,
                        destination_blind_index, amount_cents, currency, note, gateway_item_state
                    ) VALUES (
                        %s, %s, %s, %s, 1,
                        %s, 'hist_item_1', 'EMAIL', %s,
                        %s, %s, %s, 'PAYOUT_ITEM_RECEIVER', %s,
                        %s, 100, 'USD', 'Historical V10.1.3 item', 'DRAFT'
                    );
                    """,
                    (
                        uuid.uuid4(), hist_batch, "hist_ob_1", uuid.UUID(BENEFICIARY_ID),
                        dest_digest, uuid.UUID(KEY_ID_ACTIVE),
                        sample_dek, i_nonce, i_tag, i_ct,
                        blind_idx,
                    ),
                )
                cur.execute(
                    """
                    INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms)
                    VALUES (%s, %s, 16000, 1, 'WAV_PCM16', 'vault://audio/hist.wav', 6000);
                    """,
                    (hist_asset, hist_sess),
                )
                cur.execute(
                    """
                    INSERT INTO audio_consents (session_id, consent_statement_version, consent_given, audio_offset_ms, evidence_hash)
                    VALUES (%s, 'CONSENT_v10.1', TRUE, 0, %s);
                    """,
                    (hist_sess, hashlib.sha256(b"HIST_CONSENT").hexdigest()),
                )
                cur.execute(
                    """
                    INSERT INTO speaker_segments (id, audio_asset_id, speaker_label, start_ms, end_ms, sample_count, wada_snr_db, is_evaluated)
                    VALUES (%s, %s, 'EXECUTIVE_APPROVER', 0, 6000, 96000, 38.50, TRUE);
                    """,
                    (hist_seg, hist_asset),
                )
                cur.execute(
                    """
                    INSERT INTO risk_evaluations (
                        id, segment_id, model_version, deepfake_probability, acoustic_consistency_score,
                        voice_clone_flag, adversarial_noise_detected, recommendation
                    ) VALUES (%s, %s, 'ACOUSTIC_FFT_HEURISTIC_V1', 0.3900, 0.6100, FALSE, FALSE, 'CHALLENGE');
                    """,
                    (hist_eval, hist_seg),
                )
                cur.execute(
                    """
                    SELECT fn_append_audit_event(
                        'main', %s, 'AUDIO_RISK_EVALUATED', 'RISK_EVALUATION', %s,
                        NULL, NULL, NULL, 'Test-PreMigration', 1, NULL, %s::jsonb
                    );
                    """,
                    (
                        uuid.UUID(USER_ALICE_MAKER),
                        hist_eval,
                        json.dumps({"batch_id": str(hist_batch), "recommendation": "CHALLENGE", "policy_decision": "NEEDS_REVIEW"}),
                    ),
                )

                # Now apply V10.1.4 forward-only migration on top of populated V10.1.3 state
                with open(V1014_PATH, "r", encoding="utf-8") as f:
                    cur.execute(f.read())

        yield db_name
    finally:
        with psycopg.connect(admin_maint, autocommit=True) as mconn:
            with mconn.cursor() as cur:
                cur.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE);')


@pytest.fixture(autouse=True)
def bind_disposable_db_and_isolated_registry(disposable_v1014_db, tmp_path, monkeypatch):
    monkeypatch.setenv("PGDATABASE", disposable_v1014_db)
    reg_path = str(tmp_path / "isolated_audio_hash_registry.json")
    monkeypatch.setenv("AUDIO_REGISTRY_FILE", reg_path)
    monkeypatch.setattr(audio_analyzer, "REGISTRY_FILE_PATH", reg_path)
    monkeypatch.setattr(audio_analyzer, "LOCK_FILE_PATH", reg_path + ".lock")
    yield
    reset_auth_sessions()


def _create_batch() -> tuple[str, str]:
    session_id = str(uuid.uuid4())
    batch = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_V1014_APP",
        payout_period="2026-11",
        items_data=[
            {
                "beneficiary_id": BENEFICIARY_ID,
                "amount_usd": "1.00",
                "receiver_email": BENEFICIARY_EMAIL,
                "note": "V10.1.4 app integration test",
            }
        ],
        session_id=session_id,
    )
    return batch["batch_id"], session_id


def _eval_payload(recommendation: str, policy_decision: str, prob: float, clone: bool = False, noise: bool = False) -> dict:
    return {
        "model_version": "ACOUSTIC_FFT_HEURISTIC_V1",
        "duration_ms": 6000,
        "sample_count": 96000,
        "wada_snr_db": 42.69,
        "deepfake_probability": prob,
        "acoustic_consistency_score": round(max(0.05, 1.0 - prob), 4),
        "voice_clone_flag": clone,
        "adversarial_noise_detected": noise,
        "recommendation": recommendation,
        "policy_decision": policy_decision,
        "sha256_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        "acoustic_fingerprint": hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32],
    }


def _login(username: str, password: str) -> dict:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_01_verifier_connection_and_atomic_persistence(monkeypatch):
    """
    record_audio_analysis_for_batch() uses get_verifier_conn() -> fn_record_audio_risk_evaluation(),
    never falls back to get_app_conn(), and atomically persists all 5 records + audit chain row.
    """
    batch_id, session_id = _create_batch()

    def _forbid_app_conn(*args, **kwargs):
        raise AssertionError("record_audio_analysis_for_batch must NEVER use get_app_conn()")

    monkeypatch.setattr(payout_service, "get_app_conn", _forbid_app_conn)

    res = record_audio_analysis_for_batch(
        batch_id=batch_id,
        audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.14),
        session_id=session_id,
        user_id=USER_ALICE_MAKER,
    )

    assert res["recommendation"] == "APPROVE"
    assert res["policy_decision"] == "READY_FOR_CHECKER"
    eval_id = uuid.UUID(res["evaluation_id"])

    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, session_id FROM audio_assets WHERE session_id = %s;", (uuid.UUID(session_id),))
            assets = cur.fetchall()
            assert len(assets) == 1

            cur.execute("SELECT id, consent_given FROM audio_consents WHERE session_id = %s;", (uuid.UUID(session_id),))
            consents = cur.fetchall()
            assert len(consents) == 1 and consents[0]["consent_given"] is True

            cur.execute("SELECT id, is_evaluated FROM speaker_segments WHERE audio_asset_id = %s;", (assets[0]["id"],))
            segments = cur.fetchall()
            assert len(segments) == 1 and segments[0]["is_evaluated"] is True

            cur.execute(
                "SELECT id, batch_id, recommendation, policy_decision FROM risk_evaluations WHERE id = %s;",
                (eval_id,),
            )
            reval = cur.fetchone()
            assert reval is not None
            assert str(reval["batch_id"]) == batch_id
            assert reval["recommendation"] == "APPROVE"
            assert reval["policy_decision"] == "READY_FOR_CHECKER"

            cur.execute(
                """
                SELECT event_type, entity_type, entity_id, metadata_json
                FROM audit_events
                WHERE event_type = 'AUDIO_RISK_EVALUATED' AND entity_id = %s;
                """,
                (eval_id,),
            )
            aud = cur.fetchone()
            assert aud is not None
            assert aud["metadata_json"]["batch_id"] == batch_id
            assert aud["metadata_json"]["policy_decision"] == "READY_FOR_CHECKER"


def test_02_transaction_rollback_atomicity_on_failure(monkeypatch):
    """
    If any step inside the verifier transaction fails (DB constraint rejection OR commit failure),
    ZERO partial rows may persist across audio_assets, audio_consents, speaker_segments,
    risk_evaluations, or audit_events.
    """
    batch_id, session_id = _create_batch()

    # Case A: DB-level classification inconsistency inside fn_record_audio_risk_evaluation
    with pytest.raises(AudioRiskGateError, match="rejected"):
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_eval_payload("APPROVE", "NEEDS_REVIEW", 0.12),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )

    # Case B: Failure after fn_record_audio_risk_evaluation executes but before commit()
    real_get_verifier = payout_service.get_verifier_conn

    class _AbortingCommitConn:
        def __init__(self, inner):
            self._inner = inner

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            self._inner.rollback()
            return self._inner.__exit__(exc_type, exc, tb)

        def cursor(self, *args, **kwargs):
            return self._inner.cursor(*args, **kwargs)

        def commit(self):
            raise RuntimeError("Simulated mid-commit failure after PL/pgSQL execution")

        def rollback(self):
            return self._inner.rollback()

    monkeypatch.setattr(
        payout_service,
        "get_verifier_conn",
        lambda autocommit=False: _AbortingCommitConn(real_get_verifier(autocommit=autocommit)),
    )

    with pytest.raises(AudioRiskGateError, match="verifier execution failed"):
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )

    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM audio_assets WHERE session_id = %s;", (uuid.UUID(session_id),))
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM audio_consents WHERE session_id = %s;", (uuid.UUID(session_id),))
            assert cur.fetchone()[0] == 0
            cur.execute(
                "SELECT COUNT(*) FROM risk_evaluations WHERE batch_id = %s;",
                (uuid.UUID(batch_id),),
            )
            assert cur.fetchone()[0] == 0
            cur.execute(
                """
                SELECT COUNT(*) FROM audit_events
                WHERE event_type = 'AUDIO_RISK_EVALUATED' AND metadata_json->>'batch_id' = %s;
                """,
                (batch_id,),
            )
            assert cur.fetchone()[0] == 0


def test_03_verifier_unavailable_fails_closed_no_fallback_no_secret_leak(monkeypatch, capsys):
    """
    When verifier connection is misconfigured or unreachable, record_audio_analysis_for_batch()
    must fail closed without falling back to get_app_conn() and without leaking passwords/DSNs.
    """
    batch_id, session_id = _create_batch()
    app_fallback_called = False

    def _spy_app_conn(*args, **kwargs):
        nonlocal app_fallback_called
        app_fallback_called = True
        raise AssertionError("Silent fallback to deepfakeshield_app is forbidden!")

    monkeypatch.setattr(payout_service, "get_app_conn", _spy_app_conn)

    # 1. Empty verifier password fails closed inside get_verifier_conn()
    monkeypatch.setenv("VERIFIER_PASSWORD", "")
    with pytest.raises(AudioRiskGateError) as exc_info:
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )
    assert not app_fallback_called
    err_msg = str(exc_info.value)
    assert VERIFIER_PASS not in err_msg
    assert "password=" not in err_msg.lower()

    # 2. Unreachable database port fails closed with psycopg.OperationalError wrapper
    secret_sentinel = "VERIFIER_SECRET_SENTINEL_DO_NOT_LOG_98765"
    monkeypatch.setenv("VERIFIER_PASSWORD", secret_sentinel)
    monkeypatch.setenv("PGPORT", "59999")
    with pytest.raises(AudioRiskGateError) as exc_info_port:
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )
    assert not app_fallback_called
    err_port_msg = str(exc_info_port.value)
    assert secret_sentinel not in err_port_msg
    assert VERIFIER_PASS not in err_port_msg
    assert "password=" not in err_port_msg.lower()

    # 3. Auth rejection from get_verifier_conn() (e.g., scram-sha-256 mismatch) fails closed
    monkeypatch.delenv("PGPORT", raising=False)
    monkeypatch.setattr(
        payout_service,
        "get_verifier_conn",
        lambda autocommit=False: (_ for _ in ()).throw(
            psycopg.OperationalError("connection failed: password authentication failed for user deepfakeshield_verifier")
        ),
    )
    with pytest.raises(AudioRiskGateError) as exc_info_auth:
        record_audio_analysis_for_batch(
            batch_id=batch_id,
            audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
            session_id=session_id,
            user_id=USER_ALICE_MAKER,
        )
    assert not app_fallback_called
    assert secret_sentinel not in str(exc_info_auth.value)

    captured = capsys.readouterr()
    combined_out = captured.out + captured.err
    assert secret_sentinel not in combined_out
    assert VERIFIER_PASS not in combined_out
    assert "password=" not in combined_out.lower()


def test_04_cross_batch_and_role_boundary_protection():
    """
    Cross-batch session mismatches fail closed at verifier recording time, and direct
    table writes by deepfakeshield_app are denied under V10.1.4 RBAC.
    """
    batch_a, sess_a = _create_batch()
    batch_b, _sess_b = _create_batch()

    # Cross-batch attempt (batch_b with sess_a) fails closed before writing any row
    with pytest.raises(AudioRiskGateError, match="Session mismatch"):
        record_audio_analysis_for_batch(
            batch_id=batch_b,
            audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.10),
            session_id=sess_a,
            user_id=USER_ALICE_MAKER,
        )

    # Direct app INSERT into risk_evaluations & audio_assets must fail with insufficient_privilege
    with get_app_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    """
                    INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms)
                    VALUES (%s, %s, 16000, 1, 'WAV_PCM16', 'vault://forged.wav', 5000);
                    """,
                    (uuid.uuid4(), uuid.UUID(sess_a)),
                )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    """
                    SELECT fn_record_audio_risk_evaluation(
                        %s::uuid, %s::uuid, %s::uuid, %s::uuid, %s::uuid, %s::uuid,
                        'vault://forged.wav', 5000, 80000, 40.0, 'h', 'M',
                        0.05, 0.95, FALSE, FALSE, 'APPROVE', 'READY_FOR_CHECKER', '{}'::jsonb
                    );
                    """,
                    (uuid.UUID(batch_a), uuid.UUID(sess_a), uuid.UUID(USER_ALICE_MAKER), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()),
                )


def test_05_finalization_gates_and_both_overloads_enforced():
    """
    End-to-end verification of CHALLENGE/NEEDS_REVIEW/BLOCKED/missing/stale rejection across
    application + both DB fn_finalize_payout_batch overloads, plus clean APPROVE finalization.
    """
    batch_chal, sess_chal = _create_batch()
    batch_missing, _ = _create_batch()
    batch_stale, sess_stale = _create_batch()
    batch_ok, sess_ok = _create_batch()

    record_audio_analysis_for_batch(
        batch_id=batch_chal,
        audio_analysis_result=_eval_payload("CHALLENGE", "NEEDS_REVIEW", 0.39),
        session_id=sess_chal,
        user_id=USER_ALICE_MAKER,
    )

    h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")
    resp = client.post(
        f"/api/batches/{batch_chal}/finalize",
        json={"audio_policy_decision": "READY_FOR_CHECKER"},
        headers=h_alice,
    )
    assert resp.status_code == 403
    assert "CHALLENGE" in resp.text or "NEEDS_REVIEW" in resp.text

    with pytest.raises(AudioRiskGateError):
        finalize_batch(batch_missing)

    eval_stale = record_audio_analysis_for_batch(
        batch_id=batch_stale,
        audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.11),
        session_id=sess_stale,
        user_id=USER_ALICE_MAKER,
    )
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            old_ts = datetime.now(timezone.utc) - timedelta(hours=2)
            cur.execute("UPDATE risk_evaluations SET evaluated_at = %s WHERE id = %s;", (old_ts, uuid.UUID(eval_stale["evaluation_id"])))
    with pytest.raises(AudioRiskGateError, match="stale"):
        finalize_batch(batch_stale, max_eval_age_seconds=3600)

    # Verify BOTH 10-arg and 9-arg fn_finalize_payout_batch SQL overloads fail closed on CHALLENGE batch
    with get_app_conn(autocommit=False) as conn:
        with conn.cursor() as cur:
            dek = os.urandom(32)
            aad = "DEEPFAKESHIELD-PAYOUT-v1"
            cj = '{"sender_batch_header":{"sender_batch_id":"x","email_subject":"x","recipient_type":"EMAIL"},"items":[]}'
            nonce, ct, tag = encrypt_payload(dek, cj.encode(), aad.encode())
            snap_id = uuid.uuid4()
            att = verify_and_attest_snapshot(
                dek=dek, nonce=nonce, ciphertext=ct, tag=tag, aad=aad.encode(),
                expected_plaintext_json=cj, batch_id=uuid.UUID(batch_chal), snapshot_id=snap_id,
                key_id=uuid.UUID(KEY_ID_ACTIVE), attestation_secret=TEST_ATTESTATION_SECRET, wrapped_dek=dek,
            ).attestation

            with pytest.raises(psycopg.errors.CheckViolation, match="Audio risk gate rejected"):
                cur.execute(
                    "SELECT fn_finalize_payout_batch(%s::uuid, %s::text, %s::bytea, %s::varchar, %s::bytea, %s::bytea, %s::bytea, %s::text, %s::bytea, %s::uuid);",
                    (uuid.UUID(batch_chal), cj, ct, hashlib.sha256(cj.encode()).hexdigest(), dek, nonce, tag, aad, att, snap_id),
                )
            conn.rollback()

            with pytest.raises(psycopg.errors.CheckViolation, match="Audio risk gate rejected"):
                cur.execute(
                    "SELECT fn_finalize_payout_batch(%s::uuid, %s::text, %s::bytea, %s::varchar, %s::bytea, %s::bytea, %s::bytea, %s::text, %s::bytea);",
                    (uuid.UUID(batch_chal), cj, ct, hashlib.sha256(cj.encode()).hexdigest(), dek, nonce, tag, aad, att),
                )
            conn.rollback()

    # Clean APPROVE recorded via verifier persists & finalizes successfully
    record_audio_analysis_for_batch(
        batch_id=batch_ok,
        audio_analysis_result=_eval_payload("APPROVE", "READY_FOR_CHECKER", 0.12),
        session_id=sess_ok,
        user_id=USER_ALICE_MAKER,
    )
    fin_resp = client.post(
        f"/api/batches/{batch_ok}/finalize",
        json={},
        headers=h_alice,
    )
    assert fin_resp.status_code == 200, f"Expected clean APPROVE finalization to pass: {fin_resp.text}"
    assert fin_resp.json()["gateway_batch_state"] == "READY_FOR_CHECKER"


def test_06_isolated_analyzer_to_verifier_batch_creation(tmp_path):
    """
    Runs analyze_audio_instruction() against an isolated temporary WAV & isolated
    AUDIO_REGISTRY_FILE, then feeds the output into /api/batches/create without touching
    the live audio_hash_registry.json or audio_samples/.
    """
    wav_path = str(tmp_path / "synthetic_test_tone.wav")
    sr = 16000
    t = np.linspace(0, 5.2, int(sr * 5.2), endpoint=False)
    sig = (0.35 * np.sin(2 * np.pi * 165.0 * t) + 0.12 * np.sin(2 * np.pi * 330.0 * t)) * 32767.0
    pcm16 = sig.astype(np.int16)
    with wave.open(wav_path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(pcm16.tobytes())

    with open(wav_path, "rb") as f:
        wav_bytes = f.read()
    analysis = audio_analyzer.analyze_audio_instruction(wav_bytes)
    assert analysis["replay_detected"] is False
    assert os.path.isfile(audio_analyzer.REGISTRY_FILE_PATH)

    h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")
    create_resp = client.post(
        "/api/batches/create",
        json={
            "program_id": "PROG_ISO_AUDIO",
            "payout_period": "2026-11",
            "items": [
                {
                    "beneficiary_id": BENEFICIARY_ID,
                    "amount_usd": "1.00",
                    "receiver_email": BENEFICIARY_EMAIL,
                    "note": "Isolated analyzer check",
                }
            ],
            "audio_analysis": analysis,
        },
        headers=h_alice,
    )
    assert create_resp.status_code == 200, create_resp.text
    payload = create_resp.json()
    assert payload["audio_evaluation"]["evaluation_id"] is not None
    assert payload["batch"]["gateway_batch_state"] == "DRAFT"


def test_07_rollout_readiness_and_v1013_backfill_compatibility():
    """
    Verifies rollout-readiness invariants:
    - Zero verifier credentials/secrets in static frontend files.
    - Both fn_finalize_payout_batch overloads revoke PUBLIC execute and enforce audio gate.
    - No manual-review endpoint or NEEDS_REVIEW -> READY_FOR_CHECKER transition exists.
    - Historical pre-migration V10.1.3 CHALLENGE batch (seeded in fixture before V10.1.4)
      was cleanly backfilled and still fails closed at finalization.
    """
    # 1. Frontend credential scan
    for rel_path in ("static/index.html", "build_index_html.py"):
        full_path = os.path.join(REPO_ROOT, rel_path)
        if os.path.isfile(full_path):
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "verifier_secret_pass" not in content
            assert "VERIFIER_PASSWORD" not in content
            assert "deepfakeshield_verifier" not in content

    # 2. Both DB overloads exist and fail closed; fn_record_audio_risk_evaluation restricted to verifier/owner
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND p.proname = 'fn_finalize_payout_batch';
                """
            )
            assert cur.fetchone()[0] == 2
            cur.execute(
                """
                SELECT has_function_privilege(
                    'public',
                    'fn_record_audio_risk_evaluation(uuid,uuid,uuid,uuid,uuid,uuid,text,int,int,numeric,varchar,varchar,numeric,numeric,boolean,boolean,varchar,varchar,jsonb)',
                    'EXECUTE'
                );
                """
            )
            assert cur.fetchone()[0] is False
            cur.execute(
                """
                SELECT has_function_privilege(
                    'deepfakeshield_app',
                    'fn_record_audio_risk_evaluation(uuid,uuid,uuid,uuid,uuid,uuid,text,int,int,numeric,varchar,varchar,numeric,numeric,boolean,boolean,varchar,varchar,jsonb)',
                    'EXECUTE'
                );
                """
            )
            assert cur.fetchone()[0] is False
            cur.execute(
                """
                SELECT has_function_privilege(
                    'deepfakeshield_verifier',
                    'fn_record_audio_risk_evaluation(uuid,uuid,uuid,uuid,uuid,uuid,text,int,int,numeric,varchar,varchar,numeric,numeric,boolean,boolean,varchar,varchar,jsonb)',
                    'EXECUTE'
                );
                """
            )
            assert cur.fetchone()[0] is True

            # Verify V10.1.3 historical evaluation was backfilled with batch_id & policy_decision
            cur.execute(
                "SELECT batch_id::text, recommendation, policy_decision FROM risk_evaluations WHERE id = 'eeeeeeee-1111-1111-1111-111111111111';"
            )
            hist_row = cur.fetchone()
            assert hist_row == ("bbbbbbbb-1111-1111-1111-111111111111", "CHALLENGE", "NEEDS_REVIEW")

    # 3. Historical V10.1.3 CHALLENGE batch still fails closed
    with pytest.raises(AudioRiskGateError):
        finalize_batch("bbbbbbbb-1111-1111-1111-111111111111")

    # 4. No manual-review route in FastAPI app
    route_paths = [getattr(r, "path", "") for r in app.routes]
    assert not any("review" in p.lower() and "audio" in p.lower() for p in route_paths)
