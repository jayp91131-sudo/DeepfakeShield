"""
DeepfakeShield V10.1.3 -> V10.1.4 — Disposable PostgreSQL Database Audio-Gate Verification

Runs V10_1_3__security_repair.sql + V10_1_4__database_audio_finalization_gate.sql
inside an isolated disposable PostgreSQL database and drops it on teardown.
Never touches live deepfakeshield_db, historical migrations, batch 00650125-d269-4319-9ec9-1825e106a4b4,
or audio_hash_registry.json.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from psycopg.rows import dict_row

from backend.database import (
    APP_PASS,
    AUDITOR_PASS,
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
)
from crypto_verifier import (
    compute_recipient_blind_index,
    create_webauthn_assertion,
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


def _conn_str(db_name: str, user: str, password: str) -> str:
    return f"host={DB_HOST} port={DB_PORT} dbname={db_name} user={user} password={password}"


@pytest.fixture(scope="module")
def disposable_db():
    db_name = f"deepfakeshield_v1014_test_{uuid.uuid4().hex[:10]}"
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
                with open(V1014_PATH, "r", encoding="utf-8") as f:
                    cur.execute(f.read())

                # Seed minimal deterministic users, keys, credentials, beneficiary, audit head
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

        yield db_name
    finally:
        with psycopg.connect(admin_maint, autocommit=True) as mconn:
            with mconn.cursor() as cur:
                cur.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE);')


def _create_draft_batch_sql(db_name: str, session_id: str | None = None) -> tuple[str, str, str, str]:
    batch_id = str(uuid.uuid4())
    session_id = session_id or str(uuid.uuid4())
    sender_batch_id = f"batch_DBTEST_{batch_id[:8]}"
    sender_item_id = f"item_{batch_id[:6]}_1"

    app_dsn = _conn_str(db_name, "deepfakeshield_app", APP_PASS)
    with psycopg.connect(app_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (id, created_by_user_id) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING;",
                (uuid.UUID(session_id), uuid.UUID(USER_ALICE_MAKER)),
            )
            b_dek = os.urandom(32)
            bn, bc, bt = encrypt_payload(b_dek, b"DRAFT", b"PAYOUT_BATCH")
            cur.execute(
                """
                INSERT INTO payout_batches (
                    id, session_id, program_id, payout_period, currency, key_id,
                    wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_canonical_payload,
                    payload_digest, sender_batch_id, paypal_request_id, gateway_batch_state,
                    total_amount_cents, item_count, created_by_user_id
                ) VALUES (
                    %s, %s, 'PROG_DEV_2026', '2026-11', 'USD', %s,
                    %s, %s, %s, 'PAYOUT_BATCH', %s,
                    'DRAFT_PLACEHOLDER', %s, %s, 'DRAFT',
                    100, 1, %s
                );
                """,
                (
                    uuid.UUID(batch_id),
                    uuid.UUID(session_id),
                    uuid.UUID(KEY_ID_ACTIVE),
                    b_dek,
                    bn,
                    bt,
                    bc,
                    sender_batch_id,
                    uuid.uuid4(),
                    uuid.UUID(USER_ALICE_MAKER),
                ),
            )

            blind_idx = compute_recipient_blind_index(BENEFICIARY_EMAIL, TEST_BLIND_INDEX_KEY)
            dest_digest = hashlib.sha256(BENEFICIARY_EMAIL.encode("utf-8")).hexdigest()
            i_dek = os.urandom(32)
            inonce, ict, itag = encrypt_payload(i_dek, BENEFICIARY_EMAIL.encode("utf-8"), b"PAYOUT_ITEM_RECEIVER")
            cur.execute(
                """
                INSERT INTO payout_items (
                    id, batch_id, obligation_key, beneficiary_id, beneficiary_version,
                    expected_destination_digest, sender_item_id, recipient_type, key_id,
                    wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver,
                    destination_blind_index, amount_cents, currency, note, gateway_item_state
                ) VALUES (
                    %s, %s, %s, %s, 1,
                    %s, %s, 'EMAIL', %s,
                    %s, %s, %s, 'PAYOUT_ITEM_RECEIVER', %s,
                    %s, 100, 'USD', 'Sandbox test', 'DRAFT'
                );
                """,
                (
                    uuid.uuid4(),
                    uuid.UUID(batch_id),
                    f"ob_{batch_id[:8]}",
                    uuid.UUID(BENEFICIARY_ID),
                    dest_digest,
                    sender_item_id,
                    uuid.UUID(KEY_ID_ACTIVE),
                    i_dek,
                    inonce,
                    itag,
                    ict,
                    blind_idx,
                ),
            )
    return batch_id, session_id, sender_batch_id, sender_item_id


def _record_eval_as_verifier(
    db_name: str,
    batch_id: str,
    session_id: str,
    recommendation: str,
    policy_decision: str,
    prob: float,
    clone: bool = False,
    noise: bool = False,
) -> str:
    asset_id = uuid.uuid4()
    segment_id = uuid.uuid4()
    eval_id = uuid.uuid4()
    verifier_dsn = _conn_str(db_name, "deepfakeshield_verifier", VERIFIER_PASS)
    with psycopg.connect(verifier_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT fn_record_audio_risk_evaluation(
                    %s::uuid, %s::uuid, %s::uuid, %s::uuid, %s::uuid, %s::uuid,
                    %s::text, %s::int, %s::int, %s::numeric, %s::varchar,
                    'ACOUSTIC_FFT_HEURISTIC_V1'::varchar, %s::numeric, %s::numeric,
                    %s::boolean, %s::boolean, %s::varchar, %s::varchar, NULL::jsonb
                );
                """,
                (
                    uuid.UUID(batch_id),
                    uuid.UUID(session_id),
                    uuid.UUID(USER_ALICE_MAKER),
                    asset_id,
                    segment_id,
                    eval_id,
                    f"vault://audio/{asset_id}.wav",
                    6000,
                    96000,
                    42.69,
                    hashlib.sha256(b"CONSENT_OK").hexdigest(),
                    prob,
                    round(max(0.05, 1.0 - prob), 4),
                    clone,
                    noise,
                    recommendation,
                    policy_decision,
                ),
            )
            return str(cur.fetchone()[0])


def _call_finalize_sql(db_name: str, batch_id: str, sender_batch_id: str, sender_item_id: str, nine_arg: bool = False):
    payload = {
        "sender_batch_header": {
            "sender_batch_id": sender_batch_id,
            "email_subject": "Disbursement for 2026-11",
            "recipient_type": "EMAIL",
        },
        "items": [
            {
                "recipient_type": "EMAIL",
                "amount": {"value": "1.00", "currency": "USD"},
                "note": "Sandbox test",
                "sender_item_id": sender_item_id,
                "receiver": BENEFICIARY_EMAIL,
            }
        ],
    }
    canonical_json = json.dumps(payload, separators=(",", ":"))
    p_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    dek = os.urandom(32)
    aad = "DEEPFAKESHIELD-PAYOUT-v1"
    nonce, ciphertext, tag = encrypt_payload(dek, canonical_json.encode("utf-8"), aad.encode("utf-8"))
    snapshot_id = uuid.uuid4()
    attestation = verify_and_attest_snapshot(
        dek=dek,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        aad=aad.encode("utf-8"),
        expected_plaintext_json=canonical_json,
        batch_id=uuid.UUID(batch_id),
        snapshot_id=snapshot_id,
        key_id=uuid.UUID(KEY_ID_ACTIVE),
        attestation_secret=TEST_ATTESTATION_SECRET,
        wrapped_dek=dek,
    ).attestation

    app_dsn = _conn_str(db_name, "deepfakeshield_app", APP_PASS)
    with psycopg.connect(app_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            if nine_arg:
                cur.execute(
                    "SELECT fn_finalize_payout_batch(%s, %s, %s, %s, %s, %s, %s, %s, %s);",
                    (uuid.UUID(batch_id), canonical_json, ciphertext, p_digest, dek, nonce, tag, aad, attestation),
                )
            else:
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
                        aad,
                        attestation,
                        snapshot_id,
                    ),
                )
            return str(cur.fetchone()[0]), p_digest


def _assert_rejected_state_clean(db_name: str, batch_id: str) -> None:
    admin_dsn = _conn_str(db_name, DB_ADMIN_USER, DB_ADMIN_PASSWORD)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state, active_snapshot_id FROM payout_batches WHERE id = %s;", (batch_id,))
            b = cur.fetchone()
            assert b["gateway_batch_state"] == "DRAFT"
            assert b["active_snapshot_id"] is None
            cur.execute("SELECT COUNT(*) AS c FROM payout_snapshots WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0
            cur.execute("SELECT COUNT(*) AS c FROM outbox_jobs WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0
            cur.execute("SELECT COUNT(*) AS c FROM beneficiary_submission_locks WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["c"] == 0


def test_db_01_direct_sql_rejects_challenge(disposable_db):
    batch_id, session_id, sb_id, si_id = _create_draft_batch_sql(disposable_db)
    _record_eval_as_verifier(disposable_db, batch_id, session_id, "CHALLENGE", "NEEDS_REVIEW", 0.3898)

    with pytest.raises(psycopg.errors.CheckViolation, match="Audio risk gate rejected"):
        _call_finalize_sql(disposable_db, batch_id, sb_id, si_id, nine_arg=False)
    with pytest.raises(psycopg.errors.CheckViolation, match="Audio risk gate rejected"):
        _call_finalize_sql(disposable_db, batch_id, sb_id, si_id, nine_arg=True)

    _assert_rejected_state_clean(disposable_db, batch_id)


def test_db_02_direct_sql_rejects_needs_review_and_state_machine_stays_locked(disposable_db):
    batch_id, session_id, sb_id, si_id = _create_draft_batch_sql(disposable_db)
    # Even if inserted directly by admin with recommendation='APPROVE' + policy_decision='NEEDS_REVIEW', gate must block
    admin_dsn = _conn_str(disposable_db, DB_ADMIN_USER, DB_ADMIN_PASSWORD)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            asset_id, seg_id, eval_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            cur.execute(
                "INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms) VALUES (%s, %s, 16000, 1, 'WAV_PCM16', 'vault://a.wav', 6000);",
                (asset_id, uuid.UUID(session_id)),
            )
            cur.execute(
                "INSERT INTO audio_consents (session_id, consent_statement_version, consent_given, audio_offset_ms, evidence_hash) VALUES (%s, 'CONSENT_v10.1', TRUE, 0, 'abc');",
                (uuid.UUID(session_id),),
            )
            cur.execute(
                "INSERT INTO speaker_segments (id, audio_asset_id, speaker_label, start_ms, end_ms, sample_count, wada_snr_db, is_evaluated) VALUES (%s, %s, 'EXEC', 0, 6000, 96000, 40.0, TRUE);",
                (seg_id, asset_id),
            )
            cur.execute(
                "INSERT INTO risk_evaluations (id, segment_id, batch_id, model_version, deepfake_probability, acoustic_consistency_score, voice_clone_flag, adversarial_noise_detected, recommendation, policy_decision) VALUES (%s, %s, %s, 'ACOUSTIC_FFT_HEURISTIC_V1', 0.2000, 0.8000, FALSE, FALSE, 'APPROVE', 'NEEDS_REVIEW');",
                (eval_id, seg_id, uuid.UUID(batch_id)),
            )
            cur.execute(
                "SELECT fn_append_audit_event('main', %s, 'AUDIO_RISK_EVALUATED', 'RISK_EVALUATION', %s, NULL, NULL, NULL, 'test', 1, NULL, %s::jsonb);",
                (uuid.UUID(USER_ALICE_MAKER), eval_id, json.dumps({"batch_id": batch_id, "policy_decision": "NEEDS_REVIEW"})),
            )

    with pytest.raises(psycopg.errors.CheckViolation, match="Audio risk gate rejected"):
        _call_finalize_sql(disposable_db, batch_id, sb_id, si_id)
    _assert_rejected_state_clean(disposable_db, batch_id)

    # Confirm NEEDS_REVIEW state machine has zero outgoing transition
    nr_batch, _, _, _ = _create_draft_batch_sql(disposable_db)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id = %s;", (uuid.UUID(nr_batch),))
            cur.execute("UPDATE payout_batches SET gateway_batch_state = 'NEEDS_REVIEW' WHERE id = %s;", (uuid.UUID(nr_batch),))
            for illegal_target in ("READY_FOR_CHECKER", "APPROVED_TO_SUBMIT", "REJECTED_BY_CHECKER"):
                with pytest.raises(psycopg.errors.CheckViolation, match="Illegal payout batch state transition"):
                    cur.execute(
                        "UPDATE payout_batches SET gateway_batch_state = %s WHERE id = %s;",
                        (illegal_target, uuid.UUID(nr_batch)),
                    )


def test_db_03_missing_stale_or_superseded_evidence_rejected(disposable_db):
    # 3a. Missing evidence
    b_miss, _, sb_miss, si_miss = _create_draft_batch_sql(disposable_db)
    with pytest.raises(psycopg.errors.CheckViolation, match="missing explicit audio consent|missing audio_assets"):
        _call_finalize_sql(disposable_db, b_miss, sb_miss, si_miss)
    _assert_rejected_state_clean(disposable_db, b_miss)

    # 3b. Stale (> 1h) evidence
    b_stale, s_stale, sb_stale, si_stale = _create_draft_batch_sql(disposable_db)
    eval_stale = _record_eval_as_verifier(disposable_db, b_stale, s_stale, "APPROVE", "READY_FOR_CHECKER", 0.10)
    admin_dsn = _conn_str(disposable_db, DB_ADMIN_USER, DB_ADMIN_PASSWORD)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE risk_evaluations SET evaluated_at = %s WHERE id = %s;",
                (datetime.now(timezone.utc) - timedelta(hours=2), uuid.UUID(eval_stale)),
            )
    with pytest.raises(psycopg.errors.CheckViolation, match="stale"):
        _call_finalize_sql(disposable_db, b_stale, sb_stale, si_stale)
    _assert_rejected_state_clean(disposable_db, b_stale)

    # 3c. Superseded by newer unevaluated audio_assets row
    b_sup, s_sup, sb_sup, si_sup = _create_draft_batch_sql(disposable_db)
    _record_eval_as_verifier(disposable_db, b_sup, s_sup, "APPROVE", "READY_FOR_CHECKER", 0.10)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms, recorded_at) VALUES (%s, %s, 16000, 1, 'WAV_PCM16', 'vault://newer.wav', 5500, %s);",
                (uuid.uuid4(), uuid.UUID(s_sup), datetime.now(timezone.utc) + timedelta(seconds=5)),
            )
    with pytest.raises(psycopg.errors.CheckViolation, match="missing risk evaluation"):
        _call_finalize_sql(disposable_db, b_sup, sb_sup, si_sup)
    _assert_rejected_state_clean(disposable_db, b_sup)


def test_db_04_unassociated_evidence_and_shared_session_rejected(disposable_db):
    # Cross-batch shared session rejected
    shared_sess = str(uuid.uuid4())
    b1, _, sb1, si1 = _create_draft_batch_sql(disposable_db, session_id=shared_sess)
    # Attach eval to b1 fails if session is shared once b2 exists
    b2, _, sb2, si2 = _create_draft_batch_sql(disposable_db, session_id=shared_sess)
    with pytest.raises(psycopg.errors.CheckViolation, match="shared across multiple batches"):
        _call_finalize_sql(disposable_db, b2, sb2, si2)
    _assert_rejected_state_clean(disposable_db, b2)

    # Mismatched batch_id in audit/evaluation fails closed
    b3, s3, sb3, si3 = _create_draft_batch_sql(disposable_db)
    _record_eval_as_verifier(disposable_db, b3, s3, "APPROVE", "READY_FOR_CHECKER", 0.10)
    b_other, _, _, _ = _create_draft_batch_sql(disposable_db)
    admin_dsn = _conn_str(disposable_db, DB_ADMIN_USER, DB_ADMIN_PASSWORD)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE risk_evaluations SET batch_id = %s WHERE batch_id = %s;", (uuid.UUID(b_other), uuid.UUID(b3)))
    with pytest.raises(psycopg.errors.CheckViolation, match="does not match batch"):
        _call_finalize_sql(disposable_db, b3, sb3, si3)
    _assert_rejected_state_clean(disposable_db, b3)


def test_db_05_rbac_prevents_runtime_app_forgery_and_auditor_mutations(disposable_db):
    b_rbac, s_rbac, sb_rbac, si_rbac = _create_draft_batch_sql(disposable_db)
    app_dsn = _conn_str(disposable_db, "deepfakeshield_app", APP_PASS)
    with psycopg.connect(app_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            for stmt in [
                f"INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms) VALUES ('{uuid.uuid4()}', '{s_rbac}', 16000, 1, 'WAV_PCM16', 'vault://forged.wav', 6000);",
                f"INSERT INTO audio_consents (session_id, consent_statement_version, consent_given, audio_offset_ms, evidence_hash) VALUES ('{s_rbac}', 'CONSENT_v10.1', TRUE, 0, 'forged');",
                f"INSERT INTO speaker_segments (id, audio_asset_id, speaker_label, start_ms, end_ms, sample_count, wada_snr_db, is_evaluated) VALUES ('{uuid.uuid4()}', '{uuid.uuid4()}', 'EXEC', 0, 6000, 96000, 40.0, TRUE);",
                f"INSERT INTO risk_evaluations (id, segment_id, batch_id, model_version, deepfake_probability, acoustic_consistency_score, voice_clone_flag, adversarial_noise_detected, recommendation, policy_decision) VALUES ('{uuid.uuid4()}', '{uuid.uuid4()}', '{b_rbac}', 'FORGED', 0.01, 0.99, FALSE, FALSE, 'APPROVE', 'READY_FOR_CHECKER');",
                f"SELECT fn_record_audio_risk_evaluation('{b_rbac}'::uuid, '{s_rbac}'::uuid, '{USER_ALICE_MAKER}'::uuid, gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'vault://f.wav'::text, 6000, 96000, 40.0::numeric, 'h'::varchar, 'M'::varchar, 0.05::numeric, 0.95::numeric, FALSE, FALSE, 'APPROVE'::varchar, 'READY_FOR_CHECKER'::varchar, NULL::jsonb);",
            ]:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    cur.execute(stmt)

    # Auditor cannot call fn_finalize_payout_batch or fn_record_audio_risk_evaluation
    aud_dsn = _conn_str(disposable_db, "deepfakeshield_auditor", AUDITOR_PASS)
    with psycopg.connect(aud_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(f"SELECT fn_finalize_payout_batch('{b_rbac}'::uuid, '{{}}', '\\x00'::bytea, 'a', '\\x00'::bytea, '\\x00'::bytea, '\\x00'::bytea, 'aad', '\\x00'::bytea, NULL);")

    # Even verifier cannot record inconsistent APPROVE with prob >= 0.35
    with pytest.raises(psycopg.errors.CheckViolation, match="Inconsistent audio policy classification"):
        _record_eval_as_verifier(disposable_db, b_rbac, s_rbac, "APPROVE", "READY_FOR_CHECKER", 0.3898)

    _assert_rejected_state_clean(disposable_db, b_rbac)


def test_db_06_valid_positive_eval_proceeds_only_through_required_controls(disposable_db):
    b_ok, s_ok, sb_ok, si_ok = _create_draft_batch_sql(disposable_db)
    _record_eval_as_verifier(disposable_db, b_ok, s_ok, "APPROVE", "READY_FOR_CHECKER", 0.12)

    snap_id, p_digest = _call_finalize_sql(disposable_db, b_ok, sb_ok, si_ok)
    assert snap_id

    admin_dsn = _conn_str(disposable_db, DB_ADMIN_USER, DB_ADMIN_PASSWORD)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state, active_snapshot_id FROM payout_batches WHERE id = %s;", (b_ok,))
            b_row = cur.fetchone()
            assert b_row["gateway_batch_state"] == "READY_FOR_CHECKER"
            assert str(b_row["active_snapshot_id"]) == snap_id
            # Outbox job is NOT created by finalization alone (requires dual Treasury Officer WebAuthn)
            cur.execute("SELECT COUNT(*) AS c FROM outbox_jobs WHERE batch_id = %s;", (b_ok,))
            assert cur.fetchone()["c"] == 0
            cur.execute("SELECT fn_verify_payout_snapshot_envelope(%s);", (uuid.UUID(snap_id),))
            assert cur.fetchone()["fn_verify_payout_snapshot_envelope"] is True
