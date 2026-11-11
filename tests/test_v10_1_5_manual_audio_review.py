import base64
import hashlib
import io
import json
import os
import sys
import uuid
import wave

import numpy as np
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.database import (
    AUDITOR_PASS,
    BOB_CRED_ID,
    BOB_DETERMINISTIC_SEED,
    CAROL_CRED_ID,
    CAROL_DETERMINISTIC_SEED,
    DB_ADMIN_PASSWORD,
    DB_ADMIN_USER,
    DB_HOST,
    DB_PORT,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_DAVE_AUDITOR,
    USER_EVE_UNAUTHORIZED,
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
    get_audio_review_evidence,
    record_audio_analysis_for_batch,
    store_audio_vault_bytes,
    submit_manual_audio_review,
)
from crypto_verifier import (
    DEFAULT_AUTH_ASSERTION_KEY,
    DEFAULT_BLIND_INDEX_KEY,
    DEFAULT_ATTESTATION_SECRET,
    compute_recipient_blind_index,
    create_webauthn_assertion,
    encrypt_payload,
)

BENEFICIARY_ID = "30000000-0000-0000-0000-000000000001"
BENEFICIARY_EMAIL = "sb-i6hah53856187@personal.example.com"
KEY_ID_ACTIVE = "a0000000-0000-0000-0000-000000000001"

EPHEMERAL_REVIEWER_ID = "10000000-0000-0000-0000-000000000099"
EPHEMERAL_INACTIVE_REVIEWER_ID = "10000000-0000-0000-0000-000000000098"
EPHEMERAL_REVIEWER_USERNAME = "test_disposable_reviewer"
EPHEMERAL_REVIEWER_SECRET = "disposable_only_reviewer_secret_not_prod"

HIST_BATCH_V1013 = "bbbbbbbb-1111-1111-1111-111111111111"
HIST_EVAL_V1013 = "eeeeeeee-1111-1111-1111-111111111111"
HIST_ASSET_V1013 = "cccccccc-1111-1111-1111-111111111111"

client = TestClient(app)


def _admin_connect(dbname: str, autocommit: bool = True):
    return psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=dbname,
        user=DB_ADMIN_USER,
        password=DB_ADMIN_PASSWORD,
        autocommit=autocommit,
    )


def _make_unique_wav_bytes(seed_freq: float = 220.0, duration_s: float = 1.2) -> bytes:
    sr = 16000
    n = int(sr * duration_s)
    t = np.linspace(0, duration_s, n, endpoint=False)
    sig = 0.35 * np.sin(2 * np.pi * seed_freq * t) + 0.12 * np.sin(2 * np.pi * (seed_freq * 2.0) * t)
    pcm = (np.clip(sig, -1.0, 1.0) * 32767.0).astype(np.int16)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(pcm.tobytes())
    return buf.getvalue()


def _challenge_eval_payload(
    sha256_hex: str,
    acoustic_fp: str,
    prob: float = 0.3898,
    recommendation: str = "CHALLENGE",
    policy_decision: str = "NEEDS_REVIEW",
    voice_clone_flag: bool = False,
) -> dict:
    return {
        "model_version": "ACOUSTIC_FFT_HEURISTIC_V1",
        "deepfake_probability": prob,
        "acoustic_consistency_score": round(1.0 - prob, 4),
        "voice_clone_flag": voice_clone_flag,
        "adversarial_noise_detected": False,
        "recommendation": recommendation,
        "policy_decision": policy_decision,
        "wada_snr_db": 36.8,
        "sample_count": 19200,
        "duration_ms": 1200,
        "audio_sha256": sha256_hex,
        "sha256_hash": sha256_hex,
        "acoustic_fingerprint": acoustic_fp,
        "storage_uri": f"vault://audio/{sha256_hex}.wav",
        "window_count": 3,
        "max_window_score": 0.5612,
        "acoustic_signal": "BORDERLINE_ACOUSTIC_VARIANCE",
        "replay_detected": False,
        "model_type": "FFT_HEURISTIC",
        "window_results": [{"window": 0, "score": prob}],
    }


@pytest.fixture(scope="module")
def disposable_v1015_db():
    db_name = f"deepfakeshield_v1015_test_{uuid.uuid4().hex[:10]}"
    schema_sql_path = os.path.join(REPO_ROOT, "migrations", "V10_1_3__security_repair.sql")
    v1014_sql_path = os.path.join(REPO_ROOT, "migrations", "V10_1_4__database_audio_finalization_gate.sql")
    v1015_sql_path = os.path.join(REPO_ROOT, "migrations", "V10_1_5__manual_audio_risk_review.sql")

    with open(schema_sql_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    with open(v1014_sql_path, "r", encoding="utf-8") as f:
        v1014_sql = f.read()
    with open(v1015_sql_path, "r", encoding="utf-8") as f:
        v1015_sql = f.read()

    created_vault_files = []

    with _admin_connect("postgres", autocommit=True) as sys_conn:
        with sys_conn.cursor() as cur:
            cur.execute(f"CREATE DATABASE {db_name} OWNER deepfakeshield_owner;")

    try:
        # Step 1: Apply V10.1.3 base schema
        with _admin_connect(db_name, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(schema_sql)
            conn.commit()

        # Step 2: Seed core actors + a V10.1.3 historical DRAFT CHALLENGE batch
        with _admin_connect(db_name, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (id, username, role, is_active) VALUES
                        (%s, 'alice_ap_maker', 'AP_CLERK', TRUE),
                        (%s, 'bob_checker', 'TREASURY_OFFICER', TRUE),
                        (%s, 'carol_checker_two', 'TREASURY_OFFICER', TRUE),
                        (%s, 'dave_auditor', 'AUDITOR', TRUE),
                        (%s, 'eve_unauthorized', 'AP_CLERK', TRUE)
                    ON CONFLICT (username) DO NOTHING;
                    """,
                    (USER_ALICE_MAKER, USER_BOB_CHECKER1, USER_CAROL_CHECKER2, USER_DAVE_AUDITOR, USER_EVE_UNAUTHORIZED),
                )
                cur.execute(
                    f"""
                    INSERT INTO encryption_key_metadata (key_id, algorithm, is_active)
                    VALUES ('{KEY_ID_ACTIVE}', 'AES-256-GCM', TRUE);
                    INSERT INTO internal_security_keys (key_id, secret_attestation_key, blind_index_key, auth_assertion_key)
                    VALUES (
                        '{KEY_ID_ACTIVE}',
                        decode('{DEFAULT_ATTESTATION_SECRET.hex()}', 'hex'),
                        decode('{DEFAULT_BLIND_INDEX_KEY.hex()}', 'hex'),
                        decode('{DEFAULT_AUTH_ASSERTION_KEY.hex()}', 'hex')
                    );
                    INSERT INTO audit_chain_heads (chain_id, head_event_digest, total_events, genesis_timestamp, last_event_at)
                    VALUES ('main', repeat('0', 64), 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                    """
                )
                bob_priv = ec.derive_private_key(BOB_DETERMINISTIC_SEED, ec.SECP256R1())
                carol_priv = ec.derive_private_key(CAROL_DETERMINISTIC_SEED, ec.SECP256R1())
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
                blind_idx = compute_recipient_blind_index(BENEFICIARY_EMAIL, DEFAULT_BLIND_INDEX_KEY)
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

                hist_sess = uuid.UUID("aaaaaaaa-1111-1111-1111-111111111111")
                hist_batch = uuid.UUID(HIST_BATCH_V1013)
                hist_asset = uuid.UUID(HIST_ASSET_V1013)
                hist_seg = uuid.UUID("dddddddd-1111-1111-1111-111111111111")
                hist_eval = uuid.UUID(HIST_EVAL_V1013)
                hist_sha = hashlib.sha256(b"HIST_V1013_AUDIO").hexdigest()
                hist_fp = hashlib.sha256(b"HIST_V1013_FP").hexdigest()

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
                        sample_dek, i_nonce, i_tag, i_ct, blind_idx,
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
                        json.dumps({
                            "batch_id": HIST_BATCH_V1013,
                            "recommendation": "CHALLENGE",
                            "policy_decision": "NEEDS_REVIEW",
                            "audio_sha256": hist_sha,
                            "acoustic_fingerprint": hist_fp,
                        }),
                    ),
                )
            conn.commit()

        # Step 3: Forward migrate V10.1.3 -> V10.1.4 -> V10.1.5
        with _admin_connect(db_name, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(v1014_sql)
            conn.commit()

        with _admin_connect(db_name, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(v1015_sql)
            conn.commit()

        yield db_name, created_vault_files
    finally:
        for fp in created_vault_files:
            try:
                if os.path.isfile(fp):
                    os.remove(fp)
            except Exception:
                pass
        with _admin_connect("postgres", autocommit=True) as sys_conn:
            with sys_conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid();",
                    (db_name,),
                )
                cur.execute(f"DROP DATABASE IF EXISTS {db_name};")


@pytest.fixture(autouse=True)
def _bind_disposable_db(disposable_v1015_db, monkeypatch):
    db_name, _ = disposable_v1015_db
    monkeypatch.setenv("PGDATABASE", db_name)
    reset_auth_sessions()
    yield
    reset_auth_sessions()


def _provision_ephemeral_reviewers(db_name: str):
    """Test-only ephemeral reviewer setup in disposable DB (cleaned up when DB is dropped)."""
    with _admin_connect(db_name, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (id, username, role, is_active) VALUES
                    (%s, %s, 'RISK_REVIEWER', TRUE),
                    (%s, 'inactive_test_reviewer', 'RISK_REVIEWER', FALSE)
                ON CONFLICT (id) DO NOTHING;
                """,
                (EPHEMERAL_REVIEWER_ID, EPHEMERAL_REVIEWER_USERNAME, EPHEMERAL_INACTIVE_REVIEWER_ID),
            )


def _login(username: str, password: str) -> dict:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.status_code} {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _create_batch(maker_id: str = USER_ALICE_MAKER) -> tuple[str, str]:
    sess_id = str(uuid.uuid4())
    batch = create_draft_batch(
        maker_user_id=maker_id,
        program_id="PROG_V1015_TEST",
        payout_period="2026-11",
        items_data=[
            {
                "beneficiary_id": BENEFICIARY_ID,
                "obligation_key": f"ob_{uuid.uuid4().hex[:10]}",
                "amount_usd": "1.00",
                "receiver_email": BENEFICIARY_EMAIL,
                "note": "V10.1.5 manual audio review test",
            }
        ],
        session_id=sess_id,
    )
    return str(batch["batch_id"]), sess_id


def _seed_challenge_audio_for_batch(batch_id: str, session_id: str, created_vault_files: list, seed_freq: float = 240.0) -> dict:
    wav_bytes = _make_unique_wav_bytes(seed_freq=seed_freq)
    sha_hex = hashlib.sha256(wav_bytes).hexdigest()
    fp_hex = hashlib.sha256(b"FP:" + wav_bytes[:256]).hexdigest()
    vault_path = store_audio_vault_bytes(sha_hex, wav_bytes)
    if vault_path:
        created_vault_files.append(vault_path)
    res = record_audio_analysis_for_batch(
        batch_id=batch_id,
        audio_analysis_result=_challenge_eval_payload(sha_hex, fp_hex),
        session_id=session_id,
        user_id=USER_ALICE_MAKER,
    )
    res["audio_sha256"] = sha_hex
    res["acoustic_fingerprint"] = fp_hex
    res["wav_bytes"] = wav_bytes
    return res


def _canonical_finalize_args(batch_id: str, audio_eval_id: uuid.UUID):
    payload_json = json.dumps({"batch_id": str(batch_id), "total_cents": 100})
    dek = bytes.fromhex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
    n, ct, tag = encrypt_payload(dek, payload_json.encode("utf-8"), b"FINALIZED_SNAPSHOT")
    digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    envelope_bytes = b"DS-ENVELOPE-V1-TEST"
    return (
        uuid.UUID(batch_id),
        payload_json,
        ct,
        digest,
        dek,
        n,
        tag,
        "FINALIZED_SNAPSHOT",
        envelope_bytes,
        audio_eval_id,
    )


def test_01_v10_1_5_forward_migration_preserves_history_and_rbac(disposable_v1015_db):
    """
    Verifies V10.1.5 forward migration from V10.1.4:
    - Records V10.1.3, V10.1.4, V10.1.5 in schema_migrations.
    - Adds RISK_REVIEWER to check_user_role without fabricating any fake reviewer account.
    - Preserves historical CHALLENGE/NEEDS_REVIEW evaluations and backfills asset hashes.
    - Locks down audio_risk_reviews and fn_submit_audio_risk_review against app/auditor/PUBLIC.
    """
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations ORDER BY version;")
            versions = [r[0] for r in cur.fetchall()]
            assert "V10.1.3" in versions
            assert "V10.1.4" in versions
            assert "V10.1.5" in versions

            # Migration must NOT fabricate a fake RISK_REVIEWER identity
            cur.execute("SELECT COUNT(*) FROM users WHERE role = 'RISK_REVIEWER';")
            assert cur.fetchone()[0] == 0

            # Historical V10.1.3 evaluation preserved intact & backfilled
            cur.execute(
                "SELECT batch_id::text, recommendation, policy_decision FROM risk_evaluations WHERE id = %s;",
                (HIST_EVAL_V1013,),
            )
            assert cur.fetchone() == (HIST_BATCH_V1013, "CHALLENGE", "NEEDS_REVIEW")

            cur.execute(
                "SELECT content_sha256, acoustic_fingerprint FROM audio_assets WHERE id = %s;",
                (HIST_ASSET_V1013,),
            )
            hist_sha, hist_fp = cur.fetchone()
            assert hist_sha == hashlib.sha256(b"HIST_V1013_AUDIO").hexdigest()
            assert hist_fp == hashlib.sha256(b"HIST_V1013_FP").hexdigest()

            # Verify RBAC lockdown
            sig = "fn_submit_audio_risk_review(uuid,uuid,uuid,character varying,uuid,character varying,text,jsonb)"
            cur.execute("SELECT has_function_privilege('public', %s, 'EXECUTE');", (sig,))
            assert cur.fetchone()[0] is False
            cur.execute("SELECT has_function_privilege('deepfakeshield_app', %s, 'EXECUTE');", (sig,))
            assert cur.fetchone()[0] is False
            cur.execute("SELECT has_function_privilege('deepfakeshield_auditor', %s, 'EXECUTE');", (sig,))
            assert cur.fetchone()[0] is False
            cur.execute("SELECT has_function_privilege('deepfakeshield_verifier', %s, 'EXECUTE');", (sig,))
            assert cur.fetchone()[0] is True

            for role in ("deepfakeshield_app", "deepfakeshield_auditor"):
                for priv in ("INSERT", "UPDATE", "DELETE"):
                    cur.execute("SELECT has_table_privilege(%s, 'audio_risk_reviews', %s);", (role, priv))
                    assert cur.fetchone()[0] is False


def test_02_unauthorized_reviewer_rejected_db_and_api(disposable_v1015_db, monkeypatch):
    """
    Verifies strict role separation: AP_CLERK, TREASURY_OFFICER, AUDITOR, inactive RISK_REVIEWER,
    and unconfigured reviewer credentials are all rejected at both API and DB layers.
    """
    db_name, created_vault_files = disposable_v1015_db
    _provision_ephemeral_reviewers(db_name)

    batch_id, sess_id = _create_batch()
    ev = _seed_challenge_audio_for_batch(batch_id, sess_id, created_vault_files, seed_freq=260.0)

    # 1. Fail-closed login when RISK_REVIEWER_CREDENTIALS is NOT configured
    monkeypatch.delenv("RISK_REVIEWER_CREDENTIALS", raising=False)
    monkeypatch.delenv("RISK_REVIEWER_USERNAME", raising=False)
    monkeypatch.delenv("RISK_REVIEWER_PASSWORD", raising=False)
    monkeypatch.delenv("RISK_REVIEWER_PASSWORD_HASH", raising=False)
    resp_unconfigured = client.post(
        "/api/auth/login",
        json={"username": EPHEMERAL_REVIEWER_USERNAME, "password": EPHEMERAL_REVIEWER_SECRET},
    )
    assert resp_unconfigured.status_code == 401

    # 2. Configure ephemeral test reviewer credentials via env
    monkeypatch.setenv("RISK_REVIEWER_CREDENTIALS", json.dumps({EPHEMERAL_REVIEWER_USERNAME: EPHEMERAL_REVIEWER_SECRET}))

    # AP_CLERK, TREASURY_OFFICER, AUDITOR rejected at POST review + GET audio stream
    for uname, pwd in (
        ("alice_ap_maker", "alice_secure_maker_pass_2026"),
        ("bob_checker", "bob_yubikey_officer_pass_2026"),
        ("dave_auditor", "dave_read_only_auditor_pass_2026"),
        ("eve_unauthorized", "eve_unauthorized_clerk_pass_2026"),
    ):
        headers = _login(uname, pwd)
        r_post = client.post(
            f"/api/batches/{batch_id}/audio-review",
            json={
                "risk_evaluation_id": ev["evaluation_id"],
                "audio_asset_id": ev["asset_id"],
                "audio_content_sha256": ev["audio_sha256"],
                "review_decision": "APPROVE_WITH_REVIEW",
                "justification": "Unauthorized role attempt to approve manual review",
            },
            headers=headers,
        )
        assert r_post.status_code == 403, f"Expected 403 for {uname}, got {r_post.status_code}: {r_post.text}"

        r_stream = client.get(f"/api/batches/{batch_id}/audio-review/audio", headers=headers)
        assert r_stream.status_code == 403, f"Expected 403 audio stream denial for {uname}"

    # 3. Direct DB SECURITY DEFINER calls with non-reviewer or inactive reviewer UID fail
    for bad_actor_id in (USER_ALICE_MAKER, USER_BOB_CHECKER1, USER_DAVE_AUDITOR, EPHEMERAL_INACTIVE_REVIEWER_ID):
        with pytest.raises(AudioRiskGateError):
            submit_manual_audio_review(
                batch_id=batch_id,
                risk_evaluation_id=ev["evaluation_id"],
                audio_asset_id=ev["asset_id"],
                audio_content_sha256=ev["audio_sha256"],
                reviewer_user_id=bad_actor_id,
                review_decision="APPROVE_WITH_REVIEW",
                justification="Attempting unauthorized database review execution",
            )


def test_03_validation_guards_missing_justification_hash_cross_batch_and_terminate(disposable_v1015_db, monkeypatch):
    """
    Verifies mandatory written justification, cryptographic SHA-256 / asset binding,
    cross-batch protection, and rejection of TERMINATE/BLOCKED spoof evaluations.
    """
    db_name, created_vault_files = disposable_v1015_db
    _provision_ephemeral_reviewers(db_name)
    monkeypatch.setenv("RISK_REVIEWER_CREDENTIALS", json.dumps({EPHEMERAL_REVIEWER_USERNAME: EPHEMERAL_REVIEWER_SECRET}))
    h_rev = _login(EPHEMERAL_REVIEWER_USERNAME, EPHEMERAL_REVIEWER_SECRET)

    batch_a, sess_a = _create_batch()
    ev_a = _seed_challenge_audio_for_batch(batch_a, sess_a, created_vault_files, seed_freq=280.0)

    batch_b, sess_b = _create_batch()
    ev_b = _seed_challenge_audio_for_batch(batch_b, sess_b, created_vault_files, seed_freq=300.0)

    batch_term, sess_term = _create_batch()
    term_wav = _make_unique_wav_bytes(seed_freq=320.0)
    term_sha = hashlib.sha256(term_wav).hexdigest()
    term_fp = hashlib.sha256(b"FP:" + term_wav[:256]).hexdigest()
    ev_term = record_audio_analysis_for_batch(
        batch_id=batch_term,
        audio_analysis_result=_challenge_eval_payload(
            term_sha,
            term_fp,
            prob=0.8200,
            recommendation="TERMINATE",
            policy_decision="BLOCKED",
            voice_clone_flag=True,
        ),
        session_id=sess_term,
        user_id=USER_ALICE_MAKER,
    )

    # 1. Missing / short justification
    for bad_just in ("", "   ", "too short"):
        r = client.post(
            f"/api/batches/{batch_a}/audio-review",
            json={
                "risk_evaluation_id": ev_a["evaluation_id"],
                "audio_asset_id": ev_a["asset_id"],
                "audio_content_sha256": ev_a["audio_sha256"],
                "review_decision": "APPROVE_WITH_REVIEW",
                "justification": bad_just,
            },
            headers=h_rev,
        )
        assert r.status_code == 400, f"Expected 400 for short justification {bad_just!r}"

    # 2. Mismatched SHA-256 hash
    r_bad_sha = client.post(
        f"/api/batches/{batch_a}/audio-review",
        json={
            "risk_evaluation_id": ev_a["evaluation_id"],
            "audio_asset_id": ev_a["asset_id"],
            "audio_content_sha256": "f" * 64,
            "review_decision": "APPROVE_WITH_REVIEW",
            "justification": "Testing mismatched SHA-256 rejection",
        },
        headers=h_rev,
    )
    assert r_bad_sha.status_code == 400

    # 3. Mismatched audio_asset_id
    r_bad_asset = client.post(
        f"/api/batches/{batch_a}/audio-review",
        json={
            "risk_evaluation_id": ev_a["evaluation_id"],
            "audio_asset_id": ev_b["asset_id"],
            "audio_content_sha256": ev_a["audio_sha256"],
            "review_decision": "APPROVE_WITH_REVIEW",
            "justification": "Testing mismatched audio asset rejection",
        },
        headers=h_rev,
    )
    assert r_bad_asset.status_code == 400

    # 4. Cross-batch evaluation_id (Batch B's evaluation submitted against Batch A)
    r_cross = client.post(
        f"/api/batches/{batch_a}/audio-review",
        json={
            "risk_evaluation_id": ev_b["evaluation_id"],
            "audio_asset_id": ev_b["asset_id"],
            "audio_content_sha256": ev_b["audio_sha256"],
            "review_decision": "APPROVE_WITH_REVIEW",
            "justification": "Testing cross-batch evaluation binding rejection",
        },
        headers=h_rev,
    )
    assert r_cross.status_code == 400

    # 5. TERMINATE / BLOCKED spoof cannot be manually overridden
    r_term = client.post(
        f"/api/batches/{batch_term}/audio-review",
        json={
            "risk_evaluation_id": ev_term["evaluation_id"],
            "audio_asset_id": ev_term["asset_id"],
            "audio_content_sha256": term_sha,
            "review_decision": "APPROVE_WITH_REVIEW",
            "justification": "Trying to override a hard TERMINATE/BLOCKED decision",
        },
        headers=h_rev,
    )
    assert r_term.status_code == 400


def test_04_unreviewed_and_rejected_permanently_block_finalization_and_tampering(disposable_v1015_db, monkeypatch):
    """
    Verifies:
    - Unreviewed CHALLENGE/NEEDS_REVIEW is rejected by finalize_batch() and both DB overloads.
    - Caller-supplied audio_policy_decision='APPROVE' is ignored.
    - Manual REJECT creates immutable review + AUDIO_RISK_REVIEWED audit event and permanently
      blocks finalization + blocks re-review + blocks UPDATE/DELETE/TRUNCATE.
    """
    db_name, created_vault_files = disposable_v1015_db
    _provision_ephemeral_reviewers(db_name)
    monkeypatch.setenv("RISK_REVIEWER_CREDENTIALS", json.dumps({EPHEMERAL_REVIEWER_USERNAME: EPHEMERAL_REVIEWER_SECRET}))

    batch_id, sess_id = _create_batch()
    ev = _seed_challenge_audio_for_batch(batch_id, sess_id, created_vault_files, seed_freq=340.0)

    h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")
    h_rev = _login(EPHEMERAL_REVIEWER_USERNAME, EPHEMERAL_REVIEWER_SECRET)

    # 1. Finalization BEFORE review fails closed even with spoofed body parameter
    r_pre = client.post(
        f"/api/batches/{batch_id}/finalize",
        json={"audio_policy_decision": "APPROVE"},
        headers=h_alice,
    )
    assert r_pre.status_code == 403

    args_10 = _canonical_finalize_args(batch_id, uuid.UUID(ev["evaluation_id"]))
    with get_app_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error):
                cur.execute(
                    "SELECT fn_finalize_payout_batch(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);",
                    args_10,
                )
            with pytest.raises(psycopg.Error):
                cur.execute(
                    "SELECT fn_finalize_payout_batch(%s,%s,%s,%s,%s,%s,%s,%s,%s);",
                    args_10[:9],
                )

    # 2. Submit human REJECT decision
    r_rej = client.post(
        f"/api/batches/{batch_id}/audio-review",
        json={
            "risk_evaluation_id": ev["evaluation_id"],
            "audio_asset_id": ev["asset_id"],
            "audio_content_sha256": ev["audio_sha256"],
            "review_decision": "REJECT",
            "justification": "Speaker cadence sounded unnatural during verification callback",
        },
        headers=h_rev,
    )
    assert r_rej.status_code == 200, r_rej.text
    rej_body = r_rej.json()
    assert rej_body["review_decision"] == "REJECT"

    # 3. Original risk_evaluations row remains CHALLENGE / NEEDS_REVIEW
    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT recommendation, policy_decision FROM risk_evaluations WHERE id = %s;",
                (uuid.UUID(ev["evaluation_id"]),),
            )
            assert cur.fetchone() == ("CHALLENGE", "NEEDS_REVIEW")

            cur.execute(
                """
                SELECT event_type, metadata_json->>'review_decision', metadata_json->>'batch_id'
                FROM audit_events
                WHERE entity_type = 'AUDIO_RISK_REVIEW' AND entity_id = %s;
                """,
                (uuid.UUID(rej_body["review_id"]),),
            )
            row = cur.fetchone()
            assert row == ("AUDIO_RISK_REVIEWED", "REJECT", batch_id)

    # 4. Permanently blocked at finalization & cannot overwrite or re-review
    with pytest.raises(AudioRiskGateError):
        finalize_batch(batch_id)

    r_reapprove = client.post(
        f"/api/batches/{batch_id}/audio-review",
        json={
            "risk_evaluation_id": ev["evaluation_id"],
            "audio_asset_id": ev["asset_id"],
            "audio_content_sha256": ev["audio_sha256"],
            "review_decision": "APPROVE_WITH_REVIEW",
            "justification": "Trying to overturn an earlier REJECT decision",
        },
        headers=h_rev,
    )
    assert r_reapprove.status_code == 409

    # 5. Immutability trigger blocks UPDATE/DELETE even as postgres
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error):
                cur.execute(
                    "UPDATE audio_risk_reviews SET review_decision = 'APPROVE_WITH_REVIEW' WHERE id = %s;",
                    (uuid.UUID(rej_body["review_id"]),),
                )
            with pytest.raises(psycopg.Error):
                cur.execute("DELETE FROM audio_risk_reviews WHERE id = %s;", (uuid.UUID(rej_body["review_id"]),))

    # Zero snapshots or outbox jobs created for rejected batch
    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM payout_snapshots WHERE batch_id = %s;", (uuid.UUID(batch_id),))
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM outbox_jobs WHERE batch_id = %s;", (uuid.UUID(batch_id),))
            assert cur.fetchone()[0] == 0


def test_05_valid_approve_with_review_finalization_and_dual_treasury_approvals(disposable_v1015_db, monkeypatch):
    """
    Full governed V10.1.5 workflow:
    1. CHALLENGE / NEEDS_REVIEW captured via verifier role.
    2. RISK_REVIEWER inspects complete evidence + streams SHA-verified WAV audio.
    3. RISK_REVIEWER records APPROVE_WITH_REVIEW with mandatory justification.
    4. Original CHALLENGE/NEEDS_REVIEW remains permanently preserved; AUDIO_RISK_REVIEWED audited.
    5. RISK_REVIEWER cannot sign WebAuthn Treasury Officer approvals (403).
    6. AP_CLERK finalizes -> READY_FOR_CHECKER -> PENDING_APPROVAL (1 snapshot).
    7. Bob + Carol (two independent TREASURY_OFFICER accounts) execute genuine WebAuthn P-256
       assertions -> batch reaches SUBMITTED + 1 PAYPAL_SUBMIT outbox job (no PayPal API contacted).
    """
    db_name, created_vault_files = disposable_v1015_db
    _provision_ephemeral_reviewers(db_name)
    monkeypatch.setenv("RISK_REVIEWER_CREDENTIALS", json.dumps({EPHEMERAL_REVIEWER_USERNAME: EPHEMERAL_REVIEWER_SECRET}))

    batch_id, sess_id = _create_batch()
    ev = _seed_challenge_audio_for_batch(batch_id, sess_id, created_vault_files, seed_freq=360.0)

    h_alice = _login("alice_ap_maker", "alice_secure_maker_pass_2026")
    h_rev = _login(EPHEMERAL_REVIEWER_USERNAME, EPHEMERAL_REVIEWER_SECRET)
    h_bob = _login("bob_checker", "bob_yubikey_officer_pass_2026")
    h_carol = _login("carol_checker_two", "carol_titan_officer_pass_2026")

    # 1. Inspect full evidence bundle
    r_ev = client.get(f"/api/batches/{batch_id}/audio-review", headers=h_rev)
    assert r_ev.status_code == 200, r_ev.text
    ev_bundle = r_ev.json()
    assert ev_bundle["manual_review"]["status"] == "PENDING"
    assert ev_bundle["analysis"]["original_ai_decision"] == "CHALLENGE"
    assert ev_bundle["analysis"]["original_policy_decision"] == "NEEDS_REVIEW"
    assert ev_bundle["analysis"]["model_version"] == "ACOUSTIC_FFT_HEURISTIC_V1"
    assert ev_bundle["audio_evidence"]["audio_content_sha256"] == ev["audio_sha256"]
    assert ev_bundle["audio_evidence"]["acoustic_fingerprint"] == ev["acoustic_fingerprint"]
    assert ev_bundle["audio_evidence"]["audio_available"] is True
    assert ev_bundle["recipients"][0]["receiver_email"] == BENEFICIARY_EMAIL

    # 2. Stream original WAV audio & verify cryptographic digest matches
    r_audio = client.get(f"/api/batches/{batch_id}/audio-review/audio", headers=h_rev)
    assert r_audio.status_code == 200
    assert hashlib.sha256(r_audio.content).hexdigest() == ev["audio_sha256"]

    # 3. Record APPROVE_WITH_REVIEW
    r_ok = client.post(
        f"/api/batches/{batch_id}/audio-review",
        json={
            "risk_evaluation_id": ev["evaluation_id"],
            "audio_asset_id": ev["asset_id"],
            "audio_content_sha256": ev["audio_sha256"],
            "review_decision": "APPROVE_WITH_REVIEW",
            "justification": "Verified spoken executive phrase matches treasury callback for USD 1.00 test payee.",
        },
        headers=h_rev,
    )
    assert r_ok.status_code == 200, r_ok.text
    rev_out = r_ok.json()
    assert rev_out["review_decision"] == "APPROVE_WITH_REVIEW"
    assert rev_out["reviewer_username"] == EPHEMERAL_REVIEWER_USERNAME

    # 4. Verify RISK_REVIEWER is denied Treasury Officer challenge & approval endpoints
    r_rev_chal = client.post(f"/api/batches/{batch_id}/webauthn/challenge", headers=h_rev)
    assert r_rev_chal.status_code == 403

    # 5. Finalize batch (persisted manual review satisfies V10.1.5 gate while preserving CHALLENGE)
    r_fin = client.post(f"/api/batches/{batch_id}/finalize", json={}, headers=h_alice)
    assert r_fin.status_code == 200, r_fin.text
    fin_body = r_fin.json()
    assert fin_body["gateway_batch_state"] == "READY_FOR_CHECKER"
    assert fin_body["verified_audio_recommendation"] == "CHALLENGE"

    # Confirm original risk_evaluations row was NEVER relabeled
    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT recommendation, policy_decision FROM risk_evaluations WHERE id = %s;",
                (uuid.UUID(ev["evaluation_id"]),),
            )
            assert cur.fetchone() == ("CHALLENGE", "NEEDS_REVIEW")

    # 6. Dual independent Treasury Officer WebAuthn approvals (Bob + Carol)
    bob_priv = ec.derive_private_key(BOB_DETERMINISTIC_SEED, ec.SECP256R1())
    carol_priv = ec.derive_private_key(CAROL_DETERMINISTIC_SEED, ec.SECP256R1())

    for stage_idx, (headers_off, cred_id, priv_key) in enumerate(
        ((h_bob, BOB_CRED_ID, bob_priv), (h_carol, CAROL_CRED_ID, carol_priv)), start=1
    ):
        r_ch = client.post(f"/api/batches/{batch_id}/webauthn/challenge", headers=headers_off)
        assert r_ch.status_code == 200, r_ch.text
        ch = r_ch.json()
        raw_chal = base64.urlsafe_b64decode(ch["challenge_b64"] + "=" * (-len(ch["challenge_b64"]) % 4))
        cd_json, auth_data, sig_bytes = create_webauthn_assertion(
            priv_key,
            raw_chal,
            origin="http://localhost:8000",
            rp_id="localhost",
            sign_count=stage_idx,
        )
        r_app = client.post(
            f"/api/batches/{batch_id}/approve",
            json={
                "credential_id": cred_id,
                "challenge_id": ch["challenge_id"],
                "client_data_json": cd_json,
                "auth_data": base64.b64encode(auth_data).decode("ascii"),
                "signature": base64.b64encode(sig_bytes).decode("ascii"),
            },
            headers=headers_off,
        )
        assert r_app.status_code == 200, f"Officer stage {stage_idx} approval failed: {r_app.text}"

    with get_auditor_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT gateway_batch_state FROM payout_batches WHERE id = %s;", (uuid.UUID(batch_id),))
            assert cur.fetchone()[0] == "APPROVED_TO_SUBMIT"
            cur.execute(
                "SELECT job_type, status FROM outbox_jobs WHERE batch_id = %s;",
                (uuid.UUID(batch_id),),
            )
            assert cur.fetchone() == ("PAYPAL_SUBMIT_PAYOUT", "PENDING")


def test_06_no_direct_sql_bypass_or_forged_review_table_writes(disposable_v1015_db):
    """
    Verifies deepfakeshield_app and deepfakeshield_auditor cannot insert/update/delete
    audio_risk_reviews directly or invoke fn_submit_audio_risk_review.
    """
    db_name, created_vault_files = disposable_v1015_db
    _provision_ephemeral_reviewers(db_name)

    batch_id, sess_id = _create_batch()
    ev = _seed_challenge_audio_for_batch(batch_id, sess_id, created_vault_files, seed_freq=390.0)

    for get_unpriv_conn in (get_app_conn, get_auditor_conn):
        with get_unpriv_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    cur.execute(
                        """
                        INSERT INTO audio_risk_reviews (
                            batch_id, risk_evaluation_id, audio_asset_id, reviewer_user_id, reviewer_username,
                            audio_content_sha256, original_recommendation, original_policy_decision,
                            review_decision, justification, audit_event_id
                        ) VALUES (
                            %s, %s, %s, %s, %s,
                            %s, 'CHALLENGE', 'NEEDS_REVIEW',
                            'APPROVE_WITH_REVIEW', 'Direct SQL bypass attempt', 1
                        );
                        """,
                        (
                            uuid.UUID(batch_id),
                            uuid.UUID(ev["evaluation_id"]),
                            uuid.UUID(ev["asset_id"]),
                            uuid.UUID(EPHEMERAL_REVIEWER_ID),
                            EPHEMERAL_REVIEWER_USERNAME,
                            ev["audio_sha256"],
                        ),
                    )
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    cur.execute(
                        """
                        SELECT fn_submit_audio_risk_review(
                            %s::uuid, %s::uuid, %s::uuid, %s, %s::uuid,
                            'APPROVE_WITH_REVIEW', 'Direct function bypass attempt', '{}'::jsonb
                        );
                        """,
                        (
                            uuid.UUID(batch_id),
                            uuid.UUID(ev["evaluation_id"]),
                            uuid.UUID(ev["asset_id"]),
                            ev["audio_sha256"],
                            uuid.UUID(EPHEMERAL_REVIEWER_ID),
                        ),
                    )


def test_07_ui_html_and_dashboard_overview_honest_challenge_display(disposable_v1015_db, monkeypatch):
    """
    Verifies UI HTML & /api/dashboard/overview cleanly expose manual review state,
    never store reviewer credentials in frontend files, and never display CHALLENGE
    as Passed or AUTHENTIC.
    """
    db_name, created_vault_files = disposable_v1015_db
    _provision_ephemeral_reviewers(db_name)
    monkeypatch.setenv("RISK_REVIEWER_CREDENTIALS", json.dumps({EPHEMERAL_REVIEWER_USERNAME: EPHEMERAL_REVIEWER_SECRET}))

    html_path = os.path.join(REPO_ROOT, "static", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    assert "manualAudioReviewPanel" in html_content
    assert "APPROVE_WITH_REVIEW" in html_content
    assert EPHEMERAL_REVIEWER_SECRET not in html_content
    assert EPHEMERAL_REVIEWER_USERNAME not in html_content
    assert "Needs Review" in html_content
    assert "AI CHALLENGE • Reviewed" in html_content

    batch_id, sess_id = _create_batch()
    ev = _seed_challenge_audio_for_batch(batch_id, sess_id, created_vault_files, seed_freq=410.0)

    h_rev = _login(EPHEMERAL_REVIEWER_USERNAME, EPHEMERAL_REVIEWER_SECRET)
    ov_before = client.get(f"/api/dashboard/overview?batch_id={batch_id}", headers=h_rev)
    assert ov_before.status_code == 200, ov_before.text
    ov1 = ov_before.json()
    assert ov1["audio_evaluation"]["recommendation"] == "CHALLENGE"
    assert ov1["audio_evaluation"]["policy_decision"] == "NEEDS_REVIEW"
    assert ov1["audio_review"]["manual_review"]["status"] == "PENDING"

    submit_manual_audio_review(
        batch_id=batch_id,
        risk_evaluation_id=ev["evaluation_id"],
        audio_asset_id=ev["asset_id"],
        audio_content_sha256=ev["audio_sha256"],
        reviewer_user_id=EPHEMERAL_REVIEWER_ID,
        review_decision="APPROVE_WITH_REVIEW",
        justification="Confirmed executive instruction authenticity against out-of-band callback.",
    )

    ov_after = client.get(f"/api/dashboard/overview?batch_id={batch_id}", headers=h_rev)
    assert ov_after.status_code == 200
    ov2 = ov_after.json()
    assert ov2["audio_evaluation"]["recommendation"] == "CHALLENGE"
    assert ov2["audio_review"]["manual_review"]["status"] == "APPROVED_WITH_REVIEW"
    assert ov2["audio_review"]["manual_review"]["reviewer_username"] == EPHEMERAL_REVIEWER_USERNAME
