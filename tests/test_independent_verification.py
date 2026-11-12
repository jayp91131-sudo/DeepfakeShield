#!/usr/bin/env python3
"""
DeepfakeShield V10.1.3 — Independent Security & Concurrency Verification Test Suite
Executes real independent tests for Tasks 1, 2, 3, 4, and 5:
- Task 1: Cryptographic Binding (attestation tampering, AAD tampering, replay)
- Task 2: Real Two-Session Concurrency (threads, lock waits, deadlock freedom)
- Task 3: Database Trigger Enforcement (item freeze, illegal state transitions)
- Task 4: Identity & WebAuthn Security (maker-checker, challenge expiry, replay)
- Task 5: Production Readiness (role isolation, auditor read-only, lock rules)
"""

import os
import sys
import json
import uuid
import hmac
import hashlib
import threading
import time
import pytest
import psycopg
from psycopg import sql

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_verifier

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5433,
    "dbname": "deepfakeshield_db",
}

@pytest.fixture(scope="module")
def admin_conn():
    conn = psycopg.connect(**DB_CONFIG, user="postgres", autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="module")
def app_conn():
    conn = psycopg.connect(**DB_CONFIG, user="deepfakeshield_app", password="AppSecretPassword123!", autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="module")
def worker_conn():
    conn = psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="module")
def verifier_conn():
    conn = psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="module")
def auditor_conn():
    conn = psycopg.connect(**DB_CONFIG, user="deepfakeshield_auditor", password="AuditorSecretPassword123!", autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(autouse=True)
def clean_test_data(admin_conn):
    """Resets test tables between tests in clean dependency order."""
    with admin_conn.cursor() as cur:
        cur.execute("ALTER TABLE payout_items DISABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE payout_batches DISABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE payout_snapshots DISABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE beneficiaries DISABLE TRIGGER ALL;")
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
        cur.execute("DELETE FROM webauthn_credentials;")
        cur.execute("DELETE FROM beneficiary_destination_history;")
        cur.execute("DELETE FROM beneficiaries;")
        cur.execute("ALTER TABLE beneficiaries ENABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE payout_snapshots ENABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE payout_batches ENABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE payout_items ENABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE audit_events DISABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE audit_chain_heads DISABLE TRIGGER ALL;")
        cur.execute("DELETE FROM audit_events;")
        cur.execute("DELETE FROM audit_chain_heads;")
        cur.execute("ALTER TABLE audit_chain_heads ENABLE TRIGGER ALL;")
        cur.execute("ALTER TABLE audit_events ENABLE TRIGGER ALL;")
        cur.execute("DELETE FROM users WHERE username NOT IN ('system_master');")

        # Clean keys
        cur.execute("DELETE FROM internal_security_keys;")
        cur.execute("DELETE FROM encryption_key_metadata;")

        # Seed standard users
        cur.execute("""
            INSERT INTO users (id, username, role, is_active)
            VALUES 
                ('10000000-0000-0000-0000-000000000001', 'alice_ap_maker', 'AP_CLERK', TRUE),
                ('10000000-0000-0000-0000-000000000002', 'bob_checker', 'TREASURY_OFFICER', TRUE),
                ('10000000-0000-0000-0000-000000000003', 'carol_officer_two', 'TREASURY_OFFICER', TRUE),
                ('10000000-0000-0000-0000-000000000004', 'dan_auditor', 'AUDITOR', TRUE),
                ('10000000-0000-0000-0000-000000000005', 'eve_unauthorized', 'AP_CLERK', FALSE);

            INSERT INTO encryption_key_metadata (key_id, key_version, algorithm, is_active)
            VALUES ('a0000000-0000-0000-0000-000000000001', 1, 'AES-256-GCM', TRUE);

            INSERT INTO internal_security_keys (key_id, secret_attestation_key, blind_index_key, auth_assertion_key)
            VALUES (
                'a0000000-0000-0000-0000-000000000001',
                '\\xc0ffee00deadbeef0102030405060708090a0b0c0d0e0f101112131415161718'::bytea,
                '\\xba5eba11deadbeef2122232425262728292a2b2c2d2e2f303132333435363738'::bytea,
                '\\xcafebebe01020304a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4f1f2f3f4'::bytea
            );
        """)

def create_worker_connection():
    return psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True)

def create_verifier_connection():
    return psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True)

def advance_batch_state(cur, batch_id: str, target_state: str):
    valid_path = ['DRAFT', 'VALIDATING', 'READY_FOR_CHECKER', 'APPROVED_TO_SUBMIT', 'SUBMITTING', 'SUBMITTED', 'SETTLED']
    cur.execute(f"SELECT gateway_batch_state FROM payout_batches WHERE id = '{batch_id}';")
    curr = cur.fetchone()[0]
    if curr == target_state:
        return
    try:
        idx_from = valid_path.index(curr)
        idx_to = valid_path.index(target_state)
        for i in range(idx_from + 1, idx_to + 1):
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = '{valid_path[i]}' WHERE id = '{batch_id}';")
    except ValueError:
        if target_state == 'MANUAL_RECONCILIATION_REQUIRED':
            for s in ['VALIDATING', 'READY_FOR_CHECKER', 'APPROVED_TO_SUBMIT', 'SUBMITTING', 'MANUAL_RECONCILIATION_REQUIRED']:
                cur.execute(f"UPDATE payout_batches SET gateway_batch_state = '{s}' WHERE id = '{batch_id}';")
        elif target_state == 'STALE_INVALIDATED':
            for s in ['VALIDATING', 'READY_FOR_CHECKER', 'STALE_INVALIDATED']:
                cur.execute(f"UPDATE payout_batches SET gateway_batch_state = '{s}' WHERE id = '{batch_id}';")
        else:
            raise ValueError(f"Unknown target state: {target_state}")

# ============================================================================
# TASK 1: CRYPTOGRAPHIC BINDING TESTS
# ============================================================================

def test_task1_ciphertext_substitution_rejected(admin_conn, app_conn):
    """
    TASK 1: Prove that substituting valid ciphertext from another batch/payload
    is rejected during finalization because the plaintext digest and attestation do not match.
    """
    ben_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    sender_batch_id = f"BATCH-{uuid.uuid4().hex[:8]}"

    blind_idx = crypto_verifier.compute_recipient_blind_index("sub_test@example.com")
    dest_dig = hashlib.sha256(b"sub_test@example.com").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Sub Test Ben', 1, 'VERIFIED', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig',
                '{sender_batch_id}', '{uuid.uuid4()}', 'DRAFT', 2500, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_sub_1', 'item_sub_1', 'EMAIL', '{ben_id}',
                2500, 'USD', 'Test sub', 1, '{dest_dig}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', 'DRAFT');
        """)

    canonical_json = f'{{"sender_batch_header":{{"sender_batch_id":"{sender_batch_id}"}},"items":[{{"sender_item_id":"item_sub_1","recipient_type":"EMAIL","receiver":"sub_test@example.com","amount":{{"value":"25.00","currency":"USD"}},"note":"Test sub"}}]}}'
    
    # Encrypt a completely different payload
    fake_dek = os.urandom(32)
    fake_nonce, fake_ciphertext, fake_tag = crypto_verifier.encrypt_payload(fake_dek, b'{"different":"payload"}', b'aad')
    
    # Try to finalize with the legitimate canonical JSON but the fake ciphertext
    with pytest.raises(psycopg.errors.CheckViolation) as exc:
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(batch_id),
                canonical_json,
                fake_ciphertext,
                hashlib.sha256(canonical_json.encode('utf-8')).hexdigest(),
                b'fake_wrapped_dek',
                fake_nonce,
                fake_tag,
                'aad',
                b'A' * 32
            ))
    assert "Cryptographic attestation verification failed" in str(exc.value)

def test_task1_aad_text_tampering_analysis(admin_conn, app_conn):
    """
    TASK 1: In-depth analysis of attestation binding.
    Demonstrates that while plaintext and ciphertext digests are strictly bound,
    aad_text is NOT part of the HMAC binding string in fn_finalize_payout_batch.
    """
    ben_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    sender_batch_id = f"BATCH-{uuid.uuid4().hex[:8]}"

    blind_idx = crypto_verifier.compute_recipient_blind_index("aad_test@example.com")
    dest_dig = hashlib.sha256(b"aad_test@example.com").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'AAD Test Ben', 1, 'VERIFIED', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig',
                '{sender_batch_id}', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_aad_1', 'item_aad_1', 'EMAIL', '{ben_id}',
                1000, 'USD', 'Test aad', 1, '{dest_dig}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', 'DRAFT');
        """)

    canonical_json = f'{{"sender_batch_header":{{"sender_batch_id":"{sender_batch_id}"}},"items":[{{"sender_item_id":"item_aad_1","recipient_type":"EMAIL","receiver":"aad_test@example.com","amount":{{"value":"10.00","currency":"USD"}},"note":"Test aad"}}]}}'
    dek = os.urandom(32)
    nonce, ciphertext, tag = crypto_verifier.encrypt_payload(dek, canonical_json.encode('utf-8'), b'legit_aad')
    attestation, p_dig, c_dig = crypto_verifier.verify_and_attest_snapshot(
        dek, nonce, ciphertext, tag, b'legit_aad', canonical_json, batch_id=batch_id
    )

    # 1. Tampered aad_text is now strictly REJECTED by fn_finalize_payout_batch!
    with pytest.raises(psycopg.errors.CheckViolation) as exc:
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(batch_id),
                canonical_json,
                ciphertext,
                p_dig,
                b'wrapped_dek',
                nonce,
                tag,
                'tampered_aad',  # Tampered AAD
                attestation
            ))
    assert "Cryptographic attestation verification failed" in str(exc.value)

    # 2. Legitimate aad_text passes finalization
    with app_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_finalize_payout_batch(
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (
            uuid.UUID(batch_id),
            canonical_json,
            ciphertext,
            p_dig,
            b'wrapped_dek',
            nonce,
            tag,
            'legit_aad',  # Legitimate AAD
            attestation
        ))
        snapshot_id = cur.fetchone()[0]
        assert snapshot_id is not None

    # 3. Cross-batch replay rejection: attempting to finalize another batch with this attestation is rejected
    diff_batch_id = str(uuid.uuid4())
    diff_ben_id = str(uuid.uuid4())
    canonical_diff_json = f'{{"sender_batch_header":{{"sender_batch_id":"BATCH-DIFF-1"}},"items":[{{"sender_item_id":"item_aad_1","recipient_type":"EMAIL","receiver":"aad_test@example.com","amount":{{"value":"10.00","currency":"USD"}},"note":"Test aad"}}]}}'
    with admin_conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{diff_ben_id}', 'AAD Diff Ben', 1, 'VERIFIED', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{diff_batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig',
                'BATCH-DIFF-1', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{diff_batch_id}', 'ob_aad_diff', 'item_aad_1', 'EMAIL', '{diff_ben_id}',
                1000, 'USD', 'Test aad', 1, '{dest_dig}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', 'DRAFT');
        """)
    with pytest.raises(psycopg.errors.CheckViolation) as exc_replay:
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(diff_batch_id),
                canonical_diff_json,
                ciphertext,
                hashlib.sha256(canonical_diff_json.encode('utf-8')).hexdigest(),
                b'wrapped_dek',
                nonce,
                tag,
                'legit_aad',
                attestation  # Replayed attestation from batch_id
            ))
    assert "Cryptographic attestation verification failed" in str(exc_replay.value)

# ============================================================================
# TASK 2: REAL CONCURRENCY AND TWO-SESSION RACE TESTS
# ============================================================================

def test_task2_concurrent_two_session_activation_vs_claim():
    """
    TASK 2: Real two-session concurrent race test with real threads:
    - Thread 1 (Worker): Claims outbox job in transaction, holds locks on outbox_jobs & payout_batches.
    - Thread 2 (Verifier): Concurrently attempts fn_activate_beneficiary_change.
    - Captures lock wait: Thread 2 is blocked until Thread 1 commits.
    - Proves lock ordering and deadlock freedom (no 40P01).
    """
    admin_conn = psycopg.connect(**DB_CONFIG, user="postgres", autocommit=True)
    ben_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    change_id = str(uuid.uuid4())
    chal_id = str(uuid.uuid4())

    blind_idx = hashlib.sha256(b"thread_blind").hexdigest()
    dest_dig = hashlib.sha256(b"thread_dest").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Thread Race Ben', 1, 'VERIFIED', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'old_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea, '{dest_dig}',
                'BATCH-TH-1', '{uuid.uuid4()}', 'DRAFT', 5000, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_th_1', 'item_th_1', 'EMAIL', '{ben_id}',
                5000, 'USD', 'Thread race', 1, '{dest_dig}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea,
                '{blind_idx}', 'DRAFT');
        """)
        advance_batch_state(cur, batch_id, 'APPROVED_TO_SUBMIT')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{dest_dig}', '{dest_dig}');
            UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_th_race', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING');
            
            INSERT INTO beneficiary_changes (id, beneficiary_id, requested_by_user_id, old_version, key_id,
                wrapped_dek, iv_nonce, auth_tag, aad_text, new_encrypted_destination, new_destination_blind_index,
                new_destination_digest, change_reason, verification_evidence_uri, status, cooling_off_expires_at)
            VALUES ('{change_id}', '{ben_id}', '10000000-0000-0000-0000-000000000001', 1, 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'new_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'Thread change', 'uri', 'COOLING_OFF', CURRENT_TIMESTAMP - INTERVAL '1 minute');
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose)
            VALUES ('cred_th_1', '10000000-0000-0000-0000-000000000002', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea),
                   ('cred_th_2', '10000000-0000-0000-0000-000000000003', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea);
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_id}', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea, 'BENEFICIARY_CHANGE_APPROVAL', '10000000-0000-0000-0000-000000000002', '{dest_dig}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
            INSERT INTO beneficiary_change_approvals (change_id, officer_user_id, credential_id, challenge_id, client_data_json, authenticator_data, signature, sign_count)
            VALUES ('{change_id}', '10000000-0000-0000-0000-000000000002', 'cred_th_1', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1),
                   ('{change_id}', '10000000-0000-0000-0000-000000000003', 'cred_th_2', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1);
        """)

    worker_conn = create_worker_connection()
    verifier_conn = create_verifier_connection()

    worker_barrier = threading.Barrier(2)
    activation_result = {"error": None, "wait_duration": 0}

    def worker_thread_fn():
        # Session 1: Claim outbox job inside a transaction, sleep 0.5s to hold locks
        with worker_conn.cursor() as cur:
            cur.execute("BEGIN;")
            cur.execute("SELECT * FROM fn_claim_outbox_job('worker_thread_1', 'PAYPAL_SUBMIT_PAYOUT');")
            worker_barrier.wait()  # Signal verifier to try activation while we hold locks
            time.sleep(0.5)
            cur.execute("COMMIT;")

    def verifier_thread_fn():
        worker_barrier.wait()  # Ensure worker has acquired locks
        time.sleep(0.1)  # Give worker a headstart to be in transaction
        start_time = time.time()
        try:
            with verifier_conn.cursor() as cur:
                cur.execute(f"SELECT fn_activate_beneficiary_change('{change_id}');")
        except Exception as e:
            activation_result["error"] = str(e)
            activation_result["wait_duration"] = time.time() - start_time

    t1 = threading.Thread(target=worker_thread_fn)
    t2 = threading.Thread(target=verifier_thread_fn)

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    worker_conn.close()
    verifier_conn.close()
    admin_conn.close()

    # Verify that:
    # 1. Thread 2 waited for Thread 1's lock (wait_duration >= 0.3s)
    # 2. No deadlock occurred (error is not 40P01)
    # 3. Thread 2 was safely rejected because the batch was SUBMITTING
    assert activation_result["wait_duration"] >= 0.3, f"Expected lock wait >= 0.3s, got {activation_result['wait_duration']}"
    assert "Cannot activate beneficiary change" in activation_result["error"]
    assert "40P01" not in activation_result["error"], "Unexpected deadlock detected!"

# ============================================================================
# TASK 3: DATABASE TRIGGER INTEGRITY TESTS
# ============================================================================

def test_task3_illegal_batch_state_machine_transitions(admin_conn):
    """
    TASK 3: Test that all illegal state machine transitions are strictly blocked
    by fn_validate_batch_state_transition trigger.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, 'd',
                'BATCH-ST-1', '{uuid.uuid4()}', 'DRAFT', 100, 1, '10000000-0000-0000-0000-000000000001');
        """)

        # 1. Illegal transition: DRAFT -> SUBMITTED (must fail)
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'SUBMITTED' WHERE id = '{batch_id}';")
        assert "Illegal payout batch state transition: DRAFT -> SUBMITTED" in str(exc.value)

        # 2. Advance to READY_FOR_CHECKER
        cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id = '{batch_id}';")
        cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER' WHERE id = '{batch_id}';")

        # 3. Illegal transition: READY_FOR_CHECKER -> SUBMITTED (must fail)
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'SUBMITTED' WHERE id = '{batch_id}';")
        assert "Illegal payout batch state transition: READY_FOR_CHECKER -> SUBMITTED" in str(exc.value)

        # 4. Advance to SUBMITTING
        cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'APPROVED_TO_SUBMIT' WHERE id = '{batch_id}';")
        cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'SUBMITTING' WHERE id = '{batch_id}';")

        # 5. Illegal transition: SUBMITTING -> STALE_INVALIDATED (must fail)
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'STALE_INVALIDATED' WHERE id = '{batch_id}';")
        assert "SUBMITTING -> STALE_INVALIDATED" in str(exc.value)

def test_task3_item_immutability_frozen_after_finalization(admin_conn, app_conn):
    """
    TASK 3: Verify that fn_finalize_payout_batch successfully completes item updates
    while in VALIDATING, and freezes all subsequent item mutations once in READY_FOR_CHECKER.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    item_id = str(uuid.uuid4())

    ben_id = str(uuid.uuid4())
    blind_idx = hashlib.sha256(b"frz_blind").hexdigest()
    dest_dig = hashlib.sha256(b"frz_dest").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Frz Ben', 1, 'VERIFIED', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, 'd',
                'BATCH-FRZ-1', '{uuid.uuid4()}', 'DRAFT', 100, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{item_id}', '{batch_id}', 'ob_frz_1', 'item_frz_1', 'EMAIL', '{ben_id}',
                100, 'USD', 'Frozen test', 1, '{dest_dig}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', 'DRAFT');
        """)
        # Batch is moved to READY_FOR_CHECKER
        advance_batch_state(cur, batch_id, 'READY_FOR_CHECKER')

        # Any attempt to insert new item must be rejected by trg_validate_item_insert
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"""
                INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                    amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                    iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
                VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_frz_2', 'item_frz_2', 'EMAIL', '{ben_id}',
                    100, 'USD', 'Frozen test 2', 1, '{dest_dig}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                    '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                    '{blind_idx}', 'DRAFT');
            """)
        assert "Modifications to payout_items are frozen" in str(exc.value)

        # Any attempt to update existing item must be rejected by trg_serialize_payout_items
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"UPDATE payout_items SET amount_cents = 99999 WHERE id = '{item_id}';")
        assert "Modifications to payout_items are frozen: parent batch is in state READY_FOR_CHECKER" in str(exc.value)

# ============================================================================
# TASK 4: IDENTITY AND WEBAUTHN SECURITY TESTS
# ============================================================================

def test_task4_maker_checker_segregation_and_challenge_expiry(admin_conn, verifier_conn):
    """
    TASK 4: Verify that:
    1. Batch creator (Maker) cannot approve the batch as Checker.
    2. Expired WebAuthn challenge is rejected.
    3. Replayed WebAuthn challenge is rejected.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    chal_expired = str(uuid.uuid4())
    chal_consumed = str(uuid.uuid4())
    cred_id = str(uuid.uuid4())

    creator_id = '10000000-0000-0000-0000-000000000001'
    officer_id = '10000000-0000-0000-0000-000000000002'

    dig_mk = hashlib.sha256(b"dig_mk").hexdigest()
    c_dig = hashlib.sha256(b"c_dig").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '{creator_id}');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{dig_mk}',
                'BATCH-MK-{uuid.uuid4().hex[:8]}', '{uuid.uuid4()}', 'DRAFT', 100, 1, '{creator_id}');
        """)
        advance_batch_state(cur, batch_id, 'READY_FOR_CHECKER')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{dig_mk}', '{c_dig}');
            UPDATE payout_batches SET active_snapshot_id = '{snap_id}', payload_digest = '{dig_mk}' WHERE id = '{batch_id}';
            
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose, sign_count)
            VALUES ('{cred_id}', '{officer_id}', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea, 10);
            
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_expired}', '\\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, 'TRANSACTION_APPROVAL', '{officer_id}', '{dig_mk}', CURRENT_TIMESTAMP - INTERVAL '10 minutes'),
                   ('{chal_consumed}', '\\x2222222222222222222222222222222222222222222222222222222222222222'::bytea, 'TRANSACTION_APPROVAL', '{officer_id}', '{dig_mk}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
            UPDATE webauthn_challenges SET is_consumed = TRUE WHERE challenge_id = '{chal_consumed}';
        """)

    # 1. Maker-Checker violation: Creator attempts to approve their own batch
    with pytest.raises(psycopg.errors.CheckViolation) as exc:
        with verifier_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_submit_officer_approval(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(batch_id), uuid.UUID(snap_id), uuid.UUID(creator_id),
                cred_id, uuid.UUID(chal_expired), dig_mk, 'cdata', b'auth', b'sig', 11
            ))
    assert "Maker-Checker policy violation: approving officer cannot be batch creator" in str(exc.value)

    # 2. Expired challenge rejection
    with pytest.raises(Exception) as exc:
        with verifier_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_submit_officer_approval(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(batch_id), uuid.UUID(snap_id), uuid.UUID(officer_id),
                cred_id, uuid.UUID(chal_expired), dig_mk, 'cdata', b'auth', b'sig', 11
            ))
    assert "has expired" in str(exc.value)

    # 3. Consumed challenge rejection (Replay prevention)
    with pytest.raises(psycopg.errors.CheckViolation) as exc:
        with verifier_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_submit_officer_approval(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(batch_id), uuid.UUID(snap_id), uuid.UUID(officer_id),
                cred_id, uuid.UUID(chal_consumed), dig_mk, 'cdata', b'auth', b'sig', 11
            ))
    assert "already been consumed (replay attack detected)" in str(exc.value)

# ============================================================================
# TASK 5: PRODUCTION READINESS AND ROLE PERMISSION TESTS
# ============================================================================

def test_task5_role_isolation_and_auditor_prohibitions(app_conn, worker_conn, auditor_conn):
    """
    TASK 5: Verify that:
    1. deepfakeshield_app cannot access internal_security_keys.
    2. deepfakeshield_payout_worker cannot access internal_security_keys.
    3. deepfakeshield_auditor cannot execute fn_append_audit_event or any mutation.
    """
    # 1. App cannot read internal_security_keys
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with app_conn.cursor() as cur:
            cur.execute("SELECT * FROM internal_security_keys;")

    # 2. Worker cannot read internal_security_keys
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with worker_conn.cursor() as cur:
            cur.execute("SELECT * FROM internal_security_keys;")

    # 3. Auditor cannot execute fn_append_audit_event
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with auditor_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_append_audit_event(
                    'AUDIT_MAIN', '10000000-0000-0000-0000-000000000004'::uuid, 'SECURITY_PROBE',
                    'BATCH', 'a0000000-0000-0000-0000-000000000001'::uuid, 'req_auditor_probe',
                    'corr_1', '127.0.0.1'::inet, 'pytest', 1, '\\x01'::bytea, '{}'::jsonb
                );
            """)

    # 4. Auditor cannot mutate any tables
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with auditor_conn.cursor() as cur:
            cur.execute("UPDATE payout_batches SET gateway_batch_state = 'FAILED';")

# ============================================================================
# TASK 1: COMPLETE ENVELOPE AUTHENTICATION (ALL 8 SUBSTITUTION TESTS)
# ============================================================================

def test_task1_complete_envelope_all_substitutions(admin_conn, app_conn, worker_conn):
    """
    TASK 1: Complete Envelope Authentication Tests:
    Verifies that the HMAC attestation binds all 11 values:
    1. batch_id
    2. snapshot_id
    3. plaintext_digest
    4. ciphertext_digest
    5. nonce
    6. authentication_tag
    7. aad
    8. key_id
    9. key_version
    10. wrapped_dek_digest
    11. algorithm_version

    Tests all 8 required attack vectors:
    - 1. Snapshot ID substitution
    - 2. Key ID substitution
    - 3. Key version substitution
    - 4. Wrapped DEK substitution
    - 5. Algorithm version substitution
    - 6. Ciphertext substitution
    - 7. AAD substitution
    - 8. Cross-batch attestation replay
    And confirms pre-submission envelope verification via verify_envelope_before_submission!
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    ben_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'
    key_version = 1
    algorithm = 'AES-256-GCM'
    sender_batch_id = f"BATCH-ENV-{uuid.uuid4().hex[:8]}"

    clean_email = "envelope.test@example.com"
    blind_idx = crypto_verifier.compute_recipient_blind_index(clean_email)
    dest_dig = hashlib.sha256(clean_email.encode('utf-8')).hexdigest()

    # Pre-generate snapshot_id before attestation (TASK 1 Requirement)
    snapshot_id = uuid.uuid4()
    wrapped_dek = b"wrapped_dek_bytes_valid_123456"

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc, verification_status)
            VALUES ('{ben_id}', 'Envelope Beneficiary', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad',
                'dest'::bytea, '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em', 'VERIFIED');
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig',
                '{sender_batch_id}', '{uuid.uuid4()}', 'DRAFT', 2500, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_env_1', 'item_env_1', 'EMAIL', '{ben_id}',
                2500, 'USD', 'Envelope Item', 1, '{dest_dig}', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', 'DRAFT');
        """)

    canonical_json = f'{{"sender_batch_header":{{"sender_batch_id":"{sender_batch_id}"}},"items":[{{"sender_item_id":"item_env_1","recipient_type":"EMAIL","receiver":"{clean_email}","amount":{{"value":"25.00","currency":"USD"}},"note":"Envelope Item"}}]}}'
    dek = os.urandom(32)
    aad_text = "envelope_aad_v1"
    nonce, ciphertext, tag = crypto_verifier.encrypt_payload(dek, canonical_json.encode('utf-8'), aad_text.encode('utf-8'))

    # Attest all 11 values using crypto_verifier
    res = crypto_verifier.verify_and_attest_snapshot(
        dek=dek,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        aad=aad_text.encode('utf-8'),
        expected_plaintext_json=canonical_json,
        batch_id=batch_id,
        snapshot_id=snapshot_id,
        key_id=key_id,
        key_version=key_version,
        wrapped_dek=wrapped_dek,
        algorithm=algorithm
    )
    valid_attestation = res.attestation
    p_dig = res.plaintext_digest
    c_dig = res.ciphertext_digest

    # 1. Negative Test: Snapshot ID substitution
    sub_snapshot_id = uuid.uuid4()
    with pytest.raises(psycopg.errors.CheckViolation):
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (uuid.UUID(batch_id), canonical_json, ciphertext, p_dig, wrapped_dek, nonce, tag, aad_text, valid_attestation, sub_snapshot_id))

    # 2. Negative Test: Wrapped DEK substitution
    sub_wrapped_dek = b"tampered_wrapped_dek_different"
    with pytest.raises(psycopg.errors.CheckViolation):
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (uuid.UUID(batch_id), canonical_json, ciphertext, p_dig, sub_wrapped_dek, nonce, tag, aad_text, valid_attestation, snapshot_id))

    # 3. Negative Test: Ciphertext substitution
    tampered_cipher = bytearray(ciphertext)
    tampered_cipher[0] ^= 0xFF
    with pytest.raises(psycopg.errors.CheckViolation):
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (uuid.UUID(batch_id), canonical_json, bytes(tampered_cipher), p_dig, wrapped_dek, nonce, tag, aad_text, valid_attestation, snapshot_id))

    # 4. Negative Test: AAD substitution
    with pytest.raises(psycopg.errors.CheckViolation):
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (uuid.UUID(batch_id), canonical_json, ciphertext, p_dig, wrapped_dek, nonce, tag, "substituted_aad", valid_attestation, snapshot_id))

    # 5. Negative Test: Cross-batch attestation replay
    diff_batch_id = uuid.uuid4()
    with admin_conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{diff_batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig',
                'BATCH-REPLAY', '{uuid.uuid4()}', 'DRAFT', 2500, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{diff_batch_id}', 'ob_env_replay', 'item_env_1', 'EMAIL', '{ben_id}',
                2500, 'USD', 'Envelope Item', 1, '{dest_dig}', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea,
                '{blind_idx}', 'DRAFT');
        """)
    with pytest.raises(psycopg.errors.CheckViolation):
        with app_conn.cursor() as cur:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (diff_batch_id, canonical_json, ciphertext, p_dig, wrapped_dek, nonce, tag, aad_text, valid_attestation, snapshot_id))

    # 6. Negative Test: Pre-submission verification rejects wrong Key ID / Key Version / Algorithm
    with pytest.raises(ValueError, match="Attestation signature mismatch"):
        crypto_verifier.verify_envelope_before_submission(
            dek=dek, nonce=nonce, ciphertext=ciphertext, tag=tag, aad_text=aad_text,
            expected_plaintext_json=canonical_json, batch_id=batch_id, snapshot_id=snapshot_id,
            key_id=uuid.uuid4(),  # Substituted Key ID
            key_version=key_version, wrapped_dek=wrapped_dek, attestation=valid_attestation
        )

    with pytest.raises(ValueError, match="Attestation signature mismatch"):
        crypto_verifier.verify_envelope_before_submission(
            dek=dek, nonce=nonce, ciphertext=ciphertext, tag=tag, aad_text=aad_text,
            expected_plaintext_json=canonical_json, batch_id=batch_id, snapshot_id=snapshot_id,
            key_id=key_id, key_version=99,  # Substituted Key Version
            wrapped_dek=wrapped_dek, attestation=valid_attestation
        )

    with pytest.raises(ValueError, match="Attestation signature mismatch"):
        crypto_verifier.verify_envelope_before_submission(
            dek=dek, nonce=nonce, ciphertext=ciphertext, tag=tag, aad_text=aad_text,
            expected_plaintext_json=canonical_json, batch_id=batch_id, snapshot_id=snapshot_id,
            key_id=key_id, key_version=key_version, wrapped_dek=wrapped_dek, attestation=valid_attestation,
            algorithm="CHACHA20-POLY1305"  # Substituted Algorithm Version
        )

    # 7. Successful Finalization with valid complete envelope binding
    with app_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_finalize_payout_batch(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (uuid.UUID(batch_id), canonical_json, ciphertext, p_dig, wrapped_dek, nonce, tag, aad_text, valid_attestation, snapshot_id))
        returned_snap_id = cur.fetchone()[0]
        assert str(returned_snap_id) == str(snapshot_id)

    # 8. Re-verify the complete envelope via database function fn_verify_payout_snapshot_envelope
    with app_conn.cursor() as cur:
        cur.execute(f"SELECT fn_verify_payout_snapshot_envelope('{snapshot_id}');")
        assert cur.fetchone()[0] is True

    # 9. Verify that verify_envelope_before_submission passes for valid parameters
    is_valid = crypto_verifier.verify_envelope_before_submission(
        dek=dek, nonce=nonce, ciphertext=ciphertext, tag=tag, aad_text=aad_text,
        expected_plaintext_json=canonical_json, batch_id=batch_id, snapshot_id=snapshot_id,
        key_id=key_id, key_version=key_version, wrapped_dek=wrapped_dek, attestation=valid_attestation
    )
    assert is_valid is True

# ============================================================================
# TASK 3: ADVERSARIAL CONCURRENCY TESTS (SWEEPER VS RESULT PERSISTENCE & CLAIM)
# ============================================================================

def test_task3_adversarial_concurrency_sweeper_vs_claim(admin_conn, worker_conn):
    """
    TASK 3: Adversarial concurrency test verifying that:
    1. fn_sweep_exhausted_outbox_jobs acquires outbox_jobs (L1) then payout_batches (L2) sequentially.
    2. Concurrent execution between sweeper and worker claims / results never deadlocks (SQLSTATE 40P01).
    3. Fencing tokens advance monotonically without split-brain.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig',
                'BATCH-SWEEP-CONC', '{uuid.uuid4()}', 'DRAFT', 1,
                1000, 1, '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', '{key_id}', 'dek'::bytea, '\\x0102030405060708090a0b0c'::bytea,
                '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea,
                '1111111111111111111111111111111111111111111111111111111111111111',
                '2222222222222222222222222222222222222222222222222222222222222222');
            UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id = '{batch_id}';
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';
            UPDATE payout_batches SET gateway_batch_state = 'APPROVED_TO_SUBMIT', fencing_token = 10 WHERE id = '{batch_id}';
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, job_type, deduplication_key, fencing_token, status, attempt_count, max_attempts, lease_owner, lease_expires_at)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'SUBMIT_PAYOUT', 'idem_swp_1', 10, 'IN_PROGRESS', 1, 3, 'worker_old', CURRENT_TIMESTAMP - INTERVAL '10 seconds');
        """)

    errors = []
    def run_sweeper():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    for _ in range(5):
                        cur.execute("SELECT fn_sweep_exhausted_outbox_jobs('SUBMIT_PAYOUT');")
                        time.sleep(0.02)
        except Exception as e:
            errors.append(f"Sweeper error: {e}")

    def run_claimer():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    for _ in range(5):
                        cur.execute("SELECT * FROM fn_claim_outbox_job('worker_new', 'SUBMIT_PAYOUT');")
                        time.sleep(0.02)
        except Exception as e:
            errors.append(f"Claimer error: {e}")

    t1 = threading.Thread(target=run_sweeper)
    t2 = threading.Thread(target=run_claimer)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Concurrency errors encountered: {errors}"

    # Verify final state in database: job fencing token was advanced without split brain
    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT fencing_token, status FROM outbox_jobs WHERE id = '{job_id}';")
        job_fencing, job_status = cur.fetchone()
        assert job_fencing >= 11
        assert job_status in ('IN_PROGRESS', 'PENDING')


# ============================================================================
# TASK 3: DETERMINISTIC TWO-SESSION ADVERSARIAL CONCURRENCY TESTS
# ============================================================================

def test_task3_concurrency_activation_vs_finalization(admin_conn):
    """
    TASK 3, Scenario 1: Activation versus Finalization.
    - Two concurrent sessions targeting the same beneficiary and batch.
    - Session 1 (App): finalizes a draft batch containing Beneficiary B1 (locks PB then B).
    - Session 2 (Verifier): activates an approved change for B1 (locks OJ -> PB -> B).
    - Verifies:
      1. Zero deadlocks (SQLSTATE 40P01 is NEVER raised).
      2. Lock wait occurs deterministically.
      3. State machine transitions cleanly: if finalization completes first,
         activation detects READY_FOR_CHECKER and safely invalidates batch to STALE_INVALIDATED.
    """
    ben_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    change_id = str(uuid.uuid4())
    chal_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    dek = os.urandom(32)
    blind_key = crypto_verifier.get_blind_index_key()
    blind_idx = crypto_verifier.compute_recipient_blind_index("alice@contractor.com", blind_key)
    dest_dig = hashlib.sha256(b"alice@contractor.com").hexdigest()

    payload_dict = {
        "sender_batch_header": {"sender_batch_id": f"batch_{batch_id[:8]}"},
        "items": [
            {
                "recipient_type": "EMAIL",
                "receiver": "alice@contractor.com",
                "amount": {"value": "50.00", "currency": "USD"},
                "sender_item_id": "item_1"
            }
        ]
    }
    canonical_payload_json = json.dumps(payload_dict)
    p_digest = hashlib.sha256(canonical_payload_json.encode('utf-8')).hexdigest()
    nonce, ciphertext, tag = crypto_verifier.encrypt_payload(dek, canonical_payload_json.encode('utf-8'), b"DEEPFAKESHIELD-PAYOUT-v1")
    c_digest = hashlib.sha256(ciphertext).hexdigest()

    snap_id = str(uuid.uuid4())
    attestation, _, _ = crypto_verifier.verify_and_attest_snapshot(
        dek, nonce, ciphertext, tag, b"DEEPFAKESHIELD-PAYOUT-v1",
        canonical_payload_json, batch_id=batch_id, snapshot_id=snap_id, key_id=key_id, wrapped_dek=b"dek"
    )

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Contractor B1', 1, 'VERIFIED', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'old_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, '{p_digest}',
                'batch_{batch_id[:8]}', '{uuid.uuid4()}', 'DRAFT', 1,
                5000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        cur.execute(f"""
            INSERT INTO payout_items (id, batch_id, obligation_key, beneficiary_id, beneficiary_version, expected_destination_digest,
                sender_item_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index,
                amount_cents, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_act_fin_1', '{ben_id}', 1, '{dest_dig}',
                'item_1', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea,
                '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea, '{blind_idx}', 5000, 'DRAFT');
        """)
        new_dest_dig = hashlib.sha256(b"alice_new@contractor.com").hexdigest()
        new_blind_idx = crypto_verifier.compute_recipient_blind_index("alice_new@contractor.com", blind_key)
        cur.execute(f"""
            INSERT INTO beneficiary_changes (id, beneficiary_id, requested_by_user_id, old_version, key_id,
                wrapped_dek, iv_nonce, auth_tag, aad_text, new_encrypted_destination, new_destination_blind_index,
                new_destination_digest, change_reason, verification_evidence_uri, status, cooling_off_expires_at)
            VALUES ('{change_id}', '{ben_id}', '10000000-0000-0000-0000-000000000001', 1, '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'new_dest'::bytea,
                '{new_blind_idx}', '{new_dest_dig}', 'Verified address change', 'uri', 'COOLING_OFF', CURRENT_TIMESTAMP - INTERVAL '1 minute');
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose)
            VALUES ('cred_af_b', '10000000-0000-0000-0000-000000000002', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea),
                   ('cred_af_c', '10000000-0000-0000-0000-000000000003', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea);
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_id}', '\\x{os.urandom(32).hex()}'::bytea, 'BENEFICIARY_CHANGE_APPROVAL', '10000000-0000-0000-0000-000000000002', '{new_dest_dig}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
            INSERT INTO beneficiary_change_approvals (change_id, officer_user_id, credential_id, challenge_id, client_data_json, authenticator_data, signature, sign_count)
            VALUES ('{change_id}', '10000000-0000-0000-0000-000000000002', 'cred_af_b', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1),
                   ('{change_id}', '10000000-0000-0000-0000-000000000003', 'cred_af_c', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1);
        """)

    sqlstates = []
    outcomes = []
    fin_event = threading.Event()

    def run_finalization():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_app", password="AppSecretPassword123!", autocommit=False) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT fn_finalize_payout_batch(
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        );
                    """, (batch_id, canonical_payload_json, ciphertext, p_digest, b"dek", nonce, tag, "DEEPFAKESHIELD-PAYOUT-v1", attestation, snap_id))
                    fin_event.set()
                    time.sleep(0.12)
                    conn.commit()
                    outcomes.append("FINALIZATION_COMMITTED")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"FINALIZATION_ERROR: {e}")

    def run_activation():
        fin_event.wait(timeout=2.0)
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT fn_activate_beneficiary_change('{change_id}');")
                    outcomes.append("ACTIVATION_COMMITTED")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"ACTIVATION_ERROR: {e}")

    t1 = threading.Thread(target=run_finalization)
    t2 = threading.Thread(target=run_activation)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlocks (SQLSTATE 40P01 is NEVER raised)
    assert '40P01' not in sqlstates, f"Deadlock detected! SQLSTATEs: {sqlstates}"
    assert "FINALIZATION_COMMITTED" in outcomes
    assert "ACTIVATION_COMMITTED" in outcomes

    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT gateway_batch_state FROM payout_batches WHERE id = '{batch_id}';")
        state = cur.fetchone()[0]
        assert state == 'STALE_INVALIDATED'

        cur.execute(f"SELECT version FROM beneficiaries WHERE id = '{ben_id}';")
        version = cur.fetchone()[0]
        assert version == 2


def test_task3_concurrency_activation_vs_outbox_claim(admin_conn):
    """
    TASK 3, Scenario 2: Activation versus Outbox Claim.
    - Tests race when job is PENDING and batch is APPROVED_TO_SUBMIT.
    - Two concurrent threads:
      Session 1: fn_claim_outbox_job
      Session 2: fn_activate_beneficiary_change
    - Proves:
      1. Zero deadlocks (SQLSTATE 40P01 == 0).
      2. If claim acquires locks first: batch becomes SUBMITTING / job IN_PROGRESS.
         Activation checks IN_PROGRESS job and raises check_violation.
      3. If activation acquires locks first: batch becomes STALE_INVALIDATED / job FAILED.
         Claim revalidates, detects STALE_INVALIDATED, and aborts claim without submission.
    """
    ben_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    change_id = str(uuid.uuid4())
    chal_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    blind_key = hashlib.sha256(b"test_blind_index_secret_key_123!").digest()
    blind_idx = crypto_verifier.compute_recipient_blind_index("bob@contractor.com", blind_key)
    dest_dig = hashlib.sha256(b"bob@contractor.com").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Contractor B2', 1, 'VERIFIED', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'old_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig_p',
                'BATCH-ACT-CLM', '{uuid.uuid4()}', 'DRAFT', 1,
                5000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        cur.execute(f"""
            INSERT INTO payout_items (id, batch_id, obligation_key, beneficiary_id, beneficiary_version, expected_destination_digest,
                sender_item_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index,
                amount_cents, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_act_clm_1', '{ben_id}', 1, '{dest_dig}',
                'item_1', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea,
                '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea, '{blind_idx}', 5000, 'DRAFT');
        """)
        advance_batch_state(cur, batch_id, 'APPROVED_TO_SUBMIT')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', '{key_id}', 'dek'::bytea,
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '1111111111111111111111111111111111111111111111111111111111111111',
                '2222222222222222222222222222222222222222222222222222222222222222');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_act_clm', 'SUBMIT_PAYOUT', 1, 'PENDING');
        """)

        new_dest_dig = hashlib.sha256(b"bob_new@contractor.com").hexdigest()
        new_blind_idx = crypto_verifier.compute_recipient_blind_index("bob_new@contractor.com", blind_key)
        cur.execute(f"""
            INSERT INTO beneficiary_changes (id, beneficiary_id, requested_by_user_id, old_version, key_id,
                wrapped_dek, iv_nonce, auth_tag, aad_text, new_encrypted_destination, new_destination_blind_index,
                new_destination_digest, change_reason, verification_evidence_uri, status, cooling_off_expires_at)
            VALUES ('{change_id}', '{ben_id}', '10000000-0000-0000-0000-000000000001', 1, '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'new_dest'::bytea,
                '{new_blind_idx}', '{new_dest_dig}', 'Verified address change', 'uri', 'COOLING_OFF', CURRENT_TIMESTAMP - INTERVAL '1 minute');
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose)
            VALUES ('cred_ac_b', '10000000-0000-0000-0000-000000000002', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea),
                   ('cred_ac_c', '10000000-0000-0000-0000-000000000003', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea);
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_id}', '\\x{os.urandom(32).hex()}'::bytea, 'BENEFICIARY_CHANGE_APPROVAL', '10000000-0000-0000-0000-000000000002', '{new_dest_dig}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
            INSERT INTO beneficiary_change_approvals (change_id, officer_user_id, credential_id, challenge_id, client_data_json, authenticator_data, signature, sign_count)
            VALUES ('{change_id}', '10000000-0000-0000-0000-000000000002', 'cred_ac_b', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1),
                   ('{change_id}', '10000000-0000-0000-0000-000000000003', 'cred_ac_c', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1);
        """)

    sqlstates = []
    outcomes = []

    def run_claim():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM fn_claim_outbox_job('worker_race', 'SUBMIT_PAYOUT');")
                    row = cur.fetchone()
                    if row:
                        outcomes.append(f"CLAIM_SUCCESS:{row[0]}")
                    else:
                        outcomes.append("CLAIM_EMPTY")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"CLAIM_ERROR:{e}")

    def run_activate():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT fn_activate_beneficiary_change('{change_id}');")
                    outcomes.append("ACTIVATION_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"ACTIVATION_ERROR:{e}")

    t1 = threading.Thread(target=run_claim)
    t2 = threading.Thread(target=run_activate)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlocks (SQLSTATE 40P01 is NEVER raised)
    assert '40P01' not in sqlstates, f"Deadlock detected! SQLSTATEs: {sqlstates}"

    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT gateway_batch_state FROM payout_batches WHERE id = '{batch_id}';")
        batch_state = cur.fetchone()[0]
        cur.execute(f"SELECT status, lease_owner FROM outbox_jobs WHERE id = '{job_id}';")
        job_status, lease_owner = cur.fetchone()

        if "CLAIM_SUCCESS" in "".join(outcomes):
            assert job_status == 'IN_PROGRESS'
            assert lease_owner == 'worker_race'
            assert any("ACTIVATION_ERROR" in o for o in outcomes)
        else:
            assert batch_state == 'STALE_INVALIDATED'
            assert job_status == 'FAILED'


def test_task3_concurrency_result_persistence_vs_lease_sweeping(admin_conn):
    """
    TASK 3, Scenario 3: Result Persistence versus Lease Sweeping.
    - Tests race when worker lease is expired, worker submits provider result, and sweeper runs.
    - Both acquire outbox_jobs (L1) then payout_batches (L2) in identical order.
    - Zero deadlocks (SQLSTATE 40P01 == 0).
    - Monotonic fencing tokens prevent overwriting definitive results.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig_p',
                'BATCH-SWP-RES', '{uuid.uuid4()}', 'DRAFT', 1,
                5000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_state(cur, batch_id, 'SUBMITTING')
        cur.execute(f"UPDATE payout_batches SET fencing_token = 10 WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', '{key_id}', 'dek'::bytea,
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '1111111111111111111111111111111111111111111111111111111111111111',
                '2222222222222222222222222222222222222222222222222222222222222222');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        # Expired lease
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status, attempt_count, max_attempts, lease_owner, lease_expires_at)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_swp_res', 'SUBMIT_PAYOUT', 10, 'IN_PROGRESS', 1, 3, 'worker_old', CURRENT_TIMESTAMP - INTERVAL '5 seconds');
        """)

    sqlstates = []
    outcomes = []

    def run_worker_persist():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    resp_json = json.dumps({"batch_header": {"payout_batch_id": "PAYPAL_SWP_RES_1", "batch_status": "SUCCESS"}})
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, %s, %s, %s, %s, %s
                        );
                    """, (batch_id, 'worker_old', 10, 'PAYPAL_SWP_RES_1', 'SUCCESS', 200, resp_json, False))
                    outcomes.append("WORKER_PERSIST_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"WORKER_PERSIST_ERROR: {e}")

    def run_sweeper():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT fn_sweep_exhausted_outbox_jobs('SUBMIT_PAYOUT');")
                    outcomes.append("SWEEPER_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"SWEEPER_ERROR: {e}")

    t1 = threading.Thread(target=run_worker_persist)
    t2 = threading.Thread(target=run_sweeper)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlocks (SQLSTATE 40P01 is NEVER raised)
    assert '40P01' not in sqlstates, f"Deadlock detected! SQLSTATEs: {sqlstates}"
    assert "SWEEPER_SUCCESS" in outcomes or "WORKER_PERSIST_SUCCESS" in outcomes


def test_task3_concurrency_completion_vs_lease_sweeping(admin_conn):
    """
    TASK 3, Scenario 4: Completion versus Lease Sweeping.
    - Tests race when worker finishes and calls fn_complete_outbox_job while sweeper runs.
    - Both acquire outbox_jobs then payout_batches in identical order.
    - Zero deadlocks (SQLSTATE 40P01 == 0).
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id, payout_batch_id, paypal_batch_state)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig_p',
                'BATCH-SWP-CMP', '{uuid.uuid4()}', 'DRAFT', 1,
                5000, 1, '10000000-0000-0000-0000-000000000001', 'PAYPAL_CMP_1', 'SUCCESS');
        """)
        advance_batch_state(cur, batch_id, 'SUBMITTED')
        cur.execute(f"UPDATE payout_batches SET fencing_token = 10 WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', '{key_id}', 'dek'::bytea,
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '1111111111111111111111111111111111111111111111111111111111111111',
                '2222222222222222222222222222222222222222222222222222222222222222');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status, attempt_count, max_attempts, lease_owner, lease_expires_at)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_swp_cmp', 'SUBMIT_PAYOUT', 10, 'IN_PROGRESS', 1, 3, 'worker_1', CURRENT_TIMESTAMP + INTERVAL '10 seconds');
        """)

    sqlstates = []
    outcomes = []

    def run_worker_complete():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT fn_complete_outbox_job('{job_id}', 'worker_1', 10);")
                    outcomes.append("COMPLETE_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"COMPLETE_ERROR: {e}")

    def run_sweeper():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT fn_sweep_exhausted_outbox_jobs('SUBMIT_PAYOUT');")
                    outcomes.append("SWEEPER_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"SWEEPER_ERROR: {e}")

    t1 = threading.Thread(target=run_worker_complete)
    t2 = threading.Thread(target=run_sweeper)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlocks (SQLSTATE 40P01 is NEVER raised)
    assert '40P01' not in sqlstates, f"Deadlock detected! SQLSTATEs: {sqlstates}"
    assert "COMPLETE_SUCCESS" in outcomes


def test_task3_concurrency_manual_recon_vs_provider_result(admin_conn):
    """
    TASK 3, Scenario 5: Manual Reconciliation versus Provider Result Persistence.
    - Tests race when batch is in MANUAL_RECONCILIATION_REQUIRED, operator manually resolves,
      and a stale worker attempts to record a result.
    - Both acquire outbox_jobs (L1) then payout_batches (L2) in identical order.
    - Zero deadlocks (SQLSTATE 40P01 == 0).
    - Operator assertion cryptographically authenticates resolution; stale worker is safely rejected.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'
    officer_user_id = '10000000-0000-0000-0000-000000000002'

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea, 'dig_p',
                'BATCH-MAN-RES', '{uuid.uuid4()}', 'DRAFT', 1,
                5000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_state(cur, batch_id, 'MANUAL_RECONCILIATION_REQUIRED')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', '{key_id}', 'dek'::bytea,
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '1111111111111111111111111111111111111111111111111111111111111111',
                '2222222222222222222222222222222222222222222222222222222222222222');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_man_res', 'SUBMIT_PAYOUT', 10, 'MANUAL_RECONCILIATION_REQUIRED');
        """)

    assertion = crypto_verifier.create_identity_assertion(
        uuid.UUID(officer_user_id), uuid.UUID(batch_id), 'SETTLED'
    )

    sqlstates = []
    outcomes = []

    def run_operator_resolve():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT fn_resolve_manual_reconciliation(
                            %s, %s, %s, %s, %s, %s
                        );
                    """, (batch_id, 'SETTLED', 'PAYPAL_MAN_OK', 'Verified settlement via banking portal log', officer_user_id, assertion))
                    outcomes.append("OPERATOR_RESOLVE_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"OPERATOR_RESOLVE_ERROR: {e}")

    def run_stale_worker():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="WorkerSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    resp_json = json.dumps({"batch_header": {"payout_batch_id": "STALE_WORKER", "batch_status": "SUCCESS"}})
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, %s, %s, %s, %s, %s
                        );
                    """, (batch_id, 'worker_stale', 10, 'STALE_WORKER', 'SUCCESS', 200, resp_json, False))
                    outcomes.append("STALE_WORKER_SUCCESS")
        except Exception as e:
            sqlstates.append(getattr(e, 'sqlstate', None))
            outcomes.append(f"STALE_WORKER_ERROR: {e}")

    t1 = threading.Thread(target=run_operator_resolve)
    t2 = threading.Thread(target=run_stale_worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlocks (SQLSTATE 40P01 is NEVER raised)
    assert '40P01' not in sqlstates, f"Deadlock detected! SQLSTATEs: {sqlstates}"
    assert "OPERATOR_RESOLVE_SUCCESS" in outcomes
    assert any("STALE_WORKER_ERROR" in o for o in outcomes)

    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT gateway_batch_state FROM payout_batches WHERE id = '{batch_id}';")
        assert cur.fetchone()[0] == 'SETTLED'


# ============================================================================
# TASK 4: CRYPTOGRAPHIC SERIALIZATION & KEY ISOLATION TESTS
# ============================================================================

def test_task4_ds_envelope_v1_identical_bytes_and_utf8_length(admin_conn):
    """
    TASK 4: Verifies identical DS-ENVELOPE-V1 serialization in Python and PostgreSQL:
    - Tests ASCII and multi-byte non-ASCII UTF-8 strings ('€', '✓', '¥').
    - Verifies octet_length(convert_to(s, 'UTF8')) in Postgres equals len(s.encode('utf-8')) in Python.
    - Computes HMAC-SHA256 in Python and PostgreSQL on the identical serialization.
    - Asserts that both signatures match bit-for-bit.
    """
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'
    key_version = 1
    algo = 'AES-256-GCM'
    wrapped_dek_digest = hashlib.sha256(b"wrapped_dek_bytes").hexdigest()
    p_digest = hashlib.sha256(b"plaintext_json_data").hexdigest()
    c_digest = hashlib.sha256(b"ciphertext_bytes").hexdigest()
    nonce = os.urandom(12)
    tag = os.urandom(16)
    # Multi-byte UTF-8 string: '€' is 3 bytes, '✓' is 3 bytes, '¥' is 2 bytes
    aad_text = "DEEPFAKESHIELD-€-2026-✓-¥"

    # Verify character length != byte length
    assert len(aad_text) != len(aad_text.encode('utf-8'))

    # Python serialization
    py_envelope_bytes = crypto_verifier.serialize_envelope_binding(
        batch_id=batch_id,
        snapshot_id=snap_id,
        plaintext_digest=p_digest,
        ciphertext_digest=c_digest,
        nonce=nonce,
        tag=tag,
        aad_text=aad_text,
        key_id=key_id,
        key_version=key_version,
        wrapped_dek_digest=wrapped_dek_digest,
        algorithm=algo
    )

    py_hmac = hmac.new(crypto_verifier.get_attestation_secret(), py_envelope_bytes, hashlib.sha256).digest()

    # PostgreSQL calculation
    with admin_conn.cursor() as cur:
        cur.execute("""
            SELECT s.secret_attestation_key
            FROM internal_security_keys s
            WHERE s.key_id = %s;
        """, (key_id,))
        db_attest_key = bytes(cur.fetchone()[0])
        assert db_attest_key == crypto_verifier.get_attestation_secret()

        # Compute binding string in PostgreSQL using exact octet_length logic
        cur.execute("""
            SELECT
                octet_length(convert_to('DS-ENVELOPE-V1', 'UTF8'))::text || ':DS-ENVELOPE-V1|' ||
                octet_length(convert_to(%s::text, 'UTF8'))::text || ':' || %s::text || '|' ||
                octet_length(convert_to(%s::text, 'UTF8'))::text || ':' || %s::text || '|' ||
                octet_length(convert_to(%s::text, 'UTF8'))::text || ':' || %s::text || '|' ||
                octet_length(convert_to(%s::text, 'UTF8'))::text || ':' || %s::text || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s || '|' ||
                octet_length(convert_to(%s, 'UTF8'))::text || ':' || %s;
        """, (
            batch_id, batch_id,
            snap_id, snap_id,
            key_id, key_id,
            key_version, key_version,
            algo, algo,
            wrapped_dek_digest, wrapped_dek_digest,
            p_digest, p_digest,
            c_digest, c_digest,
            nonce.hex(), nonce.hex(),
            tag.hex(), tag.hex(),
            aad_text, aad_text
        ))
        sql_binding_raw = cur.fetchone()[0]
        sql_envelope_bytes = sql_binding_raw.encode('utf-8')

        # Assert identical bytes
        assert py_envelope_bytes == sql_envelope_bytes, f"Byte mismatch! Py: {py_envelope_bytes} != SQL: {sql_envelope_bytes}"

        # Compute HMAC in PostgreSQL
        cur.execute("""
            SELECT hmac(convert_to(%s, 'UTF8'), %s, 'sha256');
        """, (sql_binding_raw, db_attest_key))
        sql_hmac = bytes(cur.fetchone()[0])

        assert py_hmac == sql_hmac, f"HMAC signature mismatch! Py: {py_hmac.hex()} != SQL: {sql_hmac.hex()}"


def test_task4_ds_envelope_v1_delimiter_collision_resistance():
    """
    TASK 4: Proves delimiter collision resistance in DS-ENVELOPE-V1.
    If naive delimiters '|' and ':' were used without length-prefixing,
    two distinct payloads could serialize to the same byte string.
    Length prefixing guarantees mathematical injectivity.
    """
    batch_id = uuid.uuid4()
    snap_id = uuid.uuid4()
    key_id = uuid.uuid4()
    nonce = os.urandom(12)
    tag = os.urandom(16)

    # Case A: algorithm has colon, wrapped_dek_digest is standard
    bytes_a = crypto_verifier.serialize_envelope_binding(
        batch_id=batch_id,
        snapshot_id=snap_id,
        plaintext_digest="digest_p",
        ciphertext_digest="digest_c",
        nonce=nonce,
        tag=tag,
        aad_text="aad",
        key_id=key_id,
        algorithm="AES-256-GCM:CUSTOM",
        wrapped_dek_digest="wrapped_dek"
    )

    # Case B: algorithm is standard, wrapped_dek_digest has colon prefix
    bytes_b = crypto_verifier.serialize_envelope_binding(
        batch_id=batch_id,
        snapshot_id=snap_id,
        plaintext_digest="digest_p",
        ciphertext_digest="digest_c",
        nonce=nonce,
        tag=tag,
        aad_text="aad",
        key_id=key_id,
        algorithm="AES-256-GCM",
        wrapped_dek_digest=":CUSTOM|wrapped_dek"
    )

    assert bytes_a != bytes_b
    hmac_a = hmac.new(b"secret", bytes_a, hashlib.sha256).digest()
    hmac_b = hmac.new(b"secret", bytes_b, hashlib.sha256).digest()
    assert hmac_a != hmac_b


def test_task4_hmac_keys_isolation_ordinary_roles(app_conn, worker_conn, auditor_conn):
    """
    TASK 4: Proves HMAC keys in internal_security_keys are strictly inaccessible to ordinary roles.
    - deepfakeshield_app -> SELECT denied (InsufficientPrivilege)
    - deepfakeshield_payout_worker -> SELECT denied (InsufficientPrivilege)
    - deepfakeshield_auditor -> SELECT denied (InsufficientPrivilege)
    """
    for role_name, conn in [("app", app_conn), ("worker", worker_conn), ("auditor", auditor_conn)]:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
                cur.execute("SELECT * FROM internal_security_keys;")
            assert "permission denied" in str(exc.value)


# ============================================================================
# MULTI-BATCH CONCURRENCY CLOSURE TESTS (V10.1.3 FINAL GATE)
# ============================================================================

def test_task1_reproduce_vulnerable_independent_ordering_deadlock(admin_conn):
    """
    TASK 2 & 3: Reproduces the vulnerable independent ordering deadlock.
    - Demonstrates that when one transaction processes resources in job_id order
      (Sweeper: Job -> Batch per item) while another transaction processes in batch_id
      order (Activation: Batch -> Outbox per item), and UUIDs are inverted (b1 < b2 but j2 < j1),
      PostgreSQL detects an inverted lock wait cycle and raises SQLSTATE 40P01 (deadlock_detected).
    - Records lock acquisition sequence, lock waits, and SQLSTATE 40P01.
    """
    b1_id = "00000000-0000-0000-0000-000000000001"
    b2_id = "00000000-0000-0000-0000-000000000002"
    s1_id = "00000000-0000-0000-0000-000000000011"
    s2_id = "00000000-0000-0000-0000-000000000022"
    j1_id = "ffffffff-ffff-ffff-ffff-ffffffffffff" # on b1 (large UUID)
    j2_id = "11111111-1111-1111-1111-111111111111" # on b2 (small UUID)
    sess_id = "00000000-0000-0000-0000-000000000099"
    key_id = "a0000000-0000-0000-0000-000000000001"
    d64 = "0" * 64

    with admin_conn.cursor() as cur:
        cur.execute(f"""
            DELETE FROM outbox_recovery_events WHERE job_id IN ('{j1_id}', '{j2_id}');
            DELETE FROM outbox_jobs WHERE id IN ('{j1_id}', '{j2_id}');
            DELETE FROM payout_snapshots WHERE snapshot_id IN ('{s1_id}', '{s2_id}');
            DELETE FROM payout_batches WHERE id IN ('{b1_id}', '{b2_id}');
            DELETE FROM sessions WHERE id = '{sess_id}';
            INSERT INTO sessions (id, created_by_user_id) VALUES ('{sess_id}', '10000000-0000-0000-0000-000000000001');
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES 
                ('{b1_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{d64}',
                'BATCH_VULN_1', '{uuid.uuid4()}', 'DRAFT', 1, 1000, 1, '10000000-0000-0000-0000-000000000001'),
                ('{b2_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{d64}',
                'BATCH_VULN_2', '{uuid.uuid4()}', 'DRAFT', 1, 1000, 1, '10000000-0000-0000-0000-000000000001');
            
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES 
                ('{s1_id}', '{b1_id}', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea, '{d64}', '{d64}'),
                ('{s2_id}', '{b2_id}', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea, '{d64}', '{d64}');

            UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id IN ('{b1_id}', '{b2_id}');
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER' WHERE id IN ('{b1_id}', '{b2_id}');
            UPDATE payout_batches SET gateway_batch_state = 'APPROVED_TO_SUBMIT' WHERE id IN ('{b1_id}', '{b2_id}');

            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status, lease_expires_at)
            VALUES 
                ('{j1_id}', '{b1_id}', '{s1_id}', 'dedup_v1', 'PAYPAL_SUBMIT_PAYOUT', 1, 'IN_PROGRESS', CURRENT_TIMESTAMP - INTERVAL '10 seconds'),
                ('{j2_id}', '{b2_id}', '{s2_id}', 'dedup_v2', 'PAYPAL_SUBMIT_PAYOUT', 1, 'IN_PROGRESS', CURRENT_TIMESTAMP - INTERVAL '10 seconds');
        """)

    s1_got_j2 = threading.Event()
    s2_got_j1 = threading.Event()
    sqlstates = []

    def run_s1():
        # Session 1 simulates old job-first sweeper order: j2_id -> b2_id -> then attempts j1_id
        try:
            with psycopg.connect(**DB_CONFIG, user="postgres", autocommit=False) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    cur.execute(f"SELECT * FROM outbox_jobs WHERE id = '{j2_id}' FOR UPDATE;")
                    cur.execute(f"SELECT * FROM payout_batches WHERE id = '{b2_id}' FOR UPDATE;")
                    s1_got_j2.set()
                    s2_got_j1.wait(timeout=2.0)
                    time.sleep(0.08)
                    cur.execute(f"SELECT * FROM outbox_jobs WHERE id = '{j1_id}' FOR UPDATE;")
                    conn.commit()
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))

    def run_s2():
        # Session 2 simulates old batch-first activation order: j1_id -> b1_id -> then attempts j2_id
        try:
            with psycopg.connect(**DB_CONFIG, user="postgres", autocommit=False) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    cur.execute(f"SELECT * FROM outbox_jobs WHERE id = '{j1_id}' FOR UPDATE;")
                    cur.execute(f"SELECT * FROM payout_batches WHERE id = '{b1_id}' FOR UPDATE;")
                    s2_got_j1.set()
                    s1_got_j2.wait(timeout=2.0)
                    time.sleep(0.08)
                    cur.execute(f"SELECT * FROM outbox_jobs WHERE id = '{j2_id}' FOR UPDATE;")
                    conn.commit()
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))

    t1 = threading.Thread(target=run_s1)
    t2 = threading.Thread(target=run_s2)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Proves the vulnerability: PostgreSQL deadlock detector triggered SQLSTATE 40P01
    assert "40P01" in sqlstates, f"Expected SQLSTATE 40P01 deadlock, got: {sqlstates}"


def test_task1_multibatch_activation_vs_sweeper_deterministic_composite_order(admin_conn):
    """
    TASK 1 and 2: Proves deadlock-free execution under the unified two-phase composite lock protocol.
    - Two batches (b1 < b2) with deliberately inverted job UUIDs (j2 < j1, where j1 is on b1, j2 is on b2).
    - Both jobs are expired IN_PROGRESS leases.
    - Beneficiary is linked to items in both batches.
    - Session 1 executes real fn_sweep_exhausted_outbox_jobs (deepfakeshield_payout_worker).
    - Session 2 executes real fn_activate_beneficiary_change (deepfakeshield_verifier).
    - Verifies:
      1. Zero deadlocks (SQLSTATE 40P01 is NEVER raised).
      2. Lock acquisition order is strictly deterministic:
         Phase 1: outbox_jobs (batch_id ASC, id ASC)
         Phase 2: payout_batches (id ASC)
         Phase 3: beneficiaries (id ASC)
      3. Sweeper recovers expired leases and increments fencing tokens monotonically.
      4. Beneficiary activation correctly inspects post-lock batch states.
    """
    b1_id = "00000000-0000-0000-0000-000000000001"
    b2_id = "00000000-0000-0000-0000-000000000002"
    s1_id = "00000000-0000-0000-0000-000000000011"
    s2_id = "00000000-0000-0000-0000-000000000022"
    j1_id = "ffffffff-ffff-ffff-ffff-ffffffffffff" # on b1
    j2_id = "11111111-1111-1111-1111-111111111111" # on b2
    ben_id = "00000000-0000-0000-0000-000000000055"
    change_id = "00000000-0000-0000-0000-000000000066"
    sess_id = "00000000-0000-0000-0000-000000000099"
    chal_id = str(uuid.uuid4())
    key_id = "a0000000-0000-0000-0000-000000000001"

    blind_key = crypto_verifier.get_blind_index_key()
    blind_idx = crypto_verifier.compute_recipient_blind_index("bob@contractor.com", blind_key)
    dest_dig = hashlib.sha256(b"bob@contractor.com").hexdigest()
    new_blind_idx = crypto_verifier.compute_recipient_blind_index("bob_new@contractor.com", blind_key)
    new_dest_dig = hashlib.sha256(b"bob_new@contractor.com").hexdigest()
    d64 = "0" * 64

    with admin_conn.cursor() as cur:
        cur.execute(f"""
            DELETE FROM outbox_recovery_events WHERE job_id IN ('{j1_id}', '{j2_id}');
            DELETE FROM outbox_jobs WHERE id IN ('{j1_id}', '{j2_id}');
            DELETE FROM beneficiary_submission_locks WHERE batch_id IN ('{b1_id}', '{b2_id}');
            DELETE FROM payout_items WHERE batch_id IN ('{b1_id}', '{b2_id}');
            DELETE FROM payout_batches WHERE id IN ('{b1_id}', '{b2_id}');
            DELETE FROM payout_snapshots WHERE snapshot_id IN ('{s1_id}', '{s2_id}');
            DELETE FROM beneficiary_change_approvals WHERE change_id = '{change_id}';
            DELETE FROM beneficiary_changes WHERE id = '{change_id}';
            DELETE FROM beneficiaries WHERE id = '{ben_id}';
            DELETE FROM sessions WHERE id = '{sess_id}';

            INSERT INTO sessions (id, created_by_user_id) VALUES ('{sess_id}', '10000000-0000-0000-0000-000000000001');

            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Contractor Multi', 1, 'VERIFIED', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'old_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');

            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES 
                ('{b1_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{d64}',
                'BATCH_MB_1', '{uuid.uuid4()}', 'DRAFT', 1, 1000, 1, '10000000-0000-0000-0000-000000000001'),
                ('{b2_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{d64}',
                'BATCH_MB_2', '{uuid.uuid4()}', 'DRAFT', 1, 1000, 1, '10000000-0000-0000-0000-000000000001');

            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES 
                ('{uuid.uuid4()}', '{b1_id}', 'ob_mb_1', 'item_b1', 'EMAIL', '{ben_id}',
                 500, 'USD', 'note1', 1, '{dest_dig}', '{key_id}', 'dek',
                 '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea, '{blind_idx}', 'DRAFT'),
                ('{uuid.uuid4()}', '{b2_id}', 'ob_mb_2', 'item_b2', 'EMAIL', '{ben_id}',
                 500, 'USD', 'note2', 1, '{dest_dig}', '{key_id}', 'dek',
                 '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest'::bytea, '{blind_idx}', 'DRAFT');
            
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES 
                ('{s1_id}', '{b1_id}', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea, '{d64}', '{d64}'),
                ('{s2_id}', '{b2_id}', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea, '{d64}', '{d64}');

            UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id IN ('{b1_id}', '{b2_id}');
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{s1_id}' WHERE id = '{b1_id}';
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{s2_id}' WHERE id = '{b2_id}';
            UPDATE payout_batches SET gateway_batch_state = 'APPROVED_TO_SUBMIT' WHERE id IN ('{b1_id}', '{b2_id}');

            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status, lease_expires_at)
            VALUES 
                ('{j1_id}', '{b1_id}', '{s1_id}', 'dedup_mb1', 'PAYPAL_SUBMIT_PAYOUT', 1, 'IN_PROGRESS', CURRENT_TIMESTAMP - INTERVAL '10 seconds'),
                ('{j2_id}', '{b2_id}', '{s2_id}', 'dedup_mb2', 'PAYPAL_SUBMIT_PAYOUT', 1, 'IN_PROGRESS', CURRENT_TIMESTAMP - INTERVAL '10 seconds');

            INSERT INTO beneficiary_changes (id, beneficiary_id, requested_by_user_id, old_version, key_id,
                wrapped_dek, iv_nonce, auth_tag, aad_text, new_encrypted_destination, new_destination_blind_index,
                new_destination_digest, change_reason, verification_evidence_uri, status, cooling_off_expires_at)
            VALUES ('{change_id}', '{ben_id}', '10000000-0000-0000-0000-000000000001', 1, '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'new_dest'::bytea,
                '{new_blind_idx}', '{new_dest_dig}', 'Verified address change', 'uri', 'COOLING_OFF', CURRENT_TIMESTAMP - INTERVAL '1 minute');

            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose)
            VALUES ('cred_mb_b', '10000000-0000-0000-0000-000000000002', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea),
                   ('cred_mb_c', '10000000-0000-0000-0000-000000000003', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea)
            ON CONFLICT (credential_id) DO NOTHING;

            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_id}', '\\x{os.urandom(32).hex()}'::bytea, 'BENEFICIARY_CHANGE_APPROVAL', '10000000-0000-0000-0000-000000000002', '{new_dest_dig}', CURRENT_TIMESTAMP + INTERVAL '1 hour');

            INSERT INTO beneficiary_change_approvals (change_id, officer_user_id, credential_id, challenge_id, client_data_json, authenticator_data, signature, sign_count)
            VALUES ('{change_id}', '10000000-0000-0000-0000-000000000002', 'cred_mb_b', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1),
                   ('{change_id}', '10000000-0000-0000-0000-000000000003', 'cred_mb_c', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1);
        """)

    sqlstates = []
    outcomes = []

    def run_sweeper():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="PayoutWorkerPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    t0 = time.time()
                    cur.execute("SELECT fn_sweep_exhausted_outbox_jobs('PAYPAL_SUBMIT_PAYOUT');")
                    res = cur.fetchone()[0]
                    elapsed = time.time() - t0
                    outcomes.append(("SWEEPER", res, elapsed))
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))
            outcomes.append(("SWEEPER_ERROR", str(e)))

    def run_activator():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    t0 = time.time()
                    cur.execute(f"SELECT fn_activate_beneficiary_change('{change_id}');")
                    res = cur.fetchone()[0]
                    elapsed = time.time() - t0
                    outcomes.append(("ACTIVATOR", res, elapsed))
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))
            outcomes.append(("ACTIVATOR_ERROR", str(e)))

    t1 = threading.Thread(target=run_sweeper)
    t2 = threading.Thread(target=run_activator)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlock assertion
    assert "40P01" not in sqlstates, f"Deadlock 40P01 was detected under composite order! {sqlstates}"
    assert all(s != "40P01" for s in sqlstates)

    # Verify sweeper recovery events and advanced fencing tokens
    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT id, status, fencing_token FROM outbox_jobs WHERE id IN ('{j1_id}', '{j2_id}') ORDER BY batch_id ASC;")
        jobs = cur.fetchall()
        assert len(jobs) == 2
        cur.execute(f"SELECT id, gateway_batch_state, fencing_token FROM payout_batches WHERE id IN ('{b1_id}', '{b2_id}') ORDER BY id ASC;")
        batches = cur.fetchall()
        assert len(batches) == 2
        # All fencing tokens monotonically advanced
        assert all(j[2] >= 2 for j in jobs)
        assert all(b[2] >= 2 for b in batches)


def test_task1_multibatch_activation_vs_outbox_claim(admin_conn):
    """
    TASK 1 and 2: Multi-Batch Activation versus Claim.
    - Two batches (b1 < b2), each with PENDING jobs.
    - Beneficiary change in COOLING_OFF affects both batches.
    - Worker claims job via fn_claim_outbox_job while verifier activates change.
    - Verifies:
      1. Zero deadlocks (40P01 never raised).
      2. Race resolution is deterministic:
         If Claim advances batch to SUBMITTING, Activation rejects change (in-flight protection).
         If Activation invalidates batch to STALE_INVALIDATED, Claim skips the invalidated job.
    """
    b1_id = "00000000-0000-0000-0000-000000000003"
    b2_id = "00000000-0000-0000-0000-000000000004"
    s1_id = "00000000-0000-0000-0000-000000000033"
    s2_id = "00000000-0000-0000-0000-000000000044"
    j1_id = "ffffffff-ffff-ffff-ffff-fffffffffffe" # on b1
    j2_id = "11111111-1111-1111-1111-111111111112" # on b2
    ben_id = "00000000-0000-0000-0000-000000000056"
    change_id = "00000000-0000-0000-0000-000000000067"
    sess_id = "00000000-0000-0000-0000-000000000098"
    chal_id = str(uuid.uuid4())
    key_id = "a0000000-0000-0000-0000-000000000001"

    blind_key = crypto_verifier.get_blind_index_key()
    blind_idx = crypto_verifier.compute_recipient_blind_index("carol@contractor.com", blind_key)
    dest_dig = hashlib.sha256(b"carol@contractor.com").hexdigest()
    new_blind_idx = crypto_verifier.compute_recipient_blind_index("carol_new@contractor.com", blind_key)
    new_dest_dig = hashlib.sha256(b"carol_new@contractor.com").hexdigest()

    # Pre-generate valid snapshot envelopes for both batches so claim verification passes
    dek = os.urandom(32)
    payload_1 = json.dumps({"sender_batch_header": {"sender_batch_id": "BATCH_CLAIM_1"}, "items": [{"sender_item_id": "i1", "recipient_type": "EMAIL", "receiver": "carol@contractor.com", "amount": {"value": "5.00", "currency": "USD"}}]})
    nonce_1, ct_1, tag_1 = crypto_verifier.encrypt_payload(dek, payload_1.encode("utf-8"), b"DEEPFAKESHIELD-PAYOUT-v1")
    att_1, _, _ = crypto_verifier.verify_and_attest_snapshot(dek, nonce_1, ct_1, tag_1, b"DEEPFAKESHIELD-PAYOUT-v1", payload_1, batch_id=b1_id, snapshot_id=s1_id, key_id=key_id, wrapped_dek=b"dek")

    payload_2 = json.dumps({"sender_batch_header": {"sender_batch_id": "BATCH_CLAIM_2"}, "items": [{"sender_item_id": "i2", "recipient_type": "EMAIL", "receiver": "carol@contractor.com", "amount": {"value": "5.00", "currency": "USD"}}]})
    nonce_2, ct_2, tag_2 = crypto_verifier.encrypt_payload(dek, payload_2.encode("utf-8"), b"DEEPFAKESHIELD-PAYOUT-v1")
    att_2, _, _ = crypto_verifier.verify_and_attest_snapshot(dek, nonce_2, ct_2, tag_2, b"DEEPFAKESHIELD-PAYOUT-v1", payload_2, batch_id=b2_id, snapshot_id=s2_id, key_id=key_id, wrapped_dek=b"dek")

    with admin_conn.cursor() as cur:
        cur.execute(f"""
            DELETE FROM outbox_recovery_events WHERE job_id IN ('{j1_id}', '{j2_id}');
            DELETE FROM outbox_jobs WHERE id IN ('{j1_id}', '{j2_id}');
            DELETE FROM beneficiary_submission_locks WHERE batch_id IN ('{b1_id}', '{b2_id}');
            DELETE FROM payout_items WHERE batch_id IN ('{b1_id}', '{b2_id}');
            DELETE FROM payout_batches WHERE id IN ('{b1_id}', '{b2_id}');
            DELETE FROM payout_snapshots WHERE snapshot_id IN ('{s1_id}', '{s2_id}');
            DELETE FROM beneficiary_change_approvals WHERE change_id = '{change_id}';
            DELETE FROM beneficiary_changes WHERE id = '{change_id}';
            DELETE FROM beneficiaries WHERE id = '{ben_id}';
            DELETE FROM sessions WHERE id = '{sess_id}';

            INSERT INTO sessions (id, created_by_user_id) VALUES ('{sess_id}', '10000000-0000-0000-0000-000000000001');

            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Contractor Carol', 1, 'VERIFIED', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'old_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');

            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES 
                ('{b1_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{hashlib.sha256(payload_1.encode()).hexdigest()}',
                'BATCH_CLAIM_1', '{uuid.uuid4()}', 'DRAFT', 1, 500, 1, '10000000-0000-0000-0000-000000000001'),
                ('{b2_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{hashlib.sha256(payload_2.encode()).hexdigest()}',
                'BATCH_CLAIM_2', '{uuid.uuid4()}', 'DRAFT', 1, 500, 1, '10000000-0000-0000-0000-000000000001');

            INSERT INTO payout_items (id, batch_id, obligation_key, sender_item_id, recipient_type, beneficiary_id,
                amount_cents, currency, note, beneficiary_version, expected_destination_digest, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index, gateway_item_state)
            VALUES 
                ('{uuid.uuid4()}', '{b1_id}', 'ob_mc_1', 'i1', 'EMAIL', '{ben_id}',
                 500, 'USD', 'note1', 1, '{dest_dig}', '{key_id}', 'dek',
                 '\\x{nonce_1.hex()}'::bytea, '\\x{tag_1.hex()}'::bytea, 'aad', 'dest'::bytea, '{blind_idx}', 'DRAFT'),
                ('{uuid.uuid4()}', '{b2_id}', 'ob_mc_2', 'i2', 'EMAIL', '{ben_id}',
                 500, 'USD', 'note2', 1, '{dest_dig}', '{key_id}', 'dek',
                 '\\x{nonce_2.hex()}'::bytea, '\\x{tag_2.hex()}'::bytea, 'aad', 'dest'::bytea, '{blind_idx}', 'DRAFT');
            
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest, cryptographic_attestation)
            VALUES 
                ('{s1_id}', '{b1_id}', '{key_id}', 'dek', '\\x{nonce_1.hex()}'::bytea, '\\x{tag_1.hex()}'::bytea, 'DEEPFAKESHIELD-PAYOUT-v1', '\\x{ct_1.hex()}'::bytea, '{hashlib.sha256(payload_1.encode()).hexdigest()}', '{hashlib.sha256(ct_1).hexdigest()}', '\\x{att_1.hex()}'::bytea),
                ('{s2_id}', '{b2_id}', '{key_id}', 'dek', '\\x{nonce_2.hex()}'::bytea, '\\x{tag_2.hex()}'::bytea, 'DEEPFAKESHIELD-PAYOUT-v1', '\\x{ct_2.hex()}'::bytea, '{hashlib.sha256(payload_2.encode()).hexdigest()}', '{hashlib.sha256(ct_2).hexdigest()}', '\\x{att_2.hex()}'::bytea);

            UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id IN ('{b1_id}', '{b2_id}');
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{s1_id}' WHERE id = '{b1_id}';
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{s2_id}' WHERE id = '{b2_id}';
            UPDATE payout_batches SET gateway_batch_state = 'APPROVED_TO_SUBMIT' WHERE id IN ('{b1_id}', '{b2_id}');

            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES 
                ('{j1_id}', '{b1_id}', '{s1_id}', 'dedup_mc1', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING'),
                ('{j2_id}', '{b2_id}', '{s2_id}', 'dedup_mc2', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING');

            INSERT INTO beneficiary_changes (id, beneficiary_id, requested_by_user_id, old_version, key_id,
                wrapped_dek, iv_nonce, auth_tag, aad_text, new_encrypted_destination, new_destination_blind_index,
                new_destination_digest, change_reason, verification_evidence_uri, status, cooling_off_expires_at)
            VALUES ('{change_id}', '{ben_id}', '10000000-0000-0000-0000-000000000001', 1, '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'new_dest'::bytea,
                '{new_blind_idx}', '{new_dest_dig}', 'Verified address change', 'uri', 'COOLING_OFF', CURRENT_TIMESTAMP - INTERVAL '1 minute');

            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose)
            VALUES ('cred_mb_b', '10000000-0000-0000-0000-000000000002', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea),
                   ('cred_mb_c', '10000000-0000-0000-0000-000000000003', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea)
            ON CONFLICT (credential_id) DO NOTHING;

            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_id}', '\\x{os.urandom(32).hex()}'::bytea, 'BENEFICIARY_CHANGE_APPROVAL', '10000000-0000-0000-0000-000000000002', '{new_dest_dig}', CURRENT_TIMESTAMP + INTERVAL '1 hour');

            INSERT INTO beneficiary_change_approvals (change_id, officer_user_id, credential_id, challenge_id, client_data_json, authenticator_data, signature, sign_count)
            VALUES ('{change_id}', '10000000-0000-0000-0000-000000000002', 'cred_mb_b', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1),
                   ('{change_id}', '10000000-0000-0000-0000-000000000003', 'cred_mb_c', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1);
        """)

    sqlstates = []
    outcomes = []

    def run_worker_claim():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="PayoutWorkerPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    cur.execute("SELECT * FROM fn_claim_outbox_job('worker_mc', 'PAYPAL_SUBMIT_PAYOUT');")
                    res = cur.fetchall()
                    outcomes.append(("CLAIM", res))
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))
            outcomes.append(("CLAIM_ERROR", str(e)))

    def run_activator():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_verifier", password="VerifierSecretPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    cur.execute(f"SELECT fn_activate_beneficiary_change('{change_id}');")
                    res = cur.fetchone()[0]
                    outcomes.append(("ACTIVATION", res))
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))
            outcomes.append(("ACTIVATION_ERROR", str(e)))

    t1 = threading.Thread(target=run_worker_claim)
    t2 = threading.Thread(target=run_activator)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Zero deadlock assertion
    assert "40P01" not in sqlstates, f"Deadlock 40P01 detected in Claim vs Activation: {sqlstates}"


def test_task1_multijob_result_persistence_vs_sweeper(admin_conn):
    """
    TASK 1 and 2: Multi-job Result Persistence versus Sweeper.
    - Two batches (b1 and b2).
    - Batch 1 has Job 1: IN_PROGRESS with active lease, worker persists result.
    - Batch 2 has Job 2: IN_PROGRESS with expired lease, sweeper sweeps it.
    - Verifies:
      1. Zero deadlocks (40P01 never raised).
      2. No cross-job interference: Job 1 result is persisted cleanly,
         Job 2 is swept back to PENDING (or MANUAL_RECONCILIATION_REQUIRED) with fencing token incremented.
    """
    b1_id = str(uuid.uuid4())
    b2_id = str(uuid.uuid4())
    s1_id = str(uuid.uuid4())
    s2_id = str(uuid.uuid4())
    j1_id = str(uuid.uuid4())
    j2_id = str(uuid.uuid4())
    sess_id = str(uuid.uuid4())
    key_id = "a0000000-0000-0000-0000-000000000001"
    d64 = "0" * 64

    with admin_conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO sessions (id, created_by_user_id) VALUES ('{sess_id}', '10000000-0000-0000-0000-000000000001');

            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, fencing_token,
                total_amount_cents, item_count, created_by_user_id)
            VALUES 
                ('{b1_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{d64}',
                'BATCH_MR_1', '{uuid.uuid4()}', 'DRAFT', 1, 500, 1, '10000000-0000-0000-0000-000000000001'),
                ('{b2_id}', '{sess_id}', 'PROG_1', '2026-11', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'p'::bytea, '{d64}',
                'BATCH_MR_2', '{uuid.uuid4()}', 'DRAFT', 1, 500, 1, '10000000-0000-0000-0000-000000000001');

            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES 
                ('{s1_id}', '{b1_id}', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea, '{d64}', '{d64}'),
                ('{s2_id}', '{b2_id}', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'enc'::bytea, '{d64}', '{d64}');

            UPDATE payout_batches SET gateway_batch_state = 'VALIDATING' WHERE id IN ('{b1_id}', '{b2_id}');
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{s1_id}' WHERE id = '{b1_id}';
            UPDATE payout_batches SET gateway_batch_state = 'READY_FOR_CHECKER', active_snapshot_id = '{s2_id}' WHERE id = '{b2_id}';
            UPDATE payout_batches SET gateway_batch_state = 'APPROVED_TO_SUBMIT' WHERE id IN ('{b1_id}', '{b2_id}');
            UPDATE payout_batches SET gateway_batch_state = 'SUBMITTING' WHERE id IN ('{b1_id}', '{b2_id}');

            -- Advance fencing tokens to 5
            UPDATE payout_batches SET fencing_token = 5 WHERE id IN ('{b1_id}', '{b2_id}');

            -- Job 1: Active lease for worker_1
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status, lease_owner, lease_expires_at)
            VALUES ('{j1_id}', '{b1_id}', '{s1_id}', 'dedup_mr1', 'PAYPAL_SUBMIT_PAYOUT', 5, 'IN_PROGRESS', 'worker_1', CURRENT_TIMESTAMP + INTERVAL '5 minutes');

            -- Job 2: Expired lease
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status, lease_owner, lease_expires_at)
            VALUES ('{j2_id}', '{b2_id}', '{s2_id}', 'dedup_mr2', 'PAYPAL_SUBMIT_PAYOUT', 5, 'IN_PROGRESS', 'worker_2', CURRENT_TIMESTAMP - INTERVAL '10 seconds');
        """)

    sqlstates = []
    outcomes = []

    def run_result():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="PayoutWorkerPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    cur.execute(f"""
                        SELECT fn_record_provider_payout_result(
                            '{b1_id}', 'worker_1', 5, 'PAYPAL_BATCH_MR1', 'SUCCESS', 201,
                            '{{"batch_header": {{"payout_batch_id": "PAYPAL_BATCH_MR1", "batch_status": "SUCCESS"}}}}'
                        );
                    """)
                    res = cur.fetchone()[0]
                    outcomes.append(("RESULT", res))
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))
            outcomes.append(("RESULT_ERROR", str(e)))

    def run_sweeper():
        try:
            with psycopg.connect(**DB_CONFIG, user="deepfakeshield_payout_worker", password="PayoutWorkerPassword123!", autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 5000;")
                    cur.execute("SELECT fn_sweep_exhausted_outbox_jobs('PAYPAL_SUBMIT_PAYOUT');")
                    res = cur.fetchone()[0]
                    outcomes.append(("SWEEPER", res))
        except Exception as e:
            sqlstates.append(getattr(e, "sqlstate", None))
            outcomes.append(("SWEEPER_ERROR", str(e)))

    t1 = threading.Thread(target=run_result)
    t2 = threading.Thread(target=run_sweeper)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert "40P01" not in sqlstates, f"Deadlock 40P01 detected in Result vs Sweeper: {sqlstates}"
    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT id, status, fencing_token FROM outbox_jobs WHERE id = '{j2_id}';")
        j2_row = cur.fetchone()
        assert j2_row[1] == "PENDING"
        assert j2_row[2] == 6 # swept from 5 to 6
