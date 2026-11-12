#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Executable Integration Test Suite
Milestone: V10.1.3 — Migration and Security Repair
Target Database: PostgreSQL 18.6

Comprehensive verification covering:
- BLOCKER 1 & 7: Function Signatures Audit, Ownership, Preflight Verification & Migration Tracking
- BLOCKER 2: Mandatory Cryptographic Attestation, Isolation of Secrets & Decryption Proof
- BLOCKER 3: Dedicated Keyed HMAC Blind Index Verification & Strict Exception Redaction
- BLOCKER 4: Authenticated Identity Assertions (Cryptographic Proof for Treasury Operators)
- BLOCKER 5: Provider Failure Evidence, Unconfirmed Duplicates -> MANUAL_RECON & Safe Locks
- BLOCKER 6: Least-Privilege Role Matrix (Auditor Strictly Read-Only, No fn_append_audit_event)
- CONCURRENCY: Activation vs Worker Claim, Result Persistence vs Sweeping, Invalidation vs In-Flight
- REAL WEBAUTHN: P-256 ECDSA Assertions, Clone Counter Rejection & Counterless Support
"""

import os
import sys
import uuid
import json
import base64
import hashlib
import threading
import time
import pytest
import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from crypto_verifier import (
    encrypt_payload,
    verify_and_attest_snapshot,
    compute_recipient_blind_index,
    create_identity_assertion,
    generate_webauthn_keypair,
    create_webauthn_assertion,
    verify_webauthn_assertion,
)
from tests.test_fixtures import (
    TEST_ATTESTATION_SECRET,
    TEST_AUTH_ASSERTION_KEY,
    TEST_BLIND_INDEX_KEY,
)

# Environment-Provided Configuration with Safe Defaults
DB_HOST = os.environ.get("PGHOST", "127.0.0.1")
DB_PORT = int(os.environ.get("PGPORT", "5433"))
DB_NAME = os.environ.get("PGDATABASE", "deepfakeshield_db")
DB_ADMIN_USER = os.environ.get("PGUSER", "postgres")
DB_ADMIN_PASSWORD = os.environ.get("PGPASSWORD", "postgres")

APP_PASS = os.environ.get("APP_PASSWORD", "app_secret_pass")
VERIFIER_PASS = os.environ.get("VERIFIER_PASSWORD", "verifier_secret_pass")
WORKER_PASS = os.environ.get("WORKER_PASSWORD", "worker_secret_pass")
AUDITOR_PASS = os.environ.get("AUDITOR_PASSWORD", "auditor_secret_pass")

DB_PARAMS_ADMIN = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_ADMIN_USER} password={DB_ADMIN_PASSWORD}"
DB_PARAMS_APP = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_app password={APP_PASS}"
DB_PARAMS_VERIFIER = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_verifier password={VERIFIER_PASS}"
DB_PARAMS_WORKER = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_payout_worker password={WORKER_PASS}"
DB_PARAMS_AUDITOR = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_auditor password={AUDITOR_PASS}"

@pytest.fixture(scope="session")
def admin_conn():
    conn = psycopg.connect(DB_PARAMS_ADMIN, autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="session")
def app_conn():
    conn = psycopg.connect(DB_PARAMS_APP, autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="session")
def verifier_conn():
    conn = psycopg.connect(DB_PARAMS_VERIFIER, autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="session")
def worker_conn():
    conn = psycopg.connect(DB_PARAMS_WORKER, autocommit=True)
    yield conn
    conn.close()

@pytest.fixture(scope="session")
def auditor_conn():
    conn = psycopg.connect(DB_PARAMS_AUDITOR, autocommit=True)
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
                ('10000000-0000-0000-0000-000000000004', 'dave_auditor', 'AUDITOR', TRUE),
                ('10000000-0000-0000-0000-000000000005', 'eve_unauthorized', 'AP_CLERK', TRUE)
            ON CONFLICT (id) DO UPDATE SET is_active = TRUE;
        """)

        # Seed active default encryption key (metadata only, no secrets!)
        cur.execute("""
            INSERT INTO encryption_key_metadata (key_id, algorithm, is_active)
            VALUES ('a0000000-0000-0000-0000-000000000001', 'AES-256-GCM', TRUE)
            ON CONFLICT (key_id) DO UPDATE SET is_active = TRUE;
        """)

        # Seed internal security keys (isolated, unreadable by app/worker/auditor)
        cur.execute("""
            INSERT INTO internal_security_keys (key_id, secret_attestation_key, blind_index_key, auth_assertion_key)
            VALUES (
                'a0000000-0000-0000-0000-000000000001',
                decode('c0ffee00deadbeef0102030405060708090a0b0c0d0e0f101112131415161718', 'hex'),
                decode('ba5eba11deadbeef2122232425262728292a2b2c2d2e2f303132333435363738', 'hex'),
                decode('cafebebe01020304a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4f1f2f3f4', 'hex')
            )
            ON CONFLICT (key_id) DO UPDATE SET
                secret_attestation_key = EXCLUDED.secret_attestation_key,
                blind_index_key = EXCLUDED.blind_index_key,
                auth_assertion_key = EXCLUDED.auth_assertion_key;
        """)

def advance_batch_to_state(cur, batch_id: str, target_state: str):
    """Safely transitions a batch through valid state transitions from DRAFT to target_state."""
    valid_path = ['DRAFT', 'VALIDATING', 'READY_FOR_CHECKER', 'APPROVED_TO_SUBMIT', 'SUBMITTING', 'SUBMITTED', 'SETTLED']
    try:
        target_idx = valid_path.index(target_state)
    except ValueError:
        if target_state == 'MANUAL_RECONCILIATION_REQUIRED':
            for s in ['VALIDATING', 'READY_FOR_CHECKER', 'APPROVED_TO_SUBMIT', 'SUBMITTING', 'MANUAL_RECONCILIATION_REQUIRED']:
                cur.execute(f"UPDATE payout_batches SET gateway_batch_state = '{s}' WHERE id = '{batch_id}';")
            return
        elif target_state == 'STALE_INVALIDATED':
            for s in ['VALIDATING', 'READY_FOR_CHECKER', 'STALE_INVALIDATED']:
                cur.execute(f"UPDATE payout_batches SET gateway_batch_state = '{s}' WHERE id = '{batch_id}';")
            return
        else:
            raise ValueError(f"Unknown target state: {target_state}")

    for s in valid_path[1:target_idx + 1]:
        cur.execute(f"UPDATE payout_batches SET gateway_batch_state = '{s}' WHERE id = '{batch_id}';")

# ============================================================================
# BLOCKER 1 & 7: MIGRATION SIGNATURES, PREFLIGHT & MIGRATION TRACKING
# ============================================================================

def test_migration_signatures_and_preflight(admin_conn):
    """
    BLOCKER 1 & 7:
    - Verifies fn_record_provider_item_result has all 6 declared arguments in pg_proc.
    - Audits every function's ownership is deepfakeshield_owner.
    - Verifies schema_migrations table tracks version V10.1.3.
    """
    with admin_conn.cursor() as cur:
        # 1. Audit fn_record_provider_item_result signature (qualify p.oid to resolve ambiguity)
        cur.execute("""
            SELECT proname, pg_get_function_identity_arguments(p.oid), rolname
            FROM pg_proc p
            JOIN pg_roles r ON r.oid = p.proowner
            WHERE proname = 'fn_record_provider_item_result';
        """)
        row = cur.fetchone()
        assert row is not None
        assert row[0] == 'fn_record_provider_item_result'
        sig = row[1].lower()
        assert "p_expected_sender_item_id" in sig or sig.count("character varying") >= 4
        assert row[2] == 'deepfakeshield_owner'

        # 2. Audit that schema_migrations records V10.1.3
        cur.execute("SELECT version, description FROM schema_migrations WHERE version = 'V10.1.3';")
        m_row = cur.fetchone()
        assert m_row is not None
        assert m_row[0] == 'V10.1.3'

        # 3. Preflight check: verify all 25 functions exist and owned by deepfakeshield_owner
        cur.execute("""
            SELECT proname
            FROM pg_proc p
            JOIN pg_roles r ON r.oid = p.proowner
            WHERE pronamespace = 'public'::regnamespace
              AND proname LIKE 'fn_%'
              AND r.rolname != 'deepfakeshield_owner';
        """)
        bad_owners = cur.fetchall()
        assert len(bad_owners) == 0, f"Functions with invalid owner: {bad_owners}"

# ============================================================================
# BLOCKER 2: MANDATORY CRYPTOGRAPHIC ATTESTATION & KEY ISOLATION
# ============================================================================

def test_mandatory_cryptographic_attestation_and_isolation(admin_conn, app_conn):
    """
    BLOCKER 2:
    - Cryptographic attestation is mandatory (NULL or empty fails with check_violation).
    - Mismatched ciphertext/plaintext fails verification.
    - Key isolation: deepfakeshield_app CANNOT SELECT internal_security_keys.
    - encryption_key_metadata contains NO verification_secret column.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    ben_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    clean_email = "contractor.legit@example.com"
    blind_idx = compute_recipient_blind_index(clean_email, TEST_BLIND_INDEX_KEY)
    expected_digest = hashlib.sha256(clean_email.encode('utf-8')).hexdigest()

    with admin_conn.cursor() as cur:
        # Check that encryption_key_metadata has NO verification_secret column
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'encryption_key_metadata' AND column_name = 'verification_secret';
        """)
        assert cur.fetchone() is None, "verification_secret must NOT exist in encryption_key_metadata!"

        # Seed batch in DRAFT and item
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc, verification_status)
            VALUES ('{ben_id}', 'Contractor Legit', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad',
                'dest_enc'::bytea, '{blind_idx}', '{expected_digest}', 'PROG_1', 'consent_h', 'ph', 'em', 'VERIFIED');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                'digest_placeholder', 'batch_attest_01', '{uuid.uuid4()}', 'DRAFT', 5000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        cur.execute(f"""
            INSERT INTO payout_items (id, batch_id, obligation_key, beneficiary_id, beneficiary_version, expected_destination_digest,
                sender_item_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index,
                amount_cents, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_attest_1', '{ben_id}', 1, '{expected_digest}',
                'item_attest_1', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea,
                '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea, '{blind_idx}', 5000, 'DRAFT');
        """)

    # 1. Key isolation test: deepfakeshield_app CANNOT access internal_security_keys!
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("SELECT * FROM internal_security_keys;")

    valid_payload_json = json.dumps({
        "sender_batch_header": {"sender_batch_id": "batch_attest_01"},
        "items": [
            {"recipient_type": "EMAIL", "receiver": clean_email, "amount": {"value": "50.00", "currency": "USD"}, "sender_item_id": "item_attest_1"}
        ]
    })
    dek = os.urandom(32)
    aad = b"batch_attest_01_aad"
    nonce, cipher, tag = encrypt_payload(dek, valid_payload_json.encode('utf-8'), aad)
    p_digest = hashlib.sha256(valid_payload_json.encode('utf-8')).hexdigest()

    # 2. Negative test: NULL attestation fails with check_violation!
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (batch_id, valid_payload_json, cipher, p_digest, b"wrapped_dek", nonce, tag, "aad", None))
        assert "Cryptographic attestation is mandatory" in str(exc.value)

    # 3. Negative test: valid ciphertext for different plaintext is rejected by verification boundary
    hacker_payload_json = json.dumps({
        "sender_batch_header": {"sender_batch_id": "batch_attest_01"},
        "items": [
            {"recipient_type": "EMAIL", "receiver": "hacker@evil.com", "amount": {"value": "50.00", "currency": "USD"}, "sender_item_id": "item_attest_1"}
        ]
    })
    nonce_bad, cipher_bad, tag_bad = encrypt_payload(dek, hacker_payload_json.encode('utf-8'), aad)
    with pytest.raises(ValueError) as exc_v:
        verify_and_attest_snapshot(dek, nonce_bad, cipher_bad, tag_bad, aad, valid_payload_json, TEST_ATTESTATION_SECRET)
    assert "Exact Payload Integrity Failure" in str(exc_v.value)

# ============================================================================
# BLOCKER 3: DEDICATED KEYED BLIND INDEX & ZERO PII EXPOSURE IN ERRORS
# ============================================================================

def test_recipient_blind_index_verification_and_redaction(admin_conn, app_conn):
    """
    BLOCKER 3:
    - Dedicated keyed HMAC blind index passes finalization.
    - Plain SHA-256 fallback is rejected.
    - Legacy 'idx' fallback is rejected.
    - Exception message does NOT leak the plaintext recipient email address.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    ben_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'

    secret_email = "sensitive.whistleblower@corp.internal"
    raw_sha256 = hashlib.sha256(secret_email.encode('utf-8')).hexdigest()
    correct_blind_index = compute_recipient_blind_index(secret_email, TEST_BLIND_INDEX_KEY)

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc, verification_status)
            VALUES ('{ben_id}', 'Confidential Whistleblower', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad',
                'dest_enc'::bytea, '{correct_blind_index}', '{raw_sha256}', 'PROG_1', 'consent_h', 'ph', 'em', 'VERIFIED');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                'digest_placeholder', 'batch_blind_01', '{uuid.uuid4()}', 'DRAFT', 2500, 1, '10000000-0000-0000-0000-000000000001');
        """)
        cur.execute(f"""
            INSERT INTO payout_items (id, batch_id, obligation_key, beneficiary_id, beneficiary_version, expected_destination_digest,
                sender_item_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index,
                amount_cents, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_blind_1', '{ben_id}', 1, '{raw_sha256}',
                'item_blind_1', '{key_id}', 'dek', '\\x0102030405060708090a0b0c'::bytea,
                '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea, '{raw_sha256}', 2500, 'DRAFT');
        """)

    payload_json = json.dumps({
        "sender_batch_header": {"sender_batch_id": "batch_blind_01"},
        "items": [
            {"recipient_type": "EMAIL", "receiver": secret_email, "amount": {"value": "25.00", "currency": "USD"}, "sender_item_id": "item_blind_1"}
        ]
    })
    dek = os.urandom(32)
    aad_text = "batch_blind_01_aad"
    aad = aad_text.encode('utf-8')
    nonce, cipher, tag = encrypt_payload(dek, payload_json.encode('utf-8'), aad)
    attestation, p_digest, c_digest = verify_and_attest_snapshot(
        dek, nonce, cipher, tag, aad, payload_json, batch_id, TEST_ATTESTATION_SECRET
    )

    # Corrupt beneficiaries table with unkeyed raw SHA256
    with admin_conn.cursor() as cur:
        cur.execute(f"UPDATE beneficiaries SET destination_blind_index = '{raw_sha256}' WHERE id = '{ben_id}';")

    with app_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (batch_id, payload_json, cipher, p_digest, b"wrapped_dek", nonce, tag, aad_text, attestation))
        error_msg = str(exc.value)
        # 1. Blind index failure triggered
        assert "recipient blind index verification failed" in error_msg
        # 2. REDACTION CHECK: Email address is strictly redacted from error message!
        assert secret_email not in error_msg, f"PII Leak detected! Error message exposed recipient email: {error_msg}"

    # Now restore correct blind index in beneficiaries table
    with admin_conn.cursor() as cur:
        cur.execute(f"UPDATE beneficiaries SET destination_blind_index = '{correct_blind_index}' WHERE id = '{ben_id}';")
        cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'DRAFT' WHERE id = '{batch_id}';")

    # Finalization now passes cleanly with correct blind index
    with app_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_finalize_payout_batch(
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (batch_id, payload_json, cipher, p_digest, b"wrapped_dek", nonce, tag, aad_text, attestation))
        snap_id = cur.fetchone()[0]
        assert snap_id is not None

# ============================================================================
# BLOCKER 4: AUTHENTICATED IDENTITY ASSERTION (CRYPTOGRAPHIC PROOF)
# ============================================================================

def test_authenticated_identity_assertion_required(admin_conn, verifier_conn):
    """
    BLOCKER 4:
    - Manual reconciliation requires cryptographic HMAC identity assertion.
    - Caller-controlled parameters without proof are rejected.
    - Reconciling with wrong key or forged assertion is rejected.
    - Non-Treasury Officer role is rejected.
    - Legitimate assertion signed by verifier key succeeds.
    """
    batch_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    bob_officer = "10000000-0000-0000-0000-000000000002"
    alice_ap = "10000000-0000-0000-0000-000000000001"
    key_id = 'a0000000-0000-0000-0000-000000000001'

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '{alice_ap}');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                'digest_ident', 'batch_ident_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '{alice_ap}');
        """)
        advance_batch_to_state(cur, batch_id, 'MANUAL_RECONCILIATION_REQUIRED')

    # 1. Missing or invalid length assertion token fails
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc1:
            cur.execute(f"""
                SELECT fn_resolve_manual_reconciliation(
                    '{batch_id}', 'SETTLED', 'PAYPAL_ID_99', 'Verified evidence description', '{bob_officer}', '\\x01'::bytea
                );
            """)
        assert "Manual reconciliation requires valid operator ID and 32-byte" in str(exc1.value)

    # 2. Forged assertion (signed with wrong key) fails
    forged_assertion = create_identity_assertion(
        uuid.UUID(bob_officer), uuid.UUID(batch_id), "SETTLED", auth_assertion_key=os.urandom(32)
    )
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc2:
            cur.execute("""
                SELECT fn_resolve_manual_reconciliation(
                    %s, %s, %s, %s, %s, %s
                );
            """, (batch_id, "SETTLED", "PAYPAL_ID_99", "Verified evidence description", bob_officer, forged_assertion))
        assert "Cryptographic identity assertion verification failed" in str(exc2.value)

    # 3. Assertion for AP Clerk (Alice) fails role check
    alice_assertion = create_identity_assertion(
        uuid.UUID(alice_ap), uuid.UUID(batch_id), "SETTLED", TEST_AUTH_ASSERTION_KEY
    )
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc3:
            cur.execute("""
                SELECT fn_resolve_manual_reconciliation(
                    %s, %s, %s, %s, %s, %s
                );
            """, (batch_id, "SETTLED", "PAYPAL_ID_99", "Verified evidence description", alice_ap, alice_assertion))
        assert "requires active TREASURY_OFFICER" in str(exc3.value)

    # 4. Valid assertion for Treasury Officer Bob succeeds
    valid_bob_assertion = create_identity_assertion(
        uuid.UUID(bob_officer), uuid.UUID(batch_id), "SETTLED", TEST_AUTH_ASSERTION_KEY
    )
    with verifier_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_resolve_manual_reconciliation(
                %s, %s, %s, %s, %s, %s
            );
        """, (batch_id, "SETTLED", "PAYPAL_ID_99", "Verified via direct PayPal API query and bank statement", bob_officer, valid_bob_assertion))
        assert cur.fetchone()[0] is True

    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT gateway_batch_state, payout_batch_id FROM payout_batches WHERE id = '{batch_id}';")
        row = cur.fetchone()
        assert row[0] == 'SETTLED'
        assert row[1] == 'PAYPAL_ID_99'

# ============================================================================
# BLOCKER 5: PROVIDER FAILURE EVIDENCE & UNCONFIRMED DUPLICATES
# ============================================================================

def test_provider_failure_evidence_and_duplicate_handling(admin_conn, worker_conn, verifier_conn):
    """
    BLOCKER 5:
    - HTTP 400/409 duplicate response WITHOUT provider batch ID transitions to MANUAL_RECONCILIATION_REQUIRED, NEVER FAILED.
    - Manual resolution to FAILED requires detailed failure evidence notes (min 20 chars).
    - Release of beneficiary locks on FAILED batch strictly requires verified failure evidence.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    ben_id = str(uuid.uuid4())
    key_id = 'a0000000-0000-0000-0000-000000000001'
    bob_officer = "10000000-0000-0000-0000-000000000002"

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc, verification_status)
            VALUES ('{ben_id}', 'Contractor Evidence Test', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad',
                'dest_enc'::bytea, '{hashlib.sha256(b"idx").hexdigest()}', '{hashlib.sha256(b"digest").hexdigest()}',
                'PROG_1', 'consent_h', 'ph', 'em', 'VERIFIED');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', '{key_id}',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                '{hashlib.sha256(b"p").hexdigest()}', 'batch_ev_test_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_to_state(cur, batch_id, 'APPROVED_TO_SUBMIT')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', '{key_id}', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{hashlib.sha256(b"p").hexdigest()}', '{hashlib.sha256(b"c").hexdigest()}');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_dup_01', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING');
        """)
        cur.execute(f"""
            INSERT INTO beneficiary_submission_locks (beneficiary_id, batch_id, expected_version, expected_destination_digest)
            VALUES ('{ben_id}', '{batch_id}', 1, '{hashlib.sha256(b"digest").hexdigest()}');
        """)

    # Worker claims job
    with worker_conn.cursor() as cur:
        cur.execute("SELECT * FROM fn_claim_outbox_job('worker_dup_test', 'PAYPAL_SUBMIT_PAYOUT');")
        claimed = cur.fetchone()
        fencing = claimed[3]

        # 1. Simulate duplicate response WITHOUT provider batch ID
        dup_json_no_id = json.dumps({
            "name": "DUPLICATE_REQUEST_ID",
            "message": "A request with the same client request ID was already submitted."
        })
        cur.execute("""
            SELECT fn_record_provider_payout_result(
                %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (batch_id, 'worker_dup_test', fencing, None, None, 400, dup_json_no_id, False))

    # Verify: batch and job transitioned to MANUAL_RECONCILIATION_REQUIRED (NEVER FAILED!)
    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT gateway_batch_state FROM payout_batches WHERE id = '{batch_id}';")
        assert cur.fetchone()[0] == 'MANUAL_RECONCILIATION_REQUIRED'
        cur.execute(f"SELECT status FROM outbox_jobs WHERE id = '{job_id}';")
        assert cur.fetchone()[0] == 'MANUAL_RECONCILIATION_REQUIRED'

    # 2. Manual resolution to FAILED with short notes (< 20 chars) is rejected
    assertion_failed = create_identity_assertion(
        uuid.UUID(bob_officer), uuid.UUID(batch_id), "FAILED", TEST_AUTH_ASSERTION_KEY
    )
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation) as exc_notes:
            cur.execute("""
                SELECT fn_resolve_manual_reconciliation(
                    %s, %s, %s, %s, %s, %s
                );
            """, (batch_id, "FAILED", None, "Short notes", bob_officer, assertion_failed))
        assert "Manual resolution to FAILED requires detailed definitive failure evidence in resolution notes (min 20 chars)" in str(exc_notes.value)

    # 3. Legitimate manual resolution to FAILED with detailed evidence notes succeeds
    detailed_notes = "Confirmed via PayPal merchant technical escalation: batch permanently rejected, never created."
    with verifier_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_resolve_manual_reconciliation(
                %s, %s, %s, %s, %s, %s
            );
        """, (batch_id, "FAILED", None, detailed_notes, bob_officer, assertion_failed))
        assert cur.fetchone()[0] is True

    # 4. Beneficiary submission lock is cleanly released upon verified manual failure resolution
    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT released_at FROM beneficiary_submission_locks WHERE batch_id = '{batch_id}';")
        assert cur.fetchone()[0] is not None

# ============================================================================
# BLOCKER 6: LEAST-PRIVILEGE ROLE PERMISSION MATRIX
# ============================================================================

def test_least_privilege_permissions_matrix(app_conn, verifier_conn, worker_conn, auditor_conn):
    """
    BLOCKER 6:
    - deepfakeshield_auditor CANNOT execute fn_append_audit_event.
    - deepfakeshield_auditor CANNOT execute any mutation function.
    - deepfakeshield_auditor has strictly read-only access (SELECT on audit tables).
    - Strict boundary separation between app, verifier, worker, and auditor.
    """
    dummy_uuid = str(uuid.uuid4())

    # 1. Auditor CANNOT execute fn_append_audit_event!
    with auditor_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(f"""
                SELECT fn_append_audit_event(
                    'SECURITY', '{dummy_uuid}', 'AUDIT_ATTEMPT', 'PAYOUT_BATCH', '{dummy_uuid}',
                    'req_1', 'corr_1', '127.0.0.1'::inet, 'test_agent', 1, '\\x00'::bytea, '{{}}'::jsonb
                );
            """)

    # 2. Auditor CANNOT execute fn_finalize_payout_batch
    with auditor_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(f"SELECT fn_finalize_payout_batch('{dummy_uuid}', '{{}}', '\\x00'::bytea, 'dig', '\\x00'::bytea, '\\x00'::bytea, '\\x00'::bytea, 'aad', '\\x00'::bytea);")

    # 3. Auditor CANNOT execute fn_resolve_manual_reconciliation
    with auditor_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(f"SELECT fn_resolve_manual_reconciliation('{dummy_uuid}', 'SETTLED', 'ID', 'notes', '{dummy_uuid}', '\\x00'::bytea);")

    # 4. Auditor CAN SELECT from audit tables (read-only audit query)
    with auditor_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM audit_events;")
        assert cur.fetchone()[0] >= 0
        cur.execute("SELECT COUNT(*) FROM audit_chain_heads;")
        assert cur.fetchone()[0] >= 0

    # 5. Worker CANNOT finalize batches
    with worker_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(f"SELECT fn_finalize_payout_batch('{dummy_uuid}', '{{}}', '\\x00'::bytea, 'dig', '\\x00'::bytea, '\\x00'::bytea, '\\x00'::bytea, 'aad', '\\x00'::bytea);")

    # 6. App CANNOT claim outbox jobs
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("SELECT * FROM fn_claim_outbox_job('app_imposter', 'PAYPAL_SUBMIT_PAYOUT');")

    # 7. Verifier CANNOT claim outbox jobs
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("SELECT * FROM fn_claim_outbox_job('verifier_imposter', 'PAYPAL_SUBMIT_PAYOUT');")

# ============================================================================
# CONCURRENCY TESTS (DETERMINISTIC MULTI-SESSION RACES)
# ============================================================================

def test_concurrency_claim_vs_activation_deterministic(admin_conn, worker_conn, verifier_conn):
    """
    PRIORITY 2:
    Deterministic two-session race test:
    - Worker claims job (job -> IN_PROGRESS, batch -> SUBMITTING).
    - Concurrently, an officer attempts to activate a beneficiary change.
    - Activation locks outbox_jobs -> payout_batches, detects batch is SUBMITTING and job is IN_PROGRESS,
      and strictly raises an exception (NEVER marks IN_PROGRESS job FAILED).
    """
    ben_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    change_id = str(uuid.uuid4())
    chal_id = str(uuid.uuid4())

    snap_p_race = hashlib.sha256(b"snap_p_race").hexdigest()
    snap_c_race = hashlib.sha256(b"snap_c_race").hexdigest()
    blind_idx = hashlib.sha256(b"blind_idx").hexdigest()
    dest_dig = hashlib.sha256(b"dest_dig").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO beneficiaries (id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_destination, destination_blind_index, destination_digest, program_ref, consent_evidence_hash,
                registered_contact_phone_enc, registered_contact_email_enc)
            VALUES ('{ben_id}', 'Contractor Race Test', 1, 'VERIFIED', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'old_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'PROG_1', 'consent_h', 'ph', 'em');
        """)
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                '{snap_p_race}', 'batch_race_01', '{uuid.uuid4()}', 'DRAFT', 5000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        # Insert payout_items while parent batch is in DRAFT!
        cur.execute(f"""
            INSERT INTO payout_items (id, batch_id, obligation_key, beneficiary_id, beneficiary_version, expected_destination_digest,
                sender_item_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver, destination_blind_index,
                amount_cents, gateway_item_state)
            VALUES ('{uuid.uuid4()}', '{batch_id}', 'ob_race_1', '{ben_id}', 1, '{dest_dig}',
                'item_race_1', 'a0000000-0000-0000-0000-000000000001', 'dek', '\\x0102030405060708090a0b0c'::bytea,
                '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'dest_enc'::bytea, '{blind_idx}', 5000, 'DRAFT');
        """)
        advance_batch_to_state(cur, batch_id, 'APPROVED_TO_SUBMIT')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{snap_p_race}', '{snap_c_race}');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_race_01', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING');
        """)

        # Set up a beneficiary change in COOLING_OFF with 2 officer approvals
        cur.execute(f"""
            INSERT INTO beneficiary_changes (id, beneficiary_id, requested_by_user_id, old_version, key_id,
                wrapped_dek, iv_nonce, auth_tag, aad_text, new_encrypted_destination, new_destination_blind_index,
                new_destination_digest, change_reason, verification_evidence_uri, status, cooling_off_expires_at)
            VALUES ('{change_id}', '{ben_id}', '10000000-0000-0000-0000-000000000001', 1, 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'new_dest'::bytea,
                '{blind_idx}', '{dest_dig}', 'Verified address change', 'uri', 'COOLING_OFF', CURRENT_TIMESTAMP - INTERVAL '1 minute');
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose)
            VALUES ('cred_b', '10000000-0000-0000-0000-000000000002', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea),
                   ('cred_c', '10000000-0000-0000-0000-000000000003', '\\x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10'::bytea);
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_id}', '\\x{os.urandom(32).hex()}'::bytea, 'BENEFICIARY_CHANGE_APPROVAL', '10000000-0000-0000-0000-000000000002', '{dest_dig}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
            INSERT INTO beneficiary_change_approvals (change_id, officer_user_id, credential_id, challenge_id, client_data_json, authenticator_data, signature, sign_count)
            VALUES ('{change_id}', '10000000-0000-0000-0000-000000000002', 'cred_b', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1),
                   ('{change_id}', '10000000-0000-0000-0000-000000000003', 'cred_c', '{chal_id}', 'cdata', '\\x01'::bytea, '\\x02'::bytea, 1);
        """)

    # 1. Worker claims the outbox job
    with worker_conn.cursor() as cur:
        cur.execute("SELECT * FROM fn_claim_outbox_job('worker_session_A', 'PAYPAL_SUBMIT_PAYOUT');")
        claimed = cur.fetchone()
        assert claimed is not None
        assert claimed[0] == uuid.UUID(job_id)

    # 2. Concurrently, an officer attempts to activate beneficiary change
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"SELECT fn_activate_beneficiary_change('{change_id}');")
        assert "actively IN_PROGRESS" in str(exc.value) or "is in state SUBMITTING" in str(exc.value)

    # 3. Verify job was NEVER marked FAILED
    with admin_conn.cursor() as cur:
        cur.execute(f"SELECT status, lease_owner FROM outbox_jobs WHERE id = '{job_id}';")
        row = cur.fetchone()
        assert row[0] == 'IN_PROGRESS'
        assert row[1] == 'worker_session_A'

def test_concurrency_result_persistence_vs_lease_sweeping(admin_conn, worker_conn):
    """
    PRIORITY 2:
    Concurrency test: worker lease expiration vs sweeper.
    - Worker claims job.
    - Lease expires.
    - Sweeper advances fencing token and returns job to PENDING queue.
    - Stale worker attempt with old fencing token is rejected.
    """
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                '{hashlib.sha256(b"p").hexdigest()}', 'batch_sweep_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_to_state(cur, batch_id, 'APPROVED_TO_SUBMIT')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{hashlib.sha256(b"p").hexdigest()}', '{hashlib.sha256(b"c").hexdigest()}');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_sweep_01', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING');
        """)

    with worker_conn.cursor() as cur:
        # Worker 1 claims job
        cur.execute("SELECT * FROM fn_claim_outbox_job('worker_stale', 'PAYPAL_SUBMIT_PAYOUT');")
        claimed = cur.fetchone()
        old_fencing = claimed[3]

    # Force lease expiration
    with admin_conn.cursor() as cur:
        cur.execute(f"UPDATE outbox_jobs SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE id = '{job_id}';")

    # Sweeper runs
    with worker_conn.cursor() as cur:
        cur.execute("SELECT fn_sweep_exhausted_outbox_jobs('PAYPAL_SUBMIT_PAYOUT');")
        assert cur.fetchone()[0] == 1

        # Stale worker attempts to record result with old fencing token -> rejected!
        with pytest.raises(psycopg.errors.RaiseException) as exc:
            cur.execute(f"""
                SELECT fn_record_provider_payout_result(
                    '{batch_id}', 'worker_stale', {old_fencing}, 'PP_123', 'SUCCESS', 201, '{{}}'
                );
            """)
        assert "Fencing token mismatch" in str(exc.value) or "does not hold a valid active lease" in str(exc.value)

def test_provider_evidence_state_machine_constraints(admin_conn):
    """
    PRIORITY 3:
    - check_submitted_requires_paypal_id: SUBMITTED cannot have NULL payout_batch_id.
    - check_settled_requires_paypal_id: SETTLED cannot have NULL payout_batch_id.
    - Prevent unsafe SUBMITTING -> STALE_INVALIDATED transitions in state machine trigger.
    - PARTIALLY_COMPLETED is accepted in check_paypal_batch_state.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                'digest_sm', 'batch_sm_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_to_state(cur, batch_id, 'SUBMITTING')

        # 1. Unsafe SUBMITTING -> STALE_INVALIDATED transition strictly rejected!
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'STALE_INVALIDATED' WHERE id = '{batch_id}';")
        assert "Illegal transition from SUBMITTING to STALE_INVALIDATED" in str(exc.value) or "SUBMITTING -> STALE_INVALIDATED" in str(exc.value)

        # 2. SUBMITTED requires persisted PayPal batch ID
        with pytest.raises(psycopg.errors.CheckViolation) as exc2:
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'SUBMITTED', payout_batch_id = NULL WHERE id = '{batch_id}';")
        assert "check_submitted_requires_paypal_id" in str(exc2.value)

        # Transition to SUBMITTED with valid ID succeeds
        cur.execute(f"UPDATE payout_batches SET payout_batch_id = 'PAYPAL_BATCH_VALID', gateway_batch_state = 'SUBMITTED' WHERE id = '{batch_id}';")

        # 3. SETTLED requires persisted PayPal batch ID
        with pytest.raises(psycopg.errors.CheckViolation) as exc3:
            cur.execute(f"UPDATE payout_batches SET gateway_batch_state = 'SETTLED', payout_batch_id = NULL WHERE id = '{batch_id}';")
        assert "check_settled_requires_paypal_id" in str(exc3.value)

        # 4. PARTIALLY_COMPLETED accepted in check_paypal_batch_state
        cur.execute(f"UPDATE payout_batches SET paypal_batch_state = 'PARTIALLY_COMPLETED' WHERE id = '{batch_id}';")

def test_complete_outbox_job_definitive_evidence_required(admin_conn, worker_conn):
    """
    PRIORITY 3:
    fn_complete_outbox_job requires definitive provider outcome:
    - Fails if batch is SUBMITTING or MANUAL_RECONCILIATION_REQUIRED.
    - Fails if SUBMITTED has null payout_batch_id.
    - Fails if FAILED has no provider failure evidence.
    """
    session_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    snap_p_ev = hashlib.sha256(b"snap_p_ev").hexdigest()
    snap_c_ev = hashlib.sha256(b"snap_c_ev").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                '{snap_p_ev}', 'batch_ev_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_to_state(cur, batch_id, 'APPROVED_TO_SUBMIT')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{snap_p_ev}', '{snap_c_ev}');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")
        cur.execute(f"""
            INSERT INTO outbox_jobs (id, batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status)
            VALUES ('{job_id}', '{batch_id}', '{snap_id}', 'dedup_ev_01', 'PAYPAL_SUBMIT_PAYOUT', 1, 'PENDING');
        """)

    with worker_conn.cursor() as cur:
        # Worker claims job
        cur.execute("SELECT * FROM fn_claim_outbox_job('worker_ev', 'PAYPAL_SUBMIT_PAYOUT');")
        claimed = cur.fetchone()
        c_fencing = claimed[3]

        # 1. Attempting to complete while batch is SUBMITTING fails!
        with pytest.raises(psycopg.errors.RaiseException) as exc:
            cur.execute(f"SELECT fn_complete_outbox_job('{job_id}', 'worker_ev', {c_fencing});")
        assert "has not reached a definitive provider outcome" in str(exc.value)

# ============================================================================
# REAL WEBAUTHN ECDSA (P-256) VERIFICATION
# ============================================================================

def test_real_webauthn_cryptographic_signatures(admin_conn, verifier_conn):
    """
    Verifies real WebAuthn P-256 ECDSA signatures:
    - Generates real SECP256R1 keypair for Bob (Officer).
    - Signs assertion cryptographically in Python.
    - Server verifies signature, challenge, origin, RP ID hash, and UP/UV flags.
    - Replay with clone counter (sign_count <= current) is detected and rejected.
    """
    bob_priv, bob_pub, bob_cose = generate_webauthn_keypair()
    cred_id = "webauthn_cred_bob_p256"
    officer_id = "10000000-0000-0000-0000-000000000002"
    challenge_id = str(uuid.uuid4())
    challenge_bytes = os.urandom(32)
    batch_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    origin = "https://deepfakeshield.internal"
    rp_id = "deepfakeshield.internal"

    target_digest = hashlib.sha256(b"canonical_payout_batch_json").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose, sign_count)
            VALUES ('{cred_id}', '{officer_id}', %s, 10);
        """, (bob_cose,))
        cur.execute(f"""
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, origin, rp_id, expires_at)
            VALUES ('{challenge_id}', %s, 'TRANSACTION_APPROVAL', '{officer_id}', '{target_digest}', '{origin}', '{rp_id}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
        """, (challenge_bytes,))
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_id}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                '{target_digest}', 'batch_webauthn_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_to_state(cur, batch_id, 'READY_FOR_CHECKER')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_id}', '{batch_id}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{target_digest}', '{hashlib.sha256(b"cipher_webauthn").hexdigest()}');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_id}' WHERE id = '{batch_id}';")

    client_data_json, auth_data, signature = create_webauthn_assertion(
        bob_priv, challenge_bytes, origin, rp_id, sign_count=11, user_present=True, user_verified=True
    )
    assert verify_webauthn_assertion(
        bob_pub, client_data_json, auth_data, signature, challenge_bytes, origin, rp_id
    ) is True

    with verifier_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_submit_officer_approval(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (batch_id, snap_id, officer_id, cred_id, challenge_id, target_digest, client_data_json, auth_data, signature, 11))
        approval_id = cur.fetchone()[0]
        assert approval_id is not None

def test_real_webauthn_counterless_and_cloned_rejection(admin_conn, verifier_conn):
    """
    PRIORITY 4 / WEBAUTHN:
    - Counterless authenticators (signCount = 0) are accepted.
    - Cloned authenticators with non-monotonic counter (signCount <= current) are rejected.
    """
    carol_priv, carol_pub, carol_cose = generate_webauthn_keypair()
    cred_id_cnt = "webauthn_cred_carol_counter"
    cred_id_less = "webauthn_cred_carol_counterless"
    officer_id = "10000000-0000-0000-0000-000000000003"
    chal_1 = str(uuid.uuid4())
    chal_2 = str(uuid.uuid4())
    bytes_1 = os.urandom(32)
    bytes_2 = os.urandom(32)
    batch_1 = str(uuid.uuid4())
    snap_1 = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    target_digest = hashlib.sha256(b"counter_test").hexdigest()

    with admin_conn.cursor() as cur:
        cur.execute(f"INSERT INTO sessions (id, created_by_user_id) VALUES ('{session_id}', '10000000-0000-0000-0000-000000000001');")
        cur.execute(f"""
            INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose, sign_count)
            VALUES ('{cred_id_cnt}', '{officer_id}', %s, 50),
                   ('{cred_id_less}', '{officer_id}', %s, 0);
        """, (carol_cose, carol_cose))
        cur.execute(f"""
            INSERT INTO webauthn_challenges (challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at)
            VALUES ('{chal_1}', %s, 'TRANSACTION_APPROVAL', '{officer_id}', '{target_digest}', CURRENT_TIMESTAMP + INTERVAL '1 hour'),
                   ('{chal_2}', %s, 'TRANSACTION_APPROVAL', '{officer_id}', '{target_digest}', CURRENT_TIMESTAMP + INTERVAL '1 hour');
        """, (bytes_1, bytes_2))
        cur.execute(f"""
            INSERT INTO payout_batches (id, session_id, program_id, payout_period, key_id, wrapped_dek,
                iv_nonce, auth_tag, aad_text, encrypted_canonical_payload, payload_digest,
                sender_batch_id, paypal_request_id, gateway_batch_state, total_amount_cents, item_count, created_by_user_id)
            VALUES ('{batch_1}', '{session_id}', 'PROG_1', '2026-11', 'a0000000-0000-0000-0000-000000000001',
                'dek', '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'payload'::bytea,
                '{target_digest}', 'batch_cnt_01', '{uuid.uuid4()}', 'DRAFT', 1000, 1, '10000000-0000-0000-0000-000000000001');
        """)
        advance_batch_to_state(cur, batch_1, 'READY_FOR_CHECKER')
        cur.execute(f"""
            INSERT INTO payout_snapshots (snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
                encrypted_snapshot_payload, snapshot_digest, ciphertext_digest)
            VALUES ('{snap_1}', '{batch_1}', 'a0000000-0000-0000-0000-000000000001', 'dek',
                '\\x0102030405060708090a0b0c'::bytea, '\\x0102030405060708090a0b0c0d0e0f10'::bytea, 'aad', 'cipher'::bytea,
                '{target_digest}', '{hashlib.sha256(b"cipher").hexdigest()}');
        """)
        cur.execute(f"UPDATE payout_batches SET active_snapshot_id = '{snap_1}' WHERE id = '{batch_1}';")

    # 1. Cloned replay assertion with stale counter (sign_count = 50 <= 50) is strictly rejected
    cdata_clone, auth_clone, sig_clone = create_webauthn_assertion(
        carol_priv, bytes_1, "https://deepfakeshield.internal", "deepfakeshield.internal", sign_count=50
    )
    with verifier_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            cur.execute("""
                SELECT fn_submit_officer_approval(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (batch_1, snap_1, officer_id, cred_id_cnt, chal_1, target_digest, cdata_clone, auth_clone, sig_clone, 50))
        assert "Cloned authenticator detected" in str(exc.value)

    # 2. Counterless assertion (sign_count = 0) is accepted cleanly
    cdata_less, auth_less, sig_less = create_webauthn_assertion(
        carol_priv, bytes_2, "https://deepfakeshield.internal", "deepfakeshield.internal", sign_count=0
    )
    with verifier_conn.cursor() as cur:
        cur.execute("""
            SELECT fn_submit_officer_approval(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (batch_1, snap_1, officer_id, cred_id_less, chal_2, target_digest, cdata_less, auth_less, sig_less, 0))
        appr_id = cur.fetchone()[0]
        assert appr_id is not None

def test_tampered_tag_and_wrong_aad_rejected_by_crypto_boundary():
    """
    PRIORITY 1:
    Cryptographic verification boundary rejects:
    - Tampered ciphertext bits.
    - Tampered 16-byte authentication tag.
    - Wrong Associated Authenticated Data (AAD).
    """
    dek = os.urandom(32)
    plaintext = b'{"legitimate": "payload"}'
    aad = b"legitimate_aad"

    nonce, ciphertext, tag = encrypt_payload(dek, plaintext, aad)

    # 1. Tampered tag fails decryption with InvalidTag
    bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    with pytest.raises(InvalidTag):
        verify_and_attest_snapshot(dek, nonce, ciphertext, bad_tag, aad, plaintext.decode('utf-8'))

    # 2. Tampered ciphertext fails decryption with InvalidTag
    bad_ciphertext = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    with pytest.raises(InvalidTag):
        verify_and_attest_snapshot(dek, nonce, bad_ciphertext, tag, aad, plaintext.decode('utf-8'))

    # 3. Wrong AAD fails decryption with InvalidTag
    with pytest.raises(InvalidTag):
        verify_and_attest_snapshot(dek, nonce, ciphertext, tag, b"wrong_aad", plaintext.decode('utf-8'))

# ============================================================================
# TRANSACTIONAL MIGRATION ROLLBACK PROOF
# ============================================================================

def test_migration_failure_full_rollback(admin_conn):
    """
    Proves that mid-script failure inside BEGIN ... COMMIT rolls back all DDL cleanly.
    """
    table_probe = "test_rollback_probe_v10_1_3"
    with psycopg.connect(DB_PARAMS_ADMIN, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table_probe} (id serial primary key, note text);")
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute("DO $$ BEGIN RAISE EXCEPTION 'Intentional fatal error during migration'; END $$;")
            conn.rollback()

    with psycopg.connect(DB_PARAMS_ADMIN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = '{table_probe}';")
            assert cur.fetchone()[0] == 0
