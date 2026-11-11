#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Database Connection & Seeding Module
Milestone: V10.1.3 Hackathon Delivery Sprint
Target: PostgreSQL 18.6
"""

import os
import uuid
import hashlib
import psycopg
from psycopg.rows import dict_row
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from crypto_verifier import (
    DEFAULT_ATTESTATION_SECRET,
    DEFAULT_BLIND_INDEX_KEY,
    DEFAULT_AUTH_ASSERTION_KEY,
    compute_recipient_blind_index,
    encrypt_payload,
    generate_webauthn_keypair
)

DB_HOST = os.environ.get("PGHOST", "127.0.0.1")
DB_PORT = int(os.environ.get("PGPORT", "5433"))
DB_NAME = os.environ.get("PGDATABASE", "deepfakeshield_db")
DB_ADMIN_USER = os.environ.get("PGUSER", "postgres")
DB_ADMIN_PASSWORD = os.environ.get("PGPASSWORD", "postgres")

APP_PASS = os.environ.get("APP_PASSWORD", "app_secret_pass")
VERIFIER_PASS = os.environ.get("VERIFIER_PASSWORD", "verifier_secret_pass")
WORKER_PASS = os.environ.get("WORKER_PASSWORD", "worker_secret_pass")
AUDITOR_PASS = os.environ.get("AUDITOR_PASSWORD", "auditor_secret_pass")

CONN_ADMIN = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_ADMIN_USER} password={DB_ADMIN_PASSWORD}"
CONN_APP = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_app password={APP_PASS}"
CONN_VERIFIER = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_verifier password={VERIFIER_PASS}"
CONN_WORKER = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_payout_worker password={WORKER_PASS}"
CONN_AUDITOR = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user=deepfakeshield_auditor password={AUDITOR_PASS}"

KEY_ID_ACTIVE = "a0000000-0000-0000-0000-000000000001"
USER_ALICE_MAKER = "10000000-0000-0000-0000-000000000001"
USER_BOB_CHECKER1 = "10000000-0000-0000-0000-000000000002"
USER_CAROL_CHECKER2 = "10000000-0000-0000-0000-000000000003"
USER_DAVE_AUDITOR = "10000000-0000-0000-0000-000000000004"
USER_EVE_UNAUTHORIZED = "10000000-0000-0000-0000-000000000005"

BOB_CRED_ID = "cred_bob_yubikey_01"
CAROL_CRED_ID = "cred_carol_titan_02"

BOB_DETERMINISTIC_SEED = 0x1111111122222222333333334444444455555555666666667777777788888888
CAROL_DETERMINISTIC_SEED = 0x8888888877777777666666665555555544444444333333332222222211111111

def _derive_officer_keypair(seed_val: int):
    priv = ec.derive_private_key(seed_val, ec.SECP256R1())
    pub = priv.public_key()
    cose_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub, cose_bytes

# Stored in-memory test private keys for WebAuthn simulation
OFFICER_PRIVATE_KEYS = {
    BOB_CRED_ID: ec.derive_private_key(BOB_DETERMINISTIC_SEED, ec.SECP256R1()),
    CAROL_CRED_ID: ec.derive_private_key(CAROL_DETERMINISTIC_SEED, ec.SECP256R1())
}

def _build_conn_str(role_user: str, password_env_var: str, default_password: str) -> str:
    host = os.environ.get("PGHOST", DB_HOST)
    port = os.environ.get("PGPORT", str(DB_PORT))
    dbname = os.environ.get("PGDATABASE", DB_NAME)
    password = os.environ.get(password_env_var, default_password)
    return f"host={host} port={port} dbname={dbname} user={role_user} password={password}"

def get_admin_conn(autocommit: bool = True):
    return psycopg.connect(_build_conn_str(DB_ADMIN_USER, "PGPASSWORD", DB_ADMIN_PASSWORD), autocommit=autocommit)

def get_app_conn(autocommit: bool = False):
    return psycopg.connect(_build_conn_str("deepfakeshield_app", "APP_PASSWORD", APP_PASS), autocommit=autocommit)

def get_verifier_conn(autocommit: bool = False):
    verifier_pass = os.environ.get("VERIFIER_PASSWORD", VERIFIER_PASS)
    if not verifier_pass or not verifier_pass.strip():
        raise RuntimeError("Verifier database connection unavailable: VERIFIER_PASSWORD is not configured.")
    return psycopg.connect(
        _build_conn_str("deepfakeshield_verifier", "VERIFIER_PASSWORD", VERIFIER_PASS),
        autocommit=autocommit,
    )

def get_worker_conn(autocommit: bool = False):
    return psycopg.connect(_build_conn_str("deepfakeshield_payout_worker", "WORKER_PASSWORD", WORKER_PASS), autocommit=autocommit)

def get_auditor_conn(autocommit: bool = True):
    return psycopg.connect(_build_conn_str("deepfakeshield_auditor", "AUDITOR_PASSWORD", AUDITOR_PASS), autocommit=autocommit)

def seed_demo_data():
    """Initializes and seeds authoritative base data for the demonstration."""
    global OFFICER_PRIVATE_KEYS
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            # 1. Standard users
            cur.execute(f"""
                INSERT INTO users (id, username, role, is_active)
                VALUES 
                    ('{USER_ALICE_MAKER}', 'alice_ap_maker', 'AP_CLERK', TRUE),
                    ('{USER_BOB_CHECKER1}', 'bob_checker', 'TREASURY_OFFICER', TRUE),
                    ('{USER_CAROL_CHECKER2}', 'carol_checker_two', 'TREASURY_OFFICER', TRUE),
                    ('{USER_DAVE_AUDITOR}', 'dave_auditor', 'AUDITOR', TRUE),
                    ('{USER_EVE_UNAUTHORIZED}', 'eve_unauthorized', 'AP_CLERK', TRUE)
                ON CONFLICT (id) DO UPDATE SET is_active = TRUE;
            """)

            # Grant read-only select on read tables to deepfakeshield_auditor for least privilege
            cur.execute("""
                GRANT SELECT ON users, beneficiaries, sessions, audio_assets, speaker_segments, risk_evaluations, beneficiary_submission_locks TO deepfakeshield_auditor;
            """)

            # 2. Encryption metadata
            cur.execute(f"""
                INSERT INTO encryption_key_metadata (key_id, algorithm, is_active)
                VALUES ('{KEY_ID_ACTIVE}', 'AES-256-GCM', TRUE)
                ON CONFLICT (key_id) DO UPDATE SET is_active = TRUE;
            """)

            # 3. Internal security keys (isolated)
            cur.execute(f"""
                INSERT INTO internal_security_keys (key_id, secret_attestation_key, blind_index_key, auth_assertion_key)
                VALUES (
                    '{KEY_ID_ACTIVE}',
                    decode('{DEFAULT_ATTESTATION_SECRET.hex()}', 'hex'),
                    decode('{DEFAULT_BLIND_INDEX_KEY.hex()}', 'hex'),
                    decode('{DEFAULT_AUTH_ASSERTION_KEY.hex()}', 'hex')
                )
                ON CONFLICT (key_id) DO UPDATE SET
                    secret_attestation_key = EXCLUDED.secret_attestation_key,
                    blind_index_key = EXCLUDED.blind_index_key,
                    auth_assertion_key = EXCLUDED.auth_assertion_key;
            """)

            # 4. Generate WebAuthn credentials for Bob & Carol
            bob_priv, bob_pub, bob_cose = _derive_officer_keypair(BOB_DETERMINISTIC_SEED)
            carol_priv, carol_pub, carol_cose = _derive_officer_keypair(CAROL_DETERMINISTIC_SEED)
            OFFICER_PRIVATE_KEYS[BOB_CRED_ID] = bob_priv
            OFFICER_PRIVATE_KEYS[CAROL_CRED_ID] = carol_priv

            cur.execute(f"""
                INSERT INTO webauthn_credentials (credential_id, user_id, public_key_cose, sign_count, aaguid)
                VALUES 
                    ('{BOB_CRED_ID}', '{USER_BOB_CHECKER1}', '\\x{bob_cose.hex()}'::bytea, 0, '01020304-0506-0708-090a-0b0c0d0e0f10'::uuid),
                    ('{CAROL_CRED_ID}', '{USER_CAROL_CHECKER2}', '\\x{carol_cose.hex()}'::bytea, 0, '02030405-0607-0809-0a0b-0c0d0e0f1011'::uuid)
                ON CONFLICT (credential_id) DO UPDATE SET 
                    public_key_cose = EXCLUDED.public_key_cose,
                    sign_count = EXCLUDED.sign_count;
            """)

            # 5. Seed Contractor Beneficiaries
            contractors = [
                ("30000000-0000-0000-0000-000000000001", "Acme Engineering Corp", "contractor.acme@example.com", "PROG_DEV_2026"),
                ("30000000-0000-0000-0000-000000000002", "Cloud Infrastructure Ltd", "billing.infra@example.com", "PROG_INFRA_2026"),
                ("30000000-0000-0000-0000-000000000003", "Security Red Team LLC", "payout.redteam@example.com", "PROG_SEC_2026")
            ]

            sample_dek = bytes.fromhex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
            for c_id, name, email, prog in contractors:
                blind_idx = compute_recipient_blind_index(email, DEFAULT_BLIND_INDEX_KEY)
                dest_digest = hashlib.sha256(email.encode('utf-8')).hexdigest()
                nonce, ct, tag = encrypt_payload(sample_dek, email.encode('utf-8'), b"BENEFICIARY_REGISTRY")
                cur.execute(f"""
                    INSERT INTO beneficiaries (
                        id, legal_name, version, verification_status, key_id, wrapped_dek, iv_nonce,
                        auth_tag, aad_text, encrypted_destination, destination_blind_index, destination_digest,
                        program_ref, consent_evidence_hash, registered_contact_phone_enc, registered_contact_email_enc
                    ) VALUES (
                        '{c_id}', '{name}', 1, 'VERIFIED', '{KEY_ID_ACTIVE}', '\\x{sample_dek.hex()}'::bytea,
                        '\\x{nonce.hex()}'::bytea, '\\x{tag.hex()}'::bytea, 'BENEFICIARY_REGISTRY',
                        '\\x{ct.hex()}'::bytea, '{blind_idx}', '{dest_digest}', '{prog}',
                        '{hashlib.sha256(name.encode()).hexdigest()}', '\\x01'::bytea, '\\x02'::bytea
                    ) ON CONFLICT (id) DO UPDATE SET 
                        verification_status = 'VERIFIED',
                        destination_digest = EXCLUDED.destination_digest,
                        destination_blind_index = EXCLUDED.destination_blind_index;
                """)

            # 6. Initialize Audit Chain Genesis Head
            cur.execute("""
                INSERT INTO audit_chain_heads (chain_id, head_event_digest, total_events, genesis_timestamp, last_event_at)
                VALUES (
                    'main',
                    '0000000000000000000000000000000000000000000000000000000000000000',
                    0,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                ) ON CONFLICT (chain_id) DO NOTHING;
            """)
    print("[+] Demo data seeded successfully (Users, Keys, Credentials, Beneficiaries).")

if __name__ == "__main__":
    seed_demo_data()
