#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Database Connection & Seeding Module
Milestone: V10.1.3 Hackathon Delivery Sprint
Target: PostgreSQL 18.6
"""

import os
import json
import uuid
import hashlib
from urllib.parse import urlparse
from typing import Any, Dict, Optional
import psycopg
from psycopg.rows import dict_row
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
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

# Explicit demo-only fallbacks — NEVER active unless DEMO_MODE=true is set
_DEMO_DB_PASSWORDS: Dict[str, str] = {
    "PGPASSWORD": "postgres",
    "APP_PASSWORD": "app_secret_pass",
    "VERIFIER_PASSWORD": "verifier_secret_pass",
    "WORKER_PASSWORD": "worker_secret_pass",
    "AUDITOR_PASSWORD": "auditor_secret_pass",
}

def is_demo_mode() -> bool:
    """Returns True only when DEMO_MODE=true is explicitly enabled."""
    return os.environ.get("DEMO_MODE", "false").strip().lower() == "true"

def _is_placeholder_value(value: Optional[str]) -> bool:
    if not value or not value.strip():
        return True
    stripped = value.strip()
    return stripped.startswith("<") and stripped.endswith(">")

def validate_demo_mode_paypal_safety() -> None:
    """
    Blocks DEMO_MODE=true whenever configured with PayPal production endpoints.
    Permits only deterministic SIMULATOR or explicit PayPal Sandbox hostnames.
    """
    if not is_demo_mode():
        return

    base_url = (os.environ.get("PAYPAL_BASE_URL") or "https://api-m.sandbox.paypal.com").strip()
    mode = (os.environ.get("PAYPAL_PROVIDER_MODE") or "SIMULATOR").strip().upper()
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()

    is_sandbox_host = (
        host in ("api-m.sandbox.paypal.com", "api.sandbox.paypal.com")
        or host.endswith(".sandbox.paypal.com")
    )
    is_prod_paypal_host = (
        host in ("paypal.com", "www.paypal.com", "api.paypal.com", "api-m.paypal.com")
        or (host.endswith(".paypal.com") and not is_sandbox_host)
    )

    if is_prod_paypal_host or (mode == "SANDBOX_API" and not is_sandbox_host):
        raise RuntimeError(
            f"CRITICAL SECURITY ERROR: DEMO_MODE=true cannot be used with PayPal production or non-sandbox endpoint '{base_url}'."
        )

def _resolve_db_password(password_env_var: str) -> str:
    validate_demo_mode_paypal_safety()
    configured = os.environ.get(password_env_var)
    if not _is_placeholder_value(configured):
        return configured.strip()
    if is_demo_mode() and password_env_var in _DEMO_DB_PASSWORDS:
        return _DEMO_DB_PASSWORDS[password_env_var]
    raise RuntimeError(
        f"Database connection unavailable: {password_env_var} must be explicitly configured "
        f"(or enable DEMO_MODE=true for local Sandbox demo)."
    )

DB_ADMIN_PASSWORD: Optional[str] = os.environ.get("PGPASSWORD") or (_DEMO_DB_PASSWORDS["PGPASSWORD"] if is_demo_mode() else None)
APP_PASS: Optional[str] = os.environ.get("APP_PASSWORD") or (_DEMO_DB_PASSWORDS["APP_PASSWORD"] if is_demo_mode() else None)
VERIFIER_PASS: Optional[str] = os.environ.get("VERIFIER_PASSWORD") or (_DEMO_DB_PASSWORDS["VERIFIER_PASSWORD"] if is_demo_mode() else None)
WORKER_PASS: Optional[str] = os.environ.get("WORKER_PASSWORD") or (_DEMO_DB_PASSWORDS["WORKER_PASSWORD"] if is_demo_mode() else None)
AUDITOR_PASS: Optional[str] = os.environ.get("AUDITOR_PASSWORD") or (_DEMO_DB_PASSWORDS["AUDITOR_PASSWORD"] if is_demo_mode() else None)

KEY_ID_ACTIVE = "a0000000-0000-0000-0000-000000000001"
USER_ALICE_MAKER = "10000000-0000-0000-0000-000000000001"
USER_BOB_CHECKER1 = "10000000-0000-0000-0000-000000000002"
USER_CAROL_CHECKER2 = "10000000-0000-0000-0000-000000000003"
USER_DAVE_AUDITOR = "10000000-0000-0000-0000-000000000004"
USER_EVE_UNAUTHORIZED = "10000000-0000-0000-0000-000000000005"

BOB_CRED_ID = "cred_bob_yubikey_01"
CAROL_CRED_ID = "cred_carol_titan_02"

# Demo-only deterministic seeds — NEVER active outside explicit DEMO_MODE=true
BOB_DETERMINISTIC_SEED = 0x1111111122222222333333334444444455555555666666667777777788888888
CAROL_DETERMINISTIC_SEED = 0x8888888877777777666666665555555544444444333333332222222211111111

def _derive_officer_keypair(seed_val: int):
    priv = ec.derive_private_key(seed_val, ec.SECP256R1())
    pub = priv.public_key()
    cose_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub, cose_bytes

def _load_pem_key(pem_str: str):
    normalized = pem_str.replace("\\n", "\n").encode("utf-8")
    return load_pem_private_key(normalized, password=None)

def load_officer_private_keys() -> Dict[str, Any]:
    """
    Loads officer WebAuthn private keys from explicit environment configuration.
    Deterministic demo seeds are permitted ONLY when DEMO_MODE=true (non-production PayPal only).
    Returns an empty mapping in normal startup when no explicit env signing keys are supplied.
    """
    validate_demo_mode_paypal_safety()
    keys: Dict[str, Any] = {}

    env_json = os.environ.get("OFFICER_SIGNING_KEYS_JSON")
    if not _is_placeholder_value(env_json):
        parsed = json.loads(env_json)
        if not isinstance(parsed, dict):
            raise RuntimeError("OFFICER_SIGNING_KEYS_JSON must be a JSON object mapping credential_id -> PEM private key.")
        for cred_id, pem_val in parsed.items():
            if not _is_placeholder_value(str(pem_val)):
                keys[str(cred_id)] = _load_pem_key(str(pem_val))

    bob_pem = os.environ.get("BOB_SIGNING_PRIVATE_KEY_PEM")
    if not _is_placeholder_value(bob_pem):
        keys[BOB_CRED_ID] = _load_pem_key(bob_pem)

    carol_pem = os.environ.get("CAROL_SIGNING_PRIVATE_KEY_PEM")
    if not _is_placeholder_value(carol_pem):
        keys[CAROL_CRED_ID] = _load_pem_key(carol_pem)

    if is_demo_mode():
        keys.setdefault(BOB_CRED_ID, ec.derive_private_key(BOB_DETERMINISTIC_SEED, ec.SECP256R1()))
        keys.setdefault(CAROL_CRED_ID, ec.derive_private_key(CAROL_DETERMINISTIC_SEED, ec.SECP256R1()))

    return keys

def get_officer_private_keys() -> Dict[str, Any]:
    """Dynamically resolves officer signing keys using current environment/DEMO_MODE policy."""
    return load_officer_private_keys()

# Empty at normal startup unless explicit PEM signing keys or DEMO_MODE=true are configured
OFFICER_PRIVATE_KEYS: Dict[str, Any] = load_officer_private_keys()

def _build_conn_str(role_user: str, password_env_var: str, default_password: Optional[str] = None) -> str:
    host = os.environ.get("PGHOST", DB_HOST)
    port = os.environ.get("PGPORT", str(DB_PORT))
    dbname = os.environ.get("PGDATABASE", DB_NAME)
    configured = os.environ.get(password_env_var)
    if not _is_placeholder_value(configured):
        password = configured.strip()
    elif default_password and not _is_placeholder_value(default_password) and is_demo_mode():
        password = default_password
    else:
        password = _resolve_db_password(password_env_var)
    return f"host={host} port={port} dbname={dbname} user={role_user} password={password}"

def get_admin_conn(autocommit: bool = True):
    return psycopg.connect(_build_conn_str(DB_ADMIN_USER, "PGPASSWORD"), autocommit=autocommit)

def get_app_conn(autocommit: bool = False):
    return psycopg.connect(_build_conn_str("deepfakeshield_app", "APP_PASSWORD"), autocommit=autocommit)

def get_verifier_conn(autocommit: bool = False):
    return psycopg.connect(_build_conn_str("deepfakeshield_verifier", "VERIFIER_PASSWORD"), autocommit=autocommit)

def get_worker_conn(autocommit: bool = False):
    return psycopg.connect(_build_conn_str("deepfakeshield_payout_worker", "WORKER_PASSWORD"), autocommit=autocommit)

def get_auditor_conn(autocommit: bool = True):
    return psycopg.connect(_build_conn_str("deepfakeshield_auditor", "AUDITOR_PASSWORD"), autocommit=autocommit)

def seed_demo_data():
    """Initializes and seeds authoritative base data strictly in DEMO_MODE=true (non-production only)."""
    global OFFICER_PRIVATE_KEYS
    if not is_demo_mode():
        raise RuntimeError(
            "CRITICAL SECURITY ERROR: seed_demo_data() is restricted to DEMO_MODE=true and cannot run at normal startup."
        )
    validate_demo_mode_paypal_safety()
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
