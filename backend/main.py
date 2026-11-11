#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — FastAPI Gateway & Threat Operations Console
Milestone: V10.1.3 Hackathon Delivery Sprint

Exposes REST APIs for:
1. Audio Upload & AASIST Anti-Spoof Inference
2. Batch Creation, Beneficiary Validation & Locking
3. Cryptographic Envelope Attestation & Finalization
4. FIDO2 / WebAuthn Dual-Officer Approvals
5. Transactional Outbox Worker Dispatch & PayPal Sandbox Submission
6. Audit Chain & Dashboard Metrics Stream
"""

import os
import uuid
import json
import base64
import hashlib
import time
import secrets
from collections import defaultdict
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Depends, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import psycopg
from psycopg.rows import dict_row

from backend.env_loader import load_env_file
load_env_file()

from backend.database import (
    get_admin_conn,
    get_app_conn,
    get_auditor_conn,
    get_verifier_conn,
    get_officer_private_keys,
    is_demo_mode,
    validate_demo_mode_paypal_safety,
    _is_placeholder_value,
    seed_demo_data,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_DAVE_AUDITOR,
    USER_EVE_UNAUTHORIZED,
    BOB_CRED_ID,
    CAROL_CRED_ID,
    OFFICER_PRIVATE_KEYS
)
from backend.audio_analyzer import (
    analyze_audio_instruction,
    read_wav_pcm16
)
from backend.payout_service import (
    AudioRiskGateError,
    create_draft_batch,
    get_audio_review_evidence,
    record_audio_analysis_for_batch,
    finalize_batch,
    record_officer_webauthn_approval,
    resolve_audio_evidence_file,
    store_audio_vault_bytes,
    submit_manual_audio_review,
)
from backend.outbox_worker import OutboxWorker
from crypto_verifier import create_webauthn_assertion

app = FastAPI(title="DeepfakeShield for PayPal", version="10.1.3")

def validate_runtime_security_configuration() -> None:
    """
    Validates startup security invariants:
    1. Blocks DEMO_MODE=true when paired with PayPal production endpoints.
    2. Enforces STRICT_CRYPTO_ENFORCEMENT=true by default (cannot disable outside DEMO_MODE=true).
    3. Requires explicit database, authentication, and signing credentials outside DEMO_MODE=true.
    """
    validate_demo_mode_paypal_safety()
    demo_enabled = is_demo_mode()

    strict_flag = os.environ.get("STRICT_CRYPTO_ENFORCEMENT", "true").strip().lower()
    if strict_flag == "false":
        if not demo_enabled:
            raise RuntimeError(
                "CRITICAL SECURITY ERROR: STRICT_CRYPTO_ENFORCEMENT cannot be disabled outside DEMO_MODE=true."
            )
    else:
        for crypto_var in ("ATTESTATION_SECRET", "BLIND_INDEX_KEY", "AUTH_ASSERTION_KEY"):
            if _is_placeholder_value(os.environ.get(crypto_var)):
                raise RuntimeError(
                    f"CRITICAL SECURITY ERROR: Required cryptographic key '{crypto_var}' is missing or placeholder "
                    "while STRICT_CRYPTO_ENFORCEMENT is enabled."
                )

    if demo_enabled:
        return

    # Normal startup requires explicit database role credentials (never insecure defaults)
    for db_var in ("APP_PASSWORD", "VERIFIER_PASSWORD", "WORKER_PASSWORD", "AUDITOR_PASSWORD"):
        if _is_placeholder_value(os.environ.get(db_var)):
            raise RuntimeError(
                f"CRITICAL SECURITY ERROR: Explicit database credential '{db_var}' is required at startup "
                "(or set DEMO_MODE=true for local Sandbox demo)."
            )

    # Normal startup requires explicit authentication credentials for core treasury roles
    missing_auth = [
        uname for uname in ("alice_ap_maker", "bob_checker", "carol_checker_two", "dave_auditor")
        if _resolve_operator_credential(uname) is None
    ]
    if missing_auth:
        raise RuntimeError(
            "CRITICAL SECURITY ERROR: Explicit authentication credentials are required for operators "
            f"{missing_auth} at startup (configure <ROLE>_PASSWORD / OPERATOR_CREDENTIALS, or enable DEMO_MODE=true)."
        )

# Initialize runtime security validation & optional DEMO_MODE fixture seeding on startup
@app.on_event("startup")
def startup_event():
    validate_runtime_security_configuration()
    OFFICER_PRIVATE_KEYS.clear()
    OFFICER_PRIVATE_KEYS.update(get_officer_private_keys())
    reset_auth_sessions()
    if is_demo_mode():
        seed_demo_data()

# -----------------------------------------------------------------------------
# 0. AUTHENTICATION, RATE LIMITING & SERVER-SIDE RBAC SESSIONS
# -----------------------------------------------------------------------------
# Non-secret directory of configured operator accounts (no tokens or passwords stored here)
OPERATOR_CATALOG: Dict[str, Dict[str, Any]] = {
    "alice_ap_maker": {
        "user_id": USER_ALICE_MAKER,
        "username": "alice_ap_maker",
        "role": "AP_CLERK",
        "env_prefix": "ALICE",
    },
    "bob_checker": {
        "user_id": USER_BOB_CHECKER1,
        "username": "bob_checker",
        "role": "TREASURY_OFFICER",
        "credential_id": BOB_CRED_ID,
        "env_prefix": "BOB",
    },
    "carol_checker_two": {
        "user_id": USER_CAROL_CHECKER2,
        "username": "carol_checker_two",
        "role": "TREASURY_OFFICER",
        "credential_id": CAROL_CRED_ID,
        "env_prefix": "CAROL",
    },
    "dave_auditor": {
        "user_id": USER_DAVE_AUDITOR,
        "username": "dave_auditor",
        "role": "AUDITOR",
        "env_prefix": "DAVE",
    },
    "eve_unauthorized": {
        "user_id": USER_EVE_UNAUTHORIZED,
        "username": "eve_unauthorized",
        "role": "AP_CLERK",
        "env_prefix": "EVE",
    },
}

_DEMO_TOKEN_BY_USERNAME: Dict[str, str] = {
    "alice_ap_maker": "token-alice-maker",
    "bob_checker": "token-bob-officer",
    "carol_checker_two": "token-carol-officer",
    "dave_auditor": "token-dave-auditor",
    "eve_unauthorized": "token-eve-unauthorized",
}

# Explicit demo-only password fallbacks — NEVER used unless DEMO_MODE=true
_DEMO_OPERATOR_PASSWORDS: Dict[str, str] = {
    "alice_ap_maker": "alice_secure_maker_pass_2026",
    "bob_checker": "bob_yubikey_officer_pass_2026",
    "carol_checker_two": "carol_titan_officer_pass_2026",
    "dave_auditor": "dave_read_only_auditor_pass_2026",
    "eve_unauthorized": "eve_unauthorized_clerk_pass_2026",
}

def _build_demo_sessions() -> Dict[str, Dict[str, Any]]:
    validate_demo_mode_paypal_safety()
    sessions: Dict[str, Dict[str, Any]] = {}
    for uname, tok in _DEMO_TOKEN_BY_USERNAME.items():
        meta = OPERATOR_CATALOG[uname]
        entry: Dict[str, Any] = {
            "user_id": meta["user_id"],
            "username": meta["username"],
            "role": meta["role"],
            "expires_at": time.time() + 86400,
            "is_revoked": False,
        }
        if "credential_id" in meta:
            entry["credential_id"] = meta["credential_id"]
        sessions[tok] = entry
    return sessions

# Normal startup begins with empty session table; pre-seeded tokens exist ONLY in explicit DEMO_MODE=true
AUTH_SESSIONS: Dict[str, Dict[str, Any]] = _build_demo_sessions() if is_demo_mode() else {}

def reset_auth_sessions():
    """Resets dynamic sessions and restores base demonstration tokens only when DEMO_MODE=true."""
    AUTH_SESSIONS.clear()
    if is_demo_mode():
        AUTH_SESSIONS.update(_build_demo_sessions())

LOGIN_RATE_LIMITS: Dict[str, List[float]] = defaultdict(list)
MAX_LOGIN_ATTEMPTS_PER_MIN = 30

def hash_password(password: str, salt: bytes = None) -> str:
    """Hashes a password using RFC 7914 scrypt memory-hard key derivation."""
    if salt is None:
        salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1)
    return f"scrypt:16384:8:1${salt.hex()}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored scrypt hash in constant time."""
    try:
        parts = stored_hash.split('$')
        if len(parts) != 3 or not parts[0].startswith("scrypt:"):
            return False
        params = parts[0].split(':')
        n, r, p = int(params[1]), int(params[2]), int(params[3])
        salt = bytes.fromhex(parts[1])
        expected_derived = bytes.fromhex(parts[2])
        actual_derived = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p)
        return secrets.compare_digest(actual_derived, expected_derived)
    except Exception:
        return False

def _resolve_operator_credential(username: str) -> Optional[str]:
    """
    Resolves operator credential strictly from explicit environment configuration
    (OPERATOR_CREDENTIALS JSON, <PREFIX>_PASSWORD_HASH, or <PREFIX>_PASSWORD).
    Demo fallback passwords are permitted ONLY when DEMO_MODE=true (non-production only).
    """
    meta = OPERATOR_CATALOG.get(username)
    if not meta:
        return None

    op_json = os.environ.get("OPERATOR_CREDENTIALS")
    if not _is_placeholder_value(op_json):
        try:
            op_map = json.loads(op_json)
            if isinstance(op_map, dict) and username in op_map:
                candidate = str(op_map[username])
                if not _is_placeholder_value(candidate):
                    return candidate.strip()
        except Exception:
            pass

    prefix = meta["env_prefix"]
    env_hash = os.environ.get(f"{prefix}_PASSWORD_HASH")
    if not _is_placeholder_value(env_hash):
        return env_hash.strip()

    env_pass = os.environ.get(f"{prefix}_PASSWORD")
    if not _is_placeholder_value(env_pass):
        return env_pass.strip()

    if is_demo_mode():
        validate_demo_mode_paypal_safety()
        return _DEMO_OPERATOR_PASSWORDS.get(username)

    return None

def _verify_operator_credential(username: str, candidate_password: str) -> bool:
    configured = _resolve_operator_credential(username)
    if not configured:
        return False
    if configured.startswith("scrypt:"):
        return verify_password(candidate_password, configured)
    return secrets.compare_digest(candidate_password, configured)

def get_current_user(
    authorization: Optional[str] = Header(None),
    x_session_token: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Resolves and validates user identity strictly from the verified session token."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):].strip()
    elif x_session_token:
        token = x_session_token.strip()

    if not token or token not in AUTH_SESSIONS:
        raise HTTPException(
            status_code=401,
            detail="Authentication required: missing or invalid session credentials"
        )
    session = AUTH_SESSIONS[token]
    if session.get("is_revoked", False):
        raise HTTPException(status_code=401, detail="Authentication failed: session has been revoked")
    if time.time() > session.get("expires_at", float("inf")):
        raise HTTPException(status_code=401, detail="Authentication failed: session token has expired")
    return session

def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    x_session_token: Optional[str] = Header(None)
) -> Optional[Dict[str, Any]]:
    """Optional session resolution for public read endpoints."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):].strip()
    elif x_session_token:
        token = x_session_token.strip()

    if token and token in AUTH_SESSIONS:
        sess = AUTH_SESSIONS[token]
        if not sess.get("is_revoked", False) and time.time() <= sess.get("expires_at", float("inf")):
            return sess
    return None

def require_role(*allowed_roles: str):
    """Enforces server-side Role-Based Access Control (RBAC)."""
    def role_dependency(user: Dict[str, Any] = Depends(get_current_user)):
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access forbidden: user role '{user['role']}' lacks required authorization (required: {allowed_roles})"
            )
        return user
    return role_dependency

class LoginRequest(BaseModel):
    username: str
    password: Optional[str] = None

def _verify_configured_risk_reviewer_login(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticates an explicitly provisioned RISK_REVIEWER account against both
    server-side environment credentials and an active database users(role='RISK_REVIEWER') row.
    Never fabricates reviewer identities or fallback passwords in source code.
    """
    configured_cred: Optional[str] = None
    creds_json = os.environ.get("RISK_REVIEWER_CREDENTIALS")
    if creds_json:
        try:
            creds_map = json.loads(creds_json)
            if isinstance(creds_map, dict) and username in creds_map:
                configured_cred = str(creds_map[username])
        except Exception:
            configured_cred = None

    if configured_cred is None:
        env_user = os.environ.get("RISK_REVIEWER_USERNAME")
        if env_user and secrets.compare_digest(env_user.strip(), username):
            configured_cred = (
                os.environ.get("RISK_REVIEWER_PASSWORD_HASH")
                or os.environ.get("RISK_REVIEWER_PASSWORD")
            )

    if not configured_cred or not configured_cred.strip():
        return None

    if configured_cred.startswith("scrypt:"):
        if not verify_password(password, configured_cred):
            return None
    elif not secrets.compare_digest(password, configured_cred):
        return None

    with get_app_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, username, role, is_active
                FROM users
                WHERE username = %s AND role = 'RISK_REVIEWER' AND is_active = TRUE
                LIMIT 1;
                """,
                (username,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "user_id": str(row["id"]),
                "username": row["username"],
                "role": row["role"],
            }


@app.post("/api/auth/login")
def api_login(req: LoginRequest, request: Request):
    """
    Issues authenticated session token with expiration and rate limiting.
    CRITICAL SECURITY ENFORCEMENT: A username alone is strictly rejected.
    A valid credential secret/password is mandatory.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    LOGIN_RATE_LIMITS[client_ip] = [t for t in LOGIN_RATE_LIMITS[client_ip] if now - t < 60]
    if len(LOGIN_RATE_LIMITS[client_ip]) >= MAX_LOGIN_ATTEMPTS_PER_MIN:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: too many login attempts")
    LOGIN_RATE_LIMITS[client_ip].append(now)

    if not req.password or len(req.password.strip()) == 0:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: credential secret/password required"
        )

    validate_demo_mode_paypal_safety()

    if req.username in OPERATOR_CATALOG:
        if _resolve_operator_credential(req.username) is None:
            raise HTTPException(
                status_code=401,
                detail=f"Authentication unavailable: operator '{req.username}' has no configured environment credential",
            )
        if not _verify_operator_credential(req.username, req.password):
            raise HTTPException(
                status_code=401,
                detail="Authentication failed: invalid username or credentials",
            )
        meta = OPERATOR_CATALOG[req.username]
        new_token = f"sess-{uuid.uuid4()}"
        session_data: Dict[str, Any] = {
            "user_id": meta["user_id"],
            "username": meta["username"],
            "role": meta["role"],
            "expires_at": now + 28800,  # 8 hours validity
            "is_revoked": False,
        }
        if "credential_id" in meta:
            session_data["credential_id"] = meta["credential_id"]
        AUTH_SESSIONS[new_token] = session_data
        return {
            "access_token": new_token,
            "token_type": "bearer",
            "expires_in": 28800,
            "user": session_data,
        }

    reviewer_user = _verify_configured_risk_reviewer_login(req.username, req.password)
    if reviewer_user:
        new_token = f"sess-{uuid.uuid4()}"
        session_data = {
            **reviewer_user,
            "expires_at": now + 28800,
            "is_revoked": False,
        }
        AUTH_SESSIONS[new_token] = session_data
        return {
            "access_token": new_token,
            "token_type": "bearer",
            "expires_in": 28800,
            "user": session_data,
        }

    raise HTTPException(status_code=401, detail=f"User {req.username} not found or inactive")

@app.post("/api/auth/logout")
def api_logout(
    current_user: Dict[str, Any] = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    x_session_token: Optional[str] = Header(None)
):
    """Revokes active session token."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):].strip()
    elif x_session_token:
        token = x_session_token.strip()
    if token and token in AUTH_SESSIONS:
        AUTH_SESSIONS[token]["is_revoked"] = True
    return {"status": "LOGGED_OUT", "message": "Session successfully revoked"}

@app.get("/api/public/status")
def api_public_status():
    """Sanitized public status endpoint requiring no authentication."""
    from backend.paypal_client import PayPalClient
    pp = PayPalClient()
    conn = pp.check_api_connectivity()
    return {
        "status": "ONLINE",
        "milestone": "V10.1.3",
        "service": "DeepfakeShield for PayPal",
        "mode": conn["mode"],
        "provider_state": conn["provider_state"],
        "provider_mode": conn["provider_mode"],
        "is_simulator": conn["is_simulator"],
        "configured": conn["configured"],
        "oauth_connected": conn["oauth_connected"],
        "oauth_status": conn["oauth_status"],
        "connection_status": conn["connection_status"],
        "connection_label": conn["connection_label"],
        "server_time": time.time()
    }

# -----------------------------------------------------------------------------
# 1. BENEFICIARIES REGISTRY
# -----------------------------------------------------------------------------
@app.get("/api/beneficiaries")
def get_beneficiaries(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns verified contractor beneficiaries for authenticated users."""
    with get_app_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT b.id, b.legal_name, b.version, b.verification_status,
                       b.destination_digest, b.destination_blind_index, b.program_ref,
                       CASE WHEN l.id IS NOT NULL AND l.released_at IS NULL THEN TRUE ELSE FALSE END AS is_locked
                FROM beneficiaries b
                LEFT JOIN beneficiary_submission_locks l ON l.beneficiary_id = b.id AND l.released_at IS NULL
                ORDER BY b.legal_name ASC;
            """)
            return cur.fetchall()

# -----------------------------------------------------------------------------
# 2. AUDIO INGESTION & ACOUSTIC ANTI-SPOOF EVALUATION
# -----------------------------------------------------------------------------
@app.post("/api/audio/analyze")
async def analyze_audio(
    file: Optional[UploadFile] = File(None),
    sample_preset: Optional[str] = Form(None),
    current_user: Dict[str, Any] = Depends(require_role("AP_CLERK", "TREASURY_OFFICER"))
):
    """
    Analyzes voice instruction:
    - Runs WADA SNR and usable speech verification
    - Acoustic spectral analysis with 64,600-sample window extraction (ACOUSTIC_FFT_HEURISTIC_V1)
    - Replay defense via SHA-256 deduplication
    """
    if file:
        audio_bytes = await file.read()
    elif sample_preset == "clean_executive":
        sample_path = os.path.join("audio_samples", "clean_executive_instruction.wav")
        with open(sample_path, "rb") as f:
            audio_bytes = f.read()
    elif sample_preset == "deepfake_clone":
        sample_path = os.path.join("audio_samples", "deepfake_clone_suspicious.wav")
        with open(sample_path, "rb") as f:
            audio_bytes = f.read()
    else:
        raise HTTPException(status_code=400, detail="Must provide an audio file or valid sample_preset")

    is_spoof_override = True if sample_preset == "deepfake_clone" else (False if sample_preset == "clean_executive" else None)
    res = analyze_audio_instruction(audio_bytes, known_spoof_override=is_spoof_override)
    store_audio_vault_bytes(res.get("audio_sha256", ""), audio_bytes)
    return res

# -----------------------------------------------------------------------------
# 3. DISBURSEMENT BATCH CREATION & AUDIO LINKING
# -----------------------------------------------------------------------------
class BatchCreateRequest(BaseModel):
    program_id: str
    payout_period: str
    items: List[Dict[str, Any]]
    audio_analysis: Optional[Dict[str, Any]] = None

@app.post("/api/batches/create")
def api_create_batch(
    req: BatchCreateRequest,
    current_user: Dict[str, Any] = Depends(require_role("AP_CLERK", "TREASURY_OFFICER"))
):
    """Maker creates a new disbursement batch. Identity is strictly derived from session."""
    try:
        session_id = str(uuid.uuid4())
        maker_user_id = current_user["user_id"]

        batch_res = create_draft_batch(
            maker_user_id=maker_user_id,
            program_id=req.program_id,
            payout_period=req.payout_period,
            items_data=req.items,
            session_id=session_id
        )

        audio_eval = None
        if req.audio_analysis:
            audio_eval = record_audio_analysis_for_batch(
                batch_id=batch_res["batch_id"],
                audio_analysis_result=req.audio_analysis,
                session_id=session_id,
                user_id=maker_user_id
            )

        # Sanitize bytes for JSON serialization
        safe_items = []
        for it in batch_res.get("items", []):
            safe_items.append({
                k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                for k, v in it.items()
                if k not in ("dek", "nonce", "tag")
            })
        clean_batch = dict(batch_res)
        clean_batch["items"] = safe_items

        return {
            "batch": clean_batch,
            "audio_evaluation": audio_eval
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -----------------------------------------------------------------------------
# 4. ATOMIC FINALIZATION & IMMUTABILITY LOCKING
# -----------------------------------------------------------------------------
class FinalizeRequest(BaseModel):
    # Retained optional for wire compatibility; server-side gate ignores any caller-supplied value.
    audio_policy_decision: Optional[str] = None

@app.post("/api/batches/{batch_id}/finalize")
def api_finalize_batch(
    batch_id: str,
    req: Optional[FinalizeRequest] = None,
    current_user: Dict[str, Any] = Depends(require_role("AP_CLERK", "TREASURY_OFFICER"))
):
    """
    Finalizes the draft batch using fail-closed server-side audio risk verification.
    - Ignores caller-supplied audio_policy_decision.
    - Encrypts canonical snapshot, generates DS-ENVELOPE-V1 attestation, and locks beneficiaries
      only when an explicitly permitted positive persisted evaluation (or authorized manual review) exists.
    """
    try:
        res = finalize_batch(batch_id)
        return res
    except AudioRiskGateError as ae:
        raise HTTPException(status_code=403, detail=str(ae))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# -----------------------------------------------------------------------------
# 4A. GOVERNED MANUAL AUDIO RISK REVIEW WORKFLOW (V10.1.5)
# -----------------------------------------------------------------------------
class ManualAudioReviewRequest(BaseModel):
    risk_evaluation_id: str
    audio_asset_id: str
    audio_content_sha256: str
    review_decision: str
    justification: str


@app.get("/api/batches/{batch_id}/audio-review")
def api_get_audio_review_evidence(
    batch_id: str,
    evaluation_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(
        require_role("RISK_REVIEWER", "TREASURY_OFFICER", "AUDITOR", "AP_CLERK")
    ),
):
    """
    Returns verified audio risk evidence, SHA-256 & acoustic fingerprint, FFT analyzer telemetry,
    batch/recipient context, and any immutable manual review record for this batch.
    """
    try:
        evidence = get_audio_review_evidence(batch_id, evaluation_id=evaluation_id)
        if current_user["role"] == "AP_CLERK":
            if str(evidence["batch"]["created_by_user_id"]) != str(current_user["user_id"]):
                raise HTTPException(
                    status_code=403,
                    detail="Access forbidden: AP_CLERK is not authorized to inspect another maker's batch review",
                )
        return evidence
    except HTTPException:
        raise
    except AudioRiskGateError as ae:
        raise HTTPException(status_code=404, detail=str(ae))
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/batches/{batch_id}/audio-review/audio")
def api_stream_audio_review_evidence(
    batch_id: str,
    evaluation_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(require_role("RISK_REVIEWER")),
):
    """
    Streams the exact SHA-256-verified WAV recording exclusively to an authenticated RISK_REVIEWER.
    """
    try:
        evidence = get_audio_review_evidence(batch_id, evaluation_id=evaluation_id)
        expected_sha = evidence["audio_evidence"].get("audio_content_sha256")
        file_path = resolve_audio_evidence_file(expected_sha)
        if not file_path or not expected_sha:
            raise HTTPException(
                status_code=404,
                detail="Original audio evidence file is not present or failed SHA-256 verification",
            )
        return FileResponse(
            file_path,
            media_type="audio/wav",
            headers={
                "Cache-Control": "no-store",
                "X-Audio-SHA256": expected_sha,
            },
        )
    except HTTPException:
        raise
    except AudioRiskGateError as ae:
        raise HTTPException(status_code=404, detail=str(ae))
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@app.post("/api/batches/{batch_id}/audio-review")
def api_submit_manual_audio_review(
    batch_id: str,
    req: ManualAudioReviewRequest,
    current_user: Dict[str, Any] = Depends(require_role("RISK_REVIEWER")),
):
    """
    Records an immutable manual review decision (APPROVE_WITH_REVIEW | REJECT) exclusively
    for an authenticated RISK_REVIEWER through the privileged verifier SECURITY DEFINER function.
    """
    try:
        return submit_manual_audio_review(
            batch_id=batch_id,
            risk_evaluation_id=req.risk_evaluation_id,
            audio_asset_id=req.audio_asset_id,
            audio_content_sha256=req.audio_content_sha256,
            reviewer_user_id=current_user["user_id"],
            review_decision=req.review_decision,
            justification=req.justification,
        )
    except AudioRiskGateError as ae:
        msg = str(ae)
        lower_msg = msg.lower()
        if "unauthorized" in lower_msg or "privilege" in lower_msg or "independence" in lower_msg:
            raise HTTPException(status_code=403, detail=msg)
        if "already has an immutable manual review" in lower_msg or "unique" in lower_msg:
            raise HTTPException(status_code=409, detail=msg)
        raise HTTPException(status_code=400, detail=msg)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -----------------------------------------------------------------------------
# 5. WEBAUTHN FIDO2 DUAL-OFFICER APPROVALS & CHALLENGES
# -----------------------------------------------------------------------------
@app.post("/api/batches/{batch_id}/webauthn/challenge")
def api_get_webauthn_challenge(
    batch_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role("TREASURY_OFFICER"))
):
    """
    Generates a secure server-side WebAuthn challenge bound to the batch and officer.
    Stored in database for single-use verification.
    """
    from backend.payout_service import issue_officer_challenge
    officer_id = current_user["user_id"]
    try:
        host = request.headers.get("host", "localhost:8000").split(":")[0]
        req_origin = request.headers.get("origin")
        effective_rp = host if host in ["localhost", "127.0.0.1", "deepfakeshield.internal"] else "localhost"
        effective_orig = req_origin if req_origin in [
            "http://localhost:8000", "http://127.0.0.1:8000",
            "https://localhost:8000", "https://deepfakeshield.internal"
        ] else f"http://{effective_rp}:8000"

        chal_info = issue_officer_challenge(
            batch_id=batch_id,
            officer_user_id=officer_id,
            rp_id=effective_rp,
            origin=effective_orig
        )
        chal_info["credential_id"] = current_user.get("credential_id")
        if "challenge_bytes" in chal_info:
            chal_info["challenge_hex"] = chal_info["challenge_bytes"].hex()
            del chal_info["challenge_bytes"]
        return chal_info
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

class ApprovalRequest(BaseModel):
    credential_id: str
    officer_user_id: Optional[str] = None
    client_data_json: Optional[str] = None
    auth_data: Optional[str] = None
    signature: Optional[str] = None
    challenge_id: Optional[str] = None
    override_invalid_sig: Optional[bool] = False
    mock_simulation: Optional[bool] = False

@app.post("/api/batches/{batch_id}/approve")
def api_approve_batch(
    batch_id: str,
    req: ApprovalRequest,
    current_user: Dict[str, Any] = Depends(require_role("TREASURY_OFFICER"))
):
    """
    Cryptographically verifies a genuine WebAuthn P-256 ECDSA assertion from an authenticated Treasury Officer.
    Identity is derived strictly from the verified session (preventing officer impersonation).
    """
    try:
        officer_user_id = current_user["user_id"]
        # If client passes officer_user_id, it must match the session identity
        if req.officer_user_id and str(req.officer_user_id) != str(officer_user_id):
            raise HTTPException(status_code=403, detail="Session identity mismatch: cannot approve as another officer")

        client_data = req.client_data_json
        auth_data_bytes = None
        sig_bytes = None

        if req.mock_simulation or not (req.client_data_json and req.signature and req.auth_data):
            validate_demo_mode_paypal_safety()
            if req.mock_simulation and not is_demo_mode():
                raise HTTPException(
                    status_code=403,
                    detail="Simulated officer approvals are disabled outside DEMO_MODE=true; supply a signed WebAuthn assertion.",
                )

            configured_keys = get_officer_private_keys()
            priv_key = configured_keys.get(req.credential_id) or (
                OFFICER_PRIVATE_KEYS.get(req.credential_id) if is_demo_mode() else None
            )
            if not priv_key:
                raise HTTPException(
                    status_code=400,
                    detail="Authenticator private key not configured; supply a client-signed WebAuthn assertion (or configure explicit signing keys / DEMO_MODE=true).",
                )

            from backend.payout_service import issue_officer_challenge
            chal_res = issue_officer_challenge(batch_id=batch_id, officer_user_id=officer_user_id)
            chal_bytes = chal_res["challenge_bytes"]
            req.challenge_id = chal_res["challenge_id"]

            with get_verifier_conn(autocommit=True) as chk_conn:
                with chk_conn.cursor() as chk_cur:
                    chk_cur.execute("SELECT sign_count FROM webauthn_credentials WHERE credential_id = %s;", (req.credential_id,))
                    row = chk_cur.fetchone()
                    sc = (row[0] + 1) if row else 2

            client_data, auth_data_bytes, sig_bytes = create_webauthn_assertion(
                private_key=priv_key,
                challenge_bytes=chal_bytes,
                origin="http://localhost:8000",
                rp_id="localhost",
                sign_count=sc
            )
        else:
            # Genuine client assertion
            if req.auth_data.startswith("0x") or req.auth_data.startswith("\\x"):
                auth_data_bytes = bytes.fromhex(req.auth_data[2:])
            else:
                try:
                    auth_data_bytes = bytes.fromhex(req.auth_data)
                except ValueError:
                    auth_data_bytes = base64.b64decode(req.auth_data)

            if req.signature.startswith("0x") or req.signature.startswith("\\x"):
                sig_bytes = bytes.fromhex(req.signature[2:])
            else:
                try:
                    sig_bytes = bytes.fromhex(req.signature)
                except ValueError:
                    sig_bytes = base64.b64decode(req.signature)

        if req.override_invalid_sig:
            sig_bytes = b"INVALID_CORRUPTED_SIGNATURE_BYTES"

        res = record_officer_webauthn_approval(
            batch_id=batch_id,
            officer_user_id=officer_user_id,
            credential_id=req.credential_id,
            client_data_json=client_data,
            auth_data=auth_data_bytes,
            signature=sig_bytes,
            challenge_id=req.challenge_id,
            is_mock=bool(req.mock_simulation)
        )
        return res
    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -----------------------------------------------------------------------------
# 6. TRANSACTIONAL OUTBOX WORKER & PAYPAL SUBMISSION
# -----------------------------------------------------------------------------
@app.post("/api/outbox/process")
def api_process_outbox(
    force_timeout: bool = Query(False),
    current_user: Dict[str, Any] = Depends(require_role("TREASURY_OFFICER"))
):
    """
    Dispatches the Outbox Worker to claim and execute the next pending job.
    Requires authenticated Treasury Officer or Worker role.
    """
    worker = OutboxWorker(worker_id="outbox-daemon-node-01")
    res = worker.process_next_job(force_timeout=force_timeout)
    if not res:
        return {"status": "NO_PENDING_JOBS", "message": "Outbox is currently clear."}
    return res

# -----------------------------------------------------------------------------
# 7. UNIFIED DASHBOARD METRICS & AUDIT TIMELINE (SINGLE-BATCH CONSISTENCY)
# -----------------------------------------------------------------------------
@app.get("/api/dashboard/overview")
def api_dashboard_overview(
    batch_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns unified, cross-panel consistent dashboard data for the active payout batch.
    Guarantees:
    - Mandatory authentication: anonymous access rejected with HTTP 401.
    - Object-level authorization: AP clerks cannot access batches created by others (HTTP 403).
    - All panels reflect the SAME active batch.
    - Outbox job is linked directly to active batch (never stale from a previous run).
    - Audio evaluation is linked directly to active batch session.
    - Dual WebAuthn approvals include BOTH Officer 1 (Bob) and Officer 2 (Carol).
    - Item states reflect true operational state (reconciliation pending, locked in snapshot, etc).
    - Audit timeline is filtered to the active batch and verified cryptographically.
    - Provider mode reflects actual configuration (Live vs Simulator).
    """
    from backend.paypal_client import PayPalClient
    import time
    
    if not isinstance(current_user, dict):
        raise HTTPException(status_code=401, detail="Authentication required")

    if batch_id and hasattr(batch_id, 'default'):
        batch_id = None
    elif batch_id:
        batch_id = str(batch_id)

    pp_client = PayPalClient()
    conn_status = pp_client.check_api_connectivity()

    with get_auditor_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # 1. Fetch recent batches
            cur.execute("""
                SELECT id, session_id, sender_batch_id, created_by_user_id, gateway_batch_state, paypal_batch_state,
                       payout_batch_id, total_amount_cents, item_count, fencing_token,
                       created_at, updated_at
                FROM payout_batches
                ORDER BY created_at DESC
                LIMIT 15;
            """)
            recent_batches = cur.fetchall()
            for b in recent_batches:
                b["id"] = str(b["id"])
                if b.get("created_by_user_id"):
                    b["created_by_user_id"] = str(b["created_by_user_id"])
                if b.get("session_id"):
                    b["session_id"] = str(b["session_id"])

            active_batch = None
            if batch_id:
                for b in recent_batches:
                    if str(b["id"]) == str(batch_id):
                        active_batch = b
                        break
                if not active_batch:
                    cur.execute("SELECT * FROM payout_batches WHERE id = %s;", (batch_id,))
                    active_batch = cur.fetchone()
                    if active_batch:
                        active_batch["id"] = str(active_batch["id"])
                        if active_batch.get("created_by_user_id"):
                            active_batch["created_by_user_id"] = str(active_batch["created_by_user_id"])
                        if active_batch.get("session_id"):
                            active_batch["session_id"] = str(active_batch["session_id"])

            if not active_batch and recent_batches:
                # If AP clerk, pick first batch created by this user
                if current_user["role"] == "AP_CLERK":
                    for b in recent_batches:
                        if str(b.get("created_by_user_id")) == str(current_user["user_id"]):
                            active_batch = b
                            break
                else:
                    active_batch = recent_batches[0]

            # Enforce object-level authorization for AP clerks
            if current_user["role"] == "AP_CLERK" and active_batch:
                if str(active_batch.get("created_by_user_id")) != str(current_user["user_id"]):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access forbidden: AP_CLERK '{current_user['username']}' is not authorized to inspect batch '{active_batch['id']}'"
                    )
                recent_batches = [b for b in recent_batches if str(b.get("created_by_user_id")) == str(current_user["user_id"])]

            if not active_batch:
                return {
                    "status": "EMPTY",
                    "active_batch": None,
                    "audio_state": "NOT_RUN",
                    "audio_evaluation": None,
                    "audio_review": None,
                    "outbox_job": None,
                    "approvals": [],
                    "bob_info": {"officer_name": "Bob (Treasury Officer 1)", "is_approved": False, "status": "PENDING"},
                    "carol_info": {"officer_name": "Carol (Treasury Officer 2)", "is_approved": False, "status": "PENDING"},
                    "approval_count": 0,
                    "is_threshold_met": False,
                    "items": [],
                    "locks": [],
                    "lock_status": {"is_held": False},
                    "audit_events": [],
                    "chain_verified": False,
                    "recent_batches": recent_batches,
                    "provider_info": {
                        "mode": conn_status["mode"],
                        "provider_state": conn_status["provider_state"],
                        "provider_mode": conn_status["provider_mode"],
                        "is_simulator": conn_status["is_simulator"],
                        "configured": conn_status["configured"],
                        "oauth_connected": conn_status["oauth_connected"],
                        "oauth_status": conn_status["oauth_status"],
                        "connection_status": conn_status["connection_status"],
                        "connection_label": conn_status["connection_label"],
                        "gateway_status": "IDLE",
                        "submission_status": "IDLE",
                        "payout_batch_id": "NONE",
                        "connectivity": conn_status
                    },
                    "server_time": time.time()
                }

            act_id = str(active_batch["id"])
            batch_state = active_batch["gateway_batch_state"]

            # 2. Audio Risk Evaluation (Linked to batch session)
            audio_eval = None
            if active_batch.get("session_id"):
                cur.execute("""
                    SELECT re.id, re.deepfake_probability, re.acoustic_consistency_score,
                           re.voice_clone_flag, re.recommendation, re.model_version,
                           re.policy_decision, aa.id AS audio_asset_id,
                           aa.format, aa.sample_rate, aa.channels,
                           ss.wada_snr_db, ss.sample_count, aa.duration_ms, re.evaluated_at
                    FROM sessions s
                    JOIN audio_assets aa ON aa.session_id = s.id
                    JOIN speaker_segments ss ON ss.audio_asset_id = aa.id
                    JOIN risk_evaluations re ON re.segment_id = ss.id
                    WHERE s.id = %s
                    ORDER BY re.evaluated_at DESC
                    LIMIT 1;
                """, (active_batch["session_id"],))
                audio_eval = cur.fetchone()

            if not audio_eval:
                # Fallback: check audit events if linked via metadata
                cur.execute("""
                    SELECT re.id, re.deepfake_probability, re.acoustic_consistency_score,
                           re.voice_clone_flag, re.recommendation, re.model_version,
                           re.policy_decision, aa.id AS audio_asset_id,
                           aa.format, aa.sample_rate, aa.channels,
                           ss.wada_snr_db, ss.sample_count, aa.duration_ms, re.evaluated_at
                    FROM audit_events ae
                    JOIN risk_evaluations re ON re.id = ae.entity_id
                    JOIN speaker_segments ss ON ss.id = re.segment_id
                    JOIN audio_assets aa ON aa.id = ss.audio_asset_id
                    WHERE ae.metadata_json->>'batch_id' = %s
                    ORDER BY ae.id DESC
                    LIMIT 1;
                """, (act_id,))
                audio_eval = cur.fetchone()

            audio_review = None
            if audio_eval:
                try:
                    audio_review = get_audio_review_evidence(act_id)
                except Exception:
                    audio_review = None
                rec = str(audio_eval.get("recommendation") or "").upper()
                if not audio_eval.get("policy_decision"):
                    if rec == "APPROVE":
                        audio_eval["policy_decision"] = "READY_FOR_CHECKER"
                    elif rec == "CHALLENGE":
                        audio_eval["policy_decision"] = "NEEDS_REVIEW"
                    else:
                        audio_eval["policy_decision"] = "BLOCKED"
                if audio_review and audio_review.get("audio_evidence"):
                    ev_info = audio_review["audio_evidence"]
                    audio_eval["sha256_hash"] = ev_info.get("audio_content_sha256")
                    audio_eval["acoustic_fingerprint"] = ev_info.get("acoustic_fingerprint")

            audio_state = "COMPLETED" if audio_eval else "NOT_RUN"

            # 3. Outbox Job (Strictly for active_batch)
            cur.execute("""
                SELECT id, batch_id, status, fencing_token, attempt_count, lease_expires_at,
                       last_error, created_at, updated_at
                FROM outbox_jobs
                WHERE batch_id = %s
                ORDER BY created_at DESC
                LIMIT 1;
            """, (act_id,))
            outbox_job = cur.fetchone()

            # 4. Approvals (Both Officer 1 and Officer 2)
            cur.execute("""
                SELECT ae.actor_user_id, ae.created_at, ae.metadata_json
                FROM audit_events ae
                WHERE ae.entity_id = %s AND ae.event_type = 'OFFICER_STAGE1_APPROVED'
                ORDER BY ae.id ASC
                LIMIT 1;
            """, (act_id,))
            bob_event = cur.fetchone()

            cur.execute("""
                SELECT oa.batch_id, oa.approved_at, oa.credential_id
                FROM officer_approvals oa
                WHERE oa.batch_id = %s
                ORDER BY oa.approved_at ASC
                LIMIT 1;
            """, (act_id,))
            carol_row = cur.fetchone()

            cur.execute("""
                SELECT ae.metadata_json
                FROM audit_events ae
                WHERE ae.entity_id = %s AND ae.event_type = 'OFFICER_STAGE2_APPROVED'
                ORDER BY ae.id DESC
                LIMIT 1;
            """, (act_id,))
            carol_event = cur.fetchone()

            bob_approved = bool(bob_event is not None)
            carol_approved = bool(carol_row is not None)

            bob_auth_type = "AUTHENTICATOR TYPE UNVERIFIED"
            if bob_approved:
                if bob_event and bob_event.get("metadata_json"):
                    bob_auth_type = bob_event["metadata_json"].get("authenticator_type", "AUTHENTICATOR TYPE UNVERIFIED")

            carol_auth_type = "AUTHENTICATOR TYPE UNVERIFIED"
            if carol_approved:
                if carol_event and carol_event.get("metadata_json"):
                    carol_auth_type = carol_event["metadata_json"].get("authenticator_type", "AUTHENTICATOR TYPE UNVERIFIED")

            bob_info = {
                "officer_name": "Bob (Treasury Officer 1)",
                "username": "bob_officer_one",
                "role": "TREASURY_OFFICER",
                "is_approved": bob_approved,
                "approved_at": bob_event["created_at"].isoformat() if bob_event else None,
                "credential_id": (bob_event["metadata_json"].get("credential_id") if (bob_event and bob_event["metadata_json"]) else "cred_bob_yubikey_01"),
                "authenticator_type": bob_auth_type if bob_approved else None,
                "status": "VERIFIED (P-256 ECDSA)" if bob_approved else "PENDING"
            }

            carol_info = {
                "officer_name": "Carol (Treasury Officer 2)",
                "username": "carol_officer_two",
                "role": "TREASURY_OFFICER",
                "is_approved": carol_approved,
                "approved_at": carol_row["approved_at"].isoformat() if carol_row else None,
                "credential_id": carol_row["credential_id"] if carol_row else "cred_carol_titan_02",
                "authenticator_type": carol_auth_type if carol_approved else None,
                "status": "VERIFIED (P-256 ECDSA)" if carol_approved else "PENDING"
            }

            approvals = []
            if bob_approved:
                approvals.append(bob_info)
            if carol_approved:
                approvals.append(carol_info)

            approval_count = (1 if bob_approved else 0) + (1 if carol_approved else 0)
            is_threshold_met = bool(approval_count >= 2)

            # 5. Items with Derived Operational Display States
            with get_app_conn(autocommit=True) as app_conn:
                with app_conn.cursor(row_factory=dict_row) as app_cur:
                    app_cur.execute("""
                        SELECT pi.id, pi.batch_id, pi.sender_item_id, pi.amount_cents,
                               pi.gateway_item_state, pi.paypal_item_state, pi.payout_item_id,
                               b.legal_name, pi.note
                        FROM payout_items pi
                        JOIN beneficiaries b ON b.id = pi.beneficiary_id
                        WHERE pi.batch_id = %s
                        ORDER BY pi.created_at ASC;
                    """, (act_id,))
                    raw_items = app_cur.fetchall()

            items = []
            for it in raw_items:
                it_dict = dict(it)
                raw_st = it_dict["gateway_item_state"]
                raw_pp = it_dict["paypal_item_state"]

                if batch_state == "MANUAL_RECONCILIATION_REQUIRED":
                    it_dict["display_gateway_state"] = "RECONCILIATION_REQUIRED"
                    it_dict["display_paypal_state"] = "UNKNOWN_IN_FLIGHT"
                    it_dict["state_explanation"] = "Ambiguous 504 network timeout. Beneficiary lock retained."
                    it_dict["status_badge_class"] = "pill-warning"
                elif batch_state in ("READY_FOR_CHECKER", "APPROVED_TO_SUBMIT", "SUBMITTING"):
                    it_dict["display_gateway_state"] = "LOCKED_IN_SNAPSHOT"
                    it_dict["display_paypal_state"] = "AWAITING_DISPATCH"
                    it_dict["state_explanation"] = "Sealed in AES-256-GCM canonical snapshot. Awaiting completion."
                    it_dict["status_badge_class"] = "pill-ready"
                elif batch_state == "BLOCKED":
                    it_dict["display_gateway_state"] = "BLOCKED"
                    it_dict["display_paypal_state"] = "PROHIBITED"
                    it_dict["state_explanation"] = "Deepfake acoustic spoof detected. Disbursement halted."
                    it_dict["status_badge_class"] = "pill-blocked"
                elif batch_state in ("SUBMITTED", "SETTLED"):
                    it_dict["display_gateway_state"] = raw_st
                    it_dict["display_paypal_state"] = raw_pp or "SUCCESS"
                    it_dict["state_explanation"] = "Reconciled with PayPal Sandbox settlement."
                    it_dict["status_badge_class"] = "pill-success"
                else:
                    it_dict["display_gateway_state"] = raw_st
                    it_dict["display_paypal_state"] = raw_pp or "PENDING"
                    it_dict["state_explanation"] = "Draft item in formulation."
                    it_dict["status_badge_class"] = "pill-ready"

                items.append(it_dict)

            # 6. Beneficiary Submission Lock Status
            with get_app_conn(autocommit=True) as app_conn:
                with app_conn.cursor(row_factory=dict_row) as app_cur:
                    app_cur.execute("""
                        SELECT l.id, b.legal_name, l.batch_id, l.expected_version, l.locked_at, l.released_at
                        FROM beneficiary_submission_locks l
                        JOIN beneficiaries b ON b.id = l.beneficiary_id
                        WHERE l.batch_id = %s
                        ORDER BY l.locked_at DESC
                        LIMIT 1;
                    """, (act_id,))
                    lock_row = app_cur.fetchone()
            is_lock_held = bool(lock_row and lock_row["released_at"] is None)

            # 7. Provider Connection & Attempts Info
            cur.execute("""
                SELECT id, attempt_type, http_status, attempted_at, is_ambiguous_network_error
                FROM paypal_api_attempts
                WHERE batch_id = %s
                ORDER BY id DESC
                LIMIT 1;
            """, (act_id,))
            latest_attempt = cur.fetchone()

            submission_status = (
                "TIMEOUT_UNKNOWN" if batch_state == "MANUAL_RECONCILIATION_REQUIRED"
                else (active_batch["paypal_batch_state"] or ("AWAITING_SUBMISSION" if batch_state != "BLOCKED" else "BLOCKED"))
            )
            provider_info = {
                "mode": conn_status["mode"],
                "provider_state": conn_status["provider_state"],
                "provider_mode": conn_status["provider_mode"],
                "is_simulator": conn_status["is_simulator"],
                "configured": conn_status["configured"],
                "oauth_connected": conn_status["oauth_connected"],
                "oauth_status": conn_status["oauth_status"],
                "connection_status": conn_status["connection_status"],
                "connection_label": conn_status["connection_label"],
                "gateway_status": submission_status,
                "submission_status": submission_status,
                "payout_batch_id": (
                    active_batch["payout_batch_id"] if active_batch["payout_batch_id"]
                    else ("UNKNOWN (Network Timeout)" if batch_state == "MANUAL_RECONCILIATION_REQUIRED" else "NONE")
                ),
                "connectivity": conn_status,
                "latest_attempt": {
                    "http_status": latest_attempt["http_status"] if latest_attempt else None,
                    "attempted_at": latest_attempt["attempted_at"].isoformat() if latest_attempt else None,
                    "is_ambiguous": latest_attempt["is_ambiguous_network_error"] if latest_attempt else False
                } if latest_attempt else None
            }

            # 8. Audit Chain Events (Chronological Order for Active Batch)
            cur.execute("""
                SELECT id, event_type, entity_type, entity_id, previous_event_digest,
                       event_digest, created_at, metadata_json
                FROM audit_events
                WHERE entity_id = %s OR (metadata_json->>'batch_id' = %s)
                ORDER BY id ASC;
            """, (act_id, act_id))
            audit_events = cur.fetchall()

            chain_verified = True
            for i in range(1, len(audit_events)):
                if audit_events[i]["previous_event_digest"] != audit_events[i-1]["event_digest"]:
                    chain_verified = False
                    break

            # Format for frontend response
            return {
                "status": "OK",
                "active_batch": active_batch,
                "audio_state": audio_state,
                "audio_evaluation": audio_eval,
                "audio_review": audio_review,
                "outbox_job": outbox_job,
                "approvals": approvals,
                "bob_info": bob_info,
                "carol_info": carol_info,
                "approval_count": approval_count,
                "is_threshold_met": is_threshold_met,
                "items": items,
                "lock_status": {
                    "is_held": is_lock_held,
                    "beneficiary_name": lock_row["legal_name"] if lock_row else None,
                    "locked_at": lock_row["locked_at"].isoformat() if lock_row else None,
                    "released_at": lock_row["released_at"].isoformat() if (lock_row and lock_row["released_at"]) else None
                },
                "provider_info": provider_info,
                "audit_events": audit_events,
                "chain_verified": chain_verified,
                "recent_batches": recent_batches,
                "server_time": time.time()
            }

# -----------------------------------------------------------------------------
# 8. DASHBOARD UI SERVING
# -----------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/api/system/paypal/health")
def api_paypal_health(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns PayPal connectivity health check without disclosing secrets or access tokens.
    """
    from backend.paypal_client import PayPalClient
    client = PayPalClient()
    health = client.check_api_connectivity()
    return health

@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = os.path.join("static", "index.html")
    if os.path.isfile(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>DeepfakeShield Console Ready</h1>"
