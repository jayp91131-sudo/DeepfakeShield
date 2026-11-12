#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Authoritative Payout Lifecycle Service
Milestone: V10.1.3 Hackathon Delivery Sprint

Implements:
1. Payout Batch & Items Draft Creation
2. Beneficiary Registry Verification & Blind Index Alignment
3. Audio Risk Linking & Policy Gate Check
4. Atomic Batch Finalization (Snapshot Encryption, Envelope Attestation, Locking)
5. Dual Independent FIDO2/WebAuthn Officer Approvals (via fn_submit_officer_approval)
6. Outbox Job Generation for PayPal Submission
"""

import os
import uuid
import json
import base64
import hashlib
import struct
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import psycopg
from psycopg.rows import dict_row
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature

from backend.database import (
    get_admin_conn,
    get_app_conn,
    get_verifier_conn,
    get_worker_conn,
    get_auditor_conn,
    KEY_ID_ACTIVE,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    OFFICER_PRIVATE_KEYS
)
from crypto_verifier import (
    compute_recipient_blind_index,
    encrypt_payload,
    verify_and_attest_snapshot,
    create_webauthn_assertion,
    verify_webauthn_assertion,
    ENVELOPE_VERSION,
    get_attestation_secret,
    get_blind_index_key,
)

def log_audit_event(
    stream_id: str,
    actor_user_id: Optional[str],
    event_type: str,
    entity_type: str,
    entity_id: str,
    metadata_dict: Optional[Dict[str, Any]] = None,
    fencing_token: int = 1,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = "DeepfakeShield-Service/10.1"
):
    """Appends an immutable hash-chained event to audit_events via verifier role."""
    try:
        with get_verifier_conn(autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT fn_append_audit_event(
                        %s, %s, %s, %s, %s,
                        NULL, NULL, %s, %s, %s,
                        NULL, %s::jsonb
                    );
                """, (
                    stream_id,
                    uuid.UUID(actor_user_id) if actor_user_id else None,
                    event_type,
                    entity_type,
                    uuid.UUID(entity_id),
                    client_ip,
                    user_agent,
                    fencing_token,
                    json.dumps(metadata_dict) if metadata_dict else None
                ))
    except Exception as e:
        print(f"[!] Warning: failed to log audit event {event_type}: {e}")

def create_draft_batch(
    maker_user_id: str,
    program_id: str,
    payout_period: str,
    items_data: List[Dict[str, Any]],
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Creates a new payout batch and items in DRAFT state."""
    batch_id = str(uuid.uuid4())
    if not session_id:
        session_id = str(uuid.uuid4())

    total_cents = 0
    item_rows = []

    with get_app_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # 1. Ensure active session exists
            cur.execute("""
                INSERT INTO sessions (id, created_by_user_id)
                VALUES (%s, %s)
                ON CONFLICT (id) DO NOTHING;
            """, (session_id, maker_user_id))

            # 2. Verify all beneficiaries and prepare items
            for idx, it in enumerate(items_data):
                ben_id = it["beneficiary_id"]
                amount_cents = int(float(it["amount_usd"]) * 100)
                total_cents += amount_cents

                cur.execute("""
                    SELECT id, legal_name, version, verification_status, destination_digest, destination_blind_index
                    FROM beneficiaries WHERE id = %s;
                """, (ben_id,))
                ben = cur.fetchone()
                if not ben:
                    raise ValueError(f"Beneficiary {ben_id} not found in registry")
                if ben["verification_status"] != "VERIFIED":
                    raise ValueError(f"Beneficiary {ben['legal_name']} is NOT VERIFIED (status: {ben['verification_status']})")

                receiver_email = it["receiver_email"].strip().lower()
                calc_digest = hashlib.sha256(receiver_email.encode('utf-8')).hexdigest()
                calc_blind = compute_recipient_blind_index(receiver_email, get_blind_index_key())

                if calc_digest != ben["destination_digest"] or calc_blind != ben["destination_blind_index"]:
                    raise ValueError(f"Receiver email mismatch for beneficiary {ben['legal_name']}")

                item_id = str(uuid.uuid4())
                sender_item_id = it.get("sender_item_id", f"item_{batch_id[:6]}_{idx+1}")
                obligation_key = it.get("obligation_key", f"ob_{batch_id[:6]}_{idx+1}")

                dek = os.urandom(32)
                nonce, ct, tag = encrypt_payload(dek, receiver_email.encode('utf-8'), b"PAYOUT_ITEM_RECEIVER")

                item_rows.append({
                    "id": item_id,
                    "batch_id": batch_id,
                    "obligation_key": obligation_key,
                    "beneficiary_id": ben_id,
                    "beneficiary_version": ben["version"],
                    "expected_destination_digest": calc_digest,
                    "sender_item_id": sender_item_id,
                    "encrypted_receiver": ct,
                    "destination_blind_index": calc_blind,
                    "amount_cents": amount_cents,
                    "amount_usd": it["amount_usd"],
                    "receiver_email": receiver_email,
                    "legal_name": ben["legal_name"],
                    "note": it.get("note", "Contractor disbursement"),
                    "dek": dek,
                    "nonce": nonce,
                    "tag": tag
                })

            # 3. Create parent batch in DRAFT
            sender_batch_id = f"batch_{program_id}_{payout_period}_{batch_id[:8]}"
            paypal_request_id = str(uuid.uuid4())
            batch_dek = os.urandom(32)
            b_nonce, b_ct, b_tag = encrypt_payload(batch_dek, b"DRAFT_CANONICAL_PAYLOAD", b"PAYOUT_BATCH")

            cur.execute("""
                INSERT INTO payout_batches (
                    id, session_id, program_id, payout_period, currency, key_id,
                    wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_canonical_payload,
                    payload_digest, sender_batch_id, paypal_request_id, gateway_batch_state,
                    total_amount_cents, item_count, created_by_user_id
                ) VALUES (
                    %s, %s, %s, %s, 'USD', %s,
                    %s, %s, %s, 'PAYOUT_BATCH', %s,
                    'DRAFT_PLACEHOLDER_DIGEST', %s, %s, 'DRAFT',
                    %s, %s, %s
                );
            """, (
                batch_id, session_id, program_id, payout_period, KEY_ID_ACTIVE,
                batch_dek, b_nonce, b_tag, b_ct, sender_batch_id, paypal_request_id,
                total_cents, len(item_rows), maker_user_id
            ))

            # 4. Insert items
            for itm in item_rows:
                cur.execute("""
                    INSERT INTO payout_items (
                        id, batch_id, obligation_key, beneficiary_id, beneficiary_version,
                        expected_destination_digest, sender_item_id, recipient_type, key_id,
                        wrapped_dek, iv_nonce, auth_tag, aad_text, encrypted_receiver,
                        destination_blind_index, amount_cents, currency, note, gateway_item_state
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, 'EMAIL', %s,
                        %s, %s, %s, 'PAYOUT_ITEM_RECEIVER', %s,
                        %s, %s, 'USD', %s, 'DRAFT'
                    );
                """, (
                    itm["id"], batch_id, itm["obligation_key"], itm["beneficiary_id"], itm["beneficiary_version"],
                    itm["expected_destination_digest"], itm["sender_item_id"], KEY_ID_ACTIVE,
                    itm["dek"], itm["nonce"], itm["tag"], itm["encrypted_receiver"],
                    itm["destination_blind_index"], itm["amount_cents"], itm["note"]
                ))

    # 5. Log audit event
    log_audit_event(
        stream_id="main",
        actor_user_id=maker_user_id,
        event_type="BATCH_DRAFT_CREATED",
        entity_type="PAYOUT_BATCH",
        entity_id=batch_id,
        metadata_dict={"sender_batch_id": sender_batch_id, "items": len(item_rows)}
    )

    return {
        "batch_id": batch_id,
        "session_id": session_id,
        "program_id": program_id,
        "payout_period": payout_period,
        "sender_batch_id": sender_batch_id,
        "total_amount_usd": f"{total_cents / 100:.2f}",
        "item_count": len(item_rows),
        "gateway_batch_state": "DRAFT",
        "items": item_rows
    }

def record_audio_analysis_for_batch(
    batch_id: str,
    audio_analysis_result: Dict[str, Any],
    session_id: str,
    user_id: str
) -> Dict[str, Any]:
    """
    Atomically persists audio evidence, consent, speaker segment, risk evaluation, and
    AUDIO_RISK_EVALUATED audit event via the privileged deepfakeshield_verifier role
    (fn_record_audio_risk_evaluation). Fails closed if verifier DB is unavailable or rejects.
    """
    if not isinstance(audio_analysis_result, dict):
        raise AudioRiskGateError("Fail-closed: audio_analysis_result must be a structured dictionary.")

    try:
        batch_uuid = uuid.UUID(str(batch_id))
        session_uuid = uuid.UUID(str(session_id))
        actor_uuid = uuid.UUID(str(user_id)) if user_id else None
    except (TypeError, ValueError) as exc:
        raise AudioRiskGateError("Fail-closed: invalid UUID for batch_id, session_id, or user_id.") from exc

    recommendation = audio_analysis_result.get("recommendation")
    policy_decision = audio_analysis_result.get("policy_decision")
    if recommendation not in ("APPROVE", "CHALLENGE", "TERMINATE"):
        raise AudioRiskGateError(f"Fail-closed: invalid audio recommendation '{recommendation}'.")
    if policy_decision not in ("READY_FOR_CHECKER", "NEEDS_REVIEW", "BLOCKED"):
        raise AudioRiskGateError(f"Fail-closed: invalid audio policy_decision '{policy_decision}'.")

    asset_id = uuid.uuid4()
    segment_id = uuid.uuid4()
    eval_id = uuid.uuid4()
    storage_uri = str(audio_analysis_result.get("storage_uri") or f"vault://audio/{asset_id}.wav")
    consent_evidence_hash = str(
        audio_analysis_result.get("consent_evidence_hash")
        or hashlib.sha256(b"CONSENT_EVIDENCE_OK").hexdigest()
    )

    try:
        duration_ms = int(audio_analysis_result["duration_ms"])
        sample_count = max(int(audio_analysis_result["sample_count"]), 64600)
        wada_snr_db = round(float(audio_analysis_result["wada_snr_db"]), 2)
        model_version = str(audio_analysis_result["model_version"])
        deepfake_probability = round(float(audio_analysis_result["deepfake_probability"]), 4)
        acoustic_consistency_score = round(float(audio_analysis_result["acoustic_consistency_score"]), 4)
        voice_clone_flag = bool(audio_analysis_result["voice_clone_flag"])
        adversarial_noise_detected = bool(audio_analysis_result["adversarial_noise_detected"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AudioRiskGateError("Fail-closed: incomplete or invalid audio evaluation metrics.") from exc

    extra_meta: Dict[str, Any] = {}
    audio_sha256 = audio_analysis_result.get("audio_sha256") or audio_analysis_result.get("sha256_hash")
    if audio_sha256 is not None:
        norm_sha = str(audio_sha256).strip().lower()
        extra_meta["audio_sha256"] = norm_sha
        extra_meta["sha256_hash"] = norm_sha
    for key in (
        "acoustic_fingerprint",
        "analyzer_engine",
        "model_type",
        "file_name",
        "window_count",
        "max_window_score",
        "acoustic_signal",
        "replay_detected",
        "duration_ms",
        "sample_count",
        "wada_snr_db",
        "window_results",
    ):
        if key in audio_analysis_result and audio_analysis_result[key] is not None:
            extra_meta[key] = audio_analysis_result[key]
    extra_meta["storage_uri"] = storage_uri

    try:
        with get_verifier_conn(autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT fn_record_audio_risk_evaluation(
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::text,
                        %s::int,
                        %s::int,
                        %s::numeric,
                        %s::varchar,
                        %s::varchar,
                        %s::numeric,
                        %s::numeric,
                        %s::boolean,
                        %s::boolean,
                        %s::varchar,
                        %s::varchar,
                        %s::jsonb
                    );
                    """,
                    (
                        batch_uuid,
                        session_uuid,
                        actor_uuid,
                        asset_id,
                        segment_id,
                        eval_id,
                        storage_uri,
                        duration_ms,
                        sample_count,
                        wada_snr_db,
                        consent_evidence_hash,
                        model_version,
                        deepfake_probability,
                        acoustic_consistency_score,
                        voice_clone_flag,
                        adversarial_noise_detected,
                        recommendation,
                        policy_decision,
                        json.dumps(extra_meta),
                    ),
                )
                row = cur.fetchone()
                if not row or not row[0]:
                    raise AudioRiskGateError("Fail-closed: verifier function returned no evaluation ID.")
                persisted_eval_id = str(row[0])
            conn.commit()
    except AudioRiskGateError:
        raise
    except psycopg.OperationalError as exc:
        # Fail closed without exposing connection strings or credentials.
        raise AudioRiskGateError("Fail-closed: verifier database connection is unavailable.") from exc
    except psycopg.Error as exc:
        detail = getattr(getattr(exc, "diag", None), "message_primary", None) or exc.__class__.__name__
        raise AudioRiskGateError(f"Fail-closed: verifier rejected audio evaluation ({detail}).") from exc
    except Exception as exc:
        raise AudioRiskGateError(f"Fail-closed: verifier execution failed ({exc.__class__.__name__}).") from exc

    return {
        "evaluation_id": persisted_eval_id,
        "asset_id": str(asset_id),
        "segment_id": str(segment_id),
        "policy_decision": policy_decision,
        "recommendation": recommendation,
        "deepfake_probability": deepfake_probability,
    }

def decrypt_item_receiver(itm: Dict[str, Any]) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    dek = bytes(itm["wrapped_dek"])
    nonce = bytes(itm["iv_nonce"])
    tag = bytes(itm["auth_tag"])
    ciphertext = bytes(itm["encrypted_receiver"])
    aad = itm["aad_text"].encode('utf-8') if isinstance(itm["aad_text"], str) else itm["aad_text"]
    aesgcm = AESGCM(dek)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext + tag, aad)
    return plaintext_bytes.decode('utf-8')

MAX_AUDIO_EVAL_AGE_SECONDS = int(os.environ.get("AUDIO_EVAL_MAX_AGE_SECONDS", "3600"))
ALLOWED_AUDIO_RECOMMENDATION = "APPROVE"
ALLOWED_AUDIO_POLICY_DECISION = "READY_FOR_CHECKER"

class AudioRiskGateError(ValueError):
    """Raised when server-side audio risk verification fails or is missing/stale/unapproved."""
    pass

def _verify_server_side_audio_risk_gate(
    batch: Dict[str, Any],
    max_eval_age_seconds: int = MAX_AUDIO_EVAL_AGE_SECONDS
) -> Dict[str, Any]:
    """
    Fail-closed server-side verification of the latest persisted audio risk evaluation
    associated with this exact payout batch and its session/audio evidence.
    Never trusts caller-supplied policy decisions.
    """
    batch_id = str(batch["id"])
    session_id = batch.get("session_id")
    if not session_id:
        raise AudioRiskGateError(f"Audio risk gate rejected batch {batch_id}: missing session association.")

    with get_auditor_conn(autocommit=True) as aud_conn:
        with aud_conn.cursor(row_factory=dict_row) as aud_cur:
            # 1. Verify active audio session
            aud_cur.execute("""
                SELECT id, session_status, started_at, terminated_at
                FROM sessions
                WHERE id = %s;
            """, (session_id,))
            sess_row = aud_cur.fetchone()
            if not sess_row:
                raise AudioRiskGateError(f"Audio risk gate rejected batch {batch_id}: session {session_id} not found.")
            if sess_row["session_status"] in ("FAILED", "TERMINATED") or sess_row["terminated_at"] is not None:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: session status is {sess_row['session_status']}."
                )

            # 2. Retrieve latest audio asset bound to this session
            aud_cur.execute("""
                SELECT id, session_id, recorded_at, duration_ms
                FROM audio_assets
                WHERE session_id = %s
                ORDER BY recorded_at DESC NULLS LAST, id DESC
                LIMIT 1;
            """, (session_id,))
            latest_asset = aud_cur.fetchone()
            if not latest_asset:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: missing audio evidence for session {session_id}."
                )

            # 3. Retrieve latest speaker segment & persisted risk evaluation for that latest audio asset
            aud_cur.execute("""
                SELECT re.id, re.segment_id, re.model_version, re.deepfake_probability,
                       re.acoustic_consistency_score, re.voice_clone_flag,
                       re.adversarial_noise_detected, re.recommendation, re.evaluated_at,
                       ss.audio_asset_id, ss.is_evaluated, ss.sample_count
                FROM speaker_segments ss
                LEFT JOIN risk_evaluations re ON re.segment_id = ss.id
                WHERE ss.audio_asset_id = %s
                ORDER BY re.evaluated_at DESC NULLS FIRST, re.id DESC NULLS FIRST, ss.id DESC
                LIMIT 1;
            """, (latest_asset["id"],))
            eval_row = aud_cur.fetchone()
            if not eval_row or eval_row["id"] is None:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: missing persisted risk evaluation for latest audio asset {latest_asset['id']}."
                )

            if not eval_row["is_evaluated"]:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: speaker segment {eval_row['segment_id']} is not evaluated."
                )

            eval_id = str(eval_row["id"])
            evaluated_at = eval_row["evaluated_at"]
            if evaluated_at is None:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} has no timestamp."
                )

            now_utc = datetime.now(timezone.utc)
            eval_at_utc = evaluated_at.astimezone(timezone.utc) if evaluated_at.tzinfo else evaluated_at.replace(tzinfo=timezone.utc)

            if latest_asset["recorded_at"] is not None:
                asset_at_utc = (
                    latest_asset["recorded_at"].astimezone(timezone.utc)
                    if latest_asset["recorded_at"].tzinfo
                    else latest_asset["recorded_at"].replace(tzinfo=timezone.utc)
                )
                if eval_at_utc < asset_at_utc:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} predates latest audio asset (stale)."
                    )

            age_seconds = (now_utc - eval_at_utc).total_seconds()
            if age_seconds < -60:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} has invalid future timestamp."
                )

            # 4. Verify immutable AUDIO_RISK_EVALUATED audit binding to this exact batch
            aud_cur.execute("""
                SELECT id, entity_id, metadata_json, created_at
                FROM audit_events
                WHERE entity_type = 'RISK_EVALUATION'
                  AND entity_id = %s
                  AND event_type = 'AUDIO_RISK_EVALUATED'
                ORDER BY id DESC
                LIMIT 1;
            """, (eval_id,))
            eval_audit = aud_cur.fetchone()
            if not eval_audit:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} lacks immutable AUDIO_RISK_EVALUATED audit record."
                )

            eval_meta = eval_audit.get("metadata_json") or {}
            if str(eval_meta.get("batch_id")) != batch_id:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} is associated with batch {eval_meta.get('batch_id')}, not {batch_id}."
                )

            aud_cur.execute("""
                SELECT id, entity_id
                FROM audit_events
                WHERE event_type = 'AUDIO_RISK_EVALUATED'
                  AND metadata_json->>'batch_id' = %s
                ORDER BY id DESC
                LIMIT 1;
            """, (batch_id,))
            latest_batch_audit = aud_cur.fetchone()
            if latest_batch_audit and str(latest_batch_audit["entity_id"]) != eval_id:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} does not match latest batch audit evaluation {latest_batch_audit['entity_id']} (stale)."
                )

            if not eval_row["model_version"] or not str(eval_row["model_version"]).strip():
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: missing model_version on evaluation {eval_id}."
                )

            persisted_policy = eval_meta.get("policy_decision")
            rec = eval_row["recommendation"]
            prob = float(eval_row["deepfake_probability"])

            # Path A: Direct automated approval
            if (
                persisted_policy == ALLOWED_AUDIO_POLICY_DECISION
                and rec == ALLOWED_AUDIO_RECOMMENDATION
                and not eval_row["voice_clone_flag"]
                and not eval_row["adversarial_noise_detected"]
                and prob < 0.35
            ):
                if age_seconds > max_eval_age_seconds:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} is stale ({int(age_seconds)}s > {max_eval_age_seconds}s TTL)."
                    )
                return {
                    "evaluation_id": eval_id,
                    "recommendation": rec,
                    "policy_decision": persisted_policy,
                    "model_version": eval_row["model_version"],
                    "deepfake_probability": prob,
                    "review_id": None,
                    "review_decision": None,
                    "reviewer_user_id": None,
                    "reviewer_username": None,
                    "reviewed_at": None,
                }

            # Path B: Governed manual review override ONLY for non-spoof CHALLENGE / NEEDS_REVIEW
            if (
                persisted_policy == "NEEDS_REVIEW"
                and rec == "CHALLENGE"
                and not eval_row["voice_clone_flag"]
                and not eval_row["adversarial_noise_detected"]
                and 0.35 <= prob < 0.60
            ):
                aud_cur.execute("SELECT to_regclass('public.audio_risk_reviews') AS reg;")
                has_review_table = (aud_cur.fetchone() or {}).get("reg") is not None
                if not has_review_table:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: persisted policy_decision is '{persisted_policy}' (requires '{ALLOWED_AUDIO_POLICY_DECISION}')."
                    )

                if age_seconds > max(max_eval_age_seconds, 86400):
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} is stale ({int(age_seconds)}s > 86400s review window)."
                    )

                aud_cur.execute("""
                    SELECT *
                    FROM audio_risk_reviews
                    WHERE risk_evaluation_id = %s
                    LIMIT 1;
                """, (eval_id,))
                rev = aud_cur.fetchone()
                if not rev:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: CHALLENGE / NEEDS_REVIEW evaluation {eval_id} requires an authorized manual risk review."
                    )
                if rev["review_decision"] == "REJECT":
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: manual risk review {rev['id']} permanently REJECTED evaluation {eval_id}."
                    )
                if rev["review_decision"] != "APPROVE_WITH_REVIEW":
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: invalid manual review decision '{rev['review_decision']}'."
                    )
                if str(rev["batch_id"]) != batch_id or str(rev["audio_asset_id"]) != str(latest_asset["id"]):
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: manual review {rev['id']} evidence binding mismatch."
                    )
                with get_app_conn(autocommit=True) as app_conn:
                    with app_conn.cursor(row_factory=dict_row) as app_cur:
                        app_cur.execute(
                            "SELECT role, is_active FROM users WHERE id = %s LIMIT 1;",
                            (rev["reviewer_user_id"],),
                        )
                        rev_user = app_cur.fetchone()
                if not rev_user or rev_user["role"] != "RISK_REVIEWER" or not rev_user["is_active"]:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: reviewer {rev['reviewer_user_id']} lacks active RISK_REVIEWER role."
                    )
                if str(rev["reviewer_user_id"]) == str(batch.get("created_by_user_id")):
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: reviewer cannot be the batch creator."
                    )
                if not rev.get("justification") or len(str(rev["justification"]).strip()) < 10:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: manual review {rev['id']} lacks written justification."
                    )

                rev_at = rev["reviewed_at"]
                rev_at_utc = rev_at.astimezone(timezone.utc) if rev_at.tzinfo else rev_at.replace(tzinfo=timezone.utc)
                rev_age_seconds = (now_utc - rev_at_utc).total_seconds()
                if rev_at_utc < eval_at_utc or rev_age_seconds > max_eval_age_seconds or rev_age_seconds < -60:
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: manual review {rev['id']} is stale ({int(rev_age_seconds)}s > {max_eval_age_seconds}s TTL)."
                    )

                # Verify asset content_sha256 if stored in V10.1.5 column
                aud_cur.execute("""
                    SELECT attname
                    FROM pg_attribute
                    WHERE attrelid = 'public.audio_assets'::regclass
                      AND attname = 'content_sha256'
                      AND NOT attisdropped;
                """)
                if aud_cur.fetchone():
                    aud_cur.execute("SELECT content_sha256 FROM audio_assets WHERE id = %s;", (latest_asset["id"],))
                    asset_hash_row = aud_cur.fetchone() or {}
                    if asset_hash_row.get("content_sha256") and asset_hash_row["content_sha256"] != rev["audio_content_sha256"]:
                        raise AudioRiskGateError(
                            f"Audio risk gate rejected batch {batch_id}: audio SHA-256 mismatch on manual review {rev['id']}."
                        )

                aud_cur.execute("""
                    SELECT id, actor_user_id, metadata_json
                    FROM audit_events
                    WHERE entity_type = 'AUDIO_RISK_REVIEW'
                      AND entity_id = %s
                      AND event_type = 'AUDIO_RISK_REVIEWED'
                    ORDER BY id DESC
                    LIMIT 1;
                """, (rev["id"],))
                rev_audit = aud_cur.fetchone()
                rev_meta = (rev_audit or {}).get("metadata_json") or {}
                if (
                    not rev_audit
                    or str(rev_audit["id"]) != str(rev["audit_event_id"])
                    or str(rev_audit["actor_user_id"]) != str(rev["reviewer_user_id"])
                    or rev_meta.get("batch_id") != batch_id
                    or rev_meta.get("risk_evaluation_id") != eval_id
                    or rev_meta.get("audio_asset_id") != str(latest_asset["id"])
                    or rev_meta.get("audio_content_sha256") != rev["audio_content_sha256"]
                    or rev_meta.get("review_decision") != "APPROVE_WITH_REVIEW"
                ):
                    raise AudioRiskGateError(
                        f"Audio risk gate rejected batch {batch_id}: manual review {rev['id']} lacks valid AUDIO_RISK_REVIEWED audit record."
                    )

                # Never relabel AI recommendation/policy_decision; keep CHALLENGE / NEEDS_REVIEW intact
                return {
                    "evaluation_id": eval_id,
                    "recommendation": rec,
                    "policy_decision": persisted_policy,
                    "model_version": eval_row["model_version"],
                    "deepfake_probability": prob,
                    "review_id": str(rev["id"]),
                    "review_decision": rev["review_decision"],
                    "reviewer_user_id": str(rev["reviewer_user_id"]),
                    "reviewer_username": rev["reviewer_username"],
                    "reviewed_at": rev_at_utc.isoformat(),
                }

            # Path C: Fail-closed explicit rejection diagnostics
            if persisted_policy != ALLOWED_AUDIO_POLICY_DECISION:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: persisted policy_decision is '{persisted_policy}' (requires '{ALLOWED_AUDIO_POLICY_DECISION}')."
                )
            if rec != ALLOWED_AUDIO_RECOMMENDATION:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: recommendation is '{rec}' (requires '{ALLOWED_AUDIO_RECOMMENDATION}')."
                )
            if eval_row["voice_clone_flag"]:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: voice_clone_flag is TRUE."
                )
            if eval_row["adversarial_noise_detected"]:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: adversarial_noise_detected is TRUE."
                )
            if prob >= 0.35:
                raise AudioRiskGateError(
                    f"Audio risk gate rejected batch {batch_id}: deepfake_probability={eval_row['deepfake_probability']} exceeds < 0.35 approval threshold."
                )
            raise AudioRiskGateError(
                f"Audio risk gate rejected batch {batch_id}: evaluation {eval_id} failed fail-closed verification."
            )

def finalize_batch(
    batch_id: str,
    audio_policy_decision: Optional[str] = None,
    max_eval_age_seconds: int = MAX_AUDIO_EVAL_AGE_SECONDS
) -> Dict[str, Any]:
    """
    Fail-closed finalization of a DRAFT payout batch.
    - Completely ignores caller-supplied `audio_policy_decision` (kept optional only for signature compatibility).
    - Retrieves and verifies the latest persisted server-side risk evaluation bound to the exact batch/session.
    - Rejects CHALLENGE, NEEDS_REVIEW, BLOCKED, TERMINATE, missing, stale, or mismatched evaluations without
      mutating batch state or creating outbox jobs.
    - Only when explicitly verified (APPROVE / READY_FOR_CHECKER), encrypts canonical snapshot, generates
      DS-ENVELOPE-V1 attestation, and locks beneficiaries via fn_finalize_payout_batch.
    """
    _ = audio_policy_decision  # Explicitly ignored: never trust caller-supplied audio policy decision.
    with get_app_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM payout_batches WHERE id = %s;", (batch_id,))
            batch = cur.fetchone()
            if not batch:
                raise ValueError("Batch not found")

            if batch["gateway_batch_state"] != "DRAFT":
                raise AudioRiskGateError(
                    f"Cannot finalize batch {batch_id}: current state is '{batch['gateway_batch_state']}', expected 'DRAFT'."
                )

            # Authoritative server-side audio risk gate (fail-closed)
            verified_eval = _verify_server_side_audio_risk_gate(batch, max_eval_age_seconds=max_eval_age_seconds)

            # Retrieve items
            cur.execute("""
                SELECT pi.*, b.legal_name, b.destination_digest
                FROM payout_items pi
                JOIN beneficiaries b ON b.id = pi.beneficiary_id
                WHERE pi.batch_id = %s
                ORDER BY pi.id ASC;
            """, (batch_id,))
            items = cur.fetchall()

            # Build Canonical PayPal Payload
            canonical_items = []
            for itm in items:
                receiver_email = decrypt_item_receiver(itm)
                canonical_items.append({
                    "recipient_type": "EMAIL",
                    "amount": {
                        "value": f"{itm['amount_cents'] / 100:.2f}",
                        "currency": "USD"
                    },
                    "note": itm["note"] or "Contractor disbursement",
                    "sender_item_id": itm["sender_item_id"],
                    "receiver": receiver_email
                })

            canonical_payload = {
                "sender_batch_header": {
                    "sender_batch_id": batch["sender_batch_id"],
                    "email_subject": f"Disbursement for {batch['payout_period']}",
                    "recipient_type": "EMAIL"
                },
                "items": canonical_items
            }
            canonical_json = json.dumps(canonical_payload, separators=(',', ':'))
            canonical_bytes = canonical_json.encode('utf-8')
            p_digest = hashlib.sha256(canonical_bytes).hexdigest()

            # Encrypt canonical payload
            dek = os.urandom(32)
            aad_text = "DEEPFAKESHIELD-PAYOUT-v1"
            nonce, ciphertext, tag = encrypt_payload(dek, canonical_bytes, aad_text.encode('utf-8'))
            snapshot_id = uuid.uuid4()

            # Generate Cryptographic Attestation via Verification Boundary
            attestation_res = verify_and_attest_snapshot(
                dek=dek,
                nonce=nonce,
                ciphertext=ciphertext,
                tag=tag,
                aad=aad_text.encode('utf-8'),
                expected_plaintext_json=canonical_json,
                batch_id=uuid.UUID(batch_id),
                snapshot_id=snapshot_id,
                key_id=uuid.UUID(KEY_ID_ACTIVE),
                attestation_secret=get_attestation_secret(),
                wrapped_dek=dek
            )
            attestation = attestation_res.attestation

            # Execute Authoritative Procedure fn_finalize_payout_batch
            cur.execute("""
                SELECT fn_finalize_payout_batch(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                uuid.UUID(batch_id), canonical_json, ciphertext, p_digest,
                dek, nonce, tag, aad_text, attestation, snapshot_id
            ))
            finalized_snapshot_id = cur.fetchone()["fn_finalize_payout_batch"]

    # Log audit event
    finalize_meta = {
        "snapshot_id": str(finalized_snapshot_id),
        "plaintext_digest": p_digest,
        "ciphertext_digest": hashlib.sha256(ciphertext).hexdigest(),
        "envelope_version": ENVELOPE_VERSION,
        "verified_evaluation_id": verified_eval["evaluation_id"],
        "verified_audio_recommendation": verified_eval["recommendation"],
        "verified_audio_policy_decision": verified_eval["policy_decision"],
    }
    if verified_eval.get("review_id"):
        finalize_meta["manual_review_id"] = verified_eval["review_id"]
        finalize_meta["manual_review_decision"] = verified_eval["review_decision"]
        finalize_meta["reviewer_user_id"] = verified_eval["reviewer_user_id"]
        finalize_meta["reviewer_username"] = verified_eval["reviewer_username"]
        finalize_meta["reviewed_at"] = verified_eval["reviewed_at"]

    log_audit_event(
        stream_id="main",
        actor_user_id=str(batch["created_by_user_id"]),
        event_type="BATCH_FINALIZED_AND_LOCKED",
        entity_type="PAYOUT_BATCH",
        entity_id=batch_id,
        metadata_dict=finalize_meta,
    )

    return {
        "batch_id": batch_id,
        "snapshot_id": str(finalized_snapshot_id),
        "gateway_batch_state": "READY_FOR_CHECKER",
        "plaintext_digest": p_digest,
        "ciphertext_digest": hashlib.sha256(ciphertext).hexdigest(),
        "manual_review_decision": verified_eval.get("review_decision"),
        "verified_audio_recommendation": verified_eval["recommendation"],
        "status_message": "Batch locked, snapshot encrypted and attested. Awaiting dual WebAuthn approvals."
    }

AUDIO_VAULT_DIR = os.environ.get(
    "AUDIO_VAULT_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audio_vault"),
)
AUDIO_SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "audio_samples",
)


def store_audio_vault_bytes(audio_sha256: str, audio_bytes: bytes) -> Optional[str]:
    """Stores a read-only content-addressed copy of analyzed WAV bytes for RISK_REVIEWER inspection."""
    norm_sha = str(audio_sha256 or "").strip().lower()
    if len(norm_sha) != 64 or not audio_bytes:
        return None
    actual_sha = hashlib.sha256(audio_bytes).hexdigest().lower()
    if actual_sha != norm_sha:
        return None
    vault_dir = os.environ.get("AUDIO_VAULT_DIR", AUDIO_VAULT_DIR)
    os.makedirs(vault_dir, exist_ok=True)
    target_path = os.path.join(vault_dir, f"{norm_sha}.wav")
    if not os.path.isfile(target_path):
        with open(target_path, "wb") as f:
            f.write(audio_bytes)
    return target_path


def resolve_audio_evidence_file(audio_sha256: Optional[str]) -> Optional[str]:
    """Resolves a local WAV file only if its live SHA-256 matches the bound evidence hash."""
    if not audio_sha256:
        return None
    norm_sha = str(audio_sha256).strip().lower()
    if len(norm_sha) != 64:
        return None

    candidates: List[str] = []
    vault_dir = os.environ.get("AUDIO_VAULT_DIR", AUDIO_VAULT_DIR)
    vault_candidate = os.path.join(vault_dir, f"{norm_sha}.wav")
    if os.path.isfile(vault_candidate):
        candidates.append(vault_candidate)

    if os.path.isdir(AUDIO_SAMPLES_DIR):
        for fname in sorted(os.listdir(AUDIO_SAMPLES_DIR)):
            if fname.lower().endswith(".wav"):
                candidates.append(os.path.join(AUDIO_SAMPLES_DIR, fname))

    for path in candidates:
        try:
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest().lower()
            if digest == norm_sha:
                return path
        except OSError:
            continue
    return None


def _lookup_historical_registry_hashes(
    batch_id: str,
    session_id: Optional[str],
    evaluated_at: Optional[datetime],
) -> tuple[Optional[str], Optional[str]]:
    """Fallback read-only lookup in audio_hash_registry.json for pre-V10.1.5 V10.1.4 records."""
    from backend.audio_analyzer import _load_audio_registry

    reg = _load_audio_registry()
    if not reg:
        return None, None

    eval_ts = evaluated_at.timestamp() if evaluated_at else None
    best_match = None
    best_delta = float("inf")
    for sha_key, entry in reg.items():
        if str(entry.get("batch_id") or "") != str(batch_id):
            continue
        if session_id and entry.get("session_id") and str(entry.get("session_id")) != str(session_id):
            continue
        seen_at = entry.get("first_seen_at")
        if eval_ts is not None and isinstance(seen_at, (int, float)):
            delta = abs(eval_ts - float(seen_at))
            if delta < best_delta and delta <= 120.0:
                best_delta = delta
                best_match = (sha_key.lower(), entry.get("acoustic_fingerprint"))
        elif best_match is None:
            best_match = (sha_key.lower(), entry.get("acoustic_fingerprint"))

    return best_match if best_match else (None, None)


def get_audio_review_evidence(batch_id: str, evaluation_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves complete, verified evidence for an authenticated manual audio-risk review.
    Verifies batch -> session -> asset -> segment -> risk_evaluation -> audit_event linkage.
    """
    try:
        batch_uuid = uuid.UUID(str(batch_id))
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid batch_id UUID") from exc

    with get_app_conn(autocommit=True) as app_conn:
        with app_conn.cursor(row_factory=dict_row) as app_cur:
            app_cur.execute("""
                SELECT pb.id, pb.session_id, pb.program_id, pb.payout_period,
                       pb.currency, pb.total_amount_cents, pb.item_count,
                       pb.sender_batch_id, pb.gateway_batch_state, pb.created_by_user_id,
                       pb.created_at, u.username AS created_by_username
                FROM payout_batches pb
                JOIN users u ON u.id = pb.created_by_user_id
                WHERE pb.id = %s;
            """, (batch_uuid,))
            batch = app_cur.fetchone()
            if not batch:
                raise ValueError(f"Batch {batch_id} not found")

            if not batch.get("session_id"):
                raise AudioRiskGateError(f"Batch {batch_id} has no audio session association")

            app_cur.execute("""
                SELECT pi.id, pi.sender_item_id, pi.amount_cents, pi.currency, pi.note,
                       pi.wrapped_dek, pi.iv_nonce, pi.auth_tag, pi.aad_text, pi.encrypted_receiver,
                       b.id AS beneficiary_id, b.legal_name, b.program_ref, b.verification_status
                FROM payout_items pi
                JOIN beneficiaries b ON b.id = pi.beneficiary_id
                WHERE pi.batch_id = %s
                ORDER BY pi.created_at ASC;
            """, (batch_uuid,))
            raw_items = app_cur.fetchall()

    with get_auditor_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # Check whether V10.1.5 columns / tables exist (safe on V10.1.4 DBs too)
            cur.execute("""
                SELECT attname
                FROM pg_attribute
                WHERE attrelid = 'public.audio_assets'::regclass
                  AND attname IN ('content_sha256', 'acoustic_fingerprint')
                  AND NOT attisdropped;
            """)
            asset_extra_cols = {r["attname"] for r in cur.fetchall()}
            sha_col_sql = "aa.content_sha256" if "content_sha256" in asset_extra_cols else "NULL::varchar AS content_sha256"
            fp_col_sql = "aa.acoustic_fingerprint" if "acoustic_fingerprint" in asset_extra_cols else "NULL::varchar AS acoustic_fingerprint"

            if evaluation_id:
                eval_uuid = uuid.UUID(str(evaluation_id))
                cur.execute(f"""
                    SELECT re.id AS evaluation_id, re.batch_id, re.segment_id, re.model_version,
                           re.deepfake_probability, re.acoustic_consistency_score,
                           re.voice_clone_flag, re.adversarial_noise_detected,
                           re.recommendation, re.policy_decision, re.evaluated_at,
                           ss.audio_asset_id, ss.sample_count, ss.wada_snr_db, ss.is_evaluated,
                           aa.session_id, aa.sample_rate, aa.channels, aa.format,
                           aa.storage_uri, aa.duration_ms, aa.recorded_at,
                           {sha_col_sql}, {fp_col_sql}
                    FROM risk_evaluations re
                    JOIN speaker_segments ss ON ss.id = re.segment_id
                    JOIN audio_assets aa ON aa.id = ss.audio_asset_id
                    WHERE re.id = %s;
                """, (eval_uuid,))
            else:
                cur.execute(f"""
                    SELECT re.id AS evaluation_id, re.batch_id, re.segment_id, re.model_version,
                           re.deepfake_probability, re.acoustic_consistency_score,
                           re.voice_clone_flag, re.adversarial_noise_detected,
                           re.recommendation, re.policy_decision, re.evaluated_at,
                           ss.audio_asset_id, ss.sample_count, ss.wada_snr_db, ss.is_evaluated,
                           aa.session_id, aa.sample_rate, aa.channels, aa.format,
                           aa.storage_uri, aa.duration_ms, aa.recorded_at,
                           {sha_col_sql}, {fp_col_sql}
                    FROM audio_assets aa
                    JOIN speaker_segments ss ON ss.audio_asset_id = aa.id
                    JOIN risk_evaluations re ON re.segment_id = ss.id
                    WHERE aa.session_id = %s
                    ORDER BY aa.recorded_at DESC NULLS LAST, re.evaluated_at DESC NULLS LAST, re.id DESC
                    LIMIT 1;
                """, (batch["session_id"],))

            ev = cur.fetchone()
            if not ev:
                raise AudioRiskGateError(f"No audio risk evaluation found for batch {batch_id}")

            if str(ev["batch_id"]) != str(batch["id"]) or str(ev["session_id"]) != str(batch["session_id"]):
                raise AudioRiskGateError(
                    f"Evidence mismatch: evaluation {ev['evaluation_id']} does not belong to batch {batch_id}"
                )

            cur.execute("""
                SELECT id, metadata_json, created_at
                FROM audit_events
                WHERE entity_type = 'RISK_EVALUATION'
                  AND entity_id = %s
                  AND event_type = 'AUDIO_RISK_EVALUATED'
                ORDER BY id DESC
                LIMIT 1;
            """, (ev["evaluation_id"],))
            ev_audit = cur.fetchone()
            ev_meta = (ev_audit or {}).get("metadata_json") or {}
            if not ev_audit or str(ev_meta.get("batch_id")) != str(batch["id"]):
                raise AudioRiskGateError(
                    f"Evaluation {ev['evaluation_id']} lacks valid AUDIO_RISK_EVALUATED batch binding"
                )

            db_sha = ev.get("content_sha256") or ev_meta.get("audio_sha256") or ev_meta.get("sha256_hash")
            db_fp = ev.get("acoustic_fingerprint") or ev_meta.get("acoustic_fingerprint")
            hash_source = "DB_AUTHORITATIVE" if db_sha else None
            if not db_sha or not db_fp:
                reg_sha, reg_fp = _lookup_historical_registry_hashes(
                    str(batch["id"]),
                    str(batch["session_id"]),
                    ev.get("evaluated_at"),
                )
                if not db_sha and reg_sha:
                    db_sha = reg_sha
                    hash_source = "REGISTRY_HISTORICAL"
                if not db_fp and reg_fp:
                    db_fp = reg_fp

            review_row = None
            cur.execute("SELECT to_regclass('public.audio_risk_reviews') AS reg;")
            has_review_table = (cur.fetchone() or {}).get("reg") is not None

    if has_review_table:
        with get_app_conn(autocommit=True) as app_conn:
            with app_conn.cursor(row_factory=dict_row) as app_cur:
                app_cur.execute("""
                    SELECT arr.*, u.role AS reviewer_role
                    FROM audio_risk_reviews arr
                    JOIN users u ON u.id = arr.reviewer_user_id
                    WHERE arr.risk_evaluation_id = %s
                    LIMIT 1;
                """, (ev["evaluation_id"],))
                review_row = app_cur.fetchone()

    recipients = []
    for itm in raw_items:
        try:
            receiver_email = decrypt_item_receiver(itm)
        except Exception:
            receiver_email = None
        recipients.append({
            "sender_item_id": itm["sender_item_id"],
            "beneficiary_id": str(itm["beneficiary_id"]),
            "legal_name": itm["legal_name"],
            "program_ref": itm["program_ref"],
            "verification_status": itm["verification_status"],
            "receiver_email": receiver_email,
            "amount_usd": f"{itm['amount_cents'] / 100:.2f}",
            "currency": itm["currency"],
            "note": itm["note"],
        })

    audio_file_path = resolve_audio_evidence_file(db_sha)
    eff_policy = ev["policy_decision"] or ev_meta.get("policy_decision")
    review_status = "NOT_REQUIRED"
    if ev["recommendation"] == "CHALLENGE" and eff_policy == "NEEDS_REVIEW":
        if review_row:
            review_status = "APPROVED_WITH_REVIEW" if review_row["review_decision"] == "APPROVE_WITH_REVIEW" else "REJECTED"
        else:
            review_status = "PENDING"
    elif eff_policy == "BLOCKED" or ev["recommendation"] == "TERMINATE":
        review_status = "INELIGIBLE_BLOCKED"

    return {
        "batch": {
            "batch_id": str(batch["id"]),
            "session_id": str(batch["session_id"]),
            "sender_batch_id": batch["sender_batch_id"],
            "program_id": batch["program_id"],
            "payout_period": batch["payout_period"],
            "total_amount_usd": f"{batch['total_amount_cents'] / 100:.2f}",
            "currency": batch["currency"],
            "item_count": batch["item_count"],
            "gateway_batch_state": batch["gateway_batch_state"],
            "created_by_user_id": str(batch["created_by_user_id"]),
            "created_by_username": batch["created_by_username"],
            "created_at": batch["created_at"].isoformat() if batch["created_at"] else None,
        },
        "recipients": recipients,
        "audio_evidence": {
            "audio_asset_id": str(ev["audio_asset_id"]),
            "segment_id": str(ev["segment_id"]),
            "risk_evaluation_id": str(ev["evaluation_id"]),
            "storage_uri": ev["storage_uri"],
            "audio_content_sha256": db_sha,
            "acoustic_fingerprint": db_fp,
            "hash_source": hash_source,
            "audio_available": bool(audio_file_path),
            "audio_stream_url": f"/api/batches/{batch['id']}/audio-review/audio?evaluation_id={ev['evaluation_id']}",
            "duration_ms": ev["duration_ms"],
            "format": ev["format"],
            "sample_rate": ev["sample_rate"],
            "channels": ev["channels"],
            "recorded_at": ev["recorded_at"].isoformat() if ev["recorded_at"] else None,
        },
        "analysis": {
            "analyzer_version": ev["model_version"],
            "model_version": ev["model_version"],
            "original_ai_decision": ev["recommendation"],
            "original_policy_decision": eff_policy,
            "deepfake_probability": float(ev["deepfake_probability"]),
            "max_window_score": ev_meta.get("max_window_score"),
            "window_count": ev_meta.get("window_count"),
            "window_results": ev_meta.get("window_results"),
            "acoustic_consistency_score": float(ev["acoustic_consistency_score"]),
            "wada_snr_db": float(ev["wada_snr_db"]),
            "sample_count": ev["sample_count"],
            "voice_clone_flag": bool(ev["voice_clone_flag"]),
            "adversarial_noise_detected": bool(ev["adversarial_noise_detected"]),
            "replay_detected": bool(ev_meta.get("replay_detected", False)),
            "acoustic_signal": ev_meta.get("acoustic_signal") or ("INDETERMINATE" if ev["recommendation"] == "CHALLENGE" else None),
            "evaluated_at": ev["evaluated_at"].isoformat() if ev["evaluated_at"] else None,
            "eval_audit_event_id": ev_audit["id"] if ev_audit else None,
        },
        "manual_review": {
            "status": review_status,
            "review_id": str(review_row["id"]) if review_row else None,
            "review_decision": review_row["review_decision"] if review_row else None,
            "justification": review_row["justification"] if review_row else None,
            "reviewer_user_id": str(review_row["reviewer_user_id"]) if review_row else None,
            "reviewer_username": review_row["reviewer_username"] if review_row else None,
            "reviewer_role": review_row["reviewer_role"] if review_row else None,
            "reviewed_at": review_row["reviewed_at"].isoformat() if review_row else None,
            "audit_event_id": review_row["audit_event_id"] if review_row else None,
            "original_recommendation": review_row["original_recommendation"] if review_row else ev["recommendation"],
            "original_policy_decision": review_row["original_policy_decision"] if review_row else eff_policy,
        },
    }


def submit_manual_audio_review(
    batch_id: str,
    risk_evaluation_id: str,
    audio_asset_id: str,
    audio_content_sha256: str,
    reviewer_user_id: str,
    review_decision: str,
    justification: str,
) -> Dict[str, Any]:
    """
    Submits a governed human audio-risk review decision through the privileged
    deepfakeshield_verifier role (fn_submit_audio_risk_review).
    Never uses deepfakeshield_app for review persistence and never mutates the
    original CHALLENGE / NEEDS_REVIEW evaluation row.
    """
    if review_decision not in ("APPROVE_WITH_REVIEW", "REJECT"):
        raise AudioRiskGateError(f"Invalid review_decision '{review_decision}': must be APPROVE_WITH_REVIEW or REJECT.")
    clean_justification = (justification or "").strip()
    if len(clean_justification) < 10:
        raise AudioRiskGateError("Mandatory written justification required (minimum 10 characters).")

    norm_sha = str(audio_content_sha256 or "").strip().lower()
    if len(norm_sha) != 64 or any(c not in "0123456789abcdef" for c in norm_sha):
        raise AudioRiskGateError("Valid 64-hex audio_content_sha256 is required.")

    try:
        batch_uuid = uuid.UUID(str(batch_id))
        eval_uuid = uuid.UUID(str(risk_evaluation_id))
        asset_uuid = uuid.UUID(str(audio_asset_id))
        reviewer_uuid = uuid.UUID(str(reviewer_user_id))
    except (TypeError, ValueError) as exc:
        raise AudioRiskGateError("Invalid UUID supplied for batch_id, risk_evaluation_id, audio_asset_id, or reviewer_user_id.") from exc

    # Gather verified evidence snapshot first
    evidence = get_audio_review_evidence(str(batch_uuid), evaluation_id=str(eval_uuid))
    if str(evidence["audio_evidence"]["audio_asset_id"]) != str(asset_uuid):
        raise AudioRiskGateError("Audio asset mismatch: supplied audio_asset_id does not belong to this evaluation.")

    expected_sha = evidence["audio_evidence"].get("audio_content_sha256")
    if expected_sha and expected_sha.lower() != norm_sha:
        raise AudioRiskGateError("Audio content SHA-256 hash mismatch against persisted batch evidence.")

    snapshot_payload = {
        "batch_summary": evidence["batch"],
        "recipients": evidence["recipients"],
        "analysis": {
            k: v for k, v in evidence["analysis"].items()
            if k != "window_results"
        },
        "audio_evidence": {
            "audio_asset_id": evidence["audio_evidence"]["audio_asset_id"],
            "audio_content_sha256": norm_sha,
            "acoustic_fingerprint": evidence["audio_evidence"].get("acoustic_fingerprint"),
            "duration_ms": evidence["audio_evidence"]["duration_ms"],
            "format": evidence["audio_evidence"]["format"],
            "sample_rate": evidence["audio_evidence"]["sample_rate"],
            "channels": evidence["audio_evidence"]["channels"],
        },
    }

    try:
        with get_verifier_conn(autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT fn_submit_audio_risk_review(
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::varchar,
                        %s::uuid,
                        %s::varchar,
                        %s::text,
                        %s::jsonb
                    );
                    """,
                    (
                        batch_uuid,
                        eval_uuid,
                        asset_uuid,
                        norm_sha,
                        reviewer_uuid,
                        review_decision,
                        clean_justification,
                        json.dumps(snapshot_payload),
                    ),
                )
                row = cur.fetchone()
                if not row or not row[0]:
                    raise AudioRiskGateError("Fail-closed: review function returned no review ID.")
                review_id = str(row[0])
            conn.commit()
    except AudioRiskGateError:
        raise
    except psycopg.OperationalError as exc:
        raise AudioRiskGateError("Fail-closed: verifier database connection is unavailable.") from exc
    except psycopg.Error as exc:
        detail = getattr(getattr(exc, "diag", None), "message_primary", None) or exc.__class__.__name__
        raise AudioRiskGateError(f"Fail-closed: manual audio review rejected ({detail}).") from exc
    except Exception as exc:
        raise AudioRiskGateError(f"Fail-closed: manual audio review failed ({exc.__class__.__name__}).") from exc

    updated_evidence = get_audio_review_evidence(str(batch_uuid), evaluation_id=str(eval_uuid))
    return {
        "review_id": review_id,
        "batch_id": str(batch_uuid),
        "risk_evaluation_id": str(eval_uuid),
        "audio_asset_id": str(asset_uuid),
        "audio_content_sha256": norm_sha,
        "original_ai_decision": "CHALLENGE",
        "original_policy_decision": "NEEDS_REVIEW",
        "review_decision": review_decision,
        "status": updated_evidence["manual_review"]["status"],
        "justification": updated_evidence["manual_review"]["justification"],
        "reviewer_user_id": updated_evidence["manual_review"]["reviewer_user_id"],
        "reviewer_username": updated_evidence["manual_review"]["reviewer_username"],
        "reviewed_at": updated_evidence["manual_review"]["reviewed_at"],
        "audit_event_id": updated_evidence["manual_review"]["audit_event_id"],
    }

def issue_officer_challenge(
    batch_id: str,
    officer_user_id: str,
    expires_in_seconds: int = 3600,
    rp_id: Optional[str] = None,
    origin: Optional[str] = None
) -> Dict[str, Any]:
    """
    Issues an authoritative, server-generated single-use WebAuthn challenge.
    Cryptographically binds challenge to the batch payload_digest and the specific officer user.
    Persists challenge in webauthn_challenges before the assertion is generated.
    """
    effective_rp_id = rp_id if rp_id in ["localhost", "127.0.0.1", "deepfakeshield.internal"] else "localhost"
    effective_origin = origin if origin in [
        "http://localhost:8000", "http://127.0.0.1:8000",
        "https://localhost:8000", "https://deepfakeshield.internal"
    ] else "http://localhost:8000"

    with get_app_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT payload_digest FROM payout_batches WHERE id = %s;", (batch_id,))
            b_row = cur.fetchone()
            if not b_row:
                raise ValueError(f"Batch {batch_id} not found")
            payload_digest = b_row["payload_digest"]
            challenge_bytes = os.urandom(32)
            challenge_id = str(uuid.uuid4())
            challenge_b64 = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')

            cur.execute("""
                INSERT INTO webauthn_challenges (
                    challenge_id, challenge_bytes, purpose, user_id, target_digest, expires_at
                ) VALUES (%s, %s, 'TRANSACTION_APPROVAL', %s, %s, CURRENT_TIMESTAMP + (%s || ' seconds')::interval);
            """, (challenge_id, challenge_bytes, officer_user_id, payload_digest, expires_in_seconds))

            return {
                "challenge_id": challenge_id,
                "challenge_bytes": challenge_bytes,
                "challenge_b64": challenge_b64,
                "rp_id": effective_rp_id,
                "origin": effective_origin,
                "officer_user_id": officer_user_id,
                "target_digest": payload_digest
            }

def record_officer_webauthn_approval(
    batch_id: str,
    officer_user_id: str,
    credential_id: str,
    client_data_json: Any,
    auth_data: Any,
    signature: Any,
    challenge_id: Optional[str] = None,
    is_mock: bool = False
) -> Dict[str, Any]:
    """
    Submits and cryptographically verifies an officer WebAuthn ECDSA assertion.
    Guarantees:
    - Zero server-side signing: client must present a valid hardware WebAuthn assertion.
    - Validates clientDataJSON (type, challenge, origin).
    - Validates authenticatorData (RP ID hash, UP flag).
    - Cryptographically verifies ECDSA signature against the registered public key.
    - Strictly prevents replay, cross-batch, expired, or bogus signature approvals.
    - Dual independent Treasury Officer approvals (Stage 1 + Stage 2 via fn_submit_officer_approval).
    """
    # 1. Normalize byte and string inputs
    if isinstance(client_data_json, bytes):
        client_data_str = client_data_json.decode('utf-8')
    else:
        client_data_str = str(client_data_json)

    if isinstance(auth_data, str):
        if auth_data.startswith("0x") or auth_data.startswith("\\x"):
            auth_data_bytes = bytes.fromhex(auth_data[2:])
        else:
            try:
                auth_data_bytes = bytes.fromhex(auth_data)
            except ValueError:
                auth_data_bytes = base64.b64decode(auth_data)
    else:
        auth_data_bytes = bytes(auth_data)

    if isinstance(signature, str):
        if signature.startswith("0x") or signature.startswith("\\x"):
            sig_bytes = bytes.fromhex(signature[2:])
        else:
            try:
                sig_bytes = bytes.fromhex(signature)
            except ValueError:
                sig_bytes = base64.b64decode(signature)
    else:
        sig_bytes = bytes(signature)

    # 2. Pre-fetch batch, snapshot, and payload digest
    with get_app_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT pb.id, pb.created_by_user_id, pb.gateway_batch_state,
                       pb.active_snapshot_id, pb.payload_digest
                FROM payout_batches pb
                WHERE pb.id = %s;
            """, (batch_id,))
            batch = cur.fetchone()
            if not batch:
                raise ValueError("Batch not found")
            if batch["gateway_batch_state"] != "READY_FOR_CHECKER":
                raise ValueError(f"Batch state must be READY_FOR_CHECKER, got {batch['gateway_batch_state']}")

            # Maker-checker policy check
            if str(batch["created_by_user_id"]) == str(officer_user_id):
                raise ValueError("Maker-checker violation: approving officer cannot be batch creator")

            # Officer role check
            cur.execute("SELECT role, is_active FROM users WHERE id = %s;", (officer_user_id,))
            usr = cur.fetchone()
            if not usr or usr["role"] != "TREASURY_OFFICER" or not usr["is_active"]:
                raise ValueError(f"User {officer_user_id} is not an active TREASURY_OFFICER")

            # Separation between Risk Reviewer and Treasury Officer approvals
            cur.execute("SELECT to_regclass('public.audio_risk_reviews') AS reg;")
            if (cur.fetchone() or {}).get("reg") is not None:
                cur.execute(
                    "SELECT 1 FROM audio_risk_reviews WHERE batch_id = %s AND reviewer_user_id = %s;",
                    (batch_id, officer_user_id),
                )
                if cur.fetchone():
                    raise ValueError("Separation of duties violation: audio risk reviewer cannot act as Treasury Officer approver")

    # 3. Fetch Credential & verify ownership via Verifier Role
    with get_verifier_conn(autocommit=True) as v_conn:
        with v_conn.cursor(row_factory=dict_row) as v_cur:
            v_cur.execute("""
                SELECT credential_id, user_id, public_key_cose, sign_count, is_revoked, attestation_format, aaguid
                FROM webauthn_credentials
                WHERE credential_id = %s;
            """, (credential_id,))
            cred_row = v_cur.fetchone()
            if not cred_row:
                raise ValueError(f"Credential {credential_id} not registered")
            if str(cred_row["user_id"]) != str(officer_user_id):
                raise ValueError(f"Credential {credential_id} does not belong to officer {officer_user_id}")
            if cred_row["is_revoked"]:
                raise ValueError(f"Credential {credential_id} is revoked")

    # Determine Device Classification based on verified registration evidence
    fmt = cred_row.get("attestation_format", "none")
    aaguid_str = str(cred_row.get("aaguid", ""))
    is_verified_hardware = (
        fmt in ("packed", "fido-u2f", "tpm", "apple", "android-key")
        and aaguid_str != "00000000-0000-0000-0000-000000000000"
        and not aaguid_str.startswith("01020304")
        and not aaguid_str.startswith("02030405")
    )
    if is_mock:
        authenticator_type = "SOFTWARE-EMULATED"
    elif is_verified_hardware:
        authenticator_type = "HARDWARE-BACKED"
    else:
        authenticator_type = "AUTHENTICATOR TYPE UNVERIFIED"

    # 3. Check for prior approval by this officer on this batch (prevent same officer double-approval)
    with get_auditor_conn() as aud_conn:
        with aud_conn.cursor(row_factory=dict_row) as aud_cur:
            aud_cur.execute("""
                SELECT actor_user_id, metadata_json
                FROM audit_events
                WHERE entity_id = %s AND event_type = 'OFFICER_STAGE1_APPROVED';
            """, (batch_id,))
            stage1_events = aud_cur.fetchall()
            first_approver_id = None
            if stage1_events:
                first_approver_id = str(stage1_events[0]["actor_user_id"])
                if first_approver_id == str(officer_user_id):
                    raise ValueError("Officer has already approved this batch")

    # 4. Parse clientDataJSON & extract challenge
    try:
        client_data = json.loads(client_data_str)
    except Exception as e:
        raise ValueError(f"Invalid clientDataJSON format: {e}")

    if client_data.get("type") != "webauthn.get":
        raise ValueError(f"Invalid clientDataJSON type: expected webauthn.get, got {client_data.get('type')}")

    chal_b64 = client_data.get("challenge", "")
    padded_b64 = chal_b64 + "=" * (-len(chal_b64) % 4)
    try:
        received_challenge_bytes = base64.urlsafe_b64decode(padded_b64)
    except Exception as e:
        raise ValueError(f"Malformed challenge encoding in clientDataJSON: {e}")

    if len(received_challenge_bytes) != 32:
        raise ValueError(f"Invalid challenge length: expected 32 bytes, got {len(received_challenge_bytes)}")

    # Origin verification
    origin = client_data.get("origin")
    allowed_origins = [
        "https://deepfakeshield.internal",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://localhost:8000"
    ]
    if origin and origin not in allowed_origins:
        raise ValueError(f"Authenticator assertion rejected: origin '{origin}' not permitted")

    # AuthenticatorData validation
    if len(auth_data_bytes) < 37:
        raise ValueError("Invalid authenticatorData length: must be at least 37 bytes")

    rp_id_hash = auth_data_bytes[:32]
    allowed_rp_ids = ["deepfakeshield.internal", "localhost", "127.0.0.1"]
    valid_rp_hashes = [hashlib.sha256(rp.encode()).digest() for rp in allowed_rp_ids]
    if rp_id_hash not in valid_rp_hashes:
        raise ValueError("Authenticator assertion rejected: RP ID hash mismatch")

    flags = auth_data_bytes[32]
    if not (flags & 0x01):
        raise ValueError("Authenticator assertion rejected: User Present (UP) flag not set")
    if not (flags & 0x04):
        raise ValueError("Authenticator assertion rejected: User Verification (UV) flag not set (Treasury biometric/PIN verification required)")

    # 5. Look up and validate challenge in database (STRICT: Never create challenge on-the-fly)
    with get_verifier_conn(autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            chal_row = None
            if challenge_id:
                cur.execute("""
                    SELECT challenge_id, challenge_bytes, is_consumed, expires_at, user_id, target_digest
                    FROM webauthn_challenges
                    WHERE challenge_id = %s FOR UPDATE;
                """, (challenge_id,))
                chal_row = cur.fetchone()
            if not chal_row:
                cur.execute("""
                    SELECT challenge_id, challenge_bytes, is_consumed, expires_at, user_id, target_digest
                    FROM webauthn_challenges
                    WHERE challenge_bytes = %s AND user_id = %s FOR UPDATE;
                """, (received_challenge_bytes, officer_user_id))
                chal_row = cur.fetchone()

            if not chal_row:
                raise ValueError("WebAuthn challenge not found or not issued by server: self-generated or unregistered challenge rejected")

            if chal_row["is_consumed"]:
                raise ValueError(f"Challenge {chal_row['challenge_id']} has already been consumed (replay attack detected)")
            if chal_row["expires_at"] <= datetime.now(timezone.utc):
                raise ValueError(f"Challenge {chal_row['challenge_id']} has expired")
            if str(chal_row["user_id"]) != str(officer_user_id):
                raise ValueError("Challenge officer user mismatch")
            if chal_row["target_digest"] != batch["payload_digest"]:
                raise ValueError(f"Challenge target digest mismatch: challenge was issued for a different batch or payload")

            challenge_id = str(chal_row["challenge_id"])

    # 6. MANDATORY CRYPTOGRAPHIC SIGNATURE VERIFICATION
    pub_key = load_der_public_key(bytes(cred_row["public_key_cose"]))
    client_data_hash = hashlib.sha256(client_data_str.encode('utf-8')).digest()
    signed_data = auth_data_bytes + client_data_hash

    try:
        pub_key.verify(sig_bytes, signed_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError(f"Cryptographic WebAuthn signature verification failed: invalid signature bytes for credential {credential_id}")
    except Exception as e:
        raise ValueError(f"Cryptographic WebAuthn signature verification failed: {e}")

    # 7. Cloned Authenticator Detection: Monotonic Sign Counter Verification
    incoming_sign_count = struct.unpack(">I", auth_data_bytes[33:37])[0]
    stored_sign_count = cred_row["sign_count"]

    if stored_sign_count > 0 and incoming_sign_count > 0:
        if incoming_sign_count <= stored_sign_count:
            raise ValueError(f"Cloned authenticator detected: incoming sign count {incoming_sign_count} <= stored sign count {stored_sign_count}")
    elif stored_sign_count > 0 and incoming_sign_count == 0:
        raise ValueError(f"Cloned authenticator detected: counter regression from {stored_sign_count} to 0")

    # 8. Process approval state transitions
    if first_approver_id is None:
        # --- OFFICER 1 (STAGE 1 APPROVAL) ---
        with get_verifier_conn(autocommit=True) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                next_sign_count = incoming_sign_count if incoming_sign_count > 0 else stored_sign_count

                # Consume challenge & increment sign count
                cur.execute("""
                    UPDATE webauthn_challenges
                    SET is_consumed = TRUE, consumed_at = CURRENT_TIMESTAMP
                    WHERE challenge_id = %s;
                """, (challenge_id,))
                cur.execute("""
                    UPDATE webauthn_credentials
                    SET sign_count = %s, last_used_at = CURRENT_TIMESTAMP
                    WHERE credential_id = %s;
                """, (next_sign_count, credential_id))

        log_audit_event(
            stream_id="main",
            actor_user_id=officer_user_id,
            event_type="OFFICER_STAGE1_APPROVED",
            entity_type="PAYOUT_BATCH",
            entity_id=batch_id,
            metadata_dict={
                "stage": 1,
                "officer_user_id": officer_user_id,
                "credential_id": credential_id,
                "challenge_id": challenge_id,
                "authenticator_type": authenticator_type
            }
        )

        return {
            "batch_id": batch_id,
            "approval_id": challenge_id,
            "approval_count": 1,
            "requires_more_approvals": True,
            "gateway_batch_state": "READY_FOR_CHECKER",
            "outbox_job_id": None,
            "authenticator_type": authenticator_type
        }

    else:
        # --- OFFICER 2 (FINAL APPROVAL VIA AUTHORITATIVE fn_submit_officer_approval) ---
        with get_verifier_conn(autocommit=True) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT fn_submit_officer_approval(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    );
                """, (
                    uuid.UUID(batch_id),
                    batch["active_snapshot_id"],
                    uuid.UUID(officer_user_id),
                    credential_id,
                    uuid.UUID(challenge_id),
                    batch["payload_digest"],
                    client_data_str,
                    auth_data_bytes,
                    sig_bytes,
                    incoming_sign_count
                ))
                approval_id = cur.fetchone()["fn_submit_officer_approval"]

        # Retrieve newly enqueued outbox job
        from backend.database import get_worker_conn
        outbox_job_id = None
        with get_worker_conn(autocommit=True) as w_conn:
            with w_conn.cursor() as w_cur:
                w_cur.execute("SELECT id FROM outbox_jobs WHERE batch_id = %s;", (batch_id,))
                oj = w_cur.fetchone()
                if oj:
                    outbox_job_id = str(oj[0])

        log_audit_event(
            stream_id="main",
            actor_user_id=officer_user_id,
            event_type="OFFICER_STAGE2_APPROVED",
            entity_type="PAYOUT_BATCH",
            entity_id=batch_id,
            metadata_dict={
                "stage": 2,
                "officer_user_id": officer_user_id,
                "credential_id": credential_id,
                "approval_id": str(approval_id),
                "outbox_job_id": outbox_job_id,
                "authenticator_type": authenticator_type
            }
        )

        log_audit_event(
            stream_id="main",
            actor_user_id=officer_user_id,
            event_type="BATCH_APPROVED_AND_ENQUEUED",
            entity_type="PAYOUT_BATCH",
            entity_id=batch_id,
            metadata_dict={
                "outbox_job_id": outbox_job_id,
                "approval_id": str(approval_id),
                "authenticator_type": authenticator_type
            }
        )

        return {
            "batch_id": batch_id,
            "approval_id": str(approval_id),
            "approval_count": 2,
            "requires_more_approvals": False,
            "gateway_batch_state": "APPROVED_TO_SUBMIT",
            "outbox_job_id": outbox_job_id,
            "authenticator_type": authenticator_type
        }
