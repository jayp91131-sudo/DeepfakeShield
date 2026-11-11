#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Outbox Worker & Settlement Engine
Milestone: V10.1.3 Hackathon Delivery Sprint

Implements:
1. Atomic Job Claim via fn_claim_outbox_job
2. Pre-Submission Envelope Authenticity & Attestation Check
3. Idempotent PayPal Sandbox Submission (PayPal-Request-Id header)
4. Failure Handling: Ambiguous Network Timeout -> MANUAL_RECONCILIATION_REQUIRED
5. Post-Submission Polling & Item Reconciliation via fn_record_provider_item_result
6. Job Completion via fn_complete_outbox_job & Beneficiary Lock Release
"""

import os
import uuid
import json
import hashlib
from typing import Dict, Any, Optional
import psycopg
from psycopg.rows import dict_row

from backend.database import (
    get_worker_conn,
    KEY_ID_ACTIVE,
    DEFAULT_ATTESTATION_SECRET
)
from backend.paypal_client import PayPalClient
from crypto_verifier import (
    verify_envelope_before_submission,
    DEFAULT_ATTESTATION_SECRET
)

class OutboxWorker:
    def __init__(self, worker_id: str = "worker-primary-node-01"):
        self.worker_id = worker_id
        self.paypal_client = PayPalClient()

    def process_next_job(self, force_timeout: bool = False) -> Optional[Dict[str, Any]]:
        """Claims and processes the next pending job from outbox_jobs."""
        with get_worker_conn(autocommit=True) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                # 1. Claim job
                cur.execute("""
                    SELECT out_job_id AS job_id, out_batch_id AS batch_id,
                           out_snapshot_id AS snapshot_id, out_fencing_token AS fencing_token,
                           out_attempt_count AS attempt_count, out_resuming_reconciliation AS resuming
                    FROM fn_claim_outbox_job(%s, 'PAYPAL_SUBMIT_PAYOUT');
                """, (self.worker_id,))
                claim = cur.fetchone()
                if not claim or not claim["job_id"]:
                    return None

                job_id = str(claim["job_id"])
                batch_id = str(claim["batch_id"])
                fencing_token = claim["fencing_token"]

                # 2. Fetch snapshot and batch details
                cur.execute("""
                    SELECT pb.sender_batch_id, pb.paypal_request_id, pb.gateway_batch_state,
                           pb.payout_batch_id, ps.encrypted_snapshot_payload, ps.snapshot_digest,
                           ps.ciphertext_digest, ps.iv_nonce, ps.auth_tag, ps.aad_text,
                           ps.wrapped_dek, ps.cryptographic_attestation, ps.key_id
                    FROM payout_batches pb
                    JOIN payout_snapshots ps ON ps.snapshot_id = pb.active_snapshot_id
                    WHERE pb.id = %s;
                """, (batch_id,))
                details = cur.fetchone()
                if not details:
                    raise ValueError("Batch or snapshot details missing")

                # 3. Check for existing provider batch (Idempotency Recovery)
                if details["payout_batch_id"]:
                    return {
                        "job_id": job_id,
                        "batch_id": batch_id,
                        "status": "DUPLICATE_PREVENTED",
                        "payout_batch_id": details["payout_batch_id"],
                        "message": "Batch already has registered provider ID. Zero duplicate submissions created."
                    }

                # 3b. Provider-Side Idempotency Pre-flight: Recover in-flight payout if worker crashed
                # after PayPal accepted the batch but before fn_record_provider_payout_result was committed.
                if not details["payout_batch_id"] and claim.get("attempt_count", 1) > 1:
                    existing_prov_data = self.paypal_client.lookup_by_request_id(str(details["paypal_request_id"]))
                    if not existing_prov_data:
                        existing_prov_data = self.paypal_client.lookup_by_sender_batch_id(details["sender_batch_id"])
                    if existing_prov_data and isinstance(existing_prov_data, dict) and "batch_header" in existing_prov_data:
                        rec_payout_id = existing_prov_data["batch_header"].get("payout_batch_id")
                        if rec_payout_id:
                            cur.execute("""
                                SELECT fn_record_provider_payout_result(
                                    %s, %s, %s, %s, 'PENDING', 201, %s, FALSE
                                );
                            """, (
                                uuid.UUID(batch_id), self.worker_id, fencing_token,
                                rec_payout_id, json.dumps(existing_prov_data)
                            ))
                            details["payout_batch_id"] = rec_payout_id
                            # Proceed with post-submission status reconciliation rather than second submission


                # 4. Verify cryptographic envelope integrity before sending to PayPal
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                dek_bytes = bytes(details["wrapped_dek"])
                nonce_bytes = bytes(details["iv_nonce"])
                ct_bytes = bytes(details["encrypted_snapshot_payload"])
                tag_bytes = bytes(details["auth_tag"])
                aad_bytes = details["aad_text"].encode('utf-8') if isinstance(details["aad_text"], str) else details["aad_text"]
                aesgcm = AESGCM(dek_bytes)
                decrypted_bytes = aesgcm.decrypt(nonce_bytes, ct_bytes + tag_bytes, aad_bytes)
                expected_plaintext_json = decrypted_bytes.decode('utf-8')

                is_valid_envelope = verify_envelope_before_submission(
                    dek=dek_bytes,
                    nonce=nonce_bytes,
                    ciphertext=ct_bytes,
                    tag=tag_bytes,
                    aad_text=details["aad_text"],
                    expected_plaintext_json=expected_plaintext_json,
                    batch_id=uuid.UUID(batch_id),
                    snapshot_id=uuid.UUID(str(claim["snapshot_id"])),
                    key_id=uuid.UUID(str(details["key_id"])),
                    key_version=1,
                    wrapped_dek=dek_bytes,
                    attestation=bytes(details["cryptographic_attestation"]),
                    attestation_secret=DEFAULT_ATTESTATION_SECRET
                )
                if not is_valid_envelope:
                    raise ValueError("Cryptographic attestation verification failed prior to submission!")

                # 5. Fetch batch items to form PayPal request body
                cur.execute("""
                    SELECT pi.id, pi.sender_item_id, pi.amount_cents, pi.note,
                           pi.encrypted_receiver, pi.wrapped_dek, pi.iv_nonce, pi.auth_tag, pi.aad_text
                    FROM payout_items pi
                    WHERE pi.batch_id = %s;
                """, (batch_id,))
                items = cur.fetchall()

                from backend.payout_service import decrypt_item_receiver

                paypal_payload = {
                    "sender_batch_header": {
                        "sender_batch_id": details["sender_batch_id"],
                        "email_subject": "Contractor Disbursement",
                        "recipient_type": "EMAIL"
                    },
                    "items": [
                        {
                            "recipient_type": "EMAIL",
                            "amount": {
                                "value": f"{it['amount_cents'] / 100:.2f}",
                                "currency": "USD"
                            },
                            "note": it["note"] or "Contractor payout",
                            "sender_item_id": it["sender_item_id"],
                            "receiver": decrypt_item_receiver(it)
                        }
                        for it in items
                    ]
                }

                # 6. Execute Sandbox Submission
                http_status, resp_data, provider_mode = self.paypal_client.submit_payout(
                    batch_id=batch_id,
                    paypal_request_id=str(details["paypal_request_id"]),
                    payload_dict=paypal_payload,
                    force_network_timeout=force_timeout
                )

                # Allowed PayPal item state constraint enum
                VALID_PAYPAL_ITEM_STATES = {
                    'SUCCESS', 'FAILED', 'PENDING', 'UNCLAIMED', 'RETURNED',
                    'ONHOLD', 'BLOCKED', 'REFUNDED', 'REVERSED'
                }

                AMBIGUOUS_HTTP_STATUSES = {408, 500, 502, 503, 504}
                TRANSIENT_RATE_LIMIT_STATUSES = {429}
                DEFINITIVE_REJECTION_STATUSES = {400, 401, 403, 404, 422}

                # 6b. Handle Pre-Submission OAuth Failure (no /v1/payments/payouts POST occurred)
                if (
                    not force_timeout
                    and isinstance(resp_data, dict)
                    and resp_data.get("error") == "PAYPAL_OAUTH_PRECHECK_FAILED"
                    and resp_data.get("payout_post_attempted") is False
                ):
                    error_msg = resp_data.get("message") or "Pre-submission OAuth authentication failed"
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, NULL, NULL, %s, %s, FALSE
                        );
                    """, (
                        uuid.UUID(batch_id), self.worker_id, fencing_token,
                        http_status, json.dumps(resp_data)
                    ))
                    cur.execute("""
                        SELECT fn_complete_outbox_job(%s, %s, %s);
                    """, (uuid.UUID(job_id), self.worker_id, fencing_token))
                    cur.execute("""
                        SELECT fn_release_beneficiary_submission_locks_for_batch(%s, 'OAUTH_PRECHECK_FAILED');
                    """, (uuid.UUID(batch_id),))
                    cur.execute("""
                        SELECT fn_append_audit_event(
                            'main', NULL, 'PAYOUT_OAUTH_PRECHECK_FAILED', 'PAYOUT_BATCH', %s,
                            NULL, NULL, NULL, 'OutboxWorker/10.1', %s,
                            NULL, %s::jsonb
                        );
                    """, (
                        uuid.UUID(batch_id), fencing_token,
                        json.dumps({
                            "http_status": http_status,
                            "error": error_msg,
                            "provider_mode": provider_mode,
                            "payout_post_attempted": False,
                            "ambiguous": False
                        })
                    ))
                    return {
                        "job_id": job_id,
                        "batch_id": batch_id,
                        "status": "OAUTH_FAILED",
                        "http_status": http_status,
                        "provider_mode": provider_mode,
                        "payout_post_attempted": False,
                        "ambiguous": False,
                        "error": resp_data
                    }

                # 7. Handle Ambiguous Network Error or Gateway Timeout (HTTP 408, 500, 502, 503, 504, network timeout)
                if force_timeout or http_status in AMBIGUOUS_HTTP_STATUSES:
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, NULL, 'UNKNOWN_OUTCOME', %s, %s, TRUE
                        );
                    """, (
                        uuid.UUID(batch_id), self.worker_id, fencing_token,
                        http_status, json.dumps(resp_data) if isinstance(resp_data, (dict, list)) else str(resp_data)
                    ))

                    # Log tamper-evident audit event for ambiguous timeout
                    cur.execute("""
                        SELECT fn_append_audit_event(
                            'main', NULL, 'PAYOUT_SUBMISSION_TIMED_OUT', 'PAYOUT_BATCH', %s,
                            NULL, NULL, NULL, 'OutboxWorker/10.1', %s,
                            NULL, %s::jsonb
                        );
                    """, (
                        uuid.UUID(batch_id), fencing_token,
                        json.dumps({
                            "http_status": http_status,
                            "error": "AMBIGUOUS_GATEWAY_OUTCOME",
                            "action": "LOCK_RETAINED_MANUAL_RECONCILIATION_REQUIRED"
                        })
                    ))

                    return {
                        "job_id": job_id,
                        "batch_id": batch_id,
                        "status": "MANUAL_RECONCILIATION_REQUIRED",
                        "http_status": http_status,
                        "provider_mode": provider_mode,
                        "message": "Ambiguous network outcome encountered. Beneficiary locks retained; batch entered manual reconciliation."
                    }

                # 8. Handle Transient Rate Limiting (HTTP 429) - Retain locks and enter safe reconciliation
                if http_status in TRANSIENT_RATE_LIMIT_STATUSES:
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, NULL, 'RATE_LIMITED', %s, %s, TRUE
                        );
                    """, (
                        uuid.UUID(batch_id), self.worker_id, fencing_token,
                        http_status, json.dumps(resp_data) if isinstance(resp_data, (dict, list)) else str(resp_data)
                    ))
                    cur.execute("""
                        SELECT fn_append_audit_event(
                            'main', NULL, 'PAYOUT_SUBMISSION_RATE_LIMITED', 'PAYOUT_BATCH', %s,
                            NULL, NULL, NULL, 'OutboxWorker/10.1', %s,
                            NULL, %s::jsonb
                        );
                    """, (
                        uuid.UUID(batch_id), fencing_token,
                        json.dumps({
                            "http_status": http_status,
                            "error": "PAYPAL_RATE_LIMIT_EXCEEDED",
                            "action": "LOCK_RETAINED_MANUAL_RECONCILIATION_REQUIRED"
                        })
                    ))
                    return {
                        "job_id": job_id,
                        "batch_id": batch_id,
                        "status": "MANUAL_RECONCILIATION_REQUIRED",
                        "http_status": http_status,
                        "provider_mode": provider_mode,
                        "message": "PayPal rate limit reached (HTTP 429). Beneficiary locks retained; batch entered safe reconciliation to prevent racing."
                    }

                # 9. Handle Definitive Error or Rejection (e.g. 400, 401, 403, 404, 422)
                if http_status != 201 or not isinstance(resp_data, dict) or "batch_header" not in resp_data:
                    error_msg = resp_data.get("message") if isinstance(resp_data, dict) else str(resp_data)
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, NULL, NULL, %s, %s, FALSE
                        );
                    """, (
                        uuid.UUID(batch_id), self.worker_id, fencing_token,
                        http_status, json.dumps(resp_data) if isinstance(resp_data, (dict, list)) else str(resp_data)
                    ))
                    cur.execute("""
                        SELECT fn_complete_outbox_job(%s, %s, %s);
                    """, (uuid.UUID(job_id), self.worker_id, fencing_token))
                    cur.execute("""
                        SELECT fn_release_beneficiary_submission_locks_for_batch(%s, 'DEFINITIVE_PROVIDER_REJECTION');
                    """, (uuid.UUID(batch_id),))

                    cur.execute("""
                        SELECT fn_append_audit_event(
                            'main', NULL, 'PAYOUT_SUBMISSION_FAILED', 'PAYOUT_BATCH', %s,
                            NULL, NULL, NULL, 'OutboxWorker/10.1', %s,
                            NULL, %s::jsonb
                        );
                    """, (
                        uuid.UUID(batch_id), fencing_token,
                        json.dumps({
                            "http_status": http_status,
                            "error": error_msg,
                            "provider_mode": provider_mode,
                            "ambiguous": False
                        })
                    ))
                    return {
                        "job_id": job_id,
                        "batch_id": batch_id,
                        "status": "FAILED",
                        "http_status": http_status,
                        "provider_mode": provider_mode,
                        "error": resp_data
                    }

                # 10. Handle Successful HTTP 201 Created
                payout_batch_id = resp_data["batch_header"].get("payout_batch_id")
                paypal_batch_status = resp_data["batch_header"].get("batch_status", "PENDING")

                cur.execute("""
                    SELECT fn_record_provider_payout_result(
                        %s, %s, %s, %s, %s, %s, %s, FALSE
                    );
                """, (
                    uuid.UUID(batch_id), self.worker_id, fencing_token,
                    payout_batch_id, paypal_batch_status, http_status, json.dumps(resp_data)
                ))

                # 10. Individual Item Status Reconciliation
                status_code, status_data = self.paypal_client.fetch_payout_status(payout_batch_id)
                provider_items_list = []
                if isinstance(status_data, dict):
                    provider_items_list = status_data.get("items", [])

                # Map provider items by sender_item_id and payout_item_id
                provider_items_by_sender = {}
                for p_it in provider_items_list:
                    s_id = p_it.get("sender_item_id")
                    if s_id:
                        provider_items_by_sender[s_id] = p_it
                    p_id = p_it.get("payout_item_id")
                    if p_id:
                        provider_items_by_sender[p_id] = p_it

                reconciled_items = []
                has_failed = False
                has_unresolved = False

                for idx, it in enumerate(items):
                    sender_item_id = it["sender_item_id"]
                    p_info = provider_items_by_sender.get(sender_item_id)
                    if not p_info and idx < len(provider_items_list):
                        p_info = provider_items_list[idx]

                    if p_info:
                        payout_item_id = p_info.get("payout_item_id")
                        raw_status = p_info.get("transaction_status", "PENDING").upper()
                        activity_id = p_info.get("activity_id")
                        errors_obj = p_info.get("errors")
                        raw_error_text = json.dumps(errors_obj) if errors_obj else f"Provider status: {raw_status}"
                    else:
                        # Item genuinely missing in provider response: NEVER invent SUCCESS! Route to manual reconciliation.
                        payout_item_id = None
                        raw_status = "UNRESOLVED_MISSING"
                        activity_id = None
                        raw_error_text = "Item missing in provider status payload: manual reconciliation required"
                        has_unresolved = True

                    # Map safely to DB check constraint check_paypal_item_state
                    if raw_status in VALID_PAYPAL_ITEM_STATES:
                        db_item_state = raw_status
                    else:
                        db_item_state = "PENDING"
                        has_unresolved = True

                    if raw_status in ("FAILED", "BLOCKED", "RETURNED"):
                        has_failed = True

                    cur.execute("""
                        SELECT fn_record_provider_item_result(
                            %s, %s, %s, %s, %s, %s
                        );
                    """, (
                        uuid.UUID(str(it["id"])),
                        payout_item_id,
                        db_item_state,
                        activity_id,
                        raw_error_text,
                        sender_item_id
                    ))
                    reconciled_items.append({
                        "item_id": str(it["id"]),
                        "payout_item_id": payout_item_id,
                        "status": db_item_state,
                        "raw_status": raw_status,
                        "activity_id": activity_id
                    })

                # If missing or unknown items detected: RETAIN LOCKS and route to manual reconciliation via fn_record_provider_payout_result
                if has_unresolved:
                    cur.execute("""
                        SELECT fn_record_provider_payout_result(
                            %s, %s, %s, %s, 'UNKNOWN_OUTCOME', %s, %s, TRUE
                        );
                    """, (
                        uuid.UUID(batch_id), self.worker_id, fencing_token,
                        payout_batch_id, http_status,
                        json.dumps({"error": "ITEMS_MISSING_OR_UNRESOLVED", "reconciled_items": reconciled_items})
                    ))

                    cur.execute("""
                        SELECT fn_append_audit_event(
                            'main', NULL, 'PAYOUT_RECONCILIATION_DEFICIT', 'PAYOUT_BATCH', %s,
                            NULL, NULL, NULL, 'OutboxWorker/10.1', %s,
                            NULL, %s::jsonb
                        );
                    """, (
                        uuid.UUID(batch_id), fencing_token,
                        json.dumps({
                            "payout_batch_id": payout_batch_id,
                            "message": "Item missing or unrecognized provider status. Beneficiary locks retained for manual reconciliation."
                        })
                    ))

                    return {
                        "job_id": job_id,
                        "batch_id": batch_id,
                        "status": "MANUAL_RECONCILIATION_REQUIRED",
                        "payout_batch_id": payout_batch_id,
                        "http_status": http_status,
                        "provider_mode": provider_mode,
                        "reconciled_items": reconciled_items,
                        "message": "Item missing or unrecognized provider status. Locks retained."
                    }

                # 11. Complete Outbox Job & Release Beneficiary Submission Locks (Only when all items accounted for)
                cur.execute("""
                    SELECT fn_complete_outbox_job(%s, %s, %s);
                """, (uuid.UUID(job_id), self.worker_id, fencing_token))

                cur.execute("""
                    SELECT fn_release_beneficiary_submission_locks_for_batch(%s, %s);
                """, (uuid.UUID(batch_id), self.worker_id))

                # Audit Event
                cur.execute("""
                    SELECT fn_append_audit_event(
                        'main', NULL, 'PAYOUT_SETTLED_SUCCESS', 'PAYOUT_BATCH', %s,
                        NULL, NULL, NULL, 'OutboxWorker/10.1', %s,
                        NULL, %s::jsonb
                    );
                """, (
                    uuid.UUID(batch_id), fencing_token,
                    json.dumps({
                        "payout_batch_id": payout_batch_id,
                        "item_count": len(reconciled_items),
                        "has_failures": has_failed,
                        "provider_mode": provider_mode
                    })
                ))

                final_status = "SETTLED" if not has_failed else "PARTIALLY_SETTLED"
                return {
                    "job_id": job_id,
                    "batch_id": batch_id,
                    "status": final_status,
                    "payout_batch_id": payout_batch_id,
                    "http_status": http_status,
                    "provider_mode": provider_mode,
                    "reconciled_items": reconciled_items
                }
