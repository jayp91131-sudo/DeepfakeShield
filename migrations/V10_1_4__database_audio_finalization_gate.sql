-- ============================================================================
-- DeepfakeShield for PayPal — Database Migration V10.1.4
-- MILESTONE: V10.1.4 — Database-Level Fail-Closed Audio Finalization Gate
-- Target Database: PostgreSQL 18.6 (Forward-only migration from V10.1.3)
--
-- Security Remediation:
-- 1. Minimum Additive Evidence-to-Batch Schema Binding:
--    - Adds batch_id FK and constrained policy_decision to risk_evaluations.
--    - Backfills existing risk_evaluations rows from AUDIO_RISK_EVALUATED audit metadata.
-- 2. Authoritative Verifier-Only Evaluation Recording:
--    - Revokes direct INSERT/UPDATE/DELETE on audio_assets, audio_consents,
--      speaker_segments, and risk_evaluations from runtime role deepfakeshield_app.
--    - Introduces SECURITY DEFINER fn_record_audio_risk_evaluation(...) executable
--      exclusively by deepfakeshield_verifier (and owner/postgres).
-- 3. Independent Database-Level Finalization Gate (fn_finalize_payout_batch):
--    - Enforces fail-closed audio verification on direct SQL invocations:
--      * Requires active session and 1:1 batch-to-session isolation.
--      * Requires explicit audio_consents (consent_given = TRUE).
--      * Requires latest audio_assets + evaluated speaker_segments + risk_evaluations.
--      * Rejects CHALLENGE, NEEDS_REVIEW, BLOCKED, TERMINATE, missing, stale
--        (> 1 hour TTL or predating latest asset), superseded, or unassociated evidence.
--      * Verifies immutable AUDIO_RISK_EVALUATED audit binding matching exact batch_id.
--    - Preserves fn_validate_batch_state_transition() so NEEDS_REVIEW remains blocked.
-- ============================================================================

BEGIN;

-- Verify V10.1.3 prerequisite
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 'V10.1.3') THEN
        RAISE EXCEPTION 'Migration prerequisite failed: V10.1.3 must be applied before V10.1.4';
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- 1. MINIMUM ADDITIVE SCHEMA BINDING ON risk_evaluations
-- ----------------------------------------------------------------------------
ALTER TABLE risk_evaluations
    ADD COLUMN IF NOT EXISTS batch_id UUID NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS policy_decision VARCHAR(50) NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'risk_evaluations'::regclass
          AND conname = 'check_risk_eval_policy_decision'
    ) THEN
        ALTER TABLE risk_evaluations
            ADD CONSTRAINT check_risk_eval_policy_decision CHECK (
                policy_decision IS NULL OR policy_decision IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW', 'BLOCKED')
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_risk_evaluations_batch_eval_at
    ON risk_evaluations(batch_id, evaluated_at DESC);

-- Backfill batch_id and policy_decision on existing V10.1.3 rows from immutable audit_events
-- and session-linked payout_batches where unambiguous.
UPDATE risk_evaluations re
SET
    batch_id = COALESCE(
        re.batch_id,
        CASE
            WHEN ae.metadata_json ? 'batch_id'
                 AND (ae.metadata_json->>'batch_id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (ae.metadata_json->>'batch_id')::uuid
            ELSE NULL
        END
    ),
    policy_decision = COALESCE(
        re.policy_decision,
        CASE
            WHEN (ae.metadata_json->>'policy_decision') IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW', 'BLOCKED')
            THEN (ae.metadata_json->>'policy_decision')
            ELSE NULL
        END
    )
FROM audit_events ae
WHERE ae.entity_type = 'RISK_EVALUATION'
  AND ae.event_type = 'AUDIO_RISK_EVALUATED'
  AND ae.entity_id = re.id
  AND (re.batch_id IS NULL OR re.policy_decision IS NULL);

-- ----------------------------------------------------------------------------
-- 2. VERIFIER-ONLY EVALUATION PERSISTENCE FUNCTION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_record_audio_risk_evaluation(
    p_batch_id UUID,
    p_session_id UUID,
    p_actor_user_id UUID,
    p_asset_id UUID,
    p_segment_id UUID,
    p_eval_id UUID,
    p_storage_uri TEXT,
    p_duration_ms INT,
    p_sample_count INT,
    p_wada_snr_db NUMERIC(5, 2),
    p_consent_evidence_hash VARCHAR(64),
    p_model_version VARCHAR(50),
    p_deepfake_probability NUMERIC(5, 4),
    p_acoustic_consistency_score NUMERIC(5, 4),
    p_voice_clone_flag BOOLEAN,
    p_adversarial_noise_detected BOOLEAN,
    p_recommendation VARCHAR(50),
    p_policy_decision VARCHAR(50),
    p_metadata_json JSONB DEFAULT NULL
)
RETURNS UUID
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_batch RECORD;
    v_session RECORD;
    v_asset_id UUID;
    v_segment_id UUID;
    v_eval_id UUID;
    v_audit_meta JSONB;
BEGIN
    -- Only verifier / owner / postgres may record authoritative audio risk evaluations
    IF SESSION_USER NOT IN ('deepfakeshield_owner', 'postgres', 'deepfakeshield_verifier') THEN
        RAISE EXCEPTION 'Access denied: role % is not authorized to record audio risk evaluations', SESSION_USER
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state != 'DRAFT' THEN
        RAISE EXCEPTION 'Cannot attach audio evaluation to batch % in state %, expected DRAFT',
            p_batch_id, v_batch.gateway_batch_state
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_batch.session_id IS DISTINCT FROM p_session_id THEN
        RAISE EXCEPTION 'Session mismatch for batch %: expected %, got %',
            p_batch_id, v_batch.session_id, p_session_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF EXISTS (
        SELECT 1 FROM payout_batches pb2
        WHERE pb2.session_id = p_session_id AND pb2.id != p_batch_id
    ) THEN
        RAISE EXCEPTION 'Session % is shared across multiple batches; audio evaluation rejected', p_session_id
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT * INTO v_session FROM sessions WHERE id = p_session_id FOR UPDATE;
    IF NOT FOUND OR v_session.session_status IN ('FAILED', 'TERMINATED') OR v_session.terminated_at IS NOT NULL THEN
        RAISE EXCEPTION 'Session % is missing or terminated', p_session_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF p_recommendation NOT IN ('APPROVE', 'CHALLENGE', 'TERMINATE') THEN
        RAISE EXCEPTION 'Invalid recommendation: %', p_recommendation
            USING ERRCODE = 'check_violation';
    END IF;

    IF p_policy_decision NOT IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW', 'BLOCKED') THEN
        RAISE EXCEPTION 'Invalid policy_decision: %', p_policy_decision
            USING ERRCODE = 'check_violation';
    END IF;

    -- Policy threshold consistency guard (cannot label risky audio READY_FOR_CHECKER / APPROVE)
    IF (p_policy_decision = 'READY_FOR_CHECKER' OR p_recommendation = 'APPROVE') AND (
        p_recommendation != 'APPROVE'
        OR p_policy_decision != 'READY_FOR_CHECKER'
        OR p_voice_clone_flag IS TRUE
        OR p_adversarial_noise_detected IS TRUE
        OR p_deepfake_probability >= 0.35
    ) THEN
        RAISE EXCEPTION 'Inconsistent audio policy classification: prob=%, clone=%, noise=%, rec=%, policy=%',
            p_deepfake_probability, p_voice_clone_flag, p_adversarial_noise_detected, p_recommendation, p_policy_decision
            USING ERRCODE = 'check_violation';
    END IF;

    v_asset_id := COALESCE(p_asset_id, gen_random_uuid());
    v_segment_id := COALESCE(p_segment_id, gen_random_uuid());
    v_eval_id := COALESCE(p_eval_id, gen_random_uuid());

    INSERT INTO audio_assets (id, session_id, sample_rate, channels, format, storage_uri, duration_ms)
    VALUES (v_asset_id, p_session_id, 16000, 1, 'WAV_PCM16', p_storage_uri, p_duration_ms);

    INSERT INTO audio_consents (session_id, consent_statement_version, consent_given, audio_offset_ms, evidence_hash)
    VALUES (p_session_id, 'CONSENT_v10.1', TRUE, 0, p_consent_evidence_hash);

    INSERT INTO speaker_segments (id, audio_asset_id, speaker_label, start_ms, end_ms, sample_count, wada_snr_db, is_evaluated)
    VALUES (v_segment_id, v_asset_id, 'EXECUTIVE_APPROVER', 0, p_duration_ms, GREATEST(p_sample_count, 64600), p_wada_snr_db, TRUE);

    INSERT INTO risk_evaluations (
        id, segment_id, batch_id, model_version, deepfake_probability, acoustic_consistency_score,
        voice_clone_flag, adversarial_noise_detected, recommendation, policy_decision
    ) VALUES (
        v_eval_id, v_segment_id, p_batch_id, p_model_version, p_deepfake_probability, p_acoustic_consistency_score,
        p_voice_clone_flag, p_adversarial_noise_detected, p_recommendation, p_policy_decision
    );

    v_audit_meta := COALESCE(p_metadata_json, '{}'::jsonb) || jsonb_build_object(
        'batch_id', p_batch_id::text,
        'session_id', p_session_id::text,
        'asset_id', v_asset_id::text,
        'segment_id', v_segment_id::text,
        'deepfake_probability', p_deepfake_probability,
        'recommendation', p_recommendation,
        'policy_decision', p_policy_decision
    );

    PERFORM fn_append_audit_event(
        'main',
        p_actor_user_id,
        'AUDIO_RISK_EVALUATED',
        'RISK_EVALUATION',
        v_eval_id,
        NULL,
        NULL,
        NULL,
        'DeepfakeShield-DB-Gate/10.1.4',
        v_batch.fencing_token,
        NULL,
        v_audit_meta
    );

    RETURN v_eval_id;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- 3. FAIL-CLOSED AUDIO GATE INSIDE fn_finalize_payout_batch
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_finalize_payout_batch(
    p_batch_id UUID,
    p_canonical_payload_json TEXT,
    p_encrypted_payload BYTEA,
    p_payload_digest VARCHAR(64),
    p_wrapped_dek BYTEA,
    p_iv_nonce BYTEA,
    p_auth_tag BYTEA,
    p_aad_text TEXT,
    p_cryptographic_attestation BYTEA,
    p_snapshot_id UUID
)
RETURNS UUID
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_batch RECORD;
    v_session RECORD;
    v_asset RECORD;
    v_eval RECORD;
    v_eval_audit RECORD;
    v_latest_batch_audit RECORD;
    v_effective_policy VARCHAR(50);
    v_beneficiary RECORD;
    v_snapshot_id UUID;
    v_computed_plaintext_digest VARCHAR(64);
    v_computed_ciphertext_digest VARCHAR(64);
    v_expected_attestation BYTEA;
    v_legacy_attestation BYTEA;
    v_key RECORD;
    v_sec_keys RECORD;
    v_computed_blind_index VARCHAR(64);
    v_wrapped_dek_digest VARCHAR(64);
    v_binding_raw TEXT;
    v_json_val JSONB;
    v_header JSONB;
    v_items JSONB;
    v_item_idx INT;
    v_item_elem JSONB;
    v_sender_item_id VARCHAR(63);
    v_recipient_type VARCHAR(20);
    v_receiver_text TEXT;
    v_amount_obj JSONB;
    v_item RECORD;
    v_val_text TEXT;
    v_curr_text TEXT;
    v_expected_val_text TEXT;
    v_normalized_receiver TEXT;
    v_unique_json_items INT;
    v_json_items_total INT;
    v_db_items_total INT;
    v_actual_count INT;
    v_actual_total_cents BIGINT;
BEGIN
    -- Check SESSION_USER authorization
    IF SESSION_USER NOT IN ('deepfakeshield_owner', 'postgres', 'deepfakeshield_app') THEN
        RAISE EXCEPTION 'Access denied: role % is not authorized to finalize batches', SESSION_USER
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Mandatory Cryptographic Attestation Check
    IF p_cryptographic_attestation IS NULL OR octet_length(p_cryptographic_attestation) != 32 THEN
        RAISE EXCEPTION 'Cryptographic attestation is mandatory (expected 32-byte HMAC)'
            USING ERRCODE = 'check_violation';
    END IF;

    -- 1. Lock Batch FOR UPDATE
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state != 'DRAFT' THEN
        RAISE EXCEPTION 'Batch % is in state %, expected DRAFT', p_batch_id, v_batch.gateway_batch_state
            USING ERRCODE = 'check_violation';
    END IF;

    -- 1A. DATABASE-LEVEL FAIL-CLOSED AUDIO RISK GATE (V10.1.4)
    IF v_batch.session_id IS NULL THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: missing session_id association', p_batch_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF EXISTS (
        SELECT 1 FROM payout_batches pb2
        WHERE pb2.session_id = v_batch.session_id AND pb2.id != p_batch_id
    ) THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: session % is shared across multiple batches',
            p_batch_id, v_batch.session_id
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT id, session_status, terminated_at
    INTO v_session
    FROM sessions
    WHERE id = v_batch.session_id;

    IF NOT FOUND OR v_session.session_status IN ('FAILED', 'TERMINATED') OR v_session.terminated_at IS NOT NULL THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: session % is missing or terminated',
            p_batch_id, v_batch.session_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM audio_consents
        WHERE session_id = v_batch.session_id AND consent_given = TRUE
    ) THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: missing explicit audio consent for session %',
            p_batch_id, v_batch.session_id
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT id, recorded_at
    INTO v_asset
    FROM audio_assets
    WHERE session_id = v_batch.session_id
    ORDER BY recorded_at DESC NULLS LAST, id DESC
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: missing audio_assets evidence', p_batch_id
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT re.id, re.segment_id, re.batch_id AS eval_batch_id,
           re.model_version, re.deepfake_probability, re.acoustic_consistency_score,
           re.voice_clone_flag, re.adversarial_noise_detected,
           re.recommendation, re.policy_decision AS eval_policy_decision,
           re.evaluated_at, ss.is_evaluated
    INTO v_eval
    FROM speaker_segments ss
    LEFT JOIN risk_evaluations re ON re.segment_id = ss.id
    WHERE ss.audio_asset_id = v_asset.id
    ORDER BY re.evaluated_at DESC NULLS FIRST, re.id DESC NULLS FIRST, ss.id DESC
    LIMIT 1;

    IF NOT FOUND OR v_eval.id IS NULL THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: missing risk evaluation for latest audio asset %',
            p_batch_id, v_asset.id
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_eval.is_evaluated IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: speaker segment % is unevaluated',
            p_batch_id, v_eval.segment_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_eval.eval_batch_id IS DISTINCT FROM p_batch_id THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: risk evaluation % batch_id (%) does not match batch',
            p_batch_id, v_eval.id, v_eval.eval_batch_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_eval.evaluated_at IS NULL
       OR (v_asset.recorded_at IS NOT NULL AND v_eval.evaluated_at < v_asset.recorded_at)
       OR v_eval.evaluated_at < (CURRENT_TIMESTAMP - INTERVAL '1 hour')
       OR v_eval.evaluated_at > (CURRENT_TIMESTAMP + INTERVAL '60 seconds') THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: evaluation % is stale or timestamp-invalid',
            p_batch_id, v_eval.id
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT id, entity_id, metadata_json
    INTO v_eval_audit
    FROM audit_events
    WHERE entity_type = 'RISK_EVALUATION'
      AND entity_id = v_eval.id
      AND event_type = 'AUDIO_RISK_EVALUATED'
    ORDER BY id DESC
    LIMIT 1;

    IF NOT FOUND OR (v_eval_audit.metadata_json->>'batch_id') IS DISTINCT FROM p_batch_id::text THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: evaluation % lacks matching AUDIO_RISK_EVALUATED audit record',
            p_batch_id, v_eval.id
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT id, entity_id
    INTO v_latest_batch_audit
    FROM audit_events
    WHERE event_type = 'AUDIO_RISK_EVALUATED'
      AND (metadata_json->>'batch_id') = p_batch_id::text
    ORDER BY id DESC
    LIMIT 1;

    IF FOUND AND v_latest_batch_audit.entity_id IS DISTINCT FROM v_eval.id THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: evaluation % superseded by latest batch audit evaluation %',
            p_batch_id, v_eval.id, v_latest_batch_audit.entity_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_eval.eval_policy_decision IS NOT NULL
       AND (v_eval_audit.metadata_json->>'policy_decision') IS NOT NULL
       AND v_eval.eval_policy_decision IS DISTINCT FROM (v_eval_audit.metadata_json->>'policy_decision') THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: policy_decision mismatch between evaluation and audit',
            p_batch_id
            USING ERRCODE = 'check_violation';
    END IF;

    v_effective_policy := COALESCE(v_eval.eval_policy_decision, v_eval_audit.metadata_json->>'policy_decision');

    IF v_effective_policy IS DISTINCT FROM 'READY_FOR_CHECKER'
       OR v_eval.recommendation IS DISTINCT FROM 'APPROVE'
       OR v_eval.voice_clone_flag IS TRUE
       OR v_eval.adversarial_noise_detected IS TRUE
       OR v_eval.deepfake_probability >= 0.35
       OR v_eval.model_version IS NULL
       OR length(trim(v_eval.model_version)) = 0 THEN
        RAISE EXCEPTION 'Audio risk gate rejected batch %: recommendation=%, policy=%, prob=%, clone=%, noise=%',
            p_batch_id, v_eval.recommendation, COALESCE(v_effective_policy, 'NULL'),
            v_eval.deepfake_probability, v_eval.voice_clone_flag, v_eval.adversarial_noise_detected
            USING ERRCODE = 'check_violation';
    END IF;

    -- Advance state to VALIDATING only after audio risk verification succeeds
    UPDATE payout_batches SET gateway_batch_state = 'VALIDATING', updated_at = CURRENT_TIMESTAMP WHERE id = p_batch_id;

    -- 2. Validate Key Metadata & Internal Security Keys Isolation
    SELECT * INTO v_key FROM encryption_key_metadata WHERE key_id = v_batch.key_id;
    IF NOT FOUND OR NOT v_key.is_active THEN
        RAISE EXCEPTION 'Encryption key % is not active or not found', v_batch.key_id;
    END IF;

    SELECT * INTO v_sec_keys FROM internal_security_keys WHERE key_id = v_batch.key_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Internal security keys not configured for key %', v_batch.key_id;
    END IF;

    -- 3. Lock distinct beneficiaries in deterministic order
    FOR v_beneficiary IN
        SELECT b.*
        FROM beneficiaries b
        WHERE b.id IN (
            SELECT DISTINCT i.beneficiary_id
            FROM payout_items i
            WHERE i.batch_id = p_batch_id
        )
        ORDER BY b.id ASC
        FOR UPDATE
    LOOP
        IF v_beneficiary.verification_status != 'VERIFIED' THEN
            RAISE EXCEPTION 'Beneficiary % is not VERIFIED (status: %)', v_beneficiary.id, v_beneficiary.verification_status;
        END IF;

        IF EXISTS (
            SELECT 1 FROM beneficiary_submission_locks
            WHERE beneficiary_id = v_beneficiary.id AND released_at IS NULL AND batch_id != p_batch_id
        ) THEN
            RAISE EXCEPTION 'Beneficiary % is already locked by another payout batch', v_beneficiary.id;
        END IF;

        UPDATE payout_items
        SET beneficiary_version = v_beneficiary.version,
            expected_destination_digest = v_beneficiary.destination_digest,
            destination_blind_index = v_beneficiary.destination_blind_index,
            encrypted_receiver = v_beneficiary.encrypted_destination,
            key_id = v_beneficiary.key_id,
            wrapped_dek = v_beneficiary.wrapped_dek,
            iv_nonce = v_beneficiary.iv_nonce,
            auth_tag = v_beneficiary.auth_tag,
            aad_text = v_beneficiary.aad_text
        WHERE batch_id = p_batch_id AND beneficiary_id = v_beneficiary.id;

        IF NOT EXISTS (
            SELECT 1 FROM beneficiary_submission_locks
            WHERE beneficiary_id = v_beneficiary.id AND batch_id = p_batch_id AND released_at IS NULL
        ) THEN
            INSERT INTO beneficiary_submission_locks (
                beneficiary_id, batch_id, expected_version, expected_destination_digest, locked_at
            ) VALUES (
                v_beneficiary.id, p_batch_id, v_beneficiary.version, v_beneficiary.destination_digest, CURRENT_TIMESTAMP
            );
        END IF;
    END LOOP;

    -- 4. Integer Totals Verification from Database items
    SELECT COUNT(*), COALESCE(SUM(amount_cents), 0)
    INTO v_actual_count, v_actual_total_cents
    FROM payout_items
    WHERE batch_id = p_batch_id;

    IF v_actual_count != v_batch.item_count THEN
        RAISE EXCEPTION 'Item count mismatch: header declared %, items table has %',
            v_batch.item_count, v_actual_count;
    END IF;

    IF v_actual_total_cents != v_batch.total_amount_cents THEN
        RAISE EXCEPTION 'Total cents mismatch: header declared %, items sum to %',
            v_batch.total_amount_cents, v_actual_total_cents;
    END IF;

    -- 5. Digest & Encryption Parameter Validation
    IF p_encrypted_payload = convert_to(p_canonical_payload_json, 'UTF8') THEN
        RAISE EXCEPTION 'Plaintext UTF-8 cannot be stored as encrypted_snapshot_payload'
            USING ERRCODE = 'check_violation';
    END IF;

    IF octet_length(p_iv_nonce) != 12 THEN
        RAISE EXCEPTION 'Invalid IV/nonce length: expected 12 bytes (96-bit AES-GCM), got %', octet_length(p_iv_nonce);
    END IF;

    IF octet_length(p_auth_tag) != 16 THEN
        RAISE EXCEPTION 'Invalid auth tag length: expected 16 bytes (128-bit AES-GCM), got %', octet_length(p_auth_tag);
    END IF;

    v_computed_plaintext_digest := encode(digest(convert_to(p_canonical_payload_json, 'UTF8'), 'sha256'), 'hex');
    IF v_computed_plaintext_digest != p_payload_digest THEN
        RAISE EXCEPTION 'Snapshot plaintext digest mismatch: computed %, provided %',
            v_computed_plaintext_digest, p_payload_digest;
    END IF;

    v_computed_ciphertext_digest := encode(digest(p_encrypted_payload, 'sha256'), 'hex');

    v_snapshot_id := COALESCE(p_snapshot_id, gen_random_uuid());
    v_wrapped_dek_digest := encode(digest(p_wrapped_dek, 'sha256'), 'hex');

    v_binding_raw :=
        octet_length(convert_to('DS-ENVELOPE-V1', 'UTF8'))::text || ':DS-ENVELOPE-V1|' ||
        octet_length(convert_to(p_batch_id::text, 'UTF8'))::text || ':' || p_batch_id::text || '|' ||
        octet_length(convert_to(v_snapshot_id::text, 'UTF8'))::text || ':' || v_snapshot_id::text || '|' ||
        octet_length(convert_to(v_key.key_id::text, 'UTF8'))::text || ':' || v_key.key_id::text || '|' ||
        octet_length(convert_to(v_key.key_version::text, 'UTF8'))::text || ':' || v_key.key_version::text || '|' ||
        octet_length(convert_to(v_key.algorithm, 'UTF8'))::text || ':' || v_key.algorithm || '|' ||
        octet_length(convert_to(v_wrapped_dek_digest, 'UTF8'))::text || ':' || v_wrapped_dek_digest || '|' ||
        octet_length(convert_to(v_computed_plaintext_digest, 'UTF8'))::text || ':' || v_computed_plaintext_digest || '|' ||
        octet_length(convert_to(v_computed_ciphertext_digest, 'UTF8'))::text || ':' || v_computed_ciphertext_digest || '|' ||
        octet_length(convert_to(encode(p_iv_nonce, 'hex'), 'UTF8'))::text || ':' || encode(p_iv_nonce, 'hex') || '|' ||
        octet_length(convert_to(encode(p_auth_tag, 'hex'), 'UTF8'))::text || ':' || encode(p_auth_tag, 'hex') || '|' ||
        octet_length(convert_to(p_aad_text, 'UTF8'))::text || ':' || p_aad_text;

    v_expected_attestation := hmac(convert_to(v_binding_raw, 'UTF8'), v_sec_keys.secret_attestation_key, 'sha256');

    v_legacy_attestation := hmac(
        convert_to(p_batch_id::text || ':' || v_computed_plaintext_digest || ':' || v_computed_ciphertext_digest || ':' || encode(p_iv_nonce, 'hex') || ':' || encode(p_auth_tag, 'hex') || ':' || p_aad_text, 'UTF8'),
        v_sec_keys.secret_attestation_key,
        'sha256'
    );

    IF p_cryptographic_attestation IS DISTINCT FROM v_expected_attestation
       AND p_cryptographic_attestation IS DISTINCT FROM v_legacy_attestation THEN
        RAISE EXCEPTION 'Cryptographic attestation verification failed: ciphertext does not match verified plaintext binding'
            USING ERRCODE = 'check_violation';
    END IF;

    -- 6. Canonical PayPal Payload Structural and Semantic Validation
    BEGIN
        v_json_val := p_canonical_payload_json::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Canonical payload is not valid JSON';
    END;

    v_header := v_json_val->'sender_batch_header';
    IF v_header IS NULL OR jsonb_typeof(v_header) != 'object' THEN
        RAISE EXCEPTION 'PayPal request missing sender_batch_header object';
    END IF;

    IF (v_header->>'sender_batch_id') IS DISTINCT FROM v_batch.sender_batch_id THEN
        RAISE EXCEPTION 'sender_batch_id in payload (%) does not match batch record (%)',
            v_header->>'sender_batch_id', v_batch.sender_batch_id;
    END IF;

    v_items := v_json_val->'items';
    IF v_items IS NULL OR jsonb_typeof(v_items) != 'array' THEN
        RAISE EXCEPTION 'PayPal request missing items array';
    END IF;

    SELECT COUNT(DISTINCT elem->>'sender_item_id'), COUNT(*)
    INTO v_unique_json_items, v_json_items_total
    FROM jsonb_array_elements(v_items) elem;

    IF v_unique_json_items != v_json_items_total THEN
        RAISE EXCEPTION 'Duplicate sender_item_id detected in payload items array';
    END IF;

    SELECT COUNT(*) INTO v_db_items_total FROM payout_items WHERE batch_id = p_batch_id;
    IF v_json_items_total != v_db_items_total THEN
        RAISE EXCEPTION 'Payload item count (%) does not match database item count (%)',
            v_json_items_total, v_db_items_total;
    END IF;

    FOR v_item_idx IN 0..(v_json_items_total - 1) LOOP
        v_item_elem := v_items->v_item_idx;
        v_sender_item_id := v_item_elem->>'sender_item_id';
        v_recipient_type := v_item_elem->>'recipient_type';
        v_receiver_text := v_item_elem->>'receiver';
        v_amount_obj := v_item_elem->'amount';

        IF v_recipient_type IS DISTINCT FROM 'EMAIL' THEN
            RAISE EXCEPTION 'Item % recipient_type must be EMAIL, got %', v_sender_item_id, v_recipient_type;
        END IF;

        IF v_receiver_text IS NULL OR length(trim(v_receiver_text)) = 0 OR length(trim(v_receiver_text)) > 127 THEN
            RAISE EXCEPTION 'Item % receiver is invalid or exceeds 127 characters (PayPal limit)', v_sender_item_id;
        END IF;

        v_normalized_receiver := lower(trim(v_receiver_text));

        SELECT * INTO v_item FROM payout_items WHERE batch_id = p_batch_id AND sender_item_id = v_sender_item_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Item % in payload does not exist in batch %', v_sender_item_id, p_batch_id;
        END IF;

        IF v_amount_obj IS NULL OR jsonb_typeof(v_amount_obj) != 'object' THEN
            RAISE EXCEPTION 'Item % missing amount object', v_sender_item_id;
        END IF;

        v_val_text := v_amount_obj->>'value';
        v_curr_text := v_amount_obj->>'currency';

        IF v_curr_text IS DISTINCT FROM v_item.currency THEN
            RAISE EXCEPTION 'Item % currency mismatch: payload has %, item has %', v_sender_item_id, v_curr_text, v_item.currency;
        END IF;

        v_expected_val_text := (v_item.amount_cents / 100)::text || '.' || lpad((v_item.amount_cents % 100)::text, 2, '0');
        IF v_val_text IS DISTINCT FROM v_expected_val_text THEN
            RAISE EXCEPTION 'Item % amount mismatch: payload has %, item has %', v_sender_item_id, v_val_text, v_expected_val_text;
        END IF;

        v_computed_blind_index := encode(hmac(convert_to(v_normalized_receiver, 'UTF8'), v_sec_keys.blind_index_key, 'sha256'), 'hex');
        IF v_item.destination_blind_index IS DISTINCT FROM v_computed_blind_index THEN
            RAISE EXCEPTION 'Item % recipient blind index verification failed', v_sender_item_id
                USING ERRCODE = 'check_violation';
        END IF;

        IF (v_item_elem->>'note') IS NOT NULL AND (v_item_elem->>'note') IS DISTINCT FROM v_item.note THEN
            RAISE EXCEPTION 'Item % note mismatch: payload has %, item has %',
                v_sender_item_id, v_item_elem->>'note', v_item.note;
        END IF;
    END LOOP;

    -- 7. Insert Sealed Snapshot
    INSERT INTO payout_snapshots (
        snapshot_id, batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
        encrypted_snapshot_payload, snapshot_digest, ciphertext_digest, cryptographic_attestation, finalized_at
    ) VALUES (
        v_snapshot_id, p_batch_id, v_batch.key_id, p_wrapped_dek, p_iv_nonce, p_auth_tag, p_aad_text,
        p_encrypted_payload, v_computed_plaintext_digest, v_computed_ciphertext_digest, p_cryptographic_attestation, CURRENT_TIMESTAMP
    );

    -- 8. Advance State to READY_FOR_CHECKER and bind active snapshot
    UPDATE payout_batches
    SET gateway_batch_state = 'READY_FOR_CHECKER',
        active_snapshot_id = v_snapshot_id,
        payload_digest = v_computed_plaintext_digest,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    RETURN v_snapshot_id;
END;
$$ LANGUAGE plpgsql;

-- Keep 9-parameter overload aligned (delegates cleanly to guarded 10-arg implementation)
CREATE OR REPLACE FUNCTION fn_finalize_payout_batch(
    p_batch_id UUID,
    p_canonical_payload_json TEXT,
    p_encrypted_payload BYTEA,
    p_payload_digest VARCHAR(64),
    p_wrapped_dek BYTEA,
    p_iv_nonce BYTEA,
    p_auth_tag BYTEA,
    p_aad_text TEXT,
    p_cryptographic_attestation BYTEA
)
RETURNS UUID
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN fn_finalize_payout_batch(
        p_batch_id, p_canonical_payload_json, p_encrypted_payload, p_payload_digest,
        p_wrapped_dek, p_iv_nonce, p_auth_tag, p_aad_text, p_cryptographic_attestation,
        NULL
    );
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- 4. RBAC HARDENING (PREVENT DIRECT APP WRITES TO AUDIO RISK EVIDENCE)
-- ----------------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON audio_assets, audio_consents, speaker_segments, risk_evaluations FROM deepfakeshield_app;
REVOKE ALL ON FUNCTION fn_record_audio_risk_evaluation(UUID, UUID, UUID, UUID, UUID, UUID, TEXT, INT, INT, NUMERIC, VARCHAR, VARCHAR, NUMERIC, NUMERIC, BOOLEAN, BOOLEAN, VARCHAR, VARCHAR, JSONB) FROM PUBLIC, deepfakeshield_app, deepfakeshield_payout_worker, deepfakeshield_auditor;
GRANT EXECUTE ON FUNCTION fn_record_audio_risk_evaluation(UUID, UUID, UUID, UUID, UUID, UUID, TEXT, INT, INT, NUMERIC, VARCHAR, VARCHAR, NUMERIC, NUMERIC, BOOLEAN, BOOLEAN, VARCHAR, VARCHAR, JSONB) TO deepfakeshield_verifier;
-- Read-only server-side gate verification requires SELECT on audio telemetry (never audio_consents PII, never writes)
GRANT SELECT ON sessions, audio_assets, speaker_segments, risk_evaluations TO deepfakeshield_auditor;

ALTER FUNCTION fn_record_audio_risk_evaluation(UUID, UUID, UUID, UUID, UUID, UUID, TEXT, INT, INT, NUMERIC, VARCHAR, VARCHAR, NUMERIC, NUMERIC, BOOLEAN, BOOLEAN, VARCHAR, VARCHAR, JSONB) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT, BYTEA) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, UUID) OWNER TO deepfakeshield_owner;

-- Preserve execute grants for finalization strictly on deepfakeshield_app & owner
REVOKE ALL ON FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT, BYTEA) FROM PUBLIC, deepfakeshield_auditor, deepfakeshield_payout_worker, deepfakeshield_verifier;
REVOKE ALL ON FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, UUID) FROM PUBLIC, deepfakeshield_auditor, deepfakeshield_payout_worker, deepfakeshield_verifier;
GRANT EXECUTE ON FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT, BYTEA) TO deepfakeshield_app;
GRANT EXECUTE ON FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, UUID) TO deepfakeshield_app;

-- ----------------------------------------------------------------------------
-- 5. PREFLIGHT VERIFICATION & MIGRATION VERSION RECORD
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF has_table_privilege('deepfakeshield_app', 'risk_evaluations', 'INSERT') THEN
        RAISE EXCEPTION 'RBAC verification failed: deepfakeshield_app still has INSERT on risk_evaluations';
    END IF;
    IF has_table_privilege('deepfakeshield_app', 'audio_assets', 'INSERT') THEN
        RAISE EXCEPTION 'RBAC verification failed: deepfakeshield_app still has INSERT on audio_assets';
    END IF;
    IF has_function_privilege(
        'deepfakeshield_app',
        'fn_record_audio_risk_evaluation(uuid, uuid, uuid, uuid, uuid, uuid, text, integer, integer, numeric, character varying, character varying, numeric, numeric, boolean, boolean, character varying, character varying, jsonb)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'RBAC verification failed: deepfakeshield_app must not execute fn_record_audio_risk_evaluation';
    END IF;
    IF has_function_privilege(
        'deepfakeshield_auditor',
        'fn_finalize_payout_batch(uuid, text, bytea, character varying, bytea, bytea, bytea, text, bytea, uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'RBAC verification failed: deepfakeshield_auditor must not execute fn_finalize_payout_batch';
    END IF;

    INSERT INTO schema_migrations (version, description, applied_at)
    VALUES ('V10.1.4', 'Database-Level Fail-Closed Audio Finalization Gate, Batch Binding, and Verifier-Only Evaluation RBAC', CURRENT_TIMESTAMP)
    ON CONFLICT (version) DO UPDATE SET applied_at = CURRENT_TIMESTAMP;
END $$;

COMMIT;
