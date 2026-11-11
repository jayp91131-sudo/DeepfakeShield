-- ============================================================================
-- DeepfakeShield for PayPal — Clean PostgreSQL 18 Database Migration (V10.1)
-- ============================================================================

\set ON_ERROR_STOP on

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- 1. ENCRYPTION KEY METADATA
-- ----------------------------------------------------------------------------
CREATE TABLE encryption_key_metadata (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_version INT UNIQUE NOT NULL,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    kms_key_arn TEXT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMPTZ NULL
);

-- ----------------------------------------------------------------------------
-- 2. USERS AND WEBAUTHN CREDENTIALS
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_user_role CHECK (role IN ('AP_CLERK', 'TREASURY_OFFICER', 'AUDITOR', 'ADMIN'))
);

CREATE TABLE webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    public_key_cose BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports JSONB NULL,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ NULL
);

CREATE TABLE webauthn_challenges (
    challenge_nonce UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    rp_id VARCHAR(255) NOT NULL,
    origin VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) NOT NULL,
    target_digest VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_webauthn_purpose CHECK (purpose IN ('TRANSACTION_APPROVAL', 'BENEFICIARY_CHANGE'))
);

-- ----------------------------------------------------------------------------
-- 3. BENEFICIARIES AND DESTINATION HISTORY
-- ----------------------------------------------------------------------------
CREATE TABLE beneficiaries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name VARCHAR(255) NOT NULL,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_destination BYTEA NOT NULL,
    destination_blind_index VARCHAR(64) NOT NULL,
    destination_digest VARCHAR(64) NOT NULL,
    country VARCHAR(2) NOT NULL DEFAULT 'US',
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    program_ref VARCHAR(100) NOT NULL,
    verification_status VARCHAR(50) NOT NULL DEFAULT 'VERIFIED',
    version INT NOT NULL DEFAULT 1,
    consent_evidence_hash VARCHAR(64) NOT NULL,
    registered_contact_phone_enc BYTEA NOT NULL,
    registered_contact_email_enc BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_beneficiary_currency CHECK (currency = 'USD'),
    CONSTRAINT check_verification_status CHECK (verification_status IN ('VERIFIED', 'CHANGE_PENDING', 'SUSPENDED'))
);

CREATE TABLE beneficiary_destination_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beneficiary_id UUID NOT NULL REFERENCES beneficiaries(id) ON DELETE RESTRICT,
    version INT NOT NULL,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_destination BYTEA NOT NULL,
    destination_blind_index VARCHAR(64) NOT NULL,
    destination_digest VARCHAR(64) NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ NULL DEFAULT NULL,
    CONSTRAINT uq_beneficiary_history_version UNIQUE (beneficiary_id, version)
);

-- ----------------------------------------------------------------------------
-- 4. SESSIONS, BATCHES, AND ITEMS (INTEGER CENTS STORAGE)
-- ----------------------------------------------------------------------------
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    ip_address INET NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMPTZ NULL,
    CONSTRAINT check_session_status CHECK (session_status IN ('ACTIVE', 'CLOSED', 'EXPIRED'))
);

CREATE TABLE payout_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    program_id VARCHAR(100) NOT NULL,
    payout_period VARCHAR(50) NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_canonical_payload BYTEA NOT NULL,
    payload_digest VARCHAR(64) NOT NULL,
    sender_batch_id VARCHAR(128) UNIQUE NOT NULL,
    paypal_request_id UUID UNIQUE NOT NULL,
    payout_batch_id VARCHAR(30) UNIQUE NULL,
    gateway_batch_state VARCHAR(50) NOT NULL DEFAULT 'DRAFT',
    paypal_batch_state VARCHAR(50) NULL,
    total_amount_cents BIGINT NOT NULL,
    item_count INT NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    active_snapshot_id UUID NULL,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_usd_only CHECK (currency = 'USD'),
    CONSTRAINT check_batch_item_limit CHECK (item_count > 0 AND item_count <= 15000),
    CONSTRAINT check_total_cents_positive CHECK (total_amount_cents > 0),
    CONSTRAINT check_gateway_batch_state CHECK (gateway_batch_state IN (
        'DRAFT', 'VALIDATING', 'READY_FOR_CHECKER', 'NEEDS_REVIEW', 
        'BLOCKED', 'APPROVED_TO_SUBMIT', 'REJECTED_BY_CHECKER', 'SUBMITTING', 
        'SUBMITTED', 'STALE_INVALIDATED', 'MANUAL_RECONCILIATION_REQUIRED', 'SETTLED', 'FAILED'
    )),
    CONSTRAINT check_paypal_batch_state CHECK (paypal_batch_state IS NULL OR paypal_batch_state IN (
        'PENDING', 'PROCESSING', 'SUCCESS', 'DENIED', 'CANCELED'
    ))
);

CREATE TABLE payout_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID UNIQUE NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_snapshot_payload BYTEA NOT NULL,
    snapshot_digest VARCHAR(64) NOT NULL,
    finalized_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE payout_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    obligation_key VARCHAR(255) NOT NULL,
    beneficiary_id UUID NOT NULL REFERENCES beneficiaries(id) ON DELETE RESTRICT,
    beneficiary_version INT NOT NULL,
    expected_destination_digest VARCHAR(64) NOT NULL,
    sender_item_id VARCHAR(63) NOT NULL,
    payout_item_id VARCHAR(30) UNIQUE NULL,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_receiver BYTEA NOT NULL,
    destination_blind_index VARCHAR(64) NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    gateway_item_state VARCHAR(50) NOT NULL DEFAULT 'DRAFT',
    paypal_item_state VARCHAR(50) NULL,
    raw_provider_status_text TEXT NULL,
    activity_id VARCHAR(30) NULL,
    transaction_id VARCHAR(30) NULL,
    error_code VARCHAR(100) NULL,
    error_message TEXT NULL,
    CONSTRAINT check_usd_item CHECK (currency = 'USD'),
    CONSTRAINT check_item_cents_positive CHECK (amount_cents > 0),
    CONSTRAINT uq_batch_sender_item UNIQUE (batch_id, sender_item_id),
    CONSTRAINT check_gateway_item_state CHECK (gateway_item_state IN (
        'DRAFT', 'VALIDATING', 'APPROVED', 'SUBMITTED', 'REJECTED', 'STALE_INVALIDATED', 'SETTLED', 'FAILED', 'MANUAL_RECONCILIATION_REQUIRED'
    )),
    CONSTRAINT check_paypal_item_state CHECK (paypal_item_state IS NULL OR paypal_item_state IN (
        'PENDING', 'SUCCESS', 'UNCLAIMED', 'ONHOLD', 'BLOCKED', 'FAILED', 'RETURNED', 'REFUNDED', 'REVERSED', 'UNKNOWN_EXTERNAL_STATUS'
    ))
);

CREATE UNIQUE INDEX uq_active_obligation_key 
ON payout_items (obligation_key) 
WHERE gateway_item_state NOT IN ('REJECTED', 'STALE_INVALIDATED', 'FAILED');

-- ----------------------------------------------------------------------------
-- 5. DURABLE BENEFICIARY SUBMISSION LOCKS
-- ----------------------------------------------------------------------------
CREATE TABLE beneficiary_submission_locks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beneficiary_id UUID NOT NULL REFERENCES beneficiaries(id) ON DELETE RESTRICT,
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    expected_version INT NOT NULL,
    expected_destination_digest VARCHAR(64) NOT NULL,
    locked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX uq_active_beneficiary_lock 
ON beneficiary_submission_locks (beneficiary_id) 
WHERE released_at IS NULL;

-- ----------------------------------------------------------------------------
-- 6. BENEFICIARY CHANGES AND APPROVALS
-- ----------------------------------------------------------------------------
CREATE TABLE beneficiary_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beneficiary_id UUID NOT NULL REFERENCES beneficiaries(id) ON DELETE RESTRICT,
    requested_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    old_version INT NOT NULL,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    new_encrypted_destination BYTEA NOT NULL,
    new_destination_blind_index VARCHAR(64) NOT NULL,
    proposed_destination_digest VARCHAR(64) NOT NULL,
    verification_method VARCHAR(50) NOT NULL,
    encrypted_verification_notes BYTEA NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING_OFFICER_1',
    cooling_off_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_change_status CHECK (status IN (
        'PENDING_OFFICER_1', 'PENDING_OFFICER_2', 'COOLING_OFF', 'ACTIVATED', 'REJECTED'
    ))
);

CREATE TABLE beneficiary_change_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    change_id UUID NOT NULL REFERENCES beneficiary_changes(id) ON DELETE RESTRICT,
    officer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    credential_id TEXT NOT NULL REFERENCES webauthn_credentials(credential_id) ON DELETE RESTRICT,
    approval_order INT NOT NULL,
    destination_digest VARCHAR(64) NOT NULL,
    challenge_nonce UUID UNIQUE NOT NULL REFERENCES webauthn_challenges(challenge_nonce) ON DELETE RESTRICT,
    webauthn_signature BYTEA NOT NULL,
    approved_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_change_officer UNIQUE (change_id, officer_id),
    CONSTRAINT uq_change_order UNIQUE (change_id, approval_order),
    CONSTRAINT check_approval_order CHECK (approval_order IN (1, 2))
);

-- ----------------------------------------------------------------------------
-- 7. AUDIO EVIDENCE AND PIPELINE TABLES
-- ----------------------------------------------------------------------------
CREATE TABLE audio_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    batch_id UUID NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_file_path TEXT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    duration_seconds NUMERIC(6,2) NOT NULL,
    usable_speech_seconds NUMERIC(6,2) NOT NULL,
    is_clipped BOOLEAN NOT NULL DEFAULT FALSE,
    snr_db NUMERIC(5,2) NULL,
    retention_deadline TIMESTAMPTZ NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audio_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audio_asset_id UUID NOT NULL REFERENCES audio_assets(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    consenting_party_enc BYTEA NOT NULL,
    consent_method VARCHAR(50) NOT NULL,
    consent_timestamp TIMESTAMPTZ NOT NULL
);

CREATE TABLE speaker_segments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audio_asset_id UUID NOT NULL REFERENCES audio_assets(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    segment_index INT NOT NULL,
    start_ms INT NOT NULL,
    end_ms INT NOT NULL,
    speaker_label VARCHAR(50) NOT NULL,
    is_human_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    encrypted_raw_transcript BYTEA NOT NULL,
    asr_confidence NUMERIC(4,3) NOT NULL,
    CONSTRAINT uq_audio_segment UNIQUE (audio_asset_id, segment_index)
);

CREATE TABLE risk_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    audio_asset_id UUID NOT NULL REFERENCES audio_assets(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    aasist_version VARCHAR(50) NOT NULL,
    aasist_checkpoint_hash VARCHAR(64) NOT NULL,
    gemini_prompt_version VARCHAR(50) NOT NULL,
    window_scores_json JSONB NOT NULL,
    window_count INT NOT NULL,
    mean_window_score NUMERIC(5,4) NOT NULL,
    max_window_score NUMERIC(5,4) NOT NULL,
    acoustic_signal VARCHAR(50) NOT NULL,
    encrypted_gemini_evidence BYTEA NOT NULL,
    policy_decision VARCHAR(50) NOT NULL,
    discrepancy_flags JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_acoustic_signal CHECK (acoustic_signal IN ('ELEVATED_SIGNAL', 'NO_ELEVATED_SIGNAL', 'INDETERMINATE')),
    CONSTRAINT check_policy_decision CHECK (policy_decision IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW', 'BLOCKED'))
);

-- ----------------------------------------------------------------------------
-- 8. OFFICER APPROVALS AND OUTBOX
-- ----------------------------------------------------------------------------
CREATE TABLE officer_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID UNIQUE NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    snapshot_id UUID NOT NULL REFERENCES payout_snapshots(snapshot_id) ON DELETE RESTRICT,
    officer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    credential_id TEXT NOT NULL REFERENCES webauthn_credentials(credential_id) ON DELETE RESTRICT,
    challenge_nonce UUID UNIQUE NOT NULL REFERENCES webauthn_challenges(challenge_nonce) ON DELETE RESTRICT,
    batch_digest VARCHAR(64) NOT NULL,
    client_data_json TEXT NOT NULL,
    authenticator_data BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    verification_status VARCHAR(50) NOT NULL,
    approved_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_officer_approval_status CHECK (verification_status = 'VERIFIED')
);

CREATE TABLE outbox_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    snapshot_id UUID NOT NULL REFERENCES payout_snapshots(snapshot_id) ON DELETE RESTRICT,
    deduplication_key VARCHAR(255) UNIQUE NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    lease_owner VARCHAR(100) NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    heartbeat_at TIMESTAMPTZ NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    next_execution_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ NULL,
    last_error TEXT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    CONSTRAINT check_outbox_status CHECK (status IN (
        'PENDING', 'IN_PROGRESS', 'RETRY', 'COMPLETED', 'FAILED_EXHAUSTED', 'MANUAL_RECONCILIATION_REQUIRED'
    ))
);

CREATE TABLE outbox_recovery_events (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES outbox_jobs(id) ON DELETE RESTRICT,
    previous_lease_owner VARCHAR(100) NULL,
    previous_lease_expires_at TIMESTAMPTZ NULL,
    recovered_by_worker VARCHAR(100) NOT NULL,
    new_fencing_token BIGINT NOT NULL,
    recovery_reason TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE paypal_api_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    attempt_number INT NOT NULL,
    fencing_token BIGINT NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    paypal_request_id UUID NOT NULL,
    sender_batch_id VARCHAR(128) NOT NULL,
    request_digest VARCHAR(64) NOT NULL,
    response_http_code INT NULL,
    response_body_redacted JSONB NULL,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_batch_attempt UNIQUE (batch_id, attempt_number)
);

CREATE TABLE reconciliation_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    attempt_number INT NOT NULL,
    fencing_token BIGINT NOT NULL,
    trigger_source VARCHAR(50) NOT NULL,
    payout_batch_id VARCHAR(30) NULL,
    reconciliation_strategy VARCHAR(50) NOT NULL,
    outcome VARCHAR(50) NOT NULL,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE webhook_inbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(128) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_raw_payload BYTEA NOT NULL,
    signature_verified BOOLEAN NOT NULL,
    processed_status VARCHAR(50) NOT NULL DEFAULT 'UNPROCESSED',
    received_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMPTZ NULL,
    CONSTRAINT check_webhook_status CHECK (processed_status IN ('UNPROCESSED', 'PROCESSED', 'IGNORED', 'FAILED'))
);

-- ----------------------------------------------------------------------------
-- 9. SERIALIZED CRYPTOGRAPHIC AUDIT LOG
-- ----------------------------------------------------------------------------
CREATE TABLE audit_chain_heads (
    chain_id VARCHAR(50) PRIMARY KEY,
    head_event_id BIGINT NULL,
    head_digest VARCHAR(64) NOT NULL,
    event_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO audit_chain_heads (chain_id, head_event_id, head_digest, event_count)
VALUES ('DEFAULT', NULL, '0000000000000000000000000000000000000000000000000000000000000000', 0);

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    chain_id VARCHAR(50) NOT NULL REFERENCES audit_chain_heads(chain_id) ON DELETE RESTRICT,
    actor_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID NOT NULL,
    key_id UUID NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NULL,
    iv_nonce BYTEA NULL,
    auth_tag BYTEA NULL,
    aad_text TEXT NULL,
    encrypted_event_payload BYTEA NOT NULL,
    event_digest VARCHAR(64) NOT NULL,
    prev_event_digest VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    chain_id VARCHAR(50) NOT NULL REFERENCES audit_chain_heads(chain_id) ON DELETE RESTRICT,
    up_to_event_id BIGINT NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    checkpoint_digest VARCHAR(64) NOT NULL,
    offline_key_id VARCHAR(100) NOT NULL,
    rsa_signature BYTEA NOT NULL,
    signed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 10. TRIGGERS & STORED PROCEDURES
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_prevent_beneficiary_physical_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Physical deletion of beneficiaries is strictly prohibited. Use verification_status = SUSPENDED for archival.'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_beneficiary_no_physical_delete
BEFORE DELETE ON beneficiaries
FOR EACH ROW EXECUTE FUNCTION fn_prevent_beneficiary_physical_delete();

CREATE OR REPLACE FUNCTION fn_check_beneficiary_submission_lock()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM beneficiary_submission_locks
        WHERE beneficiary_id = OLD.id AND released_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Beneficiary % is locked under active payout submission. Modifications forbidden.', OLD.id
            USING ERRCODE = '55P03';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_beneficiary_lock_protection
BEFORE UPDATE ON beneficiaries
FOR EACH ROW EXECUTE FUNCTION fn_check_beneficiary_submission_lock();

CREATE OR REPLACE FUNCTION fn_validate_batch_state_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.gateway_batch_state = NEW.gateway_batch_state THEN
        RETURN NEW;
    END IF;

    IF OLD.gateway_batch_state = 'DRAFT' AND NEW.gateway_batch_state IN ('VALIDATING', 'BLOCKED', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'VALIDATING' AND NEW.gateway_batch_state IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW', 'BLOCKED', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'READY_FOR_CHECKER' AND NEW.gateway_batch_state IN ('APPROVED_TO_SUBMIT', 'REJECTED_BY_CHECKER', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'NEEDS_REVIEW' AND NEW.gateway_batch_state IN ('READY_FOR_CHECKER', 'APPROVED_TO_SUBMIT', 'REJECTED_BY_CHECKER', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'APPROVED_TO_SUBMIT' AND NEW.gateway_batch_state IN ('SUBMITTING', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'SUBMITTING' AND NEW.gateway_batch_state IN ('SUBMITTED', 'MANUAL_RECONCILIATION_REQUIRED', 'FAILED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'SUBMITTED' AND NEW.gateway_batch_state IN ('SETTLED', 'FAILED', 'MANUAL_RECONCILIATION_REQUIRED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'MANUAL_RECONCILIATION_REQUIRED' AND NEW.gateway_batch_state IN ('SUBMITTED', 'SETTLED', 'FAILED') THEN
        RETURN NEW;
    ELSE
        RAISE EXCEPTION 'Illegal state transition for batch %: % to %', OLD.id, OLD.gateway_batch_state, NEW.gateway_batch_state
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_batch_transition
BEFORE UPDATE OF gateway_batch_state ON payout_batches
FOR EACH ROW EXECUTE FUNCTION fn_validate_batch_state_transition();

CREATE OR REPLACE FUNCTION fn_serialize_payout_items_against_parent()
RETURNS TRIGGER AS $$
DECLARE
    v_parent_id UUID;
    v_parent_state VARCHAR(50);
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.batch_id != NEW.batch_id THEN
        IF OLD.batch_id < NEW.batch_id THEN
            SELECT gateway_batch_state INTO v_parent_state FROM payout_batches WHERE id = OLD.batch_id FOR SHARE;
            PERFORM 1 FROM payout_batches WHERE id = NEW.batch_id FOR SHARE;
        ELSE
            SELECT gateway_batch_state INTO v_parent_state FROM payout_batches WHERE id = NEW.batch_id FOR SHARE;
            PERFORM 1 FROM payout_batches WHERE id = OLD.batch_id FOR SHARE;
        END IF;
    ELSE
        v_parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.batch_id ELSE NEW.batch_id END;
        SELECT gateway_batch_state INTO v_parent_state FROM payout_batches WHERE id = v_parent_id FOR SHARE;
    END IF;

    IF v_parent_state NOT IN ('DRAFT', 'VALIDATING') THEN
        RAISE EXCEPTION 'Modifications to payout_items are frozen: parent batch is in state %', v_parent_state
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_serialize_payout_items
BEFORE INSERT OR UPDATE OR DELETE ON payout_items
FOR EACH ROW EXECUTE FUNCTION fn_serialize_payout_items_against_parent();

CREATE OR REPLACE FUNCTION fn_check_beneficiary_lock_release()
RETURNS TRIGGER AS $$
DECLARE
    v_batch RECORD;
BEGIN
    IF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL THEN
        SELECT gateway_batch_state, payout_batch_id INTO v_batch
        FROM payout_batches
        WHERE id = NEW.batch_id;

        IF v_batch.gateway_batch_state = 'SUBMITTED' AND v_batch.payout_batch_id IS NOT NULL THEN
            RETURN NEW;
        ELSIF v_batch.gateway_batch_state IN ('SETTLED', 'FAILED', 'REJECTED_BY_CHECKER', 'STALE_INVALIDATED', 'BLOCKED') THEN
            RETURN NEW;
        ELSE
            RAISE EXCEPTION 'Cannot release lock for beneficiary %: Batch % is in non-terminal state % (payout_batch_id=%)',
                NEW.beneficiary_id, NEW.batch_id, v_batch.gateway_batch_state, v_batch.payout_batch_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_beneficiary_lock_release
BEFORE UPDATE ON beneficiary_submission_locks
FOR EACH ROW EXECUTE FUNCTION fn_check_beneficiary_lock_release();

CREATE OR REPLACE FUNCTION fn_prevent_item_terminal_state_overwrite()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.paypal_item_state IN ('SUCCESS', 'FAILED', 'RETURNED', 'REFUNDED') THEN
        IF NEW.paypal_item_state IN ('PENDING', 'UNCLAIMED', 'ONHOLD') THEN
            RAISE EXCEPTION 'State Regression Violation: Item % is in terminal state %; cannot revert to %',
                OLD.id, OLD.paypal_item_state, NEW.paypal_item_state
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_item_state_regression
BEFORE UPDATE OF paypal_item_state ON payout_items
FOR EACH ROW EXECUTE FUNCTION fn_prevent_item_terminal_state_overwrite();

CREATE OR REPLACE FUNCTION fn_enforce_audit_immutability()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit events are strictly append-only. Mutation is forbidden.'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_immutability
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION fn_enforce_audit_immutability();

CREATE TRIGGER trg_audit_chain_head_no_delete
BEFORE DELETE ON audit_chain_heads
FOR EACH ROW EXECUTE FUNCTION fn_enforce_audit_immutability();

CREATE OR REPLACE FUNCTION fn_finalize_payout_batch(
    p_batch_id UUID,
    p_canonical_payload BYTEA,
    p_payload_digest VARCHAR(64),
    p_wrapped_dek BYTEA,
    p_iv_nonce BYTEA,
    p_auth_tag BYTEA,
    p_aad_text TEXT
)
RETURNS UUID AS $$
DECLARE
    v_batch RECORD;
    v_beneficiary RECORD;
    v_actual_count INT;
    v_actual_total_cents BIGINT;
    v_snapshot_id UUID;
BEGIN
    FOR v_beneficiary IN 
        SELECT id, version, verification_status, destination_digest, encrypted_destination, 
               destination_blind_index, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text
        FROM beneficiaries
        WHERE id IN (SELECT DISTINCT beneficiary_id FROM payout_items WHERE batch_id = p_batch_id)
        ORDER BY id ASC
        FOR UPDATE
    LOOP
        IF v_beneficiary.verification_status != 'VERIFIED' THEN
            RAISE EXCEPTION 'Cannot finalize: Beneficiary % status is %, expected VERIFIED',
                v_beneficiary.id, v_beneficiary.verification_status;
        END IF;

        UPDATE payout_items
        SET encrypted_receiver = v_beneficiary.encrypted_destination,
            destination_blind_index = v_beneficiary.destination_blind_index,
            expected_destination_digest = v_beneficiary.destination_digest,
            beneficiary_version = v_beneficiary.version,
            key_id = v_beneficiary.key_id,
            wrapped_dek = v_beneficiary.wrapped_dek,
            iv_nonce = v_beneficiary.iv_nonce,
            auth_tag = v_beneficiary.auth_tag,
            aad_text = v_beneficiary.aad_text
        WHERE batch_id = p_batch_id AND beneficiary_id = v_beneficiary.id;

        INSERT INTO beneficiary_submission_locks (
            beneficiary_id, batch_id, expected_version, expected_destination_digest, locked_at
        ) VALUES (
            v_beneficiary.id, p_batch_id, v_beneficiary.version, v_beneficiary.destination_digest, CURRENT_TIMESTAMP
        );
    END LOOP;

    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state != 'VALIDATING' THEN
        RAISE EXCEPTION 'Cannot finalize batch %: current state is %, expected VALIDATING',
            p_batch_id, v_batch.gateway_batch_state;
    END IF;

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

    INSERT INTO payout_snapshots (
        batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
        encrypted_snapshot_payload, snapshot_digest, finalized_at
    ) VALUES (
        p_batch_id, v_batch.key_id, p_wrapped_dek, p_iv_nonce, p_auth_tag, p_aad_text,
        p_canonical_payload, p_payload_digest, CURRENT_TIMESTAMP
    ) RETURNING snapshot_id INTO v_snapshot_id;

    UPDATE payout_batches
    SET gateway_batch_state = 'READY_FOR_CHECKER',
        active_snapshot_id = v_snapshot_id,
        payload_digest = p_payload_digest,
        encrypted_canonical_payload = p_canonical_payload,
        wrapped_dek = p_wrapped_dek,
        iv_nonce = p_iv_nonce,
        auth_tag = p_auth_tag,
        aad_text = p_aad_text,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    RETURN v_snapshot_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_submit_officer_approval(
    p_batch_id UUID,
    p_snapshot_id UUID,
    p_officer_id UUID,
    p_credential_id TEXT,
    p_challenge_nonce UUID,
    p_batch_digest VARCHAR(64),
    p_client_data_json TEXT,
    p_authenticator_data BYTEA,
    p_signature BYTEA
)
RETURNS VOID AS $$
DECLARE
    v_batch RECORD;
    v_snapshot RECORD;
    v_officer RECORD;
    v_challenge RECORD;
    v_credential RECORD;
BEGIN
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state NOT IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW') THEN
        RAISE EXCEPTION 'Batch % is in state %, not ready for approval', p_batch_id, v_batch.gateway_batch_state;
    END IF;

    IF v_batch.active_snapshot_id != p_snapshot_id THEN
        RAISE EXCEPTION 'Snapshot binding mismatch: batch references snapshot %, approval supplied %',
            v_batch.active_snapshot_id, p_snapshot_id;
    END IF;

    SELECT * INTO v_snapshot FROM payout_snapshots WHERE snapshot_id = p_snapshot_id;
    IF v_snapshot.snapshot_digest != p_batch_digest OR v_snapshot.snapshot_digest != v_batch.payload_digest THEN
        RAISE EXCEPTION 'Digest mismatch between snapshot % and supplied digest %',
            v_snapshot.snapshot_digest, p_batch_digest;
    END IF;

    SELECT * INTO v_officer FROM users WHERE id = p_officer_id;
    IF NOT FOUND OR v_officer.is_active = FALSE OR v_officer.role != 'TREASURY_OFFICER' THEN
        RAISE EXCEPTION 'User % is not an active TREASURY_OFFICER', p_officer_id;
    END IF;

    IF v_batch.created_by_user_id = p_officer_id THEN
        RAISE EXCEPTION 'Maker-Checker Violation: Officer % created batch % and cannot approve it',
            p_officer_id, p_batch_id;
    END IF;

    SELECT * INTO v_credential FROM webauthn_credentials WHERE credential_id = p_credential_id;
    IF NOT FOUND OR v_credential.user_id != p_officer_id OR v_credential.is_revoked = TRUE THEN
        RAISE EXCEPTION 'Credential % is invalid or revoked', p_credential_id;
    END IF;

    UPDATE webauthn_challenges
    SET is_consumed = TRUE, consumed_at = CURRENT_TIMESTAMP
    WHERE challenge_nonce = p_challenge_nonce
      AND user_id = p_officer_id
      AND purpose = 'TRANSACTION_APPROVAL'
      AND target_digest = p_batch_digest
      AND expires_at > CURRENT_TIMESTAMP
      AND is_consumed = FALSE
    RETURNING * INTO v_challenge;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'WebAuthn challenge is invalid, expired, mismatched, or already consumed';
    END IF;

    INSERT INTO officer_approvals (
        batch_id, snapshot_id, officer_id, credential_id, challenge_nonce, batch_digest,
        client_data_json, authenticator_data, signature, verification_status, approved_at
    ) VALUES (
        p_batch_id, p_snapshot_id, p_officer_id, p_credential_id, p_challenge_nonce, p_batch_digest,
        p_client_data_json, p_authenticator_data, p_signature, 'VERIFIED', CURRENT_TIMESTAMP
    );

    UPDATE payout_batches
    SET gateway_batch_state = 'APPROVED_TO_SUBMIT', updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    INSERT INTO outbox_jobs (
        batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status
    ) VALUES (
        p_batch_id, p_snapshot_id, 'PAYOUT_SUBMISSION_' || p_batch_id::text, 'SUBMIT_PAYOUT_BATCH',
        v_batch.fencing_token, 'PENDING'
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_activate_beneficiary_change(p_change_id UUID)
RETURNS VOID AS $$
DECLARE
    v_change RECORD;
    v_beneficiary RECORD;
    v_app1 RECORD;
    v_app2 RECORD;
BEGIN
    SELECT * INTO v_change FROM beneficiary_changes WHERE id = p_change_id FOR UPDATE;
    IF NOT FOUND OR v_change.status = 'ACTIVATED' THEN
        RAISE EXCEPTION 'Change request % is invalid or already activated', p_change_id;
    END IF;

    SELECT * INTO v_beneficiary FROM beneficiaries WHERE id = v_change.beneficiary_id FOR UPDATE;

    IF v_beneficiary.version != v_change.old_version THEN
        RAISE EXCEPTION 'Optimistic Concurrency Failure: Beneficiary is v%, change was for v%',
            v_beneficiary.version, v_change.old_version;
    END IF;

    IF v_change.cooling_off_until IS NULL OR v_change.cooling_off_until > CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Cooling-off interval has not elapsed';
    END IF;

    SELECT * INTO v_app1 FROM beneficiary_change_approvals WHERE change_id = p_change_id AND approval_order = 1;
    SELECT * INTO v_app2 FROM beneficiary_change_approvals WHERE change_id = p_change_id AND approval_order = 2;

    IF v_app1.id IS NULL OR v_app2.id IS NULL OR v_app1.officer_id = v_app2.officer_id THEN
        RAISE EXCEPTION 'Change requires exactly 2 distinct officer approvals';
    END IF;

    IF v_app1.destination_digest != v_change.proposed_destination_digest OR 
       v_app2.destination_digest != v_change.proposed_destination_digest THEN
        RAISE EXCEPTION 'Approval destination digests do not match proposed digest';
    END IF;

    IF EXISTS (
        SELECT 1 FROM beneficiary_submission_locks
        WHERE beneficiary_id = v_change.beneficiary_id AND released_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Beneficiary % is locked under active payout submission', v_change.beneficiary_id;
    END IF;

    UPDATE beneficiary_destination_history
    SET superseded_at = CURRENT_TIMESTAMP
    WHERE beneficiary_id = v_change.beneficiary_id AND superseded_at IS NULL;

    INSERT INTO beneficiary_destination_history (
        beneficiary_id, version, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
        encrypted_destination, destination_blind_index, destination_digest, activated_at
    ) VALUES (
        v_change.beneficiary_id, v_change.old_version + 1, v_change.key_id,
        v_change.wrapped_dek, v_change.iv_nonce, v_change.auth_tag, v_change.aad_text,
        v_change.new_encrypted_destination, v_change.new_destination_blind_index,
        v_change.proposed_destination_digest, CURRENT_TIMESTAMP
    );

    UPDATE beneficiaries
    SET version = version + 1,
        key_id = v_change.key_id,
        wrapped_dek = v_change.wrapped_dek,
        iv_nonce = v_change.iv_nonce,
        auth_tag = v_change.auth_tag,
        aad_text = v_change.aad_text,
        encrypted_destination = v_change.new_encrypted_destination,
        destination_blind_index = v_change.new_destination_blind_index,
        destination_digest = v_change.proposed_destination_digest,
        verification_status = 'VERIFIED',
        updated_at = CURRENT_TIMESTAMP
    WHERE id = v_change.beneficiary_id;

    PERFORM id FROM payout_batches
    WHERE id IN (SELECT DISTINCT batch_id FROM payout_items WHERE beneficiary_id = v_change.beneficiary_id)
      AND gateway_batch_state IN ('DRAFT', 'VALIDATING', 'READY_FOR_CHECKER', 'NEEDS_REVIEW', 'APPROVED_TO_SUBMIT')
    ORDER BY id ASC
    FOR UPDATE;

    UPDATE payout_batches
    SET gateway_batch_state = 'STALE_INVALIDATED', updated_at = CURRENT_TIMESTAMP
    WHERE id IN (SELECT DISTINCT batch_id FROM payout_items WHERE beneficiary_id = v_change.beneficiary_id)
      AND gateway_batch_state IN ('DRAFT', 'VALIDATING', 'READY_FOR_CHECKER', 'NEEDS_REVIEW', 'APPROVED_TO_SUBMIT');

    UPDATE payout_items
    SET gateway_item_state = 'STALE_INVALIDATED'
    WHERE beneficiary_id = v_change.beneficiary_id 
      AND gateway_item_state IN ('DRAFT', 'VALIDATING', 'APPROVED');

    UPDATE beneficiary_changes
    SET status = 'ACTIVATED'
    WHERE id = p_change_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_append_audit_event(
    p_chain_id VARCHAR(50),
    p_actor_id UUID,
    p_event_type VARCHAR(100),
    p_resource_type VARCHAR(50),
    p_resource_id UUID,
    p_key_id UUID,
    p_wrapped_dek BYTEA,
    p_iv_nonce BYTEA,
    p_auth_tag BYTEA,
    p_aad_text TEXT,
    p_encrypted_payload BYTEA,
    p_canonical_plain_json TEXT
)
RETURNS BIGINT AS $$
DECLARE
    v_head RECORD;
    v_new_event_id BIGINT;
    v_timestamp_iso TEXT;
    v_canonical_text TEXT;
    v_new_digest VARCHAR(64);
BEGIN
    SELECT * INTO v_head FROM audit_chain_heads WHERE chain_id = p_chain_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Audit chain % does not exist', p_chain_id;
    END IF;

    v_timestamp_iso := to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
    v_canonical_text := v_head.head_digest || '|' || p_chain_id || '|' || p_event_type || '|' 
                        || p_resource_type || '|' || p_resource_id::text || '|' 
                        || COALESCE(p_actor_id::text, 'SYSTEM') || '|' || v_timestamp_iso || '|' 
                        || p_canonical_plain_json;
    v_new_digest := encode(digest(v_canonical_text, 'sha256'), 'hex');

    INSERT INTO audit_events (
        chain_id, actor_id, event_type, resource_type, resource_id,
        key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
        encrypted_event_payload, event_digest, prev_event_digest, created_at
    ) VALUES (
        p_chain_id, p_actor_id, p_event_type, p_resource_type, p_resource_id,
        p_key_id, p_wrapped_dek, p_iv_nonce, p_auth_tag, p_aad_text,
        p_encrypted_payload, v_new_digest, v_head.head_digest, clock_timestamp()
    ) RETURNING id INTO v_new_event_id;

    UPDATE audit_chain_heads
    SET head_event_id = v_new_event_id,
        head_digest = v_new_digest,
        event_count = event_count + 1,
        updated_at = CURRENT_TIMESTAMP
    WHERE chain_id = p_chain_id;

    RETURN v_new_event_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_sweep_exhausted_outbox_jobs()
RETURNS INT AS $$
DECLARE
    v_swept_count INT := 0;
    v_job RECORD;
BEGIN
    FOR v_job IN
        SELECT id, batch_id FROM outbox_jobs
        WHERE status = 'IN_PROGRESS' 
          AND lease_expires_at < CURRENT_TIMESTAMP
          AND attempt_count >= max_attempts
        FOR UPDATE
    LOOP
        UPDATE outbox_jobs
        SET status = 'MANUAL_RECONCILIATION_REQUIRED',
            last_error = 'EXPIRED_LEASE_MAX_ATTEMPTS_EXHAUSTED'
        WHERE id = v_job.id;

        UPDATE payout_batches
        SET gateway_batch_state = 'MANUAL_RECONCILIATION_REQUIRED',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_job.batch_id;

        v_swept_count := v_swept_count + 1;
    END LOOP;

    RETURN v_swept_count;
END;
$$ LANGUAGE plpgsql;

COMMIT;
