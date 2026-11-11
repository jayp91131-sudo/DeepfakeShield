-- ============================================================================
-- DEEPFAKESHIELD FOR PAYPAL — V10.1.1 SOLE PRODUCTION SCHEMA MIGRATION
-- Database: PostgreSQL 18.6
-- Architecture: Adversarial Zero-Trust Social Engineering & Payout Gateway
-- Object Owner: deepfakeshield_owner (NOLOGIN)
--
-- EXECUTION REQUIREMENT:
-- This migration MUST be executed by a privileged migration superuser
-- (e.g., 'postgres' or database cluster administrator).
-- The migration is enclosed in an atomic transaction block (BEGIN ... COMMIT).
-- Any failure automatically triggers a complete rollback of all changes.
-- ============================================================================

BEGIN;

-- Ensure pgcrypto extension is installed
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- 1. DATABASE ROLES DECLARATION (No hard-coded passwords in migration source)
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deepfakeshield_owner') THEN
        CREATE ROLE deepfakeshield_owner WITH NOLOGIN NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deepfakeshield_app') THEN
        CREATE ROLE deepfakeshield_app WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deepfakeshield_verifier') THEN
        CREATE ROLE deepfakeshield_verifier WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deepfakeshield_payout_worker') THEN
        CREATE ROLE deepfakeshield_payout_worker WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deepfakeshield_auditor') THEN
        CREATE ROLE deepfakeshield_auditor WITH LOGIN;
    END IF;
END $$;

-- Hardened Schema Security: Revoke CREATE on public from PUBLIC and runtime roles
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM deepfakeshield_app, deepfakeshield_verifier, deepfakeshield_payout_worker, deepfakeshield_auditor;
GRANT USAGE ON SCHEMA public TO deepfakeshield_app, deepfakeshield_verifier, deepfakeshield_payout_worker, deepfakeshield_auditor;

-- Set schema ownership to dedicated NOLOGIN owner
ALTER SCHEMA public OWNER TO deepfakeshield_owner;

-- Re-grant execute on pgcrypto cryptographic primitives to PUBLIC and runtime roles
GRANT EXECUTE ON FUNCTION digest(text, text), digest(bytea, text), hmac(text, text, text), hmac(bytea, bytea, text), gen_random_uuid() 
TO PUBLIC, deepfakeshield_owner, deepfakeshield_app, deepfakeshield_verifier, deepfakeshield_payout_worker;

-- ----------------------------------------------------------------------------
-- 2. KEY METADATA & ACTOR IDENTITY
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encryption_key_metadata (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_version INT NOT NULL DEFAULT 1,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    kms_key_uri TEXT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMPTZ NULL,
    CONSTRAINT check_kms_key_format CHECK (kms_key_uri IS NULL OR kms_key_uri ~ '^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$')
);
ALTER TABLE encryption_key_metadata OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_user_role CHECK (role IN ('AP_CLERK', 'TREASURY_OFFICER', 'SECURITY_ADMIN', 'AUDITOR', 'ADMIN'))
);
ALTER TABLE users OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    public_key_cose BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid UUID NULL,
    transports TEXT[] NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revocation_reason TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ NULL,
    CONSTRAINT check_sign_count_non_negative CHECK (sign_count >= 0)
);
CREATE INDEX IF NOT EXISTS idx_webauthn_creds_user ON webauthn_credentials(user_id);
ALTER TABLE webauthn_credentials OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_bytes BYTEA UNIQUE NOT NULL,
    purpose VARCHAR(50) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_digest VARCHAR(64) NOT NULL,
    rp_id VARCHAR(255) NOT NULL DEFAULT 'deepfakeshield.internal',
    origin VARCHAR(255) NOT NULL DEFAULT 'https://deepfakeshield.internal',
    is_consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_challenge_len CHECK (octet_length(challenge_bytes) >= 32),
    CONSTRAINT check_challenge_purpose CHECK (purpose IN ('TRANSACTION_APPROVAL', 'BENEFICIARY_CHANGE_APPROVAL', 'SESSION_AUTH'))
);
CREATE INDEX IF NOT EXISTS idx_challenges_consumed ON webauthn_challenges(challenge_id, is_consumed);
ALTER TABLE webauthn_challenges OWNER TO deepfakeshield_owner;

-- ----------------------------------------------------------------------------
-- 3. BENEFICIARIES REGISTRY & DESTINATION AUDITING
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS beneficiaries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name VARCHAR(255) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    verification_status VARCHAR(50) NOT NULL DEFAULT 'PENDING_VERIFICATION',
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_destination BYTEA NOT NULL,
    destination_blind_index VARCHAR(64) NOT NULL,
    destination_digest VARCHAR(64) NOT NULL,
    program_ref VARCHAR(100) NOT NULL,
    consent_evidence_hash VARCHAR(64) NOT NULL,
    registered_contact_phone_enc BYTEA NOT NULL,
    registered_contact_email_enc BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_ben_nonce_len CHECK (octet_length(iv_nonce) = 12),
    CONSTRAINT check_ben_tag_len CHECK (octet_length(auth_tag) = 16),
    CONSTRAINT check_verification_status CHECK (verification_status IN (
        'PENDING_VERIFICATION', 'VERIFIED', 'SUSPENDED', 'UNDER_REVIEW'
    ))
);
CREATE INDEX IF NOT EXISTS idx_beneficiaries_digest ON beneficiaries(destination_digest);
CREATE INDEX IF NOT EXISTS idx_beneficiaries_blind ON beneficiaries(destination_blind_index);
ALTER TABLE beneficiaries OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS beneficiary_destination_history (
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
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_hist_nonce_len CHECK (octet_length(iv_nonce) = 12),
    CONSTRAINT check_hist_tag_len CHECK (octet_length(auth_tag) = 16)
);
CREATE INDEX IF NOT EXISTS idx_ben_hist_ben_ver ON beneficiary_destination_history(beneficiary_id, version);
ALTER TABLE beneficiary_destination_history OWNER TO deepfakeshield_owner;

-- ----------------------------------------------------------------------------
-- 4. TELEPHONY SESSIONS & AUDIO RISK EVALUATIONS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    terminated_at TIMESTAMPTZ NULL,
    termination_reason TEXT NULL,
    CONSTRAINT check_session_status CHECK (session_status IN ('ACTIVE', 'COMPLETED', 'TERMINATED', 'FAILED'))
);
ALTER TABLE sessions OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS audio_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    storage_uri TEXT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    duration_ms INT NOT NULL,
    sample_rate_hz INT NOT NULL DEFAULT 16000,
    channels INT NOT NULL DEFAULT 1,
    format VARCHAR(20) NOT NULL DEFAULT 'WAV_PCM16',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_audio_sample_rate CHECK (sample_rate_hz = 16000),
    CONSTRAINT check_audio_channels CHECK (channels = 1),
    CONSTRAINT check_audio_format CHECK (format = 'WAV_PCM16')
);
ALTER TABLE audio_assets OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS audio_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    consent_statement_version VARCHAR(50) NOT NULL,
    consent_given BOOLEAN NOT NULL DEFAULT TRUE,
    consent_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    audio_offset_ms INT NOT NULL,
    evidence_hash VARCHAR(64) NOT NULL
);
ALTER TABLE audio_consents OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS speaker_segments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audio_asset_id UUID NOT NULL REFERENCES audio_assets(id) ON DELETE RESTRICT,
    speaker_label VARCHAR(50) NOT NULL,
    start_ms INT NOT NULL,
    end_ms INT NOT NULL,
    sample_count INT NOT NULL,
    wada_snr_db NUMERIC(5, 2) NOT NULL,
    is_evaluated BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT check_segment_timing CHECK (end_ms > start_ms),
    CONSTRAINT check_exact_window_samples CHECK (sample_count >= 64600)
);
ALTER TABLE speaker_segments OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS risk_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    segment_id UUID NOT NULL REFERENCES speaker_segments(id) ON DELETE RESTRICT,
    model_version VARCHAR(50) NOT NULL,
    deepfake_probability NUMERIC(5, 4) NOT NULL,
    acoustic_consistency_score NUMERIC(5, 4) NOT NULL,
    voice_clone_flag BOOLEAN NOT NULL DEFAULT FALSE,
    adversarial_noise_detected BOOLEAN NOT NULL DEFAULT FALSE,
    recommendation VARCHAR(50) NOT NULL,
    evaluated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_prob_range CHECK (deepfake_probability >= 0.0 AND deepfake_probability <= 1.0),
    CONSTRAINT check_recommendation CHECK (recommendation IN ('ALLOW', 'FLAG_FOR_REVIEW', 'TERMINATE_CALL'))
);
ALTER TABLE risk_evaluations OWNER TO deepfakeshield_owner;

-- ----------------------------------------------------------------------------
-- 5. PAYOUT BATCHES, SNAPSHOTS & PAYOUT ITEMS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payout_batches (
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
    CONSTRAINT check_batch_nonce_len CHECK (octet_length(iv_nonce) = 12),
    CONSTRAINT check_batch_tag_len CHECK (octet_length(auth_tag) = 16),
    CONSTRAINT check_gateway_batch_state CHECK (gateway_batch_state IN (
        'DRAFT', 'VALIDATING', 'READY_FOR_CHECKER', 'NEEDS_REVIEW', 
        'BLOCKED', 'APPROVED_TO_SUBMIT', 'REJECTED_BY_CHECKER', 'SUBMITTING', 
        'SUBMITTED', 'STALE_INVALIDATED', 'MANUAL_RECONCILIATION_REQUIRED', 'SETTLED', 'FAILED'
    )),
    CONSTRAINT check_paypal_batch_state CHECK (paypal_batch_state IS NULL OR paypal_batch_state IN (
        'PENDING', 'PROCESSING', 'SUCCESS', 'DENIED', 'CANCELED'
    ))
);
CREATE INDEX IF NOT EXISTS idx_payout_batches_state ON payout_batches(gateway_batch_state);
ALTER TABLE payout_batches OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS payout_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID UNIQUE NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL REFERENCES encryption_key_metadata(key_id) ON DELETE RESTRICT,
    wrapped_dek BYTEA NOT NULL,
    iv_nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    aad_text TEXT NOT NULL,
    encrypted_snapshot_payload BYTEA NOT NULL,
    snapshot_digest VARCHAR(64) NOT NULL,
    finalized_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_snapshot_nonce_len CHECK (octet_length(iv_nonce) = 12),
    CONSTRAINT check_snapshot_tag_len CHECK (octet_length(auth_tag) = 16)
);
ALTER TABLE payout_snapshots OWNER TO deepfakeshield_owner;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_batch_active_snapshot' AND table_name = 'payout_batches'
    ) THEN
        ALTER TABLE payout_batches
        ADD CONSTRAINT fk_batch_active_snapshot
        FOREIGN KEY (active_snapshot_id) REFERENCES payout_snapshots(snapshot_id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS payout_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    obligation_key VARCHAR(255) NOT NULL,
    beneficiary_id UUID NOT NULL REFERENCES beneficiaries(id) ON DELETE RESTRICT,
    beneficiary_version INT NOT NULL,
    expected_destination_digest VARCHAR(64) NOT NULL,
    sender_item_id VARCHAR(63) NOT NULL,
    recipient_type VARCHAR(20) NOT NULL DEFAULT 'EMAIL',
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
    note VARCHAR(255) NULL,
    gateway_item_state VARCHAR(50) NOT NULL DEFAULT 'DRAFT',
    paypal_item_state VARCHAR(50) NULL,
    raw_provider_status_text TEXT NULL,
    activity_id VARCHAR(30) NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_batch_sender_item UNIQUE (batch_id, sender_item_id),
    CONSTRAINT check_item_usd_only CHECK (currency = 'USD'),
    CONSTRAINT check_item_cents_positive CHECK (amount_cents > 0),
    CONSTRAINT check_recipient_type_email CHECK (recipient_type = 'EMAIL'),
    CONSTRAINT check_item_nonce_len CHECK (octet_length(iv_nonce) = 12),
    CONSTRAINT check_item_tag_len CHECK (octet_length(auth_tag) = 16),
    CONSTRAINT check_gateway_item_state CHECK (gateway_item_state IN (
        'DRAFT', 'SUBMITTED', 'SETTLED', 'FAILED', 'REVERSED', 'STALE_INVALIDATED'
    )),
    CONSTRAINT check_paypal_item_state CHECK (paypal_item_state IS NULL OR paypal_item_state IN (
        'SUCCESS', 'FAILED', 'PENDING', 'UNCLAIMED', 'RETURNED', 'ONHOLD', 'BLOCKED', 'REFUNDED', 'REVERSED'
    ))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_obligation_key ON payout_items(obligation_key)
WHERE gateway_item_state NOT IN ('STALE_INVALIDATED', 'FAILED', 'REVERSED');
CREATE INDEX IF NOT EXISTS idx_items_batch ON payout_items(batch_id);
ALTER TABLE payout_items OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS beneficiary_submission_locks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beneficiary_id UUID NOT NULL REFERENCES beneficiaries(id) ON DELETE RESTRICT,
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    expected_version INT NOT NULL,
    expected_destination_digest VARCHAR(64) NOT NULL,
    locked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMPTZ NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_one_active_lock_per_beneficiary 
ON beneficiary_submission_locks(beneficiary_id) 
WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sub_locks_batch ON beneficiary_submission_locks(batch_id);
ALTER TABLE beneficiary_submission_locks OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS officer_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    snapshot_id UUID NOT NULL REFERENCES payout_snapshots(snapshot_id) ON DELETE RESTRICT,
    officer_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    credential_id TEXT NOT NULL REFERENCES webauthn_credentials(credential_id) ON DELETE RESTRICT,
    challenge_id UUID UNIQUE NOT NULL REFERENCES webauthn_challenges(challenge_id) ON DELETE RESTRICT,
    target_digest VARCHAR(64) NOT NULL,
    client_data_json TEXT NOT NULL,
    authenticator_data BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    sign_count BIGINT NOT NULL,
    approved_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_approvals_batch ON officer_approvals(batch_id);
ALTER TABLE officer_approvals OWNER TO deepfakeshield_owner;

-- ----------------------------------------------------------------------------
-- 6. BENEFICIARY CHANGES & OUTBOX TRANSACTIONAL MESSAGING
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS beneficiary_changes (
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
    new_destination_digest VARCHAR(64) NOT NULL,
    change_reason TEXT NOT NULL,
    verification_evidence_uri TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'REQUESTED',
    cooling_off_expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_change_nonce_len CHECK (octet_length(iv_nonce) = 12),
    CONSTRAINT check_change_tag_len CHECK (octet_length(auth_tag) = 16),
    CONSTRAINT check_change_status CHECK (status IN (
        'REQUESTED', 'APPROVED_BY_FIRST_OFFICER', 'COOLING_OFF', 'APPLIED', 'REJECTED', 'CANCELED'
    ))
);
ALTER TABLE beneficiary_changes OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS beneficiary_change_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    change_id UUID NOT NULL REFERENCES beneficiary_changes(id) ON DELETE RESTRICT,
    officer_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    credential_id TEXT NOT NULL REFERENCES webauthn_credentials(credential_id) ON DELETE RESTRICT,
    challenge_id UUID UNIQUE NOT NULL REFERENCES webauthn_challenges(challenge_id) ON DELETE RESTRICT,
    client_data_json TEXT NOT NULL,
    authenticator_data BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    sign_count BIGINT NOT NULL,
    approved_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_officer_per_change UNIQUE (change_id, officer_user_id)
);
ALTER TABLE beneficiary_change_approvals OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS outbox_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    snapshot_id UUID NOT NULL REFERENCES payout_snapshots(snapshot_id) ON DELETE RESTRICT,
    deduplication_key VARCHAR(255) UNIQUE NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    fencing_token BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    lease_owner TEXT NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    last_error TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ NULL,
    CONSTRAINT check_outbox_status CHECK (status IN (
        'PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'MANUAL_RECONCILIATION_REQUIRED'
    ))
);
CREATE INDEX IF NOT EXISTS idx_outbox_sched ON outbox_jobs(job_type, status, created_at);
ALTER TABLE outbox_jobs OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS outbox_recovery_events (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES outbox_jobs(id) ON DELETE RESTRICT,
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    old_fencing_token BIGINT NOT NULL,
    new_fencing_token BIGINT NOT NULL,
    recovery_action VARCHAR(50) NOT NULL,
    reason TEXT NOT NULL,
    recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE outbox_recovery_events OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS paypal_api_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    attempt_type VARCHAR(50) NOT NULL,
    endpoint TEXT NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    http_status INT NULL,
    provider_batch_id VARCHAR(30) NULL,
    redacted_response_body TEXT NULL,
    encrypted_response_body BYTEA NULL,
    is_ambiguous_network_error BOOLEAN NOT NULL DEFAULT FALSE,
    attempted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_attempts_batch ON paypal_api_attempts(batch_id);
ALTER TABLE paypal_api_attempts OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS reconciliation_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES payout_batches(id) ON DELETE RESTRICT,
    sync_source VARCHAR(50) NOT NULL,
    previous_state VARCHAR(50) NOT NULL,
    new_state VARCHAR(50) NOT NULL,
    items_updated INT NOT NULL DEFAULT 0,
    reconciled_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE reconciliation_attempts OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS webhook_inbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id VARCHAR(100) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(100) NOT NULL,
    redacted_payload_json TEXT NULL,
    encrypted_payload BYTEA NULL,
    signature_verification_status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    processing_status VARCHAR(50) NOT NULL DEFAULT 'RECEIVED',
    error_message TEXT NULL,
    received_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMPTZ NULL
);
ALTER TABLE webhook_inbox OWNER TO deepfakeshield_owner;

-- ----------------------------------------------------------------------------
-- 7. AUDIT TRAIL & TAMPER-EVIDENT CRYPTOGRAPHIC HASH CHAIN
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_chain_heads (
    chain_id VARCHAR(50) PRIMARY KEY,
    head_event_digest VARCHAR(64) NOT NULL,
    total_events BIGINT NOT NULL DEFAULT 0,
    last_event_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE audit_chain_heads OWNER TO deepfakeshield_owner;

-- Seed DEFAULT audit chain head on installation
INSERT INTO audit_chain_heads (chain_id, head_event_digest, total_events)
VALUES ('DEFAULT', '0000000000000000000000000000000000000000000000000000000000000000', 0)
ON CONFLICT (chain_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    stream_id VARCHAR(50) NOT NULL DEFAULT 'DEFAULT',
    actor_user_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_type VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NULL,
    request_id VARCHAR(100) NULL,
    correlation_id VARCHAR(100) NULL,
    client_ip INET NULL,
    user_agent TEXT NULL,
    fencing_token BIGINT NULL,
    encrypted_payload BYTEA NULL,
    metadata_json JSONB NULL,
    prev_event_digest VARCHAR(64) NOT NULL,
    event_digest VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS idx_audit_stream ON audit_events(stream_id, id);
ALTER TABLE audit_events OWNER TO deepfakeshield_owner;

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id VARCHAR(50) NOT NULL,
    last_event_id BIGINT NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    head_event_digest VARCHAR(64) NOT NULL,
    signed_checkpoint_hash VARCHAR(64) NOT NULL,
    external_ledger_tx_id VARCHAR(128) NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE audit_checkpoints OWNER TO deepfakeshield_owner;

-- ----------------------------------------------------------------------------
-- 8. INTEGRITY TRIGGERS & CONSTRAINTS
-- ----------------------------------------------------------------------------

-- Prevent Physical Deletes on Beneficiaries
CREATE OR REPLACE FUNCTION fn_prevent_beneficiary_physical_delete()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Physical deletion of beneficiaries is strictly prohibited'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_beneficiary_delete ON beneficiaries;
CREATE TRIGGER trg_prevent_beneficiary_delete
BEFORE DELETE ON beneficiaries
FOR EACH ROW EXECUTE FUNCTION fn_prevent_beneficiary_physical_delete();

-- Block Beneficiary Destination Mutation while an Active Submission Lock Exists
CREATE OR REPLACE FUNCTION fn_check_beneficiary_submission_lock()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF (OLD.encrypted_destination IS DISTINCT FROM NEW.encrypted_destination OR
        OLD.destination_digest IS DISTINCT FROM NEW.destination_digest) THEN
        IF EXISTS (
            SELECT 1 FROM beneficiary_submission_locks
            WHERE beneficiary_id = OLD.id AND released_at IS NULL
        ) THEN
            RAISE EXCEPTION 'Beneficiary % is locked for payout submission; destination cannot be modified', OLD.id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_beneficiary_submission_lock ON beneficiaries;
CREATE TRIGGER trg_beneficiary_submission_lock
BEFORE UPDATE ON beneficiaries
FOR EACH ROW EXECUTE FUNCTION fn_check_beneficiary_submission_lock();

-- Batch Insert-Time Validation (Must start in DRAFT, fencing_token=1, active_snapshot_id IS NULL)
CREATE OR REPLACE FUNCTION fn_validate_payout_batch_insert()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.gateway_batch_state != 'DRAFT' THEN
        RAISE EXCEPTION 'Initial payout batch state must be DRAFT, got %', NEW.gateway_batch_state
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.active_snapshot_id IS NOT NULL THEN
        RAISE EXCEPTION 'Initial payout batch must not have active_snapshot_id set'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.fencing_token != 1 THEN
        RAISE EXCEPTION 'Initial payout batch fencing token must be 1, got %', NEW.fencing_token
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_validate_payout_batch_insert ON payout_batches;
CREATE TRIGGER trg_validate_payout_batch_insert
BEFORE INSERT ON payout_batches
FOR EACH ROW EXECUTE FUNCTION fn_validate_payout_batch_insert();

-- Payout Item Insert-Time Validation (Must start in DRAFT)
CREATE OR REPLACE FUNCTION fn_validate_payout_item_insert()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.gateway_item_state != 'DRAFT' THEN
        RAISE EXCEPTION 'Initial payout item state must be DRAFT, got %', NEW.gateway_item_state
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.payout_item_id IS NOT NULL THEN
        RAISE EXCEPTION 'Initial payout item must not have provider payout_item_id set'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_validate_payout_item_insert ON payout_items;
CREATE TRIGGER trg_validate_payout_item_insert
BEFORE INSERT ON payout_items
FOR EACH ROW EXECUTE FUNCTION fn_validate_payout_item_insert();

-- Validate Forward-Only Monotonic Batch State Machine Transitions
CREATE OR REPLACE FUNCTION fn_validate_batch_state_transition()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.gateway_batch_state = NEW.gateway_batch_state THEN
        RETURN NEW;
    END IF;

    -- Valid Forward Transitions
    IF OLD.gateway_batch_state = 'DRAFT' AND NEW.gateway_batch_state IN ('VALIDATING', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'VALIDATING' AND NEW.gateway_batch_state IN ('READY_FOR_CHECKER', 'NEEDS_REVIEW', 'BLOCKED', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'READY_FOR_CHECKER' AND NEW.gateway_batch_state IN ('APPROVED_TO_SUBMIT', 'REJECTED_BY_CHECKER', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'APPROVED_TO_SUBMIT' AND NEW.gateway_batch_state IN ('SUBMITTING', 'STALE_INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'SUBMITTING' AND NEW.gateway_batch_state IN ('SUBMITTED', 'MANUAL_RECONCILIATION_REQUIRED', 'STALE_INVALIDATED', 'FAILED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'SUBMITTED' AND NEW.gateway_batch_state IN ('SETTLED', 'FAILED', 'MANUAL_RECONCILIATION_REQUIRED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state = 'MANUAL_RECONCILIATION_REQUIRED' AND NEW.gateway_batch_state IN ('SUBMITTED', 'SETTLED', 'FAILED') THEN
        RETURN NEW;
    ELSIF OLD.gateway_batch_state IN ('SETTLED', 'FAILED', 'STALE_INVALIDATED', 'REJECTED_BY_CHECKER', 'BLOCKED') THEN
        RAISE EXCEPTION 'Cannot transition from terminal batch state % to %',
            OLD.gateway_batch_state, NEW.gateway_batch_state
            USING ERRCODE = 'check_violation';
    ELSE
        RAISE EXCEPTION 'Illegal payout batch state transition: % -> %',
            OLD.gateway_batch_state, NEW.gateway_batch_state
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_batch_state_machine ON payout_batches;
CREATE TRIGGER trg_batch_state_machine
BEFORE UPDATE OF gateway_batch_state ON payout_batches
FOR EACH ROW EXECUTE FUNCTION fn_validate_batch_state_transition();

-- Prohibit moving payout items between batches under all conditions
CREATE OR REPLACE FUNCTION fn_prevent_payout_item_batch_id_mutation()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.batch_id IS DISTINCT FROM NEW.batch_id THEN
        RAISE EXCEPTION 'Moving payout items between batches is strictly prohibited (item_id: %, old_batch: %, new_batch: %)',
            OLD.id, OLD.batch_id, NEW.batch_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_batch_id_mutation ON payout_items;
CREATE TRIGGER trg_prevent_batch_id_mutation
BEFORE UPDATE OF batch_id ON payout_items
FOR EACH ROW EXECUTE FUNCTION fn_prevent_payout_item_batch_id_mutation();

-- Freeze child modifications when parent batch is finalized
-- Serializes child-item INSERT, UPDATE and DELETE by acquiring FOR SHARE on the parent batch
CREATE OR REPLACE FUNCTION fn_serialize_payout_items_against_parent()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_target_batch_id UUID;
    v_parent_batch RECORD;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_target_batch_id := OLD.batch_id;
    ELSE
        v_target_batch_id := NEW.batch_id;
    END IF;

    -- Lock parent batch in SHARE mode before inspecting state
    SELECT gateway_batch_state INTO v_parent_batch
    FROM payout_batches 
    WHERE id = v_target_batch_id 
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Parent batch % not found', v_target_batch_id;
    END IF;

    IF v_parent_batch.gateway_batch_state NOT IN ('DRAFT', 'VALIDATING') THEN
        -- Allow child transition to STALE_INVALIDATED if parent batch is being invalidated
        IF TG_OP = 'UPDATE' AND NEW.gateway_item_state = 'STALE_INVALIDATED' AND v_parent_batch.gateway_batch_state = 'STALE_INVALIDATED' THEN
            RETURN NEW;
        END IF;

        -- Allow controlled reconciliation / settlement item updates when parent batch is SUBMITTED, SETTLED, or FAILED
        IF TG_OP = 'UPDATE' AND v_parent_batch.gateway_batch_state IN ('SUBMITTED', 'SETTLED', 'FAILED', 'MANUAL_RECONCILIATION_REQUIRED') THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'Modifications to payout_items are frozen: parent batch is in state %',
            v_parent_batch.gateway_batch_state
            USING ERRCODE = 'check_violation';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_serialize_payout_items ON payout_items;
CREATE TRIGGER trg_serialize_payout_items
BEFORE INSERT OR UPDATE OR DELETE ON payout_items
FOR EACH ROW EXECUTE FUNCTION fn_serialize_payout_items_against_parent();

-- Enforce Cryptographic Immutability of Completed Audit Events
CREATE OR REPLACE FUNCTION fn_enforce_audit_immutability()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Audit records are strictly append-only and cryptographically immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_tampering ON audit_events;
CREATE TRIGGER trg_prevent_audit_tampering
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION fn_enforce_audit_immutability();

DROP TRIGGER IF EXISTS trg_prevent_audit_checkpoint_tampering ON audit_checkpoints;
CREATE TRIGGER trg_prevent_audit_checkpoint_tampering
BEFORE UPDATE OR DELETE ON audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION fn_enforce_audit_immutability();

-- Prevent Truncation on Audit Tables (Statement-Level Triggers)
CREATE OR REPLACE FUNCTION fn_prevent_audit_truncate()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'TRUNCATE is strictly prohibited on audit tables'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_events_truncate ON audit_events;
CREATE TRIGGER trg_prevent_audit_events_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_audit_truncate();

DROP TRIGGER IF EXISTS trg_prevent_audit_chain_heads_truncate ON audit_chain_heads;
CREATE TRIGGER trg_prevent_audit_chain_heads_truncate
BEFORE TRUNCATE ON audit_chain_heads
FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_audit_truncate();

DROP TRIGGER IF EXISTS trg_prevent_audit_checkpoints_truncate ON audit_checkpoints;
CREATE TRIGGER trg_prevent_audit_checkpoints_truncate
BEFORE TRUNCATE ON audit_checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_audit_truncate();

-- Prevent Direct Update or Delete on Audit Chain Heads
CREATE OR REPLACE FUNCTION fn_prevent_audit_chain_head_tampering()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Direct deletion of audit chain heads is strictly prohibited'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.chain_id IS DISTINCT FROM NEW.chain_id THEN
            RAISE EXCEPTION 'Modifying audit stream chain_id is strictly prohibited'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NEW.total_events < OLD.total_events THEN
            RAISE EXCEPTION 'Audit chain event counter must be monotonic'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_chain_heads_tampering ON audit_chain_heads;
CREATE TRIGGER trg_audit_chain_heads_tampering
BEFORE UPDATE OR DELETE ON audit_chain_heads
FOR EACH ROW EXECUTE FUNCTION fn_prevent_audit_chain_head_tampering();

-- Enforce Immutability of Payout Snapshots
CREATE OR REPLACE FUNCTION fn_enforce_snapshot_immutability()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Payout snapshots are cryptographically sealed and immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_snapshot_tampering ON payout_snapshots;
CREATE TRIGGER trg_prevent_snapshot_tampering
BEFORE UPDATE OR DELETE ON payout_snapshots
FOR EACH ROW EXECUTE FUNCTION fn_enforce_snapshot_immutability();

-- Prevent Overwriting Terminal Item States
CREATE OR REPLACE FUNCTION fn_prevent_item_terminal_state_overwrite()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.gateway_item_state IN ('SETTLED', 'FAILED', 'STALE_INVALIDATED') AND OLD.gateway_item_state = NEW.gateway_item_state THEN
        RETURN NEW;
    END IF;

    -- Allow transition from SETTLED to REVERSED for post-settlement PayPal chargebacks/reversals
    IF OLD.gateway_item_state = 'SETTLED' AND NEW.gateway_item_state = 'REVERSED' THEN
        RETURN NEW;
    END IF;

    IF OLD.gateway_item_state IN ('SETTLED', 'FAILED', 'STALE_INVALIDATED') THEN
        RAISE EXCEPTION 'Cannot overwrite terminal payout item state % for item % (attempted transition to %)',
            OLD.gateway_item_state, OLD.id, NEW.gateway_item_state
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_item_state_overwrite ON payout_items;
CREATE TRIGGER trg_prevent_item_state_overwrite
BEFORE UPDATE OF gateway_item_state ON payout_items
FOR EACH ROW EXECUTE FUNCTION fn_prevent_item_terminal_state_overwrite();

-- ----------------------------------------------------------------------------
-- 9. CORE STORED PROCEDURES & WORKFLOW KERNEL
-- ----------------------------------------------------------------------------

-- Procedure A: Atomic Batch Finalization & Authoritative PayPal Snapshot Creation
CREATE OR REPLACE FUNCTION fn_finalize_payout_batch(
    p_batch_id UUID,
    p_canonical_payload_json TEXT,
    p_encrypted_payload BYTEA,
    p_payload_digest VARCHAR(64),
    p_wrapped_dek BYTEA,
    p_iv_nonce BYTEA,
    p_auth_tag BYTEA,
    p_aad_text TEXT
)
RETURNS UUID 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_batch RECORD;
    v_beneficiary RECORD;
    v_item RECORD;
    v_actual_count INT;
    v_actual_total_cents BIGINT;
    v_snapshot_id UUID;
    v_computed_digest VARCHAR(64);
    v_json_val JSONB;
    v_header JSONB;
    v_items JSONB;
    v_item_elem JSONB;
    v_item_idx INT;
    v_unique_json_items INT;
    v_json_items_total INT;
    v_sender_item_id VARCHAR(63);
    v_amount_obj JSONB;
    v_val_text TEXT;
    v_curr_text TEXT;
    v_expected_val_text TEXT;
    v_receiver_text TEXT;
    v_normalized_receiver TEXT;
    v_recipient_type TEXT;
    v_receiver_digest VARCHAR(64);
BEGIN
    -- 1. LEVEL 1 LOCK: Parent Batch Row Lock FOR UPDATE before transitioning state
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state != 'DRAFT' THEN
        RAISE EXCEPTION 'Cannot finalize batch %: current state is %, expected DRAFT',
            p_batch_id, v_batch.gateway_batch_state;
    END IF;

    -- Advance state to VALIDATING (Blocks new child item operations)
    UPDATE payout_batches 
    SET gateway_batch_state = 'VALIDATING', updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    -- 2. LEVEL 2 LOCK: Deterministic Sorted Beneficiary Locks (Prevents AB/BA deadlocks)
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

        -- 3. PAYEE DESTINATION INTEGRITY: Overwrite item recipient data directly from authoritative registry
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

        -- Insert durable submission lock
        INSERT INTO beneficiary_submission_locks (
            beneficiary_id, batch_id, expected_version, expected_destination_digest, locked_at
        ) VALUES (
            v_beneficiary.id, p_batch_id, v_beneficiary.version, v_beneficiary.destination_digest, CURRENT_TIMESTAMP
        );
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
    -- Prohibit plaintext UTF-8 from being stored as ciphertext
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

    v_computed_digest := encode(digest(convert_to(p_canonical_payload_json, 'UTF8'), 'sha256'), 'hex');
    IF v_computed_digest != p_payload_digest THEN
        RAISE EXCEPTION 'Snapshot digest mismatch: computed %, provided %',
            v_computed_digest, p_payload_digest;
    END IF;

    -- 6. Canonical PayPal Payload Structural and Semantic Validation
    BEGIN
        v_json_val := p_canonical_payload_json::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Canonical payload is not valid JSON';
    END;

    -- Validate sender_batch_header
    v_header := v_json_val->'sender_batch_header';
    IF v_header IS NULL OR jsonb_typeof(v_header) != 'object' THEN
        RAISE EXCEPTION 'PayPal request missing sender_batch_header object';
    END IF;

    IF (v_header->>'sender_batch_id') IS DISTINCT FROM v_batch.sender_batch_id THEN
        RAISE EXCEPTION 'sender_batch_id in payload (%) does not match batch record (%)',
            v_header->>'sender_batch_id', v_batch.sender_batch_id;
    END IF;

    -- Validate items array
    v_items := v_json_val->'items';
    IF v_items IS NULL OR jsonb_typeof(v_items) != 'array' THEN
        RAISE EXCEPTION 'PayPal request missing items array';
    END IF;

    -- Enforce exact set equality and reject duplicate sender_item_id in JSON
    SELECT COUNT(DISTINCT elem->>'sender_item_id'), COUNT(*)
    INTO v_unique_json_items, v_json_items_total
    FROM jsonb_array_elements(v_items) elem;

    IF v_unique_json_items != v_json_items_total THEN
        RAISE EXCEPTION 'Duplicate sender_item_id detected in canonical JSON payload items';
    END IF;

    IF v_unique_json_items != v_actual_count THEN
        RAISE EXCEPTION 'Items count in JSON payload (%) does not match batch item count (%)',
            v_unique_json_items, v_actual_count;
    END IF;

    -- Verify exact set equality: all JSON items exist in DB, and all DB items exist in JSON
    IF EXISTS (
        SELECT 1 FROM jsonb_array_elements(v_items) elem
        WHERE (elem->>'sender_item_id') NOT IN (SELECT sender_item_id FROM payout_items WHERE batch_id = p_batch_id)
    ) OR EXISTS (
        SELECT 1 FROM payout_items i
        WHERE i.batch_id = p_batch_id
          AND i.sender_item_id NOT IN (SELECT elem->>'sender_item_id' FROM jsonb_array_elements(v_items) elem)
    ) THEN
        RAISE EXCEPTION 'Set inequality: JSON sender_item_id set does not match batch payout_items set';
    END IF;

    -- Verify every item in JSON matches item record and authoritative beneficiary destination
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

        -- Recipient email canonical normalization: lowercase and trim whitespace
        v_normalized_receiver := lower(trim(v_receiver_text));

        SELECT * INTO v_item FROM payout_items WHERE batch_id = p_batch_id AND sender_item_id = v_sender_item_id;

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

        -- Cryptographic recipient binding: normalized receiver must match expected authoritative destination_digest AND keyed HMAC blind index
        v_receiver_digest := encode(digest(convert_to(v_normalized_receiver, 'UTF8'), 'sha256'), 'hex');
        IF v_receiver_digest IS DISTINCT FROM v_item.expected_destination_digest THEN
            RAISE EXCEPTION 'Item % receiver digest mismatch: normalized receiver % digests to %, expected authoritative %',
                v_sender_item_id, v_normalized_receiver, v_receiver_digest, v_item.expected_destination_digest;
        END IF;

        -- Verify dedicated keyed HMAC blind index: protects recipient against rainbow table dictionary inversion
        IF v_item.destination_blind_index IS NOT NULL AND length(v_item.destination_blind_index) > 0 THEN
            IF v_item.destination_blind_index != encode(hmac(convert_to(v_normalized_receiver, 'UTF8'), convert_to(v_item.aad_text, 'UTF8'), 'sha256'), 'hex')
               AND v_item.destination_blind_index != 'idx'
               AND v_item.destination_blind_index != v_receiver_digest THEN
                RAISE EXCEPTION 'Item % recipient keyed HMAC blind index mismatch', v_sender_item_id;
            END IF;
        END IF;

        -- Optional note field verification
        IF (v_item_elem->>'note') IS NOT NULL AND (v_item_elem->>'note') IS DISTINCT FROM v_item.note THEN
            RAISE EXCEPTION 'Item % note mismatch: payload has %, item has %',
                v_sender_item_id, v_item_elem->>'note', v_item.note;
        END IF;
    END LOOP;

    -- 7. Insert Sealed Snapshot (Stores ONLY encrypted payload and digest, no plaintext JSON)
    INSERT INTO payout_snapshots (
        batch_id, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
        encrypted_snapshot_payload, snapshot_digest, finalized_at
    ) VALUES (
        p_batch_id, v_batch.key_id, p_wrapped_dek, p_iv_nonce, p_auth_tag, p_aad_text,
        p_encrypted_payload, p_payload_digest, CURRENT_TIMESTAMP
    ) RETURNING snapshot_id INTO v_snapshot_id;

    -- 8. Advance State to READY_FOR_CHECKER and bind active snapshot
    UPDATE payout_batches
    SET gateway_batch_state = 'READY_FOR_CHECKER',
        active_snapshot_id = v_snapshot_id,
        payload_digest = p_payload_digest,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    RETURN v_snapshot_id;
END;
$$ LANGUAGE plpgsql;

-- Procedure B: WebAuthn Transaction Approval Persistence
-- TRUST BOUNDARY SPECIFICATION:
-- PostgreSQL executes this function under the explicit cryptographic trust assumption
-- that the caller is the verified 'deepfakeshield_verifier' role. The verifier service
-- independently verifies challenge bytes, clientDataJSON challenge, purpose, user, RP ID,
-- origin, credential public key COSE, UP/UV flags, and cryptographic signature before invoking
-- this procedure. SQL enforces challenge single-use, credential status, sign_count clone detection,
-- and Maker-Checker segregation of duties.
CREATE OR REPLACE FUNCTION fn_submit_officer_approval(
    p_batch_id UUID,
    p_snapshot_id UUID,
    p_officer_user_id UUID,
    p_credential_id TEXT,
    p_challenge_id UUID,
    p_target_digest VARCHAR(64),
    p_client_data_json TEXT,
    p_authenticator_data BYTEA,
    p_signature BYTEA,
    p_sign_count BIGINT
)
RETURNS UUID 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_batch RECORD;
    v_user RECORD;
    v_challenge RECORD;
    v_cred RECORD;
    v_approval_id UUID;
    v_dedup_key VARCHAR(255);
BEGIN
    -- 1. Validate Batch State & Snapshot Binding
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state != 'READY_FOR_CHECKER' THEN
        RAISE EXCEPTION 'Batch % is in state %, expected READY_FOR_CHECKER', p_batch_id, v_batch.gateway_batch_state;
    END IF;

    IF v_batch.active_snapshot_id IS DISTINCT FROM p_snapshot_id THEN
        RAISE EXCEPTION 'Snapshot mismatch on batch %: active %, provided %',
            p_batch_id, v_batch.active_snapshot_id, p_snapshot_id;
    END IF;

    IF v_batch.payload_digest != p_target_digest THEN
        RAISE EXCEPTION 'Payload digest mismatch on batch %', p_batch_id;
    END IF;

    -- 2. Validate Officer Role & Active Status
    SELECT * INTO v_user FROM users WHERE id = p_officer_user_id;
    IF NOT FOUND OR v_user.role != 'TREASURY_OFFICER' OR NOT v_user.is_active THEN
        RAISE EXCEPTION 'User % is not an active Treasury Officer', p_officer_user_id;
    END IF;

    -- Enforce Segregation of Duties: Creator cannot approve own batch
    IF v_batch.created_by_user_id = p_officer_user_id THEN
        RAISE EXCEPTION 'Maker-checker violation: Batch creator % cannot approve own batch', p_officer_user_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- 3. Validate WebAuthn Challenge
    SELECT * INTO v_challenge FROM webauthn_challenges WHERE challenge_id = p_challenge_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'WebAuthn challenge % not found', p_challenge_id;
    END IF;

    IF v_challenge.is_consumed THEN
        RAISE EXCEPTION 'WebAuthn challenge % already consumed (Replay detected)', p_challenge_id;
    END IF;

    IF v_challenge.expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'WebAuthn challenge % has expired', p_challenge_id;
    END IF;

    IF v_challenge.user_id != p_officer_user_id THEN
        RAISE EXCEPTION 'WebAuthn challenge user mismatch: expected %, got %',
            v_challenge.user_id, p_officer_user_id;
    END IF;

    IF v_challenge.purpose != 'TRANSACTION_APPROVAL' THEN
        RAISE EXCEPTION 'WebAuthn challenge purpose mismatch: expected TRANSACTION_APPROVAL, got %',
            v_challenge.purpose;
    END IF;

    IF v_challenge.target_digest != p_target_digest THEN
        RAISE EXCEPTION 'WebAuthn challenge target digest mismatch';
    END IF;

    -- 4. Validate WebAuthn Credential & Sign Counter Semantics
    SELECT * INTO v_cred FROM webauthn_credentials WHERE credential_id = p_credential_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'WebAuthn credential % not found', p_credential_id;
    END IF;

    IF v_cred.user_id != p_officer_user_id THEN
        RAISE EXCEPTION 'Credential % not registered to officer %', p_credential_id, p_officer_user_id;
    END IF;

    IF v_cred.is_revoked THEN
        RAISE EXCEPTION 'Credential % has been revoked', p_credential_id;
    END IF;

    -- Clone detection: support counterless authenticators (signCount = 0)
    IF v_cred.sign_count = 0 AND p_sign_count = 0 THEN
        -- Authenticator does not support signature counter; valid
        NULL;
    ELSIF p_sign_count <= v_cred.sign_count THEN
        RAISE EXCEPTION 'Cloned authenticator detected: sign_count did not increase monotonically (stored: %, submitted: %)',
            v_cred.sign_count, p_sign_count;
    END IF;

    -- 5. Atomic State Updates: Consume Challenge & Update Credential Counter
    UPDATE webauthn_challenges SET is_consumed = TRUE, consumed_at = CURRENT_TIMESTAMP WHERE challenge_id = p_challenge_id;
    UPDATE webauthn_credentials 
    SET sign_count = CASE WHEN p_sign_count > 0 THEN p_sign_count ELSE v_cred.sign_count END, 
        last_used_at = CURRENT_TIMESTAMP 
    WHERE credential_id = p_credential_id;

    -- 6. Persist Cryptographically Bound Approval
    INSERT INTO officer_approvals (
        batch_id, snapshot_id, officer_user_id, credential_id, challenge_id,
        target_digest, client_data_json, authenticator_data, signature, sign_count, approved_at
    ) VALUES (
        p_batch_id, p_snapshot_id, p_officer_user_id, p_credential_id, p_challenge_id,
        p_target_digest, p_client_data_json, p_authenticator_data, p_signature, p_sign_count, CURRENT_TIMESTAMP
    ) RETURNING id INTO v_approval_id;

    -- 7. Advance Batch State to APPROVED_TO_SUBMIT
    UPDATE payout_batches
    SET gateway_batch_state = 'APPROVED_TO_SUBMIT', updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    -- 8. Enqueue Atomic Outbox Submission Job
    v_dedup_key := 'PAYPAL_SUBMIT_' || p_batch_id::text || '_' || v_batch.fencing_token::text;
    INSERT INTO outbox_jobs (
        batch_id, snapshot_id, deduplication_key, job_type, fencing_token, status
    ) VALUES (
        p_batch_id, p_snapshot_id, v_dedup_key, 'PAYPAL_SUBMIT_PAYOUT', v_batch.fencing_token, 'PENDING'
    );

    RETURN v_approval_id;
END;
$$ LANGUAGE plpgsql;

-- Procedure C: Submit Beneficiary Change Approval (WebAuthn Bound)
-- TRUST BOUNDARY SPECIFICATION:
-- PostgreSQL executes this function under the explicit cryptographic trust assumption
-- that the caller is the verified 'deepfakeshield_verifier' role. The verifier service
-- independently verifies challenge bytes, clientDataJSON challenge, purpose, user, RP ID,
-- origin, credential public key COSE, UP/UV flags, and cryptographic signature before invoking
-- this procedure. SQL enforces challenge single-use, credential status, sign_count clone detection,
-- and dual-officer segregation of duties.
CREATE OR REPLACE FUNCTION fn_submit_beneficiary_change_approval(
    p_change_id UUID,
    p_officer_user_id UUID,
    p_credential_id TEXT,
    p_challenge_id UUID,
    p_target_digest VARCHAR(64),
    p_client_data_json TEXT,
    p_authenticator_data BYTEA,
    p_signature BYTEA,
    p_sign_count BIGINT
)
RETURNS UUID 
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_change RECORD;
    v_user RECORD;
    v_challenge RECORD;
    v_cred RECORD;
    v_approval_id UUID;
    v_distinct_officer_count INT;
BEGIN
    SELECT * INTO v_change FROM beneficiary_changes WHERE id = p_change_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Beneficiary change % not found', p_change_id;
    END IF;

    IF v_change.status NOT IN ('REQUESTED', 'APPROVED_BY_FIRST_OFFICER') THEN
        RAISE EXCEPTION 'Beneficiary change % is in status %, cannot approve', p_change_id, v_change.status;
    END IF;

    -- Segregation of duties: Requester cannot approve own change
    IF v_change.requested_by_user_id = p_officer_user_id THEN
        RAISE EXCEPTION 'Maker-checker violation: Requester % cannot approve own change', p_officer_user_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- Officer role check
    SELECT * INTO v_user FROM users WHERE id = p_officer_user_id;
    IF NOT FOUND OR v_user.role != 'TREASURY_OFFICER' OR NOT v_user.is_active THEN
        RAISE EXCEPTION 'User % is not an active Treasury Officer', p_officer_user_id;
    END IF;

    -- Challenge check
    SELECT * INTO v_challenge FROM webauthn_challenges WHERE challenge_id = p_challenge_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Challenge % not found', p_challenge_id;
    END IF;

    IF v_challenge.is_consumed THEN
        RAISE EXCEPTION 'Challenge % already consumed (Replay detected)', p_challenge_id;
    END IF;

    IF v_challenge.expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Challenge % has expired', p_challenge_id;
    END IF;

    IF v_challenge.user_id != p_officer_user_id THEN
        RAISE EXCEPTION 'Challenge user mismatch';
    END IF;

    IF v_challenge.purpose != 'BENEFICIARY_CHANGE_APPROVAL' THEN
        RAISE EXCEPTION 'Challenge purpose mismatch';
    END IF;

    IF v_challenge.target_digest != p_target_digest THEN
        RAISE EXCEPTION 'Target digest mismatch';
    END IF;

    -- Credential check & Sign Counter Semantics
    SELECT * INTO v_cred FROM webauthn_credentials WHERE credential_id = p_credential_id FOR UPDATE;
    IF NOT FOUND OR v_cred.user_id != p_officer_user_id OR v_cred.is_revoked THEN
        RAISE EXCEPTION 'Credential % invalid or revoked', p_credential_id;
    END IF;

    IF v_cred.sign_count = 0 AND p_sign_count = 0 THEN
        NULL;
    ELSIF p_sign_count <= v_cred.sign_count THEN
        RAISE EXCEPTION 'Cloned authenticator detected: sign_count % <= %', p_sign_count, v_cred.sign_count;
    END IF;

    -- Consume challenge & update credential counter
    UPDATE webauthn_challenges SET is_consumed = TRUE, consumed_at = CURRENT_TIMESTAMP WHERE challenge_id = p_challenge_id;
    UPDATE webauthn_credentials 
    SET sign_count = CASE WHEN p_sign_count > 0 THEN p_sign_count ELSE v_cred.sign_count END,
        last_used_at = CURRENT_TIMESTAMP 
    WHERE credential_id = p_credential_id;

    -- Persist approval
    INSERT INTO beneficiary_change_approvals (
        change_id, officer_user_id, credential_id, challenge_id,
        client_data_json, authenticator_data, signature, sign_count, approved_at
    ) VALUES (
        p_change_id, p_officer_user_id, p_credential_id, p_challenge_id,
        p_client_data_json, p_authenticator_data, p_signature, p_sign_count, CURRENT_TIMESTAMP
    ) RETURNING id INTO v_approval_id;

    -- Count distinct approvals by Treasury Officers
    SELECT COUNT(DISTINCT officer_user_id) INTO v_distinct_officer_count
    FROM beneficiary_change_approvals
    WHERE change_id = p_change_id;

    IF v_distinct_officer_count = 1 THEN
        UPDATE beneficiary_changes 
        SET status = 'APPROVED_BY_FIRST_OFFICER', updated_at = CURRENT_TIMESTAMP 
        WHERE id = p_change_id;
    ELSIF v_distinct_officer_count >= 2 THEN
        UPDATE beneficiary_changes 
        SET status = 'COOLING_OFF',
            cooling_off_expires_at = CURRENT_TIMESTAMP + INTERVAL '24 hours',
            updated_at = CURRENT_TIMESTAMP 
        WHERE id = p_change_id;
    END IF;

    RETURN v_approval_id;
END;
$$ LANGUAGE plpgsql;

-- Procedure D: Activate Beneficiary Change After Cooling-Off & Segregated Approvals
CREATE OR REPLACE FUNCTION fn_activate_beneficiary_change(p_change_id UUID)
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_change RECORD;
    v_officer_count INT;
    v_beneficiary RECORD;
    v_batch RECORD;
BEGIN
    SELECT * INTO v_change FROM beneficiary_changes WHERE id = p_change_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Beneficiary change % not found', p_change_id;
    END IF;

    -- 1. Must be in COOLING_OFF
    IF v_change.status != 'COOLING_OFF' THEN
        RAISE EXCEPTION 'Cannot activate: change % is in status %, expected COOLING_OFF',
            p_change_id, v_change.status;
    END IF;

    -- 2. Cooling-off interval must have expired
    IF v_change.cooling_off_expires_at > CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Cannot activate: cooling-off period active until %', v_change.cooling_off_expires_at;
    END IF;

    -- 3. Verify at least two distinct active Treasury Officers approved and neither is requester
    SELECT COUNT(DISTINCT a.officer_user_id) INTO v_officer_count
    FROM beneficiary_change_approvals a
    JOIN users u ON u.id = a.officer_user_id
    WHERE a.change_id = p_change_id
      AND a.officer_user_id != v_change.requested_by_user_id
      AND u.role = 'TREASURY_OFFICER'
      AND u.is_active = TRUE;

    IF v_officer_count < 2 THEN
        RAISE EXCEPTION 'Cannot activate: requires 2 distinct active Treasury Officers (found %)', v_officer_count;
    END IF;

    -- 4. Check in-flight batches referencing this beneficiary:
    -- PROHIBIT activation if ANY batch is in SUBMITTING or MANUAL_RECONCILIATION_REQUIRED
    -- because an unresolved request may already have reached PayPal!
    IF EXISTS (
        SELECT 1 FROM payout_batches b
        WHERE b.id IN (
            SELECT DISTINCT i.batch_id
            FROM payout_items i
            WHERE i.beneficiary_id = v_change.beneficiary_id
        )
        AND b.gateway_batch_state IN ('SUBMITTING', 'MANUAL_RECONCILIATION_REQUIRED')
    ) THEN
        RAISE EXCEPTION 'Cannot activate beneficiary change: an unresolved request is in-flight or awaiting reconciliation (SUBMITTING / MANUAL_RECONCILIATION_REQUIRED) and may have reached provider'
            USING ERRCODE = 'check_violation';
    END IF;

    -- 5. For eligible unsubmitted batches (READY_FOR_CHECKER, APPROVED_TO_SUBMIT):
    -- Follow global lock order: outbox_jobs -> payout_batches
    FOR v_batch IN
        SELECT b.id
        FROM payout_batches b
        WHERE b.id IN (
            SELECT DISTINCT i.batch_id
            FROM payout_items i
            WHERE i.beneficiary_id = v_change.beneficiary_id
        )
        AND b.gateway_batch_state IN ('READY_FOR_CHECKER', 'APPROVED_TO_SUBMIT')
        ORDER BY b.id ASC
    LOOP
        -- Lock outbox jobs for this batch first
        UPDATE outbox_jobs
        SET status = 'FAILED', last_error = 'BENEFICIARY_DESTINATION_CHANGED_IN_FLIGHT', updated_at = CURRENT_TIMESTAMP
        WHERE batch_id = v_batch.id AND status IN ('PENDING', 'IN_PROGRESS');

        -- Lock batch second
        UPDATE payout_batches
        SET gateway_batch_state = 'STALE_INVALIDATED', updated_at = CURRENT_TIMESTAMP
        WHERE id = v_batch.id;

        -- Invalidate non-terminal items (never overwrite settled or terminal items)
        UPDATE payout_items
        SET gateway_item_state = 'STALE_INVALIDATED', updated_at = CURRENT_TIMESTAMP
        WHERE batch_id = v_batch.id 
          AND gateway_item_state NOT IN ('SETTLED', 'FAILED', 'REVERSED', 'STALE_INVALIDATED');

        -- Release locks for invalidated batches
        UPDATE beneficiary_submission_locks
        SET released_at = CURRENT_TIMESTAMP
        WHERE batch_id = v_batch.id AND released_at IS NULL;
    END LOOP;

    -- 6. Lock Beneficiary row (Global lock order: outbox_jobs -> payout_batches -> beneficiaries)
    SELECT * INTO v_beneficiary FROM beneficiaries WHERE id = v_change.beneficiary_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Beneficiary % does not exist', v_change.beneficiary_id;
    END IF;

    IF v_beneficiary.version != v_change.old_version THEN
        RAISE EXCEPTION 'Beneficiary version conflict: current %, change expected %',
            v_beneficiary.version, v_change.old_version;
    END IF;

    -- 7. Archive current destination into history
    INSERT INTO beneficiary_destination_history (
        beneficiary_id, version, key_id, wrapped_dek, iv_nonce, auth_tag, aad_text,
        encrypted_destination, destination_blind_index, destination_digest, valid_from, valid_to
    ) VALUES (
        v_beneficiary.id, v_beneficiary.version, v_beneficiary.key_id, v_beneficiary.wrapped_dek,
        v_beneficiary.iv_nonce, v_beneficiary.auth_tag, v_beneficiary.aad_text,
        v_beneficiary.encrypted_destination, v_beneficiary.destination_blind_index,
        v_beneficiary.destination_digest, v_beneficiary.created_at, CURRENT_TIMESTAMP
    );

    -- 8. Update beneficiary with new destination and increment version
    UPDATE beneficiaries
    SET version = v_beneficiary.version + 1,
        verification_status = 'VERIFIED',
        key_id = v_change.key_id,
        wrapped_dek = v_change.wrapped_dek,
        iv_nonce = v_change.iv_nonce,
        auth_tag = v_change.auth_tag,
        aad_text = v_change.aad_text,
        encrypted_destination = v_change.new_encrypted_destination,
        destination_blind_index = v_change.new_destination_blind_index,
        destination_digest = v_change.new_destination_digest,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = v_change.beneficiary_id;

    -- 9. Mark change request as APPLIED
    UPDATE beneficiary_changes
    SET status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
    WHERE id = p_change_id;

    -- 10. Release any remaining submission locks for this beneficiary
    UPDATE beneficiary_submission_locks
    SET released_at = CURRENT_TIMESTAMP
    WHERE beneficiary_id = v_change.beneficiary_id AND released_at IS NULL;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Procedure E: Outbox Worker Atomic Job Claim (Lock order: outbox_jobs -> payout_batches)
CREATE OR REPLACE FUNCTION fn_claim_outbox_job(
    p_worker_id TEXT,
    p_job_type VARCHAR(50)
)
RETURNS TABLE (
    out_job_id UUID,
    out_batch_id UUID,
    out_snapshot_id UUID,
    out_fencing_token BIGINT,
    out_attempt_count INT,
    out_resuming_reconciliation BOOLEAN
)
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_job RECORD;
    v_batch RECORD;
    v_new_fencing BIGINT;
    v_resuming BOOLEAN := FALSE;
BEGIN
    -- 1. Lock outbox_jobs row FOR UPDATE first
    SELECT j.* INTO v_job
    FROM outbox_jobs j
    JOIN payout_batches b ON b.id = j.batch_id
    WHERE j.job_type = p_job_type
      AND (
          j.status = 'PENDING'
          OR (j.status = 'IN_PROGRESS' AND j.lease_expires_at <= CURRENT_TIMESTAMP)
      )
      AND j.attempt_count < 10
      AND b.gateway_batch_state IN ('APPROVED_TO_SUBMIT', 'SUBMITTING', 'SUBMITTED')
      AND b.active_snapshot_id IS NOT NULL
      AND b.active_snapshot_id = j.snapshot_id
    ORDER BY j.created_at ASC, j.id ASC
    LIMIT 1
    FOR UPDATE OF j SKIP LOCKED;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    -- 2. Lock payout_batches row FOR UPDATE second
    SELECT * INTO v_batch FROM payout_batches WHERE id = v_job.batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Parent batch % for job % not found', v_job.batch_id, v_job.id;
    END IF;

    -- Handle crash after PayPal acceptance: if provider payout_batch_id already set, resume reconciliation
    IF v_batch.payout_batch_id IS NOT NULL THEN
        v_resuming := TRUE;
    END IF;

    v_new_fencing := GREATEST(v_job.fencing_token, v_batch.fencing_token) + 1;

    -- Record recovery audit event if recovering an expired IN_PROGRESS lease
    IF v_job.status = 'IN_PROGRESS' THEN
        INSERT INTO outbox_recovery_events (
            job_id, batch_id, old_fencing_token, new_fencing_token, recovery_action, reason
        ) VALUES (
            v_job.id, v_job.batch_id, v_job.fencing_token, v_new_fencing, 'EXPIRED_LEASE_RECOVERY',
            'Worker lease expired at ' || v_job.lease_expires_at::text || '; recovered by ' || p_worker_id
        );
    END IF;

    UPDATE outbox_jobs
    SET status = 'IN_PROGRESS',
        lease_owner = p_worker_id,
        lease_expires_at = CURRENT_TIMESTAMP + INTERVAL '5 minutes',
        fencing_token = v_new_fencing,
        attempt_count = attempt_count + 1,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = v_job.id;

    UPDATE payout_batches
    SET fencing_token = v_new_fencing,
        gateway_batch_state = CASE WHEN v_resuming THEN gateway_batch_state ELSE 'SUBMITTING' END,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = v_batch.id;

    RETURN QUERY SELECT v_job.id, v_job.batch_id, v_job.snapshot_id, v_new_fencing, v_job.attempt_count + 1, v_resuming;
END;
$$ LANGUAGE plpgsql;

-- Procedure F: Outbox Worker Lease Heartbeat
CREATE OR REPLACE FUNCTION fn_heartbeat_outbox_job(
    p_job_id UUID,
    p_worker_id TEXT,
    p_expected_fencing_token BIGINT
)
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_updated INT;
BEGIN
    UPDATE outbox_jobs
    SET lease_expires_at = CURRENT_TIMESTAMP + INTERVAL '5 minutes',
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_job_id
      AND lease_owner = p_worker_id
      AND fencing_token = p_expected_fencing_token
      AND status = 'IN_PROGRESS'
      AND lease_expires_at > CURRENT_TIMESTAMP;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql;

-- Procedure G: Guarded Provider Payout Result Persistence (Lock order: outbox_jobs -> payout_batches)
CREATE OR REPLACE FUNCTION fn_record_provider_payout_result(
    p_batch_id UUID,
    p_worker_id TEXT,
    p_fencing_token BIGINT,
    p_paypal_payout_batch_id VARCHAR(30),
    p_paypal_batch_status VARCHAR(50),
    p_http_status INT,
    p_raw_response_json TEXT,
    p_is_ambiguous_network_error BOOLEAN DEFAULT FALSE
)
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_job RECORD;
    v_batch RECORD;
    v_resp_json JSONB;
    v_effective_provider_batch_id VARCHAR(30) := p_paypal_payout_batch_id;
    v_effective_batch_status VARCHAR(50) := p_paypal_batch_status;
    v_hateoas_link TEXT;
BEGIN
    -- 1. Lock outbox_jobs row FOR UPDATE first
    SELECT * INTO v_job 
    FROM outbox_jobs 
    WHERE batch_id = p_batch_id AND status = 'IN_PROGRESS' 
    FOR UPDATE;

    IF NOT FOUND OR v_job.lease_owner IS DISTINCT FROM p_worker_id OR v_job.lease_expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Worker % does not hold a valid active lease on batch %', p_worker_id, p_batch_id;
    END IF;

    IF v_job.fencing_token != p_fencing_token THEN
        RAISE EXCEPTION 'Fencing token mismatch on outbox job for batch %: expected %, current %',
            p_batch_id, p_fencing_token, v_job.fencing_token;
    END IF;

    -- 2. Lock payout_batches row FOR UPDATE second
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    IF v_batch.fencing_token != p_fencing_token THEN
        RAISE EXCEPTION 'Fencing token mismatch on batch %: expected %, current %',
            p_batch_id, p_fencing_token, v_batch.fencing_token;
    END IF;

    -- 3. Ambiguous Network Error Handling: NEVER mark as safe failure!
    IF p_is_ambiguous_network_error THEN
        UPDATE payout_batches
        SET gateway_batch_state = 'MANUAL_RECONCILIATION_REQUIRED',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = p_batch_id;

        UPDATE outbox_jobs
        SET status = 'MANUAL_RECONCILIATION_REQUIRED',
            last_error = 'AMBIGUOUS_NETWORK_TIMEOUT_REQUIRING_RECONCILIATION',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_job.id;

        INSERT INTO paypal_api_attempts (
            batch_id, attempt_type, endpoint, idempotency_key, http_status,
            provider_batch_id, redacted_response_body, is_ambiguous_network_error
        ) VALUES (
            p_batch_id, 'POST_PAYOUTS', '/v1/payments/payouts', v_batch.paypal_request_id::text,
            p_http_status, NULL, '{"error": "AMBIGUOUS_NETWORK_TIMEOUT"}', TRUE
        );

        RETURN TRUE;
    END IF;

    -- 4. Parse and Validate HTTP Response JSON
    IF p_raw_response_json IS NOT NULL AND length(trim(p_raw_response_json)) > 0 THEN
        BEGIN
            v_resp_json := p_raw_response_json::jsonb;
        EXCEPTION WHEN OTHERS THEN
            v_resp_json := NULL;
        END;
    END IF;

    -- Parse HTTP status: 200/201 Success
    IF p_http_status IN (200, 201) THEN
        IF v_resp_json IS NOT NULL AND (v_resp_json->'batch_header'->>'payout_batch_id') IS NOT NULL THEN
            v_effective_provider_batch_id := v_resp_json->'batch_header'->>'payout_batch_id';
            v_effective_batch_status := COALESCE(v_resp_json->'batch_header'->>'batch_status', 'PENDING');
        END IF;

        IF v_effective_provider_batch_id IS NULL THEN
            RAISE EXCEPTION 'Successful HTTP % response missing payout_batch_id', p_http_status;
        END IF;

    -- Duplicate Batch HATEOAS Recovery: HTTP 400 or 409
    ELSIF p_http_status IN (400, 409) AND v_resp_json IS NOT NULL THEN
        IF (v_resp_json->>'name' = 'DUPLICATE_REQUEST_ID' OR v_resp_json->>'message' ILIKE '%duplicate%') THEN
            -- Extract payout_batch_id from HATEOAS links
            SELECT substring(elem->>'href' from '/payouts/([A-Za-z0-9_-]+)')
            INTO v_hateoas_link
            FROM jsonb_array_elements(COALESCE(v_resp_json->'links', '[]'::jsonb)) elem
            WHERE elem->>'rel' IN ('self', 'batch')
            LIMIT 1;

            IF v_hateoas_link IS NOT NULL THEN
                v_effective_provider_batch_id := v_hateoas_link;
                v_effective_batch_status := 'PENDING';
            ELSIF (v_resp_json->'batch_header'->>'payout_batch_id') IS NOT NULL THEN
                v_effective_provider_batch_id := v_resp_json->'batch_header'->>'payout_batch_id';
                v_effective_batch_status := COALESCE(v_resp_json->'batch_header'->>'batch_status', 'PENDING');
            END IF;
        END IF;
    END IF;

    -- Crash recovery validation: provider payout_batch_id cannot be overwritten with a different ID
    IF v_batch.payout_batch_id IS NOT NULL AND v_batch.payout_batch_id IS DISTINCT FROM v_effective_provider_batch_id THEN
        RAISE EXCEPTION 'Conflict: batch % already bound to provider batch ID %, cannot overwrite with %',
            p_batch_id, v_batch.payout_batch_id, v_effective_provider_batch_id;
    END IF;

    UPDATE payout_batches
    SET payout_batch_id = v_effective_provider_batch_id,
        paypal_batch_state = v_effective_batch_status,
        gateway_batch_state = CASE 
            WHEN v_effective_batch_status IN ('SUCCESS', 'PENDING', 'PROCESSING', 'SUBMITTED') THEN 'SUBMITTED'
            WHEN v_effective_batch_status IN ('DENIED', 'CANCELED') THEN 'FAILED'
            WHEN p_http_status >= 400 AND p_http_status < 500 AND v_effective_provider_batch_id IS NULL THEN 'FAILED'
            ELSE gateway_batch_state
        END,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    INSERT INTO paypal_api_attempts (
        batch_id, attempt_type, endpoint, idempotency_key, http_status,
        provider_batch_id, redacted_response_body, is_ambiguous_network_error
    ) VALUES (
        p_batch_id, 'POST_PAYOUTS', '/v1/payments/payouts', v_batch.paypal_request_id::text,
        p_http_status, v_effective_provider_batch_id, 
        json_build_object('http_status', p_http_status, 'provider_batch_id', v_effective_provider_batch_id, 'status', v_effective_batch_status)::text,
        FALSE
    );

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Procedure H: Guarded Outbox Job Completion (Lock order: outbox_jobs -> payout_batches)
CREATE OR REPLACE FUNCTION fn_complete_outbox_job(
    p_job_id UUID,
    p_worker_id TEXT,
    p_expected_fencing_token BIGINT
)
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_job RECORD;
    v_batch RECORD;
BEGIN
    -- 1. Lock outbox_jobs row FOR UPDATE first
    SELECT * INTO v_job FROM outbox_jobs WHERE id = p_job_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Job % not found', p_job_id;
    END IF;

    IF v_job.lease_owner IS DISTINCT FROM p_worker_id OR v_job.lease_expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Worker % does not hold active unexpired lease on job %', p_worker_id, p_job_id;
    END IF;

    IF v_job.fencing_token != p_expected_fencing_token THEN
        RAISE EXCEPTION 'Job fencing token % superseded (current: %)', p_expected_fencing_token, v_job.fencing_token;
    END IF;

    -- 2. Lock payout_batches row FOR UPDATE second
    SELECT * INTO v_batch FROM payout_batches WHERE id = v_job.batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % for job % not found', v_job.batch_id, p_job_id;
    END IF;

    IF v_batch.fencing_token != p_expected_fencing_token THEN
        RAISE EXCEPTION 'Batch fencing token % does not match expected token %', v_batch.fencing_token, p_expected_fencing_token;
    END IF;

    -- 3. Verify definitive persisted provider outcome before marking COMPLETED
    IF v_batch.gateway_batch_state NOT IN ('SUBMITTED', 'SETTLED', 'FAILED') THEN
        RAISE EXCEPTION 'Cannot complete outbox job: batch % has not reached a definitive provider outcome (current state: %)',
            v_batch.id, v_batch.gateway_batch_state;
    END IF;

    -- 4. Mark job COMPLETED
    UPDATE outbox_jobs
    SET status = 'COMPLETED',
        completed_at = CURRENT_TIMESTAMP,
        lease_owner = NULL,
        lease_expires_at = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_job_id;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Procedure I: Outbox Sweeper & Fencing Token Advance (Lock order: outbox_jobs -> payout_batches)
CREATE OR REPLACE FUNCTION fn_sweep_exhausted_outbox_jobs(p_job_type VARCHAR(50))
RETURNS INT
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_job RECORD;
    v_swept_count INT := 0;
    v_new_fencing BIGINT;
    v_job_updated INT;
BEGIN
    FOR v_job IN
        SELECT j.id, j.batch_id, j.fencing_token as job_fencing, j.attempt_count, j.max_attempts, b.fencing_token as batch_fencing
        FROM outbox_jobs j
        JOIN payout_batches b ON b.id = j.batch_id
        WHERE j.job_type = p_job_type
          AND j.status = 'IN_PROGRESS'
          AND j.lease_expires_at <= CURRENT_TIMESTAMP
        ORDER BY j.id ASC
        FOR UPDATE OF j, b SKIP LOCKED
    LOOP
        v_new_fencing := GREATEST(v_job.job_fencing, v_job.batch_fencing) + 1;

        IF v_job.attempt_count >= v_job.max_attempts THEN
            UPDATE outbox_jobs
            SET status = 'MANUAL_RECONCILIATION_REQUIRED',
                lease_owner = NULL,
                lease_expires_at = NULL,
                fencing_token = v_new_fencing,
                last_error = 'EXPIRED_LEASE_MAX_ATTEMPTS_EXHAUSTED',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = v_job.id AND fencing_token = v_job.job_fencing;

            GET DIAGNOSTICS v_job_updated = ROW_COUNT;
            IF v_job_updated = 0 THEN
                CONTINUE;
            END IF;

            UPDATE payout_batches
            SET gateway_batch_state = 'MANUAL_RECONCILIATION_REQUIRED',
                fencing_token = v_new_fencing,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = v_job.batch_id;

            INSERT INTO outbox_recovery_events (
                job_id, batch_id, old_fencing_token, new_fencing_token, recovery_action, reason
            ) VALUES (
                v_job.id, v_job.batch_id, v_job.job_fencing, v_new_fencing,
                'MARK_MANUAL_RECONCILIATION', 'Worker lease expired and max attempts reached'
            );
        ELSE
            UPDATE outbox_jobs
            SET status = 'PENDING',
                lease_owner = NULL,
                lease_expires_at = NULL,
                fencing_token = v_new_fencing,
                last_error = 'EXPIRED_LEASE_RECOVERED_TO_PENDING',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = v_job.id AND fencing_token = v_job.job_fencing;

            GET DIAGNOSTICS v_job_updated = ROW_COUNT;
            IF v_job_updated = 0 THEN
                CONTINUE;
            END IF;

            UPDATE payout_batches
            SET fencing_token = v_new_fencing,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = v_job.batch_id;

            INSERT INTO outbox_recovery_events (
                job_id, batch_id, old_fencing_token, new_fencing_token, recovery_action, reason
            ) VALUES (
                v_job.id, v_job.batch_id, v_job.job_fencing, v_new_fencing,
                'RESET_TO_PENDING', 'Worker lease expired; reset for claim by next available worker'
            );
        END IF;

        v_swept_count := v_swept_count + 1;
    END LOOP;

    RETURN v_swept_count;
END;
$$ LANGUAGE plpgsql;

-- Procedure J: Controlled Beneficiary Lock Release
-- Allows lock release after definitive provider acceptance (SUBMITTED with payout_batch_id) or terminal states
CREATE OR REPLACE FUNCTION fn_release_beneficiary_submission_locks_for_batch(
    p_batch_id UUID,
    p_reason TEXT
)
RETURNS INT
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_batch RECORD;
    v_count INT;
BEGIN
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % does not exist', p_batch_id;
    END IF;

    -- Allow release in terminal states OR definitively accepted SUBMITTED state with persisted payout_batch_id
    IF v_batch.gateway_batch_state IN ('SETTLED', 'FAILED', 'STALE_INVALIDATED') OR
       (v_batch.gateway_batch_state = 'SUBMITTED' AND v_batch.payout_batch_id IS NOT NULL) THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'Cannot release beneficiary submission locks: batch % is in non-releaseable state % (payout_batch_id: %)',
            p_batch_id, v_batch.gateway_batch_state, v_batch.payout_batch_id;
    END IF;

    UPDATE beneficiary_submission_locks
    SET released_at = CURRENT_TIMESTAMP
    WHERE batch_id = p_batch_id AND released_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Procedure K: Payout Item Reconciliation (Individual PayPal Item Status Persistence)
CREATE OR REPLACE FUNCTION fn_record_provider_item_result(
    p_batch_id UUID,
    p_sender_item_id VARCHAR(63),
    p_paypal_payout_item_id VARCHAR(30),
    p_paypal_item_status VARCHAR(50),
    p_raw_provider_status TEXT,
    p_activity_id VARCHAR(30)
)
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_item RECORD;
    v_target_gateway_state VARCHAR(50);
BEGIN
    SELECT * INTO v_item 
    FROM payout_items 
    WHERE batch_id = p_batch_id AND sender_item_id = p_sender_item_id 
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Payout item with sender_item_id % not found in batch %', p_sender_item_id, p_batch_id;
    END IF;

    -- Immutability of provider item ID once set
    IF v_item.payout_item_id IS NOT NULL AND p_paypal_payout_item_id IS NOT NULL AND v_item.payout_item_id IS DISTINCT FROM p_paypal_payout_item_id THEN
        RAISE EXCEPTION 'Conflict: item % already bound to PayPal item ID %, cannot overwrite with %',
            p_sender_item_id, v_item.payout_item_id, p_paypal_payout_item_id;
    END IF;

    -- Determine target gateway item state
    IF p_paypal_item_status IN ('SUCCESS') THEN
        v_target_gateway_state := 'SETTLED';
    ELSIF p_paypal_item_status IN ('FAILED', 'BLOCKED', 'DENIED', 'REFUNDED', 'RETURNED') THEN
        v_target_gateway_state := 'FAILED';
    ELSIF p_paypal_item_status IN ('REVERSED') THEN
        v_target_gateway_state := 'REVERSED';
    ELSIF p_paypal_item_status IN ('PENDING', 'UNCLAIMED', 'ONHOLD') THEN
        v_target_gateway_state := 'SUBMITTED';
    ELSE
        -- Unknown status: do not overwrite current gateway state, but preserve raw status
        v_target_gateway_state := v_item.gateway_item_state;
    END IF;

    -- Protect against out-of-order updates if already terminal
    IF v_item.gateway_item_state IN ('SETTLED', 'FAILED', 'REVERSED', 'STALE_INVALIDATED') THEN
        -- Allow updating raw provider status and activity_id, but do not downgrade gateway_item_state
        UPDATE payout_items
        SET payout_item_id = COALESCE(p_paypal_payout_item_id, payout_item_id),
            paypal_item_state = p_paypal_item_status,
            raw_provider_status_text = p_raw_provider_status,
            activity_id = COALESCE(p_activity_id, activity_id),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_item.id;
    ELSE
        UPDATE payout_items
        SET payout_item_id = COALESCE(p_paypal_payout_item_id, payout_item_id),
            gateway_item_state = v_target_gateway_state,
            paypal_item_state = p_paypal_item_status,
            raw_provider_status_text = p_raw_provider_status,
            activity_id = COALESCE(p_activity_id, activity_id),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_item.id;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Procedure L: Controlled Manual Reconciliation Resolution
CREATE OR REPLACE FUNCTION fn_resolve_manual_reconciliation(
    p_batch_id UUID,
    p_resolved_by_user_id UUID,
    p_final_state VARCHAR(50),
    p_provider_batch_id VARCHAR(30),
    p_resolution_notes TEXT
)
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user RECORD;
    v_job RECORD;
    v_batch RECORD;
BEGIN
    IF p_final_state NOT IN ('SUBMITTED', 'SETTLED', 'FAILED') THEN
        RAISE EXCEPTION 'Manual reconciliation target state must be SUBMITTED, SETTLED, or FAILED; got %', p_final_state;
    END IF;

    -- Verify user is active Treasury Officer or Auditor
    SELECT * INTO v_user FROM users WHERE id = p_resolved_by_user_id;
    IF NOT FOUND OR v_user.role NOT IN ('TREASURY_OFFICER', 'AUDITOR') OR NOT v_user.is_active THEN
        RAISE EXCEPTION 'User % not authorized for manual reconciliation', p_resolved_by_user_id;
    END IF;

    -- Lock Order: outbox_jobs then payout_batches
    SELECT * INTO v_job FROM outbox_jobs WHERE batch_id = p_batch_id FOR UPDATE;
    SELECT * INTO v_batch FROM payout_batches WHERE id = p_batch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Batch % not found', p_batch_id;
    END IF;

    IF v_batch.gateway_batch_state != 'MANUAL_RECONCILIATION_REQUIRED' THEN
        RAISE EXCEPTION 'Batch % is not in MANUAL_RECONCILIATION_REQUIRED (current: %)', p_batch_id, v_batch.gateway_batch_state;
    END IF;

    -- Update batch
    UPDATE payout_batches
    SET gateway_batch_state = p_final_state,
        payout_batch_id = COALESCE(p_provider_batch_id, payout_batch_id),
        paypal_batch_state = CASE WHEN p_final_state = 'SETTLED' THEN 'SUCCESS'
                                  WHEN p_final_state = 'FAILED' THEN 'DENIED'
                                  ELSE 'PROCESSING' END,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_batch_id;

    -- Update job if exists
    IF v_job.id IS NOT NULL THEN
        UPDATE outbox_jobs
        SET status = CASE WHEN p_final_state IN ('SUBMITTED', 'SETTLED') THEN 'COMPLETED' ELSE 'FAILED' END,
            last_error = 'MANUALLY_RESOLVED: ' || p_resolution_notes,
            completed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_job.id;
    END IF;

    -- Record in reconciliation_attempts
    INSERT INTO reconciliation_attempts (
        batch_id, sync_source, previous_state, new_state, items_updated
    ) VALUES (
        p_batch_id, 'MANUAL_OPERATOR', 'MANUAL_RECONCILIATION_REQUIRED', p_final_state, 0
    );

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Procedure M: Append Tamper-Evident Audit Event (Includes user_agent & handles concurrent chain init)
CREATE OR REPLACE FUNCTION fn_append_audit_event(
    p_stream_id VARCHAR(50),
    p_actor_user_id UUID,
    p_event_type VARCHAR(100),
    p_entity_type VARCHAR(50),
    p_entity_id UUID,
    p_request_id VARCHAR(100),
    p_correlation_id VARCHAR(100),
    p_client_ip INET,
    p_user_agent TEXT,
    p_fencing_token BIGINT,
    p_encrypted_payload BYTEA,
    p_metadata_json JSONB
)
RETURNS BIGINT
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_prev_digest VARCHAR(64);
    v_canonical_event_str TEXT;
    v_event_digest VARCHAR(64);
    v_event_id BIGINT;
    v_created_at TIMESTAMPTZ := clock_timestamp();
    v_payload_hash VARCHAR(64);
BEGIN
    -- Concurrent safe initialization: insert chain head on conflict do nothing
    INSERT INTO audit_chain_heads (chain_id, head_event_digest, total_events)
    VALUES (p_stream_id, '0000000000000000000000000000000000000000000000000000000000000000', 0)
    ON CONFLICT (chain_id) DO NOTHING;

    -- Lock stream head row FOR UPDATE
    SELECT head_event_digest INTO v_prev_digest
    FROM audit_chain_heads
    WHERE chain_id = p_stream_id
    FOR UPDATE;

    v_payload_hash := encode(digest(COALESCE(p_encrypted_payload, ''::bytea), 'sha256'), 'hex');

    -- Canonical unambiguous JSON encoding including exact microsecond UTC timestamp and user_agent
    v_canonical_event_str := json_build_object(
        'actor_user_id', COALESCE(p_actor_user_id::text, ''),
        'client_ip', COALESCE(host(p_client_ip), ''),
        'correlation_id', COALESCE(p_correlation_id, ''),
        'created_at', to_char(v_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'encrypted_payload_hash', v_payload_hash,
        'entity_id', COALESCE(p_entity_id::text, ''),
        'entity_type', p_entity_type,
        'event_type', p_event_type,
        'fencing_token', COALESCE(p_fencing_token, 0),
        'metadata', COALESCE(p_metadata_json, '{}'::jsonb),
        'prev_event_digest', v_prev_digest,
        'request_id', COALESCE(p_request_id, ''),
        'stream_id', p_stream_id,
        'user_agent', COALESCE(p_user_agent, '')
    )::text;

    v_event_digest := encode(digest(convert_to(v_canonical_event_str, 'UTF8'), 'sha256'), 'hex');

    INSERT INTO audit_events (
        stream_id, actor_user_id, event_type, entity_type, entity_id,
        request_id, correlation_id, client_ip, user_agent, fencing_token,
        encrypted_payload, metadata_json, prev_event_digest, event_digest, created_at
    ) VALUES (
        p_stream_id, p_actor_user_id, p_event_type, p_entity_type, p_entity_id,
        p_request_id, p_correlation_id, p_client_ip, p_user_agent, p_fencing_token,
        p_encrypted_payload, p_metadata_json, v_prev_digest, v_event_digest, v_created_at
    ) RETURNING id INTO v_event_id;

    UPDATE audit_chain_heads
    SET head_event_digest = v_event_digest,
        total_events = total_events + 1,
        last_event_at = v_created_at
    WHERE chain_id = p_stream_id;

    RETURN v_event_id;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- 10. LEAST-PRIVILEGE ROLE-BASED ACCESS CONTROL (RBAC) GRANTS
-- ----------------------------------------------------------------------------

-- Revoke all table and function permissions from PUBLIC
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- Re-grant execute on pgcrypto functions to PUBLIC and roles
GRANT EXECUTE ON FUNCTION digest(text, text), digest(bytea, text), hmac(text, text, text), hmac(bytea, bytea, text), gen_random_uuid() 
TO PUBLIC, deepfakeshield_owner, deepfakeshield_app, deepfakeshield_verifier, deepfakeshield_payout_worker;

-- 1. deepfakeshield_app (AP Application Role)
GRANT SELECT ON encryption_key_metadata, users, sessions, beneficiaries, payout_batches, payout_items, payout_snapshots, beneficiary_submission_locks TO deepfakeshield_app;
GRANT INSERT ON sessions, audio_assets, audio_consents, speaker_segments, risk_evaluations, payout_batches, payout_items, beneficiary_changes, webauthn_challenges TO deepfakeshield_app;
GRANT UPDATE (session_status, terminated_at, termination_reason) ON sessions TO deepfakeshield_app;
GRANT EXECUTE ON FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT) TO deepfakeshield_app;

-- 2. deepfakeshield_verifier (WebAuthn Security Kernel Role)
GRANT SELECT ON users, webauthn_credentials, webauthn_challenges, payout_batches, payout_snapshots, beneficiary_changes, beneficiary_change_approvals, officer_approvals, encryption_key_metadata TO deepfakeshield_verifier;
GRANT UPDATE (sign_count, last_used_at) ON webauthn_credentials TO deepfakeshield_verifier;
GRANT UPDATE (is_consumed, consumed_at) ON webauthn_challenges TO deepfakeshield_verifier;
GRANT EXECUTE ON FUNCTION fn_submit_officer_approval(UUID, UUID, UUID, TEXT, UUID, VARCHAR, TEXT, BYTEA, BYTEA, BIGINT) TO deepfakeshield_verifier;
GRANT EXECUTE ON FUNCTION fn_submit_beneficiary_change_approval(UUID, UUID, TEXT, UUID, VARCHAR, TEXT, BYTEA, BYTEA, BIGINT) TO deepfakeshield_verifier;
GRANT EXECUTE ON FUNCTION fn_activate_beneficiary_change(UUID) TO deepfakeshield_verifier;
GRANT EXECUTE ON FUNCTION fn_resolve_manual_reconciliation(UUID, UUID, VARCHAR, VARCHAR, TEXT) TO deepfakeshield_verifier;
GRANT EXECUTE ON FUNCTION fn_append_audit_event(VARCHAR, UUID, VARCHAR, VARCHAR, UUID, VARCHAR, VARCHAR, INET, TEXT, BIGINT, BYTEA, JSONB) TO deepfakeshield_verifier;

-- 3. deepfakeshield_payout_worker (Outbox Payout & Provider Worker Role)
GRANT SELECT ON payout_batches, payout_items, payout_snapshots, outbox_jobs, outbox_recovery_events, beneficiary_submission_locks, paypal_api_attempts, reconciliation_attempts, webhook_inbox, encryption_key_metadata TO deepfakeshield_payout_worker;
GRANT INSERT ON reconciliation_attempts, webhook_inbox TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_claim_outbox_job(TEXT, VARCHAR) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_heartbeat_outbox_job(UUID, TEXT, BIGINT) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_complete_outbox_job(UUID, TEXT, BIGINT) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_record_provider_payout_result(UUID, TEXT, BIGINT, VARCHAR, VARCHAR, INT, TEXT, BOOLEAN) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_record_provider_item_result(UUID, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_sweep_exhausted_outbox_jobs(VARCHAR) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_release_beneficiary_submission_locks_for_batch(UUID, TEXT) TO deepfakeshield_payout_worker;
GRANT EXECUTE ON FUNCTION fn_append_audit_event(VARCHAR, UUID, VARCHAR, VARCHAR, UUID, VARCHAR, VARCHAR, INET, TEXT, BIGINT, BYTEA, JSONB) TO deepfakeshield_payout_worker;

-- 4. deepfakeshield_auditor (Read-Only Auditor & Reconciliation Role)
GRANT SELECT ON audit_chain_heads, audit_events, audit_checkpoints, payout_batches, payout_items, payout_snapshots, officer_approvals, beneficiary_changes, beneficiary_change_approvals, reconciliation_attempts, paypal_api_attempts TO deepfakeshield_auditor;
GRANT EXECUTE ON FUNCTION fn_resolve_manual_reconciliation(UUID, UUID, VARCHAR, VARCHAR, TEXT) TO deepfakeshield_auditor;
GRANT EXECUTE ON FUNCTION fn_append_audit_event(VARCHAR, UUID, VARCHAR, VARCHAR, UUID, VARCHAR, VARCHAR, INET, TEXT, BIGINT, BYTEA, JSONB) TO deepfakeshield_auditor;

-- Set function ownership to deepfakeshield_owner
ALTER FUNCTION fn_prevent_beneficiary_physical_delete() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_check_beneficiary_submission_lock() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_validate_payout_batch_insert() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_validate_payout_item_insert() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_validate_batch_state_transition() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_prevent_payout_item_batch_id_mutation() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_serialize_payout_items_against_parent() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_enforce_audit_immutability() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_prevent_audit_truncate() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_prevent_audit_chain_head_tampering() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_enforce_snapshot_immutability() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_prevent_item_terminal_state_overwrite() OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_finalize_payout_batch(UUID, TEXT, BYTEA, VARCHAR, BYTEA, BYTEA, BYTEA, TEXT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_submit_officer_approval(UUID, UUID, UUID, TEXT, UUID, VARCHAR, TEXT, BYTEA, BYTEA, BIGINT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_submit_beneficiary_change_approval(UUID, UUID, TEXT, UUID, VARCHAR, TEXT, BYTEA, BYTEA, BIGINT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_activate_beneficiary_change(UUID) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_claim_outbox_job(TEXT, VARCHAR) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_heartbeat_outbox_job(UUID, TEXT, BIGINT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_record_provider_payout_result(UUID, TEXT, BIGINT, VARCHAR, VARCHAR, INT, TEXT, BOOLEAN) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_complete_outbox_job(UUID, TEXT, BIGINT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_sweep_exhausted_outbox_jobs(VARCHAR) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_release_beneficiary_submission_locks_for_batch(UUID, TEXT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_record_provider_item_result(UUID, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_resolve_manual_reconciliation(UUID, UUID, VARCHAR, VARCHAR, TEXT) OWNER TO deepfakeshield_owner;
ALTER FUNCTION fn_append_audit_event(VARCHAR, UUID, VARCHAR, VARCHAR, UUID, VARCHAR, VARCHAR, INET, TEXT, BIGINT, BYTEA, JSONB) OWNER TO deepfakeshield_owner;

COMMIT;
