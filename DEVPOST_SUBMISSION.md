# DeepfakeShield V10.1.5 — Devpost Submission

## 1. Project Title and Tagline

**DeepfakeShield for PayPal (V10.1.5)**  
*Fail-closed voice-risk verification, dual-officer cryptographic approvals, and PostgreSQL-enforced payout controls for PayPal Payouts.*

---

## 2. Problem Statement

Corporate treasury and Accounts Payable (AP) teams increasingly rely on voice callbacks and remote authorization workflows to release high-value contractor and vendor disbursements. This creates two severe, intersecting risks:

1. **Voice-Cloned Authorization Fraud & Audio Replay Attacks:** Attackers use synthetic speech or replay previously recorded genuine executive audio snippets across different payment batches to trick operators into releasing funds.
2. **Application-Layer Bypass & Double-Disbursement Risk:** When payment gates live only in web middleware, compromised application credentials, race conditions, or out-of-band SQL writes can finalize unverified batches, swap beneficiary recipients after approval, or double-submit outbound payouts.

Relying on a standalone deepfake classifier is insufficient—an attacker only needs to fool or bypass one score. Corporate payments need **multiple independent security gates** enforced before money can move.

---

## 3. Proposed Solution

**DeepfakeShield** is an AI-assisted treasury security prototype built around a fail-closed release pipeline for PayPal Payouts (`SANDBOX_API` or `SIMULATOR`). Rather than trusting a single voice score, DeepfakeShield combines:

- **Deterministic Acoustic Signal & Anti-Replay Screening** (`ACOUSTIC_FFT_HEURISTIC_V1`),
- **AI Risk Reviewer Assistant** (Google Gemini API via `google-genai` / `gemini-3.8-flash`, strictly advisory-only for human `RISK_REVIEWER` triage),
- **Governed Human Risk Review** (`RISK_REVIEWER` role with append-only `audio_risk_reviews`),
- **Dual-Officer Cryptographic Approvals** (two distinct `TREASURY_OFFICER` sign-offs with ECDSA P-256 WebAuthn assertions),
- **PostgreSQL 18 `SECURITY DEFINER` Finalization Gates** (`deepfakeshield_app`, `deepfakeshield_verifier`, `deepfakeshield_payout_worker`, `deepfakeshield_auditor`), and
- **Encrypted Payout Snapshots & Idempotent Outbox Execution** (`AES-256-GCM` + `FOR UPDATE SKIP LOCKED` + PayPal Payouts API).

---

## 4. How It Works

1. **Draft Batch & Beneficiary Integrity (`AP_CLERK`):** An Accounts Payable maker creates a draft payout batch targeting verified beneficiaries (with HMAC-SHA256 blind indexing and cooling-off controls).
2. **Audio Instruction Analysis & Anti-Replay (`ACOUSTIC_FFT_HEURISTIC_V1`):** A 16 kHz mono PCM16 WAV authorization recording is parsed, checked against an atomic file-locked registry (`audio_hash_registry.json`) for exact `SHA-256` and spectral acoustic fingerprint replay, and scored via windowed FFT spectral flatness, high-frequency energy ratio, and WADA SNR.
3. **AI-Assisted Human Review (`CHALLENGE / NEEDS_REVIEW`):**
   - If the heuristic returns `CHALLENGE` (`NEEDS_REVIEW`), batch finalization remains **blocked inside PostgreSQL**.
   - An independent `RISK_REVIEWER` inspects the SHA-256-verified WAV recording, deterministic DSP metrics, and—when `GEMINI_API_KEY` is configured—requests a structured advisory explanation from the **AI Risk Reviewer Assistant** (Google Gemini `gemini-3.8-flash`).
   - The reviewer records an immutable `APPROVE_WITH_REVIEW` or `REJECT` disposition via `fn_submit_audio_risk_review()` without overwriting the original evaluation.
4. **PostgreSQL Fail-Closed Finalization (`fn_finalize_payout_batch`):** PostgreSQL verifies active 1:1 session isolation, explicit consent (`audio_consents`), valid non-stale (`<= 1 hour`) `risk_evaluations`, and (if `CHALLENGE`) a matching `APPROVE_WITH_REVIEW` record before sealing an `AES-256-GCM` payout snapshot.
5. **Two-Officer Treasury Sign-Off (`TREASURY_OFFICER`):** Two distinct active officers (`bob_checker`, `carol_checker_two`) sign the batch digest using ECDSA P-256 WebAuthn assertions with monotonic counter checks.
6. **Idempotent PayPal Outbox Delivery:** A separate `OutboxWorker` claims `outbox_jobs` via `FOR UPDATE SKIP LOCKED` and submits the batch to PayPal (`POST /v1/payments/payouts`) with idempotent `sender_batch_id` scoping, recording outcomes and hash-chained `audit_events`.

---

## 5. Innovation and Differentiation

- **Defense-in-Depth Over Single-Score Trust:** DeepfakeShield never lets an audio score or an LLM directly move money. Every release requires acoustic screening, human review (when challenged), database-enforced state verification, and dual-officer cryptographic sign-off.
- **Advisory-Only AI Governance:** The **AI Risk Reviewer Assistant** (`backend/ai_risk_assistant.py`) strictly separates **measured DSP evidence** from **AI-generated interpretation**, transmits **zero raw audio, beneficiary emails, legal names, or credentials**, and has **zero authority** to alter risk scores, classifications, approvals, or payout state.
- **Database-Enforced Security Boundaries:** Even if application middleware is bypassed, `deepfakeshield_app` cannot insert/update `risk_evaluations` or `audio_risk_reviews` directly; only `deepfakeshield_verifier` can commit them via `SECURITY DEFINER` functions, and `fn_finalize_payout_batch()` validates every invariant inside PostgreSQL.

---

## 6. PayPal Integration and Why It Is Central

PayPal Payouts is the **settlement engine** at the end of DeepfakeShield's control plane (`backend/paypal_client.py`):

- **OAuth2 Client Credentials + Thread-Safe Token Caching:** Authenticates against `/v1/oauth2/token` (`https://api-m.sandbox.paypal.com`) with configurable timeouts and automatic token refresh.
- **Idempotent Batch Disbursement:** Submits sealed payout batches to `/v1/payments/payouts` using unique `sender_batch_id` and per-item `sender_item_id` values so worker retries after network timeouts never double-pay contractors.
- **Dual-Mode Architecture (`SANDBOX_API` & `SIMULATOR`):** Supports live PayPal Developer Sandbox API calls as well as a deterministic local `SIMULATOR` for fault-injection testing (e.g., network timeouts and manual reconciliation), while strictly blocking `DEMO_MODE=true` from ever targeting a PayPal production URL.

---

## 7. AI Technology and Precisely How It Is Used

DeepfakeShield is transparent about what is heuristic DSP versus generative AI:

- **Deterministic Acoustic Screening (`ACOUSTIC_FFT_HEURISTIC_V1`):** Uses `numpy` and `scipy` to compute WADA SNR, windowed FFT spectral flatness (Wiener entropy), and high-frequency energy ratio (`> 3.5 kHz`), combined with SHA-256 and spectral fingerprint anti-replay detection. *This is explicitly a rule-based heuristic (`CHECKPOINT_HASH=None`), not a trained neural AASIST detector.*
- **Generative AI — AI Risk Reviewer Assistant (`backend/ai_risk_assistant.py`):**
  - **Provider & SDK:** Official Google Gemini API via `google-genai` (`>= 2.30.1`), calling the Interactions API (`client.interactions.create(..., store=False)`) with `gemini-3.8-flash` (configurable via `GEMINI_MODEL`).
  - **Input:** Strictly sanitized numeric/boolean/enum acoustic telemetry (`spectral_flatness_mean/max`, `high_frequency_energy_ratio_mean/max`, `wada_snr_db`, `sha256_replay_result`, `acoustic_fingerprint_replay_result`, and heuristic classification). Raw audio, emails, names, and secrets are never transmitted.
  - **Output & Provenance:** Returns a structured explanation (`summary`, `attention_reasons`, `supporting_measurements`, `reviewer_guidance`, `limitations_notice`) alongside `provider`, `model`, `interaction_id`, `generated_at`, and `authority: "ADVISORY_ONLY_NO_DECISION_POWER"`.
  - **Fail-Safe Behavior:** If `GEMINI_API_KEY` is unset, it returns `status: "NOT_CONFIGURED"` and never fabricates an AI response. Timeouts and malformed responses fail gracefully with key redaction.

---

## 8. Architecture and Technology Stack

- **Backend API & Worker:** Python 3.11+, FastAPI, Pydantic, Uvicorn, Requests
- **AI Integration:** Google Gemini API (`google-genai >= 2.30.1`, `gemini-3.8-flash` via Interactions API)
- **Database & Enforcement:** PostgreSQL 18 (`pgcrypto`, `SECURITY DEFINER` routines, `FOR UPDATE SKIP LOCKED`, append-only audit & review triggers)
- **Cryptography:** `cryptography` (`AES-256-GCM`, ECDSA P-256 WebAuthn assertion verification, HMAC-SHA256 blind indexing & audit chaining), RFC 7914 `scrypt`
- **Signal Processing:** `numpy`, `scipy` (16 kHz Mono PCM16 WAV parsing, FFT spectral flatness, HF energy ratio, WADA SNR)
- **Frontend:** Vanilla HTML/CSS/JavaScript Operations Console (`static/index.html`)
- **CI/CD:** GitHub Actions (`.github/workflows/ci.yml`) with isolated PostgreSQL 18 service container

---

## 9. Verification Evidence

- **GitHub Actions CI Baseline (at commit `aad2995`):** Workflow run [`43187873804`](https://github.com/jayp91131-sudo/DeepfakeShield/actions/runs/43187873804) passed on `ubuntu-latest` with Python 3.11 and PostgreSQL 18 (`55 passed` across startup security, PayPal sandbox/simulator isolation, DB audio-gate migrations, manual audio review, final acceptance, and static UI labeling).
- **AI Risk Reviewer Assistant Tests (`tests/test_ai_risk_assistant.py`):** Mocked Gemini Interactions API unit tests verify unconfigured `NOT_CONFIGURED` handling, PII/raw-audio/secret exclusion, timeout & malformed JSON handling with key redaction, and non-authority invariants, plus FastAPI `RISK_REVIEWER` RBAC enforcement.
- **Note on Live Credentials:** Automated CI runs with `PAYPAL_PROVIDER_MODE=SIMULATOR` and mocked Gemini responses; live PayPal Sandbox payout settlement and live Gemini API calls require user-supplied local credentials (`PAYPAL_CLIENT_ID`/`PAYPAL_CLIENT_SECRET` and `GEMINI_API_KEY`).

---

## 10. Significant Improvements Made During the Hackathon Period

Based on the repository's Git commit history:

- **`02db16b` (2026-11-11):** Prepared initial DeepfakeShield V10.1.5 public release with PostgreSQL-enforced audio finalization gate (`V10_1_4`) and governed manual audio-risk review (`V10_1_5`).
- **`a26f989` (2026-11-11):** Enforced explicit startup credentials (`ATTESTATION_SECRET`, `BLIND_INDEX_KEY`, `AUTH_ASSERTION_KEY`, DB role passwords, operator credentials) and isolated demo fallbacks strictly behind `DEMO_MODE=true`.
- **`d95a7b5` (2026-11-12):** Eliminated cryptographic fallbacks and hardened demo isolation across `backend/database.py`, `backend/payout_service.py`, and `crypto_verifier.py`.
- **`05e3f0b` (2026-11-12):** Removed remaining static demo keys (`BOB_DETERMINISTIC_SEED`, `CAROL_DETERMINISTIC_SEED`, static DEK), enforced multi-process PEM key safety, and isolated PayPal environment tests from local `.env` overrides.
- **`aad2995` (2026-11-12):** Completed isolated PostgreSQL 18 database verification and added automated GitHub Actions CI (`.github/workflows/ci.yml`), achieving 55 passing CI tests.
- **Post-`aad2995` Addition:** Added the advisory-only **AI Risk Reviewer Assistant** (`backend/ai_risk_assistant.py`, `POST /api/batches/{batch_id}/audio-review/ai-assist`, `GET /api/ai-assistant/status`, UI panel, and `tests/test_ai_risk_assistant.py`).

---

## 11. Demo and Installation Instructions

1. **Prerequisites:** Python 3.11+, PostgreSQL 18.
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure environment:** Copy `.env.example` to `.env` (or export variables) with strong PostgreSQL role passwords, 32-byte hex crypto keys (`ATTESTATION_SECRET`, `BLIND_INDEX_KEY`, `AUTH_ASSERTION_KEY`), and operator credentials. Optionally set `GEMINI_API_KEY` for the AI Risk Reviewer Assistant and `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` for PayPal Sandbox.
4. **Initialize disposable database & apply migrations:**
   ```bash
   python setup_disposable_db.py --confirm-drop
   psql -d deepfakeshield_test_ci -f migrations/V10_1_4__database_audio_finalization_gate.sql
   psql -d deepfakeshield_test_ci -f migrations/V10_1_5__manual_audio_risk_review.sql
   ```
5. **Run API & Worker:**
   ```bash
   uvicorn backend.main:app --host 127.0.0.1 --port 8000
   python -m backend.outbox_worker
   ```
   Open `http://127.0.0.1:8000` in a browser.

---

## 12. Current Limitations and Future Work

- **Prototype Status:** DeepfakeShield V10.1.5 is an engineering prototype and is **not production-ready**.
- **Heuristic Audio Engine:** `ACOUSTIC_FFT_HEURISTIC_V1` is a deterministic DSP heuristic (`CHECKPOINT_HASH=None`), not a trained neural anti-spoofing model (such as AASIST-L). Future work includes integrating a verified neural inference service behind the same PostgreSQL `deepfakeshield_verifier` boundary.
- **Hardware WebAuthn Ceremony:** Officer assertions currently use server-verified ECDSA P-256 test/configured keys rather than full browser-side `navigator.credentials.get()` FIDO2 hardware token ceremonies.
- **Live Settlement & AI Credentials:** End-to-end live PayPal Sandbox settlement and live Gemini API responses require explicit operator credentials at runtime.

---

## 13. GitHub Repository URL

https://github.com/jayp91131-sudo/DeepfakeShield
