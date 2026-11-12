"""
Tests for the DeepfakeShield AI Risk Reviewer Assistant (Google Gemini API).

Verifies:
1. Unconfigured GEMINI_API_KEY reports NOT_CONFIGURED without fabricating output.
2. Mocked Gemini Interactions API returns structured advisory explanation with provenance.
3. Measured DSP evidence is strictly separated from AI-generated interpretation.
4. Raw audio, beneficiary emails, legal names, and credentials are never sent to Gemini.
5. Timeouts, provider failures, and malformed responses fail gracefully and redact keys.
6. AI cannot alter risk score, classification, or payout/approval state.
7. FastAPI endpoint enforces RISK_REVIEWER role separation (when FastAPI is available).
"""

import copy
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from backend.ai_risk_assistant import (
    DEFAULT_GEMINI_MODEL,
    extract_sanitized_audio_metadata,
    generate_ai_risk_explanation,
    get_ai_assistant_status,
)


def _sample_evidence() -> dict:
    return {
        "batch": {
            "batch_id": "11111111-1111-1111-1111-111111111111",
            "gateway_batch_state": "DRAFT",
            "total_amount_usd": "2250.00",
        },
        "recipients": [
            {
                "sender_item_id": "item-1",
                "legal_name": "Alice Confidential Contractor LLC",
                "receiver_email": "secret-contractor@example.com",
                "amount_usd": "2250.00",
            }
        ],
        "audio_evidence": {
            "audio_asset_id": "22222222-2222-2222-2222-222222222222",
            "risk_evaluation_id": "33333333-3333-3333-3333-333333333333",
            "audio_content_sha256": "a" * 64,
            "acoustic_fingerprint": "b" * 64,
            "audio_bytes": b"RIFF_SECRET_RAW_AUDIO_BYTES",
        },
        "analysis": {
            "analyzer_version": "ACOUSTIC_FFT_HEURISTIC_V1",
            "model_version": "ACOUSTIC_FFT_HEURISTIC_V1",
            "original_ai_decision": "CHALLENGE",
            "original_policy_decision": "NEEDS_REVIEW",
            "acoustic_signal": "INDETERMINATE",
            "deepfake_probability": 0.44,
            "max_window_score": 0.51,
            "acoustic_consistency_score": 0.52,
            "wada_snr_db": 14.2,
            "voice_clone_flag": False,
            "adversarial_noise_detected": False,
            "replay_detected": False,
            "window_count": 2,
            "window_results": [
                {
                    "window_index": 0,
                    "score": 0.41,
                    "features": {"hf_ratio": 0.18, "spectral_flatness": 0.24, "spoof_metric": 0.204},
                },
                {
                    "window_index": 1,
                    "score": 0.47,
                    "features": {"hf_ratio": 0.22, "spectral_flatness": 0.28, "spoof_metric": 0.244},
                },
            ],
        },
        "secret_leak_trap": "PAYPAL_SUPER_SECRET_DO_NOT_SEND",
    }


class TestAIRiskReviewerAssistant(unittest.TestCase):
    def test_not_configured_when_api_key_missing(self):
        evidence = _sample_evidence()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GEMINI_API_KEY", None)
            status = get_ai_assistant_status()
            self.assertFalse(status["configured"])
            self.assertEqual(status["status"], "NOT_CONFIGURED")

            res = generate_ai_risk_explanation(evidence, risk_evaluation_id="33333333-3333-3333-3333-333333333333")
            self.assertEqual(res["status"], "NOT_CONFIGURED")
            self.assertFalse(res["configured"])
            self.assertIsNone(res["ai_interpretation"])
            self.assertTrue(res["advisory_only"])
            self.assertFalse(res["can_modify_risk_score"])
            self.assertFalse(res["can_modify_classification"])
            self.assertFalse(res["can_approve_or_reject_payout"])
            self.assertFalse(res["can_bypass_treasury_approvals"])

    def test_pii_raw_audio_and_secrets_never_sent_to_provider(self):
        evidence = _sample_evidence()
        captured = {}

        def fake_create(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                id="inter_test_123",
                output_text=json.dumps({
                    "summary": "Moderate spectral flatness and HF energy triggered CHALLENGE.",
                    "attention_reasons": ["Mean deepfake score 0.44 falls in the 0.35-0.60 CHALLENGE band."],
                    "supporting_measurements": [
                        "spectral_flatness_mean=0.26",
                        "high_frequency_energy_ratio_mean=0.2",
                        "wada_snr_db=14.2",
                    ],
                    "reviewer_guidance": "Listen to the WAV recording and verify caller context.",
                    "limitations_notice": "ACOUSTIC_FFT_HEURISTIC_V1 is heuristic; AI output is advisory only.",
                }),
            )

        fake_client = SimpleNamespace(interactions=SimpleNamespace(create=fake_create))
        fake_genai = SimpleNamespace(Client=MagicMock(return_value=fake_client))

        with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaFakeSecretKeyForTestingOnly12345"}, clear=False):
            snapshot_before = copy.deepcopy(evidence)
            res = generate_ai_risk_explanation(
                evidence,
                risk_evaluation_id="33333333-3333-3333-3333-333333333333",
                genai_module=fake_genai,
            )

        self.assertEqual(evidence, snapshot_before)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provenance"]["model"], DEFAULT_GEMINI_MODEL)
        self.assertEqual(res["provenance"]["interaction_id"], "inter_test_123")
        self.assertEqual(res["provenance"]["authority"], "ADVISORY_ONLY_NO_DECISION_POWER")
        self.assertEqual(res["measured_evidence"]["heuristic_recommendation"], "CHALLENGE")
        self.assertEqual(res["measured_evidence"]["heuristic_policy_decision"], "NEEDS_REVIEW")
        self.assertAlmostEqual(res["measured_evidence"]["spectral_flatness_mean"], 0.26, places=4)
        self.assertAlmostEqual(res["measured_evidence"]["high_frequency_energy_ratio_mean"], 0.2, places=4)
        self.assertEqual(res["measured_evidence"]["wada_snr_db"], 14.2)
        self.assertEqual(res["measured_evidence"]["sha256_replay_result"], "NO_REPLAY")
        self.assertEqual(res["measured_evidence"]["acoustic_fingerprint_replay_result"], "NO_REPLAY")

        # Ensure strict privacy & non-secret boundary
        sent_text = str(captured.get("input", "")) + str(captured.get("system_instruction", ""))
        self.assertNotIn("secret-contractor@example.com", sent_text)
        self.assertNotIn("Alice Confidential Contractor LLC", sent_text)
        self.assertNotIn("RIFF_SECRET_RAW_AUDIO_BYTES", sent_text)
        self.assertNotIn("PAYPAL_SUPER_SECRET_DO_NOT_SEND", sent_text)
        self.assertNotIn("AIzaFakeSecretKeyForTestingOnly12345", sent_text)
        self.assertFalse(captured.get("store"))
        self.assertEqual(captured.get("model"), DEFAULT_GEMINI_MODEL)

    def test_timeout_and_provider_error_redact_keys_and_fail_gracefully(self):
        evidence = _sample_evidence()

        def timeout_create(**kwargs):
            raise TimeoutError("Request timed out with key AIzaLeakAttempt9999999999")

        fake_client = SimpleNamespace(interactions=SimpleNamespace(create=timeout_create))
        fake_genai = SimpleNamespace(Client=MagicMock(return_value=fake_client))

        with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaLeakAttempt9999999999", "GEMINI_TIMEOUT_SECONDS": "5"}, clear=False):
            res = generate_ai_risk_explanation(evidence, genai_module=fake_genai)

        self.assertEqual(res["status"], "ERROR")
        self.assertIsNone(res["ai_interpretation"])
        self.assertIn("TimeoutError", res["error"])
        self.assertNotIn("AIzaLeakAttempt9999999999", res["error"])
        self.assertIn("[REDACTED_KEY]", res["error"])

    def test_malformed_json_response_fails_gracefully(self):
        evidence = _sample_evidence()

        def bad_json_create(**kwargs):
            return SimpleNamespace(id="inter_bad", output_text="Not valid JSON at all")

        fake_client = SimpleNamespace(interactions=SimpleNamespace(create=bad_json_create))
        fake_genai = SimpleNamespace(Client=MagicMock(return_value=fake_client))

        with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaFakeKey1234567890"}, clear=False):
            res = generate_ai_risk_explanation(evidence, genai_module=fake_genai)

        self.assertEqual(res["status"], "ERROR")
        self.assertIsNone(res["ai_interpretation"])
        self.assertIn("JSONDecodeError", res["error"])

    def test_extract_sanitized_metadata_bounds_windows(self):
        analysis = {
            "wada_snr_db": 11.0,
            "replay_detected": True,
            "recommendation": "TERMINATE",
            "policy_decision": "BLOCKED",
            "window_results": [
                {"features": {"spectral_flatness": 0.5, "hf_ratio": 0.4}}
                for _ in range(200)
            ],
        }
        sanitized = extract_sanitized_audio_metadata(analysis)
        self.assertEqual(sanitized["sha256_replay_result"], "REPLAY_DETECTED")
        self.assertEqual(sanitized["acoustic_fingerprint_replay_result"], "REPLAY_DETECTED")
        self.assertEqual(sanitized["heuristic_recommendation"], "TERMINATE")
        self.assertEqual(sanitized["spectral_flatness_mean"], 0.5)


try:
    from fastapi.testclient import TestClient
    import backend.main as backend_main
    _FASTAPI_AVAILABLE = True
except Exception:
    _FASTAPI_AVAILABLE = False


@unittest.skipUnless(_FASTAPI_AVAILABLE, "FastAPI TestClient not available in this Python runtime")
class TestAIRiskAssistantEndpointRBAC(unittest.TestCase):
    def test_ai_assist_endpoint_requires_risk_reviewer_and_preserves_state(self):
        client = TestClient(backend_main.app)

        # Override get_current_user with AP_CLERK -> must get 403
        backend_main.app.dependency_overrides[backend_main.get_current_user] = lambda: {
            "user_id": "00000000-0000-0000-0000-000000000001",
            "username": "alice_ap_maker",
            "role": "AP_CLERK",
            "is_active": True,
        }
        try:
            resp_forbidden = client.post("/api/batches/11111111-1111-1111-1111-111111111111/audio-review/ai-assist")
            self.assertEqual(resp_forbidden.status_code, 403)

            # Override get_current_user with RISK_REVIEWER -> allowed
            backend_main.app.dependency_overrides[backend_main.get_current_user] = lambda: {
                "user_id": "00000000-0000-0000-0000-000000000099",
                "username": "risk_reviewer_test",
                "role": "RISK_REVIEWER",
                "is_active": True,
            }
            sample_ev = _sample_evidence()
            with patch("backend.main.get_audio_review_evidence", return_value=sample_ev), \
                 patch.dict(os.environ, {}, clear=False):
                os.environ.pop("GEMINI_API_KEY", None)
                resp_ok = client.post("/api/batches/11111111-1111-1111-1111-111111111111/audio-review/ai-assist")
            self.assertEqual(resp_ok.status_code, 200)
            body = resp_ok.json()
            self.assertEqual(body["status"], "NOT_CONFIGURED")
            self.assertIsNone(body["ai_interpretation"])
            self.assertEqual(body["measured_evidence"]["heuristic_recommendation"], "CHALLENGE")
            self.assertFalse(body["can_approve_or_reject_payout"])
        finally:
            backend_main.app.dependency_overrides.clear()
