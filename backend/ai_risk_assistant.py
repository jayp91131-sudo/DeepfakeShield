"""
AI Risk Reviewer Assistant for DeepfakeShield.

Provides an advisory-only explanation layer for authorized RISK_REVIEWER users
using the official Google Gemini API (google-genai SDK, Interactions API).

Security & Governance Boundaries:
1. Advisory only: never modifies risk_evaluations, risk scores, or classifications.
2. Non-authoritative: never approves, rejects, or finalizes payouts, and never
   bypasses two-officer Treasury approvals.
3. Strict PII / audio isolation: only sanitized numeric/boolean/enum acoustic
   telemetry is sent to the AI provider. Raw audio bytes, beneficiary email
   addresses, legal names, credentials, and secrets are never transmitted.
4. Fail-safe: missing GEMINI_API_KEY reports NOT_CONFIGURED without fabricating
   an AI response; provider timeouts, network failures, or malformed JSON fail
   gracefully with sanitized error details.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from google import genai as _google_genai
except ImportError:  # pragma: no cover - handled gracefully at runtime
    _google_genai = None


DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"
DEFAULT_TIMEOUT_SECONDS = 15.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 60.0
MAX_WINDOWS_FOR_STATS = 64
MAX_PROMPT_INPUT_BYTES = 4096
MAX_OUTPUT_TEXT_CHARS = 4096

_SYSTEM_INSTRUCTION = (
    "You are the DeepfakeShield AI Risk Reviewer Assistant. "
    "You assist an authorized human RISK_REVIEWER by explaining deterministic "
    "DSP audio telemetry (spectral flatness, high-frequency energy ratio, WADA SNR, "
    "replay detection flags, and heuristic classification). "
    "You MUST strictly distinguish measured DSP evidence from your advisory interpretation. "
    "You have NO authority to change the risk score, override the classification, "
    "or approve/reject/finalize any payout. "
    "Respond ONLY with a valid JSON object containing these exact string/list keys: "
    '"summary" (concise 1-3 sentence explanation), '
    '"attention_reasons" (list of 1-4 concise strings explaining why the signal needs attention), '
    '"supporting_measurements" (list of 1-5 concise strings citing specific numeric/boolean measurements), '
    '"reviewer_guidance" (concise 1-2 sentence checklist for the human reviewer), '
    '"limitations_notice" (concise reminder that ACOUSTIC_FFT_HEURISTIC_V1 is heuristic and this AI output is advisory only).'
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_timeout_seconds() -> float:
    raw = os.environ.get("GEMINI_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        val = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, val))


def _resolve_model_name() -> str:
    raw = os.environ.get("GEMINI_MODEL", "").strip()
    return raw if raw else DEFAULT_GEMINI_MODEL


def is_gemini_configured() -> bool:
    return bool((os.environ.get("GEMINI_API_KEY") or "").strip())


def get_ai_assistant_status() -> Dict[str, Any]:
    """Returns non-sensitive configuration status for the AI Risk Reviewer Assistant."""
    configured = is_gemini_configured()
    return {
        "feature": "AI Risk Reviewer Assistant",
        "provider": "google_gemini",
        "sdk": "google-genai",
        "model": _resolve_model_name(),
        "configured": configured,
        "status": "CONFIGURED" if configured else "NOT_CONFIGURED",
        "advisory_only": True,
        "authority": "ADVISORY_ONLY_NO_DECISION_POWER",
    }


def _safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    if value is None:
        return default
    try:
        num = float(value)
    except (TypeError, ValueError):
        return default
    if num != num:  # NaN guard
        return default
    return round(num, 6)


def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_sanitized_audio_metadata(evidence_or_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts an explicit allowlist of non-PII, non-secret acoustic telemetry
    from either `get_audio_review_evidence()` output or `analyze_audio_instruction()` output.
    Raw audio bytes, emails, names, hashes/keys, and credentials are never included.
    """
    if "analysis" in evidence_or_analysis and isinstance(evidence_or_analysis["analysis"], dict):
        analysis = evidence_or_analysis["analysis"]
    else:
        analysis = evidence_or_analysis

    window_results = analysis.get("window_results")
    flatness_vals: List[float] = []
    hf_vals: List[float] = []

    if isinstance(window_results, list):
        for win in window_results[:MAX_WINDOWS_FOR_STATS]:
            if not isinstance(win, dict):
                continue
            feats = win.get("features")
            if not isinstance(feats, dict):
                continue
            sf = _safe_float(feats.get("spectral_flatness"))
            hf = _safe_float(feats.get("hf_ratio"))
            if sf is not None:
                flatness_vals.append(sf)
            if hf is not None:
                hf_vals.append(hf)

    direct_sf = _safe_float(analysis.get("spectral_flatness"))
    direct_hf = _safe_float(analysis.get("hf_ratio"))

    sf_mean = round(sum(flatness_vals) / len(flatness_vals), 6) if flatness_vals else direct_sf
    sf_max = round(max(flatness_vals), 6) if flatness_vals else direct_sf
    hf_mean = round(sum(hf_vals) / len(hf_vals), 6) if hf_vals else direct_hf
    hf_max = round(max(hf_vals), 6) if hf_vals else direct_hf

    replay_detected = bool(analysis.get("replay_detected", False))
    sha256_replay = analysis.get("sha256_replay_detected")
    fp_replay = analysis.get("acoustic_fingerprint_replay_detected")

    sha256_replay_flag = bool(sha256_replay) if sha256_replay is not None else replay_detected
    fp_replay_flag = bool(fp_replay) if fp_replay is not None else replay_detected

    recommendation = str(
        analysis.get("original_ai_decision")
        or analysis.get("recommendation")
        or "UNKNOWN"
    ).strip().upper()[:32]
    policy_decision = str(
        analysis.get("original_policy_decision")
        or analysis.get("policy_decision")
        or "UNKNOWN"
    ).strip().upper()[:32]
    acoustic_signal = str(analysis.get("acoustic_signal") or "UNKNOWN").strip().upper()[:48]
    analyzer_version = str(
        analysis.get("analyzer_version")
        or analysis.get("model_version")
        or "ACOUSTIC_FFT_HEURISTIC_V1"
    ).strip()[:64]

    return {
        "analyzer_version": analyzer_version,
        "heuristic_recommendation": recommendation,
        "heuristic_policy_decision": policy_decision,
        "acoustic_signal": acoustic_signal,
        "deepfake_probability": _safe_float(analysis.get("deepfake_probability")),
        "max_window_score": _safe_float(analysis.get("max_window_score")),
        "acoustic_consistency_score": _safe_float(analysis.get("acoustic_consistency_score")),
        "wada_snr_db": _safe_float(analysis.get("wada_snr_db")),
        "spectral_flatness_mean": sf_mean,
        "spectral_flatness_max": sf_max,
        "high_frequency_energy_ratio_mean": hf_mean,
        "high_frequency_energy_ratio_max": hf_max,
        "sha256_replay_result": "REPLAY_DETECTED" if sha256_replay_flag else "NO_REPLAY",
        "acoustic_fingerprint_replay_result": "REPLAY_DETECTED" if fp_replay_flag else "NO_REPLAY",
        "voice_clone_flag": bool(analysis.get("voice_clone_flag", False)),
        "adversarial_noise_detected": bool(analysis.get("adversarial_noise_detected", False)),
        "window_count": _safe_int(analysis.get("window_count"), len(flatness_vals) or None),
    }


def _strip_markdown_fences(text: str) -> str:
    cleaned = text.strip()
    fence_match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence_match:
        return fence_match.group(1).strip()
    return cleaned


def _parse_and_validate_ai_json(raw_text: str) -> Dict[str, Any]:
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise ValueError("AI provider returned an empty response.")
    if len(raw_text) > MAX_OUTPUT_TEXT_CHARS:
        raise ValueError("AI provider response exceeded maximum allowed length.")

    cleaned = _strip_markdown_fences(raw_text)
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("AI provider response must be a JSON object.")

    required_str_keys = ("summary", "reviewer_guidance", "limitations_notice")
    required_list_keys = ("attention_reasons", "supporting_measurements")

    result: Dict[str, Any] = {}
    for key in required_str_keys:
        val = parsed.get(key)
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"AI provider response missing valid '{key}' string.")
        result[key] = val.strip()[:1000]

    for key in required_list_keys:
        val = parsed.get(key)
        if not isinstance(val, list) or not val:
            raise ValueError(f"AI provider response missing valid non-empty '{key}' list.")
        items = [str(item).strip()[:300] for item in val[:6] if str(item).strip()]
        if not items:
            raise ValueError(f"AI provider response '{key}' list contained no usable entries.")
        result[key] = items

    return result


def _sanitize_error_message(exc: Exception) -> str:
    name = type(exc).__name__
    msg = str(exc) or name
    # Redact anything resembling an API key or bearer token
    msg = re.sub(r"AIza[0-9A-Za-z\-_]{10,}", "[REDACTED_KEY]", msg)
    msg = re.sub(r"Bearer\s+[0-9A-Za-z\-_.]+", "Bearer [REDACTED]", msg, flags=re.IGNORECASE)
    return f"{name}: {msg[:240]}"


def generate_ai_risk_explanation(
    evidence_or_analysis: Dict[str, Any],
    risk_evaluation_id: Optional[str] = None,
    genai_module: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Generates a structured advisory explanation for an authorized RISK_REVIEWER
    using the Google Gemini API (Interactions API via google-genai).
    Never mutates underlying risk decisions or payout state.
    """
    measured_evidence = extract_sanitized_audio_metadata(evidence_or_analysis)
    model_name = _resolve_model_name()
    generated_at = _utc_now_iso()

    base_response: Dict[str, Any] = {
        "feature": "AI Risk Reviewer Assistant",
        "advisory_only": True,
        "can_modify_risk_score": False,
        "can_modify_classification": False,
        "can_approve_or_reject_payout": False,
        "can_bypass_treasury_approvals": False,
        "measured_evidence": measured_evidence,
        "ai_interpretation": None,
        "provenance": {
            "provider": "google_gemini",
            "sdk": "google-genai",
            "model": model_name,
            "interaction_id": None,
            "generated_at": generated_at,
            "source_risk_evaluation_id": str(risk_evaluation_id) if risk_evaluation_id else None,
            "authority": "ADVISORY_ONLY_NO_DECISION_POWER",
        },
        "error": None,
    }

    api_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    if not api_key:
        base_response["status"] = "NOT_CONFIGURED"
        base_response["configured"] = False
        base_response["error"] = "GEMINI_API_KEY is not configured in the local environment."
        return base_response

    sdk = genai_module if genai_module is not None else _google_genai
    if sdk is None:
        base_response["status"] = "ERROR"
        base_response["configured"] = True
        base_response["error"] = "google-genai SDK is not installed."
        return base_response

    payload_json = json.dumps(
        {
            "task": "Explain why this audio telemetry requires human RISK_REVIEWER attention.",
            "measured_evidence": measured_evidence,
        },
        separators=(",", ":"),
    )
    if len(payload_json.encode("utf-8")) > MAX_PROMPT_INPUT_BYTES:
        base_response["status"] = "ERROR"
        base_response["configured"] = True
        base_response["error"] = "Sanitized metadata payload exceeded bounded input size."
        return base_response

    timeout_seconds = _resolve_timeout_seconds()
    timeout_ms = int(timeout_seconds * 1000)

    try:
        client = sdk.Client(api_key=api_key, http_options={"timeout": timeout_ms})
        interaction = client.interactions.create(
            model=model_name,
            input=payload_json,
            system_instruction=_SYSTEM_INSTRUCTION,
            store=False,
        )
        raw_text = getattr(interaction, "output_text", None)
        if not raw_text:
            raise ValueError("AI provider returned no output_text.")
        parsed_interpretation = _parse_and_validate_ai_json(raw_text)
        base_response["status"] = "SUCCESS"
        base_response["configured"] = True
        base_response["ai_interpretation"] = parsed_interpretation
        base_response["provenance"]["interaction_id"] = getattr(interaction, "id", None)
        return base_response
    except Exception as exc:
        base_response["status"] = "ERROR"
        base_response["configured"] = True
        base_response["error"] = _sanitize_error_message(exc)
        return base_response
