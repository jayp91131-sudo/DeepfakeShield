#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — PayPal Sandbox REST Client & Deterministic Simulator
Milestone: V10.1.3 Hackathon Delivery Sprint

Interacts with PayPal Developer Platform (US Sandbox).
Strictly uses Sandbox endpoints. Never transfers real funds.

Modes:
- SANDBOX_API: Genuine calls to https://api-m.sandbox.paypal.com using OAuth 2.0 Client Credentials.
- SIMULATOR: Deterministic in-memory simulation for local testing, offline validation, and fault injection.

Security & Safety:
- Never logs or exposes Client Secret or Bearer Access Token.
- Fails closed if SANDBOX_API is configured without valid credentials.
- Retains idempotency via immutable PayPal-Request-Id header.
"""

import os
import uuid
import time
import json
import base64
import hashlib
import threading
import requests
from typing import Dict, Any, Tuple, Optional

# Load project-root .env if present
try:
    from backend.env_loader import load_env_file, get_env_diagnostics
    load_env_file()
except Exception:
    def load_env_file(*args, **kwargs):
        return False
    def get_env_diagnostics(*args, **kwargs):
        return {"dotenv_path": ".env", "dotenv_exists": False, "dotenv_loaded": False, "conflicts": [], "obsolete_keys": []}

PAYPAL_PROVIDER_MODE_SIMULATOR = "SIMULATOR"
PAYPAL_PROVIDER_MODE_SANDBOX_API = "SANDBOX_API"
VALID_PROVIDER_MODES = {PAYPAL_PROVIDER_MODE_SIMULATOR, PAYPAL_PROVIDER_MODE_SANDBOX_API}
DEFAULT_SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"

# Explicit provider telemetry states
STATE_SIMULATOR_ACTIVE = "SIMULATOR_ACTIVE"
STATE_SANDBOX_API_UNCONFIGURED = "SANDBOX_API_UNCONFIGURED"
STATE_SANDBOX_API_AUTH_FAILED = "SANDBOX_API_AUTH_FAILED"
STATE_SANDBOX_API_ONLINE = "SANDBOX_API_ONLINE"
STATE_SANDBOX_API_DEGRADED = "SANDBOX_API_DEGRADED"

# Thread-safe shared OAuth 2.0 Bearer token cache scoped strictly by (base_url, sha256(client_id:client_secret))
_OAUTH_CACHE_GUARD = threading.Lock()
_OAUTH_KEY_LOCKS: Dict[Tuple[str, str], threading.Lock] = {}
_OAUTH_TOKEN_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}


def clear_paypal_token_cache() -> None:
    """Clears the process-wide shared PayPal OAuth token cache."""
    with _OAUTH_CACHE_GUARD:
        _OAUTH_TOKEN_CACHE.clear()


def _make_token_cache_key(base_url: str, client_id: str, client_secret: str) -> Tuple[str, str]:
    cred_digest = hashlib.sha256(f"{client_id}:{client_secret}".encode("utf-8")).hexdigest()
    return (base_url.rstrip("/"), cred_digest)


def _get_key_lock(cache_key: Tuple[str, str]) -> threading.Lock:
    with _OAUTH_CACHE_GUARD:
        lock = _OAUTH_KEY_LOCKS.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            _OAUTH_KEY_LOCKS[cache_key] = lock
        return lock


# In-memory simulator registry for deterministic idempotency and crash recovery verification
_SIMULATED_IDEMPOTENCY_STORE: Dict[str, Tuple[int, Dict[str, Any], str]] = {}
_SIMULATED_SENDER_BATCH_MAP: Dict[str, str] = {}  # sender_batch_id -> paypal_request_id
_SIMULATED_BATCH_ITEMS: Dict[str, list] = {}  # payout_batch_id -> items list

def reset_paypal_simulator():
    """Resets simulator state for clean idempotency test runs."""
    _SIMULATED_IDEMPOTENCY_STORE.clear()
    _SIMULATED_SENDER_BATCH_MAP.clear()
    _SIMULATED_BATCH_ITEMS.clear()


class PayPalClientConfigurationError(RuntimeError):
    """Raised when SANDBOX_API mode is selected but required credentials or configs are missing."""
    pass


class PayPalOAuthError(RuntimeError):
    """Raised when pre-submission OAuth 2.0 token acquisition fails prior to payout dispatch."""
    def __init__(
        self,
        message: str,
        http_status: Optional[int] = None,
        error_code: str = "oauth_error",
        debug_id: Optional[str] = None,
        is_transient_network: bool = False,
    ):
        super().__init__(message)
        self.http_status = http_status
        self.error_code = error_code
        self.debug_id = debug_id
        self.is_transient_network = is_transient_network


class PayPalClient:
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        mode: Optional[str] = None
    ):
        load_env_file()
        self.env_diagnostics = get_env_diagnostics()

        self.client_id = client_id if client_id is not None else os.environ.get("PAYPAL_CLIENT_ID", "")
        self.client_secret = client_secret if client_secret is not None else os.environ.get("PAYPAL_CLIENT_SECRET", "")
        raw_base = base_url if base_url is not None else (os.environ.get("PAYPAL_BASE_URL") or DEFAULT_SANDBOX_BASE_URL)
        self.base_url = raw_base.strip().rstrip("/")

        # Explicit mode resolution (ignores obsolete PAYPAL_ENV)
        raw_mode = mode if mode is not None else (os.environ.get("PAYPAL_PROVIDER_MODE") or PAYPAL_PROVIDER_MODE_SIMULATOR)
        self.mode = raw_mode.strip().upper()

        self.access_token: Optional[str] = None
        self.token_expires_at: float = 0.0
        self.last_oauth_status: Optional[int] = None
        self.last_oauth_debug_id: Optional[str] = None
        self.last_token_type: Optional[str] = None
        self.last_token_app_id: Optional[str] = None
        self.last_token_expires_in: Optional[int] = None
        self.last_token_scope_count: Optional[int] = None

    def __repr__(self) -> str:
        return (
            f"<PayPalClient mode={self.mode!r} base_url={self.base_url!r} "
            f"credentials_configured={self.is_live_sandbox_configured()}>"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def is_sandbox_api_mode(self) -> bool:
        return self.mode == PAYPAL_PROVIDER_MODE_SANDBOX_API

    def is_live_sandbox_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def validate_configuration(self) -> None:
        """Validates canonical configuration; fails closed on invalid mode or missing SANDBOX_API credentials."""
        if self.mode not in VALID_PROVIDER_MODES:
            raise PayPalClientConfigurationError(
                f"Invalid PAYPAL_PROVIDER_MODE '{self.mode}'. Expected 'SANDBOX_API' or 'SIMULATOR'."
            )

        if self.is_sandbox_api_mode:
            if not self.base_url.startswith("https://"):
                raise PayPalClientConfigurationError(
                    f"Invalid PAYPAL_BASE_URL '{self.base_url}'. SANDBOX_API mode requires an HTTPS PayPal endpoint."
                )
            if not self.client_id or not self.client_secret:
                raise PayPalClientConfigurationError(
                    "PAYPAL_PROVIDER_MODE is set to 'SANDBOX_API' but PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET "
                    "is missing. Configuration must fail closed; silent fallback to SIMULATOR is strictly disabled."
                )

    def get_access_token(self, force_refresh: bool = False) -> str:
        """
        Obtains or returns cached OAuth 2.0 Bearer token via client_credentials grant.
        Uses Basic Authentication: base64(client_id:client_secret) and shares cached tokens
        safely across callers matching (base_url, client_id, client_secret).
        """
        if not self.is_sandbox_api_mode:
            self.validate_configuration()
            return "MOCK_SANDBOX_TOKEN"

        self.validate_configuration()

        # Check existing instance cached token with safety buffer before expiry
        if not force_refresh and self.access_token and time.time() < self.token_expires_at:
            return self.access_token

        cache_key = _make_token_cache_key(self.base_url, self.client_id, self.client_secret)
        key_lock = _get_key_lock(cache_key)

        with key_lock:
            if not force_refresh:
                with _OAUTH_CACHE_GUARD:
                    cached = _OAUTH_TOKEN_CACHE.get(cache_key)
                if cached and time.time() < cached["expires_at"]:
                    self.access_token = cached["access_token"]
                    self.token_expires_at = cached["expires_at"]
                    self.last_oauth_status = cached["oauth_status"]
                    self.last_oauth_debug_id = cached["debug_id"]
                    self.last_token_type = cached["token_type"]
                    self.last_token_app_id = cached["app_id"]
                    self.last_token_expires_in = cached["expires_in"]
                    self.last_token_scope_count = cached["scope_count"]
                    return self.access_token

            auth_str = f"{self.client_id}:{self.client_secret}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
            headers = {
                "Authorization": f"Basic {b64_auth}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            data = {"grant_type": "client_credentials"}

            try:
                resp = requests.post(
                    f"{self.base_url}/v1/oauth2/token",
                    headers=headers,
                    data=data,
                    timeout=12
                )
            except requests.exceptions.RequestException:
                self.last_oauth_status = None
                self.last_oauth_debug_id = None
                # Mask credentials; never expose raw request details
                raise PayPalOAuthError(
                    f"Failed to connect to PayPal OAuth token endpoint ({self.base_url}): network error",
                    http_status=None,
                    error_code="oauth_network_error",
                    debug_id=None,
                    is_transient_network=True,
                ) from None

            self.last_oauth_status = resp.status_code
            self.last_oauth_debug_id = (
                resp.headers.get("PayPal-Debug-Id")
                or resp.headers.get("Paypal-Debug-Id")
                or resp.headers.get("paypal-debug-id")
            ) if getattr(resp, "headers", None) else None

            if resp.status_code != 200:
                try:
                    err_data = resp.json()
                    err_code = err_data.get("error") or "oauth_error"
                    err_desc = err_data.get("error_description") or err_code or "Authentication failed"
                except Exception:
                    err_code = "http_error"
                    err_desc = f"HTTP {resp.status_code}"
                debug_suffix = f" [debug_id={self.last_oauth_debug_id}]" if self.last_oauth_debug_id else ""
                raise PayPalOAuthError(
                    f"PayPal OAuth 2.0 authentication failed [{resp.status_code} {err_code}]{debug_suffix}: {err_desc}",
                    http_status=resp.status_code,
                    error_code=str(err_code),
                    debug_id=self.last_oauth_debug_id,
                    is_transient_network=(resp.status_code >= 500 or resp.status_code == 429),
                )

            token_data = resp.json()
            token = token_data.get("access_token")
            if not token:
                raise PayPalOAuthError(
                    "PayPal OAuth 2.0 response did not contain an access_token",
                    http_status=502,
                    error_code="missing_access_token",
                    debug_id=self.last_oauth_debug_id,
                    is_transient_network=True,
                )

            expires_in = int(token_data.get("expires_in", 3600))
            refresh_buffer = 60 if expires_in > 120 else max(expires_in // 4, 1)
            expires_at = time.time() + max(expires_in - refresh_buffer, 0)

            self.access_token = token
            self.token_expires_at = expires_at
            self.last_token_type = token_data.get("token_type", "Bearer")
            self.last_token_app_id = token_data.get("app_id")
            self.last_token_expires_in = expires_in
            scope_str = token_data.get("scope", "")
            self.last_token_scope_count = len([s for s in str(scope_str).split() if s]) if scope_str else 0

            with _OAUTH_CACHE_GUARD:
                _OAUTH_TOKEN_CACHE[cache_key] = {
                    "access_token": self.access_token,
                    "expires_at": self.token_expires_at,
                    "oauth_status": self.last_oauth_status,
                    "debug_id": self.last_oauth_debug_id,
                    "token_type": self.last_token_type,
                    "app_id": self.last_token_app_id,
                    "expires_in": self.last_token_expires_in,
                    "scope_count": self.last_token_scope_count,
                }
            return self.access_token

    def check_api_connectivity(self) -> Dict[str, Any]:
        """
        Safe health-check helper that tests PayPal API connectivity without transferring funds.
        Represents explicit states:
        - SIMULATOR_ACTIVE
        - SANDBOX_API_UNCONFIGURED
        - SANDBOX_API_AUTH_FAILED
        - SANDBOX_API_ONLINE
        - SANDBOX_API_DEGRADED
        Never reveals secrets or access tokens.
        """
        base_diag = {
            "dotenv_path": self.env_diagnostics.get("dotenv_path"),
            "dotenv_loaded": bool(self.env_diagnostics.get("dotenv_loaded")),
            "env_conflicts": [c["key"] for c in self.env_diagnostics.get("conflicts", [])],
            "obsolete_env_vars": list(self.env_diagnostics.get("obsolete_keys", [])),
        }

        if self.mode not in VALID_PROVIDER_MODES:
            return {
                "mode": self.mode,
                "provider_state": STATE_SANDBOX_API_DEGRADED,
                "provider_mode": f"[{self.mode}]",
                "is_simulator": False,
                "configured": False,
                "oauth_connected": False,
                "oauth_status": "UNCONFIGURED",
                "api_reachable": False,
                "connection_status": STATE_SANDBOX_API_DEGRADED,
                "connection_label": f"PayPal Provider Config: DEGRADED (Invalid mode {self.mode})",
                "endpoint": self.base_url,
                **base_diag,
                "message": f"Invalid PAYPAL_PROVIDER_MODE '{self.mode}'. Expected SANDBOX_API or SIMULATOR."
            }

        if not self.is_sandbox_api_mode:
            return {
                "mode": PAYPAL_PROVIDER_MODE_SIMULATOR,
                "provider_state": STATE_SIMULATOR_ACTIVE,
                "provider_mode": "[PAYPAL_SANDBOX_SIMULATOR]",
                "is_simulator": True,
                "configured": True,
                "oauth_connected": False,
                "oauth_status": "NOT_APPLICABLE",
                "api_reachable": True,
                "connection_status": "SIMULATED_LOCAL",
                "connection_label": "PayPal Sandbox Simulator: ACTIVE (Local Fallback)",
                "endpoint": "local://simulator",
                **base_diag,
                "message": "Local deterministic simulator active (Offline / Fallback mode)"
            }

        is_conf = self.is_live_sandbox_configured()
        if not is_conf:
            return {
                "mode": PAYPAL_PROVIDER_MODE_SANDBOX_API,
                "provider_state": STATE_SANDBOX_API_UNCONFIGURED,
                "provider_mode": "[PAYPAL_SANDBOX_API]",
                "is_simulator": False,
                "configured": False,
                "oauth_connected": False,
                "oauth_status": "UNCONFIGURED",
                "api_reachable": False,
                "connection_status": STATE_SANDBOX_API_UNCONFIGURED,
                "connection_label": "PayPal Developer Sandbox: UNCONFIGURED (Credentials Missing)",
                "endpoint": self.base_url,
                **base_diag,
                "message": "PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET is missing from environment"
            }

        try:
            self.validate_configuration()
            token = self.get_access_token()
            return {
                "mode": PAYPAL_PROVIDER_MODE_SANDBOX_API,
                "provider_state": STATE_SANDBOX_API_ONLINE,
                "provider_mode": "[PAYPAL_SANDBOX_API]",
                "is_simulator": False,
                "configured": True,
                "oauth_connected": bool(token),
                "oauth_status": "AUTHENTICATED",
                "api_reachable": True,
                "connection_status": STATE_SANDBOX_API_ONLINE,
                "connection_label": "PayPal Developer Sandbox: ONLINE",
                "endpoint": self.base_url,
                "oauth_http_status": self.last_oauth_status,
                "paypal_debug_id": self.last_oauth_debug_id,
                "token_type": self.last_token_type,
                "token_expires_in": self.last_token_expires_in,
                "token_cached": bool(self.access_token and time.time() < self.token_expires_at),
                "app_id": self.last_token_app_id,
                **base_diag,
                "message": "PayPal Developer Sandbox connected successfully"
            }
        except PayPalOAuthError as oauth_err:
            is_degraded = oauth_err.is_transient_network or (
                oauth_err.http_status is not None and oauth_err.http_status >= 500
            )
            state = STATE_SANDBOX_API_DEGRADED if is_degraded else STATE_SANDBOX_API_AUTH_FAILED
            oauth_st = "DEGRADED" if is_degraded else "AUTH_FAILED"
            label = (
                "PayPal Developer Sandbox: DEGRADED (OAuth Endpoint Unreachable)"
                if is_degraded
                else "PayPal Developer Sandbox: AUTH_FAILED (OAuth Rejected)"
            )
            return {
                "mode": PAYPAL_PROVIDER_MODE_SANDBOX_API,
                "provider_state": state,
                "provider_mode": "[PAYPAL_SANDBOX_API]",
                "is_simulator": False,
                "configured": is_conf,
                "oauth_connected": False,
                "oauth_status": oauth_st,
                "api_reachable": False,
                "connection_status": state,
                "connection_label": label,
                "endpoint": self.base_url,
                "oauth_http_status": self.last_oauth_status,
                "paypal_debug_id": self.last_oauth_debug_id,
                **base_diag,
                "message": str(oauth_err)
            }
        except Exception as e:
            return {
                "mode": PAYPAL_PROVIDER_MODE_SANDBOX_API,
                "provider_state": STATE_SANDBOX_API_DEGRADED,
                "provider_mode": "[PAYPAL_SANDBOX_API]",
                "is_simulator": False,
                "configured": is_conf,
                "oauth_connected": False,
                "oauth_status": "DEGRADED",
                "api_reachable": False,
                "connection_status": STATE_SANDBOX_API_DEGRADED,
                "connection_label": "PayPal Developer Sandbox: DEGRADED (Configuration/Connection Error)",
                "endpoint": self.base_url,
                "oauth_http_status": self.last_oauth_status,
                "paypal_debug_id": self.last_oauth_debug_id,
                **base_diag,
                "message": f"Connection check failed: {str(e)}"
            }

    def submit_payout(
        self,
        batch_id: str,
        paypal_request_id: str,
        payload_dict: Dict[str, Any],
        force_network_timeout: bool = False
    ) -> Tuple[int, Dict[str, Any], str]:
        """
        Submits payout batch to PayPal.
        Pre-submission OAuth errors fail cleanly before /v1/payments/payouts POST and are
        never classified as ambiguous payout submissions.
        Returns: (http_status, response_dict, provider_mode_label).
        """
        if force_network_timeout:
            return (
                504,
                {
                    "error": "GATEWAY_TIMEOUT",
                    "message": "Read timed out connecting to PayPal Sandbox endpoint",
                    "provider": "PAYPAL_SANDBOX_SIMULATOR" if not self.is_sandbox_api_mode else "PAYPAL_SANDBOX_API"
                },
                "[PAYPAL_SANDBOX_SIMULATOR_NETWORK_TIMEOUT]" if not self.is_sandbox_api_mode else "[PAYPAL_SANDBOX_API_TIMEOUT]"
            )

        if self.is_sandbox_api_mode:
            self.validate_configuration()

            # Step 1: Acquire OAuth token BEFORE any payout POST attempt
            try:
                token = self.get_access_token()
            except PayPalOAuthError as oauth_err:
                precheck_status = oauth_err.http_status if oauth_err.http_status in (400, 401, 403) else 424
                return (
                    precheck_status,
                    {
                        "error": "PAYPAL_OAUTH_PRECHECK_FAILED",
                        "oauth_error_code": oauth_err.error_code,
                        "message": str(oauth_err),
                        "payout_post_attempted": False,
                        "ambiguous": False,
                        "paypal_debug_id": oauth_err.debug_id,
                    },
                    "[PAYPAL_SANDBOX_API_AUTH_FAILED]",
                )

            # Step 2: Execute /v1/payments/payouts POST
            try:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "PayPal-Request-Id": paypal_request_id,
                    "Accept": "application/json"
                }
                resp = requests.post(
                    f"{self.base_url}/v1/payments/payouts",
                    headers=headers,
                    json=payload_dict,
                    timeout=15
                )

                try:
                    resp_data = resp.json()
                except Exception:
                    resp_data = {"raw_response": resp.text, "status_code": resp.status_code}

                return resp.status_code, resp_data, "[PAYPAL_SANDBOX_API]"

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                # Ambiguous network timeout / drop after payout POST attempt MUST NEVER become success
                return (
                    504,
                    {"error": "GATEWAY_TIMEOUT", "message": f"Network drop or timeout connecting to PayPal Sandbox: {e}"},
                    "[PAYPAL_SANDBOX_API_TIMEOUT]"
                )
            except Exception as e:
                return (
                    500,
                    {"error": "PAYPAL_CLIENT_ERROR", "message": f"Unexpected client error: {type(e).__name__}"},
                    "[PAYPAL_SANDBOX_API_ERROR]"
                )
        else:
            # Deterministic Local Simulator Mode
            return self._simulate_successful_submission(batch_id, payload_dict, paypal_request_id=paypal_request_id)

    def _simulate_successful_submission(
        self,
        batch_id: str,
        payload_dict: Dict[str, Any],
        fallback_reason: Optional[str] = None,
        paypal_request_id: Optional[str] = None
    ) -> Tuple[int, Dict[str, Any], str]:
        """
        Faithful simulation of official PayPal Sandbox HTTP 201 response.
        Enforces true provider-side idempotency:
        - If paypal_request_id was previously accepted: returns identical 201 response without reprocessing.
        - If sender_batch_id was previously used under a DIFFERENT request_id: returns 400 DUPLICATE_BATCH_ID.
        """
        sender_header = payload_dict.get("sender_batch_header", {})
        sender_batch_id = sender_header.get("sender_batch_id", f"SB_SENDER_{batch_id[:8]}")

        # Provider-Side Idempotency: exact replay check
        if paypal_request_id and paypal_request_id in _SIMULATED_IDEMPOTENCY_STORE:
            cached_status, cached_resp, _ = _SIMULATED_IDEMPOTENCY_STORE[paypal_request_id]
            return (cached_status, cached_resp, "[PAYPAL_SANDBOX_SIMULATOR_IDEMPOTENT_REPLAY]")

        # Duplicate sender_batch_id rejection under different request id
        if sender_batch_id in _SIMULATED_SENDER_BATCH_MAP:
            prior_req_id = _SIMULATED_SENDER_BATCH_MAP[sender_batch_id]
            if prior_req_id != paypal_request_id:
                rejection = {
                    "name": "DUPLICATE_BATCH_ID",
                    "message": f"Batch with sender_batch_id '{sender_batch_id}' has already been processed.",
                    "details": [{"field": "sender_batch_id", "issue": "Duplicate batch identifier"}]
                }
                return (400, rejection, "[PAYPAL_SANDBOX_SIMULATOR_REJECT]")

        payout_batch_id = f"SB-BATCH-{uuid.uuid4().hex[:12].upper()}"
        items = payload_dict.get("items", [])
        total_cents = sum(int(float(it["amount"]["value"]) * 100) for it in items) if items else 0

        simulated_response = {
            "batch_header": {
                "payout_batch_id": payout_batch_id,
                "batch_status": "PENDING",
                "time_created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sender_batch_header": {
                    "sender_batch_id": sender_batch_id,
                    "email_subject": sender_header.get("email_subject", "You have a payout!")
                },
                "amount": {
                    "currency": "USD",
                    "value": f"{total_cents / 100:.2f}"
                },
                "fees": {
                    "currency": "USD",
                    "value": f"{len(items) * 0.25:.2f}"
                }
            },
            "links": [
                {
                    "href": f"https://api-m.sandbox.paypal.com/v1/payments/payouts/{payout_batch_id}",
                    "rel": "self",
                    "method": "GET",
                    "encType": "application/json"
                }
            ],
            "simulator_meta": {
                "mode": "PAYPAL_SANDBOX_SIMULATOR",
                "fallback_reason": fallback_reason or "Local deterministic simulator mode active"
            }
        }
        res_tuple = (201, simulated_response, "[PAYPAL_SANDBOX_SIMULATOR]")
        if paypal_request_id:
            _SIMULATED_IDEMPOTENCY_STORE[paypal_request_id] = res_tuple
        if sender_batch_id:
            _SIMULATED_SENDER_BATCH_MAP[sender_batch_id] = paypal_request_id
        _SIMULATED_BATCH_ITEMS[payout_batch_id] = items
        return res_tuple

    def lookup_by_request_id(self, paypal_request_id: str) -> Optional[Dict[str, Any]]:
        """Queries provider for existing payout created under the given idempotency key."""
        if self.is_sandbox_api_mode:
            # PayPal does not offer a direct GET by Request-Id, but in-flight lookups can query cached response if known
            pass
        if paypal_request_id in _SIMULATED_IDEMPOTENCY_STORE:
            return _SIMULATED_IDEMPOTENCY_STORE[paypal_request_id][1]
        return None

    def lookup_by_sender_batch_id(self, sender_batch_id: str) -> Optional[Dict[str, Any]]:
        """Queries provider for existing payout created under the given sender_batch_id."""
        if sender_batch_id in _SIMULATED_SENDER_BATCH_MAP:
            req_id = _SIMULATED_SENDER_BATCH_MAP[sender_batch_id]
            return self.lookup_by_request_id(req_id)
        return None

    def fetch_payout_status(self, payout_batch_id: str) -> Tuple[int, Dict[str, Any]]:
        """
        Queries status of an existing payout batch.
        In SANDBOX_API mode: performs GET /v1/payments/payouts/{payout_batch_id}.
        In SIMULATOR mode: synthesizes item-level status responses based on submitted items.
        """
        if self.is_sandbox_api_mode and not payout_batch_id.startswith("SB-BATCH-"):
            try:
                token = self.get_access_token()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
                resp = requests.get(
                    f"{self.base_url}/v1/payments/payouts/{payout_batch_id}",
                    headers=headers,
                    timeout=12
                )
                if resp.status_code == 200:
                    return resp.status_code, resp.json()
                else:
                    try:
                        return resp.status_code, resp.json()
                    except Exception:
                        return resp.status_code, {"error": "FETCH_STATUS_FAILED", "status_code": resp.status_code}
            except Exception as e:
                return 500, {"error": "FETCH_STATUS_EXCEPTION", "message": str(e)}

        # Simulator status return reflecting submitted batch items
        submitted_items = _SIMULATED_BATCH_ITEMS.get(payout_batch_id, [])
        if submitted_items:
            provider_items = [
                {
                    "payout_item_id": f"SB-ITEM-{idx}-{uuid.uuid4().hex[:8].upper()}",
                    "sender_item_id": it.get("sender_item_id", f"item-{idx}"),
                    "transaction_status": "SUCCESS",
                    "activity_id": f"ACT-{uuid.uuid4().hex[:8].upper()}"
                }
                for idx, it in enumerate(submitted_items)
            ]
        else:
            provider_items = [
                {
                    "payout_item_id": f"SB-ITEM-{uuid.uuid4().hex[:10].upper()}",
                    "transaction_status": "SUCCESS",
                    "activity_id": f"ACT-{uuid.uuid4().hex[:8].upper()}"
                }
            ]

        return (
            200,
            {
                "batch_header": {
                    "payout_batch_id": payout_batch_id,
                    "batch_status": "SUCCESS",
                    "time_completed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                },
                "items": provider_items
            }
        )
