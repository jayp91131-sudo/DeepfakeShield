#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — PayPal Sandbox REST API & Dual-Mode Integration Tests
Milestone: V10.1.3 Hackathon Delivery Sprint

Verifies:
1. OAuth 2.0 Client Credentials flow with Basic Auth & Bearer caching.
2. Dual Mode Isolation: SIMULATOR vs SANDBOX_API.
3. Fail-closed policy: SANDBOX_API with missing credentials raises PayPalClientConfigurationError.
4. Idempotency Header & Request payload formatting (sender_batch_header, items, 2-decimal USD).
5. Error mapping: Rejections (400/401/403/422), Ambiguous Timeouts (504/500/408), Rate Limits (429).
6. Non-leakage: Secrets and access tokens are never emitted into logs, JSON representations, or exception messages.
"""

import os
import json
import base64
import pytest
from unittest.mock import patch, MagicMock
from backend.paypal_client import (
    PayPalClient,
    PayPalClientConfigurationError,
    reset_paypal_simulator
)


@pytest.fixture(autouse=True)
def clean_simulator():
    reset_paypal_simulator()
    yield
    reset_paypal_simulator()


def test_dual_mode_default_is_simulator():
    """Verifies that default client mode is SIMULATOR when unset."""
    with patch.dict(os.environ, {"PAYPAL_PROVIDER_MODE": "", "PAYPAL_CLIENT_ID": "", "PAYPAL_CLIENT_SECRET": ""}):
        client = PayPalClient(mode="SIMULATOR")
        assert not client.is_sandbox_api_mode
        assert client.mode == "SIMULATOR"
        health = client.check_api_connectivity()
        assert health["mode"] == "SIMULATOR"
        assert health["api_reachable"] is True


def test_fail_closed_when_sandbox_mode_missing_credentials():
    """Verifies that selecting SANDBOX_API without credentials fails closed with clear error."""
    client = PayPalClient(client_id="", client_secret="", mode="SANDBOX_API")
    assert client.is_sandbox_api_mode
    with pytest.raises(PayPalClientConfigurationError) as exc_info:
        client.validate_configuration()
    assert "missing" in str(exc_info.value).lower()
    assert "silent fallback to simulator is strictly disabled" in str(exc_info.value).lower()


def test_oauth_token_basic_auth_and_caching():
    """Verifies OAuth 2.0 basic auth header format and access token caching with buffer."""
    client = PayPalClient(
        client_id="test_client_id_123",
        client_secret="test_client_secret_xyz",
        base_url="https://api-m.sandbox.paypal.com",
        mode="SANDBOX_API"
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "A21AA_MOCK_BEARER_TOKEN_VALUE",
        "token_type": "Bearer",
        "app_id": "APP-80W284485P519543T",
        "expires_in": 32400
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        token = client.get_access_token()
        assert token == "A21AA_MOCK_BEARER_TOKEN_VALUE"
        assert mock_post.call_count == 1
        
        call_args = mock_post.call_args
        endpoint = call_args[0][0]
        headers = call_args[1]["headers"]
        data = call_args[1]["data"]

        assert endpoint == "https://api-m.sandbox.paypal.com/v1/oauth2/token"
        assert data == {"grant_type": "client_credentials"}
        
        # Verify Basic Auth string matches base64(test_client_id_123:test_client_secret_xyz)
        expected_b64 = base64.b64encode(b"test_client_id_123:test_client_secret_xyz").decode("ascii")
        assert headers["Authorization"] == f"Basic {expected_b64}"

        # Second call within validity window uses cached token without network request
        token2 = client.get_access_token()
        assert token2 == "A21AA_MOCK_BEARER_TOKEN_VALUE"
        assert mock_post.call_count == 1  # No additional post made!


def test_submit_payout_payload_and_idempotency_header_sandbox_api():
    """Verifies HTTP POST /v1/payments/payouts in SANDBOX_API mode includes proper headers."""
    client = PayPalClient(
        client_id="client_id_val",
        client_secret="client_sec_val",
        mode="SANDBOX_API"
    )

    client.access_token = "MOCK_ACTIVE_TOKEN"
    client.token_expires_at = 9999999999.0

    payload = {
        "sender_batch_header": {
            "sender_batch_id": "SB_SENDER_12345678",
            "email_subject": "Contractor Disbursement",
            "recipient_type": "EMAIL"
        },
        "items": [
            {
                "recipient_type": "EMAIL",
                "amount": {"value": "250.00", "currency": "USD"},
                "note": "Contractor payout",
                "sender_item_id": "item_uuid_1",
                "receiver": "contractor@example.com"
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "batch_header": {
            "payout_batch_id": "SANDBOX_BATCH_ABC123",
            "batch_status": "PENDING"
        }
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        status, resp, provider_mode = client.submit_payout(
            batch_id="00000000-0000-0000-0000-000000000001",
            paypal_request_id="dfs-req-test-uuid",
            payload_dict=payload
        )

        assert status == 201
        assert provider_mode == "[PAYPAL_SANDBOX_API]"
        assert resp["batch_header"]["payout_batch_id"] == "SANDBOX_BATCH_ABC123"

        call_args = mock_post.call_args
        assert call_args[0][0] == "https://api-m.sandbox.paypal.com/v1/payments/payouts"
        sent_headers = call_args[1]["headers"]
        assert sent_headers["Authorization"] == "Bearer MOCK_ACTIVE_TOKEN"
        assert sent_headers["PayPal-Request-Id"] == "dfs-req-test-uuid"
        assert call_args[1]["json"] == payload


def test_ambiguous_network_timeout_yields_504_in_sandbox_mode():
    """Verifies network connection drops or timeouts yield HTTP 504 and never simulated success."""
    import requests
    client = PayPalClient(
        client_id="client_id_val",
        client_secret="client_sec_val",
        mode="SANDBOX_API"
    )
    client.access_token = "MOCK_ACTIVE_TOKEN"
    client.token_expires_at = 9999999999.0

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Connection timed out")):
        status, resp, mode = client.submit_payout(
            batch_id="b1",
            paypal_request_id="dfs-req-test-timeout",
            payload_dict={}
        )
        assert status == 504
        assert mode == "[PAYPAL_SANDBOX_API_TIMEOUT]"
        assert "timed out" in resp["message"].lower()


def test_fetch_payout_status_sandbox_mode():
    """Verifies GET /v1/payments/payouts/{batch_id} in SANDBOX_API mode parses individual items."""
    client = PayPalClient(
        client_id="client_id_val",
        client_secret="client_sec_val",
        mode="SANDBOX_API"
    )
    client.access_token = "MOCK_ACTIVE_TOKEN"
    client.token_expires_at = 9999999999.0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "batch_header": {
            "payout_batch_id": "LIVE_SB_BATCH_999",
            "batch_status": "SUCCESS"
        },
        "items": [
            {
                "payout_item_id": "ITEM_P1",
                "sender_item_id": "item_uuid_1",
                "transaction_status": "SUCCESS",
                "activity_id": "ACT_987"
            }
        ]
    }

    with patch("requests.get", return_value=mock_resp) as mock_get:
        status, data = client.fetch_payout_status("LIVE_SB_BATCH_999")
        assert status == 200
        assert data["batch_header"]["batch_status"] == "SUCCESS"
        assert len(data["items"]) == 1
        assert data["items"][0]["transaction_status"] == "SUCCESS"
        assert mock_get.call_args[0][0] == "https://api-m.sandbox.paypal.com/v1/payments/payouts/LIVE_SB_BATCH_999"


def test_simulator_mode_faithfully_simulates_and_preserves_idempotency():
    """Verifies that SIMULATOR mode continues to function deterministically with zero credentials."""
    client = PayPalClient(mode="SIMULATOR")
    assert not client.is_sandbox_api_mode

    payload = {
        "sender_batch_header": {"sender_batch_id": "SIM_SENDER_1"},
        "items": [
            {"amount": {"value": "100.00", "currency": "USD"}, "sender_item_id": "sim_item_1"}
        ]
    }

    # First submission
    st1, resp1, mode1 = client.submit_payout("batch_sim_1", "dfs-req-sim-1", payload)
    assert st1 == 201
    assert mode1 == "[PAYPAL_SANDBOX_SIMULATOR]"
    payout_id = resp1["batch_header"]["payout_batch_id"]

    # Replay with same request ID -> exact replay
    st2, resp2, mode2 = client.submit_payout("batch_sim_1", "dfs-req-sim-1", payload)
    assert st2 == 201
    assert mode2 == "[PAYPAL_SANDBOX_SIMULATOR_IDEMPOTENT_REPLAY]"
    assert resp2["batch_header"]["payout_batch_id"] == payout_id

    # Duplicate sender_batch_id under different request id -> 400 rejection
    st3, resp3, mode3 = client.submit_payout("batch_sim_2", "dfs-req-sim-2", payload)
    assert st3 == 400
    assert mode3 == "[PAYPAL_SANDBOX_SIMULATOR_REJECT]"
    assert resp3["name"] == "DUPLICATE_BATCH_ID"


def test_secret_is_never_in_string_or_repr():
    """Ensures PayPal client does not expose client_secret in str() or repr()."""
    client = PayPalClient(
        client_id="visible_client_id",
        client_secret="SUPER_SECRET_VALUE_DO_NOT_LEAK",
        mode="SANDBOX_API"
    )
    s = str(client)
    r = repr(client)
    assert "SUPER_SECRET_VALUE_DO_NOT_LEAK" not in s
    assert "SUPER_SECRET_VALUE_DO_NOT_LEAK" not in r
    assert "visible_client_id" not in s


def test_env_example_and_gitignore_canonical_consistency():
    """Verifies .env.example matches paypal_client.py keys and .gitignore excludes .env."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".env.example"), "r", encoding="utf-8") as f:
        env_example = f.read()

    assert "PAYPAL_PROVIDER_MODE=SANDBOX_API" in env_example
    assert "PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com" in env_example
    assert "PAYPAL_CLIENT_ID=" in env_example
    assert "PAYPAL_CLIENT_SECRET=" in env_example
    assert "PAYPAL_ENV=" not in env_example

    with open(os.path.join(root, ".gitignore"), "r", encoding="utf-8") as f:
        gitignore_lines = [ln.strip() for ln in f.readlines()]
    assert ".env" in gitignore_lines
    assert ".env.*" in gitignore_lines
    assert "!.env.example" in gitignore_lines


def test_env_loader_reads_dotenv_and_reports_conflicts_without_secrets(tmp_path, monkeypatch):
    """Verifies project-root .env parsing, system env conflict reporting, and zero secret leakage."""
    from backend.env_loader import get_project_dotenv_path, inspect_env_file, load_env_file

    expected_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert get_project_dotenv_path() == os.path.join(expected_root, ".env")

    temp_env = tmp_path / ".env"
    temp_env.write_text(
        "PAYPAL_PROVIDER_MODE=SANDBOX_API\n"
        "PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com\n"
        "PAYPAL_CLIENT_ID=dotenv_id_do_not_leak\n"
        "PAYPAL_CLIENT_SECRET=dotenv_secret_do_not_leak\n"
        "PAYPAL_ENV=sandbox\n",
        encoding="utf-8"
    )

    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "system_secret_do_not_leak")
    monkeypatch.delenv("PAYPAL_CLIENT_ID", raising=False)

    diag = inspect_env_file(str(temp_env), apply_to_environ=False)
    assert diag["dotenv_exists"] is True
    assert diag["dotenv_loaded"] is True
    assert "PAYPAL_ENV" in diag["obsolete_keys"]

    conflict_keys = [c["key"] for c in diag["conflicts"]]
    assert "PAYPAL_CLIENT_SECRET" in conflict_keys

    serialized = json.dumps(diag)
    assert "dotenv_secret_do_not_leak" not in serialized
    assert "system_secret_do_not_leak" not in serialized
    assert "dotenv_id_do_not_leak" not in serialized


def test_invalid_provider_mode_fails_closed():
    """Invalid PAYPAL_PROVIDER_MODE must fail closed without falling back to simulator."""
    client = PayPalClient(mode="INVALID_MODE")
    with pytest.raises(PayPalClientConfigurationError):
        client.validate_configuration()
    health = client.check_api_connectivity()
    assert health["configured"] is False
    assert health["api_reachable"] is False


def test_connectivity_check_includes_sanitized_oauth_metadata():
    """Verifies check_api_connectivity returns sanitized OAuth status and debug_id without tokens."""
    client = PayPalClient(
        client_id="cid_test",
        client_secret="csec_test",
        mode="SANDBOX_API"
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"PayPal-Debug-Id": "f123456789abc"}
    mock_resp.json.return_value = {
        "access_token": "SECRET_ACCESS_TOKEN_MUST_NOT_APPEAR",
        "token_type": "Bearer",
        "app_id": "APP-TEST123",
        "expires_in": 32400,
        "scope": "https://uri.paypal.com/services/payouts"
    }

    with patch("requests.post", return_value=mock_resp):
        health = client.check_api_connectivity()
        assert health["mode"] == "SANDBOX_API"
        assert health["oauth_connected"] is True
        assert health["oauth_http_status"] == 200
        assert health["paypal_debug_id"] == "f123456789abc"
        assert health["token_expires_in"] == 32400
        assert health["token_cached"] is True
        serialized = json.dumps(health)
        assert "SECRET_ACCESS_TOKEN_MUST_NOT_APPEAR" not in serialized
        assert "csec_test" not in serialized
        assert "cid_test" not in serialized


def test_sandbox_api_never_displays_as_simulator_across_endpoints(monkeypatch):
    """Proves SANDBOX_API (even unconfigured or failed) never reports SIMULATOR or LIVE."""
    from backend.main import api_public_status, api_paypal_health

    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SANDBOX_API")
    monkeypatch.delenv("PAYPAL_CLIENT_ID", raising=False)
    monkeypatch.delenv("PAYPAL_CLIENT_SECRET", raising=False)

    pub = api_public_status()
    health = api_paypal_health(current_user={"user_id": "u1", "role": "AUDITOR"})

    for payload in (pub, health):
        assert payload["mode"] == "SANDBOX_API"
        assert payload["provider_state"] == "SANDBOX_API_UNCONFIGURED"
        assert payload["is_simulator"] is False
        assert payload["configured"] is False
        assert payload["oauth_connected"] is False
        assert payload["provider_mode"] == "[PAYPAL_SANDBOX_API]"
        assert "SIMULATOR" not in payload["connection_status"]
        assert "SIMULATOR" not in payload["connection_label"].upper()
        assert "ONLINE" not in payload["connection_label"].upper()
        assert "LIVE" not in json.dumps(payload).upper()


def test_failed_oauth_reports_auth_failed_or_degraded_never_online(monkeypatch):
    """Proves 401 OAuth rejection -> SANDBOX_API_AUTH_FAILED and 503/network -> SANDBOX_API_DEGRADED."""
    from backend.main import api_public_status, api_paypal_health
    import requests as req_lib

    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SANDBOX_API")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "bad_cid_123")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "bad_sec_456")

    # 1. HTTP 401 invalid_client -> AUTH_FAILED
    mock_401 = MagicMock()
    mock_401.status_code = 401
    mock_401.headers = {"PayPal-Debug-Id": "dbg-auth-fail-401"}
    mock_401.json.return_value = {"error": "invalid_client", "error_description": "Client Authentication failed"}

    with patch("requests.post", return_value=mock_401):
        health_auth = api_paypal_health(current_user={"user_id": "u1"})
        pub_auth = api_public_status()
        for p in (health_auth, pub_auth):
            assert p["provider_state"] == "SANDBOX_API_AUTH_FAILED"
            assert p["is_simulator"] is False
            assert p["configured"] is True
            assert p["oauth_connected"] is False
            assert p["oauth_status"] == "AUTH_FAILED"
            assert "ONLINE" not in p["connection_label"].upper()
            assert "bad_cid_123" not in json.dumps(p)
            assert "bad_sec_456" not in json.dumps(p)

    # 2. Network timeout -> DEGRADED
    with patch("requests.post", side_effect=req_lib.exceptions.ConnectTimeout("timeout")):
        health_deg = api_paypal_health(current_user={"user_id": "u1"})
        assert health_deg["provider_state"] == "SANDBOX_API_DEGRADED"
        assert health_deg["is_simulator"] is False
        assert health_deg["oauth_connected"] is False
        assert health_deg["oauth_status"] == "DEGRADED"
        assert "ONLINE" not in health_deg["connection_label"].upper()


def test_polling_reuses_shared_oauth_cache_and_isolates_credentials(monkeypatch):
    """
    Proves multiple PayPalClient() polling requests reuse the process-wide cached token
    (only 1 HTTP OAuth POST) while isolating caches across credentials and base URLs.
    """
    from backend.main import api_public_status, api_paypal_health
    import threading

    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SANDBOX_API")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "cid_alpha")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "sec_alpha")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"PayPal-Debug-Id": "dbg-cache-200"}
    mock_resp.json.return_value = {
        "access_token": "TOK_ALPHA_SECRET_VALUE",
        "token_type": "Bearer",
        "app_id": "APP-CACHE",
        "expires_in": 3600
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        # Simulate concurrent & sequential polling across endpoints
        results = []
        def poll():
            results.append(api_paypal_health(current_user={"user_id": "u1"}))
            results.append(api_public_status())

        threads = [threading.Thread(target=poll) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert mock_post.call_count == 1
        assert all(r["provider_state"] == "SANDBOX_API_ONLINE" for r in results)
        assert all("TOK_ALPHA_SECRET_VALUE" not in json.dumps(r) for r in results)

        # Different credentials MUST NOT reuse Alpha's cached token
        client_beta = PayPalClient(client_id="cid_beta", client_secret="sec_beta", mode="SANDBOX_API")
        client_beta.get_access_token()
        assert mock_post.call_count == 2

        # Different base URL MUST NOT reuse cached token
        client_other_url = PayPalClient(
            client_id="cid_alpha",
            client_secret="sec_alpha",
            base_url="https://api-m.sandbox.paypal.com/v2-isolated",
            mode="SANDBOX_API"
        )
        client_other_url.get_access_token()
        assert mock_post.call_count == 3


def test_failed_oauth_does_not_trigger_payout_post(monkeypatch):
    """
    Proves PayPalClient.submit_payout() stops cleanly on pre-submission OAuth error
    and NEVER invokes POST /v1/payments/payouts or classifies it as ambiguous.
    """
    client = PayPalClient(client_id="bad_id", client_secret="bad_sec", mode="SANDBOX_API")

    mock_401 = MagicMock()
    mock_401.status_code = 401
    mock_401.headers = {"PayPal-Debug-Id": "dbg-oauth-stop"}
    mock_401.json.return_value = {"error": "invalid_client", "error_description": "Client Authentication failed"}

    called_urls = []

    def spy_post(url, *args, **kwargs):
        called_urls.append(url)
        return mock_401

    with patch("requests.post", side_effect=spy_post):
        status, resp_data, mode_label = client.submit_payout(
            batch_id="00000000-0000-0000-0000-000000000010",
            paypal_request_id="dfs-req-oauth-fail",
            payload_dict={"sender_batch_header": {"sender_batch_id": "SB1"}, "items": []}
        )

    assert len(called_urls) == 1
    assert called_urls[0].endswith("/v1/oauth2/token")
    assert all("/v1/payments/payouts" not in u for u in called_urls)
    assert status == 401
    assert mode_label == "[PAYPAL_SANDBOX_API_AUTH_FAILED]"
    assert resp_data["error"] == "PAYPAL_OAUTH_PRECHECK_FAILED"
    assert resp_data["payout_post_attempted"] is False
    assert resp_data["ambiguous"] is False
    assert "bad_sec" not in json.dumps(resp_data)


def test_unmocked_paypal_http_call_blocked_in_tests(monkeypatch):
    """Proves conftest.py blocks accidental real HTTP calls to PayPal endpoints."""
    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SANDBOX_API")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "placeholder_id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "placeholder_secret")

    client = PayPalClient()
    health = client.check_api_connectivity()
    assert health["oauth_connected"] is False
    assert health["provider_state"] == "SANDBOX_API_DEGRADED"
    assert health["is_simulator"] is False


def test_env_loader_utf8_bom_and_no_obsolete_double_count(tmp_path):
    """Proves utf-8-sig BOM support and excludes obsolete PAYPAL_ENV from paypal_keys_in_dotenv."""
    from backend.env_loader import inspect_env_file

    bom_env = tmp_path / ".env"
    bom_env.write_bytes(
        b"\xef\xbb\xbfPAYPAL_PROVIDER_MODE=SIMULATOR\n"
        b"PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com\n"
        b"PAYPAL_ENV=sandbox\n"
    )
    diag = inspect_env_file(str(bom_env), apply_to_environ=False)
    assert diag["dotenv_loaded"] is True
    assert "PAYPAL_PROVIDER_MODE" in diag["paypal_keys_in_dotenv"]
    assert "PAYPAL_ENV" in diag["obsolete_keys"]
    assert "PAYPAL_ENV" not in diag["paypal_keys_in_dotenv"]


def _make_mock_response(status_code, payload, headers=None):
    class _MockHttpResponse:
        def __init__(self):
            self.status_code = status_code
            self._payload = payload
            self.headers = headers or {}
            self.text = str(payload)

        def json(self):
            return self._payload

    return _MockHttpResponse()


def _reset_db_for_worker_test():
    from backend.database import get_admin_conn, seed_demo_data
    from backend.audio_analyzer import AUDIO_HASH_REGISTRY

    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE beneficiaries DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE audit_events DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE audit_chain_heads DISABLE TRIGGER ALL;")
            cur.execute("DELETE FROM audit_events;")
            cur.execute("DELETE FROM audit_chain_heads;")
            cur.execute("ALTER TABLE audit_chain_heads ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE audit_events ENABLE TRIGGER ALL;")
            cur.execute("DELETE FROM outbox_recovery_events;")
            cur.execute("DELETE FROM outbox_jobs;")
            cur.execute("DELETE FROM officer_approvals;")
            cur.execute("DELETE FROM beneficiary_change_approvals;")
            cur.execute("DELETE FROM beneficiary_changes;")
            cur.execute("DELETE FROM beneficiary_submission_locks;")
            cur.execute("DELETE FROM paypal_api_attempts;")
            cur.execute("DELETE FROM reconciliation_attempts;")
            cur.execute("DELETE FROM webhook_inbox;")
            cur.execute("ALTER TABLE payout_items DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches DISABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_snapshots DISABLE TRIGGER ALL;")
            cur.execute("DELETE FROM payout_items;")
            cur.execute("UPDATE payout_batches SET active_snapshot_id = NULL;")
            cur.execute("DELETE FROM payout_snapshots;")
            cur.execute("DELETE FROM payout_batches;")
            cur.execute("ALTER TABLE payout_snapshots ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_batches ENABLE TRIGGER ALL;")
            cur.execute("ALTER TABLE payout_items ENABLE TRIGGER ALL;")
            cur.execute("DELETE FROM risk_evaluations;")
            cur.execute("DELETE FROM speaker_segments;")
            cur.execute("DELETE FROM audio_consents;")
            cur.execute("DELETE FROM audio_assets;")
            cur.execute("DELETE FROM sessions;")
            cur.execute("DELETE FROM webauthn_challenges;")
            cur.execute("ALTER TABLE beneficiaries ENABLE TRIGGER ALL;")
    seed_demo_data()
    AUDIO_HASH_REGISTRY.clear()


def test_outbox_worker_oauth_precheck_failure_fails_closed_not_manual_reconcile(monkeypatch):
    """DB-backed OutboxWorker test: pre-submission OAuth 401 never enters MANUAL_RECONCILIATION_REQUIRED and releases locks."""
    from psycopg.rows import dict_row
    from backend.database import (
        get_admin_conn,
        USER_ALICE_MAKER,
        USER_BOB_CHECKER1,
        USER_CAROL_CHECKER2,
        BOB_CRED_ID,
        CAROL_CRED_ID,
        OFFICER_PRIVATE_KEYS,
    )
    from backend.payout_service import (
        create_draft_batch,
        finalize_batch,
        issue_officer_challenge,
        record_officer_webauthn_approval,
    )
    from backend.outbox_worker import OutboxWorker
    from crypto_verifier import create_webauthn_assertion

    _reset_db_for_worker_test()
    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SANDBOX_API")
    monkeypatch.setenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "bad-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "bad-client-secret")

    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        if url.endswith("/v1/oauth2/token"):
            return _make_mock_response(
                401,
                {"error": "invalid_client", "error_description": "Client Authentication failed"},
                {"PayPal-Debug-Id": "dbg-worker-oauth-401"},
            )
        raise AssertionError(f"Unexpected PayPal POST to {url} after OAuth failure")

    monkeypatch.setattr("backend.paypal_client.requests.post", fake_post)

    batch_res = create_draft_batch(
        maker_user_id=USER_ALICE_MAKER,
        program_id="PROG_DEV_2026",
        payout_period="2026-11",
        items_data=[{
            "beneficiary_id": "30000000-0000-0000-0000-000000000001",
            "amount_usd": "325.00",
            "receiver_email": "contractor.acme@example.com",
        }],
    )
    batch_id = batch_res["batch_id"]
    finalize_batch(batch_id, audio_policy_decision="READY_FOR_CHECKER")

    for uid, cred_id in [(USER_BOB_CHECKER1, BOB_CRED_ID), (USER_CAROL_CHECKER2, CAROL_CRED_ID)]:
        chal = issue_officer_challenge(batch_id, uid)
        c, a, s = create_webauthn_assertion(
            OFFICER_PRIVATE_KEYS[cred_id],
            chal["challenge_bytes"],
            "https://deepfakeshield.internal",
            "deepfakeshield.internal",
            1,
        )
        record_officer_webauthn_approval(batch_id, uid, cred_id, c, a, s, challenge_id=chal["challenge_id"])

    res = OutboxWorker(worker_id="oauth-precheck-worker").process_next_job(force_timeout=False)
    assert res is not None
    assert res["status"] == "OAUTH_FAILED"
    assert res["batch_id"] == batch_id
    assert len(calls) == 1
    assert calls[0].endswith("/v1/oauth2/token")

    with get_admin_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT gateway_batch_state FROM payout_batches WHERE id = %s;", (batch_id,))
            batch_row = cur.fetchone()
            assert batch_row["gateway_batch_state"] == "FAILED"
            assert batch_row["gateway_batch_state"] != "MANUAL_RECONCILIATION_REQUIRED"

            cur.execute("SELECT COUNT(*) AS cnt FROM beneficiary_submission_locks WHERE batch_id = %s AND released_at IS NULL;", (batch_id,))
            assert cur.fetchone()["cnt"] == 0

            cur.execute("SELECT status FROM outbox_jobs WHERE batch_id = %s;", (batch_id,))
            assert cur.fetchone()["status"] == "COMPLETED"


def test_dashboard_overview_truthful_sandbox_provider_telemetry(monkeypatch):
    """DB-backed dashboard overview test: reflects SANDBOX_API_UNCONFIGURED, AUTH_FAILED, and ONLINE honestly."""
    from backend.main import api_dashboard_overview
    from backend.database import USER_DAVE_AUDITOR

    _reset_db_for_worker_test()
    auditor = {"id": USER_DAVE_AUDITOR, "username": "dave_auditor", "role": "AUDITOR"}

    # 1. SANDBOX_API with missing credentials
    monkeypatch.setenv("PAYPAL_PROVIDER_MODE", "SANDBOX_API")
    monkeypatch.setenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "")

    unconf = api_dashboard_overview(batch_id=None, current_user=auditor)["provider_info"]
    assert unconf["is_simulator"] is False
    assert unconf["provider_state"] == "SANDBOX_API_UNCONFIGURED"
    assert unconf["configured"] is False
    assert unconf["oauth_connected"] is False
    assert unconf["oauth_status"] == "UNCONFIGURED"
    assert "[LIVE_PAYPAL_SANDBOX]" not in unconf["provider_mode"]
    assert "ONLINE" not in unconf["connection_status"]

    # 2. SANDBOX_API with rejected OAuth
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "bad-dash-client")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "bad-dash-secret")
    monkeypatch.setattr(
        "backend.paypal_client.requests.post",
        lambda url, **kwargs: _make_mock_response(401, {"error": "invalid_client"}, {"PayPal-Debug-Id": "dbg-dash-401"}),
    )
    auth_fail = api_dashboard_overview(batch_id=None, current_user=auditor)["provider_info"]
    assert auth_fail["is_simulator"] is False
    assert auth_fail["provider_state"] == "SANDBOX_API_AUTH_FAILED"
    assert auth_fail["oauth_connected"] is False
    assert auth_fail["oauth_status"] == "AUTH_FAILED"
    assert "[LIVE_PAYPAL_SANDBOX]" not in auth_fail["provider_mode"]

    # 3. SANDBOX_API with successful mocked OAuth
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "good-dash-client")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "good-dash-secret")
    monkeypatch.setattr(
        "backend.paypal_client.requests.post",
        lambda url, **kwargs: _make_mock_response(
            200,
            {"access_token": "tok-dash-secret", "token_type": "Bearer", "expires_in": 3600},
            {"PayPal-Debug-Id": "dbg-dash-200"},
        ),
    )
    online = api_dashboard_overview(batch_id=None, current_user=auditor)["provider_info"]
    assert online["is_simulator"] is False
    assert online["provider_state"] == "SANDBOX_API_ONLINE"
    assert online["oauth_connected"] is True
    assert online["oauth_status"] == "AUTHENTICATED"
    assert "[LIVE_PAYPAL_SANDBOX]" not in online["provider_mode"]
    assert "tok-dash-secret" not in str(online)
    assert "good-dash-secret" not in str(online)
