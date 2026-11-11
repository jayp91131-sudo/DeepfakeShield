import os
import pytest
import requests
from backend.database import (
    get_admin_conn,
    seed_demo_data,
    USER_ALICE_MAKER,
    USER_BOB_CHECKER1,
    USER_CAROL_CHECKER2,
    USER_DAVE_AUDITOR,
    USER_EVE_UNAUTHORIZED,
    BOB_CRED_ID,
    CAROL_CRED_ID
)

BASE_URL = "http://127.0.0.1:8000"

PASSWORDS = {
    "alice_ap_maker": "alice_secure_maker_pass_2026",
    "bob_checker": "bob_yubikey_officer_pass_2026",
    "carol_checker_two": "carol_titan_officer_pass_2026",
    "dave_auditor": "dave_read_only_auditor_pass_2026",
    "eve_unauthorized": "eve_unauthorized_clerk_pass_2026"
}

def login_user(username, password=None):
    pw = password or PASSWORDS[username]
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={"username": username, "password": pw})
    return resp

def get_token(username):
    resp = login_user(username)
    assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
    return resp.json()["access_token"]

def test_interactive_controls_sidebar_and_buttons():
    """Tests each interactive control endpoint and state transition."""
    # Ensure fresh demo data is present and outbox is clear of stale jobs
    seed_demo_data()
    with get_admin_conn(autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM outbox_recovery_events;")
            cur.execute("DELETE FROM outbox_jobs;")

    # Clear registry so presets aren't flagged as cross-test replay attacks
    reg_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audio_hash_registry.json")
    if os.path.exists(reg_file):
        try:
            os.remove(reg_file)
        except Exception:
            pass

    # 1. Login with Alice
    tok_alice = get_token("alice_ap_maker")
    headers_alice = {"Authorization": f"Bearer {tok_alice}"}

    # 2. Audio Analysis control (Clean preset)
    res_audio = requests.post(f"{BASE_URL}/api/audio/analyze", data={"sample_preset": "clean_executive"}, headers=headers_alice)
    assert res_audio.status_code == 200
    audio_data = res_audio.json()
    assert audio_data["voice_clone_flag"] is False
    assert audio_data["deepfake_probability"] < 0.50

    # 3. Audio Analysis control (Deepfake preset)
    res_spoof = requests.post(f"{BASE_URL}/api/audio/analyze", data={"sample_preset": "deepfake_clone"}, headers=headers_alice)
    assert res_spoof.status_code == 200
    spoof_data = res_spoof.json()
    assert spoof_data["voice_clone_flag"] is True
    assert spoof_data["deepfake_probability"] >= 0.50

    # 4. Beneficiaries Directory Refresh control
    res_bens = requests.get(f"{BASE_URL}/api/beneficiaries", headers=headers_alice)
    assert res_bens.status_code == 200
    bens = res_bens.json()
    assert len(bens) >= 3

    # 5. Create Draft Batch modal form control
    items = [
        {"beneficiary_id": bens[0]["id"], "amount_usd": "1250.00", "receiver_email": "contractor.acme@example.com"}
    ]
    res_batch = requests.post(f"{BASE_URL}/api/batches/create", json={
        "program_id": "PROG_DEV_2026",
        "payout_period": "2026-11",
        "items": items,
        "audio_analysis": audio_data
    }, headers=headers_alice)
    assert res_batch.status_code == 200
    batch_id = res_batch.json()["batch"]["batch_id"]

    # 6. Finalize Envelope control
    res_fin = requests.post(f"{BASE_URL}/api/batches/{batch_id}/finalize", json={"audio_policy_decision": "READY_FOR_CHECKER"}, headers=headers_alice)
    assert res_fin.status_code == 200

    # 7. Dashboard Overview Refresh control
    res_dash = requests.get(f"{BASE_URL}/api/dashboard/overview?batch_id={batch_id}", headers=headers_alice)
    assert res_dash.status_code == 200
    dash = res_dash.json()
    assert dash["active_batch"]["id"] == batch_id
    assert dash["active_batch"]["gateway_batch_state"] == "READY_FOR_CHECKER"

    # 8. Sign as Bob control
    tok_bob = get_token("bob_checker")
    headers_bob = {"Authorization": f"Bearer {tok_bob}"}
    res_chal_bob = requests.post(f"{BASE_URL}/api/batches/{batch_id}/webauthn/challenge", headers=headers_bob)
    assert res_chal_bob.status_code == 200
    chal_bob = res_chal_bob.json()["challenge_id"]

    res_app_bob = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={
        "credential_id": BOB_CRED_ID,
        "challenge_id": chal_bob,
        "mock_simulation": True
    }, headers=headers_bob)
    assert res_app_bob.status_code == 200

    # 9. Sign as Carol control
    tok_carol = get_token("carol_checker_two")
    headers_carol = {"Authorization": f"Bearer {tok_carol}"}
    res_chal_carol = requests.post(f"{BASE_URL}/api/batches/{batch_id}/webauthn/challenge", headers=headers_carol)
    assert res_chal_carol.status_code == 200
    chal_carol = res_chal_carol.json()["challenge_id"]

    res_app_carol = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={
        "credential_id": CAROL_CRED_ID,
        "challenge_id": chal_carol,
        "mock_simulation": True
    }, headers=headers_carol)
    assert res_app_carol.status_code == 200

    # 10. Dispatch Worker control
    res_worker = requests.post(f"{BASE_URL}/api/outbox/process", headers=headers_bob)
    assert res_worker.status_code == 200
    w_data = res_worker.json()
    assert w_data["status"] in ("SETTLED", "COMPLETED")
    assert w_data["payout_batch_id"].startswith("SB-BATCH-")

def test_persona_switching_authentication_and_session_lifecycle():
    """
    Tests persona authentication transitions and session security:
    - Alice to Bob
    - Bob to Carol
    - Carol to Dave
    - Eve attempting privileged actions
    - Session reuse after logout
    """
    # 1. Alice to Bob transition
    # Invalid password for Bob fails
    bad_login = login_user("bob_checker", password="wrong_password_attempt")
    assert bad_login.status_code == 401, "Switching to Bob with bad credentials must fail closed"

    # Valid login for Bob succeeds
    tok_bob = get_token("bob_checker")
    headers_bob = {"Authorization": f"Bearer {tok_bob}"}

    # Bob can view dashboard
    dash_bob = requests.get(f"{BASE_URL}/api/dashboard/overview", headers=headers_bob)
    assert dash_bob.status_code == 200

    # 2. Bob to Carol transition
    tok_carol = get_token("carol_checker_two")
    headers_carol = {"Authorization": f"Bearer {tok_carol}"}
    dash_carol = requests.get(f"{BASE_URL}/api/dashboard/overview", headers=headers_carol)
    assert dash_carol.status_code == 200

    # 3. Carol to Dave transition (Auditor)
    tok_dave = get_token("dave_auditor")
    headers_dave = {"Authorization": f"Bearer {tok_dave}"}
    dash_dave = requests.get(f"{BASE_URL}/api/dashboard/overview", headers=headers_dave)
    assert dash_dave.status_code == 200

    # Dave cannot create batches
    dave_create = requests.post(f"{BASE_URL}/api/batches/create", json={"program_id": "P", "payout_period": "2026-11", "items": []}, headers=headers_dave)
    assert dave_create.status_code == 403, "Dave as AUDITOR must be forbidden from creating batches"

    # 4. Eve attempting privileged actions
    tok_eve = get_token("eve_unauthorized")
    headers_eve = {"Authorization": f"Bearer {tok_eve}"}

    # Eve cannot process outbox
    eve_worker = requests.post(f"{BASE_URL}/api/outbox/process", headers=headers_eve)
    assert eve_worker.status_code in (401, 403), "Eve must be forbidden from processing outbox"

    # 5. Session reuse after logout
    # Logout Bob
    logout_res = requests.post(f"{BASE_URL}/api/auth/logout", headers=headers_bob)
    assert logout_res.status_code == 200
    assert logout_res.json()["status"] == "LOGGED_OUT"

    # Attempt to reuse Bob's logged out token
    reused_dash = requests.get(f"{BASE_URL}/api/dashboard/overview", headers=headers_bob)
    assert reused_dash.status_code == 401, "Reusing revoked session token must return HTTP 401 Unauthorized"
    assert "revoked" in reused_dash.text.lower() or "unauthorized" in reused_dash.text.lower()
