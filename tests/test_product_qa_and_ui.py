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

def get_token(username):
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
    return resp.json()["access_token"]

def test_static_html_navigation_sections_and_honest_labeling():
    """Verifies all navigation anchors, sections, and honest heuristic labeling in static/index.html."""
    html_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Verify navigation anchors match section IDs
    expected_sections = [
        "overview",
        "batches",
        "voice",
        "approvals",
        "beneficiaries",
        "reconciliation",
        "audit",
        "settings"
    ]
    for sec in expected_sections:
        assert f'href="#{sec}"' in content, f"Missing sidebar link for #{sec}"
        assert f'id="{sec}"' in content, f"Missing target section element id='{sec}'"

    # 2. Verify honest acoustic heuristic labeling (no false neural weight claims)
    assert "ACOUSTIC_FFT_HEURISTIC_V1" in content
    assert "Spectral Contrast • Rule-based" in content or "Spectral Heuristic" in content
    assert "AASIST Classifier v10.1 Active" not in content, "Found outdated claim of active neural AASIST weights in sidebar!"

    # 3. Verify interactive controls exist
    assert "signAsBobInteractive" in content
    assert "signAsCarolInteractive" in content
    assert "dispatchWorkerInteractive" in content
    assert "runInteractiveVoiceTest" in content
    assert "openNewBatchModal" in content

    # 4. Verify responsive drawer toggle exists
    assert "mobile-nav-toggle" in content
    assert "toggleSidebar" in content

def test_user_journey_persona_matrix():
    """Tests the 6 user journeys: Maker, Checker 1, Checker 2, Worker, Auditor, Unauthorized."""
    tok_alice = get_token("alice_ap_maker")
    tok_bob = get_token("bob_checker")
    tok_carol = get_token("carol_checker_two")
    tok_dave = get_token("dave_auditor")
    tok_eve = get_token("eve_unauthorized")

    # 1. Alice (AP Maker): Can create batch and finalize
    r = requests.post(f"{BASE_URL}/api/audio/analyze", data={"sample_preset": "clean_executive"}, headers={"Authorization": f"Bearer {tok_alice}"})
    assert r.status_code == 200
    audio_res = r.json()

    bens = requests.get(f"{BASE_URL}/api/beneficiaries", headers={"Authorization": f"Bearer {tok_alice}"}).json()
    assert len(bens) >= 3

    b_res = requests.post(f"{BASE_URL}/api/batches/create", json={
        "program_id": "PROG_DEV_2026",
        "payout_period": "2026-11",
        "items": [{"beneficiary_id": bens[0]["id"], "amount_usd": "1000.00", "receiver_email": "contractor.acme@example.com"}],
        "audio_analysis": audio_res
    }, headers={"Authorization": f"Bearer {tok_alice}"}).json()
    batch_id = b_res["batch"]["batch_id"]

    # Alice finalizes
    fin_res = requests.post(f"{BASE_URL}/api/batches/{batch_id}/finalize", json={"audio_policy_decision": "READY_FOR_CHECKER"}, headers={"Authorization": f"Bearer {tok_alice}"})
    assert fin_res.status_code == 200

    # 2. Alice CANNOT approve batch (Maker cannot be Checker)
    alice_app = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={"credential_id": BOB_CRED_ID, "mock_simulation": True}, headers={"Authorization": f"Bearer {tok_alice}"})
    assert alice_app.status_code == 403, "Alice as AP_CLERK should not be permitted to execute officer approval"

    # 3. Eve (Unauthorized): Cannot approve or view Alice's batch
    eve_app = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={"credential_id": BOB_CRED_ID, "mock_simulation": True}, headers={"Authorization": f"Bearer {tok_eve}"})
    assert eve_app.status_code in (401, 403)

    # 4. Bob (Checker 1): Can approve
    bob_app = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={"credential_id": BOB_CRED_ID, "mock_simulation": True}, headers={"Authorization": f"Bearer {tok_bob}"})
    assert bob_app.status_code == 200

    # Bob cannot approve twice
    bob_app_dup = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={"credential_id": BOB_CRED_ID, "mock_simulation": True}, headers={"Authorization": f"Bearer {tok_bob}"})
    assert bob_app_dup.status_code in (400, 409)

    # 5. Carol (Checker 2): Can approve and meet 2-of-2 threshold
    carol_app = requests.post(f"{BASE_URL}/api/batches/{batch_id}/approve", json={"credential_id": CAROL_CRED_ID, "mock_simulation": True}, headers={"Authorization": f"Bearer {tok_carol}"})
    assert carol_app.status_code == 200

    # 6. Dave (Auditor): Can read overview, but CANNOT approve or create batches
    dave_view = requests.get(f"{BASE_URL}/api/dashboard/overview?batch_id={batch_id}", headers={"Authorization": f"Bearer {tok_dave}"})
    assert dave_view.status_code == 200
    assert dave_view.json()["approval_count"] == 2

    dave_create = requests.post(f"{BASE_URL}/api/batches/create", json={"program_id": "P", "payout_period": "2026-11", "items": []}, headers={"Authorization": f"Bearer {tok_dave}"})
    assert dave_create.status_code == 403

    # 7. Payment Worker: Processes outbox job
    worker_res = requests.post(f"{BASE_URL}/api/outbox/process", headers={"Authorization": f"Bearer {tok_bob}"})
    assert worker_res.status_code == 200
    assert worker_res.json()["status"] in ("SETTLED", "COMPLETED")
