import time
import hmac
import hashlib
import json
import pytest

try:
    from src.agent import app, SECRET_KEY, PROCESSED_NONCES, evict_expired_nonces
except ImportError:
    from agent import app, SECRET_KEY, PROCESSED_NONCES, evict_expired_nonces

@pytest.fixture
def client():
    app.config["TESTING"] = True
    PROCESSED_NONCES.clear()
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "HEALTHY"
    assert "BLOCK_IP" in data["allowed_actions"]

def test_valid_hmac_action_execution(client):
    payload = json.dumps({"actionUuid": "act-101", "playbookCode": "P001", "target": "198.51.100.24"})
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-101"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["status"] == "SUCCESS"

def test_tampered_signature_rejected(client):
    payload = json.dumps({"actionUuid": "act-102", "playbookCode": "P001", "target": "198.51.100.24"})
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": "invalid-signature",
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-102"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 401

def test_expired_timestamp_rejected(client):
    payload = json.dumps({"actionUuid": "act-103", "playbookCode": "P001", "target": "198.51.100.24"})
    expired_timestamp = int(time.time()) - 120  # 2 minutes ago (> 60s window)
    message = f"{expired_timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(expired_timestamp),
        "X-BlueOps-ActionId": "act-103"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 401
    assert "expired" in res.get_json()["error"].lower()

def test_unauthorized_action_rejected(client):
    payload = json.dumps({"actionUuid": "act-104", "action": "ARBITRARY_SHELL_EXEC", "target": "198.51.100.24"})
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-104"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 400
    assert "REJECTED_UNAUTHORIZED_ACTION" in res.get_json()["error"]

def test_command_injection_target_rejected(client):
    payload = json.dumps({"actionUuid": "act-105", "playbookCode": "P001", "target": "198.51.100.24; rm -rf /"})
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-105"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 400
    assert "REJECTED_INVALID_PARAMETER" in res.get_json()["error"]

def test_cli_option_injection_target_rejected(client):
    # Tests that leading hyphens (CLI flags like --help, -o) are rejected
    payload = json.dumps({"actionUuid": "act-106", "playbookCode": "P002", "target": "--help"})
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-106"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 400
    assert "REJECTED_INVALID_PARAMETER" in res.get_json()["error"]
    assert "hyphen" in res.get_json()["message"].lower()

def test_whitespace_argument_injection_rejected(client):
    payload = json.dumps({"actionUuid": "act-107", "playbookCode": "P001", "target": "198.51.100.24 10.0.0.1"})
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-107"
    }

    res = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res.status_code == 400
    assert "REJECTED_INVALID_PARAMETER" in res.get_json()["error"]
    assert "whitespace" in res.get_json()["message"].lower()

def test_replay_attack_rejected(client):
    payload = json.dumps({"actionUuid": "act-108", "playbookCode": "P001", "target": "198.51.100.24"})
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": "act-108"
    }

    # First attempt: succeeds
    res1 = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res1.status_code == 200

    # Second attempt with same ActionId: rejected as replay
    res2 = client.post("/api/v1/execute", data=payload, headers=headers)
    assert res2.status_code == 409
    assert "Replay detected" in res2.get_json()["error"]


def _signed_headers(payload: str, action_id: str) -> dict:
    timestamp = int(time.time())
    message = f"{timestamp}:{payload}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-BlueOps-Signature": sig,
        "X-BlueOps-Timestamp": str(timestamp),
        "X-BlueOps-ActionId": action_id,
    }


def test_catalog_act_codes_supported_act001_to_act007(client):
    cases = [
        ("ACT-001", "P001", "BLOCK_IP", "198.51.100.24"),
        ("ACT-002", "P002", "DISABLE_USER", "corp.analyst"),
        ("ACT-003", "P003", "ISOLATE_HOST", "WIN-PROD-01"),
        ("ACT-004", "P004", "RESTORE_IP", "198.51.100.24"),
        ("ACT-005", "P005", "ENABLE_USER", "corp.analyst"),
        ("ACT-006", "P006", "RECONNECT_HOST", "WIN-PROD-01"),
        ("ACT-007", "P007", "COLLECT_EVIDENCE", "WIN-PROD-01"),
    ]
    for idx, (action_code, playbook_code, expected_action, target) in enumerate(cases):
        action_id = f"act-cat-{idx}"
        payload = json.dumps({
            "actionUuid": action_id,
            "actionCode": action_code,
            "playbookCode": playbook_code,
            "action": expected_action,
            "target": target,
        })
        res = client.post("/api/v1/execute", data=payload, headers=_signed_headers(payload, action_id))
        assert res.status_code == 200
        body = res.get_json()
        assert body["action"] == expected_action
        assert body["simulation"] is True


def test_unsupported_act008_rejected(client):
    payload = json.dumps({
        "actionUuid": "act-008-test",
        "actionCode": "ACT-008",
        "target": "WIN-PROD-01",
    })
    res = client.post("/api/v1/execute", data=payload, headers=_signed_headers(payload, "act-008-test"))
    assert res.status_code == 400
    assert res.get_json()["error"] == "REJECTED_UNAUTHORIZED_ACTION"


def test_mismatched_action_and_catalog_rejected(client):
    payload = json.dumps({
        "actionUuid": "act-mismatch",
        "actionCode": "ACT-001",
        "action": "ISOLATE_HOST",
        "target": "WIN-PROD-01",
    })
    res = client.post("/api/v1/execute", data=payload, headers=_signed_headers(payload, "act-mismatch"))
    assert res.status_code == 400
    assert res.get_json()["error"] == "REJECTED_UNAUTHORIZED_ACTION"


def test_resolve_execution_mode_simulation_flag_takes_precedence(monkeypatch):
    try:
        from src.agent import resolve_execution_mode
    except ImportError:
        from agent import resolve_execution_mode

    monkeypatch.setenv("EXECUTION_MODE", "LIVE")
    monkeypatch.setenv("RESPONSE_AGENT_SIMULATION_MODE", "true")
    assert resolve_execution_mode() == "SIMULATION"

    monkeypatch.setenv("RESPONSE_AGENT_SIMULATION_MODE", "false")
    assert resolve_execution_mode() == "LIVE"


def test_drivers_remain_hypothetical_even_when_live_flags_set(monkeypatch):
    try:
        from src.drivers import get_execution_driver, LinuxDriver, WindowsDriver
    except ImportError:
        from drivers import get_execution_driver, LinuxDriver, WindowsDriver

    monkeypatch.setenv("BLUEOPS_ALLOW_LIVE_HOST_DISRUPTION", "true")
    monkeypatch.setenv("EXECUTION_MODE", "LIVE")

    for drv in (get_execution_driver("LIVE"), LinuxDriver(), WindowsDriver()):
        outcome = drv.execute("BLOCK_IP", "198.51.100.24")
        assert outcome["status"] == "SUCCESS"
        assert outcome["mode"] == "HYPOTHETICAL_LAB_SANDBOX"
        assert outcome["hypothetical"] is True
