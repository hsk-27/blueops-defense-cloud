import time
import hmac
import hashlib
import json
import pytest

try:
    from src.agent import app, SECRET_KEY
except ImportError:
    from agent import app, SECRET_KEY

@pytest.fixture
def client():
    app.config["TESTING"] = True
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
