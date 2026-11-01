import time
import hmac
import hashlib
import json
import pytest
from src.agent import app, SECRET_KEY

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
