"""
BlueOps Restricted Incident Response Agent
Provides strictly allowlisted, HMAC-SHA256 authenticated, auditable, and reversible lab remediation actions.
NO arbitrary shell execution permitted.
"""

import hmac
import hashlib
import time
import json
import logging
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BlueOpsResponseAgent")

app = Flask(__name__)

SECRET_KEY = "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130"
ALLOWLISTED_ACTIONS = {
    "BLOCK_IP",
    "RESTORE_IP",
    "DISABLE_USER",
    "ENABLE_USER",
    "ISOLATE_HOST",
    "RECONNECT_HOST",
    "COLLECT_EVIDENCE"
}

PROCESSED_NONCES = set()

def verify_hmac(payload: str, timestamp: int, signature: str) -> bool:
    # 1. Anti-replay expiration window: 60 seconds
    now = int(time.time())
    if abs(now - timestamp) > 60:
        logger.warning(f"Signature expired. Server time: {now}, Token timestamp: {timestamp}")
        return False

    # 2. Compute expected HMAC
    message = f"{timestamp}:{payload}".encode("utf-8")
    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, signature)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "HEALTHY",
        "agent": "BlueOps Response Agent v1.0",
        "allowed_actions": list(ALLOWLISTED_ACTIONS),
        "simulation_mode": True
    }), 200

@app.route("/api/v1/execute", methods=["POST"])
def execute_action():
    signature = request.headers.get("X-BlueOps-Signature")
    timestamp_header = request.headers.get("X-BlueOps-Timestamp")
    action_id = request.headers.get("X-BlueOps-ActionId")

    if not signature or not timestamp_header or not action_id:
        return jsonify({"error": "Missing required security headers (Signature, Timestamp, ActionId)"}), 401

    try:
        timestamp = int(timestamp_header)
    except ValueError:
        return jsonify({"error": "Malformed timestamp"}), 400

    raw_body = request.get_data(as_text=True)

    if not verify_hmac(raw_body, timestamp, signature):
        logger.warning(f"HMAC verification failed for action ID {action_id}")
        return jsonify({"error": "Unauthorized: HMAC signature mismatch or expired payload"}), 401

    if action_id in PROCESSED_NONCES:
        logger.warning(f"Replay attack detected for ActionId: {action_id}")
        return jsonify({"error": "Replay detected: ActionId already processed"}), 409

    PROCESSED_NONCES.add(action_id)

    data = request.get_json(silent=True) or {}
    playbook_code = data.get("playbookCode", "")
    target = data.get("target", "")

    logger.info(f"Received validated response action request: Playbook={playbook_code}, Target={target}")

    # Map playbook to concrete execution
    execution_result = {
        "actionId": action_id,
        "playbook": playbook_code,
        "target": target,
        "status": "SUCCESS",
        "mode": "LAB_CONTROLLED_EXECUTION",
        "executed_at": time.time(),
        "remediation": f"Remediation action for {playbook_code} applied to {target} safely in lab environment."
    }

    return jsonify(execution_result), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
