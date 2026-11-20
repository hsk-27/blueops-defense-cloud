"""
BlueOps Restricted Incident Response Agent (SEC-002)
Provides strictly allowlisted, HMAC-SHA256 authenticated, auditable, and reversible lab remediation actions.
NO arbitrary shell execution or CLI argument injection permitted.
"""

import os
import re
import hmac
import hashlib
import time
import json
import logging
import threading
from flask import Flask, request, jsonify

try:
    from src.drivers import get_execution_driver
except ImportError:
    from drivers import get_execution_driver

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BlueOpsResponseAgent")

app = Flask(__name__)

SECRET_KEY = os.environ.get("RESPONSE_AGENT_SECRET", "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130")
EXECUTION_MODE = os.environ.get("EXECUTION_MODE", "SIMULATION")
driver = get_execution_driver(EXECUTION_MODE)

ALLOWLISTED_ACTIONS = {
    "BLOCK_IP",
    "RESTORE_IP",
    "DISABLE_USER",
    "ENABLE_USER",
    "ISOLATE_HOST",
    "RECONNECT_HOST",
    "COLLECT_EVIDENCE"
}

PLAYBOOK_TO_ACTION = {
    "P001": "BLOCK_IP",
    "P002": "DISABLE_USER",
    "P003": "ISOLATE_HOST",
    "P004": "RESTORE_IP",
    "P005": "ENABLE_USER",
    "P006": "RECONNECT_HOST",
    "P007": "COLLECT_EVIDENCE"
}

FORBIDDEN_TARGET_PATTERN = re.compile(r"[;&|`$><\r\n]")
IP_CIDR_PATTERN = re.compile(r"^[0-9a-fA-F.:/]+$")
POSIX_USER_PATTERN = re.compile(r"^[a-zA-Z0-9._][a-zA-Z0-9._-]*$")
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")

# Sliding-window nonce cache mapping: action_id -> received_timestamp
PROCESSED_NONCES: dict[str, float] = {}
NONCE_VALIDITY_WINDOW_SECONDS = 65.0  # 60s request window + 5s clock skew grace
MAX_NONCE_CACHE_CAPACITY = 10000
NONCE_LOCK = threading.Lock()

def evict_expired_nonces_locked(current_time: float) -> None:
    """Purges nonces older than the sliding validity window. Must be called while holding NONCE_LOCK."""
    cutoff = current_time - NONCE_VALIDITY_WINDOW_SECONDS
    expired_keys = [k for k, ts in PROCESSED_NONCES.items() if ts < cutoff]
    for k in expired_keys:
        del PROCESSED_NONCES[k]
    # Bound memory capacity under high-volume flood attacks within the window
    if len(PROCESSED_NONCES) > MAX_NONCE_CACHE_CAPACITY:
        sorted_keys = sorted(PROCESSED_NONCES.keys(), key=lambda k: PROCESSED_NONCES[k])
        for k in sorted_keys[:max(1, len(sorted_keys) // 5)]:
            del PROCESSED_NONCES[k]

def evict_expired_nonces(current_time: float) -> None:
    """Thread-safe wrapper to evict expired nonces."""
    with NONCE_LOCK:
        evict_expired_nonces_locked(current_time)

def check_and_register_nonce(action_id: str, current_time: float) -> bool:
    """
    Atomically checks if a nonce is fresh and registers it if not present.
    Returns True if nonce is valid and registered, False if it was already processed (replay).
    """
    with NONCE_LOCK:
        evict_expired_nonces_locked(current_time)
        if action_id in PROCESSED_NONCES:
            return False
        PROCESSED_NONCES[action_id] = current_time
        return True

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

def validate_target_parameter(action: str, target: str) -> tuple[bool, str]:
    """
    Strict validation of the target parameter.
    Blocks shell injection, argument/option injection (leading '-'), whitespace,
    and format violations per action category.
    """
    if not target:
        return False, "Target parameter is required and cannot be empty"

    if len(target) > 256:
        return False, "Target parameter exceeds maximum permitted length (256 bytes)"

    # Defense against CLI option/flag injection: target must not start with '-'
    if target.startswith("-"):
        return False, "Target parameter cannot begin with hyphen (CLI option injection rejected)"

    # Defense against multiple arguments: target must not contain whitespace
    if re.search(r"\s", target):
        return False, "Target parameter cannot contain whitespace (argument injection rejected)"

    # Defense against shell metacharacters
    if FORBIDDEN_TARGET_PATTERN.search(target):
        return False, "Target parameter contains forbidden shell metacharacters"

    # Action-specific semantic format verification
    if action in {"BLOCK_IP", "RESTORE_IP"}:
        if len(target) > 45 or not IP_CIDR_PATTERN.match(target):
            return False, f"Target '{target}' is not a valid IPv4/IPv6 address or CIDR range"
    elif action in {"DISABLE_USER", "ENABLE_USER"}:
        if len(target) > 64 or not POSIX_USER_PATTERN.match(target):
            return False, f"Target '{target}' is not a valid user account identifier"
    elif action in {"ISOLATE_HOST", "RECONNECT_HOST", "COLLECT_EVIDENCE"}:
        if not HOSTNAME_PATTERN.match(target):
            return False, f"Target '{target}' is not a valid host identifier or asset code"

    return True, ""

@app.route("/health", methods=["GET"])
def health():
    with NONCE_LOCK:
        tracked = len(PROCESSED_NONCES)
    return jsonify({
        "status": "HEALTHY",
        "agent": "BlueOps Response Agent v1.2",
        "allowed_actions": sorted(list(ALLOWLISTED_ACTIONS)),
        "execution_mode": EXECUTION_MODE,
        "driver": driver.__class__.__name__,
        "simulation_mode": EXECUTION_MODE.upper() == "SIMULATION",
        "tracked_nonces": tracked
    }), 200

@app.route("/api/v1/execute", methods=["POST"])
def execute_action():
    now = time.time()

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

    # Atomic test-and-set nonce registration to defeat race conditions and replays
    if not check_and_register_nonce(action_id, now):
        logger.warning(f"Replay attack detected for ActionId: {action_id}")
        return jsonify({"error": "Replay detected: ActionId already processed"}), 409

    data = request.get_json(silent=True) or {}
    playbook_code = str(data.get("playbookCode", "")).strip()
    action = str(data.get("action", "")).strip()
    target = str(data.get("target", "")).strip()

    # Boundary check: action authorization against allowlist
    resolved_action = action if action in ALLOWLISTED_ACTIONS else PLAYBOOK_TO_ACTION.get(playbook_code)
    if not resolved_action:
        logger.warning(f"Unauthorized action rejected: playbook={playbook_code}, action={action}")
        return jsonify({
            "error": "REJECTED_UNAUTHORIZED_ACTION",
            "message": f"Action or playbook '{action or playbook_code}' is not permitted by agent security policy"
        }), 400

    # Boundary check: strict target validation
    is_valid, validation_error = validate_target_parameter(resolved_action, target)
    if not is_valid:
        logger.warning(f"Target validation rejected for {resolved_action}: {validation_error} (target='{target}')")
        return jsonify({
            "error": "REJECTED_INVALID_PARAMETER",
            "message": validation_error
        }), 400

    logger.info(f"Received validated response action request: Action={resolved_action}, Target={target}, ActionId={action_id}")

    # Delegate execution to modular OS / simulation driver
    driver_outcome = driver.execute(resolved_action, target)

    execution_result = {
        "actionId": action_id,
        "action": resolved_action,
        "playbook": playbook_code,
        "target": target,
        "status": driver_outcome.get("status", "SUCCESS"),
        "mode": driver_outcome.get("mode", "LAB_CONTROLLED_EXECUTION"),
        "driver": driver.__class__.__name__,
        "executed_at": time.time(),
        "remediation": driver_outcome.get("remediation", f"Action '{resolved_action}' executed successfully.")
    }

    return jsonify(execution_result), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

