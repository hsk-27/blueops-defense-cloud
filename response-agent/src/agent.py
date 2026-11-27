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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    Flask = None  # type: ignore[assignment]
    request = None  # type: ignore[assignment]
    jsonify = None  # type: ignore[assignment]
    FLASK_AVAILABLE = False

try:
    from src.drivers import get_execution_driver
except ImportError:
    from drivers import get_execution_driver

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BlueOpsResponseAgent")


def resolve_execution_mode() -> str:
    """Resolve agent execution mode, defaulting fail-safe to SIMULATION."""
    sim_flag = os.environ.get("RESPONSE_AGENT_SIMULATION_MODE")
    if sim_flag is not None and sim_flag.strip().lower() in {"true", "1", "yes"}:
        return "SIMULATION"
    raw_mode = os.environ.get("EXECUTION_MODE", "")
    if raw_mode.strip().upper() == "LIVE":
        return "LIVE"
    return "SIMULATION"


SECRET_KEY = os.environ.get("RESPONSE_AGENT_SECRET", "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130")
EXECUTION_MODE = resolve_execution_mode()
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

CATALOG_TO_ACTION = {
    "ACT-001": "BLOCK_IP",
    "ACT-002": "DISABLE_USER",
    "ACT-003": "ISOLATE_HOST",
    "ACT-004": "RESTORE_IP",
    "ACT-005": "ENABLE_USER",
    "ACT-006": "RECONNECT_HOST",
    "ACT-007": "COLLECT_EVIDENCE"
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

def build_health_payload() -> tuple[dict[str, Any], int]:
    """Construct the JSON payload and HTTP status code for /health."""
    with NONCE_LOCK:
        tracked = len(PROCESSED_NONCES)
    return {
        "status": "HEALTHY",
        "agent": "BlueOps Response Agent v1.2",
        "allowed_actions": sorted(list(ALLOWLISTED_ACTIONS)),
        "execution_mode": EXECUTION_MODE,
        "driver": driver.__class__.__name__,
        "simulation_mode": EXECUTION_MODE.upper() == "SIMULATION",
        "tracked_nonces": tracked
    }, 200


def process_execute_request(headers: Mapping[str, str], raw_body: str) -> tuple[dict[str, Any], int]:
    """Authenticate, validate, and execute an allowlisted SOAR action request."""
    now = time.time()
    hdrs = {str(k).lower(): v for k, v in headers.items()}

    signature = hdrs.get("x-blueops-signature")
    timestamp_header = hdrs.get("x-blueops-timestamp")
    action_id = hdrs.get("x-blueops-actionid")

    if not signature or not timestamp_header or not action_id:
        return {"error": "Missing required security headers (Signature, Timestamp, ActionId)"}, 401

    try:
        timestamp = int(timestamp_header)
    except ValueError:
        return {"error": "Malformed timestamp"}, 400

    if not verify_hmac(raw_body, timestamp, signature):
        logger.warning(f"HMAC verification failed for action ID {action_id}")
        return {"error": "Unauthorized: HMAC signature mismatch or expired payload"}, 401

    # Atomic test-and-set nonce registration to defeat race conditions and replays
    if not check_and_register_nonce(action_id, now):
        logger.warning(f"Replay attack detected for ActionId: {action_id}")
        return {"error": "Replay detected: ActionId already processed"}, 409

    try:
        parsed = json.loads(raw_body) if raw_body else {}
        data = parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        data = {}

    playbook_code = str(data.get("playbookCode", "")).strip().upper()
    action_code = str(data.get("actionCode", "")).strip().upper()
    action = str(data.get("action", "")).strip().upper()
    target = str(data.get("target", "")).strip()

    # Boundary check: action authorization against allowlist and catalog contract
    action_from_name = action if action in ALLOWLISTED_ACTIONS else None
    action_from_catalog = CATALOG_TO_ACTION.get(action_code) if action_code else None
    action_from_playbook = (PLAYBOOK_TO_ACTION.get(playbook_code) or CATALOG_TO_ACTION.get(playbook_code)) if playbook_code else None

    candidates = [a for a in (action_from_name, action_from_catalog, action_from_playbook) if a]
    if (action and not action_from_name) or (action_code and not action_from_catalog) or (playbook_code and not action_from_playbook):
        resolved_action = None
    elif len(set(candidates)) != 1:
        resolved_action = None
    else:
        resolved_action = candidates[0]

    if not resolved_action:
        logger.warning(f"Unauthorized action rejected: actionCode={action_code}, playbook={playbook_code}, action={action}")
        return {
            "error": "REJECTED_UNAUTHORIZED_ACTION",
            "message": f"Action '{action or action_code or playbook_code}' is not permitted by agent security policy"
        }, 400

    # Boundary check: strict target validation
    is_valid, validation_error = validate_target_parameter(resolved_action, target)
    if not is_valid:
        logger.warning(f"Target validation rejected for {resolved_action}: {validation_error} (target='{target}')")
        return {
            "error": "REJECTED_INVALID_PARAMETER",
            "message": validation_error
        }, 400

    logger.info(f"Received validated response action request: Action={resolved_action}, Target={target}, ActionId={action_id}")

    # Delegate execution to hypothetical containment / simulation driver
    driver_outcome = driver.execute(resolved_action, target)
    driver_status = str(driver_outcome.get("status", "SUCCESS")).upper()
    driver_mode = driver_outcome.get("mode", "HYPOTHETICAL_LAB_SANDBOX")
    is_simulated = (
        EXECUTION_MODE.upper() == "SIMULATION"
        or bool(driver_outcome.get("hypothetical"))
        or driver_mode in {"LAB_CONTROLLED_EXECUTION", "CONTAINED_LAB_SANDBOX", "HYPOTHETICAL_LAB_SANDBOX"}
    )

    execution_result = {
        "actionId": action_id,
        "action": resolved_action,
        "actionCode": action_code,
        "playbook": playbook_code,
        "target": target,
        "status": driver_status,
        "mode": driver_mode,
        "simulation": is_simulated,
        "driver": driver.__class__.__name__,
        "executed_at": time.time(),
        "remediation": driver_outcome.get("remediation") or driver_outcome.get("error") or driver_outcome.get("message") or f"Action '{resolved_action}' processed."
    }

    http_status = 500 if driver_status in {"FAILED", "ERROR"} else 200
    return execution_result, http_status


class _StdlibResponse:
    """Minimal Flask-compatible response wrapper for stdlib test client dispatch."""

    def __init__(self, payload: dict[str, Any], status_code: int) -> None:
        self._payload = payload
        self.status_code = status_code

    def get_json(self) -> dict[str, Any]:
        """Return parsed JSON dictionary payload."""
        return self._payload


class _StdlibTestClient:
    """Zero-dependency context-managed test client mirroring FlaskClient methods used in tests."""

    def __enter__(self) -> "_StdlibTestClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False

    def get(self, path: str) -> _StdlibResponse:
        """Dispatch an in-process GET request."""
        if path == "/health":
            payload, status = build_health_payload()
            return _StdlibResponse(payload, status)
        return _StdlibResponse({"error": "Not Found"}, 404)

    def post(
        self,
        path: str,
        data: str | bytes = "",
        headers: Mapping[str, str] | None = None,
        json: dict[str, Any] | None = None,  # noqa: A002
    ) -> _StdlibResponse:
        """Dispatch an in-process POST request."""
        if path == "/api/v1/execute":
            if json is not None and not data:
                raw_body = __import__("json").dumps(json)
            elif isinstance(data, bytes):
                raw_body = data.decode("utf-8")
            else:
                raw_body = data or ""
            payload, status = process_execute_request(headers or {}, raw_body)
            return _StdlibResponse(payload, status)
        return _StdlibResponse({"error": "Not Found"}, 404)


class StdlibAgentApp:
    """Zero-dependency HTTP server and test harness used when Flask is not installed."""

    def __init__(self) -> None:
        self.config: dict[str, Any] = {}

    def test_client(self) -> _StdlibTestClient:
        """Return an in-process Flask-compatible test client."""
        return _StdlibTestClient()

    def run(self, host: str = "0.0.0.0", port: int = 5000) -> None:
        """Serve /health and /api/v1/execute over Python's built-in ThreadingHTTPServer."""
        class _Handler(BaseHTTPRequestHandler):
            def _send_json(self, payload: dict[str, Any], status_code: int) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    payload, status = build_health_payload()
                    self._send_json(payload, status)
                    return
                self._send_json({"error": "Not Found"}, 404)

            def do_POST(self) -> None:  # noqa: N802
                if self.path == "/api/v1/execute":
                    length = int(self.headers.get("Content-Length", "0") or 0)
                    raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
                    payload, status = process_execute_request(self.headers, raw_body)
                    self._send_json(payload, status)
                    return
                self._send_json({"error": "Not Found"}, 404)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                logger.info(format % args)

        server = ThreadingHTTPServer((host, port), _Handler)
        logger.info(f"BlueOps Response Agent (stdlib HTTP fallback) listening on {host}:{port}")
        server.serve_forever()


if FLASK_AVAILABLE:
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        payload, status = build_health_payload()
        return jsonify(payload), status

    @app.route("/api/v1/execute", methods=["POST"])
    def execute_action():
        payload, status = process_execute_request(request.headers, request.get_data(as_text=True))
        return jsonify(payload), status
else:
    app = StdlibAgentApp()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

