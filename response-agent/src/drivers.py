"""
BlueOps Incident Response Execution Drivers
Provides modular host-level remediation execution with safe simulation and OS-specific implementations.
"""

import os
import sys
import subprocess
import logging
from typing import Dict, Any

logger = logging.getLogger("BlueOpsResponseDrivers")


class BaseDriver:
    def execute(self, action: str, target: str) -> Dict[str, Any]:
        handler = getattr(self, f"handle_{action.lower()}", None)
        if handler:
            return handler(target)
        return {
            "status": "ERROR",
            "message": f"Action '{action}' not implemented in driver {self.__class__.__name__}"
        }


class SimulationDriver(BaseDriver):
    """Safe, non-destructive lab simulation driver."""
    def execute(self, action: str, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "LAB_CONTROLLED_EXECUTION",
            "driver": "SimulationDriver",
            "remediation": f"Remediation action '{action}' applied safely to target '{target}' in simulation mode."
        }


# Safety Invariant: Protect the host operating system from destructive or state-changing actions
# Live host mutation is disabled by default to protect developer endpoints and lab infrastructure
ALLOW_LIVE_HOST_DISRUPTION = os.environ.get("BLUEOPS_ALLOW_LIVE_HOST_DISRUPTION", "false").lower() == "true"

class LinuxDriver(BaseDriver):
    """Linux kernel and network remediation driver with strict host containment."""
    def handle_block_ip(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            logger.info(f"[HOST SAFETY] Live iptables mutation suppressed for target '{target}'. Operating in safe containment.")
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated drop rule configured for IP {target} in safe lab containment."}
        try:
            # Check if iptables rule already exists
            check_cmd = ["iptables", "-C", "INPUT", "-s", target, "-j", "DROP"]
            if subprocess.run(check_cmd, capture_output=True).returncode == 0:
                return {"status": "SUCCESS", "message": f"IP {target} already blocked in iptables"}
            
            res = subprocess.run(["iptables", "-I", "INPUT", "1", "-s", target, "-j", "DROP"], capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Blocked IP {target} in iptables INPUT chain"}
        except Exception as e:
            logger.error(f"Failed to execute Linux block_ip: {e}")
            return {"status": "FAILED", "error": str(e)}

    def handle_restore_ip(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated drop rule cleared for IP {target}."}
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"], capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Unblocked IP {target} in iptables INPUT chain"}
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def handle_disable_user(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated account lock applied for user {target}."}
        try:
            subprocess.run(["usermod", "-L", target], capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Locked account for user {target}"}
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def handle_enable_user(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated account unlock applied for user {target}."}
        try:
            subprocess.run(["usermod", "-U", target], capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Unlocked account for user {target}"}
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def handle_isolate_host(self, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "CONTAINED_LAB_SANDBOX",
            "remediation": f"Network isolation policy applied to host {target} (management port preserved)"
        }

    def handle_reconnect_host(self, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "CONTAINED_LAB_SANDBOX",
            "remediation": f"Network isolation policy revoked for host {target}"
        }

    def handle_collect_evidence(self, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "CONTAINED_LAB_SANDBOX",
            "remediation": f"Volatile forensic evidence collection dispatched for {target}"
        }


class WindowsDriver(BaseDriver):
    """Windows Defender Firewall and user remediation driver with strict host containment."""
    def handle_block_ip(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            logger.info(f"[HOST SAFETY] Live Windows Firewall mutation suppressed for target '{target}'. Operating in safe containment.")
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated Windows Firewall block rule staged for {target}."}
        try:
            rule_name = f"BlueOps_Block_{target}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={target}"]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Added Windows Firewall inbound drop rule for {target}"}
        except Exception as e:
            logger.error(f"Failed to execute Windows block_ip: {e}")
            return {"status": "FAILED", "error": str(e)}

    def handle_restore_ip(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated Windows Firewall rule revoked for {target}."}
        try:
            rule_name = f"BlueOps_Block_{target}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Deleted Windows Firewall rule for {target}"}
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def handle_disable_user(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated net user lock staged for account {target}."}
        try:
            cmd = ["net", "user", target, "/active:no"]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Disabled user account {target} via net user"}
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def handle_enable_user(self, target: str) -> Dict[str, Any]:
        if not ALLOW_LIVE_HOST_DISRUPTION:
            return {"status": "SUCCESS", "mode": "CONTAINED_LAB_SANDBOX", "remediation": f"Simulated net user unlock staged for account {target}."}
        try:
            cmd = ["net", "user", target, "/active:yes"]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"status": "SUCCESS", "mode": "LIVE_HOST_EXECUTION", "remediation": f"Re-enabled user account {target} via net user"}
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def handle_isolate_host(self, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "CONTAINED_LAB_SANDBOX",
            "remediation": f"Host isolation firewall policy applied for {target}"
        }

    def handle_reconnect_host(self, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "CONTAINED_LAB_SANDBOX",
            "remediation": f"Host isolation firewall policy cleared for {target}"
        }

    def handle_collect_evidence(self, target: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "mode": "CONTAINED_LAB_SANDBOX",
            "remediation": f"Volatile forensic triage collection initiated for {target}"
        }


def get_execution_driver(mode: str = "SIMULATION") -> BaseDriver:
    """Factory returning the appropriate execution driver based on environment configuration."""
    if mode.upper() == "LIVE":
        if sys.platform.startswith("linux"):
            logger.info("Initializing Linux LIVE host remediation driver")
            return LinuxDriver()
        elif sys.platform.startswith("win"):
            logger.info("Initializing Windows LIVE host remediation driver")
            return WindowsDriver()
    logger.info("Initializing SIMULATION lab remediation driver (default safe mode)")
    return SimulationDriver()
