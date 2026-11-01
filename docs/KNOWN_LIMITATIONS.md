# BlueOps — Known Limitations & Design Boundaries

## 1. Hardware & Virtualization Scope
- **RAM Constraints:** Designed specifically for a 16 GB laptop host. Operating both Windows and Linux target VMs simultaneously with full OpenSearch clustering can induce swap. To mitigate this, test runs can alternate between OS test suites, or use a lightweight test profile.
- **Single-Node OpenSearch:** The analytics cluster is intentionally deployed as a single node (`discovery.type=single-node`). Production multi-node clustering, shard replication, and cross-cluster replication are omitted to fit memory targets.

## 2. Telemetry & Network Visibility
- **Suricata Promiscuous Mode:** In a virtualized desktop environment (VirtualBox / Hyper-V / VMware Workstation), Suricata requires a dedicated virtual bridge or TAP interface to observe inter-VM traffic. Host loopback traffic cannot be observed by Suricata without specialized virtual network routing.
- **Sysmon Event Volumes:** Broad file creation and image loading configurations can generate gigabytes of daily telemetry. The provided `sysmon-config.xml` applies targeted filtering based on SwiftOnSecurity best practices to protect laptop disk I/O.

## 3. Incident Response Boundaries
- **No Unrestricted Remote Shell:** By security design principle 19, BlueOps strictly rejects arbitrary command or script execution. Only allowlisted, structured actions with pre-declared parameters (IP, username, asset ID) are accepted.
- **Simulation Mode Default:** Response execution defaults to simulation mode (`RESPONSE_AGENT_SIMULATION_MODE=true`) until an operator explicitly connects an authorized response agent on an isolated lab machine.
