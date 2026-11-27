# BlueOps — Known Limitations & Design Boundaries

## 1. Hardware & Virtualization Scope
- **RAM Constraints:** Designed specifically for a 16 GB laptop host. Operating both Windows and Linux target VMs simultaneously with full OpenSearch clustering can induce swap. To mitigate this, test runs can alternate between OS test suites, or use a lightweight test profile.
- **Single-Node OpenSearch:** The analytics cluster is intentionally deployed as a single node (`discovery.type=single-node`). Production multi-node clustering, shard replication, and cross-cluster replication are omitted to fit memory targets.

## 2. Telemetry & Network Visibility
- **Suricata Promiscuous Mode:** In a virtualized desktop environment (VirtualBox / Hyper-V / VMware Workstation), Suricata requires a dedicated virtual bridge or TAP interface to observe inter-VM traffic. Host loopback traffic cannot be observed by Suricata without specialized virtual network routing.
- **Sysmon Event Volumes:** Broad file creation and image loading configurations can generate gigabytes of daily telemetry. The provided `sysmon-config.xml` applies targeted filtering based on SwiftOnSecurity best practices to protect laptop disk I/O.

## 3. Incident Response & Verification Boundaries
- **No Unrestricted Remote Shell:** By security design principle, BlueOps strictly rejects arbitrary command or script execution. Only allowlisted, structured actions with pre-declared catalog codes (`ACT-001`..`ACT-007`) and validated target parameters are accepted. Catalog action `ACT-008` (`Terminate Malicious Child Process`) is retained in schema/simulation taxonomy only and is rejected cleanly (`501 UNSUPPORTED_ACTION`) during restricted live agent dispatch.
- **Hypothetical Containment Mode Locked by Default:** Response execution defaults to `SIMULATION` / hypothetical sandbox mode (`BLUEOPS_ALLOW_LIVE_EXECUTION=false`, `RESPONSE_AGENT_SIMULATION_MODE=true`, `BLUEOPS_ALLOW_LIVE_HOST_DISRUPTION=false`), and `response-agent/src/drivers.py` contains zero OS subprocess mutations (`netsh`, `iptables`, `net user`, `usermod` modeled hypothetically only). Simulation/hypothetical runs record `VerificationStatus.SIMULATION_ONLY` / `ProposalStatus.SIMULATED`. See `AGENTS.md` before changing any safety guardrails.
- **No Independent OS State Probes Implemented:** Live dispatches without external probe verification data record `VerificationStatus.UNAVAILABLE` (`ProposalStatus.EXECUTED`) rather than falsely claiming `VERIFIED`.

## 4. State Persistence & Infrastructure Limitations
- **Volatile In-Memory Telemetry & Fallback Finding Store:** `EventNormalizationService` stores recent normalized events (`1,000` capacity) and DLQ entries (`500` capacity) in memory, and `OpenSearchFindingAdapter` uses an in-memory `ConcurrentHashMap` fallback when `blueops.opensearch.enabled=false` or OpenSearch is unreachable. These unlinked in-memory caches do not survive JVM restarts.
- **Lab-Scoped Docker Compose & Unbundled Ops Scripts:** Root `docker-compose.yml` runs plain HTTP (`:80`) with `DISABLE_SECURITY_PLUGIN=true` on OpenSearch for lab usability. TLS reverse proxy configs, PostgreSQL backup cron scripts, and systemd units documented in `BLUEOPS_BACKUP_RECOVERY.md` and `BLUEOPS_DEPLOYMENT_GUIDE.md` are operator reference templates rather than active deployment automation.
