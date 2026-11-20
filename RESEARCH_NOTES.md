# BlueOps Research Notes: Literature Mapping, Prior-Art Analysis & Research Proposals

**Document ID:** BLUEOPS-RES-001  
**Classification:** Applied Cybersecurity Systems Research  
**Version:** 1.0.0  
**Status:** Working Research Record  

---

## 1. Literature Mapping & Research Context

Modern Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platforms face fundamental architectural challenges in contemporary enterprise environments:

### 1.1. Core Research Literature
1. **Multi-Source Event Correlation & Kill-Chain Reconstruction:**
   - *Milajerdi et al. (USENIX Security 2019), "HOLMES: Real-time APT Detection through Correlation of Anomalous Behaviors":* Demonstrated provenance graph compilation from endpoint audit logs to identify high-level APT stages.
   - *Hassan et al. (NDSS 2020), "Tactical Provenance Analysis for Endpoint Detection and Response Systems":* Showed that causal graph reduction and alert correlation reduce false positive alerts by orders of magnitude compared to isolated single-event rules.
2. **Heterogeneous Telemetry Normalization & Entity Disambiguation:**
   - *Open Cybersecurity Schema Framework (OCSF) & Elastic Common Schema (ECS):* While industry consortia have standardized field names, practical cross-sensor entity resolution (mapping a Suricata flow IP to a Linux auditd PID or Windows Sysmon GUID) remains brittle when network address translation (NAT), dynamic DHCP, or container virtualization is present.
3. **Automated Response Safety & Verifiability:**
   - *Al-Mohannadi et al. (IEEE Access 2020), "Cyber Security Threat Modeling in Smart Environments: Automated Response Challenges":* Highlights the risk of automated containment actions causing self-inflicted denial-of-service (DoS) or operational disruption when triggered by adversary deception or spoofed telemetry.

---

## 2. Comparative Analysis of Existing Defensive Systems

| System | Telemetry Ingestion | Detection Mechanism | Correlation Engine | Response Execution | Research Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Wazuh** | Wazuh agent (OSSEC fork) + rsyslog | Hardcoded XML decoders + hierarchical rule IDs | Basic regex parent/child rule matching | Active Response scripts (unauthenticated local pipes) | Rigid rule hierarchy; lacks native Sigma AST evaluation; active response lacks cryptographic signing. |
| **Elastic Security** | Elastic Agent + Fleet (Integrations) | EQL (Event Query Language), Lucene, ES|QL | Threshold & sequence rules over Elasticsearch indices | Webhook / API alerts; external SOAR orchestration | High resource footprint; queries executed out-of-band on Lucene indices rather than dynamic real-time stream evaluation. |
| **Security Onion** | Zeek, Suricata, Stenographer, Wazuh | Snort/Suricata rules, Sigma/ElastAlert | Alert aggregation in OpenSearch / Kibana | Manual pivot to analyst playbooks | Aggregation is analytical/dashboard-driven rather than automated causal kill-chain synthesis. |
| **BlueOps** | Multi-source (Sysmon, auditd, Suricata) via Fluent Bit | Dynamic Sigma YAML AST + Heuristic Single-Event Rules | Sliding-window causal scenario correlation (C001–C004) | Cryptographically signed (HMAC-SHA256) modular agent with simulation defaults | Requires transition from metadata parsing to full dynamic Sigma AST execution; entity resolution across NAT/DHCP needs formalization. |

---

## 3. Candidate Research Proposals

### Proposal 1: Resilient Kill-Chain Reconstruction under Sensor Dropout and Incomplete Telemetry
* **Research Problem:** Real-world enterprise networks suffer from sensor dropouts, network congestion, log forwarder crashes, and adversary defense evasion (e.g., event log clearing or auditd tampering). Rigid deterministic SIEM correlation rules fail when intermediate events in an attack sequence are dropped.
* **Proposed Contribution:** A probabilistic, state-graph correlation engine that maintains adversary attack hypothesis confidence even when intermediate telemetry nodes are missing.
* **Experimental Methodology:** Inject varying degrees of random and targeted telemetry packet loss (10% to 50%) into benchmark attack streams and measure detection degradation against deterministic baselines.
* **Adversarial Critique:** Existing provenance graph systems (e.g., NodeMerge, Poirot) have explored graph path-finding; the research contribution must focus strictly on real-time sliding-window streaming performance rather than offline retrospective graph queries.
* **Feasibility & Ranking:** **HIGH (Rank #1)** — Directly leverages BlueOps' existing ring buffer, CES schema, and correlation pipeline.

### Proposal 2: Safe SOAR Orchestration via Formal Policy Bounds and Micro-Simulation
* **Research Problem:** Autonomous response mechanisms in SOAR platforms create significant operational risks of collateral damage (e.g., blocking critical infrastructure IPs or terminating domain controllers due to spoofed or high-velocity alerts).
* **Proposed Contribution:** A formal policy verification and safe response staging framework that evaluates response blast radius and executes a localized micro-simulation prior to live driver activation.
* **Experimental Methodology:** Evaluate containment latency, false-containment prevention rate, and blast-radius bounding under deceptive adversary injection scenarios.
* **Adversarial Critique:** Simulating complex network interactions without live host execution is non-trivial; requires rigorous modeling of host dependency graphs.
* **Feasibility & Ranking:** **MEDIUM (Rank #2)** — Strong applied systems value, aligns with the existing `SimulationDriver` and `AuthoritativeAdvisor`.

### Proposal 3: Dynamic In-Memory Sigma AST Compilation for Real-Time Streaming Telemetry
* **Research Problem:** Most Sigma implementations translate Sigma YAML into backend-specific query languages (Elasticsearch DSL, Splunk SPL, SQL) that run periodically against indexing storage. In-memory stream evaluation engines either use heavy JVM rule engines (Drools) or shallow regex scanning.
* **Proposed Contribution:** A lightweight, pure-Java abstract syntax tree (AST) compiler and predicate evaluator that evaluates streaming normalized events against hundreds of Sigma rules with sub-millisecond latency.
* **Experimental Methodology:** Measure evaluation latency, throughput (events/second), and heap memory usage scaling with rule count ($N = 10, 50, 100, 500$) compared to database indexing queries.
* **Adversarial Critique:** PySigma and other tools exist, but an embedded Java stream evaluator tailored for microservice SIEM pipelines provides immediate, practical open-source utility.
* **Feasibility & Ranking:** **VERY HIGH (Rank #1 - Immediate Technical Prerequisite)** — Required to resolve the primary architectural limitation identified in the BlueOps audit.
