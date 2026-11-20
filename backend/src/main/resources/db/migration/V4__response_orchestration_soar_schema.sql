-- Milestone 6 · Controlled Response Orchestration & SOAR Schema Migration

-- 1. Response Action Catalog (Formalized Contract & Risk Taxonomy)
CREATE TABLE IF NOT EXISTS response_action_catalog (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_code VARCHAR(32) NOT NULL UNIQUE,       -- ACT-001 to ACT-010, P001 to P007
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(64) NOT NULL,                  -- DEFENSIVE_CONTAINMENT, ACCESS_CONTROL, FORENSIC_ACQUISITION, REMEDIATION
    target_type VARCHAR(32) NOT NULL,               -- IP, USERNAME, ASSET, CONTAINER
    risk_level VARCHAR(32) NOT NULL,                -- LOW, MODERATE, HIGH, CRITICAL
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    simulation_supported BOOLEAN NOT NULL DEFAULT TRUE,
    rollback_supported BOOLEAN NOT NULL DEFAULT TRUE,
    reversal_action_code VARCHAR(32),
    timeout_seconds INTEGER NOT NULL DEFAULT 30,
    verification_method VARCHAR(64) NOT NULL DEFAULT 'STATE_QUERY',
    parameter_schema TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Registered Target Registry (Target Authorization & Blast Radius Boundaries)
CREATE TABLE IF NOT EXISTS response_targets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL UNIQUE,
    target_type VARCHAR(32) NOT NULL,               -- IP, HOST, USER, CONTAINER
    identifier VARCHAR(128) NOT NULL,
    display_name VARCHAR(128),
    criticality VARCHAR(32) NOT NULL DEFAULT 'STANDARD', -- LOW, STANDARD, HIGH, CRITICAL
    environment VARCHAR(32) NOT NULL DEFAULT 'SYNTHETIC_TEST', -- SYNTHETIC_TEST, LAB, STAGING
    trust_status VARCHAR(32) NOT NULL DEFAULT 'AUTHORIZED',   -- AUTHORIZED, RESTRICTED, REVOKED
    is_protected BOOLEAN NOT NULL DEFAULT FALSE,    -- TRUE prevents any disruptive action
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Response Proposals (Full Multi-Stage SOAR Lifecycle)
CREATE TABLE IF NOT EXISTS response_proposals (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    proposal_uuid VARCHAR(64) NOT NULL UNIQUE,
    incident_id BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
    finding_id VARCHAR(64),
    correlation_id BIGINT,
    action_code VARCHAR(32) NOT NULL REFERENCES response_action_catalog(action_code),
    action_name VARCHAR(128) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    target_canonical_id VARCHAR(128),
    target_identifier VARCHAR(128) NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    parameters_json TEXT,
    proposed_by VARCHAR(64) NOT NULL,
    proposed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    risk_level VARCHAR(32) NOT NULL,
    execution_mode VARCHAR(32) NOT NULL DEFAULT 'SIMULATION', -- SIMULATION, LIVE
    policy_outcome VARCHAR(32) NOT NULL,            -- ALLOW, DENY, REQUIRE_APPROVAL, SIMULATION_ONLY, BLOCKED, INVALID
    policy_reason TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'DRAFT',    -- DRAFT, VALIDATING, REJECTED, PENDING_APPROVAL, APPROVED, DENIED, READY, EXECUTING, EXECUTION_FAILED, EXECUTED, VERIFICATION_PENDING, VERIFIED, VERIFICATION_FAILED, CANCELLED, EXPIRED
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    approver VARCHAR(64),
    approved_at TIMESTAMP WITH TIME ZONE,
    denial_reason TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    execution_id BIGINT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Response Outcome Verifications (Independent Remediation Verification)
CREATE TABLE IF NOT EXISTS response_verifications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    verification_uuid VARCHAR(64) NOT NULL UNIQUE,
    proposal_id BIGINT REFERENCES response_proposals(id) ON DELETE CASCADE,
    execution_id BIGINT,
    status VARCHAR(32) NOT NULL,                    -- PENDING, VERIFIED, FAILED, INCONCLUSIVE
    verification_method VARCHAR(64) NOT NULL,
    expected_outcome TEXT NOT NULL,
    observed_outcome TEXT NOT NULL,
    evidence_payload TEXT,
    verified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_simulation BOOLEAN NOT NULL DEFAULT TRUE
);

-- Indices for performance and concurrency protection
CREATE INDEX IF NOT EXISTS idx_proposals_status ON response_proposals(status);
CREATE INDEX IF NOT EXISTS idx_proposals_incident ON response_proposals(incident_id);
CREATE INDEX IF NOT EXISTS idx_proposals_uuid ON response_proposals(proposal_uuid);
CREATE INDEX IF NOT EXISTS idx_targets_identifier ON response_targets(identifier);
CREATE INDEX IF NOT EXISTS idx_verifications_proposal ON response_verifications(proposal_id);

-- Seed Response Action Catalog
INSERT INTO response_action_catalog (action_code, name, description, category, target_type, risk_level, requires_approval, simulation_supported, rollback_supported, reversal_action_code, timeout_seconds, verification_method, parameter_schema)
VALUES
('ACT-001', 'Block Lab Network Source IP', 'Applies dynamic perimeter drop rules against confirmed malicious network traffic.', 'DEFENSIVE_CONTAINMENT', 'IP', 'MODERATE', TRUE, TRUE, TRUE, 'ACT-004', 15, 'FIREWALL_DROP_QUERY', '{"targetIp":"string"}'),
('ACT-002', 'Disable Compromised User Identity', 'Suspends authentication credentials for an account actively participating in attack lineage.', 'ACCESS_CONTROL', 'USERNAME', 'HIGH', TRUE, TRUE, TRUE, 'ACT-005', 20, 'IDENTITY_STATUS_CHECK', '{"username":"string"}'),
('ACT-003', 'Isolate Compromised Host Endpoint', 'Enforces strict network quarantine isolating host from all traffic except telemetry management.', 'DEFENSIVE_CONTAINMENT', 'ASSET', 'CRITICAL', TRUE, TRUE, TRUE, 'ACT-006', 30, 'ENDPOINT_ISOLATION_PROBE', '{"hostname":"string"}'),
('ACT-004', 'Restore Lab Network Source IP', 'Removes perimeter drop rule, restoring normal IP connectivity.', 'REMEDIATION', 'IP', 'LOW', FALSE, TRUE, FALSE, NULL, 15, 'FIREWALL_ALLOW_QUERY', '{"targetIp":"string"}'),
('ACT-005', 'Re-enable User Identity', 'Restores account authentication capability following incident containment and credential rotation.', 'REMEDIATION', 'USERNAME', 'MODERATE', TRUE, TRUE, FALSE, NULL, 20, 'IDENTITY_STATUS_CHECK', '{"username":"string"}'),
('ACT-006', 'Reconnect Isolated Host Endpoint', 'Revokes quarantine policy and rejoins endpoint to standard production network segment.', 'REMEDIATION', 'ASSET', 'HIGH', TRUE, TRUE, FALSE, NULL, 30, 'ENDPOINT_CONNECTIVITY_PROBE', '{"hostname":"string"}'),
('ACT-007', 'Acquire Volatile Forensic Triage Archive', 'Captures process memory dump, open socket state, and volatile logs for offline forensic analysis.', 'FORENSIC_ACQUISITION', 'ASSET', 'LOW', FALSE, TRUE, FALSE, NULL, 60, 'FORENSIC_ARTIFACT_SHA256_VERIFICATION', '{"hostname":"string","memoryDump":true}'),
('ACT-008', 'Terminate Malicious Child Process', 'Sends SIGKILL/TerminateProcess to confirmed adversary execution lineage node.', 'DEFENSIVE_CONTAINMENT', 'ASSET', 'HIGH', TRUE, TRUE, FALSE, NULL, 10, 'PROCESS_TABLE_ABSENCE_CHECK', '{"hostname":"string","pid":1234,"processName":"powershell.exe"}')
ON CONFLICT (action_code) DO NOTHING;

-- Seed Authorized Synthetic Targets (Strict Blast Radius Bounds)
INSERT INTO response_targets (target_id, target_type, identifier, display_name, criticality, environment, trust_status, is_protected)
VALUES
('TGT-LAB-IP-01', 'IP', '198.51.100.24', 'External Attack Source (Lab)', 'LOW', 'SYNTHETIC_TEST', 'AUTHORIZED', FALSE),
('TGT-LAB-IP-02', 'IP', '203.0.113.88', 'CobaltStrike C2 Lab Node', 'LOW', 'SYNTHETIC_TEST', 'AUTHORIZED', FALSE),
('TGT-LAB-USR-01', 'USER', 'CORP\\analyst', 'Compromised Lab Domain Account', 'STANDARD', 'SYNTHETIC_TEST', 'AUTHORIZED', FALSE),
('TGT-LAB-USR-02', 'USER', 'root', 'Linux Gateway Root Account', 'HIGH', 'SYNTHETIC_TEST', 'AUTHORIZED', FALSE),
('TGT-LAB-HST-01', 'HOST', 'WIN-PROD-01', 'Synthetic Windows 11 Enterprise Node', 'STANDARD', 'SYNTHETIC_TEST', 'AUTHORIZED', FALSE),
('TGT-LAB-HST-02', 'HOST', 'LNX-GATEWAY', 'Synthetic Linux Gateway Node', 'HIGH', 'SYNTHETIC_TEST', 'AUTHORIZED', FALSE),
-- Protected Critical Infrastructure (Cannot be isolated or blocked)
('TGT-PROT-GW-01', 'IP', '10.0.0.1', 'Default Gateway (Protected)', 'CRITICAL', 'LAB', 'RESTRICTED', TRUE),
('TGT-PROT-DNS-01', 'IP', '10.0.0.2', 'Core DNS Server (Protected)', 'CRITICAL', 'LAB', 'RESTRICTED', TRUE),
('TGT-PROT-HOST-01', 'HOST', 'localhost', 'Localhost Developer Machine', 'CRITICAL', 'LAB', 'RESTRICTED', TRUE),
('TGT-PROT-HOST-02', 'IP', '127.0.0.1', 'Loopback Adapter', 'CRITICAL', 'LAB', 'RESTRICTED', TRUE)
ON CONFLICT (target_id) DO NOTHING;
