-- =============================================================================
-- BlueOps Initial Database Schema (Flyway V1__init_schema.sql)
-- Compatible with PostgreSQL 16 and H2 (PostgreSQL Mode)
-- =============================================================================

-- 1. Identity & RBAC
CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL, -- ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(255),
    status VARCHAR(32) NOT NULL, -- SUCCESS, FAILED_CREDENTIALS, LOCKED
    attempted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Asset Inventory
CREATE TABLE assets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    persistent_id VARCHAR(64) NOT NULL UNIQUE, -- Persistent UUID or MAC/MachineGUID
    hostname VARCHAR(128) NOT NULL,
    ip_address VARCHAR(64) NOT NULL,
    os_name VARCHAR(64) NOT NULL, -- Windows 11, Ubuntu 22.04, etc.
    os_version VARCHAR(64),
    environment VARCHAR(32) NOT NULL DEFAULT 'LAB', -- LAB, STAGING, PROD
    status VARCHAR(32) NOT NULL DEFAULT 'HEALTHY', -- HEALTHY, SUSPICIOUS, COMPROMISED, ISOLATED, OFFLINE
    criticality VARCHAR(32) NOT NULL DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
    last_telemetry_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE asset_status_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    previous_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL,
    changed_by VARCHAR(64) NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Detection Rules Management
CREATE TABLE detection_rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_code VARCHAR(32) NOT NULL UNIQUE, -- D001, D002, etc.
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    log_source VARCHAR(64) NOT NULL, -- windows_sysmon, linux_auditd, suricata
    severity VARCHAR(32) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    mitre_tactic VARCHAR(64) NOT NULL,
    mitre_technique_id VARCHAR(32) NOT NULL,
    mitre_technique_name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, DISABLED, TESTING
    query_dsl TEXT NOT NULL,
    sigma_yaml TEXT,
    false_positives TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Incidents & Findings
CREATE TABLE incidents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_number VARCHAR(32) NOT NULL UNIQUE, -- INC-2026-0001
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    status VARCHAR(32) NOT NULL DEFAULT 'NEW', -- NEW, TRIAGED, INVESTIGATING, CONTAINMENT_PENDING, CONTAINED, RESOLVED, FALSE_POSITIVE, REOPENED
    primary_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    assigned_to VARCHAR(64),
    created_by VARCHAR(64) NOT NULL,
    resolution_rationale TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    contained_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE incident_findings (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    opensearch_finding_id VARCHAR(128) NOT NULL,
    rule_code VARCHAR(32) NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    raw_document_id VARCHAR(128),
    details_json TEXT
);

CREATE TABLE incident_notes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author VARCHAR(64) NOT NULL,
    note_text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE incident_status_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    from_status VARCHAR(32) NOT NULL,
    to_status VARCHAR(32) NOT NULL,
    actor VARCHAR(64) NOT NULL,
    reason TEXT,
    transitioned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 5. Threat Intelligence (IOCs)
CREATE TABLE ioc_indicators (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_value VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(32) NOT NULL, -- IP, DOMAIN, URL, MD5, SHA256
    source VARCHAR(64) NOT NULL, -- MISP, OTX, CISA, MANUAL_TEST
    confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    severity VARCHAR(32) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    tags VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_indicator_val_type UNIQUE (indicator_value, indicator_type)
);

CREATE TABLE ioc_matches (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ioc_id BIGINT NOT NULL REFERENCES ioc_indicators(id) ON DELETE CASCADE,
    matched_value VARCHAR(255) NOT NULL,
    asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    opensearch_doc_id VARCHAR(128),
    matched_field VARCHAR(64) NOT NULL, -- destination.ip, dns.query, file.hash.sha256
    incident_id BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 6. Response Orchestration
CREATE TABLE response_playbooks (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    playbook_code VARCHAR(32) NOT NULL UNIQUE, -- P001, P002, P003
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    action_type VARCHAR(64) NOT NULL, -- BLOCK_IP, DISABLE_USER, ISOLATE_HOST, RESTORE_IP, ENABLE_USER
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    target_type VARCHAR(32) NOT NULL, -- IP, USERNAME, ASSET
    rollback_supported BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE response_actions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_uuid VARCHAR(64) NOT NULL UNIQUE,
    playbook_code VARCHAR(32) NOT NULL REFERENCES response_playbooks(playbook_code),
    incident_id BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
    target_identifier VARCHAR(128) NOT NULL, -- IP address, username, or hostname
    target_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    requested_by VARCHAR(64) NOT NULL,
    approval_status VARCHAR(32) NOT NULL DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, AUTO_APPROVED
    approved_by VARCHAR(64),
    approved_at TIMESTAMP WITH TIME ZONE,
    execution_status VARCHAR(32) NOT NULL DEFAULT 'NOT_STARTED', -- NOT_STARTED, IN_PROGRESS, SUCCEEDED, FAILED, ROLLED_BACK
    is_simulation BOOLEAN NOT NULL DEFAULT TRUE,
    reversal_action_id BIGINT REFERENCES response_actions(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE response_executions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_id BIGINT NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    execution_duration_ms BIGINT NOT NULL,
    success BOOLEAN NOT NULL,
    status_code INTEGER,
    response_payload TEXT,
    error_message TEXT,
    verification_passed BOOLEAN NOT NULL DEFAULT FALSE
);

-- 7. Audit Logging
CREATE TABLE audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL, -- LOGIN, INCIDENT_CREATE, STATUS_CHANGE, ACTION_APPROVE, ACTION_EXECUTE
    target_entity VARCHAR(64) NOT NULL, -- USER, INCIDENT, ASSET, IOC, RESPONSE_ACTION
    target_id VARCHAR(64),
    source_ip VARCHAR(64),
    details TEXT
);

-- 8. Test Lab Runs & Atomic Red Team Results
CREATE TABLE test_runs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_uuid VARCHAR(64) NOT NULL UNIQUE,
    test_scenario_code VARCHAR(32) NOT NULL, -- T001 to T010
    scenario_name VARCHAR(128) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    target_host VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL, -- RUNNING, PASSED, FAILED, INCONCLUSIVE
    detection_observed BOOLEAN NOT NULL DEFAULT FALSE,
    mttd_seconds INTEGER,
    false_positives_observed INTEGER NOT NULL DEFAULT 0,
    details TEXT
);

-- Indexes for Query Performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_assets_persistent_id ON assets(persistent_id);
CREATE INDEX idx_assets_ip ON assets(ip_address);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_asset ON incidents(primary_asset_id);
CREATE INDEX idx_findings_incident ON incident_findings(incident_id);
CREATE INDEX idx_ioc_val ON ioc_indicators(indicator_value);
CREATE INDEX idx_ioc_matches_ioc ON ioc_matches(ioc_id);
CREATE INDEX idx_response_actions_status ON response_actions(approval_status, execution_status);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_actor ON audit_logs(actor);
