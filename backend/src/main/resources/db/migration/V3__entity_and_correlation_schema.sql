-- =============================================================================
-- BlueOps Entity Modeling, Observation Provenance, Relationships & Correlation Schema
-- Flyway Migration V3__entity_and_correlation_schema.sql
-- Compatible with PostgreSQL 16 and H2 (PostgreSQL Mode)
-- =============================================================================

-- 1. Canonical Entity Inventory
CREATE TABLE entities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    canonical_id VARCHAR(255) NOT NULL UNIQUE,
    entity_type VARCHAR(32) NOT NULL, -- HOST, USER, IP_ADDRESS, DOMAIN, PROCESS, FILE, HASH
    display_name VARCHAR(255) NOT NULL,
    attributes_json TEXT,
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, SUSPICIOUS, COMPROMISED, DORMANT
    observation_count BIGINT NOT NULL DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_entities_type ON entities(entity_type);
CREATE INDEX idx_entities_display_name ON entities(display_name);
CREATE INDEX idx_entities_risk ON entities(risk_score);

-- 2. Entity Observation Provenance
CREATE TABLE entity_observations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity_id BIGINT REFERENCES entities(id) ON DELETE CASCADE,
    canonical_id VARCHAR(255) NOT NULL,
    source_type VARCHAR(64) NOT NULL, -- TELEMETRY_EVENT, FINDING, IOC_MATCH
    source_id VARCHAR(128),
    host_context VARCHAR(128),
    raw_evidence_ref VARCHAR(255),
    observed_attributes_json TEXT,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_observations_entity_id ON entity_observations(entity_id);
CREATE INDEX idx_observations_canonical_id ON entity_observations(canonical_id);
CREATE INDEX idx_observations_observed_at ON entity_observations(observed_at);

-- 3. Persistent Entity Relationships
CREATE TABLE entity_relationships (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_canonical_id VARCHAR(255) NOT NULL,
    target_canonical_id VARCHAR(255) NOT NULL,
    relation_type VARCHAR(64) NOT NULL, -- HOST_HAS_USER, HOST_HAS_PROCESS, PROCESS_CONNECTED_TO, USER_AUTHENTICATED_TO, FILE_OBSERVED_ON, ENTITY_RESOLVED_TO_IP, PROCESS_SPAWNED_PROCESS, ENTITY_ASSOCIATED_WITH_FINDING
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    observation_count BIGINT NOT NULL DEFAULT 1,
    evidence_description VARCHAR(512),
    provenance_source VARCHAR(64),
    first_observed TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_observed TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_entity_relationship UNIQUE (source_canonical_id, target_canonical_id, relation_type)
);

CREATE INDEX idx_rel_source ON entity_relationships(source_canonical_id);
CREATE INDEX idx_rel_target ON entity_relationships(target_canonical_id);
CREATE INDEX idx_rel_type ON entity_relationships(relation_type);

-- 4. Correlation Rules Specification
CREATE TABLE correlation_rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    grouping_field VARCHAR(32) NOT NULL DEFAULT 'ENTITY_HOST', -- ENTITY_HOST, ENTITY_USER, ENTITY_IP
    time_window_minutes INT NOT NULL DEFAULT 60,
    conditions_json TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed default operational correlation rules
INSERT INTO correlation_rules (rule_id, name, description, severity, grouping_field, time_window_minutes, conditions_json, enabled)
VALUES
('CORR-001', 'Linux Account Compromise & Privilege Escalation', 'Observed repeated SSH authentication failures followed by successful authentication or privileged command execution on the same host.', 'CRITICAL', 'ENTITY_HOST', 60, '{"requiredRuleIds":["D001","D002","D004"],"minFindingCount":2,"requireAnyOf":["D002","D004"]}', true),
('CORR-002', 'Windows Multi-Stage Execution Chain', 'Suspicious parent process spawned encoded PowerShell leading to anomalous outbound network connection on the same host.', 'CRITICAL', 'ENTITY_HOST', 60, '{"requiredRuleIds":["D008","D009","D014"],"minFindingCount":2,"requireAnyOf":["D008"]}', true),
('CORR-003', 'Threat Intel IOC Activity With Secondary Endpoint Behavior', 'Network threat indicator matched against threat intelligence accompanied by local endpoint execution on the same asset.', 'HIGH', 'ENTITY_HOST', 60, '{"requiredRuleIds":["D015"],"minFindingCount":2,"mustIncludeAnyOtherRule":true}', true),
('CORR-004', 'Account Creation Followed by Persistence Installation', 'Creation of new local or domain account accompanied by service or scheduled task installation on the same asset.', 'HIGH', 'ENTITY_HOST', 60, '{"requiredRuleIds":["D005","D007","D010","D018"],"minFindingCount":2,"mustIncludePrimary":"D005"}', true),
('CORR-005', 'Cross-Host Malware Hash Distribution', 'Identical malicious executable or credential harvesting tool hash observed across multiple distinct hosts within the enterprise.', 'CRITICAL', 'ENTITY_HASH', 120, '{"requiredRuleIds":["D011","D008","D016"],"minHostCount":2}', true);

-- 5. Correlation Results & Case Promotion
CREATE TABLE correlations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correlation_id VARCHAR(64) NOT NULL UNIQUE,
    rule_id VARCHAR(32) NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    primary_entity_canonical_id VARCHAR(255) NOT NULL,
    primary_entity_type VARCHAR(32) NOT NULL,
    explanation TEXT NOT NULL,
    first_finding_time TIMESTAMP WITH TIME ZONE NOT NULL,
    last_finding_time TIMESTAMP WITH TIME ZONE NOT NULL,
    incident_id BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- OPEN, TRIAGED, PROMOTED_TO_INCIDENT, DISMISSED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_corr_rule ON correlations(rule_id);
CREATE INDEX idx_corr_entity ON correlations(primary_entity_canonical_id);
CREATE INDEX idx_corr_status ON correlations(status);

-- 6. Correlation Finding Associations
CREATE TABLE correlation_findings (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correlation_id BIGINT REFERENCES correlations(id) ON DELETE CASCADE,
    finding_id VARCHAR(64) NOT NULL,
    CONSTRAINT uq_corr_finding UNIQUE (correlation_id, finding_id)
);

CREATE INDEX idx_corr_fnd_finding ON correlation_findings(finding_id);

-- 7. Correlation Entity Associations
CREATE TABLE correlation_entities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correlation_id BIGINT REFERENCES correlations(id) ON DELETE CASCADE,
    entity_canonical_id VARCHAR(255) NOT NULL,
    CONSTRAINT uq_corr_entity UNIQUE (correlation_id, entity_canonical_id)
);

CREATE INDEX idx_corr_ent_canonical ON correlation_entities(entity_canonical_id);
