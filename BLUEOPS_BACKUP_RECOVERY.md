# BlueOps Backup & Disaster Recovery Architecture (M7)

**Document ID:** BLUEOPS-DOC-M7-001  
**Milestone:** M7 Operational Hardening & Reliability  
**Classification:** Reference Runbook & Recovery Design Specification  
**Design Target RPO (Unverified in Repository):** < 15 minutes (requires external WAL archiving / scheduled cron jobs)  
**Design Target RTO (Unverified in Repository):** < 30 minutes  
**Implementation Status:** Reference documentation only — automated backup scripts, GPG key provisioning, cron jobs, and offsite S3 vaults are **not** bundled or active in this workspace.

---

## 1. Executive Summary & Objective

The BlueOps Defensive Cybersecurity Platform maintains security telemetry, detection findings, investigation dossiers, entity relationship graphs, and SOAR response audit records.

This document defines the **reference** backup, recovery, and business continuity design targets for external infrastructure operators. Wait to rely on RPO/RTO guarantees until your deployment provisions and validates the external `pg_dump`/WAL automation described below. Note that Tier 4 in-memory buffers (normalized events, DLQ, and in-memory finding fallback when OpenSearch is offline) are **volatile** and lost across JVM restarts.

---

## 2. System State & Data Tier Inventory

BlueOps segregates data into four distinct storage tiers based on persistence requirements and criticality:

| Tier | Component | Technology | Primary Contents | Criticality | Loss Tolerance |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | Relational Database | PostgreSQL 16+ | Users, RBAC, Assets, Incidents, Findings, Evidence Provenance, Correlation Rules, SOAR Proposals, Response Audit Logs | **Critical** | Zero data loss (RPO < 15m) |
| **Tier 2** | Detection Rules | Local Git / Filesystem | Dynamic Sigma YAML rules, correlation rule configurations | **Critical** | Zero loss (Git managed) |
| **Tier 3** | Search & Analytics | OpenSearch 2.13+ | Ingested finding search indices, log aggregations | **Moderate** | Reconstructible from Tier 1 & telemetry buffer |
| **Tier 4** | Ingestion Buffer & DLQ | In-Memory Ring Buffer | Recent normalized events, dead-letter queue, poison-pill quarantines | **Transient** | In-flight batch loss tolerable |

---

## 3. Recovery Objectives

### 3.1 Recovery Point Objective (RPO): < 15 Minutes
- **Tier 1 (PostgreSQL):** Continuous WAL archiving or scheduled 15-minute incremental / transaction snapshots guarantee that no more than 15 minutes of investigation history, incident updates, or audit records are lost.
- **Tier 2 (Sigma Rules):** Immutable Git repository versioning yields an effective RPO of 0 minutes.

### 3.2 Recovery Time Objective (RTO): < 30 Minutes
- In cold-start disaster scenarios, platform recovery, database restoration, schema verification via Flyway, and service readiness probes must complete within 30 minutes from backup retrieval.

---

## 4. Backup Procedures

### 4.1 Tier 1: Reference PostgreSQL Backup Template (`pg_dump`)
> **Note:** `/opt/blueops/scripts/backup_postgres.sh` is an unimplemented reference operator template and is not shipped inside this repository.

#### 4.1.1 Logical Dump (`pg_dump`)
Logical backups capture consistent relational state across Flyway schemas (`V1` through `V4`):

```bash
#!/usr/bin/env bash
# Script: /opt/blueops/scripts/backup_postgres.sh
set -euo pipefail

BACKUP_DIR="/var/backups/blueops/postgres"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/blueops_db_${TIMESTAMP}.dump"
ENCRYPTION_KEY_FILE="/etc/blueops/backup_key.gpg"

mkdir -p "${BACKUP_DIR}"

# Execute custom-format compressed backup with database schema and data
PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump \
    -h "${POSTGRES_HOST:-localhost}" \
    -U "${POSTGRES_USER:-blueops}" \
    -d "${POSTGRES_DB:-blueops}" \
    -F c \
    -b \
    -v \
    -f "${BACKUP_FILE}"

# Encrypt backup archive with GPG AES-256
gpg --batch --yes --encrypt --recipient-file "${ENCRYPTION_KEY_FILE}" "${BACKUP_FILE}"
rm -f "${BACKUP_FILE}"

# Compute SHA-256 checksum for audit and integrity verification
sha256sum "${BACKUP_FILE}.gpg" > "${BACKUP_FILE}.gpg.sha256"

# Retain local backups: prune older than 30 days
find "${BACKUP_DIR}" -type f -name "blueops_db_*.dump.gpg*" -mtime +30 -delete
```

### 4.2 Tier 2: Sigma Rule Directory Synchronization
The Sigma rule corpus (`detection-rules/sigma/`) is synchronized using Git tracking or rsync to cold backup storage:
```bash
tar -czf /var/backups/blueops/sigma/sigma_rules_${TIMESTAMP}.tar.gz -C /opt/blueops detection-rules/
```

### 4.3 Backup Retention & Off-Site Replication Schedule
- **Snapshots:** Daily snapshots at 02:00 UTC.
- **Retention:**
  - 14 daily snapshots on primary backup volume.
  - 8 weekly snapshots replicated to isolated off-site S3-compatible cold vault (object-locked with WORM compliance).
  - 12 monthly snapshots retained for statutory compliance.

---

## 5. Restore Procedures

### 5.1 Pre-Restoration Checklist
1. Validate backup integrity:
   ```bash
   sha256sum -c blueops_db_20261120_020000.dump.gpg.sha256
   ```
2. Decrypt archive:
   ```bash
   gpg --batch --decrypt --output blueops_db_restore.dump blueops_db_20261120_020000.dump.gpg
   ```
3. Stop BlueOps backend service to prevent write race conditions:
   ```bash
   systemctl stop blueops-backend
   ```

### 5.2 Database Restoration
Execute restore using `pg_restore` into a clean database:
```bash
# Drop existing active connections
psql -U postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'blueops';"

# Recreate database
psql -U postgres -c "DROP DATABASE IF EXISTS blueops;"
psql -U postgres -c "CREATE DATABASE blueops OWNER blueops;"

# Restore schema and data
pg_restore -U blueops -d blueops -v --clean --if-exists blueops_db_restore.dump
```

### 5.3 Automated Schema & Flyway Validation
Start BlueOps Backend. On boot, Spring Boot's Flyway integration runs:
```
Flyway Community Edition 10.x by Redgate
Database: PostgreSQL 16.2
Schema 'public' is up to date. No migration necessary.
```
If schema checksum mismatch occurs due to manual patch divergence:
```bash
# Run Flyway repair via backend profile or Maven wrapper
java -jar app.jar --spring.flyway.repair=true
```

### 5.4 Tier 3 (OpenSearch) Re-Initialization Note
Note that in the current modular monolith, detection findings primarily live in the OpenSearch adapter index and in-memory `ConcurrentHashMap` fallback (with incident-linked findings persisted in PostgreSQL `incident_findings`). Only findings attached to PostgreSQL incidents survive a cold JVM + empty OpenSearch cluster loss; unlinked raw findings require OpenSearch snapshots/persistence.

---

## 6. Reference Disaster Recovery Drill Checklist (Not Executed Automatically)

Operators commissioning a staging or production cluster should execute and record this verification runbook manually:

| Step | Action | Expected Result | Verification Check |
| :--- | :--- | :--- | :--- |
| **D-1** | Simulate PostgreSQL unavailability | Connection errors logged in `/api/v1/system/health` | HTTP 503 `status: DEGRADED` |
| **D-2** | Execute operator-provisioned restore script on isolated target | Clean restoration with 0 fatal errors | Exit code 0 |
| **D-3** | Point backend to restored database | Spring Boot starts cleanly; Flyway validates V1..V4 | Log `Started BlueOpsApplication in X.XX seconds` |
| **D-4** | Execute API probe | Query incidents and target catalog | Relational records match pre-drill dump |
| **D-5** | Verify response engine containment | Engine initializes in `SIMULATION` mode | `BLUEOPS_ALLOW_LIVE_HOST_DISRUPTION=false` |

---

## 7. Governance & Actual Status
- **Implemented Today:** Flyway schema validation (`V1`–`V4`) on startup; OpenSearch disconnect resilience (`in-memory` fallback).
- **Not Implemented / Not Executed:** Automated `pg_dump` cron scripts, WAL archiving, encrypted off-site S3 vaults, and automated RPO < 15m / RTO < 30m restore drills.
