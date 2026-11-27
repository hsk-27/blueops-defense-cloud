-- =============================================================================
-- Flyway Migration V5: Synchronize M4 Incident Lifecycle Columns
-- Compatible with PostgreSQL 16 and H2 (PostgreSQL Mode)
-- =============================================================================

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority VARCHAR(32) DEFAULT 'P3_MEDIUM';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closure_notes TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_by VARCHAR(64);
