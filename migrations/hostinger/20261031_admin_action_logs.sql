-- Hostinger operational database migration: administrator activity history.
-- Run against the Hostinger MySQL database after taking a backup.
CREATE TABLE IF NOT EXISTS admin_action_logs (
    id BIGINT NOT NULL AUTO_INCREMENT,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NULL,
    details_json LONGTEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    INDEX ix_admin_action_logs_created (created_at, id),
    INDEX ix_admin_action_logs_entity (entity_type, entity_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
