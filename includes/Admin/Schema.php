<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

/**
 * One-shot database schema installer for the v1.5.0 operations UI.
 *
 * Runs exclusively from the plugin activation hook — never on normal
 * boot paths. The single table `{$wpdb->prefix}hmdg_security_findings`
 * stores malware quarantine metadata. File contents NEVER enter this
 * table; the quarantined file itself lives on disk under
 * wp-content/hmdg-security-pro/quarantine/.
 *
 * Indexing strategy:
 *   - idx_status_created: serves the default list query
 *     (WHERE status=? ORDER BY created_at DESC LIMIT 20 OFFSET ?)
 *     without a filesort.
 *   - idx_severity_created: secondary admin filter.
 *   - idx_path (191-char prefix): prevents duplicate rows for the
 *     same file path on repeat detections.
 *
 * @security No runtime data is read from this table on anonymous
 *           front-end page loads. Every SELECT lives in
 *           FindingsRepository which is only instantiated inside
 *           the admin-context boot branch of Plugin.php.
 *
 * @since 1.5.0
 */
final class Schema
{
    /** Schema version marker stored in wp_options for migration tracking. */
    public const VERSION = '1.10.0';

    /** Option name holding the installed schema version. */
    public const OPTION_VERSION = 'hmdg_security_schema_version';

    /**
     * Create or upgrade the findings table. Idempotent.
     *
     * dbDelta is the only WordPress-blessed mechanism for CREATE TABLE
     * + ALTER TABLE in activation hooks; it parses the SQL statement
     * and issues the correct DDL for the current MySQL/MariaDB version.
     *
     * @return void
     */
    public static function install(): void
    {
        global $wpdb;

        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }

        $table = self::tableName();
        $lockoutLogTable = self::lockoutLogTableName();
        $charsetCollate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            severity TINYINT(3) UNSIGNED NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'quarantined',
            original_path VARCHAR(500) NOT NULL,
            quarantine_path VARCHAR(500) NULL,
            sha256 CHAR(64) NOT NULL,
            top_signal_label VARCHAR(200) NULL,
            top_signal_weight SMALLINT(6) NULL,
            signal_categories VARCHAR(200) NULL,
            source VARCHAR(64) NOT NULL,
            actioned_at DATETIME NULL,
            actioned_by BIGINT(20) UNSIGNED NULL,
            PRIMARY KEY  (id),
            KEY idx_status_created (status, created_at),
            KEY idx_severity_created (severity, created_at),
            KEY idx_path (original_path(191))
        ) {$charsetCollate};";

        $lockoutSql = "CREATE TABLE {$lockoutLogTable} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL,
            username VARCHAR(191) NOT NULL DEFAULT '',
            attempts SMALLINT(5) UNSIGNED NOT NULL,
            locked_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            lockout_duration_seconds INT(10) UNSIGNED NOT NULL,
            indefinite TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
            unlocked_at DATETIME NULL,
            unlocked_by BIGINT(20) UNSIGNED NULL,
            unlock_reason VARCHAR(32) NULL,
            PRIMARY KEY  (id),
            KEY idx_ip_locked (ip, locked_at),
            KEY idx_locked_at (locked_at),
            KEY idx_expires (expires_at),
            KEY idx_indefinite_active (indefinite, unlocked_at)
        ) {$charsetCollate};";

        dbDelta($sql);
        dbDelta($lockoutSql);

        update_option(self::OPTION_VERSION, self::VERSION, false);
    }

    /**
     * Fully-qualified table name for the findings store.
     */
    public static function tableName(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'hmdg_security_findings';
    }

    /**
     * Fully-qualified table name for the persistent lockout-history store.
     */
    public static function lockoutLogTableName(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'hmdg_security_lockout_log';
    }

    /**
     * Whether the lockout-history table currently exists.
     */
    public static function lockoutLogExists(): bool
    {
        global $wpdb;

        $table = $wpdb->get_var(
            $wpdb->prepare(
                'SHOW TABLES LIKE %s',
                self::lockoutLogTableName(),
            )
        );

        return $table === self::lockoutLogTableName();
    }
}
