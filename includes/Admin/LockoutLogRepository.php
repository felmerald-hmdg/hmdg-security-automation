<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

/**
 * Data-access layer for the persistent login-lockout history table.
 *
 * This repository is admin/cron-only by construction. Its sole runtime
 * writer is LoginProtection::lockIp() on a failed-login POST path; reads
 * happen only in the admin list table and the weekly retention purge.
 *
 * @since 1.6.0
 */
final class LockoutLogRepository
{
    public const PAGE_SIZE = 20;

    public function __construct(
        private readonly \wpdb $wpdb,
        private readonly string $table,
    ) {}

    /**
     * Insert a new lockout row. Returns the row ID, or null on failure.
     *
     * @param array<string, mixed> $data
     */
    public function insert(array $data): ?int
    {
        foreach ([
            'ip',
            'username',
            'attempts',
            'locked_at',
            'expires_at',
            'lockout_duration_seconds',
        ] as $requiredKey) {
            if (!array_key_exists($requiredKey, $data)) {
                return null;
            }
        }

        $indefinite = ((int) ($data['indefinite'] ?? 0)) === 0 ? 0 : 1;

        $result = $this->wpdb->query(
            $this->wpdb->prepare(
                'INSERT INTO %i (
                    ip,
                    username,
                    attempts,
                    locked_at,
                    expires_at,
                    lockout_duration_seconds,
                    indefinite
                ) VALUES (%s, %s, %d, %s, %s, %d, %d)',
                $this->table,
                (string) $data['ip'],
                (string) $data['username'],
                (int) $data['attempts'],
                (string) $data['locked_at'],
                (string) $data['expires_at'],
                (int) $data['lockout_duration_seconds'],
                $indefinite,
            )
        );

        if ($result === false) {
            return null;
        }

        return (int) $this->wpdb->insert_id;
    }

    /**
     * Whether an active indefinite lockout row exists for the given IP.
     *
     * "Active" = indefinite=1 AND unlocked_at IS NULL. Used as a DB
     * fallback for LoginProtection::isLockedOut() when the cache entry
     * has been evicted (Redis flush, WPE maintenance, fleet deploy with
     * CACHE_CLEAR). Only called in login-POST / XML-RPC context, never
     * on anonymous front-end GETs, per the isLoginContext() gate in
     * Plugin::boot().
     *
     * @since 1.10.0
     */
    public function hasActiveIndefiniteLockout(string $ip): bool
    {
        $row = $this->wpdb->get_var(
            $this->wpdb->prepare(
                'SELECT 1 FROM %i
                 WHERE ip = %s
                   AND indefinite = 1
                   AND unlocked_at IS NULL
                 LIMIT 1',
                $this->table,
                $ip,
            )
        );

        return $row !== null;
    }

    /**
     * Mark currently-active rows for the given IP as manually unlocked.
     *
     * v1.10.0: predicate extended to catch indefinite rows explicitly.
     * Indefinite rows use a far-future sentinel `expires_at`, so the
     * `expires_at > UTC_TIMESTAMP()` half of the OR already matches
     * them; the `indefinite = 1` half is belt-and-braces in case a
     * future migration ever changes the sentinel convention.
     */
    public function markUnlocked(string $ip, int $actionedBy, string $reason): int
    {
        $result = $this->wpdb->query(
            $this->wpdb->prepare(
                'UPDATE %i
                 SET unlocked_at = UTC_TIMESTAMP(),
                     unlocked_by = %d,
                     unlock_reason = %s
                 WHERE ip = %s
                   AND unlocked_at IS NULL
                   AND (indefinite = 1 OR expires_at > UTC_TIMESTAMP())',
                $this->table,
                $actionedBy,
                $reason,
                $ip,
            )
        );

        return $result === false ? 0 : (int) $result;
    }

    /**
     * Fetch recent lockout rows with pagination metadata.
     *
     * @return array{items: list<array<string, mixed>>, total: int}
     */
    public function listRecent(int $days = 30, int $page = 1, int $perPage = self::PAGE_SIZE): array
    {
        $days = max(1, $days);
        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $offset = ($page - 1) * $perPage;

        $total = (int) $this->wpdb->get_var(
            $this->wpdb->prepare(
                'SELECT COUNT(*)
                 FROM %i
                 WHERE locked_at >= UTC_TIMESTAMP() - INTERVAL %d DAY',
                $this->table,
                $days,
            )
        );

        /** @var list<array<string, mixed>> $items */
        $items = $this->wpdb->get_results(
            $this->wpdb->prepare(
                'SELECT *
                 FROM %i
                 WHERE locked_at >= UTC_TIMESTAMP() - INTERVAL %d DAY
                 ORDER BY locked_at DESC, id DESC
                 LIMIT %d OFFSET %d',
                $this->table,
                $days,
                $perPage,
                $offset,
            ),
            ARRAY_A,
        );

        return [
            'items' => $items ?: [],
            'total' => $total,
        ];
    }

    /**
     * Purge rows older than the given retention window.
     */
    public function purgeOlderThan(int $days): int
    {
        if (!wp_doing_cron()) {
            return 0;
        }

        $days = max(1, $days);

        // v1.10.0 — never purge an active indefinite row (indefinite = 1
        // AND unlocked_at IS NULL). Those are held intentionally until
        // an admin unlocks. Once admin-unlocked, the row re-enters the
        // standard age-based retention window.
        $result = $this->wpdb->query(
            $this->wpdb->prepare(
                'DELETE FROM %i
                 WHERE locked_at < UTC_TIMESTAMP() - INTERVAL %d DAY
                   AND (indefinite = 0 OR unlocked_at IS NOT NULL)',
                $this->table,
                $days,
            )
        );

        return $result === false ? 0 : (int) $result;
    }
}
