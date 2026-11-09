<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

use HMDG\Security\Detection\Severity;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Data-access layer for the v1.5.0 findings table.
 *
 * ALL $wpdb interaction lives here — every other Admin class talks
 * to this repository, never to $wpdb directly. Every query uses
 * $wpdb->prepare() with typed placeholders; no string concatenation
 * into SQL ever.
 *
 * Performance envelope (WP Engine + Flywheel, both Redis-backed):
 *   - list(): 1 indexed SELECT with LIMIT 20 — sub-millisecond.
 *   - count(): 1 COUNT(*), cached 60s in object cache — sub-millisecond
 *     on cache hit, ~1ms on miss.
 *   - findById(): primary-key lookup — sub-millisecond.
 *   - recordQuarantine(): 1 INSERT — ~1ms.
 *   - updateStatus(): 1 UPDATE by PK — sub-millisecond.
 *
 * Page-render budget: at most 2 queries (list + count), with count
 * typically a cache hit. Well under the 50ms PHP CPU target.
 *
 * @security Every method validates capability at the call site
 *           (AdminPage/AdminActions), but repository methods assume
 *           authenticated admin context. Do NOT call these on
 *           anonymous request paths.
 *
 * @since 1.5.0
 */
final class FindingsRepository
{
    /** Default page size for list queries. Matches the UI pagination. */
    public const PAGE_SIZE = 20;

    /** Object-cache key prefix for count caches. */
    private const COUNT_CACHE_PREFIX = 'hmdg_findings_count_';

    /** Count-cache TTL (seconds). Keeps page-change clicks snappy. */
    private const COUNT_CACHE_TTL = 60;

    /** Valid status values. */
    public const STATUS_QUARANTINED = 'quarantined';
    public const STATUS_DELETED = 'deleted';
    public const STATUS_FALSE_POSITIVE = 'false_positive';
    public const STATUS_FLAGGED = 'flagged';

    public function __construct(
        private readonly ObjectCacheService $cacheService,
    ) {}

    /**
     * Insert a new finding row. Returns the new row ID, or null on failure.
     *
     * @param array<string, mixed> $data Column map (validated by caller).
     */
    public function insert(array $data): ?int
    {
        global $wpdb;

        $now = gmdate('Y-m-d H:i:s');

        $payload = [
            'created_at'         => $data['created_at'] ?? $now,
            'severity'           => (int) ($data['severity'] ?? Severity::HighRisk->value),
            'status'             => (string) ($data['status'] ?? self::STATUS_QUARANTINED),
            'original_path'      => (string) ($data['original_path'] ?? ''),
            'quarantine_path'    => isset($data['quarantine_path']) ? (string) $data['quarantine_path'] : null,
            'sha256'             => (string) ($data['sha256'] ?? ''),
            'top_signal_label'   => isset($data['top_signal_label']) ? (string) $data['top_signal_label'] : null,
            'top_signal_weight'  => isset($data['top_signal_weight']) ? (int) $data['top_signal_weight'] : null,
            'signal_categories'  => isset($data['signal_categories']) ? (string) $data['signal_categories'] : null,
            'source'             => (string) ($data['source'] ?? 'malware_scanner'),
        ];

        $formats = ['%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s'];

        $result = $wpdb->insert(Schema::tableName(), $payload, $formats);

        if ($result === false) {
            return null;
        }

        $this->invalidateCountCache();

        return (int) $wpdb->insert_id;
    }

    /**
     * Update status + actioned metadata for a finding row.
     */
    public function updateStatus(int $id, string $newStatus, int $actionedBy): bool
    {
        global $wpdb;

        $result = $wpdb->update(
            Schema::tableName(),
            [
                'status'      => $newStatus,
                'actioned_at' => gmdate('Y-m-d H:i:s'),
                'actioned_by' => $actionedBy,
            ],
            ['id' => $id],
            ['%s', '%s', '%d'],
            ['%d'],
        );

        if ($result === false) {
            return false;
        }

        $this->invalidateCountCache();

        return true;
    }

    /**
     * Fetch a single finding by primary key.
     *
     * @return array<string, mixed>|null
     */
    public function findById(int $id): ?array
    {
        global $wpdb;

        $table = Schema::tableName();

        /** @var array<string, mixed>|null $row */
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$table} WHERE id = %d LIMIT 1",
                $id,
            ),
            ARRAY_A,
        );

        return $row ?: null;
    }

    /**
     * Paginated list of findings matching $status.
     *
     * @return list<array<string, mixed>>
     */
    public function listByStatus(string $status, int $page = 1): array
    {
        global $wpdb;

        $offset = max(0, ($page - 1) * self::PAGE_SIZE);
        $table  = Schema::tableName();

        /** @var list<array<string, mixed>> $rows */
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, created_at, severity, status, original_path,
                        quarantine_path, sha256, top_signal_label,
                        top_signal_weight, signal_categories, source,
                        actioned_at, actioned_by
                 FROM {$table}
                 WHERE status = %s
                 ORDER BY created_at DESC, id DESC
                 LIMIT %d OFFSET %d",
                $status,
                self::PAGE_SIZE,
                $offset,
            ),
            ARRAY_A,
        );

        return $rows ?: [];
    }

    /**
     * Total rows matching $status. Cached in object cache for 60s so
     * page-change clicks don't re-query.
     */
    public function countByStatus(string $status): int
    {
        $cacheKey = self::COUNT_CACHE_PREFIX . $status;
        $cached   = $this->cacheService->get(key: $cacheKey);

        if (is_int($cached)) {
            return $cached;
        }

        global $wpdb;
        $table = Schema::tableName();

        $count = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE status = %s",
                $status,
            ),
        );

        $this->cacheService->set(
            key: $cacheKey,
            value: $count,
            expiration: self::COUNT_CACHE_TTL,
        );

        return $count;
    }

    /**
     * Count rows for multiple statuses with at most one SQL query on cache miss.
     *
     * @param list<string> $statuses
     * @return array<string, int>
     */
    public function countByStatuses(array $statuses): array
    {
        $result = [];
        $missing = [];

        foreach ($statuses as $status) {
            $cacheKey = self::COUNT_CACHE_PREFIX . $status;
            $cached = $this->cacheService->get(key: $cacheKey);

            if (is_int($cached)) {
                $result[$status] = $cached;
                continue;
            }

            $missing[] = $status;
        }

        if ($missing === []) {
            return $result;
        }

        global $wpdb;
        $table = Schema::tableName();
        $placeholders = implode(', ', array_fill(0, count($missing), '%s'));

        /** @var list<array{status: string, total: string|int}> $rows */
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT status, COUNT(*) AS total
                 FROM {$table}
                 WHERE status IN ({$placeholders})
                 GROUP BY status",
                ...$missing,
            ),
            ARRAY_A,
        );

        $dbCounts = array_fill_keys($missing, 0);
        foreach ($rows as $row) {
            $status = (string) ($row['status'] ?? '');
            if ($status === '' || !array_key_exists($status, $dbCounts)) {
                continue;
            }

            $dbCounts[$status] = (int) ($row['total'] ?? 0);
        }

        foreach ($dbCounts as $status => $count) {
            $this->cacheService->set(
                key: self::COUNT_CACHE_PREFIX . $status,
                value: $count,
                expiration: self::COUNT_CACHE_TTL,
            );
            $result[$status] = $count;
        }

        return $result;
    }

    /**
     * Look up an existing quarantined row for the given original path.
     * Used by QuarantineService to implement upsert semantics on repeat
     * detections of the same file.
     *
     * @return array<string, mixed>|null
     */
    public function findByPathAndStatus(string $originalPath, string $status): ?array
    {
        global $wpdb;

        $table = Schema::tableName();

        /** @var array<string, mixed>|null $row */
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$table}
                 WHERE original_path = %s AND status = %s
                 ORDER BY id DESC
                 LIMIT 1",
                $originalPath,
                $status,
            ),
            ARRAY_A,
        );

        return $row ?: null;
    }

    /**
     * Clear cached counts for all statuses. Called after any write.
     */
    private function invalidateCountCache(): void
    {
        foreach ([
            self::STATUS_QUARANTINED,
            self::STATUS_DELETED,
            self::STATUS_FALSE_POSITIVE,
            self::STATUS_FLAGGED,
        ] as $status) {
            $this->cacheService->delete(key: self::COUNT_CACHE_PREFIX . $status);
        }
    }
}
