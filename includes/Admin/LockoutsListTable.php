<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\ObjectCacheService;

if (!class_exists('\\WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * WP_List_Table rendering the currently active brute-force lockouts.
 *
 * Data source: ObjectCacheService (Redis on WP Engine + Flywheel).
 * LoginProtection maintains a small index of locked IPs at key
 * `hmdg_security:lockout_index`; this table reads the index, then
 * hydrates each entry from the per-IP keys. No DB involvement.
 *
 * Page read cost: 1 cache GET for the index + N cache GETs for the
 * per-IP state, where N is the number of indexed IPs. The same pass
 * prunes stale entries, computes totals, and prepares the visible page.
 *
 * @since 1.5.0
 */
final class LockoutsListTable extends \WP_List_Table
{
    /** Object-cache key holding the list of locked IPs. */
    public const INDEX_KEY = 'hmdg_lockout_index';

    /** TTL for the index. Slightly exceeds the per-IP lockout TTL so
     *  the UI can show recently-expired entries fading out. */
    public const INDEX_TTL = 90000;

    /** Page size - fixed 20 per the v1.5.0 brief. */
    public const PAGE_SIZE = 20;

    public function __construct(
        private readonly ObjectCacheService $cacheService,
        private readonly SecurityConfig $config,
    ) {
        parent::__construct([
            'singular' => 'lockout',
            'plural'   => 'lockouts',
            'ajax'     => false,
            'screen'   => 'hmdg-security-lockouts',
        ]);
    }

    /** @return array<string, string> */
    public function get_columns(): array
    {
        return [
            'ip'           => __('IP Address', 'hmdg-security-pro'),
            'attempts'     => __('Attempts', 'hmdg-security-pro'),
            'locked_since' => __('Locked Since', 'hmdg-security-pro'),
            'expires_in'   => __('Expires In', 'hmdg-security-pro'),
            'actions'      => __('Actions', 'hmdg-security-pro'),
        ];
    }

    /** @return array<string, array{0: string, 1: bool}> */
    public function get_sortable_columns(): array
    {
        return [];
    }

    public function prepare_items(): void
    {
        $index = $this->fetchIndex();

        if ($index === []) {
            $this->items = [];
            $this->setPagination(0);
            return;
        }

        $survivors = [];

        foreach ($index as $ip => $meta) {
            $lockedAt = $this->cacheService->get(key: 'login_lockout_' . $ip);

            if ($lockedAt === false) {
                continue;
            }

            $effectiveLockedAt = is_int($lockedAt) ? $lockedAt : (int) ($meta['locked_at'] ?? time());

            $survivors[] = [
                'ip'           => $ip,
                'attempts'     => (int) ($meta['attempts'] ?? 0),
                'locked_since' => $effectiveLockedAt,
                'expires_in'   => $this->computeExpiresIn(lockedAt: $effectiveLockedAt),
            ];
        }

        if ($survivors === []) {
            $this->items = [];
            $this->setPagination(0);
            return;
        }

        usort(
            $survivors,
            static fn (array $a, array $b): int => ((int) ($b['locked_since'] ?? 0)) <=> ((int) ($a['locked_since'] ?? 0)),
        );

        $total = count($survivors);
        $pageNumber = $this->get_pagenum();
        $offset = ($pageNumber - 1) * self::PAGE_SIZE;

        $this->items = array_slice($survivors, $offset, self::PAGE_SIZE);
        $this->setPagination($total);
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_default($item, $column_name): string
    {
        return isset($item[$column_name]) ? (string) $item[$column_name] : '';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_ip($item): string
    {
        $ip = (string) ($item['ip'] ?? '');
        return '<code class="hmdg-ip">' . esc_html($ip) . '</code>';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_attempts($item): string
    {
        $n = (int) ($item['attempts'] ?? 0);
        return '<span class="hmdg-pill hmdg-pill--neutral">' . esc_html((string) $n) . '</span>';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_locked_since($item): string
    {
        $ts = (int) ($item['locked_since'] ?? 0);
        return esc_html($this->formatUkTime(timestamp: $ts));
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_expires_in($item): string
    {
        $remaining = (int) ($item['expires_in'] ?? 0);
        return '<span class="hmdg-countdown">' . esc_html($this->humanDuration(seconds: $remaining)) . '</span>';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_actions($item): string
    {
        $ip = (string) ($item['ip'] ?? '');
        if ($ip === '') {
            return '';
        }

        $url = wp_nonce_url(
            admin_url('admin-post.php?action=hmdg_unlock&ip=' . rawurlencode($ip)),
            'hmdg-unlock-' . $ip,
        );

        return sprintf(
            '<a href="%s" class="button button-small hmdg-btn hmdg-btn--unlock">%s</a>',
            esc_url($url),
            esc_html__('Unlock', 'hmdg-security-pro'),
        );
    }

    public function no_items(): void
    {
        echo '<div class="hmdg-empty">';
        echo '<div class="hmdg-empty__icon" aria-hidden="true">&#128737;</div>';
        echo '<h3>' . esc_html__('No active lockouts', 'hmdg-security-pro') . '</h3>';
        echo '<p>' . esc_html__('Your fleet is quiet right now. Lockouts appear here within seconds of a brute-force attempt reaching the threshold.', 'hmdg-security-pro') . '</p>';
        echo '</div>';
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function fetchIndex(): array
    {
        $raw = $this->cacheService->get(key: self::INDEX_KEY);

        if (!is_array($raw)) {
            return [];
        }

        /** @var array<string, array<string, mixed>> $raw */
        return $raw;
    }

    private function setPagination(int $total): void
    {
        $this->set_pagination_args([
            'total_items' => $total,
            'per_page'    => self::PAGE_SIZE,
            'total_pages' => $total === 0 ? 0 : (int) ceil($total / self::PAGE_SIZE),
        ]);

        $this->_column_headers = [
            $this->get_columns(),
            [],
            [],
        ];
    }

    private function computeExpiresIn(int $lockedAt): int
    {
        // SecurityConfig exposes the field as loginLockoutDuration
        // (seconds). Default to 15 minutes if somehow unset.
        $ttl = (int) ($this->config->loginLockoutDuration ?? 900);
        $elapsed = max(0, time() - $lockedAt);
        return max(0, $ttl - $elapsed);
    }

    private function formatUkTime(int $timestamp): string
    {
        if ($timestamp <= 0) {
            return '-';
        }
        try {
            $dt = new \DateTimeImmutable(
                '@' . $timestamp,
                new \DateTimeZone('UTC'),
            );
            return $dt->setTimezone(new \DateTimeZone('Europe/London'))
                ->format('d M Y H:i T');
        } catch (\Throwable) {
            return '-';
        }
    }

    private function humanDuration(int $seconds): string
    {
        if ($seconds <= 0) {
            return __('Expired', 'hmdg-security-pro');
        }
        if ($seconds < 60) {
            return sprintf(__('%ds', 'hmdg-security-pro'), $seconds);
        }
        if ($seconds < 3600) {
            return sprintf(__('%dm', 'hmdg-security-pro'), (int) floor($seconds / 60));
        }
        $hours = (int) floor($seconds / 3600);
        $minutes = (int) floor(($seconds % 3600) / 60);
        return sprintf(__('%dh %dm', 'hmdg-security-pro'), $hours, $minutes);
    }
}
