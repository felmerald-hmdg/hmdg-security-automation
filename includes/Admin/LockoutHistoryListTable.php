<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

if (!class_exists('\\WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * WP_List_Table rendering the persistent login-lockout history.
 *
 * @since 1.6.0
 */
final class LockoutHistoryListTable extends \WP_List_Table
{
    public const PAGE_SIZE = 20;

    public function __construct(
        private readonly LockoutLogRepository $repository,
    ) {
        parent::__construct([
            'singular' => 'lockout_history',
            'plural'   => 'lockout_history',
            'ajax'     => false,
            'screen'   => 'hmdg-security-lockout-history',
        ]);
    }

    /** @return array<string, string> */
    public function get_columns(): array
    {
        return [
            'ip'         => __('IP Address', 'hmdg-security-pro'),
            'username'   => __('Username', 'hmdg-security-pro'),
            'attempts'   => __('Attempts', 'hmdg-security-pro'),
            'locked_at'  => __('Locked At', 'hmdg-security-pro'),
            'expires_at' => __('Expires / Unlocked', 'hmdg-security-pro'),
            'duration'   => __('Duration', 'hmdg-security-pro'),
        ];
    }

    public function prepare_items(): void
    {
        $page = $this->get_pagenum();
        $result = $this->repository->listRecent(
            days: 30,
            page: $page,
            perPage: self::PAGE_SIZE,
        );

        $this->items = $result['items'];
        $this->set_pagination_args([
            'total_items' => $result['total'],
            'per_page'    => self::PAGE_SIZE,
            'total_pages' => $result['total'] === 0 ? 0 : (int) ceil($result['total'] / self::PAGE_SIZE),
        ]);
        $this->_column_headers = [
            $this->get_columns(),
            [],
            [],
        ];
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_default($item, $column_name): string
    {
        return isset($item[$column_name]) ? esc_html((string) $item[$column_name]) : '';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_ip($item): string
    {
        $ip = (string) ($item['ip'] ?? '');
        [$label, $class] = $this->statusBadge($item);

        return sprintf(
            '<code class="hmdg-ip">%s</code> <span class="hmdg-pill %s">%s</span>',
            esc_html($ip),
            esc_attr($class),
            esc_html($label),
        );
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_username($item): string
    {
        $username = trim((string) ($item['username'] ?? ''));

        return $username !== ''
            ? '<code class="hmdg-signal">' . esc_html($username) . '</code>'
            : '<span class="hmdg-muted">' . esc_html__('Unknown', 'hmdg-security-pro') . '</span>';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_attempts($item): string
    {
        return '<span class="hmdg-pill hmdg-pill--neutral">'
            . esc_html((string) ((int) ($item['attempts'] ?? 0)))
            . '</span>';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_locked_at($item): string
    {
        return esc_html($this->formatUkDateTime((string) ($item['locked_at'] ?? '')));
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_expires_at($item): string
    {
        $unlockedAt = (string) ($item['unlocked_at'] ?? '');

        if ($unlockedAt !== '') {
            return esc_html(
                sprintf(
                    __('Unlocked by admin at %s', 'hmdg-security-pro'),
                    $this->formatUkDateTime($unlockedAt),
                )
            );
        }

        // v1.10.0 — an indefinite lockout carries a far-future sentinel
        // expires_at but should display as a clear "admin action required"
        // status rather than "Expires 31 Dec 2099".
        if ((int) ($item['indefinite'] ?? 0) === 1) {
            return '<span class="hmdg-pill hmdg-pill--danger">'
                . esc_html__('Indefinite — admin unlock required', 'hmdg-security-pro')
                . '</span>';
        }

        return esc_html($this->formatUkDateTime((string) ($item['expires_at'] ?? '')));
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_duration($item): string
    {
        return esc_html($this->humanDuration((int) ($item['lockout_duration_seconds'] ?? 0)));
    }

    public function no_items(): void
    {
        echo '<div class="hmdg-empty">';
        echo '<div class="hmdg-empty__icon" aria-hidden="true">&#128274;</div>';
        echo '<h3>' . esc_html__('No lockout history in the last 30 days', 'hmdg-security-pro') . '</h3>';
        echo '<p>' . esc_html__('Triggered lockouts will remain visible here even after the active per-IP cache entry expires.', 'hmdg-security-pro') . '</p>';
        echo '</div>';
    }

    /**
     * @param array<string, mixed> $item
     * @return array{0: string, 1: string}
     */
    private function statusBadge(array $item): array
    {
        $unlockedAt = (string) ($item['unlocked_at'] ?? '');
        $expiresAt = (string) ($item['expires_at'] ?? '');
        $indefinite = (int) ($item['indefinite'] ?? 0) === 1;

        if ($unlockedAt !== '') {
            return [__('Unlocked', 'hmdg-security-pro'), 'hmdg-pill--ok'];
        }

        if ($indefinite) {
            return [__('Indefinite', 'hmdg-security-pro'), 'hmdg-pill--danger'];
        }

        $expiresTimestamp = $this->toTimestamp($expiresAt);
        if ($expiresTimestamp !== null && $expiresTimestamp > time()) {
            return [__('Active', 'hmdg-security-pro'), 'hmdg-pill--danger'];
        }

        return [__('Expired', 'hmdg-security-pro'), 'hmdg-pill--muted'];
    }

    private function formatUkDateTime(string $value): string
    {
        $timestamp = $this->toTimestamp($value);

        if ($timestamp === null) {
            return '-';
        }

        return (new \DateTimeImmutable('@' . $timestamp))
            ->setTimezone(new \DateTimeZone('Europe/London'))
            ->format('d M Y H:i T');
    }

    private function toTimestamp(string $value): ?int
    {
        if ($value === '') {
            return null;
        }

        try {
            return (new \DateTimeImmutable($value, new \DateTimeZone('UTC')))->getTimestamp();
        } catch (\Throwable) {
            return null;
        }
    }

    private function humanDuration(int $seconds): string
    {
        if ($seconds <= 0) {
            return __('Unknown', 'hmdg-security-pro');
        }

        if ($seconds % HOUR_IN_SECONDS === 0) {
            $hours = (int) ($seconds / HOUR_IN_SECONDS);
            return sprintf(
                _n('%d hour', '%d hours', $hours, 'hmdg-security-pro'),
                $hours,
            );
        }

        if ($seconds % MINUTE_IN_SECONDS === 0) {
            $minutes = (int) ($seconds / MINUTE_IN_SECONDS);
            return sprintf(
                _n('%d minute', '%d minutes', $minutes, 'hmdg-security-pro'),
                $minutes,
            );
        }

        return sprintf(
            _n('%d second', '%d seconds', $seconds, 'hmdg-security-pro'),
            $seconds,
        );
    }
}
