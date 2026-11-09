<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

use HMDG\Security\Detection\Severity;

if (!class_exists('\\WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * WP_List_Table rendering quarantined malware findings.
 *
 * Data source: `{$wpdb->prefix}hmdg_security_findings` via
 * FindingsRepository. Default view filters by status=quarantined.
 * A status query arg switches between quarantined / deleted /
 * false_positive / flagged.
 *
 * Query cost per render: 1 SELECT (indexed) + 1 COUNT (cached 60s
 * in Redis). Typical <2ms total on WP Engine.
 *
 * @since 1.5.0
 */
final class QuarantineListTable extends \WP_List_Table
{
    public const PAGE_SIZE = FindingsRepository::PAGE_SIZE;

    /** Currently active status filter ("quarantined" / "deleted" etc). */
    private string $status;

    public function __construct(
        private readonly FindingsRepository $repository,
        string $status = FindingsRepository::STATUS_QUARANTINED,
    ) {
        parent::__construct([
            'singular' => 'finding',
            'plural'   => 'findings',
            'ajax'     => false,
            'screen'   => 'hmdg-security-quarantine',
        ]);

        $this->status = $this->sanitiseStatus($status);
    }

    /** @return array<string, string> */
    public function get_columns(): array
    {
        return [
            'severity'   => __('Severity', 'hmdg-security-pro'),
            'file'       => __('File', 'hmdg-security-pro'),
            'detected'   => __('Detected', 'hmdg-security-pro'),
            'source'     => __('Source', 'hmdg-security-pro'),
            'top_signal' => __('Top Signal', 'hmdg-security-pro'),
            'status'     => __('Status', 'hmdg-security-pro'),
            'actions'    => __('Actions', 'hmdg-security-pro'),
        ];
    }

    public function prepare_items(): void
    {
        $pageNumber = $this->get_pagenum();
        $this->items = $this->repository->listByStatus(status: $this->status, page: $pageNumber);

        $total = $this->repository->countByStatus(status: $this->status);

        $this->set_pagination_args([
            'total_items' => $total,
            'per_page'    => self::PAGE_SIZE,
            'total_pages' => (int) ceil($total / self::PAGE_SIZE),
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
        return isset($item[$column_name]) ? (string) $item[$column_name] : '';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_severity($item): string
    {
        $value = (int) ($item['severity'] ?? 0);
        $severity = Severity::tryFrom($value) ?? Severity::Informational;

        $class = match ($severity) {
            Severity::HighRisk       => 'hmdg-pill--danger',
            Severity::Suspicious     => 'hmdg-pill--warning',
            Severity::NeedsReview    => 'hmdg-pill--info',
            Severity::Informational  => 'hmdg-pill--muted',
            Severity::ExpectedUpdate => 'hmdg-pill--neutral',
            Severity::Safe           => 'hmdg-pill--ok',
        };

        $label = $this->severityLabel(severity: $severity);

        return sprintf(
            '<span class="hmdg-pill %s">%s</span>',
            esc_attr($class),
            esc_html($label),
        );
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_file($item): string
    {
        $path = (string) ($item['original_path'] ?? '');
        if ($path === '') {
            return '<em>' . esc_html__('(unknown)', 'hmdg-security-pro') . '</em>';
        }

        $short = $this->truncateMiddle(value: $path, max: 64);

        return sprintf(
            '<span class="hmdg-file" title="%s"><code>%s</code></span>',
            esc_attr($path),
            esc_html($short),
        );
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_detected($item): string
    {
        $raw = (string) ($item['created_at'] ?? '');
        if ($raw === '') {
            return '—';
        }
        try {
            $dt = new \DateTimeImmutable($raw, new \DateTimeZone('UTC'));
            return esc_html($dt->setTimezone(new \DateTimeZone('Europe/London'))->format('d M Y H:i T'));
        } catch (\Throwable) {
            return esc_html($raw);
        }
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_source($item): string
    {
        $source = (string) ($item['source'] ?? '');
        $label = match ($source) {
            'malware_scanner'      => __('Malware Scanner', 'hmdg-security-pro'),
            'file_integrity_scan'  => __('Integrity Scan', 'hmdg-security-pro'),
            default                => ucwords(str_replace('_', ' ', $source)),
        };
        return '<span class="hmdg-source">' . esc_html($label) . '</span>';
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_top_signal($item): string
    {
        $label = (string) ($item['top_signal_label'] ?? '');
        $weight = $item['top_signal_weight'] ?? null;
        if ($label === '') {
            return '—';
        }

        $short = $this->truncateMiddle(value: $label, max: 48);
        $weightStr = $weight !== null ? sprintf(' <span class="hmdg-weight">%d</span>', (int) $weight) : '';

        return sprintf(
            '<span class="hmdg-signal" title="%s">%s</span>%s',
            esc_attr($label),
            esc_html($short),
            $weightStr,
        );
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_status($item): string
    {
        $status = (string) ($item['status'] ?? '');
        $class = match ($status) {
            FindingsRepository::STATUS_QUARANTINED    => 'hmdg-status--quarantined',
            FindingsRepository::STATUS_DELETED        => 'hmdg-status--deleted',
            FindingsRepository::STATUS_FALSE_POSITIVE => 'hmdg-status--fp',
            FindingsRepository::STATUS_FLAGGED        => 'hmdg-status--flagged',
            default                                    => 'hmdg-status--neutral',
        };

        return sprintf(
            '<span class="hmdg-status %s"><span class="hmdg-status__dot" aria-hidden="true"></span>%s</span>',
            esc_attr($class),
            esc_html($this->statusLabel(status: $status)),
        );
    }

    /**
     * @param array<string, mixed> $item
     */
    public function column_actions($item): string
    {
        $id = (int) ($item['id'] ?? 0);
        $status = (string) ($item['status'] ?? '');
        if ($id === 0 || $status !== FindingsRepository::STATUS_QUARANTINED) {
            return '<span class="hmdg-muted">—</span>';
        }

        $deleteUrl = wp_nonce_url(
            admin_url('admin-post.php?action=hmdg_quarantine_delete&id=' . $id),
            'hmdg-quarantine-delete-' . $id,
        );
        $fpUrl = wp_nonce_url(
            admin_url('admin-post.php?action=hmdg_quarantine_false_positive&id=' . $id),
            'hmdg-quarantine-fp-' . $id,
        );

        $confirmDelete = esc_js(__('Permanently delete this quarantined file? This cannot be undone.', 'hmdg-security-pro'));
        $confirmFp = esc_js(__('Restore this file to its original location and mark the alert as a false positive?', 'hmdg-security-pro'));

        return sprintf(
            '<div class="hmdg-actions">'
            . '<a href="%s" class="button button-small hmdg-btn hmdg-btn--danger" onclick="return confirm(\'%s\');">%s</a>'
            . '<a href="%s" class="button button-small hmdg-btn hmdg-btn--ok" onclick="return confirm(\'%s\');">%s</a>'
            . '</div>',
            esc_url($deleteUrl),
            $confirmDelete,
            esc_html__('Delete', 'hmdg-security-pro'),
            esc_url($fpUrl),
            $confirmFp,
            esc_html__('False positive', 'hmdg-security-pro'),
        );
    }

    public function no_items(): void
    {
        $message = match ($this->status) {
            FindingsRepository::STATUS_QUARANTINED =>
                __('Nothing in quarantine. Your fleet is clean.', 'hmdg-security-pro'),
            FindingsRepository::STATUS_DELETED =>
                __('No findings have been permanently deleted yet.', 'hmdg-security-pro'),
            FindingsRepository::STATUS_FALSE_POSITIVE =>
                __('No findings flagged as false positives.', 'hmdg-security-pro'),
            default =>
                __('No findings.', 'hmdg-security-pro'),
        };

        echo '<div class="hmdg-empty">';
        echo '<div class="hmdg-empty__icon" aria-hidden="true">✅</div>';
        echo '<h3>' . esc_html__('All clear', 'hmdg-security-pro') . '</h3>';
        echo '<p>' . esc_html($message) . '</p>';
        echo '</div>';
    }

    private function sanitiseStatus(string $status): string
    {
        $allowed = [
            FindingsRepository::STATUS_QUARANTINED,
            FindingsRepository::STATUS_DELETED,
            FindingsRepository::STATUS_FALSE_POSITIVE,
            FindingsRepository::STATUS_FLAGGED,
        ];
        return in_array($status, $allowed, true) ? $status : FindingsRepository::STATUS_QUARANTINED;
    }

    private function severityLabel(Severity $severity): string
    {
        return match ($severity) {
            Severity::HighRisk       => __('High Risk', 'hmdg-security-pro'),
            Severity::Suspicious     => __('Suspicious', 'hmdg-security-pro'),
            Severity::NeedsReview    => __('Needs Review', 'hmdg-security-pro'),
            Severity::Informational  => __('Info', 'hmdg-security-pro'),
            Severity::ExpectedUpdate => __('Expected Update', 'hmdg-security-pro'),
            Severity::Safe           => __('Safe', 'hmdg-security-pro'),
        };
    }

    private function statusLabel(string $status): string
    {
        return match ($status) {
            FindingsRepository::STATUS_QUARANTINED    => __('Quarantined', 'hmdg-security-pro'),
            FindingsRepository::STATUS_DELETED        => __('Deleted', 'hmdg-security-pro'),
            FindingsRepository::STATUS_FALSE_POSITIVE => __('False positive', 'hmdg-security-pro'),
            FindingsRepository::STATUS_FLAGGED        => __('Flagged', 'hmdg-security-pro'),
            default                                    => ucfirst($status),
        };
    }

    private function truncateMiddle(string $value, int $max): string
    {
        if (strlen($value) <= $max) {
            return $value;
        }
        $half = (int) floor(($max - 1) / 2);
        return substr($value, 0, $half) . '…' . substr($value, -$half);
    }
}
