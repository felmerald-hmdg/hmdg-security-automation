<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

use HMDG\Security\Modules\LoginProtection;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;

/**
 * admin-post.php action handlers for the v1.5.0 operations UI.
 *
 * Every handler enforces:
 *   - current_user_can('manage_options')
 *   - wp_verify_nonce with a per-action key
 *   - per-user rate limit (30 actions/min via object cache)
 *   - structured audit log via LogService
 *
 * @security No state-changing action is exposed outside admin-post.php.
 *           Every route is registered with the admin_post_<action>
 *           hook — the admin_post_nopriv_* variant is NOT registered,
 *           so anonymous callers receive a 0 response from WordPress.
 *
 * @since 1.5.0
 */
final class AdminActions
{
    /** Module identifier used in log entries. */
    private const MODULE = 'AdminActions';

    /** Object-cache prefix for per-user action rate counters. */
    private const RATE_LIMIT_PREFIX = 'hmdg_admin_rate_';

    /** Max actions per user per window. */
    private const RATE_LIMIT_MAX = 30;

    /** Rate-limit window (seconds). */
    private const RATE_LIMIT_WINDOW = 60;

    public function __construct(
        private readonly QuarantineService $quarantineService,
        private readonly FindingsRepository $repository,
        private readonly LockoutLogRepository $lockoutLog,
        private readonly ObjectCacheService $cacheService,
        private readonly LogService $logService,
        private readonly LoginProtection $loginProtection,
    ) {}

    public function register(): void
    {
        add_action('admin_post_hmdg_unlock', [$this, 'handleUnlock']);
        add_action('admin_post_hmdg_quarantine_delete', [$this, 'handleQuarantineDelete']);
        add_action('admin_post_hmdg_quarantine_false_positive', [$this, 'handleQuarantineFalsePositive']);
    }

    public function handleUnlock(): void
    {
        $ip = isset($_GET['ip']) ? sanitize_text_field(wp_unslash((string) $_GET['ip'])) : '';

        if ($ip === '' || !$this->isValidIp(ip: $ip)) {
            $this->bail(status: 'invalid_input', tab: 'lockouts');
        }

        if (!current_user_can('manage_options')) {
            $this->bail(status: 'forbidden', tab: 'lockouts');
        }

        if (!check_admin_referer('hmdg-unlock-' . $ip)) {
            $this->bail(status: 'nonce_failed', tab: 'lockouts');
        }

        if (!$this->allowByRateLimit()) {
            $this->bail(status: 'rate_limited', tab: 'lockouts');
        }

        $userId = get_current_user_id();

        $this->loginProtection->unlock(ip: $ip);
        $this->lockoutLog->markUnlocked($ip, $userId, 'admin_manual');

        $this->logService->info(
            module: self::MODULE,
            message: 'Admin unlocked IP',
            context: [
                'ip'       => $ip,
                'user_id'  => $userId,
            ],
        );

        $this->redirectBack(status: 'unlocked', tab: 'lockouts');
    }

    public function handleQuarantineDelete(): void
    {
        $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

        if ($id <= 0) {
            $this->bail(status: 'invalid_input', tab: 'quarantine');
        }

        if (!current_user_can('manage_options')) {
            $this->bail(status: 'forbidden', tab: 'quarantine');
        }

        if (!check_admin_referer('hmdg-quarantine-delete-' . $id)) {
            $this->bail(status: 'nonce_failed', tab: 'quarantine');
        }

        if (!$this->allowByRateLimit()) {
            $this->bail(status: 'rate_limited', tab: 'quarantine');
        }

        $ok = $this->quarantineService->deletePermanently(
            findingId: $id,
            actorId: get_current_user_id(),
        );

        $this->logService->info(
            module: self::MODULE,
            message: $ok
                ? 'Admin permanently deleted quarantined finding'
                : 'Admin delete-quarantine attempt failed',
            context: [
                'finding_id' => $id,
                'user_id'    => get_current_user_id(),
                'ok'         => $ok,
            ],
        );

        $this->redirectBack(status: $ok ? 'deleted' : 'delete_failed', tab: 'quarantine');
    }

    public function handleQuarantineFalsePositive(): void
    {
        $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

        if ($id <= 0) {
            $this->bail(status: 'invalid_input', tab: 'quarantine');
        }

        if (!current_user_can('manage_options')) {
            $this->bail(status: 'forbidden', tab: 'quarantine');
        }

        if (!check_admin_referer('hmdg-quarantine-fp-' . $id)) {
            $this->bail(status: 'nonce_failed', tab: 'quarantine');
        }

        if (!$this->allowByRateLimit()) {
            $this->bail(status: 'rate_limited', tab: 'quarantine');
        }

        $ok = $this->quarantineService->restore(
            findingId: $id,
            actorId: get_current_user_id(),
        );

        $this->logService->info(
            module: self::MODULE,
            message: $ok
                ? 'Admin restored quarantined file as false positive'
                : 'Admin restore-quarantine attempt failed',
            context: [
                'finding_id' => $id,
                'user_id'    => get_current_user_id(),
                'ok'         => $ok,
            ],
        );

        $this->redirectBack(status: $ok ? 'restored' : 'restore_failed', tab: 'quarantine');
    }

    /**
     * Per-user action rate limiter. Returns false if the cap is hit.
     */
    private function allowByRateLimit(): bool
    {
        $userId = get_current_user_id();
        if ($userId <= 0) {
            return false;
        }

        $key = self::RATE_LIMIT_PREFIX . $userId;
        $count = $this->cacheService->increment(
            key: $key,
            offset: 1,
            expiration: self::RATE_LIMIT_WINDOW,
        );

        if ($count === false) {
            // Cache failure — fail closed to prevent bypass via cache outage.
            return false;
        }

        return $count <= self::RATE_LIMIT_MAX;
    }

    private function isValidIp(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP);
    }

    private function redirectBack(string $status, string $tab): void
    {
        $target = add_query_arg([
            'page'          => 'hmdg-security',
            'tab'           => $tab,
            'hmdg_notice'   => $status,
        ], admin_url('admin.php'));

        wp_safe_redirect($target);
        exit;
    }

    /**
     * Redirect with an error status. Logs the event for audit.
     */
    private function bail(string $status, string $tab): never
    {
        $this->logService->warning(
            module: self::MODULE,
            message: 'Admin action rejected',
            context: [
                'status'  => $status,
                'tab'     => $tab,
                'user_id' => get_current_user_id(),
            ],
        );

        $this->redirectBack(status: $status, tab: $tab);
        exit;
    }
}
