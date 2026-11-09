<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Nervous system for every background operation in the plugin.
 *
 * Owns: hosting environment detection, custom cron schedule registration,
 * scheduled-event registration, the overlap-lock primitive used by every
 * heavy callback, the Flywheel-warning admin notice, and deactivation
 * cleanup. Owns NO actual scan logic — modules implement their own work,
 * acquire/release locks via this service, and trust this service to fire
 * them at the right times.
 *
 * # Hosting environments
 *
 * **WP Engine** (`IS_WPE` / `IS_WPE_SNAPSHOT` constants set by their
 * mu-plugin before everything): the platform forces
 * `define('DISABLE_WP_CRON', true)` and runs a real server cron every
 * 15 minutes. Visitor requests never trigger cron. We do nothing special
 * here — `wp_schedule_event()` works, and the platform fires it.
 *
 * **Flywheel** (detected by ABSPATH path signatures): `WP-Cron` runs in
 * the default WordPress mode, meaning visitor requests can occasionally
 * trigger a cron sweep. Two protections compensate:
 *  1. Every heavy callback wraps its work in an overlap lock + a
 *     `wp_doing_cron()` guard. Even if a visitor's request triggers cron,
 *     the visitor never executes scan work synchronously.
 *  2. We log a persistent (throttled) warning to security.log AND show a
 *     single dismissible admin notice to administrators with the exact
 *     server-cron line they need to add.
 *
 * # Locks
 *
 * Heavy callbacks acquire a 25-minute object-cache lock keyed
 * `hmdg_<job_name>_lock` before any work, and release it in `finally`.
 * The TTL is the safety net for callbacks that die without the finally
 * clause running (e.g. fatal error). Without the lock, two simultaneous
 * cron firings could double memory and corrupt batch progress.
 *
 * @since 1.0.0
 */
final class CronService
{
    // ─── Public hook constants ─────────────────────────────────────────
    // Modules and tests reference these by symbol, never by string.

    public const HOOK_DAILY_REPORT  = 'hmdg_daily_security_report';
    public const HOOK_INTEGRITY     = 'hmdg_weekly_file_integrity_check';
    public const HOOK_MALWARE       = 'hmdg_weekly_malware_scan';
    public const HOOK_CLEANUP       = 'hmdg_weekly_database_cleanup';
    public const HOOK_FULL_REPORT   = 'hmdg_weekly_full_report';
    public const HOOK_SCAN_BATCH    = 'hmdg_scan_next_batch';
    public const HOOK_MALWARE_BATCH = 'hmdg_malware_next_batch';

    /**
     * Every hook this service is responsible for scheduling/clearing.
     *
     * @var list<string>
     */
    public const MANAGED_HOOKS = [
        self::HOOK_DAILY_REPORT,
        self::HOOK_INTEGRITY,
        self::HOOK_MALWARE,
        self::HOOK_CLEANUP,
        self::HOOK_FULL_REPORT,
        self::HOOK_SCAN_BATCH,
        self::HOOK_MALWARE_BATCH,
    ];

    /**
     * Pre-rename cron event hooks from earlier plugin versions.
     *
     * Cleared on every registration sweep AND on deactivation so a site
     * that activated an old build never accumulates dead schedules.
     *
     * @var list<string>
     */
    private const LEGACY_HOOKS = [
        'hmdg_security_file_integrity_scan',
        'hmdg_security_malware_scan',
        'hmdg_security_database_cleanup',
    ];

    /** Overlap-lock TTL — long enough for slow batches, short enough to self-heal. */
    private const LOCK_TTL = 25 * MINUTE_IN_SECONDS;

    /** Throttle TTL for the per-boot Flywheel warning log line. */
    private const FLYWHEEL_LOG_THROTTLE = HOUR_IN_SECONDS;

    /** Object-cache key for Flywheel warning log throttle. */
    private const FLYWHEEL_LOG_THROTTLE_KEY = 'cron_flywheel_warning_throttle';

    /** Option storing the random Sunday-time minute offset (attack-5 mitigation). */
    private const RANDOM_OFFSET_OPTION = 'hmdg_security_cron_offset_minutes';

    /** Option storing whether the Flywheel admin notice has been dismissed. */
    private const FLYWHEEL_NOTICE_DISMISSED_OPTION = 'hmdg_security_flywheel_notice_dismissed';

    /** Nonce action for dismissing the Flywheel notice via AJAX. */
    private const NOTICE_DISMISS_NONCE = 'hmdg_dismiss_flywheel_notice';

    /** Object-cache key prefix for per-job last-run timestamps (health check). */
    private const LAST_RUN_KEY_PREFIX = 'cron_last_run_';

    // ─── Per-request memoisation ───────────────────────────────────────

    /** Cached WP Engine detection result. */
    private static ?bool $isWpEngine = null;

    /** Cached Flywheel detection result. */
    private static ?bool $isFlywheel = null;

    /**
     * Per-request flag — registration sweep happens at most once per request.
     *
     * Without this, an unrelated re-instantiation of Plugin within the same
     * request would re-run wp_next_scheduled() N times. The check itself is
     * cheap, but the principle is: do registration work exactly once.
     */
    private static bool $eventsRegistered = false;

    public function __construct(
        private readonly LogService $logService,
        private readonly ObjectCacheService $cacheService,
    ) {}

    // ═══════════════════════════════════════════════════════════════════
    //  Environment detection
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Whether the current request is running on WP Engine.
     *
     * Detection: WP Engine's mu-plugin defines `IS_WPE` and/or
     * `IS_WPE_SNAPSHOT` before any plugin code runs. These constants
     * cannot be set via HTTP — they are PHP constants defined server-side.
     */
    public function isWpEngine(): bool
    {
        if (self::$isWpEngine !== null) {
            return self::$isWpEngine;
        }

        self::$isWpEngine = (defined('IS_WPE') && constant('IS_WPE') === true)
            || (defined('IS_WPE_SNAPSHOT') && constant('IS_WPE_SNAPSHOT') === true);

        return self::$isWpEngine;
    }

    /**
     * Whether the current request is running on Flywheel.
     *
     * Flywheel does not expose a clean constant. Detect via filesystem
     * signatures: ABSPATH always lives under `/www/flywheel/` or
     * `/var/www/flywheel/` on their managed environment, and the
     * platform writes `/etc/flywheel-config`. Any one match suffices.
     *
     * ABSPATH is defined in wp-config.php before plugins load and
     * cannot be set via HTTP request.
     */
    public function isFlywheel(): bool
    {
        if (self::$isFlywheel !== null) {
            return self::$isFlywheel;
        }

        $abspath = defined('ABSPATH') ? (string) constant('ABSPATH') : '';
        $abspathNormalised = str_replace('\\', '/', $abspath);

        self::$isFlywheel = str_contains($abspathNormalised, '/www/flywheel/')
            || str_contains($abspathNormalised, '/var/www/flywheel/')
            || file_exists('/etc/flywheel-config');

        return self::$isFlywheel;
    }

    /**
     * Symbolic environment label for logs and reports.
     *
     * @return 'wpe'|'flywheel'|'unknown'
     */
    public function getEnvironment(): string
    {
        if ($this->isWpEngine()) {
            return 'wpe';
        }
        if ($this->isFlywheel()) {
            return 'flywheel';
        }
        return 'unknown';
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Custom cron intervals
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Register the `weekly` and `monthly` schedule entries.
     *
     * Note: WordPress added `weekly` to core in 5.4. Re-registering
     * with the same key is a no-op so this is safe across versions.
     */
    public function registerCustomIntervals(): void
    {
        add_filter('cron_schedules', [$this, 'addCronSchedules'], 10, 1);
    }

    /**
     * Filter callback that injects our custom intervals.
     *
     * @param array<string, array{interval: int, display: string}> $schedules
     * @return array<string, array{interval: int, display: string}>
     */
    public function addCronSchedules(array $schedules): array
    {
        if (!isset($schedules['weekly'])) {
            $schedules['weekly'] = [
                'interval' => WEEK_IN_SECONDS,
                'display'  => __('Once Weekly', 'hmdg-security-pro'),
            ];
        }
        if (!isset($schedules['monthly'])) {
            $schedules['monthly'] = [
                'interval' => 30 * DAY_IN_SECONDS,
                'display'  => __('Once Monthly', 'hmdg-security-pro'),
            ];
        }
        return $schedules;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Scheduled-event registration
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Schedule every managed event on plugins_loaded.
     *
     * Idempotent: each event is only scheduled if `wp_next_scheduled()`
     * reports it absent. Legacy hook names from earlier plugin versions
     * are unscheduled in the same sweep so a long-lived install never
     * accumulates dead entries.
     *
     * @perf On WP Engine + Redis, each `wp_next_scheduled()` is a Redis GET
     *   (~0.1ms). 7 events = ~0.7ms. The static `eventsRegistered` flag
     *   prevents re-running on repeat-instantiation within the same request.
     */
    public function registerScheduledEvents(): void
    {
        if (self::$eventsRegistered) {
            return;
        }
        self::$eventsRegistered = true;

        // Drop any legacy hook names we used to schedule.
        $this->clearLegacyEvents();

        // Single random minute offset shared by all weekly events. Chosen
        // once on first activation and persisted, so the schedule is
        // unpredictable to an attacker but stable across reboots.
        $offsetMinutes = $this->getOrCreateRandomOffset();

        // Daily security report — every morning at 07:00 Europe/London.
        $this->scheduleDaily(
            hook: self::HOOK_DAILY_REPORT,
            hour: 7,
            minute: 0,
        );

        // Weekly heavy operations — Sunday early morning, with the random
        // shared offset applied to all three so they retain their relative
        // 30-minute spacing while being unpredictable in absolute time.
        // Base times (no offset): 03:00 / 03:30 / 04:00.
        // With offset(-60..+60), live windows are roughly:
        //   integrity: 02:00–04:00
        //   malware:   02:30–04:30
        //   cleanup:   03:00–05:00
        $integrityMinutes = (3 * 60) + ($offsetMinutes - 60);
        $malwareMinutes   = $integrityMinutes + 30;
        $cleanupMinutes   = $integrityMinutes + 60;

        $this->scheduleWeekly(
            hook: self::HOOK_INTEGRITY,
            dayOfWeek: 'sunday',
            totalMinutes: $integrityMinutes,
        );
        $this->scheduleWeekly(
            hook: self::HOOK_MALWARE,
            dayOfWeek: 'sunday',
            totalMinutes: $malwareMinutes,
        );
        $this->scheduleWeekly(
            hook: self::HOOK_CLEANUP,
            dayOfWeek: 'sunday',
            totalMinutes: $cleanupMinutes,
        );

        // Weekly full report — Monday morning so it contains fresh scan results.
        $this->scheduleWeekly(
            hook: self::HOOK_FULL_REPORT,
            dayOfWeek: 'monday',
            totalMinutes: 7 * 60,
        );
    }

    /**
     * Clear any cron event whose hook this plugin no longer schedules.
     *
     * Legacy hooks were renamed in the v1.1 cron rewrite. Without this
     * sweep, sites that activated an older build would keep firing the
     * old hook names indefinitely with no callback bound.
     */
    private function clearLegacyEvents(): void
    {
        foreach (self::LEGACY_HOOKS as $legacyHook) {
            if (wp_next_scheduled($legacyHook)) {
                wp_clear_scheduled_hook($legacyHook);
            }
        }
    }

    /**
     * Schedule a recurring daily event at the given UK-local time.
     */
    private function scheduleDaily(string $hook, int $hour, int $minute = 0): void
    {
        if (wp_next_scheduled($hook)) {
            return;
        }

        $timestamp = $this->getNextDailyOccurrence($hour, $minute);
        $result = wp_schedule_event($timestamp, 'daily', $hook);

        if ($result === false) {
            $this->logService->warning(
                module: 'CronService',
                message: 'wp_schedule_event() failed for daily hook',
                context: ['hook' => $hook, 'timestamp' => $timestamp],
            );
        }
    }

    /**
     * Schedule a recurring weekly event for the given day at minute-of-day.
     *
     * @param string $dayOfWeek    e.g. 'sunday', 'monday'
     * @param int    $totalMinutes Minutes since midnight (0–10080); values
     *                             outside 0–1439 are normalised.
     */
    private function scheduleWeekly(string $hook, string $dayOfWeek, int $totalMinutes): void
    {
        if (wp_next_scheduled($hook)) {
            return;
        }

        // Normalise to 0–1439 and shift the day boundary if the random offset
        // pushed the target to the previous/next day.
        $dayShift = (int) floor($totalMinutes / 1440);
        $minuteOfDay = (($totalMinutes % 1440) + 1440) % 1440;
        $hour = intdiv($minuteOfDay, 60);
        $minute = $minuteOfDay % 60;

        $timestamp = $this->getNextOccurrence($dayOfWeek, $hour, $minute);
        if ($dayShift !== 0) {
            $timestamp += $dayShift * DAY_IN_SECONDS;
        }

        $result = wp_schedule_event($timestamp, 'weekly', $hook);

        if ($result === false) {
            $this->logService->warning(
                module: 'CronService',
                message: 'wp_schedule_event() failed for weekly hook',
                context: ['hook' => $hook, 'timestamp' => $timestamp],
            );
        }
    }

    /**
     * Read the persisted Sunday-time minute offset, or generate one.
     *
     * Stored with autoload=false because it is read once per request at
     * scheduling time and never on the hot path. random_int() is a CSPRNG
     * — appropriate for this anti-attacker timing-randomisation use case.
     */
    private function getOrCreateRandomOffset(): int
    {
        $stored = get_option(self::RANDOM_OFFSET_OPTION, false);

        if ($stored === false || !is_numeric($stored)) {
            $offset = random_int(0, 120);
            update_option(self::RANDOM_OFFSET_OPTION, (string) $offset, false);
            return $offset;
        }

        $offset = (int) $stored;
        // Defensive clamp: persisted value should be 0–120 but clamp anyway
        if ($offset < 0 || $offset > 120) {
            $offset = max(0, min(120, $offset));
        }
        return $offset;
    }

    /**
     * UTC timestamp of the next occurrence of `<dayOfWeek> at hour:minute`
     * in Europe/London time, accounting correctly for GMT/BST.
     *
     * Never subtracts hours from UTC — that pattern silently breaks across
     * DST boundaries. Always uses `wp_timezone()` and DateTimeImmutable.
     */
    private function getNextOccurrence(string $dayOfWeek, int $hour, int $minute = 0): int
    {
        $timezone = wp_timezone();
        $now = new \DateTimeImmutable('now', $timezone);

        $target = new \DateTimeImmutable(
            'next ' . strtolower($dayOfWeek) . ' ' . sprintf('%02d:%02d:00', $hour, $minute),
            $timezone,
        );

        if ($target <= $now) {
            $target = $target->modify('+1 week');
        }

        return $target->getTimestamp();
    }

    /**
     * UTC timestamp of the next daily occurrence at `hour:minute` UK local time.
     */
    private function getNextDailyOccurrence(int $hour, int $minute = 0): int
    {
        $timezone = wp_timezone();
        $now = new \DateTimeImmutable('now', $timezone);
        $target = $now->setTime($hour, $minute, 0);

        if ($target <= $now) {
            $target = $target->modify('+1 day');
        }

        return $target->getTimestamp();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Overlap lock primitive
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Try to atomically acquire the overlap lock for a heavy job.
     *
     * Returns true if the lock was acquired (caller should proceed with
     * work and release in a `finally`). Returns false if another worker
     * already holds it (caller should log and return early).
     *
     * @security Uses `wp_cache_add` (Redis SET NX semantics) — fully
     *   atomic. A previous implementation used `exists` then `set`, which
     *   under concurrent cron firings could let two workers both pass the
     *   exists check and both proceed. That race is now closed.
     */
    public function acquireLock(string $jobName): bool
    {
        return $this->cacheService->add(
            key: $this->lockKey($jobName),
            value: time(),
            expiration: self::LOCK_TTL,
        );
    }

    /**
     * Release the overlap lock for a heavy job.
     *
     * Safe to call even if the lock was never acquired — wp_cache_delete
     * is idempotent.
     */
    public function releaseLock(string $jobName): void
    {
        $this->cacheService->delete(key: $this->lockKey($jobName));
    }

    /**
     * Whether the overlap lock for a job is currently held.
     */
    public function isLocked(string $jobName): bool
    {
        return $this->cacheService->exists(key: $this->lockKey($jobName));
    }

    /**
     * Persist the last-run timestamp for a job (used by the health check).
     *
     * Stored in object cache only — no DB write on cron completion.
     */
    public function recordRun(string $jobName): void
    {
        $this->cacheService->set(
            key: self::LAST_RUN_KEY_PREFIX . $jobName,
            value: time(),
            expiration: 30 * DAY_IN_SECONDS,
        );
    }

    private function lockKey(string $jobName): string
    {
        return 'hmdg_' . $jobName . '_lock';
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Health check
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Snapshot of every managed cron event's current state.
     *
     * Structure per event:
     *   - hook            (string)
     *   - next_run_uk     (string Y-m-d H:i T)  — empty if not scheduled
     *   - next_run_unix   (int)                 — 0 if not scheduled
     *   - is_overdue      (bool)
     *   - last_run_uk     (string)              — empty if never run
     *   - last_run_unix   (int)                 — 0 if never run
     *   - recurrence      (string)              — 'daily'|'weekly'|'single'|'unknown'
     *   - is_locked       (bool)
     *
     * @perf Reads `_get_cron_array()` which on WP Engine is served from
     *   the autoloaded options Redis cache. Single read per call. No DB
     *   queries when persistent cache is active.
     *
     * @security The 'recurrence' field originates from values inserted
     *   into the WordPress cron array by ANY plugin (potentially via
     *   third-party `wp_schedule_event` calls). Although our managed
     *   hooks always have known recurrence values, consumers that render
     *   any field of this output into an HTML email body MUST escape with
     *   `esc_html()`, and consumers placing any value in an email subject
     *   line MUST run it through `sanitize_text_field()` first. The
     *   strings returned here are NOT pre-sanitised for those contexts.
     *
     * @return list<array{
     *   hook: string, next_run_uk: string, next_run_unix: int,
     *   is_overdue: bool, last_run_uk: string, last_run_unix: int,
     *   recurrence: string, is_locked: bool
     * }>
     */
    public function getHealthStatus(): array
    {
        $cronArray = _get_cron_array();
        if (!is_array($cronArray)) {
            $cronArray = [];
        }

        // Build a flat lookup of hook => [timestamp, recurrence]
        $hookLookup = [];
        foreach ($cronArray as $timestamp => $hooks) {
            if (!is_int($timestamp) || !is_array($hooks)) {
                continue;
            }
            foreach ($hooks as $hookName => $events) {
                if (!is_string($hookName) || !is_array($events)) {
                    continue;
                }
                if (isset($hookLookup[$hookName])) {
                    continue;
                }
                $first = reset($events);
                $schedule = is_array($first) ? ($first['schedule'] ?? '') : '';
                $hookLookup[$hookName] = [
                    'timestamp' => $timestamp,
                    'recurrence' => is_string($schedule) && $schedule !== '' ? $schedule : 'single',
                ];
            }
        }

        $timezone = wp_timezone();
        $now = time();
        $report = [];

        foreach (self::MANAGED_HOOKS as $hook) {
            $entry = $hookLookup[$hook] ?? null;
            $nextRunUnix = $entry['timestamp'] ?? 0;
            $recurrence = $entry['recurrence'] ?? 'unknown';

            $lastRunUnix = (int) ($this->cacheService->get(key: self::LAST_RUN_KEY_PREFIX . $hook) ?: 0);

            $report[] = [
                'hook' => $hook,
                'next_run_uk' => $nextRunUnix > 0
                    ? (new \DateTimeImmutable('@' . $nextRunUnix))
                        ->setTimezone($timezone)
                        ->format('Y-m-d H:i T')
                    : '',
                'next_run_unix' => $nextRunUnix,
                'is_overdue' => $nextRunUnix > 0 && $nextRunUnix < $now - HOUR_IN_SECONDS,
                'last_run_uk' => $lastRunUnix > 0
                    ? (new \DateTimeImmutable('@' . $lastRunUnix))
                        ->setTimezone($timezone)
                        ->format('Y-m-d H:i T')
                    : '',
                'last_run_unix' => $lastRunUnix,
                'recurrence' => $recurrence,
                'is_locked' => $this->isLocked($hook),
            ];
        }

        return $report;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Boot-time logging + Flywheel admin notice
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Log the active environment once on activation, and a throttled
     * warning on every boot when running on Flywheel without server cron.
     *
     * The warning is throttled to once per hour via object cache so it
     * does not produce a file write on every page load. The admin notice
     * is the primary visibility mechanism — the log entry is forensic.
     */
    public function logEnvironmentOnBoot(): void
    {
        if ($this->isWpEngine()) {
            // Single low-noise INFO; LogService caches its directory check
            // per-request so this is at most one file write per request.
            // Throttled to once per day to avoid log churn.
            $throttleKey = 'cron_wpe_boot_throttle';
            if (!$this->cacheService->exists(key: $throttleKey)) {
                $this->cacheService->set(
                    key: $throttleKey,
                    value: time(),
                    expiration: DAY_IN_SECONDS,
                );
                $this->logService->info(
                    module: 'CronService',
                    message: 'WP Engine environment detected — server cron handles execution.',
                    context: ['environment' => 'wpe'],
                );
            }
            return;
        }

        if ($this->isFlywheel()) {
            // Throttled WARNING — fires at most once per hour per process,
            // visible in security.log without flooding it.
            if ($this->cacheService->exists(key: self::FLYWHEEL_LOG_THROTTLE_KEY)) {
                return;
            }
            $this->cacheService->set(
                key: self::FLYWHEEL_LOG_THROTTLE_KEY,
                value: time(),
                expiration: self::FLYWHEEL_LOG_THROTTLE,
            );

            $siteUrl = esc_url_raw(site_url());
            $command = sprintf(
                '*/15 * * * * wget -q -O - %s/wp-cron.php?doing_wp_cron > /dev/null 2>&1',
                rtrim($siteUrl, '/'),
            );

            $this->logService->warning(
                module: 'CronService',
                message: 'Flywheel environment detected. WP-Cron is visitor-triggered on this site. '
                    . 'Security scans are guarded and will not impact visitor page loads but cron '
                    . 'execution is unreliable. Configure server cron immediately.',
                context: [
                    'environment' => 'flywheel',
                    'site_url' => $siteUrl,
                    'recommended_cron_command' => $command,
                ],
            );
        }
    }

    /**
     * Register the Flywheel admin notice + dismissal handler.
     *
     * The notice is the only admin-area UI this plugin ever produces.
     * It is shown only on Flywheel, only to administrators, and only
     * if not previously dismissed. Dismissal is persisted in wp_options
     * with autoload=false (read only when rendering the notice).
     */
    public function registerAdminNotice(): void
    {
        if (!$this->isFlywheel()) {
            return;
        }

        add_action('admin_notices', [$this, 'renderFlywheelNotice'], 10, 0);
        add_action('wp_ajax_hmdg_dismiss_flywheel_notice', [$this, 'handleNoticeDismissal'], 10, 0);
    }

    /**
     * Render the dismissible Flywheel cron-config notice.
     *
     * Visible only to users with `manage_options` capability and only if
     * the dismissal option has not been set.
     */
    public function renderFlywheelNotice(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $dismissed = get_option(self::FLYWHEEL_NOTICE_DISMISSED_OPTION, false);
        if ($dismissed) {
            return;
        }

        $siteUrl = esc_url(rtrim(site_url(), '/'));
        $cronUrl = $siteUrl . '/wp-cron.php?doing_wp_cron';
        $nonce = wp_create_nonce(self::NOTICE_DISMISS_NONCE);

        // Notice text rewritten 2026-04-16. The previous version told
        // operators to "go to Flywheel → Tools → Cron Jobs and add a
        // crontab entry" — but Flywheel does NOT expose any server-cron
        // UI (their official docs:
        // https://getflywheel.com/wordpress-support/what-is-a-cron-job-and-how-do-they-work-at-flywheel/
        // — "we don't allow users to create or manage cron jobs at the
        // server-level"). The instruction was impossible to follow.
        // It also mistyped the WP-Cron-disable constant as
        // `DISALLOW_WP_CRON` — the real one is `DISABLE_WP_CRON`.
        // See CRON-SETUP.md for the three real options.
        $heading = esc_html__('HMDG Security Pro: cron timing on Flywheel', 'hmdg-security-pro');
        $line1 = esc_html__(
            'This site runs on Flywheel, which does not offer a server-cron control. '
            . 'WP-Cron only fires when a visitor loads a page. On low-traffic sites the '
            . "weekly file-integrity, malware, and database-cleanup scans may delay or "
            . 'skip a week. The plugin protects visitors regardless — they never run scan '
            . 'work — only the schedule is at risk.',
            'hmdg-security-pro',
        );
        $line2 = esc_html__(
            'Recommended (HMDG operations): the GitHub Actions workflow '
            . 'flywheel-cron-ping.yml hits this site\'s wp-cron.php every 15 minutes '
            . 'from GitHub\'s runners. Add this site\'s name to flywheel-sites.json '
            . 'in the plugin repo and the next deploy starts the pings.',
            'hmdg-security-pro',
        );
        $line3 = esc_html__(
            'Alternative: register a free job at cron-job.org or EasyCron pointing at:',
            'hmdg-security-pro',
        );
        $line4 = esc_html__(
            'Optional: also add the line below to wp-config.php (above "Stop editing"). '
            . 'It removes the visitor-side WP-Cron dispatch entirely. '
            . 'Only set this AFTER one of the ping mechanisms above is in place — '
            . 'otherwise nothing will trigger cron at all.',
            'hmdg-security-pro',
        );
        $dismissLabel = esc_html__('Dismiss', 'hmdg-security-pro');

        ?>
        <div class="notice notice-warning is-dismissible" id="hmdg-flywheel-notice"
             data-nonce="<?php echo esc_attr($nonce); ?>">
            <p><strong><?php echo $heading; ?></strong></p>
            <p><?php echo $line1; ?></p>
            <p><?php echo $line2; ?></p>
            <p><?php echo $line3; ?></p>
            <p><code style="display:block;padding:8px;background:#f6f7f7;word-break:break-all;"><?php echo esc_html($cronUrl); ?></code></p>
            <p><?php echo $line4; ?></p>
            <p><code style="display:block;padding:8px;background:#f6f7f7;">define('DISABLE_WP_CRON', true);</code></p>
            <p><button type="button" class="button" id="hmdg-flywheel-notice-dismiss"><?php echo $dismissLabel; ?></button></p>
        </div>
        <script>
        (function() {
            var btn = document.getElementById('hmdg-flywheel-notice-dismiss');
            var notice = document.getElementById('hmdg-flywheel-notice');
            if (!btn || !notice) return;
            btn.addEventListener('click', function() {
                var data = new FormData();
                data.append('action', 'hmdg_dismiss_flywheel_notice');
                data.append('_wpnonce', notice.getAttribute('data-nonce'));
                fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: data })
                    .then(function() { notice.style.display = 'none'; });
            });
            // The is-dismissible X button — also persist dismissal
            notice.addEventListener('click', function(e) {
                if (e.target && e.target.classList && e.target.classList.contains('notice-dismiss')) {
                    var d = new FormData();
                    d.append('action', 'hmdg_dismiss_flywheel_notice');
                    d.append('_wpnonce', notice.getAttribute('data-nonce'));
                    fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: d });
                }
            });
        })();
        </script>
        <?php
    }

    /**
     * AJAX handler for dismissing the Flywheel notice.
     *
     * Verifies nonce + capability before persisting. Stores the dismissal
     * with autoload=false so it never appears on the front-end page-load
     * autoloaded options blob.
     */
    public function handleNoticeDismissal(): void
    {
        check_ajax_referer(self::NOTICE_DISMISS_NONCE);

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['reason' => 'forbidden'], 403);
        }

        update_option(self::FLYWHEEL_NOTICE_DISMISSED_OPTION, true, false);

        wp_send_json_success();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Deactivation
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Clear every event registered by this plugin and clean up state.
     *
     * Removes:
     *  - Every managed cron hook (current names)
     *  - Every legacy cron hook (renamed in v1.1)
     *  - Every overlap-lock key in object cache
     *  - The Flywheel notice dismissal option (so re-activation re-shows it)
     *
     * Preserves:
     *  - security.log and rotated copies (forensic record)
     *  - checksums.json (re-used on re-activation; saves rebuild cost)
     *  - The random-offset option (consistency across re-activations)
     */
    public function deactivate(): void
    {
        $cleared = [];

        foreach (self::MANAGED_HOOKS as $hook) {
            if (wp_next_scheduled($hook)) {
                wp_clear_scheduled_hook($hook);
                $cleared[] = $hook;
            }
            $this->cacheService->delete(key: $this->lockKey($hook));
        }

        foreach (self::LEGACY_HOOKS as $legacyHook) {
            if (wp_next_scheduled($legacyHook)) {
                wp_clear_scheduled_hook($legacyHook);
                $cleared[] = $legacyHook;
            }
        }

        delete_option(self::FLYWHEEL_NOTICE_DISMISSED_OPTION);

        $this->logService->info(
            module: 'CronService',
            message: 'Plugin deactivated — cleared ' . count($cleared) . ' scheduled events',
            context: ['cleared_hooks' => $cleared],
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Callback binding helpers
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Hook the daily-report and weekly-report events to placeholder handlers.
     *
     * The dedicated report module (planned for a follow-up release) will
     * unhook these placeholders and bind its own handlers via priority 10.
     * Until then, the events fire harmlessly and log a single info line so
     * the cron health check can still report 'last run' timestamps.
     */
    public function bindReportPlaceholders(): void
    {
        add_action(self::HOOK_DAILY_REPORT, [$this, 'handleDailyReportPlaceholder'], 10, 0);
        add_action(self::HOOK_FULL_REPORT, [$this, 'handleWeeklyReportPlaceholder'], 10, 0);
    }

    /**
     * Placeholder handler for the daily report event.
     *
     * Records the run + logs once, so the health check has a 'last run'
     * value and operators can confirm the schedule is firing.
     */
    public function handleDailyReportPlaceholder(): void
    {
        if (!wp_doing_cron() && !(defined('WP_CLI') && WP_CLI)) {
            $this->logService->warning(
                module: 'CronService',
                message: 'Daily report handler called outside cron context — aborted',
            );
            return;
        }

        $this->recordRun(self::HOOK_DAILY_REPORT);
        $this->logService->info(
            module: 'CronService',
            message: 'Daily security report event fired (handler not yet implemented)',
            context: ['health' => $this->getHealthStatus()],
        );
    }

    /**
     * Placeholder handler for the weekly full-report event.
     */
    public function handleWeeklyReportPlaceholder(): void
    {
        if (!wp_doing_cron() && !(defined('WP_CLI') && WP_CLI)) {
            $this->logService->warning(
                module: 'CronService',
                message: 'Weekly full report handler called outside cron context — aborted',
            );
            return;
        }

        $this->recordRun(self::HOOK_FULL_REPORT);
        $this->logService->info(
            module: 'CronService',
            message: 'Weekly full report event fired (handler not yet implemented)',
            context: ['health' => $this->getHealthStatus()],
        );
    }
}
