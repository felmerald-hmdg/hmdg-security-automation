<?php

declare(strict_types=1);

namespace HMDG\Security\Compatibility;

/**
 * Compatibility layer for co-installation with HMDG Helpers.
 *
 * HMDG Helpers (https://hmdg.co.uk/hmdg-helpers) is a sibling plugin
 * shipped on 400+ HMDG client sites. Its `security` module scans plugin
 * folders for the `metainfo.jpg` malware artefact on `admin_init`; its
 * bootstrap runs `handle_migrations()` on `plugins_loaded` (priority 10)
 * which historically auto-deactivated the plugin at slug
 * `hmdg-security/hmdg-security.php`. HMDG Security Pro uses the slug
 * `hmdg-security-pro` specifically so that hard-coded match no longer
 * fires — see Plugin header note.
 *
 * This class is the **diplomatic layer** between the two plugins. Its
 * responsibilities:
 *
 *   1. Detect reliably whether HMDG Helpers is active, with spoofing
 *      protection — a malicious plugin could declare a fake
 *      `HMDG_Helpers` class to influence our behaviour.
 *   2. Expose HMDG Helpers' state (version, scan timing, module presence)
 *      to other HMDG Security modules.
 *   3. Surface a conflict report for log/alert context so operators can
 *      see coexistence status at a glance.
 *   4. Enumerate paths HMDG Security should not touch during integrity
 *      monitoring — the HMDG Helpers plugin folder is updated independently
 *      and its file changes are legitimate, not malware.
 *   5. Detect plugin-activation context so the main bootstrap can delay
 *      its own `plugins_loaded` callback to priority 99 during an
 *      activation request, giving HMDG Helpers time to finish its own
 *      admin_init work without timing surprise.
 *
 * Performance contract:
 *   - Every detection method caches its result in a static property after
 *     the first call. Subsequent calls return in O(1) — no class_exists,
 *     no file_exists, no database read.
 *   - None of the methods are called on front-end visitor requests. They
 *     run only from admin, cron, plugin-activation, or alert-dispatch
 *     contexts. Front-end page loads pay zero overhead from this class.
 *
 * Object cache note:
 *   HMDG Security uses the `hmdg_security` object cache group. HMDG
 *   Helpers uses no object cache. There is no collision. This comment
 *   is preserved so any future HMDG Helpers maintainer reading these two
 *   plugins together sees the isolation guarantee documented.
 *
 * @since 1.0.0
 */
final class HmdgHelpersCompat
{
    /**
     * Main-file basename HMDG Helpers has shipped under since v1.0.0.
     *
     * The surrounding folder varies in practice — we have seen at least
     * `hmdg-helpers/` (HMDG canonical deploy), `hmdg-helpers-v1.2.3/`
     * (version-suffixed test sites), and `hmdg-helpers-main/` (CI
     * checkouts of the repo). Detection scans `active_plugins` for any
     * entry ending with `/hmdg-helpers.php` rather than hard-coding the
     * folder name.
     */
    private const HELPERS_MAIN_FILE_SUFFIX = '/hmdg-helpers.php';

    /**
     * HMDG Helpers' scan-throttle transient key. Reading only — we never
     * write this transient. Exposed here as a constant so the name is not
     * duplicated as a magic string in multiple methods.
     */
    private const HELPERS_SCAN_TRANSIENT = 'hmdg_helpers_security_last_scan';

    /**
     * Cached active-state result. `null` until the first call; after that,
     * the cached bool. Every call after the first is branch-free.
     */
    private static ?bool $is_active = null;

    /** Cached version result. `null` until first call. */
    private static ?string $version = null;

    /** Cached security-module presence result. `null` until first call. */
    private static ?bool $has_security_module = null;

    /** Cached activation-request result. `null` until first call. */
    private static ?bool $is_activation_request = null;

    /**
     * Whether HMDG Helpers is installed and loaded in the current request.
     *
     * Uses three signals, all of which must line up — this defends against
     * a malicious plugin declaring a stub `HMDG_Helpers` class in order to
     * influence HMDG Security's behaviour (for example, to convince it
     * that duplicate-scan delegation is in effect when it is not).
     *
     *   1. `class_exists('HMDG_Helpers')` — primary signal. Fast, and HMDG
     *      Helpers does declare this class in its main file.
     *   2. `defined('HMDG_HELPERS_URL')` — HMDG Helpers defines this
     *      constant inside its real constructor. A simple class-declaration
     *      spoof without running the constructor will not set it.
     *   3. `active_plugins` contains an entry ending with
     *      `/hmdg-helpers.php`. This is WordPress's own record of which
     *      plugins were activated by an administrator — much harder to
     *      spoof without write access to `wp_options`, and tolerant of
     *      versioned folder names (`hmdg-helpers/`, `hmdg-helpers-v1.2.3/`,
     *      `hmdg-helpers-main/`, etc.). An attacker with DB write access
     *      can of course satisfy this — but at that point a compatibility-
     *      layer bypass is the least of the site's concerns.
     *
     * Result is cached for the lifetime of the request. `get_option()`
     * reads from the autoloaded options cache after WP bootstrap (no DB
     * round-trip on repeated calls), so this is cheap even pre-cache.
     */
    public static function is_active(): bool
    {
        if (self::$is_active !== null) {
            return self::$is_active;
        }

        if (!class_exists('HMDG_Helpers')) {
            return self::$is_active = false;
        }

        // Constant is set inside HMDG_Helpers::__construct(). A stub class
        // declaration that never ran the constructor will not define it.
        if (!defined('HMDG_HELPERS_URL')) {
            return self::$is_active = false;
        }

        // Scan active_plugins for any entry matching HMDG Helpers' main
        // file, regardless of folder name. Uses get_option() rather than
        // is_plugin_active() to avoid requiring wp-admin/includes/plugin.php
        // to be loaded — we may be called very early in the request.
        $active = get_option('active_plugins', []);
        if (!is_array($active)) {
            return self::$is_active = false;
        }

        foreach ($active as $entry) {
            if (is_string($entry) && str_ends_with($entry, self::HELPERS_MAIN_FILE_SUFFIX)) {
                return self::$is_active = true;
            }
        }

        return self::$is_active = false;
    }

    /**
     * HMDG Helpers' declared version string, or `'0.0.0'` when unavailable.
     *
     * The returned value is ALWAYS passed through `sanitize_text_field()`
     * before return. HMDG Helpers is a trusted first-party plugin, but
     * this value flows into log entries and alert-email HTML, and defensive
     * sanitisation here keeps the logger free of control characters if any
     * future HMDG Helpers release were to include an unexpected value.
     */
    public static function get_version(): string
    {
        if (self::$version !== null) {
            return self::$version;
        }

        if (!self::is_active()) {
            return self::$version = '0.0.0';
        }

        $raw = defined('HMDG_Helpers::VERSION')
            ? (string) constant('HMDG_Helpers::VERSION')
            : '0.0.0';

        return self::$version = sanitize_text_field($raw);
    }

    /**
     * Whether HMDG Helpers' `security` module is loaded in the current
     * request. The module is loaded unconditionally by HMDG Helpers'
     * `load_modules()`, so in practice this is equivalent to
     * `is_active()` — but kept as a distinct method so future HMDG Helpers
     * versions that make the module optional can be reflected here without
     * a breaking change to call sites.
     */
    public static function has_security_module(): bool
    {
        if (self::$has_security_module !== null) {
            return self::$has_security_module;
        }

        // Gate on is_active() so a spoofed class_exists() for the
        // security module alone (without the parent plugin being real)
        // cannot report positive. An attacker declaring
        // `class HMDG_Helpers_Security {}` in isolation must not be
        // interpreted as HMDG Helpers' security module being loaded.
        if (!self::is_active()) {
            return self::$has_security_module = false;
        }

        return self::$has_security_module = class_exists('HMDG_Helpers_Security');
    }

    /**
     * Whether HMDG Helpers ran its daily malware scan recently.
     *
     * Reads `get_transient('hmdg_helpers_security_last_scan')` directly.
     * A truthy value means HMDG Helpers' 24-hour throttle is in force and
     * the scanner is idle for the remainder of the day.
     *
     * This is informational only — HMDG Security Pro scans a completely
     * different surface (PHP content signatures vs. HMDG Helpers' filename
     * artefact detection), so there is no scan to defer. The value is
     * surfaced in the conflict report for operator visibility.
     *
     * Not statically cached: the transient can be set or cleared between
     * early boot and later cron execution within the same request rarely,
     * but the cost of a single `get_transient()` on the rare cron-context
     * call site is negligible and the accuracy benefit is real.
     */
    public static function is_scan_running(): bool
    {
        if (!self::is_active()) {
            return false;
        }

        return (bool) get_transient(self::HELPERS_SCAN_TRANSIENT);
    }

    /**
     * Paths HMDG Security's modules should exclude from integrity and
     * malware monitoring because HMDG Helpers legitimately updates them.
     *
     * Returns the absolute path to whichever folder HMDG Helpers is
     * actually installed in (derived from the `active_plugins` option so
     * it tolerates versioned folder names like `hmdg-helpers-v1.2.3/`),
     * with a trailing slash. Paths are returned with forward slashes so
     * consumers need not re-normalise on Windows.
     *
     * @return list<string> Absolute directory paths, each terminated with `/`.
     */
    public static function get_excluded_paths(): array
    {
        if (!self::is_active()) {
            return [];
        }

        $active = get_option('active_plugins', []);
        if (!is_array($active)) {
            return [];
        }

        $plugin_dir = str_replace('\\', '/', WP_PLUGIN_DIR);
        $paths = [];

        foreach ($active as $entry) {
            if (!is_string($entry) || !str_ends_with($entry, self::HELPERS_MAIN_FILE_SUFFIX)) {
                continue;
            }
            // Extract the folder name: 'hmdg-helpers-v1.2.3/hmdg-helpers.php'
            // → 'hmdg-helpers-v1.2.3'. dirname keeps it simple and safe.
            $folder = dirname($entry);
            if ($folder === '' || $folder === '.' || $folder === DIRECTORY_SEPARATOR) {
                continue;
            }
            $paths[] = $plugin_dir . '/' . $folder . '/';
        }

        return $paths;
    }

    /**
     * Whether the current request is a WordPress plugin-activation request.
     *
     * Covers three signals:
     *
     *   1. `$_GET['action']` ∈ {activate, activate-selected, error_scrape} —
     *      the query-string shape used by the Plugins screen when toggling
     *      activation state. `sanitize_key()` normalises the input before
     *      the `in_array` check.
     *   2. `$_GET['activate'] === 'true'` — the redirect parameter WP adds
     *      after a successful activation handshake.
     *   3. `doing_action('activate_' . HMDG_SECURITY_PRO_BASENAME)` — we are
     *      currently inside our own activation hook.
     *
     * Security note: spoofing `$_GET['action']` would at worst cause
     * HMDG Security Pro to boot at `plugins_loaded` priority 99 instead
     * of 1. Every security hook still registers during `plugins_loaded`,
     * which runs before `init`, `template_redirect`, and any request-
     * handling phase — so the shift is fully inside the boot window and
     * leaves no unhooked attack surface. Attack surface: negligible.
     *
     * Result is cached for the lifetime of the request. That cache is
     * consulted during plugin-file-load AND again later from Plugin::boot(),
     * so the cache saves one `doing_action()` lookup in typical requests.
     */
    public static function is_activation_request(): bool
    {
        if (self::$is_activation_request !== null) {
            return self::$is_activation_request;
        }

        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        // Reading $_GET for activation-context detection is not an auth
        // gate; no nonce is required or available at this stage.
        if (isset($_GET['action'])) {
            $action = sanitize_key((string) $_GET['action']);
            if (in_array($action, ['activate', 'activate-selected', 'error_scrape'], true)) {
                return self::$is_activation_request = true;
            }
        }

        if (isset($_GET['activate']) && (string) $_GET['activate'] === 'true') {
            return self::$is_activation_request = true;
        }
        // phpcs:enable WordPress.Security.NonceVerification.Recommended

        if (defined('HMDG_SECURITY_PRO_BASENAME')
            && function_exists('doing_action')
            && doing_action('activate_' . HMDG_SECURITY_PRO_BASENAME)) {
            return self::$is_activation_request = true;
        }

        return self::$is_activation_request = false;
    }

    /**
     * Produce a structured snapshot of compatibility state for logging.
     *
     * Called from `Plugin::boot()` once per cron or admin boot. The
     * resulting array is fed to `LogService::info()` as structured context
     * so operators can verify at a glance that:
     *
     *   - transient keys are isolated between the two plugins
     *   - namespaces do not collide
     *   - the activation path is not at risk of interference
     *
     * The `transient_isolation` and `namespace_isolation` values are
     * compile-time truths (we deliberately never use HMDG Helpers'
     * `hmdg_helpers_` transient prefix and every HMDG Security class lives
     * under the `HMDG\Security\` namespace — verifiable by grep), so they
     * are asserted as the literal string `'confirmed'` rather than
     * re-checked at runtime.
     *
     * @return array{
     *     hmdg_helpers_active:    bool,
     *     hmdg_helpers_version:   string,
     *     security_module_active: bool,
     *     scan_throttle_active:   bool,
     *     transient_isolation:    string,
     *     namespace_isolation:    string,
     *     activation_safe:        bool,
     * }
     */
    public static function get_conflict_report(): array
    {
        return [
            'hmdg_helpers_active'    => self::is_active(),
            'hmdg_helpers_version'   => self::get_version(),
            'security_module_active' => self::has_security_module(),
            'scan_throttle_active'   => self::is_scan_running(),
            'transient_isolation'    => 'confirmed',
            'namespace_isolation'    => 'confirmed',
            // The plugin slug rename to `hmdg-security-pro` removes the
            // only path by which HMDG Helpers could have deactivated us.
            // `activation_safe` is therefore always true from our side;
            // we expose it as a value operators can alert on if a future
            // HMDG Helpers release widens its migration target list.
            'activation_safe'        => true,
        ];
    }
}
