<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Cross-references the local hash of a WordPress core file against the
 * canonical wp.org core checksums API.
 *
 * If the API confirms the on-disk hash is the expected stock-WordPress
 * hash, the file is Safe no matter what signals the detectors tripped
 * on it — core regularly contains patterns like `assert(`, `eval(`,
 * and long encoded strings in its own source, and those are legitimate.
 *
 * Endpoint: https://api.wordpress.org/core/checksums/1.0/?version=X&locale=en_US
 *
 * @security CRITICAL: this performs an outbound HTTP call. It is gated
 *           so it can ONLY fire in cron, WP-CLI, or admin contexts —
 *           never on an anonymous front-end page load. The guard is
 *           enforced at the top of matchesCoreBaseline(); every other
 *           method is a helper that does no network I/O.
 *
 * Cache: the successful response is cached for 24h in the object cache.
 *        A failed fetch is NOT cached — the next call retries.
 *
 * Failure mode: any error (network, HTTP code, JSON, hash mismatch,
 *               path outside ABSPATH) returns false. False means "we
 *               could not confirm this is stock core", which leaves
 *               the alert pipeline free to continue evaluating signals.
 *               The API is a suppression aid, not a gating requirement.
 *
 * @since 1.4.0
 */
final class CoreChecksumClient
{
    /** Module identifier used in log entries. */
    private const MODULE = 'CoreChecksumClient';

    public const STATUS_MATCH = 'match';
    public const STATUS_MISMATCH = 'mismatch';
    public const STATUS_UNVERIFIABLE = 'unverifiable';
    public const STATUS_NOT_CORE = 'not_core';

    /** wp.org core-checksums endpoint. */
    private const API_ENDPOINT = 'https://api.wordpress.org/core/checksums/1.0/';

    /** Outbound request timeout, seconds. */
    private const REQUEST_TIMEOUT = 10;

    /** Cache TTL for a successful response (24 hours). */
    private const CACHE_TTL = DAY_IN_SECONDS;

    /** Object-cache key for the core-checksum map. Versioned so bumping
     *  WordPress triggers a fresh fetch automatically. */
    private const CACHE_KEY_PREFIX = 'core_checksums_';

    /**
     * @param ObjectCacheService $cacheService Object-cache wrapper.
     * @param LogService         $logService   Structured logger.
     */
    public function __construct(
        private readonly ObjectCacheService $cacheService,
        private readonly LogService $logService,
    ) {}

    /**
     * Whether the given file matches the wp.org core-distribution hash.
     *
     * Return values:
     *   - true  : path is inside ABSPATH (and NOT inside wp-content),
     *             the fetched checksum map contains this path, and
     *             the local hash matches the canonical hash.
     *   - false : any of: path is outside ABSPATH, path is in
     *             wp-content (not a core file), the API returned an
     *             error, the JSON was malformed, the path is not in
     *             the returned map, or the hashes do not match.
     *
     * @param string $absolutePath Absolute filesystem path.
     * @param string $currentHash  MD5 hex digest of the file's bytes.
     *                             Note: wp.org publishes MD5 hashes.
     *                             Caller is expected to supply the MD5,
     *                             not the SHA-256 used elsewhere.
     *
     * @security Enforces the cron/admin/CLI gate before any HTTP call.
     */
    public function matchesCoreBaseline(string $absolutePath, string $currentHash): bool
    {
        return $this->coreBaselineStatus(
            absolutePath: $absolutePath,
            currentHash: $currentHash,
        ) === self::STATUS_MATCH;
    }

    /**
     * Return the baseline-verification status for a candidate core file.
     *
     * Status values:
     *   - self::STATUS_MATCH        confirmed canonical core file
     *   - self::STATUS_MISMATCH     confirmed core file, hash differs
     *   - self::STATUS_UNVERIFIABLE eligible core path but baseline could
     *                               not be fetched or resolved
     *   - self::STATUS_NOT_CORE     path is not an eligible core file
     */
    public function coreBaselineStatus(string $absolutePath, string $currentHash): string
    {
        // Hard gate — never make an outbound HTTP call on an anonymous
        // front-end request. The iron-law rule in .claude/CLAUDE.md is
        // unambiguous: "NEVER external HTTP on page loads".
        if (!$this->isAllowedContext()) {
            return self::STATUS_UNVERIFIABLE;
        }

        if ($absolutePath === '' || $currentHash === '') {
            return self::STATUS_UNVERIFIABLE;
        }

        if (!defined('ABSPATH')) {
            return self::STATUS_UNVERIFIABLE;
        }

        $normalised = str_replace('\\', '/', $absolutePath);
        $abspath    = rtrim(str_replace('\\', '/', \ABSPATH), '/') . '/';

        // Path must be inside ABSPATH.
        if (!str_starts_with($normalised, $abspath)) {
            return self::STATUS_NOT_CORE;
        }

        $relative = ltrim(substr($normalised, strlen($abspath)), '/');

        if ($relative === '') {
            return self::STATUS_NOT_CORE;
        }

        // The wp.org checksum API only covers core paths. wp-content/
        // (plugins, themes, uploads, mu-plugins) is excluded because
        // it is by definition not part of the core distribution.
        if (str_starts_with($relative, 'wp-content/')) {
            return self::STATUS_NOT_CORE;
        }

        $checksums = $this->fetchChecksums();

        if ($checksums === []) {
            return self::STATUS_UNVERIFIABLE;
        }

        $expected = $checksums[$relative] ?? null;

        if (!is_string($expected) || $expected === '') {
            return self::STATUS_UNVERIFIABLE;
        }

        return hash_equals($expected, strtolower($currentHash))
            ? self::STATUS_MATCH
            : self::STATUS_MISMATCH;
    }

    /**
     * Fetch the core-checksum map for the current WordPress version.
     *
     * Cached for 24h in the object cache. On miss, calls wp_remote_get.
     * On any failure returns [] — the caller treats [] as "no baseline
     * confirmation available".
     *
     * @return array<string, string> Map of relative-path => MD5 hash.
     */
    private function fetchChecksums(): array
    {
        $version = function_exists('get_bloginfo') ? (string) get_bloginfo('version') : '';

        if ($version === '') {
            return [];
        }

        $cacheKey = self::CACHE_KEY_PREFIX . $version;
        $cached   = $this->cacheService->get(key: $cacheKey);

        if (is_array($cached)) {
            /** @var array<string, string> $cached */
            return $cached;
        }

        $url = self::API_ENDPOINT . '?version=' . rawurlencode($version) . '&locale=en_US';

        // wp_remote_get is the WordPress HTTP abstraction. It honours
        // the WP_HTTP_BLOCK_EXTERNAL constant some hosts set, fails
        // gracefully on DNS / timeout, and returns a WP_Error rather
        // than throwing.
        if (!function_exists('wp_remote_get')) {
            return [];
        }

        $response = wp_remote_get($url, [
            'timeout'     => self::REQUEST_TIMEOUT,
            'redirection' => 2,
            'sslverify'   => true,
            'user-agent'  => 'HMDG-Security/1.4 (+https://hmdg.co.uk)',
        ]);

        if (is_wp_error($response)) {
            $this->logService->info(
                module: self::MODULE,
                message: 'wp.org checksum fetch failed — fail open',
                context: [
                    'wp_version' => $version,
                    'error'      => $response->get_error_message(),
                ],
            );
            return [];
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        $body = (string) wp_remote_retrieve_body($response);

        if ($code !== 200 || $body === '') {
            $this->logService->info(
                module: self::MODULE,
                message: 'wp.org checksum fetch returned non-200 — fail open',
                context: [
                    'wp_version' => $version,
                    'http_code'  => $code,
                ],
            );
            return [];
        }

        $decoded = json_decode(json: $body, associative: true);

        if (!is_array($decoded) || !isset($decoded['checksums']) || !is_array($decoded['checksums'])) {
            $this->logService->info(
                module: self::MODULE,
                message: 'wp.org checksum payload malformed — fail open',
                context: ['wp_version' => $version],
            );
            return [];
        }

        /** @var array<string, string> $checksums */
        $checksums = array_filter(
            $decoded['checksums'],
            static fn ($v): bool => is_string($v),
        );

        $this->cacheService->set(
            key: $cacheKey,
            value: $checksums,
            expiration: self::CACHE_TTL,
        );

        return $checksums;
    }

    /**
     * Whether the current request context is allowed to issue outbound
     * HTTP calls. Matches Plugin::shouldBindCronCallbacks() — admin,
     * cron, or WP-CLI only.
     */
    private function isAllowedContext(): bool
    {
        if (function_exists('wp_doing_cron') && wp_doing_cron()) {
            return true;
        }

        if (defined('WP_CLI') && \WP_CLI) {
            return true;
        }

        if (function_exists('is_admin') && is_admin()) {
            return true;
        }

        return false;
    }
}
