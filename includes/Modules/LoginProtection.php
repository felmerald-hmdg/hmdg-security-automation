<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\Admin\LockoutLogRepository;
use HMDG\Security\SecurityConfig;
use HMDG\Security\SecurityEvent;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Brute-force login protection with IP-based rate limiting, lockout,
 * timing randomisation, and XML-RPC authentication hardening.
 *
 * All state is stored exclusively in the WordPress object cache — no
 * database tables, no options, no transients. A persistent cache backend
 * (Redis, Memcached) is required for cross-request protection.
 *
 * Builder AJAX requests (Elementor/Divi licence activation callbacks)
 * are exempt from all rate limiting to prevent false lockouts.
 *
 * @since 1.0.0
 */
final class LoginProtection
{
    /**
     * Cache key prefix for failed login attempt counters.
     */
    private const CACHE_KEY_ATTEMPTS = 'login_attempts_';

    /**
     * Cache key prefix for IP lockout flags.
     */
    private const CACHE_KEY_LOCKOUT = 'login_lockout_';

    /**
     * Generic error message returned on all login failures.
     *
     * Deliberately vague to prevent username enumeration attacks.
     */
    private const GENERIC_LOGIN_ERROR = 'Authentication failed. Please check your credentials.';

    /**
     * Generic message displayed to locked-out IP addresses.
     *
     * Does not reveal lockout duration or attempt thresholds.
     */
    private const LOCKOUT_MESSAGE = 'Too many failed login attempts. Please try again later.';

    /**
     * Minimum microseconds for timing randomisation delay.
     */
    private const TIMING_DELAY_MIN = 100_000;

    /**
     * Maximum microseconds for timing randomisation delay.
     */
    private const TIMING_DELAY_MAX = 500_000;

    /**
     * XML-RPC methods that involve authentication and must be rate-limited.
     *
     * @var list<string>
     */
    private const XMLRPC_AUTH_METHODS = [
        'wp.getUsersBlogs',
        'wp.getOptions',
        'wp.getUsers',
        'wp.getProfile',
        'wp.editProfile',
        'wp.getAuthors',
        'wp.getPost',
        'wp.getPosts',
        'wp.newPost',
        'wp.editPost',
        'wp.deletePost',
        'wp.getMediaItem',
        'wp.getMediaLibrary',
        'wp.uploadFile',
        'wp.getComments',
        'wp.newComment',
        'wp.editComment',
        'wp.deleteComment',
        'wp.getTaxonomies',
        'wp.getTaxonomy',
        'wp.getTerms',
        'wp.getTerm',
        'wp.getPages',
        'wp.getPage',
        'wp.newPage',
        'wp.editPage',
        'wp.deletePage',
    ];

    /**
     * Register all WordPress hooks for login protection.
     *
     * @param SecurityConfig          $config           Immutable plugin configuration.
     * @param ObjectCacheService      $cacheService     Object cache wrapper.
     * @param AlertService            $alertService     Alert dispatch service.
     * @param LogService              $logService       Structured logging service.
     * @param BuilderDetectionService $builderDetection Page builder detection service.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly ObjectCacheService $cacheService,
        private readonly AlertService $alertService,
        private readonly LogService $logService,
        private readonly BuilderDetectionService $builderDetection,
        private readonly LockoutLogRepository $lockoutLog,
    ) {
        $this->registerHooks();
    }

    /**
     * Attach all WordPress action and filter hooks.
     */
    private function registerHooks(): void
    {
        // Check lockout before authentication runs
        add_action('wp_authenticate', [$this, 'checkLockout'], 1, 1);

        // Record failed login attempts
        add_action('wp_login_failed', [$this, 'handleFailedLogin'], 10, 1);

        // Clear lockout on successful login
        add_action('wp_login', [$this, 'handleSuccessfulLogin'], 10, 1);

        // Suppress detailed login error messages
        add_filter('login_errors', [$this, 'sanitiseLoginErrors'], 10, 1);

        // Add timing randomisation after WordPress authentication checks
        add_filter('authenticate', [$this, 'addTimingRandomisation'], 30, 1);

        // Rate-limit XML-RPC authentication methods
        add_action('xmlrpc_call', [$this, 'handleXmlRpcCall'], 10, 1);
    }

    /**
     * Check whether the requesting IP is currently locked out.
     *
     * Runs on wp_authenticate at priority 1 (before WordPress performs
     * credential verification). If the IP is locked out, execution halts
     * with wp_die() and a generic message.
     *
     * Builder AJAX requests are exempt to avoid blocking Elementor/Divi
     * licence activation callbacks.
     *
     * @param string $username The username being authenticated (unused but required by hook signature).
     */
    public function checkLockout(string $username): void
    {
        if ($this->builderDetection->isBuilderAjax()) {
            return;
        }

        $ip = $this->getClientIp();

        if (!$this->isLockedOut(ip: $ip)) {
            return;
        }

        $this->logService->warning(
            module: 'LoginProtection',
            message: 'Locked-out IP attempted login',
            context: [
                'ip' => $ip,
                'username' => $username,
            ],
        );

        wp_die(
            message: self::LOCKOUT_MESSAGE,
            title: 'Access Denied',
            args: ['response' => 403],
        );
    }

    /**
     * Record a failed login attempt and trigger lockout if threshold is reached.
     *
     * Increments the attempt counter for the requesting IP in object cache.
     * When the counter reaches the configured maximum, a lockout flag is set
     * and an alert is dispatched to the site administrator.
     *
     * Builder AJAX requests are exempt.
     *
     * @param string $username The username that failed authentication.
     */
    public function handleFailedLogin(string $username): void
    {
        if ($this->builderDetection->isBuilderAjax()) {
            return;
        }

        $ip = $this->getClientIp();
        $attemptsKey = self::CACHE_KEY_ATTEMPTS . $ip;

        // Atomic increment with explicit TTL — no separate set() needed.
        // Previous code did increment() then conditionally set() on attempt 1,
        // which had two issues: (1) non-atomic check-then-set race, (2) TTL
        // coupling between two layers (DEFAULT_EXPIRATION vs loginLockoutDuration).
        $attempts = $this->cacheService->increment(
            key: $attemptsKey,
            offset: 1,
            expiration: $this->config->loginLockoutDuration,
        );

        $this->logService->info(
            module: 'LoginProtection',
            message: 'Failed login attempt recorded',
            context: [
                'ip' => $ip,
                'username' => $username,
                'attempts' => $attempts,
                'max_attempts' => $this->config->loginMaxAttempts,
            ],
        );

        if ($attempts !== false && $attempts >= $this->config->loginMaxAttempts) {
            $this->lockIp(ip: $ip, username: $username, attempts: $attempts);
        }
    }

    /**
     * Clear attempt counter and lockout flag on successful login.
     *
     * @param string $username The username that successfully authenticated.
     */
    public function handleSuccessfulLogin(string $username): void
    {
        $ip = $this->getClientIp();

        $this->cacheService->delete(key: self::CACHE_KEY_ATTEMPTS . $ip);
        $this->cacheService->delete(key: self::CACHE_KEY_LOCKOUT . $ip);

        $this->logService->info(
            module: 'LoginProtection',
            message: 'Successful login — lockout state cleared',
            context: [
                'ip' => $ip,
                'username' => $username,
            ],
        );
    }

    /**
     * Replace all login error messages with a generic response.
     *
     * WordPress login errors typically reveal whether a username exists
     * ("Unknown username") or just the password is wrong. This filter
     * replaces every error with an identical generic message to prevent
     * username enumeration.
     *
     * @param string $errors The original login error message HTML.
     *
     * @return string Generic error message.
     */
    public function sanitiseLoginErrors(string $errors): string
    {
        return self::GENERIC_LOGIN_ERROR;
    }

    /**
     * Add random microsecond delay after authentication to prevent timing attacks.
     *
     * Timing attacks can determine whether a username exists by measuring
     * response time differences. A random delay of 100-500ms normalises
     * response times regardless of the authentication outcome.
     *
     * Runs at priority 30 on the 'authenticate' filter — after WordPress
     * core authentication checks (priority 20).
     *
     * @param \WP_User|\WP_Error|null $user The authentication result.
     *
     * @return \WP_User|\WP_Error|null Pass-through, unmodified.
     */
    public function addTimingRandomisation(\WP_User|\WP_Error|null $user): \WP_User|\WP_Error|null
    {
        usleep(random_int(self::TIMING_DELAY_MIN, self::TIMING_DELAY_MAX));

        return $user;
    }

    /**
     * Apply rate limiting to XML-RPC methods that require authentication.
     *
     * XML-RPC is a common brute-force vector because it allows multiple
     * authentication attempts within a single HTTP request (system.multicall).
     * This handler applies the same IP-based rate limiting used for wp-login.php.
     *
     * Builder AJAX requests are exempt.
     *
     * @param string $method The XML-RPC method being called.
     */
    public function handleXmlRpcCall(string $method): void
    {
        if ($this->builderDetection->isBuilderAjax()) {
            return;
        }

        if (!$this->isXmlRpcAuthMethod(method: $method)) {
            return;
        }

        $ip = $this->getClientIp();

        // Block if already locked out
        if ($this->isLockedOut(ip: $ip)) {
            $this->logService->warning(
                module: 'LoginProtection',
                message: 'Locked-out IP attempted XML-RPC authentication',
                context: [
                    'ip' => $ip,
                    'method' => $method,
                ],
            );

            wp_die(
                message: self::LOCKOUT_MESSAGE,
                title: 'Access Denied',
                args: ['response' => 403],
            );
        }

        // Increment attempt counter for XML-RPC auth methods (atomic, with TTL)
        $attemptsKey = self::CACHE_KEY_ATTEMPTS . $ip;
        $attempts = $this->cacheService->increment(
            key: $attemptsKey,
            offset: 1,
            expiration: $this->config->loginLockoutDuration,
        );

        $this->logService->info(
            module: 'LoginProtection',
            message: 'XML-RPC authentication attempt recorded',
            context: [
                'ip' => $ip,
                'method' => $method,
                'attempts' => $attempts,
            ],
        );

        if ($attempts !== false && $attempts >= $this->config->loginMaxAttempts) {
            $this->lockIp(ip: $ip, username: 'xmlrpc:' . $method, attempts: $attempts);
        }
    }

    /**
     * Set the lockout flag in cache and dispatch an alert.
     *
     * @param string     $ip       The IP address being locked out.
     * @param string     $username The username associated with the final failed attempt.
     * @param int|false  $attempts Total failed attempts recorded.
     */
    private function lockIp(string $ip, string $username, int|false $attempts): void
    {
        $lockoutKey = self::CACHE_KEY_LOCKOUT . $ip;
        $lockoutStart = time();

        // v1.10.0 — when indefinite mode is on, cache TTL is effectively
        // forever (1 year) and the DB row carries a far-future sentinel
        // `expires_at`. Admin unlock is the only way out. When off, the
        // pre-v1.10 behaviour is preserved exactly.
        $indefinite = $this->config->loginLockoutIndefinite;
        $cacheTtl = $indefinite ? YEAR_IN_SECONDS : $this->config->loginLockoutDuration;
        $expiresAt = $indefinite
            ? '2099-12-31 23:59:59'
            : gmdate('Y-m-d H:i:s', $lockoutStart + $this->config->loginLockoutDuration);

        // Store the Unix timestamp of the lockout rather than a bool;
        // the v1.5.0 admin UI reads this to compute "expires in".
        // exists() still returns true for any non-evicted key.
        $this->cacheService->set(
            key: $lockoutKey,
            value: $lockoutStart,
            expiration: $cacheTtl,
        );

        // v1.5.0 — maintain a small index of currently-locked IPs so
        // the admin UI can enumerate them without SCANing the cache.
        $this->indexLockout(
            ip: $ip,
            lockedAt: $lockoutStart,
            attempts: is_int($attempts) ? $attempts : 0,
        );

        try {
            $this->lockoutLog->insert([
                'ip'                       => $ip,
                'username'                 => $username,
                'attempts'                 => is_int($attempts) ? $attempts : 0,
                'locked_at'                => gmdate('Y-m-d H:i:s', $lockoutStart),
                'expires_at'               => $expiresAt,
                'lockout_duration_seconds' => $this->config->loginLockoutDuration,
                'indefinite'               => $indefinite ? 1 : 0,
            ]);
        } catch (\Throwable) {
            // Lockout enforcement must never fail because the history log write did.
        }

        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone('Europe/London'),
        ))->format('Y-m-d H:i:s T');

        $siteUrl = get_site_url();

        $context = [
            'ip' => $ip,
            'username' => $username,
            'attempts' => $attempts,
            'timestamp' => $timestamp,
            'site_url' => $siteUrl,
            'lockout_duration_seconds' => $this->config->loginLockoutDuration,
            'recommendation' => 'Verify whether this IP belongs to a legitimate user. '
                . 'If the lockout is unexpected, check server access logs for additional context. '
                . 'Consider permanently blocking the IP at the firewall level if attacks persist.',
        ];

        $this->logService->critical(
            module: 'LoginProtection',
            message: 'IP locked out after exceeding maximum failed login attempts',
            context: $context,
        );

        $this->alertService->send(
            event: SecurityEvent::LoginLockout,
            context: $context,
        );
    }

    /**
     * Whether the given IP address is currently locked out.
     *
     * Fast path: single cache lookup.
     *
     * v1.10.0 slow path: when indefinite mode is on AND the cache has
     * no entry for this IP, fall back to a DB query for active
     * indefinite rows. If found, re-warm the cache with a year-long
     * TTL so subsequent requests in this worker hit the fast path.
     *
     * Only runs in login-POST / XML-RPC context because `LoginProtection`
     * itself is only instantiated when `Plugin::isLoginContext()` returns
     * true — so the DB fallback cannot fire on anonymous front-end GETs.
     *
     * @param string $ip The IP address to check.
     *
     * @return bool True if this IP is currently locked out.
     */
    private function isLockedOut(string $ip): bool
    {
        $cacheKey = self::CACHE_KEY_LOCKOUT . $ip;

        if ($this->cacheService->exists(key: $cacheKey)) {
            return true;
        }

        if (!$this->config->loginLockoutIndefinite) {
            return false;
        }

        if (!$this->lockoutLog->hasActiveIndefiniteLockout($ip)) {
            return false;
        }

        // Re-warm the cache — Redis likely got flushed (WPE maintenance,
        // fleet deploy CACHE_CLEAR, etc.). Future requests in this worker
        // skip the DB fallback and take the fast path above.
        $this->cacheService->set(
            key: $cacheKey,
            value: time(),
            expiration: YEAR_IN_SECONDS,
        );

        return true;
    }

    /**
     * v1.5.0 — add / refresh an IP entry in the lockout index used by
     * the HMDG Security admin page. The index is a small array stored
     * at a single cache key so the UI can enumerate lockouts with one
     * cache read. TTL slightly exceeds the per-IP lockout so the UI
     * can gracefully show recently-expired rows.
     */
    private function indexLockout(string $ip, int $lockedAt, int $attempts): void
    {
        $indexKey = 'hmdg_lockout_index';
        $raw = $this->cacheService->get(key: $indexKey);

        $index = is_array($raw) ? $raw : [];
        $index[$ip] = [
            'locked_at' => $lockedAt,
            'attempts'  => $attempts,
        ];

        // Keep the index bounded — pathological brute-force waves from
        // a large botnet could otherwise balloon the stored array. Retain
        // the 200 newest entries by locked_at, drop the rest.
        if (count($index) > 200) {
            uasort(
                $index,
                static fn ($a, $b): int => ($b['locked_at'] ?? 0) <=> ($a['locked_at'] ?? 0),
            );
            $index = array_slice($index, 0, 200, true);
        }

        $this->cacheService->set(
            key: $indexKey,
            value: $index,
            expiration: max(
                $this->config->loginLockoutDuration + 3600,
                90000,
            ),
        );
    }

    /**
     * v1.5.0 — remove the lockout + attempts counter for a single IP
     * and drop it from the admin lockout index. Called ONLY from the
     * AdminActions Unlock handler; the standard successful-login path
     * has its own clearing logic in handleSuccessfulLogin().
     */
    public function unlock(string $ip): void
    {
        if ($ip === '') {
            return;
        }

        $this->cacheService->delete(key: self::CACHE_KEY_ATTEMPTS . $ip);
        $this->cacheService->delete(key: self::CACHE_KEY_LOCKOUT . $ip);

        $indexKey = 'hmdg_lockout_index';
        $raw = $this->cacheService->get(key: $indexKey);
        if (is_array($raw) && isset($raw[$ip])) {
            unset($raw[$ip]);
            $this->cacheService->set(
                key: $indexKey,
                value: $raw,
                expiration: max(
                    $this->config->loginLockoutDuration + 3600,
                    90000,
                ),
            );
        }
    }

    /**
     * Whether the given XML-RPC method requires authentication.
     *
     * Matches against an explicit list of known auth-requiring methods
     * and a prefix-based fallback for any wp.* method not in the list.
     *
     * @param string $method The XML-RPC method name.
     *
     * @return bool True if the method involves authentication.
     */
    private function isXmlRpcAuthMethod(string $method): bool
    {
        if (in_array($method, self::XMLRPC_AUTH_METHODS, true)) {
            return true;
        }

        // Catch any wp.* method not explicitly listed — they all require auth
        return str_starts_with($method, 'wp.');
    }

    /**
     * Retrieve the client IP address from the server environment.
     *
     * Uses REMOTE_ADDR exclusively. X-Forwarded-For is not trusted because
     * it is trivially spoofable by clients. WP Engine and similar managed
     * hosts set REMOTE_ADDR to the real client IP behind their reverse proxy.
     *
     * The returned value is sanitised to contain only valid IP characters.
     *
     * @return string The sanitised client IP address, or '0.0.0.0' if unavailable.
     */
    private function getClientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Sanitise: allow only valid IP address characters (digits, dots, colons for IPv6, hex letters)
        $sanitised = preg_replace('/[^0-9a-fA-F.:\/]/', '', $ip);

        if ($sanitised === '' || $sanitised === null) {
            return '0.0.0.0';
        }

        // Validate as a proper IP address
        if (filter_var($sanitised, \FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }

        return $sanitised;
    }
}
