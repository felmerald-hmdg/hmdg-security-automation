<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\SecurityEvent;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\LogService;

/**
 * Security hardening for the Divi Builder and Divi theme.
 *
 * Covers three attack surfaces specific to Divi-powered sites:
 *
 *  1. **Contact form spam** — honeypot, timestamp, and pattern-based
 *     validation on Divi contact modules. Injected via JavaScript on the
 *     front-end and validated server-side on `template_redirect`.
 *  2. **Builder data** — `et_pb_layout` post types and `et-cache`
 *     directories are handled by DatabaseCleanup and MalwareScanner
 *     exclusions respectively, not by this module.
 *  3. **Outbound API monitoring** — elegantthemes.com licence requests
 *     are whitelisted. Outbound HTTP requests originating from Divi files
 *     to unknown domains are logged (not blocked) for manual review via
 *     the `http_api_debug` hook, **registered admin-only** because that is
 *     where Divi makes API calls and where `debug_backtrace()` cost is
 *     acceptable. Front-end requests never trigger the backtrace.
 *
 * The module self-disables when Divi is not installed.
 *
 * @since 1.0.0
 */
final class DiviSecurity
{
    /** Module identifier used in log entries. */
    private const MODULE = 'DiviSecurity';

    /**
     * Standard WordPress domains that should never trigger an alert when
     * contacted by Divi code.
     *
     * @var list<string>
     */
    private const WORDPRESS_CORE_DOMAINS = [
        'wordpress.org',
        'api.wordpress.org',
        'downloads.wordpress.org',
        'gravatar.com',
        'secure.gravatar.com',
        's.w.org',
    ];

    /**
     * @param SecurityConfig          $config           Immutable plugin configuration.
     * @param AlertService            $alertService     Alert dispatcher for security events.
     * @param LogService              $logService       File-based security logger.
     * @param BuilderDetectionService $builderDetection Builder state detection service.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly AlertService $alertService,
        private readonly LogService $logService,
        private readonly BuilderDetectionService $builderDetection,
    ) {
        if (!$this->builderDetection->isDiviInstalled()) {
            return;
        }

        $this->registerFormHooks();
        $this->registerHoneypotInjection();
        $this->registerApiMonitoring();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Form Security — Divi Contact Modules
    // ═══════════════════════════════════════════════════════════════════

    private function registerFormHooks(): void
    {
        add_action('template_redirect', [$this, 'validateDiviContactForm'], 1, 0);
    }

    /**
     * Validate Divi contact form submissions for spam indicators.
     */
    public function validateDiviContactForm(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Divi handles its own nonce
        if (!isset($_POST['et_pb_contactform_submit'])) {
            return;
        }

        $this->checkHoneypot();
        $this->checkTimestamp();
        $this->checkPatterns();
    }

    /**
     * Check the honeypot hidden field for bot activity.
     */
    private function checkHoneypot(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Divi handles its own nonce
        $honeypotValue = sanitize_text_field(wp_unslash($_POST['hmdg_hp_field'] ?? ''));

        if ($honeypotValue === '') {
            return;
        }

        $ip = $this->getClientIp();

        $this->logService->warning(self::MODULE, 'Honeypot triggered on Divi contact form.', [
            'honeypot_value' => $honeypotValue,
            'ip'             => $ip,
        ]);

        $this->alertService->send(SecurityEvent::SpamDetected, [
            'source'         => $ip,
            'form_type'      => 'divi_contact_form',
            'reason'         => 'honeypot',
            'honeypot_value' => $honeypotValue,
            'ip'             => $ip,
        ]);

        wp_die(
            message: 'Submission failed.',
            title: 'Spam Detected',
            args: ['response' => 403, 'back_link' => true],
        );
    }

    /**
     * Check the timestamp hidden field for automated rapid submission.
     *
     * Missing/zero timestamp is logged as suspicious but not hard-rejected
     * — pages cached before plugin activation will not have the field.
     */
    private function checkTimestamp(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Divi handles its own nonce
        $timestamp = (int) sanitize_text_field(wp_unslash($_POST['hmdg_ts'] ?? '0'));

        if ($timestamp <= 0) {
            return;
        }

        $elapsed = time() - $timestamp;

        if ($elapsed >= $this->config->spamMinSubmitTime) {
            return;
        }

        $ip = $this->getClientIp();

        $this->logService->warning(self::MODULE, 'Time-based spam check failed on Divi contact form.', [
            'elapsed_seconds' => $elapsed,
            'min_required'    => $this->config->spamMinSubmitTime,
            'ip'              => $ip,
        ]);

        $this->alertService->send(SecurityEvent::SpamDetected, [
            'source'          => $ip,
            'form_type'       => 'divi_contact_form',
            'reason'          => 'too_fast',
            'elapsed_seconds' => $elapsed,
            'ip'              => $ip,
        ]);

        wp_die(
            message: 'Submission failed.',
            title: 'Spam Detected',
            args: ['response' => 403, 'back_link' => true],
        );
    }

    /**
     * Scan all POST fields for spam patterns, excessive URLs, and
     * disposable email domains.
     */
    private function checkPatterns(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Divi handles its own nonce
        $postData = $_POST;

        $ip = $this->getClientIp();

        foreach ($postData as $key => $value) {
            if (!is_string($value)) {
                continue;
            }

            $value = sanitize_text_field(wp_unslash($value));

            if ($value === '') {
                continue;
            }

            // ── URL count check (substr_count is faster than preg_match_all) ──
            $urlCount = substr_count($value, 'http://') + substr_count($value, 'https://');

            if ($urlCount > $this->config->spamMaxUrls) {
                $this->logService->warning(self::MODULE, 'Excessive URLs detected in Divi contact form field.', [
                    'field_key' => $key,
                    'url_count' => $urlCount,
                    'max_urls'  => $this->config->spamMaxUrls,
                    'ip'        => $ip,
                ]);

                $this->alertService->send(SecurityEvent::SpamDetected, [
                    'source'    => $ip,
                    'form_type' => 'divi_contact_form',
                    'reason'    => 'excessive_urls',
                    'field_key' => $key,
                    'url_count' => $urlCount,
                    'ip'        => $ip,
                ]);

                wp_die(
                    message: 'Submission failed.',
                    title: 'Spam Detected',
                    args: ['response' => 403, 'back_link' => true],
                );
            }

            // ── Spam phrase check ──────────────────────────────────
            $lowerValue = strtolower($value);

            foreach ($this->config->spamPhrases as $phrase) {
                if (str_contains($lowerValue, $phrase)) {
                    $this->logService->warning(self::MODULE, 'Spam phrase detected in Divi contact form field.', [
                        'field_key' => $key,
                        'phrase'    => $phrase,
                        'ip'        => $ip,
                    ]);

                    $this->alertService->send(SecurityEvent::SpamDetected, [
                        'source'    => $ip,
                        'form_type' => 'divi_contact_form',
                        'reason'    => 'spam_phrase',
                        'field_key' => $key,
                        'phrase'    => $phrase,
                        'ip'        => $ip,
                    ]);

                    wp_die(
                        message: 'Submission failed.',
                        title: 'Spam Detected',
                        args: ['response' => 403, 'back_link' => true],
                    );
                }
            }

            // ── Disposable email check ─────────────────────────────
            if (is_email($value)) {
                $emailDomain = $this->extractEmailDomain($value);

                if ($emailDomain !== '' && in_array($emailDomain, $this->config->disposableEmailDomains, true)) {
                    $this->logService->warning(self::MODULE, 'Disposable email domain detected in Divi contact form.', [
                        'field_key' => $key,
                        'domain'    => $emailDomain,
                        'ip'        => $ip,
                    ]);

                    $this->alertService->send(SecurityEvent::SpamDetected, [
                        'source'    => $ip,
                        'form_type' => 'divi_contact_form',
                        'reason'    => 'disposable_email',
                        'field_key' => $key,
                        'domain'    => $emailDomain,
                        'ip'        => $ip,
                    ]);

                    wp_die(
                        message: 'Submission failed.',
                        title: 'Spam Detected',
                        args: ['response' => 403, 'back_link' => true],
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Honeypot Injection — Front-end JavaScript
    // ═══════════════════════════════════════════════════════════════════

    private function registerHoneypotInjection(): void
    {
        add_action('wp_footer', [$this, 'injectHoneypotFields'], 99, 0);
    }

    /**
     * Output an inline script that appends honeypot and timestamp hidden
     * inputs to every `.et_pb_contact_form` element on the page.
     */
    public function injectHoneypotFields(): void
    {
        if ($this->builderDetection->isDiviBuilderActive()) {
            return;
        }

        $timestamp = time();

        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var forms = document.querySelectorAll('.et_pb_contact_form');
            for (var i = 0; i < forms.length; i++) {
                var form = forms[i];
                if (form.querySelector('input[name="hmdg_hp_field"]')) {
                    continue;
                }
                var hp = document.createElement('div');
                hp.setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;overflow:hidden;');
                hp.setAttribute('aria-hidden', 'true');
                hp.innerHTML = '<input type="text" name="hmdg_hp_field" value="" tabindex="-1" autocomplete="off" />';
                form.appendChild(hp);
                var ts = document.createElement('input');
                ts.setAttribute('type', 'hidden');
                ts.setAttribute('name', 'hmdg_ts');
                ts.setAttribute('value', '<?php echo esc_js((string) $timestamp); ?>');
                form.appendChild(ts);
            }
        });
        </script>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Divi API Monitoring
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Register the `http_api_debug` hook for monitoring outbound HTTP
     * requests made by Divi code — admin-only.
     *
     * @perf debug_backtrace() with limit 20 costs ~0.2-0.5ms per outbound
     *   HTTP call. On the front-end this could fire on every wp_remote_*
     *   call (update checks etc.), inflating overhead. Divi makes its
     *   licence/API calls in admin, so we register the hook only there.
     *   Front-end pages now pay zero cost for this monitoring.
     */
    private function registerApiMonitoring(): void
    {
        if (!is_admin()) {
            return;
        }
        add_action('http_api_debug', [$this, 'monitorOutboundRequests'], 10, 5);
    }

    /**
     * Inspect completed outbound HTTP requests for suspicious Divi-origin
     * traffic to unknown domains.
     *
     * @param array|\WP_Error      $response  HTTP response or WP_Error.
     * @param string               $context   Context identifier ('response').
     * @param string               $transport Transport class name.
     * @param array<string, mixed> $args      Request arguments.
     * @param string               $url       The requested URL.
     */
    public function monitorOutboundRequests(
        array|\WP_Error $response,
        string $context,
        string $transport,
        array $args,
        string $url,
    ): void {
        if ($context !== 'response') {
            return;
        }

        $parsedUrl = wp_parse_url($url);
        $host      = strtolower($parsedUrl['host'] ?? '');

        if ($host === '') {
            return;
        }

        if ($this->isDomainLegitimate($host)) {
            return;
        }

        if (!$this->isFromDiviContext()) {
            return;
        }

        $ip = $this->getClientIp();

        $this->logService->warning(self::MODULE, 'Divi code contacted an unknown external domain.', [
            'url'    => $url,
            'domain' => $host,
            'ip'     => $ip,
        ]);

        $this->alertService->send(SecurityEvent::BuilderAnomalyDetected, [
            'source' => $ip,
            'url'    => $url,
            'domain' => $host,
            'ip'     => $ip,
        ]);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Private Helpers
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Determine whether a domain is in the combined legitimate domain list.
     *
     * @param string $host Lowercase hostname to check.
     */
    private function isDomainLegitimate(string $host): bool
    {
        $legitimateDomains = [
            ...$this->config->builderExternalDomains,
            ...self::WORDPRESS_CORE_DOMAINS,
        ];

        foreach ($legitimateDomains as $domain) {
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check whether the current call stack originates from Divi code.
     */
    private function isFromDiviContext(): bool
    {
        $diviPathMarkers = [
            'et-builder',
            '/Divi/',
            '/extra/',
            'divi-builder',
        ];

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Security monitoring
        $backtrace = debug_backtrace(options: DEBUG_BACKTRACE_IGNORE_ARGS, limit: 20);

        foreach ($backtrace as $frame) {
            $file = $frame['file'] ?? '';

            if ($file === '') {
                continue;
            }

            foreach ($diviPathMarkers as $marker) {
                if (str_contains($file, $marker)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Extract the domain portion from an email address.
     *
     * @param string $email The email address to parse.
     *
     * @return string Lowercase domain, or empty string if unparseable.
     */
    private function extractEmailDomain(string $email): string
    {
        $parts = explode('@', $email, 2);

        if (count($parts) !== 2) {
            return '';
        }

        return strtolower(trim($parts[1]));
    }

    /**
     * Retrieve the client IP from $_SERVER['REMOTE_ADDR'] only.
     *
     * @security On WP Engine and Flywheel, REMOTE_ADDR is set by the load
     *   balancer to the real visitor IP. Trusting HTTP_X_FORWARDED_FOR /
     *   HTTP_CF_CONNECTING_IP / HTTP_X_REAL_IP is a CRITICAL bug because
     *   any client can spoof those headers. Previous versions of this
     *   method trusted those headers and were rewritten.
     */
    private function getClientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        $sanitised = preg_replace('/[^0-9a-fA-F.:]/', '', $ip);

        if ($sanitised === '' || $sanitised === null) {
            return '0.0.0.0';
        }

        if (filter_var($sanitised, \FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }

        return $sanitised;
    }
}
