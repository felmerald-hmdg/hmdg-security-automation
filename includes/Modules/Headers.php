<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\BuilderDetectionService;

/**
 * Sends security-related HTTP response headers on every front-end and
 * admin page load.
 *
 * Headers are the first line of defence against XSS, clickjacking,
 * MIME-sniffing, and protocol-downgrade attacks. Every header is
 * builder-aware: Elementor and Divi load their editors inside iframes,
 * issue internal AJAX/REST calls, and rely on inline scripts + eval()
 * for their visual builders. Naively strict headers would break the
 * editing experience, so we relax or skip headers when builder
 * internals are detected.
 *
 * @see https://owasp.org/www-project-secure-headers/
 */
final class Headers
{
    /** Module identifier used in log entries. */
    private const MODULE = 'headers';

    public function __construct(
        private readonly SecurityConfig $config,
        private readonly BuilderDetectionService $builderDetection,
    ) {
        add_action('send_headers', $this->sendSecurityHeaders(...), 10, 0);
    }

    /**
     * Emit all security headers in one callback to minimise hook overhead.
     *
     * Skips execution entirely for builder AJAX and REST requests because
     * those are internal transport calls that never render in a browser
     * tab — headers are irrelevant and some (like X-Frame-Options) would
     * actively interfere with builder iframe communication.
     */
    public function sendSecurityHeaders(): void
    {
        /*
         * Builder AJAX requests (admin-ajax.php with a builder action)
         * and builder REST requests (/elementor/v1/*, /et/v1/*) are
         * internal data-transport calls. They are consumed by JavaScript,
         * not rendered as HTML, so browser security headers are
         * meaningless and some (X-Frame-Options) would break builder
         * iframes that consume these responses.
         */
        if ($this->builderDetection->isBuilderAjax() || $this->builderDetection->isBuilderRestRequest()) {
            return;
        }

        $this->setXFrameOptions();
        $this->setXContentTypeOptions();
        $this->setXXssProtection();
        $this->setReferrerPolicy();
        $this->setPermissionsPolicy();
        $this->setStrictTransportSecurity();
        $this->setContentSecurityPolicyReportOnly();
        $this->removeServerFingerprints();
    }

    // ── 1. X-Frame-Options ─────────────────────────────────────────────

    /**
     * Prevents the page from being embedded in a frame on a foreign
     * origin, mitigating clickjacking attacks.
     *
     * Elementor exception: the Elementor editor loads the front-end
     * inside an <iframe> on the same origin. SAMEORIGIN allows this,
     * but Elementor's preview frame can trigger edge-case breakage in
     * some browsers when X-Frame-Options is present alongside its own
     * CSP frame-ancestors directive. We therefore skip this header
     * entirely when Elementor edit mode is detected, relying on the
     * frame-ancestors 'self' directive in our CSP-RO header instead.
     */
    private function setXFrameOptions(): void
    {
        if ($this->builderDetection->isElementorEditMode()) {
            return;
        }

        header('X-Frame-Options: SAMEORIGIN');
    }

    // ── 2. X-Content-Type-Options ──────────────────────────────────────

    /**
     * Prevents browsers from MIME-sniffing a response away from the
     * declared Content-Type. Without this, an attacker who uploads a
     * file named image.jpg containing JavaScript could have the browser
     * execute it as a script.
     */
    private function setXContentTypeOptions(): void
    {
        header('X-Content-Type-Options: nosniff');
    }

    // ── 3. X-XSS-Protection ────────────────────────────────────────────

    /**
     * Enables the browser's built-in XSS filter in blocking mode.
     * Modern browsers have deprecated this in favour of CSP, but it
     * remains a useful defence-in-depth layer for legacy browsers
     * (IE 11, older Edge) that some enterprise visitors still use.
     */
    private function setXXssProtection(): void
    {
        header('X-XSS-Protection: 1; mode=block');
    }

    // ── 4. Referrer-Policy ─────────────────────────────────────────────

    /**
     * Controls how much referrer information is sent with navigations
     * and sub-resource requests. strict-origin-when-cross-origin sends
     * the full URL for same-origin requests (needed for analytics) but
     * only the origin for cross-origin requests, preventing URL-based
     * information leakage to third parties.
     */
    private function setReferrerPolicy(): void
    {
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }

    // ── 5. Permissions-Policy ──────────────────────────────────────────

    /**
     * Restricts access to powerful browser APIs that the site does not
     * use. Even if an XSS payload executes, it cannot activate the
     * camera, microphone, or geolocation without explicit policy
     * permission. The empty () value denies the feature to all origins,
     * including the page itself.
     */
    private function setPermissionsPolicy(): void
    {
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    }

    // ── 6. Strict-Transport-Security ───────────────────────────────────

    /**
     * Tells browsers to only connect to the site over HTTPS for one
     * year, including all subdomains. This prevents protocol-downgrade
     * and cookie-hijacking attacks. Only sent when the current request
     * is already on HTTPS — sending HSTS over plain HTTP is a spec
     * violation and browsers ignore it.
     */
    private function setStrictTransportSecurity(): void
    {
        if (!is_ssl()) {
            return;
        }

        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    // ── 7. Content-Security-Policy-Report-Only ─────────────────────────

    /**
     * A report-only CSP that logs violations without blocking resources.
     * This lets us monitor what a strict CSP would break before
     * enforcing it, which is critical on sites running page builders.
     *
     * Why unsafe-inline and unsafe-eval are required:
     * - Both Elementor and Divi inject inline <style> and <script> tags
     *   at render time for responsive styling and widget logic.
     * - Elementor's editor uses eval() for dynamic widget rendering and
     *   its controls framework. Divi's Visual Builder compiles Backbone
     *   templates via new Function() which requires unsafe-eval.
     * - Removing either would completely break both builders' front-end
     *   rendering and back-end editing experiences.
     *
     * connect-src whitelist:
     * - api.elementor.com / my.elementor.com: Elementor license checks,
     *   template library, and usage analytics.
     * - api.elegantthemes.com: Divi license verification and layout
     *   pack downloads.
     */
    private function setContentSecurityPolicyReportOnly(): void
    {
        $directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
            "font-src 'self' fonts.gstatic.com data:",
            "img-src 'self' data: https:",
            "connect-src 'self' api.elementor.com my.elementor.com api.elegantthemes.com",
            "frame-ancestors 'self'",
        ];

        header('Content-Security-Policy-Report-Only: ' . implode('; ', $directives));
    }

    // ── Remove server fingerprints ─────────────────────────────────────

    /**
     * Strips headers that reveal server software and PHP version.
     *
     * X-Powered-By is set by PHP itself and discloses the exact PHP
     * version. The Server header is set by Apache/Nginx and may include
     * version and module information. header_remove() works for
     * X-Powered-By on all hosts; Server removal depends on the web
     * server configuration (Apache's ServerTokens, Nginx's
     * server_tokens off) and may silently fail — this is safe to attempt
     * and succeeds on most managed hosting environments.
     */
    private function removeServerFingerprints(): void
    {
        header_remove('X-Powered-By');
        header_remove('Server');
    }
}
