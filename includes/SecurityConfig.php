<?php

declare(strict_types=1);

namespace HMDG\Security;

/**
 * Immutable configuration for all security modules.
 *
 * Every threshold, list, and toggle lives here as a readonly property.
 * No database reads — values are baked in at instantiation. Tuning
 * happens in code via the CI/CD pipeline, not through wp-admin.
 */
final class SecurityConfig
{
    // ── Login Protection ────────────────────────────────────────────

    /** Maximum failed login attempts before lockout. */
    public readonly int $loginMaxAttempts;

    /** Lockout duration in seconds (default 1 hour). Ignored when `$loginLockoutIndefinite` is true. */
    public readonly int $loginLockoutDuration;

    /**
     * When true, triggered lockouts hold until an admin manually
     * unlocks the IP via wp-admin. Cache TTL is effectively forever
     * (YEAR_IN_SECONDS) and the DB row's `expires_at` is a sentinel
     * far-future date. Admin Unlock clears both.
     *
     * Tradeoff: legitimate users who forget their password and hit
     * the threshold stay locked out until an admin intervenes. On
     * the 281-site fleet this could produce support requests.
     * Flip to false per-site in `__construct()` if the default
     * does not suit a specific install.
     *
     * @since 1.10.0
     */
    public readonly bool $loginLockoutIndefinite;

    // ── Spam Protection ─────────────────────────────────────────────

    /** Minimum seconds between page load and form submission. */
    public readonly int $spamMinSubmitTime;

    /** Maximum URLs allowed in a single form submission. */
    public readonly int $spamMaxUrls;

    /** Maximum links allowed in a single comment. */
    public readonly int $commentMaxLinks;

    /** Duplicate comment cooldown in seconds. */
    public readonly int $commentDuplicateCooldown;

    /** Known spam phrases — lowercase, matched as substrings. */
    public readonly array $spamPhrases;

    /** Top 50 disposable email domains. */
    public readonly array $disposableEmailDomains;

    /** Spam user-agent patterns (regex fragments). */
    public readonly array $spamUserAgentPatterns;

    // ── File Integrity ──────────────────────────────────────────────

    /** Path to stored checksums file. */
    public readonly string $checksumFilePath;

    /** Directories excluded from integrity monitoring. */
    public readonly array $integrityExcludedPaths;

    // ── Malware Scanner ─────────────────────────────────────────────

    /** Files to scan per cron batch. */
    public readonly int $malwareBatchSize;

    /** Minimum base64 string length to flag as suspicious. */
    public readonly int $malwareBase64MinLength;

    /** Legitimate domains that plugins/themes may contact. */
    public readonly array $legitimateDomains;

    /** Malware signature patterns (PCRE). */
    public readonly array $malwareSignatures;

    // ── Database Cleanup ────────────────────────────────────────────

    /** Days before trashed/spam comments are purged. */
    public readonly int $cleanupCommentAge;

    /** Days before auto-drafts are purged. */
    public readonly int $cleanupAutoDraftAge;

    /** Max revisions kept for standard posts. */
    public readonly int $revisionsStandard;

    /** Max revisions kept for Elementor/Divi posts. */
    public readonly int $revisionsBuilder;

    /** Row limit per cleanup query to prevent timeouts. */
    public readonly int $cleanupBatchLimit;

    // ── Hardening ───────────────────────────────────────────────────

    /** Whether to disable RSS/Atom feeds entirely. */
    public readonly bool $disableFeeds;

    /**
     * Whether to disallow file modifications (DISALLOW_FILE_MODS).
     * Set false when clients need to install Divi layouts or Elementor templates.
     */
    public readonly bool $disableFileMods;

    // ── Alerts ──────────────────────────────────────────────────────

    /** Alert recipient email address. */
    public readonly string $alertEmail;

    /** Minimum seconds between duplicate alerts (same event + source). */
    public readonly int $alertRateLimitSeconds;

    // ── Reserved Usernames ──────────────────────────────────────────

    /** Usernames that must not be registered. */
    public readonly array $reservedUsernames;

    // ── v1.4.0 Detection Engine ─────────────────────────────────────

    /**
     * Severity-tier score thresholds used by RiskScorer.
     *
     * Keys: 'high_risk', 'suspicious', 'needs_review', 'informational'.
     * All numbers are post-modifier score cut-offs. Exposed here as a
     * readonly array so the values are discoverable in code without
     * needing to open RiskScorer.
     *
     * The scorer still holds its own constants for the actual
     * comparison (faster + clearer in the matching match() block); this
     * array mirrors them for documentation and future configurability.
     *
     * @var array<string, int>
     */
    public readonly array $severityThresholds;

    /**
     * Per-signal weights baked into each detector.
     *
     * Mirrors the weights used by the SignalDetectors/* classes. Kept
     * in config for discoverability; the detectors themselves still
     * hard-code the values (hot-path literals) per the no-filter-hook
     * rule in .claude/decisions.md.
     *
     * @var array<string, int>
     */
    public readonly array $signalWeights;

    /**
     * Trusted-update grace window in days. Matches UpdateMonitor's TTL.
     */
    public readonly int $trustedUpdateWindowDays;

    // ── Builder Domains ─────────────────────────────────────────────

    /** Known legitimate builder AJAX actions — Elementor. */
    public readonly array $elementorAjaxActions;

    /** Known legitimate builder AJAX actions — Divi. */
    public readonly array $diviAjaxActions;

    /** Known legitimate builder REST route prefixes. */
    public readonly array $builderRestPrefixes;

    /** Known legitimate external domains used by page builders. */
    public readonly array $builderExternalDomains;

    public function __construct()
    {
        // ── Login Protection ────────────────────────────────────────
        $this->loginMaxAttempts = 5;
        $this->loginLockoutDuration = 3600;
        $this->loginLockoutIndefinite = true;

        // ── Spam Protection ─────────────────────────────────────────
        $this->spamMinSubmitTime = 3;
        $this->spamMaxUrls = 3;
        $this->commentMaxLinks = 2;
        $this->commentDuplicateCooldown = 60;

        $this->spamPhrases = [
            'buy now', 'cheap viagra', 'cialis online', 'casino bonus',
            'online gambling', 'poker online', 'slot machine', 'payday loan',
            'seo backlinks', 'buy backlinks', 'link building service',
            'guest post service', 'cheap seo', 'rank first page',
            'cryptocurrency investment', 'binary options', 'forex trading signals',
            'weight loss pills', 'diet supplement', 'enlargement pills',
            'nigerian prince', 'wire transfer', 'western union',
            'click here to win', 'congratulations you won',
            'earn money fast', 'work from home opportunity',
            'free iphone', 'free gift card', 'claim your prize',
        ];

        $this->disposableEmailDomains = [
            'mailinator.com', 'guerrillamail.com', 'tempmail.com',
            'throwaway.email', 'yopmail.com', 'sharklasers.com',
            'guerrillamailblock.com', 'grr.la', 'dispostable.com',
            'mailnesia.com', 'maildrop.cc', 'discard.email',
            'temp-mail.org', 'fakeinbox.com', 'tempail.com',
            'trashmail.com', 'trashmail.net', 'trashmail.org',
            'harakirimail.com', 'mailcatch.com', 'tempr.email',
            'getairmail.com', 'getnada.com', 'emailondeck.com',
            'mintemail.com', 'mohmal.com', 'burnermail.io',
            'inboxkitten.com', 'tempinbox.com', 'mailtemp.info',
            'tempmailaddress.com', 'crazymailing.com', 'trash-mail.com',
            'guerrillamail.info', 'guerrillamail.net', 'guerrillamail.org',
            'guerrillamail.de', 'mailexpire.com', 'safetymail.info',
            'filzmail.com', 'mytrashmail.com', 'mailzilla.com',
            'spamgourmet.com', 'spamfree24.org', 'binkmail.com',
            'spamavert.com', 'incognitomail.org', 'anonymbox.com',
            'throwam.com', 'mailnull.com', 'nomail.xl.cx',
            'spamcero.com',
        ];

        $this->spamUserAgentPatterns = [
            'Wget', 'curl/', 'libwww-perl', 'Python-urllib',
            'PHPCrawl', 'MJ12bot', 'AhrefsBot', 'SemrushBot',
            'DotBot', 'masscan',
        ];

        // ── File Integrity ──────────────────────────────────────────
        $this->checksumFilePath = WP_CONTENT_DIR . '/hmdg-security-pro/checksums.json';

        $this->integrityExcludedPaths = [
            WP_CONTENT_DIR . '/uploads/elementor/css',
            WP_CONTENT_DIR . '/uploads/et-cache',
            WP_CONTENT_DIR . '/cache',
            WP_CONTENT_DIR . '/wflogs',
        ];

        // ── Malware Scanner ─────────────────────────────────────────
        $this->malwareBatchSize = 50;
        $this->malwareBase64MinLength = 500;

        $this->legitimateDomains = [
            'elementor.com', 'my.elementor.com', 'api.elementor.com',
            'elegantthemes.com', 'api.elegantthemes.com',
            'fonts.googleapis.com', 'fonts.gstatic.com',
            'wordpress.org', 'api.wordpress.org',
            'gravatar.com', 'secure.gravatar.com',
        ];

        $this->malwareSignatures = [
            // Obfuscated code execution
            '/\beval\s*\(\s*base64_decode\s*\(/i',
            '/\beval\s*\(\s*gzinflate\s*\(/i',
            '/\beval\s*\(\s*str_rot13\s*\(/i',
            // Deprecated preg_replace /e modifier — code execution
            '/\bpreg_replace\s*\(\s*["\'].*\/e["\']/',
            // Variable function calls ($$var())
            '/\$\$\w+\s*\(/',
            // Direct shell access in suspicious context
            '/\b(?:passthru|shell_exec|system)\s*\(\s*\$/i',
            // Deprecated create_function — used in old backdoors
            '/\bcreate_function\s*\(/i',
            // assert() with STRING LITERAL argument — code execution vector.
            // Historically this pattern included '$' in the char class to catch
            // assert($attacker_controlled_var). v1.3.3 removed '$' because it
            // false-flagged every PHPUnit test fixture + type-assertion in
            // bundled vendor libraries (WPForms apimatic TestCase, WP Rocket
            // simple_html_dom, etc.) on the 281-site fleet. Real code-execution
            // attacks use assert('...string payload...') — string-literal form.
            // PHP 7.2+ deprecated eval-via-assert, making the $var form even rarer
            // in real malware. Only match the '..' or ".." forms now.
            '/\bassert\s*\(\s*["\']/i',
            // Hidden iframes injected via PHP echo/print
            '/["\'].*<iframe[^>]+style\s*=\s*["\'][^"\']*display\s*:\s*none/i',
        ];

        // ── Database Cleanup ────────────────────────────────────────
        $this->cleanupCommentAge = 30;
        $this->cleanupAutoDraftAge = 7;
        $this->revisionsStandard = 5;
        $this->revisionsBuilder = 10;
        $this->cleanupBatchLimit = 500;

        // ── Hardening ───────────────────────────────────────────────
        $this->disableFeeds = true;
        $this->disableFileMods = false;

        // ── Alerts ──────────────────────────────────────────────────
        $this->alertEmail = 'felmerald@hmdg.co.uk';
        $this->alertRateLimitSeconds = 3600;

        // ── Reserved Usernames ──────────────────────────────────────
        $this->reservedUsernames = [
            'admin', 'administrator', 'root', 'webmaster',
            'wp-admin', 'hmdg', 'elementor', 'divi',
        ];

        // ── v1.4.0 Detection Engine ─────────────────────────────────
        $this->severityThresholds = [
            'high_risk'     => 70,
            'suspicious'    => 40,
            'needs_review'  => 20,
            'informational' => 10,
        ];

        $this->signalWeights = [
            'obfuscation_eval_wrapper'    => 40,
            'obfuscation_preg_replace_e'  => 30,
            'obfuscation_long_base64'     => 25,
            'obfuscation_double_dollar'   => 20,
            'obfuscation_create_function' => 20,
            'code_context_assert_string'  => 15,
            'remote_exec_shell_var'       => 25,
            'remote_exec_external_url'    => 20,
            'persistence_uploads_php'     => 30,
            'persistence_hidden_iframe'   => 15,
            'path_anomaly_core_mismatch'  => 35,
            'path_anomaly_bootstrap_mod'  => 20,
            'baseline_hash_mismatch'      => 25,
            'baseline_new_file'           => 10,
            'baseline_file_removed'       => 5,
        ];

        $this->trustedUpdateWindowDays = 7;

        // ── Builder AJAX Actions ────────────────────────────────────
        $this->elementorAjaxActions = [
            'elementor_ajax',
            'elementor_pro_forms_send_form',
            'elementor_connect',
        ];

        $this->diviAjaxActions = [
            'et_pb_process_computed_property',
            'et_pb_get_backbone_templates',
            'et_core_portability_export',
            'et_core_portability_import',
            // Visual Builder save + template + subscribe — adding these
            // closes a real bug: SpamProtection would otherwise potentially
            // block legitimate Divi save operations and subscription forms.
            'et_fb_ajax_save',
            'et_fb_get_saved_layouts',
            'et_pb_submit_subscribe_form',
        ];

        $this->builderRestPrefixes = [
            '/elementor/v1',
            '/et/v1',
        ];

        $this->builderExternalDomains = [
            'elementor.com',
            'my.elementor.com',
            'api.elementor.com',
            'elegantthemes.com',
            'api.elegantthemes.com',
            'fonts.googleapis.com',
            'fonts.gstatic.com',
        ];
    }
}
