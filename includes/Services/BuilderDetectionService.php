<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Detects active page builders (Elementor, Divi) and their operational state.
 *
 * Every security module queries this service before performing actions that
 * could conflict with page builder edit modes, AJAX handlers, REST endpoints,
 * or asset loading. All detection results are cached per-request via a static
 * array property to eliminate redundant checks within the same PHP process.
 *
 * @since 1.0.0
 */
final class BuilderDetectionService
{
    /**
     * Per-request detection cache keyed by method name.
     *
     * @var array<string, mixed>
     */
    private static array $cache = [];

    /**
     * Known legitimate external domains used by page builders.
     *
     * @var list<string>
     */
    private readonly array $builderDomains;

    /**
     * Known Elementor AJAX action identifiers.
     *
     * @var list<string>
     */
    private readonly array $elementorAjaxActions;

    /**
     * Known Divi AJAX action identifiers.
     *
     * @var list<string>
     */
    private readonly array $diviAjaxActions;

    /**
     * Known builder REST route prefixes.
     *
     * @var list<string>
     */
    private readonly array $builderRestPrefixes;

    public function __construct()
    {
        $this->builderDomains = [
            'elementor.com',
            'my.elementor.com',
            'api.elementor.com',
            'elegantthemes.com',
            'api.elegantthemes.com',
            'fonts.googleapis.com',
            'fonts.gstatic.com',
        ];

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
            'et_fb_ajax_save',
            'et_fb_get_saved_layouts',
            'et_pb_submit_subscribe_form',
        ];

        $this->builderRestPrefixes = [
            '/elementor/v1',
            '/et/v1',
        ];
    }

    /**
     * Whether the Elementor plugin is installed and active.
     *
     * Checks for the ELEMENTOR_VERSION constant that Elementor defines
     * when loaded by WordPress.
     */
    public function isElementorInstalled(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: static fn (): bool => defined('ELEMENTOR_VERSION'),
        );
    }

    /**
     * Whether the Divi theme or builder plugin is installed and active.
     *
     * Checks for the ET_BUILDER_VERSION constant that Divi defines
     * when loaded by WordPress.
     */
    public function isDiviInstalled(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: static fn (): bool => defined('ET_BUILDER_VERSION'),
        );
    }

    /**
     * Whether the current request is an Elementor editor session.
     *
     * Detects the ?elementor-preview query parameter in the request URI,
     * the presence of Elementor Pro, and verifies the current user has
     * editing capabilities.
     */
    public function isElementorEditMode(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: function (): bool {
                $requestUri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? ''));

                if (!str_contains($requestUri, 'elementor-preview')) {
                    return false;
                }

                if (!defined('ELEMENTOR_PRO_VERSION')) {
                    return false;
                }

                return current_user_can('edit_posts');
            },
        );
    }

    /**
     * Whether the Divi Visual Builder is currently active.
     *
     * Detects the ET_BUILDER_VERSION constant, the ?et_fb_preview query
     * parameter, and the et_fb_activation_nonce in the request.
     */
    public function isDiviBuilderActive(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: static function (): bool {
                if (!defined('ET_BUILDER_VERSION')) {
                    return false;
                }

                $etFbPreview = sanitize_text_field(wp_unslash($_GET['et_fb_preview'] ?? ''));
                if ($etFbPreview !== '') {
                    return true;
                }

                $etFbNonce = sanitize_text_field(wp_unslash($_REQUEST['et_fb_activation_nonce'] ?? ''));
                if ($etFbNonce !== '') {
                    return true;
                }

                return false;
            },
        );
    }

    /**
     * Whether the current request is a builder-initiated AJAX call.
     *
     * Matches the AJAX action parameter against known Elementor and Divi
     * action identifiers. Returns false if not an AJAX request.
     */
    public function isBuilderAjax(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: function (): bool {
                if (!wp_doing_ajax()) {
                    return false;
                }

                $action = sanitize_text_field(wp_unslash($_REQUEST['action'] ?? ''));

                if ($action === '') {
                    return false;
                }

                $allActions = [...$this->elementorAjaxActions, ...$this->diviAjaxActions];

                return in_array($action, $allActions, true);
            },
        );
    }

    /**
     * Whether the current request is a builder-initiated REST API call.
     *
     * Matches the request URI against known builder REST route prefixes.
     * Returns false if REST_REQUEST is not defined.
     */
    public function isBuilderRestRequest(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: function (): bool {
                if (!defined('REST_REQUEST') || !REST_REQUEST) {
                    return false;
                }

                $requestUri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? ''));

                foreach ($this->builderRestPrefixes as $prefix) {
                    if (str_contains($requestUri, $prefix)) {
                        return true;
                    }
                }

                return false;
            },
        );
    }

    /**
     * Whether a given URL belongs to a known builder asset domain.
     *
     * Parses the URL host and compares it against the list of known
     * legitimate builder external domains.
     *
     * @param string $url The URL to check.
     */
    public function isBuilderAssetUrl(string $url): bool
    {
        $parsed = wp_parse_url($url);
        $host = $parsed['host'] ?? '';

        if ($host === '') {
            return false;
        }

        $host = strtolower($host);

        foreach ($this->builderDomains as $domain) {
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns a list of currently active page builder identifiers.
     *
     * @return list<string> Zero or more of 'elementor', 'divi'.
     */
    public function getActiveBuilders(): array
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: function (): array {
                $builders = [];

                if ($this->isElementorInstalled()) {
                    $builders[] = 'elementor';
                }

                if ($this->isDiviInstalled()) {
                    $builders[] = 'divi';
                }

                return $builders;
            },
        );
    }

    /**
     * Whether a builder import operation is currently in progress.
     *
     * Checks the WordPress object cache for the hmdg_builder_import_active
     * flag, which is set by builder-specific modules during template or
     * layout import operations.
     */
    public function isBuilderImportActive(): bool
    {
        return $this->cached(
            key: __FUNCTION__,
            callback: static function (): bool {
                $found = false;
                $value = wp_cache_get('hmdg_builder_import_active', 'hmdg_security', false, $found);

                return $found && (bool) $value;
            },
        );
    }

    /**
     * Retrieve a cached detection result or compute and cache it.
     *
     * @template T
     *
     * @param string        $key      Cache key (typically __FUNCTION__).
     * @param callable(): T $callback Computation to run on cache miss.
     *
     * @return T Cached or freshly computed result.
     */
    private function cached(string $key, callable $callback): mixed
    {
        if (array_key_exists($key, self::$cache)) {
            return self::$cache[$key];
        }

        $result = $callback();
        self::$cache[$key] = $result;

        return $result;
    }
}
