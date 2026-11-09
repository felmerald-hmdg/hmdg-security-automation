<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Reads the promoted public release without adding visitor-request work.
 *
 * @package HMDG\Security
 * @since 1.11.0
 */
final class ReleaseMetadata
{
    private const CACHE_KEY = 'signed_release_latest_v1';
    private const FAILURE = 'release_lookup_failed';
    private const MAX_METADATA_BYTES = 262144;

    /** @param ObjectCacheService $cacheService Plugin-scoped persistent cache. */
    public function __construct(
        private readonly ObjectCacheService $cacheService,
        private readonly ?LogService $logService = null,
    ) {
    }

    /** @return bool Whether the request may perform update operations. */
    public static function allowedContext(): bool
    {
        return is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI);
    }

    /** @return array<string, string>|null Validated promoted release. */
    public function latest(): ?array
    {
        if (!self::allowedContext()) {
            return null;
        }
        $cached = $this->cacheService->get(self::CACHE_KEY);
        if ($cached === self::FAILURE) {
            return null;
        }
        if (is_array($cached)) {
            return $cached;
        }
        $response = wp_safe_remote_get(
            'https://api.github.com/repos/' . ReleaseUpdater::PUBLIC_REPOSITORY . '/releases/latest',
            ['timeout' => 15, 'redirection' => 0, 'limit_response_size' => self::MAX_METADATA_BYTES,
                'headers' => ['Accept' => 'application/vnd.github+json',
                    'X-GitHub-Api-Version' => '2022-11-28'], 'user-agent' => 'HMDG-Security-Pro-Updater'],
        );
        $release = !is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200
            ? self::validate(json_decode(wp_remote_retrieve_body($response), true)) : null;
        $this->cacheService->set(self::CACHE_KEY, $release ?? self::FAILURE,
            $release === null ? 3600 + random_int(0, 300) : 43200 + random_int(0, 1800));
        if ($release === null) {
            $this->logService?->warning('ReleaseUpdater', 'Promoted release lookup failed; keeping the installed version.');
        }
        return $release;
    }

    /** @return void Remove metadata after this plugin has been upgraded. */
    public function clear(): void
    {
        if (self::allowedContext()) {
            $this->cacheService->delete(self::CACHE_KEY);
        }
    }

    /**
     * @param mixed $data Untrusted GitHub metadata.
     * @return array<string, string>|null Canonical fields, never an arbitrary asset URL.
     */
    public static function validate(mixed $data): ?array
    {
        if (!is_array($data) || ($data['draft'] ?? null) !== false
            || ($data['prerelease'] ?? null) !== false || !is_string($data['tag_name'] ?? null)
            || preg_match('/^v([0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8})$/D', $data['tag_name'], $match) !== 1
            || !is_array($data['assets'] ?? null) || count($data['assets']) > 30) {
            return null;
        }
        $package = self::packageUrl($match[1]);
        $expected = ['hmdg-security-pro.zip' => $package, 'hmdg-security-pro.zip.sig' => $package . '.sig'];
        $found = [];
        foreach ($data['assets'] as $asset) {
            $name = is_array($asset) ? ($asset['name'] ?? null) : null;
            if (!is_string($name) || !isset($expected[$name])) {
                continue;
            }
            if (isset($found[$name]) || ($asset['browser_download_url'] ?? null) !== $expected[$name]
                || !is_int($asset['size'] ?? null) || $asset['size'] < 1
                || $asset['size'] > ($name === 'hmdg-security-pro.zip' ? SignedReleasePackage::MAX_BYTES : 1024)) {
                return null;
            }
            $found[$name] = true;
        }
        if (count($found) !== 2) {
            return null;
        }
        return ['version' => $match[1], 'package' => $package,
            'notes' => is_string($data['body'] ?? null) ? substr($data['body'], 0, 65536) : '',
            'published' => is_string($data['published_at'] ?? null) ? $data['published_at'] : ''];
    }

    /** @param string $version Validated stable version. @return string Exact release asset URL. */
    public static function packageUrl(string $version): string
    {
        return 'https://github.com/' . ReleaseUpdater::PUBLIC_REPOSITORY
            . '/releases/download/v' . $version . '/hmdg-security-pro.zip';
    }

    /** @param string $url Untrusted download URL. @return string|null Exact release version or refusal. */
    public static function packageVersion(string $url): ?string
    {
        $prefix = preg_quote('https://github.com/' . ReleaseUpdater::PUBLIC_REPOSITORY . '/releases/download/v', '#');
        return preg_match('#^' . $prefix . '([0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8})/hmdg-security-pro\.zip$#D', $url, $match) === 1
            ? $match[1] : null;
    }
}
