<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

use HMDG\Security\Modules\UpdateMonitor;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Read-only adapter over UpdateMonitor's object-cache markers.
 *
 * UpdateMonitor plants `hmdg_recent_update_<sha256(relativePath)>` keys
 * in the object cache after every `upgrader_process_complete` firing.
 * This class walks a file's ancestor directories (from deepest to
 * ABSPATH) and checks each for a fresh marker. First hit wins — the
 * caller (RiskScorer) uses the result to short-circuit to
 * Severity::ExpectedUpdate.
 *
 * Zero writes. Zero DB. Zero HTTP. Pure cache reads.
 *
 * The key format is identical to the one UpdateMonitor already writes:
 *
 *   UpdateMonitor::RECENT_UPDATE_PREFIX . hash('sha256', $relativePath)
 *
 * so any future change to the marker shape must update both classes.
 *
 * @since 1.4.0
 */
final class UpdateCorrelator
{
    /**
     * @param ObjectCacheService $cacheService Object-cache wrapper.
     */
    public function __construct(
        private readonly ObjectCacheService $cacheService,
    ) {}

    /**
     * Whether the given absolute path lives inside a plugin, theme,
     * or core area that UpdateMonitor recently marked as updated.
     *
     * Walks from the deepest ancestor (the directory containing the
     * file) up to the ABSPATH root, computing the SHA-256 of the
     * relative path at each step and probing the object cache. On
     * first hit returns true.
     *
     * A hit means "this path is within UpdateMonitor's 7-day grace
     * window" — the caller should short-circuit.
     *
     * @param string $absolutePath Absolute filesystem path.
     */
    public function isWithinTrustedWindow(string $absolutePath): bool
    {
        if ($absolutePath === '') {
            return false;
        }

        $relative = $this->toRelative(absolutePath: $absolutePath);

        if ($relative === '') {
            return false;
        }

        foreach ($this->buildAncestorCandidates(relativePath: $relative) as $candidate) {
            $key = UpdateMonitor::RECENT_UPDATE_PREFIX . hash('sha256', $candidate);

            if ($this->cacheService->exists(key: $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build the ordered list of ancestor markers to probe.
     *
     * For `wp-content/plugins/acme/sub/file.php` we check, in order:
     *   - wp-content/plugins/acme/sub/file.php
     *   - wp-content/plugins/acme/sub/
     *   - wp-content/plugins/acme/
     *   - wp-content/plugins/
     *   - wp-content/
     *   - wp-core-root  (core-update sentinel used by UpdateMonitor)
     *
     * The `wp-admin/` and `wp-includes/` prefixes are covered by the
     * generic ancestor walk — UpdateMonitor plants markers at those
     * exact relative paths, and they fall out naturally from the walk.
     *
     * @param string $relativePath ABSPATH-relative forward-slash path.
     *
     * @return list<string>
     */
    private function buildAncestorCandidates(string $relativePath): array
    {
        $normalised = ltrim(str_replace('\\', '/', $relativePath), '/');
        $candidates = [$normalised];

        // Walk parent directories. For each directory we probe both the
        // trailing-slash form (plugin/theme/core paths are marked with a
        // trailing slash by UpdateMonitor) and the bare form (handles
        // any future mark formats without a trailing slash).
        $current = $normalised;
        while (true) {
            $slashPos = strrpos($current, '/');
            if ($slashPos === false) {
                break;
            }
            $parent = substr($current, 0, $slashPos);
            if ($parent === '') {
                break;
            }
            // Directory form with trailing slash — this is the key shape
            // UpdateMonitor writes for plugin/theme/core paths.
            $candidates[] = $parent . '/';
            $current = $parent;
        }

        // Root-level fallback used by UpdateMonitor::handleCoreUpdate()
        // for files directly under ABSPATH (wp-login.php etc.).
        $candidates[] = 'wp-core-root';

        return $candidates;
    }

    /**
     * Convert an absolute path to an ABSPATH-relative forward-slash
     * path. If the path falls outside ABSPATH, returns the
     * forward-slash-normalised absolute path unchanged.
     *
     * @param string $absolutePath Absolute filesystem path.
     */
    private function toRelative(string $absolutePath): string
    {
        $normalised = str_replace('\\', '/', $absolutePath);

        if (!defined('ABSPATH')) {
            return $normalised;
        }

        $abspath = rtrim(str_replace('\\', '/', \ABSPATH), '/') . '/';

        if (str_starts_with($normalised, $abspath)) {
            return ltrim(substr($normalised, strlen($abspath)), '/');
        }

        return $normalised;
    }
}
