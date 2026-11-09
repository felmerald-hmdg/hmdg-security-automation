<?php

declare(strict_types=1);

namespace HMDG\Security\Detection\SignalDetectors;

use HMDG\Security\Detection\CoreChecksumClient;
use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalCategory;

/**
 * Detects path-anomaly signals that indicate tampering in locations
 * where the baseline is external (e.g. wp.org checksums) or
 * structurally important (root bootstrap files).
 *
 *   - Core-file MD5 does NOT match the wp.org core checksum — weight 35.
 *   - Modification of a root bootstrap file (wp-load.php etc.) — weight 20.
 *
 * @since 1.4.0
 */
final class PathAnomaly
{
    /** Category for every Signal this detector emits. */
    private const CATEGORY = SignalCategory::PathAnomaly;

    /** Bootstrap files — modification here is always unusual. */
    private const BOOTSTRAP_FILES = [
        'wp-load.php',
        'wp-settings.php',
        'wp-config.php',
        'wp-blog-header.php',
        'wp-cron.php',
        'index.php',
    ];

    /**
     * @param CoreChecksumClient $coreChecksumClient wp.org baseline client.
     */
    public function __construct(
        private readonly CoreChecksumClient $coreChecksumClient,
    ) {}

    /**
     * Produce every PathAnomaly Signal for the given file.
     *
     * @param string $absolutePath     Absolute filesystem path.
     * @param bool   $baselineMismatch Whether the SHA-256 baseline
     *                                 hash check already failed for
     *                                 this file. When false (hash
     *                                 matches baseline) the bootstrap
     *                                 signal is suppressed — an
     *                                 unmodified bootstrap file is
     *                                 not anomalous.
     *
     * @return list<Signal>
     */
    public function detect(string $absolutePath, bool $baselineMismatch): array
    {
        $signals = [];

        // Core-checksum mismatch — ask wp.org whether this is a stock
        // core file. We only emit the signal if the API returns a
        // definitive NO: i.e. the path is in ABSPATH, is not in
        // wp-content, and the fetched checksum disagrees with the
        // on-disk MD5. The `matchesCoreBaseline()` client already
        // short-circuits on any of the API-error cases.
        $md5 = hash_file('md5', $absolutePath);

        if (is_string($md5) && $md5 !== '') {
            if ($this->isCoreCandidate(absolutePath: $absolutePath)) {
                $status = $this->coreChecksumClient->coreBaselineStatus(
                    absolutePath: $absolutePath,
                    currentHash: $md5,
                );

                if ($status === CoreChecksumClient::STATUS_MISMATCH) {
                    $signals[] = new Signal(
                        category: self::CATEGORY,
                        weight: 35,
                        label: 'Core file hash does not match wp.org baseline',
                        context: [
                            'line'    => 1,
                            'snippet' => '',
                            'pattern' => 'wp_org_checksum_mismatch',
                        ],
                    );
                }
            }
        }

        // Bootstrap-file modification — only when the SHA-256 baseline
        // has already disagreed with the file's current hash.
        if ($baselineMismatch && $this->isBootstrapFile(absolutePath: $absolutePath)) {
            $signals[] = new Signal(
                category: self::CATEGORY,
                weight: 20,
                label: 'Root bootstrap file modified',
                context: [
                    'line'    => 1,
                    'snippet' => '',
                    'pattern' => 'bootstrap_modified',
                ],
            );
        }

        return $signals;
    }

    /**
     * Whether $absolutePath is a WordPress core-distribution file
     * candidate — i.e. inside ABSPATH and outside wp-content.
     */
    private function isCoreCandidate(string $absolutePath): bool
    {
        if (!defined('ABSPATH')) {
            return false;
        }

        $normalised = str_replace('\\', '/', $absolutePath);
        $abspath    = rtrim(str_replace('\\', '/', \ABSPATH), '/') . '/';

        if (!str_starts_with($normalised, $abspath)) {
            return false;
        }

        $relative = substr($normalised, strlen($abspath));

        return !str_starts_with($relative, 'wp-content/');
    }

    /**
     * Whether $absolutePath is one of the root bootstrap files.
     */
    private function isBootstrapFile(string $absolutePath): bool
    {
        if (!defined('ABSPATH')) {
            return false;
        }

        $normalised = str_replace('\\', '/', $absolutePath);
        $abspath = rtrim(str_replace('\\', '/', \ABSPATH), '/') . '/';
        $basename = basename($normalised);

        if (!in_array($basename, self::BOOTSTRAP_FILES, true)) {
            return false;
        }

        if ($basename === 'wp-config.php') {
            $configInRoot = $abspath . 'wp-config.php';
            $configOneUp = rtrim(str_replace('\\', '/', dirname(rtrim(\ABSPATH, '/\\'))), '/') . '/wp-config.php';

            return $normalised === $configInRoot || $normalised === $configOneUp;
        }

        return $normalised === $abspath . $basename;
    }
}
