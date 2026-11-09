<?php

declare(strict_types=1);

namespace HMDG\Security\Detection\SignalDetectors;

use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalCategory;

/**
 * Produces Baseline signals that reflect SHA-256 checksum drift.
 *
 * Because FileIntegrity already owns the stored-baseline map, this
 * detector is call-site driven — FileIntegrity has already compared
 * the current file hash to the stored hash and tells us which of
 * the three outcomes applies.
 *
 * Weights (per the v1.4.0 design):
 *   hash mismatch vs stored baseline         -> 25
 *   new file with no baseline entry          -> 10
 *   file removed vs stored baseline          ->  5
 *
 * @since 1.4.0
 */
final class Baseline
{
    /** Category for every Signal this detector emits. */
    private const CATEGORY = SignalCategory::Baseline;

    /**
     * Signal for a hash mismatch between the current file and the
     * stored SHA-256 baseline.
     */
    public function forHashMismatch(string $relativePath, string $expectedHash, string $currentHash): Signal
    {
        return new Signal(
            category: self::CATEGORY,
            weight: 25,
            label: 'SHA-256 hash mismatch vs stored baseline',
            context: [
                'line'          => 1,
                'snippet'       => '',
                'pattern'       => 'baseline_hash_mismatch',
                'relative_path' => $relativePath,
                'expected_hash' => $expectedHash,
                'current_hash'  => $currentHash,
            ],
        );
    }

    /**
     * Signal for a file that exists on disk but has no baseline entry.
     * Lower weight because new files are common after legitimate
     * updates; a higher tier relies on combination with other signals.
     */
    public function forNewFile(string $relativePath): Signal
    {
        return new Signal(
            category: self::CATEGORY,
            weight: 10,
            label: 'File is new — no baseline entry',
            context: [
                'line'          => 1,
                'snippet'       => '',
                'pattern'       => 'baseline_new_file',
                'relative_path' => $relativePath,
            ],
        );
    }

    /**
     * Signal for a file that was in the baseline but is missing on disk.
     * Lowest weight — file deletion is frequent during legitimate
     * maintenance.
     */
    public function forRemovedFile(string $relativePath, string $expectedHash): Signal
    {
        return new Signal(
            category: self::CATEGORY,
            weight: 5,
            label: 'File removed — present in baseline, missing on disk',
            context: [
                'line'          => 1,
                'snippet'       => '',
                'pattern'       => 'baseline_file_removed',
                'relative_path' => $relativePath,
                'expected_hash' => $expectedHash,
            ],
        );
    }
}
