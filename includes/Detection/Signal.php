<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

/**
 * Immutable value object carrying a single detection signal.
 *
 * Signals are the inputs to the risk scorer. Detectors return zero or
 * more Signal instances for a given file; the RiskScorer sums their
 * weights, counts their categories, and applies path-based modifiers
 * to produce a final Severity.
 *
 * Properties
 *   - category  : SignalCategory the signal belongs to (drives quorum).
 *   - weight    : Integer weight added to the raw score (higher = more
 *                 suspicious). Per-signal weights are documented in the
 *                 individual detector classes.
 *   - label     : Short human-readable description for the alert email
 *                 and log entry (e.g. "eval(base64_decode(...))").
 *   - context   : Optional free-form context data (line number, matched
 *                 snippet, pattern, etc.) threaded through to the alert.
 *
 * @since 1.4.0
 */
final class Signal
{
    /**
     * @param SignalCategory        $category Signal category driving quorum logic.
     * @param int                   $weight   Numeric weight for score summation.
     * @param string                $label    Short human-readable label.
     * @param array<string, mixed>  $context  Optional extra context.
     */
    public function __construct(
        public readonly SignalCategory $category,
        public readonly int $weight,
        public readonly string $label,
        public readonly array $context = [],
    ) {}
}
