<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

/**
 * Core risk-scoring engine for v1.4.0 detection.
 *
 * Takes an absolute path, the list of Signals a detector pipeline
 * produced for that path, and the file's current hash, and returns
 * a Severity tier. Replaces the v1.3.x single-signal-equals-alert
 * model that drove the false-positive flood.
 *
 * Decision flow (v1.4.0 post-review hardening):
 *   1. If CoreChecksumClient::matchesCoreBaseline() is true, return
 *      Severity::Safe. (wp.org vouches for this file.)
 *   2. If there are no signals, return Severity::Safe.
 *   3. Classify signal payload:
 *        - hasMaliciousStrongSignal(): any Obfuscation/RemoteExec >= 20
 *          weight, OR direct_eval_input, OR uploads_php_with_exec.
 *        - hasOnlyBaselineSignals(): no non-Baseline signals present.
 *   4. If inside trusted update window AND no malicious-strong signals
 *      AND only baseline signals, return Severity::ExpectedUpdate.
 *      (The trusted window ONLY suppresses baseline drift; it can
 *       never suppress content-execution signals.)
 *   5. If inside trusted update window AND malicious-strong signals are
 *      present, append a synthetic PathAnomaly "update_window_override"
 *      signal so the alert body surfaces the override.
 *   6. Run override bands (checkOverrideBands()) — unambiguous single-
 *      pattern malware shapes bypass the 2-category requirement:
 *        - RemoteExec + pattern_id=direct_eval_input → HighRisk
 *        - Persistence + pattern_id=uploads_php_with_exec → HighRisk
 *        - Obfuscation + pattern_id=eval_wrapper + weight>=60 +
 *          non-LowRisk path → HighRisk
 *   7. Sum signal weights; apply PathClassifier modifier; count
 *      distinct categories.
 *   8. If score >= 70 AND categoryCount >= 2:
 *        - LowRisk path: require quorum (>= 3 signals AND >= 2
 *          categories AND at least one from {Persistence, PathAnomaly}).
 *          Pass → HighRisk, fail → Suspicious.
 *        - Else: HighRisk.
 *   9. Otherwise: score >= 40 → Suspicious, >= 20 → NeedsReview,
 *      >= 10 → Informational, else Safe.
 *
 * @since 1.4.0
 */
final class RiskScorer
{
    /** Minimum score for HighRisk consideration. */
    private const HIGH_RISK_THRESHOLD = 70;

    /** Minimum score for Suspicious. */
    private const SUSPICIOUS_THRESHOLD = 40;

    /** Minimum score for NeedsReview. */
    private const NEEDS_REVIEW_THRESHOLD = 20;

    /** Minimum score for Informational. */
    private const INFORMATIONAL_THRESHOLD = 10;

    /** Minimum category count for HighRisk. */
    private const HIGH_RISK_MIN_CATEGORIES = 2;

    /** Minimum signal count for LowRisk-path HighRisk quorum. */
    private const LOW_RISK_QUORUM_MIN_SIGNALS = 3;

    /** Minimum category count for LowRisk-path HighRisk quorum. */
    private const LOW_RISK_QUORUM_MIN_CATEGORIES = 2;

    /**
     * @param PathClassifier     $pathClassifier    Path-class decider.
     * @param UpdateCorrelator   $updateCorrelator  Trusted-update short-circuit.
     * @param CoreChecksumClient $coreChecksumClient wp.org baseline check.
     */
    public function __construct(
        private readonly PathClassifier $pathClassifier,
        private readonly UpdateCorrelator $updateCorrelator,
        private readonly CoreChecksumClient $coreChecksumClient,
    ) {}

    /**
     * Classify a set of signals for a file into a Severity tier.
     *
     * @param string       $absolutePath Absolute path to the scanned file.
     * @param list<Signal> $signals      Signals produced for this file.
     * @param string       $currentHash  File hash used for the wp.org
     *                                   core-baseline comparison. The
     *                                   CoreChecksumClient expects MD5
     *                                   (what wp.org publishes); if the
     *                                   caller supplied a SHA-256 the
     *                                   core check will fail-closed
     *                                   (returning false) and the rest
     *                                   of the pipeline continues.
     */
    public function classify(string $absolutePath, array $signals, string $currentHash): Severity
    {
        // Rule 2: wp.org core baseline confirms the file is legitimate.
        if ($this->coreChecksumClient->matchesCoreBaseline(
            absolutePath: $absolutePath,
            currentHash: $currentHash,
        )) {
            return Severity::Safe;
        }

        // Rule 3: no signals means nothing to alert on.
        if ($signals === []) {
            return Severity::Safe;
        }

        // NEW — classify signal payload before consulting the trust window.
        $hasMaliciousStrong    = $this->hasMaliciousStrongSignal(signals: $signals);
        $hasOnlyBaselineSignal = $this->hasOnlyBaselineSignals(signals: $signals);

        $isTrusted = $this->updateCorrelator->isWithinTrustedWindow(
            absolutePath: $absolutePath,
        );

        // Rule 1 (REVISED): trusted-update window short-circuits ONLY when
        // the signal set is baseline-only. A trusted-update window MUST
        // NEVER suppress malicious-strong signals.
        if ($isTrusted && !$hasMaliciousStrong && $hasOnlyBaselineSignal) {
            return Severity::ExpectedUpdate;
        }

        // If trust was bypassed because of a malicious-strong signal,
        // annotate that fact on the signal set so the eventual email
        // body surfaces it to the operator.
        if ($isTrusted && $hasMaliciousStrong) {
            $signals[] = new Signal(
                category: SignalCategory::PathAnomaly,
                weight: 10,
                label: 'Trusted-update window override — malicious-strong signal found inside update grace window',
                context: ['reason' => 'update_window_override'],
            );
        }

        // NEW — override bands escape the 2-category requirement for
        // unambiguous single-pattern malware shapes.
        $override = $this->checkOverrideBands(
            absolutePath: $absolutePath,
            signals: $signals,
        );
        if ($override !== null) {
            return $override;
        }

        // Rule 4: raw score sum.
        $rawScore = 0;
        $categoryMap = [];

        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                // Defensive — malformed input gets ignored rather than
                // silently inflating the score.
                continue;
            }
            $rawScore += $signal->weight;
            $categoryMap[$signal->category->value] = true;
        }

        $pathClass   = $this->pathClassifier->classify(absolutePath: $absolutePath);
        $modifier    = $pathClass->downgradeModifier();
        $score       = (int) floor($rawScore * $modifier);
        $categoryCount = count($categoryMap);

        // Rule 7: HighRisk tier (with LowRisk quorum).
        if ($score >= self::HIGH_RISK_THRESHOLD
            && $categoryCount >= self::HIGH_RISK_MIN_CATEGORIES
        ) {
            if ($pathClass === PathClass::LowRisk) {
                if ($this->passesLowRiskQuorum(signals: $signals, categoryMap: $categoryMap)) {
                    return Severity::HighRisk;
                }
                return Severity::Suspicious;
            }
            return Severity::HighRisk;
        }

        // Rules 8-11: descending tiers.
        return match (true) {
            $score >= self::SUSPICIOUS_THRESHOLD    => Severity::Suspicious,
            $score >= self::NEEDS_REVIEW_THRESHOLD  => Severity::NeedsReview,
            $score >= self::INFORMATIONAL_THRESHOLD => Severity::Informational,
            default                                 => Severity::Safe,
        };
    }

    /**
     * Override bands — unambiguous single-pattern malware shapes that
     * bypass the 2-category HighRisk requirement.
     *
     * @param list<Signal> $signals
     */
    private function checkOverrideBands(string $absolutePath, array $signals): ?Severity
    {
        $pathClass = $this->pathClassifier->classify(absolutePath: $absolutePath);

        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            $patternId = $signal->context['pattern_id'] ?? null;

            if ($signal->category === SignalCategory::RemoteExec
                && $patternId === 'direct_eval_input'
            ) {
                return Severity::HighRisk;
            }

            if ($signal->category === SignalCategory::Persistence
                && $patternId === 'uploads_php_with_exec'
            ) {
                return Severity::HighRisk;
            }

            if ($signal->category === SignalCategory::Obfuscation
                && $patternId === 'eval_wrapper'
                && $signal->weight >= 60
                && $pathClass !== PathClass::LowRisk
            ) {
                return Severity::HighRisk;
            }
        }

        return null;
    }

    /**
     * A signal is "malicious-strong" if it indicates code-execution
     * capability that no legitimate plugin update should introduce.
     * These must override the trusted-update window.
     *
     * @param list<Signal> $signals
     */
    private function hasMaliciousStrongSignal(array $signals): bool
    {
        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            $patternId = $signal->context['pattern_id'] ?? null;

            if (in_array($signal->category, [
                SignalCategory::Obfuscation,
                SignalCategory::RemoteExec,
            ], true) && $signal->weight >= 20) {
                return true;
            }

            if ($signal->category === SignalCategory::RemoteExec
                && $patternId === 'direct_eval_input'
            ) {
                return true;
            }

            if ($signal->category === SignalCategory::Persistence
                && $patternId === 'uploads_php_with_exec'
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the signal set contains only Baseline-category signals —
     * i.e. hash drift without content-execution indicators.
     *
     * @param list<Signal> $signals
     */
    private function hasOnlyBaselineSignals(array $signals): bool
    {
        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            if ($signal->category !== SignalCategory::Baseline) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether the LowRisk HighRisk-escalation quorum passes.
     *
     * Quorum requires:
     *   - >= 3 signals,
     *   - >= 2 distinct categories,
     *   - at least one signal in {Persistence, PathAnomaly}.
     *
     * LowRisk paths routinely trigger obfuscation or code-context
     * patterns from legitimate vendored libraries; the quorum demands
     * a persistence or path-anomaly signal on top of that before
     * treating the finding as HighRisk rather than Suspicious.
     *
     * @param list<Signal>         $signals     Signals under consideration.
     * @param array<string, true>  $categoryMap Pre-computed category map.
     */
    private function passesLowRiskQuorum(array $signals, array $categoryMap): bool
    {
        if (count($signals) < self::LOW_RISK_QUORUM_MIN_SIGNALS) {
            return false;
        }

        if (count($categoryMap) < self::LOW_RISK_QUORUM_MIN_CATEGORIES) {
            return false;
        }

        $hasPersistenceOrPathAnomaly = isset($categoryMap[SignalCategory::Persistence->value])
            || isset($categoryMap[SignalCategory::PathAnomaly->value]);

        return $hasPersistenceOrPathAnomaly;
    }
}
