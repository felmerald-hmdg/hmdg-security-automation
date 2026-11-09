<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

/**
 * Categories that group individual detection signals.
 *
 * The risk scorer uses category counts (not just raw score sums) to
 * decide whether a finding is multi-faceted enough to warrant a
 * HighRisk alert. Multi-category quorum is the whole point of the
 * v1.4.0 design: a file that trips one obfuscation rule is noise; a
 * file that trips obfuscation AND remote execution AND sits in a
 * path anomaly is real malware.
 *
 * Categories are mutually exclusive — a single Signal belongs to
 * exactly one category. Detectors that emit multiple signals for one
 * file may touch multiple categories (that is the intended design).
 *
 * @since 1.4.0
 */
enum SignalCategory: string
{
    /** Obfuscated code execution: eval(base64_decode), create_function, $$var(). */
    case Obfuscation  = 'obfuscation';

    /** Remote execution: passthru/shell_exec/system, external HTTP to unknown hosts. */
    case RemoteExec   = 'remote_exec';

    /** Persistence: PHP in uploads/, hidden iframes embedded in output. */
    case Persistence  = 'persistence';

    /** Code-context shapes: assert('string'), preg_replace('/.../e', ...). */
    case CodeContext  = 'code_context';

    /** Path anomalies: wp.org-checksum mismatch, bootstrap-file tamper. */
    case PathAnomaly  = 'path_anomaly';

    /** SHA-256 baseline drift: hash mismatch, file added, file removed. */
    case Baseline     = 'baseline';
}
