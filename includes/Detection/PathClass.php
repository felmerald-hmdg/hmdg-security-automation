<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

/**
 * Classification of a file path for score-modifier purposes.
 *
 * Not every path deserves the same scrutiny. A signal found in a
 * bundled `vendor/` or `tests/` directory is routinely a benign
 * byproduct of the vendor library shipping an obfuscation-adjacent
 * fixture — Sucuri's clean-ground-truth runs across the 281-site
 * fleet repeatedly showed these paths generating false positives.
 *
 * Conversely, a signal in `wp-load.php` or another root bootstrap
 * file is exactly where a persistent backdoor would live, so the
 * scorer treats those paths at full weight.
 *
 * @since 1.4.0
 */
enum PathClass: string
{
    /** Normal plugin/theme/core file — full score applies. */
    case Standard    = 'standard';

    /** vendor/, tests/, node_modules/, docs/, fixtures/ — score halved. */
    case LowRisk     = 'low_risk';

    /** Root bootstrap files (wp-load.php, wp-settings.php) — full weight. */
    case Bootstrap   = 'bootstrap';

    /** wp-content/uploads/ — full weight; PHP here is always suspect. */
    case UploadsDir  = 'uploads_dir';

    /** This plugin's own directory — excluded entirely. */
    case PluginSelf  = 'plugin_self';

    /**
     * Score modifier applied to the raw signal sum for this path class.
     *
     * LowRisk paths have their score halved before tiering decisions.
     * PluginSelf returns 0.0 so any accidental match collapses to Safe
     * (the active exclusion layers upstream should prevent us ever
     * seeing a PluginSelf path, but defence in depth).
     */
    public function downgradeModifier(): float
    {
        return match ($this) {
            self::LowRisk    => 0.5,
            self::PluginSelf => 0.0,
            self::Standard,
            self::Bootstrap,
            self::UploadsDir => 1.0,
        };
    }
}
