<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

/**
 * Classifies absolute filesystem paths into PathClass values.
 *
 * Every RiskScorer::classify() call consults this once per file. The
 * classification drives (a) the raw-score modifier on PathClass and
 * (b) the quorum-escalation rule in RiskScorer: LowRisk paths must
 * clear an additional signal-count + category mix test to qualify
 * for HighRisk.
 *
 * @since 1.4.0
 */
final class PathClassifier
{
    /**
     * Low-risk path segments that routinely carry benign obfuscation-
     * adjacent code (vendored dependencies, fixtures, minified assets,
     * language files, build artefacts). Matched against the normalised
     * forward-slash path.
     *
     * @var list<string>
     */
    private const LOW_RISK_PATTERNS = [
        '#/vendor/#',
        '#/vendor_prefixed/#',
        '#/node_modules/#',
        '#/tests?/#i',
        '#/Tests?/#',
        '#/TestCase/#',
        '#/_tests?/#',
        '#/__tests?__/#',
        '#/spec/#i',
        '#/specs/#i',
        '#/features/#',
        '#/fixtures?/#',
        '#/examples?/#i',
        '#/docs?/#i',
        '#/documentation/#',
        '#/composer/autoload[^/]*\.php$#',
        '#/composer/ClassLoader\.php$#',
        '#/composer/InstalledVersions\.php$#',
        '#\.min\.(js|css)$#',
        '#/build/#',
        '#/dist/#',
        '#/assets/#i',
        '#/languages?/#',
    ];

    /**
     * Root WordPress bootstrap files. A modification here would be the
     * most valuable place in the install for a persistent backdoor, so
     * they are treated at full score regardless of other signals.
     *
     * @var list<string>
     */
    private const BOOTSTRAP_FILES = [
        'wp-load.php',
        'wp-settings.php',
        'wp-config.php',
        'wp-blog-header.php',
        'wp-cron.php',
        'index.php',
    ];

    /**
     * Classify an absolute path.
     *
     * Order of precedence:
     *   1. PluginSelf — inside this plugin's own directory.
     *   2. UploadsDir — inside wp-content/uploads/ (any file there is
     *      full-weight, even if the path also matches a LowRisk pattern
     *      like /assets/; malware in uploads does not get a discount).
     *   3. Bootstrap — exact-basename match for a root bootstrap file.
     *   4. LowRisk — matches any of the LOW_RISK_PATTERNS.
     *   5. Standard — everything else.
     *
     * @param string $absolutePath Absolute filesystem path.
     */
    public function classify(string $absolutePath): PathClass
    {
        $normalised = str_replace('\\', '/', $absolutePath);

        // 1. Plugin-self check. Uses the same anchor strategy as
        // MalwareScanner::buildFileList() — absolute prefix derived
        // from WP_PLUGIN_DIR so an unrelated plugin whose slug happens
        // to share the segment cannot collide.
        $selfPluginDirname = defined('HMDG_SECURITY_PRO_BASENAME')
            ? dirname((string) \HMDG_SECURITY_PRO_BASENAME)
            : 'hmdg-security-pro';

        if (defined('WP_PLUGIN_DIR')) {
            $selfAbsoluteDir = str_replace('\\', '/', rtrim(\WP_PLUGIN_DIR, '/\\')) . '/' . $selfPluginDirname . '/';

            if (str_starts_with($normalised, $selfAbsoluteDir)) {
                return PathClass::PluginSelf;
            }
        }

        // 2. Uploads directory — PHP here is always suspect.
        if (defined('WP_CONTENT_DIR')) {
            $uploadsDir = str_replace('\\', '/', rtrim(\WP_CONTENT_DIR, '/\\')) . '/uploads/';

            if (str_starts_with($normalised, $uploadsDir)) {
                return PathClass::UploadsDir;
            }
        }

        // 3. Bootstrap files — only true WordPress root/bootstrap paths.
        if ($this->isRootBootstrapFile($normalised)) {
            return PathClass::Bootstrap;
        }

        // 4. Low-risk patterns.
        foreach (self::LOW_RISK_PATTERNS as $pattern) {
            if (preg_match($pattern, $normalised) === 1) {
                return PathClass::LowRisk;
            }
        }

        // 5. Default.
        return PathClass::Standard;
    }

    private function isRootBootstrapFile(string $absolutePath): bool
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
