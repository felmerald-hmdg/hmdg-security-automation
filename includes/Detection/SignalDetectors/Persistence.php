<?php

declare(strict_types=1);

namespace HMDG\Security\Detection\SignalDetectors;

use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalCategory;

/**
 * Detects persistence-signal shapes:
 *   - PHP files in wp-content/uploads/ that are NOT benign
 *     "Silence is golden" stubs - weight 30.
 *   - Hidden iframes embedded via PHP echo/print - weight 15.
 *
 * Preserves the v1.3.2 `isBenignIndexStub()` byte-exact allowlist so
 * legitimate stubs dropped by core, WooCommerce, ACF, WPForms, etc.
 * do not generate persistence signals.
 *
 * @since 1.4.0
 */
final class Persistence
{
    /** Category for every Signal this detector emits. */
    private const CATEGORY = SignalCategory::Persistence;

    /** Max characters of a matched snippet to include in a Signal. */
    private const SNIPPET_MAX_LENGTH = 200;

    /** Hidden-iframe detection pattern. */
    private const HIDDEN_IFRAME = '/<iframe[^>]+style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|height\s*:\s*0|width\s*:\s*0)/i';

    /**
     * Byte-exact allowlist of known-safe index.php stubs. Copied from
     * FileIntegrity::isBenignIndexStub() - any deviation from an
     * allowlisted string still produces a persistence signal.
     *
     * @var list<string>
     */
    private const BENIGN_STUBS = [
        '<?php',
        '<?php ',
        "<?php\n// Silence is golden",
        "<?php\n// Silence is golden.",
        "<?php\n//Silence is golden",
        "<?php\n//Silence is golden.",
        "<?php\r\n// Silence is golden",
        "<?php\r\n// Silence is golden.",
        "<?php\r\n// Silence is golden\r\n?>",
        "<?php\r\n// Silence is golden.\r\n?>",
        '<?php //Silence is golden',
        '<?php //Silence is golden.',
        '<?php // Silence is golden',
        '<?php // Silence is golden.',
        '<?php /* Silence is golden */',
        '<?php /* Silence is golden. */',
        '<?php /** Silence is golden */',
        '<?php /** Silence is golden. */',
        "<?php\n// There are many ways to WordPress.",
        "<?php\n// There are many ways to WordPress",
        "<?php\nif (!defined('ABSPATH')) {\n\texit;\n}",
        "<?php\nif ( ! defined( 'ABSPATH' ) ) {\n\texit;\n}",
        "<?php\nif (!defined('ABSPATH')) {\n    exit;\n}",
        "<?php\nif ( ! defined( 'ABSPATH' ) ) {\n    exit;\n}",
        "<?php\nif (!defined('ABSPATH')) {\n    die('Access denied.');\n}",
    ];

    /**
     * Produce every Persistence Signal detectable for the given path
     * and contents.
     *
     * @param string $absolutePath Absolute filesystem path to the file.
     * @param string $contents     File contents (may be empty).
     *
     * @return list<Signal>
     */
    public function detect(string $absolutePath, string $contents): array
    {
        $signals = [];

        // Uploads-PHP persistence signal. Tests both the path (uploads)
        // and the benign-stub filter - matches the v1.3.2 behaviour.
        if ($this->isUploadsPhp(absolutePath: $absolutePath)
            && !$this->isBenignIndexStub(path: $absolutePath)
        ) {
            $hasExec = $this->containsExecutionPrimitive(contents: $contents);

            $signals[] = new Signal(
                category: self::CATEGORY,
                weight: $hasExec ? 70 : 30,
                label: $hasExec
                    ? 'PHP file in uploads/ containing code-execution primitive - webshell'
                    : 'PHP file in wp-content/uploads/',
                context: [
                    'line'       => 1,
                    'snippet'    => mb_substr($contents, 0, self::SNIPPET_MAX_LENGTH),
                    'pattern'    => 'uploads_php',
                    'pattern_id' => $hasExec ? 'uploads_php_with_exec' : 'uploads_php',
                ],
            );
        }

        // Hidden iframe signal.
        if ($contents !== '' && preg_match(self::HIDDEN_IFRAME, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
            /** @var array{0: string, 1: int} $m */
            $m = $matches[0];
            $offset = (int) $m[1];

            $signals[] = new Signal(
                category: self::CATEGORY,
                weight: 15,
                label: 'Hidden iframe embedded in file output',
                context: [
                    'line'    => $this->lineFor(contents: $contents, offset: $offset),
                    'snippet' => mb_substr($contents, $offset, self::SNIPPET_MAX_LENGTH),
                    'pattern' => self::HIDDEN_IFRAME,
                ],
            );
        }

        return $signals;
    }

    /**
     * Whether the absolute path sits inside wp-content/uploads/ and
     * has a .php extension.
     */
    private function isUploadsPhp(string $absolutePath): bool
    {
        if ($absolutePath === '' || !defined('WP_CONTENT_DIR')) {
            return false;
        }

        $normalised = str_replace('\\', '/', $absolutePath);
        $uploadsDir = str_replace('\\', '/', rtrim(\WP_CONTENT_DIR, '/\\')) . '/uploads/';

        if (!str_starts_with($normalised, $uploadsDir)) {
            return false;
        }

        return strtolower(pathinfo($normalised, PATHINFO_EXTENSION)) === 'php';
    }

    /**
     * Whether a discovered PHP file is a benign stub.
     */
    private function isBenignIndexStub(string $path): bool
    {
        if (basename($path) !== 'index.php') {
            return false;
        }

        if (!is_file($path) || !is_readable($path)) {
            return false;
        }

        $size = filesize($path);

        if ($size === false || $size < 0) {
            return false;
        }

        if ($size === 0) {
            return true;
        }

        if ($size > 256) {
            return false;
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            return false;
        }

        $normalised = rtrim($contents);

        if (in_array($normalised, self::BENIGN_STUBS, true)) {
            return true;
        }

        return $this->isCommentOnlyPhpFile($contents);
    }

    /**
     * True if the file contains only a PHP open tag plus comments and whitespace.
     *
     * @security Token-based. Removes PHP comments, then rejects any content
     * containing executable syntax tokens such as $, (, [, ;, backticks, or
     * nested PHP tags.
     */
    private function isCommentOnlyPhpFile(string $contents): bool
    {
        if ($contents === '') {
            return true;
        }

        if (str_starts_with($contents, "\xEF\xBB\xBF")) {
            $contents = substr($contents, 3);
        }

        $contents = ltrim($contents);

        if (!str_starts_with($contents, '<?')) {
            return false;
        }

        $body = preg_replace('/^<\?(?:php)?\s*/', '', $contents) ?? '';
        $body = preg_replace('/\?>\s*$/', '', $body) ?? '';
        $body = preg_replace('#/\*.*?\*/#s', '', $body) ?? '';
        $body = preg_replace('#//[^\r\n]*#', '', $body) ?? '';
        $body = preg_replace('#^\s*\#[^\r\n]*#m', '', $body) ?? '';
        $body = trim($body);

        if ($body === '') {
            return true;
        }

        foreach (['$', '(', '[', ';', '`', '<?', '?>'] as $token) {
            if (str_contains($body, $token)) {
                return false;
            }
        }

        return false;
    }

    /**
     * Whether file contents contain any PHP code-execution primitive.
     * Used to escalate uploads/*.php findings that carry active payloads.
     */
    private function containsExecutionPrimitive(string $contents): bool
    {
        if ($contents === '') {
            return false;
        }

        $lowered = strtolower($contents);

        $primitives = [
            'eval(',
            'assert(',
            'passthru(',
            'shell_exec(',
            'create_function(',
            'base64_decode(',
            'gzinflate(',
            'gzuncompress(',
            'gzdecode(',
            'str_rot13(',
            'hex2bin(',
        ];

        foreach ($primitives as $p) {
            if (str_contains($lowered, $p)) {
                return true;
            }
        }

        if (preg_match('/(?<![a-z_])(exec|system|popen|proc_open|pcntl_exec)\s*\(/', $lowered) === 1) {
            return true;
        }

        if (preg_match('/`[^`\n]*\$[^`\n]*`/', $contents) === 1) {
            return true;
        }

        return false;
    }

    private function lineFor(string $contents, int $offset): int
    {
        if ($offset <= 0) {
            return 1;
        }
        return substr_count(substr($contents, 0, $offset), "\n") + 1;
    }
}
