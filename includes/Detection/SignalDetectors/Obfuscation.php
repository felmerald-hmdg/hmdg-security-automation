<?php

declare(strict_types=1);

namespace HMDG\Security\Detection\SignalDetectors;

use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalCategory;

/**
 * Detects obfuscation primitives: eval(base64_decode(...)),
 * eval(gzinflate(...)), eval(str_rot13(...)), create_function(),
 * $$var() dynamic calls, preg_replace with the /e modifier, and the
 * canonical long-base64-plus-decode-sink shape.
 *
 * Returns zero or more Signal objects with SignalCategory::Obfuscation.
 *
 * Weights (per the v1.4.0 design):
 *   eval(base64_decode(/gzinflate(/str_rot13(       -> 60
 *   $$var(                                          -> 20
 *   create_function(                                -> 20
 *   preg_replace('/e modifier                       -> 30
 *   long base64 near decode sink                    -> 25
 *
 * Preserves the v1.3.2 false-positive suppression logic:
 *   - isBenignBase64Match() — suppresses data-URI preludes.
 *   - hasDecodeSinkNearby() — requires a decode/exec sink in the file.
 *
 * @since 1.4.0
 */
final class Obfuscation
{
    /** Category for every Signal this detector emits. */
    private const CATEGORY = SignalCategory::Obfuscation;

    /** Max characters of a matched snippet to include in a Signal. */
    private const SNIPPET_MAX_LENGTH = 200;

    /**
     * High-weight eval-wrapping patterns.
     *
     * @var array<string, int> pattern => weight
     */
    private const EVAL_WRAPPER_PATTERNS = [
        '/\beval\s*\(\s*base64_decode\s*\(/i' => 60,
        '/\beval\s*\(\s*gzinflate\s*\(/i'     => 60,
        '/\beval\s*\(\s*gzuncompress\s*\(/i'  => 60,
        '/\beval\s*\(\s*gzdecode\s*\(/i'      => 60,
        '/\beval\s*\(\s*str_rot13\s*\(/i'     => 60,
        '/\beval\s*\(\s*hex2bin\s*\(/i'       => 60,
    ];

    /** preg_replace('/e') modifier — deprecated RCE vector. */
    private const PREG_REPLACE_E = '/\bpreg_replace\s*\(\s*["\'].*\/e["\']/';

    /** Variable-variable function calls — dynamic dispatch backdoors. */
    private const DOUBLE_DOLLAR_CALL = '/\$\$\w+\s*\(/';

    /** create_function() — deprecated + widely used in backdoors. */
    private const CREATE_FUNCTION = '/\bcreate_function\s*\(/i';

    /** Pre-compiled long-base64 pattern built from the config threshold. */
    private readonly string $base64Pattern;

    /**
     * @param int $base64MinLength Minimum alphabet-run length to flag.
     */
    public function __construct(int $base64MinLength)
    {
        $this->base64Pattern = '/[A-Za-z0-9+\/=]{' . $base64MinLength . ',}/';
    }

    /**
     * Produce every Obfuscation Signal detectable in $contents.
     *
     * @return list<Signal>
     */
    public function detect(string $contents): array
    {
        if ($contents === '') {
            return [];
        }

        $signals = [];

        // eval(base64_decode/gzinflate/str_rot13)
        foreach (self::EVAL_WRAPPER_PATTERNS as $pattern => $weight) {
            if (preg_match($pattern, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
                $signals[] = $this->makeSignal(
                    weight: $weight,
                    label: 'eval() wrapping a decoder — obfuscated execution',
                    match: $matches[0],
                    contents: $contents,
                    pattern: $pattern,
                    patternId: 'eval_wrapper',
                );
            }
        }

        // preg_replace /e
        if (preg_match(self::PREG_REPLACE_E, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
            $signals[] = $this->makeSignal(
                weight: 30,
                label: 'preg_replace /e modifier — deprecated code execution vector',
                match: $matches[0],
                contents: $contents,
                pattern: self::PREG_REPLACE_E,
            );
        }

        // $$var(
        if (preg_match(self::DOUBLE_DOLLAR_CALL, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
            $signals[] = $this->makeSignal(
                weight: 20,
                label: 'Variable-variable function call — dynamic dispatch',
                match: $matches[0],
                contents: $contents,
                pattern: self::DOUBLE_DOLLAR_CALL,
            );
        }

        // create_function(
        if (preg_match(self::CREATE_FUNCTION, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
            $signals[] = $this->makeSignal(
                weight: 20,
                label: 'create_function() — deprecated, frequently used in backdoors',
                match: $matches[0],
                contents: $contents,
                pattern: self::CREATE_FUNCTION,
            );
        }

        // Long base64 blob with a decode sink somewhere in the file.
        // Preserves the v1.3.2 tuning: first benign match short-circuits
        // (data-URI preludes), and we need a decode/exec sink somewhere
        // in the file for the match to count.
        if (preg_match_all($this->base64Pattern, $contents, $b64All, PREG_OFFSET_CAPTURE) > 0) {
            /** @var list<array{0: string, 1: int}> $b64List */
            $b64List = $b64All[0];

            foreach ($b64List as $b64Match) {
                $offset = $b64Match[1];
                $matchText = $b64Match[0];

                if ($this->isBenignBase64Match(contents: $contents, offset: $offset)) {
                    continue;
                }

                if (!$this->hasDecodeSinkNearby(contents: $contents)) {
                    continue;
                }

                $signals[] = $this->makeSignal(
                    weight: 25,
                    label: sprintf(
                        'Long encoded string (%d chars) near decode sink',
                        strlen($matchText),
                    ),
                    match: [mb_substr($matchText, 0, self::SNIPPET_MAX_LENGTH), $offset],
                    contents: $contents,
                    pattern: $this->base64Pattern,
                );

                // One long-blob Signal per file is enough; the scorer
                // already has the signal it needs.
                break;
            }
        }

        return $signals;
    }

    /**
     * Package a PCRE capture into a Signal with line + snippet context.
     *
     * @param array{0: string, 1: int}|list<mixed> $match
     */
    private function makeSignal(
        int $weight,
        string $label,
        array $match,
        string $contents,
        string $pattern,
        ?string $patternId = null,
    ): Signal {
        /** @var array{0: string, 1: int} $m */
        $m = $match;
        $offset = (int) ($m[1] ?? 0);
        $snippet = mb_substr(
            (string) ($m[0] ?? ''),
            0,
            self::SNIPPET_MAX_LENGTH,
        );

        return new Signal(
            category: self::CATEGORY,
            weight: $weight,
            label: $label,
            context: [
                'line'       => $this->lineFor(contents: $contents, offset: $offset),
                'snippet'    => $snippet,
                'pattern'    => $pattern,
                'pattern_id' => $patternId,
            ],
        );
    }

    /**
     * 1-based line number for a byte offset in $contents.
     */
    private function lineFor(string $contents, int $offset): int
    {
        if ($offset <= 0) {
            return 1;
        }
        return substr_count(substr($contents, 0, $offset), "\n") + 1;
    }

    /**
     * Whether a base64-alphabet match is clearly inside a data: URI.
     *
     * Copied verbatim from the v1.3.2 MalwareScanner — every site on
     * the fleet depends on this suppression to stop flagging inline
     * SVGs, data-URI images, and embedded fonts as obfuscation.
     */
    private function isBenignBase64Match(string $contents, int $offset): bool
    {
        $windowStart = max(0, $offset - 200);
        $windowLength = $offset - $windowStart;

        if ($windowLength <= 0) {
            return false;
        }

        $before = substr($contents, $windowStart, $windowLength);
        $beforeLower = strtolower($before);

        $dataUriPreludes = [
            ';base64,',
            'data:image/',
            'data:font/',
            'data:application/',
            'data:application/font',
            'data:application/octet-stream;base64,',
            'data:text/',
            'data:video/',
            'data:audio/',
            'url(data:',
            'src="data:',
            "src='data:",
            'href="data:',
            "href='data:",
            'xlink:href="data:',
            "xlink:href='data:",
            '"data:',
            "'data:",
        ];

        foreach ($dataUriPreludes as $prelude) {
            if (str_contains($beforeLower, strtolower($prelude))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a decode/execution sink appears anywhere in the file.
     *
     * Mirrors v1.3.2 MalwareScanner::hasDecodeSinkNearby() — the
     * whole-file scan + word-boundary ambiguous-sink guard.
     */
    private function hasDecodeSinkNearby(string $contents): bool
    {
        if ($contents === '') {
            return false;
        }

        $lowered = strtolower($contents);

        $substringSinks = [
            'eval(',
            'base64_decode(',
            'gzinflate(',
            'gzuncompress(',
            'gzdecode(',
            'str_rot13(',
            'create_function(',
            'passthru(',
            'shell_exec(',
            'hex2bin(',
            'pack(',
        ];

        foreach ($substringSinks as $sink) {
            if (str_contains($lowered, $sink)) {
                return true;
            }
        }

        if (preg_match('/(?<![a-z_])(exec|system|assert)\s*\(/', $lowered) === 1) {
            return true;
        }

        if (preg_match('/preg_replace\s*\(\s*[\'"][^\'"]*\/e[\'"]/i', $lowered) === 1) {
            return true;
        }

        return false;
    }
}
