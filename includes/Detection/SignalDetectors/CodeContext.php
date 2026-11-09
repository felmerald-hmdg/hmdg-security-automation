<?php

declare(strict_types=1);

namespace HMDG\Security\Detection\SignalDetectors;

use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalCategory;

/**
 * Detects code-context shapes that are low-confidence on their own but
 * add meaningful weight when combined with other signals.
 *
 * Currently:
 *   assert('string-literal') / assert("string-literal") — weight 15.
 *
 * The v1.3.3 hotfix learned the hard way that `assert($var)` patterns
 * are ubiquitous in legitimate vendored code (PHPUnit fixtures,
 * type-guard invariants in simple_html_dom, etc.) — we ONLY care
 * about the string-literal form, which is the actual RCE vector.
 *
 * @since 1.4.0
 */
final class CodeContext
{
    /** Category for every Signal this detector emits. */
    private const CATEGORY = SignalCategory::CodeContext;

    /** Max characters of a matched snippet to include in a Signal. */
    private const SNIPPET_MAX_LENGTH = 200;

    /**
     * assert() with a string-literal first argument only. The lookahead
     * `["\']` ensures we only match the form that can still eval in
     * older PHP builds — `assert($var)` is deliberately excluded.
     *
     * This is the v1.3.3 pattern baked in permanently.
     */
    private const ASSERT_STRING_LITERAL = '/\bassert\s*\(\s*[\'"]/i';

    /**
     * Detect CodeContext signals in $contents.
     *
     * @return list<Signal>
     */
    public function detect(string $contents): array
    {
        if ($contents === '') {
            return [];
        }

        $signals = [];

        if (preg_match(self::ASSERT_STRING_LITERAL, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
            /** @var array{0: string, 1: int} $m */
            $m = $matches[0];
            $offset = (int) $m[1];

            $signals[] = new Signal(
                category: self::CATEGORY,
                weight: 15,
                label: 'assert() with string-literal argument — historical RCE vector',
                context: [
                    'line'    => $this->lineFor(contents: $contents, offset: $offset),
                    'snippet' => mb_substr($contents, $offset, self::SNIPPET_MAX_LENGTH),
                    'pattern' => self::ASSERT_STRING_LITERAL,
                ],
            );
        }

        return $signals;
    }

    private function lineFor(string $contents, int $offset): int
    {
        if ($offset <= 0) {
            return 1;
        }
        return substr_count(substr($contents, 0, $offset), "\n") + 1;
    }
}
