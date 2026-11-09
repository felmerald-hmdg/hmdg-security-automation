<?php

declare(strict_types=1);

namespace HMDG\Security\Detection\SignalDetectors;

use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalCategory;

/**
 * Detects remote-execution signals:
 *   - passthru|shell_exec|system with a variable-argument invocation
 *     (`passthru($cmd)` etc.) — weight 25.
 *   - file_get_contents()/curl_exec() to an external domain not on the
 *     legitimate-domains allowlist — weight 20.
 *
 * The variable-argument requirement is critical: legitimate libraries
 * routinely define functions named `system`, `exec`, etc., but they
 * rarely call `system($user_input)`. Requiring a `$...` argument
 * anchors the match to the dynamic-invocation shape that real
 * backdoors use.
 *
 * @since 1.4.0
 */
final class RemoteExec
{
    /** Category for every Signal this detector emits. */
    private const CATEGORY = SignalCategory::RemoteExec;

    /** Max characters of a matched snippet to include in a Signal. */
    private const SNIPPET_MAX_LENGTH = 200;

    /**
     * Direct eval of attacker-controlled input. Zero legitimate use —
     * no modern plugin calls eval() on $_POST/$_GET/etc.
     *
     * @var array<string, int> pattern => weight
     */
    private const DIRECT_EVAL_PATTERNS = [
        '/\beval\s*\(\s*@?\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/i' => 60,
        '/\bassert\s*\(\s*@?\s*\$_(?:POST|GET|REQUEST|COOKIE)\b/i'            => 60,
    ];

    /** Variable-argument shell invocations. */
    private const SHELL_VAR_INVOCATION = '/\b(?:passthru|shell_exec|system|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$/i';

    /** External-URL pattern inside file_get_contents/curl_exec. */
    private const EXTERNAL_URL = '/\b(?:file_get_contents|curl_exec)\s*\(\s*[\'"]https?:\/\/([^\/\'"]+)/i';

    /**
     * @param list<string> $legitimateDomains Domains allowed without a
     *                                        signal (exact or subdomain
     *                                        match against each entry).
     */
    public function __construct(
        private readonly array $legitimateDomains,
    ) {}

    /**
     * Produce every RemoteExec Signal detectable in $contents.
     *
     * @return list<Signal>
     */
    public function detect(string $contents): array
    {
        if ($contents === '') {
            return [];
        }

        $signals = [];

        foreach (self::DIRECT_EVAL_PATTERNS as $pattern => $weight) {
            if (preg_match($pattern, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
                /** @var array{0: string, 1: int} $m */
                $m = $matches[0];
                $offset = (int) $m[1];

                $signals[] = new Signal(
                    category: self::CATEGORY,
                    weight: $weight,
                    label: 'Direct eval/assert of superglobal input — webshell',
                    context: [
                        'line'       => $this->lineFor(contents: $contents, offset: $offset),
                        'snippet'    => mb_substr($contents, $offset, self::SNIPPET_MAX_LENGTH),
                        'pattern'    => $pattern,
                        'pattern_id' => 'direct_eval_input',
                    ],
                );
            }
        }

        if (preg_match(self::SHELL_VAR_INVOCATION, $contents, $matches, PREG_OFFSET_CAPTURE) === 1) {
            /** @var array{0: string, 1: int} $m */
            $m = $matches[0];
            $offset = (int) $m[1];

            $signals[] = new Signal(
                category: self::CATEGORY,
                weight: 25,
                label: 'passthru/shell_exec/system with variable argument',
                context: [
                    'line'    => $this->lineFor(contents: $contents, offset: $offset),
                    'snippet' => mb_substr($contents, $offset, self::SNIPPET_MAX_LENGTH),
                    'pattern' => self::SHELL_VAR_INVOCATION,
                ],
            );
        }

        if (preg_match('/`[^`\n]{0,200}\$[^`\n]{0,200}`/', $contents, $btMatches, PREG_OFFSET_CAPTURE) === 1) {
            /** @var array{0: string, 1: int} $m */
            $m = $btMatches[0];
            $offset = (int) $m[1];

            $signals[] = new Signal(
                category: self::CATEGORY,
                weight: 25,
                label: 'Backtick shell execution with variable interpolation',
                context: [
                    'line'       => $this->lineFor(contents: $contents, offset: $offset),
                    'snippet'    => mb_substr($contents, $offset, self::SNIPPET_MAX_LENGTH),
                    'pattern'    => '/`...$...`/',
                    'pattern_id' => 'backtick_var',
                ],
            );
        }

        if (preg_match_all(self::EXTERNAL_URL, $contents, $urlAll, PREG_OFFSET_CAPTURE) > 0) {
            /** @var list<array{0: string, 1: int}> $domainMatches */
            $domainMatches = $urlAll[1];

            /** @var list<array{0: string, 1: int}> $fullMatches */
            $fullMatches = $urlAll[0];

            foreach ($domainMatches as $index => $dom) {
                $domain = strtolower($dom[0]);

                if ($this->isLegitimateDomain(domain: $domain)) {
                    continue;
                }

                $offset = (int) $fullMatches[$index][1];

                $signals[] = new Signal(
                    category: self::CATEGORY,
                    weight: 20,
                    label: 'External HTTP call to unknown domain: ' . $domain,
                    context: [
                        'line'    => $this->lineFor(contents: $contents, offset: $offset),
                        'snippet' => mb_substr($contents, $offset, self::SNIPPET_MAX_LENGTH),
                        'pattern' => self::EXTERNAL_URL,
                        'domain'  => $domain,
                    ],
                );

                // One external-URL signal per file is enough — multiple
                // hits inflate the score without adding information.
                break;
            }
        }

        return $signals;
    }

    /**
     * Whether the domain matches one of the allowlisted legitimate
     * domains (exact or subdomain).
     */
    private function isLegitimateDomain(string $domain): bool
    {
        $domain = strtolower(trim($domain));

        foreach ($this->legitimateDomains as $legit) {
            $legitLower = strtolower($legit);

            if ($domain === $legitLower) {
                return true;
            }

            if (str_ends_with($domain, '.' . $legitLower)) {
                return true;
            }
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
