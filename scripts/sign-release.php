<?php
declare(strict_types=1);

namespace HMDG\Security\Release;

/**
 * Sign a verified release artifact without executing plugin source.
 *
 * @package HMDG\Security\Release
 * @since 1.11.0
 */
final class ReleaseSigner
{
    /**
     * @param string $archivePath Verified runtime ZIP path.
     * @param string $updaterPath Source file containing the trusted public key.
     * @return void
     * @security The seed must match the updater's pinned key before any signature is written.
     */
    public static function sign(string $archivePath, string $updaterPath): void
    {
        if (!extension_loaded('sodium') || !function_exists('sodium_crypto_sign_seed_keypair')) {
            throw new \RuntimeException('The sodium extension is required.');
        }

        $seedText = trim((string) getenv('HMDG_RELEASE_SIGNING_KEY'));
        $seed = base64_decode($seedText, true);
        if ($seed === false || strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES || base64_encode($seed) !== $seedText) {
            throw new \RuntimeException('The signing seed must be canonical base64 for exactly 32 bytes.');
        }

        $keypair = '';
        $secretKey = '';
        try {
            $trustedPublicKey = self::readTrustedKey($updaterPath);
            $keypair = sodium_crypto_sign_seed_keypair($seed);
            $publicKey = sodium_crypto_sign_publickey($keypair);
            if (!hash_equals($trustedPublicKey, $publicKey)) {
                throw new \RuntimeException('The signing seed does not match the embedded public key.');
            }

            $archive = self::readRegular($archivePath);
            if (!str_starts_with($archive, "PK\x03\x04")) {
                throw new \RuntimeException('The release artifact is not a ZIP archive.');
            }
            $secretKey = sodium_crypto_sign_secretkey($keypair);
            $signature = sodium_crypto_sign_detached($archive, $secretKey);
            if (!sodium_crypto_sign_verify_detached($signature, $archive, $trustedPublicKey)) {
                throw new \RuntimeException('Release signature self-verification failed.');
            }
            self::writeSignature($archivePath . '.sig', base64_encode($signature));
        } finally {
            sodium_memzero($seed);
            if ($keypair !== '') {
                sodium_memzero($keypair);
            }
            if ($secretKey !== '') {
                sodium_memzero($secretKey);
            }
        }
    }

    private static function readTrustedKey(string $path): string
    {
        $source = self::readRegular($path);
        $matches = [];
        $matched = preg_match_all('/\bPUBLIC_KEY\s*=\s*([\'"])([A-Za-z0-9+\/=]+)\1\s*;/', $source, $matches);
        if ($matched !== 1) {
            throw new \RuntimeException('Exactly one embedded public key is required.');
        }
        $publicKey = base64_decode($matches[2][0], true);
        if ($publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \RuntimeException('The embedded public key is invalid.');
        }
        return $publicKey;
    }

    private static function readRegular(string $path): string
    {
        if (is_link($path) || !is_file($path) || !is_readable($path)) {
            throw new \RuntimeException('A required regular file is missing or unsafe.');
        }
        $content = file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException('A required file could not be read.');
        }
        return $content;
    }

    private static function writeSignature(string $path, string $signature): void
    {
        if (is_link($path) || file_exists($path)) {
            throw new \RuntimeException('The signature output path already exists.');
        }
        $handle = fopen($path, 'x');
        if ($handle === false) {
            throw new \RuntimeException('The signature output could not be created.');
        }
        try {
            if (fwrite($handle, $signature . "\n") !== strlen($signature) + 1) {
                throw new \RuntimeException('The signature could not be written completely.');
            }
        } finally {
            fclose($handle);
        }
    }
}

if (PHP_SAPI !== 'cli' || count($argv) !== 3) {
    fwrite(STDERR, "Usage: php scripts/sign-release.php <archive.zip> <ReleaseUpdater.php>\n");
    exit(1);
}

try {
    ReleaseSigner::sign($argv[1], $argv[2]);
    fwrite(STDOUT, "Release signed and verified against the embedded public key.\n");
} catch (\Throwable) {
    // No filesystem paths, seed values or private source excerpts enter Actions logs.
    fwrite(STDERR, "Release signing failed; check the sodium extension, signing seed, embedded key and output path.\n");
    exit(1);
}
