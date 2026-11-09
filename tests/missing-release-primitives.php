<?php

declare(strict_types=1);

/** Run with php -n (or just one required extension) to prove verification fails closed. */
final class WP_Error
{
    public function __construct(public string $code, public string $message = '') {}
}
function is_admin(): bool { return true; }
function wp_doing_cron(): bool { return false; }
require_once __DIR__ . '/../includes/Services/ReleaseMetadata.php';
require_once __DIR__ . '/../includes/Services/SignedReleasePackage.php';
require_once __DIR__ . '/../includes/Services/ReleaseUpdater.php';

use HMDG\Security\Services\ReleaseMetadata;
use HMDG\Security\Services\SignedReleasePackage;

if (function_exists('sodium_crypto_sign_verify_detached') && class_exists(ZipArchive::class)) {
    echo "SKIP: both verification primitives are available; run this test with php -n.\n";
    exit(0);
}
$result = SignedReleasePackage::download(ReleaseMetadata::packageUrl('1.12.0'), '');
if (!$result instanceof WP_Error || $result->code !== 'hmdg_security_verification_unavailable') {
    throw new RuntimeException('Missing verification support did not fail closed.');
}
// No HTTP/download helpers exist in this process: reaching one would itself fail the test.
echo "PASS: missing verification primitive refuses download before network or filesystem work\n";
