"""Release tooling regression tests with fictional source and ephemeral signing keys."""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_release", ROOT / "scripts" / "build_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        (self.root / "includes" / "Services").mkdir(parents=True)
        (self.root / release.MAIN).write_text("<?php\n/**\n * Version: 1.2.3\n */\ndefine('HMDG_SECURITY_VERSION', '1.2.3');\n", encoding="utf-8")
        (self.root / "CHANGELOG.md").write_text("# History\n\n## [Unreleased]\n\n## [1.2.3] - 2026-01-01\n\nFictional release.\n\n## [1.2.2] - 2025-12-01\n", encoding="utf-8")
        (self.root / "README.md").write_text("# Fictional plugin\n\n- Version: `1.2.3` - example\n", encoding="utf-8")
        (self.root / "includes" / "Services" / "Example.php").write_text("<?php\ndeclare(strict_types=1);\n", encoding="utf-8")
        self.output = Path(self.temporary.name) / "hmdg-security-pro.zip"


class PackagingTests(ReleaseFixture):
    def test_versions_and_runtime_only_allowlist(self):
        (self.root / "sites.json").write_text('{"private":"must-not-ship"}')
        (self.root / ".env").write_text("SECRET=must-not-ship")
        (self.root / "private-notes.md").write_text("must-not-ship")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "private.php").write_text("<?php // must-not-ship")
        version, count = release.build_release(self.root, self.output)
        self.assertEqual((version, count), ("1.2.3", 2))
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(set(archive.namelist()), {"hmdg-security-pro/hmdg-security-pro.php", "hmdg-security-pro/includes/Services/Example.php"})
            self.assertNotIn(b"must-not-ship", b"".join(archive.read(name) for name in archive.namelist()))

    def test_output_is_reproducible_despite_mtime_changes(self):
        release.build_release(self.root, self.output)
        first = self.output.read_bytes()
        os.utime(self.root / release.MAIN, (1700000000, 1700000000))
        release.build_release(self.root, self.output)
        self.assertEqual(first, self.output.read_bytes())

    def test_each_version_declaration_must_match(self):
        for filename, old, new in ((release.MAIN, "Version: 1.2.3", "Version: 1.2.4"), (release.MAIN, "'1.2.3'", "'1.2.4'"), ("CHANGELOG.md", "[1.2.3]", "[1.2.4]"), ("README.md", "`1.2.3`", "`1.2.4`")):
            path = self.root / filename
            original = path.read_text()
            path.write_text(original.replace(old, new))
            with self.subTest(filename=filename, old=old), self.assertRaises(release.ReleaseError):
                release.build_release(self.root, self.output)
            path.write_text(original)

    def test_missing_or_duplicate_version_declarations_fail(self):
        path = self.root / release.MAIN
        original = path.read_text()
        for content in (original.replace(" * Version: 1.2.3\n", ""), original + "\ndefine('HMDG_SECURITY_VERSION', '1.2.3');\n"):
            path.write_text(content)
            with self.assertRaises(release.ReleaseError):
                release.read_version(self.root)

    def test_symlink_file_directory_and_output_are_rejected(self):
        outside = Path(self.temporary.name) / "private-value"
        outside.write_text("PRIVATE_VALUE")
        for directory in (False, True):
            link = self.root / "includes" / "unsafe"
            try:
                link.symlink_to(outside.parent if directory else outside, target_is_directory=directory)
            except OSError:
                self.skipTest("Symlink creation is unavailable for this account.")
            with self.subTest(directory=directory), self.assertRaises(release.ReleaseError):
                release.build_release(self.root, self.output)
            link.unlink()
        self.output.symlink_to(outside)
        with self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.output)
        self.assertEqual(outside.read_text(), "PRIVATE_VALUE")

    def test_hidden_runtime_entries_are_rejected(self):
        (self.root / "includes" / ".credential").write_text("SECRET")
        with self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.output)

    def test_non_php_include_cannot_publish_an_uninstallable_package(self):
        (self.root / "includes" / "client-inventory.json").write_text('{"private":"must-not-ship"}')
        with self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.output)

    def test_archive_and_unpacked_limits_match_the_installed_updater(self):
        with patch.object(release, "MAX_ARCHIVE_BYTES", 10), self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.output)
        with patch.object(release, "MAX_BYTES", 10), self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.output)

    def test_runtime_inputs_cannot_be_overwritten_by_output(self):
        original = (self.root / release.MAIN).read_bytes()
        with self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.root / release.MAIN)
        self.assertEqual((self.root / release.MAIN).read_bytes(), original)
        with self.assertRaises(release.ReleaseError):
            release.build_release(self.root, self.root / "includes" / "hmdg-security-pro.zip")

    def test_archive_path_and_file_type_guards(self):
        cases = ["../escape.php", "other-plugin/file.php", "hmdg-security-pro/sites.json", "hmdg-security-pro/includes/../../escape", "hmdg-security-pro/includes\\escape", "hmdg-security-pro/includes/.private"]
        for name in cases:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(name, "PRIVATE_VALUE")
            with self.subTest(name=name), self.assertRaises(release.ReleaseError):
                release.validate_archive(stream.getvalue())
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            info = zipfile.ZipInfo("hmdg-security-pro/includes/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../../private")
        with self.assertRaises(release.ReleaseError):
            release.validate_archive(stream.getvalue())

    def test_cli_failure_does_not_expose_private_paths(self):
        with patch.object(sys, "argv", ["build_release.py", "--source", str(self.root / "PRIVATE_SOURCE_PATH")]), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(release.main(), 1)
        self.assertNotIn("PRIVATE_SOURCE_PATH", output.getvalue())


class SigningTests(ReleaseFixture):
    def setUp(self):
        super().setUp()
        self.php = os.environ.get("TEST_PHP_BINARY") or shutil.which("php")
        if not self.php:
            self.skipTest("Set TEST_PHP_BINARY to run sodium signing regressions.")
        flags = json.loads(os.environ.get("TEST_PHP_FLAGS_JSON", "[]"))
        self.command = [self.php, *flags]
        check = subprocess.run([*self.command, "-r", "exit(extension_loaded('sodium') ? 0 : 1);"], capture_output=True)
        if check.returncode:
            self.skipTest("The selected PHP binary has no sodium extension.")
        seed = bytes(range(32))
        self.seed = base64.b64encode(seed).decode()
        env = dict(os.environ, TEST_SEED=self.seed)
        public = subprocess.run([*self.command, "-r", "echo base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(base64_decode(getenv('TEST_SEED')))));"], env=env, capture_output=True, check=True).stdout.decode()
        self.updater = self.root / "includes" / "Services" / "ReleaseUpdater.php"
        self.updater.write_text("<?php\nfinal class ExampleUpdater { public const PUBLIC_KEY = '" + public + "'; }\n")
        release.build_release(self.root, self.output)

    def sign(self, seed):
        env = dict(os.environ, HMDG_RELEASE_SIGNING_KEY=seed)
        return subprocess.run([*self.command, str(ROOT / "scripts" / "sign-release.php"), str(self.output), str(self.updater)], env=env, capture_output=True)

    def test_signature_matches_zip_and_rejects_tampering(self):
        result = self.sign(self.seed)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        signature = Path(str(self.output) + ".sig")
        self.assertEqual(len(base64.b64decode(signature.read_text().strip(), validate=True)), 64)
        env = dict(os.environ, TEST_SEED=self.seed)
        verify = "exit(sodium_crypto_sign_verify_detached(base64_decode(trim(file_get_contents($argv[2]))), file_get_contents($argv[1]), sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(base64_decode(getenv('TEST_SEED'))))) ? 0 : 1);"
        command = [*self.command, "-r", verify, str(self.output), str(signature)]
        self.assertEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)
        self.output.write_bytes(self.output.read_bytes() + b"tampered")
        self.assertNotEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)

    def test_wrong_missing_and_malformed_seed_never_write_signature(self):
        for seed in ("", "not-base64", base64.b64encode(b"short").decode(), base64.b64encode(bytes([99]) * 32).decode()):
            result = self.sign(seed)
            with self.subTest(seed_length=len(seed)):
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(Path(str(self.output) + ".sig").exists())
                self.assertNotIn(str(self.temporary.name).encode(), result.stderr)

    def test_existing_signature_is_not_overwritten(self):
        signature = Path(str(self.output) + ".sig")
        signature.write_text("existing")
        self.assertNotEqual(self.sign(self.seed).returncode, 0)
        self.assertEqual(signature.read_text(), "existing")


if __name__ == "__main__":
    unittest.main()
