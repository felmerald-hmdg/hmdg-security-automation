#!/usr/bin/env python3
"""Build and verify a reproducible runtime-only WordPress plugin release."""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

SLUG = "hmdg-security-pro"
MAIN = SLUG + ".php"
VERSION_PATTERN = r"[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}"
FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
MAX_FILES = 2000
MAX_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
INCLUDE_PATTERN = r"includes/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.php"


class ReleaseError(Exception):
    """Failure text is deliberately independent of private source contents."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def read_regular(path: Path, root: Path) -> bytes:
    require(not path.is_symlink() and path.is_file(), "A release input is missing or is not a regular file.")
    require(path.resolve().is_relative_to(root.resolve()), "A release input escapes the source root.")
    require(stat.S_ISREG(path.stat().st_mode), "A release input is not a regular file.")
    require(path.stat().st_size <= MAX_BYTES, "A release input exceeds the size limit.")
    return path.read_bytes()


def read_version(root: Path) -> str:
    try:
        bootstrap = read_regular(root / MAIN, root).decode("utf-8-sig").replace("\r\n", "\n")
        changelog = read_regular(root / "CHANGELOG.md", root).decode("utf-8-sig").replace("\r\n", "\n")
        readme = read_regular(root / "README.md", root).decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeError:
        raise ReleaseError("Release metadata must use UTF-8.") from None
    header = re.findall(r"^[ \t]*\*[ \t]*Version:[ \t]*(" + VERSION_PATTERN + r")[ \t]*$", bootstrap, re.MULTILINE)
    constant = re.findall(r"\bdefine\([ \t]*['\"]HMDG_SECURITY_VERSION['\"][ \t]*,[ \t]*['\"](" + VERSION_PATTERN + r")[ '\"]*\)[ \t]*;", bootstrap)
    dated = re.search(r"^##[ \t]+\[(" + VERSION_PATTERN + r")\][ \t]+-[ \t]+[0-9]{4}-[0-9]{2}-[0-9]{2}[ \t]*$", changelog, re.MULTILINE)
    overview = re.findall(r"^- Version:[ \t]*`(" + VERSION_PATTERN + r")`(?:[ \t].*)?$", readme, re.MULTILINE)
    require(len(header) == 1 and len(constant) == 1 and dated is not None and len(overview) == 1, "The four release version declarations could not be verified.")
    version = header[0]
    require(version == constant[0] == dated.group(1) == overview[0], "The release version declarations do not agree.")
    return version


def runtime_files(root: Path) -> list[tuple[str, bytes]]:
    require(root.is_dir() and not root.is_symlink(), "The source root must be a regular directory.")
    includes = root / "includes"
    require(includes.is_dir() and not includes.is_symlink(), "The runtime includes directory is missing or unsafe.")
    files = [(MAIN, read_regular(root / MAIN, root))]
    for parent, directories, filenames in os.walk(includes, followlinks=False):
        directory = Path(parent)
        for name in directories:
            require(not (directory / name).is_symlink(), "Symlink directories are not allowed in the runtime package.")
        for name in filenames:
            path = directory / name
            relative = path.relative_to(root).as_posix()
            require(not any(part.startswith(".") for part in PurePosixPath(relative).parts), "Hidden runtime entries are not allowed.")
            require(re.fullmatch(INCLUDE_PATTERN, relative) is not None and ".." not in relative, "Only safe PHP include files are supported by the installed updater.")
            files.append((relative, read_regular(path, root)))
            require(len(files) <= MAX_FILES, "The runtime package exceeds the file limit.")
    require(any(name.startswith("includes/") for name, _ in files), "The runtime includes directory is empty.")
    require(sum(len(content) for _, content in files) <= MAX_BYTES, "The runtime package exceeds the size limit.")
    require(len({name for name, _ in files}) == len(files), "Duplicate runtime paths are not allowed.")
    return sorted(files)


def validate_archive(data: bytes, expected: dict[str, bytes] | None = None) -> None:
    require(0 < len(data) <= MAX_ARCHIVE_BYTES, "The compressed release archive exceeds the installed updater's limit.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= MAX_FILES and len({entry.filename for entry in infos}) == len(infos), "The release archive contains duplicate or excessive entries.")
            contents: dict[str, bytes] = {}
            total = 0
            for info in infos:
                parts = PurePosixPath(info.filename).parts
                require(bool(parts) and parts[0] == SLUG and not info.filename.startswith("/") and ".." not in parts and "\\" not in info.filename, "The release archive contains an unsafe path.")
                require(not info.is_dir() and len(parts) >= 2, "The release archive contains an unexpected directory entry.")
                relative = "/".join(parts[1:])
                require(relative == MAIN or (re.fullmatch(INCLUDE_PATTERN, relative) is not None and ".." not in relative), "The release archive contains a file outside its runtime allowlist.")
                require(not any(part.startswith(".") for part in parts), "The release archive contains a hidden entry.")
                mode = info.external_attr >> 16
                require(stat.S_IFMT(mode) in {0, stat.S_IFREG}, "The release archive contains a non-regular file.")
                require(not (info.flag_bits & 1), "Encrypted release archives are not supported.")
                total += info.file_size
                require(total <= MAX_BYTES, "The release archive exceeds the size limit.")
                contents[info.filename] = archive.read(info)
            require(SLUG + "/" + MAIN in contents and any(name.startswith(SLUG + "/includes/") for name in contents), "The release archive is incomplete.")
            if expected is not None:
                require(contents == expected, "The release archive differs from the verified runtime inputs.")
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError):
        raise ReleaseError("The release archive could not be verified.") from None


def build_release(root: Path, output: Path) -> tuple[str, int]:
    version = read_version(root)
    files = runtime_files(root)
    require(output.name == SLUG + ".zip", "The release archive must use the fixed plugin filename.")
    require(not output.is_symlink(), "The output path must not be a symlink.")
    require(not output.resolve().is_relative_to((root / "includes").resolve()), "The archive cannot be written inside runtime inputs.")
    expected = {SLUG + "/" + name: content for name, content in files}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in expected.items():
            info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, content)
    data = stream.getvalue()
    validate_archive(data, expected)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return version, len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", "--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path(SLUG + ".zip"))
    parser.add_argument("--version-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.version_only:
            print(read_version(args.source))
        else:
            version, count = build_release(args.source, args.output)
            print("Built " + SLUG + " " + version + ": " + str(count) + " verified runtime files.")
    except Exception:
        print("::error::Release packaging failed; check version agreement and runtime file safety.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
