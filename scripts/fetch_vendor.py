#!/usr/bin/env python3
"""Download pinned helpers, verify bytes, then atomically install each binary.

Usage: python scripts/fetch_vendor.py --platform linux-amd64
       python scripts/fetch_vendor.py --platform windows-amd64

No helper is executed here. A nonzero exit means callers must not proceed
using an older cached binary. The download and archive are always checked,
even when a destination executable already exists.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import sys
import tarfile
import tempfile
import time
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ("linux-amd64", "windows-amd64")
NAMES = ("wireproxy", "wgcf")
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
SOCKET_TIMEOUT = 15.0
DOWNLOAD_DEADLINE = 120.0


class VendorError(Exception):
    """A download, manifest or archive failed validation; do not use its bytes."""


class HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    """Allow GitHub's signed asset redirects, but never downgrade to HTTP."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise VendorError("Refusing a non-HTTPS download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def binary_name(platform: str, name: str) -> str:
    if platform not in PLATFORMS or name not in NAMES:
        raise VendorError("Unknown helper or platform")
    return name + (".exe" if platform == "windows-amd64" else "")


def load_manifest(root: Path = ROOT) -> list[dict[str, str]]:
    """Read only the checked-in manifest; the CLI never accepts remote URLs."""
    try:
        data = json.loads((root / "vendor" / "manifest.json").read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise VendorError(f"Cannot read vendor manifest: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise VendorError("Unsupported vendor manifest schema")
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        raise VendorError("Manifest artifacts must be a list")
    seen = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise VendorError("Invalid artifact record")
        platform, name = artifact.get("platform"), artifact.get("name")
        target = binary_name(platform, name)
        key = (platform, name)
        if key in seen:
            raise VendorError("Duplicate artifact record")
        seen.add(key)
        digest = artifact.get("sha256", "")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise VendorError("Artifact SHA-256 must be 64 lowercase hex digits")
        url = artifact.get("url", "")
        if not isinstance(url, str):
            raise VendorError("Invalid artifact URL")
        parsed = urlsplit(url)
        repository = "windtf/wireproxy" if name == "wireproxy" else "ViRb3/wgcf"
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or not parsed.path.startswith(f"/{repository}/releases/download/")
            or parsed.query
            or parsed.fragment
        ):
            raise VendorError("Artifact URL must be a fixed upstream HTTPS release")
        if name == "wireproxy":
            if artifact.get("archive_member") != target or not url.endswith(".tar.gz"):
                raise VendorError("Unexpected wireproxy archive member")
        elif "archive_member" in artifact:
            raise VendorError("wgcf must be a raw executable, not an archive")
    if seen != {(platform, name) for platform in PLATFORMS for name in NAMES}:
        raise VendorError("Manifest must contain exactly the four supported artifacts")
    return artifacts


def download_verified(artifact: dict[str, str], destination: Path) -> None:
    """Save at most 64 MiB over verified TLS and reject any digest mismatch.

    There is a 120-second wall-clock budget checked between reads, plus a
    15-second maximum socket operation. No retry or unverified fallback exists.
    """
    deadline = time.monotonic() + DOWNLOAD_DEADLINE
    digest = hashlib.sha256()
    total = 0
    opener = build_opener(
        HTTPSOnlyRedirectHandler(), HTTPSHandler(context=ssl.create_default_context())
    )
    request = Request(artifact["url"], headers={"User-Agent": "WarpPocket-vendor/0.1"})
    try:
        with opener.open(request, timeout=SOCKET_TIMEOUT) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise VendorError("Refusing a non-HTTPS download response")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    length = int(content_length)
                except ValueError as exc:
                    raise VendorError("Invalid download Content-Length") from exc
                if length < 0 or length > MAX_DOWNLOAD_BYTES:
                    raise VendorError("Download exceeds the size limit")
            with destination.open("xb") as stream:
                while True:
                    if time.monotonic() >= deadline:
                        raise VendorError("Download exceeded its time budget")
                    # read1 does at most one underlying read, so a peer cannot
                    # postpone the deadline check by slowly filling a chunk.
                    chunk = response.read1(CHUNK_BYTES)
                    if time.monotonic() >= deadline:
                        raise VendorError("Download exceeded its time budget")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise VendorError("Download exceeds the size limit")
                    digest.update(chunk)
                    stream.write(chunk)
        if total == 0:
            raise VendorError("Downloaded an empty artifact")
        if not hmac.compare_digest(digest.hexdigest(), artifact["sha256"]):
            raise VendorError(f"SHA-256 mismatch for {artifact['name']}")
    except (URLError, OSError, ValueError, HTTPException) as exc:
        raise VendorError(f"Download failed for {artifact['name']}: {exc}") from exc


def unpack_binary(archive_path: Path, member_name: str, destination: Path) -> None:
    """Copy one exact regular member; never extract paths from an archive."""
    count = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                count += 1
                if (
                    count != 1
                    or member.name != member_name
                    or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or member.sparse is not None
                ):
                    raise VendorError("Archive must contain exactly the expected regular file")
                if member.size <= 0 or member.size > MAX_BINARY_BYTES:
                    raise VendorError("Archive member exceeds the binary size limit")
                source = archive.extractfile(member)
                if source is None:
                    raise VendorError("Cannot read expected archive member")
                with source, destination.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        chunk = source.read(min(CHUNK_BYTES, remaining))
                        if not chunk:
                            raise VendorError("Truncated archive member")
                        output.write(chunk)
                        remaining -= len(chunk)
        if count != 1:
            raise VendorError("Archive is missing the expected regular file")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise VendorError(f"Invalid helper archive: {exc}") from exc


def fetch_artifact(artifact: dict[str, str], directory: Path) -> Path:
    """Stage verified bytes beside the target and atomically replace it."""
    target = directory / binary_name(artifact["platform"], artifact["name"])
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".fetch-", dir=directory) as temporary:
        staging = Path(temporary)
        downloaded = staging / "download"
        executable = staging / "executable"
        download_verified(artifact, downloaded)
        if "archive_member" in artifact:
            unpack_binary(downloaded, artifact["archive_member"], executable)
        else:
            if downloaded.stat().st_size > MAX_BINARY_BYTES:
                raise VendorError("Helper exceeds the binary size limit")
            shutil.copyfile(downloaded, executable)
        executable.chmod(0o755 if artifact["platform"] == "linux-amd64" else 0o644)
        with executable.open("rb+") as stream:
            os.fsync(stream.fileno())
        os.replace(executable, target)
    return target


def fetch_platform(platform: str, *, root: Path = ROOT) -> list[Path]:
    if platform not in PLATFORMS:
        raise VendorError("Unsupported platform")
    artifacts = load_manifest(root)
    directory = root / "vendor" / platform
    return [
        fetch_artifact(artifact, directory)
        for artifact in artifacts
        if artifact["platform"] == platform
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    args = parser.parse_args(argv)
    try:
        paths = fetch_platform(args.platform)
    except (VendorError, OSError) as exc:
        print(f"Vendor fetch failed: {exc}. Do not use cached helpers.", file=sys.stderr)
        return 1
    for path in paths:
        print(f"Verified {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
