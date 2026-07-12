#!/usr/bin/env python3
"""Fail closed if an existing GitHub release asset differs from a local asset."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, BinaryIO


REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
CHUNK_SIZE = 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub owner/repository")
    parser.add_argument("--tag", required=True, help="release tag")
    parser.add_argument(
        "--github-output",
        type=pathlib.Path,
        help="optional GitHub Actions output file",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail when the release or any local asset is still missing remotely",
    )
    parser.add_argument("assets", nargs="+", type=pathlib.Path)
    return parser.parse_args()


def sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    with path.open("rb") as handle:
        return sha256_stream(handle)


def github_request(url: str, token: str | None, accept: str) -> urllib.request.Request:
    headers = {
        "Accept": accept,
        "User-Agent": "docdex-release-asset-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def fetch_release(repository: str, tag: str, token: str | None) -> dict[str, Any] | None:
    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    encoded_tag = urllib.parse.quote(tag, safe="")
    url = f"{api_base}/repos/{repository}/releases/tags/{encoded_tag}"
    try:
        with urllib.request.urlopen(
            github_request(url, token, "application/vnd.github+json"), timeout=30
        ) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RuntimeError(f"GitHub release lookup failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub release lookup failed: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise RuntimeError("GitHub release response has an unrecognized schema")
    return payload


def remote_sha256(asset: dict[str, Any]) -> str:
    digest = asset.get("digest")
    if isinstance(digest, str) and digest.startswith("sha256:"):
        value = digest.removeprefix("sha256:")
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            return value.lower()

    download_url = asset.get("browser_download_url")
    if not isinstance(download_url, str) or not download_url.startswith("https://"):
        raise RuntimeError(f"asset {asset.get('name')!r} has no safe download URL or digest")
    try:
        # Release assets are public. Deliberately omit the GitHub token so it
        # cannot be forwarded to the release asset CDN during redirects.
        with urllib.request.urlopen(
            github_request(download_url, None, "application/octet-stream"), timeout=120
        ) as response:
            return sha256_stream(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"failed to download existing asset {asset.get('name')!r}: {exc}") from exc


def append_output(path: pathlib.Path | None, upload_required: bool) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"upload-required={'true' if upload_required else 'false'}\n")


def main() -> int:
    args = parse_args()
    if not REPOSITORY.fullmatch(args.repository):
        raise SystemExit("--repository must use owner/repository syntax")

    local: dict[str, pathlib.Path] = {}
    for raw_path in args.assets:
        path = raw_path.resolve()
        if not path.is_file():
            raise SystemExit(f"local release asset is missing: {raw_path}")
        if path.name in local:
            raise SystemExit(f"duplicate local release asset name: {path.name}")
        local[path.name] = path

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    release = fetch_release(args.repository, args.tag, token)
    if release is None:
        if args.require_complete:
            raise SystemExit(f"GitHub release {args.tag} does not exist")
        append_output(args.github_output, True)
        print(f"release {args.tag} does not exist yet; {len(local)} assets require upload")
        return 0

    remote: dict[str, dict[str, Any]] = {}
    for asset in release["assets"]:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise SystemExit("GitHub release contains an asset with an invalid schema")
        name = asset["name"]
        if name in remote:
            raise SystemExit(f"GitHub release contains duplicate asset name: {name}")
        remote[name] = asset

    missing: list[str] = []
    for name, path in sorted(local.items()):
        existing = remote.get(name)
        if existing is None:
            missing.append(name)
            continue
        local_digest = sha256_file(path)
        existing_digest = remote_sha256(existing)
        if existing_digest != local_digest:
            raise SystemExit(
                f"immutable release asset mismatch for {name}: "
                f"remote sha256={existing_digest}, local sha256={local_digest}"
            )
        print(f"existing release asset matches exactly and will be reused: {name}")

    if missing and args.require_complete:
        raise SystemExit("GitHub release is missing required assets: " + ", ".join(missing))
    append_output(args.github_output, bool(missing))
    if missing:
        print("release assets requiring upload: " + ", ".join(missing))
    else:
        print("all release assets already exist with matching SHA-256 values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
