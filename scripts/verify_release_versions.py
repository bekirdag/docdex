#!/usr/bin/env python3
"""Verify that every shipped Docdex version surface is synchronized."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib
from typing import Any


PROMPT_HEADER = re.compile(r"---- START OF DOCDEX INFO V([^ ]+) ----")


def read_json(root: pathlib.Path, path: str) -> dict[str, Any]:
    return json.loads((root / path).read_text(encoding="utf-8"))


def prompt_version(root: pathlib.Path, path: str) -> str | None:
    lines = (root / path).read_text(encoding="utf-8").splitlines()
    if not lines:
        return None
    match = PROMPT_HEADER.fullmatch(lines[0])
    return match.group(1) if match else None


def changelog_has_version(root: pathlib.Path, path: str, version: str) -> bool:
    text = (root / path).read_text(encoding="utf-8")
    return re.search(rf"^## {re.escape(version)}$", text, flags=re.MULTILINE) is not None


def version_surfaces(root: pathlib.Path) -> tuple[str, dict[str, str | None]]:
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    expected = cargo["package"]["version"]
    cargo_lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    root_package = read_json(root, "package.json")
    npm_package = read_json(root, "npm/package.json")
    npm_lock = read_json(root, "npm/package-lock.json")
    release_manifest = read_json(root, ".release-please-manifest.json")
    server = read_json(root, "server.json")
    server_card = read_json(root, ".well-known/mcp/server-card.json")
    legacy_server_card = read_json(root, ".well-known/mcp.json")
    cargo_lock_version = next(
        (
            package["version"]
            for package in cargo_lock["package"]
            if package["name"] == "docdexd"
        ),
        None,
    )
    server_packages = server.get("packages") or [{}]

    return expected, {
        "Cargo.lock docdexd": cargo_lock_version,
        "package.json": root_package.get("version"),
        "npm/package.json": npm_package.get("version"),
        "npm/package-lock.json": npm_lock.get("version"),
        "npm/package-lock.json packages['']": (npm_lock.get("packages") or {})
        .get("", {})
        .get("version"),
        ".release-please-manifest.json .": release_manifest.get("."),
        ".release-please-manifest.json npm": release_manifest.get("npm"),
        "server.json": server.get("version"),
        "server.json packages[0]": server_packages[0].get("version"),
        ".well-known/mcp/server-card.json": server_card.get("version"),
        ".well-known/mcp/server-card.json serverInfo": (
            server_card.get("serverInfo") or {}
        ).get("version"),
        ".well-known/mcp.json": legacy_server_card.get("version"),
        ".well-known/mcp.json serverInfo": (
            legacy_server_card.get("serverInfo") or {}
        ).get("version"),
        "AGENTS.md prompt header": prompt_version(root, "AGENTS.md"),
        "AGENT_PROMPT.md prompt header": prompt_version(root, "AGENT_PROMPT.md"),
        "npm/assets/agents.md prompt header": prompt_version(
            root, "npm/assets/agents.md"
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    parser.add_argument(
        "--tag",
        help="optional release tag, which must equal v<Cargo.toml version>",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    expected, surfaces = version_surfaces(root)
    mismatches = [
        (name, value) for name, value in surfaces.items() if value != expected
    ]
    if args.tag is not None and args.tag != f"v{expected}":
        mismatches.append(("release tag", args.tag))

    identity_errors: list[str] = []
    npm_package = read_json(root, "npm/package.json")
    server = read_json(root, "server.json")
    mcp_name = npm_package.get("mcpName")
    server_name = server.get("name")
    if not isinstance(mcp_name, str) or not mcp_name:
        identity_errors.append("npm/package.json mcpName must be a non-empty string")
    elif mcp_name != server_name:
        identity_errors.append(
            f"MCP identity mismatch: npm/package.json mcpName={mcp_name!r}; "
            f"server.json name={server_name!r}"
        )

    for changelog in ("CHANGELOG.md", "npm/CHANGELOG.md"):
        if not changelog_has_version(root, changelog, expected):
            identity_errors.append(
                f"{changelog} is missing an exact '## {expected}' release heading"
            )

    if mismatches or identity_errors:
        for name, value in mismatches:
            print(
                f"version mismatch: {name}={value!r}; expected {expected!r}",
                file=sys.stderr,
            )
        for error in identity_errors:
            print(error, file=sys.stderr)
        return 1

    suffix = f" and tag {args.tag}" if args.tag else ""
    print(f"release version surfaces are synchronized at {expected}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
