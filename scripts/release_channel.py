#!/usr/bin/env python3
"""Select a publication channel from a validated semantic release tag."""
import argparse
import json
import pathlib
import re


def publication_channel(tag: str) -> dict[str, str]:
    match = re.fullmatch(
        r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?", tag
    )
    if match is None:
        raise ValueError("release tag must be v<semantic version> without build metadata")
    suffix = match.group(4)
    if suffix and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in suffix.split(".")):
        raise ValueError("numeric prerelease identifiers cannot have leading zeros")
    return {"prerelease": "true" if suffix else "false", "npm_dist_tag": "next" if suffix else "latest"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--github-output", type=pathlib.Path)
    args = parser.parse_args()
    channel = publication_channel(args.tag)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for key, value in channel.items():
                output.write(f"{key}={value}\n")
    print(json.dumps(channel))
