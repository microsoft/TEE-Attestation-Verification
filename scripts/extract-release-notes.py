#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import argparse
import pathlib
import re
import sys


VERSION_HEADING = re.compile(
    r"^##\s+\[?v?(\d+\.\d+\.\d+(?:[-+][^\]\s]+)?)\]?"
)


class ReleaseNotesError(Exception):
    """Expected failure while extracting release notes."""


def extract_release_notes(changelog: str, version: str) -> str:
    lines = changelog.splitlines()
    start = None
    end = len(lines)

    for index, line in enumerate(lines):
        match = VERSION_HEADING.match(line)
        if match is None:
            continue
        if start is None:
            if match.group(1) == version:
                start = index + 1
        else:
            end = index
            break

    if start is None:
        raise ReleaseNotesError(f"CHANGELOG.md has no section for version {version}")

    link_definition = re.compile(rf"^\[v?{re.escape(version)}\]:\s+")
    notes = [line for line in lines[start:end] if not link_definition.match(line)]
    result = "\n".join(notes).strip()
    if not result:
        raise ReleaseNotesError(
            f"CHANGELOG.md section for version {version} has no release notes"
        )
    return result + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract one version's GitHub release notes from CHANGELOG.md."
    )
    parser.add_argument("--changelog", type=pathlib.Path, default="CHANGELOG.md")
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    try:
        notes = extract_release_notes(
            args.changelog.read_text(encoding="utf-8"), args.version
        )
    except (OSError, ReleaseNotesError) as error:
        print(error, file=sys.stderr)
        return 1

    if args.output is None:
        sys.stdout.write(notes)
    else:
        args.output.write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
