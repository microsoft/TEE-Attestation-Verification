#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Generate or check the exported C ABI symbols of a shared library.

The canonical export list is the set of dynamic, defined symbols whose names
begin with ``tav_``, one per line, sorted in C (ASCII) order. Reducing the raw
``nm`` output to this canonical form strips per-build metadata (symbol
addresses and types) and non-deterministic ordering, so the result can be
diffed against a checked-in golden file.

Only symbols with the ``tav_`` prefix are considered: a Rust ``cdylib`` exports
just its ``#[no_mangle] pub extern`` functions today, but filtering keeps the
golden stable even if a future toolchain starts leaking runtime symbols such as
``rust_eh_personality``.

Run against the shared library (``.so``); a static archive (``.a``) also lists
internal object symbols and is not a canonical ABI surface.
"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import subprocess
import sys


SYMBOL_PREFIX = "tav_"


class ExportsError(Exception):
    """Expected validation failure for the exports check."""


def canonical_exports(library: pathlib.Path) -> list[str]:
    if not library.is_file():
        raise ExportsError(f"Library not found: {library}")

    try:
        result = subprocess.run(
            ["nm", "-D", "--defined-only", str(library)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise ExportsError("`nm` not found; install binutils") from error
    except subprocess.CalledProcessError as error:
        raise ExportsError(
            f"nm failed for {library}: {error.stderr.strip()}"
        ) from error

    symbols = set()
    for line in result.stdout.splitlines():
        # Defined symbols are printed as "<address> <type> <name>".
        fields = line.split()
        if len(fields) != 3:
            continue
        name = fields[2]
        if name.startswith(SYMBOL_PREFIX):
            symbols.add(name)

    return sorted(symbols)


def render(symbols: list[str]) -> str:
    return "".join(f"{symbol}\n" for symbol in symbols)


def update_golden(library: pathlib.Path, golden: pathlib.Path) -> None:
    symbols = canonical_exports(library)
    golden.write_text(render(symbols), encoding="utf-8")
    print(f"Wrote {len(symbols)} exported {SYMBOL_PREFIX} symbols to {golden}")


def check_golden(library: pathlib.Path, golden: pathlib.Path) -> None:
    if not golden.is_file():
        raise ExportsError(
            f"Golden file not found: {golden} (run with --update to create it)"
        )

    actual = canonical_exports(library)
    expected = golden.read_text(encoding="utf-8").splitlines()

    if actual != expected:
        diff = difflib.unified_diff(
            expected,
            actual,
            fromfile=str(golden),
            tofile=f"{library} (actual)",
            lineterm="",
        )
        raise ExportsError(
            "Exported C ABI symbols do not match the golden file:\n"
            + "\n".join(diff)
            + f"\n\nIf this change is intentional, regenerate with "
            f"--update and commit {golden}."
        )

    print(f"{library}: {len(actual)} exported {SYMBOL_PREFIX} symbols match {golden}")


def main() -> int:
    argparser = argparse.ArgumentParser(
        description="Check that a shared library's exported C ABI symbols match a golden file"
    )
    argparser.add_argument(
        "--library",
        required=True,
        type=pathlib.Path,
        help="Path to the shared library (.so) to inspect",
    )
    argparser.add_argument(
        "--golden",
        required=True,
        type=pathlib.Path,
        help="Path to the golden exports file",
    )
    argparser.add_argument(
        "--update",
        action="store_true",
        help="Write the canonical export list to the golden file instead of checking it",
    )

    args = argparser.parse_args()

    try:
        if args.update:
            update_golden(args.library, args.golden)
        else:
            check_golden(args.library, args.golden)
    except ExportsError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
