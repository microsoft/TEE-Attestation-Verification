# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "extract-release-notes.py"
SPEC = importlib.util.spec_from_file_location("extract_release_notes", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExtractReleaseNotesTest(unittest.TestCase):
    def test_extracts_only_requested_version_body(self) -> None:
        changelog = """\
# Changelog

## [1.2.0] - 2026-09-02

[1.2.0]: https://example.test/1.2.0

### Added

- New feature.

## [1.1.0]

### Fixed

- Old fix.
"""

        self.assertEqual(
            MODULE.extract_release_notes(changelog, "1.2.0"),
            "### Added\n\n- New feature.\n",
        )

    def test_extracts_latest_repository_changelog_entry(self) -> None:
        changelog_path = SCRIPT_PATH.parents[1] / "CHANGELOG.md"
        changelog = changelog_path.read_text(encoding="utf-8")
        latest = next(
            match.group(1)
            for line in changelog.splitlines()
            if (match := MODULE.VERSION_HEADING.match(line)) is not None
        )

        self.assertTrue(MODULE.extract_release_notes(changelog, latest).strip())

    def test_rejects_missing_version(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ReleaseNotesError, "has no section for version 2.0.0"
        ):
            MODULE.extract_release_notes("## [1.0.0]\n\n- Initial release.\n", "2.0.0")

    def test_rejects_empty_section(self) -> None:
        changelog = """\
## [1.2.0]

[1.2.0]: https://example.test/1.2.0

## [1.1.0]

- Old fix.
"""

        with self.assertRaisesRegex(MODULE.ReleaseNotesError, "has no release notes"):
            MODULE.extract_release_notes(changelog, "1.2.0")


if __name__ == "__main__":
    unittest.main()
