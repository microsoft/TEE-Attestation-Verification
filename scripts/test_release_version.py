# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("check-version-sync.py")


class PrintVersionTests(unittest.TestCase):
    def create_repository(self, root: pathlib.Path, package_version: str) -> None:
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [1.2.3] - 2026-07-29\n",
            encoding="utf-8",
        )
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crate"]\n',
            encoding="utf-8",
        )
        package = root / "crate"
        package.mkdir()
        (package / "Cargo.toml").write_text(
            f'[package]\nname = "example"\nversion = "{package_version}"\n',
            encoding="utf-8",
        )

    def run_checker(self, root: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--root-path",
                str(root),
                "--print-version",
            ],
            capture_output=True,
            text=True,
        )

    def test_prints_validated_changelog_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.create_repository(root, "1.2.3")

            result = self.run_checker(root)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("1.2.3\n", result.stdout)

    def test_rejects_unsynchronized_package_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.create_repository(root, "9.9.9")

            result = self.run_checker(root)

            self.assertEqual(1, result.returncode)
            self.assertIn("does not match", result.stderr)
            self.assertEqual("", result.stdout)


if __name__ == "__main__":
    unittest.main()
