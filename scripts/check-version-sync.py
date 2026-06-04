#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import glob
import pathlib
import re
import sys
import tomllib
from collections.abc import Iterator
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION_HEADING = re.compile(
    r"^##\s+\[?v?(\d+\.\d+\.\d+(?:[-+][^\]\s]+)?)\]?",
    re.MULTILINE,
)


class VersionSyncError(Exception):
    """Expected validation failure for the version-sync check."""


def relative_path(path: pathlib.Path) -> pathlib.Path:
    return path.relative_to(ROOT)


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise VersionSyncError(f"Failed to read {relative_path(path)}: {error}") from error


def latest_changelog_version() -> str:
    changelog = read_text(ROOT / "CHANGELOG.md")
    latest = VERSION_HEADING.search(changelog)
    if latest is None:
        raise VersionSyncError(
            "Could not find a version heading like '## [1.2.3]' in CHANGELOG.md"
        )
    return latest.group(1)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as error:
        raise VersionSyncError(f"Failed to parse {relative_path(path)}: {error}") from error


def workspace_manifest_paths() -> list[pathlib.Path]:
    workspace_manifest = ROOT / "Cargo.toml"
    workspace = load_toml(workspace_manifest)
    workspace_members = workspace.get("workspace", {}).get("members")
    if not isinstance(workspace_members, list):
        raise VersionSyncError("Cargo.toml must define [workspace].members")

    manifest_paths = []

    if "package" in workspace:
        manifest_paths.append(workspace_manifest)

    for member in workspace_members:
        matches = glob.glob(str(ROOT / member))
        if not matches:
            raise VersionSyncError(f"Workspace member pattern matched nothing: {member}")
        manifest_paths.extend(pathlib.Path(match) / "Cargo.toml" for match in matches)

    return sorted(set(manifest_paths))


def dependency_sections(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield section, data.get(section, {})

    for target_name, target in data.get("target", {}).items():
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield f"target.{target_name}.{section}", target.get(section, {})


def check_version_sync() -> None:
    changelog_version = latest_changelog_version()
    manifests = {
        manifest_path: load_toml(manifest_path) for manifest_path in workspace_manifest_paths()
    }
    package_versions = {}
    errors = []
    for manifest_path, data in manifests.items():
        package = data.get("package")
        if package is None:
            continue

        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise VersionSyncError(
                f"{relative_path(manifest_path)}: [package] must define string name and version"
            )

        package_versions[name] = version

        if version != changelog_version:
            errors.append(
                f"{relative_path(manifest_path)}: package {name} version {version} "
                f"does not match CHANGELOG.md latest version {changelog_version}"
            )

    for manifest_path, data in manifests.items():
        for section, dependencies in dependency_sections(data):
            for alias, spec in dependencies.items():
                if isinstance(spec, str):
                    package_name = alias
                    actual_version = spec
                elif isinstance(spec, dict):
                    package_name = spec.get("package", alias)
                    actual_version = spec.get("version")
                else:
                    continue

                expected_version = package_versions.get(package_name)
                if expected_version is None:
                    continue
                if actual_version != expected_version:
                    errors.append(
                        f"{relative_path(manifest_path)}: {section}.{alias} points at internal "
                        f"package {package_name} but version is {actual_version!r}; "
                        f"expected {expected_version!r}"
                    )

    if errors:
        raise VersionSyncError("\n".join(errors))

    print(f"All Cargo package versions and internal dependency versions match {changelog_version}")


def main() -> int:
    try:
        check_version_sync()
    except VersionSyncError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
