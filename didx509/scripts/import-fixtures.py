#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Refresh pinned upstream conformance fixtures using only the Python standard library."""

import hashlib
import json
import base64
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "did-x509": (
        "microsoft/did-x509",
        "471c7ca05824f6b25b010a0c4da6cab85ad55dcf",
        ["test-vectors.json", "specification.md", "LICENSE"],
    ),
    "didx509cpp": (
        "microsoft/didx509cpp",
        "f754568baebcba3c39e62fdfe47beed3357b72a7",
        [
            "LICENSE",
            "test/test-data/cn-embedded-nul.pem",
            "test/test-data/cn-utf8.pem",
            "test/test-data/custom-oid-subject.pem",
            "test/test-data/dns-san.pem",
            "test/test-data/ec-leading-zero.pem",
            "test/test-data/fulcio-email.pem",
            "test/test-data/fulcio-github-actions.pem",
            "test/test-data/ms-code-signing.pem",
            "test/test-data/ms-test.pem",
            "test/test-data/san-subject-fallback.pem",
            "test/test-data/uri-san-embedded-nul.pem",
            "test/test-data/utf8-subject.pem",
            "test/test-data/wildcard-dns-san.pem",
        ],
    ),
}


def main():
    for name, (repository, revision, paths) in SOURCES.items():
        destination = ROOT / "fixtures" / "upstream" / name
        destination.mkdir(parents=True, exist_ok=True)
        manifest = {"repository": repository, "revision": revision, "files": {}}
        for path in paths:
            url = f"https://raw.githubusercontent.com/{repository}/{revision}/{path}"
            with urlopen(url, timeout=60) as response:
                data = response.read()
            filename = Path(path).name
            (destination / filename).write_bytes(data)
            manifest["files"][filename] = {
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        (destination / "source.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Imported {len(paths)} files from {repository}@{revision}")
    vectors_path = ROOT / "fixtures/upstream/did-x509/test-vectors.json"
    times = {}
    for vector in json.loads(vectors_path.read_text()):
        starts, ends = [], []
        for encoded in vector["input"]["chain"]:
            der = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            result = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-noout", "-dates"],
                input=der, capture_output=True, check=True,
            )
            dates = [
                datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
                .replace(tzinfo=timezone.utc).timestamp()
                for line in result.stdout.decode().splitlines()
            ]
            starts.append(int(dates[0]))
            ends.append(int(dates[1]))
        if starts:
            start, end = max(starts), min(ends)
            if start > end:
                raise ValueError(f"No common validity interval: {vector['id']}")
            times[vector["id"]] = start + (end - start) // 2
        else:
            times[vector["id"]] = 1785542400
    (vectors_path.parent / "validation-times.json").write_text(
        json.dumps(times, indent=2) + "\n", encoding="utf-8"
    )
    cpp = ROOT / "fixtures/upstream/didx509cpp"
    times = {}
    for path in cpp.glob("*.pem"):
        blocks = path.read_bytes().split(b"-----END CERTIFICATE-----")
        starts, ends = [], []
        for block in blocks:
            if not block.strip():
                continue
            result = subprocess.run(
                ["openssl", "x509", "-noout", "-dates"],
                input=block + b"-----END CERTIFICATE-----", capture_output=True, check=True,
            )
            dates = [
                int(datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
                    .replace(tzinfo=timezone.utc).timestamp())
                for line in result.stdout.decode().splitlines()
            ]
            starts.append(dates[0])
            ends.append(dates[1])
        start, end = max(starts), min(ends)
        if start > end:
            raise ValueError(f"No common validity interval: {path.name}")
        times[path.name] = start + (end - start) // 2
    (cpp / "validation-times.json").write_text(json.dumps(times, indent=2) + "\n")


if __name__ == "__main__":
    main()
