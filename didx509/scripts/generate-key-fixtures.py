#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Generate public certificate fixtures; ephemeral private keys never leave the temp directory."""

import argparse
from datetime import datetime, timezone
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "fixtures/keys"


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsupported-key-only", action="store_true",
                        help="regenerate only the Ed25519 leaf used by validation-only tests")
    args = parser.parse_args()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="didx509-key-fixtures-") as directory:
        work = Path(directory)
        for name, algorithm, option, digest, leaf_algorithm in [
            ("rsa", "RSA", "rsa_keygen_bits:2048", "-sha256", None),
            ("p256", "EC", "ec_paramgen_curve:P-256", "-sha256", None),
            ("p384-sha256", "EC", "ec_paramgen_curve:P-384", "-sha256", None),
            ("p521", "EC", "ec_paramgen_curve:P-521", "-sha512", None),
            ("ed25519-leaf", "RSA", "rsa_keygen_bits:2048", "-sha256", "ED25519"),
        ]:
            if args.unsupported_key_only and leaf_algorithm is None:
                continue
            key, root, csr, leaf = (work / item for item in ["key.pem", "root.pem", "leaf.csr", "leaf.pem"])
            run("openssl", "genpkey", "-algorithm", algorithm, "-pkeyopt", option, "-out", str(key))
            run("openssl", "req", "-new", "-x509", "-key", str(key), "-subj", "/CN=Fixture Root",
                "-days", "3650", digest, "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign", "-out", str(root))
            leaf_key = key
            if leaf_algorithm is not None:
                leaf_key = work / "leaf-key.pem"
                run("openssl", "genpkey", "-algorithm", leaf_algorithm, "-out", str(leaf_key))
            run("openssl", "req", "-new", "-key", str(leaf_key), "-subj", "/CN=Fixture Leaf", "-out", str(csr))
            run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(root), "-CAkey", str(key),
                "-set_serial", "2", "-days", "3650", digest, "-out", str(leaf))
            (OUTPUT / f"{name}.pem").write_bytes(leaf.read_bytes() + root.read_bytes())
            # Fixed time in the certificates' common validity interval, not wall-clock test time.
            start = run("openssl", "x509", "-in", str(leaf), "-noout", "-startdate").decode().strip().split("=", 1)[1]
            timestamp = int(datetime.strptime(start, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).timestamp()) + 60
            time_file = "ed25519-validation-time.json" if leaf_algorithm else "validation-time.json"
            (OUTPUT / time_file).write_text(json.dumps(timestamp) + "\n")


if __name__ == "__main__":
    main()
