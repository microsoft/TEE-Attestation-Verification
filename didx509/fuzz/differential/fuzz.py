#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Differential fuzzer: resolve generated did:x509 cases with didx509cpp and TAV.

Each iteration builds a valid signed chain and a matching DID, then either keeps it
or applies one mutation so the negative case is one edit away from a valid one.
The parent must resolve successfully in both oracles before mutation. Each
mutation has explicit expected outcomes, and accepted keys must match the parent.
Failures are written to fuzz/differential/failures/<seed>-<index>/ for replay.

Uses only the Python standard library and the openssl command-line tool.
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
BUILD = HERE / "target"
FAILURES = HERE / "failures"

CPP_REPOSITORY = "microsoft/didx509cpp"
CPP_REVISION = "f754568baebcba3c39e62fdfe47beed3357b72a7"
CPP_HEADER_SHA256 = "071f7a37b1856da23b880e247ae6a165b3ff19fc08ec0e9f184276dc587a3aaa"

CPP_EKU_CODE_SIGNING = "1.3.6.1.4.1.311.76.59.1.2"
FULCIO_ISSUER_OID = "1.3.6.1.4.1.57264.1.1"

# Expected (C++, Rust) acceptance. The fragment case is the only allowed divergence:
# the pinned C++ rejects fragments accepted by specification.md line 74.
EXPECTED_OUTCOMES = {
    "none": (True, True),
    "wrong-fingerprint": (False, False),
    "leaf-fingerprint": (False, False),
    "predicate-case": (False, False),
    "predicate-suffix": (False, False),
    "san-kind": (False, False),
    "reorder": (False, False),
    "truncate": (False, False),
    "unrelated-ca": (False, False),
    "expired-leaf": (False, False),
    "fragment": (False, True),
    "algorithm-mismatch": (False, False),
    "repeated-subject": (True, True),
    "empty-value": (False, False),
}

SUBJECT_KEYS = [("CN", "CN"), ("O", "O"), ("OU", "OU"), ("L", "L"), ("ST", "ST")]
WORDS = ["Contoso", "Fabrikam", "caf\u00e9", "\u6771\u4eac", "Test Leaf", "a.b-c_d", "Ltd", "Dev Ops"]
DNS_NAMES = ["example.com", "leaf.example.test", "*.wild.example"]
EMAILS = ["dev@example.com", "ops+ci@example.test"]
URIS = ["https://example.com/anchor", "spiffe://trust.example/workload"]
EKUS = ["serverAuth", "clientAuth", "codeSigning", CPP_EKU_CODE_SIGNING, "1.2.3.4.5"]
ISSUERS = ["https://token.actions.githubusercontent.com", "https://accounts.example.test"]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def percent_encode(value):
    return "".join(
        chr(byte) if chr(byte).isalnum() and byte < 128 or chr(byte) in "-._" else f"%{byte:02X}"
        for byte in value.encode()
    )


def base64url(data):
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fingerprint(der, algorithm):
    return base64url(hashlib.new(algorithm, der).digest())


class Toolchain:
    """Builds both oracles once; certificate keys come from a shared pool."""

    def __init__(self, work):
        self.work = work
        if "not_before" not in subprocess.run(["openssl", "x509", "-help"], capture_output=True, text=True).stderr:
            sys.exit("openssl >= 3.4 is required on PATH (x509 -not_before/-not_after)")
        BUILD.mkdir(parents=True, exist_ok=True)
        self.cpp = self.build_cpp()
        self.rust = self.build_rust()
        self.keys = {}
        for name, algorithm, option in [
            ("rsa2048", "RSA", "rsa_keygen_bits:2048"),
            ("p256", "EC", "ec_paramgen_curve:P-256"),
            ("p384", "EC", "ec_paramgen_curve:P-384"),
            ("p521", "EC", "ec_paramgen_curve:P-521"),
        ]:
            path = work / f"{name}.key"
            run("openssl", "genpkey", "-algorithm", algorithm, "-pkeyopt", option, "-out", str(path))
            self.keys[name] = path
        # A key nobody in the chain uses, so "unrelated-ca" can present a stranger as anchor.
        self.stranger_key = work / "stranger.key"
        run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(self.stranger_key))

    def build_cpp(self):
        header = BUILD / "didx509cpp.h"
        if not header.exists() or hashlib.sha256(header.read_bytes()).hexdigest() != CPP_HEADER_SHA256:
            url = f"https://raw.githubusercontent.com/{CPP_REPOSITORY}/{CPP_REVISION}/didx509cpp.h"
            with urlopen(url, timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != CPP_HEADER_SHA256:
                sys.exit("didx509cpp.h hash mismatch; refusing to build the oracle")
            header.write_bytes(data)
        binary = BUILD / "cpp-oracle"
        source = HERE / "oracle.cpp"
        if not binary.exists() or binary.stat().st_mtime < max(source.stat().st_mtime, header.stat().st_mtime):
            flags = run("pkg-config", "--cflags", "--libs", "openssl").decode().split()
            run("g++", "-std=c++20", "-O1", "-I", str(BUILD), str(source), "-o", str(binary), *flags)
        return binary

    def build_rust(self):
        environment = os.environ.copy()
        cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1
        environment.setdefault("CARGO_BUILD_JOBS", str((cpus + 1) // 2))
        run("cargo", "build", "--locked", "--quiet", "--manifest-path", str(HERE / "Cargo.toml"),
            "--target-dir", str(BUILD / "rust"), cwd=HERE, env=environment)
        return BUILD / "rust/debug/didx509-rust-oracle"


class Case:
    """One generated chain (leaf first) plus DID, with the values needed to mutate it."""

    def __init__(self, toolchain, rng, index):
        self.toolchain = toolchain
        self.rng = rng
        self.dir = toolchain.work / f"case-{index}"
        self.dir.mkdir()
        self.certs = []  # (pem_path, key_path, subject attrs, sans, ekus, key usage)
        self.mutation = "none"

    def subject(self):
        picked = self.rng.sample(SUBJECT_KEYS, self.rng.randint(1, 3))
        attrs = [(key, self.rng.choice(WORDS)) for key, _ in picked]
        if not any(key == "CN" for key, _ in attrs):
            attrs.insert(0, ("CN", self.rng.choice(WORDS)))
        return attrs

    @staticmethod
    def subj_arg(attrs):
        return "".join(f"/{key}={value}" for key, value in attrs)

    def issue(self, name, key, attrs, issuer=None, ca=False, sans=(), ekus=(), key_usage=None,
              fulcio_issuer=None, days=365, start_offset_days=0):
        pem = self.dir / f"{name}.pem"
        ext = [f"basicConstraints=critical,CA:{'TRUE' if ca else 'FALSE'}"]
        if ca:
            ext.append("keyUsage=critical,keyCertSign,cRLSign")
        elif key_usage:
            ext.append(f"keyUsage=critical,{key_usage}")
        if sans:
            ext.append("subjectAltName=" + ",".join(f"{kind}:{value}" for kind, value in sans))
        if ekus:
            ext.append("extendedKeyUsage=" + ",".join(ekus))
        if fulcio_issuer:
            # Legacy Fulcio issuer (OID .1.1) is raw bytes inside the extension, not an IA5String.
            ext.append(f"{FULCIO_ISSUER_OID}=DER:{fulcio_issuer.encode().hex()}")
        extfile = self.dir / f"{name}.ext"
        extfile.write_text("\n".join(ext) + "\n")
        digest = self.rng.choice(["-sha256", "-sha384", "-sha512"])
        if issuer is None:
            run("openssl", "req", "-new", "-x509", "-utf8", "-key", str(key), "-subj", self.subj_arg(attrs),
                "-days", str(days), digest, "-extensions", "v3", "-config", str(self.req_config(extfile)),
                "-out", str(pem))
        else:
            issuer_pem, issuer_key = issuer
            csr = self.dir / f"{name}.csr"
            run("openssl", "req", "-new", "-utf8", "-key", str(key), "-subj", self.subj_arg(attrs), "-out", str(csr))
            if start_offset_days:
                stamp = lambda days: time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + days * 86400))
                validity = ["-not_before", stamp(start_offset_days), "-not_after", stamp(start_offset_days + days)]
            else:
                validity = ["-days", str(days)]
            run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer_pem), "-CAkey", str(issuer_key),
                "-set_serial", str(self.rng.randint(2, 2**62)), digest, "-extfile", str(extfile),
                "-out", str(pem), *validity)
        self.certs.insert(0, (pem, key, attrs, list(sans), list(ekus), key_usage, fulcio_issuer))
        return pem

    def req_config(self, extfile):
        config = self.dir / "req.cnf"
        config.write_text(
            "[req]\ndistinguished_name=dn\nutf8=yes\nstring_mask=utf8only\n[dn]\n[v3]\n" + extfile.read_text()
        )
        return config

    def build_valid(self):
        rng = self.rng
        key_names = list(self.toolchain.keys)
        depth = rng.choice([2, 2, 3, 4])
        root_key = self.toolchain.keys[rng.choice(key_names)]
        issuer_pem = self.issue("ca0", root_key, self.subject(), ca=True, days=3650)
        issuer = (issuer_pem, root_key)
        for level in range(1, depth - 1):
            key = self.toolchain.keys[rng.choice(key_names)]
            issuer = (self.issue(f"ca{level}", key, self.subject(), issuer=issuer, ca=True, days=1000), key)
        leaf_key = self.toolchain.keys[rng.choice(key_names)]
        sans = []
        if rng.random() < 0.6:
            sans.append(("DNS", rng.choice(DNS_NAMES)))
        if rng.random() < 0.4:
            sans.append(("email", rng.choice(EMAILS)))
        if rng.random() < 0.4:
            sans.append(("URI", rng.choice(URIS)))
        ekus = rng.sample(EKUS, rng.randint(0, 2))
        key_usage = rng.choice([None, "digitalSignature", "keyAgreement", "digitalSignature,keyAgreement",
                                "digitalSignature,keyEncipherment"])
        fulcio = rng.choice(ISSUERS) if rng.random() < 0.3 else None
        self.issue("leaf", leaf_key, self.subject(), issuer=issuer, sans=sans, ekus=ekus,
                   key_usage=key_usage, fulcio_issuer=fulcio)
        self.did = self.make_did()

    def der(self, pem):
        return run("openssl", "x509", "-in", str(pem), "-outform", "DER")

    def make_did(self, ca_index=None, algorithm=None):
        rng = self.rng
        cas = self.certs[1:]
        ca = cas[rng.randrange(len(cas)) if ca_index is None else ca_index]
        algorithm = algorithm or rng.choice(["sha256", "sha256", "sha384", "sha512"])
        _, _, attrs, sans, ekus, _, fulcio = self.certs[0]
        predicates = []
        options = ["subject"]
        if sans:
            options.append("san")
        if ekus:
            options.append("eku")
        if fulcio:
            options.append("fulcio")
        for kind in rng.sample(options, rng.randint(1, len(options))):
            if kind == "subject":
                chosen = rng.sample(attrs, rng.randint(1, len(attrs)))
                predicates.append("subject:" + ":".join(f"{k}:{percent_encode(v)}" for k, v in chosen))
            elif kind == "san":
                san_kind, value = rng.choice(sans)
                predicates.append(f"san:{san_kind.lower()}:{percent_encode(value)}")
            elif kind == "eku":
                eku = rng.choice(ekus)
                predicates.append("eku:" + {"serverAuth": "1.3.6.1.5.5.7.3.1", "clientAuth": "1.3.6.1.5.5.7.3.2",
                                            "codeSigning": "1.3.6.1.5.5.7.3.3"}.get(eku, eku))
            else:
                predicates.append("fulcio-issuer:" + percent_encode(fulcio.removeprefix("https://")))
        return f"did:x509:0:{algorithm}:{fingerprint(self.der(ca[0]), algorithm)}::" + "::".join(predicates)

    def chain_pem(self):
        return b"".join(pem.read_bytes() for pem, *_ in self.certs)

    def mutate(self):
        """Apply one mutation. Returns the (did, chain_pem_bytes) to test."""
        rng = self.rng
        did = self.did
        chain = self.chain_pem()
        self.mutation = rng.choice(["none", "none", *EXPECTED_OUTCOMES])
        m = self.mutation
        prefix, predicates = did.split("::", 1)
        if m == "wrong-fingerprint":
            parts = prefix.split(":")
            parts[4] = base64url(rng.randbytes(len(hashlib.new(parts[3]).digest())))
            did = ":".join(parts) + "::" + predicates
        elif m == "leaf-fingerprint":
            parts = prefix.split(":")
            parts[4] = fingerprint(self.der(self.certs[0][0]), parts[3])
            did = ":".join(parts) + "::" + predicates
        elif m == "predicate-case":
            cn = dict(self.certs[0][2])["CN"]
            if cn.swapcase() != cn:
                did += "::subject:CN:" + percent_encode(cn.swapcase())
            else:
                self.mutation = "none"
        elif m == "predicate-suffix":
            did = did + "x"
        elif m == "san-kind":
            for a, b in [("san:dns:", "san:uri:"), ("san:email:", "san:dns:"), ("san:uri:", "san:email:")]:
                if a in predicates:
                    did = prefix + "::" + predicates.replace(a, b, 1)
                    break
            else:
                self.mutation = "none"
        elif m == "reorder":
            blocks = [pem.read_bytes() for pem, *_ in self.certs]
            chain = b"".join(reversed(blocks))
        elif m == "truncate":
            chain = self.certs[0][0].read_bytes()
        elif m == "unrelated-ca":
            # Same DID (fingerprint of the real root), but the anchor presented is a stranger.
            real = list(self.certs)
            stranger = self.issue("stranger", self.toolchain.stranger_key, [("CN", "Stranger Root")],
                                  ca=True, days=3650)
            self.certs = real
            chain = b"".join(pem.read_bytes() for pem, *_ in real[:-1]) + stranger.read_bytes()
        elif m == "expired-leaf":
            leaf_pem, leaf_key, attrs, sans, ekus, key_usage, fulcio = self.certs[0]
            issuer = (self.certs[1][0], self.certs[1][1])
            self.certs.pop(0)
            self.issue("leaf-expired", leaf_key, attrs, issuer=issuer, sans=sans, ekus=ekus,
                       key_usage=key_usage, fulcio_issuer=fulcio, days=10, start_offset_days=-30)
            chain = self.chain_pem()
        elif m == "fragment":
            did = did + "#0"
        elif m == "algorithm-mismatch":
            parts = prefix.split(":")
            parts[3] = {"sha256": "sha384", "sha384": "sha512", "sha512": "sha256"}[parts[3]]
            did = ":".join(parts) + "::" + predicates
        elif m == "repeated-subject":
            # Repeating a satisfied predicate is valid, unlike duplicate fields within one.
            cn = percent_encode(dict(self.certs[0][2])["CN"])
            did += f"::subject:CN:{cn}::subject:CN:{cn}"
        elif m == "empty-value":
            did = did + "::san:dns:"
        return did, chain


def run_oracle(binary, did, chain_path):
    try:
        output = subprocess.run([str(binary), did, str(chain_path)], capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
    except (subprocess.TimeoutExpired, OSError, UnicodeDecodeError) as error:
        return {"ok": None, "detail": f"{type(error).__name__}: {error}"}
    if output.returncode != 0:
        return {"ok": None, "detail": f"exit {output.returncode}: {output.stderr.strip()}"}
    status, _, detail = output.stdout.partition("\n")
    detail = detail.strip()
    if status == "err" and detail and "\n" not in detail:
        return {"ok": False, "detail": detail}
    if status != "ok":
        return {"ok": None, "detail": f"invalid oracle protocol: {output.stdout!r}"}
    try:
        key = json.loads(detail)
    except json.JSONDecodeError as error:
        return {"ok": None, "detail": f"invalid oracle JSON: {error}: {detail!r}"}
    if not isinstance(key, dict):
        return {"ok": None, "detail": f"expected a JWK object: {key!r}"}
    fields = {"RSA": {"kty", "n", "e"}, "EC": {"kty", "crv", "x", "y"}}
    kind = key.get("kty")
    if (not isinstance(kind, str) or kind not in fields or set(key) != fields[kind]
            or not all(isinstance(value, str) and value for value in key.values())):
        return {"ok": None, "detail": f"invalid public JWK fields: {key!r}"}
    return {"ok": True, "jwk": key}


def compare(cpp, rust, expected=(True, True), parent_jwk=None):
    for name, result, accepted in zip(("cpp", "rust"), (cpp, rust), expected):
        if result["ok"] is None:
            return f"{name} oracle failed: {result['detail']}"
        if result["ok"] is not accepted:
            return f"{name}: expected acceptance={accepted}, got {result}"
        if accepted and parent_jwk is not None and result["jwk"] != parent_jwk:
            return f"{name}: accepted key differs from the valid parent's key"
    if cpp["ok"] and rust["ok"] and cpp["jwk"] != rust["jwk"]:
        return f"jwk differs: cpp={cpp['jwk']} rust={rust['jwk']}"
    return None


def evaluate_case(toolchain, case):
    parent_chain = case.chain_pem()
    (case.dir / "parent-chain.pem").write_bytes(parent_chain)
    (case.dir / "parent-did.txt").write_text(case.did + "\n")
    (case.dir / "chain.pem").write_bytes(parent_chain)
    (case.dir / "did.txt").write_text(case.did + "\n")
    cpp = run_oracle(toolchain.cpp, case.did, case.dir / "chain.pem")
    rust = run_oracle(toolchain.rust, case.did, case.dir / "chain.pem")
    report = {
        "cpp_revision": CPP_REVISION, "stage": "parent", "mutation": "none",
        "expected": [True, True], "parent_jwk": None, "cpp": cpp, "rust": rust,
        "reason": compare(cpp, rust),
    }
    if report["reason"]:
        return report

    parent_jwk = cpp["jwk"]
    did, chain = case.mutate()
    (case.dir / "chain.pem").write_bytes(chain)
    (case.dir / "did.txt").write_text(did + "\n")
    cpp = run_oracle(toolchain.cpp, did, case.dir / "chain.pem")
    rust = run_oracle(toolchain.rust, did, case.dir / "chain.pem")
    expected = EXPECTED_OUTCOMES[case.mutation]
    report.update({
        "stage": "mutation", "mutation": case.mutation, "expected": list(expected),
        "parent_jwk": parent_jwk, "cpp": cpp, "rust": rust,
        "reason": compare(cpp, rust, expected, parent_jwk),
    })
    return report


def save_failure(destination, case, report):
    destination.mkdir(parents=True, exist_ok=True)
    for filename in ("did.txt", "chain.pem", "parent-did.txt", "parent-chain.pem"):
        (destination / filename).write_bytes((case.dir / filename).read_bytes())
    (destination / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def replay_failure(toolchain, directory):
    report = json.loads((directory / "report.json").read_text())
    if "expected" not in report or "parent_jwk" not in report:
        raise ValueError("Legacy replay lacks expected outcomes; regenerate it with the hardened driver")
    did = (directory / "did.txt").read_text().removesuffix("\n")
    cpp = run_oracle(toolchain.cpp, did, directory / "chain.pem")
    rust = run_oracle(toolchain.rust, did, directory / "chain.pem")
    report.update(cpp=cpp, rust=rust,
                  reason=compare(cpp, rust, report["expected"], report["parent_jwk"]))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--seed", type=int, default=int(time.time()))
    parser.add_argument("--replay", type=Path, help="failure directory to re-run instead of generating")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")

    with tempfile.TemporaryDirectory(prefix="didx509-differential-") as directory:
        work = Path(directory)
        toolchain = Toolchain(work)
        if args.replay:
            report = replay_failure(toolchain, args.replay)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            sys.exit(1 if report["reason"] else 0)

        rng = random.Random(args.seed)
        print(f"seed {args.seed}, {args.iterations} iterations")
        outcomes = {}
        fragments = 0
        failures = 0
        for index in range(args.iterations):
            case = Case(toolchain, rng, index)
            case.build_valid()
            report = evaluate_case(toolchain, case)
            report.update(seed=args.seed, index=index)
            key = (report["stage"], report["mutation"], report["cpp"]["ok"], report["rust"]["ok"])
            outcomes[key] = outcomes.get(key, 0) + 1
            if report["reason"]:
                failures += 1
                out = FAILURES / f"{args.seed}-{index}"
                save_failure(out, case, report)
                print(f"[{index}] {report['stage']} {report['mutation']}: {report['reason']}")
            elif report["mutation"] == "fragment":
                fragments += 1
        print("\nstage     mutation                 cpp   rust  count")
        for (stage, mutation, cpp_ok, rust_ok), count in sorted(outcomes.items(), key=str):
            print(f"{stage:9} {mutation:24} {str(cpp_ok):5} {str(rust_ok):5} {count}")
        if fragments:
            print(f"\n{fragments} fragment cases: C++ rejected, Rust retained the valid parent's key")
        print(f"\n{failures} failure(s)" + (f", saved under {FAILURES}" if failures else ""))
        sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
