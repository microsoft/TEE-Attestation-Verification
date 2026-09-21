# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for the differential driver's verdicts, not the resolvers."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fuzz


KEY = {"kty": "RSA", "n": "AQ", "e": "AQAB"}
OTHER_KEY = {"kty": "RSA", "n": "Ag", "e": "AQAB"}
ACCEPT = {"ok": True, "jwk": KEY}
REJECT = {"ok": False, "detail": "predicate mismatch"}
CRASH = {"ok": None, "detail": "exit -11"}


class BuildTests(unittest.TestCase):
    def test_rust_build_uses_separate_workspace_and_local_target(self):
        tools = object.__new__(fuzz.Toolchain)
        with patch("fuzz.run") as run:
            binary = tools.build_rust()
        args, kwargs = run.call_args
        self.assertEqual(args, (
            "cargo", "build", "--locked", "--quiet", "--manifest-path", str(fuzz.HERE / "Cargo.toml"),
            "--target-dir", str(fuzz.BUILD / "rust"),
        ))
        self.assertEqual(kwargs["cwd"], fuzz.HERE)
        self.assertEqual(binary, fuzz.BUILD / "rust/debug/didx509-rust-oracle")

    def test_rust_build_defaults_to_half_the_available_cpus(self):
        tools = object.__new__(fuzz.Toolchain)
        with patch.dict(os.environ, {}, clear=True), \
                patch("fuzz.os.sched_getaffinity", return_value=set(range(7)), create=True), \
                patch("fuzz.run") as run:
            tools.build_rust()
        self.assertEqual(run.call_args.kwargs["env"]["CARGO_BUILD_JOBS"], "4")

    def test_rust_build_preserves_explicit_job_count(self):
        tools = object.__new__(fuzz.Toolchain)
        with patch.dict(os.environ, {"CARGO_BUILD_JOBS": "2"}), patch("fuzz.run") as run:
            tools.build_rust()
        self.assertEqual(run.call_args.kwargs["env"]["CARGO_BUILD_JOBS"], "2")


class VerdictTests(unittest.TestCase):
    def test_both_crashes_are_not_agreement(self):
        self.assertIsNotNone(fuzz.compare(CRASH, CRASH))

    def test_parent_must_be_accepted(self):
        self.assertIsNotNone(fuzz.compare(REJECT, REJECT))
        self.assertIsNone(fuzz.compare(ACCEPT, ACCEPT))

    def test_invalid_mutation_must_be_rejected_by_each_oracle(self):
        expected = (False, False)
        for cpp, rust in [(ACCEPT, ACCEPT), (ACCEPT, REJECT), (REJECT, ACCEPT)]:
            with self.subTest(cpp=cpp, rust=rust):
                self.assertIsNotNone(fuzz.compare(cpp, rust, expected, KEY))
        self.assertIsNone(fuzz.compare(REJECT, REJECT, expected, KEY))

    def test_fragment_exception_only_allows_expected_rejection_and_unchanged_key(self):
        expected = (False, True)
        self.assertIsNone(fuzz.compare(REJECT, ACCEPT, expected, KEY))
        for cpp, rust in [
            (ACCEPT, REJECT),
            (REJECT, REJECT),
            (ACCEPT, ACCEPT),
            (CRASH, ACCEPT),
            (REJECT, CRASH),
            (REJECT, {"ok": True, "jwk": OTHER_KEY}),
        ]:
            with self.subTest(cpp=cpp, rust=rust):
                self.assertIsNotNone(fuzz.compare(cpp, rust, expected, KEY))

    def test_shared_wrong_key_cannot_replace_parent_key(self):
        changed = {"ok": True, "jwk": OTHER_KEY}
        self.assertIsNotNone(fuzz.compare(changed, changed, (True, True), KEY))
        self.assertIsNotNone(fuzz.compare(ACCEPT, changed))


class ProtocolTests(unittest.TestCase):
    def invoke(self, stdout="", returncode=0, stderr=""):
        result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with patch("fuzz.subprocess.run", return_value=result):
            return fuzz.run_oracle(Path("oracle"), "did", Path("chain.pem"))

    def test_valid_protocol(self):
        self.assertEqual(self.invoke("ok\n" + json.dumps(KEY) + "\n"), ACCEPT)
        self.assertEqual(self.invoke("err\npredicate mismatch\n"), REJECT)

    def test_malformed_protocol_is_not_rejection(self):
        for output in [
            "", "unknown\nfailure", "err\n", "ok\nerr\nfailure", "ok\n{",
            "ok\nnull", "ok\n[]", 'ok\n{"kty":"RSA"}',
            'ok\n{"kty":"RSA","n":1,"e":"AQAB"}',
            'ok\n{"kty":"RSA","n":"","e":"AQAB"}',
            'ok\n{"kty":"RSA","n":"AQ","e":"AQAB","unexpected":true}',
        ]:
            with self.subTest(output=output):
                self.assertIsNone(self.invoke(output)["ok"])

    def test_abnormal_exit_even_with_valid_output_is_failure(self):
        self.assertIsNone(self.invoke("ok\n" + json.dumps(KEY), -11)["ok"])

    def test_timeout_launch_error_and_invalid_utf8_are_failures(self):
        for error in [
            subprocess.TimeoutExpired("oracle", 60),
            FileNotFoundError("oracle"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
        ]:
            with self.subTest(error=error), patch("fuzz.subprocess.run", side_effect=error):
                self.assertIsNone(fuzz.run_oracle(Path("oracle"), "did", Path("chain"))["ok"])


class CaseExecutionTests(unittest.TestCase):
    def test_parent_failure_is_saved_without_mutating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = unittest.mock.Mock(dir=root, did="parent-did", mutation="none")
            case.chain_pem.return_value = b"parent-chain"
            tools = unittest.mock.Mock(cpp="cpp", rust="rust")
            with patch("fuzz.run_oracle", return_value=CRASH):
                report = fuzz.evaluate_case(tools, case)
            case.mutate.assert_not_called()
            self.assertEqual(report["stage"], "parent")
            self.assertIsNotNone(report["reason"])
            fuzz.save_failure(root / "failure", case, report)
            self.assertEqual((root / "failure/chain.pem").read_bytes(), b"parent-chain")
            self.assertEqual(json.loads((root / "failure/report.json").read_text())["cpp"], CRASH)

    def test_mutation_failure_saves_parent_and_replays_the_same_assertions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = unittest.mock.Mock(dir=root, did="parent-did", mutation="wrong-fingerprint")
            case.chain_pem.return_value = b"parent-chain"
            case.mutate.return_value = ("mutated-did", b"mutated-chain")
            tools = unittest.mock.Mock(cpp="cpp", rust="rust")
            with patch("fuzz.run_oracle", side_effect=[ACCEPT, ACCEPT, ACCEPT, ACCEPT]) as oracle:
                report = fuzz.evaluate_case(tools, case)
            self.assertEqual([call.args[1] for call in oracle.call_args_list],
                             ["parent-did", "parent-did", "mutated-did", "mutated-did"])
            self.assertIsNotNone(report["reason"])
            destination = root / "failure"
            fuzz.save_failure(destination, case, report)
            self.assertEqual((destination / "chain.pem").read_bytes(), b"mutated-chain")
            self.assertEqual((destination / "parent-chain.pem").read_bytes(), b"parent-chain")
            self.assertEqual((destination / "did.txt").read_text(), "mutated-did\n")
            with patch("fuzz.run_oracle", return_value=ACCEPT):
                replay = fuzz.replay_failure(tools, destination)
            self.assertIsNotNone(replay["reason"])
            self.assertEqual(replay["parent_jwk"], KEY)

    def test_timeout_during_mutation_is_saved_for_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = unittest.mock.Mock(dir=root, did="parent-did", mutation="fragment")
            case.chain_pem.return_value = b"parent-chain"
            case.mutate.return_value = ("parent-did#0", b"parent-chain")
            tools = unittest.mock.Mock(cpp="cpp", rust="rust")
            accepted = subprocess.CompletedProcess([], 0, "ok\n" + json.dumps(KEY), "")
            rejected = subprocess.CompletedProcess([], 0, "err\nfragment not supported\n", "")
            with patch("fuzz.subprocess.run", side_effect=[
                accepted, accepted, rejected, subprocess.TimeoutExpired("rust", 60)
            ]):
                report = fuzz.evaluate_case(tools, case)
            self.assertIsNone(report["rust"]["ok"])
            self.assertIn("TimeoutExpired", report["reason"])
            fuzz.save_failure(root / "failure", case, report)
            self.assertEqual((root / "failure/did.txt").read_text(), "parent-did#0\n")
            saved = json.loads((root / "failure/report.json").read_text())
            self.assertEqual(saved["expected"], [False, True])
            self.assertEqual(saved["parent_jwk"], KEY)


class MutationTests(unittest.TestCase):
    def mutate_subject(self, mutation, cn):
        with tempfile.TemporaryDirectory() as directory:
            tools = SimpleNamespace(work=Path(directory))
            rng = unittest.mock.Mock()
            rng.choice.return_value = mutation
            case = fuzz.Case(tools, rng, 0)
            pem = Path(directory) / "leaf.pem"
            pem.write_bytes(b"certificate")
            case.certs = [(pem, None, [("CN", cn)], [], [], None, None)]
            case.did = "did:x509:0:sha256:fp::subject:CN:" + fuzz.percent_encode(cn)
            did, chain = case.mutate()
            self.assertEqual(chain, b"certificate")
            return case, did

    def test_case_mutation_keeps_grammar_and_changes_only_the_value(self):
        case, did = self.mutate_subject("predicate-case", "Test Leaf")
        self.assertEqual(did, case.did + "::subject:CN:tEST%20lEAF")
        self.assertEqual(fuzz.EXPECTED_OUTCOMES[case.mutation], (False, False))

    def test_uncased_subject_is_a_positive_noop(self):
        case, did = self.mutate_subject("predicate-case", "\u6771\u4eac")
        self.assertEqual(did, case.did)
        self.assertEqual(fuzz.EXPECTED_OUTCOMES[case.mutation], (True, True))

    def test_repeated_predicate_uses_the_actual_subject_and_expects_acceptance(self):
        case, did = self.mutate_subject("repeated-subject", "Fabrikam")
        self.assertEqual(did, case.did + "::subject:CN:Fabrikam::subject:CN:Fabrikam")
        self.assertEqual(fuzz.EXPECTED_OUTCOMES[case.mutation], (True, True))


if __name__ == "__main__":
    unittest.main()
