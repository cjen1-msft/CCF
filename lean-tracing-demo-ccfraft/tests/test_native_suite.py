# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture discovery and measurement contracts; mocks are not semantic evidence."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_suite import load_cases, main, run_case, run_suite
from Shared.solver import ValidationError


class NativeSuiteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-suite-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "Captured").mkdir()
        (self.root / "Captured/a.ndjson").write_text("{}\n", encoding="utf-8")
        self.manifest = self.root / "suite.json"
        self.document = {
            "schema": "ccfraft-native-suite/v1",
            "directories": ["Captured"],
            "cases": [
                {
                    "trace": "Captured/a.ndjson",
                    "bootstrap": ["node"],
                    "expected": "sat",
                    "reason": "A consistent example.",
                }
            ],
        }
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.document), encoding="utf-8")

    def test_repository_manifest_covers_saved_captures(self):
        cases = load_cases()
        self.assertTrue(
            {"Captured/bad_network.ndjson", "Captured/soft_rollback.ndjson"}
            <= {case.trace for case in cases}
        )
        self.assertTrue(all(case.reason for case in cases))
        expected = {case.trace: case.expected for case in cases}
        self.assertEqual(expected["Controls/configuration_callback.ndjson"], "sat")
        self.assertEqual(expected["Captured/bad_network.ndjson"], "sat")
        self.assertEqual(expected["Captured/soft_rollback.ndjson"], "sat")
        self.assertTrue(
            all(
                case.expected == "unsat"
                for case in cases
                if case.trace.startswith("Mutated/")
            )
        )

    def test_new_nested_captures_require_explicit_metadata(self):
        directory = self.root / "future/scenario"
        directory.mkdir(parents=True)
        (directory / "b.ndjson").write_text("{}\n", encoding="utf-8")
        self.document["directories"].append("future")
        self.save()
        with self.assertRaisesRegex(ValidationError, "missing suite metadata"):
            load_cases(self.manifest)
        additional = deepcopy(self.document["cases"][0])
        additional["trace"] = "future/scenario/b.ndjson"
        self.document["cases"].append(additional)
        self.save()
        self.assertEqual(len(load_cases(self.manifest)), 2)

    def test_invalid_case_metadata_is_rejected(self):
        original = deepcopy(self.document)
        for changes in (
            {"trace": "../outside.ndjson"},
            {"trace": "Captured/missing.ndjson"},
            {"bootstrap": []},
            {"bootstrap": ["node", "node"]},
            {"bootstrap": [[]]},
            {"expected": "unknown"},
            {"reason": ""},
            {"extra": True},
        ):
            with self.subTest(changes=changes):
                self.document = deepcopy(original)
                self.document["cases"][0].update(changes)
                self.save()
                with self.assertRaises(ValidationError):
                    load_cases(self.manifest)
        self.document = original
        self.document["cases"] *= 2
        self.save()
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            load_cases(self.manifest)

    def test_invalid_directory_scopes_are_rejected(self):
        for directories in (
            [],
            ["missing"],
            ["../outside"],
            ["Captured", "Captured"],
            [None],
        ):
            with self.subTest(directories=directories):
                self.document["directories"] = directories
                self.save()
                with self.assertRaises(ValidationError):
                    load_cases(self.manifest)

    def test_external_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="native-external-") as temporary:
            external = Path(temporary) / "trace.ndjson"
            external.write_text("{}\n", encoding="utf-8")
            source = self.root / "Captured/a.ndjson"
            source.unlink()
            source.symlink_to(external)
            with self.assertRaisesRegex(ValidationError, "escapes"):
                load_cases(self.manifest)

    def test_build_and_warmups_are_excluded_from_samples(self):
        cases = load_cases(self.manifest)
        events = []

        def fake_run(case, output, _z3):
            events.append(output.name)
            duration = {
                "warmup-1": 9000,
                "sample-1": 30,
                "sample-2": 10,
                "sample-3": 20,
            }
            return {
                "trace": case.trace,
                "status": "sat",
                "total_ms": duration[output.name],
                "solver_ms": 2,
            }

        with (
            patch("native_suite.prepare", side_effect=lambda _: events.append("build")),
            patch("native_suite.run_case", side_effect=fake_run),
        ):
            report = run_suite(
                cases, self.root / "out", Path("/unused/z3"), samples=3, warmups=1
            )
        self.assertEqual(
            events, ["build", "warmup-1", "sample-1", "sample-2", "sample-3"]
        )
        row = report["cases"][0]
        self.assertEqual(row["median_total_ms"], 20)
        self.assertEqual((row["min_total_ms"], row["max_total_ms"]), (10, 30))
        self.assertEqual(len(row["samples"]), 3)
        self.assertEqual(
            json.loads((self.root / "out/summary.json").read_text()), report
        )

    def test_measurement_wraps_cli_and_checks_retained_outcome(self):
        case = load_cases(self.manifest)[0]
        summary = {"status": "sat", "solver_ms": 2}
        retained = SimpleNamespace(
            result=summary, document={"instructions": []}, details={"clauses": []}
        )
        completed = subprocess.CompletedProcess([], 0, json.dumps(summary), "")
        with (
            patch("native_suite.subprocess.run", return_value=completed) as command,
            patch("native_suite.NativeRun.load", return_value=retained),
            patch("native_suite.time.perf_counter_ns", side_effect=[0, 25_000_000]),
        ):
            result = run_case(case, self.root / "run", Path("/unused/z3"))
        self.assertEqual(result["total_ms"], 25)
        self.assertEqual(result["solver_ms"], 2)
        self.assertIn("--raw", command.call_args.args[0])
        self.assertIn("--bootstrap", command.call_args.args[0])

    def test_unexpected_verdict_is_not_a_successful_regression(self):
        case = load_cases(self.manifest)[0]
        summary = {"status": "unknown", "solver_ms": 2}
        with (
            patch(
                "native_suite.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(summary), ""
                ),
            ),
            patch(
                "native_suite.NativeRun.load",
                return_value=SimpleNamespace(result=summary),
            ),
            self.assertRaisesRegex(ValidationError, "expected sat, got unknown"),
        ):
            run_case(case, self.root / "run", Path("/unused/z3"))

    def test_failure_does_not_publish_summary(self):
        output = self.root / "out"
        with (
            patch("native_suite.prepare"),
            patch("native_suite.run_case", side_effect=ValidationError("rejected")),
            self.assertRaisesRegex(ValidationError, "rejected"),
        ):
            run_suite(load_cases(self.manifest), output, Path("/unused/z3"))
        self.assertFalse((output / "summary.json").exists())

    def test_existing_output_is_not_overwritten(self):
        output = self.root / "out"
        output.mkdir()
        marker = output / "summary.json"
        marker.write_text("retained", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            run_suite(load_cases(self.manifest), output, Path("/unused/z3"))
        self.assertEqual(marker.read_text(), "retained")

    def test_artifacts_cannot_be_created_inside_the_trace_tree(self):
        output = self.root / "new-artifacts"
        with (
            patch(
                "sys.argv",
                [
                    "native_suite.py",
                    "--manifest",
                    str(self.manifest),
                    "--output-dir",
                    str(output),
                ],
            ),
            patch("sys.stderr"),
            patch("native_suite.find_z3") as find,
            self.assertRaises(SystemExit) as error,
        ):
            main()
        self.assertEqual(error.exception.code, 2)
        find.assert_not_called()
        self.assertFalse(output.exists())

    def test_invalid_sample_counts_do_not_create_artifacts(self):
        for samples, warmups in ((0, 0), (-1, 0), (1, -1)):
            with self.subTest(samples=samples, warmups=warmups):
                output = self.root / "out"
                with self.assertRaises(ValidationError):
                    run_suite(
                        load_cases(self.manifest),
                        output,
                        Path("/unused/z3"),
                        samples=samples,
                        warmups=warmups,
                    )
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
