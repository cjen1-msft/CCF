# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Raw CLI orchestration with mock encoding and solving, not semantic evidence."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_lean
from native_run import ARTIFACTS, ASSURANCE, ENCODING_SCHEMA, NativeRun
from native_origin import RAW_ARTIFACTS
from Shared.solver import SolverRun, ValidationError

ROOT = Path(__file__).resolve().parents[1]


def encoding(document):
    return {
        "schema": ENCODING_SCHEMA,
        "input": document,
        "script": "(set-logic ALL)\n(check-sat)\n",
        "queries": {"unsatCore": "(get-unsat-core)\n"},
        "groups": [
            {"instruction": index, "start": 0, "stop": 0}
            for index in [None, *range(len(document["instructions"]))]
        ],
        "clauses": [],
    }


def solver(_binary, _script, _query, directory, stem):
    (directory / f"{stem}.stdout").write_text("unknown\n", encoding="utf-8")
    (directory / f"{stem}.stderr").write_text("", encoding="utf-8")
    return SolverRun("unknown", "unknown\n", "", 0.1)


class NativeRawCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-raw-cli-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "run"
        self.source = ROOT / "Traces/Captured/soft_rollback.ndjson"

    def invoke(self, *arguments, emit=encoding, solve=solver):
        output = StringIO()
        errors = StringIO()
        with (
            patch("sys.argv", ["native_lean.py", *map(str, arguments)]),
            patch("native_lean.encode_details", side_effect=emit) as encoder,
            patch("native_lean.find_z3", return_value=Path("/unused/z3")),
            patch("native_lean.run_z3", side_effect=solve),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            native_lean.main()
        return json.loads(output.getvalue()), encoder

    def test_raw_run_retains_exact_source_and_explicit_bootstrap(self):
        summary, encoder = self.invoke(
            self.source, "--output-dir", self.output, "--raw", "--bootstrap", "0"
        )
        run = NativeRun.load(self.output)
        self.assertEqual(summary, run.result)
        self.assertEqual(run.result["status"], "unknown")
        self.assertEqual(
            run.result["assurance"], {**ASSURANCE, "raw_reducer_integrated": True}
        )
        self.assertEqual(run.document["bootstrap"], ["0"])
        self.assertTrue(run.document["unknowns"])
        self.assertEqual(
            (self.output / "raw.ndjson").read_bytes(), self.source.read_bytes()
        )
        self.assertEqual(set(run.result["artifacts"]), set(ARTIFACTS + RAW_ARTIFACTS))
        self.assertEqual(run.instruction(238)["origin"]["records"][0]["line"], 45)
        encoder.assert_called_once_with(run.document)

    def test_reduced_input_route_remains_available(self):
        source = self.root / "model.json"
        document = {"nodes": ["a"], "bootstrap": ["a"], "instructions": []}
        source.write_text(json.dumps(document), encoding="utf-8")
        self.invoke(source, "--output-dir", self.output)
        run = NativeRun.load(self.output)
        self.assertEqual(run.document, document)
        self.assertIsNone(run.origin)
        self.assertEqual(set(run.result["artifacts"]), set(ARTIFACTS))

    def test_bootstrap_must_be_explicit_and_raw_only(self):
        for options in (("--raw",), ("--bootstrap", "0")):
            with self.subTest(options=options), self.assertRaises(SystemExit) as error:
                self.invoke(self.source, "--output-dir", self.output, *options)
            self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_invalid_raw_input_clears_stale_result(self):
        self.output.mkdir()
        result = self.output / "result.json"
        result.write_text('{"old": true}', encoding="utf-8")
        source = self.root / "invalid.ndjson"
        source.write_text("{not JSON}\n", encoding="utf-8")
        with self.assertRaises(SystemExit) as error:
            self.invoke(
                source, "--output-dir", self.output, "--raw", "--bootstrap", "0"
            )
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(result.exists())

    def test_reduction_errors_are_cli_diagnostics(self):
        with self.assertRaises(SystemExit) as error:
            self.invoke(
                self.source,
                "--output-dir",
                self.output,
                "--raw",
                "--bootstrap",
                "missing",
            )
        self.assertEqual(error.exception.code, 2)
        self.assertFalse((self.output / "result.json").exists())

    def test_reserved_outputs_cannot_overwrite_the_source(self):
        self.output.mkdir()
        data = self.source.read_bytes()
        for name in ARTIFACTS + RAW_ARTIFACTS + ("result.json", "result.json.tmp"):
            with self.subTest(name=name):
                source = self.output / name
                source.write_bytes(data)
                with self.assertRaises(SystemExit) as error:
                    self.invoke(
                        source, "--output-dir", self.output, "--raw", "--bootstrap", "0"
                    )
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(source.read_bytes(), data)

    def test_output_symlink_cannot_overwrite_the_source(self):
        self.output.mkdir()
        source = self.root / "source.ndjson"
        data = self.source.read_bytes()
        source.write_bytes(data)
        (self.output / "raw.ndjson").symlink_to(source)
        with self.assertRaises(SystemExit) as error:
            self.invoke(
                source, "--output-dir", self.output, "--raw", "--bootstrap", "0"
            )
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(source.read_bytes(), data)

    def test_encoder_and_solver_failures_do_not_publish_a_result(self):
        self.output.mkdir()
        result = self.output / "result.json"
        for stage in ("emit", "solve"):
            with self.subTest(stage=stage):
                result.write_text('{"old": true}', encoding="utf-8")
                with self.assertRaises(SystemExit) as error:
                    self.invoke(
                        self.source,
                        "--output-dir",
                        self.output,
                        "--raw",
                        "--bootstrap",
                        "0",
                        **{stage: ValidationError("rejected")},
                    )
                self.assertEqual(error.exception.code, 2)
                self.assertFalse(result.exists())


if __name__ == "__main__":
    unittest.main()
