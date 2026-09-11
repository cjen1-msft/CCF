"""Offline checks for the native benchmark's case and evidence metadata."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.benchmark_conditional_queue import check_emission, expected_case, matrix_cases
from Shared.solver import ValidationError


class ConditionalQueueBenchmarkTests(unittest.TestCase):
    def test_native_fixture_names(self) -> None:
        native_shapes = {
            (40, "cycle4"): "cycle4",
            (400, "cycle4"): "cycle4",
            (40, "cycleDistinct"): "cycle19",
            (400, "cycleDistinct"): "cycle199",
            (40, "send"): "send",
            (400, "send"): "send",
        }
        text = b"(set-logic QF_UFLIA)\n(check-sat)\n"
        with tempfile.TemporaryDirectory(prefix="conditional-benchmark-metadata-") as directory:
            script = Path(directory) / "query.smt2"
            script.write_bytes(text)
            for parameters in matrix_cases():
                size, shape, keys, guards, verdict = parameters
                name = f"{size}-{native_shapes[size, shape]}-{keys}-{guards}-{verdict}"
                with self.subTest(parameters=parameters):
                    case = {
                        **expected_case(*parameters),
                        "case": name,
                        "bytes": len(text),
                        "script_sha256": hashlib.sha256(text).hexdigest(),
                        "formula_ns": 1,
                        "commands_ns": 2,
                        "text_ns": 3,
                        "encoding_ns": 6,
                        "warm_encoding_ns": 7,
                    }
                    check_emission(case, parameters, script)
                    with self.assertRaisesRegex(ValidationError, "Wrong fixture case"):
                        check_emission({**case, "case": name + "-wrong"}, parameters, script)
                    with self.assertRaisesRegex(ValidationError, "phase timing sum"):
                        check_emission({**case, "encoding_ns": 7}, parameters, script)

    def test_matrix_and_alias_controls(self) -> None:
        cases = list(matrix_cases())
        self.assertEqual(len(cases), 54)
        self.assertEqual(len(set(cases)), 54)
        aliases = [parameters for parameters in cases if parameters[-1] == "alias"]
        self.assertEqual(len(aliases), 6)
        for parameters in aliases:
            with self.subTest(parameters=parameters):
                expected = expected_case(*parameters)
                self.assertEqual(expected["final_length"], 1)
                self.assertEqual(expected["expected"], "sat")
        with self.assertRaisesRegex(ValidationError, "alias requires"):
            expected_case(40, "send", "literal", "alternating", "alias")


if __name__ == "__main__":
    unittest.main()
