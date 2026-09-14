# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from copy import deepcopy
from pathlib import Path
import unittest

from native_origin import reduce_raw, validate_raw_origin
from native_reduction import native_document
from Shared.solver import ValidationError

ROOT = Path(__file__).resolve().parents[1]


class NativeOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / "Traces/Captured/soft_rollback.ndjson").read_bytes()
        cls.origin = reduce_raw(cls.data)
        cls.document = native_document(cls.origin.trace, ["0"])

    def test_saved_captures_bind_every_instruction_to_raw_records(self):
        captures = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        captures += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        self.assertEqual(len(captures), 6)
        for path in captures:
            with self.subTest(capture=path.name):
                data = path.read_bytes()
                raw_lines = data.decode("utf-8").splitlines()
                origin = reduce_raw(data)
                document = native_document(origin.trace, ["0"])
                retained = validate_raw_origin(data, origin.certificate, document)
                self.assertEqual(
                    len(retained.trace.steps), len(document["instructions"])
                )
                for index, step in enumerate(retained.trace.steps):
                    detail = retained.instruction(index)
                    self.assertEqual(detail["step"], step)
                    self.assertEqual(
                        detail["evidence"], retained.trace.evidence.get(index + 1)
                    )
                    self.assertTrue(detail["records"])
                    for record, provenance in zip(
                        detail["records"], step["provenance"]
                    ):
                        self.assertEqual(record["line"], provenance["line"])
                        self.assertEqual(
                            record["raw"],
                            raw_lines[record["line"] - 1],
                        )

    def test_changed_reduction_is_rejected(self):
        certificate = deepcopy(self.origin.certificate)
        certificate["steps"].pop()
        with self.assertRaisesRegex(ValidationError, "does not match"):
            validate_raw_origin(self.data, certificate, self.document)

    def test_removed_abstraction_policy_is_not_replayed(self):
        certificate = deepcopy(self.origin.certificate)
        certificate["preprocessing"]["abstract_rejected_callbacks"] = True
        with self.assertRaisesRegex(ValidationError, "does not match"):
            validate_raw_origin(self.data, certificate, self.document)

    def test_different_capture_is_rejected(self):
        data = (ROOT / "Traces/Captured/bad_network.ndjson").read_bytes()
        with self.assertRaisesRegex(ValidationError, "does not match"):
            validate_raw_origin(data, self.origin.certificate, self.document)

    def test_changed_projected_instruction_is_rejected(self):
        document = deepcopy(self.document)
        document["instructions"][0]["value"] = "different"
        with self.assertRaisesRegex(ValidationError, "different Model input"):
            validate_raw_origin(self.data, self.origin.certificate, document)

    def test_explicit_bootstrap_is_preserved_not_inferred(self):
        document = native_document(self.origin.trace, ["0", "1"])
        retained = validate_raw_origin(self.data, self.origin.certificate, document)
        self.assertEqual(retained.trace, self.origin.trace)
        self.assertEqual(document["bootstrap"], ["0", "1"])


if __name__ == "__main__":
    unittest.main()
