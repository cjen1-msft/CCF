# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from Shared.trace_io import NDJSONError, loads_ndjson


class TraceIOTests(unittest.TestCase):
    def test_retains_arbitrary_objects_and_line_provenance(self) -> None:
        text = '{"function":"not-semantic","nested":{"value":1}}\n{"x":true}'

        records = loads_ndjson(text, source="sample.ndjson")

        self.assertEqual([record.line_number for record in records], [1, 2])
        self.assertEqual(records[0].raw, text.splitlines()[0])
        self.assertEqual(records[0].value["function"], "not-semantic")
        self.assertEqual(records[1].value, {"x": True})

    def test_rejects_non_object_or_empty_records(self) -> None:
        with self.assertRaisesRegex(NDJSONError, "not an object"):
            loads_ndjson("[]\n")
        with self.assertRaisesRegex(NDJSONError, "empty NDJSON record"):
            loads_ndjson('{"ok":true}\n\n')


if __name__ == "__main__":
    unittest.main()
