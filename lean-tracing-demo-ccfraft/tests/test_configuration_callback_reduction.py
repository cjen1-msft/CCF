# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Keep callback packet facts exact while omitting only the mixed log snapshot."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from native_reduction import native_document
from raw_normalization import normalize
from reduction import build_certificate
from Shared.trace_io import loads_ndjson, read_ndjson

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationCallbackReductionTests(unittest.TestCase):
    def test_saved_control_is_the_exact_raw_prefix(self):
        source = (ROOT / "Traces/Captured/soft_rollback.ndjson").read_bytes()
        control = (ROOT / "Traces/Controls/configuration_callback.ndjson").read_bytes()
        self.assertEqual(control, b"".join(source.splitlines(keepends=True)[:22]))

    def test_captures_preserve_callback_packet_and_receive_bounds(self):
        paths = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        paths += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        for path in paths:
            with self.subTest(capture=path.name):
                records = read_ndjson(path)
                before = deepcopy(records)
                certificate = build_certificate(records)
                document = native_document(
                    normalize(certificate, native_ids=True), ["0"]
                )
                self.assertEqual(records, before)
                self.assertNotIn(
                    "abstract_rejected_callbacks", certificate["preprocessing"]
                )
                for send_line, receive_line, end in ((15, 19, 2), (45, 49, 4)):
                    send = next(
                        item
                        for step, item in zip(
                            certificate["steps"], document["instructions"]
                        )
                        if step.get("action") == "appendEntries"
                        and step["provenance"][0]["line"] == send_line
                    )
                    packet = records[send_line - 1].value["msg"]["packet"]
                    self.assertEqual(send["batchEnd"], packet["idx"])
                    self.assertEqual(send["batchEnd"], end)
                    received = next(
                        item
                        for step, item in zip(
                            certificate["steps"], document["instructions"]
                        )
                        if step.get("variable") == "firstMessageFrom"
                        and step["provenance"][0]["line"] == receive_line
                    )
                    self.assertEqual(received["value"]["prevLogIndex"], end)
                    self.assertEqual(received["value"]["entriesLength"], 0)
                    self.assertFalse(
                        any(
                            step.get("variable") == "logLength"
                            and step["provenance"][0]["line"] == send_line
                            for step in certificate["steps"]
                        )
                    )

    def test_new_command_ends_the_mixed_snapshot(self):
        values = [
            record.value
            for record in read_ndjson(ROOT / "Traces/Captured/soft_rollback.ndjson")
        ]
        values.insert(14, {"tag": "raft_trace", "cmd": "periodic_all,10"})
        records = loads_ndjson("\n".join(json.dumps(value) for value in values))
        certificate = build_certificate(records)
        self.assertTrue(
            any(
                step.get("variable") == "logLength"
                and step["provenance"][0]["line"] == 16
                for step in certificate["steps"]
            )
        )


if __name__ == "__main__":
    unittest.main()
