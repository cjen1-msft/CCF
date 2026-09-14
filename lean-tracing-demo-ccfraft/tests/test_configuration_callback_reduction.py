# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Guard the packet abstraction for closed, rejected configuration probes."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from native_reduction import native_document
from raw_normalization import normalize
from reduction import ReductionError, build_certificate
from Shared.trace_io import loads_ndjson, read_ndjson

ROOT = Path(__file__).resolve().parents[1]
RULE = "abstract-rejected-configuration-callback"


class ConfigurationCallbackReductionTests(unittest.TestCase):
    def setUp(self):
        self.values = [
            deepcopy(record.value)
            for record in read_ndjson(ROOT / "Traces/Captured/soft_rollback.ndjson")[
                :52
            ]
        ]

    def records(self):
        values = deepcopy(self.values)
        for index, value in enumerate(values, 1):
            if "h_ts" in value:
                value["h_ts"] = str(index)
        return loads_ndjson("\n".join(json.dumps(value) for value in values))

    def abstractions(self):
        return [
            group
            for group in build_certificate(
                self.records(), abstract_rejected_callbacks=True
            )["preprocessing"]["groups"]
            if group["rule"] == RULE
        ]

    def assert_first_probe_is_literal(self):
        self.assertNotIn(2, [group["rawBatchEnd"] for group in self.abstractions()])

    def test_closed_exchanges_preserve_raw_records_and_state_observations(self):
        records = self.records()
        before = deepcopy(records)
        with patch("reduction._abstract_rejected_configuration_callbacks"):
            literal = build_certificate(records, abstract_rejected_callbacks=True)
        abstracted = build_certificate(records, abstract_rejected_callbacks=True)
        self.assertEqual(records, before)
        self.assertEqual(literal["counts"], abstracted["counts"])
        changes = []
        for old, new in zip(literal["steps"], abstracted["steps"], strict=True):
            old, new = deepcopy(old), deepcopy(new)
            old.pop("rule")
            new.pop("rule")
            if new.get("action") in {"appendEntries", "receive"} and (
                "callbackAbstraction" in new.get("evidence", {})
            ):
                evidence = new["evidence"].pop("callbackAbstraction")
                self.assertEqual(evidence["modelBatchEnd"], evidence["rawBatchEnd"] + 1)
                self.assertTrue(evidence["provenance"])
                if new["action"] == "appendEntries":
                    changes.append((old["batchEnd"], new["batchEnd"]))
                    new["batchEnd"] = old["batchEnd"]
                    del new["evidence"]
            elif new.get("variable") == "firstMessageFrom" and old != new:
                self.assertEqual(new["value"]["batchEnd"], old["value"]["batchEnd"] + 1)
                new["value"]["batchEnd"] = old["value"]["batchEnd"]
            self.assertEqual(old, new)
        self.assertEqual(changes, [(2, 3), (4, 5)])
        document = native_document(normalize(abstracted, native_ids=True), ["0"])
        selected = [
            item["value"]
            for step, item in zip(
                abstracted["steps"], document["instructions"], strict=True
            )
            if item["kind"] == "queuePattern"
            and step["rule"] == RULE
            and item["value"]["kind"] == "appendEntriesRequest"
        ]
        self.assertEqual([item["entriesLength"] for item in selected], [1, 1])
        self.assertEqual([item["prevLogIndex"] for item in selected], [2, 4])

    def test_packet_header_disagreement_is_not_hidden(self):
        for field in ("idx", "prev_term", "leader_commit_idx", "term"):
            with self.subTest(field=field):
                original = deepcopy(self.values)
                self.values[18]["msg"]["packet"][field] += 1
                if field == "term":
                    with self.assertRaises(ReductionError):
                        self.abstractions()
                else:
                    self.assert_first_probe_is_literal()
                self.values = original

    def test_nonempty_receiver_is_not_abstracted(self):
        self.values[18]["msg"]["state"]["last_idx"] = 2
        self.values[19]["msg"]["state"]["last_idx"] = 2
        self.values[20]["msg"]["state"]["last_idx"] = 2
        self.assert_first_probe_is_literal()

    def test_successful_or_nonzero_nack_is_not_abstracted(self):
        for field, value in (("success", "OK"), ("last_log_idx", 1)):
            with self.subTest(field=field):
                original = deepcopy(self.values)
                for index in (20, 21):
                    self.values[index]["msg"]["packet"][field] = value
                self.assert_first_probe_is_literal()
                self.values = original

    def test_incomplete_exchange_is_not_abstracted(self):
        self.values = self.values[:21]
        self.assert_first_probe_is_literal()

    def test_duplicate_send_and_drop_are_not_abstracted(self):
        for function in ("send_append_entries", "drop_pending_to"):
            with self.subTest(function=function):
                original = deepcopy(self.values)
                additional = deepcopy(self.values[14])
                additional["msg"]["function"] = function
                self.values.insert(15, additional)
                self.assert_first_probe_is_literal()
                self.values = original

    def test_intervening_leader_transition_is_not_abstracted(self):
        transition = deepcopy(self.values[16])
        transition["msg"]["function"] = "become_leader"
        self.values.insert(17, transition)
        self.assert_first_probe_is_literal()

    def test_preexisting_peer_is_not_abstracted(self):
        self.values[13]["msg"]["configurations"][-1]["nodes"]["1"] = {"address": ":"}
        self.assert_first_probe_is_literal()

    def test_new_command_ends_the_callback_snapshot(self):
        self.values.insert(14, {"tag": "raft_trace", "cmd": "periodic_all,10"})
        certificate = build_certificate(self.records())
        self.assert_first_probe_is_literal()
        self.assertTrue(
            any(
                step.get("variable") == "logLength"
                and step["provenance"][0]["line"] == 16
                for step in certificate["steps"]
            )
        )

    def test_capture_families_have_the_same_guarded_exchanges(self):
        paths = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        paths += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        for path in paths:
            with self.subTest(trace=path.name):
                certificate = build_certificate(
                    read_ndjson(path), abstract_rejected_callbacks=True
                )
                self.assertEqual(
                    [
                        (group["rawBatchEnd"], group["modelBatchEnd"])
                        for group in certificate["preprocessing"]["groups"]
                        if group["rule"] == RULE
                    ],
                    [(2, 3), (4, 5)],
                )

    def test_standalone_cli_records_the_selected_mode(self):
        with tempfile.TemporaryDirectory(prefix="callback-reduction-") as temporary:
            output = Path(temporary) / "reduction.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "reduction.py"),
                    str(ROOT / "Traces/Captured/soft_rollback.ndjson"),
                    str(output),
                    "--abstract-rejected-callbacks",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            certificate = json.loads(output.read_text())
            self.assertTrue(certificate["preprocessing"]["abstract_rejected_callbacks"])
            self.assertEqual(
                sum(
                    group["rule"] == RULE
                    for group in certificate["preprocessing"]["groups"]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
