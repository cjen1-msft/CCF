# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reduction import (
    PreprocessedTrace,
    ReductionError,
    build_certificate,
    preprocess,
    reduce,
)
from Shared.trace_io import loads_ndjson, read_ndjson

CAPTURED = ROOT / "Traces" / "Captured"
MUTATED = ROOT / "Traces" / "Mutated"
CERTIFICATES = ROOT / "Traces" / "Certificates"
ACTION_FAMILIES = {
    "advanceCommitIndex",
    "appendEntries",
    "becomeLeader",
    "changeConfiguration",
    "clientRequest",
    "receive",
    "requestVote",
    "signCommittableMessages",
    "timeout",
    "updateTerm",
}


def actions(certificate: dict[str, object]) -> list[dict[str, object]]:
    reduced = certificate["reduced_trace"]
    assert isinstance(reduced, dict)
    steps = reduced["steps"]
    assert isinstance(steps, list)
    return [step["action"] for step in steps]


def observations(certificate: dict[str, object]) -> list[dict[str, object]]:
    reduced = certificate["reduced_trace"]
    assert isinstance(reduced, dict)
    entry = reduced["observations_at_entry"]
    steps = reduced["steps"]
    assert isinstance(entry, list)
    assert isinstance(steps, list)
    return entry + [
        observation for step in steps for observation in step["observations_after"]
    ]


class ReductionTests(unittest.TestCase):
    def test_parsing_and_semantic_preprocessing_are_separate(self) -> None:
        records = loads_ndjson(
            '{"tag":"raft_trace","cmd":"start"}\n'
            '{"tag":"raft_trace","h_ts":"1","msg":{'
            '"function":"future_function","state":{'
            '"node_id":"0","leadership_state":"Leader",'
            '"membership_state":"Active","current_view":1,'
            '"last_idx":0,"commit_idx":0}}}\n'
        )

        self.assertEqual(records[1].value["msg"]["function"], "future_function")
        with self.assertRaisesRegex(ReductionError, "unaudited function"):
            preprocess(records)

    def test_captured_traces_cover_all_current_action_families(self) -> None:
        seen: set[str] = set()
        for path in sorted(CAPTURED.glob("*.ndjson")):
            preprocessed = preprocess(read_ndjson(path))
            self.assertIsInstance(preprocessed, PreprocessedTrace)
            certificate = reduce(preprocessed)
            trace_actions = actions(certificate)
            trace_observations = observations(certificate)
            seen.update(str(action["kind"]) for action in trace_actions)

            self.assertTrue(
                all(action["rule"] and action["provenance"] for action in trace_actions)
            )
            self.assertTrue(
                all(
                    observation["rule"]
                    and observation["reduction_rule"]
                    and observation["provenance"]
                    for observation in trace_observations
                )
            )
            ignored = certificate["preprocessing"]["ignored_events"]
            self.assertTrue(all(item["rule"] and item["reason"] for item in ignored))
            associations = certificate["preprocessing"]["command_associations"]
            self.assertTrue(
                all(
                    item["rule"] == "associate-command"
                    and item["command"]
                    and item["command_line"] < item["event_line"]
                    for item in associations
                )
            )

        self.assertEqual(seen, ACTION_FAMILIES)

    def test_reduction_is_deterministic(self) -> None:
        for path in sorted(CAPTURED.glob("*.ndjson")):
            records = read_ndjson(path)
            first = json.dumps(
                build_certificate(records),
                indent=2,
                sort_keys=True,
            )
            second = json.dumps(
                build_certificate(records),
                indent=2,
                sort_keys=True,
            )
            self.assertEqual(first, second)

    def test_negative_traces_reach_symbolic_validation(self) -> None:
        for path in sorted(MUTATED.glob("*.ndjson")):
            certificate = build_certificate(read_ndjson(path))
            self.assertGreater(certificate["counts"]["actions"], 0)

    def test_checked_in_certificates_are_current(self) -> None:
        inputs = sorted(CAPTURED.glob("*.ndjson")) + sorted(MUTATED.glob("*.ndjson"))
        for path in inputs:
            expected = build_certificate(read_ndjson(path))
            actual = json.loads(
                (CERTIFICATES / f"{path.stem}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(actual, expected, path.name)

    def test_cli_writes_stable_sorted_json(self) -> None:
        output_path = pathlib.Path(__file__).with_name(".reduction-cli.json")
        try:
            for input_path in sorted(CAPTURED.glob("*.ndjson")):
                command = [
                    sys.executable,
                    str(ROOT / "reduction.py"),
                    str(input_path),
                    str(output_path),
                ]
                subprocess.run(command, check=True, cwd=ROOT)
                first = output_path.read_bytes()
                subprocess.run(command, check=True, cwd=ROOT)
                second = output_path.read_bytes()
                self.assertEqual(first, second)
                parsed = json.loads(first)
                self.assertEqual(
                    first,
                    (json.dumps(parsed, indent=2, sort_keys=True) + "\n").encode(),
                )
        finally:
            output_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
