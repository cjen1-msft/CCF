# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import pathlib
import subprocess

from raft_trace import run_driver


def read_json_traces(output: str) -> list[dict]:
    traces = []
    for line in output.splitlines():
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if parsed.get("tag") == "raft_trace":
            traces.append({"cmd": parsed["cmd"]} if "cmd" in parsed else parsed["msg"])
    return traces


def collect_msgpack_traces(
    driver: pathlib.Path, scenario: pathlib.Path, *, buffered=False
) -> list[dict]:
    result, traces = run_driver(driver, scenario, buffered=buffered)
    result.check_returncode()
    if result.stderr:
        raise AssertionError(result.stderr)
    return [record["msg"] for record in traces]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline_driver", type=pathlib.Path)
    parser.add_argument("candidate_driver", type=pathlib.Path)
    parser.add_argument("scenarios", type=pathlib.Path)
    parser.add_argument("--buffered", action="store_true")
    args = parser.parse_args()

    total = 0
    count = 0
    for scenario in sorted(args.scenarios.rglob("*")):
        if not scenario.is_file():
            continue

        baseline = subprocess.run(
            [args.baseline_driver.resolve(), scenario],
            check=True,
            capture_output=True,
            text=True,
        )
        expected = read_json_traces(baseline.stdout)
        if not any("function" in record for record in expected):
            raise AssertionError(f"{scenario}: baseline has no Raft trace events")
        actual = collect_msgpack_traces(
            args.candidate_driver, scenario, buffered=args.buffered
        )
        if actual != expected:
            mismatch = next(
                (
                    i
                    for i, pair in enumerate(zip(actual, expected))
                    if pair[0] != pair[1]
                ),
                min(len(actual), len(expected)),
            )
            raise AssertionError(
                f"{scenario.name}: trace mismatch at event {mismatch}; "
                f"expected {len(expected)} events, got {len(actual)}\n"
                f"Expected: {expected[mismatch:mismatch+1]}\n"
                f"Actual: {actual[mismatch:mismatch+1]}"
            )

        print(f"{scenario.name}: {len(actual)} traces match")
        total += len(actual)
        count += 1
    if count == 0:
        raise AssertionError("No scenarios found")
    print(f"{total} records match across {count} scenarios")


if __name__ == "__main__":
    main()
