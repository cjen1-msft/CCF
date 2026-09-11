# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compare Lean-emitted SMT with kernel-proved fixture verdicts."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from explorer_api import ExplorerApi
from native_run import NativeRun
from Shared.solver import find_cvc5, run_solver

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("CCF_NATIVE_ARRAY_TESTS") == "1",
    "set CCF_NATIVE_ARRAY_TESTS=1 to run Lean/cvc5 fixtures",
)
class NativeLeanSmtTests(unittest.TestCase):
    def test_proved_fixtures(self):
        result = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeSmtFixtureMain.lean"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertGreaterEqual(len(fixtures), 25)
        self.assertEqual(len(fixtures), len({item["name"] for item in fixtures}))
        self.solve(fixtures)

    def solve(self, fixtures):
        requested = os.environ.get("CVC5")
        solver = find_cvc5(Path(requested) if requested else None)
        with tempfile.TemporaryDirectory(prefix="native-lean-smt-") as temporary:
            artifacts = Path(os.environ.get("CCF_NATIVE_ARRAY_ARTIFACTS", temporary))
            artifacts.mkdir(parents=True, exist_ok=True)
            for fixture in fixtures:
                with self.subTest(name=fixture["name"]):
                    name = f"lean-smt-{fixture['name']}"
                    path = artifacts / f"{name}.smt2"
                    path.write_text(fixture["script"], encoding="ascii")
                    result = run_solver(
                        solver,
                        path,
                        artifacts,
                        name,
                        extra_arguments=("--arrays-exp", "--mbqi"),
                    )
                    self.assertEqual(result.status, fixture["expected"])

    def encode(self, documents):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeEncodeMain.lean",
                "--batch",
            ],
            cwd=ROOT,
            input=json.dumps(
                documents, separators=(",", ":"), sort_keys=True, ensure_ascii=False
            ),
            capture_output=True,
            text=True,
            check=True,
        )
        scripts = json.loads(result.stdout)
        self.assertEqual(len(scripts), len(documents))
        return scripts

    def test_actual_model_check_quorum(self):
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "--run",
                "Sparse/NativeArrayCheckQuorumFixtureMain.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        fixtures = json.loads(result.stdout)
        self.assertEqual(len(fixtures), 150)
        scripts = self.encode([fixture["trace"] for fixture in fixtures])
        self.solve(
            [
                {
                    "name": f"model-quorum-{index}",
                    "script": script,
                    "expected": fixture["expected"],
                }
                for index, (fixture, script) in enumerate(zip(fixtures, scripts))
            ]
        )

    def test_history_and_arbitrary_size(self):
        names = [f"node-{index}" for index in range(21)]
        initial = [
            {"kind": "role", "node": names[0], "value": "leader"},
            {"kind": "logLength", "node": names[0], "value": 0},
            {"kind": "checkQuorum", "node": names[0]},
            {"kind": "role", "node": names[0], "value": "follower"},
            {"kind": "newFollower", "node": names[0], "value": True},
        ]
        cases = [
            ("twenty-one-node-quorum", initial, "sat"),
            (
                "quorum-preserves-history",
                initial + [{"kind": "checkQuorum", "node": names[0]}],
                "unsat",
            ),
            (
                "trillion-entry-log",
                [{"kind": "logLength", "node": names[0], "value": 10**12}],
                "sat",
            ),
        ]
        documents = [
            {
                "nodes": names,
                "bootstrap": [names[0], names[-1]],
                "instructions": instructions,
            }
            for _, instructions, _ in cases
        ]
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )
        self.assertLess(len(scripts[-1]), 100_000)

    def test_typed_observation_values(self):
        cases = []
        roles = ["none", "follower", "preVoteCandidate", "candidate", "leader"]
        for index, role in enumerate(roles):
            observed = {"kind": "role", "node": "a", "value": role}
            cases.append((f"role-{role}", [observed], "sat"))
            cases.append(
                (
                    f"role-{role}-conflict",
                    [
                        observed,
                        {
                            "kind": "role",
                            "node": "a",
                            "value": roles[(index + 1) % len(roles)],
                        },
                    ],
                    "unsat",
                )
            )
        contents = [
            "signature",
            {"transaction": 10**30},
            {"reconfiguration": ["a", "b"]},
            {"retiredCommitted": ["b"]},
        ]
        for index, content in enumerate(contents):
            observed = {
                "kind": "entry",
                "node": "a",
                "index": 0,
                "value": {"term": 10**30, "content": content},
            }
            cases.append((f"entry-variant-{index}", [observed], "sat"))
            other = dict(
                observed,
                value={
                    "term": 10**30,
                    "content": contents[(index + 1) % len(contents)],
                },
            )
            cases.append(
                (f"entry-variant-{index}-conflict", [observed, other], "unsat")
            )
        cases.append(
            (
                "configuration-members-ignore-order-and-duplicates",
                [
                    {
                        "kind": "entry",
                        "node": "a",
                        "index": 0,
                        "value": {"term": 0, "content": {"reconfiguration": members}},
                    }
                    for members in (["a", "b"], ["b", "a", "b"])
                ],
                "sat",
            )
        )
        scripts = self.encode(
            [
                {"nodes": ["a", "b"], "bootstrap": ["a"], "instructions": instructions}
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_retirement_index_observations(self):
        def observed(value):
            return {"kind": "retirementIndex", "node": "a", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        absent = {"kind": "allocated", "node": "a", "value": False}
        cases = [
            ("retirement-none", [observed(None)], "sat"),
            ("retirement-zero", [observed(0)], "sat"),
            ("retirement-absent-node", [absent, observed(None)], "sat"),
            ("retirement-requires-node", [absent, observed(0)], "unsat"),
            (
                "retirement-beyond-log",
                [
                    {"kind": "logLength", "node": "a", "value": 0},
                    observed(10**30),
                ],
                "sat",
            ),
            ("retirement-conflict", [observed(None), observed(0)], "unsat"),
            ("retirement-quorum-frame", [observed(7), quorum, observed(7)], "sat"),
            (
                "retirement-quorum-conflict",
                [observed(7), quorum, observed(None)],
                "unsat",
            ),
        ]
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": instructions,
                }
                for _, instructions, _ in cases
            ]
        )
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )

    def test_decoded_bootstrap_sets(self):
        variants = [["a", "b"], ["b", "a"], ["b", "a", "a"], ["a"]]
        scripts = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": bootstrap,
                    "instructions": [{"kind": "checkQuorum", "node": "a"}],
                }
                for bootstrap in variants
            ]
        )
        self.assertEqual(scripts[1:3], [scripts[0], scripts[0]])
        self.assertNotEqual(scripts[0], scripts[3])

    def test_input_errors_do_not_emit_smt(self):
        valid = {"nodes": ["a"], "bootstrap": ["a"], "instructions": []}
        invalid = [
            (
                "duplicate-field",
                '{"bootstrap":["a"],"instructions":[],"nodes":["a"],"nodes":["a"]}',
            ),
            (
                "unsupported-instruction",
                json.dumps(
                    dict(valid, instructions=[{"kind": "receive", "node": "a"}]),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
            (
                "undeclared-node",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": "allocated", "node": "b", "value": True}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        ]
        invalid.extend(
            (
                name,
                json.dumps(
                    dict(valid, bootstrap=bootstrap),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, bootstrap in [
                ("empty-bootstrap", []),
                ("undeclared-bootstrap-node", ["b"]),
                ("non-array-bootstrap", "a"),
                ("non-string-bootstrap-node", [0]),
            ]
        )
        invalid.extend(
            (
                f"retirement-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {
                                "kind": "retirementIndex",
                                "node": "a",
                                "value": value,
                            }
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, value in [
                ("negative", -1),
                ("fractional", 1.5),
                ("boolean", True),
                ("string", "1"),
            ]
        )
        for name, document in invalid:
            with self.subTest(name=name):
                result = subprocess.run(
                    ["lake", "env", "lean", "--run", "Sparse/NativeEncodeMain.lean"],
                    cwd=ROOT,
                    input=document,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("native encoding error:", result.stderr)

    def test_python_wrapper_and_solver_outcomes(self):
        requested = os.environ.get("CVC5")
        solver = find_cvc5(Path(requested) if requested else None)
        name = "node-\u03bb"
        with tempfile.TemporaryDirectory(prefix="native-lean-cli-") as temporary:
            directory = Path(temporary)
            unknown = directory / "unknown-cvc5"
            unknown.write_text("#!/bin/sh\nprintf 'unknown\\n'\n", encoding="ascii")
            unknown.chmod(0o755)
            for status, instructions, executable in [
                ("sat", [], solver),
                (
                    "unsat",
                    [
                        {"kind": "allocated", "node": name, "value": False},
                        {"kind": "role", "node": name, "value": "leader"},
                    ],
                    solver,
                ),
                ("unknown", [], unknown),
            ]:
                with self.subTest(status=status):
                    path = directory / f"{status}.json"
                    path.write_text(
                        json.dumps(
                            {
                                "nodes": [name],
                                "bootstrap": [name],
                                "instructions": instructions,
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    output = directory / status
                    result = subprocess.run(
                        [
                            sys.executable,
                            "native_lean.py",
                            str(path),
                            "--output-dir",
                            str(output),
                            "--cvc5",
                            str(executable),
                        ],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    summary = json.loads(result.stdout)
                    self.assertEqual(summary["status"], status)
                    self.assertEqual(summary["encoder"], "native-lean-experimental")
                    for artifact in ("trace.smt2", "trace.stdout", "trace.stderr"):
                        self.assertTrue((output / artifact).is_file())
                    snapshot = NativeRun.load(output)
                    api = ExplorerApi(snapshot)
                    self.assertEqual(api.get("/api/run")["result"]["status"], status)
                    self.assertEqual(
                        api.get("/api/instructions")["total"], len(instructions)
                    )
                    self.assertEqual(
                        bool(api.get("/api/core")["clauses"]), status == "unsat"
                    )


if __name__ == "__main__":
    unittest.main()
