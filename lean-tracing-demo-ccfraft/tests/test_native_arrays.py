# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check the direct-array printer against actual Model guards and edge cases."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from native_arrays import SOLVER_ARGUMENTS, encode, unique_object
from Shared.solver import ValidationError, find_cvc5, run_solver, solver_status

ROOT = Path(__file__).resolve().parents[1]


def observation(kind, value, node="a"):
    return {"kind": kind, "node": node, "value": value}


def action(node="a"):
    return {"kind": "checkQuorum", "node": node}


def trace(instructions, nodes=None, bootstrap=None):
    return {
        "nodes": ["a", "b"] if nodes is None else nodes,
        "bootstrap": ["a", "b"] if bootstrap is None else bootstrap,
        "instructions": instructions,
    }


def entry(index, content, term=1, node="a"):
    return {
        "kind": "entry",
        "node": node,
        "index": index,
        "value": {"term": term, "content": content},
    }


class NativeArrayInputTests(unittest.TestCase):
    def test_strict_input(self):
        valid = trace([observation("logLength", 0)])
        invalid = [
            trace([], nodes=[]),
            trace([], nodes=["a", "a"]),
            trace([], bootstrap=[]),
            trace([], bootstrap=["undeclared"]),
            trace([action("undeclared")]),
            trace([{"kind": "send", "node": "a"}]),
            trace([observation("logLength", -1)]),
            trace([observation("logLength", True)]),
            trace([observation("commit", 1.5)]),
            trace([observation("allocated", 1)]),
            trace([observation("role", "bogus")]),
            trace([observation("role", [])]),
            trace([entry(0, {"reconfiguration": ["missing"]})]),
            trace([entry(0, {"transaction": -1})]),
            trace([entry(0, "signature", term=-1)]),
            trace([entry(-1, "signature")]),
            trace([entry(0, {"unknown": 0})]),
            trace([entry(0, {"transaction": 0, "reconfiguration": []})]),
            trace([dict(action(), extra=True)]),
            trace([42]),
            dict(valid, extra=True),
            dict(valid, instructions={}),
        ]
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(ValidationError):
                encode(document)
        with self.assertRaises(ValidationError):
            json.loads('{"nodes": [], "nodes": ["a"]}', object_pairs_hook=unique_object)

    def test_names_are_data(self):
        script = encode(
            trace(
                [action("x)\n(assert false)")],
                nodes=["a", "x)\n(assert false)"],
                bootstrap=["a"],
            )
        )
        self.assertNotIn("assert false", script)
        self.assertEqual(script, encode(trace([action("b")], bootstrap=["a"])))
        self.assertTrue(script.isascii())

    def test_unknown_is_not_a_verdict(self):
        self.assertEqual(solver_status("unknown\n"), "unknown")
        with self.assertRaises(ValidationError):
            solver_status('(error "failure")')

    def test_flat_versions_and_bounded_text(self):
        short = trace([observation("logLength", 10), action()])
        long = trace([observation("logLength", 10**12), action()])
        self.assertEqual(len(encode(long)) - len(encode(short)), 11)
        script = encode(trace([action(), action("b")]))
        self.assertIn("(store role_1 n1 r_follower)", script)
        self.assertNotIn("(store (store", script)
        for line in script.splitlines():
            self.assertEqual(line.count("("), line.count(")"), line)


@unittest.skipUnless(
    os.environ.get("CCF_NATIVE_ARRAY_TESTS") == "1",
    "set CCF_NATIVE_ARRAY_TESTS=1 with Lean and cvc5 available",
)
class NativeArraySolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        requested = os.environ.get("CVC5")
        cls.cvc5 = find_cvc5(Path(requested) if requested else None)
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-arrays-")
        cls.artifacts = Path(
            os.environ.get("CCF_NATIVE_ARRAY_ARTIFACTS", cls.temporary.name)
        )
        cls.artifacts.mkdir(parents=True, exist_ok=True)
        cls.measurements = []

    @classmethod
    def tearDownClass(cls):
        (cls.artifacts / "measurements.json").write_text(
            json.dumps(cls.measurements, indent=2) + "\n", encoding="utf-8"
        )
        cls.temporary.cleanup()

    def solve(self, name, document, expected):
        started = time.perf_counter_ns()
        script = encode(document)
        encoder_ms = (time.perf_counter_ns() - started) / 1_000_000
        path = self.artifacts / f"{name}.smt2"
        path.write_text(script, encoding="ascii")
        result = run_solver(
            self.cvc5, path, self.artifacts, name, extra_arguments=SOLVER_ARGUMENTS
        )
        self.measurements.append(
            {
                "name": name,
                "bytes": len(script),
                "status": result.status,
                "encoder_ms": encoder_ms,
                "solver_ms": result.wall_time_ms,
            }
        )
        self.assertEqual(result.status, expected, name)

    def test_cli(self):
        for name, document, status in (
            ("cli-sat", trace([action()]), "sat"),
            ("cli-unsat", trace([action(), action()]), "unsat"),
            ("cli-unsupported", trace([{"kind": "send", "node": "a"}]), None),
        ):
            with self.subTest(name=name):
                source = self.artifacts / f"{name}.json"
                source.write_text(json.dumps(document), encoding="utf-8")
                output = self.artifacts / name
                completed = subprocess.run(
                    [
                        "python3",
                        "native_arrays.py",
                        str(source),
                        "--output-dir",
                        str(output),
                        "--cvc5",
                        str(self.cvc5),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if status is None:
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn(
                        "instruction 0: unsupported kind 'send'", completed.stderr
                    )
                    self.assertEqual(completed.stdout, "")
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(json.loads(completed.stdout)["status"], status)
                    for filename in ("trace.smt2", "trace.stdout", "trace.stderr"):
                        self.assertTrue((output / filename).is_file())

    def test_actual_model_oracle(self):
        subprocess.run(
            [
                "nice",
                "-n",
                "10",
                "lake",
                "build",
                "Sparse.NativeArrayCheckQuorumFixtureMain",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        generated = subprocess.run(
            [
                "nice",
                "-n",
                "10",
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
        cases = json.loads(generated.stdout)
        self.assertEqual(len(cases), 150)
        self.assertEqual({case["expected"] for case in cases}, {"sat", "unsat"})
        for number, case in enumerate(cases):
            with self.subTest(number=number):
                self.solve(f"model-{number}", case["trace"], case["expected"])

    def test_state_and_history(self):
        cases = [
            ("empty", [], "sat"),
            ("arbitrary-initial", [action()], "sat"),
            (
                "absent-defaults",
                [
                    observation("allocated", False),
                    observation("role", "none"),
                    observation("newFollower", True),
                    observation("logLength", 0),
                    observation("commit", 0),
                ],
                "sat",
            ),
            ("absent-not-leader", [observation("allocated", False), action()], "unsat"),
            (
                "role-needs-allocation",
                [observation("role", "leader"), observation("allocated", False)],
                "unsat",
            ),
            (
                "post-demotion",
                [
                    action(),
                    observation("role", "follower"),
                    observation("newFollower", True),
                ],
                "sat",
            ),
            (
                "post-leader-conflict",
                [action(), observation("role", "leader")],
                "unsat",
            ),
            ("repeat-disabled", [action(), action()], "unsat"),
            (
                "node-frame",
                [
                    observation("role", "candidate", "b"),
                    action(),
                    observation("role", "candidate", "b"),
                ],
                "sat",
            ),
            (
                "node-frame-conflict",
                [
                    observation("role", "candidate", "b"),
                    action(),
                    observation("role", "follower", "b"),
                ],
                "unsat",
            ),
            (
                "log-frame-conflict",
                [observation("logLength", 1), action(), observation("logLength", 2)],
                "unsat",
            ),
            (
                "commit-frame-conflict",
                [observation("commit", 1), action(), observation("commit", 2)],
                "unsat",
            ),
            (
                "entry-frame-conflict",
                [entry(0, "signature"), action(), entry(0, {"transaction": 1})],
                "unsat",
            ),
            (
                "late-log-materialization",
                [
                    action(),
                    observation("logLength", 1),
                    observation("commit", 1),
                    entry(0, {"reconfiguration": ["a"]}),
                ],
                "unsat",
            ),
            (
                "live-bound",
                [observation("logLength", 1), entry(1, "signature")],
                "unsat",
            ),
        ]
        for name, instructions, expected in cases:
            with self.subTest(name=name):
                self.solve(name, trace(instructions), expected)

    def test_symbolic_scale_and_node_count(self):
        for length in (10**6, 10**12):
            self.solve(
                f"symbolic-{length}",
                trace(
                    [
                        observation("logLength", length),
                        observation("commit", length + 100),
                        entry(length - 1, {"reconfiguration": ["a", "b"]}),
                        action(),
                    ]
                ),
                "sat",
            )
            self.solve(
                f"symbolic-self-only-{length}",
                trace(
                    [
                        observation("logLength", length),
                        observation("commit", length),
                        entry(length - 1, {"reconfiguration": ["a"]}),
                        action(),
                    ]
                ),
                "unsat",
            )
        nodes = [f"node-{i}" for i in range(21)]
        self.solve(
            "twenty-one-nodes",
            trace(
                [
                    observation("logLength", 1, nodes[0]),
                    observation("commit", 1, nodes[0]),
                    entry(0, {"reconfiguration": [nodes[-1]]}, node=nodes[0]),
                    action(nodes[0]),
                ],
                nodes=nodes,
                bootstrap=[nodes[0]],
            ),
            "sat",
        )
        nodes = [f"node-{i}" for i in range(200)]
        records = []
        for node in nodes:
            records.extend([observation("logLength", 0, node), action(node)])
        self.solve(
            "four-hundred-records",
            trace(records, nodes=nodes, bootstrap=nodes[:2]),
            "sat",
        )

    def test_tail_irrelevance(self):
        document = trace([observation("logLength", 0), action()])
        script = encode(document)
        # Negative tail payloads deliberately violate the live-entry domain.
        constrained = script.replace(
            "(check-sat)",
            "(assert (= (select (select logs_0 n0) 0) (entry (- 7) (transaction (- 9)))))\n(check-sat)",
        )
        path = self.artifacts / "irrelevant-tail.smt2"
        path.write_text(constrained, encoding="ascii")
        result = run_solver(
            self.cvc5,
            path,
            self.artifacts,
            "irrelevant-tail",
            extra_arguments=SOLVER_ARGUMENTS,
        )
        self.assertEqual(result.status, "sat")
        live = copy.deepcopy(document)
        live["instructions"][0]["value"] = 1
        constrained = encode(live).replace(
            "(check-sat)",
            "(assert (= (select (select logs_0 n0) 0) (entry (- 7) (transaction (- 9)))))\n(check-sat)",
        )
        path.write_text(constrained, encoding="ascii")
        result = run_solver(
            self.cvc5,
            path,
            self.artifacts,
            "invalid-live-entry",
            extra_arguments=SOLVER_ARGUMENTS,
        )
        self.assertEqual(result.status, "unsat")


if __name__ == "__main__":
    unittest.main()
