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

from native_arrays import (
    GLOBAL_FIELDS,
    NODE_FIELDS,
    ROLES,
    SOLVER_ARGUMENTS,
    Encoder,
    encode,
    unique_object,
)
from native_packets import PACKET_FIELDS
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


def vote(pre_vote=False, source="a", destination="b"):
    return {
        "kind": "requestPreVote" if pre_vote else "requestVote",
        "source": source,
        "destination": destination,
    }


def queue_length(value, source="a", destination="b"):
    return dict(
        vote(source=source, destination=destination), kind="queueLength", value=value
    )


def update_term(source="a", destination="b"):
    return dict(vote(source=source, destination=destination), kind="updateTerm")


def peer_index(kind, value, node="a", peer="b"):
    return dict(observation(kind, value, node), peer=peer)


def queue_point(index, pre_vote=False, **packet_fields):
    return {
        "kind": "queuePoint",
        "source": "a",
        "destination": "b",
        "index": index,
        "value": {
            "kind": "requestPreVote" if pre_vote else "requestVoteRequest",
            "term": 4,
            "lastCommittableTerm": 0,
            "lastCommittableIndex": 0,
            "source": "a",
            "destination": "b",
            **packet_fields,
        },
    }


def vote_initial(pre_vote=False):
    return [
        observation("role", "preVoteCandidate" if pre_vote else "candidate"),
        observation("logLength", 0),
        observation("currentTerm", 4),
        observation("commit", 0),
    ]


def queued_packet(kind, index=0, **overrides):
    value = {
        field: {"Int": 0, "Bool": False, "Node": "a", "(Array Int Entry)": []}[sort]
        for field, sort in PACKET_FIELDS[kind]
        if field != "entriesLength"
    }
    value.update({"kind": kind, "destination": "b", **overrides})
    return dict(queue_point(index), value=value)


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
            trace([observation("currentTerm", -1)]),
            trace([queue_length(True)]),
            trace([queue_point(-1)]),
            trace([queue_point(0, term=-1)]),
            trace([queue_point(0, kind="appendEntriesResponse")]),
            trace([queue_point(0, source="missing")]),
            trace([queue_point(0, kind=[])]),
            trace([queued_packet("appendEntriesRequest", entries={})]),
            trace(
                [
                    queued_packet(
                        "appendEntriesRequest",
                        entries=[{"term": -1, "content": "signature"}],
                    )
                ]
            ),
            trace([queued_packet("appendEntriesRequest", entriesLength=0)]),
            trace([queued_packet("requestVoteResponse", voteGranted=1)]),
            trace([queued_packet("appendEntriesResponse", success="false")]),
            trace([observation("votedFor", "missing")]),
            trace([observation("votedFor", False)]),
            trace([observation("votesGranted", ["missing"])]),
            trace([observation("preVotesGranted", None)]),
            trace([observation("membershipState", "unknown")]),
            trace([observation("retirementIndex", -1)]),
            trace([observation("retirementCommittableIndex", False)]),
            trace([observation("retiredCommittedIndex", "1")]),
            trace([observation("sentIndex", 0)]),
            trace([peer_index("matchIndex", 0, peer="missing")]),
            trace([peer_index("sentIndex", True)]),
            trace([{"kind": "hasJoined", "value": ["missing"]}]),
            trace([observation("preVoteStatus", "unknown")]),
            trace([observation("retirementCompleted", None)]),
            trace([{"kind": "submittedTxId", "txId": -1, "value": True}]),
            trace([{"kind": "submittedTxId", "txId": 7, "value": 1}]),
            trace([{"kind": "hasJoined", "node": "a", "value": []}]),
            trace([dict(vote(), destination="missing")]),
            trace([dict(vote(), extra=True)]),
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

    def test_vote_reader_versions(self):
        encoder = Encoder(trace([]))
        first = encoder.configuration_index("n0")
        snapshot = encoder.election_snapshot("n0")
        self.assertEqual(first, encoder.configuration_index("n0"))
        self.assertEqual(snapshot, encoder.election_snapshot("n0"))
        encoder.refs["role"] = "role_1"
        self.assertEqual(first, encoder.configuration_index("n0"))
        self.assertEqual(snapshot, encoder.election_snapshot("n0"))
        encoder.event += 1
        encoder.refs["commit"] = "commit_1"
        self.assertNotEqual(first, encoder.configuration_index("n0"))
        self.assertNotEqual(snapshot, encoder.election_snapshot("n0"))
        script = encode(trace([vote(), vote()]))
        self.assertEqual(script.count("(declare-const signature_n0_"), 1)
        self.assertEqual(script.count("(declare-const current_n0_"), 1)
        self.assertIn("(store q_n1_n0_cells_1 ", script)
        self.assertNotIn("(store (store", script)

    def test_initial_columns_are_declared_on_first_use(self):
        script = encode(trace([vote(), update_term()]))
        for field in (
            "sentIndex",
            "matchIndex",
            "retirementIndex",
            "retirementCommittableIndex",
            "retiredCommittedIndex",
        ):
            self.assertNotIn(f"(declare-const {field}_0 ", script)
        script = encode(
            trace(
                [
                    update_term(),
                    observation("votedFor", None, "b"),
                    peer_index("sentIndex", 99),
                    peer_index("sentIndex", 99),
                ]
            )
        )
        self.assertEqual(script.count("(declare-const sentIndex_0 "), 1)
        self.assertEqual(script.count("(declare-const votedFor_0 "), 1)
        self.assertIn("(store votedFor_0 n1 noNode)", script)
        self.assertIn("(select votedFor_1 n1)", script)
        self.assertNotIn("sentIndex_1", script)


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
        self.solve_script(name, script, expected, encoder_ms)

    def solve_script(self, name, script, expected, encoder_ms=0):
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

    def model_fixtures(self, module):
        subprocess.run(
            [
                "nice",
                "-n",
                "10",
                "lake",
                "build",
                f"Sparse.{module}",
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
                f"Sparse/{module}.lean",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(generated.stdout)

    def test_actual_model_oracle(self):
        cases = self.model_fixtures("NativeArrayCheckQuorumFixtureMain")
        self.assertEqual(len(cases), 150)
        self.assertEqual({case["expected"] for case in cases}, {"sat", "unsat"})
        for number, case in enumerate(cases):
            with self.subTest(number=number):
                self.solve(f"model-{number}", case["trace"], case["expected"])

    def test_vote_model_oracle(self):
        cases = self.model_fixtures("NativeArrayVoteFixtureMain")
        self.assertEqual(len(cases), 400)
        self.assertEqual({case["expected"] for case in cases}, {"sat", "unsat"})
        for number, case in enumerate(cases):
            with self.subTest(number=number):
                self.solve(f"vote-model-{number}", case["trace"], case["expected"])

    def test_term_model_oracle(self):
        cases = self.model_fixtures("NativeArrayTermFixtureMain")
        self.assertEqual(len(cases), 168)
        self.assertEqual({case["expected"] for case in cases}, {"sat", "unsat"})
        for number, case in enumerate(cases):
            with self.subTest(number=number):
                self.solve(f"term-model-{number}", case["trace"], case["expected"])

    def test_full_node_model_oracle(self):
        cases = self.model_fixtures("NativeArrayNodeFixtureMain")
        self.assertEqual(len(cases), 360)
        observations = {
            instruction["kind"]
            for case in cases
            for instruction in case["trace"]["instructions"]
            if "node" in instruction
            and "value" in instruction
            and instruction["kind"] not in GLOBAL_FIELDS
        }
        self.assertEqual(observations, (NODE_FIELDS.keys() - {"logs"}) | {"entry"})
        self.assertEqual({case["expected"] for case in cases}, {"sat", "unsat"})
        for number, case in enumerate(cases):
            with self.subTest(number=number):
                self.solve(f"full-node-model-{number}", case["trace"], case["expected"])

    def test_global_history(self):
        for before, after in (
            ({"kind": "hasJoined", "value": ["b"]}, {"kind": "hasJoined", "value": []}),
            (
                observation("preVoteStatus", "enabled"),
                observation("preVoteStatus", "capable"),
            ),
            (
                observation("retirementCompleted", ["b"]),
                observation("retirementCompleted", []),
            ),
            (
                {"kind": "submittedTxId", "txId": 10**12, "value": True},
                {"kind": "submittedTxId", "txId": 10**12, "value": False},
            ),
        ):
            kind = before["kind"]
            self.solve(f"global-frame-{kind}", trace([before, action(), before]), "sat")
            self.solve(
                f"global-conflict-{kind}", trace([before, action(), after]), "unsat"
            )
        self.solve(
            "globals-independent-of-allocation",
            trace(
                [
                    observation("allocated", False),
                    observation("preVoteStatus", "enabled"),
                    observation("retirementCompleted", ["a"]),
                    {"kind": "hasJoined", "value": ["a"]},
                ]
            ),
            "sat",
        )
        self.solve(
            "submitted-arbitrary-identities",
            trace(
                [
                    {"kind": "submittedTxId", "txId": key, "value": present}
                    for key, present in (
                        (0, False),
                        (7, True),
                        (10**12, True),
                        (10**12 + 1, False),
                    )
                ]
            ),
            "sat",
        )
        script = encode(trace([{"kind": "submittedTxId", "txId": 7, "value": True}]))
        self.solve_script(
            "submitted-live-bound",
            script.replace(
                "(check-sat)", "(assert (= submitted_limit_0 7))\n(check-sat)"
            ),
            "unsat",
        )
        self.solve_script(
            "submitted-tail",
            script.replace(
                "(check-sat)",
                "(assert (select global_submittedTxIds_0 submitted_limit_0))\n(check-sat)",
            ),
            "unsat",
        )

    def test_full_node_history(self):
        values = {
            "votedFor": ("b", None),
            "votesGranted": (["a", "b"], ["a"]),
            "preVotesGranted": (["b"], []),
            "membershipState": ("retiredCommitted", "active"),
            "retirementIndex": (None, 0),
            "retirementCommittableIndex": (99, None),
            "retiredCommittedIndex": (0, 1),
        }
        for kind, (before, wrong) in values.items():
            initial = [observation(kind, before), action()]
            self.solve(
                f"full-node-frame-{kind}",
                trace([*initial, observation(kind, before)]),
                "sat",
            )
            self.solve(
                f"full-node-conflict-{kind}",
                trace([*initial, observation(kind, wrong)]),
                "unsat",
            )
        for kind in ("sentIndex", "matchIndex"):
            self.solve(
                f"peer-table-{kind}",
                trace(
                    [
                        peer_index(kind, 7, peer="a"),
                        peer_index(kind, 99),
                        action(),
                        peer_index(kind, 7, peer="a"),
                        peer_index(kind, 99),
                        peer_index(kind, 3, node="b", peer="a"),
                    ]
                ),
                "sat",
            )
            self.solve(
                f"peer-table-conflict-{kind}",
                trace([peer_index(kind, 99), action(), peer_index(kind, 100)]),
                "unsat",
            )
            self.solve(
                f"absent-peer-{kind}",
                trace([observation("allocated", False), peer_index(kind, 1)]),
                "unsat",
            )
        initial = [
            observation("votedFor", "a", "b"),
            observation("votesGranted", ["a", "b"], "b"),
            observation("preVotesGranted", ["a"], "b"),
            observation("currentTerm", 1, "b"),
            queue_point(0),
            update_term(),
        ]
        self.solve(
            "term-clears-election-fields",
            trace(
                [
                    *initial,
                    observation("votedFor", None, "b"),
                    observation("preVotesGranted", [], "b"),
                    observation("votesGranted", ["a", "b"], "b"),
                ]
            ),
            "sat",
        )
        for kind, wrong in (
            ("votedFor", "a"),
            ("preVotesGranted", ["a"]),
            ("votesGranted", []),
        ):
            self.solve(
                f"term-election-field-conflict-{kind}",
                trace([*initial, observation(kind, wrong, "b")]),
                "unsat",
            )

    def test_term_history(self):
        initial = [
            *vote_initial(),
            observation("currentTerm", 1, "b"),
            queue_length(0),
            vote(),
        ]
        cases = [
            (
                "term-update",
                [
                    update_term(),
                    observation("currentTerm", 4, "b"),
                    observation("role", "follower", "b"),
                    observation("newFollower", True, "b"),
                    queue_length(1),
                    queue_point(0),
                ],
                "sat",
            ),
            ("term-no-pop", [update_term(), queue_length(0)], "unsat"),
            ("term-repeat-disabled", [update_term(), update_term()], "unsat"),
            (
                "term-source-frame",
                [
                    update_term(),
                    observation("role", "candidate"),
                    observation("currentTerm", 4),
                ],
                "sat",
            ),
            (
                "term-source-conflict",
                [update_term(), observation("currentTerm", 5)],
                "unsat",
            ),
            (
                "term-role-conflict",
                [update_term(), observation("role", "leader", "b")],
                "unsat",
            ),
            (
                "term-late-packet-conflict",
                [update_term(), queue_point(0, term=5)],
                "unsat",
            ),
            (
                "term-other-queue",
                [queue_length(3, "b", "a"), update_term(), queue_length(3, "b", "a")],
                "sat",
            ),
            ("term-check-quorum-disabled", [update_term(), action("b")], "unsat"),
        ]
        for name, instructions, expected in cases:
            with self.subTest(name=name):
                self.solve(name, trace([*initial, *instructions]), expected)
        self.solve("term-empty-queue", trace([queue_length(0), update_term()]), "unsat")
        for role in ROLES:
            self.solve(
                f"term-any-role-{role}",
                trace([observation("role", role, "b"), *initial, update_term()]),
                "sat",
            )
        self.solve(
            "term-first-source-head",
            trace(
                [
                    observation("currentTerm", 2, "b"),
                    queue_length(2),
                    queue_point(0, term=1),
                    queue_point(1, term=3),
                    update_term(),
                ]
            ),
            "unsat",
        )
        self.solve(
            "term-symbolic-queue",
            trace(
                [
                    queue_length(10**12),
                    update_term(),
                    queue_length(10**12),
                    observation("currentTerm", 7, "b"),
                    queue_point(0, term=7),
                ]
            ),
            "sat",
        )

    def test_full_packet_observations(self):
        for kind in PACKET_FIELDS:
            point = queued_packet(kind)
            self.solve(
                f"packet-repeat-{kind}", trace([queue_length(1), point, point]), "sat"
            )
            changed = copy.deepcopy(point)
            changed["value"]["term"] = 1
            self.solve(f"packet-conflict-{kind}", trace([point, changed]), "unsat")
        payload = [
            {"term": 8, "content": "signature"},
            {"term": 2, "content": {"transaction": 7}},
            {"term": 1, "content": {"reconfiguration": ["a"]}},
        ]
        point = queued_packet("appendEntriesRequest", entries=payload)
        self.solve("packet-live-payload", trace([point, point]), "sat")
        changed = copy.deepcopy(point)
        changed["value"]["entries"][1]["content"]["transaction"] = 8
        self.solve("packet-live-payload-conflict", trace([point, changed]), "unsat")
        self.solve(
            "packet-payload-length-conflict",
            trace([point, queued_packet("appendEntriesRequest")]),
            "unsat",
        )
        script = encode(trace([point]))
        self.solve_script(
            "packet-observation-tail",
            script.replace(
                "(check-sat)",
                "(assert (= (select observed_entries_0 3) (entry (- 1) signature)))\n(check-sat)",
            ),
            "sat",
        )

    def test_term_scale(self):
        nodes = [f"node-{index}" for index in range(100)]
        instructions = [
            observation("role", "candidate", nodes[0]),
            observation("logLength", 0, nodes[0]),
            observation("currentTerm", 4, nodes[0]),
            observation("commit", 0, nodes[0]),
        ]
        for node in nodes[1:]:
            instructions.extend(
                [
                    vote(source=nodes[0], destination=node),
                    update_term(nodes[0], node),
                    queue_length(1, nodes[0], node),
                    observation("currentTerm", 4, node),
                ]
            )
        self.assertEqual(len(instructions), 400)
        self.solve(
            "term-four-hundred-records", trace(instructions, nodes, nodes), "sat"
        )

    def test_vote_guards_and_packets(self):
        for pre_vote in (False, True):
            initial = vote_initial(pre_vote)
            send = vote(pre_vote)
            for role in ROLES:
                expected = "sat" if role == initial[0]["value"] else "unsat"
                self.solve(
                    f"vote-role-{pre_vote}-{role}",
                    trace([observation("role", role), *initial[1:], send]),
                    expected,
                )
            for node in ("a", "b"):
                self.solve(
                    f"vote-absent-{pre_vote}-{node}",
                    trace([*initial, observation("allocated", False, node), send]),
                    "unsat",
                )
            self.solve(
                f"vote-self-{pre_vote}",
                trace([*initial, dict(send, destination="a")]),
                "unsat",
            )
            base = [*initial, queue_length(0), send]
            self.solve(
                f"vote-duplicates-{pre_vote}",
                trace(
                    [
                        *base,
                        queue_point(0, pre_vote),
                        send,
                        queue_length(2),
                        queue_point(1, pre_vote),
                    ]
                ),
                "sat",
            )
            self.solve(
                f"vote-not-deduplicated-{pre_vote}",
                trace([*base, send, queue_length(1)]),
                "unsat",
            )
            wrong_fields = {
                "kind": "requestVoteRequest" if pre_vote else "requestPreVote",
                "term": 5,
                "lastCommittableTerm": 1,
                "lastCommittableIndex": 1,
                "source": "b",
                "destination": "a",
            }
            for field, wrong in wrong_fields.items():
                self.solve(
                    f"vote-wrong-{pre_vote}-{field}",
                    trace([*base, queue_point(0, pre_vote, **{field: wrong})]),
                    "unsat",
                )

    def test_vote_initial_queues_and_history(self):
        for name, instructions, expected in (
            (
                "late-initial-packet",
                [vote(), queue_point(0, term=7), queue_point(1), queue_length(2)],
                "sat",
            ),
            (
                "late-initial-source",
                [queue_length(1), queue_point(0, source="b")],
                "unsat",
            ),
            (
                "malformed-initial-destination",
                [queue_length(1), queue_point(0, destination="a")],
                "sat",
            ),
            (
                "initial-packet-conflict",
                [queue_point(0, term=7), vote(), queue_point(0, term=8)],
                "unsat",
            ),
            (
                "queue-frame",
                [queue_length(3, "b", "a"), vote(), queue_length(3, "b", "a")],
                "sat",
            ),
            (
                "queue-frame-conflict",
                [queue_length(3, "b", "a"), vote(), queue_length(4, "b", "a")],
                "unsat",
            ),
            ("point-live-bound", [queue_length(0), vote(), queue_point(1)], "unsat"),
            ("term-history", [vote(), observation("currentTerm", 5)], "unsat"),
            ("late-initial-role", [vote(), observation("role", "leader")], "unsat"),
            (
                "combined-node-and-vote",
                [action("b"), vote(), observation("role", "follower", "b")],
                "sat",
            ),
        ):
            with self.subTest(name=name):
                self.solve(name, trace([*vote_initial(), *instructions]), expected)
        self.solve(
            "late-vote-term",
            trace(
                [
                    queue_length(0),
                    vote(),
                    queue_point(0, term=7),
                    observation("currentTerm", 8),
                ]
            ),
            "unsat",
        )

    def test_vote_scale(self):
        length = 10**12
        self.solve(
            "vote-symbolic-log-and-queue",
            trace(
                [
                    observation("role", "candidate"),
                    observation("logLength", length),
                    observation("commit", length),
                    observation("currentTerm", 4),
                    entry(length - 1, "signature", term=9),
                    queue_length(length),
                    vote(),
                    queue_length(length + 1),
                    queue_point(
                        length, lastCommittableIndex=length, lastCommittableTerm=9
                    ),
                ]
            ),
            "sat",
        )
        nodes = [f"node-{index}" for index in range(21)]
        self.solve(
            "vote-twenty-one-nodes",
            trace(
                [
                    observation("logLength", 0, nodes[0]),
                    vote(source=nodes[0], destination=nodes[-1]),
                ],
                nodes=nodes,
                bootstrap=nodes,
            ),
            "sat",
        )
        instructions = [
            observation("role", "candidate"),
            observation("logLength", 0),
            observation("currentTerm", 4),
            queue_length(0),
        ]
        for index in range(198):
            instructions.extend([vote(), queue_length(index + 1)])
        self.assertEqual(len(instructions), 400)
        self.solve("vote-four-hundred-records", trace(instructions), "sat")

    def test_initial_packet_domains(self):
        script = encode(trace([queue_length(1)]))
        script = script.replace(
            "(check-sat)",
            "(declare-const payload (Array Int Entry))\n"
            "(assert (= (select payload 0) (entry 0 (transaction 7))))\n"
            "(assert (= (select payload 1) (entry (- 1) signature)))\n(check-sat)",
        )
        for kind, schema in PACKET_FIELDS.items():
            arguments = {
                field: {
                    "Int": "0",
                    "Bool": "false",
                    "Node": "n0",
                    "(Array Int Entry)": "payload",
                }[sort]
                for field, sort in schema
            }
            if kind == "appendEntriesRequest":
                arguments["entriesLength"] = "1"
            variants = [("valid", arguments, "sat")]
            variants.extend(
                (field, dict(arguments, **{field: "(- 1)"}), "unsat")
                for field, sort in schema
                if sort == "Int"
            )
            if kind == "appendEntriesRequest":
                variants.append(
                    ("live-payload", dict(arguments, entriesLength="2"), "unsat")
                )
            for name, values, expected in variants:
                packet = (
                    f"(msg_{kind} {' '.join(values[field] for field, _ in schema)})"
                )
                constrained = script.replace(
                    "(check-sat)",
                    f"(assert (= (select q_n1_n0_cells_0 q_n1_n0_head_0) {packet}))\n(check-sat)",
                )
                with self.subTest(kind=kind, name=name):
                    self.solve_script(
                        f"packet-domain-{kind}-{name}", constrained, expected
                    )

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
                    observation("currentTerm", 0),
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
