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
RETIREMENT_FIELDS = (
    "retirementIndex",
    "retirementCommittableIndex",
    "retiredCommittedIndex",
)
VOTE_SET_FIELDS = ("votesGranted", "preVotesGranted")
PEER_INDEX_FIELDS = ("sentIndex", "matchIndex")
MEMBERSHIP_STATES = (
    "active",
    "retirementOrdered",
    "retirementSigned",
    "retirementCompleted",
    "retiredCommitted",
)


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
        self.assertGreaterEqual(len(fixtures), 62)
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

    def framed_observation_cases(
        self, kind, default, value, other, *, allocation_guarded=True
    ):
        """Cases for quorum framing and allocation-dependent or global fields."""

        def observed(value):
            return {"kind": kind, "node": "a", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        absent = {"kind": "allocated", "node": "a", "value": False}
        cases = [
            ("default", [observed(default)], "sat"),
            ("value", [observed(value)], "sat"),
            ("absent-node", [absent, observed(default)], "sat"),
            (
                "requires-node" if allocation_guarded else "unallocated-value",
                [absent, observed(value)],
                "unsat" if allocation_guarded else "sat",
            ),
            ("default-conflict", [observed(default), observed(value)], "unsat"),
            ("value-conflict", [observed(value), observed(other)], "unsat"),
            ("quorum-frame", [observed(value), quorum, observed(value)], "sat"),
            (
                "quorum-conflict",
                [observed(value), quorum, observed(default)],
                "unsat",
            ),
        ]
        return [
            (f"{kind}-{name}", instructions, expected)
            for name, instructions, expected in cases
        ]

    def test_retirement_index_observations(self):
        cases = [
            case
            for kind in RETIREMENT_FIELDS
            for case in self.framed_observation_cases(kind, None, 0, 10**30)
        ]
        cases.extend(
            (
                f"{kind}-beyond-log",
                [
                    {"kind": "logLength", "node": "a", "value": 0},
                    {"kind": kind, "node": "a", "value": 10**30},
                ],
                "sat",
            )
            for kind in RETIREMENT_FIELDS
        )
        independent = [
            {"kind": kind, "node": "a", "value": index}
            for index, kind in enumerate(RETIREMENT_FIELDS)
        ]
        cases.append(
            (
                "independent-retirement-fields",
                independent + [{"kind": "checkQuorum", "node": "a"}] + independent,
                "sat",
            )
        )
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

    def test_voted_for_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = self.framed_observation_cases("votedFor", None, names[-1], "a")
        cases.extend(
            [
                (
                    "votedFor-self",
                    [{"kind": "votedFor", "node": "a", "value": "a"}],
                    "sat",
                ),
                (
                    "votedFor-absent-target-outside-bootstrap",
                    [
                        {"kind": "allocated", "node": names[-1], "value": False},
                        {"kind": "votedFor", "node": "a", "value": names[-1]},
                    ],
                    "sat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": names,
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

    def test_vote_set_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = []
        for kind in VOTE_SET_FIELDS:
            cases.extend(self.framed_observation_cases(kind, [], [names[-1]], ["a"]))
            cases.extend(
                [
                    (
                        f"{kind}-order-and-duplicates",
                        [
                            {"kind": kind, "node": "a", "value": members}
                            for members in (
                                ["a", names[-1]],
                                [names[-1], "a", names[-1]],
                            )
                        ],
                        "sat",
                    ),
                    (
                        f"{kind}-absent-voter-outside-bootstrap",
                        [
                            {"kind": "allocated", "node": names[-1], "value": False},
                            {"kind": kind, "node": "a", "value": [names[-1]]},
                        ],
                        "sat",
                    ),
                ]
            )
        scripts = self.encode(
            [
                {
                    "nodes": names,
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

    def test_vote_set_independence(self):
        observed = [
            {"kind": "votesGranted", "node": "a", "value": ["a"]},
            {"kind": "preVotesGranted", "node": "a", "value": ["b"]},
        ]
        script = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": observed
                    + [{"kind": "checkQuorum", "node": "a"}]
                    + observed,
                }
            ]
        )[0]
        self.solve(
            [{"name": "independent-vote-sets", "script": script, "expected": "sat"}]
        )

    def test_membership_observations(self):
        def observed(value):
            return {"kind": "membershipState", "node": "a", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        cases = self.framed_observation_cases(
            "membershipState", "active", "retirementOrdered", "retiredCommitted"
        )
        for index, state in enumerate(MEMBERSHIP_STATES):
            cases.extend(
                [
                    (f"membership-{state}", [observed(state)], "sat"),
                    (
                        f"membership-{state}-conflict",
                        [
                            observed(state),
                            observed(
                                MEMBERSHIP_STATES[(index + 1) % len(MEMBERSHIP_STATES)]
                            ),
                        ],
                        "unsat",
                    ),
                    (
                        f"membership-{state}-frame",
                        [observed(state), quorum, observed(state)],
                        "sat",
                    ),
                    (
                        f"membership-{state}-absent",
                        [
                            {"kind": "allocated", "node": "a", "value": False},
                            observed(state),
                        ],
                        "sat" if state == "active" else "unsat",
                    ),
                ]
            )
        cases.append(
            (
                "membership-does-not-infer-retirement-indices",
                [observed("retiredCommitted")]
                + [
                    {"kind": kind, "node": "a", "value": None}
                    for kind in RETIREMENT_FIELDS
                ],
                "sat",
            )
        )
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

    def test_peer_index_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = []
        for kind in PEER_INDEX_FIELDS:
            cases.extend(
                (
                    name,
                    [
                        dict(item, peer=names[-1]) if item["kind"] == kind else item
                        for item in instructions
                    ],
                    expected,
                )
                for name, instructions, expected in self.framed_observation_cases(
                    kind, 0, 10**30, 7
                )
            )
            cases.extend(
                [
                    (
                        f"{kind}-beyond-log",
                        [
                            {"kind": "logLength", "node": "a", "value": 0},
                            {
                                "kind": kind,
                                "node": "a",
                                "peer": names[-1],
                                "value": 10**30,
                            },
                        ],
                        "sat",
                    ),
                    (
                        f"{kind}-absent-peer",
                        [
                            {"kind": "allocated", "node": names[-1], "value": False},
                            {
                                "kind": kind,
                                "node": "a",
                                "peer": names[-1],
                                "value": 42,
                            },
                        ],
                        "sat",
                    ),
                    (
                        f"{kind}-independent-cells",
                        [
                            {"kind": kind, "node": "a", "peer": "a", "value": 1},
                            {"kind": kind, "node": "a", "peer": "b", "value": 2},
                            {"kind": kind, "node": "b", "peer": "a", "value": 3},
                        ],
                        "sat",
                    ),
                ]
            )
        scripts = self.encode(
            [
                {
                    "nodes": names,
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

    def test_complete_local_state_frame(self):
        values = {
            "allocated": True,
            "role": "leader",
            "newFollower": False,
            "logLength": 1,
            "commit": 9,
            "currentTerm": 3,
            "retirementIndex": None,
            "retirementCommittableIndex": 0,
            "retiredCommittedIndex": 10**30,
            "votedFor": "b",
            "votesGranted": ["a"],
            "preVotesGranted": ["b"],
            "membershipState": "retirementSigned",
        }
        observed = [
            {"kind": kind, "node": "a", "value": value}
            for kind, value in values.items()
        ] + [
            {
                "kind": "entry",
                "node": "a",
                "index": 0,
                "value": {"term": 10**30, "content": {"transaction": 42}},
            },
            {"kind": "sentIndex", "node": "a", "peer": "b", "value": 10**30},
            {"kind": "matchIndex", "node": "a", "peer": "b", "value": 3},
        ]
        after = [
            (
                dict(item, value="follower")
                if item["kind"] == "role"
                else dict(item, value=True) if item["kind"] == "newFollower" else item
            )
            for item in observed
        ]
        script = self.encode(
            [
                {
                    "nodes": ["a", "b"],
                    "bootstrap": ["a", "b"],
                    "instructions": observed
                    + [{"kind": "checkQuorum", "node": "a"}]
                    + after,
                }
            ]
        )[0]
        self.solve(
            [
                {
                    "name": "complete-local-state-frame",
                    "script": script,
                    "expected": "sat",
                }
            ]
        )

    def test_joined_set_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]

        def observed(value):
            return {"kind": "hasJoined", "value": value}

        quorum = {"kind": "checkQuorum", "node": "a"}
        cases = [
            ("joined-empty", [observed([])], "sat"),
            ("joined-all-identities", [observed(names)], "sat"),
            (
                "joined-order-and-duplicates",
                [observed(["a", names[-1]]), observed([names[-1], "a", "a"])],
                "sat",
            ),
            ("joined-empty-conflict", [observed([]), observed(["a"])], "unsat"),
            ("joined-value-conflict", [observed(["a"]), observed(["b"])], "unsat"),
            (
                "joined-independent-of-allocation",
                [{"kind": "allocated", "node": name, "value": False} for name in names]
                + [observed(names)],
                "sat",
            ),
            ("joined-empty-quorum-frame", [observed([]), quorum, observed([])], "sat"),
            ("joined-quorum-frame", [observed(["a"]), quorum, observed(["a"])], "sat"),
            (
                "joined-quorum-conflict",
                [observed(["a"]), quorum, observed(["b"])],
                "unsat",
            ),
        ]
        scripts = self.encode(
            [
                {
                    "nodes": names,
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

    def test_pre_vote_status_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = self.framed_observation_cases(
            "preVoteStatus", "capable", "enabled", "capable", allocation_guarded=False
        )
        mixed = [
            {
                "kind": "preVoteStatus",
                "node": node,
                "value": "enabled" if index % 2 else "capable",
            }
            for index, node in enumerate(names)
        ]
        cases.extend(
            [
                (
                    "pre-vote-independent-rows-and-joined-set",
                    mixed
                    + [
                        {"kind": "hasJoined", "value": [names[-1]]},
                        {"kind": "checkQuorum", "node": "a"},
                    ]
                    + mixed,
                    "sat",
                ),
                (
                    "pre-vote-all-nodes-absent",
                    [
                        {"kind": "allocated", "node": node, "value": False}
                        for node in names
                    ]
                    + mixed,
                    "sat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": names,
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

    def test_pre_vote_status_input_errors(self):
        valid = {"kind": "preVoteStatus", "node": "a", "value": "capable"}
        self.assert_invalid_instructions(
            [
                dict(valid, value="unknown"),
                dict(valid, value=True),
                dict(valid, value=None),
                dict(valid, value=0),
                dict(valid, node="b"),
                dict(valid, peer="a"),
                {"kind": "preVoteStatus", "value": "capable"},
            ]
        )

    def test_retirement_completed_observations(self):
        names = ["a", "b"] + [f"node-{index}" for index in range(2, 21)]
        cases = self.framed_observation_cases(
            "retirementCompleted", [], [names[-1]], ["a"], allocation_guarded=False
        )
        mixed = [
            {"kind": "retirementCompleted", "node": node, "value": names[: index + 1]}
            for index, node in enumerate(names)
        ]
        cases.extend(
            [
                (
                    "completed-order-and-duplicates",
                    [
                        {"kind": "retirementCompleted", "node": "a", "value": names},
                        {
                            "kind": "retirementCompleted",
                            "node": "a",
                            "value": list(reversed(names)) + names,
                        },
                    ],
                    "sat",
                ),
                (
                    "completed-independent-rows-and-local-state",
                    mixed
                    + [
                        {"kind": kind, "node": "a", "value": None}
                        for kind in RETIREMENT_FIELDS
                    ]
                    + [
                        {"kind": "membershipState", "node": "a", "value": "active"},
                        {"kind": "hasJoined", "value": []},
                        {"kind": "preVoteStatus", "node": "a", "value": "enabled"},
                        {"kind": "checkQuorum", "node": "a"},
                    ]
                    + mixed,
                    "sat",
                ),
                (
                    "completed-all-nodes-absent",
                    [
                        {"kind": "allocated", "node": node, "value": False}
                        for node in names
                    ]
                    + mixed,
                    "sat",
                ),
            ]
        )
        scripts = self.encode(
            [
                {
                    "nodes": names,
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

    def test_retirement_completed_input_errors(self):
        valid = {"kind": "retirementCompleted", "node": "a", "value": []}
        self.assert_invalid_instructions(
            [
                dict(valid, value=["b"]),
                dict(valid, value=[0]),
                dict(valid, value="a"),
                dict(valid, value=None),
                dict(valid, node="b"),
                dict(valid, peer="a"),
                {"kind": "retirementCompleted", "value": []},
            ]
        )

    def test_submitted_transaction_observations(self):
        names = ["a", "b"]

        def observed(tx_id, present):
            return {"kind": "submittedTxId", "txId": tx_id, "value": present}

        quorum = {"kind": "checkQuorum", "node": "a"}
        cases = []
        for tx_id in (0, 7, 10**30):
            for present in (False, True):
                observation = observed(tx_id, present)
                cases.extend(
                    [
                        (f"submitted-{tx_id}-{present}", [observation], "sat"),
                        (
                            f"submitted-{tx_id}-{present}-quorum-frame",
                            [observation, quorum, observation],
                            "sat",
                        ),
                        (
                            f"submitted-{tx_id}-{present}-conflict",
                            [observation, quorum, observed(tx_id, not present)],
                            "unsat",
                        ),
                    ]
                )
        cases.extend(
            [
                (
                    "submitted-observations-do-not-exhaust-set",
                    [observed(0, False), observed(7, False), observed(10**30, True)],
                    "sat",
                ),
                (
                    "submitted-independent-of-nodes-and-other-globals",
                    [
                        {"kind": "allocated", "node": node, "value": False}
                        for node in names
                    ]
                    + [
                        {"kind": "hasJoined", "value": []},
                        {"kind": "preVoteStatus", "node": "a", "value": "enabled"},
                        {"kind": "retirementCompleted", "node": "a", "value": ["b"]},
                        observed(0, True),
                        observed(7, False),
                        observed(10**30, True),
                    ],
                    "sat",
                ),
            ]
        )
        documents = [
            {
                "nodes": names,
                "bootstrap": names,
                "instructions": instructions,
            }
            for _, instructions, _ in cases
        ]
        for width in (1, 21):
            universe = [f"node-{index}" for index in range(width)]
            node = universe[0]
            instructions = [
                {"kind": "allocated", "node": node, "value": False},
                {"kind": "hasJoined", "value": universe},
                {"kind": "preVoteStatus", "node": node, "value": "enabled"},
                {"kind": "retirementCompleted", "node": node, "value": universe},
                observed(0, True),
                observed(7, False),
                observed(10**30, True),
            ]
            cases.append((f"submitted-global-sorts-{width}", instructions, "sat"))
            documents.append(
                {"nodes": universe, "bootstrap": [node], "instructions": instructions}
            )
        scripts = self.encode(documents)
        self.solve(
            [
                {"name": name, "script": script, "expected": expected}
                for (name, _, expected), script in zip(cases, scripts)
            ]
        )
        sizes = {name: len(script) for (name, _, _), script in zip(cases, scripts)}
        self.assertEqual(
            sizes[f"submitted-{10**30}-False"] - sizes["submitted-0-False"], 30
        )

    def test_submitted_transaction_input_errors(self):
        valid = {"kind": "submittedTxId", "txId": 0, "value": True}
        self.assert_invalid_instructions(
            [
                dict(valid, txId=-1),
                dict(valid, txId=True),
                dict(valid, txId="0"),
                dict(valid, txId=None),
                dict(valid, value=0),
                dict(valid, value="true"),
                dict(valid, node="a"),
                {"kind": "submittedTxId", "value": True},
            ]
        )

    def assert_invalid_instructions(self, instructions):
        self.assert_input_errors(
            [
                (
                    f"instruction-{index}",
                    json.dumps(
                        {
                            "nodes": ["a"],
                            "bootstrap": ["a"],
                            "instructions": [instruction],
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
                for index, instruction in enumerate(instructions)
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
                f"{kind}-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {
                                "kind": kind,
                                "node": "a",
                                "value": value,
                            }
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for kind in RETIREMENT_FIELDS
            for name, value in [
                ("negative", -1),
                ("fractional", 1.5),
                ("boolean", True),
                ("string", "1"),
            ]
        )
        invalid.extend(
            (
                f"votedFor-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": "votedFor", "node": "a", "value": value}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, value in [
                ("undeclared", "b"),
                ("numeric", 0),
                ("boolean", False),
                ("array", ["a"]),
            ]
        )
        invalid.extend(
            (
                f"{kind}-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[{"kind": kind, "node": "a", "value": value}],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for kind in VOTE_SET_FIELDS
            for name, value in [
                ("undeclared", ["b"]),
                ("numeric", [0]),
                ("non-array", "a"),
                ("null", None),
            ]
        )
        invalid.extend(
            (
                f"membership-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": "membershipState", "node": "a", "value": value}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, value in [
                ("unknown", "retired"),
                ("numeric", 0),
                ("boolean", False),
                ("null", None),
            ]
        )
        invalid.extend(
            (
                f"{kind}-{name}",
                json.dumps(
                    dict(
                        valid,
                        instructions=[
                            {"kind": kind, "node": "a", "peer": peer, "value": value}
                        ],
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for kind in PEER_INDEX_FIELDS
            for name, peer, value in [
                ("undeclared-peer", "b", 0),
                ("numeric-peer", 0, 0),
                ("negative-index", "a", -1),
                ("null-index", "a", None),
            ]
        )
        invalid.extend(
            (
                f"hasJoined-{name}",
                json.dumps(
                    dict(valid, instructions=[instruction]),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            for name, instruction in [
                ("undeclared", {"kind": "hasJoined", "value": ["b"]}),
                ("numeric-member", {"kind": "hasJoined", "value": [0]}),
                ("non-array", {"kind": "hasJoined", "value": "a"}),
                ("null", {"kind": "hasJoined", "value": None}),
                ("extra-node", {"kind": "hasJoined", "node": "a", "value": []}),
            ]
        )
        self.assert_input_errors(invalid)

    def assert_input_errors(self, invalid):
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
            for label, status, instructions, executable in [
                ("sat", "sat", [], solver),
                (
                    "joined",
                    "unsat",
                    [
                        {"kind": "hasJoined", "value": [name]},
                        {"kind": "hasJoined", "value": []},
                    ],
                    solver,
                ),
                (
                    "submitted",
                    "unsat",
                    [
                        {"kind": "submittedTxId", "txId": 10**30, "value": True},
                        {"kind": "submittedTxId", "txId": 10**30, "value": False},
                    ],
                    solver,
                ),
                ("unknown", "unknown", [], unknown),
            ]:
                with self.subTest(label=label):
                    path = directory / f"{label}.json"
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
                    output = directory / label
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
                    if status == "unsat":
                        self.assertEqual(api.get("/api/core")["instructions"], [0, 1])
                        for index, item in enumerate(instructions):
                            self.assertEqual(
                                api.get(f"/api/instructions/{index}")["instruction"],
                                item,
                            )


if __name__ == "__main__":
    unittest.main()
