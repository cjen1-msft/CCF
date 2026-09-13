# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Project normalized raw steps to native input without emitting SMT."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from typing import Any

from raw_normalization import NormalizedTrace, PACKETS
from reduction import ReductionError

LOCAL_ACTIONS = {
    "checkQuorum",
    "timeout",
    "becomePreVoteCandidate",
    "becomeLeader",
    "advanceCommitIndex",
    "signCommittableMessages",
}
NETWORK_ACTIONS = {"requestVote", "requestPreVote", "updateTerm", "appendEntries"}
RECEIVE_KINDS = {
    "raft_request_vote": "receiveRequestVote",
    "raft_request_vote_response": "receiveRequestVoteResponse",
    "raft_request_pre_vote_response": "receiveRequestPreVoteResponse",
    "raft_append_entries": "receiveAppendEntries",
    "raft_append_entries_response": "receiveAppendEntriesResponse",
}
OBSERVATION_KINDS = {
    "allocated": "allocated",
    "joined": "joined",
    "role": "role",
    "preVoteStatus": "preVoteStatus",
    "membershipState": "membershipState",
    "retirementIndex": "retirementIndex",
    "retirementCommittableIndex": "retirementCommittableIndex",
    "retiredCommittedIndex": "retiredCommittedIndex",
    "currentTerm": "currentTerm",
    "commitIndex": "commit",
    "logLength": "logLength",
}


def _name(trace: NormalizedTrace, index: object) -> str:
    if type(index) is not int or index not in trace.node_names:
        raise ReductionError(f"undeclared normalized identity: {index!r}")
    return trace.node_names[index]


def _receive_kind(trace: NormalizedTrace, index: int, step: dict[str, Any]) -> str:
    evidence = trace.evidence.get(index + 1)
    if not isinstance(evidence, dict):
        raise ReductionError(f"step {index + 1}: receive has no packet-family evidence")
    family = evidence.get("messageType")
    if not isinstance(family, str) or family not in RECEIVE_KINDS:
        raise ReductionError(f"step {index + 1}: unsupported receive family {family!r}")
    previous = trace.steps[index - 1] if index else None
    if (
        previous is None
        or previous.get("kind") != "observation"
        or previous.get("variable") != "firstMessageFrom"
    ):
        raise ReductionError(
            f"step {index + 1}: receive lacks its selected-packet observation"
        )
    pattern = previous["value"]
    if (
        previous["node"] != step["destination"]
        or pattern["source"] != step["node"]
        or pattern["destination"] != step["destination"]
        or pattern["kind"] != PACKETS[family][0]
    ):
        raise ReductionError(
            f"step {index + 1}: receive evidence disagrees with its selected packet"
        )
    return RECEIVE_KINDS[family]


def native_document(trace: NormalizedTrace, bootstrap: Sequence[str]) -> dict[str, Any]:
    """Keep one instruction per normalized step and require an explicit bootstrap.

    Instruction i corresponds to ``trace.steps[i]``. Evidence keeps its
    existing one-based keys.
    This projection is untrusted. Lean validates its input and emits SMT.
    """
    if not trace.native_ids:
        raise ReductionError(
            "native projection requires native identifier normalization"
        )
    names = [trace.node_names[index] for index in sorted(trace.node_names)]
    if (
        not isinstance(bootstrap, Sequence)
        or isinstance(bootstrap, (str, bytes))
        or not bootstrap
        or any(not isinstance(node, str) or node not in names for node in bootstrap)
    ):
        raise ReductionError("bootstrap must contain observed identity strings")
    instructions = []
    for index, step in enumerate(trace.steps):
        if step["kind"] == "observation":
            variable = step["variable"]
            if variable == "firstMessageFrom":
                pattern = deepcopy(step["value"])
                pattern["source"] = _name(trace, pattern["source"])
                pattern["destination"] = _name(trace, pattern["destination"])
                instruction = {
                    "kind": "queuePattern",
                    "source": pattern["source"],
                    "destination": pattern["destination"],
                    "index": 0,
                    "value": pattern,
                }
            elif variable in OBSERVATION_KINDS:
                instruction = {
                    "kind": OBSERVATION_KINDS[variable],
                    "node": _name(trace, step["node"]),
                    "value": deepcopy(step["value"]),
                }
            else:
                raise ReductionError(
                    f"step {index + 1}: unsupported observation {variable!r}"
                )
        elif step["kind"] == "action":
            action = step["action"]
            if action in LOCAL_ACTIONS:
                instruction = {"kind": action, "node": _name(trace, step["node"])}
            elif action in NETWORK_ACTIONS or action == "receive":
                instruction = {
                    "kind": (
                        _receive_kind(trace, index, step)
                        if action == "receive"
                        else action
                    ),
                    "source": _name(trace, step["node"]),
                    "destination": _name(trace, step["destination"]),
                }
                if action == "appendEntries":
                    instruction["batchEnd"] = step["batchEnd"]
            elif action == "clientRequest":
                instruction = {
                    "kind": action,
                    "node": _name(trace, step["node"]),
                    "transaction": deepcopy(step["transaction"]),
                }
            elif action == "changeConfiguration":
                instruction = {
                    "kind": action,
                    "source": _name(trace, step["node"]),
                    "configuration": [
                        _name(trace, node) for node in step["configuration"]
                    ],
                }
            else:
                raise ReductionError(
                    f"step {index + 1}: unsupported native action {action!r}"
                )
        else:
            raise ReductionError(
                f"step {index + 1}: unsupported step kind {step['kind']!r}"
            )
        instructions.append(instruction)
    return {
        "nodes": names,
        "bootstrap": list(bootstrap),
        "unknowns": list(trace.unknowns),
        "instructions": instructions,
    }
