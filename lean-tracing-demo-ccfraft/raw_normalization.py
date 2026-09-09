# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Translate reduced raw identifiers and packet summaries without filling gaps."""

from __future__ import annotations

from copy import deepcopy
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from reduction import SCHEMA_VERSION, ReductionError

ACTION_PARAMETERS = {
    "clientRequest": {"transaction"},
    "signCommittableMessages": set(),
    "changeConfiguration": {"configuration"},
    "appendRetiredCommitted": set(),
    "appendEntries": {"destination", "batchEnd"},
    "advanceCommitIndex": set(),
    "timeout": set(),
    "becomePreVoteCandidate": set(),
    "becomeCandidate": set(),
    "requestVote": {"destination"},
    "requestPreVote": {"destination"},
    "checkQuorum": set(),
    "updateTerm": {"source"},
    "becomeLeader": set(),
    "proposeVote": {"destination"},
    "advanceCommitIndexAndProposeVote": {"destination"},
    "receive": {"source"},
}
STATE_OBSERVATIONS = {
    "allocated",
    "joined",
    "role",
    "preVoteStatus",
    "membershipState",
    "retirementIndex",
    "retirementCommittableIndex",
    "retiredCommittedIndex",
    "currentTerm",
    "commitIndex",
    "logLength",
}
PACKETS = {
    "raft_append_entries": (
        "appendEntriesRequest",
        {
            "previousIndex": "prevLogIndex",
            "batchEnd": "entriesLength",
            "leaderCommitIndex": "leaderCommit",
        },
    ),
    "raft_append_entries_response": (
        "appendEntriesResponse",
        {"lastLogIndex": "lastLogIndex", "success": "success"},
    ),
    "raft_request_vote": (
        "requestVoteRequest",
        {
            "lastCommittableIndex": "lastCommittableIndex",
            "lastCommittableTerm": "lastCommittableTerm",
        },
    ),
    "raft_request_pre_vote": (
        "requestPreVote",
        {
            "lastCommittableIndex": "lastCommittableIndex",
            "lastCommittableTerm": "lastCommittableTerm",
        },
    ),
    "raft_request_vote_response": (
        "requestVoteResponse",
        {"voteGranted": "voteGranted"},
    ),
    "raft_request_pre_vote_response": (
        "requestPreVoteResponse",
        {"voteGranted": "voteGranted"},
    ),
    "raft_propose_request_vote": ("proposeVoteRequest", {}),
}
BOUND_FIELDS = {
    "transaction_count",
    "term_count",
    "index_count",
    "log_capacity",
    "queue_capacity",
}


@dataclass(frozen=True)
class NormalizedTrace:
    """A flat trace plus the names represented by its numeric identifiers."""

    node_names: dict[int, str]
    unknowns: tuple[str, ...]
    steps: list[dict[str, Any]]
    evidence: dict[int, dict[str, Any]]

    def certificate(self, bounds: Mapping[str, object]) -> dict[str, Any]:
        """Declare a fully symbolic entry constrained by the ordered observations."""
        _require(set(bounds) == BOUND_FIELDS, "declare exactly the five model bounds")
        _require(
            all(type(value) is int and value >= 0 for value in bounds.values()),
            "model bounds must be non-negative integers",
        )
        return {
            "schema_version": "ccfraft-symbolic-trace/v1",
            "bounds": dict(bounds),
            "unknowns": list(self.unknowns),
            "entry": "symbolic",
            "steps": deepcopy(self.steps),
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReductionError(message)


def _node_name(value: Any) -> str:
    _require(
        isinstance(value, str)
        and value.isascii()
        and value.isdecimal()
        and str(int(value)) == value
        and int(value) < 15,
        f"raw node {value!r} must be a canonical ID from 0 to 14; the model has 15 slots",
    )
    return value


def _message_pattern(
    summary: dict[str, Any], nodes: dict[str, int], destination: int
) -> dict[str, Any]:
    family = summary.get("messageType")
    _require(
        isinstance(family, str) and family in PACKETS,
        f"unsupported reduced packet family: {family!r}",
    )
    kind, fields = PACKETS[family]
    expected = {
        "messageType",
        "source",
        "term",
        "batchCount",
        "batchPosition",
        *fields,
    }
    _require(
        set(summary) == expected,
        f"{family}: unexpected or missing packet-summary fields",
    )
    count, position = summary["batchCount"], summary["batchPosition"]
    _require(
        type(count) is int and type(position) is int and 1 <= position <= count,
        f"{family}: invalid batch position",
    )
    pattern = {
        "kind": kind,
        "source": nodes[summary["source"]],
        "destination": destination,
        "term": summary["term"],
        **{target: summary[source] for source, target in fields.items()},
    }
    if kind == "appendEntriesRequest":
        previous, end = summary["previousIndex"], summary["batchEnd"]
        _require(
            type(previous) is int and type(end) is int and 0 <= previous <= end,
            "AppendEntries summary has an invalid index range",
        )
        pattern["entriesLength"] = end - previous
    if "success" in pattern:
        _require(
            pattern["success"] in {"OK", "FAIL"},
            f"{family}: invalid response success",
        )
        pattern["success"] = pattern["success"] == "OK"
    return pattern


def normalize(certificate: dict[str, Any]) -> NormalizedTrace:
    """Preserve step order, provenance, and unknown transaction aliasing.

    This does not supply an entry state or choose bounds. Unmentioned packet
    fields stay absent from the pattern rather than becoming concrete values.
    """
    _require(
        certificate.get("schema_version") == SCHEMA_VERSION,
        "unsupported raw reduction certificate schema",
    )
    steps = certificate.get("steps")
    _require(isinstance(steps, list), "reduced steps must be an array")
    names: set[str] = set()
    for step in steps:
        _require(isinstance(step, dict), "reduced instruction must be an object")
        names.add(_node_name(step.get("node")))
        kind = step.get("kind")
        if kind == "action":
            action = step.get("action")
            _require(
                isinstance(action, str) and action in ACTION_PARAMETERS,
                f"unsupported raw action: {action!r}",
            )
            parameters = ACTION_PARAMETERS[action]
            _require(
                set(step) - {"kind", "action", "node", "provenance", "rule", "evidence"}
                == parameters,
                f"{action}: unexpected or missing action parameters",
            )
            for field in ("source", "destination"):
                if field in parameters:
                    names.add(_node_name(step[field]))
            if "configuration" in parameters:
                _require(
                    isinstance(step["configuration"], list),
                    "configuration must be an array",
                )
                names.update(_node_name(node) for node in step["configuration"])
        elif kind == "observation":
            variable = step.get("variable")
            _require(
                isinstance(variable, str)
                and (variable in STATE_OBSERVATIONS or variable == "firstMessageFrom"),
                f"unsupported raw observation: {variable!r}",
            )
            _require(
                set(step)
                == {"kind", "node", "provenance", "rule", "value", "variable"},
                f"{variable}: unexpected or missing observation fields",
            )
            if variable == "firstMessageFrom":
                _require(
                    isinstance(step["value"], dict), "packet summary must be an object"
                )
                names.add(_node_name(step["value"].get("source")))
        else:
            raise ReductionError(f"unsupported reduced instruction kind: {kind!r}")

    # Renumbering sparse IDs would change the implicit bootstrap configuration.
    nodes = {name: int(name) for name in sorted(names, key=int)}
    node_names = {node: name for name, node in nodes.items()}
    unknowns: dict[str, None] = {}
    evidence = {}
    normalized = []
    for index, original in enumerate(steps, 1):
        step = deepcopy(original)
        step["node"] = nodes[original["node"]]
        if step["kind"] == "action":
            if "evidence" in step:
                evidence[index] = step.pop("evidence")
            if "source" in step:
                step["destination"] = step["node"]
                step["node"] = nodes[step.pop("source")]
            elif "destination" in step:
                step["destination"] = nodes[step["destination"]]
            if "configuration" in step:
                step["configuration"] = [nodes[node] for node in step["configuration"]]
            if step["action"] == "clientRequest":
                name = step["transaction"]
                _require(
                    isinstance(name, str) and bool(name),
                    "raw transaction identity must be a nonempty string",
                )
                unknowns[name] = None
                step["transaction"] = {"unknown": name}
        elif step["variable"] == "firstMessageFrom":
            step["value"] = _message_pattern(step["value"], nodes, step["node"])
        normalized.append(step)
    return NormalizedTrace(node_names, tuple(unknowns), normalized, evidence)
