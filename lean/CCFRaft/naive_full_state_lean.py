#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate a canonical Lean checker for the naive full-state SMT witness."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import naive_full_state_smt as smt

CHECKER_SCHEMA = "ccfraft-naive-full-state-canonical-check/v1"
SOURCE_NAME = "CanonicalNaiveFullStateWitness.lean"
EXPECTED_SPANS = {9, 11, 20, 25, 26, 31}


class CheckGenerationError(RuntimeError):
    """Report an exact malformed input or unsupported certificate field."""


def require(condition: bool, message: str) -> None:
    """Raise a labelled generation error when a requirement is false."""

    if not condition:
        raise CheckGenerationError(message)


def sha256_file(path: Path) -> str:
    """Hash one file exactly as stored."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    """Write stable JSON."""

    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def strict_dict(value: Any, field: str) -> dict[str, Any]:
    """Read an object without accepting a list or scalar."""

    require(isinstance(value, dict), f"{field}: expected object")
    return value


def strict_list(value: Any, field: str) -> list[Any]:
    """Read a list."""

    require(isinstance(value, list), f"{field}: expected list")
    return value


def strict_int(value: Any, field: str) -> int:
    """Read an integer without accepting Python booleans."""

    require(type(value) is int, f"{field}: expected integer")
    require(value >= 0, f"{field}: negative integer {value}")
    return value


def strict_bool(value: Any, field: str) -> bool:
    """Read a JSON boolean."""

    require(type(value) is bool, f"{field}: expected boolean")
    return value


def strict_string(value: Any, field: str) -> str:
    """Read a JSON string."""

    require(isinstance(value, str), f"{field}: expected string")
    require(value.isascii(), f"{field}: non-ASCII string")
    return value


def require_keys(
    value: Mapping[str, Any],
    expected: set[str],
    field: str,
) -> None:
    """Reject missing or unrecognized fields in a decoded record."""

    actual = set(value)
    require(
        actual == expected,
        f"{field}: fields differ; missing={sorted(expected - actual)} "
        f"unsupported={sorted(actual - expected)}",
    )


def lean_string(value: str) -> str:
    """Encode one ASCII string as a Lean string literal."""

    require(value.isascii(), "generated Lean string is not ASCII")
    return json.dumps(value, ensure_ascii=True)


def lean_bool(value: bool) -> str:
    """Encode one Boolean literal."""

    return "true" if value else "false"


def lean_list(values: Iterable[Any], encode: Any = str) -> str:
    """Encode one Lean list literal."""

    return "[" + ", ".join(encode(value) for value in values) + "]"


def json_path_value(message: Mapping[str, Any], path: str) -> Any:
    """Read a projected message leaf with ordinary dotted components."""

    value: Any = message
    for component in path.split(".")[1:]:
        value = strict_dict(value, path)[component]
    return value


def checkpoint_state_step(position: Mapping[str, Any]) -> int:
    """Resolve the certificate's explicit checkpoint to S0 through S43."""

    require(
        position.get("kind") == "action_checkpoint",
        f"unsupported checkpoint position {position}",
    )
    action = strict_int(position.get("action"), "field_position.action")
    relation = position.get("relation")
    require(1 <= action <= smt.EXPECTED_ACTIONS, "checkpoint action out of range")
    if relation == "before":
        return action - 1
    if relation == "after":
        return action
    require(relation == "during", f"unsupported checkpoint relation {relation}")
    if position.get("phase") == "pre-reconfiguration-send-hook":
        return action - 1
    return action


def field_state_step(decision: Mapping[str, Any]) -> int:
    """Resolve a state-positioned projected field."""

    position = strict_dict(decision["field_position"], "field_position")
    if position.get("kind") == "action_checkpoint":
        return checkpoint_state_step(position)
    if position.get("kind") == "span_start":
        action = strict_int(position.get("before_action"), "before_action")
        require(1 <= action <= smt.EXPECTED_ACTIONS, "span action out of range")
        return action - 1
    raise CheckGenerationError(
        f"field {decision['path']}: unsupported state position {position}"
    )


def action_range(position: Mapping[str, Any]) -> range:
    """Resolve an action checkpoint or whole span."""

    kind = position.get("kind")
    if kind == "action_checkpoint":
        action = strict_int(position.get("action"), "field_position.action")
        return range(action, action + 1)
    if kind == "whole_action_span":
        start = strict_int(position.get("start_action"), "start_action")
        end = strict_int(position.get("end_action"), "end_action")
        require(1 <= start <= end <= smt.EXPECTED_ACTIONS, "span out of range")
        return range(start, end + 1)
    if kind == "span_start":
        action = strict_int(position.get("before_action"), "before_action")
        return range(action, action + 1)
    raise CheckGenerationError(f"unsupported action position {position}")


def load_inputs(
    witness_path: Path,
    certificate_path: Path,
) -> tuple[dict[str, Any], smt.Certificate]:
    """Load the current witness and certificate and verify their binding."""

    certificate = smt.load_certificate(certificate_path)
    try:
        witness_value = json.loads(witness_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise CheckGenerationError(f"witness JSON is invalid: {error}") from error
    witness = strict_dict(witness_value, "witness")
    require(
        witness.get("schema_version") == smt.WITNESS_SCHEMA,
        "witness.schema_version: unsupported schema",
    )
    require(
        witness.get("sat_classification") == "SAT_BOUNDED_PROTOTYPE",
        "witness.sat_classification: expected SAT_BOUNDED_PROTOTYPE",
    )
    counts = strict_dict(witness.get("counts"), "witness.counts")
    for field, expected in (
        ("events", smt.EXPECTED_EVENTS),
        ("reductions", smt.EXPECTED_REDUCTIONS),
        ("actions", smt.EXPECTED_ACTIONS),
        ("states", smt.EXPECTED_ACTIONS + 1),
    ):
        require(
            counts.get(field) == expected,
            f"witness.counts.{field}: expected {expected}",
        )
    initial_semantics = strict_dict(
        witness.get("initial_state_semantics"),
        "witness.initial_state_semantics",
    )
    require(
        initial_semantics.get("canonical_initial_state") is False,
        "witness.initial_state_semantics: S0 is incorrectly canonical",
    )
    require(
        initial_semantics.get("reachable_claim") is False,
        "witness.initial_state_semantics: S0 incorrectly claims Reachable",
    )
    require(
        initial_semantics.get("arbitrary_existential_completion") is True,
        "witness.initial_state_semantics: arbitrary existential S0 is absent",
    )
    hashes = strict_dict(witness.get("hashes"), "witness.hashes")
    require(
        hashes.get("certificate_sha256") == sha256_file(certificate_path),
        "witness.hashes.certificate_sha256: certificate hash differs",
    )
    require(
        hashes.get("input_trace_sha256") == certificate.data["input"]["sha256"],
        "witness.hashes.input_trace_sha256: trace hash differs",
    )
    return witness, certificate


def validate_entry(slot: Mapping[str, Any], field: str) -> None:
    """Validate the complete decoded entry-slot shape."""

    require_keys(
        slot,
        {"index", "active", "term", "content"},
        field,
    )
    strict_int(slot["index"], f"{field}.index")
    strict_bool(slot["active"], f"{field}.active")
    strict_int(slot["term"], f"{field}.term")
    content = strict_dict(slot["content"], f"{field}.content")
    require_keys(
        content,
        {
            "tag",
            "tag_value",
            "transaction_id",
            "configuration_membership",
            "configuration_nodes",
        },
        f"{field}.content",
    )
    strict_string(content["tag"], f"{field}.content.tag")
    strict_int(content["tag_value"], f"{field}.content.tag_value")
    strict_int(content["transaction_id"], f"{field}.content.transaction_id")
    membership = strict_list(
        content["configuration_membership"],
        f"{field}.content.configuration_membership",
    )
    require(
        len(membership) == 15,
        f"{field}.content.configuration_membership: expected 15 bits",
    )
    for index, present in enumerate(membership):
        strict_bool(present, f"{field}.content.configuration_membership[{index}]")
    nodes = strict_list(
        content["configuration_nodes"],
        f"{field}.content.configuration_nodes",
    )
    expected_nodes = [index for index, present in enumerate(membership) if present]
    require(
        nodes == expected_nodes,
        f"{field}.content.configuration_nodes: membership summary differs",
    )


def validate_node(node: Mapping[str, Any], expected_node: int) -> None:
    """Validate all fields of one complete S0 node record."""

    field = f"S0.nodes[{expected_node}]"
    require_keys(
        node,
        {
            "node",
            "role",
            "role_value",
            "current_term",
            "log_length",
            "commit_index",
            "is_new_follower",
            "voted_for",
            "votes_granted_membership",
            "votes_granted_nodes",
            "sent_index",
            "match_index",
            "log_capacity",
            "log_slots",
        },
        field,
    )
    require(node["node"] == expected_node, f"{field}.node: index differs")
    strict_string(node["role"], f"{field}.role")
    strict_int(node["role_value"], f"{field}.role_value")
    strict_int(node["current_term"], f"{field}.current_term")
    strict_int(node["log_length"], f"{field}.log_length")
    strict_int(node["commit_index"], f"{field}.commit_index")
    strict_bool(node["is_new_follower"], f"{field}.is_new_follower")
    voted_for = strict_dict(node["voted_for"], f"{field}.voted_for")
    require_keys(
        voted_for,
        {"has_value", "value", "node"},
        f"{field}.voted_for",
    )
    has_value = strict_bool(
        voted_for["has_value"],
        f"{field}.voted_for.has_value",
    )
    value = strict_int(voted_for["value"], f"{field}.voted_for.value")
    require(
        voted_for["node"] == (value if has_value else None),
        f"{field}.voted_for.node: option summary differs",
    )
    for list_field, expected_length in (
        ("votes_granted_membership", 15),
        ("sent_index", 15),
        ("match_index", 15),
    ):
        values = strict_list(node[list_field], f"{field}.{list_field}")
        require(
            len(values) == expected_length,
            f"{field}.{list_field}: expected {expected_length} values",
        )
        for index, item in enumerate(values):
            if list_field == "votes_granted_membership":
                strict_bool(item, f"{field}.{list_field}[{index}]")
            else:
                strict_int(item, f"{field}.{list_field}[{index}]")
    votes = node["votes_granted_membership"]
    require(
        node["votes_granted_nodes"]
        == [index for index, present in enumerate(votes) if present],
        f"{field}.votes_granted_nodes: membership summary differs",
    )
    require(
        node["log_capacity"] == 7,
        f"{field}.log_capacity: expected 7",
    )
    slots = strict_list(node["log_slots"], f"{field}.log_slots")
    require(len(slots) == 7, f"{field}.log_slots: expected 7 slots")
    for slot_index, slot_value in enumerate(slots, 1):
        slot = strict_dict(slot_value, f"{field}.log_slots[{slot_index}]")
        validate_entry(slot, f"{field}.log_slots[{slot_index}]")
        require(
            slot["index"] == slot_index,
            f"{field}.log_slots[{slot_index}].index: sequence differs",
        )


def validate_queue_slot(slot: Mapping[str, Any], field: str) -> None:
    """Validate all decoded fields of one bounded queue slot."""

    require_keys(
        slot,
        {
            "slot",
            "active",
            "tag",
            "tag_value",
            "source",
            "destination",
            "term",
            "append_entries_request",
            "append_entries_response",
            "request_vote_request",
            "request_vote_response",
        },
        field,
    )
    strict_int(slot["slot"], f"{field}.slot")
    strict_bool(slot["active"], f"{field}.active")
    strict_string(slot["tag"], f"{field}.tag")
    strict_int(slot["tag_value"], f"{field}.tag_value")
    for name in ("source", "destination", "term"):
        strict_int(slot[name], f"{field}.{name}")
    request = strict_dict(
        slot["append_entries_request"],
        f"{field}.append_entries_request",
    )
    require_keys(
        request,
        {
            "prev_log_index",
            "prev_log_term",
            "leader_commit",
            "entry_present",
            "entry",
        },
        f"{field}.append_entries_request",
    )
    for name in ("prev_log_index", "prev_log_term", "leader_commit"):
        strict_int(request[name], f"{field}.append_entries_request.{name}")
    strict_bool(
        request["entry_present"],
        f"{field}.append_entries_request.entry_present",
    )
    entry = strict_dict(
        request["entry"],
        f"{field}.append_entries_request.entry",
    )
    require_keys(entry, {"term", "content"}, f"{field}.append_entries_request.entry")
    strict_int(entry["term"], f"{field}.append_entries_request.entry.term")
    validate_entry(
        {
            "index": 1,
            "active": request["entry_present"],
            "term": entry["term"],
            "content": entry["content"],
        },
        f"{field}.append_entries_request.entry",
    )
    response = strict_dict(
        slot["append_entries_response"],
        f"{field}.append_entries_response",
    )
    require_keys(
        response,
        {"success", "last_log_index"},
        f"{field}.append_entries_response",
    )
    strict_bool(response["success"], f"{field}.append_entries_response.success")
    strict_int(
        response["last_log_index"],
        f"{field}.append_entries_response.last_log_index",
    )
    vote_request = strict_dict(
        slot["request_vote_request"],
        f"{field}.request_vote_request",
    )
    require_keys(
        vote_request,
        {"last_committable_term", "last_committable_index"},
        f"{field}.request_vote_request",
    )
    strict_int(
        vote_request["last_committable_term"],
        f"{field}.request_vote_request.last_committable_term",
    )
    strict_int(
        vote_request["last_committable_index"],
        f"{field}.request_vote_request.last_committable_index",
    )
    vote_response = strict_dict(
        slot["request_vote_response"],
        f"{field}.request_vote_response",
    )
    require_keys(
        vote_response,
        {"vote_granted"},
        f"{field}.request_vote_response",
    )
    strict_bool(
        vote_response["vote_granted"],
        f"{field}.request_vote_response.vote_granted",
    )


def validate_initial_state(
    initial: Mapping[str, Any],
    certificate: smt.Certificate,
) -> None:
    """Validate the complete S0 record before emitting Lean."""

    require_keys(
        initial,
        {
            "state",
            "synthetic_checkpoint",
            "nodes",
            "network",
            "submitted_transaction_membership",
            "submitted_transaction_ids",
            "has_joined_membership",
            "has_joined_nodes",
        },
        "S0",
    )
    require(initial["state"] == 0, "S0.state: expected zero")
    strict_string(initial["synthetic_checkpoint"], "S0.synthetic_checkpoint")
    nodes = strict_list(initial["nodes"], "S0.nodes")
    require(len(nodes) == certificate.node_count, "S0.nodes: expected 15 nodes")
    for index, node_value in enumerate(nodes):
        validate_node(strict_dict(node_value, f"S0.nodes[{index}]"), index)
    network = strict_list(initial["network"], "S0.network")
    require(
        len(network) == certificate.node_count,
        "S0.network: expected 15 queues",
    )
    for destination, queue_value in enumerate(network):
        field = f"S0.network[{destination}]"
        queue = strict_dict(queue_value, field)
        require_keys(
            queue,
            {"destination", "length", "capacity", "slots"},
            field,
        )
        require(
            queue["destination"] == destination,
            f"{field}.destination: sequence differs",
        )
        strict_int(queue["length"], f"{field}.length")
        require(queue["capacity"] == 4, f"{field}.capacity: expected 4")
        slots = strict_list(queue["slots"], f"{field}.slots")
        require(len(slots) == 4, f"{field}.slots: expected 4 slots")
        for slot_index, slot_value in enumerate(slots):
            slot = strict_dict(slot_value, f"{field}.slots[{slot_index}]")
            validate_queue_slot(slot, f"{field}.slots[{slot_index}]")
            require(
                slot["slot"] == slot_index,
                f"{field}.slots[{slot_index}].slot: sequence differs",
            )
    for membership_field, summary_field, expected_length in (
        ("submitted_transaction_membership", "submitted_transaction_ids", 64),
        ("has_joined_membership", "has_joined_nodes", 15),
    ):
        membership = strict_list(initial[membership_field], f"S0.{membership_field}")
        require(
            len(membership) == expected_length,
            f"S0.{membership_field}: expected {expected_length} bits",
        )
        for index, present in enumerate(membership):
            strict_bool(present, f"S0.{membership_field}[{index}]")
        require(
            initial[summary_field]
            == [index for index, present in enumerate(membership) if present],
            f"S0.{summary_field}: membership summary differs",
        )


def validate_actions(
    actions_value: Any,
    certificate: smt.Certificate,
    fresh_tx: int,
) -> list[dict[str, Any]]:
    """Validate every concrete action field against the v2 certificate."""

    values = strict_list(actions_value, "actions")
    require(len(values) == smt.EXPECTED_ACTIONS, "actions: expected 43 records")
    actions: list[dict[str, Any]] = []
    for number, value in enumerate(values, 1):
        field = f"action {number}"
        action = strict_dict(value, field)
        require_keys(
            action,
            {
                "action",
                "kind",
                "kind_value",
                "source",
                "destination",
                "parameter",
                "transaction",
                "configuration_membership",
                "configuration_nodes",
                "certificate_template",
                "certificate_parameters",
                "reduction",
            },
            field,
        )
        require(action["action"] == number, f"{field}.action: sequence differs")
        kind = strict_string(action["kind"], f"{field}.kind")
        kind_value = strict_int(action["kind_value"], f"{field}.kind_value")
        require(
            smt.ACTION_KIND_NAMES.get(kind_value) == kind,
            f"{field}.kind: name/tag differ",
        )
        source = strict_int(action["source"], f"{field}.source")
        destination = strict_int(action["destination"], f"{field}.destination")
        parameter = strict_int(action["parameter"], f"{field}.parameter")
        transaction = strict_int(action["transaction"], f"{field}.transaction")
        require(source < 15, f"{field}.source: outside Fin 15")
        require(destination < 15, f"{field}.destination: outside Fin 15")
        membership = strict_list(
            action["configuration_membership"],
            f"{field}.configuration_membership",
        )
        require(
            len(membership) == 15,
            f"{field}.configuration_membership: expected 15 bits",
        )
        for index, present in enumerate(membership):
            strict_bool(present, f"{field}.configuration_membership[{index}]")
        configuration_nodes = [
            index for index, present in enumerate(membership) if present
        ]
        require(
            action["configuration_nodes"] == configuration_nodes,
            f"{field}.configuration_nodes: membership summary differs",
        )
        certificate_action = certificate.actions[number - 1]
        require(
            kind == certificate_action["kind"],
            f"{field}.kind: witness/certificate differ",
        )
        parameters = certificate_action["parameters"]
        expected_source = parameters.get("source", parameters.get("node", 0))
        expected_destination = parameters.get("destination", 0)
        expected_parameter = parameters.get("batch_end", 0)
        expected_transaction = fresh_tx if kind == "clientRequest" else 0
        expected_configuration = parameters.get("new_configuration", [])
        require(source == expected_source, f"{field}.source: certificate differs")
        require(
            destination == expected_destination,
            f"{field}.destination: certificate differs",
        )
        require(
            parameter == expected_parameter,
            f"{field}.parameter: certificate differs",
        )
        require(
            transaction == expected_transaction,
            f"{field}.transaction: certificate differs",
        )
        require(
            configuration_nodes == expected_configuration,
            f"{field}.configuration_membership: certificate differs",
        )
        actions.append(action)
    return actions


def raw_entry_literal(slot: Mapping[str, Any]) -> str:
    """Emit one complete raw log slot."""

    content = slot["content"]
    return (
        "{ "
        f"index := {slot['index']}, "
        f"active := {lean_bool(slot['active'])}, "
        f"term := {slot['term']}, "
        f"tag := {lean_string(content['tag'])}, "
        f"tagValue := {content['tag_value']}, "
        f"transactionId := {content['transaction_id']}, "
        "configurationMembership := "
        f"{lean_list(content['configuration_membership'], lean_bool)}"
        " }"
    )


def raw_node_literal(node: Mapping[str, Any]) -> str:
    """Emit one complete raw node."""

    voted_for = node["voted_for"]
    slots = ",\n        ".join(raw_entry_literal(slot) for slot in node["log_slots"])
    return "\n".join(
        [
            "    {",
            f"      node := {node['node']}",
            f"      role := {lean_string(node['role'])}",
            f"      roleValue := {node['role_value']}",
            f"      currentTerm := {node['current_term']}",
            f"      logLength := {node['log_length']}",
            f"      commitIndex := {node['commit_index']}",
            f"      isNewFollower := {lean_bool(node['is_new_follower'])}",
            "      votedForHasValue := " f"{lean_bool(voted_for['has_value'])}",
            f"      votedForValue := {voted_for['value']}",
            "      votesGrantedMembership := "
            f"{lean_list(node['votes_granted_membership'], lean_bool)}",
            f"      sentIndex := {lean_list(node['sent_index'])}",
            f"      matchIndex := {lean_list(node['match_index'])}",
            f"      logCapacity := {node['log_capacity']}",
            "      logSlots := [",
            f"        {slots}",
            "      ]",
            "    }",
        ]
    )


def raw_queue_slot_literal(slot: Mapping[str, Any]) -> str:
    """Emit every field of one raw queue slot."""

    request = slot["append_entries_request"]
    entry = request["entry"]
    content = entry["content"]
    response = slot["append_entries_response"]
    vote_request = slot["request_vote_request"]
    vote_response = slot["request_vote_response"]
    return (
        "{ "
        f"slot := {slot['slot']}, "
        f"active := {lean_bool(slot['active'])}, "
        f"tag := {lean_string(slot['tag'])}, "
        f"tagValue := {slot['tag_value']}, "
        f"source := {slot['source']}, "
        f"destination := {slot['destination']}, "
        f"term := {slot['term']}, "
        f"prevLogIndex := {request['prev_log_index']}, "
        f"prevLogTerm := {request['prev_log_term']}, "
        f"leaderCommit := {request['leader_commit']}, "
        f"entryPresent := {lean_bool(request['entry_present'])}, "
        f"entryTerm := {entry['term']}, "
        f"entryTag := {lean_string(content['tag'])}, "
        f"entryTagValue := {content['tag_value']}, "
        f"entryTransactionId := {content['transaction_id']}, "
        "entryConfigurationMembership := "
        f"{lean_list(content['configuration_membership'], lean_bool)}, "
        f"responseSuccess := {lean_bool(response['success'])}, "
        f"responseLastLogIndex := {response['last_log_index']}, "
        "voteLastCommittableTerm := "
        f"{vote_request['last_committable_term']}, "
        "voteLastCommittableIndex := "
        f"{vote_request['last_committable_index']}, "
        f"voteGranted := {lean_bool(vote_response['vote_granted'])}"
        " }"
    )


def raw_queue_literal(queue: Mapping[str, Any]) -> str:
    """Emit one complete raw destination queue."""

    slots = ",\n        ".join(raw_queue_slot_literal(slot) for slot in queue["slots"])
    return "\n".join(
        [
            "    {",
            f"      destination := {queue['destination']}",
            f"      length := {queue['length']}",
            f"      capacity := {queue['capacity']}",
            "      slots := [",
            f"        {slots}",
            "      ]",
            "    }",
        ]
    )


def raw_action_literal(action: Mapping[str, Any]) -> str:
    """Emit one complete raw action value."""

    return "\n".join(
        [
            "    {",
            f"      action := {action['action']}",
            f"      kind := {lean_string(action['kind'])}",
            f"      kindValue := {action['kind_value']}",
            f"      source := {action['source']}",
            f"      destination := {action['destination']}",
            f"      parameter := {action['parameter']}",
            f"      transaction := {action['transaction']}",
            "      configurationMembership := "
            f"{lean_list(action['configuration_membership'], lean_bool)}",
            "    }",
        ]
    )


def label_for(
    event_number: int,
    path: str,
    position: Mapping[str, Any],
) -> str:
    """Build the exact failure label for one projected field."""

    return (
        f"event {event_number} field {path} at "
        f"{json.dumps(position, sort_keys=True, separators=(',', ':'))}"
    )


def indent_block(lines: Sequence[str]) -> list[str]:
    """Wrap statements in a local do block."""

    return ["  do", *[f"    {line}" for line in lines]]


def action_field_lines(
    label: str,
    action_number: int,
    field: str,
    expected: Any,
) -> list[str]:
    """Emit an action accessor assertion."""

    lines = [f"let action <- actionAt actions {action_number} {lean_string(label)}"]
    if field == "kind":
        lines.append(
            f"expectEq {lean_string(label)} (actionKind action) "
            f"{lean_string(expected)}"
        )
    elif field == "source":
        lines.append(
            f"expectEq {lean_string(label)} (actionSource action).val {expected}"
        )
    elif field == "destination":
        lines.append(
            f"expectEq {lean_string(label)} "
            "((actionDestination? action).map fun node => node.val) "
            f"(some {expected})"
        )
    elif field == "parameter":
        lines.append(
            f"expectEq {lean_string(label)} (actionParameter? action) "
            f"(some {expected})"
        )
    else:
        raise CheckGenerationError(f"{label}: unsupported action field {field}")
    return indent_block(lines)


def state_field_lines(
    label: str,
    step: int,
    node: int,
    field: str,
    expected: Any,
) -> list[str]:
    """Emit one canonical node-state assertion."""

    lines = [
        f"let state <- stateAt states {step} {lean_string(label)}",
        f"let node <- nodeOfNat {lean_string(label)} {node}",
    ]
    accessors = {
        "currentTerm": "(state.nodes node).currentTerm",
        "logLength": "(state.nodes node).log.length",
        "commitIndex": "(state.nodes node).commitIndex",
        "role": "reprStr (state.nodes node).role",
    }
    if field == "role":
        role_repr = {
            "None": "CCFRaft.Role.none",
            "Follower": "CCFRaft.Role.follower",
            "Candidate": "CCFRaft.Role.candidate",
            "Leader": "CCFRaft.Role.leader",
        }[expected]
        lines[-1:] = [
            f"let node <- nodeOfNat {lean_string(label)} {node}",
            f"expectTrue {lean_string(label)} "
            f"(decide ((state.nodes node).role = {role_repr}))",
        ]
        return indent_block(lines)
    lines.append(f"expectEq {lean_string(label)} {accessors[field]} {expected}")
    return indent_block(lines)


def pair_field_lines(
    label: str,
    step: int,
    node: int,
    peer: int,
    field: str,
    expected: int,
) -> list[str]:
    """Emit one sentIndex or matchIndex assertion."""

    accessor = "sentIndex" if field == "sent" else "matchIndex"
    return indent_block(
        [
            f"let state <- stateAt states {step} {lean_string(label)}",
            f"let node <- nodeOfNat {lean_string(label)} {node}",
            f"let peer <- nodeOfNat {lean_string(label)} {peer}",
            f"expectEq {lean_string(label)} "
            f"((state.nodes node).{accessor} peer) {expected}",
        ]
    )


def message_lines(
    label: str,
    step: int,
    destination: int,
    slot: int | None,
    statements: Sequence[str],
) -> list[str]:
    """Bind one queue message, optionally from the queue tail."""

    if slot is None:
        binding = (
            f"let message <- queueTailAt states {step} {destination} "
            f"{lean_string(label)}"
        )
    else:
        binding = (
            f"let message <- queueMessageAt states {step} {destination} {slot} "
            f"{lean_string(label)}"
        )
    return indent_block([binding, *statements])


def packet_point_lines(
    certificate: smt.Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    label: str,
    step: int,
) -> list[str]:
    """Emit one non-span packet-field assertion."""

    message = certificate.events[event_number]["msg"]
    function = message["function"]
    packet = message["packet"]
    path = decision["path"]
    value = packet[path.rsplit(".", 1)[1]]
    actions = action_range(decision["field_position"])
    require(len(actions) == 1, f"{label}: packet spans multiple actions")
    action_number = actions.start
    if function == "send_append_entries":
        action_kind = certificate.actions[action_number - 1]["kind"]
        if action_kind != "appendEntries":
            require(
                event_number == 3 and action_kind == "changeConfiguration",
                f"{label}: unsupported non-append packet preview",
            )
            if path == "msg.packet.msg":
                return action_field_lines(
                    label,
                    action_number,
                    "kind",
                    action_kind,
                )
            if path == "msg.packet.term":
                return state_field_lines(
                    label,
                    step,
                    int(message["state"]["node_id"]),
                    "currentTerm",
                    value,
                )
            if path == "msg.packet.leader_commit_idx":
                return state_field_lines(
                    label,
                    step,
                    int(message["state"]["node_id"]),
                    "commitIndex",
                    value,
                )
            raise CheckGenerationError(
                f"{label}: unsupported pre-reconfiguration packet field"
            )
        statements = [
            f"let request <- previewAppendRequest states actions {action_number} "
            f"{lean_string(label)}"
        ]
        if path == "msg.packet.msg":
            statements.append(
                f"expectEq {lean_string(label)} "
                f"{lean_string('appendEntriesRequest')} "
                f"{lean_string('appendEntriesRequest')}"
            )
        elif path == "msg.packet.term":
            statements.append(f"expectEq {lean_string(label)} request.term {value}")
        elif path == "msg.packet.leader_commit_idx":
            statements.append(
                f"expectEq {lean_string(label)} request.leaderCommit {value}"
            )
        elif path == "msg.packet.prev_idx":
            statements.append(
                f"expectEq {lean_string(label)} request.prevLogIndex {value}"
            )
        elif path == "msg.packet.idx":
            statements.append(
                f"expectEq {lean_string(label)} (appendRequestEnd request) {value}"
            )
        elif path == "msg.packet.prev_term":
            statements.append(
                f"expectEq {lean_string(label)} request.prevLogTerm {value}"
            )
        elif path == "msg.packet.term_of_idx":
            statements.append(
                f"expectEq {lean_string(label)} "
                f"(appendRequestEndTerm request) {value}"
            )
        else:
            raise CheckGenerationError(f"{label}: unsupported send packet field")
        return indent_block(statements)

    if function == "recv_append_entries":
        destination, slot = 1, 0
        kind = "request"
    elif function == "recv_append_entries_response":
        destination, slot = 0, 0
        kind = "response"
    elif function == "send_append_entries_response":
        destination, slot = 0, None
        kind = "response"
    else:
        raise CheckGenerationError(f"{label}: unsupported packet function {function}")

    statements: list[str] = []
    if path == "msg.packet.msg":
        expected_kind = (
            "appendEntriesRequest" if kind == "request" else "appendEntriesResponse"
        )
        statements.append(
            f"expectEq {lean_string(label)} (messageKind message) "
            f"{lean_string(expected_kind)}"
        )
    elif path == "msg.packet.term":
        statements.append(
            f"expectEq {lean_string(label)} (Message.term message) {value}"
        )
    elif kind == "request":
        statements.append(f"let request <- appendRequest {lean_string(label)} message")
        if path == "msg.packet.leader_commit_idx":
            statements.append(
                f"expectEq {lean_string(label)} request.leaderCommit {value}"
            )
        elif path == "msg.packet.prev_idx":
            statements.append(
                f"expectEq {lean_string(label)} request.prevLogIndex {value}"
            )
        elif path == "msg.packet.idx":
            if event_number == 5:
                statements.append(
                    f"expectTrue {lean_string(label)} "
                    f"(decide ({value} <= appendRequestEnd request))"
                )
            else:
                statements.append(
                    f"expectEq {lean_string(label)} "
                    f"(appendRequestEnd request) {value}"
                )
        elif path == "msg.packet.prev_term":
            statements.append(
                f"expectEq {lean_string(label)} request.prevLogTerm {value}"
            )
        elif path == "msg.packet.term_of_idx":
            if event_number == 5:
                statements.append(
                    f"let term <- entryTermAt states {step} 0 {packet['idx']} "
                    f"{lean_string(label)}"
                )
                statements.append(f"expectEq {lean_string(label)} term {value}")
            else:
                statements.append(
                    f"expectEq {lean_string(label)} "
                    f"(appendRequestEndTerm request) {value}"
                )
        else:
            raise CheckGenerationError(f"{label}: unsupported request packet field")
    else:
        statements.append(
            f"let response <- appendResponse {lean_string(label)} message"
        )
        if path == "msg.packet.success":
            statements.append(
                f"expectEq {lean_string(label)} response.success "
                f"{lean_bool(value == 'OK')}"
            )
        elif path == "msg.packet.last_log_idx":
            statements.append(
                f"expectEq {lean_string(label)} response.lastLogIndex {value}"
            )
        else:
            raise CheckGenerationError(f"{label}: unsupported response packet field")
    return message_lines(label, step, destination, slot, statements)


def span_metadata(
    certificate: smt.Certificate,
    event_number: int,
    decision: Mapping[str, Any],
) -> tuple[Mapping[str, Any], range, range]:
    """Validate and return a certificate-owned span."""

    observation = certificate.observations[event_number]
    position = strict_dict(observation["position"], "observation.position")
    field_position = strict_dict(decision["field_position"], "field_position")
    require(
        position.get("kind") == "action_span"
        and field_position.get("kind") == "whole_action_span",
        f"event {event_number} field {decision['path']}: invalid span metadata",
    )
    actions = action_range(field_position)
    require(
        actions.start == position.get("start_action")
        and actions.stop - 1 == position.get("end_action"),
        f"event {event_number} field {decision['path']}: span differs",
    )
    absolute = strict_dict(position.get("absolute_index_range"), "absolute range")
    indices = range(
        strict_int(absolute.get("start"), "absolute start"),
        strict_int(absolute.get("end"), "absolute end") + 1,
    )
    require(
        len(actions) == len(indices),
        f"event {event_number} field {decision['path']}: span lengths differ",
    )
    return position, actions, indices


def span_grammar_lines(
    label: str,
    actions: range,
    kind: str,
    source: int,
    destination: int,
    indices: range | None = None,
) -> list[str]:
    """Emit the action grammar owned by one aggregate projected field."""

    lines: list[str] = []
    for offset, action_number in enumerate(actions):
        lines.extend(
            [
                f"let action <- actionAt actions {action_number} "
                f"{lean_string(label)}",
                f"expectEq {lean_string(label)} (actionKind action) "
                f"{lean_string(kind)}",
                f"expectEq {lean_string(label)} (actionSource action).val {source}",
                f"expectEq {lean_string(label)} "
                "((actionDestination? action).map fun node => node.val) "
                f"(some {destination})",
            ]
        )
        if indices is not None:
            lines.append(
                f"expectEq {lean_string(label)} (actionParameter? action) "
                f"(some {indices.start + offset})"
            )
    return lines


def span_field_lines(
    certificate: smt.Certificate,
    event_number: int,
    decision: Mapping[str, Any],
    label: str,
) -> list[str]:
    """Emit one aggregate span assertion from explicit certificate metadata."""

    position, actions, indices = span_metadata(
        certificate,
        event_number,
        decision,
    )
    message = certificate.events[event_number]["msg"]
    path = decision["path"]
    value = json_path_value(message, path)
    span_kind = position["span_kind"]
    start_step = actions.start - 1
    if span_kind == "append_entries_batch_send":
        source = int(message["state"]["node_id"])
        destination = int(message["to_node_id"])
        lines = span_grammar_lines(
            label,
            actions,
            "appendEntries",
            source,
            destination,
            indices,
        )
        if path in {"msg.function", "msg.packet.msg"}:
            pass
        elif path == "msg.to_node_id":
            require(
                int(value) == destination,
                f"{label}: destination metadata differs",
            )
        elif path in {"msg.packet.term", "msg.packet.leader_commit_idx"}:
            field = "term" if path.endswith(".term") else "leaderCommit"
            for action_number in actions:
                lines.extend(
                    [
                        f"let request <- previewAppendRequest states actions "
                        f"{action_number} {lean_string(label)}",
                        f"expectEq {lean_string(label)} request.{field} {value}",
                    ]
                )
        elif path == "msg.packet.prev_idx":
            lines.extend(
                [
                    f"let request <- previewAppendRequest states actions "
                    f"{actions.start} {lean_string(label)}",
                    f"expectEq {lean_string(label)} request.prevLogIndex {value}",
                    f"expectEq {lean_string(label)} ({value} + 1) {indices.start}",
                ]
            )
        elif path == "msg.packet.idx":
            lines.extend(
                [
                    f"let request <- previewAppendRequest states actions "
                    f"{actions.stop - 1} {lean_string(label)}",
                    f"expectEq {lean_string(label)} "
                    f"(appendRequestEnd request) {value}",
                    f"expectEq {lean_string(label)} {value} {indices.stop - 1}",
                ]
            )
        elif path == "msg.packet.prev_term":
            lines.extend(
                [
                    f"let request <- previewAppendRequest states actions "
                    f"{actions.start} {lean_string(label)}",
                    f"expectEq {lean_string(label)} request.prevLogTerm {value}",
                ]
            )
        elif path == "msg.packet.term_of_idx":
            lines.extend(
                [
                    f"let term <- entryTermAt states {start_step} {source} "
                    f"{message['packet']['idx']} {lean_string(label)}",
                    f"expectEq {lean_string(label)} term {value}",
                ]
            )
        else:
            raise CheckGenerationError(f"{label}: unsupported aggregate send field")
        return indent_block(lines)

    source = int(message["from_node_id"])
    destination = int(message["state"]["node_id"])
    lines = span_grammar_lines(
        label,
        actions,
        "receive",
        source,
        destination,
    )
    if span_kind == "append_entries_batch_receive":
        if path in {"msg.function", "msg.from_node_id"}:
            pass
        elif path == "msg.packet.msg":
            for slot in range(len(actions)):
                lines.extend(
                    [
                        f"let message <- queueMessageAt states {start_step} "
                        f"{destination} {slot} {lean_string(label)}",
                        f"expectEq {lean_string(label)} (messageKind message) "
                        f"{lean_string('appendEntriesRequest')}",
                    ]
                )
        elif path in {"msg.packet.term", "msg.packet.leader_commit_idx"}:
            for slot in range(len(actions)):
                lines.append(
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} {slot} {lean_string(label)}"
                )
                lines.append(
                    f"let request <- appendRequest {lean_string(label)} message"
                )
                accessor = "term" if path.endswith(".term") else "leaderCommit"
                lines.append(
                    f"expectEq {lean_string(label)} request.{accessor} {value}"
                )
        elif path == "msg.packet.prev_idx":
            lines.extend(
                [
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} 0 {lean_string(label)}",
                    f"let request <- appendRequest {lean_string(label)} message",
                    f"expectEq {lean_string(label)} request.prevLogIndex {value}",
                    f"expectEq {lean_string(label)} ({value} + 1) {indices.start}",
                ]
            )
        elif path == "msg.packet.idx":
            lines.extend(
                [
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} {len(actions) - 1} {lean_string(label)}",
                    f"let request <- appendRequest {lean_string(label)} message",
                    f"expectEq {lean_string(label)} "
                    f"(appendRequestEnd request) {value}",
                    f"expectEq {lean_string(label)} {value} {indices.stop - 1}",
                ]
            )
        elif path == "msg.packet.prev_term":
            lines.extend(
                [
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} 0 {lean_string(label)}",
                    f"let request <- appendRequest {lean_string(label)} message",
                    f"expectEq {lean_string(label)} request.prevLogTerm {value}",
                ]
            )
        elif path == "msg.packet.term_of_idx":
            lines.extend(
                [
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} {len(actions) - 1} {lean_string(label)}",
                    f"let request <- appendRequest {lean_string(label)} message",
                    f"expectEq {lean_string(label)} "
                    f"(appendRequestEndTerm request) {value}",
                ]
            )
        else:
            raise CheckGenerationError(f"{label}: unsupported aggregate request field")
        return indent_block(lines)

    require(
        span_kind == "append_entries_batch_response_receive",
        f"{label}: unsupported span kind {span_kind}",
    )
    if path in {"msg.function", "msg.from_node_id"}:
        pass
    elif path == "msg.packet.msg":
        for slot in range(len(actions)):
            lines.extend(
                [
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} {slot} {lean_string(label)}",
                    f"expectEq {lean_string(label)} (messageKind message) "
                    f"{lean_string('appendEntriesResponse')}",
                ]
            )
    elif path in {"msg.packet.term", "msg.packet.success"}:
        for slot in range(len(actions)):
            lines.extend(
                [
                    f"let message <- queueMessageAt states {start_step} "
                    f"{destination} {slot} {lean_string(label)}",
                    f"let response <- appendResponse {lean_string(label)} message",
                ]
            )
            if path.endswith(".term"):
                lines.append(f"expectEq {lean_string(label)} response.term {value}")
            else:
                lines.append(
                    f"expectEq {lean_string(label)} response.success "
                    f"{lean_bool(value == 'OK')}"
                )
    elif path == "msg.packet.last_log_idx":
        lines.extend(
            [
                f"let message <- queueMessageAt states {start_step} "
                f"{destination} {len(actions) - 1} {lean_string(label)}",
                f"let response <- appendResponse {lean_string(label)} message",
                f"expectEq {lean_string(label)} response.lastLogIndex {value}",
                f"expectEq {lean_string(label)} {value} {indices.stop - 1}",
            ]
        )
    else:
        raise CheckGenerationError(f"{label}: unsupported aggregate response field")
    return indent_block(lines)


def projected_field_lines(
    certificate: smt.Certificate,
    event_number: int,
    decision: Mapping[str, Any],
) -> list[str]:
    """Translate exactly one projected certificate field to Lean checks."""

    path = strict_string(decision["path"], f"event {event_number}.path")
    position = strict_dict(decision["field_position"], "field_position")
    label = label_for(event_number, path, position)
    if position.get("kind") == "whole_action_span":
        return span_field_lines(certificate, event_number, decision, label)

    message = certificate.events[event_number]["msg"]
    step = field_state_step(decision)
    state = message["state"]
    node = int(state["node_id"])
    if path == "msg.state.current_view":
        return state_field_lines(
            label, step, node, "currentTerm", state["current_view"]
        )
    if path == "msg.state.last_idx":
        return state_field_lines(label, step, node, "logLength", state["last_idx"])
    if path == "msg.state.commit_idx":
        return state_field_lines(label, step, node, "commitIndex", state["commit_idx"])
    if path == "msg.state.leadership_state":
        return state_field_lines(
            label,
            step,
            node,
            "role",
            state["leadership_state"],
        )
    if path == "msg.state.node_id":
        actions = action_range(position)
        require(len(actions) == 1, f"{label}: state owner spans actions")
        action_number = actions.start
        action_kind = certificate.actions[action_number - 1]["kind"]
        owner_field = (
            "destination" if action_kind in {"receive", "updateTerm"} else "source"
        )
        return action_field_lines(label, action_number, owner_field, node)
    if path == "msg.function":
        actions = action_range(position)
        require(len(actions) == 1, f"{label}: function spans actions")
        action_number = actions.start
        return action_field_lines(
            label,
            action_number,
            "kind",
            certificate.actions[action_number - 1]["kind"],
        )
    if path.startswith("msg.packet."):
        return packet_point_lines(
            certificate,
            event_number,
            decision,
            label,
            step,
        )
    if path == "msg.from_node_id":
        actions = action_range(position)
        require(len(actions) == 1, f"{label}: source spans actions")
        return action_field_lines(
            label,
            actions.start,
            "source",
            int(message["from_node_id"]),
        )
    if path == "msg.to_node_id":
        expected = int(message["to_node_id"])
        if message["function"] == "send_append_entries":
            actions = action_range(position)
            require(len(actions) == 1, f"{label}: destination spans actions")
            if event_number == 3:
                return indent_block(
                    [
                        f"let action <- actionAt actions {actions.start} "
                        f"{lean_string(label)}",
                        f"let expected <- nodeOfNat {lean_string(label)} "
                        f"{expected}",
                        f"expectTrue {lean_string(label)} "
                        "(match actionConfiguration? action with "
                        "| some configuration => "
                        "decide (Membership.mem configuration expected) "
                        "| none => false)",
                    ]
                )
            return action_field_lines(
                label,
                actions.start,
                "destination",
                expected,
            )
        return message_lines(
            label,
            step,
            0,
            None,
            [
                f"expectEq {lean_string(label)} "
                "(Message.destination message).val "
                f"{expected}"
            ],
        )
    if path in {"msg.sent_idx", "msg.match_idx"}:
        field = "sent" if path == "msg.sent_idx" else "match"
        return pair_field_lines(
            label,
            step,
            node,
            1,
            field,
            int(message[path.split(".")[1]]),
        )
    if path == "msg.view":
        return state_field_lines(label, step, node, "currentTerm", message["view"])
    if path == "msg.seqno":
        actions = action_range(position)
        require(len(actions) == 1, f"{label}: sequence spans actions")
        return indent_block(
            [
                f"let state <- stateAt states {step} {lean_string(label)}",
                f"let node <- nodeOfNat {lean_string(label)} {node}",
                f"let action <- actionAt actions {actions.start} "
                f"{lean_string(label)}",
                f"expectEq {lean_string(label)} "
                f"((state.nodes node).log.length + 1) {message['seqno']}",
                f"expectTrue {lean_string(label)} "
                '(actionKind action == "clientRequest" || '
                'actionKind action == "signCommittableMessages")',
            ]
        )
    if path == "msg.globally_committable":
        actions = action_range(position)
        expected_kind = (
            "signCommittableMessages"
            if message["globally_committable"]
            else "clientRequest"
        )
        return action_field_lines(
            label,
            actions.start,
            "kind",
            expected_kind,
        )
    if path.startswith("msg.args.configuration."):
        configuration = message["args"]["configuration"]
        index = int(configuration["idx"])
        members = {int(member) for member in configuration["nodes"]}
        membership = [member in members for member in range(15)]
        actions = action_range(position)
        require(len(actions) == 1, f"{label}: configuration spans actions")
        if event_number == 2:
            lines = [
                f"let state <- stateAt states {step} {lean_string(label)}",
                f"let node <- nodeOfNat {lean_string(label)} 0",
            ]
            if path.endswith(".idx"):
                lines.append(
                    f"expectEq {lean_string(label)} "
                    f"((state.nodes node).log.length + 1) {index}"
                )
            else:
                lines.extend(
                    [
                        f"let action <- actionAt actions {actions.start} "
                        f"{lean_string(label)}",
                        f"let expected <- decodeNodeMembership "
                        f"{lean_string(label)} "
                        f"{lean_list(membership, lean_bool)}",
                        f"expectTrue {lean_string(label)} "
                        "(decide (actionConfiguration? action = some expected))",
                    ]
                )
            return indent_block(lines)
        lines = [
            f"let configuration <- configurationAt states {step} {node} {index} "
            f"{lean_string(label)}"
        ]
        if path.endswith(".idx"):
            lines.append(f"expectEq {lean_string(label)} {index} {index}")
        else:
            lines.extend(
                [
                    f"let expected <- decodeNodeMembership {lean_string(label)} "
                    f"{lean_list(membership, lean_bool)}",
                    f"expectTrue {lean_string(label)} "
                    "(decide (configuration = expected))",
                ]
            )
        return indent_block(lines)
    if path == "msg.args.idx":
        actions = action_range(position)
        target_step = actions.start
        target = int(message["args"]["idx"])
        return state_field_lines(
            label,
            target_step,
            node,
            "commitIndex",
            target,
        )
    raise CheckGenerationError(
        f"event {event_number} field {path}: unsupported projected field"
    )


def observation_check_source(
    certificate: smt.Certificate,
) -> tuple[str, int, int, list[dict[str, Any]]]:
    """Emit every projected field and retain every explicit omission."""

    definitions: list[str] = []
    calls: list[str] = []
    projected_count = 0
    omissions: list[dict[str, Any]] = []
    owned_events: list[int] = []
    span_events: set[int] = set()
    for event_number in range(1, smt.EXPECTED_EVENTS + 1):
        event_lines = [
            f"def checkEvent{event_number:02d}",
            "    (states : Array SimState)",
            "    (actions : Array SimAction) :",
            "    Except String Unit := do",
        ]
        observation = certificate.observations[event_number]
        owned_events.append(event_number)
        if observation["position"].get("kind") == "action_span":
            span_events.add(event_number)
        event_projected = 0
        for decision_value in observation["field_decisions"]:
            decision = strict_dict(
                decision_value,
                f"event {event_number}.field_decision",
            )
            status = decision.get("status")
            if status == "omitted":
                omissions.append(
                    {
                        "event": event_number,
                        "path": decision["path"],
                        "reason": decision["reason"],
                        "field_kind": decision["field_kind"],
                        "field_position": decision["field_position"],
                    }
                )
                continue
            require(
                status == "projected",
                f"event {event_number} field {decision.get('path')}: "
                f"unsupported status {status}",
            )
            generated = projected_field_lines(
                certificate,
                event_number,
                decision,
            )
            require(
                generated,
                f"event {event_number} field {decision['path']}: emitted no check",
            )
            event_lines.extend(generated)
            projected_count += 1
            event_projected += 1
        require(event_projected > 0, f"event {event_number}: no projected fields")
        event_lines.append("  pure ()")
        definitions.append("\n".join(event_lines))
        calls.append(f"  checkEvent{event_number:02d} states actions")
    require(
        owned_events == list(range(1, smt.EXPECTED_EVENTS + 1)),
        "events are not owned exactly once",
    )
    require(span_events == EXPECTED_SPANS, "span event ownership differs")
    dispatcher = "\n".join(
        [
            "def checkObservations",
            "    (states : Array SimState)",
            "    (actions : Array SimAction) :",
            "    Except String Unit := do",
            *calls,
            "  pure ()",
        ]
    )
    return (
        "\n\n".join([*definitions, dispatcher]),
        projected_count,
        len(omissions),
        omissions,
    )


def expected_action_source(
    certificate: smt.Certificate,
    actions: Sequence[Mapping[str, Any]],
) -> str:
    """Emit independent per-field action checks against certificate metadata."""

    definitions: list[str] = []
    calls: list[str] = []
    for number, raw in enumerate(actions, 1):
        lines = [
            f"def checkCertificateAction{number:02d} " "(actions : Array SimAction) :",
            "    Except String Unit := do",
        ]
        certificate_action = certificate.actions[number - 1]
        parameters = certificate_action["parameters"]
        kind = certificate_action["kind"]
        source = parameters.get("source", parameters.get("node", 0))
        lines.extend(
            action_field_lines(f"action {number} field kind", number, "kind", kind)
        )
        lines.extend(
            action_field_lines(
                f"action {number} field source",
                number,
                "source",
                source,
            )
        )
        if kind in {"appendEntries", "receive", "requestVote", "updateTerm"}:
            lines.extend(
                action_field_lines(
                    f"action {number} field destination",
                    number,
                    "destination",
                    parameters["destination"],
                )
            )
        if kind == "appendEntries":
            lines.extend(
                action_field_lines(
                    f"action {number} field parameter",
                    number,
                    "parameter",
                    parameters["batch_end"],
                )
            )
        if kind == "changeConfiguration":
            membership = raw["configuration_membership"]
            label = f"action {number} field configuration"
            lines.extend(
                indent_block(
                    [
                        f"let action <- actionAt actions {number} "
                        f"{lean_string(label)}",
                        f"let expected <- decodeNodeMembership "
                        f"{lean_string(label)} "
                        f"{lean_list(membership, lean_bool)}",
                        f"expectTrue {lean_string(label)} "
                        "(decide (actionConfiguration? action = some expected))",
                    ]
                )
            )
        lines.append("  pure ()")
        definitions.append("\n".join(lines))
        calls.append(f"  checkCertificateAction{number:02d} actions")
    dispatcher = "\n".join(
        [
            "def checkCertificateActions (actions : Array SimAction) :",
            "    Except String Unit := do",
            *calls,
            "  pure ()",
        ]
    )
    return "\n\n".join([*definitions, dispatcher])


def generated_source(
    witness: Mapping[str, Any],
    certificate: smt.Certificate,
    witness_path: Path,
    certificate_path: Path,
) -> tuple[str, dict[str, Any]]:
    """Build the complete generated Lean source and generation report."""

    initial = strict_dict(witness["initial_state"], "S0")
    validate_initial_state(initial, certificate)
    fresh_tx = strict_int(witness["fresh_transaction_id"], "fresh_transaction_id")
    require(fresh_tx < 64, "fresh_transaction_id: outside Fin 64")
    actions = validate_actions(witness["actions"], certificate, fresh_tx)
    observations, projected_count, omitted_count, omissions = observation_check_source(
        certificate
    )
    action_checks = expected_action_source(certificate, actions)
    witness_hash = sha256_file(witness_path)
    certificate_hash = sha256_file(certificate_path)
    nodes = ",\n".join(raw_node_literal(node) for node in initial["nodes"])
    queues = ",\n".join(raw_queue_literal(queue) for queue in initial["network"])
    action_literals = ",\n".join(raw_action_literal(action) for action in actions)
    source = f"""-- Generated by CCFRaft/naive_full_state_lean.py. Do not edit.
-- witness_sha256={witness_hash}
-- certificate_sha256={certificate_hash}

import CCFRaft.NaiveFullStateWitness

set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 100000
set_option linter.unusedVariables false

namespace CCFRaft.GeneratedNaiveFullStateWitness

open CCFRaft.NaiveFullStateWitness
open CCFRaft.Simulation

def inputWitnessSHA256 : String := {lean_string(witness_hash)}
def inputCertificateSHA256 : String := {lean_string(certificate_hash)}
def checkerSchema : String := {lean_string(CHECKER_SCHEMA)}

def singletonBootstrap : Bootstrap Node where
  configuration := {{Fin.mk 0 (by decide)}}
  leader := Fin.mk 0 (by decide)
  leader_mem := by decide

local instance : Bootstrap Node := singletonBootstrap

def rawInitialState : RawInitialState where
  nodes := [
{nodes}
  ]
  network := [
{queues}
  ]
  submittedTransactionMembership :=
    {lean_list(initial['submitted_transaction_membership'], lean_bool)}
  hasJoinedMembership :=
    {lean_list(initial['has_joined_membership'], lean_bool)}

def rawActions : List RawAction := [
{action_literals}
]

def freshTransactionIdValue : Nat := {fresh_tx}
def projectedFieldCount : Nat := {projected_count}
def explicitlyOmittedFieldCount : Nat := {omitted_count}
def observationCount : Nat := {smt.EXPECTED_EVENTS}
def checkpointObservationCount : Nat := 47
def spanObservationCount : Nat := 6

{action_checks}

{observations}

def checkFinalState
    (states : Array SimState)
    (actions : Array SimAction) :
    Except String Unit := do
  let initial <- stateAt states 0 "final expected state"
  let final <- stateAt states 43 "final expected state"
  let node0 <- nodeOfNat "final expected state node0" 0
  let node1 <- nodeOfNat "final expected state node1" 1
  let fresh <- txOfNat "final expected state fresh transaction" freshTransactionIdValue
  expectEq "final.nodes[0].log.length" (final.nodes node0).log.length 7
  expectEq "final.nodes[1].log.length" (final.nodes node1).log.length 7
  expectEq "final.nodes[0].commitIndex" (final.nodes node0).commitIndex 7
  expectEq "final.nodes[1].commitIndex" (final.nodes node1).commitIndex 7
  expectTrue "final.nodes[0/1].log" (decide ((final.nodes node0).log = (final.nodes node1).log))
  for node in allNodes do
    expectEq s!"final.network[{{node.val}}].length" (final.network node).length 0
  expectTrue "S0.submittedTxIds.fresh"
    (decide (Not (Membership.mem initial.submittedTxIds fresh)))
  expectTrue "final.submittedTxIds.fresh"
    (decide (Membership.mem final.submittedTxIds fresh))
  expectTrue "final.nodes[0].log.fresh" (containsTransaction final node0 fresh)
  expectTrue "final.nodes[1].log.fresh" (containsTransaction final node1 fresh)
  let action21 <- actionAt actions 21 "action 21 transaction"
  expectTrue "action 21 transaction" (decide (action21 = .clientRequest node0 fresh))

def check : Except String Unit := do
  let initial <- decodeInitialState rawInitialState
  let actions <- decodeActions rawActions
  checkCertificateActions actions
  let states <- replayCanonical initial actions
  expectEq "canonical replay state count" states.size 44
  checkObservations states actions
  checkFinalState states actions

def run : IO UInt32 := do
  match check with
  | .error message =>
      IO.println s!"ENCODING_BUG {{message}}"
      pure 1
  | .ok () =>
      IO.println "S0_STATE_CHECKS=passed"
      IO.println
        "segment_entry arbitrary_existential=true reachable_claim=false invariant_claim=false"
      IO.println
        s!"counts actions={{ACTION_COUNT}} observations={{observationCount}} checkpoints={{
          checkpointObservationCount}} spans={{spanObservationCount}} projected_fields={{
          projectedFieldCount}} projected_unchecked=0 explicit_omissions={{
          explicitlyOmittedFieldCount}}"
      IO.println
        s!"final_state node0_log=7 node1_log=7 node0_commit=7 node1_commit=7 queues_drained=15 fresh_tx={{
          freshTransactionIdValue}} submitted=true"
      IO.println "VALID_SEGMENT"
      pure 0

end CCFRaft.GeneratedNaiveFullStateWitness

def main : IO UInt32 :=
  CCFRaft.GeneratedNaiveFullStateWitness.run
"""
    report = {
        "schema_version": CHECKER_SCHEMA,
        "witness_sha256": witness_hash,
        "certificate_sha256": certificate_hash,
        "counts": {
            "actions": smt.EXPECTED_ACTIONS,
            "events": smt.EXPECTED_EVENTS,
            "checkpoint_observations": 47,
            "span_observations": 6,
            "projected_fields": projected_count,
            "explicit_omissions": omitted_count,
            "projected_unchecked": 0,
        },
        "span_events": sorted(EXPECTED_SPANS),
        "initial_state_semantics": witness["initial_state_semantics"],
        "s0_node2": {
            "role": initial["nodes"][2]["role"],
            "term": initial["nodes"][2]["current_term"],
            "log_length": initial["nodes"][2]["log_length"],
            "commit_index": initial["nodes"][2]["commit_index"],
        },
        "structural_omissions": witness["structural_checks"][
            "omitted_from_executable_stateChecks"
        ],
        "omissions": omissions,
    }
    return source, report


def generate(
    witness_path: Path,
    certificate_path: Path,
    output_dir: Path,
) -> None:
    """Generate the Lean source and complete omission report."""

    witness, certificate = load_inputs(witness_path, certificate_path)
    source, report = generated_source(
        witness,
        certificate,
        witness_path,
        certificate_path,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / SOURCE_NAME
    source_path.write_text(source, encoding="utf-8")
    write_json(output_dir / "canonical-check-report-v1.json", report)
    print(
        f"generated source={source_path} "
        f"projected={report['counts']['projected_fields']} "
        f"omitted={report['counts']['explicit_omissions']}"
    )


def verify_source(
    witness_path: Path,
    certificate_path: Path,
    source_path: Path,
) -> None:
    """Verify that the shell is compiling source bound to its current inputs."""

    text = source_path.read_text(encoding="utf-8")
    witness_hash = sha256_file(witness_path)
    certificate_hash = sha256_file(certificate_path)
    for name, digest in (
        ("witness_sha256", witness_hash),
        ("certificate_sha256", certificate_hash),
    ):
        marker = f"-- {name}={digest}\n"
        require(marker in text, f"generated source {name} marker differs")
    print(
        f"verified witness_sha256={witness_hash} "
        f"certificate_sha256={certificate_hash}"
    )


def mutate(
    kind: str,
    witness_path: Path,
    certificate_path: Path,
    output_dir: Path,
) -> None:
    """Create one exact negative-test input copy."""

    witness = strict_dict(
        json.loads(witness_path.read_text(encoding="utf-8")),
        "witness",
    )
    certificate = strict_dict(
        json.loads(certificate_path.read_text(encoding="utf-8")),
        "certificate",
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    mutated_witness = copy.deepcopy(witness)
    mutated_certificate = copy.deepcopy(certificate)
    if kind == "initial-field":
        mutated_witness["initial_state"]["nodes"][0]["commit_index"] = 1
    elif kind == "projected-observation":
        retained = mutated_certificate["raw_events"][52]
        row = json.loads(retained["raw"])
        row["msg"]["state"]["commit_idx"] = 8
        raw = json.dumps(row, separators=(",", ":"), sort_keys=False)
        retained["raw"] = raw
        retained["sha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        raw_lines = [item["raw"] for item in mutated_certificate["raw_events"]]
        input_text = "\n".join(raw_lines) + "\n"
        input_hash = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
        mutated_certificate["input"]["sha256"] = input_hash
        mutated_witness["hashes"]["input_trace_sha256"] = input_hash
    else:
        raise CheckGenerationError(f"unsupported mutation {kind}")
    certificate_output = output_dir / certificate_path.name
    witness_output = output_dir / witness_path.name
    write_json(certificate_output, mutated_certificate)
    mutated_witness["hashes"]["certificate_sha256"] = sha256_file(certificate_output)
    write_json(witness_output, mutated_witness)
    print(
        f"mutation={kind} witness={witness_output} " f"certificate={certificate_output}"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the generator command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--witness", type=Path, required=True)
    generate_parser.add_argument("--certificate", type=Path, required=True)
    generate_parser.add_argument("--output-dir", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify-source")
    verify_parser.add_argument("--witness", type=Path, required=True)
    verify_parser.add_argument("--certificate", type=Path, required=True)
    verify_parser.add_argument("--source", type=Path, required=True)

    mutation_parser = subparsers.add_parser("mutate")
    mutation_parser.add_argument(
        "--kind",
        choices=("initial-field", "projected-observation"),
        required=True,
    )
    mutation_parser.add_argument("--witness", type=Path, required=True)
    mutation_parser.add_argument("--certificate", type=Path, required=True)
    mutation_parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one generator operation with stable ENCODING_BUG output."""

    args = parse_args(argv)
    try:
        if args.command == "generate":
            generate(args.witness, args.certificate, args.output_dir)
        elif args.command == "verify-source":
            verify_source(args.witness, args.certificate, args.source)
        elif args.command == "mutate":
            mutate(
                args.kind,
                args.witness,
                args.certificate,
                args.output_dir,
            )
        else:
            raise CheckGenerationError(f"unsupported command {args.command}")
    except (CheckGenerationError, smt.EncodingError, OSError) as error:
        print(f"ENCODING_BUG {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
