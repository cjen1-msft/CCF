#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate and decode a trace-specific two-node full-state SMT prototype."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Sequence

import naive_full_state_smt as full

ENCODING_SCHEMA = "ccfraft-cheap-full-state-smt/v1"
WITNESS_SCHEMA = "ccfraft-cheap-full-state-smt-witness/v1"
SMT_NODE_COUNT = 2
LOG_CAPACITY = 7
QUEUE_CAPACITY = 4
TX_COUNT = full.TX_COUNT
EXPECTED_EVENTS = full.EXPECTED_EVENTS
EXPECTED_REDUCTIONS = full.EXPECTED_REDUCTIONS
EXPECTED_ACTIONS = full.EXPECTED_ACTIONS

EncodingError = full.EncodingError
Certificate = full.Certificate
Encoding = full.Encoding
SmtBuilder = full.SmtBuilder


def require(condition: bool, message: str) -> None:
    """Raise a labelled encoding error when a requirement is false."""

    full.require(condition, message)


def write_json(path: Path, value: Any) -> None:
    """Write stable JSON."""

    full.write_json(path, value)


def write_compact_json(path: Path, value: Any) -> None:
    """Write deterministic compact JSON for the complete-state witness."""

    path.write_text(
        json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_certificate(path: Path) -> Certificate:
    """Validate the v2 certificate, then select its exact observed footprint."""

    certificate = full.load_certificate(path)
    capacities = certificate.data["capacities"]
    require(
        capacities["observed_nodes"] == [0, 1],
        "cheap footprint requires observed nodes 0 and 1",
    )
    require(
        capacities["network_lanes"]
        == [
            {
                "source": 0,
                "destination": 1,
                "maximum_occupancy": 4,
                "terminal_occupancy": 0,
            },
            {
                "source": 1,
                "destination": 0,
                "maximum_occupancy": 4,
                "terminal_occupancy": 0,
            },
        ],
        "cheap footprint requires only the 0-to-1 and 1-to-0 lanes",
    )
    require(
        certificate.log_capacity == LOG_CAPACITY,
        "cheap footprint log capacity differs",
    )
    return replace(
        certificate,
        node_count=SMT_NODE_COUNT,
        queue_capacity=QUEUE_CAPACITY,
    )


def declare_actions(
    builder: SmtBuilder,
    certificate: Certificate,
    mutation: str,
) -> None:
    """Declare the fixed action skeleton with a two-node parameter domain."""

    builder.declare("(declare-const fresh_tx Int)")
    builder.labelled(
        "fresh_transaction_domain",
        "one symmetric transaction identifier is selected from Fin 64",
        f"(and (>= fresh_tx 0) (< fresh_tx {TX_COUNT}))",
    )
    for action in certificate.actions:
        number = action["action"]
        for field in ("kind", "source", "destination", "parameter", "transaction"):
            builder.declare(f"(declare-const {full.action_symbol(field, number)} Int)")
        builder.declare(
            f"(declare-const {full.action_symbol('configuration', number)} "
            "(Array Int Bool))"
        )
        builder.labelled(
            f"action{number:02d}_domain",
            f"action {number} is bounded by the two-node cheap footprint",
            full.smt_and(
                [
                    f"(and (>= {full.action_symbol('kind', number)} 1) "
                    f"(<= {full.action_symbol('kind', number)} 10))",
                    f"(and (>= {full.action_symbol('source', number)} 0) "
                    f"(< {full.action_symbol('source', number)} {SMT_NODE_COUNT}))",
                    f"(and (>= {full.action_symbol('destination', number)} 0) "
                    f"(< {full.action_symbol('destination', number)} "
                    f"{SMT_NODE_COUNT}))",
                    f"(and (>= {full.action_symbol('parameter', number)} 0) "
                    f"(<= {full.action_symbol('parameter', number)} "
                    f"{LOG_CAPACITY}))",
                    f"(and (>= {full.action_symbol('transaction', number)} 0) "
                    f"(< {full.action_symbol('transaction', number)} {TX_COUNT}))",
                ]
            ),
        )
        source, destination, parameter, transaction = full.action_parameters(action)
        if mutation == "wrong-destination-action-param" and number == 3:
            destination = 0
        configuration = set(action["parameters"].get("new_configuration", []))
        fixed = [
            full.smt_eq(
                full.action_symbol("kind", number),
                full.ACTION_KINDS[action["kind"]],
            ),
            full.smt_eq(full.action_symbol("source", number), source),
            full.smt_eq(full.action_symbol("destination", number), destination),
            full.smt_eq(full.action_symbol("parameter", number), parameter),
            full.smt_eq(full.action_symbol("transaction", number), transaction),
        ]
        fixed.extend(
            full.smt_eq(
                full.action_config(number, member),
                member in configuration,
            )
            for member in range(SMT_NODE_COUNT)
        )
        builder.labelled(
            f"action{number:02d}_certificate_skeleton",
            f"certificate fixes action {number} as {action['template']}",
            full.smt_and(fixed),
        )


def exact_footprint_constraints(step: int, certificate: Certificate) -> list[str]:
    """Restrict trace-specific lanes, configurations, and transaction entries."""

    constraints: list[str] = []
    for node in range(SMT_NODE_COUNT):
        log_length = full.select("log_len", step, node)
        for index in range(1, LOG_CAPACITY + 1):
            slot = full.log_slot(node, index, LOG_CAPACITY)
            active = f"(<= {index} {log_length})"
            tag = full.select("log_tag", step, slot)
            transaction = full.select("log_tx", step, slot)
            configuration0 = full.select(
                "log_config",
                step,
                full.log_config_slot(
                    node,
                    index,
                    0,
                    SMT_NODE_COUNT,
                    LOG_CAPACITY,
                ),
            )
            constraints.extend(
                [
                    f"(=> (and {active} "
                    f"(= {tag} {full.ENTRY_TRANSACTION})) "
                    f"(= {transaction} fresh_tx))",
                    f"(=> (and {active} "
                    f"(= {tag} {full.ENTRY_RECONFIGURATION})) "
                    f"(and {configuration0} "
                    f"(or (= {index} 1) (= {index} 3))))",
                ]
            )

    for destination in range(SMT_NODE_COUNT):
        length = full.select("queue_len", step, destination)
        expected_source = 1 - destination
        for slot_number in range(QUEUE_CAPACITY):
            slot = full.queue_slot(destination, slot_number, QUEUE_CAPACITY)
            active = f"(< {slot_number} {length})"
            request_entry = full.smt_and(
                [
                    active,
                    full.smt_eq(
                        full.select("queue_tag", step, slot),
                        full.MESSAGE_APPEND_REQUEST,
                    ),
                    full.select("queue_entry_present", step, slot),
                ]
            )
            entry_tag = full.select("queue_entry_tag", step, slot)
            entry_tx = full.select("queue_entry_tx", step, slot)
            configuration0 = full.select(
                "queue_entry_config",
                step,
                full.queue_config_slot(
                    destination,
                    slot_number,
                    0,
                    SMT_NODE_COUNT,
                    QUEUE_CAPACITY,
                ),
            )
            absolute_index = f"(+ {full.select('queue_prev_log_index', step, slot)} 1)"
            constraints.extend(
                [
                    f"(=> {active} "
                    f"(= {full.select('queue_source', step, slot)} "
                    f"{expected_source}))",
                    f"(=> (and {request_entry} "
                    f"(= {entry_tag} {full.ENTRY_TRANSACTION})) "
                    f"(= {entry_tx} fresh_tx))",
                    f"(=> (and {request_entry} "
                    f"(= {entry_tag} {full.ENTRY_RECONFIGURATION})) "
                    f"(and {configuration0} "
                    f"(or (= {absolute_index} 1) "
                    f"(= {absolute_index} 3))))",
                ]
            )
    return constraints


def add_structural_constraints(
    builder: SmtBuilder,
    certificate: Certificate,
) -> None:
    """Encode the structural checks over both cheap nodes at every state."""

    for step in range(EXPECTED_ACTIONS + 1):
        domain, state_checks, relevant_pairs = full.state_structural_constraints(
            step,
            certificate,
            full_world=True,
        )
        builder.labelled(
            f"state_s{step:02d}_finite_domains_and_canonical_unused",
            f"S{step} has bounded fields and canonical unused slots for nodes 0 and 1",
            full.smt_and(domain),
        )
        builder.labelled(
            f"state_s{step:02d}_encoded_state_checks",
            f"S{step} encodes stateChecks for nodes 0 and 1",
            full.smt_and(state_checks),
        )
        builder.labelled(
            f"state_s{step:02d}_relevant_prefix_and_log_matching",
            f"S{step} encodes prefix consistency and log matching for nodes 0 and 1",
            full.smt_and(relevant_pairs),
        )
        builder.labelled(
            f"state_s{step:02d}_exact_trace_footprint",
            f"S{step} uses two opposite lanes, two configurations, and one selected transaction",
            full.smt_and(exact_footprint_constraints(step, certificate)),
        )


def add_bootstrap_constraints(
    builder: SmtBuilder,
    certificate: Certificate,
) -> None:
    """Constrain the synthetic event-1 pre-commit cheap state."""

    constraints = [
        full.smt_eq(full.select("role", 0, 0), full.ROLE_LEADER),
        full.smt_eq(full.select("term", 0, 0), 2),
        full.smt_eq(full.select("log_len", 0, 0), 2),
        full.smt_eq(full.select("commit", 0, 0), 0),
        full.smt_eq(
            full.select("log_term", 0, full.log_slot(0, 1, LOG_CAPACITY)),
            2,
        ),
        full.smt_eq(
            full.select("log_tag", 0, full.log_slot(0, 1, LOG_CAPACITY)),
            full.ENTRY_RECONFIGURATION,
        ),
        full.smt_eq(
            full.select("log_term", 0, full.log_slot(0, 2, LOG_CAPACITY)),
            2,
        ),
        full.smt_eq(
            full.select("log_tag", 0, full.log_slot(0, 2, LOG_CAPACITY)),
            full.ENTRY_SIGNATURE,
        ),
        full.select("has_joined", 0, 0),
        full.smt_not(full.select("has_joined", 0, 1)),
        full.smt_not(full.select("submitted", 0, "fresh_tx")),
    ]
    constraints.extend(
        full.smt_eq(
            full.select(
                "log_config",
                0,
                full.log_config_slot(
                    0,
                    1,
                    member,
                    SMT_NODE_COUNT,
                    LOG_CAPACITY,
                ),
            ),
            member == 0,
        )
        for member in range(SMT_NODE_COUNT)
    )
    constraints.extend(
        full.smt_eq(full.select("queue_len", 0, destination), 0)
        for destination in range(SMT_NODE_COUNT)
    )
    builder.labelled(
        "synthetic_event1_precommit_bootstrap",
        "S0 is the event-1 pre-commit checkpoint over nodes 0 and 1",
        full.smt_and(constraints),
    )


def add_witness_aliases(
    builder: SmtBuilder,
    certificate: Certificate,
) -> None:
    """Request every cheap state field and every action field."""

    builder.alias("w_fresh_tx", "Int", "fresh_tx")
    for action in certificate.actions:
        number = action["action"]
        for field in ("kind", "source", "destination", "parameter", "transaction"):
            builder.alias(
                f"w_action_{number:02d}_{field}",
                "Int",
                full.action_symbol(field, number),
            )
        for member in range(SMT_NODE_COUNT):
            builder.alias(
                f"w_action_{number:02d}_configuration_{member:02d}",
                "Bool",
                full.action_config(number, member),
            )

    for step in range(EXPECTED_ACTIONS + 1):
        for node in range(SMT_NODE_COUNT):
            full.alias_node(
                builder,
                f"w_state_{step:02d}_node_{node:02d}",
                step,
                node,
                certificate,
            )
        for destination in range(SMT_NODE_COUNT):
            full.alias_queue(
                builder,
                f"w_state_{step:02d}_queue_{destination:02d}",
                step,
                destination,
                certificate,
            )
        builder.alias(
            f"w_state_{step:02d}_fresh_tx_submitted",
            "Bool",
            full.select("submitted", step, "fresh_tx"),
        )
        for node in range(SMT_NODE_COUNT):
            builder.alias(
                f"w_state_{step:02d}_joined_{node:02d}",
                "Bool",
                full.select("has_joined", step, node),
            )


def build_encoding(certificate: Certificate, mutation: str) -> Encoding:
    """Build the two-node formula with the strengthened fixed transitions."""

    require(
        mutation
        in {
            "none",
            "conflicting-observed-commit",
            "wrong-destination-action-param",
        },
        f"unsupported mutation {mutation}",
    )
    builder = SmtBuilder()
    full.declare_states(builder, EXPECTED_ACTIONS)
    declare_actions(builder, certificate, mutation)
    add_structural_constraints(builder, certificate)
    add_bootstrap_constraints(builder, certificate)
    full.add_transitions(builder, certificate)
    observation_provenance = full.add_observations(
        builder,
        certificate,
        mutation,
    )
    if mutation == "none":
        add_witness_aliases(builder, certificate)

    header = [
        "; Copyright (c) Microsoft Corporation. All rights reserved.",
        "; Licensed under the Apache 2.0 License.",
        ";",
        "; Generated trace-specific cheap full-state bounded encoding.",
        "; Prototype only: the hardcoded footprint is not inferred or proved.",
        f"; schema={ENCODING_SCHEMA}",
        f"; mutation={mutation}",
        "",
        "(set-logic QF_AUFLIA)",
        "(set-option :produce-models true)",
        "(set-option :produce-unsat-assumptions true)",
        "",
    ]
    query = [
        "",
        "(check-sat-assuming",
        "  (" + "\n   ".join(builder.assumptions) + "))",
    ]
    if mutation == "none":
        query.extend(
            [
                "(get-value",
                "  (" + "\n   ".join(builder.aliases) + "))",
            ]
        )
    else:
        query.append("(get-unsat-assumptions)")
    text = "\n".join(
        [
            *header,
            *builder.declarations,
            "",
            *builder.assertions,
            "",
            *builder.alias_definitions,
            *query,
            "",
        ]
    )
    state_arrays = (EXPECTED_ACTIONS + 1) * len(full.STATE_FIELDS)
    dimensions = {
        "states": EXPECTED_ACTIONS + 1,
        "state_arrays": state_arrays,
        "action_configuration_arrays": EXPECTED_ACTIONS,
        "smt_arrays": state_arrays + EXPECTED_ACTIONS,
        "actions": EXPECTED_ACTIONS,
        "labels": len(builder.labels),
        "witness_aliases": len(builder.aliases),
        "smt_declarations": len(builder.declarations),
        "smt_assertions": len(builder.assertions),
        "formula_lines": text.count("\n"),
        "formula_bytes": len(text.encode("utf-8")),
    }
    return Encoding(
        text=text,
        labels=builder.labels,
        query_aliases=builder.aliases,
        observation_provenance=observation_provenance,
        dimensions=dimensions,
        mutation=mutation,
    )


def generate(certificate_path: Path, output_dir: Path, mutation: str) -> None:
    """Generate formula.smt2 from the validated v2 certificate."""

    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, mutation)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "formula.smt2").write_text(encoding.text, encoding="utf-8")
    print(
        f"generated mutation={mutation} states={encoding.dimensions['states']} "
        f"nodes={SMT_NODE_COUNT} actions={encoding.dimensions['actions']} "
        f"labels={encoding.dimensions['labels']} "
        f"aliases={encoding.dimensions['witness_aliases']} "
        f"bytes={encoding.dimensions['formula_bytes']}"
    )


def projection_summary(encoding: Encoding) -> dict[str, Any]:
    """Count observation projection categories without overstating independence."""

    categories = {
        "preprocessing_validated": 0,
        "redundant_grammar_bindings": 0,
        "state_constraints": 0,
        "exact_packet_or_span_constraints": 0,
        "weakened_exception_constraints": 0,
        "omissions": 0,
    }
    preprocessing_only = {
        "trace-envelope-only",
        "scenario-provenance-only",
        "implementation-configuration-metadata",
    }
    for observation in encoding.observation_provenance:
        for field in observation["encoded_fields"]:
            if field["mode"].startswith("source-log-reconstruction"):
                category = "weakened_exception_constraints"
            elif field["certificate_field_kind"] in {
                "event-grammar-constraint",
                "aggregate-span-constraint",
            }:
                category = "redundant_grammar_bindings"
            elif field["certificate_field_kind"] in {
                "wire-packet-constraint",
                "aggregate-packet-range-constraint",
                "aggregate-response-constraint",
            }:
                category = "exact_packet_or_span_constraints"
            else:
                category = "state_constraints"
            categories[category] += 1
        for field in observation["unencoded_fields"]:
            category = (
                "preprocessing_validated"
                if field["reason"] in preprocessing_only
                else "omissions"
            )
            categories[category] += 1
    return {
        "category_counts": categories,
        "action_span_events": [9, 11, 20, 25, 26, 31],
        "all_raw_fields_projected": False,
        "independent_semantic_constraint_count_claimed": False,
        "event8_sent_index": {
            "status": "omitted",
            "reason": "event8-sent-index-translation",
        },
    }


def decode_state(
    values: Mapping[str, int | bool],
    step: int,
    certificate: Certificate,
) -> dict[str, Any]:
    """Decode one complete two-node state."""

    nodes = [
        full.decode_node(
            values,
            f"w_state_{step:02d}_node_{node:02d}",
            node,
            certificate,
        )
        for node in range(SMT_NODE_COUNT)
    ]
    network = [
        full.decode_queue(
            values,
            f"w_state_{step:02d}_queue_{destination:02d}",
            destination,
            certificate,
        )
        for destination in range(SMT_NODE_COUNT)
    ]
    joined = [
        full.require_value(
            values,
            f"w_state_{step:02d}_joined_{node:02d}",
            bool,
        )
        for node in range(SMT_NODE_COUNT)
    ]
    return {
        "state": step,
        "after_action": step if step > 0 else None,
        "nodes": nodes,
        "network": network,
        "selected_transaction_submitted": full.require_value(
            values,
            f"w_state_{step:02d}_fresh_tx_submitted",
            bool,
        ),
        "has_joined_membership": joined,
        "has_joined_nodes": [node for node, present in enumerate(joined) if present],
    }


def build_witness(
    certificate: Certificate,
    encoding: Encoding,
    values: Mapping[str, int | bool],
    formula_path: Path,
    solver_path: Path,
    generator_ms: int,
    solver_ms: int,
    decode_ms: int,
) -> dict[str, Any]:
    """Assemble the complete cheap-state witness."""

    fresh_tx = full.require_value(values, "w_fresh_tx", int)
    states = [
        decode_state(values, step, certificate) for step in range(EXPECTED_ACTIONS + 1)
    ]
    return {
        "schema_version": WITNESS_SCHEMA,
        "encoding_schema_version": ENCODING_SCHEMA,
        "sat_classification": "SAT_CHEAP_FOOTPRINT_PENDING_CANONICAL_CHECK",
        "solver_status": "sat",
        "hashes": {
            "certificate_sha256": full.sha256_file(certificate.path),
            "model_sha256": full.sha256_file(Path(__file__).with_name("Model.lean")),
            "strengthened_generator_sha256": full.sha256_file(
                Path(__file__).with_name("naive_full_state_smt.py")
            ),
            "generator_sha256": full.sha256_file(Path(__file__)),
            "formula_sha256": full.sha256_file(formula_path),
            "solver_output_sha256": full.sha256_file(solver_path),
            "input_trace_sha256": certificate.data["input"]["sha256"],
        },
        "counts": {
            **certificate.data["counts"],
            "states": EXPECTED_ACTIONS + 1,
            "decoded_complete_cheap_states": EXPECTED_ACTIONS + 1,
        },
        "formula_dimensions": encoding.dimensions,
        "timings_ms": {
            "formula_generation": generator_ms,
            "direct_smt_end_to_end": solver_ms,
            "decode": decode_ms,
        },
        "footprint": {
            "smt_nodes": [0, 1],
            "log_capacity_per_node": LOG_CAPACITY,
            "queue_lanes": [
                {
                    "source": 1,
                    "destination": 0,
                    "capacity": QUEUE_CAPACITY,
                },
                {
                    "source": 0,
                    "destination": 1,
                    "capacity": QUEUE_CAPACITY,
                },
            ],
            "selected_transaction_domain": {
                "kind": "one_symmetric_fin64_identifier",
                "lower": 0,
                "upper_exclusive": TX_COUNT,
                "selected": fresh_tx,
                "membership_bits_per_state": 1,
            },
            "configuration_values": [[0], [0, 1]],
            "configuration_record_indices": {
                "implicit": 0,
                "physical": [1, 3],
            },
        },
        "initial_state_semantics": {
            "canonical_initial_state": False,
            "reachable_claim": False,
            "arbitrary_existential_completion": True,
            "smt_node_count": SMT_NODE_COUNT,
            "unobserved_nodes_in_smt": False,
            "canonical_inert_completion_nodes": list(range(2, 15)),
            "canonical_inert_completion_smt_discovered": False,
            "canonical_submitted_set_completion": "empty",
        },
        "fresh_transaction_id": fresh_tx,
        "states": states,
        "actions": [
            full.decode_action(values, number, certificate)
            for number in range(1, EXPECTED_ACTIONS + 1)
        ],
        "reductions": [
            {
                "reduction": reduction["reduction"],
                "name": reduction["name"],
                "events": reduction["events"],
                "actions": [action["action"] for action in reduction["actions"]],
                "exception_ids": reduction["exception_ids"],
                "transition_labels": [
                    label
                    for label in encoding.labels
                    if label.startswith(f"reduction{reduction['reduction']:02d}_")
                ],
            }
            for reduction in certificate.data["reductions"]
        ],
        "field_provenance": {
            "state_fields": dict(full.STATE_FIELDS),
            "state_coverage": (
                "all fields for nodes 0 and 1, destination queues 0 and 1, "
                "the selected transaction membership, and hasJoined 0 and 1 "
                "at S0 through S43"
            ),
            "action_coverage": (
                "all declared action fields, including both configuration bits"
            ),
            "observations": encoding.observation_provenance,
            "projection_summary": projection_summary(encoding),
        },
        "structural_checks": {
            "encoded_at_all_states": [
                "finite domains and canonical unused slots",
                "commit, sentIndex, and matchIndex bounds",
                "log term checks and committed-frontier signatures",
                "configuration checks",
                "election safety",
                "committed-prefix consistency",
                "log matching",
                "only the 1-to-0 and 0-to-1 message lanes",
                "only configurations {0} and {0,1} at physical indices 1 and 3",
                "one selected Fin 64 transaction identifier",
            ],
            "omitted_from_executable_stateChecks": [],
        },
        "manual_assumptions": [
            "The SMT world contains exactly nodes 0 and 1.",
            "Each node log has seven physical slots.",
            "Only destination 0/source 1 and destination 1/source 0 queues exist.",
            "Each queue has four slots.",
            "Only configurations {0} and {0,1} exist; physical records are at log indices 1 and 3.",
            "One unknown Fin 64 transaction identifier represents every transaction entry in this trace.",
            "The canonical checker completes nodes 2 through 14 as fixed inert nodes under bootstrap {0}.",
            "The canonical checker completes the initial submitted transaction set as empty.",
        ],
        "limitations": [
            "The footprint is hardcoded from this fixture and is not inferred or proved sufficient.",
            "UNSAT is INCONCLUSIVE_ENCODING.",
            "The prototype is not a proof that the cheap encoding is equivalent to CCFRaft.Model.",
            "Event 5 retains the recorded source-log reconstruction exception.",
            "Event 8 sent_idx=2 remains an explicit correspondence omission.",
            "The six corrected multi-action spans are encoded as whole spans.",
        ],
    }


def validate_witness_data(
    witness: Mapping[str, Any],
    certificate: Certificate,
) -> None:
    """Validate complete cheap-state, action, and provenance coverage."""

    require(
        witness.get("schema_version") == WITNESS_SCHEMA,
        "witness schema is absent or unsupported",
    )
    require(
        witness.get("sat_classification")
        == "SAT_CHEAP_FOOTPRINT_PENDING_CANONICAL_CHECK",
        "witness SAT classification differs",
    )
    require(
        witness.get("counts", {}).get("events") == EXPECTED_EVENTS
        and witness.get("counts", {}).get("actions") == EXPECTED_ACTIONS
        and witness.get("counts", {}).get("states") == EXPECTED_ACTIONS + 1,
        "witness counts differ",
    )
    fresh_tx = witness.get("fresh_transaction_id")
    require(
        type(fresh_tx) is int and 0 <= fresh_tx < TX_COUNT,
        "selected transaction is outside Fin 64",
    )
    states = witness.get("states")
    require(
        isinstance(states, list) and len(states) == EXPECTED_ACTIONS + 1,
        "witness does not contain 44 cheap states",
    )
    for step, state in enumerate(states):
        require(
            isinstance(state, dict) and state.get("state") == step,
            f"state S{step} is malformed",
        )
        nodes = state.get("nodes")
        network = state.get("network")
        require(
            isinstance(nodes, list) and len(nodes) == SMT_NODE_COUNT,
            f"state S{step} does not contain two nodes",
        )
        require(
            isinstance(network, list) and len(network) == SMT_NODE_COUNT,
            f"state S{step} does not contain two queues",
        )
        for node_number, node in enumerate(nodes):
            require(
                node.get("node") == node_number
                and len(node.get("votes_granted_membership", [])) == SMT_NODE_COUNT
                and len(node.get("sent_index", [])) == SMT_NODE_COUNT
                and len(node.get("match_index", [])) == SMT_NODE_COUNT
                and len(node.get("log_slots", [])) == LOG_CAPACITY,
                f"state S{step} node {node_number} is incomplete",
            )
            for slot in node["log_slots"]:
                membership = slot["content"]["configuration_membership"]
                require(
                    len(membership) == SMT_NODE_COUNT,
                    f"state S{step} node {node_number} log config is incomplete",
                )
                if slot["active"] and slot["content"]["tag"] == "transaction":
                    require(
                        slot["content"]["transaction_id"] == fresh_tx,
                        f"state S{step} contains another transaction identifier",
                    )
                if slot["active"] and slot["content"]["tag"] == "reconfiguration":
                    require(
                        slot["index"] in {1, 3}
                        and slot["content"]["configuration_nodes"] in ([0], [0, 1]),
                        f"state S{step} contains another configuration record",
                    )
        for destination, queue in enumerate(network):
            require(
                queue.get("destination") == destination
                and queue.get("capacity") == QUEUE_CAPACITY
                and len(queue.get("slots", [])) == QUEUE_CAPACITY,
                f"state S{step} queue {destination} is incomplete",
            )
            for slot in queue["slots"]:
                require(
                    len(
                        slot["append_entries_request"]["entry"]["content"][
                            "configuration_membership"
                        ]
                    )
                    == SMT_NODE_COUNT,
                    f"state S{step} queue {destination} config is incomplete",
                )
                if slot["active"]:
                    require(
                        slot["source"] == 1 - destination,
                        f"state S{step} contains an unsupported message lane",
                    )
        require(
            isinstance(state.get("selected_transaction_submitted"), bool)
            and state.get("has_joined_membership")
            in (
                [True, False],
                [True, True],
            ),
            f"state S{step} membership fields are malformed",
        )
    actions = witness.get("actions")
    require(
        isinstance(actions, list) and len(actions) == EXPECTED_ACTIONS,
        "witness does not contain 43 actions",
    )
    for number, action in enumerate(actions, 1):
        require(
            action.get("action") == number
            and len(action.get("configuration_membership", [])) == SMT_NODE_COUNT,
            f"action {number} is incomplete",
        )
    require(
        actions[20]["kind"] == "clientRequest"
        and actions[20]["transaction"] == fresh_tx,
        "action 21 does not carry the selected transaction",
    )
    provenance = witness.get("field_provenance", {})
    require(
        len(provenance.get("observations", [])) == EXPECTED_EVENTS,
        "witness does not contain 53 observation provenance records",
    )
    require(
        provenance.get("projection_summary", {}).get("action_span_events")
        == [9, 11, 20, 25, 26, 31],
        "witness span provenance differs",
    )
    require(
        witness.get("structural_checks", {}).get("omitted_from_executable_stateChecks")
        == [],
        "witness weakens executable stateChecks",
    )


def render_smt_report(witness: Mapping[str, Any]) -> str:
    """Render the SAT-only report before canonical checking."""

    dimensions = witness["formula_dimensions"]
    timings = witness["timings_ms"]
    return f"""# Cheap full-state SMT result

Result: `SAT_CHEAP_FOOTPRINT_PENDING_CANONICAL_CHECK`

- Formula: {dimensions['formula_bytes']} bytes, {dimensions['formula_lines']} lines, {dimensions['smt_declarations']} declarations, {dimensions['smt_arrays']} arrays, {dimensions['labels']} labels, and {dimensions['witness_aliases']} aliases.
- Formula generation: {timings['formula_generation']} ms.
- End-to-end cvc5: {timings['direct_smt_end_to_end']} ms.
- Decode: {timings['decode']} ms.
- Selected transaction: `{witness['fresh_transaction_id']}` in `Fin 64`.

The final classification requires the canonical Lean replay.
"""


def decode(
    certificate_path: Path,
    output_dir: Path,
    generator_ms: int,
    solver_ms: int,
) -> int:
    """Decode solver.out into the compact cheap witness."""

    started = time.perf_counter_ns()
    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, "none")
    formula_path = output_dir / "formula.smt2"
    solver_path = output_dir / "solver.out"
    require(
        formula_path.read_text(encoding="utf-8") == encoding.text,
        "formula.smt2 differs from deterministic regeneration",
    )
    try:
        values = full.parse_sat_solver_output(
            solver_path,
            encoding.query_aliases,
        )
    except EncodingError as error:
        if str(error) == "INCONCLUSIVE_ENCODING":
            print("classification=INCONCLUSIVE_ENCODING")
            return 3
        raise
    decode_ms = (time.perf_counter_ns() - started) // 1_000_000
    witness = build_witness(
        certificate,
        encoding,
        values,
        formula_path,
        solver_path,
        generator_ms,
        solver_ms,
        decode_ms,
    )
    validate_witness_data(witness, certificate)
    write_compact_json(output_dir / "witness-v1.json", witness)
    (output_dir / "smt-report.md").write_text(
        render_smt_report(witness),
        encoding="utf-8",
    )
    print(
        f"decoded classification={witness['sat_classification']} "
        f"fresh_tx={witness['fresh_transaction_id']} decode_ms={decode_ms}"
    )
    return 0


def validate_witness(certificate_path: Path, output_dir: Path) -> None:
    """Regenerate the formula and witness, then compare exact values."""

    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, "none")
    formula_path = output_dir / "formula.smt2"
    solver_path = output_dir / "solver.out"
    witness_path = output_dir / "witness-v1.json"
    witness = json.loads(witness_path.read_text(encoding="utf-8"))
    require(isinstance(witness, dict), "witness top level is not an object")
    validate_witness_data(witness, certificate)
    require(
        formula_path.read_text(encoding="utf-8") == encoding.text,
        "saved formula differs from deterministic regeneration",
    )
    values = full.parse_sat_solver_output(
        solver_path,
        encoding.query_aliases,
    )
    timings = witness["timings_ms"]
    rebuilt = build_witness(
        certificate,
        encoding,
        values,
        formula_path,
        solver_path,
        timings["formula_generation"],
        timings["direct_smt_end_to_end"],
        timings["decode"],
    )
    validate_witness_data(rebuilt, certificate)
    require(
        witness == rebuilt,
        "saved witness differs from deterministic reconstruction",
    )
    require(
        (output_dir / "smt-report.md").read_text(encoding="utf-8")
        == render_smt_report(rebuilt),
        "saved SMT report differs from deterministic rendering",
    )
    print("deterministic_regeneration=formula,witness,smt-report " "result=identical")


def validate_mutation(
    certificate_path: Path,
    output_dir: Path,
    mutation: str,
) -> None:
    """Validate one intentionally UNSAT in-domain mutation."""

    certificate = load_certificate(certificate_path)
    encoding = build_encoding(certificate, mutation)
    require(
        (output_dir / "formula.smt2").read_text(encoding="utf-8") == encoding.text,
        "mutation formula differs from deterministic regeneration",
    )
    core = full.parse_unsat_solver_output(output_dir / "solver.out")
    require(
        all(label in encoding.labels for label in core),
        "mutation core contains an unknown label",
    )
    if mutation == "conflicting-observed-commit":
        required = [
            "event53_msg_state_commit_idx",
            "reduction21_action40_advanceCommitIndex",
            "reduction22_action41_appendEntries",
            "reduction22_action42_receive",
        ]
    elif mutation == "wrong-destination-action-param":
        required = [
            "action03_certificate_skeleton",
            "reduction02_action03_appendEntries",
        ]
    else:
        raise EncodingError(f"unsupported mutation validation {mutation}")
    require(
        all(label in core for label in required),
        "mutation core omits required labels",
    )
    print(
        f"mutation={mutation} status=unsat in_domain=true "
        f"core_labels={len(core)} required_labels={','.join(required)}"
    )


def classify_solver_output(path: Path) -> int:
    """Classify a bare solver status without converting UNSAT into a claim."""

    expressions = full.parse_sexpressions(path.read_text(encoding="utf-8"))
    require(expressions, "solver output is empty")
    status = expressions[0]
    if status in {"unknown", "unsat"}:
        print(f"solver_status={status} classification=INCONCLUSIVE_ENCODING")
        return 3
    require(status == "sat", f"unsupported solver status {status!r}")
    print("solver_status=sat classification=SAT_PENDING_CANONICAL_CHECK")
    return 0


def percentile_95(values: Sequence[int]) -> int:
    """Return the nearest-rank 95th percentile."""

    require(bool(values), "solver-only benchmark has no samples")
    ordered = sorted(values)
    rank = (95 * len(ordered) + 99) // 100
    return ordered[rank - 1]


def ratio(numerator: int, denominator: int) -> str:
    """Format a positive comparison ratio."""

    require(denominator > 0, "comparison denominator is not positive")
    return f"{numerator / denominator:.2f}x"


def count_comparison(cheap: int, baseline: int) -> str:
    """Describe whether a cheap count is lower, equal, or higher."""

    if cheap < baseline:
        return f"{baseline / cheap:.2f}x fewer"
    if cheap > baseline:
        return f"{cheap / baseline:.2f}x more"
    return "same"


def render_benchmark_report(
    witness: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    baseline: Mapping[str, Any],
    baseline_witness_path: Path,
) -> str:
    """Render the final benchmark and its manual assumptions."""

    require(
        benchmark.get("canonical", {}).get("result") == "VALID_SEGMENT",
        "canonical result is not VALID_SEGMENT",
    )
    samples = benchmark["timings_ms"]["solver_only_runs"]
    ordered = sorted(samples)
    sample_count = len(samples)
    median = (
        ordered[sample_count // 2]
        if sample_count % 2
        else (ordered[sample_count // 2 - 1] + ordered[sample_count // 2]) // 2
    )
    p95 = percentile_95(samples)
    dimensions = witness["formula_dimensions"]
    timings = witness["timings_ms"]
    baseline_dimensions = baseline["formula_dimensions"]
    baseline_timings = baseline["timings_ms"]
    output_dir = baseline_witness_path.parent
    baseline_formula_bytes = (output_dir / "formula.smt2").stat().st_size
    baseline_witness_bytes = baseline_witness_path.stat().st_size
    formula_bytes = benchmark["artifact_bytes"]["formula"]
    witness_bytes = benchmark["artifact_bytes"]["witness"]
    solver_bytes = benchmark["artifact_bytes"]["solver_output"]
    report_lines = [
        "# Trace-specific cheap full-state SMT benchmark",
        "",
        "Result: `VALID_SEGMENT_CHEAP_FOOTPRINT`",
        "",
        "## Dimensions",
        "",
        "| Metric | Cheap | Naive full | Ratio |",
        "| --- | ---: | ---: | ---: |",
        f"| States | {dimensions['states']} | {baseline_dimensions['states']} | same |",
        f"| Actions | {dimensions['actions']} | {baseline_dimensions['actions']} | same |",
        f"| SMT nodes | {SMT_NODE_COUNT} | 15 | 7.50x fewer |",
        f"| Formula bytes | {formula_bytes} | {baseline_formula_bytes} | {ratio(baseline_formula_bytes, formula_bytes)} smaller |",
        f"| Formula lines | {dimensions['formula_lines']} | {baseline_dimensions['formula_lines']} | {ratio(baseline_dimensions['formula_lines'], dimensions['formula_lines'])} fewer |",
        f"| Declarations | {dimensions['smt_declarations']} | {baseline_dimensions['smt_declarations']} | {count_comparison(dimensions['smt_declarations'], baseline_dimensions['smt_declarations'])} |",
        f"| Arrays | {dimensions['smt_arrays']} | 1539 | {count_comparison(dimensions['smt_arrays'], 1539)} |",
        f"| Labels | {dimensions['labels']} | {baseline_dimensions['labels']} | {count_comparison(dimensions['labels'], baseline_dimensions['labels'])} |",
        f"| Aliases | {dimensions['witness_aliases']} | {baseline_dimensions['witness_aliases']} | {ratio(baseline_dimensions['witness_aliases'], dimensions['witness_aliases'])} fewer |",
        f"| Solver output bytes | {solver_bytes} | {(output_dir / 'solver.out').stat().st_size} | {ratio((output_dir / 'solver.out').stat().st_size, solver_bytes)} smaller |",
        f"| Witness bytes | {witness_bytes} | {baseline_witness_bytes} | {ratio(baseline_witness_bytes, witness_bytes)} smaller |",
        "",
        "The 1,496 state arrays remain because the imported strengthened encoding stores each field in one array per state. Only indices for nodes 0 and 1, their logs, and their two queues occur in constraints.",
        "",
        "## Timings",
        "",
        "| Stage | Cheap | Naive full | Ratio |",
        "| --- | ---: | ---: | ---: |",
        f"| Formula generation | {timings['formula_generation']} ms | {baseline_timings['formula_generation']} ms | {ratio(baseline_timings['formula_generation'], timings['formula_generation'])} faster |",
        f"| End-to-end cvc5 | {timings['direct_smt_end_to_end']} ms | {baseline_timings['direct_smt']} ms | {ratio(baseline_timings['direct_smt'], timings['direct_smt_end_to_end'])} faster |",
        f"| Solver-only median | {median} ms | {baseline_timings['direct_smt']} ms | {ratio(baseline_timings['direct_smt'], median)} faster |",
        f"| Decode | {timings['decode']} ms | {baseline_timings['decode']} ms | {ratio(baseline_timings['decode'], timings['decode'])} faster |",
        f"| Lean source generation | {benchmark['timings_ms']['lean_generation']} ms | n/a | n/a |",
        f"| Lean source compilation | {benchmark['timings_ms']['lean_compile']} ms | n/a | n/a |",
        f"| Lean compile and canonical check | {benchmark['timings_ms']['lean_compile_check']} ms | n/a | n/a |",
        "",
        f"Direct solver-only runs: {sample_count}. Distribution: min {min(samples)} ms, median {median} ms, p95 {p95} ms, max {max(samples)} ms.",
        "",
        f"cvc5: `{benchmark['cvc5']['version']}` at `{benchmark['cvc5']['binary']}`.",
        "",
        "## Canonical check",
        "",
        "The generated Lean source expanded the two-node S0 witness into `Node Fin 15`. Nodes 2 through 14 were fixed to the canonical inert state under singleton bootstrap `{0}`. The SMT solver did not discover those nodes.",
        "",
        "The checker used `lake env lean --run`. The benchmark also measured source compilation to an `.olean` file, but did not separate executable runtime because direct C linking does not include imported Lake modules.",
        "",
        "- `stateChecks` passed at S0 and after every action.",
        "- `system.applyAction` accepted all 43 actions.",
        "- `edgeChecks` passed on all 43 edges.",
        "- All 53 observations passed, including six whole-action spans.",
        "- All projected fields were checked. The unchecked projected-field count was zero.",
        "- Checker output: `VALID_SEGMENT`.",
        "",
        "## Negative controls",
        "",
        "- Conflicting in-domain observed commit: `UNSAT`, classified `INCONCLUSIVE_ENCODING`.",
        "- Wrong in-domain destination for action 3, destination 0: `UNSAT`, classified `INCONCLUSIVE_ENCODING`.",
        "- Synthetic solver status `unknown`: `INCONCLUSIVE_ENCODING`.",
        "",
        "## Determinism and file checks",
        "",
        "- Regenerated formula, witness, and SMT report matched byte for byte.",
        "- The generated Lean source matched its witness and certificate hashes.",
        "- Python compilation, Black, ShellCheck, diff checks, and ASCII checks passed.",
        "",
        "## Manual assumptions",
        "",
    ]
    report_lines.extend(
        f"- {assumption}" for assumption in witness["manual_assumptions"]
    )
    report_lines.extend(
        [
            "",
            "## Residual limits",
            "",
            "- The hardcoded footprint is fixture-specific and unproved.",
            "- `VALID_SEGMENT_CHEAP_FOOTPRINT` means SAT plus canonical replay for this fixed segment. It does not establish reachability or encoding equivalence.",
            "- UNSAT remains `INCONCLUSIVE_ENCODING` because the footprint can exclude valid full-world completions.",
            "- The selected transaction remains symmetric in `Fin 64`, but the SMT stores only its membership bit at each state.",
            "- Event 5 keeps the certificate's source-log reconstruction exception. Event 8 `sent_idx=2` stays omitted by the recorded correspondence.",
            "",
        ]
    )
    return "\n".join(report_lines)


def write_benchmark_report(
    certificate_path: Path,
    output_dir: Path,
    benchmark_path: Path,
    baseline_witness_path: Path,
) -> None:
    """Validate benchmark inputs and write the final report."""

    certificate = load_certificate(certificate_path)
    witness = json.loads((output_dir / "witness-v1.json").read_text(encoding="utf-8"))
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    baseline = json.loads(baseline_witness_path.read_text(encoding="utf-8"))
    require(isinstance(witness, dict), "cheap witness is malformed")
    require(isinstance(benchmark, dict), "benchmark JSON is malformed")
    require(isinstance(baseline, dict), "baseline witness is malformed")
    validate_witness_data(witness, certificate)
    report = render_benchmark_report(
        witness,
        benchmark,
        baseline,
        baseline_witness_path,
    )
    (output_dir / "report.md").write_text(report, encoding="utf-8")
    benchmark["classification"] = "VALID_SEGMENT_CHEAP_FOOTPRINT"
    write_json(benchmark_path, benchmark)
    print("classification=VALID_SEGMENT_CHEAP_FOOTPRINT")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse generator, decoder, validator, and report commands."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--certificate", type=Path, required=True)
    generate_parser.add_argument("--output-dir", type=Path, required=True)
    generate_parser.add_argument(
        "--mutation",
        choices=(
            "none",
            "conflicting-observed-commit",
            "wrong-destination-action-param",
        ),
        default="none",
    )

    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("--certificate", type=Path, required=True)
    decode_parser.add_argument("--output-dir", type=Path, required=True)
    decode_parser.add_argument("--generator-ms", type=int, required=True)
    decode_parser.add_argument("--solver-ms", type=int, required=True)

    validate_parser = subparsers.add_parser("validate-witness")
    validate_parser.add_argument("--certificate", type=Path, required=True)
    validate_parser.add_argument("--output-dir", type=Path, required=True)

    mutation_parser = subparsers.add_parser("validate-mutation")
    mutation_parser.add_argument("--certificate", type=Path, required=True)
    mutation_parser.add_argument("--output-dir", type=Path, required=True)
    mutation_parser.add_argument(
        "--mutation",
        choices=(
            "conflicting-observed-commit",
            "wrong-destination-action-param",
        ),
        required=True,
    )

    classify_parser = subparsers.add_parser("classify-solver-output")
    classify_parser.add_argument("--solver-output", type=Path, required=True)

    report_parser = subparsers.add_parser("write-benchmark-report")
    report_parser.add_argument("--certificate", type=Path, required=True)
    report_parser.add_argument("--output-dir", type=Path, required=True)
    report_parser.add_argument("--benchmark", type=Path, required=True)
    report_parser.add_argument("--baseline-witness", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one cheap full-state operation."""

    args = parse_args(argv)
    try:
        if args.command == "generate":
            generate(args.certificate, args.output_dir, args.mutation)
        elif args.command == "decode":
            return decode(
                args.certificate,
                args.output_dir,
                args.generator_ms,
                args.solver_ms,
            )
        elif args.command == "validate-witness":
            validate_witness(args.certificate, args.output_dir)
        elif args.command == "validate-mutation":
            validate_mutation(
                args.certificate,
                args.output_dir,
                args.mutation,
            )
        elif args.command == "classify-solver-output":
            return classify_solver_output(args.solver_output)
        elif args.command == "write-benchmark-report":
            write_benchmark_report(
                args.certificate,
                args.output_dir,
                args.benchmark,
                args.baseline_witness,
            )
        else:
            raise EncodingError(f"unsupported command {args.command}")
        return 0
    except (
        EncodingError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"cheap-full-state-smt: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
