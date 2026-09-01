#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate a canonical Lean checker for the cheap full-state witness."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import cheap_full_state_smt as cheap
import naive_full_state_lean as base
import naive_full_state_smt as full

CHECKER_SCHEMA = "ccfraft-cheap-full-state-canonical-check/v1"
SOURCE_NAME = "CanonicalCheapFullStateWitness.lean"


def require(condition: bool, message: str) -> None:
    """Raise a labelled generation error when a requirement is false."""

    base.require(condition, message)


def load_inputs(
    witness_path: Path,
    certificate_path: Path,
) -> tuple[dict[str, Any], cheap.Certificate, full.Certificate]:
    """Load the compact witness and both certificate views."""

    cheap_certificate = cheap.load_certificate(certificate_path)
    full_certificate = full.load_certificate(certificate_path)
    witness = json.loads(witness_path.read_text(encoding="utf-8"))
    require(isinstance(witness, dict), "witness top level is not an object")
    cheap.validate_witness_data(witness, cheap_certificate)
    require(
        witness["hashes"]["certificate_sha256"] == base.sha256_file(certificate_path),
        "witness certificate hash differs",
    )
    require(
        witness["hashes"]["input_trace_sha256"]
        == full_certificate.data["input"]["sha256"],
        "witness trace hash differs",
    )
    return witness, cheap_certificate, full_certificate


def expand_membership(values: Sequence[bool]) -> list[bool]:
    """Expand two cheap membership bits to the canonical Fin 15 world."""

    require(len(values) == cheap.SMT_NODE_COUNT, "cheap membership width differs")
    return list(values) + [False] * (15 - cheap.SMT_NODE_COUNT)


def expand_content(content: Mapping[str, Any]) -> dict[str, Any]:
    """Expand one entry-content membership field."""

    expanded = copy.deepcopy(dict(content))
    membership = expand_membership(content["configuration_membership"])
    expanded["configuration_membership"] = membership
    expanded["configuration_nodes"] = [
        node for node, present in enumerate(membership) if present
    ]
    return expanded


def expand_node(node: Mapping[str, Any]) -> dict[str, Any]:
    """Expand a cheap node's peer tables and entry memberships."""

    expanded = copy.deepcopy(dict(node))
    expanded["votes_granted_membership"] = expand_membership(
        node["votes_granted_membership"]
    )
    expanded["votes_granted_nodes"] = [
        peer
        for peer, granted in enumerate(expanded["votes_granted_membership"])
        if granted
    ]
    expanded["sent_index"] = list(node["sent_index"]) + [0] * 13
    expanded["match_index"] = list(node["match_index"]) + [0] * 13
    expanded["log_slots"] = [
        {**copy.deepcopy(slot), "content": expand_content(slot["content"])}
        for slot in node["log_slots"]
    ]
    return expanded


def expand_queue(queue: Mapping[str, Any]) -> dict[str, Any]:
    """Expand queued entry memberships to Fin 15."""

    expanded = copy.deepcopy(dict(queue))
    for slot in expanded["slots"]:
        entry = slot["append_entries_request"]["entry"]
        entry["content"] = expand_content(entry["content"])
    return expanded


def expand_action(action: Mapping[str, Any]) -> dict[str, Any]:
    """Expand an action configuration to Fin 15."""

    expanded = copy.deepcopy(dict(action))
    membership = expand_membership(action["configuration_membership"])
    expanded["configuration_membership"] = membership
    expanded["configuration_nodes"] = [
        node for node, present in enumerate(membership) if present
    ]
    return expanded


def generated_source(
    witness: Mapping[str, Any],
    full_certificate: full.Certificate,
    witness_path: Path,
    certificate_path: Path,
) -> tuple[str, dict[str, Any]]:
    """Build generated Lean source with an explicit inert-node completion."""

    initial_cheap = witness["states"][0]
    observed_nodes = [expand_node(node) for node in initial_cheap["nodes"]]
    observed_queues = [expand_queue(queue) for queue in initial_cheap["network"]]
    actions = [expand_action(action) for action in witness["actions"]]
    fresh_tx = witness["fresh_transaction_id"]

    initial_for_validation = {
        "state": 0,
        "synthetic_checkpoint": "event 1 pre-commit",
        "nodes": [
            *observed_nodes,
            *[
                {
                    "node": node,
                    "role": "none",
                    "role_value": full.ROLE_NONE,
                    "current_term": 0,
                    "log_length": 0,
                    "commit_index": 0,
                    "is_new_follower": True,
                    "voted_for": {
                        "has_value": False,
                        "value": 0,
                        "node": None,
                    },
                    "votes_granted_membership": [False] * 15,
                    "votes_granted_nodes": [],
                    "sent_index": [0] * 15,
                    "match_index": [0] * 15,
                    "log_capacity": 7,
                    "log_slots": [
                        {
                            "index": index,
                            "active": False,
                            "term": 0,
                            "content": {
                                "tag": "unused",
                                "tag_value": full.ENTRY_UNUSED,
                                "transaction_id": 0,
                                "configuration_membership": [False] * 15,
                                "configuration_nodes": [],
                            },
                        }
                        for index in range(1, 8)
                    ],
                }
                for node in range(2, 15)
            ],
        ],
        "network": [
            *observed_queues,
            *[
                {
                    "destination": destination,
                    "length": 0,
                    "capacity": 4,
                    "slots": [
                        {
                            "slot": slot,
                            "active": False,
                            "tag": "unused",
                            "tag_value": full.MESSAGE_UNUSED,
                            "source": 0,
                            "destination": 0,
                            "term": 0,
                            "append_entries_request": {
                                "prev_log_index": 0,
                                "prev_log_term": 0,
                                "leader_commit": 0,
                                "entry_present": False,
                                "entry": {
                                    "term": 0,
                                    "content": {
                                        "tag": "unused",
                                        "tag_value": full.ENTRY_UNUSED,
                                        "transaction_id": 0,
                                        "configuration_membership": [False] * 15,
                                        "configuration_nodes": [],
                                    },
                                },
                            },
                            "append_entries_response": {
                                "success": False,
                                "last_log_index": 0,
                            },
                            "request_vote_request": {
                                "last_committable_term": 0,
                                "last_committable_index": 0,
                            },
                            "request_vote_response": {
                                "vote_granted": False,
                            },
                        }
                        for slot in range(4)
                    ],
                }
                for destination in range(2, 15)
            ],
        ],
        "submitted_transaction_membership": [False] * 64,
        "submitted_transaction_ids": [],
        "has_joined_membership": [True, False] + [False] * 13,
        "has_joined_nodes": [0],
    }
    base.validate_initial_state(initial_for_validation, full_certificate)
    base.validate_actions(actions, full_certificate, fresh_tx)

    observations, projected_count, omitted_count, omissions = (
        base.observation_check_source(full_certificate)
    )
    action_checks = base.expected_action_source(full_certificate, actions)
    witness_hash = base.sha256_file(witness_path)
    certificate_hash = base.sha256_file(certificate_path)
    node_literals = ",\n".join(base.raw_node_literal(node) for node in observed_nodes)
    queue_literals = ",\n".join(
        base.raw_queue_literal(queue) for queue in observed_queues
    )
    action_literals = ",\n".join(base.raw_action_literal(action) for action in actions)
    inert_nodes = ",\n".join(f"    rawInertNode {node}" for node in range(2, 15))
    inert_queues = ",\n".join(f"    rawInertQueue {node}" for node in range(2, 15))
    source = f"""-- Generated by CCFRaft/cheap_full_state_lean.py. Do not edit.
-- witness_sha256={witness_hash}
-- certificate_sha256={certificate_hash}

import CCFRaft.NaiveFullStateWitness

set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 100000
set_option linter.unusedVariables false

namespace CCFRaft.GeneratedCheapFullStateWitness

open CCFRaft.NaiveFullStateWitness
open CCFRaft.Simulation

def inputWitnessSHA256 : String := {base.lean_string(witness_hash)}
def inputCertificateSHA256 : String := {base.lean_string(certificate_hash)}
def checkerSchema : String := {base.lean_string(CHECKER_SCHEMA)}

def singletonBootstrap : Bootstrap Node where
  configuration := {{Fin.mk 0 (by decide)}}
  leader := Fin.mk 0 (by decide)
  leader_mem := by decide

local instance : Bootstrap Node := singletonBootstrap

def rawUnusedEntrySlot (index : Nat) : RawEntrySlot where
  index := index
  active := false
  term := 0
  tag := "unused"
  tagValue := 0
  transactionId := 0
  configurationMembership := List.replicate NODE_COUNT false

def rawInertNode (node : Nat) : RawNode where
  node := node
  role := "none"
  roleValue := 0
  currentTerm := 0
  logLength := 0
  commitIndex := 0
  isNewFollower := true
  votedForHasValue := false
  votedForValue := 0
  votesGrantedMembership := List.replicate NODE_COUNT false
  sentIndex := List.replicate NODE_COUNT 0
  matchIndex := List.replicate NODE_COUNT 0
  logCapacity := LOG_CAPACITY
  logSlots := (List.range LOG_CAPACITY).map fun offset =>
    rawUnusedEntrySlot (offset + 1)

def rawUnusedQueueSlot (slot : Nat) : RawQueueSlot where
  slot := slot
  active := false
  tag := "unused"
  tagValue := 0
  source := 0
  destination := 0
  term := 0
  prevLogIndex := 0
  prevLogTerm := 0
  leaderCommit := 0
  entryPresent := false
  entryTerm := 0
  entryTag := "unused"
  entryTagValue := 0
  entryTransactionId := 0
  entryConfigurationMembership := List.replicate NODE_COUNT false
  responseSuccess := false
  responseLastLogIndex := 0
  voteLastCommittableTerm := 0
  voteLastCommittableIndex := 0
  voteGranted := false

def rawInertQueue (destination : Nat) : RawQueue where
  destination := destination
  length := 0
  capacity := QUEUE_CAPACITY
  slots := (List.range QUEUE_CAPACITY).map rawUnusedQueueSlot

def rawInitialState : RawInitialState where
  nodes := [
{node_literals},
{inert_nodes}
  ]
  network := [
{queue_literals},
{inert_queues}
  ]
  submittedTransactionMembership := List.replicate TX_COUNT false
  hasJoinedMembership :=
    {base.lean_list(initial_for_validation['has_joined_membership'], base.lean_bool)}

def rawActions : List RawAction := [
{action_literals}
]

def freshTransactionIdValue : Nat := {fresh_tx}
def projectedFieldCount : Nat := {projected_count}
def explicitlyOmittedFieldCount : Nat := {omitted_count}
def observationCount : Nat := {full.EXPECTED_EVENTS}
def checkpointObservationCount : Nat := 47
def spanObservationCount : Nat := 6
def inertCompletionCount : Nat := 13

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
  expectTrue "final.nodes[0/1].log"
    (decide ((final.nodes node0).log = (final.nodes node1).log))
  for node in allNodes do
    expectEq s!"final.network[{{node.val}}].length" (final.network node).length 0
  expectTrue "S0.submittedTxIds.fresh"
    (decide (Not (Membership.mem initial.submittedTxIds fresh)))
  expectTrue "final.submittedTxIds.fresh"
    (decide (Membership.mem final.submittedTxIds fresh))
  expectTrue "final.nodes[0].log.fresh" (containsTransaction final node0 fresh)
  expectTrue "final.nodes[1].log.fresh" (containsTransaction final node1 fresh)
  let action21 <- actionAt actions 21 "action 21 transaction"
  expectTrue "action 21 transaction"
    (decide (action21 = .clientRequest node0 fresh))

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
        s!"completion smt_nodes=2 inert_nodes={{inertCompletionCount}} inert_smt_discovered=false bootstrap=singleton-0"
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

end CCFRaft.GeneratedCheapFullStateWitness

def main : IO UInt32 :=
  CCFRaft.GeneratedCheapFullStateWitness.run
"""
    report = {
        "schema_version": CHECKER_SCHEMA,
        "witness_sha256": witness_hash,
        "certificate_sha256": certificate_hash,
        "counts": {
            "actions": full.EXPECTED_ACTIONS,
            "events": full.EXPECTED_EVENTS,
            "checkpoint_observations": 47,
            "span_observations": 6,
            "projected_fields": projected_count,
            "explicit_omissions": omitted_count,
            "projected_unchecked": 0,
        },
        "span_events": [9, 11, 20, 25, 26, 31],
        "initial_state_semantics": witness["initial_state_semantics"],
        "canonical_completion": {
            "bootstrap": [0],
            "inert_nodes": list(range(2, 15)),
            "smt_discovered": False,
            "submitted_transaction_set": [],
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
    """Generate the canonical source and its completion report."""

    witness, _, full_certificate = load_inputs(witness_path, certificate_path)
    source, report = generated_source(
        witness,
        full_certificate,
        witness_path,
        certificate_path,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / SOURCE_NAME
    source_path.write_text(source, encoding="utf-8")
    base.write_json(output_dir / "canonical-check-report-v1.json", report)
    print(
        f"generated source={source_path} "
        f"projected={report['counts']['projected_fields']} "
        f"omitted={report['counts']['explicit_omissions']} "
        "projected_unchecked=0 inert_completion=13"
    )


def verify_source(
    witness_path: Path,
    certificate_path: Path,
    source_path: Path,
) -> None:
    """Verify that generated source is bound to its current inputs."""

    text = source_path.read_text(encoding="utf-8")
    for name, digest in (
        ("witness_sha256", base.sha256_file(witness_path)),
        ("certificate_sha256", base.sha256_file(certificate_path)),
    ):
        require(
            f"-- {name}={digest}\n" in text,
            f"generated source {name} marker differs",
        )
    print("verified generated source hashes")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse generator commands."""

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
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one cheap canonical-checker generation operation."""

    args = parse_args(argv)
    try:
        if args.command == "generate":
            generate(args.witness, args.certificate, args.output_dir)
        elif args.command == "verify-source":
            verify_source(args.witness, args.certificate, args.source)
        else:
            raise base.CheckGenerationError(f"unsupported command {args.command}")
        return 0
    except (
        base.CheckGenerationError,
        cheap.EncodingError,
        json.JSONDecodeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        print(f"ENCODING_BUG {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
