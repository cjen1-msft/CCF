-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayMembershipFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

inductive Mutation where
  | unchanged
  | sourceTerm
  | peerTerm
  | peerRole
  | peerLog
  | peerCommit
  | peerVote
  | peerCursor
  | peerRetirement
  | hasJoined
  | completed
  | queue
  deriving DecidableEq, Repr

def mutate (state : State (Fin 3) Nat) (mutation : Mutation) : State (Fin 3) Nat :=
  let peer := state.nodes 2
  match mutation with
  | .unchanged => state
  | .sourceTerm =>
    { state with
      nodes := updateNode state.nodes 0
        { (state.nodes 0) with currentTerm := (state.nodes 0).currentTerm + 1 } }
  | .peerTerm =>
    { state with nodes := updateNode state.nodes 2 { peer with currentTerm := peer.currentTerm + 1 } }
  | .peerRole =>
    { state with
      nodes := updateNode state.nodes 2
        { peer with role := if peer.role = .leader then .follower else .leader } }
  | .peerLog =>
    { state with
      nodes := updateNode state.nodes 2
        { peer with log := peer.log ++ [{ term := 1, content := .signature }] } }
  | .peerCommit =>
    { state with nodes := updateNode state.nodes 2 { peer with commitIndex := peer.commitIndex + 1 } }
  | .peerVote =>
    { state with
      nodes := updateNode state.nodes 2
        { peer with votedFor := if peer.votedFor.isSome then none else some 0 } }
  | .peerCursor =>
    { state with
      nodes := updateNode state.nodes 2
        { peer with sentIndex := updateIndex peer.sentIndex 1 (peer.sentIndex 1 + 1) } }
  | .peerRetirement =>
    { state with
      nodes := updateNode state.nodes 2
        { peer with retirementIndex := some (peer.retirementIndex.getD 0 + 1) } }
  | .hasJoined =>
    { state with hasJoined := if 2 ∈ state.hasJoined then state.hasJoined.erase 2 else insert 2 state.hasJoined }
  | .completed =>
    { state with
      retirementCompleted := Function.update state.retirementCompleted 0
        (if 2 ∈ state.retirementCompleted 0 then (state.retirementCompleted 0).erase 2
          else insert 2 (state.retirementCompleted 0)) }
  | .queue =>
    { state with
      network := enqueue state.network (.proposeVoteRequest { term := 99, source := 2, destination := 1 }) }

def fixture (log : List (Entry (Fin 3) Nat)) (commit : Nat)
    (configuration present joined : Finset (Fin 3)) (role : Role)
    (membership : MembershipState) (mutation : Mutation) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role, membershipState := membership, currentTerm := 10 ^ 30, log, commitIndex := commit,
      votedFor := some 1, votesGranted := {0, 2}, preVotesGranted := {1},
      retirementIndex := some 99, retirementCommittableIndex := some 88,
      retiredCommittedIndex := some 77, sentIndex := fun _ => 9, matchIndex := fun _ => 8 }
  let packet : Message (Fin 3) Nat :=
    .requestVoteRequest
      { term := 7, source := 2, destination := 1, lastCommittableTerm := 3, lastCommittableIndex := 4 }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset present fun _ => row,
      network := fun node => if node = 1 then [packet, packet] else [],
      hasJoined := joined, submittedTxIds := {7}, preVoteStatus := fun _ => .enabled,
      retirementCompleted := fun _ => {0, 2} }
  let action := Action.changeConfiguration 0 configuration
  let allowed := decide (Enabled state action)
  let actual := CCFRaft.next state action
  let observed := mutate actual mutation
  let event := Json.mkObj [("kind", toJson "changeConfiguration"), ("source", toJson "a"),
    ("configuration", toJson (nodeNames configuration))]
  Json.mkObj [
    ("mutation", toJson (reprStr mutation)), ("modelEnabled", toJson allowed),
    ("peerInitiallyAllocated", toJson (decide (state.allocated 2))),
    ("expected", toJson (if allowed && decide (mutation = .unchanged) then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (frameObservations state [0, 7] ++ [event] ++ frameObservations observed [0, 7]))])]

def cases : List Json :=
  let sets := (List.finRange 3).sublists.map List.toFinset
  let logs : List (List (Entry (Fin 3) Nat) × Nat) := [
    ([], 0),
    ([{ term := 8, content := .signature }, { term := 1, content := .reconfiguration {0} }], 0),
    ([{ term := 8, content := .reconfiguration {1} }, { term := 2, content := .signature },
      { term := 1, content := .retiredCommitted {0} }], 3),
    ([{ term := 8, content := .reconfiguration {0, 1, 2} },
      { term := 1, content := .reconfiguration {0, 1} }], 0)]
  let matrix := logs.flatMap fun (log, commit) =>
    sets.flatMap fun configuration =>
      sets.flatMap fun present =>
        ([{0}, {0, 1}, {0, 1, 2}] : List (Finset (Fin 3))).flatMap fun joined =>
          [.unchanged, .sourceTerm].map (fixture log commit configuration present joined .leader .active)
  let guards := [.follower, .candidate, .leader].flatMap fun role =>
    [.active, .retiredCommitted].flatMap fun membership =>
      [.unchanged, .sourceTerm].map (fixture [] 0 {0, 1, 2} {0, 1} {0, 1} role membership)
  let allocation := ([{0, 1}, {0, 1, 2}] : List (Finset (Fin 3))).flatMap fun present =>
    [.unchanged, .sourceTerm, .peerTerm, .peerRole, .peerLog, .peerCommit, .peerVote,
      .peerCursor, .peerRetirement, .hasJoined, .completed, .queue].map
        (fixture [] 0 {0, 1, 2} present {0, 1} .leader .active)
  matrix ++ guards ++ allocation

end CCFRaft.NativeArrayMembershipFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayMembershipFixtures.cases).compress
