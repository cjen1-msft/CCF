-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayVoteResponseFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

structure Scenario where
  preVote : Bool
  role : Role
  term : Nat
  granted : Bool := true
  source : Fin 3 := 0
  present : Finset (Fin 3) := {0, 1, 2}
  packetDestination : Fin 3 := 1

private def fixture (index : Nat) (scenario : Scenario) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := scenario.role
      currentTerm := 1
      isNewFollower := false
      log := [{ term := 9, content := .signature }, { term := 0, content := .transaction 99 }]
      commitIndex := 7
      votedFor := some 2
      votesGranted := {2}
      preVotesGranted := {2}
      membershipState := .retiredCommitted
      retirementIndex := some 0
      retirementCommittableIndex := some 8
      retiredCommittedIndex := none
      sentIndex := fun peer => 10 + peer.val
      matchIndex := fun peer => 20 + peer.val }
  let packet : Message (Fin 3) Nat :=
    if scenario.preVote then
      .requestPreVoteResponse {
        source := scenario.source, destination := scenario.packetDestination
        term := scenario.term, voteGranted := scenario.granted }
    else
      .requestVoteResponse {
        source := scenario.source, destination := scenario.packetDestination
        term := scenario.term, voteGranted := scenario.granted }
  let unrelated : Message (Fin 3) Nat :=
    .proposeVoteRequest { term := 42, source := 2, destination := 1 }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset scenario.present fun node =>
        if node = 1 then row else { row with currentTerm := 30 + node.val }
      network := fun node => if node = 1 then [unrelated, packet, packet] else []
      submittedTxIds := {0, 99}
      hasJoined := {0, 1, 2}
      preVoteStatus := fun _ => .capable
      retirementCompleted := fun _ => {2} }
  let action : Action (Fin 3) Nat := .receive scenario.source 1
  let enabled := decide (CCFRaft.Enabled state action)
  let before := frameObservations state [0, 99, 100]
  let instruction := Json.mkObj [
    ("kind", toJson (if scenario.preVote then "receiveRequestPreVoteResponse" else "receiveRequestVoteResponse")),
    ("source", toJson (nodeName scenario.source)), ("destination", toJson "b")]
  let after := if enabled then frameObservations (CCFRaft.next state action) [0, 99, 100] else []
  Json.mkObj [
    ("name", toJson s!"vote-response-model-{index}"),
    ("preVote", toJson scenario.preVote),
    ("role", toJson (roleName scenario.role)),
    ("term", toJson scenario.term),
    ("granted", toJson scenario.granted),
    ("source", toJson (nodeName scenario.source)),
    ("sourceAllocated", toJson (decide (state.allocated scenario.source))),
    ("destinationAllocated", toJson (decide (state.allocated 1))),
    ("recipientMatches", toJson (scenario.packetDestination == 1)),
    ("stepIndex", toJson before.length),
    ("expected", toJson (if enabled then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (before ++ [instruction] ++ after))])]

private def scenarios : List Scenario :=
  let standard : List Scenario := [false, true].flatMap fun preVote =>
    [Role.none, .follower, .preVoteCandidate, .candidate, .leader].flatMap fun role =>
      [0, 1, 2].flatMap fun term =>
        [false, true].map fun granted => { preVote, role, term, granted := granted }
  let sourceAbsent := [false, true].flatMap fun preVote =>
    [(if preVote then Role.preVoteCandidate else .candidate), .follower].flatMap fun role =>
      [0, 1, 2].map fun term => { preVote, role, term, present := {1, 2} }
  let destinationAbsent := [false, true].flatMap fun preVote =>
    [({0, 2} : Finset (Fin 3)), {2}].flatMap fun present =>
      [0, 1, 2].map fun term =>
        { preVote, role := if preVote then .preVoteCandidate else .candidate, term, present }
  let wrongRecipient := [false, true].flatMap fun preVote =>
    [({0, 1, 2} : Finset (Fin 3)), {1, 2}].flatMap fun present =>
      [0, 1, 2].map fun term =>
        { preVote, role := if preVote then .preVoteCandidate else .candidate
          term, present, packetDestination := 2 }
  let selfResponses := [false, true].flatMap fun preVote =>
    [({1, 2} : Finset (Fin 3)), {2}].flatMap fun present =>
      [0, 1, 2].flatMap fun term =>
        [false, true].map fun granted =>
          { preVote, role := if preVote then .preVoteCandidate else .candidate
            term, granted, source := 1, present }
  standard ++ sourceAbsent ++ destinationAbsent ++ wrongRecipient ++ selfResponses

def cases : List Json :=
  scenarios.zipIdx.map fun (scenario, index) => fixture index scenario

end CCFRaft.NativeArrayVoteResponseFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayVoteResponseFixtures.cases).compress
