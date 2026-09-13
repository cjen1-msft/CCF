-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayAppendResponseFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

structure Scenario where
  role : Role := .leader
  term : Nat := 1
  success : Bool := true
  lastLogIndex : Nat := 2
  terms : List Nat := [9, 0]
  sent : Nat := 10
  matched : Nat := 20
  source : Fin 3 := 0
  present : Finset (Fin 3) := {0, 1, 2}
  packetDestination : Fin 3 := 1

private def fixture (index : Nat) (scenario : Scenario) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := scenario.role
      currentTerm := 1
      isNewFollower := false
      log := scenario.terms.mapIdx fun index term =>
        { term, content := if index % 2 = 0 then .signature else .transaction 99 }
      commitIndex := 7
      votedFor := some 2
      votesGranted := {2}
      preVotesGranted := {2}
      membershipState := .retiredCommitted
      retirementIndex := some 0
      retirementCommittableIndex := some 8
      retiredCommittedIndex := none
      sentIndex := fun peer => if peer = scenario.source then scenario.sent else 10 + peer.val
      matchIndex := fun peer => if peer = scenario.source then scenario.matched else 20 + peer.val }
  let packet : Message (Fin 3) Nat := .appendEntriesResponse {
    source := scenario.source, destination := scenario.packetDestination
    term := scenario.term, success := scenario.success, lastLogIndex := scenario.lastLogIndex }
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
  let afterState := if enabled then CCFRaft.next state action else state
  let before := frameObservations state [0, 99, 100]
  let instruction := Json.mkObj [
    ("kind", toJson "receiveAppendEntriesResponse"),
    ("source", toJson (nodeName scenario.source)), ("destination", toJson "b")]
  let after := if enabled then frameObservations afterState [0, 99, 100] else []
  Json.mkObj [
    ("name", toJson s!"append-response-model-{index}"),
    ("role", toJson (roleName scenario.role)),
    ("term", toJson scenario.term),
    ("success", toJson scenario.success),
    ("lastLogIndex", toJson scenario.lastLogIndex),
    ("logTerms", toJson scenario.terms),
    ("sentBefore", toJson ((state.nodes 1).sentIndex scenario.source)),
    ("matchBefore", toJson ((state.nodes 1).matchIndex scenario.source)),
    ("sentAfter", toJson ((afterState.nodes 1).sentIndex scenario.source)),
    ("matchAfter", toJson ((afterState.nodes 1).matchIndex scenario.source)),
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
  let standard : List Scenario :=
    [Role.none, .follower, .preVoteCandidate, .candidate, .leader].flatMap fun role =>
      [0, 1, 2].flatMap fun term =>
        [false, true].map fun success => { role, term, success }
  let sourceAbsent := [Role.leader, .follower].flatMap fun role =>
    [0, 1, 2].flatMap fun term =>
      [false, true].map fun success => { role, term, success, present := {1, 2} }
  let destinationAbsent := [({0, 2} : Finset (Fin 3)), {2}].flatMap fun present =>
    [0, 1, 2].flatMap fun term =>
      [false, true].map fun success => { term := term, success, present }
  let wrongRecipient := [({0, 1, 2} : Finset (Fin 3)), {1, 2}].flatMap fun present =>
    [0, 1, 2].flatMap fun term =>
      [false, true].map fun success => { term, success, present, packetDestination := 2 }
  let selfResponses := [({1, 2} : Finset (Fin 3)), {2}].flatMap fun present =>
    [0, 1, 2].flatMap fun term =>
      [false, true].map fun success => { term, success, source := 1, present }
  let logs : List (List Nat × Nat × Nat) :=
    [([], 0, 0), ([4, 0, 2], 10, 0), ([8, 2, 5, 1], 1, 12),
      ([3, 1, 4, 0], 2, 1), ([0, 0, 0], 3, 0), ([10^30, 1], 10^30, 0)]
  let scanCases := logs.flatMap fun (terms, sent, matched) =>
    [0, 1, 2, 3, 4, 10^30].flatMap fun lastLogIndex =>
      [0, 1, 3, 10^30].map fun term =>
        { success := false, terms, sent, matched, lastLogIndex, term : Scenario }
  let ackBounds := [0, 20, 21, 10^30].map fun lastLogIndex => { lastLogIndex : Scenario }
  standard ++ sourceAbsent ++ destinationAbsent ++ wrongRecipient ++ selfResponses ++ scanCases ++ ackBounds

def cases : List Json :=
  scenarios.zipIdx.map fun (scenario, index) => fixture index scenario

end CCFRaft.NativeArrayAppendResponseFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayAppendResponseFixtures.cases).compress
