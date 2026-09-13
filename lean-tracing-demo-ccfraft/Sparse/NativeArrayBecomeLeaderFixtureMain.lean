-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayBecomeLeaderFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

structure Scenario where
  name : String
  role : Role := .candidate
  term : Nat := 0
  log : List (Entry (Fin 3) Nat) := []
  commit : Nat := 7
  votes : Finset (Fin 3) := {0, 1}
  membership : MembershipState := .active
  present : Finset (Fin 3) := {0, 1, 2}
  newFollower : Bool := true
  votedFor : Option (Fin 3) := none

private def fixture (scenario : Scenario) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := scenario.role
      currentTerm := scenario.term
      isNewFollower := scenario.newFollower
      log := scenario.log
      commitIndex := scenario.commit
      votedFor := scenario.votedFor
      votesGranted := scenario.votes
      preVotesGranted := {2}
      membershipState := scenario.membership
      retirementIndex := some 0
      retirementCommittableIndex := some 8
      retiredCommittedIndex := none
      sentIndex := fun peer => 10 + peer.val
      matchIndex := fun peer => 20 + peer.val }
  let packet : Message (Fin 3) Nat :=
    .proposeVoteRequest { term := 42, source := 2, destination := 1 }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset scenario.present fun node =>
        if node = 0 then row else { row with currentTerm := 30 + node.val }
      network := fun node => if node = 1 then [packet, packet] else []
      submittedTxIds := {0, 99}
      hasJoined := {0, 1, 2}
      preVoteStatus := fun _ => .capable
      retirementCompleted := fun _ => {2} }
  let action : Action (Fin 3) Nat := .becomeLeader 0
  let enabled := decide (CCFRaft.Enabled state action)
  let afterState := if enabled then CCFRaft.next state action else state
  let before := frameObservations state [0, 99, 100]
  let instruction := Json.mkObj [("kind", toJson "becomeLeader"), ("node", toJson "a")]
  let after := if enabled then frameObservations afterState [0, 99, 100] else []
  Json.mkObj [
    ("name", toJson scenario.name),
    ("latestSignature", toJson (maxCommittableIndex row.log)),
    ("logLengthAfter", toJson (afterState.nodes 0).log.length),
    ("commitAfter", toJson (afterState.nodes 0).commitIndex),
    ("newFollowerAfter", toJson (afterState.nodes 0).isNewFollower),
    ("electionMajority", toJson (decide (hasElectionMajority state 0))),
    ("stepIndex", toJson before.length),
    ("expected", toJson (if enabled then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (before ++ [instruction] ++ after))])]

private def transaction (term : Nat) : Entry (Fin 3) Nat :=
  { term, content := .transaction 99 }

private def signature (term : Nat) : Entry (Fin 3) Nat :=
  { term, content := .signature }

private def configuration (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
  { term := 1, content := .reconfiguration nodes }

private def scenarios : List Scenario :=
  let logs : List (String × List (Entry (Fin 3) Nat)) :=
    [("empty", []),
      ("unsigned", [transaction 9, transaction 0]),
      ("truncate", [transaction 9, signature 0, transaction 10]),
      ("last-signature", [signature 9, transaction 0, signature 1, transaction 0]),
      ("discard-configuration", [configuration {1, 2}]),
      ("joint", [configuration {1, 2}, signature 0, configuration {0, 2}]),
      ("empty-configuration", [configuration {}, signature 0]),
      ("retirement-completed", [configuration {1, 2}, signature 0,
        configuration {1, 2}, signature 1]),
      ("terminal", [configuration {1, 2}, signature 0,
        { term := 0, content := .retiredCommitted {0} }, signature 1]),
      ("discard-terminal", [{ term := 0, content := .retiredCommitted {0} }])]
  let support : List (Finset (Fin 3)) := [{}, {0}, {1}, {0, 1}, {0, 2}, {0, 1, 2}]
  let matrix := logs.flatMap fun (name, log) =>
    [0, 2, 7].flatMap fun commit =>
      support.zipIdx.map fun (votes, index) =>
        { name := s!"{name}-commit-{commit}-votes-{index}", log, commit, votes : Scenario }
  let roles := [Role.none, .follower, .preVoteCandidate, .candidate, .leader].map fun role =>
    { name := s!"role-{roleName role}", role : Scenario }
  let memberships :=
    [MembershipState.active, .retirementOrdered, .retirementSigned,
      .retirementCompleted, .retiredCommitted].zipIdx.map
      fun (membership, index) => { name := s!"membership-{index}", membership : Scenario }
  let allocation := [({0} : Finset (Fin 3)), {1, 2}, {}].zipIdx.map fun (present, index) =>
    { name := s!"allocation-{index}", present : Scenario }
  let preservation := [false, true].flatMap fun newFollower =>
    [(none : Option (Fin 3)), some 0, some 1, some 2].zipIdx.map fun (votedFor, index) =>
      { name := s!"preserve-{newFollower}-{index}", newFollower, votedFor : Scenario }
  matrix ++ roles ++ memberships ++ allocation ++ preservation ++
    [{ name := "large-naturals", term := 10^30, commit := 10^30,
       log := [signature (10^30), transaction 0] }]

def cases : List Json :=
  scenarios.map fixture

end CCFRaft.NativeArrayBecomeLeaderFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayBecomeLeaderFixtures.cases).compress
