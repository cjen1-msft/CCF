-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVote
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false

namespace CCFRaft.NativeArrayNodeFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

private def fixture (membership : MembershipState) (index : Option Nat)
    (votedFor : Option (Fin 3)) (allocated : Bool) (kind : Nat) : Json :=
  let role := if kind = 2 then Role.candidate else if kind = 3 then .preVoteCandidate else .leader
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (if allocated then {0, 1} else {0}) fun node =>
        if node = 1 then
          { role, currentTerm := 7, isNewFollower := false, commitIndex := 99,
            log := [{ term := 9, content := .signature }, { term := 2, content := .transaction 5 }],
            sentIndex := fun peer => peer.val + 100, matchIndex := fun peer => peer.val + 200,
            votedFor, votesGranted := {0, 2}, preVotesGranted := {1, 2}, membershipState := membership,
            retirementIndex := index, retirementCommittableIndex := index, retiredCommittedIndex := index }
        else freshNodeState
      network := fun node => if node = 1 then
        [.requestVoteRequest {
          term := 9, source := 0, destination := 1,
          lastCommittableTerm := 8, lastCommittableIndex := 10 }] else []
      submittedTxIds := {7, 1000000000000}, hasJoined := {2}
      preVoteStatus := fun node => if node = 2 then .enabled else .capable
      retirementCompleted := fun node => if node = 2 then {0, 1} else {2} }
  let action : Action (Fin 3) Nat :=
    if kind = 0 then .checkQuorum 1 else if kind = 1 then .updateTerm 0 1
    else if kind = 2 then .requestVote 1 0 else .requestPreVote 1 0
  let event := if kind = 0 then Json.mkObj [("kind", toJson "checkQuorum"), ("node", toJson "b")]
    else Json.mkObj [("kind", toJson (if kind = 1 then "updateTerm" else if kind = 2 then "requestVote" else "requestPreVote")),
      ("source", toJson (if kind = 1 then "a" else "b")), ("destination", toJson (if kind = 1 then "b" else "a"))]
  let observations := fun (state : State (Fin 3) Nat) =>
    globalObservations state [0, 5, 7, 999999999999, 1000000000000, 1000000000001] ++
    (List.finRange 3).flatMap (fun node =>
      Json.mkObj [("kind", toJson "allocated"), ("node", toJson (nodeName node)),
        ("value", toJson (state.node? node).isSome)] :: nodeObservations node (state.nodes node))
  let instructions := observations state ++
    [Json.mkObj [("kind", toJson "queueLength"), ("source", toJson "a"), ("destination", toJson "b"),
      ("value", toJson 1)],
      Json.mkObj [("kind", toJson "queuePoint"), ("source", toJson "a"), ("destination", toJson "b"),
        ("index", toJson 0), ("value", messageJson (.requestVoteRequest
          { term := 9, source := 0, destination := 1, lastCommittableTerm := 8, lastCommittableIndex := 10 }))],
      event] ++ observations (CCFRaft.next state action)
  Json.mkObj [
    ("expected", toJson (if decide (CCFRaft.Enabled state action) then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)), ("instructions", toJson instructions)])]

def cases : List Json :=
  [MembershipState.active, .retirementOrdered, .retirementSigned, .retirementCompleted,
    .retiredCommitted].flatMap fun membership =>
      [none, some 0, some 99].flatMap fun index =>
        [none, some 0, some 2].flatMap fun votedFor =>
          [false, true].flatMap fun allocated =>
            [0, 1, 2, 3].map (fixture membership index votedFor allocated)

end CCFRaft.NativeArrayNodeFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayNodeFixtures.cases).compress
