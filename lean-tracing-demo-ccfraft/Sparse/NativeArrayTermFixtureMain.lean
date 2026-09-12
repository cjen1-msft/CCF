-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVote
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false

namespace CCFRaft.NativeArrayTermFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

private def packets (term : Nat) (destination : Fin 3) : List (Message (Fin 3) Nat) :=
  [.appendEntriesRequest {
      term, source := 0, destination, prevLogIndex := 9, prevLogTerm := 8,
      leaderCommit := 10, entries := [
        { term := 8, content := .signature }, { term := 2, content := .transaction 7 },
        { term := 1, content := .reconfiguration {0, 2} }] },
    .appendEntriesResponse { term, source := 0, destination, success := false, lastLogIndex := 7 },
    .requestVoteRequest { term, source := 0, destination, lastCommittableTerm := 8, lastCommittableIndex := 9 },
    .requestPreVote { term, source := 0, destination, lastCommittableTerm := 8, lastCommittableIndex := 9 },
    .requestVoteResponse { term, source := 0, destination, voteGranted := true },
    .requestPreVoteResponse { term, source := 0, destination, voteGranted := false },
    .proposeVoteRequest { term, source := 0, destination }]

private def observation (kind : String) (node : Fin 3) (value : Json) : Json :=
  Json.mkObj [("kind", toJson kind), ("node", toJson (nodeName node)), ("value", value)]

private def queueObservation (kind : String) (source : Fin 3) (value : Json)
    (extra : List (String × Json) := []) : Json :=
  Json.mkObj ([("kind", toJson kind), ("source", toJson (nodeName source)),
    ("destination", toJson "b"), ("value", value)] ++ extra)

private def fixture (sourceKnown destinationKnown : Bool) (message : Message (Fin 3) Nat) : Json :=
  let unrelated : Message (Fin 3) Nat := .proposeVoteRequest { term := 99, source := 2, destination := 1 }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset
        (Finset.univ.filter fun node => if node = 0 then sourceKnown else if node = 1 then destinationKnown else true)
        (fun node => if node = 1 then
          { (freshNodeState : NodeState (Fin 3) Nat) with
            role := .leader, currentTerm := 2, isNewFollower := false,
            votedFor := some 2, votesGranted := {0, 2}, preVotesGranted := {1, 2},
            commitIndex := 9, log := [{ term := 8, content := .transaction 3 }] }
          else freshNodeState)
      network := fun node => if node = 1 then [unrelated, message, message] else []
      submittedTxIds := {}, hasJoined := {} }
  let action : Action (Fin 3) Nat := .updateTerm 0 1
  let updated := CCFRaft.next state action
  let before := state.nodes 1
  let after := updated.nodes 1
  let sourceQueue := fun (state : State (Fin 3) Nat) => Sparse.Queue.partition 0 (state.network 1)
  let instructions := [
    observation "allocated" 0 (toJson sourceKnown),
    observation "allocated" 1 (toJson destinationKnown),
    observation "role" 1 (toJson (roleName before.role)),
    observation "currentTerm" 1 (toJson before.currentTerm),
    observation "newFollower" 1 (toJson before.isNewFollower),
    observation "commit" 1 (toJson before.commitIndex),
    observation "logLength" 1 (toJson before.log.length),
    observation "votedFor" 1 (toJson (before.votedFor.map nodeName)),
    observation "votesGranted" 1 (toJson (nodeNames before.votesGranted)),
    observation "preVotesGranted" 1 (toJson (nodeNames before.preVotesGranted)),
    queueObservation "queueLength" 0 (toJson (sourceQueue state).length),
    queueObservation "queuePoint" 0 (messageJson message) [("index", toJson 0)],
    queueObservation "queuePoint" 2 (messageJson unrelated) [("index", toJson 0)],
    Json.mkObj [("kind", toJson "updateTerm"), ("source", toJson "a"), ("destination", toJson "b")],
    observation "currentTerm" 1 (toJson after.currentTerm),
    observation "role" 1 (toJson (roleName after.role)),
    observation "newFollower" 1 (toJson after.isNewFollower),
    observation "commit" 1 (toJson after.commitIndex),
    observation "logLength" 1 (toJson after.log.length),
    observation "votedFor" 1 (toJson (after.votedFor.map nodeName)),
    observation "votesGranted" 1 (toJson (nodeNames after.votesGranted)),
    observation "preVotesGranted" 1 (toJson (nodeNames after.preVotesGranted)),
    queueObservation "queueLength" 0 (toJson (sourceQueue updated).length),
    queueObservation "queuePoint" 0 (messageJson message) [("index", toJson 0)],
    queueObservation "queuePoint" 0 (messageJson message) [("index", toJson 1)],
    queueObservation "queuePoint" 2 (messageJson unrelated) [("index", toJson 0)]]
  Json.mkObj [
    ("expected", toJson (if decide (CCFRaft.Enabled state action) then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)), ("instructions", toJson instructions)])]

def cases : List Json :=
  [false, true].flatMap fun source =>
    [false, true].flatMap fun destination =>
      [1, 2, 3].flatMap fun term =>
        ([0, 1] : List (Fin 3)).flatMap fun recipient =>
          (packets term recipient).map (fixture source destination)

end CCFRaft.NativeArrayTermFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayTermFixtures.cases).compress
