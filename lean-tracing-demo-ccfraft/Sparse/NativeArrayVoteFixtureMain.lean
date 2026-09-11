-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVote
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.NativeArrayVoteFixtures

open Lean

private def observation (kind : String) (value : Json) : Json :=
  Json.mkObj [("kind", toJson kind), ("node", toJson "a"), ("value", value)]

private def names (nodes : Finset (Fin 3)) : List String :=
  ((List.finRange 3).filter fun node => node ∈ nodes).map
    fun node => if node = 0 then "a" else if node = 1 then "b" else "c"

private def contentJson : EntryContent (Fin 3) Nat -> Json
  | .signature => toJson "signature"
  | .transaction tx => Json.mkObj [("transaction", toJson tx)]
  | .reconfiguration nodes => Json.mkObj [("reconfiguration", toJson (names nodes))]
  | .retiredCommitted nodes => Json.mkObj [("retiredCommitted", toJson (names nodes))]

private def queueLength (length : Nat) : Json :=
  Json.mkObj [("kind", toJson "queueLength"), ("source", toJson "a"),
    ("destination", toJson "b"), ("value", toJson length)]

private def point (index : Nat) (value : Json) : Json :=
  Json.mkObj [("kind", toJson "queuePoint"), ("source", toJson "a"),
    ("destination", toJson "b"), ("index", toJson index), ("value", value)]

private def fixture (preVote twoPeers : Bool) (contents : List (EntryContent (Fin 3) Nat))
    (commit : Nat) : Json :=
  letI : Bootstrap (Fin 3) :=
    { configuration := if twoPeers then {0, 1} else {0}
      leader := 0
      leader_mem := by cases twoPeers <;> simp }
  let log : List (Entry (Fin 3) Nat) :=
    contents.zipIdx.map fun (content, index) => { term := if index = 0 then 8 else 2, content }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset {0, 1} fun node =>
        if node = 0 then
          { (freshNodeState : NodeState (Fin 3) Nat) with
            role := if preVote then .preVoteCandidate else .candidate
            currentTerm := 4
            log
            commitIndex := commit }
        else freshNodeState
      network := fun _ => []
      submittedTxIds := {}
      hasJoined := {} }
  let request := makeRequestVoteRequest state 0 1
  let message : Message (Fin 3) Nat :=
    if preVote then .requestPreVote (makeRequestPreVote state 0 1)
    else .requestVoteRequest request
  let copies := if log.length = 2 then 2 else 0
  let state := { state with network := fun node => if node = 1 then List.replicate copies message else [] }
  let action : Action (Fin 3) Nat :=
    if preVote then .requestPreVote 0 1 else .requestVote 0 1
  let allowed := decide (CCFRaft.Enabled state action)
  let (term, lastTerm, lastIndex) :=
    if preVote then
      let request := makeRequestPreVote state 0 1
      (request.term, request.lastCommittableTerm, request.lastCommittableIndex)
    else (request.term, request.lastCommittableTerm, request.lastCommittableIndex)
  let packet := Json.mkObj [
    ("kind", toJson (if preVote then "requestPreVote" else "requestVoteRequest")),
    ("term", toJson term), ("lastCommittableTerm", toJson lastTerm),
    ("lastCommittableIndex", toJson lastIndex),
    ("source", toJson "a"), ("destination", toJson "b")]
  let points := log.zipIdx.map fun (entry, index) =>
    Json.mkObj [("kind", toJson "entry"), ("node", toJson "a"), ("index", toJson index),
      ("value", Json.mkObj [("term", toJson entry.term), ("content", contentJson entry.content)])]
  let instructions :=
    [observation "allocated" (toJson true),
      Json.mkObj [("kind", toJson "allocated"), ("node", toJson "b"), ("value", toJson true)],
      observation "role" (toJson (if preVote then "preVoteCandidate" else "candidate")),
      observation "logLength" (toJson log.length), observation "commit" (toJson commit),
      observation "currentTerm" (toJson 4), queueLength copies] ++
    points ++ (List.range copies).map (fun index => point index packet) ++
    [Json.mkObj [("kind", toJson (if preVote then "requestPreVote" else "requestVote")),
      ("source", toJson "a"), ("destination", toJson "b")],
      queueLength ((CCFRaft.next state action).network 1).length, point copies packet]
  Json.mkObj [
    ("expected", toJson (if allowed then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (names (INITIAL_CONFIGURATION (Node := Fin 3)))),
      ("instructions", toJson instructions)])]

def cases : List Json :=
  let alphabet : List (EntryContent (Fin 3) Nat) :=
    [.signature, .transaction 7, .reconfiguration {}, .reconfiguration {0},
      .reconfiguration {1}, .retiredCommitted {1}]
  let logs := [[]] ++ alphabet.map (fun content => [content]) ++
    [.signature, .reconfiguration {0}, .reconfiguration {0, 1}].flatMap
      (fun left => alphabet.map fun right => [left, right])
  [false, true].flatMap fun preVote =>
    [false, true].flatMap fun peers =>
      logs.flatMap fun log => [0, 1, 2, 3].map fun commit => fixture preVote peers log commit

end CCFRaft.NativeArrayVoteFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayVoteFixtures.cases).compress
