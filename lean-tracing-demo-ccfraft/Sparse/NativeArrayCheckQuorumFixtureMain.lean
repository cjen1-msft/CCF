-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.NativeArrayCheckQuorumFixtures

open Lean

private def observation (kind : String) (value : Json) : Json :=
  Json.mkObj [("kind", toJson kind), ("node", toJson "a"), ("value", value)]

private def nodeNames (nodes : Finset (Fin 3)) : List String :=
  ((List.finRange 3).filter fun node => node ∈ nodes).map
    fun node => if node = 0 then "a" else if node = 1 then "b" else "c"

private def contentJson : EntryContent (Fin 3) Nat -> Json
  | .signature => toJson "signature"
  | .transaction tx => Json.mkObj [("transaction", toJson tx)]
  | .reconfiguration nodes => Json.mkObj [("reconfiguration", toJson (nodeNames nodes))]
  | .retiredCommitted nodes => Json.mkObj [("retiredCommitted", toJson (nodeNames nodes))]

private def fixture (twoPeers : Bool) (contents : List (EntryContent (Fin 3) Nat))
    (commit : Nat) : Json :=
  letI : Bootstrap (Fin 3) :=
    { configuration := if twoPeers then {0, 1} else {0}
      leader := 0
      leader_mem := by cases twoPeers <;> simp }
  let log : List (Entry (Fin 3) Nat) :=
    contents.zipIdx.map fun (content, index) => { term := index + 1, content }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset {0} fun _ =>
        { (freshNodeState : NodeState (Fin 3) Nat) with
          role := .leader, isNewFollower := false, log, commitIndex := commit }
      network := fun _ => [], submittedTxIds := {}, hasJoined := {} }
  let allowed := decide (CCFRaft.Enabled state (.checkQuorum 0))
  let points := log.zipIdx.map fun (entry, index) =>
    Json.mkObj [
      ("kind", toJson "entry"), ("node", toJson "a"), ("index", toJson index),
      ("value", Json.mkObj [("term", toJson entry.term), ("content", contentJson entry.content)])]
  let instructions :=
    [observation "allocated" (toJson true), observation "role" (toJson "leader"),
      observation "newFollower" (toJson false), observation "logLength" (toJson log.length),
      observation "commit" (toJson commit)] ++ points ++
    [Json.mkObj [("kind", toJson "checkQuorum"), ("node", toJson "a")],
      observation "role" (toJson "follower"), observation "newFollower" (toJson true)]
  Json.mkObj [
    ("expected", toJson (if allowed then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (nodeNames (INITIAL_CONFIGURATION (Node := Fin 3)))),
      ("instructions", toJson instructions)])]

def cases : List Json :=
  let alphabet : List (EntryContent (Fin 3) Nat) :=
    [.signature, .reconfiguration {}, .reconfiguration {0}, .reconfiguration {1},
      .retiredCommitted {1}, .transaction 7]
  let logs := [[]] ++ alphabet.map (fun content => [content]) ++
    [.reconfiguration {}, .reconfiguration {0}, .reconfiguration {0, 1}].flatMap
      (fun left => alphabet.map fun right => [left, right])
  [false, true].flatMap fun peers =>
    logs.flatMap fun log => [0, 1, 3].map fun commit => fixture peers log commit

end CCFRaft.NativeArrayCheckQuorumFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayCheckQuorumFixtures.cases).compress
