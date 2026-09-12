-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipEncoding
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeMembershipFixtures

open Lean NativeSmt NativeEncode

def alphabet : List (EntryContent (Fin 3) Nat) :=
  [.signature, .transaction (10 ^ 30), .reconfiguration {}, .reconfiguration {0, 1},
    .reconfiguration {2}, .retiredCommitted {1}]

def logs : List (List (EntryContent (Fin 3) Nat)) :=
  [[]] ++ alphabet.map (fun content => [content]) ++
    alphabet.flatMap (fun left => alphabet.map (fun right => [left, right]))

def fixture (name : String) (twoPeers : Bool) (contents : List (EntryContent (Fin 3) Nat))
    (committed : Nat) (peer : Fin 3) (witness : Option Int) : Json :=
  letI : Bootstrap (Fin 3) :=
    { configuration := if twoPeers then {0, 1} else {0}
      leader := 0
      leader_mem := by cases twoPeers <;> simp }
  let log : List (Entry (Fin 3) Nat) :=
    contents.zipIdx.map fun (content, index) => { term := index + 1, content }
  let state : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with log, commitIndex := committed }
  let allowed := match witness with
    | none => decide (peer ∈ activeNodeUnion state)
    | some index => (activeConfigurations state).any fun configuration =>
        decide (peer ∈ configuration.nodes) &&
          (configuration.index == 0 || (configuration.index : Int) == index)
  let assertions : List (Expr .bool) := [
    .equal (allocated 0) (.boolean true),
    .equal (length 0) (.integer log.length),
    .equal (commit 0) (.integer committed),
    .equal (.select (.free (.array .int (.array .int (entryTy 3))) 6) (.integer 0)) (.snd (logTerm log)),
    currentCandidate 3 0 24,
    noLaterConfiguration 3 0 24,
    activeMemberTerm 3 (encodeBits (width := 3) (INITIAL_CONFIGURATION (Node := Fin 3)))
      0 peer (.free .int 24) (.free .int 25)]
  let assertions := assertions ++ witness.toList.map (fun value => .equal (.free .int 25) (.integer value))
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if allowed then "sat" else "unsat"))]

def cases : List Json :=
  let free := [false, true].flatMap fun twoPeers =>
    logs.zipIdx.flatMap fun (log, index) =>
      [0, 1, 2, 10 ^ 30].flatMap fun committed =>
        (List.finRange 3).map fun peer =>
          fixture s!"membership-free-{twoPeers}-{index}-{committed}-{peer.val}"
            twoPeers log committed peer none
  let fixed := [false, true].flatMap fun twoPeers =>
    ([[], [.reconfiguration {1}], [.signature, .reconfiguration {2}]] :
      List (List (EntryContent (Fin 3) Nat))).zipIdx.flatMap fun (log, index) =>
      (List.finRange 3).flatMap fun peer =>
        ([-1, 0, 1, 2, 3, 10 ^ 30] : List Int).map fun witness =>
          fixture s!"membership-fixed-{twoPeers}-{index}-{peer.val}-{witness}"
            twoPeers log 1 peer (some witness)
  free ++ fixed

end CCFRaft.NativeMembershipFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeMembershipFixtures.cases).compress
