-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendGuardEncoding
import Sparse.NativeFrameEncode
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendGuardFixtures

open Lean NativeSmt NativeEncode NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def fixture (index : Nat) (state : State (Fin 3) Nat) (destination : Fin 3) (batchEnd : Nat) :
    Except String Json := do
  let observations := (List.finRange 3).map (fun node =>
      Json.mkObj [("kind", toJson "allocated"), ("node", toJson (nodeName node)),
        ("value", toJson (decide (state.allocated node)))]) ++
    nodeObservations 0 (state.nodes 0) ++ globalObservations state []
  let input <- decodeFrameDocument (Json.mkObj [
    ("nodes", toJson (["a", "b", "c"] : List String)), ("bootstrap", toJson (["a", "b"] : List String)),
    ("instructions", toJson observations)])
  let source <- resolve input.width #["a", "b", "c"] (toJson "a")
  let destinationId <- resolve input.width #["a", "b", "c"] (toJson (nodeName destination))
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do frameInstruction instruction
    let before <- get
    let base <- fresh
    let _ <- fresh
    assertAll (appendGuards before.toColumns before.bootstrap source destinationId batchEnd base)
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [("name", toJson s!"append-guard-model-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if decide (TraceEnabled state (.appendEntries 0 destination batchEnd)) then "sat" else "unsat"))]

def state (present : Finset (Fin 3)) (role : Role) (membershipState : MembershipState)
    (completed : Bool) (log : List (Entry (Fin 3) Nat)) (previous : Nat) : State (Fin 3) Nat :=
  { nodes := NodeStore.ofFinset present fun _ =>
      { (freshNodeState : NodeState (Fin 3) Nat) with
        role, membershipState, log, commitIndex := 1, currentTerm := 10 ^ 30,
        sentIndex := fun _ => previous }
    retirementCompleted := fun _ => if completed then {1} else {}
    preVoteStatus := fun _ => .capable
    network := fun _ => [], hasJoined := {}, submittedTxIds := {} }

def cases : Except String (List Json) := do
  let logs : List (List (Entry (Fin 3) Nat)) := [
    [], [{ term := 1, content := .signature }],
    [{ term := 1, content := .reconfiguration {0} }],
    [{ term := 1, content := .reconfiguration {0} }, { term := 2, content := .reconfiguration {1} }]]
  let matrix := [.leader, .follower].flatMap fun role =>
    [.active, .retirementOrdered, .retirementSigned, .retirementCompleted, .retiredCommitted].flatMap fun membership =>
      [false, true].flatMap fun completed =>
        logs.flatMap fun log =>
          [0, 1, 2, 3, 10 ^ 30].flatMap fun previous =>
            let frontier := min (previous + 1) log.length
            [previous, frontier, frontier + 1, 10 ^ 30].map fun batchEnd =>
              (state {0, 1} role membership completed log previous, (1 : Fin 3), batchEnd)
  let allocation := [false, true].flatMap fun sourcePresent =>
    [false, true].flatMap fun destinationPresent =>
      [false, true].flatMap fun self =>
        [false, true].map fun completed =>
          let present := (if sourcePresent then {0} else {}) ∪ (if destinationPresent then {1} else {})
          (state present .leader .active completed [] 0, (if self then 0 else 1 : Fin 3), 0)
  (matrix ++ allocation).zipIdx.mapM fun ((model, destination, batchEnd), index) =>
    fixture index model destination batchEnd

end CCFRaft.NativeAppendGuardFixtures

def main : IO Unit :=
  match CCFRaft.NativeAppendGuardFixtures.cases with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
