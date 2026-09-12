-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveWrites
import Sparse.NativeNodeRowFixtureTerms
import Sparse.NativeArrayAppendReceiveFixtures
import Sparse.NativeFrameEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendReceiveWriteFixtures

open Lean NativeSmt NativeEncode NativeArrayFixtures NativeArrayAppendReceiveFixtures
  NativeNodeRowWriteFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def changeCompleted (state : State (Fin 3) Nat) (destination : Fin 3) : State (Fin 3) Nat :=
  { state with
    retirementCompleted := fun node =>
      if node = destination then
        if 0 ∈ state.retirementCompleted node then (state.retirementCompleted node).erase 0
        else insert 0 (state.retirementCompleted node)
      else state.retirementCompleted node }

def fixture (index mutation : Nat) (state : State (Fin 3) Nat) (source destination : Fin 3) :
    Except String Json := do
  let some (.appendEntriesRequest request, _) := takeFirstFrom source (state.network destination)
    | throw "write fixture has no selected append request"
  unless decide (Enabled state (.receive source destination)) do
    throw "write fixture selected a disabled receive"
  let stepsDown := (returnToFollowerState? (state.nodes destination) request).isSome
  let actual := CCFRaft.next state (.receive source destination)
  let (response, completed) <- if stepsDown then do
      let response : AppendEntriesResponse (Fin 3) :=
        { term := 10 ^ 30
          source := destination
          destination := source
          success := false
          lastLogIndex := 10 ^ 30 }
      pure (response, ({2} : Finset (Fin 3)))
    else
      match handleAppendEntriesRequest? (state.nodes destination) request with
      | none => throw "consuming write fixture has no handler result"
      | some (row, response) => pure (response, retirementCompletedNodes row.log row.commitIndex)
  let other : Fin 3 := if destination = 0 then 1 else 0
  let changedDestination := { actual.nodes destination with
    currentTerm := (actual.nodes destination).currentTerm + 1 }
  let changedOther := { actual.nodes other with currentTerm := (actual.nodes other).currentTerm + 1 }
  let observed := match mutation with
    | 1 => { actual with nodes := updateNode actual.nodes destination changedDestination }
    | 2 => { actual with
        network := updateQueue actual.network source
          (actual.network source ++ [.proposeVoteRequest { term := 17, source := destination, destination := source }]) }
    | 3 => changeCompleted actual destination
    | 4 => { actual with nodes := updateNode actual.nodes other changedOther }
    | 6 => state
    | _ => actual
  let decode := fun frame =>
    (frameObservations frame [0, 7]).toArray.mapM (decodeFrameInstruction 3 #["a", "b", "c"])
  let before <- decode state
  let after <- decode observed
  let program : EncodeM 3 Unit := do
    initialFrameDomains 3
    for receiver in List.finRange 3 do
      for sender in List.finRange 3 do
        assertion (.equal
          (.select (.select (.free (.array .int (.array .int .int)) 22) (.integer receiver.val)) (.integer sender.val))
          (.integer (if index % 2 = 0 then -5 else 10 ^ 30)))
    for item in before do frameInstruction item
    appendReceiveWrites source destination
      (.boolean (if mutation = 5 then !stepsDown else stepsDown))
      (rowTerms (actual.nodes destination)) (packetTerm (.appendEntriesResponse response))
      (.bits (encodeBits completed))
    for item in after do frameInstruction item
  let (_, final) <- program.run (initialEncoding 3 {0, 1})
  unless final.next = 48 do
    throw "append receive write allocated an unexpected number of symbols"
  return Json.mkObj [("name", toJson s!"append-receive-writes-{index}-{mutation}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("branch", toJson (branch state source destination)),
    ("sourcePresent", toJson (decide (state.allocated source))),
    ("self", toJson (source == destination)),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def cases : Except String Json := do
  let normal := scenarios.flatMap fun scenario =>
    [.follower, .candidate, .preVoteCandidate, .leader].flatMap fun role =>
      [false, true].flatMap fun newFollower =>
        [4, 5, 6].flatMap fun term =>
          ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).map fun (source, destination) =>
            (NativeArrayAppendReceiveFixtures.initialState scenario role newFollower term
              source destination true true 0, source, destination)
  let absentSource := scenarios.flatMap fun scenario =>
    [4, 5].map fun term =>
      (NativeArrayAppendReceiveFixtures.initialState scenario .candidate false term
        0 1 false true 0, (0 : Fin 3), (1 : Fin 3))
  let enabled := (normal ++ absentSource).filter fun (state, source, destination) =>
    decide (Enabled state (.receive source destination))
  let fixtures <- enabled.zipIdx.flatMapM fun ((state, source, destination), index) =>
    (List.range 7).mapM fun mutation => fixture index mutation state source destination
  let mut rejected := #[]
  let values := rowTerms (freshNodeState : NodeState (Fin 3) Nat)
  let response := packetTerm (width := 3) (.appendEntriesResponse
    { term := 0, source := 1, destination := 0, success := false, lastLogIndex := 0 })
  for kind in ["stepDown", "response", "completed", "row"] do
    for symbol in [24, 39, 47, 1024] do
      let writes := appendReceiveWrites (width := 3) 0 1
        (if kind = "stepDown" then .free .bool symbol else .boolean false)
        (if kind = "row" then { values with role := .free .int symbol } else values)
        (if kind = "response" then .free (packetTy 3) symbol else response)
        (if kind = "completed" then .free (.bits 3) symbol else .bits 0)
      match writes.run (initialEncoding 3 {0, 1}) with
      | .error error =>
        rejected := rejected.push (Json.mkObj [
          ("kind", toJson kind), ("symbol", toJson symbol), ("error", toJson error)])
      | .ok _ => throw "append receive write accepted a future symbol"
  return Json.mkObj [("fixtures", toJson fixtures), ("rejected", toJson rejected)]

end CCFRaft.NativeAppendReceiveWriteFixtures

def main : IO Unit :=
  match CCFRaft.NativeAppendReceiveWriteFixtures.cases with
  | .ok result => IO.println result.compress
  | .error error => throw (IO.userError error)
