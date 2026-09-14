-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson
import Sparse.TraceEnabled
import MachineGenerated.ModelProofs

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayAppendFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def fixture (log : List (Entry (Fin 3) Nat)) (commit previous : Nat) (completed : Bool)
    (present : Finset (Fin 3)) (destination : Fin 3) (role : Role)
    (membershipState : MembershipState) (conflict : Bool) : Json :=
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset present fun node =>
        if node = 0 then
          { (freshNodeState : NodeState (Fin 3) Nat) with
            role, membershipState, log, commitIndex := commit, currentTerm := 10 ^ 30,
            sentIndex := fun peer => if peer = destination then previous else 99,
            matchIndex := fun _ => 7, votedFor := some 2, votesGranted := {0, 2}, preVotesGranted := {1} }
        else { freshNodeState with currentTerm := 42 }
      network := fun _ => [], hasJoined := {0, 2}, submittedTxIds := {1, 10 ^ 30},
      preVoteStatus := fun _ => .enabled
      retirementCompleted := fun _ => if completed then {destination} else {} }
  let batchEnd := min ((state.nodes 0).sentIndex destination + 1) (state.nodes 0).log.length
  let message := Message.appendEntriesRequest (makeAppendEntriesRequest state 0 destination batchEnd)
  let packets := [message, message, .proposeVoteRequest { term := 8, source := 2, destination := 2 }]
  let state := { state with network := fun node => packets.filter fun packet => packet.destination == node }
  let action := Action.appendEntries 0 destination batchEnd
  let actual := CCFRaft.next state action
  let observed := if conflict then
      { actual with
        nodes := updateNode actual.nodes 0
          { (actual.nodes 0) with
            sentIndex := updateIndex (actual.nodes 0).sentIndex destination (batchEnd + 1) } }
    else actual
  let event := Json.mkObj [("kind", toJson "appendEntries"), ("source", toJson "a"),
    ("destination", toJson (nodeName destination)), ("batchEnd", toJson batchEnd)]
  Json.mkObj [
    ("expected", toJson (if decide (TraceEnabled state action) && !conflict then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (frameObservations state [0, 1, 10 ^ 30] ++ [event] ++
        frameObservations observed [0, 1, 10 ^ 30]))])]

def cases : List Json :=
  let alphabet : List (EntryContent (Fin 3) Nat) :=
    [.signature, .transaction 99, .reconfiguration {0}, .retiredCommitted {1}]
  let contents := [[]] ++ alphabet.map (fun content => [content]) ++
    alphabet.flatMap (fun left => alphabet.map fun right => [left, right])
  let matrix := contents.flatMap fun contents =>
    let log := contents.zipIdx.map fun (content, index) => { term := if index = 0 then 8 else 2, content }
    [0, 1, 10 ^ 30].flatMap fun commit =>
      [0, 1, 2, 10 ^ 30].flatMap fun previous =>
        [false, true].flatMap fun completed =>
          [false, true].map (fixture log commit previous completed {0, 1, 2} 1 .leader .active)
  let guards := [false, true].flatMap fun sourcePresent =>
    [false, true].flatMap fun destinationPresent =>
      [false, true].flatMap fun self =>
        [.follower, .candidate, .leader].flatMap fun role =>
          [.active, .retiredCommitted].flatMap fun membership =>
            [0, 1].flatMap fun previous =>
              let present := (if sourcePresent then {0} else {}) ∪ (if destinationPresent then {1} else {})
              [false, true].map (fixture [{ term := 2, content := .signature }] 0 previous false present
                (if self then 0 else 1) role membership)
  matrix ++ guards

end CCFRaft.NativeArrayAppendFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayAppendFixtures.cases).compress
