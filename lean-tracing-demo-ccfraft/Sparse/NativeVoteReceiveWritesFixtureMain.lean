-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveWritesEncoding
import Sparse.NativeQueueHead
import Sparse.NativeFrameEncode
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeVoteReceiveWriteFixtures

open Lean NativeSmt NativeEncode NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def observations (state : State (Fin 3) Nat) (source destination : Fin 3) (conflict : Bool) : List Json :=
  (List.finRange 3).flatMap (fun node =>
    Json.mkObj [("kind", toJson "allocated"), ("node", toJson (nodeName node)),
      ("value", toJson (decide (state.allocated node)))] :: nodeObservations node (state.nodes node)) ++
  globalObservations state [] ++
  (List.finRange 3).flatMap fun receiver =>
    (List.finRange 3).flatMap fun sender =>
      let packets := Sparse.Queue.partition sender (state.network receiver)
      let length := packets.length + if conflict && receiver == source && sender == destination then 1 else 0
      Json.mkObj [("kind", toJson "queueLength"), ("source", toJson (nodeName sender)),
        ("destination", toJson (nodeName receiver)), ("value", toJson length)] ::
      packets.zipIdx.map fun (packet, index) =>
        Json.mkObj [("kind", toJson "queuePoint"), ("source", toJson (nodeName sender)),
          ("destination", toJson (nodeName receiver)), ("index", toJson index), ("value", messageJson packet)]

def decodeObservations (items : List Json) : Except String (Array (FrameInstruction 3)) := do
  items.toArray.mapM (decodeFrameInstruction 3 #["a", "b", "c"])

def fixture (index : Nat) (log : List (Entry (Fin 3) Nat)) (term : Nat)
    (chosen : Option (Fin 3)) (source destination : Fin 3) (sourcePresent conflict : Bool) :
    Except String Json := do
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      currentTerm := 5, log, commitIndex := 10 ^ 30, votedFor := chosen }
  let request : RequestVoteRequest (Fin 3) :=
    { term, source, destination, lastCommittableTerm := 4, lastCommittableIndex := 10 ^ 30 }
  let (_, response) <- match handleRequestVoteRequest? row request with
    | some result => pure result
    | none => throw "vote fixture request is disabled"
  let packets : List (Message (Fin 3) Nat) := [
    .requestVoteRequest request, .requestVoteRequest request, .requestVoteResponse response,
    .proposeVoteRequest { term := 2, source := 2, destination }]
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (if sourcePresent then Finset.univ else {destination}) fun _ => row
      network := fun node => packets.filter fun packet => packet.destination == node
      hasJoined := {0, 2}, submittedTxIds := {}, preVoteStatus := fun _ => .enabled,
      retirementCompleted := fun _ => {1, 2} }
  unless decide (Enabled state (.receive source destination)) do
    throw "vote fixture receive is disabled"
  let before <- decodeObservations (observations state source destination false)
  let after <- decodeObservations (observations (CCFRaft.next state (.receive source destination))
    source destination conflict)
  let program : EncodeM 3 Unit := do
    initialFrameDomains 3
    for receiver in List.finRange 3 do
      for sender in List.finRange 3 do
        assertion (.equal
          (.select (.select (.free (.array .int (.array .int .int)) 22) (.integer receiver.val)) (.integer sender.val))
          (.integer (if index % 4 < 2 then -3 else 10 ^ 30)))
    for item in before do frameInstruction item
    let columns := (<- get).toColumns
    let signature <- fresh
    assertion (signatureIndexTerm 3 destination.val (.free .int signature))
    voteReceiveWrites source destination (queueHeadPacketTerm columns source destination) (.free .int signature)
    for item in after do frameInstruction item
  let (_, final) <- program.run (initialEncoding 3 {0, 1})
  return Json.mkObj [("name", toJson s!"vote-receive-writes-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if conflict then "unsat" else "sat"))]

def cases : Except String Json := do
  let logs : List (List (Entry (Fin 3) Nat)) := [
    [], [{ term := 3, content := .signature }], [{ term := 7, content := .transaction 99 }],
    [{ term := 3, content := .signature }, { term := 1, content := .signature }]]
  let parameters := logs.flatMap fun log =>
    [4, 5].flatMap fun term =>
      [none, some (0 : Fin 3), some 2].flatMap fun chosen =>
        ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
          [false, true].flatMap fun sourcePresent =>
            [false, true].map fun conflict => (log, term, chosen, source, destination, sourcePresent, conflict)
  let fixtures <- parameters.zipIdx.mapM fun ((log, term, chosen, source, destination, sourcePresent, conflict), index) =>
    fixture index log term chosen source destination sourcePresent conflict
  let mut rejected := #[]
  for (packetId, signatureId) in [(24, 23), (23, 24), (24, 24), (1024, 23)] do
    match (voteReceiveWrites (width := 3) 0 1 (.free (packetTy 3) packetId) (.free .int signatureId)).run
        (initialEncoding 3 {0, 1}) with
    | .error error =>
      rejected := rejected.push (Json.mkObj [("packet", toJson packetId), ("signature", toJson signatureId),
        ("error", toJson error)])
    | .ok _ => throw "vote receive writes accepted an unallocated symbol"
  return Json.mkObj [("fixtures", toJson fixtures), ("rejected", toJson rejected)]

end CCFRaft.NativeVoteReceiveWriteFixtures

def main : IO Unit :=
  match CCFRaft.NativeVoteReceiveWriteFixtures.cases with
  | .ok result => IO.println result.compress
  | .error error => throw (IO.userError error)
