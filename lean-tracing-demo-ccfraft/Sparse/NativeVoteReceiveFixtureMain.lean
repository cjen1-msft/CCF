-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveGuardEncoding
import Sparse.NativeScript

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeVoteReceiveFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def fixture (index : Nat) (log : List (Entry (Fin 3) Nat))
    (requestTerm summaryTerm summaryIndex : Nat) (chosen : Option (Fin 3))
    (source destination : Fin 3) (agrees : Bool) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      currentTerm := 5, votedFor := chosen, log, commitIndex := 10 ^ 30 }
  let request : RequestVoteRequest (Fin 3) :=
    { term := requestTerm, lastCommittableTerm := summaryTerm,
      lastCommittableIndex := summaryIndex, source, destination }
  let result := handleRequestVoteRequest? row request
  let columns : Columns := { currentTerm := 25, votedFor := 26 }
  let packet : Expr (packetTy 3) := .free (packetTy 3) 24
  let signature : Expr .int := .free .int 27
  let expected := match result with
    | some (_, response) => packetTerm (width := 3) (.requestVoteResponse response)
    | none => packetTerm (width := 3) (.requestVoteResponse
        { term := 5, voteGranted := false, source := destination, destination := source })
  let equality : Expr .bool := .equal (voteResponseTerm (width := 3) columns destination packet signature) expected
  let assertions : List (Expr .bool) := [
    .equal (allocated destination.val) (.boolean true),
    .equal (read 5 destination.val (.integer 0)) (.integer 99),
    .equal (read 25 destination.val (.integer 0)) (.integer 5),
    .equal (read 26 destination.val (.inl .unit)) (optionalTerm (fun node : Fin 3 => (node.val : Int)) chosen),
    .equal (length destination.val) (.integer log.length),
    .equal (commit destination.val) (.integer row.commitIndex),
    .equal (.select (.free (.array .int (.array .int (entryTy 3))) 6) (.integer destination.val)) (.snd (logTerm log)),
    .equal packet (packetTerm (width := 3) (.requestVoteRequest request)),
    signatureIndexTerm 3 destination.val signature,
    isVoteRequestTerm packet,
    .le (.fst (.fst packet)) (read columns.currentTerm destination.val (.integer 0)),
    if agrees then equality else .not equality]
  Json.mkObj [("name", toJson s!"vote-receive-{index}-{requestTerm}-{summaryTerm}-{summaryIndex}-{chosen.map Fin.val}-{source.val}-{destination.val}-{agrees}"),
    ("script", toJson (renderScript assertions)),
    ("expected", toJson (if result.isSome && agrees then "sat" else "unsat"))]

def responseCases : List Json :=
  let logs : List (List (Entry (Fin 3) Nat)) :=
    [[], [{ term := 3, content := .signature }],
      [{ term := 7, content := .transaction 99 }],
      [{ term := 3, content := .signature }, { term := 1, content := .signature }]]
  logs.zipIdx.flatMap fun (log, index) =>
    [4, 5, 6].flatMap fun term =>
      [0, 1, 4].flatMap fun summaryTerm =>
        [0, 1, 10 ^ 30].flatMap fun summaryIndex =>
          [none, some (0 : Fin 3), some 2].flatMap fun chosen =>
            ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
              [false, true].map (fixture index log term summaryTerm summaryIndex chosen source destination)

def guardFixture (sourcePresent destinationPresent preVote : Bool)
    (term count : Nat) (recipient : Fin 3) (head : Int) : Json :=
  let request : RequestVoteRequest (Fin 3) :=
    { term, source := 0, destination := recipient, lastCommittableTerm := 0, lastCommittableIndex := 0 }
  let message : Message (Fin 3) Nat := if preVote then .requestPreVote
    { term, source := 0, destination := recipient, lastCommittableTerm := 0, lastCommittableIndex := 0 }
    else .requestVoteRequest request
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset
        (Finset.univ.filter fun node => if node = 0 then sourcePresent else if node = 1 then destinationPresent else false)
        (fun _ => { (freshNodeState : NodeState (Fin 3) Nat) with currentTerm := 5 })
      network := fun node => if node = 1 then List.replicate count message else []
      hasJoined := {}, submittedTxIds := {} }
  let assertions : List (Expr .bool) := [
    .equal (allocated 0) (.boolean sourcePresent),
    .equal (allocated 1) (.boolean destinationPresent),
    .equal (.select (.free (.array .int .int) 5) (.integer 1)) (.integer 5),
    .equal (.select (.select (.free (.array .int (.array .int .int)) 21) (.integer 1)) (.integer 0)) (.integer count),
    .equal (.select (.select (.free (.array .int (.array .int .int)) 22) (.integer 1)) (.integer 0)) (.integer head),
    .equal (.select (queueCellsTerm (width := 3) 23 (.integer 1) (.integer 0)) (.integer head.toNat))
      (packetTerm (width := 3) message)]
  Json.mkObj [("name", toJson s!"vote-receive-guard-{sourcePresent}-{destinationPresent}-{preVote}-{term}-{count}-{recipient.val}-{head}"),
    ("script", toJson (renderScript (assertions ++ voteReceiveGuards (width := 3) {} 0 1))),
    ("expected", toJson (if !preVote && decide (Enabled state (.receive 0 1)) then "sat" else "unsat"))]

def cases : List Json :=
  responseCases ++ [false, true].flatMap fun sourcePresent =>
    [false, true].flatMap fun destinationPresent =>
      [false, true].flatMap fun preVote =>
        [4, 5, 6].flatMap fun term =>
          [0, 1, 2].flatMap fun count =>
            ([0, 1] : List (Fin 3)).flatMap fun recipient =>
              ([-3, 0, 10 ^ 30] : List Int).map
                (guardFixture sourcePresent destinationPresent preVote term count recipient)

end CCFRaft.NativeVoteReceiveFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeVoteReceiveFixtures.cases).compress
