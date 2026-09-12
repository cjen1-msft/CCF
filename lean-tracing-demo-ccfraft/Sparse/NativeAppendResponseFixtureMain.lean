-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendResponseTerm
import Sparse.NativePacketTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendResponseFixtures

open Lean NativeSmt NativeEncode

def observed (response : AppendEntriesResponse (Fin 3)) (mutation : Nat) :
    Message (Fin 3) Nat :=
  if mutation = 1 then .appendEntriesResponse { response with term := response.term + 1 }
  else if mutation = 2 then .appendEntriesResponse { response with lastLogIndex := response.lastLogIndex + 1 }
  else if mutation = 3 then .appendEntriesResponse { response with success := !response.success }
  else if mutation = 4 then .appendEntriesResponse { response with source := response.source + 1 }
  else if mutation = 5 then .appendEntriesResponse { response with destination := response.destination + 1 }
  else if mutation = 6 then
    .requestVoteResponse
      { term := response.term, source := response.source, destination := response.destination,
        voteGranted := response.success }
  else .appendEntriesResponse response

def predicate {context : List Ty} (source destination : Fin 3)
    (term : Term context .int) (success : Term context .bool) (lastIndex : Term context .int)
    (expected : Message (Fin 3) Nat) : Term context .bool :=
  .equal (appendResponseTerm 3 source destination term success lastIndex) (packetTerm expected)

def fixture (name : String) (source destination : Fin 3)
    (term lastIndex mutation : Nat) (success nested : Bool) : Json :=
  let response : AppendEntriesResponse (Fin 3) :=
    { term, source, destination, success, lastLogIndex := lastIndex }
  let expected := observed response mutation
  let query : Expr .bool := if nested then
      .forall_ .bool (implies (.equal (.bound .here) (.boolean success))
        (.forall_ .int (implies (.equal (.bound .here) (.integer term))
          (.forall_ .int (implies (.equal (.bound .here) (.integer lastIndex))
            (predicate source destination (.bound (.there .here))
              (.bound (.there (.there .here))) (.bound .here) expected))))))
    else predicate source destination (.free .int 0) (.free .bool 1) (.free .int 2) expected
  let assertions : List (Expr .bool) := [
    .equal (.free .int 0) (.integer term),
    .equal (.free .bool 1) (.boolean success),
    .equal (.free .int 2) (.integer lastIndex), query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def cases : List Json :=
  ([(0, 1), (1, 0), (2, 2)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
    ([0, 9, 10 ^ 30] : List Nat).flatMap fun term =>
      ([0, 1, 10 ^ 30] : List Nat).flatMap fun lastIndex =>
        [false, true].flatMap fun success =>
          [false, true].flatMap fun nested =>
            (List.range 7).map fun mutation =>
              fixture s!"append-response-{source.val}-{destination.val}-{term}-{lastIndex}-{success}-{nested}-{mutation}"
                source destination term lastIndex mutation success nested

end CCFRaft.NativeAppendResponseFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeAppendResponseFixtures.cases).compress
