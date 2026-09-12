-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogRangeEncoding
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeLogRangeFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def cells (entries : List (Entry (Fin 3) Nat)) (noncanonical : Bool) :
    Expr (.array .int (entryTy 3)) :=
  let live := entries.zipIdx.foldl (fun array (entry, index) =>
    let term : Int := if noncanonical && entry.term == 0 then -5 else entry.term
    let content := match entry.content with
      | .transaction 0 => if noncanonical then .inr (.inl (.integer (-7))) else contentTerm entry.content
      | _ => contentTerm entry.content
    .store array (.integer index) (.pair (.integer term) content)) (.defaultValue _)
  let poison := entryTerm (width := 3) { term := 99, content := .retiredCommitted {0, 1, 2} }
  .store (.store live (.integer (-1)) poison) (.integer entries.length) poison

def predicate {context : List Ty} (kind : Nat)
    (oldLength previous : Term context .int) : Term context .bool :=
  let oldEntries := .free (.array .int (entryTy 3)) 0
  let payloadEntries := .free (.array .int (entryTy 3)) 1
  let payloadLength := .free .int 4
  if kind = 0 then
    appendAlreadyDoneTerm 3 oldLength oldEntries payloadLength payloadEntries previous
  else if kind = 1 then
    appendTermConflictTerm 3 oldLength oldEntries payloadLength payloadEntries previous
  else
    appendNoConflictExtensionTerm 3 oldLength oldEntries payloadLength payloadEntries previous

def fixture (name : String) (old payload : List (Entry (Fin 3) Nat))
    (previous kind : Nat) (oldRaw payloadRaw nested claimed : Bool) : Json :=
  let row : NodeState (Fin 3) Nat := { (freshNodeState : NodeState (Fin 3) Nat) with log := old }
  let request : AppendEntriesRequest (Fin 3) Nat :=
    { term := 0, source := 0, destination := 1, prevLogIndex := previous, prevLogTerm := 0,
      leaderCommit := 0, entries := payload }
  let actual := if kind = 0 then decide (alreadyDone row request)
    else if kind = 1 then decide (hasTermConflict row request)
    else decide (noConflictExtension row request)
  let query : Expr .bool := if nested then
      .forall_ .int (implies (.equal (.bound .here) (.integer previous))
        (.forall_ .int (implies (.equal (.bound .here) (.integer old.length))
          (predicate kind (.bound .here) (.bound (.there .here))))))
    else predicate kind (.free .int 3) (.free .int 5)
  let assertions : List (Expr .bool) := [
    .equal (.free (.array .int (entryTy 3)) 0) (cells old oldRaw),
    .equal (.free (.array .int (entryTy 3)) 1) (cells payload payloadRaw),
    .equal (.free .int 3) (.integer old.length),
    .equal (.free .int 4) (.integer payload.length),
    .equal (.free .int 5) (.integer previous),
    if claimed then query else .not query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if claimed == actual then "sat" else "unsat"))]

def cases : List Json :=
  let signature : Entry (Fin 3) Nat := { term := 0, content := .signature }
  let transaction : Entry (Fin 3) Nat := { term := 0, content := .transaction 0 }
  let laterTransaction : Entry (Fin 3) Nat := { term := 2, content := .transaction 7 }
  let laterSignature : Entry (Fin 3) Nat := { term := 1, content := .signature }
  let configuration : Entry (Fin 3) Nat := { term := 0, content := .reconfiguration {0, 2} }
  let retired : Entry (Fin 3) Nat := { term := 0, content := .retiredCommitted {1} }
  let oldLogs := [[], [signature], [transaction], [signature, laterTransaction], [signature, configuration, retired]]
  let payloads := [[], [signature], [transaction], [signature, laterTransaction, laterSignature],
    [transaction, laterSignature]]
  oldLogs.zipIdx.flatMap fun (old, oldIndex) =>
    payloads.zipIdx.flatMap fun (payload, payloadIndex) =>
      ([0, 1, 2, 10 ^ 30] : List Nat).flatMap fun previous =>
        [false, true].flatMap fun oldRaw =>
          [false, true].flatMap fun payloadRaw =>
            [false, true].flatMap fun nested =>
              (List.range 3).flatMap fun kind =>
                [false, true].map fun claimed =>
                  fixture s!"log-range-{oldIndex}-{payloadIndex}-{previous}-{oldRaw}-{payloadRaw}-{nested}-{kind}-{claimed}"
                    old payload previous kind oldRaw payloadRaw nested claimed

end CCFRaft.NativeLogRangeFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeLogRangeFixtures.cases).compress
