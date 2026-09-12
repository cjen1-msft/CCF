-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogSpliceEncoding
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeLogSpliceFixtures

open Lean NativeSmt NativeEncode

def rawEntry (noncanonical : Bool) (entry : Entry (Fin 3) Nat) : Expr (entryTy 3) :=
  if noncanonical && entry.term == 0 then
    .pair (.integer (-5)) (match entry.content with
      | .transaction 0 => .inr (.inl (.integer (-7)))
      | _ => contentTerm entry.content)
  else entryTerm entry

def cells (entries : List (Expr (entryTy 3))) : Expr (.array .int (entryTy 3)) :=
  let poison := entryTerm (width := 3) { term := 99, content := .retiredCommitted {0, 1, 2} }
  let initial := .store (.defaultValue (.array .int (entryTy 3))) (.integer (-1)) poison
  let live := entries.zipIdx.foldl
    (fun array (entry, index) => .store array (.integer index) entry) initial
  .store live (.integer entries.length) poison

def predicate {context : List Ty} (oldLength previous : Term context .int)
    (expectedLength : Nat) : Term context .bool :=
  all [
    .equal (logSpliceLength oldLength (.free .int 4) previous) (.integer expectedLength),
    logSpliceTerm 3 oldLength (.free (.array .int (entryTy 3)) 0)
      (.free .int 4) (.free (.array .int (entryTy 3)) 1) previous
      (.free (.array .int (entryTy 3)) 2)]

def fixture (name : String) (old payload : List (Entry (Fin 3) Nat))
    (previous : Nat) (noncanonical nested : Bool) (mutation : Nat) : Json :=
  let result := old.take previous ++ payload
  let oldRaw := old.map (rawEntry noncanonical)
  let payloadRaw := payload.map (rawEntry noncanonical)
  let output := cells (oldRaw.take previous ++ payloadRaw)
  let different := entryTerm (width := 3) { term := 1000, content := .signature }
  let output := if mutation = 1 then .store output (.integer 0) different
    else if mutation = 2 then .store output (.integer (-1)) different
    else if mutation = 3 then .store output (.integer result.length) different
    else output
  let expectedLength := if mutation = 4 then result.length + 1 else result.length
  let query : Expr .bool := if nested then
      .forall_ .int (implies (.equal (.bound .here) (.integer previous))
        (.forall_ .int (implies (.equal (.bound .here) (.integer old.length))
          (predicate (.bound .here) (.bound (.there .here)) expectedLength))))
    else predicate (.free .int 3) (.free .int 5) expectedLength
  let assertions : List (Expr .bool) := [
    .equal (.free (.array .int (entryTy 3)) 0) (cells oldRaw),
    .equal (.free (.array .int (entryTy 3)) 1) (cells payloadRaw),
    .equal (.free (.array .int (entryTy 3)) 2) output,
    .equal (.free .int 3) (.integer old.length),
    .equal (.free .int 4) (.integer payload.length),
    .equal (.free .int 5) (.integer previous), query]
  let accepted := mutation != 4 && !(mutation == 1 && !result.isEmpty)
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if accepted then "sat" else "unsat"))]

def cases : List Json :=
  let signature : Entry (Fin 3) Nat := { term := 0, content := .signature }
  let transaction : Entry (Fin 3) Nat := { term := 0, content := .transaction 0 }
  let configuration : Entry (Fin 3) Nat := { term := 2, content := .reconfiguration {0, 2} }
  let retired : Entry (Fin 3) Nat := { term := 0, content := .retiredCommitted {1} }
  let oldLogs := [[], [signature], [transaction, configuration], [signature, retired, transaction]]
  let payloads := [[], [signature], [transaction], [configuration, retired, signature]]
  oldLogs.zipIdx.flatMap fun (old, oldIndex) =>
    payloads.zipIdx.flatMap fun (payload, payloadIndex) =>
      ([0, 1, 2, 10 ^ 30] : List Nat).flatMap fun previous =>
        [false, true].flatMap fun noncanonical =>
          [false, true].flatMap fun nested =>
            (List.range 5).map fun mutation =>
              fixture s!"log-splice-{oldIndex}-{payloadIndex}-{previous}-{noncanonical}-{nested}-{mutation}"
                old payload previous noncanonical nested mutation

end CCFRaft.NativeLogSpliceFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeLogSpliceFixtures.cases).compress
