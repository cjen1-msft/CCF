-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementEncoding
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRetirementFixtures

open Lean NativeSmt NativeEncode

def logs : Nat -> List (List (Entry (Fin 3) Nat))
  | 0 => [[]]
  | count + 1 =>
    (logs count).flatMap fun earlier =>
      [.signature, .transaction 0, .reconfiguration {0}, .retiredCommitted {1}].map fun content =>
        earlier ++ [{ term := 0, content }]

def rawEntry (entry : Entry (Fin 3) Nat) : Expr (entryTy 3) :=
  .pair (.integer (-5)) (match entry.content with
    | .transaction _ => .inr (.inl (.integer (-7)))
    | _ => contentTerm entry.content)

def predicate {context : List Ty} (kind : Nat) (row : Term context .int) : Term context .bool :=
  let entries := .select (.free (.array .int (.array .int (entryTy 3))) 17) row
  if kind = 0 then signatureAfterRetirementTerm 3 (.free .int 1) entries row (.free .int 2)
  else retiredRecordTerm 3 (.free .int 1) entries (if kind = 1 then 0 else 1) (.free .int 2)

def fixture (name : String) (log : List (Entry (Fin 3) Nat))
    (kind retirement : Nat) (candidate : Int) (nested : Bool) : Json :=
  let expected := (if kind = 0 then retirementCommittableIndexInLog log retirement
    else retiredCommittedIndexInLog (if kind = 1 then 0 else 1) log).map (· - 1)
  let cells : Expr (.array .int (entryTy 3)) := log.zipIdx.foldl
    (fun cells (entry, index) => .store cells (.integer index) (rawEntry entry)) (.defaultValue _)
  let tail := entryTerm (width := 3) { term := 0, content := .retiredCommitted {0, 1} }
  let cells := .store (.store cells (.integer (-1)) tail) (.integer log.length) tail
  let matrix := .store (.defaultValue (.array .int (.array .int (entryTy 3)))) (.integer retirement) cells
  let query : Expr .bool := if nested then
      .forall_ .int (implies (.equal (.bound .here) (.integer retirement)) (predicate kind (.bound .here)))
    else predicate kind (.integer retirement)
  let assertions : List (Expr .bool) := [
    .equal (.free (.array .int (.array .int (entryTy 3))) 17) matrix,
    .equal (.free .int 1) (.integer log.length),
    .equal (.free .int 2) (.integer candidate), query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if candidate = firstMatchValue expected then "sat" else "unsat"))]

def cases : List Json :=
  (List.range 3).flatMap fun count =>
    ((logs count).zipIdx).flatMap fun (log, index) =>
      ([(0, 0), (0, 1), (0, 10 ^ 30), (1, 7), (2, 7)] : List (Nat × Nat)).flatMap fun (kind, retirement) =>
        (((List.range (count + 4)).map fun candidate => (candidate : Int) - 2) ++ [10 ^ 30]).flatMap fun candidate =>
          [false, true].map fun nested =>
            fixture s!"retirement-scan-{count}-{index}-{kind}-{retirement}-{candidate}-{nested}"
              log kind retirement candidate nested

end CCFRaft.NativeRetirementFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeRetirementFixtures.cases).compress
