-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSignatureEncoding
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeSignatureFixtures

open Lean NativeSmt NativeEncode

def entries : List (Entry (Fin 3) Nat) :=
  [{ term := 1, content := .signature },
    { term := 2, content := .transaction (10 ^ 30) },
    { term := 3, content := .reconfiguration {0, 2} },
    { term := 4, content := .retiredCommitted {1} }]

def logs : Nat -> List (List (Entry (Fin 3) Nat))
  | 0 => [[]]
  | count + 1 => (logs count).flatMap fun earlier => entries.map fun entry => earlier ++ [entry]

def fixture (name : String) (log : List (Entry (Fin 3) Nat)) (candidate : Int) : Json :=
  let assertions : List (Term [] .bool) := [
    .equal (allocated 0) (.boolean true),
    .equal (length 0) (.integer log.length),
    .equal
      (.select (.free (.array .int (.array .int (entryTy 3))) 6) (.integer 0))
      (.snd (logTerm log)),
    signatureIndexTerm 3 0 (.integer candidate)]
  Json.mkObj [
    ("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if candidate = (maxCommittableIndex log : Int) then "sat" else "unsat"))]

def cases : List Json :=
  (List.range 4).flatMap fun count =>
    ((logs count).zipIdx).flatMap fun (log, index) =>
      (List.range (count + 3)).map fun candidate =>
        fixture s!"signature-{count}-{index}-{candidate}" log ((candidate : Int) - 1)

end CCFRaft.NativeSignatureFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeSignatureFixtures.cases).compress
