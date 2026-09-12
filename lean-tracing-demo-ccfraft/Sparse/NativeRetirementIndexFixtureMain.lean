-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementIndexEncoding
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRetirementIndexFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def candidates (expected : Option Nat) : List Int :=
  let selected := firstMatchValue expected
  [-2, -1, selected, selected - 1, selected + 1, 10 ^ 30].eraseDups

def rawEntry (entry : Entry (Fin 3) Nat) : Expr (entryTy 3) :=
  .pair (.integer (if entry.term = 0 then -5 else entry.term))
    (match entry.content with
      | .transaction 0 => .inr (.inl (.integer (-7)))
      | _ => contentTerm entry.content)

def predicate {context : List Ty} (node : Fin 3)
    (row first : Term context .int) : Term context .bool :=
  retirementIndexTerm 3 (encodeBits ({0, 1} : Finset (Fin 3)))
    (.free .int 1) (.select (.free (.array .int (.array .int (entryTy 3))) 17) row)
    node first (.free .int 2)

def fixture (name : String) (log : List (Entry (Fin 3) Nat))
    (node : Fin 3) (first retirement : Int) (nested : Bool) : Json :=
  let included := ((allConfigurations log).find?
    (fun configuration => decide (node ∈ configuration.nodes))).map Configuration.index
  let retired := retirementIndexInLog node log
  let cells : Expr (.array .int (entryTy 3)) := log.zipIdx.foldl
    (fun cells (entry, index) => .store cells (.integer index) (rawEntry entry)) (.defaultValue _)
  let tail := entryTerm (width := 3) { term := 0, content := .reconfiguration {} }
  let cells := .store (.store cells (.integer (-1)) tail) (.integer log.length) tail
  let matrix := .store (.defaultValue (.array .int (.array .int (entryTy 3)))) (.integer 7) cells
  let query : Expr .bool := if nested then
      .forall_ .int (implies (.equal (.bound .here) (.integer 7))
        (.forall_ .int (implies (.equal (.bound .here) (.integer first))
          (predicate node (.bound (.there .here)) (.bound .here)))))
    else predicate node (.integer 7) (.free .int 3)
  let assertions : List (Expr .bool) := [
    .equal (.free (.array .int (.array .int (entryTy 3))) 17) matrix,
    .equal (.free .int 1) (.integer log.length),
    .equal (.free .int 2) (.integer retirement),
    .equal (.free .int 3) (.integer first), query]
  let accepted := first == firstMatchValue included && retirement == firstMatchValue retired
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if accepted then "sat" else "unsat"))]

def cases : List Json :=
  let contents : List (List (EntryContent (Fin 3) Nat)) := [
    [],
    [.signature],
    [.transaction 0],
    [.retiredCommitted {0, 1, 2}],
    [.reconfiguration {}],
    [.reconfiguration {2}],
    [.reconfiguration {0, 1, 2}],
    [.signature, .reconfiguration {0}, .retiredCommitted {1}, .reconfiguration {0, 1, 2}],
    [.reconfiguration {2}, .reconfiguration {}, .reconfiguration {0, 1, 2}, .reconfiguration {0}],
    [.reconfiguration {}, .reconfiguration {2}, .signature, .reconfiguration {0}],
    [.reconfiguration {0, 2}, .signature, .reconfiguration {0}, .reconfiguration {2},
      .reconfiguration {}, .reconfiguration {0, 1, 2}],
    [.reconfiguration {0}, .reconfiguration {0, 1}, .reconfiguration {0}, .reconfiguration {1},
      .reconfiguration {0, 1, 2}]]
  contents.zipIdx.flatMap fun (entries, index) =>
    let log := entries.zipIdx.map fun (content, position) =>
      { term := if position % 2 = 0 then 5 else 0, content }
    (List.finRange 3).flatMap fun node =>
      let included := ((allConfigurations log).find?
        (fun configuration => decide (node ∈ configuration.nodes))).map Configuration.index
      (candidates included).flatMap fun first =>
        (candidates (retirementIndexInLog node log)).flatMap fun retirement =>
          [false, true].map fun nested =>
            fixture s!"retirement-index-{index}-{node.val}-{first}-{retirement}-{nested}"
              log node first retirement nested

end CCFRaft.NativeRetirementIndexFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeRetirementIndexFixtures.cases).compress
