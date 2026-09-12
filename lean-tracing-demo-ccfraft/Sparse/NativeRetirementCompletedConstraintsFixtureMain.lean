-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementCompletedConstraints
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRetirementCompletedConstraintFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def fixture (index : Nat) (log : List (Entry (Fin 3) Nat)) (cap : Nat)
    (enabled : Bool) (mutation : Nat) : Except String Json := do
  let expected := retirementCompletedNodes log cap
  let observed := if mutation = 1 then
      if 0 ∈ expected then expected.erase 0 else insert 0 expected
    else expected
  let tail := entryTerm (width := 3) { term := 0, content := .retiredCommitted {0, 1, 2} }
  let raw := .store (.store (.snd (logTerm (width := 3) log))
    (.integer (-1)) tail) (.integer log.length) tail
  let count : Expr .int := .free .int 0
  let entries : Expr (.array .int (entryTy 3)) := .free _ 1
  let commit : Expr .int := .free .int 2
  let current : Expr .int := .free .int 3
  let active : Expr .bool := .free .bool 4
  let bootstrap := encodeBits (width := 3) ({0, 1} : Finset (Fin 3))
  let program : EncodeM 3 Unit := do
    assertAll [
      .equal count (.integer log.length), .equal entries raw,
      .equal commit (.integer cap),
      .equal current (.integer (if enabled then (currentConfigurationAt log cap).index else -17)),
      .equal active (.boolean enabled),
      implies active (currentConfigurationIndexTerm 3 count entries commit current)]
    let before <- get
    let completed <- retirementCompletedConstraints bootstrap active count entries commit current
    let after <- get
    unless completed = before.next && after.next = before.next + 10 &&
        after.assertions.size = before.assertions.size + 9 do
      throw "completed-retirement loop changed its allocation or assertion shape"
    assertion (.equal (.free (.bits 3) completed) (.bits (encodeBits observed)))
    if mutation = 2 then
      assertion (.equal (.free .int (before.next + 4)) (.integer 100000))
  let (_, final) <- program.run (initialEncoding 3 {0, 1})
  return Json.mkObj [
    ("name", toJson s!"completed-constraints-{index}-{cap}-{enabled}-{mutation}"),
    ("enabled", toJson enabled), ("mutation", toJson mutation),
    ("modelBits", toJson (encodeBits (width := 3) expected).toNat),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if !enabled || mutation = 0 then "sat" else "unsat"))]

def cases : Except String Json := do
  let contents : List (List (EntryContent (Fin 3) Nat)) := [
    [], [.reconfiguration {0}], [.reconfiguration {0}, .signature],
    [.reconfiguration {0}, .retiredCommitted {1}],
    [.reconfiguration {0, 1, 2}, .reconfiguration {0}, .signature, .retiredCommitted {1}],
    [.reconfiguration {0, 1, 2}, .reconfiguration {0}, .reconfiguration {0, 2}],
    [.retiredCommitted {1}], [.reconfiguration {}, .signature, .reconfiguration {1}]]
  let fixtures <- contents.zipIdx.flatMapM fun (contents, index) =>
    let log := contents.zipIdx.map fun (content, position) =>
      { term := if position % 2 = 0 then 9 else 0, content }
    ([0, 1, 2, 3, 10 ^ 30] : List Nat).flatMapM fun cap =>
      [false, true].flatMapM fun enabled =>
        (List.range 3).mapM fun mutation => fixture index log cap enabled mutation
  let mut rejected := #[]
  for kind in ["enabled", "length", "entries", "commit", "current"] do
    for symbol in [24, 25, 33, 1024] do
      let operation : EncodeM 3 Nat := retirementCompletedConstraints 0
        (if kind = "enabled" then .free .bool symbol else .boolean false)
        (if kind = "length" then .free .int symbol else .integer 0)
        (if kind = "entries" then .free _ symbol else .defaultValue _)
        (if kind = "commit" then .free .int symbol else .integer 0)
        (if kind = "current" then .free .int symbol else .integer 0)
      match operation.run (initialEncoding 3 {0, 1}) with
      | .error error =>
        rejected := rejected.push (Json.mkObj [
          ("kind", toJson kind), ("symbol", toJson symbol), ("error", toJson error)])
      | .ok _ => throw "completed-retirement loop accepted an unallocated input symbol"
  return Json.mkObj [("fixtures", toJson fixtures), ("rejected", toJson rejected)]

end CCFRaft.NativeRetirementCompletedConstraintFixtures

def main : IO Unit :=
  match CCFRaft.NativeRetirementCompletedConstraintFixtures.cases with
  | .ok result => IO.println result.compress
  | .error error => throw (IO.userError error)
