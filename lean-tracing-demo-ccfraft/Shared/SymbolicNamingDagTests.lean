-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNaming
import Shared.SymbolicSmt
import Shared.SymbolicEvalMemo

set_option autoImplicit false

namespace Symbolic.NamingDagTests

private def history (depth : Nat) : Expr .nat :=
  ((List.range depth).foldl (fun (prior, current) index =>
    (current, Expr.ite (.eq (.unknown (index + 2)) (.nat 0)) current prior))
    (Expr.unknown 0, Expr.unknown 1)).1

private def doubled : Nat → Expr .nat
  | 0 => .unknown 0
  | depth + 1 =>
      let value := doubled depth
      .ite (.eq (.unknown 1) (.nat 0)) value value

theorem doubled_correct (assignment : Assignment) (depth : Nat) :
    (doubled depth).eval assignment = assignment 0 := by
  induction depth <;> simp_all [doubled, Expr.eval]

private def declarations {s : Ty} (renamed : Expr s) : IO Nat := do
  match prepareGroups [[], [], [.eq renamed renamed]] with
  | .ok (_, printed) => pure printed.stateDeclarations.size
  | .error message => throw (IO.userError message)

private def checkFields : IO Unit := do
  let after := history 12
  for (first, expected) in [(Expr.unknown 1000, 4), (Expr.unknown 0, 3)] do
    let (renamed, stats) := nameChangedWithStats 2
      (.pair first (.unknown 1000)) (.pair after after)
    unless stats.names == expected && (← declarations renamed) == expected do
      throw (IO.userError "writer definitions leaked between corresponding fields")
  let (copied, stats) := nameChangedWithStats 2
    (.pair after (.unknown 1000)) (.pair after after)
  unless stats.names == 2 && (← declarations copied) == 2 do
    throw (IO.userError "copying a shared DAG from another field lost its writer")
  IO.println "field-local names and cross-field copies passed"

private def concealed (value : Expr .nat) : Expr .nat :=
  .add (.nat 0) (.add (.nat 0) (.add (.nat 0) (.add (.nat 0) value)))

private def checkCollisions : IO Unit := do
  let left := concealed (.unknown 0)
  let right := concealed (.unknown 1)
  unless left.memoKey == right.memoKey do
    throw (IO.userError "fixture does not collide")
  let original := Expr.ite (.eq (.unknown 2) (.nat 0)) left right
  let (renamed, stats) := nameChangedWithStats 2 (.unknown 1000) original
  unless stats.names == 2 && (← declarations renamed) == 2 do
    throw (IO.userError "hash collision merged distinct alternatives")
  for assignment in [fun index => index, fun index => if index = 2 then 0 else index] do
    unless renamed.evalMemo assignment == original.evalMemo assignment do
      throw (IO.userError "colliding alternatives changed evaluation")
  let emptyNats : Expr (.seq .nat) := .nil
  let emptyBools : Expr (.seq .bool) := .nil
  unless emptyNats.memoKey == emptyBools.memoKey do
    throw (IO.userError "fixture types do not collide")
  let (typed, stats) := nameChangedWithStats 2
    (.pair (.ofList [.nat 1]) (.ofList [.bool true])) (.pair emptyNats emptyBools)
  unless stats.names == 2 && (← declarations typed) == 2 &&
      typed.evalMemo (fun _ => 0) == ([], []) do
    throw (IO.userError "typed cache collision changed payloads or ownership")
  IO.println "exact syntax and type collision checks passed"

private def checkDoubled (enforce : Bool) : IO Unit := do
  for depth in (if enforce then [4, 8, 12, 24, 48] else [4, 8, 12]) do
    let original := doubled depth
    let (renamed, stats) := nameChangedWithStats 2 (.unknown 1000) original
    let names ← declarations renamed
    IO.println s!"doubled depth={depth} names={names} choices={stats.choiceVisits} leaves={stats.leafVisits}"
    if enforce then
      unless names == 1 && stats.names == 1 &&
          stats.choiceVisits ≤ depth + 2 && stats.leafVisits == 1 do
        throw (IO.userError s!"depth {depth}: identical-branch DAG expanded before collapse")
      unless @decide _ (renamed.sharedDecEq (.named 2 0 (.unknown 0))) do
        throw (IO.userError s!"depth {depth}: identical branches retained spurious dependencies")
      for assignment in [fun _ => 0, fun index => index + 7, fun index => index % 2] do
        unless renamed.evalMemo assignment == original.evalMemo assignment do
          throw (IO.userError s!"depth {depth}: identical-branch naming changed evaluation")

def run (enforce : Bool) : IO Unit := do
  for depth in (if enforce then [4, 8, 12, 24, 48] else [4, 8, 12]) do
    let original := history depth
    let (renamed, stats) := nameChangedWithStats 2 (.unknown 1000) original
    let names ← declarations renamed
    IO.println s!"overlapping depth={depth} names={names} choices={stats.choiceVisits} leaves={stats.leafVisits}"
    if enforce then
      unless names == 2 && stats.names == 2 do
        throw (IO.userError s!"depth {depth}: shared alternatives acquired duplicate names")
      unless stats.choiceVisits ≤ depth + 2 && stats.leafVisits ≤ depth + 1 do
        throw (IO.userError s!"depth {depth}: naming traversed a shared subtree repeatedly")
      for assignment in [fun _ => 0, fun index => index, fun index => index % 2] do
        unless renamed.evalMemo assignment == original.evalMemo assignment do
          throw (IO.userError s!"depth {depth}: naming changed evaluation")
  checkDoubled enforce
  if enforce then
    checkFields
    checkCollisions

end Symbolic.NamingDagTests

run_cmd do
  for theoremName in [``Symbolic.nameChanged_correct, ``Symbolic.nameChangedWithStats_correct,
      ``Symbolic.NamingDagTests.doubled_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [] => Symbolic.NamingDagTests.run true
  | ["--counts"] => Symbolic.NamingDagTests.run false
  | _ => throw (IO.userError "usage: SymbolicNamingDagTests.lean [--counts]")
