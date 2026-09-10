-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalizeMemo
import Shared.SymbolicSmt

set_option autoImplicit false

namespace Symbolic.MemoSelectorTests

private def condition : Expr .bool := .eq (.unknown 0) (.nat 0)
private def pair : Expr (.pair .nat .bool) :=
  .ite condition (.pair (.nat 7) (.bool true)) (.pair (.nat 8) (.bool false))
private def sum : Expr (.sum .nat .bool) :=
  .ite condition (.inl (.nat 9)) (.inr (.bool false))
private def sequence : Expr (.seq .nat) := .ofList [.nat 7, .nat 8, .nat 9]

private def equivalentSyntax {s : Ty} (a b : Expr s) : Bool :=
  @decide (a = b) (a.sharedDecEq b)

#guard equivalentSyntax pair.fst.normalizeMemo (.ite condition (.nat 7) (.nat 8))
#guard equivalentSyntax pair.snd.normalizeMemo (.ite condition (.bool true) (.bool false))
#guard equivalentSyntax sum.isLeft.normalizeMemo (.ite condition (.bool true) (.bool false))
#guard equivalentSyntax (sum.leftD (.nat 0)).normalizeMemo (.ite condition (.nat 9) (.nat 0))
#guard equivalentSyntax (sum.rightD (.bool true)).normalizeMemo
  (.ite condition (.bool true) (.bool false))
#guard equivalentSyntax (Expr.append sequence sequence).length.normalizeMemo (.nat 6)
#guard equivalentSyntax (Expr.drop (.nat 1) sequence).length.normalizeMemo (.nat 2)

private def queries : List ((s : Ty) × Expr s) :=
  [⟨_, pair.fst⟩, ⟨_, pair.snd⟩, ⟨_, sum.isLeft⟩,
   ⟨_, sum.leftD (.nat 0)⟩, ⟨_, sum.rightD (.bool true)⟩,
   ⟨_, sequence.length⟩,
   ⟨_, (Expr.append sequence sequence).length⟩,
   ⟨_, (Expr.take (.unknown 0) sequence).length⟩,
   ⟨_, (Expr.drop (.unknown 0) sequence).length⟩,
   ⟨_, (Expr.ite condition sequence (.nil : Expr (.seq .nat))).length⟩,
   ⟨_, sequence.get? (.unknown 0)⟩,
   ⟨_, (Expr.take (.unknown 0) sequence).get? (.unknown 1)⟩,
   ⟨_, (Expr.drop (.unknown 0) sequence).get? (.unknown 1)⟩,
   ⟨_, (Expr.ite condition sequence .nil).get? (.unknown 1)⟩,
   ⟨_, (Expr.append sequence sequence).get? (.unknown 1)⟩,
   ⟨_, (sequence.get? (.unknown 1)).rightD (.nat 0)⟩,
   ⟨_, (sequence.get? (.unknown 1)).isLeft⟩]

#guard [0, 1, 2, 3, 9].all fun first => [0, 1, 2, 3, 9].all fun second =>
  let assignment := fun i => if i = 0 then first else second
  queries.all fun ⟨_, expression⟩ =>
    decide (expression.normalizeMemo.eval assignment = expression.eval assignment) &&
    decide (expression.normalizeMemo.eval assignment = expression.normalize.eval assignment)

-- Cache entries from helper recursion and root normalization are interchangeable.
#guard [0, 1, 9].all fun value =>
  let assignment := fun _ => value
  let normalizeAll : StateM Expr.NormalizationState (List Bool) := do
    queries.mapM fun ⟨_, expression⟩ => do
      let normalized ← expression.normalizeMemoM
      return decide (normalized.eval assignment = expression.eval assignment)
  ((normalizeAll *> normalizeAll).run {}).1.all id

private def namedPair : Expr (.pair .nat .bool) := .named 0 0 pair
private def namedSum : Expr (.sum .nat .bool) := .named 0 1 sum
private def namedSequence : Expr (.seq .nat) := .named 0 2 sequence
#guard equivalentSyntax namedPair.fst.normalizeMemo namedPair.fst
#guard equivalentSyntax namedPair.snd.normalizeMemo namedPair.snd
#guard equivalentSyntax namedSum.isLeft.normalizeMemo namedSum.isLeft
#guard equivalentSyntax (namedSum.leftD (.nat 0)).normalizeMemo (namedSum.leftD (.nat 0))
#guard equivalentSyntax (namedSum.rightD (.bool false)).normalizeMemo
  (namedSum.rightD (.bool false))
#guard equivalentSyntax namedSequence.length.normalizeMemo namedSequence.length
#guard equivalentSyntax (namedSequence.get? (.nat 1)).normalizeMemo (namedSequence.get? (.nat 1))

private def conditionalDag {s : Ty} (depth : Nat) (leaf : Expr s) : Expr s :=
  (List.range depth).foldl
    (fun value index => .ite (.eq (.unknown index) (.nat 0)) value value) leaf

private def appendDag (depth : Nat) : Expr (.seq .nat) :=
  (List.range depth).foldl (fun value _ => .append value value) (.ofList [.unknown 0])

private def deepQueries (depth : Nat) : List (Expr .bool) :=
  let pair := conditionalDag depth (Expr.pair (.nat 7) (.bool true))
  let sum := conditionalDag depth (Expr.inl (.nat 9) : Expr (.sum .nat .bool))
  let values := conditionalDag depth sequence
  [.eq pair.fst (.nat 7), pair.snd, sum.isLeft,
   .eq (sum.leftD (.nat 0)) (.nat 9), sum.rightD (.bool true),
   .eq values.length (.nat 3),
   .eq (values.get? (.nat 1)) (.inr (.nat 8)),
   .eq (appendDag depth).length (.nat (2 ^ depth))]

private def checked {α : Type} (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error message => throw (IO.userError message)

private def expectStatus (solver text expected : String) : IO Unit := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 && (result.stdout.splitOn "\n").head? == some expected do
    throw (IO.userError s!"expected {expected}: {result.stdout}\n{result.stderr}")

def run (solver : Option String := none) (depths : List Nat := [32, 64]) : IO Unit := do
  for depth in depths do
    let start ← IO.monoMsNow
    let formulas := deepQueries depth
    let text ← checked (script formulas)
    unless text.utf8ByteSize <= 1000 * (depth + 1) do
      throw (IO.userError s!"selector DAG output grew beyond linear size: {text.utf8ByteSize}")
    let contradictory ← checked (script [.not (formulas.foldr Expr.and (.bool true))])
    if let some solver := solver then
      expectStatus solver text "sat"
      expectStatus solver contradictory "unsat"
    IO.println s!"selector depth={depth} bytes={text.utf8ByteSize} ms={(← IO.monoMsNow) - start}"

end Symbolic.MemoSelectorTests

run_cmd do
  for name in [``Symbolic.Expr.normalizeMemoM_correct, ``Symbolic.Expr.normalizeMemo_correct] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"
