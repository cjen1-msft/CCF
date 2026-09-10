-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalizeMemo
import Shared.SymbolicSmt

set_option autoImplicit false

namespace Symbolic.MemoTests

private def number : Expr .nat := .unknown 0
private def numbers : Expr (.seq .nat) := .ofList [number, .nat 3]
private def pair : Expr (.pair .nat .bool) := .pair number (.bool true)
private def left : Expr (.sum .nat .bool) := .inl number
private def right : Expr (.sum .nat .bool) := .inr (.bool false)

private def examples : List ((s : Ty) × Expr s) :=
  [⟨_, .nat 2⟩, ⟨_, .bool false⟩, ⟨_, Expr.unit⟩, ⟨_, number⟩,
   ⟨_, .named 0 0 number⟩, ⟨_, .add number (.nat 1)⟩,
   ⟨_, .sub (.nat 1) number⟩, ⟨_, .lt number (.nat 2)⟩,
   ⟨_, .eq number (.nat 2)⟩, ⟨_, .not (.bool true)⟩,
   ⟨_, .and (.bool false) (.eq number (.nat 2))⟩,
   ⟨_, .and (.eq number (.nat 2)) (.bool true)⟩,
   ⟨_, .ite (.bool true) number (.nat 9)⟩,
   ⟨_, .ite (.bool false) number (.nat 9)⟩,
   ⟨_, .ite (.eq number (.nat 2)) number (.nat 9)⟩,
   ⟨_, pair⟩, ⟨_, pair.fst⟩, ⟨_, pair.snd⟩,
   ⟨_, left⟩, ⟨_, right⟩, ⟨_, left.isLeft⟩, ⟨_, right.isLeft⟩,
   ⟨_, .leftD left (.nat 4)⟩, ⟨_, .leftD right (.nat 4)⟩,
   ⟨_, .rightD left (.bool true)⟩, ⟨_, .rightD right (.bool true)⟩,
   ⟨_, (Expr.nil : Expr (.seq .nat))⟩, ⟨_, numbers⟩,
   ⟨_, .append numbers numbers⟩, ⟨_, numbers.length⟩,
   ⟨_, .take number numbers⟩, ⟨_, .drop number numbers⟩,
   ⟨_, .get? numbers number⟩, ⟨_, .set numbers number (.nat 7)⟩,
   ⟨_, .contains numbers number⟩]

private def conditionalPair : Expr (.pair .nat .bool) :=
  .ite (.eq number (.nat 2)) pair (.pair (.nat 8) (.bool false))
private def conditionalSum : Expr (.sum .nat .bool) :=
  .ite (.eq number (.nat 2)) left right

private def projections : List ((s : Ty) × Expr s) :=
  [⟨_, conditionalPair.fst⟩, ⟨_, conditionalPair.snd⟩,
   ⟨_, conditionalSum.isLeft⟩, ⟨_, .leftD conditionalSum (.nat 4)⟩,
   ⟨_, .rightD conditionalSum (.bool true)⟩]

#guard [0, 1, 2, 9].all fun value =>
  (examples ++ projections).all fun ⟨_, expression⟩ =>
    decide (expression.normalizeMemo.eval (fun _ => value) = expression.eval (fun _ => value))

private def shared (depth : Nat) : Expr .nat :=
  (List.range depth).foldl (fun value _ => .add value value) number

private def leftDepth : Expr .nat → Nat
  | .add left _ => leftDepth left + 1
  | _ => 0

private def collision (value : Nat) : Expr .bool :=
  .not (.not (.not (.not (.eq number (.nat value)))))

#guard (collision 0).memoKey == (collision 1).memoKey
#guard (Expr.nil : Expr (.seq .nat)).memoKey == (Expr.nil : Expr (.seq .bool)).memoKey
#guard [0, 1, 2].all fun value =>
  (Expr.and (collision 0) (collision 1)).normalizeMemo.eval (fun _ => value) == false

private def checkedScript (assertions : List (Expr .bool)) : IO String :=
  match script assertions with
  | .ok text => pure text
  | .error error => throw (IO.userError error)

private def expectStatus (solver text expected : String) : IO Unit := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 && (result.stdout.splitOn "\n").head? == some expected do
    throw (IO.userError s!"expected {expected}: {result.stdout}\n{result.stderr}")

def run (solver : Option String := none) : IO Unit := do
  let collisions ← checkedScript
    [collision 0, collision 1,
      .not (.contains (Expr.nil : Expr (.seq .nat)) (.nat 0)),
      .not (.contains (Expr.nil : Expr (.seq .bool)) (.bool false))]
  if let some solver := solver then
    expectStatus solver collisions "unsat"
  for depth in [16, 32, 64] do
    let value := shared depth
    let started ← IO.monoMsNow
    let discarded := (Expr.fst (.pair (.nat 7) value)).normalizeMemo
    unless discarded == .nat 7 do
      throw (IO.userError "normalization retained a discarded payload")
    let kept := value.normalizeMemo
    unless leftDepth kept == depth do
      throw (IO.userError "normalization changed the retained arithmetic graph")
    let retained ← checkedScript [.eq value (.nat (2 ^ depth))]
    let projected ← checkedScript [.eq (.fst (.pair (.nat 7) value)) (.nat 7)]
    let conflicting ← checkedScript [.eq (.add value (.nat 0)) (.add value (.nat 1))]
    unless retained.utf8ByteSize ≤ 1000 * (depth + 1) &&
        conflicting.utf8ByteSize ≤ 1000 * (depth + 1) && projected.utf8ByteSize ≤ 1000 do
      throw (IO.userError "serialized shared graph exceeds linear size")
    if let some solver := solver then
      expectStatus solver retained "sat"
      expectStatus solver projected "sat"
      expectStatus solver conflicting "unsat"
    IO.println s!"memo depth={depth} bytes={retained.utf8ByteSize} ms={(← IO.monoMsNow) - started}"

end Symbolic.MemoTests

run_cmd do
  for theoremName in [``Symbolic.Expr.normalizeMemo_correct,
      ``Symbolic.Expr.normalizeMemoM_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
