-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicSharing

set_option autoImplicit false

namespace Symbolic.SharingTests

private abbrev PackedExpr := (s : Ty) × Expr s

private def same {s : Ty} (a b : Expr s) : Bool :=
  @decide (a = b) (a.sharedDecEq b)

private def samples : List PackedExpr :=
  [⟨.nat, .nat 0⟩, ⟨.nat, .nat 1⟩,
   ⟨.bool, .bool false⟩, ⟨.bool, .bool true⟩, ⟨.unit, .unit⟩,
   ⟨.nat, .unknown 0⟩, ⟨.nat, .unknown 1⟩,
   ⟨.nat, .named 0 0 (.nat 1)⟩, ⟨.nat, .named 0 1 (.nat 1)⟩,
   ⟨.nat, .named 1 0 (.nat 1)⟩, ⟨.bool, .named 0 0 (.bool true)⟩,
   ⟨.nat, .add (.unknown 0) (.nat 1)⟩, ⟨.nat, .add (.unknown 0) (.nat 2)⟩,
   ⟨.nat, .sub (.unknown 0) (.nat 1)⟩,
   ⟨.bool, .lt (.unknown 0) (.nat 1)⟩,
   ⟨.bool, .eq (.nat 1) (.nat 1)⟩, ⟨.bool, .eq (.bool true) (.bool true)⟩,
   ⟨.bool, .not (.bool true)⟩, ⟨.bool, .and (.bool true) (.bool false)⟩,
   ⟨.nat, .ite (.bool true) (.nat 0) (.nat 1)⟩,
   ⟨.pair .nat .bool, .pair (.nat 0) (.bool true)⟩,
   ⟨.nat, .fst (.pair (.nat 0) (.bool true))⟩,
   ⟨.nat, .fst (.pair (.nat 0) .unit)⟩,
   ⟨.bool, .snd (.pair (.nat 0) (.bool true))⟩,
   ⟨.bool, .snd (.pair .unit (.bool true))⟩,
   ⟨.sum .nat .bool, .inl (.nat 0)⟩, ⟨.sum .nat .unit, .inl (.nat 0)⟩,
   ⟨.sum .nat .bool, .inr (.bool true)⟩,
   ⟨.bool, .isLeft (.inl (.nat 0) : Expr (.sum .nat .bool))⟩,
   ⟨.bool, .isLeft (.inl (.nat 0) : Expr (.sum .nat .unit))⟩,
   ⟨.nat, .leftD (.inr (.bool true)) (.nat 0)⟩,
   ⟨.bool, .rightD (.inl (.nat 0)) (.bool false)⟩,
   ⟨.seq .nat, .nil⟩, ⟨.seq .bool, .nil⟩,
   ⟨.seq .nat, .cons (.nat 1) .nil⟩,
   ⟨.seq .nat, .append .nil (.cons (.nat 1) .nil)⟩,
   ⟨.nat, .length (.nil : Expr (.seq .nat))⟩,
   ⟨.nat, .length (.nil : Expr (.seq .bool))⟩,
   ⟨.seq .nat, .take (.nat 0) (.cons (.nat 1) .nil)⟩,
   ⟨.seq .nat, .drop (.nat 0) (.cons (.nat 1) .nil)⟩,
   ⟨.sum .unit .nat, .get? (.cons (.nat 1) .nil) (.nat 0)⟩,
   ⟨.seq .nat, .set (.cons (.nat 1) .nil) (.nat 0) (.nat 2)⟩,
   ⟨.bool, .contains (.cons (.nat 1) .nil) (.nat 1)⟩]

#guard samples.all fun a => samples.all fun b =>
  @decide (a = b) (packedExprEq a b) == decide (a = b)

-- Names and arithmetic remain syntactic, even when evaluations coincide.
#guard !same (.named 0 0 (.nat 1)) (.named 0 0 (.add (.nat 0) (.nat 1)))
#guard !same (.add (.nat 0) (.nat 1)) (.nat 1)
#guard !same (.named 0 0 (.nat 1)) (.named 1 0 (.nat 1))
#guard !same (.named 0 0 (.nat 1)) (.named 0 1 (.nat 1))

private def dag : Nat -> Expr .nat
  | 0 => .unknown 0
  | depth + 1 => let child := dag depth; .add child child

private def separateDag (depth : Nat) : Expr .nat :=
  (List.range depth).foldl (fun child _ => .add child child) (.unknown 0)

#guard same (dag 8) (separateDag 8)
#guard same (.named 3 9 (dag 8)) (.named 3 9 (separateDag 8))
#guard !same (.add (dag 8) (.nat 1)) (.add (separateDag 8) (.nat 0))

private def overlapping : Nat -> Expr .nat × Expr .nat
  | 0 => (.unknown 0, .unknown 1)
  | depth + 1 =>
      let (current, previous) := overlapping depth
      (.add current previous, current)

private def separateOverlapping (depth : Nat) : Expr .nat × Expr .nat :=
  (List.range depth).foldl
    (fun (current, previous) _ => (.add current previous, current))
    (.unknown 0, .unknown 1)

#guard same (dag 64) (separateDag 64)
#guard !same (.add (dag 64) (.nat 1)) (.add (separateDag 64) (.nat 0))
#guard same (overlapping 64).1 (separateOverlapping 64).1

private def sharedPrefixMismatch (depth : Nat) : Bool :=
  let child := dag depth
  !same (.add child (.nat 1)) (.add child (.nat 0))

#guard sharedPrefixMismatch 40

private def tree : Nat -> Nat -> Expr .nat
  | 0, index => .nat index
  | depth + 1, index => .add (tree depth (2 * index)) (tree depth (2 * index + 1))

private def separateTree : Nat -> Nat -> Expr .nat
  | 0, index => .nat (index + 1 - 1)
  | depth + 1, index =>
      .add (separateTree depth (index + index)) (separateTree depth (index + index + 1))

-- A shallow tree can visit thousands of distinct nodes. The old CPS comparison
-- accumulated call frames across completed siblings, not just along tree depth.
#guard same (tree 10 0) (separateTree 10 0)
#guard !same (.add (tree 10 0) (.nat 0)) (.add (separateTree 10 0) (.nat 1))

private def chain (depth : Nat) : Expr .nat :=
  (List.range depth).foldl (fun child index => .add child (.nat index)) (.unknown 0)

private def separateChain (depth : Nat) : Expr .nat :=
  (List.range depth).foldl (fun child index =>
    .add child (.nat (index + 1 - 1))) (.unknown 0)

example {s : Ty} (a b : Expr s) :
    letI : DecidableEq (Expr s) := Expr.sharedDecEq
    decide (a = b) = true ↔ a = b := by
  simp

/-- Run explicitly with `#eval`; importing these tests does not run a benchmark. -/
def profile : IO Unit := do
  for depth in [13, 17, 25, 40] do
    let shared := dag depth
    let start ← IO.monoMsNow
    for index in [:2000] do
      if same (.add shared (.nat index)) (.add shared (.nat (index + 1))) then
        throw (IO.userError "distinct fields compared equal")
    let elapsed := (← IO.monoMsNow) - start
    IO.println s!"depth={depth} comparisons=2000 elapsed_ms={elapsed}"
  for depth in [16, 32, 64] do
    let start ← IO.monoMsNow
    unless same (dag depth) (separateDag depth) &&
        same (overlapping depth).1 (separateOverlapping depth).1 do
      throw (IO.userError "separate equal expression graphs compared unequal")
    IO.println s!"independent DAG depth={depth} elapsed_ms={(← IO.monoMsNow) - start}"
  for depth in [10, 12, 14] do
    let left := tree depth 0
    let right := separateTree depth 0
    let start ← IO.monoMsNow
    unless same left right && !same (.add left (.nat 0)) (.add right (.nat 1)) do
      throw (IO.userError "wide independent tree equality or late mismatch failed")
    IO.println s!"independent tree depth={depth} nodes={2 ^ (depth + 1) - 1} elapsed_ms={(← IO.monoMsNow) - start}"
  let start ← IO.monoMsNow
  unless same (chain 4096) (separateChain 4096) do
    throw (IO.userError "deep independent chain compared unequal")
  IO.println s!"independent chain depth=4096 elapsed_ms={(← IO.monoMsNow) - start}"

end Symbolic.SharingTests

run_cmd do
  for name in [
      ``Symbolic.Expr.sharedDecEq, ``Symbolic.packedExprEq,
      ``Symbolic.Expr.sharedDecEq_correct, ``Symbolic.packedExprEq_correct] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"
