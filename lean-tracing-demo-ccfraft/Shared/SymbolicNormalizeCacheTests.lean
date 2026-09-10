-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalizeMemo

set_option autoImplicit false

namespace Symbolic.NormalizeCacheTests

def recordTy : Nat → Ty
  | 0 => .nat
  | n + 1 => .pair .nat (recordTy n)

def record : (n : Nat) → Expr (recordTy n)
  | 0 => .unknown 0
  | n + 1 => .pair (.unknown (n + 1)) (record n)

def fields : (n : Nat) → Expr (recordTy n) → List (Expr .nat)
  | 0, value => [value]
  | n + 1, value => value.fst :: fields n value.snd

private def checkSelectors (depth : Nat) : Bool :=
  let inputs := fields depth (.named 0 0 (record depth))
  let (outputs, state) := (inputs.mapM Expr.normalizeMemoM).run { stats := some {} }
  (inputs.zip outputs).all (fun (a, b) => @decide (a = b) (a.sharedDecEq b)) &&
    outputs.length == inputs.length &&
    state.stats.any (fun stats => stats.candidates == depth && stats.hits == depth) &&
    state.entries.size == 2 * depth + 1

#guard [0, 1, 16, 32, 64, 128].all checkSelectors

private def collision (n : Nat) : Expr .bool :=
  .not (.not (.not (.not (.eq (.unknown 0) (.nat n)))))

#guard (collision 0).memoKey == (collision 1).memoKey
#guard (Expr.nil : Expr (.seq .nat)).memoKey == (Expr.nil : Expr (.seq .bool)).memoKey

private def collisions : StateM Expr.NormalizationState (Expr .bool × Expr .bool) := do
  let _ ← (Expr.nil : Expr (.seq .nat)).normalizeMemoM
  let _ ← (Expr.nil : Expr (.seq .bool)).normalizeMemoM
  let a ← (collision 0).normalizeMemoM
  let b ← (collision 1).normalizeMemoM
  return (a, b)

#guard
  let ((a, b), state) := collisions.run { stats := some {} }
  state.stats.any (fun stats => stats.candidates > stats.hits) &&
    a.eval (fun _ => 0) && !(b.eval (fun _ => 0)) &&
    !(a.eval (fun _ => 1)) && b.eval (fun _ => 1)

example {s : Ty} (assignment : Assignment) (original : Expr s) (stats : Expr.NormalizationStats) :
    ((original.normalizeMemoM).run { stats := some stats }).1.eval assignment =
      original.eval assignment :=
  Expr.normalizeMemoM_correct assignment original _

end Symbolic.NormalizeCacheTests

run_cmd do
  for name in [``Symbolic.Expr.normalizeMemoM_correct, ``Symbolic.Expr.normalizeMemo_correct] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"
