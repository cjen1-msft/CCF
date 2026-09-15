-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionEvaluation

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionEvaluationTests

open Symbolic SymbolicModel SymbolicTransition

def emptyEntry : Expr (stateCodec 0).ty :=
  (stateCodec 0).literal
    (Vector.ofFn (fun _ => none), Vector.ofFn (fun _ => []), ∅, ∅,
      Vector.ofFn (fun _ => .capable), Vector.ofFn (fun _ => ∅))

def run : IO Unit := do
  for n in [0, 7] do
    let ρ : Assignment := fun _ => n
    let shared : Expr .nat := .named 0 0 (.add (.unknown 0) (.nat 1))
    let (first, cache) := (shared.evalMemoM ρ).run {}
    let (guard, cache) := ((Expr.eq shared (.nat (n + 1))).evalMemoM ρ).run cache
    let (again, reused) := (shared.evalMemoM ρ).run cache
    unless first == n + 1 && guard && again == first && reused.size == cache.size do
      throw (IO.userError "assignment-scoped cache reuse failed")
    let decoded := decodeMemo (Codec.nat.prod Codec.bool) ρ
      (.pair shared (.eq shared (.nat (n + 1))))
    unless decoded == (n + 1, true) do
      throw (IO.userError "memoized record decoding failed")
  let zero : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  let ρ : Assignment := fun _ => 0
  let (state, cache) := (evalEntryMemoM zero ρ emptyEntry).run {}
  let (again, reused) := (evalEntryMemoM zero ρ emptyEntry).run cache
  unless decide (BoundedState.WithinBounds zero state) &&
      decide (BoundedState.encode state = BoundedState.encode again) && reused.size == cache.size do
    throw (IO.userError "memoized empty-state decoding failed")

#eval run

run_cmd do
  for name in [``decodeMemo_correct, ``evalEntryMemoM_correct, ``evalEntryMemo_correct,
      ``evaluateActionMemo_correct] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

end CCFRaft.SymbolicTransitionEvaluationTests
