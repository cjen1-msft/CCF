-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicTrace

set_option autoImplicit false

namespace Symbolic.Trace.Tests

private def counter : Semantics .nat Nat (Expr .nat) Nat where
  decode := fun ρ state => state.eval ρ
  within := fun state => state < 4
  enabled := fun ρ _ amount => amount.eval ρ > 0
  next := fun ρ state amount => state + amount.eval ρ
  observes := fun _ state value => state = value
  bounds := fun state => .lt state (.nat 4)
  step := fun state amount => ⟨.lt (.nat 0) amount, .add state amount⟩
  observe := fun state value => .eq state (.nat value)
  bounds_correct := by intros; simp [Expr.eval]
  enabled_correct := by intros; simp [Expr.eval]
  next_correct := by intros; rfl
  observe_correct := by intros; simp [Expr.eval]

private def check (ρ : Assignment) (entry : Nat)
    (trace : List (Instruction (Expr .nat) Nat)) : Bool :=
  (encode counter (.nat entry) trace).all (fun group => group.eval ρ)

#guard check (fun _ => 1) 0 [.action (.unknown 0), .observation 1]
#guard !(check (fun _ => 2) 0 [.action (.unknown 0), .observation 1])
#guard !(check (fun _ => 0) 0 [.action (.unknown 0)])
#guard !(check (fun _ => 4) 0 [.action (.unknown 0)])
#guard !(check (fun _ => 0) 4 [])
#guard check (fun _ => 0) 3 []
#guard (encode counter (.nat 0) [.observation 0, .action (.nat 1)]).length = 3

end Symbolic.Trace.Tests

run_cmd do
  for theoremName in [
      ``Symbolic.Trace.encode_correct, ``Symbolic.Trace.encode_group_count] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
