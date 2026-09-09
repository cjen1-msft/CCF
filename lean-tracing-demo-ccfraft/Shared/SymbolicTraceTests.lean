-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicTrace
import Shared.SymbolicSmt

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

private def namedTrace :=
  encodeWith counter (fun group value => .named group 0 value) 1
    (.named 0 0 (.nat 0))
    [.action (.unknown 0), .observation 1, .action (.nat 1), .observation 2]

#guard namedTrace.all (fun group => group.eval (fun _ => 1))
#guard !(namedTrace.all (fun group => group.eval (fun _ => 2)))
#guard match namedTrace with
  | [_, _, _, .and (.lt (.named 3 0 _) (.nat 4)) _, .lt (.named 3 0 _) (.nat 4)] => true
  | _ => false

example (ρ : Assignment) (state : Expr .nat)
    (trace : List (Instruction (Expr .nat) Nat)) :
    Holds ρ (encodeWith counter (fun group value => .named group 0 value) 1 state trace) ↔
      Follows counter ρ (state.eval ρ) trace :=
  encodeWith_correct counter _ (by intros; rfl) ρ 1 state trace

def causalFixture : Except String String :=
  scriptGroups <| ([Expr.bool true] ::
    (encodeWith counter (fun group value => .named group 0 value) 1
      (.named 0 0 (.nat 0))
      [.action (.nat 1), .observation 2]).map (fun expression => [expression]))

end Symbolic.Trace.Tests

run_cmd do
  for theoremName in [
      ``Symbolic.Trace.encodeWith_correct, ``Symbolic.Trace.encodeWith_group_count,
      ``Symbolic.Trace.encode_correct, ``Symbolic.Trace.encode_group_count] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO UInt32 := do
  unless args == ["--smt"] do
    (← IO.getStderr).putStrLn "usage: SymbolicTraceTests.lean --smt"
    return 1
  match Symbolic.Trace.Tests.causalFixture with
  | .ok script => IO.print script; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 1
