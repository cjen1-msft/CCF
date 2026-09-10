-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicTrace

set_option autoImplicit false

namespace Symbolic.Trace.Scaling

private def counter : Semantics .nat Nat Nat Nat where
  decode := fun ρ state => state.eval ρ
  within := fun state => state < 4
  enabled := fun _ _ amount => amount > 0
  next := fun _ state amount => state + amount
  observes := fun _ state value => state = value
  bounds := fun state => .lt state (.nat 4)
  step := fun state amount => ⟨.lt (.nat 0) (.nat amount), .add state (.nat amount)⟩
  observe := fun state value => .eq state (.nat value)
  bounds_correct := by intros; simp [Expr.eval]
  enabled_correct := by intros; simp [Expr.eval]
  next_correct := by intros; rfl
  observe_correct := by intros; simp [Expr.eval]

private def instrumented : Semantics .nat Nat Nat Nat :=
  { counter with
    bounds := fun state => dbgTrace "TRACE_BOUNDS_CALL" fun _ => counter.bounds state }

private def nameState (group : Nat) (state : Expr .nat) : Expr .nat :=
  .named group 0 state

private def instrumentedName (group : Nat) (state : Expr .nat) : Expr .nat :=
  dbgTrace s!"TRACE_NAME_CALL:{group}" fun _ => nameState group state

-- The original recursion is an exact-syntax oracle, without instrumentation.
private def reference {s : Ty} {State Action Observation : Type}
    (semantics : Semantics s State Action Observation)
    (name : Nat -> Expr s -> Expr s) (group : Nat) (state : Expr s) :
    List (Instruction Action Observation) -> List (Expr .bool)
  | [] => [semantics.bounds state]
  | .action action :: rest =>
      let result := semantics.step state action
      .and (semantics.bounds state) result.enabled ::
        reference semantics name (group + 1) (name group result.successor) rest
  | .observation observation :: rest =>
      .and (semantics.bounds state) (semantics.observe state observation) ::
        reference semantics name (group + 1) state rest

theorem exact_reference {s : Ty} {State Action Observation : Type}
    (semantics : Semantics s State Action Observation)
    (name : Nat -> Expr s -> Expr s) (group : Nat) (state : Expr s)
    (trace : List (Instruction Action Observation)) :
    encodeWith semantics name group state trace = reference semantics name group state trace := by
  induction trace generalizing group state with
  | nil => rfl
  | cons instruction rest inductionHypothesis =>
      cases instruction <;> simp [reference, inductionHypothesis]

private def fixture (observations : Nat) : List (Instruction Nat Nat) :=
  List.replicate observations (.observation 0) ++ [.action 1] ++
    List.replicate observations (.observation 1) ++ [.action 2] ++
    List.replicate observations (.observation 3)

def check (observations : Nat) : IO Unit := do
  let trace := fixture observations
  let entry := Expr.named 0 0 (.unknown 0)
  let groups := encodeWith instrumented instrumentedName 1 entry trace
  unless groups == reference counter nameState 1 entry trace do
    throw <| IO.userError "encoded AST differs from original recursion"
  unless groups.length == 3 * observations + 3 do
    throw <| IO.userError "instruction or final bounds group missing"
  unless groups.all (fun expression => expression.eval (fun _ => 0)) do
    throw <| IO.userError "valid trace rejected"
  unless !(groups.all (fun expression => expression.eval (fun _ => 1))) do
    throw <| IO.userError "assignment-sensitive invalid trace accepted"
  let first := nameState (observations + 1) (.add entry (.nat 1))
  let last := nameState (2 * observations + 2) (.add first (.nat 2))
  unless groups.getLast? == some (.lt last (.nat 4)) do
    throw <| IO.userError "action naming indices or terminal state changed"
  IO.println s!"SCALING_OK:{observations}:{groups.length}"

end Symbolic.Trace.Scaling

run_cmd do
  for theoremName in [
      ``Symbolic.Trace.Scaling.exact_reference,
      ``Symbolic.Trace.encodeWith_nil, ``Symbolic.Trace.encodeWith_action,
      ``Symbolic.Trace.encodeWith_observation,
      ``Symbolic.Trace.encodeWith_correct, ``Symbolic.Trace.encodeWith_group_count,
      ``Symbolic.Trace.encode_correct, ``Symbolic.Trace.encode_group_count] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO UInt32 := do
  let [count] := args
    | throw <| IO.userError "usage: SymbolicTraceScalingMain.lean observations-per-block"
  let some observations := count.toNat?
    | throw <| IO.userError "observation count must be a natural number"
  Symbolic.Trace.Scaling.check observations
  return 0
