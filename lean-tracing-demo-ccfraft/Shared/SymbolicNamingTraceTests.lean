-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNaming
import Shared.SymbolicTrace
import Shared.SymbolicSmt

set_option autoImplicit false

namespace Symbolic.NamingTraceTests

private def counters : Trace.Semantics (.pair .nat .nat) (Nat × Nat) Bool (Bool × Nat) where
  decode := fun assignment state => state.eval assignment
  within := fun state => state.1 < 5 ∧ state.2 < 5
  enabled := fun _ _ _ => True
  next := fun _ state first =>
    if first then (state.1 + 1, state.2) else (state.1, state.2 + 1)
  observes := fun _ state observation =>
    (if observation.1 then state.1 else state.2) = observation.2
  bounds := fun state => .and (.lt state.fst (.nat 5)) (.lt state.snd (.nat 5))
  step := fun state first =>
    ⟨.bool true, if first then .pair (.add state.fst (.nat 1)) state.snd
      else .pair state.fst (.add state.snd (.nat 1))⟩
  observe := fun state observation =>
    .eq (if observation.1 then state.fst else state.snd) (.nat observation.2)
  bounds_correct := by intros; simp [Expr.eval]
  enabled_correct := by intros; simp [Expr.eval]
  next_correct := by
    intro assignment state first _ _
    cases first <;> rfl
  observe_correct := by
    intro assignment state observation _
    rcases observation with ⟨first, value⟩
    cases first <;> simp [Expr.eval]

private def entry : Expr (.pair .nat .nat) :=
  .named 0 0 (.pair (.unknown 0) (.unknown 1))

private def encoded (first : Bool) (observed : Nat) : List (Expr .bool) :=
  .bool true :: Trace.encodeWithState counters nameChanged 1 entry
    [.observation (first, 0), .action false, .observation (first, observed)]

example (assignment : Assignment) (state : Expr (.pair .nat .nat))
    (trace : List (Trace.Instruction Bool (Bool × Nat))) :
    Trace.Holds assignment (Trace.encodeWithState counters nameChanged 1 state trace) ↔
      Trace.Follows counters assignment (state.eval assignment) trace :=
  Trace.encodeWithState_correct counters nameChanged
    (fun assignment group before after => nameChanged_correct assignment group before after)
    assignment 1 state trace

example (state : Expr (.pair .nat .nat))
    (trace : List (Trace.Instruction Bool (Bool × Nat))) :
    Trace.encodeWith counters (fun group value => .named group 0 value) 1 state trace =
      Trace.encodeWithState counters (fun group _ value => .named group 0 value)
        1 state trace := rfl

-- Observations carry the exact same bounds expression into the suffix.
example (state : Expr (.pair .nat .nat)) :
    Trace.encodeWithState counters nameChanged 1 state
      [.observation (true, 0), .observation (false, 0)] =
      [.and (counters.bounds state) (counters.observe state (true, 0)),
       .and (counters.bounds state) (counters.observe state (false, 0)),
       counters.bounds state] := rfl

#guard (encoded true 0).all (fun group => group.eval (fun _ => 0))
#guard !((encoded true 1).all (fun group => group.eval (fun _ => 0)))
#guard (encoded false 1).all (fun group => group.eval (fun _ => 0))
#guard !((encoded false 2).all (fun group => group.eval (fun _ => 0)))
#guard (encoded true 1).length == 5

private def twice : List (List (Expr .bool)) :=
  [[]] ++ (Trace.encodeWithState counters nameChanged 1 entry
    [.observation (false, 0), .action false, .observation (false, 1),
      .action false, .observation (false, 2)]).map (fun expression => [expression])

#guard match prepareGroups twice with
  | .error _ => false
  | .ok (_, printed) =>
      printed.stateDeclarations.size == 3 &&
        printed.stateDeclarations.any (fun line => (line.splitOn "state_2_0").length > 1) &&
        printed.stateDeclarations.any (fun line => (line.splitOn "state_4_0").length > 1)

private def expect (solver text expected : String) : IO Unit := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 &&
      (result.stdout.splitOn "\n").head? == some expected do
    throw (IO.userError s!"expected {expected}, got {result.stdout}\n{result.stderr}")

private def checked {α : Type} (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

def run (solver : String) : IO Unit := do
  for (first, observed, expectedWithoutWriter) in
      [(true, 1, "unsat"), (false, 2, "sat")] do
    let text ← checked (scriptGroups ((encoded first observed).map fun value => [value]))
    expect solver text "unsat"
    let reduced := String.intercalate "\n" <| (text.splitOn "\n").filter fun line =>
      !((line.splitOn ":named group_2)").length > 1)
    expect solver reduced expectedWithoutWriter
  expect solver (← checked (scriptGroups twice)) "sat"
  IO.println "state-aware trace naming, legacy API, bounds reuse, and group positions passed"

end Symbolic.NamingTraceTests

run_cmd do
  for theoremName in [``Symbolic.nameChanged_correct,
      ``Symbolic.Trace.encodeWithState_correct, ``Symbolic.Trace.encodeWithState_group_count,
      ``Symbolic.Trace.encodeWith_correct, ``Symbolic.Trace.encodeWith_group_count] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => Symbolic.NamingTraceTests.run solver
  | _ => throw (IO.userError "usage: SymbolicNamingTraceTests.lean /path/to/cvc5")
