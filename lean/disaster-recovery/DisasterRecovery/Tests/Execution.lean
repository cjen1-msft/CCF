module

public import DisasterRecovery.Proofs.Trace

@[expose] public section

namespace DisasterRecovery.Tests.Execution

open CCF
open CCF.Execution

private def counter : TransitionSystem Nat Bool where
  init state := state = 0
  step state increment := if increment then some (state + 1) else some state

-- Stutters are allowed when the recorded action is enabled.
private def counting : Trace Nat Bool :=
  { initial := 0, actions := Stream'.Seq.ofList [false, true, true] }

private theorem counting_valid : counting.Valid counter :=
  Proofs.Trace.valid_of_stateAt_length (final := 2) rfl (by decide)

example : counter.Reachable 2 :=
  counting_valid.reachable_stateAt (index := 3) (by decide)

example (state : Nat)
    : counter.Reachable state
      <-> exists trace : Trace Nat Bool,
            trace.Valid counter /\ state ∈ trace.states counter :=
  reachable_iff_trace

-- An empty action sequence still records an initial state.
example : (Trace.mk 0 (Stream'.Seq.ofList [])).Valid counter :=
  Proofs.Trace.valid_of_stateAt_length rfl (Trace.stateAt_zero _ _)

example : ¬ (Trace.mk 1 (Stream'.Seq.ofList [])).Valid counter := by
  rintro ⟨initialized, _⟩
  simp [counter] at initialized

example : counting.stepAt counter 0 = some { before := 0, action := false, after := 0 } :=
  Trace.stepAt_eq_some.mpr ⟨rfl, rfl, rfl⟩

example : counting.stateAt counter 3 = some 2 := by decide

example : counting.stateAt counter 4 = none := by decide

example
    : ¬ (Trace.mk 0 (Stream'.Seq.ofList [()])).Valid
          ({ init := fun state => state = 0, step := fun _ _ => none }
            : TransitionSystem Nat Unit) := by
  rintro ⟨_, steps⟩
  obtain ⟨_, _, _, step⟩ := steps 0 () rfl
  cases step

private def stoppingCounter : TransitionSystem Nat Bool where
  init state := state = 0
  step state increment := if increment then some (state + 1) else none

private def stopped : Trace Nat Bool :=
  { initial := 0, actions := Stream'.Seq.ofList [true, false, true] }

-- Stopped replay does not discard the disabled action or the recorded suffix.
example : stopped.stateAt stoppingCounter 1 = some 1 := by decide

example : stopped.stateAt stoppingCounter 2 = none := by decide

example : stopped.actionAt 2 = some true := rfl

example : ¬ stopped.Valid stoppingCounter := by
  rintro ⟨_, steps⟩
  obtain ⟨_, _, _, step⟩ := steps 1 false rfl
  simp [stoppingCounter] at step

end DisasterRecovery.Tests.Execution
