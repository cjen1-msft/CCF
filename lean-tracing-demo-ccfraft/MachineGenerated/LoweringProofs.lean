-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Lowering

set_option autoImplicit false

namespace CCFRaft.MachineGenerated

variable {Node TxId Observation : Type}
variable [DecidableEq Node] [DecidableEq TxId]
variable [Bootstrap Node]

theorem lowerAction_correct
    (before after : State Node TxId)
    (action : Action Node TxId) :
    ActionConstraint before after (lowerAction action) <->
      Enabled before action /\ after = next before action := by
  cases action <;> rfl

theorem lowerSteps_correct
    (observes : Observation -> State Node TxId -> Prop)
    (state : State Node TxId)
    (steps : List (TraceValidation.Step (Action Node TxId) Observation)) :
    formulaFollows observes state (steps.map lowerStep) <->
      TraceValidation.follows Enabled next observes state steps := by
  induction steps generalizing state with
  | nil => rfl
  | cons step rest inductionHypothesis =>
      constructor
      · intro lowered
        rcases lowered with
          ⟨after, actionConstraint, observations, loweredRest⟩
        have action :=
          (lowerAction_correct state after step.action).mp actionConstraint
        rcases action with ⟨enabled, afterIsNext⟩
        subst after
        exact
          ⟨enabled, observations,
            (inductionHypothesis (state := next state step.action)).mp
              loweredRest⟩
      · intro canonical
        rcases canonical with ⟨enabled, observations, canonicalRest⟩
        exact
          ⟨next state step.action,
            (lowerAction_correct
              state (next state step.action) step.action).mpr
              ⟨enabled, rfl⟩,
            observations,
            (inductionHypothesis (state := next state step.action)).mpr
              canonicalRest⟩

theorem lowerTraceCorrect
    (validEntryState : State Node TxId -> Prop)
    (observes : Observation -> State Node TxId -> Prop)
    (trace : TraceValidation.ReducedTrace (Action Node TxId) Observation)
    (formula : Formula Node TxId Observation)
    (lowered : lowerTrace trace = .ok formula) :
    Satisfiable validEntryState observes formula <->
      TraceValidation.Satisfiable
        validEntryState Enabled next observes trace := by
  simp only [lowerTrace, Except.ok.injEq] at lowered
  subst formula
  constructor
  · rintro ⟨entry, valid, entryObservations, loweredSteps⟩
    exact
      ⟨entry, valid, entryObservations,
        (lowerSteps_correct observes entry trace.steps).mp loweredSteps⟩
  · rintro ⟨entry, valid, entryObservations, canonicalSteps⟩
    exact
      ⟨entry, valid, entryObservations,
        (lowerSteps_correct observes entry trace.steps).mpr canonicalSteps⟩

end CCFRaft.MachineGenerated
