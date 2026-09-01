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

theorem lowerInstructions_correct
    (observes : Observation -> State Node TxId -> Prop)
    (state : State Node TxId)
    (instructions :
      List (TraceValidation.Instruction (Action Node TxId) Observation)) :
    formulaFollows observes state (instructions.map lowerInstruction) <->
      TraceValidation.follows Enabled next observes state instructions := by
  induction instructions generalizing state with
  | nil => rfl
  | cons instruction rest inductionHypothesis =>
      cases instruction with
      | observation observation =>
          simp only [List.map_cons, lowerInstruction, formulaFollows,
            TraceValidation.follows]
          constructor
          · rintro ⟨holds, loweredRest⟩
            exact ⟨holds, (inductionHypothesis state).mp loweredRest⟩
          · rintro ⟨holds, canonicalRest⟩
            exact ⟨holds, (inductionHypothesis state).mpr canonicalRest⟩
      | action action =>
          simp only [List.map_cons, lowerInstruction, formulaFollows,
            TraceValidation.follows]
          constructor
          · rintro ⟨after, actionConstraint, loweredRest⟩
            rcases
              (lowerAction_correct state after action).mp actionConstraint
            with ⟨enabled, afterIsNext⟩
            subst after
            exact
              ⟨enabled,
                (inductionHypothesis (next state action)).mp loweredRest⟩
          · rintro ⟨enabled, canonicalRest⟩
            exact
              ⟨next state action,
                (lowerAction_correct
                  state (next state action) action).mpr ⟨enabled, rfl⟩,
                (inductionHypothesis (next state action)).mpr canonicalRest⟩

theorem lowerTraceCorrect
    (validEntryState : State Node TxId -> Prop)
    (observes : Observation -> State Node TxId -> Prop)
    (trace :
      List (TraceValidation.Instruction (Action Node TxId) Observation))
    (formula : Formula Node TxId Observation)
    (lowered : lowerTrace trace = .ok formula) :
    Satisfiable validEntryState observes formula <->
      TraceValidation.Satisfiable
        validEntryState Enabled next observes trace := by
  simp only [lowerTrace, Except.ok.injEq] at lowered
  subst formula
  constructor
  · rintro ⟨entry, valid, loweredInstructions⟩
    exact
      ⟨entry, valid,
        (lowerInstructions_correct observes entry trace).mp
          loweredInstructions⟩
  · rintro ⟨entry, valid, canonicalInstructions⟩
    exact
      ⟨entry, valid,
        (lowerInstructions_correct observes entry trace).mpr
          canonicalInstructions⟩

end CCFRaft.MachineGenerated
