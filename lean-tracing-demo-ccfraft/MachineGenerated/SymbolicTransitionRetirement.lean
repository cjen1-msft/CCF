-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionLog

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem isSome_value {α : Type} (c : Codec α) (ρ : Assignment) (value : Expr c.option.ty) :
    (isSome value).eval ρ = (c.option.decode ρ value).isSome :=
  Bool.eq_iff_iff.mpr (isSome_correct c ρ value)

def filterIndexExpr (value : Expr Codec.nat.option.ty) (commit : Expr .nat) :
    Expr Codec.nat.option.ty :=
  optionCases value (.inl .unit) fun index => .ite (index.le commit) (.inr index) (.inl .unit)

theorem filterIndexExpr_correct (ρ : Assignment) (value : Expr Codec.nat.option.ty)
    (commit : Expr .nat) :
    Codec.nat.option.decode ρ (filterIndexExpr value commit) =
      (Codec.nat.option.decode ρ value).filter (fun index => index ≤ commit.eval ρ) := by
  have step (index : Expr .nat) :
      Codec.nat.option.decode ρ (.ite (index.le commit) (.inr index) (.inl .unit)) =
        if index.eval ρ ≤ commit.eval ρ then some (index.eval ρ) else none := by
    rw [decode_choose]
    simp [eval_le, Codec.decode, Codec.option, Codec.nat, Expr.eval]
  rw [filterIndexExpr, optionCases_correct Codec.nat Codec.nat.option ρ _ _ _
    (fun index => if index ≤ commit.eval ρ then some index else none) step]
  cases Codec.nat.option.decode ρ value <;>
    simp [Option.filter, Codec.decode, Codec.option, Expr.eval]

def signatureBindExpr (capacity : Nat) (log : Expr logCodec.ty)
    (retirement : Expr Codec.nat.option.ty) : Expr Codec.nat.option.ty :=
  optionCases retirement (.inl .unit) (fun index => signatureAfter capacity index (.nat 1) log)

theorem signatureBindExpr_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) (retirement : Expr Codec.nat.option.ty) :
    Codec.nat.option.decode ρ (signatureBindExpr capacity log retirement) =
      (Codec.nat.option.decode ρ retirement).bind
        (retirementCommittableIndexInLog (logCodec.decode ρ log)) := by
  have step (index : Expr .nat) :
      Codec.nat.option.decode ρ (signatureAfter capacity index (.nat 1) log) =
        retirementCommittableIndexInLog (logCodec.decode ρ log) (Codec.nat.decode ρ index) :=
    signatureAfter_correct ρ capacity index (.nat 1) log bound
  rw [signatureBindExpr, optionCases_correct Codec.nat Codec.nat.option ρ _ _ _
    (retirementCommittableIndexInLog (logCodec.decode ρ log)) step]
  cases Codec.nat.option.decode ρ retirement <;> rfl

def membershipExpr (retirement committable retired : Expr Codec.nat.option.ty) (commit : Expr .nat) :
    Expr membershipCodec.ty :=
  optionCases retirement (membershipCodec.literal .active) fun index =>
    .ite (isSome retired) (membershipCodec.literal .retiredCommitted)
      (.ite (index.le commit) (membershipCodec.literal .retirementCompleted)
        (.ite (isSome committable) (membershipCodec.literal .retirementSigned)
          (membershipCodec.literal .retirementOrdered)))

theorem membershipExpr_correct (ρ : Assignment)
    (retirement committable retired : Expr Codec.nat.option.ty) (commit : Expr .nat) :
    membershipCodec.decode ρ (membershipExpr retirement committable retired commit) =
      (Codec.nat.option.decode ρ retirement).elim .active (fun index =>
        if (Codec.nat.option.decode ρ retired).isSome then .retiredCommitted
        else if index ≤ commit.eval ρ then .retirementCompleted
        else if (Codec.nat.option.decode ρ committable).isSome then .retirementSigned
        else .retirementOrdered) := by
  have step (index : Expr .nat) :
      membershipCodec.decode ρ
        (.ite (isSome retired) (membershipCodec.literal .retiredCommitted)
          (.ite (index.le commit) (membershipCodec.literal .retirementCompleted)
            (.ite (isSome committable) (membershipCodec.literal .retirementSigned)
              (membershipCodec.literal .retirementOrdered)))) =
        (if (Codec.nat.option.decode ρ retired).isSome then .retiredCommitted
        else if index.eval ρ ≤ commit.eval ρ then .retirementCompleted
        else if (Codec.nat.option.decode ρ committable).isSome then .retirementSigned
        else .retirementOrdered) := by
    simp only [decode_choose, Codec.decode_literal, isSome_value Codec.nat ρ,
      eval_le, decide_eq_true_eq]
  rw [membershipExpr, optionCases_correct Codec.nat membershipCodec ρ _ _ _
    (fun index => if (Codec.nat.option.decode ρ retired).isSome then .retiredCommitted
      else if index ≤ commit.eval ρ then .retirementCompleted
      else if (Codec.nat.option.decode ρ committable).isSome then .retirementSigned
      else .retirementOrdered) step,
    Codec.decode_literal]

def setRetirementFields (value : Expr localCodec.ty) (membership : Expr membershipCodec.ty)
    (retirement committable retired : Expr Codec.nat.option.ty) : Expr localCodec.ty :=
  .pair value.fst (.pair value.snd.fst (.pair value.snd.snd.fst
    (.pair value.snd.snd.snd.fst (.pair value.snd.snd.snd.snd.fst
      (.pair value.snd.snd.snd.snd.snd.fst (.pair value.snd.snd.snd.snd.snd.snd.fst
        (.pair value.snd.snd.snd.snd.snd.snd.snd.fst
          (.pair value.snd.snd.snd.snd.snd.snd.snd.snd.fst
            (.pair value.snd.snd.snd.snd.snd.snd.snd.snd.snd.fst
              (.pair membership (.pair retirement (.pair committable retired))))))))))))

theorem setRetirementFields_correct (ρ : Assignment) (value : Expr localCodec.ty)
    (membership : Expr membershipCodec.ty) (retirement committable retired : Expr Codec.nat.option.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ
      (setRetirementFields value membership retirement committable retired)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with
        membershipState := membershipCodec.decode ρ membership
        retirementIndex := Codec.nat.option.decode ρ retirement
        retirementCommittableIndex := Codec.nat.option.decode ρ committable
        retiredCommittedIndex := Codec.nat.option.decode ρ retired } := by
  rfl

def refreshRetirementExpr (capacity : Nat) (node : Expr nodeCodec.ty) (value : Expr localCodec.ty) :
    Expr localCodec.ty :=
  let log := value.snd.snd.fst.normalizeMemo
  let commit := value.snd.snd.snd.fst
  let retirement := (retirementIndexExpr capacity node log).normalizeMemo
  let committable := (signatureBindExpr capacity log retirement).normalizeMemo
  let retired := (filterIndexExpr (retiredIndex capacity node (.nat 1) log) commit).normalizeMemo
  setRetirementFields value (membershipExpr retirement committable retired commit)
    retirement committable retired

theorem refreshRetirementExpr_correct (ρ : Assignment) (capacity : Nat)
    (node : Expr nodeCodec.ty) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    BoundedState.decodeLocal (localCodec.decode ρ (refreshRetirementExpr capacity node value)) =
      refreshRetirementState (nodeCodec.decode ρ node)
        (BoundedState.decodeLocal (localCodec.decode ρ value)) := by
  have hlog : logCodec.decode ρ value.snd.snd.fst.normalizeMemo = (localCodec.decode ρ value).log := by
    rw [decode_normalizeMemo]
    rfl
  have hb : (logCodec.decode ρ value.snd.snd.fst.normalizeMemo).length ≤ capacity := by
    simpa [hlog] using bound
  have hcommit : value.snd.snd.snd.fst.eval ρ = (localCodec.decode ρ value).commitIndex := rfl
  simp only [Expr.eval] at hcommit
  simp only [refreshRetirementExpr, setRetirementFields_correct, membershipExpr_correct,
    decode_normalizeMemo, filterIndexExpr_correct, signatureBindExpr_correct ρ capacity _ hb,
    retirementIndexExpr_correct ρ capacity _ _ hb, retiredIndex_correct ρ capacity _ _ _ hb,
    hlog, hcommit, Expr.eval]
  simp only [refreshRetirementState, BoundedState.decodeLocal, retiredCommittedIndexInLog]
  cases retirementIndexInLog (nodeCodec.decode ρ node) (localCodec.decode ρ value).log <;>
    simp

theorem model_log_bound (bounds : BoundedState.Bounds) (state : CCFRaft.State Node Nat)
    (node : Node) (within : BoundedState.WithinBounds bounds state) :
    (state.nodes node).log.length ≤ bounds.logCapacity := by
  have bound := within.1 node
  change ((state.node? node).getD freshNodeState).log.length ≤ bounds.logCapacity
  cases found : state.node? node with
  | none => simp [found, freshNodeState]
  | some value =>
      have localBound : BoundedState.LocalWithin bounds value := by
        simpa [BoundedState.OptionalLocalWithin, found] using bound
      simpa [found] using localBound.2.1

theorem readLocal_log_bound (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (localCodec.decode ρ (readLocal bounds.transactionCount state node)).log.length ≤ bounds.logCapacity := by
  change (BoundedState.decodeLocal
    (localCodec.decode ρ (readLocal bounds.transactionCount state node))).log.length ≤ _
  rw [readLocal_correct]
  exact model_log_bound bounds (evalEntry bounds ρ state) (nodeCodec.decode ρ node) within

theorem refreshReadLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ
      (refreshRetirementExpr bounds.logCapacity node (readLocal bounds.transactionCount state node))) =
      refreshRetirementState (nodeCodec.decode ρ node)
        ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)) := by
  rw [refreshRetirementExpr_correct ρ bounds.logCapacity node _
    (readLocal_log_bound bounds ρ state node within), readLocal_correct]

end CCFRaft.SymbolicTransition
