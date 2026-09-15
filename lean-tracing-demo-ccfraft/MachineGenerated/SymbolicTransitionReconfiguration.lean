-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionAllocation
import MachineGenerated.SymbolicTransitionSignature

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem configurationContent_correct (ρ : Assignment) (configuration : Expr nodeSetCodec.ty) :
    contentCodec.decode ρ (.inr (.inr (.inl configuration))) =
      .reconfiguration (nodeSetCodec.decode ρ configuration) := rfl

def previousConfigurationExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr nodeSetCodec.ty :=
  (latestConfigurationExpr bounds.logCapacity
    (readLocal bounds.transactionCount state node).snd.snd.fst.normalizeMemo).snd

theorem previousConfigurationExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    nodeSetCodec.decode ρ (previousConfigurationExpr bounds state node) =
      (latestConfiguration ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node))).nodes := by
  have hlog : logCodec.decode ρ (readLocal bounds.transactionCount state node).snd.snd.fst.normalizeMemo =
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).log := by
    rw [decode_normalizeMemo]
    exact congrArg NodeState.log (readLocal_correct bounds ρ state node)
  exact congrArg Configuration.nodes
    (latestConfigurationExpr_correct ρ bounds.logCapacity _
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)) hlog
      (model_log_bound bounds _ _ within))

def addedConfigurationExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty) : Expr nodeSetCodec.ty :=
  setDifference configuration (previousConfigurationExpr bounds state node).normalizeMemo

theorem addedConfigurationExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    nodeSetCodec.decode ρ (addedConfigurationExpr bounds state node configuration) =
      nodeSetCodec.decode ρ configuration \
        (latestConfiguration ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node))).nodes := by
  rw [addedConfigurationExpr, setDifference_correct, decode_normalizeMemo,
    previousConfigurationExpr_correct bounds ρ state node within]

def configurationLocal (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty) : Expr localCodec.ty :=
  setAddedSentExpr (appendRefreshedLocal bounds state node (.inr (.inr (.inl configuration)))).normalizeMemo
    (addedConfigurationExpr bounds state node configuration).normalizeMemo
    (readLocal bounds.transactionCount state node).snd.snd.fst.length

theorem configurationLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ (configurationLocal bounds state node configuration)) =
      let value := (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)
      let nodes := nodeSetCodec.decode ρ configuration
      refreshRetirementState (nodeCodec.decode ρ node)
        { value with
          log := value.log ++ [⟨value.currentTerm, .reconfiguration nodes⟩]
          sentIndex := fun peer => if peer ∈ nodes \ (latestConfiguration value).nodes then value.log.length
            else value.sentIndex peer } := by
  have hlength :
      (readLocal bounds.transactionCount state node).snd.snd.fst.length.eval ρ =
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).log.length := by
    have hlog := congrArg NodeState.log (readLocal_correct bounds ρ state node)
    change logCodec.decode ρ (readLocal bounds.transactionCount state node).snd.snd.fst = _ at hlog
    rw [← hlog]
    simp [Codec.decode, Codec.list, Expr.eval]
  rw [configurationLocal, setAddedSentExpr_correct]
  simp only [decode_normalizeMemo,
    appendRefreshedLocal_correct bounds ρ state node _ within,
    addedConfigurationExpr_correct bounds ρ state node configuration within,
    configurationContent_correct, hlength]
  rw [withAddedSent_refresh]
  generalize (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node) = value
  apply congrArg (refreshRetirementState (TxId := Nat) (nodeCodec.decode ρ node))
  rfl

theorem configurationLocal_log_bound (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (localCodec.decode ρ (configurationLocal bounds state node configuration)).log.length ≤ bounds.logCapacity + 1 := by
  change (BoundedState.decodeLocal
    (localCodec.decode ρ (configurationLocal bounds state node configuration))).log.length ≤ _
  rw [configurationLocal, setAddedSentExpr_correct]
  change (localCodec.decode ρ
    (appendRefreshedLocal bounds state node (.inr (.inr (.inl configuration)))).normalizeMemo).log.length ≤ _
  rw [decode_normalizeMemo]
  exact appendRefreshedLocal_log_bound bounds ρ state node _ within

def unjoinedAddedExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty) : Expr .bool :=
  .eq (setIntersection (addedConfigurationExpr bounds state node configuration).normalizeMemo state.snd.snd.snd.fst)
    (nodeSetCodec.literal ∅)

theorem unjoinedAddedExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (unjoinedAddedExpr bounds state node configuration).eval ρ = true ↔
      ∀ peer ∈ nodeSetCodec.decode ρ configuration \
        (latestConfiguration ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node))).nodes,
        peer ∉ (evalEntry bounds ρ state).hasJoined := by
  rw [unjoinedAddedExpr, nodeSetCodec.equal_correct, setIntersection_correct,
    decode_normalizeMemo, addedConfigurationExpr_correct bounds ρ state node configuration within, Codec.decode_literal]
  have joined : nodeSetCodec.decode ρ state.snd.snd.snd.fst = (evalEntry bounds ρ state).hasJoined := rfl
  rw [joined]
  exact intersection_empty_iff _ _

def configurationEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  (Expr.and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .leader))
      (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
        (.and (.not (.eq configuration (nodeSetCodec.literal ∅)))
          (.and (.not (.eq configuration (previousConfigurationExpr bounds state node)))
            (.and (unjoinedAddedExpr bounds state node configuration)
              (.not (.eq (localMembership (configurationLocal bounds state node configuration))
                (membershipCodec.literal .retiredCommitted))))))))).normalizeMemo

theorem configurationEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (configurationEnabled bounds state node configuration).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.changeConfiguration (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ configuration)) := by
  have hrole := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have hmember := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  have hnext := congrArg NodeState.membershipState
    (configurationLocal_correct bounds ρ state node configuration within)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at hrole
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).membershipState = _ at hmember
  change (localCodec.decode ρ (configurationLocal bounds state node configuration)).membershipState = _ at hnext
  have conjunction (a b : Expr .bool) :
      (Expr.and a b).eval ρ = true ↔ a.eval ρ = true ∧ b.eval ρ = true := by simp [Expr.eval]
  have negation (a : Expr .bool) : (Expr.not a).eval ρ = true ↔ ¬a.eval ρ = true := by simp [Expr.eval]
  simp only [configurationEnabled, Expr.normalizeMemo_correct, conjunction, negation, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader),
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node))
      (membershipCodec.literal .retiredCommitted),
    membershipCodec.equal_correct ρ (localMembership (configurationLocal bounds state node configuration))
      (membershipCodec.literal .retiredCommitted),
    nodeSetCodec.equal_correct ρ configuration (nodeSetCodec.literal ∅),
    nodeSetCodec.equal_correct ρ configuration (previousConfigurationExpr bounds state node),
    unjoinedAddedExpr_correct bounds ρ state node configuration within,
    previousConfigurationExpr_correct bounds ρ state node within,
    Codec.decode_literal, localMembership_correct ρ, hrole, hmember, hnext, Enabled,
    Finset.nonempty_iff_ne_empty]
  generalize (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node) = value
  rfl

def configurationNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty) : Expr (stateCodec bounds.transactionCount).ty :=
  let added := (addedConfigurationExpr bounds state node configuration).normalizeMemo
  let value := (configurationLocal bounds state node configuration).normalizeMemo
  let allocated := (allocateExpr bounds.transactionCount state added).normalizeMemo
  let updated := (writeLocal bounds.transactionCount allocated node value).normalizeMemo
  let joined := (setJoinedExpr bounds.transactionCount updated (setUnion state.snd.snd.snd.fst added).normalizeMemo).normalizeMemo
  (refreshCompletedExpr bounds (bounds.logCapacity + 1) joined node value).normalizeMemo

theorem configurationNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (configurationNext bounds state node configuration) =
      next (evalEntry bounds ρ state)
        (.changeConfiguration (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ configuration)) := by
  have hb : (localCodec.decode ρ (configurationLocal bounds state node configuration).normalizeMemo).log.length ≤
      bounds.logCapacity + 1 := by
    simpa only [decode_normalizeMemo] using configurationLocal_log_bound bounds ρ state node configuration within
  rw [configurationNext, evalEntry_normalizeMemo,
    refreshCompletedExpr_correct bounds ρ (bounds.logCapacity + 1) _ node _ hb,
    evalEntry_normalizeMemo, setJoinedExpr_correct, evalEntry_normalizeMemo, writeLocal_correct,
    evalEntry_normalizeMemo, allocateExpr_correct]
  simp only [decode_normalizeMemo, setUnion_correct,
    addedConfigurationExpr_correct bounds ρ state node configuration within,
    configurationLocal_correct bounds ρ state node configuration within]
  rfl

def configurationAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty) : Expr .bool :=
  .and (configurationEnabled bounds state node configuration)
    (stateWithin bounds (configurationNext bounds state node configuration))

theorem configurationAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (configuration : Expr nodeSetCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (configurationAccepted bounds state node configuration).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.changeConfiguration (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ configuration)) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state)
          (.changeConfiguration (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ configuration))) := by
  simp only [configurationAccepted, Expr.eval, Bool.and_eq_true,
    configurationEnabled_correct bounds ρ state node configuration within, stateWithin_correct bounds ρ,
    configurationNext_correct bounds ρ state node configuration within]

theorem configuration_complete_model (bounds : BoundedState.Bounds) (start : Nat)
    (state : CCFRaft.State Node Nat) (node : Node) (configuration : Finset Node)
    (before : BoundedState.WithinBounds bounds state)
    (enabled : Enabled state (.changeConfiguration node configuration))
    (after : BoundedState.WithinBounds bounds (next state (.changeConfiguration node configuration))) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
      (configurationAccepted bounds (freshEntry bounds start)
        (nodeCodec.literal node) (nodeSetCodec.literal configuration)).eval ρ = true ∧
      evalEntry bounds ρ (configurationNext bounds (freshEntry bounds start)
        (nodeCodec.literal node) (nodeSetCodec.literal configuration)) =
          next state (.changeConfiguration node configuration) := by
  obtain ⟨ρ, hs⟩ := freshEntry_complete_model bounds start state before
  have hb : BoundedState.WithinBounds bounds (evalEntry bounds ρ (freshEntry bounds start)) := by
    simpa only [hs] using before
  refine ⟨ρ, hs, ?_, ?_⟩
  · apply (configurationAccepted_correct bounds ρ _ _ _ hb).mpr
    simpa only [hs, Codec.decode_literal] using And.intro enabled after
  · simpa only [hs, Codec.decode_literal] using configurationNext_correct bounds ρ
      (freshEntry bounds start) (nodeCodec.literal node) (nodeSetCodec.literal configuration) hb

end CCFRaft.SymbolicTransition
