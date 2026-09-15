-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionSignature

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def pendingRetiredExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr nodeSetCodec.ty :=
  let log := (readLocal bounds.transactionCount state node).snd.snd.fst.normalizeMemo
  setDifference (tableSelect state.snd.snd.snd.snd.snd node).normalizeMemo
    (committedRetiredNodesExpr bounds.logCapacity log.length (.nat 1) log).normalizeMemo

theorem pendingRetiredExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    nodeSetCodec.decode ρ (pendingRetiredExpr bounds state node) =
      pendingRetiredCommittedNodes (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  let log := (readLocal bounds.transactionCount state node).snd.snd.fst.normalizeMemo
  have hlog : logCodec.decode ρ log = ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).log := by
    rw [show log = (readLocal bounds.transactionCount state node).snd.snd.fst.normalizeMemo from rfl,
      decode_normalizeMemo]
    exact congrArg NodeState.log (readLocal_correct bounds ρ state node)
  have hb : (logCodec.decode ρ log).length ≤ bounds.logCapacity := by
    rw [hlog]
    exact model_log_bound bounds (evalEntry bounds ρ state) (nodeCodec.decode ρ node) within
  have hlength : log.length.eval ρ = ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).log.length := by
    rw [← hlog]
    simp [Codec.decode, Codec.list, Expr.eval]
  have htable : nodeSetCodec.decode ρ (tableSelect state.snd.snd.snd.snd.snd node) =
      (evalEntry bounds ρ state).retirementCompleted (nodeCodec.decode ρ node) :=
    nodeTableSelect_correct nodeSetCodec ρ state.snd.snd.snd.snd.snd node
  change nodeSetCodec.decode ρ
    (setDifference (tableSelect state.snd.snd.snd.snd.snd node).normalizeMemo
      (committedRetiredNodesExpr bounds.logCapacity log.length (.nat 1) log).normalizeMemo) = _
  rw [setDifference_correct, decode_normalizeMemo, decode_normalizeMemo,
    committedRetiredNodesExpr_correct ρ bounds.logCapacity log.length (.nat 1) log hb,
    htable, hlog, hlength]
  rfl

def retiredWriteContent (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr contentCodec.ty :=
  .inr (.inr (.inr (pendingRetiredExpr bounds state node)))

theorem retiredWriteContent_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    contentCodec.decode ρ (retiredWriteContent bounds state node) =
      .retiredCommitted (pendingRetiredCommittedNodes (evalEntry bounds ρ state) (nodeCodec.decode ρ node)) := by
  change EntryContent.retiredCommitted (nodeSetCodec.decode ρ (pendingRetiredExpr bounds state node)) = _
  rw [pendingRetiredExpr_correct bounds ρ state node within]

def retiredWriteLocal (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr localCodec.ty :=
  appendRefreshedLocal bounds state node (retiredWriteContent bounds state node)

theorem retiredWriteLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ (retiredWriteLocal bounds state node)) =
      let before := evalEntry bounds ρ state
      let actor := nodeCodec.decode ρ node
      refreshRetirementState actor
        { before.nodes actor with
          log := (before.nodes actor).log ++
            [⟨(before.nodes actor).currentTerm, .retiredCommitted (pendingRetiredCommittedNodes before actor)⟩] } := by
  rw [retiredWriteLocal, appendRefreshedLocal_correct bounds ρ state node _ within,
    retiredWriteContent_correct bounds ρ state node within]

def retiredWriteEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  (Expr.and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .leader))
      (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
        (.and (.not (.eq (pendingRetiredExpr bounds state node) (nodeSetCodec.literal ∅)))
          (.not (.eq (localMembership (retiredWriteLocal bounds state node))
            (membershipCodec.literal .retiredCommitted))))))).normalizeMemo

theorem retiredWriteEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (retiredWriteEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.appendRetiredCommitted (nodeCodec.decode ρ node)) := by
  have hrole := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have hmember := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  have hnext := congrArg NodeState.membershipState (retiredWriteLocal_correct bounds ρ state node within)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at hrole
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).membershipState = _ at hmember
  change (localCodec.decode ρ (retiredWriteLocal bounds state node)).membershipState = _ at hnext
  have conjunction (a b : Expr .bool) :
      (Expr.and a b).eval ρ = true ↔ a.eval ρ = true ∧ b.eval ρ = true := by simp [Expr.eval]
  have negation (a : Expr .bool) : (Expr.not a).eval ρ = true ↔ ¬a.eval ρ = true := by simp [Expr.eval]
  simp only [retiredWriteEnabled, Expr.normalizeMemo_correct, conjunction, negation,
    allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader),
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node))
      (membershipCodec.literal .retiredCommitted),
    membershipCodec.equal_correct ρ (localMembership (retiredWriteLocal bounds state node))
      (membershipCodec.literal .retiredCommitted),
    nodeSetCodec.equal_correct ρ (pendingRetiredExpr bounds state node) (nodeSetCodec.literal ∅),
    pendingRetiredExpr_correct bounds ρ state node within, Codec.decode_literal,
    localMembership_correct ρ, hrole, hmember, hnext, Enabled, Finset.nonempty_iff_ne_empty]

def retiredWriteNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  writeEntryNext bounds state node (retiredWriteContent bounds state node)

theorem retiredWriteNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (retiredWriteNext bounds state node) =
      next (evalEntry bounds ρ state) (.appendRetiredCommitted (nodeCodec.decode ρ node)) := by
  rw [retiredWriteNext, writeEntryNext_correct bounds ρ state node _ within,
    retiredWriteContent_correct bounds ρ state node within]
  rfl

def retiredWriteGuard (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (stateWithin bounds state)
    (.and (retiredWriteEnabled bounds state node) (stateWithin bounds (retiredWriteNext bounds state node)))

theorem retiredWriteGuard_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    (retiredWriteGuard bounds state node).eval ρ = true ↔
      BoundedState.WithinBounds bounds (evalEntry bounds ρ state) ∧
        Enabled (evalEntry bounds ρ state) (.appendRetiredCommitted (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds
          (next (evalEntry bounds ρ state) (.appendRetiredCommitted (nodeCodec.decode ρ node))) := by
  simp only [retiredWriteGuard, Expr.eval, Bool.and_eq_true, stateWithin_correct bounds ρ]
  constructor
  · rintro ⟨hb, he, hn⟩
    rw [retiredWriteEnabled_correct bounds ρ state node hb] at he
    rw [retiredWriteNext_correct bounds ρ state node hb] at hn
    exact ⟨hb, he, hn⟩
  · rintro ⟨hb, he, hn⟩
    rw [retiredWriteEnabled_correct bounds ρ state node hb, retiredWriteNext_correct bounds ρ state node hb]
    exact ⟨hb, he, hn⟩

theorem retiredWrite_complete_model (bounds : BoundedState.Bounds) (start : Nat)
    (state : CCFRaft.State Node Nat) (node : Node)
    (before : BoundedState.WithinBounds bounds state)
    (enabled : Enabled state (.appendRetiredCommitted node))
    (after : BoundedState.WithinBounds bounds (next state (.appendRetiredCommitted node))) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
      (retiredWriteGuard bounds (freshEntry bounds start) (nodeCodec.literal node)).eval ρ = true ∧
      evalEntry bounds ρ (retiredWriteNext bounds (freshEntry bounds start) (nodeCodec.literal node)) =
        next state (.appendRetiredCommitted node) := by
  obtain ⟨ρ, hs⟩ := freshEntry_complete_model bounds start state before
  refine ⟨ρ, hs, ?_, ?_⟩
  · apply (retiredWriteGuard_correct bounds ρ _ _).mpr
    simpa only [hs, Codec.decode_literal] using And.intro before (And.intro enabled after)
  · have hb : BoundedState.WithinBounds bounds (evalEntry bounds ρ (freshEntry bounds start)) := by
      simpa only [hs] using before
    simpa only [hs, Codec.decode_literal] using
      retiredWriteNext_correct bounds ρ (freshEntry bounds start) (nodeCodec.literal node) hb

end CCFRaft.SymbolicTransition
