-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionCommitScan

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def setCommitExpr (value : Expr localCodec.ty) (index : Expr .nat) : Expr localCodec.ty :=
  .pair value.fst (.pair value.snd.fst (.pair value.snd.snd.fst
    (.pair index value.snd.snd.snd.snd)))

theorem setCommitExpr_correct (ρ : Assignment) (value : Expr localCodec.ty) (index : Expr .nat) :
    BoundedState.decodeLocal (localCodec.decode ρ (setCommitExpr value index)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with commitIndex := index.eval ρ } := rfl

def advancedLocal (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr localCodec.ty :=
  (refreshRetirementExpr bounds.logCapacity node
    (setCommitExpr (readLocal bounds.transactionCount state node)
      (SymbolicReceive.compact (highestCommitExpr bounds state node))).normalizeMemo).normalizeMemo

theorem advancedLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ (advancedLocal bounds state node)) =
      refreshRetirementState (nodeCodec.decode ρ node)
        { (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node) with
          commitIndex := highestCommittableIndex (evalEntry bounds ρ state) (nodeCodec.decode ρ node) } := by
  have hb : (localCodec.decode ρ
      (setCommitExpr (readLocal bounds.transactionCount state node)
        (SymbolicReceive.compact (highestCommitExpr bounds state node))).normalizeMemo).log.length ≤ bounds.logCapacity := by
    rw [decode_normalizeMemo]
    exact readLocal_log_bound bounds ρ state node within
  rw [advancedLocal, decode_normalizeMemo, refreshRetirementExpr_correct ρ bounds.logCapacity node _ hb,
    decode_normalizeMemo, setCommitExpr_correct, SymbolicReceive.compact_correct,
    highestCommitExpr_correct bounds ρ state node within, readLocal_correct]

theorem advancedLocal_log_bound (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (localCodec.decode ρ (advancedLocal bounds state node)).log.length ≤ bounds.logCapacity := by
  have transfer (data : BoundedState.LocalStateData) (before : NodeState Node Nat)
      (actor : Node) (index capacity : Nat)
      (equal : BoundedState.decodeLocal data = refreshRetirementState actor { before with commitIndex := index })
      (bound : before.log.length ≤ capacity) : data.log.length ≤ capacity := by
    have logeq := congrArg NodeState.log equal
    change data.log = before.log at logeq
    rw [logeq]
    exact bound
  exact transfer _ _ _ _ _ (advancedLocal_correct bounds ρ state node within)
    (model_log_bound bounds (evalEntry bounds ρ state) (nodeCodec.decode ρ node) within)

def advanceStateExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  let value := (advancedLocal bounds state node).normalizeMemo
  (refreshCompletedExpr bounds bounds.logCapacity
    (writeLocal bounds.transactionCount state node value) node value).normalizeMemo

theorem advanceStateExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (advanceStateExpr bounds state node) =
      advanceCommitState (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  have hb : (localCodec.decode ρ (advancedLocal bounds state node).normalizeMemo).log.length ≤ bounds.logCapacity := by
    rw [decode_normalizeMemo]
    exact advancedLocal_log_bound bounds ρ state node within
  rw [advanceStateExpr, evalEntry_normalizeMemo,
    refreshCompletedExpr_correct bounds ρ bounds.logCapacity _ node _ hb,
    writeLocal_correct]
  simp only [decode_normalizeMemo, advancedLocal_correct bounds ρ state node within]
  rfl

def demoteExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  .ite (.eq (localMembership (readLocal bounds.transactionCount state node)) (membershipCodec.literal .retiredCommitted))
    (checkQuorumNext bounds state node) state

theorem demoteExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    evalEntry bounds ρ (demoteExpr bounds state node) =
      demoteRetiredCommitted (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  have membership := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  change membershipCodec.decode ρ (localMembership (readLocal bounds.transactionCount state node)) = _ at membership
  simp only [demoteExpr, SymbolicReceive.evalEntry_choose,
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node))
      (membershipCodec.literal .retiredCommitted),
    Codec.decode_literal, membership, checkQuorumNext_correct, next, demoteRetiredCommitted]

def advanceNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  (demoteExpr bounds (advanceStateExpr bounds state node) node).normalizeMemo

theorem advanceNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (advanceNext bounds state node) =
      next (evalEntry bounds ρ state) (.advanceCommitIndex (nodeCodec.decode ρ node)) := by
  rw [advanceNext, evalEntry_normalizeMemo, demoteExpr_correct, advanceStateExpr_correct bounds ρ state node within]
  rfl

def terminalCommitExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .eq (localMembership (advancedLocal bounds state node)) (membershipCodec.literal .retiredCommitted)

theorem terminalCommitExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (terminalCommitExpr bounds state node).eval ρ = true ↔
      terminalRetirementCommit (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  rw [terminalCommitExpr, membershipCodec.equal_correct, Codec.decode_literal, localMembership_correct]
  change (BoundedState.decodeLocal (localCodec.decode ρ (advancedLocal bounds state node))).membershipState =
    .retiredCommitted ↔ _
  rw [advancedLocal_correct bounds ρ state node within]
  rfl

def advanceReady (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  .and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .leader))
      (.lt value.snd.snd.snd.fst (highestCommitExpr bounds state node)))

theorem advanceReady_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (advanceReady bounds state node).eval ρ = true ↔
      (evalEntry bounds ρ state).allocated (nodeCodec.decode ρ node) ∧
        ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).role = .leader ∧
        ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).commitIndex <
          highestCommittableIndex (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have commit := congrArg NodeState.commitIndex (readLocal_correct bounds ρ state node)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at role
  change (readLocal bounds.transactionCount state node).snd.snd.snd.fst.eval ρ = _ at commit
  simp only [advanceReady, boolAnd_true ρ, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader),
    Codec.decode_literal, role,
    natLt_true ρ (readLocal bounds.transactionCount state node).snd.snd.snd.fst (highestCommitExpr bounds state node),
    commit, highestCommitExpr_correct bounds ρ state node within]

def advanceEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (advanceReady bounds state node) (.not (terminalCommitExpr bounds state node))

theorem advanceEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (advanceEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.advanceCommitIndex (nodeCodec.decode ρ node)) := by
  simp only [advanceEnabled, boolAnd_true ρ, boolNot_true ρ, advanceReady_correct bounds ρ state node within,
    terminalCommitExpr_correct bounds ρ state node within, Enabled, and_assoc]

def advanceAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (advanceEnabled bounds state node) (stateWithin bounds (advanceNext bounds state node))

theorem advanceAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (advanceAccepted bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.advanceCommitIndex (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (.advanceCommitIndex (nodeCodec.decode ρ node))) := by
  simp only [advanceAccepted, boolAnd_true ρ, advanceEnabled_correct bounds ρ state node within,
    stateWithin_correct bounds ρ, advanceNext_correct bounds ρ state node within]

def advanceProposalEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr .bool :=
  .and (advanceReady bounds state source)
    (.and (allocated bounds.transactionCount state destination)
      (.and (terminalCommitExpr bounds state source) (plausibleSuccessorExpr bounds state source destination)))

theorem advanceProposalEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (advanceProposalEnabled bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.advanceCommitIndexAndProposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  simp only [advanceProposalEnabled, boolAnd_true ρ, allocated_correct bounds ρ,
    advanceReady_correct bounds ρ state source within, terminalCommitExpr_correct bounds ρ state source within,
    plausibleSuccessorExpr_correct bounds ρ state source destination within, Enabled]
  constructor
  · rintro ⟨⟨a, r, i⟩, d, t, p⟩
    exact ⟨a, d, r, i, t, p⟩
  · rintro ⟨a, d, r, i, t, p⟩
    exact ⟨⟨a, r, i⟩, d, t, p⟩

def advanceProposalNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  SymbolicReceive.enqueue bounds.transactionCount (advanceNext bounds state source)
    (proposalMessage bounds state source destination).normalizeMemo

theorem advanceProposalNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (advanceProposalNext bounds state source destination) =
      next (evalEntry bounds ρ state)
        (.advanceCommitIndexAndProposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  rw [advanceProposalNext, SymbolicReceive.enqueue_correct,
    advanceNext_correct bounds ρ state source within, decode_normalizeMemo, proposalMessage_correct]
  rfl

def advanceProposalAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr .bool :=
  .and (advanceProposalEnabled bounds state source destination)
    (stateWithin bounds (advanceProposalNext bounds state source destination))

theorem advanceProposalAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (advanceProposalAccepted bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.advanceCommitIndexAndProposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) ∧
      BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state)
        (.advanceCommitIndexAndProposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination))) := by
  simp only [advanceProposalAccepted, boolAnd_true ρ, advanceProposalEnabled_correct bounds ρ state source destination within,
    stateWithin_correct bounds ρ, advanceProposalNext_correct bounds ρ state source destination within]

end CCFRaft.SymbolicTransition
