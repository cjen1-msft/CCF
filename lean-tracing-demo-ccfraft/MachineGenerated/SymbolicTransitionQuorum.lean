-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionElectionStart

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem eraseNode_correct (ρ : Assignment) (nodes : Expr nodeSetCodec.ty) (node : Expr nodeCodec.ty) :
    nodeSetCodec.decode ρ (setErase nodes (finValue node)) =
      (nodeSetCodec.decode ρ nodes).erase (nodeCodec.decode ρ node) := by
  ext peer
  rw [setErase_correct]
  simp [finValue_correct, Codec.decode, Codec.fin, Fin.ext_iff, eq_comm]
  intro _
  rfl

def otherActiveExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .not (.eq (setErase (localActiveNodes bounds.logCapacity (readLocal bounds.transactionCount state node))
    (finValue node)) (nodeSetCodec.literal ∅))

theorem otherActiveExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (otherActiveExpr bounds state node).eval ρ = true ↔
      hasOtherActiveReplica (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  have hb := readLocal_log_bound bounds ρ state node within
  rw [otherActiveExpr, boolNot_true, nodeSetCodec.equal_correct, eraseNode_correct,
    localActiveNodes_correct ρ bounds.logCapacity _ hb, readLocal_correct, Codec.decode_literal]
  simp only [hasOtherActiveReplica, Finset.nonempty_iff_ne_empty]

def checkQuorumEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (allocated bounds.transactionCount state node)
    (.and (.eq (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader))
      (otherActiveExpr bounds state node))

theorem checkQuorumEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (checkQuorumEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.checkQuorum (nodeCodec.decode ρ node)) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at role
  simp only [checkQuorumEnabled, boolAnd_true ρ, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader),
    Codec.decode_literal, role, otherActiveExpr_correct bounds ρ state node within, Enabled]

def checkQuorumNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  writeLocal bounds.transactionCount state node
    (stepDownLocal (readLocal bounds.transactionCount state node)).normalizeMemo

theorem checkQuorumNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    evalEntry bounds ρ (checkQuorumNext bounds state node) =
      next (evalEntry bounds ρ state) (.checkQuorum (nodeCodec.decode ρ node)) := by
  rw [checkQuorumNext, writeLocal_correct, decode_normalizeMemo,
    stepDownLocal_correct, readLocal_correct]
  rfl

def checkQuorumAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (checkQuorumEnabled bounds state node) (stateWithin bounds (checkQuorumNext bounds state node))

theorem checkQuorumAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (checkQuorumAccepted bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.checkQuorum (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (.checkQuorum (nodeCodec.decode ρ node))) := by
  simp only [checkQuorumAccepted, boolAnd_true ρ, checkQuorumEnabled_correct bounds ρ state node within,
    stateWithin_correct bounds ρ, checkQuorumNext_correct]

end CCFRaft.SymbolicTransition
