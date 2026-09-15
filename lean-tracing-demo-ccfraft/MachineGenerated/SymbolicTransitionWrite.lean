-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionCompleted
import MachineGenerated.SymbolicTransitionCoverage
import MachineGenerated.SymbolicBounds

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def appendLocalEntry (value : Expr localCodec.ty) (entry : Expr entryCodec.ty) : Expr localCodec.ty :=
  .pair value.fst (.pair value.snd.fst
    (.pair (appendSequence value.snd.snd.fst.normalizeMemo (.cons entry .nil)) value.snd.snd.snd))

theorem appendLocalEntry_correct (ρ : Assignment) (value : Expr localCodec.ty)
    (entry : Expr entryCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (appendLocalEntry value entry)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with
        log := (localCodec.decode ρ value).log ++ [entryCodec.decode ρ entry] } := by
  have hlog : logCodec.decode ρ (appendSequence value.snd.snd.fst.normalizeMemo (.cons entry .nil)) =
      (localCodec.decode ρ value).log ++ [entryCodec.decode ρ entry] := by
    change logCodec.decode ρ (appendSequence value.snd.snd.fst.normalizeMemo (.cons entry .nil)) =
      logCodec.decode ρ value.snd.snd.fst ++ [entryCodec.decode ρ entry]
    simp [Codec.decode, Codec.list, appendSequence_correct, Expr.normalizeMemo_correct, Expr.eval, List.map_append]
  change { BoundedState.decodeLocal (localCodec.decode ρ value) with
    log := logCodec.decode ρ (appendSequence value.snd.snd.fst.normalizeMemo (.cons entry .nil)) } = _
  rw [hlog]

theorem appendLocalEntry_log_bound (ρ : Assignment) (capacity : Nat)
    (value : Expr localCodec.ty) (entry : Expr entryCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (localCodec.decode ρ (appendLocalEntry value entry)).log.length ≤ capacity + 1 := by
  change (BoundedState.decodeLocal (localCodec.decode ρ (appendLocalEntry value entry))).log.length ≤ _
  rw [appendLocalEntry_correct]
  simpa using Nat.succ_le_succ bound

def appendRefreshedLocal (bounds : BoundedState.Bounds) (state : Expr (stateCodec bounds.transactionCount).ty)
    (node : Expr nodeCodec.ty) (content : Expr contentCodec.ty) : Expr localCodec.ty :=
  let value := readLocal bounds.transactionCount state node
  refreshRetirementExpr (bounds.logCapacity + 1) node
    (appendLocalEntry value (.pair value.snd.fst content)).normalizeMemo

theorem appendRefreshedLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (content : Expr contentCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ (appendRefreshedLocal bounds state node content)) =
      refreshRetirementState (nodeCodec.decode ρ node)
        { (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node) with
          log := ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).log ++
            [⟨((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).currentTerm,
              contentCodec.decode ρ content⟩] } := by
  have hb := appendLocalEntry_log_bound ρ bounds.logCapacity
    (readLocal bounds.transactionCount state node)
    (.pair (readLocal bounds.transactionCount state node).snd.fst content)
    (readLocal_log_bound bounds ρ state node within)
  rw [appendRefreshedLocal, refreshRetirementExpr_correct ρ (bounds.logCapacity + 1) node _
    (by simpa only [decode_normalizeMemo] using hb), decode_normalizeMemo, appendLocalEntry_correct]
  have hlog := congrArg NodeState.log (readLocal_correct bounds ρ state node)
  have hterm := congrArg NodeState.currentTerm (readLocal_correct bounds ρ state node)
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).log = _ at hlog
  change Codec.nat.decode ρ (readLocal bounds.transactionCount state node).snd.fst = _ at hterm
  have hentry :
      entryCodec.decode ρ (.pair (readLocal bounds.transactionCount state node).snd.fst content) =
      Entry.mk ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).currentTerm
        (contentCodec.decode ρ content) := by
    change Entry.mk (Codec.nat.decode ρ (readLocal bounds.transactionCount state node).snd.fst)
      (contentCodec.decode ρ content) = _
    rw [hterm]
  rw [readLocal_correct, hlog, hentry]

theorem appendRefreshedLocal_log_bound (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (content : Expr contentCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (localCodec.decode ρ (appendRefreshedLocal bounds state node content)).log.length ≤ bounds.logCapacity + 1 := by
  change (BoundedState.decodeLocal (localCodec.decode ρ (appendRefreshedLocal bounds state node content))).log.length ≤ _
  rw [appendRefreshedLocal_correct bounds ρ state node content within]
  have log_preserved (n : Node) (value : NodeState Node Nat) :
      (refreshRetirementState n value).log = value.log := rfl
  rw [log_preserved]
  simpa only [List.length_append, List.length_singleton] using Nat.succ_le_succ
    (model_log_bound bounds (evalEntry bounds ρ state) (nodeCodec.decode ρ node) within)

def writeEntryNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (content : Expr contentCodec.ty) : Expr (stateCodec bounds.transactionCount).ty :=
  let value := (appendRefreshedLocal bounds state node content).normalizeMemo
  (refreshCompletedExpr bounds (bounds.logCapacity + 1)
    (writeLocal bounds.transactionCount state node value).normalizeMemo node value).normalizeMemo

theorem writeEntryNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (content : Expr contentCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (writeEntryNext bounds state node content) =
      let before := evalEntry bounds ρ state
      let actor := nodeCodec.decode ρ node
      let value := refreshRetirementState actor
        { before.nodes actor with
          log := (before.nodes actor).log ++
            [⟨(before.nodes actor).currentTerm, contentCodec.decode ρ content⟩] }
      { before with
        nodes := updateNode before.nodes actor value
        retirementCompleted := refreshRetirementCompleted before.retirementCompleted actor value } := by
  have hb : (localCodec.decode ρ (appendRefreshedLocal bounds state node content).normalizeMemo).log.length ≤
      bounds.logCapacity + 1 := by
    simpa only [decode_normalizeMemo] using appendRefreshedLocal_log_bound bounds ρ state node content within
  rw [writeEntryNext, evalEntry_normalizeMemo,
    refreshCompletedExpr_correct bounds ρ (bounds.logCapacity + 1) _ node _ hb,
    evalEntry_normalizeMemo, writeLocal_correct, decode_normalizeMemo,
    appendRefreshedLocal_correct bounds ρ state node content within]

end CCFRaft.SymbolicTransition
