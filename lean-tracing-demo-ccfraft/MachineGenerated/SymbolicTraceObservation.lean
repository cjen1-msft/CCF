-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceObservation
import MachineGenerated.SymbolicStateObservation
import MachineGenerated.SymbolicMessageSummary

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceObservation

open Symbolic SymbolicModel SymbolicStateObservation

def expression (bounds : BoundedState.Bounds)
    (entry : Expr (stateCodec bounds.transactionCount).ty) : Observation -> Expr .bool
  | .role node value => .eq (localState entry node).fst (roleCodec.literal value)
  | .currentTerm node value => .eq (localState entry node).snd.fst (.nat value)
  | .logLength node value => .eq (localState entry node).snd.snd.fst.length (.nat value)
  | .queueLength node value => .eq (tableGet entry.snd.fst node).length (.nat value)
  | .commitIndex node value => .eq (localState entry node).snd.snd.snd.fst (.nat value)
  | .allocated node value => .eq (tableGet entry.fst node).isLeft.not (.bool value)
  | .joined node value => .eq (tableGet entry.snd.snd.snd.fst node) (.bool value)
  | .submitted transaction value =>
      .and (.lt transaction (.nat bounds.transactionCount))
        (.eq (setMember entry.snd.snd.fst transaction) (.bool value))
  | .state observation => SymbolicStateObservation.expression bounds entry observation
  | .message summary => entryMatchesSummary bounds entry summary

theorem expression_correct (bounds : BoundedState.Bounds) (assignment : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (observation : Observation)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds assignment entry)) :
    (expression bounds entry observation).eval assignment = true ↔
      observation.Holds bounds assignment (evalEntry bounds assignment entry) := by
  cases observation with
  | role node value =>
      rw [expression, roleCodec.equal_correct, Codec.decode_literal, Observation.Holds,
        ← localState_correct bounds assignment entry node]
      rfl
  | currentTerm node value =>
      rw [expression, Codec.nat.equal_correct, Observation.Holds,
        ← localState_correct bounds assignment entry node]
      rfl
  | logLength node value =>
      rw [expression, Codec.nat.equal_correct, Observation.Holds,
        ← localState_correct bounds assignment entry node]
      simp [Codec.decode, Codec.prod, Codec.transport, Codec.list,
        BoundedState.decodeLocal, Expr.eval]
  | queueLength node value =>
      simp [expression, Observation.Holds, evalEntry, EntryData.toData,
        BoundedState.decode, Codec.decode, Codec.prod, Codec.transport, Codec.table,
        nodeTableCodec, BoundedState.NodeTable.get, Codec.list, Expr.eval]
  | commitIndex node value =>
      rw [expression, Codec.nat.equal_correct, Observation.Holds,
        ← localState_correct bounds assignment entry node]
      rfl
  | allocated node value =>
      have selected := evalEntry_node? bounds assignment entry node
      have slot :
          localCodec.option.decode assignment (tableGet entry.fst node) =
            ((stateCodec bounds.transactionCount).decode assignment entry).1.get node := by
        simp [Codec.decode, Codec.option, Codec.prod, Expr.eval, nodeTableCodec,
          Codec.table, Codec.transport, BoundedState.NodeTable.get]
      rw [expression, Codec.bool.equal_correct, Observation.Holds]
      change (tableGet entry.fst node).isLeft.not.eval assignment = value ↔
        decide ((evalEntry bounds assignment entry).node? node |>.isSome) = value
      rw [selected, ← slot]
      cases chosen : (tableGet entry.fst node).eval assignment <;>
        simp [Expr.eval, Codec.decode, Codec.option, chosen]
  | joined node value =>
      simp [expression, Observation.Holds, evalEntry, EntryData.toData,
        BoundedState.decode, Codec.decode, Codec.prod, Codec.transport, Codec.table,
        Codec.finset, Codec.bool, Expr.eval]
  | submitted transaction value =>
      have member :
          (setMember entry.snd.snd.fst transaction).eval assignment = true ↔
            transaction.eval assignment ∈ (evalEntry bounds assignment entry).submittedTxIds := by
        simpa [evalEntry, EntryData.toData, BoundedState.decode, Codec.decode, Codec.prod,
          Expr.eval] using setMember_correct assignment entry.snd.snd.fst transaction
      have same :
          (setMember entry.snd.snd.fst transaction).eval assignment =
            decide (transaction.eval assignment ∈
              (evalEntry bounds assignment entry).submittedTxIds) := by
        cases chosen : (setMember entry.snd.snd.fst transaction).eval assignment <;> simp_all
      simp only [expression, Expr.eval, Bool.and_eq_true, decide_eq_true_eq,
        Observation.Holds]
      rw [same]
  | state observation =>
      exact SymbolicStateObservation.expression_correct bounds assignment entry observation
  | message summary =>
      exact entryMatchesSummary_correct bounds assignment entry summary within

end CCFRaft.SymbolicTraceObservation
