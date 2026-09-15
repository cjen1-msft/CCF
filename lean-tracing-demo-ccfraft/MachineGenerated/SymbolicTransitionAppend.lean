-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionAllocation
import MachineGenerated.SymbolicTransitionVoteSend

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def sentTo (value : Expr localCodec.ty) (destination : Expr nodeCodec.ty) : Expr .nat :=
  tableSelect value.snd.snd.snd.snd.fst destination

theorem sentTo_correct (ρ : Assignment) (value : Expr localCodec.ty) (destination : Expr nodeCodec.ty) :
    (sentTo value destination).eval ρ =
      (BoundedState.decodeLocal (localCodec.decode ρ value)).sentIndex (nodeCodec.decode ρ destination) := by
  exact nodeTableSelect_correct Codec.nat ρ value.snd.snd.snd.snd.fst destination

def appendRequestFields (value : Expr localCodec.ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) : Expr appendRequestCodec.ty :=
  let previous := sentTo value destination
  let log := value.snd.snd.fst
  .pair value.snd.fst (.pair previous (.pair (termAtExpr log previous)
    (.pair (logSlice log previous batchEnd) (.pair value.snd.snd.snd.fst (.pair source destination)))))

theorem appendRequestFields_correct (ρ : Assignment) (value : Expr localCodec.ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) :
    appendRequestCodec.decode ρ (appendRequestFields value source destination batchEnd) =
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      let previous := before.sentIndex (nodeCodec.decode ρ destination)
      AppendEntriesRequest.mk before.currentTerm previous (termAt before.log previous)
        (messageEntries before.log previous (batchEnd.eval ρ)) before.commitIndex
        (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) := by
  change AppendEntriesRequest.mk (value.snd.fst.eval ρ) ((sentTo value destination).eval ρ)
    ((termAtExpr value.snd.snd.fst (sentTo value destination)).eval ρ)
    (logCodec.decode ρ (logSlice value.snd.snd.fst (sentTo value destination) batchEnd))
    (value.snd.snd.snd.fst.eval ρ) (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) = _
  simp only [termAtExpr_correct, logSlice_correct, sentTo_correct]
  rfl

def appendSendMessage (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) : Expr messageCodec.ty :=
  .inl (appendRequestFields (readLocal bounds.transactionCount state source) source destination batchEnd)

theorem appendSendMessage_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) :
    messageCodec.decode ρ (appendSendMessage bounds state source destination batchEnd) =
      .appendEntriesRequest (makeAppendEntriesRequest (evalEntry bounds ρ state)
        (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) (batchEnd.eval ρ)) := by
  change Message.appendEntriesRequest
    (appendRequestCodec.decode ρ (appendRequestFields
      (readLocal bounds.transactionCount state source) source destination batchEnd)) = _
  rw [appendRequestFields_correct, readLocal_correct]
  rfl

def setSentTo (value : Expr localCodec.ty) (destination : Expr nodeCodec.ty) (index : Expr .nat) :
    Expr localCodec.ty :=
  setSentExpr value (tableStore value.snd.snd.snd.snd.fst (finValue destination) index)

theorem setSentTo_correct (ρ : Assignment) (value : Expr localCodec.ty)
    (destination : Expr nodeCodec.ty) (index : Expr .nat) :
    BoundedState.decodeLocal (localCodec.decode ρ (setSentTo value destination index)) =
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      { before with sentIndex := updateIndex before.sentIndex (nodeCodec.decode ρ destination) (index.eval ρ) } := by
  rw [setSentTo, setSentExpr_correct]
  have indices : ((nodeTableCodec Codec.nat).decode ρ
      (tableStore value.snd.snd.snd.snd.fst (finValue destination) index)).get =
      updateIndex (BoundedState.decodeLocal (localCodec.decode ρ value)).sentIndex
        (nodeCodec.decode ρ destination) (index.eval ρ) := by
    funext peer
    rw [nodeTableStore_correct]
    change (if nodeCodec.decode ρ destination = peer then index.eval ρ else
      (BoundedState.decodeLocal (localCodec.decode ρ value)).sentIndex peer) = _
    simp only [updateIndex, Function.update_apply, eq_comm]
  rw [indices]

def appendSendEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) : Expr .bool :=
  let value := readLocal bounds.transactionCount state source
  let previous := sentTo value destination
  .and (allocated bounds.transactionCount state source)
    (.and (allocated bounds.transactionCount state destination)
      (.and (.eq value.fst (roleCodec.literal .leader))
        (.and (.not (.eq source destination))
          (.and (.or (nodeSetContains (localActiveNodes bounds.logCapacity value) destination)
              (nodeSetContains (readCompleted bounds.transactionCount state source) destination))
            (.and (.eq batchEnd (SymbolicReceive.minimum (.add previous (.nat 1)) value.snd.snd.fst.length))
              (.or (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
                (.lt previous batchEnd)))))))

theorem appendSendEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (appendSendEnabled bounds state source destination batchEnd).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.appendEntries (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) (batchEnd.eval ρ)) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state source)
  have member := congrArg NodeState.membershipState (readLocal_correct bounds ρ state source)
  have logeq := congrArg NodeState.log (readLocal_correct bounds ρ state source)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state source).fst = _ at role
  change membershipCodec.decode ρ (localMembership (readLocal bounds.transactionCount state source)) = _ at member
  change logCodec.decode ρ (readLocal bounds.transactionCount state source).snd.snd.fst = _ at logeq
  have length : ((readLocal bounds.transactionCount state source).eval ρ).2.2.1.length =
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source)).log.length := by
    simpa [Codec.decode, Codec.list, Expr.eval] using congrArg List.length logeq
  simp only [appendSendEnabled, boolAnd_true ρ, boolOr_true ρ, boolNot_true ρ,
    allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state source).fst (roleCodec.literal .leader),
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state source))
      (membershipCodec.literal .retiredCommitted),
    nodeCodec.equal_correct ρ source destination,
    nodeSetContains_correct ρ, localActiveNodes_correct ρ bounds.logCapacity _
      (readLocal_log_bound bounds ρ state source within), readCompleted_correct,
    Codec.decode_literal, role, member, readLocal_correct]
  simp only [Expr.eval, SymbolicReceive.minimum_correct, sentTo_correct, readLocal_correct,
    length, decide_eq_true_eq, Enabled]

def appendSendNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) : Expr (stateCodec bounds.transactionCount).ty :=
  let value := (setSentTo (readLocal bounds.transactionCount state source) destination batchEnd).normalizeMemo
  (SymbolicReceive.enqueue bounds.transactionCount
    (writeLocal bounds.transactionCount state source value).normalizeMemo
    (appendSendMessage bounds state source destination batchEnd).normalizeMemo).normalizeMemo

theorem appendSendNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) :
    evalEntry bounds ρ (appendSendNext bounds state source destination batchEnd) =
      next (evalEntry bounds ρ state)
        (.appendEntries (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) (batchEnd.eval ρ)) := by
  rw [appendSendNext, evalEntry_normalizeMemo, SymbolicReceive.enqueue_correct,
    evalEntry_normalizeMemo, writeLocal_correct]
  simp only [decode_normalizeMemo, setSentTo_correct, readLocal_correct, appendSendMessage_correct]
  rfl

def appendSendAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat) : Expr .bool :=
  .and (appendSendEnabled bounds state source destination batchEnd)
    (stateWithin bounds (appendSendNext bounds state source destination batchEnd))

theorem appendSendAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) (batchEnd : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (appendSendAccepted bounds state source destination batchEnd).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.appendEntries (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) (batchEnd.eval ρ)) ∧
      BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state)
        (.appendEntries (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) (batchEnd.eval ρ))) := by
  simp only [appendSendAccepted, boolAnd_true ρ, appendSendEnabled_correct bounds ρ state source destination batchEnd within,
    stateWithin_correct bounds ρ, appendSendNext_correct]

end CCFRaft.SymbolicTransition
