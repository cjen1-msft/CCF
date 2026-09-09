-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicEntry
import Shared.SymbolicFinite
import TraceStateObservation

set_option autoImplicit false

namespace CCFRaft.SymbolicStateObservation

open Symbolic SymbolicModel TraceStateObservation

/-- The fallback is the model's fresh state, not an arbitrary codec inhabitant. -/
def localState {transactions : Nat} (entry : Expr (stateCodec transactions).ty)
    (node : Node) : Expr localCodec.ty :=
  (tableGet entry.fst node).rightD
    (localCodec.literal (BoundedState.encodeLocal freshNodeState))

private theorem localGetD_correct (ρ : Assignment) (slot : Expr localCodec.option.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ
      (slot.rightD (localCodec.literal (BoundedState.encodeLocal freshNodeState)))) =
      ((localCodec.option.decode ρ slot).map BoundedState.decodeLocal).getD freshNodeState := by
  cases selected : slot.eval ρ with
  | inl value =>
      simp [Codec.decode, Codec.option, Expr.eval, selected, Codec.literal]
  | inr value => simp [Codec.decode, Codec.option, Expr.eval, selected]

theorem localState_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (node : Node) :
    BoundedState.decodeLocal (localCodec.decode ρ (localState entry node)) =
      (evalEntry bounds ρ entry).nodes node := by
  rw [localState, localGetD_correct]
  change _ = ((evalEntry bounds ρ entry).node? node).getD freshNodeState
  rw [evalEntry_node?]
  congr 2
  simp [Codec.decode, Codec.option, Codec.prod, Expr.eval, nodeTableCodec,
    Codec.table, Codec.transport, BoundedState.NodeTable.get]

private def retirementFields (state : Expr localCodec.ty) :
    Expr (membershipCodec.prod (Codec.nat.option.prod
      (Codec.nat.option.prod Codec.nat.option))).ty :=
  state.snd.snd.snd.snd.snd.snd.snd.snd.snd.snd

private theorem preVote_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (node : Node) :
    preVoteCodec.decode ρ (tableGet entry.snd.snd.snd.snd.fst node) =
      (evalEntry bounds ρ entry).preVoteStatus node := by
  simp [evalEntry, EntryData.toData, BoundedState.decode, Codec.decode, Codec.prod,
    nodeTableCodec, Codec.table, Codec.transport, BoundedState.NodeTable.get, Expr.eval]

private theorem retirementCompleted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (observer : Node) :
    nodeSetCodec.decode ρ (tableGet entry.snd.snd.snd.snd.snd observer) =
      (evalEntry bounds ρ entry).retirementCompleted observer := by
  simp [evalEntry, EntryData.toData, BoundedState.decode, Codec.decode, Codec.prod,
    nodeTableCodec, Codec.table, Codec.transport, BoundedState.NodeTable.get, Expr.eval]

private theorem nodeMember_correct (ρ : Assignment) (bits : Expr nodeSetCodec.ty)
    (node : Node) :
    (setMember bits (.nat node.val)).eval ρ =
      decide (node ∈ nodeSetCodec.decode ρ bits) := by
  have correct : (setMember bits (.nat node.val)).eval ρ = true ↔
      node ∈ nodeSetCodec.decode ρ bits :=
    (setMember_correct ρ bits (.nat node.val)).trans (by
      change node.val ∈ (nodeSetCodec.decode ρ bits).image Fin.val ↔ _
      rw [Finset.mem_image]
      constructor
      · rintro ⟨other, member, same⟩
        exact (Fin.ext same : other = node) ▸ member
      · exact fun member => ⟨node, member, rfl⟩)
  cases evaluated : (setMember bits (.nat node.val)).eval ρ <;> simp_all

def expression (bounds : BoundedState.Bounds)
    (entry : Expr (stateCodec bounds.transactionCount).ty) :
    Observation Node -> Expr .bool
  | .preVoteStatus node value =>
      .eq (tableGet entry.snd.snd.snd.snd.fst node) (preVoteCodec.literal value)
  | .membershipState node value =>
      .eq (retirementFields (localState entry node)).fst (membershipCodec.literal value)
  | .retirementIndex node value =>
      .eq (retirementFields (localState entry node)).snd.fst (Codec.nat.option.literal value)
  | .retirementCommittableIndex node value =>
      .eq (retirementFields (localState entry node)).snd.snd.fst (Codec.nat.option.literal value)
  | .retiredCommittedIndex node value =>
      .eq (retirementFields (localState entry node)).snd.snd.snd (Codec.nat.option.literal value)
  | .retirementCompleted observer retired value =>
      .eq (setMember (tableGet entry.snd.snd.snd.snd.snd observer) (.nat retired.val))
        (.bool value)

theorem expression_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (observation : Observation Node) :
    (expression bounds entry observation).eval ρ = true ↔
      observation.Holds (evalEntry bounds ρ entry) := by
  cases observation with
  | preVoteStatus node value =>
      simp only [expression, preVoteCodec.equal_correct, Codec.decode_literal,
        preVote_correct, Observation.Holds]
  | membershipState node value =>
      rw [expression, membershipCodec.equal_correct, Codec.decode_literal, Observation.Holds,
        ← localState_correct bounds ρ entry node]
      rfl
  | retirementIndex node value =>
      rw [expression, Codec.nat.option.equal_correct, Codec.decode_literal, Observation.Holds,
        ← localState_correct bounds ρ entry node]
      rfl
  | retirementCommittableIndex node value =>
      rw [expression, Codec.nat.option.equal_correct, Codec.decode_literal, Observation.Holds,
        ← localState_correct bounds ρ entry node]
      rfl
  | retiredCommittedIndex node value =>
      rw [expression, Codec.nat.option.equal_correct, Codec.decode_literal, Observation.Holds,
        ← localState_correct bounds ρ entry node]
      rfl
  | retirementCompleted observer retired value =>
      rw [expression, Codec.bool.equal_correct]
      change (setMember (tableGet entry.snd.snd.snd.snd.snd observer)
        (.nat retired.val)).eval ρ = value ↔ _
      rw [nodeMember_correct, retirementCompleted_correct]
      rfl

end CCFRaft.SymbolicStateObservation
