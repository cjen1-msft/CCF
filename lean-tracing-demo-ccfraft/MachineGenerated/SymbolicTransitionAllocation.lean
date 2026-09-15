-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionWrite
import MachineGenerated.LeaderWriteMappingProofs

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem nodeTableExpr_correct {α : Type} (c : Codec α) (ρ : Assignment)
    (values : Node → Expr c.ty) (node : Node) :
    ((nodeTableCodec c).decode ρ (tableExpr values)).get node = c.decode ρ (values node) := by
  simp [nodeTableCodec, Codec.decode, Codec.transport, Codec.table, BoundedState.NodeTable.get]

theorem nodeTableGet_correct {α : Type} (c : Codec α) (ρ : Assignment)
    (values : Expr (nodeTableCodec c).ty) (node : Node) :
    c.decode ρ (tableGet values node) = ((nodeTableCodec c).decode ρ values).get node := by
  simp [nodeTableCodec, Codec.decode, Codec.transport, Codec.table, BoundedState.NodeTable.get]

theorem nodeSetBit_correct (ρ : Assignment) (nodes : Expr nodeSetCodec.ty) (node : Node) :
    (tableGet nodes node).eval ρ = decide (node ∈ nodeSetCodec.decode ρ nodes) := by
  simp [Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool]

def allocateSlot (old : Option BoundedState.LocalStateData) (added : Bool) :
    Option BoundedState.LocalStateData :=
  match old with
  | some value => some value
  | none => if added then some (BoundedState.encodeLocal freshNodeState) else none

def allocateSlotExpr (old : Expr localCodec.option.ty) (added : Expr .bool) : Expr localCodec.option.ty :=
  .ite (.and added (.not (isSome old)))
    (localCodec.option.literal (some (BoundedState.encodeLocal freshNodeState))) old

theorem allocateSlotExpr_correct (ρ : Assignment) (old : Expr localCodec.option.ty) (added : Expr .bool) :
    localCodec.option.decode ρ (allocateSlotExpr old added) =
      allocateSlot (localCodec.option.decode ρ old) (added.eval ρ) := by
  rw [allocateSlotExpr, decode_choose]
  have present := isSome_value localCodec ρ old
  change (isSome old).eval ρ = (localCodec.option.decode ρ old).isSome at present
  simp only [Expr.eval, present]
  cases ho : localCodec.option.decode ρ old <;>
    cases ha : added.eval ρ <;> simp [allocateSlot, Codec.decode_literal, ho, ha]

def allocateData {transactions : Nat} (state : EntryData transactions) (added : Finset Node) :
    EntryData transactions :=
  (Vector.ofFn (fun node => allocateSlot (state.1.get node) (decide (node ∈ added))), state.2)

theorem allocateData_correct {transactions : Nat} (state : EntryData transactions) (added : Finset Node) :
    BoundedState.decode (allocateData state added).toData =
      { BoundedState.decode state.toData with nodes := (BoundedState.decode state.toData).nodes.allocate added } := by
  apply state_ext
  · intro node
    have old : state.toData.decodeNodes.node? node =
        (state.1.get node).map BoundedState.decodeLocal := by
      simp [BoundedState.Data.node?_decodeNodes, EntryData.toData]
    simp only [State.node?, BoundedState.decode, BoundedState.Data.node?_decodeNodes]
    change ((Vector.ofFn (fun candidate =>
      allocateSlot (state.1.get candidate) (decide (candidate ∈ added)))).get node).map
        BoundedState.decodeLocal = _
    rw [Vector.get_ofFn]
    cases hslot : state.1.get node with
    | some value =>
        have present : state.toData.decodeNodes.allocated node := by
          simp [NodeStore.allocated, old, hslot]
        rw [NodeStore.node?_allocate_of_allocated _ added node present, old, hslot]
        rfl
    | none =>
        have absent : ¬state.toData.decodeNodes.allocated node := by
          simp [NodeStore.allocated, old, hslot]
        by_cases member : node ∈ added
        · rw [NodeStore.node?_allocate_of_not_allocated_of_mem _ added node absent member]
          simp [allocateSlot, member]
        · rw [TransactionMapping.NodeStore.node?_allocate_of_not_allocated_of_not_mem
            _ added node absent member]
          simp [allocateSlot, member]
  all_goals rfl

def allocateExpr (transactions : Nat) (state : Expr (stateCodec transactions).ty) (added : Expr nodeSetCodec.ty) :
    Expr (stateCodec transactions).ty :=
  .pair (tableExpr fun node => (allocateSlotExpr (tableGet state.fst node) (tableGet added node)).normalizeMemo) state.snd

theorem allocateExpr_decode (transactions : Nat) (ρ : Assignment)
    (state : Expr (stateCodec transactions).ty) (added : Expr nodeSetCodec.ty) :
    (stateCodec transactions).decode ρ (allocateExpr transactions state added) =
      allocateData ((stateCodec transactions).decode ρ state) (nodeSetCodec.decode ρ added) := by
  apply Prod.ext
  · apply Vector.ext
    intro i hi
    have h := nodeTableExpr_correct localCodec.option ρ
      (fun node => (allocateSlotExpr (tableGet state.fst node) (tableGet added node)).normalizeMemo) ⟨i, hi⟩
    rw [decode_normalizeMemo, allocateSlotExpr_correct, nodeTableGet_correct, nodeSetBit_correct] at h
    simpa only [allocateData, Vector.get, Vector.getElem_ofFn] using h
  · rfl

theorem allocateExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (added : Expr nodeSetCodec.ty) :
    evalEntry bounds ρ (allocateExpr bounds.transactionCount state added) =
      { evalEntry bounds ρ state with nodes := (evalEntry bounds ρ state).nodes.allocate (nodeSetCodec.decode ρ added) } := by
  unfold evalEntry
  rw [allocateExpr_decode]
  exact allocateData_correct _ _

def setJoinedData {transactions : Nat} (state : EntryData transactions) (joined : Finset Node) :
    EntryData transactions :=
  (state.1, state.2.1, state.2.2.1, joined, state.2.2.2.2)

theorem setJoinedData_correct {transactions : Nat} (state : EntryData transactions) (joined : Finset Node) :
    BoundedState.decode (setJoinedData state joined).toData =
      { BoundedState.decode state.toData with hasJoined := joined } := by
  rfl

def setJoinedExpr (transactions : Nat) (state : Expr (stateCodec transactions).ty) (joined : Expr nodeSetCodec.ty) :
    Expr (stateCodec transactions).ty :=
  .pair state.fst (.pair state.snd.fst (.pair state.snd.snd.fst (.pair joined state.snd.snd.snd.snd)))

theorem setJoinedExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (joined : Expr nodeSetCodec.ty) :
    evalEntry bounds ρ (setJoinedExpr bounds.transactionCount state joined) =
      { evalEntry bounds ρ state with hasJoined := nodeSetCodec.decode ρ joined } := by
  exact setJoinedData_correct ((stateCodec bounds.transactionCount).decode ρ state)
    (nodeSetCodec.decode ρ joined)

def setSentExpr (value : Expr localCodec.ty) (sent : Expr (nodeTableCodec Codec.nat).ty) : Expr localCodec.ty :=
  .pair value.fst (.pair value.snd.fst (.pair value.snd.snd.fst
    (.pair value.snd.snd.snd.fst (.pair sent value.snd.snd.snd.snd.snd))))

theorem setSentExpr_correct (ρ : Assignment) (value : Expr localCodec.ty) (sent : Expr (nodeTableCodec Codec.nat).ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (setSentExpr value sent)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with
        sentIndex := ((nodeTableCodec Codec.nat).decode ρ sent).get } := by
  rfl

def setAddedSentExpr (value : Expr localCodec.ty) (added : Expr nodeSetCodec.ty) (index : Expr .nat) :
    Expr localCodec.ty :=
  setSentExpr value (tableExpr fun node =>
    .ite (tableGet added node) index (tableGet value.snd.snd.snd.snd.fst node))

def withAddedSent (value : NodeState Node Nat) (added : Finset Node) (index : Nat) : NodeState Node Nat :=
  { value with sentIndex := fun node => if node ∈ added then index else value.sentIndex node }

theorem setAddedSentExpr_correct (ρ : Assignment) (value : Expr localCodec.ty)
    (added : Expr nodeSetCodec.ty) (index : Expr .nat) :
    BoundedState.decodeLocal (localCodec.decode ρ (setAddedSentExpr value added index)) =
      withAddedSent (BoundedState.decodeLocal (localCodec.decode ρ value))
        (nodeSetCodec.decode ρ added) (index.eval ρ) := by
  have sent :
      ((nodeTableCodec Codec.nat).decode ρ (tableExpr fun node =>
        Expr.ite (tableGet added node) index (tableGet value.snd.snd.snd.snd.fst node))).get =
      fun node => if node ∈ nodeSetCodec.decode ρ added then index.eval ρ
        else (BoundedState.decodeLocal (localCodec.decode ρ value)).sentIndex node := by
    funext node
    rw [nodeTableExpr_correct]
    change (if (tableGet added node).eval ρ = true then index.eval ρ
      else (tableGet value.snd.snd.snd.snd.fst node).eval ρ) =
      if node ∈ nodeSetCodec.decode ρ added then index.eval ρ
      else (BoundedState.decodeLocal (localCodec.decode ρ value)).sentIndex node
    have member : node ∈ nodeSetCodec.decode ρ added ↔ (tableGet added node).eval ρ = true := by
      simp [Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool]
    by_cases present : node ∈ nodeSetCodec.decode ρ added
    · rw [if_pos (member.mp present), if_pos present]
    · have absent : ¬(tableGet added node).eval ρ = true := fun h => present (member.mpr h)
      rw [if_neg absent, if_neg present]
      exact nodeTableGet_correct Codec.nat ρ value.snd.snd.snd.snd.fst node
  rw [setAddedSentExpr, setSentExpr_correct, sent]
  rfl

theorem refreshRetirement_setSent (node : Node) (value : NodeState Node Nat) (sent : Node → Nat) :
    refreshRetirementState node { value with sentIndex := sent } =
      { refreshRetirementState node value with sentIndex := sent } := by
  rfl

theorem withAddedSent_refresh (node : Node) (value : NodeState Node Nat) (added : Finset Node) (index : Nat) :
    withAddedSent (refreshRetirementState node value) added index =
      refreshRetirementState node (withAddedSent value added index) := by
  rfl

theorem intersection_empty_iff (a b : Finset Node) :
    a ∩ b = ∅ ↔ ∀ node ∈ a, node ∉ b := by
  constructor
  · intro empty node ha hb
    have member : node ∈ a ∩ b := Finset.mem_inter.mpr ⟨ha, hb⟩
    rw [empty] at member
    simp at member
  · intro disjoint
    ext node
    constructor
    · intro member
      exact False.elim (disjoint node (Finset.mem_inter.mp member).1 (Finset.mem_inter.mp member).2)
    · intro member
      simp at member

end CCFRaft.SymbolicTransition
