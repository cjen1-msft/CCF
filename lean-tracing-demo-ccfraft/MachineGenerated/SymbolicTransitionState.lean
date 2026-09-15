-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionHelpers
import MachineGenerated.SymbolicObservations
import Shared.SymbolicNormalizeMemo

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem decode_normalize {α : Type} (c : Codec α) (ρ : Assignment) (value : Expr c.ty) :
    c.decode ρ value.normalize = c.decode ρ value := by
  simp only [Codec.decode, Expr.normalize_correct]

theorem decode_normalizeMemo {α : Type} (c : Codec α) (ρ : Assignment) (value : Expr c.ty) :
    c.decode ρ value.normalizeMemo = c.decode ρ value := by
  simp only [Codec.decode, Expr.normalizeMemo_correct]

theorem evalEntry_normalize (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) :
    evalEntry bounds ρ state.normalize = evalEntry bounds ρ state := by
  simp only [evalEntry, decode_normalize]

theorem evalEntry_normalizeMemo (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) :
    evalEntry bounds ρ state.normalizeMemo = evalEntry bounds ρ state := by
  simp only [evalEntry, decode_normalizeMemo]

def compactCase {a b c : Ty} (value : Expr (.sum a b))
    (onLeft : Expr a → Expr c) (onRight : Expr b → Expr c) : Expr c :=
  matchSum value.normalizeMemo (fun x => onLeft x.normalizeMemo) (fun x => onRight x.normalizeMemo)

theorem compactCase_correct {a b c : Ty} (ρ : Assignment) (value : Expr (.sum a b))
    (onLeft : Expr a → Expr c) (onRight : Expr b → Expr c)
    (f : a.Value → c.Value) (g : b.Value → c.Value)
    (hl : ∀ x, (onLeft x).eval ρ = f (x.eval ρ))
    (hr : ∀ x, (onRight x).eval ρ = g (x.eval ρ)) :
    (compactCase value onLeft onRight).eval ρ =
      match value.eval ρ with | .inl x => f x | .inr x => g x := by
  unfold compactCase
  rw [matchSum_correct ρ value.normalizeMemo
    (fun x => onLeft x.normalizeMemo) (fun x => onRight x.normalizeMemo) f g
    (fun x => by simp only [hl, Expr.normalizeMemo_correct])
    (fun x => by simp only [hr, Expr.normalizeMemo_correct]), Expr.normalizeMemo_correct]
  rfl

def optionCases {a b : Ty} (value : Expr (.sum .unit a))
    (onNone : Expr b) (onSome : Expr a → Expr b) : Expr b :=
  compactCase value (fun _ => onNone) onSome

theorem optionCases_correct {α β : Type} (a : Codec α) (b : Codec β)
    (ρ : Assignment) (value : Expr a.option.ty) (onNone : Expr b.ty)
    (onSome : Expr a.ty → Expr b.ty) (f : α → β)
    (correct : ∀ x, b.decode ρ (onSome x) = f (a.decode ρ x)) :
    b.decode ρ (optionCases value onNone onSome) =
      (a.option.decode ρ value).elim (b.decode ρ onNone) f := by
  cases hv : value.eval ρ <;>
    simp [optionCases, compactCase, matchSum, Codec.decode, Codec.option, Expr.normalizeMemo_correct, Expr.eval, hv,
      show ∀ x, b.equiv ((onSome x).eval ρ) = f (a.equiv (x.eval ρ)) from correct]

def isSome {a : Ty} (value : Expr (.sum .unit a)) : Expr .bool :=
  .not value.isLeft

theorem isSome_correct {α : Type} (a : Codec α) (ρ : Assignment)
    (value : Expr a.option.ty) :
    (isSome value).eval ρ = true ↔ (a.option.decode ρ value).isSome := by
  cases hv : value.eval ρ <;> simp [isSome, Codec.decode, Codec.option, Expr.eval, hv]

theorem nodeTableSelect_correct {α : Type} (c : Codec α) (ρ : Assignment)
    (values : Expr (nodeTableCodec c).ty) (node : Expr nodeCodec.ty) :
    c.decode ρ (tableSelect values node) =
      ((nodeTableCodec c).decode ρ values).get (nodeCodec.decode ρ node) := by
  simp [tableSelect_correct, nodeTableCodec, Codec.decode, Codec.table,
    Codec.transport, BoundedState.NodeTable.get, Codec.fin]
  rfl

theorem nodeTableStore_correct {α : Type} (c : Codec α) (ρ : Assignment)
    (values : Expr (nodeTableCodec c).ty) (node : Expr nodeCodec.ty)
    (value : Expr c.ty) (n : Node) :
    ((nodeTableCodec c).decode ρ (tableStore values (finValue node) value)).get n =
      if nodeCodec.decode ρ node = n then c.decode ρ value
      else ((nodeTableCodec c).decode ρ values).get n := by
  simp [nodeTableCodec, Codec.decode, Codec.table, Codec.transport,
    BoundedState.NodeTable.get, tableStore_correct, finValue_correct, Codec.fin,
    Fin.val_inj]
  split_ifs <;> first | rfl | contradiction

def entryNode (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) : Expr localCodec.option.ty :=
  tableSelect state.fst node

theorem entryNode_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    (localCodec.option.decode ρ (entryNode bounds.transactionCount state node)).map
      BoundedState.decodeLocal = (evalEntry bounds ρ state).node? (nodeCodec.decode ρ node) := by
  rw [evalEntry_node?]
  exact congrArg (Option.map BoundedState.decodeLocal)
    (nodeTableSelect_correct localCodec.option ρ state.fst node)

def allocated (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) : Expr .bool :=
  isSome (entryNode transactions state node)

theorem allocated_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    (allocated bounds.transactionCount state node).eval ρ = true ↔
      (evalEntry bounds ρ state).allocated (nodeCodec.decode ρ node) := by
  rw [allocated, isSome_correct]
  change _ ↔ ((evalEntry bounds ρ state).node? (nodeCodec.decode ρ node)).isSome
  rw [← entryNode_correct bounds ρ state node, Option.isSome_map]

def readLocal (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) : Expr localCodec.ty :=
  optionCases (entryNode transactions state node)
    (localCodec.literal (BoundedState.encodeLocal freshNodeState)) id

theorem readLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (readLocal bounds.transactionCount state node)) =
      (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node) := by
  rw [readLocal, optionCases_correct localCodec localCodec ρ _ _ id id (fun _ => rfl),
    Codec.decode_literal]
  change _ = ((evalEntry bounds ρ state).node? (nodeCodec.decode ρ node)).getD freshNodeState
  rw [← entryNode_correct bounds ρ state node]
  cases localCodec.option.decode ρ (entryNode bounds.transactionCount state node) <;> simp

def writeLocal (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) (value : Expr localCodec.ty) : Expr (stateCodec transactions).ty :=
  .pair (tableStore state.fst (finValue node) (.inr value)) state.snd

theorem state_ext (s t : CCFRaft.State Node Nat)
    (hn : ∀ n, s.node? n = t.node? n)
    (hq : s.network = t.network) (ht : s.submittedTxIds = t.submittedTxIds)
    (hj : s.hasJoined = t.hasJoined) (hp : s.preVoteStatus = t.preVoteStatus)
    (hr : s.retirementCompleted = t.retirementCompleted) : s = t := by
  have hs : s.nodes = t.nodes := by
    cases left : s.nodes with
    | mk l =>
        cases right : t.nodes with
        | mk r =>
            congr 1
            apply Finmap.ext_lookup
            intro n
            simpa [State.node?, NodeStore.node?, left, right] using hn n
  cases s
  cases t
  simp_all

def writeLocalData {transactions : Nat} (state : EntryData transactions)
    (node : Node) (value : BoundedState.LocalStateData) : EntryData transactions :=
  (Vector.ofFn (fun n => if node = n then some value else state.1.get n), state.2)

theorem writeLocalData_correct {transactions : Nat} (state : EntryData transactions)
    (node : Node) (value : BoundedState.LocalStateData) :
    BoundedState.decode (writeLocalData state node value).toData =
      { BoundedState.decode state.toData with
        nodes := updateNode (BoundedState.decode state.toData).nodes node
          (BoundedState.decodeLocal value) } := by
  apply state_ext
  · intro n
    simp only [State.node?, BoundedState.decode, BoundedState.Data.node?_decodeNodes]
    change ((Vector.ofFn (fun n => if node = n then some value else state.1.get n)).get n).map
      BoundedState.decodeLocal = _
    simp only [Vector.get_ofFn]
    by_cases hn : node = n
    · subst n
      simp [updateNode]
    · rw [if_neg hn]
      simp [updateNode, Ne.symm hn, EntryData.toData]
  all_goals rfl

theorem writeLocal_decode (transactions : Nat) (ρ : Assignment)
    (state : Expr (stateCodec transactions).ty) (node : Expr nodeCodec.ty)
    (value : Expr localCodec.ty) :
    (stateCodec transactions).decode ρ (writeLocal transactions state node value) =
      writeLocalData ((stateCodec transactions).decode ρ state)
        (nodeCodec.decode ρ node) (localCodec.decode ρ value) := by
  apply Prod.ext
  · apply Vector.ext
    intro i hi
    have h := nodeTableStore_correct localCodec.option ρ state.fst node (.inr value) ⟨i, hi⟩
    simpa only [writeLocalData, BoundedState.NodeTable.get, Vector.get,
      Vector.getElem_ofFn] using h
  · rfl

theorem writeLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (value : Expr localCodec.ty) :
    evalEntry bounds ρ (writeLocal bounds.transactionCount state node value) =
      { evalEntry bounds ρ state with
        nodes := updateNode (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)
          (BoundedState.decodeLocal (localCodec.decode ρ value)) } := by
  unfold evalEntry
  rw [writeLocal_decode]
  exact writeLocalData_correct _ _ _

end CCFRaft.SymbolicTransition
