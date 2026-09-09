-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicModel
import Shared.SymbolicInput

set_option autoImplicit false

namespace CCFRaft.SymbolicModel

open Symbolic

abbrev EntryData (transactions : Nat) :=
  BoundedState.NodeTable (Option BoundedState.LocalStateData) ×
    BoundedState.NodeTable (List (Message Node Nat)) × Finset (Fin transactions) ×
      Finset Node × BoundedState.NodeTable PreVoteStatus ×
        BoundedState.NodeTable (Finset Node)

abbrev stateCodec (transactions : Nat) : Codec (EntryData transactions) :=
  (nodeTableCodec localCodec.option).prod ((nodeTableCodec queueCodec).prod
    ((Codec.finset transactions).prod (nodeSetCodec.prod
      ((nodeTableCodec preVoteCodec).prod (nodeTableCodec nodeSetCodec)))))

def EntryData.toData {transactions : Nat} (v : EntryData transactions) : BoundedState.Data where
  nodes := v.1
  network := v.2.1
  submittedTxIds := v.2.2.1.image Fin.val
  hasJoined := v.2.2.2.1
  preVoteStatus := v.2.2.2.2.1
  retirementCompleted := v.2.2.2.2.2

def capacities (bounds : BoundedState.Bounds) : Capacities := fun s =>
  if s = queueCodec.ty then bounds.queueCapacity
  else if s = logCodec.ty then bounds.logCapacity
  else 0

def freshEntry (bounds : BoundedState.Bounds) (start : Nat := 0) :
    Expr (stateCodec bounds.transactionCount).ty :=
  fresh (capacities bounds) (stateCodec bounds.transactionCount).ty start

def entryWidth (bounds : BoundedState.Bounds) : Nat :=
  inputWidth (capacities bounds) (stateCodec bounds.transactionCount).ty

def evalEntry (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr (stateCodec bounds.transactionCount).ty) : CCFRaft.State Node Nat :=
  BoundedState.decode ((stateCodec bounds.transactionCount).decode ρ e).toData

theorem freshEntry_fits (bounds : BoundedState.Bounds) (start : Nat) (ρ : Assignment) :
    Fits (capacities bounds) (stateCodec bounds.transactionCount).ty
      ((freshEntry bounds start).eval ρ) :=
  fresh_fits (capacities bounds) _ start ρ

-- The premise is the exact recursive capacity predicate, not reachability.
theorem freshEntry_complete (bounds : BoundedState.Bounds) (start : Nat)
    (v : EntryData bounds.transactionCount)
    (fits : Fits (capacities bounds) (stateCodec bounds.transactionCount).ty
      ((stateCodec bounds.transactionCount).equiv.symm v)) :
    ∃ ρ : Assignment, evalEntry bounds ρ (freshEntry bounds start) =
      BoundedState.decode v.toData := by
  obtain ⟨ρ, hρ⟩ := fresh_surjective (capacities bounds)
    (stateCodec bounds.transactionCount).ty start
    ((stateCodec bounds.transactionCount).equiv.symm v) fits
  refine ⟨ρ, ?_⟩
  simp [evalEntry, freshEntry, Codec.decode, hρ]

theorem evalEntry_node? (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr (stateCodec bounds.transactionCount).ty) (node : Node) :
    (evalEntry bounds ρ e).node? node =
      (((stateCodec bounds.transactionCount).decode ρ e).1.get node).map
        BoundedState.decodeLocal := by
  simp [evalEntry, BoundedState.decode, CCFRaft.State.node?, EntryData.toData]

theorem evalEntry_bounds_iff (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr (stateCodec bounds.transactionCount).ty) :
    BoundedState.WithinBounds bounds (evalEntry bounds ρ e) ↔
      BoundedState.DataWithinBounds bounds
        ((stateCodec bounds.transactionCount).decode ρ e).toData :=
  BoundedState.decode_withinBounds_iff bounds _

end CCFRaft.SymbolicModel
