-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicEntry

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem submittedTransactionBound (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (transaction : Nat)
    (member : transaction ∈ (evalEntry bounds ρ state).submittedTxIds) :
    transaction < bounds.transactionCount := by
  change transaction ∈ ((stateCodec bounds.transactionCount).decode ρ state).2.2.1.image Fin.val at member
  obtain ⟨index, _, same⟩ := Finset.mem_image.mp member
  rw [← same]
  exact index.isLt

theorem clientTransactionBound_of_successorWithin (bounds : BoundedState.Bounds)
    (state : CCFRaft.State Node Nat) (node : Node) (transaction : Nat)
    (after : BoundedState.WithinBounds bounds (next state (.clientRequest node transaction))) :
    transaction < bounds.transactionCount := by
  apply after.2.2 transaction
  exact Finset.mem_insert_self transaction state.submittedTxIds

theorem clientNext_outside_unrepresentable (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : CCFRaft.State Node Nat) (node : Node) (transaction : Nat)
    (outside : bounds.transactionCount ≤ transaction)
    (encoded : Expr (stateCodec bounds.transactionCount).ty) :
    evalEntry bounds ρ encoded ≠ next state (.clientRequest node transaction) := by
  intro same
  have member : transaction ∈ (evalEntry bounds ρ encoded).submittedTxIds := by
    rw [same]
    exact Finset.mem_insert_self transaction state.submittedTxIds
  have bound := submittedTransactionBound bounds ρ encoded transaction member
  omega

end CCFRaft.SymbolicTransition
