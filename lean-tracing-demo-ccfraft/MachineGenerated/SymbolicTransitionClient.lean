-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionSignature
import MachineGenerated.SymbolicTransitionTransactionDomain

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def submittedContains (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (transaction : Expr .nat) : Expr .bool :=
  setMember state.snd.snd.fst transaction

theorem submittedContains_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (transaction : Expr .nat) :
    (submittedContains bounds state transaction).eval ρ = true ↔
      transaction.eval ρ ∈ (evalEntry bounds ρ state).submittedTxIds :=
  setMember_correct ρ state.snd.snd.fst transaction

def setSubmittedData {transactions : Nat} (state : EntryData transactions)
    (submitted : Finset (Fin transactions)) : EntryData transactions :=
  (state.1, state.2.1, submitted, state.2.2.2)

theorem setSubmittedData_correct {transactions : Nat} (state : EntryData transactions)
    (submitted : Finset (Fin transactions)) :
    BoundedState.decode (setSubmittedData state submitted).toData =
      { BoundedState.decode state.toData with submittedTxIds := submitted.image Fin.val } := by
  rfl

def setSubmittedExpr (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (submitted : Expr (Codec.finset transactions).ty) : Expr (stateCodec transactions).ty :=
  .pair state.fst (.pair state.snd.fst (.pair submitted state.snd.snd.snd))

theorem setSubmittedExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (submitted : Expr (Codec.finset bounds.transactionCount).ty) :
    evalEntry bounds ρ (setSubmittedExpr bounds.transactionCount state submitted) =
      { evalEntry bounds ρ state with
        submittedTxIds := ((Codec.finset bounds.transactionCount).decode ρ submitted).image Fin.val } := by
  exact setSubmittedData_correct ((stateCodec bounds.transactionCount).decode ρ state)
    ((Codec.finset bounds.transactionCount).decode ρ submitted)

theorem setInsert_image_correct {count : Nat} (ρ : Assignment)
    (submitted : Expr (Codec.finset count).ty) (transaction : Expr .nat)
    (bound : transaction.eval ρ < count) :
    ((Codec.finset count).decode ρ (setInsert submitted transaction)).image Fin.val =
      insert (transaction.eval ρ) (((Codec.finset count).decode ρ submitted).image Fin.val) := by
  have update : (Codec.finset count).decode ρ (setInsert submitted transaction) =
      insert ⟨transaction.eval ρ, bound⟩ ((Codec.finset count).decode ρ submitted) := by
    ext index
    rw [setInsert_correct]
    simp [Fin.ext_iff, eq_comm]
  rw [update, Finset.image_insert]

def insertSubmitted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (transaction : Expr .nat) :
    Expr (stateCodec bounds.transactionCount).ty :=
  setSubmittedExpr bounds.transactionCount state (setInsert state.snd.snd.fst transaction)

theorem insertSubmitted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (transaction : Expr .nat)
    (bound : transaction.eval ρ < bounds.transactionCount) :
    evalEntry bounds ρ (insertSubmitted bounds state transaction) =
      { evalEntry bounds ρ state with
        submittedTxIds := insert (transaction.eval ρ) (evalEntry bounds ρ state).submittedTxIds } := by
  rw [insertSubmitted, setSubmittedExpr_correct, setInsert_image_correct ρ _ transaction bound]
  rfl

def clientLocal (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat) : Expr localCodec.ty :=
  appendRefreshedLocal bounds state node (.inl transaction)

theorem clientLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ (clientLocal bounds state node transaction)) =
      let before := evalEntry bounds ρ state
      let actor := nodeCodec.decode ρ node
      refreshRetirementState actor
        { before.nodes actor with
          log := (before.nodes actor).log ++
            [⟨(before.nodes actor).currentTerm, .transaction (transaction.eval ρ)⟩] } := by
  exact appendRefreshedLocal_correct bounds ρ state node (.inl transaction) within

def clientEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  (Expr.and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .leader))
      (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
        (.and (.not (submittedContains bounds state transaction))
          (.not (.eq (localMembership (clientLocal bounds state node transaction))
            (membershipCodec.literal .retiredCommitted))))))).normalizeMemo

theorem clientEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (clientEnabled bounds state node transaction).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ)) := by
  have hrole := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have hmember := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  have hnext := congrArg NodeState.membershipState (clientLocal_correct bounds ρ state node transaction within)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at hrole
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).membershipState = _ at hmember
  change (localCodec.decode ρ (clientLocal bounds state node transaction)).membershipState = _ at hnext
  have conjunction (a b : Expr .bool) :
      (Expr.and a b).eval ρ = true ↔ a.eval ρ = true ∧ b.eval ρ = true := by simp [Expr.eval]
  have negation (a : Expr .bool) : (Expr.not a).eval ρ = true ↔ ¬a.eval ρ = true := by simp [Expr.eval]
  simp only [clientEnabled, Expr.normalizeMemo_correct, conjunction, negation, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader),
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node))
      (membershipCodec.literal .retiredCommitted),
    membershipCodec.equal_correct ρ (localMembership (clientLocal bounds state node transaction))
      (membershipCodec.literal .retiredCommitted),
    submittedContains_correct bounds ρ state transaction, Codec.decode_literal,
    localMembership_correct ρ, hrole, hmember, hnext, Enabled]

def clientNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat) : Expr (stateCodec bounds.transactionCount).ty :=
  (insertSubmitted bounds (writeEntryNext bounds state node (.inl transaction)) transaction).normalizeMemo

theorem clientNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state))
    (domain : transaction.eval ρ < bounds.transactionCount) :
    evalEntry bounds ρ (clientNext bounds state node transaction) =
      next (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ)) := by
  rw [clientNext, evalEntry_normalizeMemo, insertSubmitted_correct bounds ρ _ transaction domain,
    writeEntryNext_correct bounds ρ state node (.inl transaction) within]
  rfl

def clientAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat) : Expr .bool :=
  .and (.lt transaction (.nat bounds.transactionCount))
    (.and (clientEnabled bounds state node transaction)
      (stateWithin bounds (clientNext bounds state node transaction)))

theorem clientAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (clientAccepted bounds state node transaction).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ)) ∧
        BoundedState.WithinBounds bounds
          (next (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ))) := by
  simp only [clientAccepted, Expr.eval, Bool.and_eq_true, decide_eq_true_eq,
    stateWithin_correct bounds ρ, clientEnabled_correct bounds ρ state node transaction within]
  constructor
  · rintro ⟨domain, enabled, after⟩
    rw [clientNext_correct bounds ρ state node transaction within domain] at after
    exact ⟨enabled, after⟩
  · rintro ⟨enabled, after⟩
    have domain := clientTransactionBound_of_successorWithin bounds (evalEntry bounds ρ state)
      (nodeCodec.decode ρ node) (transaction.eval ρ) after
    rw [clientNext_correct bounds ρ state node transaction within domain]
    exact ⟨domain, enabled, after⟩

theorem clientNext_bounded_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state))
    (after : BoundedState.WithinBounds bounds
      (next (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ)))) :
    evalEntry bounds ρ (clientNext bounds state node transaction) =
      next (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ)) :=
  clientNext_correct bounds ρ state node transaction within
    (clientTransactionBound_of_successorWithin bounds _ _ _ after)

def clientGuard (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat) : Expr .bool :=
  .and (stateWithin bounds state) (clientAccepted bounds state node transaction)

theorem clientGuard_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (transaction : Expr .nat) :
    (clientGuard bounds state node transaction).eval ρ = true ↔
      BoundedState.WithinBounds bounds (evalEntry bounds ρ state) ∧
        Enabled (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ)) ∧
        BoundedState.WithinBounds bounds
          (next (evalEntry bounds ρ state) (.clientRequest (nodeCodec.decode ρ node) (transaction.eval ρ))) := by
  simp only [clientGuard, Expr.eval, Bool.and_eq_true, stateWithin_correct bounds ρ]
  constructor
  · rintro ⟨within, accepted⟩
    exact ⟨within, (clientAccepted_correct bounds ρ state node transaction within).mp accepted⟩
  · rintro ⟨within, accepted⟩
    exact ⟨within, (clientAccepted_correct bounds ρ state node transaction within).mpr accepted⟩

theorem client_complete_model (bounds : BoundedState.Bounds) (start : Nat)
    (state : CCFRaft.State Node Nat) (node : Node) (transaction : Nat)
    (before : BoundedState.WithinBounds bounds state)
    (enabled : Enabled state (.clientRequest node transaction))
    (after : BoundedState.WithinBounds bounds (next state (.clientRequest node transaction))) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
      (clientGuard bounds (freshEntry bounds start) (nodeCodec.literal node) (.nat transaction)).eval ρ = true ∧
      evalEntry bounds ρ (clientNext bounds (freshEntry bounds start) (nodeCodec.literal node) (.nat transaction)) =
        next state (.clientRequest node transaction) := by
  obtain ⟨ρ, hs⟩ := freshEntry_complete_model bounds start state before
  refine ⟨ρ, hs, ?_, ?_⟩
  · apply (clientGuard_correct bounds ρ _ _ _).mpr
    simpa only [hs, Codec.decode_literal, Expr.eval] using And.intro before (And.intro enabled after)
  · have hb : BoundedState.WithinBounds bounds (evalEntry bounds ρ (freshEntry bounds start)) := by
      simpa only [hs] using before
    have domain : (Expr.nat transaction).eval ρ < bounds.transactionCount :=
      clientTransactionBound_of_successorWithin bounds state node transaction after
    simpa only [hs, Codec.decode_literal, Expr.eval] using
      clientNext_correct bounds ρ (freshEntry bounds start) (nodeCodec.literal node) (.nat transaction) hb domain

end CCFRaft.SymbolicTransition
