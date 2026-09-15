-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionWrite

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def signatureLocal (bounds : BoundedState.Bounds) (state : Expr (stateCodec bounds.transactionCount).ty)
    (node : Expr nodeCodec.ty) : Expr localCodec.ty :=
  appendRefreshedLocal bounds state node (contentCodec.literal .signature)

theorem signatureLocal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    BoundedState.decodeLocal (localCodec.decode ρ (signatureLocal bounds state node)) =
      refreshRetirementState (nodeCodec.decode ρ node)
        { (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node) with
          log := ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).log ++
            [⟨((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)).currentTerm, .signature⟩] } := by
  simpa only [signatureLocal, Codec.decode_literal] using
    appendRefreshedLocal_correct bounds ρ state node (contentCodec.literal .signature) within

theorem signatureLocal_log_bound (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (localCodec.decode ρ (signatureLocal bounds state node)).log.length ≤ bounds.logCapacity + 1 := by
  exact appendRefreshedLocal_log_bound bounds ρ state node (contentCodec.literal .signature) within

def localMembership (value : Expr localCodec.ty) : Expr membershipCodec.ty :=
  value.snd.snd.snd.snd.snd.snd.snd.snd.snd.snd.fst

theorem localMembership_correct (ρ : Assignment) (value : Expr localCodec.ty) :
    membershipCodec.decode ρ (localMembership value) = (localCodec.decode ρ value).membershipState := rfl

private theorem conjunction_eval (ρ : Assignment) (a b : Expr .bool) :
    (Expr.and a b).eval ρ = true ↔ a.eval ρ = true ∧ b.eval ρ = true := by
  simp [Expr.eval]

private theorem negation_eval (ρ : Assignment) (a : Expr .bool) :
    (Expr.not a).eval ρ = true ↔ ¬a.eval ρ = true := by
  simp [Expr.eval]

def signatureEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  (Expr.and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .leader))
      (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
        (.and (.not (.eq value.snd.snd.fst (logCodec.literal [])))
          (.not (.eq (localMembership (signatureLocal bounds state node))
            (membershipCodec.literal .retiredCommitted))))))).normalizeMemo

theorem signatureEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (signatureEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.signCommittableMessages (nodeCodec.decode ρ node)) := by
  have hrole := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have hmember := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  have hlog := congrArg NodeState.log (readLocal_correct bounds ρ state node)
  have hnext := congrArg NodeState.membershipState (signatureLocal_correct bounds ρ state node within)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at hrole
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).membershipState = _ at hmember
  change logCodec.decode ρ (readLocal bounds.transactionCount state node).snd.snd.fst = _ at hlog
  change (localCodec.decode ρ (signatureLocal bounds state node)).membershipState = _ at hnext
  simp only [signatureEnabled, Expr.normalizeMemo_correct, conjunction_eval ρ, negation_eval ρ, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .leader),
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node))
      (membershipCodec.literal .retiredCommitted),
    membershipCodec.equal_correct ρ (localMembership (signatureLocal bounds state node))
      (membershipCodec.literal .retiredCommitted),
    logCodec.equal_correct ρ (readLocal bounds.transactionCount state node).snd.snd.fst (logCodec.literal []),
    Codec.decode_literal, localMembership_correct ρ, hrole, hmember, hlog, hnext, Enabled]

def signatureNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  writeEntryNext bounds state node (contentCodec.literal .signature)

theorem signatureNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (signatureNext bounds state node) =
      next (evalEntry bounds ρ state) (.signCommittableMessages (nodeCodec.decode ρ node)) := by
  simpa only [signatureNext, Codec.decode_literal, next] using
    writeEntryNext_correct bounds ρ state node (contentCodec.literal .signature) within

def signatureGuard (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (stateWithin bounds state)
    (.and (signatureEnabled bounds state node) (stateWithin bounds (signatureNext bounds state node)))

theorem signatureGuard_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    (signatureGuard bounds state node).eval ρ = true ↔
      BoundedState.WithinBounds bounds (evalEntry bounds ρ state) ∧
        Enabled (evalEntry bounds ρ state) (.signCommittableMessages (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds
          (next (evalEntry bounds ρ state) (.signCommittableMessages (nodeCodec.decode ρ node))) := by
  simp only [signatureGuard, conjunction_eval ρ, stateWithin_correct bounds ρ]
  constructor
  · rintro ⟨hb, he, hn⟩
    rw [signatureEnabled_correct bounds ρ state node hb] at he
    rw [signatureNext_correct bounds ρ state node hb] at hn
    exact ⟨hb, he, hn⟩
  · rintro ⟨hb, he, hn⟩
    rw [signatureEnabled_correct bounds ρ state node hb, signatureNext_correct bounds ρ state node hb]
    exact ⟨hb, he, hn⟩

theorem signature_complete_model (bounds : BoundedState.Bounds) (start : Nat)
    (state : CCFRaft.State Node Nat) (node : Node)
    (before : BoundedState.WithinBounds bounds state)
    (enabled : Enabled state (.signCommittableMessages node))
    (after : BoundedState.WithinBounds bounds (next state (.signCommittableMessages node))) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
      (signatureGuard bounds (freshEntry bounds start) (nodeCodec.literal node)).eval ρ = true ∧
      evalEntry bounds ρ (signatureNext bounds (freshEntry bounds start) (nodeCodec.literal node)) =
        next state (.signCommittableMessages node) := by
  obtain ⟨ρ, hs⟩ := freshEntry_complete_model bounds start state before
  refine ⟨ρ, hs, ?_, ?_⟩
  · apply (signatureGuard_correct bounds ρ _ _).mpr
    simpa only [hs, Codec.decode_literal] using And.intro before (And.intro enabled after)
  · have hb : BoundedState.WithinBounds bounds (evalEntry bounds ρ (freshEntry bounds start)) := by
      simpa only [hs] using before
    simpa only [hs, Codec.decode_literal] using
      signatureNext_correct bounds ρ (freshEntry bounds start) (nodeCodec.literal node) hb

end CCFRaft.SymbolicTransition
