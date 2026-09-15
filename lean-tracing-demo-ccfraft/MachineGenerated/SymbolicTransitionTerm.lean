-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionQueue
import MachineGenerated.SymbolicTransitionCoverage
import MachineGenerated.SymbolicBounds

set_option autoImplicit false

/-!
`updateTermGuard` checks exact bounds before and after the enabled Model step.
`updateTermNext` preserves the selected packet and every unrelated state field.
`updateTerm_complete_model` supplies one assignment for any bounded Model entry
whose enabled successor is also bounded. It does not require a concrete entry.

`SymbolicTransitionConfiguration`, `SymbolicTransitionLog`, and
`SymbolicTransitionRetirement` supply configuration, signature, and local
retirement helpers. `SymbolicTransitionCompleted` supplies global retirement
updates; `SymbolicTransitionSignature` lowers `signCommittableMessages`.
Other action families still need their complete guards and successors.
Raw observations, trace composition, and causal action names remain separate.
-/

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def sourceAllowed (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (message : Expr messageCodec.ty) : Expr .bool :=
  compactCase message (fun _ => .bool true) fun message =>
    compactCase message (fun r => allocated transactions state r.snd.snd.snd.fst) fun message =>
      compactCase message (fun _ => .bool true) fun message =>
        compactCase message (fun r => allocated transactions state r.snd.snd.fst) fun message =>
          compactCase message (fun _ => .bool true) fun message =>
            compactCase message (fun r => allocated transactions state r.snd.snd.fst)
              (fun _ => .bool true)

theorem sourceAllowed_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (message : Expr messageCodec.ty) :
    (sourceAllowed bounds.transactionCount state message).eval ρ = true ↔
      messageSourceAllowed (evalEntry bounds ρ state) (messageCodec.decode ρ message) := by
  generalize hm : message.eval ρ = v
  rcases v with r | (r | (r | (r | (r | (r | r))))) <;>
    simp [sourceAllowed, compactCase, matchSum, Expr.normalizeMemo_correct, Expr.eval, allocated_correct bounds ρ,
      Codec.decode, Codec.transport, Codec.sum, Codec.prod, messageSourceAllowed, hm]

def newerMessage (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    Expr messageCodec.option.ty :=
  optionCases (queueTakeFirstById bounds.queueCapacity source
    (entryQueue bounds.transactionCount state destination)) (.inl .unit) fun pair =>
      .ite (.and (sourceAllowed bounds.transactionCount state pair.fst)
        (.lt (readLocal bounds.transactionCount state destination).snd.fst (messageTerm pair.fst)))
        (.inr pair.fst) (.inl .unit)

theorem newerMessage_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (bound : ((evalEntry bounds ρ state).network (nodeCodec.decode ρ destination)).length ≤
      bounds.queueCapacity) :
    messageCodec.option.decode ρ (newerMessage bounds state source destination) =
      newerMessage? (evalEntry bounds ρ state) (nodeCodec.decode ρ source)
        (nodeCodec.decode ρ destination) := by
  let f := fun pair : Message Node Nat × List (Message Node Nat) =>
    if messageSourceAllowed (evalEntry bounds ρ state) pair.1 ∧
        ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ destination)).currentTerm < pair.1.term
    then some pair.1 else none
  have term := congrArg NodeState.currentTerm (readLocal_correct bounds ρ state destination)
  change ((readLocal bounds.transactionCount state destination).snd.fst).eval ρ = _ at term
  simp only [Expr.eval] at term
  have body (pair : Expr (messageCodec.prod queueCodec).ty) :
      messageCodec.option.decode ρ
        (.ite (.and (sourceAllowed bounds.transactionCount state pair.fst)
          (.lt (readLocal bounds.transactionCount state destination).snd.fst (messageTerm pair.fst)))
          (.inr pair.fst) (.inl .unit)) =
        f ((messageCodec.prod queueCodec).decode ρ pair) := by
    rw [decode_choose]
    have condition :
        (Expr.and (sourceAllowed bounds.transactionCount state pair.fst)
          (.lt (readLocal bounds.transactionCount state destination).snd.fst
            (messageTerm pair.fst))).eval ρ =
        decide (messageSourceAllowed (evalEntry bounds ρ state) (messageCodec.decode ρ pair.fst) ∧
          ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ destination)).currentTerm <
            (messageCodec.decode ρ pair.fst).term) := by
      apply Bool.eq_iff_iff.mpr
      simp only [Expr.eval, Bool.and_eq_true, decide_eq_true_iff,
        sourceAllowed_correct bounds ρ, term, messageTerm_correct]
    rw [condition]
    simp only [decide_eq_true_eq]
    rfl
  have hb : (queueCodec.decode ρ (entryQueue bounds.transactionCount state destination)).length ≤
      bounds.queueCapacity := by simpa only [entryQueue_correct] using bound
  rw [newerMessage, optionCases_correct (messageCodec.prod queueCodec) messageCodec.option
    ρ _ _ _ f body, queueTakeFirstById_correct ρ _ _ _ hb, entryQueue_correct bounds ρ]
  cases h : takeFirstFrom (nodeCodec.decode ρ source)
      ((evalEntry bounds ρ state).network (nodeCodec.decode ρ destination)) <;>
    simp [newerMessage?, h, f] <;> rfl

def adoptTerm (value : Expr localCodec.ty) (term : Expr .nat) : Expr localCodec.ty :=
  .pair (roleCodec.literal .follower) (.pair term
    (.pair value.snd.snd.fst (.pair value.snd.snd.snd.fst
      (.pair value.snd.snd.snd.snd.fst (.pair value.snd.snd.snd.snd.snd.fst
        (.pair (.bool true) (.pair (.inl .unit)
          (.pair value.snd.snd.snd.snd.snd.snd.snd.snd.fst
            (.pair (nodeSetCodec.literal ∅) value.snd.snd.snd.snd.snd.snd.snd.snd.snd.snd)))))))))

theorem adoptTerm_correct (ρ : Assignment) (value : Expr localCodec.ty) (term : Expr .nat) :
    BoundedState.decodeLocal (localCodec.decode ρ (adoptTerm value term)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with
        role := .follower
        currentTerm := term.eval ρ
        isNewFollower := true
        votedFor := none
        preVotesGranted := ∅ } := by
  change { BoundedState.decodeLocal (localCodec.decode ρ value) with
    role := roleCodec.decode ρ (roleCodec.literal .follower)
    currentTerm := term.eval ρ
    isNewFollower := true
    votedFor := none
    preVotesGranted := nodeSetCodec.decode ρ (nodeSetCodec.literal ∅) } = _
  simp only [Codec.decode_literal]

def updateTermEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    Expr .bool :=
  .and (allocated bounds.transactionCount state destination)
    (isSome (newerMessage bounds state source destination))

theorem updateTermEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (bound : ((evalEntry bounds ρ state).network (nodeCodec.decode ρ destination)).length ≤
      bounds.queueCapacity) :
    (updateTermEnabled bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (.updateTerm (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  simp only [updateTermEnabled, Expr.eval, Bool.and_eq_true, allocated_correct bounds ρ,
    isSome_correct messageCodec ρ, newerMessage_correct bounds ρ state source destination bound, Enabled]

def updateTermNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  optionCases (newerMessage bounds state source destination) state fun selected =>
    (writeLocal bounds.transactionCount state destination
      (adoptTerm (readLocal bounds.transactionCount state destination) (messageTerm selected)).normalizeMemo).normalizeMemo

theorem evalEntry_optionCases {α : Type} (a : Codec α)
    (bounds : BoundedState.Bounds) (ρ : Assignment) (value : Expr a.option.ty)
    (onNone : Expr (stateCodec bounds.transactionCount).ty)
    (onSome : Expr a.ty → Expr (stateCodec bounds.transactionCount).ty)
    (f : α → CCFRaft.State Node Nat)
    (correct : ∀ x, evalEntry bounds ρ (onSome x) = f (a.decode ρ x)) :
    evalEntry bounds ρ (optionCases value onNone onSome) =
      (a.option.decode ρ value).elim (evalEntry bounds ρ onNone) f := by
  simp only [evalEntry, Codec.decode] at correct ⊢
  cases hv : value.eval ρ <;>
    simp [optionCases, compactCase, matchSum, Codec.option, Expr.normalizeMemo_correct, Expr.eval, hv, correct]

theorem updateTermNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (bound : ((evalEntry bounds ρ state).network (nodeCodec.decode ρ destination)).length ≤
      bounds.queueCapacity) :
    evalEntry bounds ρ (updateTermNext bounds state source destination) =
      next (evalEntry bounds ρ state)
        (.updateTerm (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  let s := evalEntry bounds ρ state
  let d := nodeCodec.decode ρ destination
  let f := fun selected : Message Node Nat =>
    { s with
      nodes := updateNode s.nodes d
        { s.nodes d with
          role := .follower
          currentTerm := selected.term
          votedFor := none
          isNewFollower := true
          preVotesGranted := ∅ } }
  have body (selected : Expr messageCodec.ty) :
      evalEntry bounds ρ (writeLocal bounds.transactionCount state destination
        (adoptTerm (readLocal bounds.transactionCount state destination) (messageTerm selected)).normalizeMemo).normalizeMemo =
        f (messageCodec.decode ρ selected) := by
    rw [evalEntry_normalizeMemo, writeLocal_correct, decode_normalizeMemo,
      adoptTerm_correct, readLocal_correct, messageTerm_correct]
  rw [updateTermNext, evalEntry_optionCases messageCodec bounds ρ _ _ _ f body,
    newerMessage_correct bounds ρ state source destination bound]
  cases h : newerMessage? s (nodeCodec.decode ρ source) d <;>
    simp [next, s, d, f, h]

def updateTermGuard (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    Expr .bool :=
  .and (stateWithin bounds state)
    (.and (updateTermEnabled bounds state source destination)
      (stateWithin bounds (updateTermNext bounds state source destination)))

theorem updateTermGuard_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    (updateTermGuard bounds state source destination).eval ρ = true ↔
      BoundedState.WithinBounds bounds (evalEntry bounds ρ state) ∧
        Enabled (evalEntry bounds ρ state)
          (.updateTerm (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state)
          (.updateTerm (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination))) := by
  simp only [updateTermGuard, Expr.eval, Bool.and_eq_true, stateWithin_correct bounds ρ]
  constructor
  · rintro ⟨hb, he, hn⟩
    have hq := (hb.2.1 (nodeCodec.decode ρ destination)).1
    rw [updateTermEnabled_correct bounds ρ state source destination hq] at he
    rw [updateTermNext_correct bounds ρ state source destination hq] at hn
    exact ⟨hb, he, hn⟩
  · rintro ⟨hb, he, hn⟩
    have hq := (hb.2.1 (nodeCodec.decode ρ destination)).1
    rw [updateTermEnabled_correct bounds ρ state source destination hq,
      updateTermNext_correct bounds ρ state source destination hq]
    exact ⟨hb, he, hn⟩

theorem updateTerm_complete_model (bounds : BoundedState.Bounds) (start : Nat)
    (state : CCFRaft.State Node Nat) (source destination : Node)
    (before : BoundedState.WithinBounds bounds state)
    (enabled : Enabled state (.updateTerm source destination))
    (after : BoundedState.WithinBounds bounds (next state (.updateTerm source destination))) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
      (updateTermGuard bounds (freshEntry bounds start)
        (nodeCodec.literal source) (nodeCodec.literal destination)).eval ρ = true ∧
      evalEntry bounds ρ (updateTermNext bounds (freshEntry bounds start)
        (nodeCodec.literal source) (nodeCodec.literal destination)) =
          next state (.updateTerm source destination) := by
  obtain ⟨ρ, hs⟩ := freshEntry_complete_model bounds start state before
  have hq : ((evalEntry bounds ρ (freshEntry bounds start)).network
      (nodeCodec.decode ρ (nodeCodec.literal destination))).length ≤ bounds.queueCapacity := by
    simpa only [hs, Codec.decode_literal] using (before.2.1 destination).1
  refine ⟨ρ, hs, ?_, ?_⟩
  · apply (updateTermGuard_correct bounds ρ _ _ _).mpr
    simpa only [hs, Codec.decode_literal] using And.intro before (And.intro enabled after)
  · simpa only [hs, Codec.decode_literal] using
      updateTermNext_correct bounds ρ (freshEntry bounds start)
        (nodeCodec.literal source) (nodeCodec.literal destination) hq

end CCFRaft.SymbolicTransition
