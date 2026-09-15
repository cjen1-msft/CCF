-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionElectionStart
import MachineGenerated.SymbolicReceiveState

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def voteSendAction (preVote : Bool) (source destination : Node) : Action Node Nat :=
  if preVote then .requestPreVote source destination else .requestVote source destination

def voteSendEnabled (preVote : Bool) (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state source
  .and (allocated bounds.transactionCount state source)
    (.and (allocated bounds.transactionCount state destination)
      (.and (.eq value.fst (roleCodec.literal (if preVote then .preVoteCandidate else .candidate)))
        (.and (.not (.eq source destination))
          (nodeSetContains (localActiveNodes bounds.logCapacity value) destination))))

theorem voteSendEnabled_correct (preVote : Bool) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (voteSendEnabled preVote bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (voteSendAction preVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state source)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state source).fst = _ at role
  cases preVote <;>
    simp only [voteSendEnabled, Bool.false_eq_true, ↓reduceIte,
      boolAnd_true ρ, boolNot_true ρ, allocated_correct bounds ρ,
      roleCodec.equal_correct ρ (readLocal bounds.transactionCount state source).fst,
      nodeCodec.equal_correct ρ source destination, Codec.decode_literal, role,
      nodeSetContains_correct ρ,
      localActiveNodes_correct ρ bounds.logCapacity _ (readLocal_log_bound bounds ρ state source within),
      readLocal_correct, voteSendAction, Enabled]

def voteRequestFields (capacity : Nat) (value : Expr localCodec.ty)
    (source destination : Expr nodeCodec.ty) : Expr voteRequestCodec.ty :=
  let log := value.snd.snd.fst
  let index := maximumExpr value.snd.snd.snd.fst (maxCommittableExpr capacity log)
  .pair value.snd.fst (.pair (termAtExpr log index) (.pair index (.pair source destination)))

theorem voteRequestFields_correct (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (source destination : Expr nodeCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    voteRequestCodec.decode ρ (voteRequestFields capacity value source destination) =
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      RequestVoteRequest.mk before.currentTerm (lastCommittableTerm before) (lastCommittableIndex before)
        (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) := by
  change RequestVoteRequest.mk (value.snd.fst.eval ρ)
    ((termAtExpr value.snd.snd.fst
      (maximumExpr value.snd.snd.snd.fst (maxCommittableExpr capacity value.snd.snd.fst))).eval ρ)
    ((maximumExpr value.snd.snd.snd.fst (maxCommittableExpr capacity value.snd.snd.fst)).eval ρ)
    (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) = _
  simp only [termAtExpr_correct, maximumExpr_correct,
    maxCommittableExpr_correct ρ capacity value.snd.snd.fst bound]
  rfl

def voteSendMessage (preVote : Bool) (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr messageCodec.ty :=
  let request := voteRequestFields bounds.logCapacity
    (readLocal bounds.transactionCount state source) source destination
  if preVote then .inr (.inr (.inr (.inr (.inl request)))) else .inr (.inr (.inl request))

theorem voteSendMessage_correct (preVote : Bool) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    messageCodec.decode ρ (voteSendMessage preVote bounds state source destination) =
      if preVote then
        .requestPreVote (makeRequestPreVote (evalEntry bounds ρ state)
          (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination))
      else .requestVoteRequest (makeRequestVoteRequest (evalEntry bounds ρ state)
          (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  have request := voteRequestFields_correct ρ bounds.logCapacity
    (readLocal bounds.transactionCount state source) source destination
    (readLocal_log_bound bounds ρ state source within)
  rw [readLocal_correct] at request
  cases preVote with
  | false =>
    change Message.requestVoteRequest
      (voteRequestCodec.decode ρ (voteRequestFields bounds.logCapacity
        (readLocal bounds.transactionCount state source) source destination)) = _
    rw [request]
    rfl
  | true =>
    let convert := fun r : RequestVoteRequest Node =>
      Message.requestPreVote (TxId := Nat)
        (RequestPreVote.mk r.term r.lastCommittableTerm r.lastCommittableIndex r.source r.destination)
    change convert (voteRequestCodec.decode ρ
      (voteRequestFields bounds.logCapacity (readLocal bounds.transactionCount state source) source destination)) = _
    rw [request]
    dsimp only [convert, makeRequestPreVote]
    rfl

def voteSendNext (preVote : Bool) (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr (stateCodec bounds.transactionCount).ty :=
  (SymbolicReceive.enqueue bounds.transactionCount state
    (voteSendMessage preVote bounds state source destination).normalizeMemo).normalizeMemo

theorem voteSendNext_correct (preVote : Bool) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (voteSendNext preVote bounds state source destination) =
      next (evalEntry bounds ρ state)
        (voteSendAction preVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  rw [voteSendNext, evalEntry_normalizeMemo, SymbolicReceive.enqueue_correct, decode_normalizeMemo,
    voteSendMessage_correct preVote bounds ρ state source destination within]
  cases preVote <;> rfl

def voteSendAccepted (preVote : Bool) (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr .bool :=
  .and (voteSendEnabled preVote bounds state source destination)
    (stateWithin bounds (voteSendNext preVote bounds state source destination))

theorem voteSendAccepted_correct (preVote : Bool) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (voteSendAccepted preVote bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state)
        (voteSendAction preVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) ∧
      BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state)
        (voteSendAction preVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination))) := by
  simp only [voteSendAccepted, boolAnd_true ρ, voteSendEnabled_correct preVote bounds ρ state source destination within,
    stateWithin_correct bounds ρ, voteSendNext_correct preVote bounds ρ state source destination within]

end CCFRaft.SymbolicTransition
