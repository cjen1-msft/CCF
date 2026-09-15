-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionElectionHelpers

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def nodeSingleton (node : Expr nodeCodec.ty) : Expr nodeSetCodec.ty :=
  setInsert (nodeSetCodec.literal ∅) (finValue node)

theorem nodeSingleton_correct (ρ : Assignment) (node : Expr nodeCodec.ty) :
    nodeSetCodec.decode ρ (nodeSingleton node) = {nodeCodec.decode ρ node} := by
  ext peer
  rw [nodeSingleton, setInsert_correct, Codec.decode_literal]
  simp [finValue_correct, Codec.decode, Codec.fin, Fin.ext_iff, eq_comm]
  rfl

def setElectionFields (value : Expr localCodec.ty) (role : Expr roleCodec.ty) (term : Expr .nat)
    (newFollower : Expr .bool) (voted : Expr nodeCodec.option.ty)
    (votes preVotes : Expr nodeSetCodec.ty) : Expr localCodec.ty :=
  .pair role (.pair term (.pair value.snd.snd.fst (.pair value.snd.snd.snd.fst
    (.pair value.snd.snd.snd.snd.fst (.pair value.snd.snd.snd.snd.snd.fst
      (.pair newFollower (.pair voted (.pair votes (.pair preVotes
        value.snd.snd.snd.snd.snd.snd.snd.snd.snd.snd)))))))))

theorem setElectionFields_correct (ρ : Assignment) (value : Expr localCodec.ty)
    (role : Expr roleCodec.ty) (term : Expr .nat) (newFollower : Expr .bool)
    (voted : Expr nodeCodec.option.ty) (votes preVotes : Expr nodeSetCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (setElectionFields value role term newFollower voted votes preVotes)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with
        role := roleCodec.decode ρ role, currentTerm := term.eval ρ,
        isNewFollower := newFollower.eval ρ, votedFor := nodeCodec.option.decode ρ voted,
        votesGranted := nodeSetCodec.decode ρ votes, preVotesGranted := nodeSetCodec.decode ρ preVotes } := by
  rfl

def candidateLocal (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) : Expr localCodec.ty :=
  setElectionFields value (roleCodec.literal .candidate) (.add value.snd.fst (.nat 1))
    value.snd.snd.snd.snd.snd.snd.fst (.inr node) (nodeSingleton node) (nodeSetCodec.literal ∅)

theorem candidateLocal_correct (ρ : Assignment) (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (candidateLocal value node)) =
      becomeCandidateNodeState (BoundedState.decodeLocal (localCodec.decode ρ value)) (nodeCodec.decode ρ node) := by
  rw [candidateLocal, setElectionFields_correct, Codec.decode_literal, nodeSingleton_correct, Codec.decode_literal]
  rfl

def preCandidateLocal (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) : Expr localCodec.ty :=
  setElectionFields value (roleCodec.literal .preVoteCandidate) value.snd.fst
    value.snd.snd.snd.snd.snd.snd.fst value.snd.snd.snd.snd.snd.snd.snd.fst
    value.snd.snd.snd.snd.snd.snd.snd.snd.fst (nodeSingleton node)

theorem preCandidateLocal_correct (ρ : Assignment) (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (preCandidateLocal value node)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with
        role := .preVoteCandidate, preVotesGranted := {nodeCodec.decode ρ node} } := by
  rw [preCandidateLocal, setElectionFields_correct, Codec.decode_literal, nodeSingleton_correct]
  rfl

def stepDownLocal (value : Expr localCodec.ty) : Expr localCodec.ty :=
  setElectionFields value (roleCodec.literal .follower) value.snd.fst (.bool true)
    value.snd.snd.snd.snd.snd.snd.snd.fst value.snd.snd.snd.snd.snd.snd.snd.snd.fst
    value.snd.snd.snd.snd.snd.snd.snd.snd.snd.fst

theorem stepDownLocal_correct (ρ : Assignment) (value : Expr localCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (stepDownLocal value)) =
      { BoundedState.decodeLocal (localCodec.decode ρ value) with role := .follower, isNewFollower := true } := by
  rw [stepDownLocal, setElectionFields_correct, Codec.decode_literal]
  rfl

def candidateTransitionExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  .and (allocated bounds.transactionCount state node)
    (.and ((Expr.eq value.fst (roleCodec.literal .follower)).or
      ((Expr.eq value.fst (roleCodec.literal .preVoteCandidate)).or (.eq value.fst (roleCodec.literal .candidate))))
      (.and (campaignSupport bounds state node)
        (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))))

theorem candidateTransitionExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (candidateTransitionExpr bounds state node).eval ρ = true ↔
      candidateTransitionEnabled (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have membership := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at role
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).membershipState = _ at membership
  simp only [candidateTransitionExpr, boolAnd_true ρ, boolOr_true ρ, boolNot_true ρ,
    allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst,
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node)),
    Codec.decode_literal, localMembership_correct ρ, role, membership,
    campaignSupport_correct bounds ρ state node within, candidateTransitionEnabled]

def timeoutEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (candidateTransitionExpr bounds state node)
    (.not (.eq (readPreVote bounds.transactionCount state node) (preVoteCodec.literal .enabled)))

theorem timeoutEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (timeoutEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.timeout (nodeCodec.decode ρ node)) := by
  simp only [timeoutEnabled, boolAnd_true ρ, boolNot_true ρ,
    candidateTransitionExpr_correct bounds ρ state node within,
    preVoteCodec.equal_correct ρ (readPreVote bounds.transactionCount state node) (preVoteCodec.literal .enabled),
    readPreVote_correct, Codec.decode_literal, candidateTransitionEnabled, Enabled, and_assoc]

def preCandidateEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (candidateTransitionExpr bounds state node)
    (.eq (readPreVote bounds.transactionCount state node) (preVoteCodec.literal .enabled))

theorem preCandidateEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (preCandidateEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.becomePreVoteCandidate (nodeCodec.decode ρ node)) := by
  simp only [preCandidateEnabled, boolAnd_true ρ,
    candidateTransitionExpr_correct bounds ρ state node within,
    preVoteCodec.equal_correct ρ (readPreVote bounds.transactionCount state node) (preVoteCodec.literal .enabled),
    readPreVote_correct, Codec.decode_literal, candidateTransitionEnabled, Enabled, and_assoc]

def preMajorityExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  configurationMajorities bounds.logCapacity value.snd.snd.snd.snd.snd.snd.snd.snd.snd.fst value

theorem preMajorityExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (preMajorityExpr bounds state node).eval ρ = true ↔
      hasPreVoteMajority (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  rw [preMajorityExpr, configurationMajorities_correct ρ bounds.logCapacity _ _
    (readLocal_log_bound bounds ρ state node within)]
  have votes := congrArg NodeState.preVotesGranted (readLocal_correct bounds ρ state node)
  change nodeSetCodec.decode ρ (readLocal bounds.transactionCount state node).snd.snd.snd.snd.snd.snd.snd.snd.snd.fst = _ at votes
  simp only [readLocal_correct bounds ρ state node, votes]
  rfl

def candidateEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  .and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .preVoteCandidate))
      (.and (campaignSupport bounds state node)
        (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
          (.and (.eq (readPreVote bounds.transactionCount state node) (preVoteCodec.literal .enabled))
            (preMajorityExpr bounds state node)))))

theorem candidateEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (candidateEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.becomeCandidate (nodeCodec.decode ρ node)) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have membership := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state node).fst = _ at role
  change (localCodec.decode ρ (readLocal bounds.transactionCount state node)).membershipState = _ at membership
  simp only [candidateEnabled, boolAnd_true ρ, boolNot_true ρ, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state node).fst (roleCodec.literal .preVoteCandidate),
    membershipCodec.equal_correct ρ (localMembership (readLocal bounds.transactionCount state node))
      (membershipCodec.literal .retiredCommitted),
    preVoteCodec.equal_correct ρ (readPreVote bounds.transactionCount state node) (preVoteCodec.literal .enabled),
    Codec.decode_literal, localMembership_correct ρ, role, membership, readPreVote_correct,
    campaignSupport_correct bounds ρ state node within, preMajorityExpr_correct bounds ρ state node within, Enabled]

def candidateNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  (writeLocal bounds.transactionCount state node
    (candidateLocal (readLocal bounds.transactionCount state node) node).normalizeMemo).normalizeMemo

theorem candidateNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    evalEntry bounds ρ (candidateNext bounds state node) =
      becomeCandidateState (evalEntry bounds ρ state) (nodeCodec.decode ρ node) := by
  rw [candidateNext, evalEntry_normalizeMemo, writeLocal_correct, decode_normalizeMemo,
    candidateLocal_correct, readLocal_correct]
  rfl

def preCandidateNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  (writeLocal bounds.transactionCount state node
    (preCandidateLocal (readLocal bounds.transactionCount state node) node).normalizeMemo).normalizeMemo

theorem preCandidateNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    evalEntry bounds ρ (preCandidateNext bounds state node) =
      next (evalEntry bounds ρ state) (.becomePreVoteCandidate (nodeCodec.decode ρ node)) := by
  rw [preCandidateNext, evalEntry_normalizeMemo, writeLocal_correct, decode_normalizeMemo,
    preCandidateLocal_correct, readLocal_correct]
  rfl

def timeoutAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (timeoutEnabled bounds state node) (stateWithin bounds (candidateNext bounds state node))

theorem timeoutAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (timeoutAccepted bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.timeout (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (.timeout (nodeCodec.decode ρ node))) := by
  simp only [timeoutAccepted, boolAnd_true ρ, timeoutEnabled_correct bounds ρ state node within,
    stateWithin_correct bounds ρ, candidateNext_correct, next]

def preCandidateAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (preCandidateEnabled bounds state node) (stateWithin bounds (preCandidateNext bounds state node))

theorem preCandidateAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (preCandidateAccepted bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.becomePreVoteCandidate (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds
          (next (evalEntry bounds ρ state) (.becomePreVoteCandidate (nodeCodec.decode ρ node))) := by
  simp only [preCandidateAccepted, boolAnd_true ρ, preCandidateEnabled_correct bounds ρ state node within,
    stateWithin_correct bounds ρ, preCandidateNext_correct]

def candidateAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (candidateEnabled bounds state node) (stateWithin bounds (candidateNext bounds state node))

theorem candidateAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (candidateAccepted bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.becomeCandidate (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds
          (next (evalEntry bounds ρ state) (.becomeCandidate (nodeCodec.decode ρ node))) := by
  simp only [candidateAccepted, boolAnd_true ρ, candidateEnabled_correct bounds ρ state node within,
    stateWithin_correct bounds ρ, candidateNext_correct, next]

end CCFRaft.SymbolicTransition
