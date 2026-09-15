-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTraceEncoding
import MachineGenerated.SymbolicTransitionTerm
import MachineGenerated.SymbolicTransitionClient
import MachineGenerated.SymbolicTransitionRetiredWrite
import MachineGenerated.SymbolicTransitionReconfiguration
import MachineGenerated.SymbolicTransitionAppend
import MachineGenerated.SymbolicTransitionLeader
import MachineGenerated.SymbolicTransitionCommit
import MachineGenerated.SymbolicReceive

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel BoundedSymbolicTrace

structure ReceiveAdapter (bounds : BoundedState.Bounds) where
  step : Expr (stateCodec bounds.transactionCount).ty → Node → Node →
    Trace.Step (stateCodec bounds.transactionCount).ty
  accepted_correct : ∀ ρ state source destination,
    BoundedState.WithinBounds bounds (evalEntry bounds ρ state) →
      ((step state source destination).enabled.eval ρ = true ↔
        Enabled (evalEntry bounds ρ state) (.receive source destination) ∧
          BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (.receive source destination)))
  next_correct : ∀ ρ state source destination,
    BoundedState.WithinBounds bounds (evalEntry bounds ρ state) →
    Enabled (evalEntry bounds ρ state) (.receive source destination) →
    BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (.receive source destination)) →
      evalEntry bounds ρ (step state source destination).successor =
        next (evalEntry bounds ρ state) (.receive source destination)

def dispatch (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) :
    SymbolicAction → Trace.Step (stateCodec bounds.transactionCount).ty
  | .clientRequest node transaction =>
      ⟨clientAccepted bounds state (nodeCodec.literal node) transaction,
        clientNext bounds state (nodeCodec.literal node) transaction⟩
  | .signCommittableMessages node =>
      ⟨signatureGuard bounds state (nodeCodec.literal node), signatureNext bounds state (nodeCodec.literal node)⟩
  | .changeConfiguration node configuration =>
      ⟨configurationAccepted bounds state (nodeCodec.literal node) (nodeSetCodec.literal configuration),
        configurationNext bounds state (nodeCodec.literal node) (nodeSetCodec.literal configuration)⟩
  | .appendRetiredCommitted node =>
      ⟨retiredWriteGuard bounds state (nodeCodec.literal node), retiredWriteNext bounds state (nodeCodec.literal node)⟩
  | .appendEntries source destination batchEnd =>
      ⟨appendSendAccepted bounds state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd),
        appendSendNext bounds state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd)⟩
  | .receive source destination => receive.step state source destination
  | .timeout node =>
      ⟨timeoutAccepted bounds state (nodeCodec.literal node), candidateNext bounds state (nodeCodec.literal node)⟩
  | .becomePreVoteCandidate node =>
      ⟨preCandidateAccepted bounds state (nodeCodec.literal node), preCandidateNext bounds state (nodeCodec.literal node)⟩
  | .becomeCandidate node =>
      ⟨candidateAccepted bounds state (nodeCodec.literal node), candidateNext bounds state (nodeCodec.literal node)⟩
  | .advanceCommitIndex node =>
      ⟨advanceAccepted bounds state (nodeCodec.literal node), advanceNext bounds state (nodeCodec.literal node)⟩
  | .checkQuorum node =>
      ⟨checkQuorumAccepted bounds state (nodeCodec.literal node), checkQuorumNext bounds state (nodeCodec.literal node)⟩
  | .updateTerm source destination =>
      ⟨updateTermGuard bounds state (nodeCodec.literal source) (nodeCodec.literal destination),
        updateTermNext bounds state (nodeCodec.literal source) (nodeCodec.literal destination)⟩
  | .becomeLeader node =>
      ⟨leaderAccepted bounds state (nodeCodec.literal node), leaderNext bounds state (nodeCodec.literal node)⟩
  | .requestVote source destination =>
      ⟨voteSendAccepted false bounds state (nodeCodec.literal source) (nodeCodec.literal destination),
        voteSendNext false bounds state (nodeCodec.literal source) (nodeCodec.literal destination)⟩
  | .requestPreVote source destination =>
      ⟨voteSendAccepted true bounds state (nodeCodec.literal source) (nodeCodec.literal destination),
        voteSendNext true bounds state (nodeCodec.literal source) (nodeCodec.literal destination)⟩
  | .proposeVote source destination =>
      ⟨proposalAccepted bounds state (nodeCodec.literal source) (nodeCodec.literal destination),
        proposalNext bounds state (nodeCodec.literal source) (nodeCodec.literal destination)⟩
  | .advanceCommitIndexAndProposeVote source destination =>
      ⟨advanceProposalAccepted bounds state (nodeCodec.literal source) (nodeCodec.literal destination),
        advanceProposalNext bounds state (nodeCodec.literal source) (nodeCodec.literal destination)⟩

theorem dispatch_accepted_correct (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (ρ : Assignment) (state : Expr (stateCodec bounds.transactionCount).ty) (action : SymbolicAction)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (dispatch bounds receive state action).enabled.eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (evaluateAction ρ action) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (evaluateAction ρ action)) := by
  cases action with
  | clientRequest node transaction =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        clientAccepted_correct bounds ρ state (nodeCodec.literal node) transaction within
  | signCommittableMessages node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, within, true_and] using
        signatureGuard_correct bounds ρ state (nodeCodec.literal node)
  | changeConfiguration node configuration =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        configurationAccepted_correct bounds ρ state (nodeCodec.literal node) (nodeSetCodec.literal configuration) within
  | appendRetiredCommitted node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, within, true_and] using
        retiredWriteGuard_correct bounds ρ state (nodeCodec.literal node)
  | appendEntries source destination batchEnd =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, Expr.eval] using
        appendSendAccepted_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd) within
  | receive source destination => exact receive.accepted_correct ρ state source destination within
  | timeout node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        timeoutAccepted_correct bounds ρ state (nodeCodec.literal node) within
  | becomePreVoteCandidate node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        preCandidateAccepted_correct bounds ρ state (nodeCodec.literal node) within
  | becomeCandidate node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        candidateAccepted_correct bounds ρ state (nodeCodec.literal node) within
  | advanceCommitIndex node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        advanceAccepted_correct bounds ρ state (nodeCodec.literal node) within
  | checkQuorum node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        checkQuorumAccepted_correct bounds ρ state (nodeCodec.literal node) within
  | updateTerm source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, within, true_and] using
        updateTermGuard_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination)
  | becomeLeader node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        leaderAccepted_correct bounds ρ state (nodeCodec.literal node) within
  | requestVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        voteSendAccepted_correct false bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within
  | requestPreVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        voteSendAccepted_correct true bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within
  | proposeVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        proposalAccepted_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within
  | advanceCommitIndexAndProposeVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        advanceProposalAccepted_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within

theorem dispatch_next_correct (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (ρ : Assignment) (state : Expr (stateCodec bounds.transactionCount).ty) (action : SymbolicAction)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state))
    (enabled : Enabled (evalEntry bounds ρ state) (evaluateAction ρ action))
    (after : BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (evaluateAction ρ action))) :
    evalEntry bounds ρ (dispatch bounds receive state action).successor =
      next (evalEntry bounds ρ state) (evaluateAction ρ action) := by
  cases action with
  | clientRequest node transaction =>
      have bounded := clientNext_bounded_correct bounds ρ state (nodeCodec.literal node) transaction within
        (by simpa only [Codec.decode_literal] using after)
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using bounded
  | signCommittableMessages node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        signatureNext_correct bounds ρ state (nodeCodec.literal node) within
  | changeConfiguration node configuration =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        configurationNext_correct bounds ρ state (nodeCodec.literal node) (nodeSetCodec.literal configuration) within
  | appendRetiredCommitted node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        retiredWriteNext_correct bounds ρ state (nodeCodec.literal node) within
  | appendEntries source destination batchEnd =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, Expr.eval] using
        appendSendNext_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd)
  | receive source destination => exact receive.next_correct ρ state source destination within enabled after
  | timeout node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, next] using
        candidateNext_correct bounds ρ state (nodeCodec.literal node)
  | becomePreVoteCandidate node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        preCandidateNext_correct bounds ρ state (nodeCodec.literal node)
  | becomeCandidate node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal, next] using
        candidateNext_correct bounds ρ state (nodeCodec.literal node)
  | advanceCommitIndex node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        advanceNext_correct bounds ρ state (nodeCodec.literal node) within
  | checkQuorum node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        checkQuorumNext_correct bounds ρ state (nodeCodec.literal node)
  | updateTerm source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        updateTermNext_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination)
          (by simpa only [Codec.decode_literal] using (within.2.1 destination).1)
  | becomeLeader node =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        leaderNext_correct bounds ρ state (nodeCodec.literal node) within
  | requestVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        voteSendNext_correct false bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within
  | requestPreVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        voteSendNext_correct true bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within
  | proposeVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        proposalNext_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination)
  | advanceCommitIndexAndProposeVote source destination =>
      simpa only [dispatch, evaluateAction, Codec.decode_literal] using
        advanceProposalNext_correct bounds ρ state (nodeCodec.literal source) (nodeCodec.literal destination) within

def adapter (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds) :
    SymbolicTraceEncoding.Adapter bounds where
  step := dispatch bounds receive
  accepted_correct := fun ρ state action within => dispatch_accepted_correct bounds receive ρ state action within
  next_correct := fun ρ state action within enabled after =>
    dispatch_next_correct bounds receive ρ state action within enabled after

theorem verifiedEncoder (receive : ∀ bounds, ReceiveAdapter bounds) :
    VerifiedEncoder (fun bounds => SymbolicTraceEncoding.encode bounds (adapter bounds (receive bounds))) :=
  SymbolicTraceEncoding.verifiedEncoder (fun bounds => adapter bounds (receive bounds))

def modelReceive (bounds : BoundedState.Bounds) : ReceiveAdapter bounds where
  step := SymbolicReceive.step bounds
  accepted_correct := SymbolicReceive.step_accepted_correct bounds
  next_correct := fun assignment entry source destination within _ _ =>
    SymbolicReceive.step_next_correct bounds assignment entry source destination within

def checkedEncoder : {encode // VerifiedEncoder encode} :=
  ⟨fun bounds => SymbolicTraceEncoding.encode bounds (adapter bounds (modelReceive bounds)),
    verifiedEncoder modelReceive⟩

end CCFRaft.SymbolicTransition
