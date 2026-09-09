-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicObservations
import TraceMessageSummary

set_option autoImplicit false

namespace CCFRaft.SymbolicModel

open Symbolic TraceMessageSummary

def messageMatchesSummary (message : Expr messageCodec.ty) :
    Summary Node -> Expr .bool
  | .appendEntriesRequest expected =>
      appendRequestMatches message fun request =>
        .and (.eq request.fst (.nat expected.term))
        (.and (.eq request.snd.fst (.nat expected.prevLogIndex))
        (.and (.eq (.length request.snd.snd.snd.fst) (.nat expected.entriesLength))
        (.and (.eq request.snd.snd.snd.snd.fst (.nat expected.leaderCommit))
        (.and (.eq request.snd.snd.snd.snd.snd.fst (nodeCodec.literal expected.source))
          (.eq request.snd.snd.snd.snd.snd.snd (nodeCodec.literal expected.destination))))))
  | .appendEntriesResponse expected =>
      .eq message (messageCodec.literal (.appendEntriesResponse expected))
  | .requestVoteRequest expected =>
      .eq message (messageCodec.literal (.requestVoteRequest expected))
  | .requestVoteResponse expected =>
      .eq message (messageCodec.literal (.requestVoteResponse expected))
  | .requestPreVote expected =>
      .eq message (messageCodec.literal (.requestPreVote expected))
  | .requestPreVoteResponse expected =>
      .eq message (messageCodec.literal (.requestPreVoteResponse expected))
  | .proposeVoteRequest expected =>
      .eq message (messageCodec.literal (.proposeVoteRequest expected))

theorem messageMatchesSummary_correct (ρ : Assignment)
    (message : Expr messageCodec.ty) (summary : Summary Node) :
    (messageMatchesSummary message summary).eval ρ = true ↔
      ofMessage (messageCodec.decode ρ message) = summary := by
  cases summary with
  | appendEntriesRequest expected =>
      have node_equal (v : (enumTy 14).Value) (n : Node) :
          v = enumEncode 14 n ↔ enumDecode 14 v = n := by
        exact (nodeCodec.equiv.apply_eq_iff_eq_symm_apply).symm
      cases expected
      generalize he : message.eval ρ = value
      rcases value with r | (r | (r | (r | (r | (r | r))))) <;>
        simp [messageMatchesSummary, appendRequestMatches, matchSum, Expr.eval,
          Codec.decode, Codec.literal, Codec.transport, Codec.sum, Codec.prod,
          Codec.nat, Codec.list, Codec.fin, he, ofMessage, node_equal,
          Equiv.coe_fn_mk]
      intros
      rfl
  | appendEntriesResponse expected
  | requestVoteRequest expected
  | requestVoteResponse expected
  | requestPreVote expected
  | requestPreVoteResponse expected
  | proposeVoteRequest expected =>
      simp only [messageMatchesSummary, messageCodec.equal_correct, Codec.decode_literal]
      cases messageCodec.decode ρ message <;> simp [ofMessage]

def queueMatchesSummary (capacity : Nat) (queue : Expr queueCodec.ty)
    (summary : Summary Node) : Expr .bool :=
  firstFromMatches capacity (nodeCodec.literal summary.source) queue
    (fun message => messageMatchesSummary message summary)

theorem queueMatchesSummary_correct (ρ : Assignment) (capacity : Nat)
    (queue : Expr queueCodec.ty) (summary : Summary Node)
    (bound : (queueCodec.decode ρ queue).length ≤ capacity) :
    (queueMatchesSummary capacity queue summary).eval ρ = true ↔
      ∃ message rest,
        takeFirstFrom summary.source (queueCodec.decode ρ queue) = some (message, rest) ∧
          ofMessage message = summary := by
  simpa [queueMatchesSummary] using
    firstFromMatches_correct ρ capacity (nodeCodec.literal summary.source) queue
      (fun message => messageMatchesSummary message summary)
      (fun message => ofMessage message = summary)
      (fun message => messageMatchesSummary_correct ρ message summary) bound

def entryMatchesSummary (bounds : BoundedState.Bounds)
    (entry : Expr (stateCodec bounds.transactionCount).ty)
    (summary : Summary Node) : Expr .bool :=
  queueMatchesSummary bounds.queueCapacity
    (entryQueue bounds.transactionCount entry (nodeCodec.literal summary.destination))
    summary

theorem entryMatchesSummary_correct (bounds : BoundedState.Bounds)
    (ρ : Assignment) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (summary : Summary Node)
    (bound : BoundedState.WithinBounds bounds (evalEntry bounds ρ entry)) :
    (entryMatchesSummary bounds entry summary).eval ρ = true ↔
      summary.matchesFirst (evalEntry bounds ρ entry) = true := by
  have queue :
      queueCodec.decode ρ
        (entryQueue bounds.transactionCount entry (nodeCodec.literal summary.destination)) =
          (evalEntry bounds ρ entry).network summary.destination := by
    simp [entryQueue_correct]
  have capacity :
      (queueCodec.decode ρ
        (entryQueue bounds.transactionCount entry (nodeCodec.literal summary.destination))).length ≤
          bounds.queueCapacity := by
    rw [queue]
    exact (bound.2.1 summary.destination).1
  rw [entryMatchesSummary, queueMatchesSummary_correct ρ _ _ _ capacity, queue]
  unfold Summary.matchesFirst
  cases takeFirstFrom summary.source ((evalEntry bounds ρ entry).network summary.destination) with
  | none => simp
  | some selected => rcases selected with ⟨message, rest⟩; simp

end CCFRaft.SymbolicModel
