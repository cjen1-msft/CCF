-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVoteState
import Sparse.NativeArrayVoteReceive
import Sparse.NativeArrayAppend
import Sparse.NativeArrayAppendNetwork

set_option autoImplicit false

namespace CCFRaft.NativeArrayVote

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

inductive Instruction (N T : Type) where
  | node (instruction : NativeArrayCheckQuorum.Instruction N T)
  | vote (preVote : Bool) (source destination : N)
  | updateTerm (source destination : N)
  | campaign (preVote : Bool) (node : N)
  | receiveVote (source destination : N)
  | receiveAppend (source destination : N)
  | appendEntries (source destination : N) (batchEnd : Nat)
  | submittedTxId (txId : T) (expected : Bool)
  | hasJoined (expected : Finset N)
  | preVoteStatus (node : N) (expected : PreVoteStatus)
  | retirementCompleted (node : N) (expected : Finset N)
  | queueLength (source destination : N) (expected : Nat)
  | queuePoint (source destination : N) (index : Nat) (expected : Message N T)

def follows (frame : Frame N T) : List (Instruction N T) -> Prop
  | [] => True
  | .node instruction :: rest =>
      NativeArrayCheckQuorum.follows frame.nodes [instruction] /\
        follows (frame.nodeStep instruction) rest
  | .vote preVote source destination :: rest =>
      enabled frame.nodes preVote source destination /\
        exists signature, SignatureIndex (get frame.nodes source).log signature /\
          follows (frame.vote preVote source destination signature) rest
  | .updateTerm source destination :: rest =>
      (frame.nodes destination).isSome = true /\
        (newerMessage? frame source destination).isSome = true /\
          follows (frame.updateTerm source destination) rest
  | .campaign preVote node :: rest =>
      campaignEnabled frame preVote node /\ follows (frame.campaign preVote node) rest
  | .receiveVote source destination :: rest =>
      (frame.nodes destination).isSome = true /\
        exists request signature,
          (frame.queues destination source).peek = some (.requestVoteRequest request) /\
          request.source = source /\ request.destination = destination /\
          request.term <= (get frame.nodes destination).currentTerm /\
          SignatureIndex (get frame.nodes destination).log signature /\
          follows (NativeArrayVoteReceive.receive frame destination request signature) rest
  | .receiveAppend source destination :: rest =>
      exists nextFrame,
        NativeArrayAppendNetwork.ReceiveAppend frame source destination nextFrame /\
          follows nextFrame rest
  | .appendEntries source destination batchEnd :: rest =>
      NativeArrayAppend.enabled frame source destination batchEnd /\
        follows (NativeArrayAppend.send frame source destination batchEnd) rest
  | .submittedTxId txId expected :: rest =>
      decide (txId ∈ frame.globals.submittedTxIds) = expected /\ follows frame rest
  | .hasJoined expected :: rest => frame.globals.hasJoined = expected /\ follows frame rest
  | .preVoteStatus node expected :: rest => frame.globals.preVoteStatus node = expected /\ follows frame rest
  | .retirementCompleted node expected :: rest =>
      frame.globals.retirementCompleted node = expected /\ follows frame rest
  | .queueLength source destination expected :: rest =>
      (frame.queues destination source).length = expected /\ follows frame rest
  | .queuePoint source destination index expected :: rest =>
      (index < (frame.queues destination source).length /\
        (frame.queues destination source).cells ((frame.queues destination source).head + index) = expected) /\
          follows frame rest

def modelFollows (state : State N T) : List (Instruction N T) -> Prop
  | [] => True
  | .node instruction :: rest =>
      NativeArrayCheckQuorum.modelFollows state [instruction] /\
        modelFollows (nodeModelStep state instruction) rest
  | .vote preVote source destination :: rest =>
      CCFRaft.Enabled state (action preVote source destination) /\
        modelFollows (CCFRaft.next state (action preVote source destination)) rest
  | .updateTerm source destination :: rest =>
      CCFRaft.Enabled state (.updateTerm source destination) /\
        modelFollows (CCFRaft.next state (.updateTerm source destination)) rest
  | .campaign preVote node :: rest =>
      CCFRaft.Enabled state (campaignAction preVote node) /\
        modelFollows (CCFRaft.next state (campaignAction preVote node)) rest
  | .receiveVote source destination :: rest =>
      CCFRaft.Enabled state (.receive source destination) /\
        (exists request remaining, takeFirstFrom source (state.network destination) =
          some (.requestVoteRequest request, remaining)) /\
        modelFollows (CCFRaft.next state (.receive source destination)) rest
  | .receiveAppend source destination :: rest =>
      CCFRaft.Enabled state (.receive source destination) /\
        (exists request remaining, takeFirstFrom source (state.network destination) =
          some (.appendEntriesRequest request, remaining)) /\
        modelFollows (CCFRaft.next state (.receive source destination)) rest
  | .appendEntries source destination batchEnd :: rest =>
      CCFRaft.Enabled state (.appendEntries source destination batchEnd) /\
        modelFollows (CCFRaft.next state (.appendEntries source destination batchEnd)) rest
  | .submittedTxId txId expected :: rest =>
      decide (txId ∈ state.submittedTxIds) = expected /\ modelFollows state rest
  | .hasJoined expected :: rest => state.hasJoined = expected /\ modelFollows state rest
  | .preVoteStatus node expected :: rest => state.preVoteStatus node = expected /\ modelFollows state rest
  | .retirementCompleted node expected :: rest =>
      state.retirementCompleted node = expected /\ modelFollows state rest
  | .queueLength source destination expected :: rest =>
      (Sparse.Queue.partition source (state.network destination)).length = expected /\
        modelFollows state rest
  | .queuePoint source destination index expected :: rest =>
      (Sparse.Queue.partition source (state.network destination))[index]? = some expected /\
        modelFollows state rest

theorem follows_correct (trace : List (Instruction N T)) (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) : follows frame trace <-> modelFollows state trace := by
  induction trace generalizing frame state with
  | nil => rfl
  | cons instruction rest ih =>
    cases instruction with
    | node instruction =>
      exact and_congr (NativeArrayCheckQuorum.follows_correct [instruction] _ _ rep.nodes)
        (ih _ _ (node_step_rep frame state rep instruction))
    | vote preVote source destination =>
      apply and_congr (enabled_correct frame.nodes state rep.nodes preVote source destination)
      constructor
      · rintro ⟨signature, latest, held⟩
        exact (ih _ _ (vote_rep frame state rep preVote source destination signature latest)).mp held
      · intro held
        let signature := maxCommittableIndex (get frame.nodes source).log.decode
        have latest : SignatureIndex (get frame.nodes source).log signature :=
          (signature_index_correct _ _).mpr rfl
        exact ⟨signature, latest,
          (ih _ _ (vote_rep frame state rep preVote source destination signature latest)).mpr held⟩
    | updateTerm source destination =>
      simp only [follows, modelFollows, CCFRaft.Enabled,
        allocated_rep frame.nodes state rep.nodes, newer_correct frame state rep,
        ih _ _ (update_term_rep frame state rep source destination), and_assoc]
    | campaign preVote node =>
      exact and_congr (campaign_enabled_correct frame state rep preVote node)
        (ih _ _ (campaign_rep frame state rep preVote node))
    | receiveVote source destination =>
      constructor
      · rintro ⟨present, request, signature, selected, sameSource, recipient, term, latest, held⟩
        obtain ⟨remaining, taken⟩ :=
          NativeArrayVoteReceive.selected_model_take frame state rep source destination _ selected
        have takenFromRequest :
            takeFirstFrom request.source (state.network destination) =
              some (.requestVoteRequest request, remaining) := by
          simpa only [sameSource] using taken
        have enabled := (NativeArrayVoteReceive.enabled_correct frame state rep destination request remaining
          takenFromRequest).mpr ⟨present, recipient, term⟩
        have nextRep := NativeArrayVoteReceive.receive_rep frame state rep destination request signature latest
          term recipient remaining takenFromRequest
        rw [sameSource] at enabled nextRep
        exact ⟨enabled, ⟨request, remaining, taken⟩, (ih _ _ nextRep).mp held⟩
      · rintro ⟨enabled, ⟨request, remaining, taken⟩, held⟩
        have sameSource : request.source = source :=
          (Sparse.Queue.take_some_spec source (state.network destination) _ remaining taken).1
        have takenFromRequest :
            takeFirstFrom request.source (state.network destination) =
              some (.requestVoteRequest request, remaining) := by
          simpa only [sameSource] using taken
        obtain ⟨present, recipient, term⟩ :=
          (NativeArrayVoteReceive.enabled_correct frame state rep destination request remaining takenFromRequest).mp
            (by simpa only [sameSource] using enabled)
        let signature := maxCommittableIndex (get frame.nodes destination).log.decode
        have latest : SignatureIndex (get frame.nodes destination).log signature :=
          (signature_index_correct _ _).mpr rfl
        have nextRep := NativeArrayVoteReceive.receive_rep frame state rep destination request signature latest
          term recipient remaining takenFromRequest
        rw [sameSource] at nextRep
        refine ⟨present, request, signature, ?_, sameSource, recipient, term, latest, (ih _ _ nextRep).mpr held⟩
        rw [NativeArrayQueue.model_peek_correct frame.queues state.network rep.queues source destination, taken]
        rfl
    | receiveAppend source destination =>
      constructor
      · rintro ⟨nextFrame, step, held⟩
        have enabled := NativeArrayAppendNetwork.receive_append_enabled
          frame state rep source destination nextFrame step
        have selected : exists request,
            NativeArrayAppendNetwork.SelectedAppend frame source destination request := by
          cases step <;> exact ⟨_, by assumption⟩
        obtain ⟨request, selected⟩ := selected
        obtain ⟨remaining, taken⟩ :=
          NativeArrayVoteReceive.selected_model_take frame state rep source destination
            (.appendEntriesRequest request) selected.head
        have nextRep := NativeArrayAppendNetwork.receive_append_rep
          frame state rep source destination nextFrame step
        exact ⟨enabled, ⟨request, remaining, taken⟩, (ih _ _ nextRep).mp held⟩
      · rintro ⟨enabled, ⟨request, remaining, taken⟩, held⟩
        have selectedHead :
            (frame.queues destination source).peek =
              some (.appendEntriesRequest request) := by
          rw [NativeArrayQueue.model_peek_correct
            frame.queues state.network rep.queues source destination, taken]
          rfl
        have guard := (NativeArrayAppendReceiveGuard.enabled_correct frame state rep
          source destination request (Log.ofList request.entries) selectedHead (by simp)).mp enabled
        have selected : NativeArrayAppendNetwork.SelectedAppend
            frame source destination request :=
          ⟨selectedHead, guard.1,
            NativeArrayAppendReceiveGuard.selected_append_source
              frame state rep source destination request selectedHead,
            guard.2.1⟩
        obtain ⟨nextFrame, step⟩ :=
          NativeArrayAppendNetwork.receive_append_exists
            frame state rep source destination request selected enabled
        have nextRep := NativeArrayAppendNetwork.receive_append_rep
          frame state rep source destination nextFrame step
        exact ⟨nextFrame, step, (ih _ _ nextRep).mpr held⟩
    | appendEntries source destination batchEnd =>
      constructor
      · rintro ⟨enabled, held⟩
        have nextRep := NativeArrayAppend.send_rep frame state rep source destination batchEnd enabled.2.2.2.2.2.1
        exact ⟨(NativeArrayAppend.enabled_correct frame state rep source destination batchEnd).mp enabled,
          (ih _ _ nextRep).mp held⟩
      · rintro ⟨enabled, held⟩
        have native := (NativeArrayAppend.enabled_correct frame state rep source destination batchEnd).mpr enabled
        have nextRep := NativeArrayAppend.send_rep frame state rep source destination batchEnd native.2.2.2.2.2.1
        exact ⟨native, (ih _ _ nextRep).mpr held⟩
    | queueLength source destination expected =>
      have same := congrArg List.length (congrFun (congrFun rep.queues destination) source)
      simp only [NativeArrayQueue.decodeNetwork, NativeArrayQueue.Queue.decode_length,
        Sparse.Queue.abstractNetwork] at same
      simp only [follows, modelFollows, same, ih frame state rep]
    | queuePoint source destination index expected =>
      have same := congrFun (congrFun rep.queues destination) source
      simp only [NativeArrayQueue.decodeNetwork, Sparse.Queue.abstractNetwork] at same
      simp only [follows, modelFollows, NativeArrayQueue.Queue.point_correct, same, ih frame state rep]
    | submittedTxId txId expected =>
      simp only [follows, modelFollows, rep.globals, Globals.ofModel, ih frame state rep]
    | hasJoined expected =>
      simp only [follows, modelFollows, rep.globals, Globals.ofModel, ih frame state rep]
    | preVoteStatus node expected =>
      simp only [follows, modelFollows, rep.globals, Globals.ofModel, ih frame state rep]
    | retirementCompleted node expected =>
      simp only [follows, modelFollows, rep.globals, Globals.ofModel, ih frame state rep]

theorem exists_iff [Fintype N] (trace : List (Instruction N T)) :
    (exists frame, frame.Valid /\ follows frame trace) <->
      exists state, modelFollows state trace := by
  constructor
  · rintro ⟨frame, valid, held⟩
    exact ⟨frame.realize, (follows_correct trace _ _ (realize_rep frame valid)).mp held⟩
  · rintro ⟨state, held⟩
    exact ⟨Frame.ofModel state, of_model_valid state,
      (follows_correct trace _ _ (of_model_rep state)).mpr held⟩

theorem exists_submitted_array_iff [Fintype N] (trace : List (Instruction N Nat)) :
    (exists array : NativeArrayNatSet.Array, array.Valid /\
      exists frame : Frame N Nat, frame.Valid /\
        frame.globals.submittedTxIds = array.decode /\ follows frame trace) <->
      exists state, modelFollows state trace := by
  constructor
  · rintro ⟨array, _, frame, valid, _, holds⟩
    exact (exists_iff trace).mp ⟨frame, valid, holds⟩
  · intro holds
    rcases (exists_iff trace).mpr holds with ⟨frame, valid, follows⟩
    exact ⟨NativeArrayNatSet.Array.ofFinset frame.globals.submittedTxIds,
      NativeArrayNatSet.of_finset_valid _, frame, valid,
      (NativeArrayNatSet.of_finset_correct _).symm, follows⟩

end CCFRaft.NativeArrayVote

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayVote).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
