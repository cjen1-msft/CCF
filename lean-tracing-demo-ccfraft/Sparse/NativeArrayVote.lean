-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum
import Sparse.NativeArrayQueue
import Sparse.ConfigSignature

set_option autoImplicit false

namespace CCFRaft.NativeArrayVote

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def MemberAt (log : Log N T) (current : Nat) (peer : N) : Prop :=
  (current = 0 /\ peer ∈ INITIAL_CONFIGURATION) \/
    exists index nodes, current <= index /\ Reconfiguration log index nodes /\ peer ∈ nodes

theorem member_at_correct (log : Log N T) (state : NodeState N T) (peer : N)
    (same : state.log = log.decode) :
    MemberAt log (currentConfiguration state).index peer <-> peer ∈ activeNodeUnion state := by
  have empty : peer ∈ (∅ : Finset N) ↔ False := by simp
  simp only [activeNodeUnion, mem_union, empty, false_or, activeConfigurations,
    List.mem_filter, decide_eq_true_eq, allConfigurations, List.mem_cons]
  constructor
  · intro h
    rcases h with ⟨zero, member⟩ | ⟨index, nodes, lower, physical, member⟩
    · exact ⟨implicitConfiguration, ⟨Or.inl rfl, by simp [implicitConfiguration, zero]⟩, member⟩
    · refine ⟨{ index, nodes }, ⟨Or.inr ?_, lower⟩, member⟩
      rw [same, Sparse.ConfigurationSnapshot.mem_configurations_iff]
      exact (reconfiguration_correct _ _ _).mp physical
  · rintro ⟨configuration, ⟨member, lower⟩, included⟩
    rcases member with implicit | physical
    · subst configuration
      exact Or.inl ⟨by simpa [implicitConfiguration] using lower, included⟩
    · refine Or.inr ⟨configuration.index, configuration.nodes, lower, ?_, included⟩
      apply (reconfiguration_correct _ _ _).mpr
      rw [same, Sparse.ConfigurationSnapshot.mem_configurations_iff] at physical
      exact physical

def SignatureAt (log : Log N T) (index : Nat) : Prop :=
  0 < index /\ index <= log.length /\ (log.entries (index - 1)).content = .signature

theorem signature_at_correct (log : Log N T) (index : Nat) :
    SignatureAt log index <-> Sparse.ConfigSignature.SignatureAt log.decode index := by
  by_cases positive : 0 < index
  · by_cases within : index <= log.length
    · have live : index - 1 < log.length := by omega
      simp [SignatureAt, Sparse.ConfigSignature.SignatureAt, entryAt?, Log.decode,
        positive, Nat.ne_of_gt positive, within, live]
    · constructor
      · intro h; exact False.elim (within h.2.1)
      · intro h
        have bound := Sparse.ConfigSignature.signature_bounds h
        simp only [Log.decode_length] at bound
        exact False.elim (within bound.2)
  · have zero : index = 0 := by omega
    simp [SignatureAt, Sparse.ConfigSignature.SignatureAt, entryAt?, zero]

def SignatureIndex (log : Log N T) (index : Nat) : Prop :=
  index <= log.length /\ (index = 0 \/ SignatureAt log index) /\
    forall candidate, index < candidate -> candidate <= log.length -> Not (SignatureAt log candidate)

theorem signature_index_correct (log : Log N T) (index : Nat) :
    SignatureIndex log index <-> maxCommittableIndex log.decode = index := by
  have spec := Sparse.ConfigSignature.signature_maximum_exclusion_iff log.decode log.decode.length index
  simp only [maxCommittableIndexUpTo, List.take_length, Nat.min_self] at spec
  simpa only [SignatureIndex, signature_at_correct, Log.decode_length] using spec.symm

def termAt (log : Log N T) (index : Nat) : Nat :=
  if 0 < index /\ index <= log.length then (log.entries (index - 1)).term else 0

theorem term_at_correct (log : Log N T) (index : Nat) :
    termAt log index = CCFRaft.termAt log.decode index := by
  by_cases positive : 0 < index
  · by_cases within : index <= log.length
    · have live : index - 1 < log.length := by omega
      simp [termAt, CCFRaft.termAt, entryAt?, Log.decode,
        positive, Nat.ne_of_gt positive, within, live]
    · have outside : Not (index - 1 < log.length) := by omega
      simp [termAt, CCFRaft.termAt, entryAt?, Log.decode,
        positive, Nat.ne_of_gt positive, within, outside]
  · have zero : index = 0 := by omega
    simp [termAt, CCFRaft.termAt, entryAt?, zero]

def request (row : Local N T) (source destination : N) (signature : Nat) : RequestVoteRequest N :=
  let index := max row.commit signature
  { term := row.currentTerm, lastCommittableIndex := index,
    lastCommittableTerm := termAt row.log index, source, destination }

theorem request_correct (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state)
    (source destination : N) (signature : Nat)
    (latest : SignatureIndex (get arrays source).log signature) :
    request (get arrays source) source destination signature = makeRequestVoteRequest state source destination := by
  have fields := get_rep arrays state rep source
  have latest := (signature_index_correct _ _).mp latest
  simp [request, makeRequestVoteRequest, lastCommittableIndex, lastCommittableTerm,
    term_at_correct, ← fields, Local.toModel, latest]

def action (preVote : Bool) (source destination : N) : Action N T :=
  if preVote then .requestPreVote source destination else .requestVote source destination

def enabled (arrays : Arrays N T) (preVote : Bool) (source destination : N) : Prop :=
  (arrays source).isSome = true /\ (arrays destination).isSome = true /\
    (get arrays source).role = (if preVote then .preVoteCandidate else .candidate) /\
    source ≠ destination /\
    exists current, CurrentIndex (get arrays source).log (get arrays source).commit current /\
      MemberAt (get arrays source).log current destination

theorem enabled_correct (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state)
    (preVote : Bool) (source destination : N) :
    enabled arrays preVote source destination <-> CCFRaft.Enabled state (action preVote source destination) := by
  have fields := get_rep arrays state rep source
  have member := member_at_correct (get arrays source).log (get arrays source).toModel destination rfl
  cases preVote <;>
    simp [enabled, action, CCFRaft.Enabled, allocated_rep arrays state rep source,
      allocated_rep arrays state rep destination, ← fields, Local.toModel, current_index_correct,
      exists_eq_left', currentConfiguration] at member ⊢
  all_goals exact fun _ _ _ _ => member

def packet (row : Local N T) (preVote : Bool) (source destination : N) (signature : Nat) :
    Message N T :=
  let vote := request row source destination signature
  if preVote then
    .requestPreVote
      { term := vote.term
        lastCommittableTerm := vote.lastCommittableTerm
        lastCommittableIndex := vote.lastCommittableIndex
        source
        destination }
  else .requestVoteRequest vote

theorem packet_correct (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state)
    (preVote : Bool) (source destination : N) (signature : Nat)
    (latest : SignatureIndex (get arrays source).log signature) :
    packet (get arrays source) preVote source destination signature =
      if preVote then .requestPreVote (makeRequestPreVote state source destination)
      else .requestVoteRequest (makeRequestVoteRequest state source destination) := by
  simp only [packet, request_correct arrays state rep source destination signature latest]
  cases preVote <;> rfl

structure Frame (N T : Type) where
  nodes : Arrays N T
  queues : NativeArrayQueue.Network N T

def Frame.Rep (frame : Frame N T) (state : State N T) : Prop :=
  NativeArrayCheckQuorum.Rep frame.nodes state /\
    NativeArrayQueue.decodeNetwork frame.queues = Sparse.Queue.abstractNetwork state.network

def Frame.Valid (frame : Frame N T) : Prop :=
  forall destination, Sparse.Queue.WellFormed (NativeArrayQueue.decodeNetwork frame.queues destination)

def Frame.vote (frame : Frame N T) (preVote : Bool) (source destination : N) (signature : Nat) :
    Frame N T :=
  { frame with
    queues := NativeArrayQueue.send frame.queues
      (packet (get frame.nodes source) preVote source destination signature) }

theorem vote_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (preVote : Bool) (source destination : N) (signature : Nat)
    (latest : SignatureIndex (get frame.nodes source).log signature) :
    (frame.vote preVote source destination signature).Rep
      (CCFRaft.next state (action preVote source destination)) := by
  constructor
  · cases preVote <;> exact rep.1
  · change NativeArrayQueue.decodeNetwork (NativeArrayQueue.send frame.queues
      (packet (get frame.nodes source) preVote source destination signature)) = _
    rw [NativeArrayQueue.model_send_correct frame.queues state.network rep.2,
      packet_correct frame.nodes state rep.1 preVote source destination signature latest]
    cases preVote <;> rfl

def Frame.nodeStep (frame : Frame N T) (instruction : NativeArrayCheckQuorum.Instruction N T) :
    Frame N T :=
  match instruction with
  | .checkQuorum node => { frame with nodes := NativeArrayCheckQuorum.step frame.nodes node }
  | _ => frame

def nodeModelStep (state : State N T) (instruction : NativeArrayCheckQuorum.Instruction N T) :
    State N T :=
  match instruction with
  | .checkQuorum node => CCFRaft.next state (.checkQuorum node)
  | _ => state

theorem node_step_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (instruction : NativeArrayCheckQuorum.Instruction N T) :
    (frame.nodeStep instruction).Rep (nodeModelStep state instruction) := by
  cases instruction <;> first
    | exact rep
    | exact ⟨NativeArrayCheckQuorum.step_correct _ _ rep.1 _, rep.2⟩

def sourceAllowed (nodes : Arrays N T) : Message N T -> Prop
  | .appendEntriesResponse response => (nodes response.source).isSome = true
  | .requestVoteResponse response => (nodes response.source).isSome = true
  | .requestPreVoteResponse response => (nodes response.source).isSome = true
  | _ => True

instance (nodes : Arrays N T) (message : Message N T) :
    Decidable (sourceAllowed nodes message) := by
  cases message <;> simp only [sourceAllowed] <;> infer_instance

theorem source_allowed_correct (arrays : Arrays N T) (state : State N T)
    (rep : Rep arrays state) (message : Message N T) :
    sourceAllowed arrays message <-> messageSourceAllowed state message := by
  cases message <;> simp [sourceAllowed, messageSourceAllowed, allocated_rep arrays state rep]

def newerMessage? (frame : Frame N T) (source destination : N) : Option (Message N T) := do
  let selected <- (frame.queues destination source).peek
  if sourceAllowed frame.nodes selected /\
      (get frame.nodes destination).currentTerm < selected.term then
    some selected
  else none

theorem newer_correct (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) :
    newerMessage? frame source destination = CCFRaft.newerMessage? state source destination := by
  unfold newerMessage? CCFRaft.newerMessage?
  rw [NativeArrayQueue.model_peek_correct frame.queues state.network rep.2 source destination]
  cases taken : takeFirstFrom source (state.network destination) with
  | none => rfl
  | some pair =>
    simp [source_allowed_correct frame.nodes state rep.1,
      ← get_rep frame.nodes state rep.1 destination, Local.toModel]

def Frame.updateTerm (frame : Frame N T) (source destination : N) : Frame N T :=
  match newerMessage? frame source destination with
  | none => frame
  | some selected =>
    { frame with
      nodes := Function.update frame.nodes destination
        (some { get frame.nodes destination with
          role := .follower, currentTerm := selected.term, isNewFollower := true,
          votedFor := none, preVotesGranted := ∅ }) }

theorem update_term_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) :
    (frame.updateTerm source destination).Rep (CCFRaft.next state (.updateTerm source destination)) := by
  simp only [Frame.updateTerm, CCFRaft.next, newer_correct frame state rep]
  cases found : CCFRaft.newerMessage? state source destination with
  | none => exact rep
  | some selected =>
    constructor
    · intro peer
      by_cases same : peer = destination
      · subst peer
        have fields := get_rep frame.nodes state rep.1 destination
        simp [State.node?, updateNode, Local.Rep, ← fields, Local.toModel]
      · simpa [State.node?, updateNode, same] using rep.1 peer
    · exact rep.2

inductive Instruction (N T : Type) where
  | node (instruction : NativeArrayCheckQuorum.Instruction N T)
  | vote (preVote : Bool) (source destination : N)
  | updateTerm (source destination : N)
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
      exact and_congr (NativeArrayCheckQuorum.follows_correct [instruction] _ _ rep.1)
        (ih _ _ (node_step_rep frame state rep instruction))
    | vote preVote source destination =>
      apply and_congr (enabled_correct frame.nodes state rep.1 preVote source destination)
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
        allocated_rep frame.nodes state rep.1, newer_correct frame state rep,
        ih _ _ (update_term_rep frame state rep source destination), and_assoc]
    | queueLength source destination expected =>
      have same := congrArg List.length (congrFun (congrFun rep.2 destination) source)
      simp only [NativeArrayQueue.decodeNetwork, NativeArrayQueue.Queue.decode_length,
        Sparse.Queue.abstractNetwork] at same
      simp only [follows, modelFollows, same, ih frame state rep]
    | queuePoint source destination index expected =>
      have same := congrFun (congrFun rep.2 destination) source
      simp only [NativeArrayQueue.decodeNetwork, Sparse.Queue.abstractNetwork] at same
      simp only [follows, modelFollows, NativeArrayQueue.Queue.point_correct, same, ih frame state rep]

private def filler : Message N T :=
  .proposeVoteRequest { term := 0, source := INITIAL_LEADER, destination := INITIAL_LEADER }

def Frame.ofModel (state : State N T) : Frame N T :=
  { nodes := NativeArrayCheckQuorum.ofModel state
    queues := fun destination source =>
      NativeArrayQueue.Queue.ofList filler (Sparse.Queue.partition source (state.network destination)) }

theorem of_model_rep (state : State N T) : (Frame.ofModel state).Rep state := by
  refine ⟨NativeArrayCheckQuorum.of_model_rep state, ?_⟩
  funext destination source
  simp [Frame.ofModel, NativeArrayQueue.decodeNetwork, Sparse.Queue.abstractNetwork]

theorem of_model_valid (state : State N T) : (Frame.ofModel state).Valid := by
  unfold Frame.Valid
  rw [(of_model_rep state).2]
  exact fun destination => Sparse.Queue.partition_wellFormed (state.network destination)

noncomputable def Frame.realize [Fintype N] (frame : Frame N T) : State N T :=
  { NativeArrayCheckQuorum.realize frame.nodes with
    network := Sparse.Queue.realizeNetwork (NativeArrayQueue.decodeNetwork frame.queues) }

theorem realize_rep [Fintype N] (frame : Frame N T) (valid : frame.Valid) :
    frame.Rep frame.realize := by
  exact ⟨NativeArrayCheckQuorum.realize_rep frame.nodes,
    (Sparse.Queue.network_realizability _ valid).symm⟩

theorem exists_iff [Fintype N] (trace : List (Instruction N T)) :
    (exists frame, frame.Valid /\ follows frame trace) <->
      exists state, modelFollows state trace := by
  constructor
  · rintro ⟨frame, valid, held⟩
    exact ⟨frame.realize, (follows_correct trace _ _ (realize_rep frame valid)).mp held⟩
  · rintro ⟨state, held⟩
    exact ⟨Frame.ofModel state, of_model_valid state,
      (follows_correct trace _ _ (of_model_rep state)).mpr held⟩

end CCFRaft.NativeArrayVote

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayVote).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
