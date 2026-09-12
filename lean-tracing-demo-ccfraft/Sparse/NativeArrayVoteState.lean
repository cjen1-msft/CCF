-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum
import Sparse.NativeArrayQueue
import Sparse.NativeArrayNatSet
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

def CampaignAt (log : Log N T) (current signature : Nat) (node : N) : Prop :=
  (current = 0 /\ node ∈ INITIAL_CONFIGURATION) \/
    exists index nodes, current <= index /\ index <= signature /\
      Reconfiguration log index nodes /\ node ∈ nodes

theorem campaign_at_correct (log : Log N T) (state : NodeState N T) (node : N)
    (same : state.log = log.decode) :
    CampaignAt log (currentConfiguration state).index (maxCommittableIndex state.log) node <->
      campaignEligible node state := by
  simp only [campaignEligible, List.any_eq_true, decide_eq_true_eq, activeConfigurations,
    List.mem_filter, allConfigurations, List.mem_cons]
  constructor
  · rintro (⟨zero, member⟩ | ⟨index, nodes, lower, upper, physical, member⟩)
    · exact ⟨implicitConfiguration, ⟨Or.inl rfl, by simp [implicitConfiguration, zero]⟩,
        member, by simp [implicitConfiguration]⟩
    · refine ⟨{ index, nodes }, ⟨Or.inr ?_, lower⟩, member, upper⟩
      rw [same, Sparse.ConfigurationSnapshot.mem_configurations_iff]
      exact (reconfiguration_correct _ _ _).mp physical
  · rintro ⟨configuration, ⟨member, lower⟩, included, upper⟩
    rcases member with implicit | physical
    · subst configuration
      exact Or.inl ⟨by simpa [implicitConfiguration] using lower, included⟩
    · refine Or.inr ⟨configuration.index, configuration.nodes, lower, upper, ?_, included⟩
      apply (reconfiguration_correct _ _ _).mpr
      rw [same, Sparse.ConfigurationSnapshot.mem_configurations_iff] at physical
      exact physical

theorem campaign_member (state : NodeState N T) (node : N) (eligible : campaignEligible node state) :
    node ∈ activeNodeUnion state := by
  simp only [campaignEligible, List.any_eq_true, decide_eq_true_eq] at eligible
  rcases eligible with ⟨configuration, active, member, _⟩
  simp only [activeNodeUnion, mem_union]
  exact Or.inr ⟨configuration, active, member⟩

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

structure Globals (N T : Type) where
  submittedTxIds : Finset T
  hasJoined : Finset N
  preVoteStatus : N -> PreVoteStatus
  retirementCompleted : N -> Finset N

def Globals.ofModel (state : State N T) : Globals N T :=
  { submittedTxIds := state.submittedTxIds, hasJoined := state.hasJoined,
    preVoteStatus := state.preVoteStatus, retirementCompleted := state.retirementCompleted }

structure Frame (N T : Type) where
  nodes : Arrays N T
  queues : NativeArrayQueue.Network N T
  globals : Globals N T

structure Frame.Rep (frame : Frame N T) (state : State N T) : Prop where
  nodes : NativeArrayCheckQuorum.Rep frame.nodes state
  queues : NativeArrayQueue.decodeNetwork frame.queues = Sparse.Queue.abstractNetwork state.network
  globals : frame.globals = Globals.ofModel state

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
  · cases preVote <;> exact rep.nodes
  · change NativeArrayQueue.decodeNetwork (NativeArrayQueue.send frame.queues
      (packet (get frame.nodes source) preVote source destination signature)) = _
    rw [NativeArrayQueue.model_send_correct frame.queues state.network rep.queues,
      packet_correct frame.nodes state rep.nodes preVote source destination signature latest]
    cases preVote <;> rfl
  · cases preVote <;> exact rep.globals

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
    | exact ⟨NativeArrayCheckQuorum.step_correct _ _ rep.nodes _, rep.queues, rep.globals⟩

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
  rw [NativeArrayQueue.model_peek_correct frame.queues state.network rep.queues source destination]
  cases taken : takeFirstFrom source (state.network destination) with
  | none => rfl
  | some pair =>
    simp [source_allowed_correct frame.nodes state rep.nodes,
      ← get_rep frame.nodes state rep.nodes destination, Local.toModel]

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
        have fields := get_rep frame.nodes state rep.nodes destination
        simp [State.node?, updateNode, Local.Rep, ← fields, Local.toModel]
      · simpa [State.node?, updateNode, same] using rep.nodes peer
    · exact rep.queues
    · exact rep.globals

def campaignAction (preVote : Bool) (node : N) : Action N T :=
  if preVote then .becomePreVoteCandidate node else .timeout node

def campaignEnabled (frame : Frame N T) (preVote : Bool) (node : N) : Prop :=
  (frame.nodes node).isSome = true /\
    ((get frame.nodes node).role = .follower \/
      (get frame.nodes node).role = .preVoteCandidate \/ (get frame.nodes node).role = .candidate) /\
    (get frame.nodes node).membershipState ≠ .retiredCommitted /\
    frame.globals.preVoteStatus node = (if preVote then .enabled else .capable) /\
    exists current, CurrentIndex (get frame.nodes node).log (get frame.nodes node).commit current /\
      exists signature, SignatureIndex (get frame.nodes node).log signature /\
        (CampaignAt (get frame.nodes node).log current signature node \/
          node ∈ frame.globals.retirementCompleted node)

theorem campaign_enabled_correct (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (preVote : Bool) (node : N) :
    campaignEnabled frame preVote node <-> CCFRaft.Enabled state (campaignAction preVote node) := by
  have fields := get_rep frame.nodes state rep.nodes node
  have log : (get frame.nodes node).log.decode = (state.nodes node).log :=
    congrArg NodeState.log fields
  have commit : (get frame.nodes node).commit = (state.nodes node).commitIndex :=
    congrArg NodeState.commitIndex fields
  have role : (get frame.nodes node).role = (state.nodes node).role :=
    congrArg NodeState.role fields
  have membership : (get frame.nodes node).membershipState = (state.nodes node).membershipState :=
    congrArg NodeState.membershipState fields
  have ready :
      (exists current, CurrentIndex (get frame.nodes node).log (get frame.nodes node).commit current /\
        exists signature, SignatureIndex (get frame.nodes node).log signature /\
          (CampaignAt (get frame.nodes node).log current signature node \/
            node ∈ frame.globals.retirementCompleted node)) <->
      (campaignEligible node (state.nodes node) \/ node ∈ state.retirementCompleted node) := by
    simp only [current_index_correct, signature_index_correct, log, commit,
      rep.globals, Globals.ofModel, exists_eq_left']
    exact or_congr (campaign_at_correct _ _ node log.symm) Iff.rfl
  have redundant :
      (node ∈ activeNodeUnion (state.nodes node) /\
        campaignEligible node (state.nodes node)) <->
      campaignEligible node (state.nodes node) :=
    ⟨And.right, fun eligible => ⟨campaign_member _ _ eligible, eligible⟩⟩
  simp only [campaignEnabled, ready]
  cases preVote <;> cases status : state.preVoteStatus node <;>
    simp [campaignAction, CCFRaft.Enabled,
      allocated_rep frame.nodes state rep.nodes, rep.globals, Globals.ofModel,
      role, membership, status, redundant, and_comm, and_left_comm]

def Frame.campaign (frame : Frame N T) (preVote : Bool) (node : N) : Frame N T :=
  let row := get frame.nodes node
  let updated := if preVote then { row with role := .preVoteCandidate, preVotesGranted := {node} }
    else
      { row with
        role := .candidate
        currentTerm := row.currentTerm + 1
        votedFor := some node
        votesGranted := {node}
        preVotesGranted := ∅ }
  { frame with nodes := Function.update frame.nodes node (some updated) }

theorem campaign_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (preVote : Bool) (node : N) :
    (frame.campaign preVote node).Rep (CCFRaft.next state (campaignAction preVote node)) := by
  constructor
  · intro peer
    by_cases same : peer = node
    · subst peer
      have fields := get_rep frame.nodes state rep.nodes node
      cases preVote <;>
        simp [Frame.campaign, campaignAction, CCFRaft.next, State.node?, updateNode,
          Local.Rep, ← fields, Local.toModel]
    · cases preVote <;>
        simpa [Frame.campaign, campaignAction, CCFRaft.next, State.node?, updateNode, same] using rep.nodes peer
  · cases preVote <;> exact rep.queues
  · cases preVote <;> exact rep.globals

private def filler : Message N T :=
  .proposeVoteRequest { term := 0, source := INITIAL_LEADER, destination := INITIAL_LEADER }

def Frame.ofModel (state : State N T) : Frame N T :=
  { nodes := NativeArrayCheckQuorum.ofModel state
    queues := fun destination source =>
      NativeArrayQueue.Queue.ofList filler (Sparse.Queue.partition source (state.network destination))
    globals := Globals.ofModel state }

theorem of_model_rep (state : State N T) : (Frame.ofModel state).Rep state := by
  refine ⟨NativeArrayCheckQuorum.of_model_rep state, ?_, rfl⟩
  funext destination source
  simp [Frame.ofModel, NativeArrayQueue.decodeNetwork, Sparse.Queue.abstractNetwork]

theorem of_model_valid (state : State N T) : (Frame.ofModel state).Valid := by
  unfold Frame.Valid
  rw [(of_model_rep state).queues]
  exact fun destination => Sparse.Queue.partition_wellFormed (state.network destination)

noncomputable def Frame.realize [Fintype N] (frame : Frame N T) : State N T :=
  { NativeArrayCheckQuorum.realize frame.nodes with
    network := Sparse.Queue.realizeNetwork (NativeArrayQueue.decodeNetwork frame.queues)
    submittedTxIds := frame.globals.submittedTxIds
    hasJoined := frame.globals.hasJoined
    preVoteStatus := frame.globals.preVoteStatus
    retirementCompleted := frame.globals.retirementCompleted }

theorem realize_rep [Fintype N] (frame : Frame N T) (valid : frame.Valid) :
    frame.Rep frame.realize := by
  exact ⟨NativeArrayCheckQuorum.realize_rep frame.nodes,
    (Sparse.Queue.network_realizability _ valid).symm, rfl⟩

end CCFRaft.NativeArrayVote

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayVote).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
