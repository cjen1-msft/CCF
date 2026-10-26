module

public import CCFRaft.Proofs.Leadership.InitRaiseNode

@[expose] public section

set_option linter.unusedSectionVars false

/-!
A regular election request is part of a complete broadcast.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety

variable [Config.InitialConfiguration]

/-- Every regular election request in the output was broadcast to all peers. -/
def VotePackets (self : NodeID) (after : NodeState) (sent : List Model.Envelope) : Prop :=
  Not (after.role = .primary)
  -> Not (after.role = .none)
  -> forall envelope request,
      envelope ∈ sent
      -> envelope.payload = .requestVoteRequest request
      -> sent = broadcast self after (.requestVoteRequest request)

/-- An empty output satisfies the broadcast condition. -/
theorem VotePackets.empty (self : NodeID) (state : NodeState)
    : VotePackets self state [] := by
  intro _ _ envelope _ member _
  cases member

/-- A singleton non-vote output satisfies the broadcast condition. -/
theorem VotePackets.singleton (self : NodeID) (state : NodeState)
    (envelope : Model.Envelope)
    (notVote : forall request, Not (envelope.payload = .requestVoteRequest request))
    : VotePackets self state [envelope] := by
  intro _ _ e request member eq
  simp only [List.mem_singleton] at member
  subst e
  exact (notVote request eq).elim

/-- Outputs containing no vote request satisfy the broadcast condition. -/
theorem VotePackets.no_votes {self : NodeID} {state : NodeState}
    {sent : List Model.Envelope}
    (none
      : forall envelope,
          envelope ∈ sent
          -> forall request, Not (envelope.payload = .requestVoteRequest request))
    : VotePackets self state sent := by
  intro _ _ e request member eq
  exact (none e member request eq).elim

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

/-- Electing a candidate either changes no output or leaves it primary or retired. -/
theorem elect_nonleader (state : NodeState)
    : Sends
        (fun after sent =>
          Not (after.role = .primary)
          -> Not (after.role = .none)
          -> after = state /\ sent = [])
        (electIfQuorum caps self state) := by
  refine Sends.mono (electIfQuorum_sends self state)
    fun after sent result noPrimary active => ?_
  rcases result with result | ⟨_, _, advance, _⟩
  · exact result
  · rcases Advance.role advance with role | role
    · exact (noPrimary (by simpa [primaryState] using role)).elim
    · exact (active role).elim

/-- Starting a regular election broadcasts the resulting candidate's request. -/
theorem candidate_broadcast (state : NodeState)
    : Sends
        (fun after sent =>
          Not (after.role = .primary)
          -> Not (after.role = .none)
          -> after = freshCandidate self state
              /\ sent
                  = broadcast self after
                      (.requestVoteRequest (makeRequestVoteRequest after)))
        (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (elect_nonleader self (freshCandidate self state))
    fun after sent result => ?_
  refine Sends.bind' (broadcast_exact self _ _) fun _ later eq => Sends.pure' ?_
  intro noPrimary active
  obtain ⟨rfl, rfl⟩ := result noPrimary active
  exact ⟨rfl, by simpa [freshCandidate] using eq⟩

/-- A candidate broadcast satisfies the uniform vote-packet condition. -/
theorem candidate_votes (state : NodeState)
    : Sends (VotePackets self) (becomeCandidate caps state self) := by
  refine Sends.mono (candidate_broadcast self state) fun after sent result
    noPrimary active e request member payload => ?_
  obtain ⟨_, eq⟩ := result noPrimary active
  rw [eq] at member
  obtain ⟨target, _, targetEq⟩ := List.mem_map.mp member
  have reqEq : makeRequestVoteRequest after = request := by
    have p := congrArg (fun e : Model.Envelope => e.payload) targetEq
    rw [payload] at p
    exact Message.requestVoteRequest.inj p
  rw [reqEq] at eq
  exact eq

/-- A timeout either broadcasts pre-votes or starts a regular election. -/
theorem timeout_votes (state : NodeState)
    : Sends (VotePackets self) (startElection caps state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => candidate_votes self _) fun _ => ?_
  refine Sends.bind' (broadcast_exact self _ _) fun _ sent eq => Sends.pure' ?_
  apply VotePackets.no_votes
  intro envelope member request payload
  simp only [List.nil_append, List.append_nil, eq, broadcast, List.mem_map] at member
  obtain ⟨_, _, rfl⟩ := member
  cases payload

/-- A pre-vote response only broadcasts regular votes when it starts a candidacy. -/
theorem pre_response_votes (state : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (VotePackets self)
        (handleRequestPreVoteResponse caps self state source response) := by
  unfold handleRequestPreVoteResponse
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (VotePackets.empty self _)
  exact Sends.ite' (fun _ => candidate_votes self _) fun _ =>
    Sends.pure' (VotePackets.empty self _)

/-- A nomination only broadcasts regular votes when it starts a candidacy. -/
theorem proposal_votes (state : NodeState) (term : Nat)
    : Sends (VotePackets self)
        (handleProposeRequestVoteRequest caps state self term) := by
  unfold handleProposeRequestVoteRequest
  exact Sends.ite' (fun _ => candidate_votes self _) fun _ =>
    Sends.pure' (VotePackets.empty self _)

/-- Electing a candidate never emits a regular vote request. -/
theorem elect_votes (state : NodeState)
    : Sends (VotePackets self) (electIfQuorum caps self state) := by
  refine Sends.mono (elect_nonleader self state) fun after sent result noPrimary active
    envelope _ member _ => ?_
  rw [(result noPrimary active).2] at member
  cases member

/-- Advancing commit emits nominations, not regular vote requests. -/
theorem advance_votes (state : NodeState)
    : Sends (VotePackets self) (advanceCommit caps state self) := by
  refine Sends.mono (advanceCommit_sends self state) fun after sent result => ?_
  apply VotePackets.no_votes
  intro e member request payload
  have sent := result.2 e member
  rcases sent with ⟨_, eq⟩
  rw [payload] at eq
  cases eq

/-- An AppendEntries response emits no regular election request. -/
theorem ae_response_votes (state : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends (VotePackets self)
        (handleAppendEntriesResponse caps self state source response) := by
  unfold handleAppendEntriesResponse
  refine Sends.ite' (fun _ => Sends.pure' (VotePackets.empty self _)) fun _ => ?_
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (VotePackets.empty self _)
  exact Sends.ite' (fun _ => advance_votes self _) fun _ =>
    Sends.pure' (VotePackets.empty self _)

/-- An AppendEntries request emits only AppendEntries responses. -/
theorem ae_request_votes (state : NodeState) (source : NodeID)
    (request : AppendEntriesRequest) (le : request.term <= state.currentTerm)
    : Sends (VotePackets self)
        (handleAppendEntriesRequest caps self source state request) := by
  refine Sends.mono (aeReply self source state request le) fun after sent result => ?_
  apply VotePackets.no_votes
  intro e member vote payload
  rcases result.2.2.2.2.2.2.2 with ⟨_, _, sends⟩ | ⟨_, _, _, _, _, response, eq, _, responsePayload⟩
  · obtain ⟨_, response, responsePayload, _⟩ := sends e member
    rw [payload] at responsePayload
    cases responsePayload
  · rw [eq] at member
    simp only [List.mem_singleton] at member
    subst e
    have eq := responsePayload.2
    rw [payload] at eq
    cases eq

/-- Receiving any packet preserves the uniform regular-election broadcast property. -/
theorem receive_votes (state : NodeState) (source : NodeID) (message : Message)
    : Sends (VotePackets self) (receive caps self source state message) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (VotePackets.empty self _)) fun _ => ?_
  cases message with
  | appendEntriesRequest request =>
      apply ae_request_votes self _ source request
      simp only [observeTerm, Message.term, updateTerm]
      by_cases h : state.currentTerm < request.term <;>
        simp [h, becomeAwareOfNewTerm]
      omega
  | appendEntriesResponse response => exact ae_response_votes self _ source response
  | requestVoteRequest request =>
      unfold handleRequestVoteRequest
      refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
      subst sent
      simp only [List.append_nil]
      exact VotePackets.singleton self _ _ (by intro request eq; cases eq)
  | requestPreVoteRequest request =>
      unfold handleRequestPreVoteRequest
      refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
      subst sent
      simp only [List.append_nil]
      exact VotePackets.singleton self _ _ (by intro request eq; cases eq)
  | requestVoteResponse response =>
      unfold handleRequestVoteResponse
      exact Sends.ite' (fun _ => elect_votes self _) fun _ =>
        Sends.pure' (VotePackets.empty self _)
  | requestPreVoteResponse response => exact pre_response_votes self _ source response
  | proposeRequestVoteRequest term => exact proposal_votes self _ term

/-- Non-timeout local steps cannot emit a regular election request. -/
theorem local_votes (state : NodeState) (input : Input)
    : Sends (VotePackets self) (act caps self state input) := by
  by_cases timeout : input = .timeout .election
  · subst input
    exact timeout_votes self state
  · refine Sends.mono (CCFRaft.Proofs.Safety.summary self state (.internal input)) ?_
    intro after sent summary
    apply VotePackets.no_votes
    intro e member request payload
    have send := (CCFRaft.Proofs.Safety.Summary.sends summary e member).2
    simp only [payload] at send
    rcases CCFRaft.Proofs.Safety.Summary.term_cause summary with le | ⟨_, fresh⟩ | ⟨_, _, eq, _⟩
    · omega
    · simp [FreshCause, timeout] at fresh
    · cases eq

/-- Every vote request emitted by a local transition was broadcast to every peer. -/
theorem step_votes (state : NodeState) (event : Model.Node.Event)
    : Sends (VotePackets self) (Model.Node.step caps self state event) := by
  cases event with
  | internal input => exact local_votes self state input
  | receive source message => exact receive_votes self state source message

end Steps

end CCFRaft.Proofs.Leadership.InitRaise
