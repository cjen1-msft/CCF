module

public import CCFRaft.Proofs.Replication.Step

@[expose] public section

/-!
# The race, one node step at a time

NOT IMPORTED BY `Properties`. The exact effect of each step a node can take
during a race (`Proofs.Duel.Race`): what it becomes and what it sends.
-/

namespace CCFRaft.Proofs.Duel.Racing

open CCF
open Model.Node
open CCFRaft.Proofs.Safety

/-- A pending payload that cannot change a role or grant anything: an
AppendEntries response, or a refused vote or pre-vote. -/
def Inert : Message -> Prop
  | .appendEntriesResponse _ => True
  | .requestVoteResponse response => response.voteGranted = false
  | .requestPreVoteResponse response => response.voteGranted = false
  | _ => False

/-- A step keeps every field the configuration views read. -/
def Keeps (before after : NodeState) : Prop :=
  after.log = before.log
  /\ after.commitIndex = before.commitIndex
  /\ after.retiredCommittedIndex = before.retiredCommittedIndex

namespace Keeps

variable {first second third : NodeState}

theorem refl (state : NodeState) : Keeps state state := ⟨rfl, rfl, rfl⟩

theorem trans (left : Keeps first second) (right : Keeps second third)
    : Keeps first third :=
  ⟨right.1.trans left.1, right.2.1.trans left.2.1, right.2.2.trans left.2.2⟩

theorem configurations (keeps : Keeps first second)
    : second.activeConfigurations = first.activeConfigurations := by
  simp [NodeState.activeConfigurations, keeps.1, keeps.2.1]

theorem members (keeps : Keeps first second)
    : second.activeMembers = first.activeMembers := by
  simp only [NodeState.activeMembers, keeps.configurations]

theorem peers (keeps : Keeps first second) (self : NodeID)
    : eligiblePeers second self = eligiblePeers first self := by
  unfold eligiblePeers NodeState.retirementCompletedNodes NodeState.committedLog
  rw [keeps.members, keeps.1, keeps.2.1]

theorem retired (keeps : Keeps first second) (self : NodeID)
    : second.isRetiredCommitted self <-> first.isRetiredCommitted self := by
  simp [NodeState.isRetiredCommitted, NodeState.retirement, keeps.1, keeps.2.1, keeps.2.2]

theorem upToDate (keeps : Keeps first second) (request : RequestVoteRequest)
    : voteLogUpToDate second request <-> voteLogUpToDate first request := by
  simp [voteLogUpToDate, keeps.1]

theorem request (keeps : Keeps first second)
    : makeRequestVoteRequest second
      = { makeRequestVoteRequest first with term := second.currentTerm } := by
  simp [makeRequestVoteRequest, lastCommittableTerm, lastCommittableIndex, keeps.1, keeps.2.1]

end Keeps

theorem keeps_bumped (state : NodeState) (term : Nat)
    : Keeps state (bumpedState state term) :=
  ⟨rfl, rfl, rfl⟩

theorem sends_run {α : Type} {P : α -> List Model.Envelope -> Prop}
    {m : NodeEffect α} (sends : Sends P m) {result : α}
    {outputs : Outputs NodeID Message Notification}
    (ran : m.run {} = some (result, outputs))
    : P result outputs.outgoing := by
  obtain ⟨new, eq, holds⟩ := sends {} result outputs ran
  simpa [eq] using holds

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

/-- The state a received message leaves before its handler runs. -/
def Observed (before : NodeState) (term : Nat) (after : NodeState) : Prop :=
  after = before \/ (before.currentTerm < term /\ after = bumpedState before term)

theorem Observed.keeps {before after : NodeState} {term : Nat}
    (observed : Observed before term after)
    : Keeps before after := by
  rcases observed with rfl | ⟨_, rfl⟩
  · exact Keeps.refl _
  · exact keeps_bumped _ _

/-- An inert message changes no role, sends nothing, and at most raises the term. -/
theorem inert_receive (source : NodeID) (before : NodeState) (message : Message)
    (inert : Inert message) (notPrimary : Not (before.role = .primary))
    : Sends (fun after sent => sent = [] /\ Observed before message.term after)
        (receive caps self source before message) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' ⟨rfl, Or.inl rfl⟩) fun _ => ?_
  cases message with
  | appendEntriesResponse response =>
      simp only [observeTerm, notPrimary, ite_false, handleAppendEntriesResponse]
      have : (before.role != .primary) = true := by simpa using notPrimary
      simp only [this, ite_true]
      exact Sends.pure' ⟨rfl, Or.inl rfl⟩
  | requestVoteResponse response =>
      simp only [Inert] at inert
      rcases observe_bumping before (message := .requestVoteResponse response) trivial
        with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse, inert] <;>
        simp only [Bool.false_eq_true, and_false, ite_false]
      · exact Sends.pure' ⟨rfl, Or.inr ⟨bump, rfl⟩⟩
      · exact Sends.pure' ⟨rfl, Or.inl rfl⟩
  | requestPreVoteResponse response =>
      simp only [Inert] at inert
      rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
        with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;>
        simp only [handleRequestPreVoteResponse, inert] <;>
        simp only [Bool.false_eq_true, and_false, ite_false]
      · exact Sends.pure' ⟨rfl, Or.inr ⟨bump, rfl⟩⟩
      · exact Sends.pure' ⟨rfl, Or.inl rfl⟩
  | _ => simp [Inert] at inert

/-- A pre-vote request is answered, granted exactly when its term is the receiver's
(after adopting it) and the requester's log is up to date. -/
theorem preVoteRequest_receive (source : NodeID) (before : NodeState)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Observed before request.term after
          /\ request.term <= after.currentTerm
          /\ sent
              = [{
                  source := self
                  target := source
                  payload :=
                    .requestPreVoteResponse
                      {
                        term := after.currentTerm,
                        voteGranted :=
                          decide
                            (request.term = after.currentTerm
                              /\ voteLogUpToDate after request
                              /\ !after.primaryKnown)
                      }
                }])
        (receive caps self source before (.requestPreVoteRequest request)) := by
  simp only [receive]
  refine Sends.ite' (fun no => by simp at no) fun _ => ?_
  rcases observe_bumping before (message := .requestPreVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_ <;> subst eq
  · exact ⟨Or.inr ⟨bump, rfl⟩, by simp [bumpedState, Message.term], rfl⟩
  · exact ⟨Or.inl rfl, le, rfl⟩

/-- A vote request is answered; a grant records the vote. -/
theorem voteRequest_receive (source : NodeID) (before : NodeState)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          exists middle granted,
            Observed before request.term middle
            /\ request.term <= middle.currentTerm
            /\ (granted = true
                <-> request.term = middle.currentTerm
                    /\ voteLogUpToDate middle request
                    /\ middle.primaryKnown = false
                    /\ (middle.votedFor = none \/ middle.votedFor = some source))
            /\ after
                = (if granted then { middle with votedFor := some source } else middle)
            /\ sent
                = [{
                    source := self
                    target := source
                    payload :=
                      .requestVoteResponse
                        { term := middle.currentTerm, voteGranted := granted }
                  }])
        (receive caps self source before (.requestVoteRequest request)) := by
  simp only [receive]
  refine Sends.ite' (fun no => by simp at no) fun _ => ?_
  rcases observe_bumping before (message := .requestVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_ <;> subst eq
  · exact ⟨_, _, Or.inr ⟨bump, rfl⟩, by simp [bumpedState],
      by simp [Message.term], rfl, rfl⟩
  · exact ⟨_, _, Or.inl rfl, le, by simp, rfl, rfl⟩

/-- What a broadcast to the other active members sends. -/
def Broadcast (self : NodeID) (state : NodeState) (message : Message)
    : List Model.Envelope :=
  ((state.activeMembers.erase self).sort).map
    fun target =>
      { source := self, target, payload := message }

theorem forIn_sends (message : Message) (targets : List NodeID)
    : Sends
        (fun _ sent =>
          sent = targets.map fun target => { source := self, target, payload := message })
        (forIn targets PUnit.unit
          fun destination _ => do
            (Capabilities.record self : Caps).send message destination
            pure (ForInStep.yield PUnit.unit)) := by
  induction targets with
  | nil => exact Sends.pure' rfl
  | cons head tail ih =>
      rw [List.forIn_cons]
      refine Sends.bind'
        (Q :=
          fun step sent =>
            step = ForInStep.yield PUnit.unit
            /\ sent = [{ source := self, target := head, payload := message }])
        (Sends.bind' (Sends.send _ _ _)
          fun _ sent eq => Sends.pure' ⟨rfl, by simpa using eq⟩)
        fun step sent ⟨stepEq, eq⟩ => ?_
      subst stepEq eq
      exact Sends.mono ih fun _ later eq => by subst eq; simp

theorem broadcast_exact (state : NodeState) (message : Message)
    : Sends (fun _ sent => sent = Broadcast self state message)
        (broadcastToOthers caps self state message) := by
  unfold broadcastToOthers Broadcast
  exact Sends.bind' (forIn_sends self message _)
    fun _ sent eq => Sends.pure' (by simpa using eq)

/-- A primary's first step: it becomes primary of the candidate's term and sends only
AppendEntries of that term. -/
def Wins (self : NodeID) (candidate after : NodeState) (sent : List Model.Envelope)
    : Prop :=
  after.role = .primary
  /\ after.currentTerm = candidate.currentTerm
  /\ forall e,
      e ∈ sent
      -> e.source = self
          /\ exists request,
              e.payload = .appendEntriesRequest request
              /\ request.term = candidate.currentTerm

/-- A log whose entries are all below the current term. -/
def Below (state : NodeState) : Prop :=
  forall entry, entry ∈ state.log -> entry.term < state.currentTerm

theorem Below.no_commit {state : NodeState} (below : Below state)
    : highestCommittableIndex state self <= state.commitIndex := by
  by_contra ahead
  have spec := highestCommittableIndex_spec state self (by omega)
  have termEq := spec.2.2.1
  have pos : 0 < highestCommittableIndex state self := by omega
  have lt : highestCommittableIndex state self - 1 < state.log.length := by
    have := spec.1; omega
  unfold termAt entryAt? at termEq
  have ne : highestCommittableIndex state self ≠ 0 := by omega
  simp only [ne, ↓reduceIte, List.getElem?_eq_getElem lt] at termEq
  have := below _ (List.getElem_mem lt)
  simp at termEq
  omega

theorem becomePrimary_wins (candidate : NodeState) (below : Below candidate)
    : Sends (Wins self candidate) (becomePrimary caps self candidate) := by
  unfold becomePrimary
  have primaryBelow : Below (primaryState candidate) := by
    intro entry member
    simp only [primaryState] at member ⊢
    split at member
    · exact below entry (List.mem_of_mem_take member)
    · exact below entry member
  have noAdvance : advanceCommit caps (primaryState candidate) self
      = pure (primaryState candidate) := by
    unfold advanceCommit
    simp only [primaryBelow.no_commit self, ↓reduceIte]
  dsimp only
  rw [noAdvance]
  refine Sends.bind'
    (Sends.pure'
      (P :=
        fun state sent =>
          state = primaryState candidate /\ sent = [])
      ⟨rfl, rfl⟩)
    fun leader _ ⟨eq, nil⟩ => ?_
  subst eq nil
  refine Sends.bind' (Q := fun _ later => forall e, e ∈ later -> e.source = self
      /\ exists request, e.payload = .appendEntriesRequest request
        /\ request.term = candidate.currentTerm)
    (Sends.forIn' fun peer _ member => ?_) fun _ later beats => Sends.pure' ?_
  · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member => ?_
    simp only [eq, List.append_nil, List.mem_singleton] at member
    subst member
    exact ⟨rfl, _, rfl, by simp [makeAppendEntriesRequest, primaryState]⟩
  · refine ⟨by simp [primaryState], by simp [primaryState], fun e member => beats e ?_⟩
    simpa using member

/-- What `electIfQuorum` does. -/
def Elect (self : NodeID) (state after : NodeState) (sent : List Model.Envelope) : Prop :=
  if state.role = .candidate
      /\ hasQuorum state.activeConfigurations state.votesGranted
      /\ Not (state.isRetiredCommitted self) then
    Below state -> Wins self state after sent
  else
    after = state /\ sent = []

theorem electIfQuorum_elect (state : NodeState)
    : Sends (Elect self state) (electIfQuorum caps self state) := by
  unfold electIfQuorum Elect
  split
  · by_cases below : Below state
    · exact Sends.mono (becomePrimary_wins self state below) fun _ _ wins _ => wins
    · exact Sends.mono (becomePrimary_sends self state) fun _ _ _ b => absurd b below
  · exact Sends.pure' ⟨rfl, rfl⟩

/-- What `becomeCandidate` does: elect on the self-vote, then ask for votes. -/
def Candidacy (self : NodeID) (state after : NodeState) (sent : List Model.Envelope)
    : Prop :=
  exists won,
    Elect self (freshCandidate self state) after won
    /\ sent
        = won
          ++ Broadcast self (freshCandidate self state)
              (.requestVoteRequest (makeRequestVoteRequest (freshCandidate self state)))

theorem becomeCandidate_candidacy (state : NodeState)
    : Sends (Candidacy self state) (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_elect self (freshCandidate self state))
    fun next won elected => ?_
  refine Sends.bind' (broadcast_exact self _ _) fun _ later eq => Sends.pure' ?_
  exact ⟨won, elected, by simp [eq]; rfl⟩

/-- What a pre-vote candidate does once its pre-votes change. -/
def PreVoted (self : NodeID) (state after : NodeState) (sent : List Model.Envelope)
    : Prop :=
  if hasQuorum state.activeConfigurations state.preVotesGranted then
    Candidacy self state after sent
  else
    after = state /\ sent = []

/-- What an election timeout does. -/
theorem startElection_outcome (state : NodeState)
    : Sends
        (fun after sent =>
          canStartElection state self
          /\ if hasQuorum (preVoteState self state).activeConfigurations
                  (preVoteState self state).preVotesGranted then
                Candidacy self (preVoteState self state) after sent
              else
                after = preVoteState self state
                /\ sent
                    = Broadcast self (preVoteState self state)
                        (.requestPreVoteRequest
                          (makeRequestVoteRequest (preVoteState self state))))
        (startElection caps state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨can, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun quorum => ?_) fun quorum => ?_
  · refine Sends.mono (becomeCandidate_candidacy self _) fun _ _ done => ⟨can, ?_⟩
    split
    · exact done
    · contradiction
  · refine Sends.bind' (broadcast_exact self _ _) fun _ sent eq => Sends.pure' ⟨can, ?_⟩
    split
    · contradiction
    · exact ⟨rfl, by rw [List.append_nil, List.nil_append, eq]; rfl⟩

/-- A pre-vote response. -/
theorem preVoteResponse_receive (source : NodeID) (before : NodeState)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          exists middle,
            Observed before response.term middle
            /\ if source ∈ eligiblePeers before self
                  /\ middle.role = .preVoteCandidate
                  /\ response.term = middle.currentTerm
                  /\ response.voteGranted = true then
                  PreVoted self
                    {
                      middle with
                        preVotesGranted := insert source middle.preVotesGranted
                    }
                    after sent
                else
                  after = middle /\ sent = [])
        (receive caps self source before (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun no => ?_) fun yes => ?_
  · have : source ∉ eligiblePeers before self := by simpa using no
    exact Sends.pure' ⟨before, Or.inl rfl, by simp [this]⟩
  · have eligible : source ∈ eligiblePeers before self := by simpa using yes
    have observed
        : Observed before response.term (observeTerm before (.requestPreVoteResponse response)) := by
      rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
        with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
      · exact Or.inr ⟨bump, rfl⟩
      · exact Or.inl rfl
    generalize observeTerm before (.requestPreVoteResponse response) = middle at observed ⊢
    simp only [handleRequestPreVoteResponse]
    refine Sends.ite' (fun cond => ?_) fun cond => ?_
    · refine Sends.mono (P := PreVoted self
          { middle with preVotesGranted := insert source middle.preVotesGranted }) ?_
        fun _ _ h => ⟨middle, observed, by simpa [eligible, cond] using h⟩
      unfold PreVoted
      dsimp only
      refine Sends.ite' (fun quorum => ?_) fun quorum => ?_
      · exact Sends.mono (becomeCandidate_candidacy self _) fun _ _ h => by
          split
          · exact h
          · contradiction
      · exact Sends.pure' (by
          split
          · contradiction
          · exact ⟨rfl, rfl⟩)
    · exact Sends.pure' ⟨middle, observed, by simp_all⟩

/-- A vote response. -/
theorem voteResponse_receive (source : NodeID) (before : NodeState)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          exists middle,
            Observed before response.term middle
            /\ if source ∈ eligiblePeers before self
                  /\ middle.role = .candidate
                  /\ response.term = middle.currentTerm
                  /\ response.voteGranted = true then
                  Elect self
                    { middle with votesGranted := insert source middle.votesGranted }
                    after sent
                else
                  after = middle /\ sent = [])
        (receive caps self source before (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun no => ?_) fun yes => ?_
  · have : source ∉ eligiblePeers before self := by simpa using no
    exact Sends.pure' ⟨before, Or.inl rfl, by simp [this]⟩
  · have eligible : source ∈ eligiblePeers before self := by simpa using yes
    have observed
        : Observed before response.term (observeTerm before (.requestVoteResponse response)) := by
      rcases observe_bumping before (message := .requestVoteResponse response) trivial
        with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
      · exact Or.inr ⟨bump, rfl⟩
      · exact Or.inl rfl
    generalize observeTerm before (.requestVoteResponse response) = middle at observed ⊢
    simp only [handleRequestVoteResponse]
    refine Sends.ite' (fun cond => ?_) fun cond => ?_
    · exact Sends.mono (electIfQuorum_elect self _)
        fun _ _ h => ⟨middle, observed, by simpa [eligible, cond] using h⟩
    · exact Sends.pure' ⟨middle, observed, by simp_all⟩

/-- Only a primary acts on anything but an election timeout. -/
theorem act_primary {state : NodeState} {input : Input}
    (other : input ≠ .timeout .election) {result : NodeState}
    {outputs : Outputs NodeID Message Notification}
    (ran : (act caps self state input).run {} = some (result, outputs))
    : state.role = .primary := by
  by_contra notPrimary
  cases input with
  | append entries =>
      simp [act, appendBatch, notPrimary, guard] at ran
  | sendEntries destination batchEnds =>
      simp [act, sendEntries, notPrimary, guard] at ran
  | timeout kind =>
      cases kind with
      | election => exact other rfl
      | checkQuorum => simp [act, checkQuorum, notPrimary, guard] at ran
  | nominateSuccessor =>
      simp [act, nominateSuccessor, notPrimary, guard] at ran

end Steps

end CCFRaft.Proofs.Duel.Racing
