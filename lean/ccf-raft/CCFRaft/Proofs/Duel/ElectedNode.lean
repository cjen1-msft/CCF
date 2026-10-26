module

public import CCFRaft.Proofs.Leadership.AnchorNode
public import CCFRaft.Proofs.Duel.RaceNode

@[expose] public section

/-!
# The elected node, one local step at a time

Role changes, election messages, primary knowledge, and the first heartbeats
of a newly elected primary.
-/

namespace CCFRaft.Proofs.Duel.Elected

open CCF
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Ledger
open CCFRaft.Proofs.Leadership

structure ElectedStep (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState) (sent : List Model.Envelope)
    : Prop where
  /-- Role `none` is entered only by committing the node's own retirement. -/
  none
    : after.role = .none
      -> (before.role = .none /\ after.currentTerm = before.currentTerm)
          \/ after.isRetiredCommitted self
  /-- A primary knows it is primary, unless it already did not in this term. -/
  known
    : after.role = .primary
      -> after.primaryKnown = true
          \/ (before.role = .primary
              /\ before.currentTerm = after.currentTerm
              /\ before.primaryKnown = false)
          \/ after.isRetiredCommitted self
  /-- Vote proposals come only from a nomination or a committed retirement. -/
  proposals
    : forall e,
        e ∈ sent
        -> forall term,
            e.payload = .proposeRequestVoteRequest term
            -> event = .internal .nominateSuccessor \/ after.isRetiredCommitted self
  /-- Pre-vote requests come only from an election timeout. -/
  preVoteRequests
    : forall e,
        e ∈ sent
        -> forall request,
            e.payload = .requestPreVoteRequest request
            -> event = .internal (.timeout .election)
  /-- A granted pre-vote answers a pre-vote request of the same term. -/
  preVoteGrants
    : forall e,
        e ∈ sent
        -> forall response,
            e.payload = .requestPreVoteResponse response
            -> response.voteGranted = true
            -> exists source request,
                event = .receive source (.requestPreVoteRequest request)
                /\ request.term = response.term
  /-- A follower with a matching log accepts its term's primary. -/
  accept
    : forall source request,
        event = .receive source (.appendEntriesRequest request)
        -> before.role = .follower
        -> before.currentTerm = request.term
        -> request.prevLogIndex <= before.log.length
        -> termAt before.log request.prevLogIndex = request.prevLogTerm
        -> (after.primaryKnown = true
              /\ after.role = .follower
              /\ after.currentTerm = request.term)
            \/ after.isRetiredCommitted self
  /-- A new primary sends its term's AppendEntries to every eligible peer. -/
  heartbeats
    : after.role = .primary
      -> Not (before.role = .primary /\ before.currentTerm = after.currentTerm)
      -> forall peer,
          peer ∈ eligiblePeers after self
          -> exists request,
              (⟨self, peer, .appendEntriesRequest request⟩ : Model.Envelope) ∈ sent
              /\ request.term = after.currentTerm

/-- The three election-message origin conditions, checked per payload. -/
def PacketOK (self : NodeID) (event : Event) (after : NodeState) : Message -> Prop
  | .proposeRequestVoteRequest _ =>
      event = .internal .nominateSuccessor \/ after.isRetiredCommitted self
  | .requestPreVoteRequest _ => event = .internal (.timeout .election)
  | .requestPreVoteResponse response =>
      response.voteGranted = true
      -> exists source request,
          event = .receive source (.requestPreVoteRequest request)
          /\ request.term = response.term
  | _ => True

def NotAppend (event : Event) : Prop :=
  forall source request, Not (event = .receive source (.appendEntriesRequest request))

namespace ElectedStep

variable {self : NodeID} {before after : NodeState} {event : Event}
  {sent : List Model.Envelope}

theorem packets (step : ElectedStep self before event after sent)
    (e : Model.Envelope) (member : e ∈ sent)
    : PacketOK self event after e.payload := by
  cases eq : e.payload <;> simp only [PacketOK]
  all_goals first
    | exact ElectedStep.proposals step e member _ eq
    | exact ElectedStep.preVoteRequests step e member _ eq
    | exact ElectedStep.preVoteGrants step e member _ eq

theorem of_packets
    (none
      : after.role = .none
        -> (before.role = .none /\ after.currentTerm = before.currentTerm)
            \/ after.isRetiredCommitted self)
    (known
      : after.role = .primary
        -> after.primaryKnown = true
            \/ (before.role = .primary
                /\ before.currentTerm = after.currentTerm
                /\ before.primaryKnown = false)
            \/ after.isRetiredCommitted self)
    (beats
      : after.role = .primary
        -> Not (before.role = .primary /\ before.currentTerm = after.currentTerm)
        -> forall peer,
            peer ∈ eligiblePeers after self
            -> exists request,
                (⟨self, peer, .appendEntriesRequest request⟩ : Model.Envelope) ∈ sent
                /\ request.term = after.currentTerm)
    (packets : forall e, e ∈ sent -> PacketOK self event after e.payload)
    (accept
      : forall source request,
          event = .receive source (.appendEntriesRequest request)
          -> before.role = .follower
          -> before.currentTerm = request.term
          -> request.prevLogIndex <= before.log.length
          -> termAt before.log request.prevLogIndex = request.prevLogTerm
          -> (after.primaryKnown = true
                /\ after.role = .follower
                /\ after.currentTerm = request.term)
              \/ after.isRetiredCommitted self)
    : ElectedStep self before event after sent where
  none := none
  known := known
  heartbeats := beats
  proposals := fun e mem _ eq => by simpa only [eq, PacketOK] using packets e mem
  preVoteRequests := fun e mem _ eq => by simpa only [eq, PacketOK] using packets e mem
  preVoteGrants := fun e mem _ eq => by simpa only [eq, PacketOK] using packets e mem
  accept := accept

theorem quiet
    (latched : Latched self before after)
    (role : after.role = before.role \/ after.role = .none)
    (term : after.currentTerm = before.currentTerm)
    (packets : forall e, e ∈ sent -> PacketOK self event after e.payload)
    (notAppend : NotAppend event)
    : ElectedStep self before event after sent := by
  refine of_packets ?_ ?_ ?_ packets (fun s r eq => (notAppend s r eq).elim)
  · intro none
    rcases latched with ⟨role, _⟩ | retired
    · exact Or.inl ⟨role.symm.trans none, term⟩
    · exact Or.inr retired
  · intro primary
    rcases latched with ⟨role, known⟩ | retired
    · cases h : before.primaryKnown with
      | false => exact Or.inr (Or.inl ⟨role.symm.trans primary, term.symm, rfl⟩)
      | true => exact Or.inl (known.trans h)
    · exact Or.inr (Or.inr retired)
  · intro primary fresh
    rcases role with role | role
    · exact (fresh ⟨role.symm.trans primary, term.symm⟩).elim
    · rw [role] at primary
      cases primary

theorem refl (self : NodeID) (before : NodeState) (event : Event)
    (notAppend : NotAppend event)
    : ElectedStep self before event before [] :=
  quiet (Latched.refl self before) (Or.inl rfl) rfl (by simp) notAppend

theorem nonleader
    (none : Not (after.role = .none)) (primary : Not (after.role = .primary))
    (packets : forall e, e ∈ sent -> PacketOK self event after e.payload)
    (notAppend : NotAppend event)
    : ElectedStep self before event after sent :=
  of_packets (fun h => (none h).elim) (fun h => (primary h).elim)
    (fun h => (primary h).elim) packets (fun s r eq => (notAppend s r eq).elim)

theorem extend {more : List Model.Envelope}
    (step : ElectedStep self before event after sent)
    (included : forall e, e ∈ sent -> e ∈ more)
    (packets : forall e, e ∈ more -> PacketOK self event after e.payload)
    : ElectedStep self before event after more := by
  refine of_packets (ElectedStep.none step) (ElectedStep.known step) ?_ packets
    (ElectedStep.accept step)
  intro primary fresh peer member
  obtain ⟨request, mem, term⟩ := ElectedStep.heartbeats step primary fresh peer member
  exact ⟨request, included _ mem, term⟩

end ElectedStep

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem advanceCommit_elected (before middle : NodeState) (event : Event)
    (role : middle.role = before.role) (term : middle.currentTerm = before.currentTerm)
    (known : middle.primaryKnown = before.primaryKnown) (notAppend : NotAppend event)
    : Sends (fun after sent => ElectedStep self before event after sent)
        (advanceCommit caps middle self) := by
  refine Sends.mono
    (Sends.and' (advanceCommit_latched self middle)
      (Sends.and' (advanceCommit_sends self middle) (advanceCommit_retires self middle)))
    fun after sent ⟨⟨latched, _, term'⟩, ⟨advance, packets⟩, retires⟩ => ?_
  refine ElectedStep.quiet ?_ ?_ (term'.trans term) ?_ notAppend
  · rcases latched with ⟨r, k⟩ | retired
    · exact Or.inl ⟨r.trans role, k.trans known⟩
    · exact Or.inr retired
  · exact advance.role.imp_left (fun r => r.trans role)
  · intro e member
    rw [(packets e member).2]
    exact Or.inr (retires (List.ne_nil_of_mem member))

theorem becomePrimary_elected (before candidate : NodeState) (event : Event)
    (notAppend : NotAppend event)
    : Sends (fun after sent => ElectedStep self before event after sent)
        (becomePrimary caps self candidate) := by
  unfold becomePrimary
  refine Sends.bind'
    (Sends.and' (advanceCommit_latched self _)
      (Sends.and' (advanceCommit_sends self _) (advanceCommit_retires self _)))
    fun leader nominated ⟨⟨latched, _, _⟩, ⟨advance, packets⟩, retires⟩ => ?_
  refine Sends.bind' (Racing.forIn_sends self _ _) fun _ beats eq => Sends.pure' ?_
  subst eq
  simp only [List.append_nil]
  refine ElectedStep.of_packets ?_ ?_ ?_ ?_
    (fun s r eq => (notAppend s r eq).elim)
  · intro none
    rcases latched with ⟨role, _⟩ | retired
    · simp [primaryState, none] at role
    · exact Or.inr retired
  · intro _
    rcases latched with ⟨_, known⟩ | retired
    · exact Or.inl known
    · exact Or.inr (Or.inr retired)
  · intro _ _ peer member
    refine ⟨makeAppendEntriesRequest leader leader.log.length leader.log.length,
      List.mem_append_right _ ?_, rfl⟩
    exact List.mem_map.mpr ⟨peer, by simpa using member, rfl⟩
  · intro e member
    rcases List.mem_append.mp member with old | new
    · rw [(packets e old).2]
      exact Or.inr (retires (List.ne_nil_of_mem old))
    · obtain ⟨_, _, rfl⟩ := List.mem_map.mp new
      trivial

theorem electIfQuorum_elected (before candidate : NodeState) (event : Event)
    (initial : ElectedStep self before event candidate [])
    (notAppend : NotAppend event)
    : Sends (fun after sent => ElectedStep self before event after sent)
        (electIfQuorum caps self candidate) := by
  unfold electIfQuorum
  exact Sends.ite' (fun _ => becomePrimary_elected self before candidate event notAppend)
    (fun _ => Sends.pure' initial)

theorem becomeCandidate_elected (before state : NodeState) (event : Event)
    (notAppend : NotAppend event)
    : Sends (fun after sent => ElectedStep self before event after sent)
        (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind'
    (electIfQuorum_elected self before _ event
      (ElectedStep.nonleader (by simp) (by simp) (by simp) notAppend) notAppend)
    fun after sent step => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ later requests => Sends.pure' ?_
  simp only [List.append_nil]
  refine step.extend (fun _ mem => List.mem_append_left _ mem) ?_
  intro e member
  rcases List.mem_append.mp member with old | new
  · exact step.packets e old
  · rw [(requests e new).2.2]
    trivial

theorem appendBatch_elected (before : NodeState) (contents : List EntryContent)
    : Sends
        (fun after sent =>
          ElectedStep self before (.internal (.append contents)) after sent)
        (act caps self before (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind'
    (Sends.mono
      (Sends.foldlM' (I := BatchState self before)
        (fun value sent' item batch =>
          appendEntry_batch self before value sent' item batch)
        contents before [] (BatchState.start self before))
      fun _ _ done => by simpa using done)
    fun appended sent batch => ?_
  obtain ⟨⟨entries, sentIndex, rfl, _, _⟩, beats⟩ := batch
  refine Sends.mono
    (advanceCommit_elected self before _ (.internal (.append contents))
      rfl rfl rfl (by intro s r eq; cases eq))
    fun after later step => ?_
  simp only [List.nil_append]
  refine step.extend (fun _ mem => List.mem_append_right _ mem) ?_
  intro e member
  rcases List.mem_append.mp member with old | new
  · obtain ⟨_, _, request, payload, _⟩ := beats e old
    rw [payload]
    trivial
  · exact step.packets e new

theorem sendEntries_elected (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat)
    : Sends
        (fun after sent =>
          ElectedStep self before (.internal (.sendEntries destination batchEnds)) after
            sent)
        (act caps self before (.sendEntries destination batchEnds)) := by
  refine Sends.mono (sendEntries_pass self before destination batchEnds)
    fun after sent pass => ?_
  rw [pass.state]
  refine ElectedStep.quiet (Or.inl ⟨rfl, rfl⟩) (Or.inl rfl) rfl ?_
    (by intro s r eq; cases eq)
  intro e member
  obtain ⟨batch, _, rfl⟩ := pass.sends e member
  trivial

theorem startElection_elected (before : NodeState)
    : Sends
        (fun after sent =>
          ElectedStep self before (.internal (.timeout .election)) after sent)
        (act caps self before (.timeout .election)) := by
  simp only [act]
  unfold startElection
  refine Sends.guard_bind fun _ => ?_
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite'
    (fun _ => becomeCandidate_elected self before _ _ (by intro s r eq; cases eq))
    fun _ => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ sent requests => Sends.pure' ?_
  refine ElectedStep.nonleader
    (by simp)
    (by simp)
    ?_
    (by intro s r eq; cases eq)
  intro e member
  rw [(requests e (by simpa using member)).2.2]
  rfl

theorem checkQuorum_elected (before : NodeState)
    : Sends
        (fun after sent =>
          ElectedStep self before (.internal (.timeout .checkQuorum)) after sent)
        (act caps self before (.timeout .checkQuorum)) := by
  simp only [act]
  unfold checkQuorum
  exact Sends.guard_bind
    fun _ =>
      Sends.pure'
        (ElectedStep.nonleader
          (by simp)
          (by simp)
          (by simp)
          (by intro s r eq; cases eq))

theorem nominate_elected (before : NodeState)
    : Sends
        (fun after sent =>
          ElectedStep self before (.internal .nominateSuccessor) after sent)
        (act caps self before .nominateSuccessor) := by
  refine Sends.mono (nominate_sends self before) fun after sent ⟨eq, _, packets⟩ => ?_
  subst after
  refine ElectedStep.quiet (Latched.refl self before) (Or.inl rfl) rfl ?_
    (by intro s r eq; cases eq)
  intro e member
  rw [(packets e member).2]
  exact Or.inl rfl

theorem voteRequest_elected (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.requestVoteRequest request)) after
            sent)
        (receive caps self source before (.requestVoteRequest request)) := by
  refine Sends.mono (Racing.voteRequest_receive self source before request)
    fun after sent result => ?_
  obtain ⟨middle, granted, observed, _, _, afterEq, sentEq⟩ := result
  rw [afterEq, sentEq]
  have packets : forall e : Model.Envelope,
      e ∈ [⟨self, source, .requestVoteResponse
          { term := middle.currentTerm, voteGranted := granted }⟩] ->
      PacketOK self (.receive source (.requestVoteRequest request))
        (if granted then { middle with votedFor := some source } else middle) e.payload := by
    intro e member
    simp only [List.mem_singleton] at member
    subst member
    trivial
  rcases observed with eq | ⟨_, eq⟩ <;> rw [eq] at packets ⊢
  · refine ElectedStep.quiet ?_ ?_ ?_ packets (by intro s r eq; cases eq)
    · split <;> exact Or.inl ⟨rfl, rfl⟩
    · split <;> exact Or.inl rfl
    · split <;> rfl
  · exact ElectedStep.nonleader (by split <;> simp [bumpedState])
      (by split <;> simp [bumpedState]) packets (by intro s r eq; cases eq)

theorem preVoteRequest_elected (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.requestPreVoteRequest request)) after
            sent)
        (receive caps self source before (.requestPreVoteRequest request)) := by
  refine Sends.mono (Racing.preVoteRequest_receive self source before request)
    fun after sent ⟨observed, _, sentEq⟩ => ?_
  rw [sentEq]
  have packets : forall e : Model.Envelope, e ∈ [⟨self, source, .requestPreVoteResponse
        {
          term := after.currentTerm
          voteGranted := decide (request.term = after.currentTerm
            /\ voteLogUpToDate after request /\ !after.primaryKnown)
        }⟩] ->
      PacketOK self (.receive source (.requestPreVoteRequest request)) after e.payload := by
    intro e member
    simp only [List.mem_singleton] at member
    subst member
    intro granted
    exact ⟨source, request, rfl, (of_decide_eq_true granted).1⟩
  rcases observed with eq | ⟨_, eq⟩ <;> rw [eq] at packets ⊢
  · exact ElectedStep.quiet (Latched.refl self before) (Or.inl rfl) rfl packets
      (by intro s r eq; cases eq)
  · exact ElectedStep.nonleader (by simp [bumpedState]) (by simp [bumpedState])
      packets (by intro s r eq; cases eq)

theorem appendEntriesResponse_elected (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.appendEntriesResponse response))
            after sent)
        (receive caps self source before (.appendEntriesResponse response)) := by
  have quiet := ElectedStep.refl self before (.receive source (.appendEntriesResponse response))
    (by intro s r eq; cases eq)
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' quiet) fun _ => ?_
  rcases observe_response before response with ⟨_, _, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · refine Sends.ite' (fun _ => Sends.pure'
      (ElectedStep.nonleader (by simp [bumpedState]) (by simp [bumpedState])
        (by simp) (by intro s r eq; cases eq))) fun notFollower => ?_
    exact (notFollower (by simp [bumpedState])).elim
  · refine Sends.ite' (fun _ => Sends.pure' quiet) fun _ => ?_
    refine Sends.ite'
      (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' quiet)
      fun _ => Sends.pure'
        (ElectedStep.quiet (Or.inl ⟨rfl, rfl⟩) (Or.inl rfl) rfl
          (by simp) (by intro s r eq; cases eq))
    exact advanceCommit_elected self before _ _ rfl rfl rfl (by intro s r eq; cases eq)

theorem voteResponse_elected (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.requestVoteResponse response)) after
            sent)
        (receive caps self source before (.requestVoteResponse response)) := by
  have quiet := ElectedStep.refl self before (.receive source (.requestVoteResponse response))
    (by intro s r eq; cases eq)
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' quiet) fun _ => ?_
  rcases observe_bumping before (message := .requestVoteResponse response) trivial
    with ⟨_, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (ElectedStep.nonleader (by simp [bumpedState]) (by simp [bumpedState])
        (by simp) (by intro s r eq; cases eq))
  · refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' quiet
    exact electIfQuorum_elected self before _ _
      (ElectedStep.quiet (Or.inl ⟨rfl, rfl⟩) (Or.inl rfl) rfl
        (by simp) (by intro s r eq; cases eq)) (by intro s r eq; cases eq)

theorem preVoteResponse_elected (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.requestPreVoteResponse response))
            after sent)
        (receive caps self source before (.requestPreVoteResponse response)) := by
  have quiet := ElectedStep.refl self before (.receive source (.requestPreVoteResponse response))
    (by intro s r eq; cases eq)
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' quiet) fun _ => ?_
  rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
    with ⟨_, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (ElectedStep.nonleader (by simp [bumpedState]) (by simp [bumpedState])
        (by simp) (by intro s r eq; cases eq))
  · refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' quiet
    refine Sends.ite' (fun _ => becomeCandidate_elected self before _ _
      (by intro s r eq; cases eq)) fun _ => Sends.pure' ?_
    exact ElectedStep.quiet (Or.inl ⟨rfl, rfl⟩) (Or.inl rfl) rfl
      (by simp) (by intro s r eq; cases eq)

theorem proposeVote_elected (before : NodeState) (source : NodeID) (term : Nat)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.proposeRequestVoteRequest term))
            after sent)
        (receive caps self source before (.proposeRequestVoteRequest term)) := by
  have quiet := ElectedStep.refl self before (.receive source (.proposeRequestVoteRequest term))
    (by intro s r eq; cases eq)
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' quiet) fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  exact Sends.ite'
    (fun _ => becomeCandidate_elected self before _ _ (by intro s r eq; cases eq))
    fun _ => Sends.pure' quiet

/-- The AppendEntries walk also records why the primary was not accepted. -/
theorem ae_evidence (source : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          ((after = awareState z r
              /\ (r.term < (awareState z r).currentTerm
                  \/ Not (appendEntryMatchesLog (awareState z r) r)))
            \/ Latched self { awareState z r with primaryKnown := true } after)
          /\ (after.role = (awareState z r).role \/ after.role = .none)
          /\ after.currentTerm = (awareState z r).currentTerm
          /\ forall e,
              e ∈ sent -> exists response, e.payload = .appendEntriesResponse response)
        (handleAppendEntriesRequest caps self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have hw' : awareState z r = w := hw
  rw [hw']
  refine Sends.ite' (fun reject => ?_) fun _ => ?_
  · refine Sends.ite' (fun _ => ?_) fun _ => ?_ <;>
      refine Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
        Sends.pure' ⟨Or.inl ⟨rfl, reject⟩, Or.inl rfl, rfl, ?_⟩ <;>
      subst eq <;> intro e member <;> simp only [List.append_nil, List.mem_singleton] at member <;>
      subst member <;> exact ⟨_, rfl⟩
  refine Sends.ite'
    (fun _ => Sends.pure' ⟨Or.inr (Or.inl ⟨rfl, rfl⟩), Or.inl rfl, rfl, by simp⟩)
    fun _ => ?_
  have tail : forall v : NodeState,
      v.role = w.role -> v.primaryKnown = true -> v.currentTerm = w.currentTerm ->
      Sends
        (fun after sent =>
          ((after = w /\ (r.term < w.currentTerm \/ Not (appendEntryMatchesLog w r)))
            \/ Latched self { w with primaryKnown := true } after)
          /\ (after.role = w.role \/ after.role = .none)
          /\ after.currentTerm = w.currentTerm
          /\ forall e, e ∈ sent -> exists response,
              e.payload = .appendEntriesResponse response)
        (do
          let (state, response) := handleAppendEntiresFromPrimary self v r
          (Capabilities.record self).send (.appendEntriesResponse response) source
          return state : NodeEffect _) := by
    intro v role known term
    have latched := fromPrimary_latched self v r
    have spec := fromLeader_spec self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    rw [hres] at latched spec
    simp only [hres]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
      Sends.pure' ⟨Or.inr ?_, ?_, spec.1.trans term, ?_⟩
    · rcases latched with ⟨r', k'⟩ | retired
      · exact Or.inl ⟨r'.trans role, k'.trans known⟩
      · exact Or.inr retired
    · exact spec.2.2.2.2.1.imp_left (fun r' => r'.trans role)
    · subst eq
      intro e member
      simp only [List.append_nil, List.mem_singleton] at member
      subst member
      exact ⟨_, rfl⟩
  split <;> exact tail _ rfl rfl rfl

theorem ae_elected (before z : NodeState) (source : NodeID)
    (request : AppendEntriesRequest) (observed : Racing.Observed before request.term z)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.appendEntriesRequest request)) after
            sent)
        (handleAppendEntriesRequest caps self source z request) := by
  refine Sends.mono (ae_evidence self source z request)
    fun after sent ⟨shape, role, term, packets⟩ => ?_
  have aware : awareState z request = before \/ (awareState z request).role = .follower := by
    rcases observed with rfl | ⟨_, rfl⟩
    · unfold awareState
      split
      · exact Or.inr rfl
      · exact Or.inl rfl
    · right
      simp [awareState, bumpedState]
  refine ElectedStep.of_packets ?_ ?_ ?_ ?_ ?_
  · intro none
    rcases shape with ⟨same, _⟩ | (⟨kept, _⟩ | retired)
    · have kept : after.role = (awareState z request).role := congrArg NodeState.role same
      rcases aware with eq | follower
      · exact Or.inl ⟨by rw [eq] at kept; exact kept.symm.trans none, by simpa [eq] using term⟩
      · rw [kept, follower] at none
        cases none
    · rcases aware with eq | follower
      · exact Or.inl ⟨by simpa [eq, none] using kept.symm, by simpa [eq] using term⟩
      · have : after.role = .follower := kept.trans follower
        rw [this] at none
        cases none
    · exact Or.inr retired
  · intro primary
    rcases shape with ⟨same, _⟩ | (⟨_, known⟩ | retired)
    · rcases aware with eq | follower
      · have afterEq : after = before := same.trans eq
        rw [afterEq] at primary ⊢
        cases h : before.primaryKnown with
        | false => exact Or.inr (Or.inl ⟨primary, rfl, rfl⟩)
        | true => exact Or.inl rfl
      · have : after.role = .follower := (congrArg NodeState.role same).trans follower
        rw [this] at primary
        cases primary
    · exact Or.inl known
    · exact Or.inr (Or.inr retired)
  · intro primary fresh
    rcases role with kept | none
    · rcases aware with eq | follower
      · exact (fresh ⟨by rw [eq] at kept; exact kept.symm.trans primary,
          by simpa [eq] using term.symm⟩).elim
      · rw [kept, follower] at primary
        cases primary
    · rw [none] at primary
      cases primary
  · intro e member
    obtain ⟨_, payload⟩ := packets e member
    rw [payload]
    trivial
  · intro s r eq
    cases eq
    intro follower same bound matching
    have zEq : z = before := by
      rcases observed with eq | ⟨raised, _⟩
      · exact eq
      · omega
    have awareEq : awareState z request = before := by
      rw [zEq]
      simp [awareState, follower]
    rw [awareEq] at shape term
    rcases shape with ⟨_, reject⟩ | (⟨role, known⟩ | retired)
    · have notReject : Not (request.term < before.currentTerm
          \/ Not (appendEntryMatchesLog before request)) := by
        simp [same, appendEntryMatchesLog, bound, matching]
      exact (notReject reject).elim
    · exact Or.inl ⟨known, role.trans follower, term.trans same⟩
    · exact Or.inr retired

theorem appendEntriesRequest_elected (before : NodeState) (source : NodeID)
    (request : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          ElectedStep self before (.receive source (.appendEntriesRequest request)) after
            sent)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
  · exact ae_elected self before _ source request (Or.inr ⟨bump, rfl⟩)
  · exact ae_elected self before _ source request (Or.inl rfl)

/-- Every local step satisfies `ElectedStep`. -/
theorem electedStep (before : NodeState) (event : Event)
    : Sends (fun after sent => ElectedStep self before event after sent)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_elected self before contents
      | sendEntries destination batchEnds =>
          exact sendEntries_elected self before destination batchEnds
      | timeout kind =>
          cases kind with
          | election => exact startElection_elected self before
          | checkQuorum => exact checkQuorum_elected self before
      | nominateSuccessor => exact nominate_elected self before
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_elected self before source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_elected self before source response
      | requestVoteRequest request => exact voteRequest_elected self before source request
      | requestVoteResponse response =>
          exact voteResponse_elected self before source response
      | requestPreVoteRequest request =>
          exact preVoteRequest_elected self before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_elected self before source response
      | proposeRequestVoteRequest term =>
          exact proposeVote_elected self before source term

end Steps

theorem LocalTransition.electedStep {before after : Model.State}
    (transition : LocalTransition before after)
    : ElectedStep transition.actor transition.pre transition.event transition.post
        transition.outputs.outgoing := by
  obtain ⟨new, eq, holds⟩ :=
    Elected.electedStep transition.actor transition.pre transition.event {} _ _ transition.ran
  simpa [eq] using holds

end CCFRaft.Proofs.Duel.Elected
