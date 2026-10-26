module

public import CCFRaft.Proofs.Duel.SplitDefs
public import CCFRaft.Proofs.Duel.ElectedNode
public import CCFRaft.Proofs.Duel.CommittedWindow

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The leaderless round: the frozen invariant

Once every participant has adopted `term + 1`, and as long as no participant is
primary of `term + 1`, the round is `Frozen`, the participants' logs and
configurations stay put, and a participant's timer is reset only by its own timeouts.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Duel.Racing (Keeps)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-! ## One node's step in the frozen round -/

section Node

open CCF
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Duel.Racing (Observed sends_run)
open CCFRaft.Proofs.Duel.Racing (keeps_bumped keeps_preVote keeps_fresh)

/-- What the frozen invariant knows of a participant in `T`. -/
def Ready (T : Nat) (state : NodeState) : Prop :=
  state.currentTerm = T
  -> state.primaryKnown = false
      /\ (Not (state.role = .preVoteCandidate) -> state.preVotesGranted = ∅)
      /\ Not (state.role = .primary)

/-- A step from `before` to `after` keeps the frozen facts of a non-primary in `T`,
and keeps its log once it is in `T`. -/
def Good (T : Nat) (before after : NodeState) : Prop :=
  after.currentTerm = T
  -> Not (after.role = .primary)
  -> Not (after.role = .none)
  -> after.primaryKnown = false
      /\ (Not (after.role = .preVoteCandidate) -> after.preVotesGranted = ∅)
      /\ (before.currentTerm = T -> Keeps before after)

variable {T : Nat} {before : NodeState}

theorem good_self (ready : Ready T before) : Good T before before :=
  fun term _ _ => ⟨(ready term).1, (ready term).2.1, fun _ => Racing.Keeps.refl _⟩

theorem good_bumped (term : Nat) : Good T before (bumpedState before term) :=
  fun _ _ _ => ⟨rfl, fun _ => rfl, fun _ => keeps_bumped _ _⟩

theorem good_observed (ready : Ready T before) {term : Nat} {middle : NodeState}
    (observed : Observed before term middle)
    : Good T before middle := by
  rcases observed with rfl | ⟨_, rfl⟩
  · exact good_self ready
  · exact good_bumped _

theorem good_fresh (self : NodeID) {state : NodeState} (keeps : Keeps before state)
    : Good T before (freshCandidate self state) :=
  fun _ _ _ => ⟨rfl, fun _ => rfl, fun _ => keeps.trans (keeps_fresh self state)⟩

theorem good_advance {self : NodeID} {state after : NodeState}
    (advance : Advance self (primaryState state) after)
    : Good T before after := by
  intro _ notPrimary notNone
  rcases advance.role with eq | eq
  · exact absurd (by rw [eq]; rfl) notPrimary
  · exact absurd eq notNone

theorem good_mild {middle after : NodeState} (good : Good T before middle)
    (term : after.currentTerm = middle.currentTerm) (role : after.role = middle.role)
    (known : after.primaryKnown = middle.primaryKnown)
    (votes : after.preVotesGranted = middle.preVotesGranted) (keeps : Keeps middle after)
    : Good T before after := by
  intro termEq notPrimary notNone
  rw [role] at notPrimary notNone
  obtain ⟨knownEq, empty, kept⟩ := good (term ▸ termEq) notPrimary notNone
  exact ⟨known.trans knownEq, fun notPre => votes.trans (empty (role ▸ notPre)),
    fun preT => (kept preT).trans keeps⟩

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem electIfQuorum_good {state : NodeState} (good : Good T before state)
    : Sends (fun after _ => Good T before after) (electIfQuorum caps self state) :=
  Sends.mono (electIfQuorum_sends self state)
    fun _ _ done =>
      done.elim (fun ⟨eq, _⟩ => eq ▸ good) fun ⟨_, _, advance, _⟩ => good_advance advance

theorem becomeCandidate_good {state : NodeState} (keeps : Keeps before state)
    : Sends (fun after _ => Good T before after) (becomeCandidate caps state self) :=
  Sends.mono (becomeCandidate_sends self state)
    fun _ _ done =>
      done.elim (fun ⟨eq, _⟩ => eq ▸ good_fresh self keeps)
        fun ⟨_, advance, _⟩ => good_advance advance

theorem startElection_good
    : Sends (fun after _ => Good T before after) (startElection caps before self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · exact Sends.mono (becomeCandidate_good self (keeps_preVote self before))
      fun _ _ done => done
  · refine Sends.bind' (Racing.broadcast_exact self _ _) fun _ _ _ => Sends.pure' ?_
    exact fun _ _ _ => ⟨rfl, fun notPre => absurd rfl notPre,
      fun _ => keeps_preVote self before⟩

/-- An election timeout's pre-vote requests carry the state it leaves. -/
theorem startElection_requests
    : Sends
        (fun after sent =>
          forall e,
            e ∈ sent
            -> forall request,
                e.payload = .requestPreVoteRequest request
                -> request = makeRequestVoteRequest after)
        (startElection caps before self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.mono (becomeCandidate_sends self _) fun _ sent done e member request eq => ?_
    simp only [List.nil_append] at member
    rcases done with ⟨_, requests⟩ | ⟨_, _, starts⟩
    · rw [(requests e member).2] at eq
      cases eq
    · rcases starts e member with (⟨_, payload⟩ | ⟨_, _, _, payload, _⟩) | ⟨_, payload⟩ <;>
        rw [payload] at eq <;> cases eq
  · refine Sends.bind' (Racing.broadcast_exact self _ _) fun _ sent eq =>
      Sends.pure' fun e member request payload => ?_
    simp only [List.nil_append, List.append_nil, eq] at member
    obtain ⟨_, _, rfl⟩ := Racing.mem_broadcast.mp member
    cases payload
    rfl

/-- A stale AppendEntries request changes nothing. -/
theorem staleRequest_receive (source : NodeID) (request : AppendEntriesRequest)
    (stale : request.term < before.currentTerm)
    : Sends (fun after _ => after = before)
        (receive caps self source before (.appendEntriesRequest request)) := by
  have observed : observeTerm before (.appendEntriesRequest request) = before := by
    simp [observeTerm, updateTerm, Message.term, Nat.not_lt.mpr stale.le]
  simp only [receive]
  refine Sends.ite' (fun no => by simp at no) fun _ => ?_
  rw [observed]
  simp only [handleAppendEntriesRequest, Nat.ne_of_lt stale, false_and, ite_false, stale,
    true_or, ite_true]
  exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' rfl

/-- An AppendEntries response leaves the state, adopts its term, or keeps a primary's
term. -/
theorem appendResponse_receive (source : NodeID) (response : AppendEntriesResponse)
    : Sends
        (fun after _ =>
          after = before
          \/ after = bumpedState before response.term
          \/ (before.role = .primary /\ after.currentTerm = before.currentTerm))
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (Or.inl rfl)) fun _ => ?_
  rcases observe_response before response with ⟨leader, bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · refine Sends.ite' (fun _ => Sends.pure' (Or.inr (Or.inl rfl))) fun notFollower =>
      absurd notFollower (by simp [bumpedState])
  · refine Sends.ite' (fun _ => Sends.pure' (Or.inl rfl)) fun leader => ?_
    simp only [bne_iff_ne, ne_eq, Decidable.not_not] at leader
    refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Or.inr (Or.inr ⟨leader, rfl⟩))
    refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Or.inl rfl)
    exact Sends.mono (advanceCommit_sends self _) fun _ _ ⟨advance, _⟩ =>
      Or.inr (Or.inr ⟨leader, advance.term⟩)

theorem observed_of (message : Message) (bumping : Bumping message)
    : Observed before message.term (observeTerm before message) := by
  rcases observe_bumping before bumping with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
  · exact Or.inr ⟨bump, rfl⟩
  · exact Or.inl rfl

theorem voteResponse_good (ready : Ready T before) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (fun after _ => Good T before after)
        (receive caps self source before (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (good_self ready)) fun _ => ?_
  have observed := observed_of (before := before) (.requestVoteResponse response) trivial
  generalize observeTerm before (.requestVoteResponse response) = middle at observed ⊢
  have good := good_observed ready observed
  simp only [handleRequestVoteResponse]
  refine Sends.ite' (fun _ => electIfQuorum_good self ?_) fun _ => Sends.pure' good
  exact good_mild good rfl rfl rfl rfl ⟨rfl, rfl, rfl⟩

theorem preVoteResponse_good (ready : Ready T before) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (fun after _ => Good T before after)
        (receive caps self source before (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (good_self ready)) fun _ => ?_
  have observed := observed_of (before := before) (.requestPreVoteResponse response) trivial
  generalize observeTerm before (.requestPreVoteResponse response) = middle at observed ⊢
  have good := good_observed ready observed
  simp only [handleRequestPreVoteResponse]
  refine Sends.ite' (fun cond => ?_) fun _ => Sends.pure' good
  have counted
      : Good T before
          { middle with preVotesGranted := insert source middle.preVotesGranted } := by
    intro term notPrimary notNone
    obtain ⟨known, _, kept⟩ := good term notPrimary notNone
    exact ⟨known, fun notPre => absurd cond.1 notPre, fun preT => kept preT⟩
  refine Sends.ite' (fun _ => becomeCandidate_good self ?_) fun _ => Sends.pure' counted
  exact observed.keeps

theorem propose_good (ready : Ready T before) (source : NodeID) (term : Nat)
    : Sends (fun after _ => Good T before after)
        (receive caps self source before (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite' (fun no => by simp at no) fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  exact Sends.ite' (fun _ => becomeCandidate_good self (Racing.Keeps.refl _))
    fun _ => Sends.pure' (good_self ready)

/-- A step of a node at most `T` keeps the frozen facts, given what the frozen round
knows of it and that no AppendEntries request of `T` reaches it. -/
theorem frozen_node {event : Model.Node.Event} {after : NodeState}
    {outputs : Outputs NodeID Message Notification} (ready : Ready T before)
    (le : before.currentTerm <= T)
    (noRequest
      : forall source request,
          event = .receive source (.appendEntriesRequest request) -> request.term < T)
    (ran : (Model.Node.step caps self before event).run {} = some (after, outputs))
    : Good T before after := by
  have sum := sends_run (summary self before event) ran
  cases event with
  | internal input =>
      by_cases election : input = .timeout .election
      · subst election
        exact sends_run (startElection_good self) ran
      · have primary := Racing.act_primary self election ran
        intro term
        exfalso
        have notT : Not (before.currentTerm = T) := fun eq => (ready eq).2.2 primary
        rcases Summary.term_cause sum with lePre | ⟨_, fresh⟩ | ⟨_, _, eq, _⟩
        · omega
        · rcases fresh with eq | ⟨_, _, eq, _⟩ | ⟨_, eq⟩
          · injection eq with eq
            exact election eq
          · cases eq
          · cases eq
        · cases eq
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          have stale := noRequest source request rfl
          intro term
          by_cases preT : before.currentTerm = T
          · have eq := sends_run (staleRequest_receive self source request (by omega)) ran
            subst eq
            exact good_self ready term
          · exfalso
            rcases Summary.term_cause sum with lePre | ⟨_, fresh⟩ | ⟨_, message, eq, termLe⟩
            · omega
            · rcases fresh with eq | ⟨_, _, eq, _⟩ | ⟨_, eq⟩ <;> cases eq
            · injection eq with _ eq
              subst eq
              simp only [Message.term] at termLe
              omega
      | appendEntriesResponse response =>
          by_cases primary : before.role = .primary
          · have notT : Not (before.currentTerm = T) := fun eq => (ready eq).2.2 primary
            rcases sends_run (appendResponse_receive self source response) ran with
              rfl | rfl | ⟨_, termEq⟩
            · exact fun term => absurd term notT
            · exact good_bumped _
            · exact fun term => absurd (termEq ▸ term) notT
          · obtain ⟨_, observed⟩ :=
              sends_run (Racing.inert_receive self source before (.appendEntriesResponse response) trivial
                primary) ran
            exact good_observed ready observed
      | requestVoteRequest request =>
          obtain ⟨middle, granted, observed, _, _, afterEq, _⟩ :=
            sends_run (Racing.voteRequest_receive self source before request) ran
          have good := good_observed ready observed
          subst afterEq
          split
          · exact good_mild good rfl rfl rfl rfl ⟨rfl, rfl, rfl⟩
          · exact good
      | requestVoteResponse response =>
          exact sends_run (voteResponse_good self ready source response) ran
      | requestPreVoteRequest request =>
          exact good_observed ready
            (sends_run (Racing.preVoteRequest_receive self source before request) ran).1
      | requestPreVoteResponse response =>
          exact sends_run (preVoteResponse_good self ready source response) ran
      | proposeRequestVoteRequest term =>
          exact sends_run (propose_good self ready source term) ran

end Node

/-! ## The frozen invariant -/

omit [HasLive W] [HasTimers W] [Config.InitialConfiguration] in
/-- What the frozen round keeps at every capped index: what each participant in
`term + 1` knows, and what is pending between participants. -/
structure Calm (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term index : Nat) (point : W)
    : Prop where
  nodes
    : forall node state,
        node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1
        -> state.primaryKnown = false
            /\ (Not (state.role = .preVoteCandidate) -> state.preVotesGranted = ∅)
            /\ Not (state.role = .none)
            /\ (state.role = .preVoteCandidate
                -> state.preVotesGranted ⊆ insert node (Grantors participants point state)
                    /\ exists earlier,
                        c <= earlier
                        /\ earlier < index
                        /\ TermTimeout trace term earlier node)
  packets
    : forall packet,
        packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> (forall request,
              packet.envelope.payload = .appendEntriesRequest request
              -> request.term <= term)
            /\ packet.envelope.payload ≠ .proposeRequestVoteRequest (term + 1)
            /\ (forall request,
                  packet.envelope.payload = .requestPreVoteRequest request
                  -> request.term = term + 1
                  -> (exists state,
                        nodeState (proto point) packet.envelope.source = some state
                        /\ request = makeRequestVoteRequest state)
                      /\ exists earlier,
                          c <= earlier
                          /\ earlier < index
                          /\ TermTimeout trace term earlier packet.envelope.source)
            /\ (packet.envelope.payload
                  = .requestPreVoteResponse { term := term + 1, voteGranted := true }
                -> (forall state,
                      nodeState (proto point) packet.envelope.target = some state
                      -> packet.envelope.source ∈ Grantors participants point state)
                    /\ exists earlier,
                        c <= earlier
                        /\ earlier < index
                        /\ TermTimeout trace term earlier packet.envelope.target)

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] in
/-- Grantors only grow when every voter keeps its log and the requester keeps its. -/
theorem grantors_mono {first second : W} {state state' : NodeState}
    (voters
      : forall voter,
          voter ∈ participants
          -> forall voterState,
              nodeState (proto first) voter = some voterState
              -> exists voterState',
                  nodeState (proto second) voter = some voterState'
                  /\ Keeps voterState voterState')
    (keeps : Keeps state state')
    : Grantors participants first state ⊆ Grantors participants second state' := by
  intro voter member
  simp only [Grantors, Finset.mem_filter] at member ⊢
  obtain ⟨voterIn, voterState, found, upToDate⟩ := member
  obtain ⟨voterState', found', kept⟩ := voters voter voterIn voterState found
  refine ⟨voterIn, voterState', found', ?_⟩
  rw [keeps.request]
  exact Racing.upToDate_term.mpr ((kept.upToDate _).mpr upToDate)

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] in
theorem grantors_congr {first second : W} (same : proto second = proto first)
    (state : NodeState)
    : Grantors participants second state = Grantors participants first state := by
  simp only [Grantors, same]

theorem request_keeps {state state' : NodeState} (keeps : Keeps state state')
    (term : state'.currentTerm = state.currentTerm)
    : makeRequestVoteRequest state' = makeRequestVoteRequest state := by
  rw [keeps.request, term]
  rfl

section Frozen

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup originFound noElection

/-- A step's actor that is in `term + 1` afterwards stays a non-primary that knows
no primary, and keeps its log if it was in `term + 1` before. -/
theorem RoundSetup.actor_good {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (bounded
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    (calm : Calm trace participants c term index step.before) {actor : NodeID}
    (actorIn : actor ∈ participants) {pre post : NodeState} {event : Model.Node.Event}
    {outputs : CCF.Outputs NodeID Message Notification}
    (preFound : nodeState (proto step.before) actor = some pre)
    (postFound : nodeState (proto step.after) actor = some post)
    (cause
      : (exists input, step.action = .local actor input /\ event = .internal input)
        \/ exists packet,
            step.action = .deliver packet
            /\ packet.envelope.target = actor
            /\ event = .receive packet.envelope.source packet.envelope.payload)
    (ran
      : (Model.Node.step (CCF.Capabilities.record actor) actor pre event).run {}
        = some (post, outputs))
    (postTerm : post.currentTerm = term + 1)
    : post.primaryKnown = false
      /\ (Not (post.role = .preVoteCandidate) -> post.preVotesGranted = ∅)
      /\ Not (post.role = .none)
      /\ Not (post.role = .primary)
      /\ (pre.currentTerm = term + 1 -> Keeps pre post) := by
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeLe := (setup.admissible.timing.next stepped).1
  have cappedBefore := capped.down le (Nat.le_succ index)
  have within := setup.inside originFound index step.before le beforeFound (by linarith)
  have withinAfter :=
    setup.inside originFound (index + 1) step.after (Nat.le_succ_of_le le) afterFound
      (by linarith)
  have ready : Ready (term + 1) pre := fun preTerm =>
    have known := calm.nodes actor pre actorIn preFound preTerm
    ⟨known.1, known.2.1,
      noElection index step.before actor pre cappedBefore beforeFound (by linarith) actorIn
        preFound preTerm⟩
  have noRequest
      : forall source request,
          event = .receive source (.appendEntriesRequest request)
          -> request.term < term + 1 := by
    intro source request eventEq
    obtain ⟨delivered, delivery, consumed, targetEq, _, payload⟩ :=
      setup.received stepped cause eventEq
    have targetIn : delivered.envelope.target ∈ participants := targetEq ▸ actorIn
    have sourceIn :=
      setup.period.isolated index step delivered.envelope within stepped
        (by simp [delivery, Liveness.Event.delivered]) targetIn
    have := (calm.packets delivered consumed sourceIn targetIn).1 request payload
    omega
  have good :=
    frozen_node actor ready
      (capped.2 index step.before actor pre le (Nat.le_succ index) beforeFound actorIn
        preFound)
      noRequest ran
  have notPrimary :=
    noElection (index + 1) step.after actor post capped afterFound (by linarith) actorIn
      postFound postTerm
  have notNone : Not (post.role = .none) := by
    intro isNone
    rcases Elected.ElectedStep.none (Racing.sends_run (Elected.electedStep actor pre event) ran)
        isNone with
      ⟨preNone, same⟩ | retired
    · exact (calm.nodes actor pre actorIn preFound (by omega)).2.2.1 preNone
    · exact setup.active (index + 1) step.after actor post withinAfter afterFound actorIn
        postFound retired
  obtain ⟨known, granted, keeps⟩ := good postTerm notPrimary notNone
  exact ⟨known, granted, notNone, notPrimary, keeps⟩

/-- A step keeps the log of every participant that is in `term + 1` on both sides. -/
theorem RoundSetup.step_pair {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (bounded
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    (calm : Calm trace participants c term index step.before) {node : NodeID}
    (member : node ∈ participants)
    : (forall state,
        nodeState (proto step.before) node = some state
        -> exists state',
            nodeState (proto step.after) node = some state'
            /\ (state.currentTerm = term + 1
                -> state'.currentTerm = term + 1
                -> Keeps state state'))
      /\ (forall state',
            nodeState (proto step.after) node = some state'
            -> exists state,
                nodeState (proto step.before) node = some state
                /\ (state.currentTerm = term + 1
                    -> state'.currentTerm = term + 1
                    -> Keeps state state')) := by
  rcases selected : step.action.action with _ | action
  · have same := setup.admissible.stutter stepped selected
    refine ⟨fun state found => ⟨state, by rw [same]; exact found,
        fun _ _ => Racing.Keeps.refl _⟩,
      fun state found => ⟨state, by rw [← same]; exact found,
        fun _ _ => Racing.Keeps.refl _⟩⟩
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, _⟩ :=
    setup.view stepped selected
  by_cases actorEq : node = actor
  · subst actorEq
    have keeps := fun preTerm postTerm =>
      (setup.actor_good originFound noElection le stepped capped bounded calm member preFound
        postFound cause ran postTerm).2.2.2.2 preTerm
    refine ⟨fun state found => ⟨post, postFound, ?_⟩, fun state found => ⟨pre, preFound, ?_⟩⟩
    · rw [preFound, Option.some.injEq] at found
      subst found
      exact keeps
    · rw [postFound, Option.some.injEq] at found
      subst found
      exact keeps
  · refine ⟨fun state found => ⟨state, by rw [others node actorEq]; exact found,
        fun _ _ => Racing.Keeps.refl _⟩,
      fun state found => ⟨state, by rw [← others node actorEq]; exact found,
        fun _ _ => Racing.Keeps.refl _⟩⟩

/-- Once every participant has adopted `term + 1`, a step keeps every participant's
log. -/
theorem RoundSetup.steady {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (bounded
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    (calm : Calm trace participants c term index step.before)
    (late : time origin + maxDelay < time step.before) {node : NodeID}
    (member : node ∈ participants)
    : (forall state,
        nodeState (proto step.before) node = some state
        -> exists state',
            nodeState (proto step.after) node = some state' /\ Keeps state state')
      /\ (forall state',
            nodeState (proto step.after) node = some state'
            -> exists state,
                nodeState (proto step.before) node = some state
                /\ Keeps state state') := by
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeLe := (setup.admissible.timing.next stepped).1
  have before :=
    setup.adopted (capped.down le (Nat.le_succ index)) originFound beforeFound late node
  have after := setup.adopted capped originFound afterFound (by linarith) node
  obtain ⟨forward, backward⟩ :=
    setup.step_pair originFound noElection le stepped capped bounded calm member
  refine ⟨fun state found => ?_, fun state' found => ?_⟩
  · obtain ⟨state', found', keeps⟩ := forward state found
    exact ⟨state', found', keeps (before state member found) (after state' member found')⟩
  · obtain ⟨state, found0, keeps⟩ := backward state' found
    exact ⟨state, found0, keeps (before state member found0) (after state' member found)⟩

/-- Once every participant has adopted `term + 1`, a step only grows the grantors of a
kept log. -/
theorem RoundSetup.transport {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (bounded
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    (calm : Calm trace participants c term index step.before)
    (late : time origin + maxDelay < time step.before) {state state' : NodeState}
    (keeps : Keeps state state')
    : Grantors participants step.before state ⊆ Grantors participants step.after state' :=
  grantors_mono
    (fun _ voterIn =>
      (setup.steady originFound noElection le stepped capped bounded calm late voterIn).1)
    keeps

/-- A timeout of `term + 1` in the round comes after every participant adopted it. -/
theorem RoundSetup.late_of {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {earlier : Nat} (first : c <= earlier)
    (last : earlier <= index) {node : NodeID} (member : node ∈ participants)
    (timeout : TermTimeout trace term earlier node)
    : time origin + maxDelay < time step.before := by
  obtain ⟨stepE, stateE, steppedE, action, foundE, termE⟩ := timeout
  have := setup.timeout_late originFound first steppedE member foundE termE action
  have := setup.admissible.time_le last (setup.admissible.before steppedE)
    (setup.admissible.before stepped)
  linarith [setup.ratio, setup.nonnegative]

/-- The participants' part of `Calm` survives a step. -/
theorem RoundSetup.calm_nodes {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (bounded
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    (calm : Calm trace participants c term index step.before)
    : forall node state,
        node ∈ participants
        -> nodeState (proto step.after) node = some state
        -> state.currentTerm = term + 1
        -> state.primaryKnown = false
            /\ (Not (state.role = .preVoteCandidate) -> state.preVotesGranted = ∅)
            /\ Not (state.role = .none)
            /\ (state.role = .preVoteCandidate
                -> state.preVotesGranted
                      ⊆ insert node (Grantors participants step.after state)
                    /\ exists earlier,
                        c <= earlier
                        /\ earlier < index + 1
                        /\ TermTimeout trace term earlier node) := by
  intro node state member found termEq
  have beforeFound := setup.admissible.before stepped
  have timeLe := (setup.admissible.timing.next stepped).1
  rcases selected : step.action.action with _ | action
  · have same := setup.admissible.stutter stepped selected
    rw [same] at found
    obtain ⟨known, granted, notNone, polling⟩ := calm.nodes node state member found termEq
    refine ⟨known, granted, notNone, fun candidate => ?_⟩
    obtain ⟨sub, earlier, first, last, timeout⟩ := polling candidate
    refine ⟨?_, earlier, first, by omega, timeout⟩
    rw [grantors_congr same]
    exact sub
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, _⟩ :=
    setup.view stepped selected
  by_cases actorEq : node = actor
  swap
  · rw [others node actorEq] at found
    obtain ⟨known, granted, notNone, polling⟩ := calm.nodes node state member found termEq
    refine ⟨known, granted, notNone, fun candidate => ?_⟩
    obtain ⟨sub, earlier, first, last, timeout⟩ := polling candidate
    have late := setup.late_of originFound noElection stepped first (by omega) member timeout
    exact ⟨sub.trans (Finset.insert_subset_insert _
        (setup.transport originFound noElection le stepped capped bounded calm late
          (Racing.Keeps.refl _))),
      earlier, first, by omega, timeout⟩
  subst actorEq
  rw [postFound, Option.some.injEq] at found
  subst found
  obtain ⟨known, granted, notNone, _, keeps⟩ :=
    setup.actor_good originFound noElection le stepped capped bounded calm member preFound
      postFound cause ran termEq
  refine ⟨known, granted, notNone, fun candidate => ?_⟩
  have sum := Racing.sends_run (Safety.summary node pre event) ran
  obtain ⟨sameTerm, preCause⟩ := Safety.Summary.pre_vote sum candidate
  have preTerm : pre.currentTerm = term + 1 := by omega
  have keeps := keeps preTerm
  have counts :=
    Leadership.AnchorStep.counts (Racing.sends_run (Leadership.anchorStep node pre event) ran)
  have witness
      : exists earlier,
          c <= earlier /\ earlier < index + 1 /\ TermTimeout trace term earlier node := by
    rcases preCause with prePolling | eventEq
    · obtain ⟨_, earlier, first, last, timeout⟩ :=
        (calm.nodes node pre member preFound preTerm).2.2.2 prePolling
      exact ⟨earlier, first, by omega, timeout⟩
    · exact ⟨index, le, by omega, step, pre, stepped, setup.local_of_event cause eventEq,
        preFound, preTerm⟩
  obtain ⟨earlier, first, last, timeout⟩ := witness
  have late := setup.late_of originFound noElection stepped first (by omega) member timeout
  have move :=
    setup.transport originFound noElection le stepped capped bounded calm late keeps
  refine ⟨fun voter counted => ?_, earlier, first, last, timeout⟩
  rcases counts voter counted with
    ⟨_, rfl⟩ | ⟨notTimeout, old⟩ | ⟨response, eventEq, responseTerm, responseGranted⟩
  · exact Finset.mem_insert_self _ _
  · have prePolling : pre.role = .preVoteCandidate := preCause.resolve_right notTimeout
    have sub := ((calm.nodes node pre member preFound preTerm).2.2.2 prePolling).1 old
    rcases Finset.mem_insert.mp sub with eq | grantor
    · exact Finset.mem_insert.mpr (Or.inl eq)
    · exact Finset.mem_insert_of_mem (move grantor)
  · obtain ⟨delivered, delivery, consumed, targetEq, sourceEq, payload⟩ :=
      setup.received stepped cause eventEq
    have within := setup.inside originFound index step.before le beforeFound (by linarith)
    have targetIn : delivered.envelope.target ∈ participants := by rw [targetEq]; exact member
    have sourceIn :=
      setup.period.isolated index step delivered.envelope within stepped
        (by simp [delivery, Liveness.Event.delivered]) targetIn
    have grant
        : delivered.envelope.payload
          = .requestPreVoteResponse { term := term + 1, voteGranted := true } := by
      rw [payload]
      obtain ⟨t, g⟩ := response
      simp only at responseTerm responseGranted
      rw [responseTerm, responseGranted, preTerm]
    have grantor :=
      ((calm.packets delivered consumed sourceIn targetIn).2.2.2 grant).1 pre
        (by rw [targetEq]; exact preFound)
    rw [sourceEq] at grantor
    exact Finset.mem_insert_of_mem (move grantor)

/-- `Calm` survives a step of the round. -/
theorem RoundSetup.calm_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (bounded
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    (calm : Calm trace participants c term index step.before)
    : Calm trace participants c term (index + 1) step.after := by
  refine ⟨setup.calm_nodes originFound noElection le stepped capped bounded calm,
    fun packet member sourceIn targetIn => ?_⟩
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeLe := (setup.admissible.timing.next stepped).1
  have cappedBefore := capped.down le (Nat.le_succ index)
  have within := setup.inside originFound index step.before le beforeFound (by linarith)
  have withinAfter :=
    setup.inside originFound (index + 1) step.after (Nat.le_succ_of_le le) afterFound
      (by linarith)
  rcases selected : step.action.action with _ | action
  · have same := setup.admissible.stutter stepped selected
    obtain ⟨requests, proposals, polls, grants⟩ :=
      calm.packets packet (setup.pending_env stepped selected member) sourceIn targetIn
    refine ⟨requests, proposals, fun request payload termEq => ?_, fun payload => ?_⟩
    · obtain ⟨⟨state, found, eq⟩, earlier, first, last, timeout⟩ :=
        polls request payload termEq
      exact ⟨⟨state, by rw [same]; exact found, eq⟩, earlier, first, by omega, timeout⟩
    · obtain ⟨grant, earlier, first, last, timeout⟩ := grants payload
      refine ⟨fun state found => ?_, earlier, first, by omega, timeout⟩
      rw [grantors_congr same]
      exact grant state (by rw [← same]; exact found)
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, ledger⟩ :=
    setup.view stepped selected
  rcases Racing.pending_after_cases ledger member with old | ⟨new, _⟩
  · obtain ⟨requests, proposals, polls, grants⟩ := calm.packets packet old sourceIn targetIn
    refine ⟨requests, proposals, fun request payload termEq => ?_, fun payload => ?_⟩
    · obtain ⟨⟨state, found, eq⟩, earlier, first, last, timeout⟩ :=
        polls request payload termEq
      have late := setup.late_of originFound noElection stepped first (by omega) sourceIn timeout
      obtain ⟨state', found', keeps⟩ :=
        (setup.steady originFound noElection le stepped capped bounded calm late sourceIn).1
          state found
      have termBefore :=
        setup.adopted cappedBefore originFound beforeFound late _ state sourceIn found
      have termAfter :=
        setup.adopted capped originFound afterFound (by linarith) _ state' sourceIn found'
      refine ⟨⟨state', found', ?_⟩, earlier, first, by omega, timeout⟩
      rw [request_keeps keeps (by omega), eq]
    · obtain ⟨grant, earlier, first, last, timeout⟩ := grants payload
      have late := setup.late_of originFound noElection stepped first (by omega) targetIn timeout
      refine ⟨fun state' found' => ?_, earlier, first, by omega, timeout⟩
      obtain ⟨state, found, keeps⟩ :=
        (setup.steady originFound noElection le stepped capped bounded calm late targetIn).2
          state' found'
      exact setup.transport originFound noElection le stepped capped bounded calm late keeps
        (grant state found)
  have sum := Racing.sends_run (Safety.summary actor pre event) ran
  have actorEq : packet.envelope.source = actor := (Safety.Summary.sends sum _ new).1
  have actorIn : actor ∈ participants := actorEq ▸ sourceIn
  have send := Racing.sends_run (round_sends actor pre event) ran _ new
  refine ⟨fun request payload => ?_, fun payload => ?_, fun request payload termEq => ?_,
    fun payload => ?_⟩
  · have ok := (Safety.Summary.sends sum _ new).2
    simp only [payload] at ok
    obtain ⟨requestOk, _, sender⟩ := ok
    have postLe :=
      capped.2 (index + 1) step.after actor post (Nat.le_succ_of_le le) le_rfl afterFound
        actorIn postFound
    have requestTerm := requestOk.2.1
    by_contra high
    have postTerm : post.currentTerm = term + 1 := by omega
    obtain ⟨_, _, notNone, notPrimary, _⟩ :=
      setup.actor_good originFound noElection le stepped capped bounded calm actorIn preFound
        postFound cause ran postTerm
    rcases sender with ⟨prePrimary, same⟩ | ⟨candidate, _, _, advance⟩
    · exact noElection index step.before actor pre cappedBefore beforeFound (by linarith)
        actorIn preFound (by omega) prePrimary
    · rcases Safety.Advance.role advance with role | role
      · exact notPrimary (by rw [role]; simp [primaryState])
      · exact notNone role
  · rcases send.2.2 _ payload with eventEq | retired
    · exact setup.period.noNominations index step actor within stepped
        (setup.local_of_event cause eventEq)
    · exact setup.active (index + 1) step.after actor post withinAfter afterFound actorIn
        postFound retired
  · obtain ⟨eventEq, requestTerm⟩ := send.1 request payload
    have preTerm : pre.currentTerm = term + 1 := by omega
    have action := setup.local_of_event cause eventEq
    subst eventEq
    have eq :=
      Racing.sends_run (startElection_requests actor (before := pre)) ran _ new request
        payload
    refine ⟨⟨post, by rw [actorEq]; exact postFound, eq⟩, index, le, by omega, ?_⟩
    rw [actorEq]
    exact ⟨step, pre, stepped, action, preFound, preTerm⟩
  · obtain ⟨request, eventEq, requestTerm⟩ := send.2.1 _ payload rfl
    simp only at requestTerm
    obtain ⟨delivered, delivery, consumed, targetEq, sourceEq, deliveredPayload⟩ :=
      setup.received stepped cause eventEq
    have deliveredTarget : delivered.envelope.target ∈ participants := by
      rw [targetEq]; exact actorIn
    have deliveredSource : delivered.envelope.source ∈ participants := by
      rw [sourceEq]; exact targetIn
    obtain ⟨⟨state, found, requestEq⟩, earlier, first, last, timeout⟩ :=
      (calm.packets delivered consumed deliveredSource deliveredTarget).2.2.1 request
        deliveredPayload requestTerm
    rw [sourceEq] at found timeout
    have late := setup.late_of originFound noElection stepped first (by omega) targetIn timeout
    refine ⟨fun state' found' => ?_, earlier, first, by omega, timeout⟩
    obtain ⟨state0, found0, keeps⟩ :=
      (setup.steady originFound noElection le stepped capped bounded calm late targetIn).2
        state' found'
    rw [found, Option.some.injEq] at found0
    subst found0
    have termBefore :=
      setup.adopted cappedBefore originFound beforeFound late _ state targetIn found
    have termAfter :=
      setup.adopted capped originFound afterFound (by linarith) _ state' targetIn found'
    rw [eventEq] at ran
    obtain ⟨_, _, sent⟩ :=
      Racing.sends_run
        (Racing.preVoteRequest_receive actor packet.envelope.target pre request) ran
    rw [sent, List.mem_singleton] at new
    rw [new] at payload
    simp at payload
    rw [actorEq]
    simp only [Grantors, Finset.mem_filter]
    refine ⟨actorIn, post, postFound, ?_⟩
    rw [request_keeps keeps (by omega), ← requestEq]
    exact payload.2.2.1

theorem RoundSetup.calm_base : Calm trace participants c term c origin := by
  refine ⟨fun node state member found termEq => ?_,
    fun packet member sourceIn targetIn => ?_⟩
  · have := setup.round.low origin node state originFound member found
    omega
  · have low := setup.round.messages origin packet originFound member sourceIn targetIn
    refine ⟨fun request payload => ?_, fun payload => ?_, fun request payload termEq => ?_,
      fun payload => ?_⟩ <;> rw [payload] at low <;> simp [Message.term] at low
    · exact low
    · omega

/-- `Calm` holds at every capped index of the round. -/
theorem RoundSetup.calm_from
    : forall index point,
        Capped trace participants c term index
        -> trace.stateAt index = some point
        -> time point <= time origin + roundLength electionTimeout maxDelay + jump
        -> Calm trace participants c term index point := by
  intro index
  induction index with
  | zero =>
      intro point capped found _
      have : c = 0 := by have := capped.1; omega
      subst this
      rw [originFound, Option.some.injEq] at found
      subst found
      exact setup.calm_base originFound noElection
  | succ index ih =>
      intro point capped found bounded
      by_cases atStart : c = index + 1
      · subst atStart
        rw [originFound, Option.some.injEq] at found
        subst found
        exact setup.calm_base originFound noElection
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have le : c <= index := by have := capped.1; omega
      have beforeFound := setup.admissible.before stepped
      have timeLe := (setup.admissible.timing.next stepped).1
      have calm :=
        ih step.before (capped.down le (Nat.le_succ index)) beforeFound (by linarith)
      exact setup.calm_step originFound noElection le stepped capped bounded calm

/-- The good period restricted to the round. -/
theorem RoundSetup.good_round
    : GoodPeriod trace c (roundLength electionTimeout maxDelay + jump) participants := by
  have inside : forall index,
      Within trace c (roundLength electionTimeout maxDelay + jump) index
      -> Within trace start duration index := by
    intro index bounded
    refine ⟨setup.startLe.trans bounded.1, ?_⟩
    intro first last firstFound lastFound
    exact (setup.inside originFound index last bounded.1 lastFound
      (bounded.2 origin last originFound lastFound)).2 first last firstFound lastFound
  exact {
    participantsLive := fun i p n w => setup.period.participantsLive i p n (inside i w)
    quorum := fun i p n s w => setup.period.quorum i p n s (inside i w)
    noReconfiguration := fun i s n es w =>
      setup.period.noReconfiguration i s n es (inside i w)
    noNominations := fun i s n w => setup.period.noNominations i s n (inside i w)
    noQuorumChecks := fun i s n w => setup.period.noQuorumChecks i s n (inside i w)
    lossless := fun i s p w => setup.period.lossless i s p (inside i w)
    isolated := fun i s e w => setup.period.isolated i s e (inside i w)
  }

/-- A participant with a role other than primary or none may campaign within the
round. -/
theorem RoundSetup.can_start {index : Nat} {point : W} (le : c <= index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants) {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    (notNone : Not (state.role = .none)) (notPrimary : Not (state.role = .primary))
    : canStartElection state node := by
  have mem := Concrete.mem_of_nodeState nodeFound
  have within := setup.inside originFound index point le found (by linarith)
  have committed := Leadership.committed_later setup.admissible (start := c)
    (fun first state found nodeFound =>
      Leadership.committed_iff.mp
        (setup.configured first found node state (Concrete.mem_of_nodeState nodeFound)
          member))
    le found nodeFound
  have frontier :=
    Direct.commitFrontier_invariant.reachable (setup.admissible.reachable found) node state
      mem
  have membership :=
    Leadership.Membership.window setup.admissible
      (setup.good_round originFound noElection) setup.membership index point
      ⟨le, fun first last firstFound lastFound => by
        rw [originFound, Option.some.injEq] at firstFound
        rw [found, Option.some.injEq] at lastFound
        subst first last
        linarith⟩
      found
  refine ⟨
    ?_,
    Or.inl ?_,
    setup.active index point node state within found member nodeFound
  ⟩
  · cases h : state.role with
    | none => exact (notNone h).elim
    | primary => exact (notPrimary h).elim
    | follower => exact Or.inl rfl
    | preVoteCandidate => exact Or.inr (Or.inl rfl)
    | candidate => exact Or.inr (Or.inr rfl)
  · exact Leadership.member_signed membership mem member (setup.subset member) frontier
      committed

/-- An index later than one delay into the round is at or after its start. -/
theorem RoundSetup.start_le {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {slack : Real} (nonneg : 0 <= slack)
    (late : time origin + slack < time point)
    : c <= index := by
  by_contra lt
  have := setup.admissible.time_le (Nat.le_of_not_le lt) found originFound
  linarith

/-- A leaderless round is frozen from one delay after its start. -/
theorem RoundSetup.frozen {index : Nat} {point : W}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (late : time origin + maxDelay < time point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    : Frozen trace participants c term index point := by
  have calm := setup.calm_from originFound noElection index point capped found timeLe
  have adopted := setup.adopted capped originFound found late
  refine ⟨fun node state member nodeFound => ?_, fun node state member nodeFound => ?_,
    calm.packets⟩
  · have termEq := adopted node state member nodeFound
    obtain ⟨known, _, notNone, _⟩ := calm.nodes node state member nodeFound termEq
    exact ⟨termEq, known,
      setup.can_start originFound noElection capped.1 found timeLe member nodeFound notNone
        (noElection index point node state capped found (by linarith) member nodeFound
          termEq)⟩
  · have termEq := adopted node state member nodeFound
    obtain ⟨_, granted, _, polling⟩ := calm.nodes node state member nodeFound termEq
    by_cases candidate : state.role = .preVoteCandidate
    · exact ⟨(polling candidate).1, fun _ => (polling candidate).2⟩
    · rw [granted candidate]
      exact ⟨Finset.empty_subset _, fun h => absurd h candidate⟩

/-- A leaderless round keeps every participant's log, commit index and retirement
from one delay after its start. -/
theorem RoundSetup.frozen_keeps {index later : Nat} {point laterPoint : W}
    (capped : Capped trace participants c term later) (le : index <= later)
    (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint)
    (late : time origin + maxDelay < time point)
    (timeLe
      : time laterPoint <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants) {state laterState : NodeState}
    (stateFound : nodeState (proto point) node = some state)
    (laterStateFound : nodeState (proto laterPoint) node = some laterState)
    : Keeps state laterState := by
  have first := setup.start_le originFound noElection found setup.nonnegative late
  have claim
      : forall k laterPoint laterState,
          Capped trace participants c term (index + k)
          -> trace.stateAt (index + k) = some laterPoint
          -> time laterPoint <= time origin + roundLength electionTimeout maxDelay + jump
          -> nodeState (proto laterPoint) node = some laterState
          -> Keeps state laterState := by
    intro k
    induction k with
    | zero =>
        intro laterPoint laterState _ laterFound _ laterStateFound
        rw [Nat.add_zero, found, Option.some.injEq] at laterFound
        subst laterFound
        rw [stateFound, Option.some.injEq] at laterStateFound
        subst laterStateFound
        exact Racing.Keeps.refl _
    | succ k ih =>
        intro laterPoint laterState capped laterFound timeLe laterStateFound
        obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
        have beforeFound := setup.admissible.before stepped
        have timeLe' := (setup.admissible.timing.next stepped).1
        have earlier := setup.admissible.time_le (Nat.le_add_right index k) found beforeFound
        have cappedBefore :=
          capped.down (first.trans (Nat.le_add_right index k)) (Nat.le_succ _)
        have calm :=
          setup.calm_from originFound noElection (index + k) step.before cappedBefore
            beforeFound (by linarith)
        obtain ⟨middle, middleFound, keeps⟩ :=
          (setup.steady originFound noElection (first.trans (Nat.le_add_right index k))
            stepped capped timeLe calm (by linarith) member).2 laterState laterStateFound
        exact (ih step.before middle cappedBefore beforeFound (by linarith)
                middleFound).trans
          keeps
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le le
  exact claim k laterPoint laterState capped laterFound timeLe laterStateFound

/-- From two delays after the start of a leaderless round, only a participant's own
timeouts reset its timer, until the step that ends the round. -/
theorem RoundSetup.reset_late {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (capped : Capped trace participants c term (index + 1))
    (stepped : trace.stepAt index = some step)
    (late : time origin + 2 * maxDelay < time step.before)
    (timeLe
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants) (reset : ElectionReset step node)
    : TermTimeout trace term index node := by
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeLe' := (setup.admissible.timing.next stepped).1
  have le := setup.start_le originFound noElection beforeFound
    (by linarith [setup.nonnegative] : (0 : Real) <= 2 * maxDelay) late
  have cappedBefore := capped.down le (Nat.le_succ index)
  have within := setup.inside originFound index step.before le beforeFound (by linarith)
  have adopted :=
    setup.adopted cappedBefore originFound beforeFound (by linarith [setup.nonnegative])
  unfold ElectionReset at reset
  split at reset
  · rename_i timedOut kind action
    rw [reset] at action
    clear reset timedOut
    have selected : step.action.action = some (.local node (.timeout kind)) := by
      rw [action]
      rfl
    obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, _⟩ :=
      setup.view stepped selected
    rcases cause with ⟨input, actionEq, eventEq⟩ | ⟨packet, actionEq, _⟩
    · rw [action] at actionEq
      injection actionEq with nodeEq inputEq
      subst nodeEq inputEq eventEq
      have preTerm := adopted node pre member preFound
      cases kind with
      | election => exact ⟨step, pre, stepped, action, preFound, preTerm⟩
      | checkQuorum =>
          have primary := Racing.act_primary node
            (show Input.timeout .checkQuorum ≠ Input.timeout .election by simp) ran
          exact absurd primary
            (noElection index step.before node pre cappedBefore beforeFound (by linarith)
              member preFound preTerm)
    · rw [action] at actionEq
      cases actionEq
  · rename_i packet action
    obtain ⟨targetEq, reset⟩ := reset
    have consumed : packet ∈ pending step.before :=
      setup.admissible.consumed_pending stepped
        (by simp [action, Liveness.Event.consumedPacket])
    have targetIn : packet.envelope.target ∈ participants := by rw [targetEq]; exact member
    have sourceIn :=
      setup.period.isolated index step packet.envelope within stepped
        (by simp [action, Liveness.Event.delivered]) targetIn
    split at reset
    · exact reset.elim
    rename_i state stateFound
    have termEq := adopted node state member stateFound
    rcases reset with raised | received
    · split at raised
      · rename_i after afterStateFound
        have := capped.2 (index + 1) step.after node after (Nat.le_succ_of_le le) le_rfl
          afterFound member afterStateFound
        omega
      · exact raised.elim
    · have calm :=
        setup.calm_from originFound noElection index step.before cappedBefore beforeFound
          (by linarith)
      split at received
      · rename_i request payload
        have := (calm.packets packet consumed sourceIn targetIn).1 request payload
        omega
      · rename_i request payload
        have sentLe :=
          (setup.packets cappedBefore originFound beforeFound consumed sourceIn
            targetIn).2.2.1 request payload
        have alive :=
          setup.period.participantsLive index step.before packet.envelope.target within
            beforeFound targetIn
        have := setup.delay_at beforeFound consumed alive
        linarith
      · exact received.elim
  · exact reset.elim

end Frozen

end CCFRaft.Proofs.Duel.Round
