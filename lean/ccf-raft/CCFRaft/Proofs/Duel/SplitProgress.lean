module

public import CCFRaft.Proofs.Duel.SplitFrozen
public import CCFRaft.Proofs.Leadership.ConfiguredWindow
public import CCFRaft.Proofs.Leadership.FirstReset

@[expose] public section

/-!
# The leaderless round: progress

NOT IMPORTED BY `Properties`. In a leaderless round a participant that can gather a
pre-vote quorum and times out raises the next round within two delays: its requests
arrive within one delay, every participant its log covers grants, and the grants
arrive within another. A participant with a longest log can gather one, and its
timer fires within an election timeout of its last reset, so a leaderless round ends
within a round length plus the overshoot.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open HasLive (live)
open HasNetwork (pending)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Duel.Racing (Keeps Progress)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-- The candidacy a pre-vote quorum starts moves its node one term up. -/
theorem candidacy_term {self : NodeID} {state after : NodeState}
    {sent : List Model.Envelope} (candidacy : Racing.Candidacy self state after sent)
    (below : forall entry, entry ∈ state.log -> entry.term <= state.currentTerm)
    : after.currentTerm = state.currentTerm + 1 := by
  obtain ⟨won, elect, _⟩ := candidacy
  unfold Racing.Elect at elect
  split at elect
  · obtain ⟨_, termEq, _⟩ := elect (fun entry member => by
      have := below entry member
      simp only [freshCandidate]
      omega)
    rw [termEq]
    rfl
  · rw [elect.1]
    rfl

omit [HasTime W] [HasLive W] in
/-- `node`, which timed out at time `sent` from `initial`, still polls for pre-votes:
it has not reached a quorum, and every grantor other than itself has granted, or the
request or the grant is in flight. -/
def Polling (point : W) (node : NodeID) (initial : NodeState) (grantors : Finset NodeID)
    (term : Nat) (sent electionTimeout maxDelay : Real)
    : Prop :=
  sent + electionTimeout / 2 <= deadline point node
  /\ exists state,
      nodeState (proto point) node = some state
      /\ state.role = .preVoteCandidate
      /\ state.currentTerm = term + 1
      /\ Keeps initial state
      /\ node ∈ state.preVotesGranted
      /\ Not (hasQuorum state.activeConfigurations state.preVotesGranted)
      /\ forall voter,
          voter ∈ grantors
          -> voter ≠ node
          -> Progress point node voter state.preVotesGranted
              (.requestPreVoteRequest (makeRequestVoteRequest initial))
              (.requestPreVoteResponse { term := term + 1, voteGranted := true }) sent
              maxDelay

omit [HasLive W] [HasNetwork W] [HasTimers W] in
/-- `node` times out at `timeoutPoint` from `initial` in `term + 1`, late enough in the
round and two delays before `bound`, and can gather a pre-vote quorum of grantors. -/
structure PollStart (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term : Nat) (origin : W) (bound electionTimeout maxDelay : Real) (node : NodeID)
    (timeoutIndex : Nat) (timeoutPoint : W) (initial : NodeState)
    : Prop where
  le : c <= timeoutIndex
  found : trace.stateAt timeoutIndex = some timeoutPoint
  member : node ∈ participants
  initialFound : nodeState (proto timeoutPoint) node = some initial
  initialTerm : initial.currentTerm = term + 1
  late : time origin + electionTimeout / 2 <= time timeoutPoint
  timeLe : time timeoutPoint + 2 * maxDelay <= time origin + bound
  quorum
    : hasQuorum initial.activeConfigurations
        (insert node (Grantors participants timeoutPoint initial))

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
theorem grantor_mem {participants : Finset NodeID} {point : W} {state : NodeState}
    {voter : NodeID} (grantor : voter ∈ Grantors participants point state)
    : voter ∈ participants
      /\ exists voterState,
          nodeState (proto point) voter = some voterState
          /\ voteLogUpToDate voterState (makeRequestVoteRequest state) := by
  unfold Grantors at grantor
  exact Finset.mem_filter.mp grantor

section Progress

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup originFound noElection

/-- The good period, restricted to the round. -/
theorem RoundSetup.round_good
    : GoodPeriod trace c (roundLength electionTimeout maxDelay + jump) participants := by
  have inside := setup.inside originFound
  have sub : forall index,
      Within trace c (roundLength electionTimeout maxDelay + jump) index
      -> Within trace start duration index := by
    intro index bounded
    refine ⟨le_trans setup.startLe bounded.1, fun first last firstFound lastFound => ?_⟩
    exact (inside index last bounded.1 lastFound
      (by linarith [bounded.2 origin last originFound lastFound])).2 first last firstFound
      lastFound
  exact {
    participantsLive := fun i p n w => setup.period.participantsLive i p n (sub i w)
    quorum := fun i p n s w => setup.period.quorum i p n s (sub i w)
    noReconfiguration := fun i s n es w =>
      setup.period.noReconfiguration i s n es (sub i w)
    noNominations := fun i s n w => setup.period.noNominations i s n (sub i w)
    noQuorumChecks := fun i s n w => setup.period.noQuorumChecks i s n (sub i w)
    lossless := fun i s p w => setup.period.lossless i s p (sub i w)
    isolated := fun i s e w => setup.period.isolated i s e (sub i w)
  }

/-- The membership is fixed throughout the round. -/
theorem RoundSetup.round_membership {index : Nat} {point : W} (le : c <= index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    : Liveness.Membership participants members (proto point) := by
  apply Leadership.Membership.window setup.admissible
    (setup.round_good originFound noElection) setup.membership index point ?_ found
  refine ⟨le, fun first last firstFound lastFound => ?_⟩
  rw [originFound, Option.some.injEq] at firstFound
  rw [found, Option.some.injEq] at lastFound
  subst first last
  linarith

/-- A grantor receiving a polling participant's request grants it, within a delay of
the request. -/
theorem RoundSetup.poll_grant {timeoutIndex index : Nat} {timeoutPoint : W}
    {step : CCF.Execution.Step W Liveness.Event}
    (timeoutFound : trace.stateAt timeoutIndex = some timeoutPoint)
    (timeoutLate : time origin + electionTimeout / 2 <= time timeoutPoint)
    (timeLe
      : time timeoutPoint + 2 * maxDelay
        <= time origin + roundLength electionTimeout maxDelay + jump)
    (le : timeoutIndex <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term index)
    (timeBefore : time step.before <= time timeoutPoint + 2 * maxDelay)
    {node voter : NodeID} {initial voterInitial : NodeState}
    (initialTerm : initial.currentTerm = term + 1) (voterIn : voter ∈ participants)
    (voterFound : nodeState (proto timeoutPoint) voter = some voterInitial)
    (upToDate : voteLogUpToDate voterInitial (makeRequestVoteRequest initial))
    {packet : Packet} (event : step.action = .deliver packet)
    (envEq
      : packet.envelope
        = ⟨node, voter, .requestPreVoteRequest (makeRequestVoteRequest initial)⟩)
    (sentEq : packet.sentAt = time timeoutPoint)
    : exists response,
        response ∈ pending step.after
        /\ response.envelope
            = ⟨
              voter,
              node,
              .requestPreVoteResponse { term := term + 1, voteGranted := true }
            ⟩
        /\ response.sentAt <= time timeoutPoint + maxDelay := by
  have beforeFound := setup.admissible.before stepped
  have selected : step.action.action = some (.deliver packet.envelope) := by
    simp [event, Liveness.Event.action]
  obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
    Racing.protocol_view setup.admissible stepped selected
  rcases ran with ⟨input, eq, _⟩ | ⟨delivered, eq, targetEq, ran⟩
  · rw [event] at eq
    cases eq
  rw [event, Liveness.Event.deliver.injEq] at eq
  subst eq targetEq
  have member : packet ∈ pending step.before :=
    setup.admissible.consumed_pending stepped (by simp [event, Liveness.Event.consumedPacket])
  have alive : packet.envelope.target ∈ live step.before :=
    setup.admissible.actor_live stepped (by simp [event, Liveness.Event.actor])
  have delayLe := setup.delay_at beforeFound member alive
  rw [envEq] at preFound ran
  have timeoutLe := setup.admissible.time_le le timeoutFound beforeFound
  have late : time origin + maxDelay < time timeoutPoint := by
    linarith [setup.nonnegative, setup.ratio]
  have frozen :=
    setup.frozen originFound noElection capped beforeFound (by linarith) (by linarith)
  obtain ⟨preTerm, preKnown, _⟩ := frozen.nodes voter pre voterIn preFound
  have keeps :=
    setup.frozen_keeps originFound noElection capped le timeoutFound beforeFound late
      (by linarith) voterIn voterFound preFound
  obtain ⟨observed, _, sentOut⟩ :=
    Racing.sends_run (Racing.preVoteRequest_receive voter node pre _) ran
  have postEq : post = pre := by
    rcases observed with rfl | ⟨lt, _⟩
    · rfl
    · simp only [makeRequestVoteRequest] at lt
      omega
  subst postEq
  have sent
      : (⟨voter, node, .requestPreVoteResponse { term := term + 1, voteGranted := true }⟩
          : Model.Envelope)
        ∈ outputs.outgoing := by
    have covered := (keeps.upToDate _).mpr upToDate
    rw [sentOut, List.mem_singleton]
    simp only [covered, preKnown, preTerm]
    simp [makeRequestVoteRequest, initialTerm]
  obtain ⟨response, pend, envOut, sentAtOut⟩ := Racing.pending_of_sent ledger sent
  exact ⟨response, pend, envOut, by rw [sentAtOut]; linarith⟩

/-- Every log entry is at most its node's term. -/
theorem RoundSetup.log_below {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    : forall entry, entry ∈ state.log -> entry.term <= state.currentTerm := by
  obtain ⟨rest, exec⟩ := history_at setup.admissible found
  exact (good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)).terms node state
    (now_of_found nodeFound)

/-- The participants other than a polling node are among its active members. -/
theorem RoundSetup.poll_members {node : NodeID} {timeoutIndex : Nat} {timeoutPoint : W}
    {initial : NodeState}
    (poll
      : PollStart trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) electionTimeout maxDelay node
          timeoutIndex timeoutPoint initial)
    {voter : NodeID} (voterIn : voter ∈ participants) (ne : voter ≠ node)
    : voter ∈ initial.activeMembers.erase node /\ voter ∈ eligiblePeers initial node := by
  have membership :=
    setup.round_membership originFound noElection poll.le poll.found
      (by linarith [poll.timeLe, setup.nonnegative])
  rcases membership.activeMembers (Concrete.mem_of_nodeState poll.initialFound) poll.member
    with empty | same
  · exact absurd empty poll.quorum.1
  have active : voter ∈ initial.activeMembers := by
    rw [same]
    exact setup.subset voterIn
  refine ⟨Finset.mem_erase.mpr ⟨ne, active⟩, ?_⟩
  unfold eligiblePeers
  exact Finset.mem_erase.mpr ⟨ne, Finset.mem_union_left _ active⟩

/-- A voter's progress survives a step that delivers neither tracked packet. -/
theorem RoundSetup.progress_step {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) {node voter : NodeID}
    (nodeIn : node ∈ participants) (voterIn : voter ∈ participants)
    {granted granted' : Finset NodeID} {request response : Message} {sent : Real}
    (progress : Progress step.before node voter granted request response sent maxDelay)
    (sub : granted ⊆ granted')
    (onRequest
      : forall packet,
          step.action = .deliver packet
          -> packet.envelope = ⟨node, voter, request⟩
          -> packet.sentAt = sent
          -> Progress step.after node voter granted' request response sent maxDelay)
    (onResponse
      : forall packet,
          step.action = .deliver packet
          -> packet.envelope = ⟨voter, node, response⟩
          -> voter ∈ granted')
    : Progress step.after node voter granted' request response sent maxDelay := by
  rcases progress with member | ⟨packet, pend, ⟨envEq, sentEq⟩ | ⟨envEq, sentLe⟩⟩
  · exact Or.inl (sub member)
  · by_cases delivered : step.action = .deliver packet
    · exact onRequest packet delivered envEq sentEq
    · exact Or.inr ⟨packet,
        setup.kept within stepped pend (by simp [envEq, nodeIn]) (by simp [envEq, voterIn])
          delivered,
        Or.inl ⟨envEq, sentEq⟩⟩
  · by_cases delivered : step.action = .deliver packet
    · exact Or.inl (onResponse packet delivered envEq)
    · exact Or.inr ⟨packet,
        setup.kept within stepped pend (by simp [envEq, voterIn]) (by simp [envEq, nodeIn])
          delivered,
        Or.inr ⟨envEq, sentLe⟩⟩

/-- A node still polling after a step that starts within two delays of its timeout
is still within two delays of it. -/
theorem RoundSetup.poll_time {node : NodeID} {timeoutIndex : Nat} {timeoutPoint : W}
    {initial : NodeState}
    (poll
      : PollStart trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) electionTimeout maxDelay node
          timeoutIndex timeoutPoint initial)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : timeoutIndex <= index) (stepped : trace.stepAt index = some step)
    (timeBefore : time step.before <= time timeoutPoint + 2 * maxDelay)
    (polling
      : Polling step.after node initial (Grantors participants timeoutPoint initial) term
          (time timeoutPoint) electionTimeout maxDelay)
    : time step.after <= time timeoutPoint + 2 * maxDelay := by
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have within :=
    setup.inside originFound index step.before (le_trans poll.le le) beforeFound
      (by linarith [poll.timeLe])
  obtain ⟨_, state, _, _, _, keeps, selfIn, noQuorum, progress⟩ := polling
  by_contra beyond
  push Not at beyond
  apply noQuorum
  have quorum := poll.quorum
  rw [← keeps.configurations] at quorum
  refine hasQuorum_mono quorum fun voter voterIn => ?_
  rcases Finset.mem_insert.mp voterIn with rfl | grantor
  · exact selfIn
  by_cases ne : voter = node
  · subst ne
    exact selfIn
  have voterPart := (grantor_mem grantor).1
  rcases progress voter grantor ne with
    granted | ⟨packet, pend, ⟨envEq, sentEq⟩ | ⟨envEq, sentLe⟩⟩
  · exact granted
  · have alive : packet.envelope.target ∈ live step.after := by
      rw [envEq]
      exact setup.stays_live within stepped voterPart
    have := setup.delay_at afterFound pend alive
    linarith [setup.nonnegative]
  · have alive : packet.envelope.target ∈ live step.after := by
      rw [envEq]
      exact setup.stays_live within stepped poll.member
    have := setup.delay_at afterFound pend alive
    linarith

/-- The timeout starts the polling. -/
theorem RoundSetup.poll_start {node : NodeID} {timeoutIndex : Nat} {timeoutPoint : W}
    {initial : NodeState}
    (poll
      : PollStart trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) electionTimeout maxDelay node
          timeoutIndex timeoutPoint initial)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt timeoutIndex = some step)
    (event : step.action = .local node (.timeout .election))
    (capped : Capped trace participants c term (timeoutIndex + 1))
    : Polling step.after node initial (Grantors participants timeoutPoint initial) term
        (time timeoutPoint) electionTimeout maxDelay := by
  have beforeFound := setup.admissible.before stepped
  have beforeEq : step.before = timeoutPoint := by
    rw [poll.found, Option.some.injEq] at beforeFound
    exact beforeFound.symm
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have selected : step.action.action = some (.local node (.timeout .election)) := by
    simp [event, Liveness.Event.action]
  obtain ⟨actor, pre, post, outputs, preFound, postFound, _, ran, ledger⟩ :=
    Racing.protocol_view setup.admissible stepped selected
  obtain ⟨input, eq, ran⟩ : exists input, step.action = .local actor input
      /\ (act (CCF.Capabilities.record actor) actor pre input).run {}
          = some (post, outputs) := by
    rcases ran with found | ⟨_, eq, _⟩
    · exact found
    · rw [event] at eq
      cases eq
  rw [event, Liveness.Event.local.injEq] at eq
  obtain ⟨rfl, rfl⟩ := eq
  simp only [act] at ran
  obtain ⟨_, outcome⟩ := Racing.sends_run (Racing.startElection_outcome node pre) ran
  have preEq : pre = initial := by
    rw [beforeEq, poll.initialFound, Option.some.injEq] at preFound
    exact preFound.symm
  subst preEq
  have deadlineAfter
      : time timeoutPoint + electionTimeout / 2 <= deadline step.after node := by
    have reset : ElectionReset step node := by simp [ElectionReset, event]
    have := (((setup.timers.next stepped) node).1 reset).1
    rw [beforeEq] at this
    exact this
  have keeps : Keeps pre (preVoteState node pre) := Racing.keeps_preVote _ _
  split at outcome
  · exfalso
    have raised := candidacy_term outcome (fun entry member => by
      have := setup.log_below originFound noElection poll.found poll.initialFound entry member
      simpa [preVoteState] using this)
    have capLe :=
      capped.2 (timeoutIndex + 1) step.after node post (by have := poll.le; omega) (le_refl _)
        afterFound poll.member postFound
    simp only [preVoteState] at raised
    have := poll.initialTerm
    omega
  · rename_i quorum
    obtain ⟨postEq, sentEq⟩ := outcome
    subst postEq
    have requestEq
        : makeRequestVoteRequest (preVoteState node pre) = makeRequestVoteRequest pre := by
      simp [makeRequestVoteRequest, preVoteState, lastCommittableTerm, lastCommittableIndex]
    refine ⟨deadlineAfter, _, postFound, rfl, by simp [preVoteState, poll.initialTerm], keeps,
      by simp [preVoteState], quorum, fun voter voterIn voterNe => ?_⟩
    have targetIn :=
      (setup.poll_members originFound noElection poll (grantor_mem voterIn).1 voterNe).1
    have sentMem
        : (⟨node, voter, .requestPreVoteRequest (makeRequestVoteRequest pre)⟩
            : Model.Envelope)
          ∈ outputs.outgoing := by
      rw [sentEq, Racing.mem_broadcast]
      refine ⟨voter, ?_, by rw [requestEq]⟩
      rwa [keeps.members]
    obtain ⟨packet, member', envEq, sentAt⟩ := Racing.pending_of_sent ledger sentMem
    exact Or.inr ⟨packet, member', Or.inl ⟨envEq, by rw [sentAt, beforeEq]⟩⟩

/-- A delivery to a polling node keeps it polling. -/
theorem RoundSetup.poll_deliver {node : NodeID} {timeoutIndex : Nat} {timeoutPoint : W}
    {initial : NodeState}
    (poll
      : PollStart trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) electionTimeout maxDelay node
          timeoutIndex timeoutPoint initial)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : timeoutIndex <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (timeBefore : time step.before <= time timeoutPoint + 2 * maxDelay)
    (polling
      : Polling step.before node initial (Grantors participants timeoutPoint initial) term
          (time timeoutPoint) electionTimeout maxDelay)
    {packet : Packet} (event : step.action = .deliver packet)
    (target : packet.envelope.target = node)
    (deadlineAfter : time timeoutPoint + electionTimeout / 2 <= deadline step.after node)
    : Polling step.after node initial (Grantors participants timeoutPoint initial) term
        (time timeoutPoint) electionTimeout maxDelay := by
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeoutLe := setup.admissible.time_le le poll.found beforeFound
  have within :=
    setup.inside originFound index step.before (le_trans poll.le le) beforeFound
      (by linarith [poll.timeLe])
  have cappedBefore := capped.down (le_trans poll.le le) (Nat.le_succ index)
  have frozen :=
    setup.frozen originFound noElection cappedBefore beforeFound
      (by linarith [poll.late, setup.ratio, setup.nonnegative]) (by linarith [poll.timeLe])
  obtain ⟨_, state, stateFound, role, termEq, keeps, selfIn, noQuorum, progress⟩ := polling
  have selected : step.action.action = some (.deliver packet.envelope) := by
    simp [event, Liveness.Event.action]
  obtain ⟨actor, pre, post, outputs, preFound, postFound, _, ran, _⟩ :=
    Racing.protocol_view setup.admissible stepped selected
  rcases ran with ⟨input, eq, _⟩ | ⟨delivered, eq, targetEq, ran⟩
  · rw [event] at eq
    cases eq
  rw [event, Liveness.Event.deliver.injEq] at eq
  subst eq targetEq
  have member : packet ∈ pending step.before :=
    setup.admissible.consumed_pending stepped (by simp [event, Liveness.Event.consumedPacket])
  have alive : packet.envelope.target ∈ live step.before :=
    setup.admissible.actor_live stepped (by simp [event, Liveness.Event.actor])
  have delayLe := setup.delay_at beforeFound member alive
  have targetIn : packet.envelope.target ∈ participants := target ▸ poll.member
  have sourceIn : packet.envelope.source ∈ participants :=
    setup.period.isolated index step packet.envelope within stepped
      (by simp [event, Liveness.Event.delivered]) targetIn
  have shape := setup.packets cappedBefore originFound beforeFound member sourceIn targetIn
  have frozenPk := frozen.packets packet member sourceIn targetIn
  have early : packet.sentAt <= time origin + 2 * maxDelay -> False := fun sentLe => by
    linarith [poll.late, setup.ratio, setup.nonnegative]
  have lowContra
      : packet.envelope.payload.term <= term
        -> (forall response, packet.envelope.payload ≠ .appendEntriesResponse response)
        -> False :=
    fun low notResponse =>
      early (by linarith [shape.2.1 low notResponse, setup.nonnegative])
  have termLe : packet.envelope.payload.term <= term + 1 := shape.1
  rw [target] at preFound postFound ran
  rw [stateFound, Option.some.injEq] at preFound
  subst preFound
  have below := setup.log_below originFound noElection beforeFound stateFound
  have raisedContra
      : forall next : NodeState, post.currentTerm = next.currentTerm + 1
        -> next.currentTerm = term + 1 -> False := by
    intro next raised nextTerm
    have := capped.2 (index + 1) step.after node post (by have := poll.le; omega) (le_refl _)
      afterFound poll.member postFound
    omega
  have conclude
      : forall next : NodeState,
          nodeState (proto step.after) node = some next
          -> next.role = .preVoteCandidate
          -> next.currentTerm = term + 1
          -> Keeps initial next
          -> node ∈ next.preVotesGranted
          -> Not (hasQuorum next.activeConfigurations next.preVotesGranted)
          -> state.preVotesGranted ⊆ next.preVotesGranted
          -> (forall voter,
                voter ∈ Grantors participants timeoutPoint initial
                -> voter ≠ node
                -> packet.envelope
                    = ⟨voter, node,
                        .requestPreVoteResponse { term := term + 1, voteGranted := true }⟩
                -> voter ∈ next.preVotesGranted)
          -> Polling step.after node initial (Grantors participants timeoutPoint initial)
              term (time timeoutPoint) electionTimeout maxDelay := by
    intro next nextFound nextRole nextTerm nextKeeps nextSelf nextQuorum sub got
    refine ⟨deadlineAfter, next, nextFound, nextRole, nextTerm, nextKeeps, nextSelf, nextQuorum,
      fun voter voterIn voterNe => ?_⟩
    refine setup.progress_step originFound noElection within stepped poll.member (grantor_mem voterIn).1
      (progress voter voterIn voterNe) sub (fun other deliv envEq _ => ?_)
      (fun other deliv envEq => ?_)
    · rw [event, Liveness.Event.deliver.injEq] at deliv
      subst deliv
      exfalso
      apply voterNe
      simpa [envEq] using target
    · rw [event, Liveness.Event.deliver.injEq] at deliv
      subst deliv
      exact got voter voterIn voterNe envEq
  have stay
      : post = state
        -> packet.envelope.payload
            ≠ .requestPreVoteResponse { term := term + 1, voteGranted := true }
        -> Polling step.after node initial (Grantors participants timeoutPoint initial) term
            (time timeoutPoint) electionTimeout maxDelay := by
    intro postEq ne
    subst postEq
    exact conclude _ postFound role termEq keeps selfIn noQuorum (subset_refl _)
      fun voter _ _ envEq => absurd (by rw [envEq]) ne
  have inertCase
      : Racing.Inert packet.envelope.payload
        -> Polling step.after node initial (Grantors participants timeoutPoint initial) term
            (time timeoutPoint) electionTimeout maxDelay := by
    intro inert
    obtain ⟨_, observed⟩ :=
      Racing.sends_run
        (Racing.inert_receive node packet.envelope.source state packet.envelope.payload inert
          (by rw [role]; simp))
        ran
    rcases observed with postEq | ⟨lt, _⟩
    · refine stay postEq fun grant => ?_
      rw [grant] at inert
      simp [Racing.Inert] at inert
    · omega
  cases payloadEq : packet.envelope.payload with
  | appendEntriesRequest request =>
      exfalso
      exact lowContra
        (by rw [payloadEq]; exact frozenPk.1 request payloadEq)
        (fun response eq => by rw [payloadEq] at eq; cases eq)
  | appendEntriesResponse response =>
      exact inertCase (by rw [payloadEq]; simp [Racing.Inert])
  | requestVoteRequest request =>
      exfalso
      exact early (by linarith [shape.2.2.1 request payloadEq, setup.nonnegative])
  | requestVoteResponse response =>
      by_cases granted : response.voteGranted = true
      · exfalso
        rw [payloadEq] at termLe
        by_cases low : response.term <= term
        · exact lowContra (by rw [payloadEq]; exact low)
            (fun other eq => by rw [payloadEq] at eq; cases eq)
        · have respEq : response = { term := term + 1, voteGranted := true } := by
            obtain ⟨responseTerm, responseGranted⟩ := response
            simp only [Message.term] at termLe low granted
            subst granted
            have : responseTerm = term + 1 := by omega
            subst this
            rfl
          exact early (by linarith [shape.2.2.2.1 (by rw [payloadEq, respEq])])
      · exact inertCase (by rw [payloadEq]; simpa [Racing.Inert] using granted)
  | requestPreVoteRequest request =>
      rw [payloadEq] at ran termLe
      obtain ⟨observed, _, _⟩ :=
        Racing.sends_run (Racing.preVoteRequest_receive node packet.envelope.source state request)
          ran
      rcases observed with postEq | ⟨lt, _⟩
      · exact stay postEq (by rw [payloadEq]; simp)
      · simp only [Message.term] at termLe
        omega
  | requestPreVoteResponse response =>
      by_cases granted : response.voteGranted = true
      · rw [payloadEq] at termLe
        by_cases low : response.term <= term
        · exact absurd (lowContra (by rw [payloadEq]; exact low)
            (fun other eq => by rw [payloadEq] at eq; cases eq)) id
        have respEq : response = { term := term + 1, voteGranted := true } := by
          obtain ⟨responseTerm, responseGranted⟩ := response
          simp only [Message.term] at termLe low granted
          subst granted
          have : responseTerm = term + 1 := by omega
          subst this
          rfl
        subst respEq
        rw [payloadEq] at ran
        obtain ⟨middle, observed, outcome⟩ :=
          Racing.sends_run
            (Racing.preVoteResponse_receive node packet.envelope.source state _) ran
        have middleEq : middle = state := by
          rcases observed with rfl | ⟨lt, _⟩
          · rfl
          · simp only at lt
            omega
        subst middleEq
        split at outcome
        · unfold Racing.PreVoted at outcome
          split at outcome
          · exfalso
            exact raisedContra _ (candidacy_term outcome below) termEq
          · rename_i quorum
            obtain ⟨postEq, _⟩ := outcome
            subst postEq
            exact conclude _ postFound role termEq (keeps.trans ⟨rfl, rfl, rfl⟩)
              (Finset.mem_insert_of_mem selfIn) quorum (Finset.subset_insert _ _)
              fun voter _ _ envEq => by simp [envEq]
        · rename_i cond
          obtain ⟨postEq, _⟩ := outcome
          refine conclude _ (postEq ▸ postFound) role termEq keeps selfIn noQuorum
            (subset_refl _) fun voter voterIn voterNe envEq => ?_
          exfalso
          apply cond
          have sourceEq : packet.envelope.source = voter := by rw [envEq]
          refine ⟨?_, role, by simp [termEq], rfl⟩
          rw [sourceEq, keeps.peers]
          exact (setup.poll_members originFound noElection poll (grantor_mem voterIn).1
            voterNe).2
      · exact inertCase (by rw [payloadEq]; simpa [Racing.Inert] using granted)
  | proposeRequestVoteRequest proposed =>
      exfalso
      rw [payloadEq] at termLe
      by_cases low : proposed <= term
      · exact lowContra (by rw [payloadEq]; exact low)
          (fun other eq => by rw [payloadEq] at eq; cases eq)
      · have : proposed = term + 1 := by
          simp only [Message.term] at termLe
          omega
        exact frozenPk.2.1 (by rw [payloadEq, this])

/-- A step keeps a node polling while it is within two delays of its timeout. -/
theorem RoundSetup.poll_step {node : NodeID} {timeoutIndex : Nat} {timeoutPoint : W}
    {initial : NodeState}
    (poll
      : PollStart trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) electionTimeout maxDelay node
          timeoutIndex timeoutPoint initial)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : timeoutIndex <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (timeBefore : time step.before <= time timeoutPoint + 2 * maxDelay)
    (polling
      : Polling step.before node initial (Grantors participants timeoutPoint initial) term
          (time timeoutPoint) electionTimeout maxDelay)
    : Polling step.after node initial (Grantors participants timeoutPoint initial) term
        (time timeoutPoint) electionTimeout maxDelay := by
  have beforeFound := setup.admissible.before stepped
  have timeoutLe := setup.admissible.time_le le poll.found beforeFound
  have within :=
    setup.inside originFound index step.before (le_trans poll.le le) beforeFound
      (by linarith [poll.timeLe])
  have deadlineAfter : time timeoutPoint + electionTimeout / 2 <= deadline step.after node := by
    have timer := (setup.timers.next stepped) node
    by_cases reset : ElectionReset step node
    · linarith [(timer.1 reset).1]
    · rw [timer.2.1 reset]
      exact polling.1
  obtain ⟨deadlineBefore, state, stateFound, role, termEq, keeps, selfIn, noQuorum, progress⟩ :=
    id polling
  cases selected : step.action.action with
  | none =>
      have stutter := setup.admissible.stutter stepped selected
      refine ⟨
        deadlineAfter,
        state,
        by rw [stutter]; exact stateFound,
        role,
        termEq,
        keeps,
        selfIn,
        noQuorum,
        fun voter voterIn voterNe =>
          setup.progress_step originFound noElection within stepped poll.member
            (grantor_mem voterIn).1 (progress voter voterIn voterNe) (subset_refl _)
            (fun other deliv _ _ => ?_) (fun other deliv _ => ?_)
      ⟩
      · rw [deliv] at selected
        simp [Liveness.Event.action] at selected
      · rw [deliv] at selected
        simp [Liveness.Event.action] at selected
  | some action =>
      obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
        Racing.protocol_view setup.admissible stepped selected
      by_cases actorEq : actor = node
      · subst actorEq
        rcases ran with ⟨input, eventEq, ran⟩ | ⟨packet, eventEq, targetEq, _⟩
        · exfalso
          rw [stateFound, Option.some.injEq] at preFound
          subst preFound
          by_cases timeout : input = .timeout .election
          · subst timeout
            have := ((setup.timers.next stepped) actor).2.2 eventEq
            linarith [setup.ratio, setup.nonnegative]
          · have := Racing.act_primary actor timeout ran
            rw [role] at this
            cases this
        · exact setup.poll_deliver originFound noElection poll le stepped capped timeBefore
            polling eventEq targetEq deadlineAfter
      · refine ⟨deadlineAfter, state, by rw [others node (Ne.symm actorEq)]; exact stateFound,
          role, termEq, keeps, selfIn, noQuorum, fun voter voterIn voterNe =>
            setup.progress_step originFound noElection within stepped poll.member (grantor_mem voterIn).1
              (progress voter voterIn voterNe) (subset_refl _)
              (fun other deliv envEq sentEq => ?_) (fun other deliv envEq => ?_)⟩
        · obtain ⟨voterPart, voterState, voterFound, upToDate⟩ := grantor_mem voterIn
          obtain ⟨response, pend, envOut, sentLe⟩ :=
            setup.poll_grant originFound noElection poll.found poll.late
              (by linarith [poll.timeLe]) le stepped
              (capped.down (le_trans poll.le le) (Nat.le_succ index)) timeBefore
              poll.initialTerm voterPart voterFound upToDate deliv envEq sentEq
          exact Or.inr ⟨response, pend, Or.inr ⟨envOut, sentLe⟩⟩
        · exfalso
          apply actorEq
          rcases ran with ⟨input, eventEq, _⟩ | ⟨packet, eventEq, targetEq, _⟩
          · rw [deliv] at eventEq
            cases eventEq
          · rw [deliv, Liveness.Event.deliver.injEq] at eventEq
            subst eventEq
            simpa [envEq] using targetEq.symm

/-- A participant that can gather a pre-vote quorum and times out in `term + 1` ends
the round within two delays. -/
theorem RoundSetup.poll {timeoutIndex : Nat} {node : NodeID} {timeoutPoint : W}
    (member : node ∈ participants) (timedOut : TermTimeout trace term timeoutIndex node)
    (timeoutCapped : Capped trace participants c term timeoutIndex)
    (timeoutFound : trace.stateAt timeoutIndex = some timeoutPoint)
    (hopeful : Not (Racing.Hopeless participants timeoutPoint node))
    (timeLe
      : time timeoutPoint + 2 * maxDelay
        <= time origin + roundLength electionTimeout maxDelay + jump)
    {index : Nat} {point : W} (le : timeoutIndex <= index)
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    : time point <= time timeoutPoint + 2 * maxDelay := by
  obtain ⟨timeoutStep, initial, stepped, event, initialFound, initialTerm⟩ := timedOut
  have beforeFound := setup.admissible.before stepped
  have beforeEq : timeoutStep.before = timeoutPoint := by
    rw [timeoutFound, Option.some.injEq] at beforeFound
    exact beforeFound.symm
  rw [beforeEq] at initialFound
  have late : time origin + electionTimeout / 2 <= time timeoutPoint := by
    have := setup.timeout_late originFound timeoutCapped.1 stepped member
      (beforeEq ▸ initialFound) initialTerm event
    rwa [beforeEq] at this
  have frozen :=
    setup.frozen originFound noElection timeoutCapped timeoutFound
      (by linarith [setup.ratio, setup.nonnegative]) (by linarith [setup.nonnegative])
  have quorum
      : hasQuorum initial.activeConfigurations
          (insert node (Grantors participants timeoutPoint initial)) := by
    by_contra noQuorum
    apply hopeful
    refine ⟨initial, initialFound, fun preQuorum => noQuorum (hasQuorum_mono preQuorum ?_)⟩
    intro voter voterIn
    simp only [Racing.PreVoters, Finset.mem_insert, Finset.mem_union] at voterIn
    rcases voterIn with rfl | granted | covered
    · exact Finset.mem_insert_self _ _
    · exact (frozen.polling node initial member initialFound).1 granted
    · apply Finset.mem_insert_of_mem
      unfold Grantors
      exact Finset.mem_filter.mpr (Finset.mem_filter.mp covered)
  have poll
      : PollStart trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) electionTimeout maxDelay node
          timeoutIndex timeoutPoint initial :=
    {
      le := timeoutCapped.1
      found := timeoutFound
      member
      initialFound
      initialTerm
      late
      timeLe := by linarith
      quorum
    }
  have run
      : forall n, timeoutIndex + n + 1 <= index
        -> forall later, trace.stateAt (timeoutIndex + n + 1) = some later
        -> Polling later node initial (Grantors participants timeoutPoint initial) term
            (time timeoutPoint) electionTimeout maxDelay
          /\ time later <= time timeoutPoint + 2 * maxDelay := by
    intro n
    induction n with
    | zero =>
        intro bound later laterFound
        obtain ⟨step, stepped', rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
        rw [stepped, Option.some.injEq] at stepped'
        subst stepped'
        have polling :=
          setup.poll_start originFound noElection poll stepped event
            (capped.down (by have := timeoutCapped.1; omega) bound)
        exact ⟨
          polling,
          setup.poll_time originFound noElection poll (le_refl _) stepped
            (by rw [beforeEq]; linarith [setup.nonnegative]) polling
        ⟩
    | succ n ih =>
        intro bound later laterFound
        obtain ⟨step, stepped', rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
        obtain ⟨polling, timeBefore⟩ :=
          ih (by omega) step.before (setup.admissible.before stepped')
        have polling' :=
          setup.poll_step originFound noElection poll (by omega) stepped'
            (capped.down (by have := timeoutCapped.1; omega) bound) timeBefore polling
        exact ⟨
          polling',
          setup.poll_time originFound noElection poll (by omega) stepped'
            timeBefore polling'
        ⟩
  rcases Nat.eq_or_lt_of_le le with same | lt
  · subst same
    rw [timeoutFound, Option.some.injEq] at found
    subst found
    linarith [setup.nonnegative]
  · obtain ⟨n, rfl⟩ : exists n, index = timeoutIndex + n + 1 := ⟨index - timeoutIndex - 1, by omega⟩
    exact (run n (le_refl _) point found).2

/-- A leaderless round ends within a round length plus the overshoot of its steps. -/
theorem RoundSetup.progress {slack : Real} (slackNonnegative : 0 <= slack)
    (slackLe : slack <= jump) {index : Nat} {point : W}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (overshoot
      : forall earlier step node,
          node ∈ participants
          -> c <= earlier
          -> earlier < index
          -> trace.stepAt earlier = some step
          -> NoOvershoot (some slack) step node)
    : time point <= time origin + roundLength electionTimeout maxDelay + slack := by
  sorry

end Progress

end CCFRaft.Proofs.Duel.Round
