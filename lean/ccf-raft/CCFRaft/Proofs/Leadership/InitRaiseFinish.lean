module

public import CCFRaft.Proofs.Leadership.InitRaiseQuorum

@[expose] public section

set_option linter.unusedSectionVars false

/-!
NOT IMPORTED BY `Properties`.

The best cleared participant completes a pre-vote before its next timeout.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- Cleared participants cannot remain capped through the best log's next
timeout and the resulting pre-vote round trip. -/
theorem win_after_clear {start since term : Nat}
    {duration electionTimeout maxDelay jump limit : Real}
    {participants members : Finset NodeID} {origin first : W}
    {winner : NodeID} {initial : NodeState}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
    (nonnegative : 0 <= maxDelay) (jumpNonnegative : 0 <= jump)
    (ratio : 4 * maxDelay < electionTimeout)
    (good : GoodPeriod trace start duration participants)
    (subset : participants ⊆ members)
    (originFound : trace.stateAt start = some origin)
    (afterStart : start <= since)
    (firstFound : trace.stateAt since = some first)
    (early : time first <= limit)
    (room : limit + electionTimeout + jump + 2 * maxDelay <= time origin + duration)
    (initialFound : nodeState (proto first) winner = some initial)
    (initialTerm : initial.currentTerm = term) (winnerIn : winner ∈ participants)
    (cleared
      : forall node,
          node ∈ participants
          -> exists state,
              nodeState (proto first) node = some state
              /\ state.currentTerm = term
              /\ state.primaryKnown = false)
    (best
      : forall node state,
          node ∈ participants
          -> nodeState (proto first) node = some state
          -> voteLogUpToDate state (makeRequestVoteRequest initial))
    (firing
      : forall node,
          node ∈ participants
          -> Scheduled trace (some 0) (fun point => TimeoutDue point node)
              (fun step => step.action = .local node (.timeout .election)))
    (overshoot
      : forall index step node,
          node ∈ participants
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> NoOvershoot (some jump) step node)
    (ready
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.activeMembers = members
              /\ (Not (state.role = .primary) -> canStartElection state node))
    (noLeader
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.currentTerm = term
          -> Not (state.role = .primary))
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (resets
      : forall index step node,
          since <= index
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> node ∈ participants
          -> ElectionReset step node
          -> step.action = .local node (.timeout .election))
    (old
      : forall index step packet request,
          since <= index
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .deliver packet
          -> packet.envelope.target ∈ participants
          -> packet.envelope.payload = .appendEntriesRequest request
          -> request.term < term)
    : False := by
  have within : forall index point, since <= index
      -> trace.stateAt index = some point
      -> time point <= limit + electionTimeout + jump + 2 * maxDelay
      -> Within trace start duration index := by
    intro index point lower found early
    refine ⟨afterStart.trans lower, fun origin' point' originFound' found' => ?_⟩
    rw [originFound, Option.some.injEq] at originFound'
    rw [found, Option.some.injEq] at found'
    subst origin' point'
    exact early.trans room
  have readyCan := fun index point node state win found member nodeFound =>
    (ready index point node state win found member nodeFound).2
  have firstWithin := within since first le_rfl firstFound (by linarith)
  have initialCan := readyCan since first winner initial firstWithin firstFound winnerIn initialFound
    (noLeader since first winner initial firstWithin firstFound winnerIn initialFound initialTerm)
  have initialDeadline := eligible_deadline admissible timers firstFound initialFound initialCan
  have eligible : forall index point, since <= index
      -> trace.stateAt index = some point -> time point <= limit + electionTimeout + jump
      -> winner ∈ live point /\ exists state,
        nodeState (proto point) winner = some state /\ canStartElection state winner := by
    intro index point lower found early
    have win := within index point lower found (by linarith)
    obtain ⟨state, stateFound, stateTerm⟩ := top_stays admissible firstFound initialFound initialTerm
      winnerIn lower found (low index win)
    exact ⟨good.participantsLive index point winner win found winnerIn, state, stateFound,
      readyCan index point winner state win found winnerIn stateFound
        (noLeader index point winner state win found winnerIn stateFound stateTerm)⟩
  obtain ⟨fired, step, afterSince, stepped, firedEarly, firedLate, reset⟩ :=
    reset_or_event admissible timers diverges firstFound
      (by linarith : time first <= limit + electionTimeout + jump)
      (by linarith : deadline first winner <= limit + electionTimeout)
      (le_refl (limit + electionTimeout + jump)) (firing winner winnerIn) eligible
      (fun index step lower stepped early => overshoot index step winner winnerIn
        (within index step.before lower (admissible.before stepped) (by linarith)) stepped)
      (fun _ step => limit < time step.before /\ ElectionReset step winner)
      (fun _ s _ _ _ reset => by
        by_cases early : time s.before <= limit
        · exact Or.inl early
        · exact Or.inr ⟨by linarith, reset⟩)
  have firedWithin := within fired step.before afterSince (admissible.before stepped) (by linarith)
  have action := resets fired step winner afterSince firedWithin stepped winnerIn reset
  have nextWithin := admissible.within_after firedWithin stepped (by rw [action]; simp)
  obtain ⟨before, beforeFound, beforeTerm⟩ := top_stays admissible firstFound initialFound initialTerm
    winnerIn afterSince (admissible.before stepped) (low fired firedWithin)
  obtain ⟨after, afterFound, afterTerm⟩ := top_stays admissible firstFound initialFound initialTerm
    winnerIn (by omega) (Trace.stateAt_succ_of_stepAt stepped) (low (fired + 1) nextWithin)
  have selected : step.action.action = some (.local winner (.timeout .election)) := by rw [action]; rfl
  obtain ⟨tr, ⟨actorEq, eventEq⟩, output⟩ := transition_acts (admissible.step stepped selected)
  have preEq : tr.pre = before := by
    have pre := tr.found
    rw [actorEq, beforeFound, Option.some.injEq] at pre
    exact pre.symm
  have postEq : tr.post = after := by
    have post := Direct.nodeState_of_mem
      (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped))) tr.post_mem
    rw [actorEq, afterFound, Option.some.injEq] at post
    exact post.symm
  have ran : (startElection (Capabilities.record winner) before winner).run {}
      = some (after, tr.outputs) := by
    simpa only [actorEq, eventEq, preEq, postEq, Model.Node.step, act] using tr.ran
  obtain ⟨sent, outputs, outcome⟩ := timeout_outcome winner before {} _ _ ran
  have outcome : after = preVoteState winner before
      /\ tr.outputs.outgoing = broadcast winner before
        (.requestPreVoteRequest (makeRequestVoteRequest before)) := by
    simpa [outputs] using outcome (by omega)
  obtain ⟨_, _, polling⟩ := timeout_polling winner before {} _ _ ran
  obtain ⟨role, selfVote, noQuorum⟩ := polling (by omega)
  have afterTime := (admissible.timing.next stepped).2 (by rw [action]; simp)
  obtain ⟨last, cross, afterFired, crossed, near, far⟩ :=
    boundary admissible diverges (Trace.stateAt_succ_of_stepAt stepped)
      (by linarith : time step.after <= time step.before + 2 * maxDelay)
  have crossWithin := within last cross.before (by omega) (admissible.before crossed) (by linarith)
  obtain ⟨finalState, finalFound, _⟩ := top_stays admissible firstFound initialFound initialTerm
    winnerIn (by omega) (admissible.before crossed) (low last crossWithin)
  have noTimeout : forall index s, fired + 1 <= index -> index < last
      -> trace.stepAt index = some s -> Not (s.action = .local winner (.timeout .election)) := by
    intro index s lower upper at_ timeout
    have scheduled := CCFRaft.Proofs.Liveness.electionScheduling_of_timerModel
      admissible.coherent admissible.timing timers
    have minimum := scheduled fired index step s winner lower stepped at_ timeout reset
    have upper := admissible.time_le upper.le (admissible.before at_) (admissible.before crossed)
    linarith
  have beforeFrozen := state_frozen admissible afterStart firstFound initialFound initialTerm
    winnerIn readyCan noLeader low
    (fun i s p r lower win at_ delivered target payload =>
      old i s p r lower win at_ delivered (target ▸ winnerIn) payload)
    afterSince firedWithin (admissible.before stepped) beforeFound
  apply quorum_contradiction admissible good subset (afterStart.trans (by omega))
    (Trace.stateAt_succ_of_stepAt stepped) afterFound afterTerm winnerIn role selfVote
    noQuorum low
    (fun index point state _ win found nodeFound =>
      (ready index point winner state win found winnerIn nodeFound).1)
    noTimeout
    (fun i s p r lower _ win at_ delivered target payload =>
      old i s p r (by omega) win at_ delivered (target ▸ winnerIn) payload)
    ?_ afterFired crossWithin (admissible.before crossed) finalFound
  intro voter voterIn different
  have membersEq := (ready fired step.before winner before firedWithin
    (admissible.before stepped) winnerIn beforeFound).1
  have requestMem : ({ source := winner, target := voter, payload := .requestPreVoteRequest (makeRequestVoteRequest before) } : Model.Envelope)
      ∈ tr.outputs.outgoing := by
    rw [outcome.2]
    exact mem_broadcast (by rw [membersEq]; exact subset voterIn) different
  obtain ⟨requestPacket, requestSent, requestEq, requestTime⟩ :=
    admissible.sentAt_of_emitted stepped selected output requestMem
  obtain ⟨delivered, deliveryStep, afterSend, deliveryAt, deliveryEarly, deliveryAction⟩ :=
    sent_delivered admissible delay diverges good originFound firedWithin requestSent
      (by rw [requestEq]; exact winnerIn) (by rw [requestEq]; exact voterIn)
      (by rw [requestTime]; linarith)
  have deliveryWithin := within delivered deliveryStep.before (by omega) (admissible.before deliveryAt)
    (by rw [requestTime] at deliveryEarly; linarith)
  obtain ⟨voterInitial, voterInitialFound, voterInitialTerm, voterUnknown⟩ := cleared voter voterIn
  obtain ⟨voterState, voterFound, voterTerm⟩ := top_stays admissible firstFound voterInitialFound
    voterInitialTerm voterIn (by omega) (admissible.before deliveryAt) (low delivered deliveryWithin)
  have voterFrozen := state_frozen admissible afterStart firstFound voterInitialFound voterInitialTerm
    voterIn readyCan noLeader low
    (fun i s p r lower win at_ delivered target payload =>
      old i s p r lower win at_ delivered (target ▸ voterIn) payload)
    (by omega) deliveryWithin (admissible.before deliveryAt) voterFound
  have fresh : voteLogUpToDate voterState (makeRequestVoteRequest before) := by
    have best := best voter voterInitial voterIn voterInitialFound
    simpa only [voteLogUpToDate, makeRequestVoteRequest, lastCommittableTerm,
      lastCommittableIndex, beforeFrozen.1, beforeFrozen.2.1, voterFrozen.1] using best
  obtain ⟨reply, replySent, replySource, replyTarget, replyPayload⟩ :=
    request_gets_grant admissible deliveryAt deliveryAction
      (by rw [requestEq]) (by rw [requestEq]; exact voterFound)
      (by change before.currentTerm = voterState.currentTerm; omega) fresh
      (voterFrozen.2.2 voterUnknown)
  have replySource : reply.envelope.source = voter := by simpa only [requestEq] using replySource
  have replyTarget : reply.envelope.target = winner := by simpa only [requestEq] using replyTarget
  obtain ⟨replyStep, _, _, replyAt, _, _, _, _, _, replyTime⟩ := admissible.sentAt_emitted replySent
  rw [deliveryAt, Option.some.injEq] at replyAt
  subst replyStep
  obtain ⟨received, responseStep, afterDelivery, responseAt, responseEarly, responseAction⟩ :=
    sent_delivered admissible delay diverges good originFound deliveryWithin replySent
      (replySource ▸ voterIn) (replyTarget ▸ winnerIn) (by
        rw [replyTime]
        have deliveredEarly := deliveryEarly
        rw [requestTime] at deliveredEarly
        linarith)
  have receivedBefore : received < last := by
    by_contra later
    have late := busy_after_crossing admissible crossed near far (by omega) responseAt
      (by rw [responseAction]; simp)
    rw [replyTime] at responseEarly
    rw [requestTime] at deliveryEarly
    linarith
  exact ⟨
    received,
    responseStep,
    reply,
    { term := voterState.currentTerm, voteGranted := true },
    by omega,
    receivedBefore,
    responseAt,
    responseAction,
    replySource,
    replyTarget,
    replyPayload,
    voterTerm,
    rfl
  ⟩

end CCFRaft.Proofs.Leadership.InitRaise
