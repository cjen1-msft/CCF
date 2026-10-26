module

public import CCFRaft.Proofs.Leadership.InitIncumbentDelivery

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Fresh timers and flushing vote proposals at the incumbent handoff boundary.
-/

namespace CCFRaft.Proofs.Leadership.InitIncumbent

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open HasNetwork (pending)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- From a pristine state, a node remains pristine until its first reset. -/
theorem pristine_since {first index : Nat} {initial point : W} {node : NodeID}
    {state : NodeState} (initialFound : trace.stateAt first = some initial)
    (nodeFound : nodeState (proto initial) node = some state) (pristine : Pristine state)
    (later : first <= index) (found : trace.stateAt index = some point)
    : forall state,
        nodeState (proto point) node = some state
        -> Pristine state
            \/ exists earlier reset,
                first <= earlier
                /\ earlier < index
                /\ trace.stepAt earlier = some reset
                /\ ElectionReset reset node := by
  refine admissible.coherent.induction (start := first)
    (motive :=
      fun index point =>
        forall state,
          nodeState (proto point) node = some state
          -> Pristine state
              \/ exists earlier reset,
                  first <= earlier
                  /\ earlier < index
                  /\ trace.stepAt earlier = some reset
                  /\ ElectionReset reset node)
    (fun point found other otherFound => ?_)
    (fun index step after stepped held state stateFound => ?_)
    index point later found
  · rw [initialFound, Option.some.injEq] at found
    subst point
    rw [nodeFound, Option.some.injEq] at otherFound
    subst other
    exact Or.inl pristine
  · have lift : (exists earlier reset, first <= earlier /\ earlier < index
        /\ trace.stepAt earlier = some reset /\ ElectionReset reset node) ->
        exists earlier reset, first <= earlier /\ earlier < index + 1
          /\ trace.stepAt earlier = some reset /\ ElectionReset reset node :=
      fun ⟨earlier, reset, lower, lt, at_, resets⟩ =>
        ⟨earlier, reset, lower, Nat.lt_succ_of_lt lt, at_, resets⟩
    by_cases resets : ElectionReset step node
    · exact Or.inr ⟨index, step, after, Nat.lt_succ_self _, stepped, resets⟩
    cases selected : step.action.action with
    | none =>
        rw [admissible.stutter stepped selected] at stateFound
        exact (held state stateFound).imp_right lift
    | some action =>
        obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
        rcases tr.mem_after (Concrete.mem_of_nodeState stateFound)
          with ⟨rfl, rfl⟩ | ⟨_, mem⟩
        · rcases held _ tr.found with pristine | earlier
          · exact Or.inl (pristine_step pristine tr.summary (LocalTransition.wake tr) fun reset =>
              resets (electionReset_of_reset selected acts tr.found stateFound reset))
          · exact Or.inr (lift earlier)
        · exact (held state (Direct.nodeState_of_mem
            (Direct.keys_nodup (admissible.reachable_before stepped)) mem)).imp_right lift

/-- A node that was primary cannot time out until a later reset's fresh period ends. -/
theorem primary_timeout_late {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {first index : Nat} {initial : W}
    {node : NodeID} {state : NodeState}
    (initialFound : trace.stateAt first = some initial)
    (nodeFound : nodeState (proto initial) node = some state)
    (primary : state.role = .primary) (later : first <= index)
    {step : Execution.Step W Liveness.Event} (stepped : trace.stepAt index = some step)
    (fired : step.action = .local node (.timeout .election))
    : time initial + electionTimeout / 2 <= time step.before := by
  have selected : step.action.action = some (.local node (.timeout .election)) := by rw [fired]; rfl
  obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
  have actor : tr.actor = node := acts.1
  have event : tr.event = .internal (.timeout .election) := acts.2
  have ran := tr.ran
  rw [actor, event] at ran
  obtain ⟨_, _, can⟩ := startElection_guard node tr.pre {} _ _ ran
  have preFound : nodeState (proto step.before) node = some tr.pre := actor ▸ tr.found
  obtain ⟨earlier, reset, lower, before, resetAt, resets⟩ :=
    (pristine_since admissible initialFound nodeFound (Or.inr (Or.inl primary)) later
      (admissible.before stepped) tr.pre preFound).resolve_left (fun p => p.not_eligible can)
  have elapsed := admissible.time_le lower initialFound (admissible.before resetAt)
  have scheduled := CCFRaft.Proofs.Liveness.electionScheduling_of_timerModel
    admissible.coherent admissible.timing timers earlier index reset step node before
      resetAt stepped fired resets
  linarith

/-- A live non-retired incumbent prevents new proposals of its term in the window. -/
theorem no_proposal_sent {start : Nat} {duration : Real} {participants : Finset NodeID}
    {leader : NodeID} {term : Nat} (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (roled
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> Not (state.role = .none))
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {index : Nat} {packet : Packet} (within : Within trace start duration index)
    (sentAt : trace.SentAt index packet)
    (sourceIn : packet.envelope.source ∈ participants)
    (payload : packet.envelope.payload = .proposeRequestVoteRequest term)
    : False := by
  obtain ⟨step, action, emitted, stepped, selected, output, emittedMem, _, _, _⟩ :=
    admissible.sentAt_emitted sentAt
  obtain ⟨tr, acts, output'⟩ := transition_acts (admissible.step stepped selected)
  rw [output', Option.some.injEq] at output
  subst emitted
  have sends := CCFRaft.Proofs.Safety.Summary.sends tr.summary packet.envelope emittedMem
  have actorIn : tr.actor ∈ participants := sends.1 ▸ sourceIn
  have busy : Not (step.action = .idle) := by intro idle; simp [idle, Liveness.Event.action] at selected
  have nextWithin := admissible.within_after within stepped busy
  have nextFound := Trace.stateAt_succ_of_stepAt stepped
  have postFound := Direct.nodeState_of_mem
    (Direct.keys_nodup (admissible.reachable nextFound)) tr.post_mem
  have ok := sends.2
  simp only [payload] at ok
  obtain ⟨termEq, (⟨_, _, nominate | retired⟩ | wins)⟩ := ok
  · exact good.noNominations index step tr.actor within stepped
      (InitRaise.internal_event selected acts nominate)
  · exact active (index + 1) step.after tr.actor tr.post nextWithin nextFound actorIn postFound retired
  · have postRole := (InitRaise.wins_role wins).resolve_right
      (roled (index + 1) step.after tr.actor tr.post nextWithin nextFound actorIn postFound)
    obtain ⟨primary, primaryFound, primaryTerm, primaryRole⟩ :=
      leads (index + 1) step.after nextWithin nextFound
    have actorEq := primary_unique admissible nextFound primaryFound primaryRole primaryTerm
      postFound postRole termEq.symm
    obtain ⟨before, beforeFound, beforeTerm, beforeRole⟩ :=
      leads index step.before within (admissible.before stepped)
    have same := state_unique (Direct.keys_nodup (admissible.reachable_before stepped))
      (actorEq ▸ tr.pre_mem) (Concrete.mem_of_nodeState beforeFound)
    have preRole : tr.pre.role = .primary := same ▸ beforeRole
    have preTerm : tr.pre.currentTerm = term := same ▸ beforeTerm
    obtain ⟨candidate, campaign, _, advance⟩ := wins
    have endTerm := advance.term
    change tr.post.currentTerm = candidate.currentTerm at endTerm
    obtain ⟨_, _, _, ⟨_, raised, _⟩ | ⟨old, _⟩⟩ := campaign
    · omega
    · rw [preRole] at old; cases old

/-- No old proposal survives the idle step crossing the handoff horizon. -/
theorem proposals_flushed {start stop : Nat} {duration maxDelay : Real}
    {participants : Finset NodeID} {leader : NodeID} {term : Nat}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (roled
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> Not (state.role = .none))
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {first : W} (firstFound : trace.stateAt start = some first)
    {cross : Execution.Step W Liveness.Event}
    (lower : start <= stop) (crossed : trace.stepAt stop = some cross)
    (near : time cross.before <= time first + duration)
    (far : time first + duration < time cross.after) (room : maxDelay <= duration)
    : NoProposals participants term cross.before := by
  have within : Within trace start duration stop := by
    refine ⟨lower, fun f p ff pf => ?_⟩
    rw [firstFound, Option.some.injEq] at ff
    rw [admissible.before crossed, Option.some.injEq] at pf
    subst f p
    exact near
  have idle : cross.action = .idle := by
    by_contra busy
    have := (admissible.timing.next crossed).2 busy
    linarith
  intro packet queued sourceIn targetIn payload
  obtain ⟨sent, earlier, sentAt⟩ := admissible.pending_sent (admissible.before crossed) queued
  have old : sent < start := by
    by_contra late
    exact no_proposal_sent admissible good active roled leads
      (InitRaise.within_before admissible within (admissible.before crossed)
        (by omega) earlier.le) sentAt sourceIn payload
  obtain ⟨send, _, _, sendAt, _, _, _, _, _, sentTime⟩ := admissible.sentAt_emitted sentAt
  have sentEarly := admissible.time_le old.le (admissible.before sendAt) firstFound
  have stillQueued : packet ∈ pending cross.after := by
    by_contra gone
    have consumed := admissible.consumed_of_left crossed queued gone
    simp [idle, Liveness.Event.consumedPacket] at consumed
  have deadline := CCFRaft.Proofs.Liveness.pending_deadline delay
    (Trace.stateAt_succ_of_stepAt crossed) stillQueued
    (InitRaise.participant_live_after admissible good within crossed targetIn)
  rw [sentTime] at deadline
  linarith

end CCFRaft.Proofs.Leadership.InitIncumbent
