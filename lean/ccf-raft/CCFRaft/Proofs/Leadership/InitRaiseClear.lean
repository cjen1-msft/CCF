module

public import CCFRaft.Proofs.Leadership.InitRaiseUnknown

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Every participant clears its primary knowledge within one election interval
after non-timeout resets stop.
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

/-- Once only election timeouts reset timers and AppendEntries are old, all
participants clear primary knowledge within an election timeout and overshoot. -/
theorem clear_by {start since term : Nat} {duration electionTimeout jump limit : Real}
    {participants : Finset NodeID} {origin first : W}
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
    (positive : 0 <= electionTimeout) (nonnegative : 0 <= jump)
    (good : GoodPeriod trace start duration participants)
    (originFound : trace.stateAt start = some origin)
    (afterStart : start <= since)
    (firstFound : trace.stateAt since = some first)
    (early : time first <= limit)
    (room : limit + electionTimeout + jump <= time origin + duration)
    (adopted
      : forall node,
          node ∈ participants
          -> exists state,
              nodeState (proto first) node = some state /\ state.currentTerm = term)
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
          -> Not (state.role = .primary)
          -> canStartElection state node)
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
    : exists last cross,
        since <= last
        /\ trace.stepAt last = some cross
        /\ time cross.before <= limit + electionTimeout + jump
        /\ limit + electionTimeout + jump < time cross.after
        /\ forall node,
            node ∈ participants
            -> exists state,
                nodeState (proto cross.before) node = some state
                /\ state.currentTerm = term
                /\ state.primaryKnown = false := by
  have within : forall index point, since <= index
      -> trace.stateAt index = some point -> time point <= limit + electionTimeout + jump
      -> Within trace start duration index := by
    intro index point lower found early
    refine ⟨afterStart.trans lower, fun origin' point' originFound' found' => ?_⟩
    rw [originFound, Option.some.injEq] at originFound'
    rw [found, Option.some.injEq] at found'
    subst origin' point'
    exact early.trans room
  obtain ⟨last, cross, lower, crossed, near, far⟩ :=
    boundary admissible diverges firstFound (by linarith : time first <= limit + electionTimeout + jump)
  have crossWithin := within last cross.before lower (admissible.before crossed) near
  have firstWithin := within since first le_rfl firstFound (by linarith)
  refine ⟨last, cross, lower, crossed, near, far, ?_⟩
  intro node member
  obtain ⟨initial, initialFound, initialTerm⟩ := adopted node member
  have can := ready since first node initial firstWithin firstFound member initialFound
    (noLeader since first node initial firstWithin firstFound member initialFound initialTerm)
  have initialDeadline := eligible_deadline admissible timers firstFound initialFound can
  have eligible : forall index point, since <= index
      -> trace.stateAt index = some point -> time point <= limit + electionTimeout + jump
      -> node ∈ live point /\ exists state,
        nodeState (proto point) node = some state /\ canStartElection state node := by
    intro index point lower found early
    have bounded := within index point lower found early
    obtain ⟨state, stateFound, stateTerm⟩ := top_stays admissible firstFound initialFound initialTerm
      member lower found (low index bounded)
    exact ⟨good.participantsLive index point node bounded found member, state, stateFound,
      ready index point node state bounded found member stateFound
        (noLeader index point node state bounded found member stateFound stateTerm)⟩
  obtain ⟨fired, step, afterSince, stepped, firedEarly, action⟩ :=
    reset_or_event admissible timers diverges firstFound
      (by linarith : time first <= limit + electionTimeout + jump)
      (by linarith : deadline first node <= limit + electionTimeout)
      (le_refl (limit + electionTimeout + jump)) (firing node member) eligible
      (fun index step lower stepped early => overshoot index step node member
        (within index step.before lower (admissible.before stepped) early) stepped)
      (fun _ step => step.action = .local node (.timeout .election))
      (fun index step lower stepped early reset => Or.inr (resets index step node lower
        (within index step.before lower (admissible.before stepped) early) stepped member reset))
  have before : fired < last := by
    by_contra late
    have tooLate := busy_after_crossing admissible crossed near far (by omega) stepped
      (by rw [action]; simp)
    linarith
  have firedWithin := within fired step.before afterSince (admissible.before stepped) firedEarly
  have nextWithin := admissible.within_after firedWithin stepped (by rw [action]; simp)
  have selected : step.action.action = some (.local node (.timeout .election)) := by rw [action]; rfl
  obtain ⟨tr, ⟨actorEq, eventEq⟩, _⟩ := transition_acts (admissible.step stepped selected)
  have postFound : nodeState (proto step.after) node = some tr.post := by
    rw [← actorEq]
    exact Direct.nodeState_of_mem
      (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped))) tr.post_mem
  obtain ⟨post, postFound', postTerm⟩ := top_stays admissible firstFound initialFound initialTerm
    member (by omega) (Trace.stateAt_succ_of_stepAt stepped) (low (fired + 1) nextWithin)
  rw [postFound, Option.some.injEq] at postFound'
  subst post
  have postNotPrimary := noLeader (fired + 1) step.after node tr.post nextWithin
    (Trace.stateAt_succ_of_stepAt stepped) member postFound postTerm
  have postActive := eligible_not_none (ready (fired + 1) step.after node tr.post nextWithin
    (Trace.stateAt_succ_of_stepAt stepped) member postFound postNotPrimary)
  have ran : (startElection (Capabilities.record node) tr.pre node).run {} = some (tr.post, tr.outputs) := by
    simpa only [actorEq, eventEq, Model.Node.step, act] using tr.ran
  obtain ⟨_, _, unknown⟩ := timeout_unknown node tr.pre {} _ _ ran
  have unknown := unknown postNotPrimary postActive
  obtain ⟨state, stateFound, stateTerm⟩ := top_stays admissible firstFound initialFound initialTerm
    member lower (admissible.before crossed) (low last crossWithin)
  have frozen := state_frozen admissible (afterStart.trans (by omega : since <= fired + 1))
    (Trace.stateAt_succ_of_stepAt stepped) postFound postTerm member ready noLeader low
    (fun index step packet request lower within stepped delivered target payload =>
      old index step packet request (by omega) within stepped delivered (target ▸ member) payload)
    (by omega : fired + 1 <= last) crossWithin (admissible.before crossed) stateFound
  exact ⟨state, stateFound, stateTerm, frozen.2.2 unknown⟩

end CCFRaft.Proofs.Leadership.InitRaise
