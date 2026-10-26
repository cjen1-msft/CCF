module

public import CCFRaft.Proofs.Leadership.InitRaiseFlush

@[expose] public section

set_option linter.unusedSectionVars false

/-!
NOT IMPORTED BY `Properties`.

The first election activity in the top term must occur promptly.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

/-- A top-term timeout or a regular election request sent in that term. -/
def TermActivity {W : Type} [HasProtocol W Model.State] [HasNetwork W]
    (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (index term : Nat)
    : Prop :=
  (exists step node state,
    trace.stepAt index = some step
    /\ step.action = .local node (.timeout .election)
    /\ node ∈ participants
    /\ nodeState (proto step.before) node = some state
    /\ state.currentTerm = term)
  \/ exists packet request,
      trace.SentAt index packet
      /\ packet.envelope.source ∈ participants
      /\ packet.envelope.payload = .requestVoteRequest request
      /\ request.term = term

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- A participant already at the cap remains there while all terms stay capped. -/
theorem top_stays {start index term : Nat} {first point : W} {node : NodeID}
    {state : NodeState} {participants : Finset NodeID}
    (firstFound : trace.stateAt start = some first)
    (topFound : nodeState (proto first) node = some state)
    (topTerm : state.currentTerm = term) (member : node ∈ participants)
    (later : start <= index) (found : trace.stateAt index = some point)
    (low : Low trace participants index term)
    : exists next,
        nodeState (proto point) node = some next /\ next.currentTerm = term := by
  obtain ⟨next, nextFound, grows⟩ := CCFRaft.Proofs.StablePrimary.term_mono admissible later
    (Trace.nodeAt_eq_some.mpr ⟨first, firstFound, topFound⟩) found
  rw [Trace.nodeAt_of_stateAt found] at nextFound
  have cap := low point node next found member nextFound
  exact ⟨next, nextFound, by omega⟩

/-- With no raise or primary, an election activity in the top term happens
within one delay, one election timeout, and one scheduling overshoot. -/
theorem first_activity {start : Nat} {duration electionTimeout maxDelay jump : Real}
    {participants : Finset NodeID} {term : Nat}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
    (nonnegative : 0 <= maxDelay)
    (room : maxDelay + electionTimeout + jump <= duration)
    (good : GoodPeriod trace start duration participants)
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
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (noLeader
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.currentTerm = term
          -> Not (state.role = .primary))
    {first : W} {node : NodeID} {state : NodeState}
    (firstFound : trace.stateAt start = some first)
    (topFound : nodeState (proto first) node = some state)
    (topTerm : state.currentTerm = term) (member : node ∈ participants)
    (initial : 0 <= maxDelay + electionTimeout + jump)
    : exists index point,
        start <= index
        /\ trace.stateAt index = some point
        /\ time point <= time first + maxDelay + electionTimeout + jump
        /\ TermActivity trace participants index term := by
  have within : forall index point,
      start <= index -> trace.stateAt index = some point
      -> time point <= time first + maxDelay + electionTimeout + jump
      -> Within trace start duration index := by
    intro index point lower found early
    refine ⟨lower, fun first' point' firstFound' found' => ?_⟩
    rw [firstFound, Option.some.injEq] at firstFound'
    rw [found, Option.some.injEq] at found'
    subst first' point'
    linarith
  have firstWithin := within start first le_rfl firstFound (by linarith)
  have firstCan := ready start first node state firstWithin firstFound member topFound
    (noLeader start first node state firstWithin firstFound member topFound topTerm)
  have initialDeadline := eligible_deadline admissible timers firstFound topFound firstCan
  let Activity (index : Nat) (_ : Execution.Step W Liveness.Event) :=
    exists earlier point,
      start <= earlier /\ earlier <= index /\ trace.stateAt earlier = some point
      /\ time point <= time first + maxDelay + electionTimeout + jump
      /\ TermActivity trace participants earlier term
  have eligible : forall index point,
      start <= index -> trace.stateAt index = some point
      -> time point <= time first + maxDelay + electionTimeout + jump
      -> node ∈ live point /\ exists state,
        nodeState (proto point) node = some state /\ canStartElection state node := by
    intro index point lower found early
    have bounded := within index point lower found early
    obtain ⟨next, nextFound, nextTerm⟩ := top_stays admissible firstFound topFound topTerm
      member lower found (low index bounded)
    exact ⟨good.participantsLive index point node bounded found member, next, nextFound,
      ready index point node next bounded found member nextFound
        (noLeader index point node next bounded found member nextFound nextTerm)⟩
  have classify : forall index step,
      start <= index -> trace.stepAt index = some step
      -> time step.before <= time first + maxDelay + electionTimeout + jump
      -> ElectionReset step node
      -> time step.before <= time first + maxDelay \/ Activity index step := by
    intro index step lower stepped early reset
    have bounded := within index step.before lower (admissible.before stepped) early
    obtain ⟨before, beforeFound, beforeTerm⟩ := top_stays admissible firstFound topFound topTerm
      member lower (admissible.before stepped) (low index bounded)
    cases action : step.action with
    | «local» actor input =>
        cases input with
        | timeout kind =>
            have same : actor = node := by simpa [ElectionReset, action] using reset
            subst actor
            cases kind with
            | election =>
                exact Or.inr ⟨index, step.before, lower, le_rfl, admissible.before stepped,
                  early, Or.inl ⟨step, node, before, stepped, action, member, beforeFound, beforeTerm⟩⟩
            | checkQuorum =>
                exact (good.noQuorumChecks index step node bounded stepped member action).elim
        | _ => simp [ElectionReset, action] at reset
    | deliver packet =>
        have busy : Not (step.action = .idle) := by rw [action]; simp
        have nextWithin := admissible.within_after bounded stepped busy
        have nextFound := Trace.stateAt_succ_of_stepAt stepped
        obtain ⟨after, afterFound, afterTerm⟩ := top_stays admissible firstFound topFound topTerm
          member (by omega) nextFound (low (index + 1) nextWithin)
        simp only [ElectionReset, action, beforeFound, afterFound] at reset
        have targetIn : packet.envelope.target ∈ participants := reset.1 ▸ member
        have sourceIn := good.isolated index step packet.envelope bounded stepped
          (by rw [action]; rfl) targetIn
        rcases reset.2 with raised | reset
        · omega
        · cases payload : packet.envelope.payload with
          | appendEntriesRequest request =>
              simp only [payload] at reset
              rcases reset with raised | ⟨eq, _⟩
              · have queued := admissible.consumed_pending stepped
                  (by rw [action]; rfl)
                obtain ⟨source, sourceFound, cap⟩ := pending_term_le admissible
                  (admissible.before stepped) queued
                have sourceLow := low index bounded step.before packet.envelope.source
                  source (admissible.before stepped) sourceIn sourceFound
                simp only [payload, Message.term] at cap
                omega
              · exact Or.inl (append_delivered_early admissible delay good ready noLeader
                  firstFound bounded stepped action targetIn payload (eq.symm.trans beforeTerm))
          | requestVoteRequest request =>
              simp only [payload] at reset
              have requestTerm : request.term = term := reset.1.symm.trans beforeTerm
              obtain ⟨sent, earlier, sentAt⟩ := admissible.consumed_sent stepped
                (by rw [action]; rfl)
              obtain ⟨sentStep, _, _, sentStepped, _, _, _, _, _, sentTime⟩ :=
                admissible.sentAt_emitted sentAt
              by_cases old : sent < start
              · have sentEarly := admissible.time_le (Nat.le_of_lt old)
                  (admissible.before sentStepped) firstFound
                have queued := admissible.consumed_pending stepped (by rw [action]; rfl)
                have alive := good.participantsLive index step.before packet.envelope.target
                  bounded (admissible.before stepped) targetIn
                have deadline := CCFRaft.Proofs.Liveness.pending_deadline delay
                  (admissible.before stepped) queued alive
                rw [sentTime] at deadline
                exact Or.inl (by linarith)
              · have elapsed := admissible.time_le (Nat.le_of_lt earlier)
                  (admissible.before sentStepped) (admissible.before stepped)
                exact Or.inr ⟨sent, sentStep.before, by omega, by omega,
                  admissible.before sentStepped, elapsed.trans early,
                  Or.inr ⟨packet, request, sentAt, sourceIn, payload, requestTerm⟩⟩
          | _ => simp [payload] at reset
    | _ => simp [ElectionReset, action] at reset
  obtain ⟨_, _, _, _, _, earlier, point, lower, _, found, early, activity⟩ :=
    reset_or_event admissible timers diverges firstFound (by linarith : time first <=
      time first + maxDelay + electionTimeout + jump)
      (by linarith : deadline first node <= time first + maxDelay + electionTimeout)
      (by linarith : time first + maxDelay + electionTimeout + jump <=
        time first + maxDelay + electionTimeout + jump)
      (firing node member) eligible
      (fun index step lower stepped early =>
        overshoot index step node member
          (within index step.before lower (admissible.before stepped) early) stepped)
      Activity classify
  exact ⟨earlier, point, lower, found, early, activity⟩

end CCFRaft.Proofs.Leadership.InitRaise
