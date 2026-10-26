module

public import CCFRaft.Proofs.Leadership.InitIncumbentFinish

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Two delivered incumbent heartbeats settle every participant before the horizon.
-/

namespace CCFRaft.Proofs.Leadership.InitIncumbent

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat} {duration heartbeat maxDelay : Real}
  {participants members : Finset NodeID}
  {leader : NodeID} {term : Nat}

include admissible

/-- The next incumbent heartbeat is delivered within one heartbeat plus one delay. -/
theorem heartbeat_delivered
    (delay : trace.Valid (boundedDelayModel maxDelay)) (diverges : TimeDiverges trace)
    (heartbeats : trace.HeartbeatScheduling (some heartbeat))
    (nonnegative : 0 <= maxDelay)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (membership
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> Membership participants members (proto point))
    (subset : participants ⊆ members) (leaderIn : leader ∈ participants)
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {first origin : W} (firstFound : trace.stateAt start = some first)
    {base : Nat} (originFound : trace.stateAt base = some origin)
    (within : Within trace start duration base)
    (room : time origin + heartbeat + maxDelay <= time first + duration)
    {peer : NodeID} (peerIn : peer ∈ participants) (different : Not (peer = leader))
    : exists index step packet request,
        base < index
        /\ trace.stepAt index = some step
        /\ step.action = .deliver packet
        /\ packet.envelope.source = leader
        /\ packet.envelope.target = peer
        /\ packet.envelope.payload = .appendEntriesRequest request
        /\ request.term = term
        /\ time step.before <= time origin + heartbeat + maxDelay := by
  obtain ⟨sent, packet, request, later, sentAt, sourceEq, targetEq, payload, requestTerm, early⟩ :=
    send_by admissible good active membership subset leaderIn leads heartbeats firstFound
      originFound within (by linarith) peerIn different
  obtain ⟨send, _, _, sendAt, _, _, _, _, _, sentTime⟩ := admissible.sentAt_emitted sentAt
  have sentWithin : Within trace start duration sent := by
    refine ⟨within.1.trans later, fun f p ff pf => ?_⟩
    rw [firstFound, Option.some.injEq] at ff
    rw [admissible.before sendAt, Option.some.injEq] at pf
    subst f p
    rw [sentTime] at early
    linarith
  obtain ⟨index, step, afterSend, stepped, timely, delivered⟩ :=
    InitRaise.sent_delivered admissible delay diverges good firstFound sentWithin sentAt
      (sourceEq ▸ leaderIn) (targetEq ▸ peerIn) (by linarith)
  exact ⟨
    index,
    step,
    packet,
    request,
    by omega,
    stepped,
    delivered,
    sourceEq,
    targetEq,
    payload,
    requestTerm,
    by linarith
  ⟩

/-- Every other participant is settled and has reset after the incumbent-window origin. -/
theorem settled_by {electionTimeout : Real}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout)) (diverges : TimeDiverges trace)
    (heartbeats : trace.HeartbeatScheduling (some heartbeat))
    (nonnegative : 0 <= maxDelay) (heartbeatNonnegative : 0 <= heartbeat)
    (room : 2 * (heartbeat + maxDelay) <= duration)
    (ratio : duration < electionTimeout / 2)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (matching : Window.Matching trace start duration participants)
    (membership
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> Membership participants members (proto point))
    (subset : participants ⊆ members) (leaderIn : leader ∈ participants)
    (roled
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> Not (state.role = .none))
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {first : W} (firstFound : trace.stateAt start = some first) {stop : Nat}
    {cross : Execution.Step W Liveness.Event} (lower : start <= stop)
    (crossed : trace.stepAt stop = some cross)
    (near : time cross.before <= time first + duration)
    (far : time first + duration < time cross.after)
    : forall peer,
        peer ∈ participants
        -> Not (peer = leader)
        -> exists state resetIndex reset,
            nodeState (proto cross.before) peer = some state
            /\ state.currentTerm = term
            /\ state.role = .follower
            /\ state.primaryKnown = true
            /\ start <= resetIndex
            /\ resetIndex < stop
            /\ trace.stepAt resetIndex = some reset
            /\ ElectionReset reset peer := by
  have withinTime : forall index point, start <= index -> trace.stateAt index = some point ->
      time point <= time first + duration -> Within trace start duration index := by
    intro index point lower found early
    refine ⟨lower, fun f p ff pf => ?_⟩
    rw [firstFound, Option.some.injEq] at ff
    rw [found, Option.some.injEq] at pf
    subst f p
    exact early
  have firstWithin := withinTime start first le_rfl firstFound (by linarith)
  have stopWithin := withinTime stop cross.before lower (admissible.before crossed) near
  have beforeStop : forall index step, trace.stepAt index = some step ->
      Not (step.action = .idle) -> time step.before <= time first + duration -> index < stop := by
    intro index step stepped busy early
    by_contra later
    have late := InitRaise.busy_after_crossing admissible crossed near far
      (by omega) stepped busy
    linarith
  intro peer peerIn different
  obtain ⟨one, firstDelivery, packet, request, afterStart, oneAt, delivered, sourceEq, targetEq,
      payload, requestTerm, early⟩ :=
    heartbeat_delivered admissible delay diverges heartbeats nonnegative good active membership subset
      leaderIn leads firstFound firstFound firstWithin (by linarith) peerIn different
  have oneWithin := withinTime one firstDelivery.before afterStart.le (admissible.before oneAt) (by linarith)
  have oneBusy : Not (firstDelivery.action = .idle) := by rw [delivered]; simp
  have oneStop := beforeStop one firstDelivery oneAt oneBusy (by linarith)
  have reset := delivery_resets admissible matching low oneWithin oneAt delivered
    (targetEq ▸ peerIn) (by simpa [targetEq, sourceEq] using different) payload requestTerm
  rw [targetEq] at reset
  obtain ⟨follower, followerFound, followerTerm, followerRole⟩ :=
    delivered_follower admissible low roled leads oneWithin oneAt delivered
      (targetEq ▸ peerIn) (by simpa [targetEq] using different) payload requestTerm
  rw [targetEq] at followerFound
  have oneAfterFound := Trace.stateAt_succ_of_stepAt oneAt
  have oneAfterWithin := admissible.within_after oneWithin oneAt oneBusy
  have unchanged := (admissible.timing.next oneAt).2 oneBusy
  have noTimeout : forall index step, one < index ->
      trace.stepAt index = some step -> Within trace start duration index ->
      Not (step.action = .local peer (.timeout .election)) := by
    intro index step later stepped within fired
    have scheduled := CCFRaft.Proofs.Liveness.electionScheduling_of_timerModel
      admissible.coherent admissible.timing timers one index firstDelivery step peer later
      oneAt stepped fired reset
    have elapsed := admissible.time_le afterStart.le firstFound (admissible.before oneAt)
    have early := within.2 first step.before firstFound (admissible.before stepped)
    linarith
  obtain ⟨two, secondDelivery, packet2, request2, afterOne, twoAt, delivered2, sourceEq2, targetEq2,
      payload2, requestTerm2, early2⟩ :=
    heartbeat_delivered admissible delay diverges heartbeats nonnegative good active membership subset
      leaderIn leads firstFound oneAfterFound oneAfterWithin (by rw [unchanged]; linarith) peerIn different
  have twoWithin := withinTime two secondDelivery.before (by omega) (admissible.before twoAt)
    (by rw [unchanged] at early2; linarith)
  have twoBusy : Not (secondDelivery.action = .idle) := by rw [delivered2]; simp
  have twoStop := beforeStop two secondDelivery twoAt twoBusy
    (twoWithin.2 first secondDelivery.before firstFound (admissible.before twoAt))
  obtain ⟨before, beforeFound, beforeTerm, beforeRole⟩ :=
    follower_kept admissible low roled leads oneAfterFound peerIn different followerFound followerTerm
      followerRole (by omega) afterOne.le (admissible.before twoAt) twoWithin
      (fun index step lo hi stepped => noTimeout index step (by omega) stepped
        (InitRaise.within_before admissible twoWithin (admissible.before twoAt) (by omega) hi.le))
  obtain ⟨primary, primaryFound, primaryTerm, primaryRole⟩ := leads two secondDelivery.before
    twoWithin (admissible.before twoAt)
  obtain ⟨settled, settledFound, settledTerm, settledRole, settledKnown⟩ :=
    delivered_known admissible active matching twoWithin twoAt delivered2
      (targetEq2 ▸ peerIn) (by simpa [targetEq2, sourceEq2] using different) payload2 requestTerm2
      (targetEq2 ▸ beforeFound) beforeTerm beforeRole
      (sourceEq2 ▸ primaryFound) primaryTerm primaryRole
  rw [targetEq2] at settledFound
  obtain ⟨state, stateFound, stateTerm, stateRole, stateKnown⟩ :=
    settled_kept admissible good active low (Trace.stateAt_succ_of_stepAt twoAt) peerIn
      settledFound settledTerm settledRole settledKnown (by omega) (by omega)
      (admissible.before crossed) stopWithin
      (fun index step lo hi stepped => noTimeout index step (by omega) stepped
        (InitRaise.within_before admissible stopWithin (admissible.before crossed) (by omega) hi.le))
  exact ⟨state, one, firstDelivery, stateFound, stateTerm, stateRole, stateKnown,
    afterStart.le, oneStop, oneAt, reset⟩

end CCFRaft.Proofs.Leadership.InitIncumbent
