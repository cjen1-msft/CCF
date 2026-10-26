module

public import CCFRaft.Proofs.Leadership.InitRaiseNode
public import CCFRaft.Proofs.Leadership.InitRaiseTime

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Old AppendEntries requests flush within one network delay in INIT.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- An earlier recorded index in the same interval remains in its time window. -/
theorem within_before {start duration index earlier} {point : W}
    (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    (lower : start <= earlier) (upper : earlier <= index)
    : Within trace start duration earlier := by
  refine ⟨lower, fun first before firstFound beforeFound => ?_⟩
  exact (admissible.time_le upper beforeFound found).trans
    (within.2 first point firstFound found)

/-- A participant remains live even across the idle step leaving a good window. -/
theorem participant_live_after {start : Nat} {duration : Real}
    {participants : Finset NodeID} (good : GoodPeriod trace start duration participants)
    {index : Nat} {step : Execution.Step W Liveness.Event}
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (member : node ∈ participants)
    : node ∈ live step.after := by
  have alive := good.participantsLive index step.before node within
    (admissible.before stepped) member
  by_contra dead
  have crashed := admissible.crashes stepped alive dead
  have next := admissible.within_after within stepped
    (fun idle => by rw [crashed] at idle; cases idle)
  exact dead (good.participantsLive (index + 1) step.after node next
    (Trace.stateAt_succ_of_stepAt stepped) member)

/-- A packet sent inside a good window is delivered by its delay deadline,
provided that deadline is still inside the window. -/
theorem sent_delivered {start sent : Nat} {duration maxDelay : Real}
    {participants : Finset NodeID} {first : W} {packet : Packet}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (diverges : TimeDiverges trace)
    (good : GoodPeriod trace start duration participants)
    (firstFound : trace.stateAt start = some first)
    (within : Within trace start duration sent)
    (sentAt : trace.SentAt sent packet)
    (sourceIn : packet.envelope.source ∈ participants)
    (targetIn : packet.envelope.target ∈ participants)
    (room : packet.sentAt + maxDelay <= time first + duration)
    : exists index step,
        sent < index
        /\ trace.stepAt index = some step
        /\ time step.before <= packet.sentAt + maxDelay
        /\ step.action = .deliver packet := by
  obtain ⟨sentStep, sentStepped, queued, _⟩ := sentAt
  have alive := participant_live_after admissible good within sentStepped targetIn
  obtain ⟨index, step, later, stepped, early, consumed⟩ :=
    admissible.consumed_within delay diverges (Trace.stateAt_succ_of_stepAt sentStepped)
      queued alive
  have bounded : Within trace start duration index := by
    refine ⟨within.1.trans (Nat.le_of_lt later), fun first' point found' found => ?_⟩
    rw [firstFound, Option.some.injEq] at found'
    rw [admissible.before stepped, Option.some.injEq] at found
    subst first' point
    exact early.trans room
  refine ⟨index, step, later, stepped, early, ?_⟩
  rcases consumed with consumed | crashed
  · cases action : step.action with
    | deliver p =>
        simp only [action, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
        exact congrArg Liveness.Event.deliver consumed
    | drop p =>
        simp only [action, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
        subst p
        exact (good.lossless index step packet bounded stepped action ⟨sourceIn, targetIn⟩).elim
    | _ => simp [action, Liveness.Event.consumedPacket] at consumed
  · have alive := participant_live_after admissible good bounded stepped targetIn
    have crash := admissible.crash.next stepped
    simp [crashModel, crashSystem, crashed, Liveness.Event.actor, Liveness.Event.liveAfter] at crash
    rw [← crash.2] at alive
    exact (Finset.notMem_erase _ _ alive).elim

/-- AppendEntries of an absent primary's term were sent before the window. -/
theorem append_sent_before {start : Nat} {duration : Real}
    {participants : Finset NodeID} {term : Nat}
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
    {index sent : Nat} {point : W} {packet : Packet} {request : AppendEntriesRequest}
    (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    (sentAt : trace.SentAt sent packet) (earlier : sent < index)
    (member : packet.envelope.source ∈ participants)
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term)
    : sent < start := by
  by_contra late
  have lower : start <= sent := by omega
  obtain ⟨sentStep, action, emitted, stepped, selected, output, emittedMem, _, _, _⟩ :=
    admissible.sentAt_emitted sentAt
  obtain ⟨tr, _, output'⟩ := transition_acts (admissible.step stepped selected)
  rw [output', Option.some.injEq] at output
  subst emitted
  have summary := tr.summary
  have sends := CCFRaft.Proofs.Safety.Summary.sends summary packet.envelope emittedMem
  have actorIn : tr.actor ∈ participants := sends.1 ▸ member
  have nextFound := Trace.stateAt_succ_of_stepAt stepped
  have postFound := Direct.nodeState_of_mem
    (Direct.keys_nodup (admissible.reachable nextFound)) tr.post_mem
  have postWithin := within_before admissible within found (by omega) (by omega : sent + 1 <= index)
  have preWithin := within_before admissible within found lower (by omega : sent <= index)
  have sentTerm : request.term = tr.post.currentTerm := by
    have ok := sends.2
    simp only [payload] at ok
    exact ok.1.2.1
  have postTerm : tr.post.currentTerm = term := sentTerm.symm.trans requestTerm
  have postNotPrimary := noLeader (sent + 1) sentStep.after tr.actor tr.post
    postWithin nextFound actorIn postFound postTerm
  have postEligible := ready (sent + 1) sentStep.after tr.actor tr.post
    postWithin nextFound actorIn postFound postNotPrimary
  rcases (append_sender summary emittedMem payload (eligible_not_none postEligible)).2.2 with
    ⟨primary, eq⟩ | ⟨primary, _⟩
  · exact noLeader sent sentStep.before tr.actor tr.pre preWithin
      (admissible.before stepped) actorIn tr.found (eq.trans requestTerm) primary
  · exact postNotPrimary primary

/-- Every delivered AppendEntries request of the absent primary's term arrives
within one delay of the window's start. -/
theorem append_delivered_early {start : Nat} {duration maxDelay : Real}
    {participants : Finset NodeID} {term : Nat}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (good : GoodPeriod trace start duration participants)
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
    {first : W} (firstFound : trace.stateAt start = some first)
    {index : Nat} {step : Execution.Step W Liveness.Event}
    {packet : Packet} {request : AppendEntriesRequest}
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step)
    (delivered : step.action = .deliver packet)
    (member : packet.envelope.target ∈ participants)
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term)
    : time step.before <= time first + maxDelay := by
  have consumed : step.action.consumedPacket = some packet := by
    rw [delivered]
    rfl
  have delivered' : step.action.delivered = some packet.envelope := by
    rw [delivered]
    rfl
  have sourceIn := good.isolated index step packet.envelope within stepped delivered' member
  obtain ⟨sent, earlier, sentAt⟩ := admissible.consumed_sent stepped consumed
  have old := append_sent_before admissible ready noLeader within
    (admissible.before stepped) sentAt earlier sourceIn payload requestTerm
  obtain ⟨sentStep, _, _, sentStepped, _, _, _, _, _, sentTime⟩ :=
    admissible.sentAt_emitted sentAt
  have early := admissible.time_le (Nat.le_of_lt old)
    (admissible.before sentStepped) firstFound
  have queued := admissible.consumed_pending stepped consumed
  have alive := good.participantsLive index step.before packet.envelope.target
    within (admissible.before stepped) member
  have deadline := CCFRaft.Proofs.Liveness.pending_deadline delay
    (admissible.before stepped) queued alive
  rw [sentTime] at deadline
  linarith

end CCFRaft.Proofs.Leadership.InitRaise
