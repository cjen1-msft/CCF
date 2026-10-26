module

public import CCFRaft.Proofs.Leadership.InitRaiseConverge

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Regular vote requests flush after every participant adopts the top term.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- Once all participants have adopted a term, none sends a regular request
for that term: starting a candidacy strictly increases the sender's term. -/
theorem vote_sent_before {settled sent term : Nat} {point : W}
    {participants : Finset NodeID}
    (found : trace.stateAt settled = some point)
    (adopted
      : forall node,
          node ∈ participants
          -> exists state,
              nodeState (proto point) node = some state /\ state.currentTerm = term)
    {packet : Packet} {request : RequestVoteRequest}
    (sentAt : trace.SentAt sent packet) (member : packet.envelope.source ∈ participants)
    (payload : packet.envelope.payload = .requestVoteRequest request)
    (requestTerm : request.term = term)
    : sent < settled := by
  by_contra early
  obtain ⟨step, action, emitted, stepped, selected, output, sentMem, _, _, _⟩ :=
    admissible.sentAt_emitted sentAt
  obtain ⟨tr, _, output'⟩ := transition_acts (admissible.step stepped selected)
  rw [output', Option.some.injEq] at output
  subst emitted
  have sends := CCFRaft.Proofs.Safety.Summary.sends tr.summary packet.envelope sentMem
  have sourceIn : tr.actor ∈ participants := sends.1 ▸ member
  obtain ⟨state, stateFound, stateTerm⟩ := adopted tr.actor sourceIn
  obtain ⟨before, beforeFound, grows⟩ := CCFRaft.Proofs.StablePrimary.term_mono admissible
    (by omega : settled <= sent)
    (Trace.nodeAt_eq_some.mpr ⟨point, found, stateFound⟩) (admissible.before stepped)
  rw [Trace.nodeAt_of_stateAt (admissible.before stepped), tr.found, Option.some.injEq] at beforeFound
  subst before
  have sent := sends.2
  simp only [payload] at sent
  omega

/-- Requests for a term arrive at most one delay after everyone adopts it. -/
theorem vote_delivered_early {start settled index term : Nat} {duration maxDelay : Real}
    {participants : Finset NodeID} {point : W}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (good : GoodPeriod trace start duration participants)
    (found : trace.stateAt settled = some point)
    (adopted
      : forall node,
          node ∈ participants
          -> exists state,
              nodeState (proto point) node = some state /\ state.currentTerm = term)
    {step : Execution.Step W Liveness.Event} {packet : Packet}
    {request : RequestVoteRequest} (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) (delivered : step.action = .deliver packet)
    (member : packet.envelope.target ∈ participants)
    (payload : packet.envelope.payload = .requestVoteRequest request)
    (requestTerm : request.term = term)
    : time step.before <= time point + maxDelay := by
  have consumed : step.action.consumedPacket = some packet := by rw [delivered]; rfl
  have sourceIn := good.isolated index step packet.envelope within stepped
    (by rw [delivered]; rfl) member
  obtain ⟨sent, _, sentAt⟩ := admissible.consumed_sent stepped consumed
  have old := vote_sent_before admissible found adopted sentAt sourceIn payload requestTerm
  obtain ⟨sentStep, _, _, sentStepped, _, _, _, _, _, sentTime⟩ :=
    admissible.sentAt_emitted sentAt
  have early := admissible.time_le (Nat.le_of_lt old) (admissible.before sentStepped) found
  have queued := admissible.consumed_pending stepped consumed
  have alive := good.participantsLive index step.before packet.envelope.target
    within (admissible.before stepped) member
  have deadline := CCFRaft.Proofs.Liveness.pending_deadline delay
    (admissible.before stepped) queued alive
  rw [sentTime] at deadline
  linarith

/-- A non-idle action at or after a crossing happens strictly beyond its bound. -/
theorem busy_after_crossing {crossing index : Nat}
    {cross step : Execution.Step W Liveness.Event} {bound : Real}
    (crossed : trace.stepAt crossing = some cross)
    (near : time cross.before <= bound) (far : bound < time cross.after)
    (later : crossing <= index) (stepped : trace.stepAt index = some step)
    (busy : Not (step.action = .idle))
    : bound < time step.before := by
  by_cases same : index = crossing
  · subst index
    rw [crossed, Option.some.injEq] at stepped
    subst step
    have sameTime := (admissible.timing.next crossed).2 busy
    linarith
  · exact far.trans_le (admissible.time_le (by omega : crossing + 1 <= index)
      (Trace.stateAt_succ_of_stepAt crossed) (admissible.before stepped))

/-- After old AppendEntries and vote requests flush, every reset is the
participant's own election timeout. -/
theorem reset_is_timeout {start settled crossing index term : Nat}
    {duration maxDelay bound : Real} {participants : Finset NodeID} {first point : W}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (good : GoodPeriod trace start duration participants)
    (firstFound : trace.stateAt start = some first)
    (settledFound : trace.stateAt settled = some point)
    (adopted
      : forall node,
          node ∈ participants
          -> exists state,
              nodeState (proto point) node = some state /\ state.currentTerm = term)
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
    {cross step : Execution.Step W Liveness.Event}
    (crossed : trace.stepAt crossing = some cross)
    (near : time cross.before <= bound) (far : bound < time cross.after)
    (aeBound : time first + maxDelay <= bound)
    (voteBound : time point + maxDelay <= bound)
    (later : crossing <= index) (afterSettled : settled <= index)
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step)
    {node : NodeID} (member : node ∈ participants) (reset : ElectionReset step node)
    : step.action = .local node (.timeout .election) := by
  have busy : Not (step.action = .idle) := by
    intro idle
    simp [ElectionReset, idle] at reset
  have late := busy_after_crossing admissible crossed near far later stepped busy
  obtain ⟨state, stateFound, stateTerm⟩ := adopted node member
  obtain ⟨before, beforeFound, beforeTerm⟩ := top_stays admissible settledFound stateFound
    stateTerm member afterSettled (admissible.before stepped) (low index within)
  have nextWithin := admissible.within_after within stepped busy
  obtain ⟨after, afterFound, afterTerm⟩ := top_stays admissible settledFound stateFound
    stateTerm member (by omega) (Trace.stateAt_succ_of_stepAt stepped) (low (index + 1) nextWithin)
  cases action : step.action with
  | «local» actor input =>
      cases input with
      | timeout kind =>
          have same : actor = node := by simpa [ElectionReset, action] using reset
          subst actor
          cases kind with
          | election => rfl
          | checkQuorum =>
              exact (good.noQuorumChecks index step node within stepped member action).elim
      | _ => simp [ElectionReset, action] at reset
  | deliver packet =>
      simp only [ElectionReset, action, beforeFound, afterFound] at reset
      have targetIn : packet.envelope.target ∈ participants := reset.1 ▸ member
      have sourceIn := good.isolated index step packet.envelope within stepped
        (by rw [action]; rfl) targetIn
      rcases reset.2 with raised | reset
      · omega
      · cases payload : packet.envelope.payload with
        | appendEntriesRequest request =>
            simp only [payload] at reset
            rcases reset with raised | ⟨eq, _⟩
            · have queued := admissible.consumed_pending stepped (by rw [action]; rfl)
              obtain ⟨source, sourceFound, cap⟩ := pending_term_le admissible
                (admissible.before stepped) queued
              have sourceLow := low index within step.before packet.envelope.source
                source (admissible.before stepped) sourceIn sourceFound
              simp only [payload, Message.term] at cap
              omega
            · have early := append_delivered_early admissible delay good ready noLeader
                firstFound within stepped action targetIn payload (eq.symm.trans beforeTerm)
              linarith
        | requestVoteRequest request =>
            simp only [payload] at reset
            have early := vote_delivered_early admissible delay good settledFound adopted
              within stepped action targetIn payload (reset.1.symm.trans beforeTerm)
            linarith
        | _ => simp [payload] at reset
  | _ => simp [ElectionReset, action] at reset

end CCFRaft.Proofs.Leadership.InitRaise
