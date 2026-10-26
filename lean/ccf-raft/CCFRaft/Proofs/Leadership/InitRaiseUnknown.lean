module

public import CCFRaft.Proofs.Leadership.InitRaiseReset

@[expose] public section

set_option linter.unusedSectionVars false

/-!
NOT IMPORTED BY `Properties`.

After a timeout, a participant stays unaware of a primary once current-term
AppendEntries have flushed.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)

variable [Config.InitialConfiguration]

/-- A live protocol role other than primary knows no primary. -/
def UnknownResult (state : NodeState) : Prop :=
  Not (state.role = .primary) -> Not (state.role = .none) -> state.primaryKnown = false

/-- Observing a message never introduces knowledge of a primary. -/
theorem observe_unknown {state : NodeState} (unknown : state.primaryKnown = false)
    (message : Message)
    : (observeTerm state message).primaryKnown = false := by
  cases message <;> simp only [observeTerm, updateTerm] <;>
    (try split_ifs) <;> simp_all [becomeAwareOfNewTerm]

section Steps

variable (self : NodeID)
local notation "caps" => (Capabilities.record self : Caps)

/-- A newly created candidate that does not become primary knows none. -/
theorem candidate_unknown (state : NodeState)
    : Sends (fun after _ => UnknownResult after) (becomeCandidate caps state self) := by
  refine Sends.mono (candidate_broadcast self state) fun after _ result notPrimary active => ?_
  rw [(result notPrimary active).1]
  rfl

/-- An unsuccessful election preserves the candidate's lack of primary knowledge. -/
theorem elect_unknown (state : NodeState) (unknown : state.primaryKnown = false)
    : Sends (fun after _ => UnknownResult after) (electIfQuorum caps self state) := by
  refine Sends.mono (elect_nonleader self state) fun after _ result notPrimary active => ?_
  rw [(result notPrimary active).1]
  exact unknown

/-- A timeout clears primary knowledge unless it elects the node primary. -/
theorem timeout_unknown (state : NodeState)
    : Sends (fun after _ => UnknownResult after) (startElection caps state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ _ _ => ?_
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => candidate_unknown self _) fun _ => ?_
  exact Sends.bind' (broadcast_sends self _ _) fun _ _ _ => Sends.pure' (fun _ _ => rfl)

/-- Without a primary or current-term AppendEntries, reception preserves ignorance. -/
theorem receive_unknown (state : NodeState) (source : NodeID) (message : Message)
    (unknown : state.primaryKnown = false) (notPrimary : Not (state.role = .primary))
    (old
      : forall request,
          message = .appendEntriesRequest request -> request.term < state.currentTerm)
    : Sends (fun after _ => UnknownResult after)
        (receive caps self source state message) := by
  have observed := observe_unknown unknown message
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (fun _ _ => unknown)) fun _ => ?_
  cases message with
  | appendEntriesRequest request =>
      have older := old request rfl
      have observed : observeTerm state (.appendEntriesRequest request) = state := by
        simp only [observeTerm, Message.term]
        exact updateTerm_of_le (Nat.le_of_lt older)
      rw [observed]
      unfold handleAppendEntriesRequest
      simp only [ne_of_lt older, false_and, ite_false, older, true_or, ite_true]
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (fun _ _ => unknown)
  | appendEntriesResponse response =>
      simp only [observeTerm, ite_false, handleAppendEntriesResponse,
        bne_iff_ne, ne_eq, notPrimary, not_false_eq_true, ite_true]
      exact Sends.pure' (fun _ _ => unknown)
  | requestVoteRequest request =>
      unfold handleRequestVoteRequest
      refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
      intro _ _
      split <;> exact observed
  | requestPreVoteRequest request =>
      unfold handleRequestPreVoteRequest
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (fun _ _ => observed)
  | requestVoteResponse response =>
      unfold handleRequestVoteResponse
      exact Sends.ite' (fun _ => elect_unknown self _ observed) fun _ =>
        Sends.pure' (fun _ _ => observed)
  | requestPreVoteResponse response =>
      unfold handleRequestPreVoteResponse
      refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (fun _ _ => observed)
      exact Sends.ite' (fun _ => candidate_unknown self _) fun _ =>
        Sends.pure' (fun _ _ => observed)
  | proposeRequestVoteRequest term =>
      unfold handleProposeRequestVoteRequest
      exact Sends.ite' (fun _ => candidate_unknown self _) fun _ =>
        Sends.pure' (fun _ _ => observed)

/-- A non-primary's local actions do not introduce primary knowledge. -/
theorem local_unknown (state : NodeState) (input : Input)
    (notPrimary : Not (state.role = .primary))
    : Sends (fun after _ => UnknownResult after) (act caps self state input) := by
  cases input with
  | timeout kind =>
      cases kind with
      | election => exact timeout_unknown self state
      | checkQuorum =>
          simp only [act]
          unfold checkQuorum
          exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ =>
            (notPrimary allowed.1).elim
  | append entries =>
      simp only [act]
      unfold appendBatch
      exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed.1).elim
  | sendEntries destination ends =>
      simp only [act]
      unfold sendEntries
      exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed.1).elim
  | nominateSuccessor =>
      simp only [act]
      unfold nominateSuccessor
      exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed).elim

/-- A participant that knows no primary keeps that property after old-message flushing. -/
theorem step_unknown (self : NodeID) (state : NodeState) (event : Model.Node.Event)
    (unknown : state.primaryKnown = false) (notPrimary : Not (state.role = .primary))
    (old
      : forall source request,
          event = .receive source (.appendEntriesRequest request)
          -> request.term < state.currentTerm)
    : Sends (fun after _ => UnknownResult after)
        (Model.Node.step (Capabilities.record self) self state event) := by
  cases event with
  | internal input => exact local_unknown self state input notPrimary
  | receive source message =>
      exact receive_unknown self state source message unknown notPrimary
        (fun request eq => old source request (by rw [eq]))

end Steps

section Trace

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

omit admissible in
/-- A node-local reception comes from the packet delivered by the recorded event. -/
theorem received_packet {step : Execution.Step W Liveness.Event} {action : Model.Action}
    {actor source : NodeID} {message : Message} {event : Model.Node.Event}
    (selected : step.action.action = some action)
    (acts : CCFRaft.Proofs.StablePrimary.Acts action actor event)
    (received : event = .receive source message)
    : exists packet,
        step.action = .deliver packet
        /\ packet.envelope.target = actor
        /\ packet.envelope.source = source
        /\ packet.envelope.payload = message := by
  cases eq : step.action with
  | deliver packet =>
      simp only [eq, Liveness.Event.action, Option.some.injEq] at selected
      subst action
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at received
      cases received
      exact ⟨packet, rfl, actorEq.symm, rfl, rfl⟩
  | «local» node input =>
      simp only [eq, Liveness.Event.action, Option.some.injEq] at selected
      subst action
      rw [acts.2] at received
      cases received
  | _ => simp [eq, Liveness.Event.action] at selected

/-- After a crossing past the AppendEntries flush bound, all later AppendEntries
delivered to participants are strictly older than the top term. -/
theorem append_old_after {start crossing index term : Nat}
    {duration maxDelay bound : Real} {participants : Finset NodeID} {first : W}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (good : GoodPeriod trace start duration participants)
    (firstFound : trace.stateAt start = some first)
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
    (low : Low trace participants index term)
    {cross step : Execution.Step W Liveness.Event}
    (crossed : trace.stepAt crossing = some cross)
    (near : time cross.before <= bound) (far : bound < time cross.after)
    (aeBound : time first + maxDelay <= bound)
    (later : crossing <= index)
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step)
    {packet : Packet} {request : AppendEntriesRequest}
    (delivered : step.action = .deliver packet)
    (member : packet.envelope.target ∈ participants)
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : request.term < term := by
  have sourceIn := good.isolated index step packet.envelope within stepped
    (by rw [delivered]; rfl) member
  have queued := admissible.consumed_pending stepped (by rw [delivered]; rfl)
  obtain ⟨source, sourceFound, cap⟩ := pending_term_le admissible (admissible.before stepped) queued
  have sourceLow := low step.before packet.envelope.source source
    (admissible.before stepped) sourceIn sourceFound
  simp only [payload, Message.term] at cap
  have late := busy_after_crossing admissible crossed near far later stepped (by rw [delivered]; simp)
  by_contra notOld
  have eq : request.term = term := by omega
  have early := append_delivered_early admissible delay good ready noLeader
    firstFound within stepped delivered member payload eq
  linarith

/-- With current-term AppendEntries absent, logs freeze and cleared primary
knowledge remains cleared throughout the capped, leaderless interval. -/
theorem state_frozen {start since index term : Nat} {duration : Real}
    {participants : Finset NodeID} {first point : W} {node : NodeID}
    {initial state : NodeState} (afterStart : start <= since)
    (firstFound : trace.stateAt since = some first)
    (initialFound : nodeState (proto first) node = some initial)
    (initialTerm : initial.currentTerm = term) (member : node ∈ participants)
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
    (old
      : forall index step packet request,
          since <= index
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .deliver packet
          -> packet.envelope.target = node
          -> packet.envelope.payload = .appendEntriesRequest request
          -> request.term < term)
    (later : since <= index) (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    (stateFound : nodeState (proto point) node = some state)
    : state.log = initial.log
      /\ state.commitIndex = initial.commitIndex
      /\ (initial.primaryKnown = false -> state.primaryKnown = false) := by
  refine admissible.coherent.induction (start := since)
    (motive := fun index point => Within trace start duration index
      -> forall state, nodeState (proto point) node = some state
      -> state.log = initial.log /\ state.commitIndex = initial.commitIndex
        /\ (initial.primaryKnown = false -> state.primaryKnown = false))
    (fun point found _ state stateFound => ?_)
    (fun index step lower stepped held within state stateFound => ?_)
    index point later found within state stateFound
  · rw [firstFound, Option.some.injEq] at found
    subst point
    rw [initialFound, Option.some.injEq] at stateFound
    subst state
    exact ⟨rfl, rfl, id⟩
  · have beforeWithin := within_before admissible within
      (Trace.stateAt_succ_of_stepAt stepped) (afterStart.trans lower) (Nat.le_succ _)
    cases selected : step.action.action with
    | none =>
        rw [admissible.stutter stepped selected] at stateFound
        exact held beforeWithin state stateFound
    | some action =>
        obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
        rcases tr.mem_after (Concrete.mem_of_nodeState stateFound) with ⟨rfl, rfl⟩ | ⟨_, mem⟩
        · have previous := held beforeWithin tr.pre tr.found
          obtain ⟨before, beforeFound, beforeTerm⟩ := top_stays admissible firstFound initialFound initialTerm
            member lower (admissible.before stepped) (low index beforeWithin)
          rw [tr.found, Option.some.injEq] at beforeFound
          subst before
          obtain ⟨after, afterFound, afterTerm⟩ := top_stays admissible firstFound initialFound initialTerm
            member (by omega) (Trace.stateAt_succ_of_stepAt stepped) (low (index + 1) within)
          rw [stateFound, Option.some.injEq] at afterFound
          subst after
          have notPrimary := noLeader index step.before tr.actor tr.pre beforeWithin
            (admissible.before stepped) member tr.found beforeTerm
          have afterNotPrimary := noLeader (index + 1) step.after tr.actor tr.post within
            (Trace.stateAt_succ_of_stepAt stepped) member stateFound afterTerm
          have active := eligible_not_none (ready (index + 1) step.after tr.actor tr.post within
            (Trace.stateAt_succ_of_stepAt stepped) member stateFound afterNotPrimary)
          have oldLocal : forall source request,
              tr.event = .receive source (.appendEntriesRequest request)
              -> request.term < tr.pre.currentTerm := by
            intro source request received
            obtain ⟨packet, delivered, targetEq, _, payload⟩ := received_packet selected acts received
            rw [beforeTerm]
            exact old index step packet request lower beforeWithin stepped delivered targetEq payload
          have ledger := ledger_kept tr.summary notPrimary afterNotPrimary active
            (fun source request received eq => by
              have older := oldLocal source request received
              omega)
          refine ⟨ledger.1.trans previous.1, ledger.2.trans previous.2.1, ?_⟩
          intro unknown
          obtain ⟨_, _, result⟩ := step_unknown tr.actor tr.pre tr.event
            (previous.2.2 unknown) notPrimary oldLocal {} _ _ tr.ran
          exact result afterNotPrimary active
        · exact held beforeWithin state
            (Direct.nodeState_of_mem (Direct.keys_nodup (admissible.reachable_before stepped)) mem)

end Trace

end CCFRaft.Proofs.Leadership.InitRaise
