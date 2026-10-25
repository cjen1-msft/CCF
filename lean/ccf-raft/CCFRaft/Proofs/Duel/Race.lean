module

public import CCFRaft.Proofs.Liveness.Network
public import CCFRaft.Proofs.Duel.RaceNode
public import CCFRaft.Liveness.Assumptions.Window
public import CCFRaft.Liveness.Model.Timers

@[expose] public section

/-!
# The deterministic race lemma

NOT IMPORTED BY `Properties`. Part (b) of the duel: a race with a margin ends in a
fresh quiet start for a live primary.

At index `first`, participant `winner` of term `term` times out. Nothing that can
change a role is in flight between participants, every other participant's deadline is
more than `4 * maxDelay` away, and a quorum of participants would grant `winner` its
pre-vote and vote. Then by `time first + 4 * maxDelay` the winner is a live primary
of `term + 1`, no participant or packet between participants is past `term + 1`, and
no participant of `term + 1` times out before `electionTimeout / 2 - 2 * maxDelay`
after that index (`FreshStart` with `fresh = electionTimeout / 2 - 2 * maxDelay`).

Nodes outside the participants are unconstrained: the good period keeps their packets
from reaching participants, so they never disturb the race.

The no-overshoot rule is not needed here: while a packet to a live node is pending,
`boundedDelayModel` already stops time from jumping past its delivery bound, and the
race never leaves a deadline to be overshot.
-/

namespace CCFRaft.Proofs.Duel.Racing

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-- The state at `first`, when `winner` of `term` times out, from which it wins. -/
structure Race (trace : Trace W Liveness.Event) (electionTimeout maxDelay : Real)
    (participants : Finset NodeID) (first : Nat) (winner : NodeID) (term : Nat)
    : Prop where
  timeout
    : forall step,
        trace.stepAt first = some step -> step.action = .local winner (.timeout .election)
  /-- The winner competes and is in `term`. -/
  competes
    : forall point,
        trace.stateAt first = some point
        -> winner ∈ participants
            /\ exists state,
                nodeState (proto point) winner = some state /\ state.currentTerm = term
  /-- No participant is past `term` or primary. -/
  settled
    : forall point node state,
        trace.stateAt first = some point
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm <= term /\ state.role ≠ .primary
  /-- Nothing in flight between participants can change a role or grant anything. -/
  inert
    : forall point packet,
        trace.stateAt first = some point
        -> packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> packet.envelope.payload.term <= term /\ Inert packet.envelope.payload
  /-- The margin: every other participant's timer is more than four delays away. -/
  margin
    : forall point node,
        trace.stateAt first = some point
        -> node ∈ participants
        -> node ≠ winner
        -> time point + 4 * maxDelay < deadline point node
  /-- A quorum of the winner's configurations would grant it: up to date, and
  knowing no primary, since a node that knows one refuses pre-votes. -/
  capable
    : forall point state,
        trace.stateAt first = some point
        -> nodeState (proto point) winner = some state
        -> exists voters,
            hasQuorum state.activeConfigurations voters
            /\ forall voter,
                voter ∈ voters
                -> voter ≠ winner
                -> voter ∈ participants
                    /\ voter ∈ state.activeMembers.erase winner
                    /\ voter ∈ eligiblePeers state winner
                    /\ exists voterState,
                        nodeState (proto point) voter = some voterState
                        /\ voteLogUpToDate voterState (makeRequestVoteRequest state)
                        /\ voterState.primaryKnown = false
  /-- The good period covers the race. -/
  covered
    : forall point,
        trace.stateAt first = some point
        -> exists start duration origin,
            GoodPeriod trace start duration participants
            /\ start <= first
            /\ trace.stateAt start = some origin
            /\ time point + 4 * maxDelay <= time origin + duration

/-- The fresh quiet start a race ends in, as raw facts about participants so that a
`Quiet` over participants can be assembled from it. -/
structure Won (trace : Trace W Liveness.Event) (electionTimeout maxDelay : Real)
    (participants : Finset NodeID) (first leaderIndex : Nat) (winner : NodeID)
    (term : Nat)
    : Prop where
  found
    : exists origin point,
        trace.stateAt first = some origin
        /\ trace.stateAt leaderIndex = some point
        /\ first <= leaderIndex
        /\ time point <= time origin + 4 * maxDelay
        /\ winner ∈ live point
        /\ exists state,
            nodeState (proto point) winner = some state
            /\ state.role = .primary
            /\ state.currentTerm = term + 1
  nodes
    : forall point node state,
        trace.stateAt leaderIndex = some point
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm <= term + 1
            /\ (state.role = .preVoteCandidate -> state.currentTerm < term + 1)
  messages
    : forall point packet,
        trace.stateAt leaderIndex = some point
        -> packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> packet.envelope.payload.term <= term + 1
            /\ packet.envelope.payload ≠ .proposeRequestVoteRequest (term + 1)
  /-- `FreshStart.timers` with `fresh = electionTimeout / 2 - 2 * maxDelay`, for
  participants. -/
  timers
    : forall leaderPoint index step node state,
        trace.stateAt leaderIndex = some leaderPoint
        -> leaderIndex <= index
        -> trace.stepAt index = some step
        -> node ∈ participants
        -> step.action = .local node (.timeout .election)
        -> nodeState (proto step.before) node = some state
        -> state.currentTerm = term + 1
        -> time leaderPoint + (electionTimeout / 2 - 2 * maxDelay) <= time step.before

theorem local_of_internal {event : Liveness.Event} {action : Model.Action}
    {actor : NodeID} {localEvent : Model.Node.Event} {input : Input}
    (selected : event.action = some action) (acts : Acts action actor localEvent)
    (internal : localEvent = .internal input)
    : event = .local actor input := by
  cases action with
  | «local» node input' =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal
      rw [actorEq]
      cases event <;> simp_all [Liveness.Event.action]
  | deliver envelope =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal

section Trace

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

omit [HasTimers W] in
/-- A node recorded after a step was recorded before it, in no later term. -/
theorem node_before {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {node : NodeID} {after : NodeState}
    (afterFound : nodeState (proto step.after) node = some after)
    : exists before,
        nodeState (proto step.before) node = some before
        /\ before.currentTerm <= after.currentTerm := by
  rcases selected : step.action.action with _ | action
  · rw [admissible.stutter stepped selected] at afterFound
    exact ⟨after, afterFound, le_rfl⟩
  obtain ⟨rest, c, _, _⟩ := ctx_at admissible stepped selected
  rcases c.now_after (now_of_found (rest := proto step.before :: rest) afterFound) with
    ⟨actorEq, postEq⟩ | ⟨_, otherNow⟩
  · subst actorEq postEq
    exact ⟨c.pre, c.tr.found, (Summary.term_le c.sum)⟩
  · exact ⟨after, found_of_now c.prior otherNow, le_rfl⟩

omit [HasTimers W] in
/-- A node's term rises only at an election reset of that node. -/
theorem reset_of_term_lt {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {node : NodeID} {before after : NodeState}
    (beforeFound : nodeState (proto step.before) node = some before)
    (afterFound : nodeState (proto step.after) node = some after)
    (lt : before.currentTerm < after.currentTerm)
    : ElectionReset step node := by
  rcases selected : step.action.action with _ | action
  · rw [admissible.stutter stepped selected, beforeFound, Option.some.injEq] at afterFound
    subst afterFound
    omega
  obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
  have beforeNow := now_of_found (rest := rest) beforeFound
  have afterNow := now_of_found (rest := proto step.before :: rest) afterFound
  rcases c.now_after afterNow with ⟨actorEq, postEq⟩ | ⟨different, otherNow⟩
  · have preEq := c.now_pre (actorEq ▸ beforeNow)
    subst preEq postEq
    have deliver : forall {source message}, c.event = .receive source message
        -> ElectionReset step node := by
      intro source message eventEq
      obtain ⟨envelope, actionEq, targetEq, _, _⟩ := acts_receive acts eventEq
      subst actionEq
      cases event : step.action with
      | deliver packet =>
          simp only [event, Liveness.Event.action, Option.some.injEq] at selected
          injection selected with selected
          simp only [ElectionReset, event, beforeFound, afterFound]
          exact ⟨by rw [selected, actorEq]; exact targetEq.symm, Or.inl lt⟩
      | _ => simp [event, Liveness.Event.action] at selected
    rcases Summary.term_cause c.sum with le | ⟨_, cause⟩ | ⟨source, message, eventEq, _⟩
    · omega
    · rcases cause with eventEq | ⟨source, response, eventEq, _⟩ | ⟨source, eventEq⟩
      · have := local_of_internal selected acts eventEq
        simp [ElectionReset, this, actorEq]
      all_goals exact deliver eventEq
    · exact deliver eventEq
  · have := now_unique c.prior beforeNow otherNow
    subst this
    omega

/-- Once every node of `members` is at most `term`, a member of `term + 1` was reset
since, so its deadline is half an election timeout past that point. -/
theorem term_fresh {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {members : Finset NodeID}
    {term : Nat} {first : Nat} {origin : W}
    (originFound : trace.stateAt first = some origin)
    (low
      : forall node state,
          node ∈ members
          -> nodeState (proto origin) node = some state
          -> state.currentTerm <= term)
    : forall index point node state,
        first <= index
        -> trace.stateAt index = some point
        -> node ∈ members
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1
        -> time origin + electionTimeout / 2 <= deadline point node := by
  intro index
  induction index with
  | zero =>
      intro point node state le found alive nodeFound termEq
      have : first = 0 := by omega
      subst this
      rw [originFound, Option.some.injEq] at found
      subst found
      have := low node state alive nodeFound
      omega
  | succ index ih =>
      intro point node state le found alive nodeFound termEq
      by_cases atFirst : first = index + 1
      · subst atFirst
        rw [originFound, Option.some.injEq] at found
        subst found
        have := low node state alive nodeFound
        omega
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeFound := admissible.before stepped
      have timeLe := admissible.time_le (by omega : first <= index) originFound beforeFound
      have rule := (timers.next stepped) node
      by_cases reset : ElectionReset step node
      · linarith [(rule.1 reset).1]
      rw [rule.2.1 reset]
      obtain ⟨before, nodeBefore, termLe⟩ := node_before admissible stepped nodeFound
      have : before.currentTerm = term + 1 := by
        by_contra ne
        exact reset (reset_of_term_lt admissible stepped nodeBefore nodeFound (by omega))
      exact ih step.before node before (by omega) beforeFound alive nodeBefore this

omit [HasTimers W] in
/-- A protocol step, seen as one node's handler run and the packets it adds. -/
theorem protocol_view {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action)
    : exists actor pre post,
    exists outputs : CCF.Outputs NodeID Message Notification,
      nodeState (proto step.before) actor = some pre
      /\ nodeState (proto step.after) actor = some post
      /\ (forall node,
            node ≠ actor
            -> nodeState (proto step.after) node = nodeState (proto step.before) node)
      /\ ((exists input,
            step.action = .local actor input
            /\ (act (CCF.Capabilities.record actor) actor pre input).run {}
                = some (post, outputs))
          \/ (exists packet,
                step.action = .deliver packet
                /\ packet.envelope.target = actor
                /\ (receive (CCF.Capabilities.record actor) actor packet.envelope.source
                      pre packet.envelope.payload).run
                      {}
                    = some (post, outputs)))
      /\ pending step.after
          = step.action.remaining (pending step.before)
            ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
                (time step.before) := by
  obtain ⟨rest, c, acts, out⟩ := ctx_at admissible stepped selected
  refine ⟨c.tr.actor, c.tr.pre, c.tr.post, c.tr.outputs, c.tr.found,
    found_of_now c.exec c.post_now, ?_, ?_, ?_⟩
  · intro node ne
    cases beforeEq : nodeState (proto step.before) node with
    | none =>
        cases afterEq : nodeState (proto step.after) node with
        | none => rfl
        | some state =>
            rcases c.now_after (now_of_found (rest := proto step.before :: rest) afterEq) with
              ⟨same, _⟩ | ⟨_, now⟩
            · exact absurd same ne
            · rw [found_of_now c.prior now] at beforeEq
              cases beforeEq
    | some state =>
        exact found_of_now c.exec (c.now_other ne (now_of_found (rest := rest) beforeEq))
  · have ran := c.tr.ran
    cases action with
    | «local» node input =>
        obtain ⟨actorEq, eventEq⟩ := acts
        rw [eventEq] at ran
        refine Or.inl ⟨input, ?_, ran⟩
        cases event : step.action <;> simp_all [Liveness.Event.action]
    | deliver envelope =>
        obtain ⟨actorEq, eventEq⟩ := acts
        rw [eventEq] at ran
        cases event : step.action with
        | deliver packet =>
            simp only [event, Liveness.Event.action, Option.some.injEq] at selected
            injection selected with selected
            subst selected
            exact Or.inr ⟨packet, rfl, actorEq.symm, ran⟩
        | _ => simp [event, Liveness.Event.action] at selected
  · obtain ⟨_, _, emitted, emittedEq, _, ledger⟩ := admissible.delivery.next stepped
    simp only [selected, admissible.step stepped selected, out, Option.bind_eq_bind,
      Option.bind_some, Option.some.injEq] at emittedEq
    rw [ledger, emittedEq]

end Trace

end CCFRaft.Proofs.Duel.Racing
