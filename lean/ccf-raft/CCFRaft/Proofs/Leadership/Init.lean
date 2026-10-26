module

public import CCFRaft.Proofs.Leadership.InitRaise
public import CCFRaft.Proofs.Leadership.InitEligible
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# INIT: a configured good period reaches a handoff or a round start

At `start` let `term` be the highest participant term. If, within
`initRaiseLength` of `start` and while every participant is at or below `term`, a
participant is primary at `term`, the incumbent branch gives an anchored start or
a round start within `bound` of that index. Otherwise `init_raise` moves a
participant past `term` within `initRaiseLength`, and the first such step starts
a round.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)

section Keys

variable [Config.InitialConfiguration]

/-- The system's nodes are the keys of every reachable state. -/
theorem keys_eq {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : state.nodes.map Prod.fst = nodes := by
  induction reachable with
  | initial initialized => exact initialized.2.1
  | @step before after action _ stepped ih =>
      cases action with
      | «local» actor input =>
          obtain ⟨_, _, _, _, _, rfl⟩ := Concrete.step_local stepped
          simpa [Concrete.replaceNode_keys] using ih
      | deliver envelope =>
          obtain ⟨_, _, _, _, _, _, rfl⟩ := Concrete.step_deliver stepped
          simpa [Concrete.replaceNode_keys] using ih

end Keys

section Trace

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- Each of the system's nodes has a state at every recorded index. -/
theorem nodeState_of_node {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} (present : node ∈ nodes)
    : exists state, nodeState (proto point) node = some state := by
  have reachable := admissible.reachable found
  rw [← keys_eq reachable] at present
  obtain ⟨⟨_, state⟩, mem, rfl⟩ := List.mem_map.mp present
  exact ⟨state, Direct.nodeState_of_mem (Direct.keys_nodup reachable) mem⟩

/-- A trace whose time diverges records a state at every index. -/
theorem recorded_of_diverges (diverges : TimeDiverges trace) (index : Nat)
    : exists point, trace.stateAt index = some point := by
  induction index with
  | zero => exact ⟨trace.initial, rfl⟩
  | succ index ih =>
      obtain ⟨point, found⟩ := ih
      cases next : trace.stateAt (index + 1) with
      | some after => exact ⟨after, rfl⟩
      | none =>
          obtain ⟨far, farPoint, farFound, late⟩ := diverges (time point + 1)
          have farLe : far <= index := by
            by_contra beyond
            obtain ⟨_, recorded⟩ :=
              Trace.stateAt_of_le (earlier := index + 1) (by omega) farFound
            rw [next] at recorded
            cases recorded
          have := admissible.time_le farLe farFound found
          linarith

/-- With every participant present, the highest participant term at a recorded
index bounds them all and one of them holds it. -/
theorem top_exists {participants : Finset NodeID} (nonempty : participants.Nonempty)
    (present : forall node, node ∈ participants -> node ∈ nodes) {start : Nat}
    {first : W} (firstFound : trace.stateAt start = some first)
    : exists term,
        Low trace participants start term
        /\ exists node state,
            node ∈ participants
            /\ nodeState (proto first) node = some state
            /\ state.currentTerm = term := by
  let termOf := fun node => ((nodeState (proto first) node).map NodeState.currentTerm).getD 0
  obtain ⟨top, topIn, topEq⟩ := Finset.exists_mem_eq_sup participants nonempty termOf
  obtain ⟨state, nodeFound⟩ := nodeState_of_node admissible firstFound (present top topIn)
  refine ⟨participants.sup termOf, ?_, top, state, topIn, nodeFound, ?_⟩
  · intro point node state' found member nodeFound'
    rw [firstFound, Option.some.injEq] at found
    subst found
    have := Finset.le_sup (f := termOf) member
    simp only [termOf, nodeFound', Option.map_some, Option.getD_some] at this
    exact this
  · rw [topEq]
    simp [termOf, nodeFound]

/-- Through a good period from a configured fixed membership whose participants
have roles, every participant's active members are the membership, and every
participant other than a primary may start an election. -/
theorem ready_window {start : Nat} {duration : Real}
    {participants members : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    (membership
      : forall first,
          trace.stateAt start = some first
          -> Membership participants members (proto first))
    (subset : participants ⊆ members)
    (configured
      : forall first,
          trace.stateAt start = some first
          -> ConfigurationCommitted participants (proto first))
    (roled
      : forall first node state,
          trace.stateAt start = some first
          -> node ∈ participants
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
    (active : Window.AnchorActive trace start duration participants)
    : forall index point node state,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.activeMembers = members
            /\ (Not (state.role = .primary) -> canStartElection state node) := by
  intro index point node state within found member nodeFound
  refine ⟨?_, eligible_window admissible good membership subset configured roled active
    within found member nodeFound⟩
  have committed := committed_later admissible
    (fun first state found nodeFound =>
      committed_iff.mp (configured first found node state (Concrete.mem_of_nodeState nodeFound)
        member))
    within.1 found nodeFound
  rcases (Membership.window admissible good membership index point within found).activeMembers
    (Concrete.mem_of_nodeState nodeFound) member with empty | same
  · obtain ⟨rest, split, _⟩ := activeConfigurations_last committed
    simp only [NodeState.activeConfigurations] at empty
    rw [split] at empty
    simp at empty
  · exact same

/-- INIT, given the incumbent branch: from a configured good period, within
`initRaiseLength + bound` of `start` an anchored start follows or a round starts.

`incumbent` is the branch where a participant is primary at the top term while
every participant is at or below it. -/
theorem init_of_incumbent {electionTimeout maxDelay jump duration bound fresh : Real}
    {start : Nat} {participants members : Finset NodeID}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
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
    (nonnegative : 0 <= maxDelay) (jumpNonnegative : 0 <= jump)
    (ratio : 4 * maxDelay < electionTimeout)
    (long : initRaiseLength electionTimeout maxDelay jump <= duration)
    (boundNonnegative : 0 <= bound)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (membership
      : forall first,
          trace.stateAt start = some first
          -> Membership participants members (proto first))
    (subset : participants ⊆ members)
    (configured
      : forall first,
          trace.stateAt start = some first
          -> ConfigurationCommitted participants (proto first))
    (roled
      : forall first node state,
          trace.stateAt start = some first
          -> node ∈ participants
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
    (nonempty : participants.Nonempty)
    (present : forall node, node ∈ participants -> node ∈ nodes)
    (incumbent
      : forall index point leader state term,
          Within trace start (initRaiseLength electionTimeout maxDelay jump) index
          -> Low trace participants index term
          -> trace.stateAt index = some point
          -> leader ∈ participants
          -> nodeState (proto point) leader = some state
          -> state.currentTerm = term
          -> state.role = .primary
          -> HandoffBy trace participants index bound fresh
              \/ exists c after,
                  index <= c
                  /\ trace.stateAt c = some after
                  /\ time after <= time point + bound
                  /\ RoundStart trace participants c term)
    : HandoffBy trace participants start
        (initRaiseLength electionTimeout maxDelay jump + bound) fresh
      \/ exists c term origin point,
          start <= c
          /\ trace.stateAt start = some origin
          /\ trace.stateAt c = some point
          /\ time point
              <= time origin + (initRaiseLength electionTimeout maxDelay jump + bound)
          /\ RoundStart trace participants c term := by
  obtain ⟨origin, originFound⟩ := recorded_of_diverges admissible diverges start
  obtain ⟨term, low, top, topState, topIn, topFound, topTerm⟩ :=
    top_exists admissible nonempty present originFound
  by_cases incumbentAt
    : exists index point leader state,
        Within trace start (initRaiseLength electionTimeout maxDelay jump) index
        /\ Low trace participants index term
        /\ trace.stateAt index = some point
        /\ leader ∈ participants
        /\ nodeState (proto point) leader = some state
        /\ state.currentTerm = term
        /\ state.role = .primary
  · obtain ⟨index, point, leader, state, within, lowAt, found, leaderIn, leaderFound,
      leaderTerm, primary⟩ := incumbentAt
    have shift := within.2 origin point originFound found
    rcases incumbent index point leader state term within lowAt found leaderIn leaderFound
        leaderTerm primary with handoff | ⟨c, after, le, afterFound, afterTime, round⟩
    · obtain ⟨index', leader', term', anchor, origin', point', le', originFound', found',
        time', anchored⟩ := handoff
      rw [found, Option.some.injEq] at originFound'
      subst originFound'
      exact Or.inl ⟨index', leader', term', anchor, origin, point', within.1.trans le',
        originFound, found', by linarith, anchored⟩
    · exact Or.inr ⟨c, term, origin, after, within.1.trans le, originFound, afterFound,
        by linarith, round⟩
  · obtain ⟨c, first, point, le, firstFound, found, timeLe, round⟩ :=
      init_raise admissible delay timers diverges firing overshoot nonnegative
        jumpNonnegative ratio long good subset
        (ready_window admissible good membership subset configured roled active) low
        ⟨origin, top, topState, originFound, topIn, topFound, topTerm⟩
        fun index point node state within lowAt found member nodeFound termEq primary =>
          incumbentAt
            ⟨index, point, node, state, within, lowAt, found, member, nodeFound, termEq,
              primary⟩
    exact Or.inr ⟨c, term, first, point, le, firstFound, found, by linarith, round⟩

end Trace

end CCFRaft.Proofs.Leadership
