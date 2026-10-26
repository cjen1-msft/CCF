module

public import CCFRaft.Proofs.Leadership.FirstReset
public import CCFRaft.Proofs.Leadership.InitTimeout
public import CCFRaft.Proofs.Liveness.Delay

@[expose] public section

set_option linter.unusedSectionVars false

/-!
NOT IMPORTED BY `Properties`.

Time boundaries and election deadline bounds used by the INIT argument.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
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

/-- A diverging recording crosses every time bound above a recorded point. -/
theorem boundary (diverges : TimeDiverges trace) {start : Nat} {first : W}
    (firstFound : trace.stateAt start = some first) {bound : Real}
    (initial : time first <= bound)
    : exists index step,
        start <= index
        /\ trace.stepAt index = some step
        /\ time step.before <= bound
        /\ bound < time step.after := by
  obtain ⟨far, point, found, late⟩ := diverges (bound + 1)
  have farLe : start <= far := by
    by_contra h
    have := admissible.time_le (by omega : far <= start) found firstFound
    linarith
  obtain ⟨index, le, lt, ⟨before, beforeFound, early⟩, outside⟩ :=
    CCFRaft.Proofs.Liveness.exists_exit
      (holds := fun i => exists p, trace.stateAt i = some p /\ time p <= bound)
      farLe ⟨first, firstFound, initial⟩ (by
        rintro ⟨p, pf, early⟩
        rw [found, Option.some.injEq] at pf
        subst p
        linarith)
  obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt lt found
  rw [admissible.before stepped, Option.some.injEq] at beforeFound
  subst before
  refine ⟨index, step, le, stepped, early, ?_⟩
  by_contra h
  exact outside ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, by linarith⟩

/-- Resets before a fixed time keep the deadline below that time plus a timeout. -/
theorem deadline_le_of_resets_before {electionTimeout bound : Real}
    (timers : trace.Valid (timerModel electionTimeout))
    {start last : Nat} {first point : W} {node : NodeID}
    (firstFound : trace.stateAt start = some first)
    (found : trace.stateAt last = some point) (le : start <= last)
    (initial : deadline first node <= bound + electionTimeout)
    (resets
      : forall index step,
          start <= index
          -> index < last
          -> trace.stepAt index = some step
          -> ElectionReset step node
          -> time step.before <= bound)
    : deadline point node <= bound + electionTimeout := by
  have invariant : forall index p,
      start <= index -> trace.stateAt index = some p -> index <= last
      -> deadline p node <= bound + electionTimeout :=
    admissible.coherent.induction
      (motive := fun index p =>
        index <= last -> deadline p node <= bound + electionTimeout)
      (fun p pf _ => by
        rw [firstFound, Option.some.injEq] at pf
        subst p
        exact initial)
      (fun index step after stepped held before => by
        by_cases reset : ElectionReset step node
        · have drawn := (((timers.next stepped) node).1 reset).2
          have early := resets index step after (by omega) stepped reset
          linarith
        · rw [((timers.next stepped) node).2.1 reset]
          exact held (by omega))
  exact invariant last point le found le_rfl

/-- A live eligible node prevents an idle jump past its deadline and overshoot. -/
theorem crossing_deadline {index : Nat} {step : Execution.Step W Liveness.Event}
    {node : NodeID} {jump bound electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout))
    (stepped : trace.stepAt index = some step)
    (crossed : time step.before <= bound /\ bound < time step.after)
    (alive : node ∈ live step.before)
    (eligible
      : exists state,
          nodeState (proto step.before) node = some state /\ canStartElection state node)
    (overshoot : NoOvershoot (some jump) step node)
    (firing
      : Scheduled trace (some 0) (fun point => TimeoutDue point node)
          (fun step => step.action = .local node (.timeout .election)))
    : bound < deadline step.before node + jump := by
  by_contra late
  have due : TimeoutDue step.before node := by
    refine ⟨alive, ?_, eligible⟩
    by_contra early
    have capped := overshoot alive eligible (by linarith)
    linarith
  have same_index : forall later point,
      index <= later -> trace.stateAt later = some point
      -> time point <= time step.before -> later = index := by
    intro later point le found timely
    by_contra different
    have elapsed := admissible.time_le (by omega : index + 1 <= later)
      (Trace.stateAt_succ_of_stepAt stepped) found
    linarith
  obtain ⟨later, other, le, otherAt, timely, resolved⟩ :=
    due_resets admissible timers firing (admissible.before stepped) due
      (fun later point le found early => by
        have same := same_index later point le found early
        subst later
        rw [admissible.before stepped, Option.some.injEq] at found
        subst point
        exact ⟨alive, eligible⟩)
  have same := same_index later other.before le (admissible.before otherAt) timely
  subst later
  rw [stepped, Option.some.injEq] at otherAt
  subst other
  have busy : Not (step.action = .idle) := by
    intro idle
    rcases resolved with fires | reset
    · rw [idle] at fires
      cases fires
    · simp [ElectionReset, idle] at reset
  have unchanged := (admissible.timing.next stepped).2 busy
  linarith

/-- After old resets stop, another reset must occur by the deadline bound.
The predicate can classify that reset as a timeout or a term broadcast. -/
theorem reset_or_event {electionTimeout jump resetBound horizon : Real}
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace) {start : Nat} {first : W} {node : NodeID}
    (firstFound : trace.stateAt start = some first)
    (initial : time first <= horizon)
    (deadlineBound : deadline first node <= resetBound + electionTimeout)
    (room : resetBound + electionTimeout + jump <= horizon)
    (firing
      : Scheduled trace (some 0) (fun point => TimeoutDue point node)
          (fun step => step.action = .local node (.timeout .election)))
    (eligible
      : forall index point,
          start <= index
          -> trace.stateAt index = some point
          -> time point <= horizon
          -> node ∈ live point
              /\ exists state,
                  nodeState (proto point) node = some state
                  /\ canStartElection state node)
    (overshoot
      : forall index step,
          start <= index
          -> trace.stepAt index = some step
          -> time step.before <= horizon
          -> NoOvershoot (some jump) step node)
    (Event : Nat -> Execution.Step W Liveness.Event -> Prop)
    (classify
      : forall index step,
          start <= index
          -> trace.stepAt index = some step
          -> time step.before <= horizon
          -> ElectionReset step node
          -> time step.before <= resetBound \/ Event index step)
    : exists index step,
        start <= index
        /\ trace.stepAt index = some step
        /\ time step.before <= horizon
        /\ Event index step := by
  classical
  by_contra absent
  obtain ⟨index, step, after, stepped, near, far⟩ :=
    boundary admissible diverges firstFound initial
  have resets : forall earlier reset,
      start <= earlier -> earlier < index -> trace.stepAt earlier = some reset
      -> ElectionReset reset node -> time reset.before <= resetBound := by
    intro earlier reset lower upper resetAt resets
    have early := admissible.time_le (by omega : earlier <= index)
      (admissible.before resetAt) (admissible.before stepped)
    have bound : time reset.before <= horizon := early.trans near
    exact (classify earlier reset lower resetAt bound resets).resolve_right
      (fun event => absent ⟨earlier, reset, lower, resetAt, bound, event⟩)
  have deadlineBound := deadline_le_of_resets_before admissible timers firstFound
    (admissible.before stepped) after deadlineBound resets
  obtain ⟨alive, can⟩ := eligible index step.before after (admissible.before stepped) near
  have crossed := crossing_deadline admissible timers stepped ⟨near, far⟩ alive can
    (overshoot index step after stepped near) firing
  linarith

end CCFRaft.Proofs.Leadership.InitRaise
