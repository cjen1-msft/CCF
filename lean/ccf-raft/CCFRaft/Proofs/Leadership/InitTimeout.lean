module

public import CCFRaft.Proofs.Liveness.Admissible
public import CCFRaft.Liveness.Model.Timers
public import Mathlib.Tactic.Linarith

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A node that stays ready resets by its deadline

A live node that may start an election keeps its deadline until its timer is
reset. Once the deadline passes, timeout scheduling fires it at once, and no
step carries the clock more than the overshoot bound past the deadline. So from
any recorded state, the node's timer is reset, by its own election timeout or
otherwise, no later than the overshoot bound past the later of its deadline and
the current time.
-/

namespace CCFRaft.Proofs.Leadership

open CCFRaft.Liveness
open Model.Node
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] {system : CCF.TransitionSystem Model.State Model.Action}
  {trace : Trace W Liveness.Event}

/-- A live node that may start an election. -/
def TimeoutReady (point : W) (node : NodeID) : Prop :=
  node ∈ live point
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
      /\ canStartElection state node

/-- The conclusion: a step from `index` that times `node` out or resets its timer,
starting no later than `bound`. -/
def ResetsBy (trace : Trace W Liveness.Event) (index : Nat) (node : NodeID) (bound : Real)
    : Prop :=
  exists later step,
    index <= later
    /\ trace.stepAt later = some step
    /\ time step.before <= bound
    /\ (step.action = .local node (.timeout .election) \/ ElectionReset step node)

theorem ResetsBy.mono {index : Nat} {node : NodeID} {bound bound' : Real}
    (resets : ResetsBy trace index node bound) (le : bound <= bound')
    : ResetsBy trace index node bound' := by
  obtain ⟨later, step, after, stepped, time, fires⟩ := resets
  exact ⟨later, step, after, stepped, time.trans le, fires⟩

/-- A reset is not an idle step. -/
theorem ElectionReset.busy {step : CCF.Execution.Step W Liveness.Event} {node : NodeID}
    (resets : ElectionReset step node)
    : Not (step.action = .idle) := by
  intro idle
  simp only [ElectionReset, idle] at resets

section Trace

variable (admissible : Admissible system trace)

include admissible

/-- Without a reset from `index`, a node keeps its deadline. -/
theorem deadline_keep {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {later : Nat}
    {laterPoint : W} (le : index <= later)
    (laterFound : trace.stateAt later = some laterPoint)
    (quiet
      : forall earlier step,
          index <= earlier
          -> earlier < later
          -> trace.stepAt earlier = some step
          -> Not (ElectionReset step node))
    : deadline laterPoint node = deadline point node := by
  have := admissible.coherent.induction (start := index)
    (motive := fun current currentPoint =>
      current <= later -> deadline currentPoint node = deadline point node)
    (fun first firstFound _ => by
      rw [found, Option.some.injEq] at firstFound
      rw [firstFound])
    (fun current step afterStart stepped held le' => by
      rw [((timers.next stepped) node).2.1 (quiet current step afterStart (by omega) stepped)]
      exact held (by omega))
    later laterPoint le laterFound
  exact this le_rfl

/-- A reset between two recorded states, if the deadline changed. -/
theorem reset_of_deadline_ne {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {later : Nat}
    {laterPoint : W} (le : index <= later)
    (laterFound : trace.stateAt later = some laterPoint)
    (changed : Not (deadline laterPoint node = deadline point node))
    : exists earlier step,
        index <= earlier
        /\ earlier < later
        /\ trace.stepAt earlier = some step
        /\ ElectionReset step node := by
  by_contra none
  push Not at none
  exact changed (deadline_keep admissible timers found le laterFound
    fun earlier step afterStart before stepped resets =>
      none earlier step afterStart before stepped resets)

/-- A due node that stays ready resets without the clock advancing. -/
theorem due_resets {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {node : NodeID}
    (firing
      : Scheduled trace (some 0) (fun point => TimeoutDue point node)
          (fun step => step.action = .local node (.timeout .election)))
    {index : Nat} {point : W} (found : trace.stateAt index = some point)
    (due : TimeoutDue point node)
    (ready
      : forall later laterPoint,
          index <= later
          -> trace.stateAt later = some laterPoint
          -> time laterPoint <= time point
          -> TimeoutReady laterPoint node)
    : ResetsBy trace index node (time point) := by
  obtain ⟨later, laterPoint, le, laterFound, bounded, resolved⟩ := firing index point found due
  have bounded : time laterPoint <= time point := by
    simp only [Deadline] at bounded
    linarith
  rcases resolved with notDue | ⟨step, stepped, fires⟩
  · obtain ⟨liveNow, state, nodeFound, can⟩ := ready later laterPoint le laterFound bounded
    have passed : deadline point node <= time point := due.2.1
    have moved : time laterPoint < deadline laterPoint node := by
      by_contra notMoved
      exact notDue ⟨liveNow, not_lt.mp notMoved, state, nodeFound, can⟩
    have timeMono := admissible.time_le le found laterFound
    obtain ⟨earlier, step, afterStart, before, stepped, resets⟩ :=
      reset_of_deadline_ne admissible timers found le laterFound (by
        intro same
        linarith)
    have stepTime :=
      admissible.time_le before.le (admissible.before stepped) laterFound
    exact ⟨earlier, step, afterStart, stepped, stepTime.trans bounded, Or.inr resets⟩
  · rw [admissible.before stepped, Option.some.injEq] at laterFound
    subst laterFound
    exact ⟨later, step, le, stepped, bounded, Or.inl fires⟩

/-- A node that stays ready until the later of its deadline plus `jump` and now
resets by then. -/
theorem resets_by {electionTimeout jump : Real} (nonneg : 0 <= jump)
    (timers : trace.Valid (timerModel electionTimeout)) (diverges : TimeDiverges trace)
    {node : NodeID}
    (firing
      : Scheduled trace (some 0) (fun point => TimeoutDue point node)
          (fun step => step.action = .local node (.timeout .election)))
    {index : Nat} {point : W} (found : trace.stateAt index = some point)
    (overshoot
      : forall later step,
          index <= later
          -> trace.stepAt later = some step
          -> time step.before < deadline point node
          -> NoOvershoot (some jump) step node)
    (ready
      : forall later laterPoint,
          index <= later
          -> trace.stateAt later = some laterPoint
          -> time laterPoint <= max (deadline point node + jump) (time point)
          -> TimeoutReady laterPoint node)
    : ResetsBy trace index node (max (deadline point node + jump) (time point)) := by
  classical
  have maxLeft := le_max_left (deadline point node + jump) (time point)
  have maxRight := le_max_right (deadline point node + jump) (time point)
  by_cases passed : deadline point node <= time point
  · obtain ⟨liveNow, state, nodeFound, can⟩ :=
      ready index point le_rfl found (by linarith)
    have resets :=
      due_resets admissible timers firing found ⟨liveNow, passed, state, nodeFound, can⟩
        fun later laterPoint le laterFound early =>
          ready later laterPoint le laterFound (by linarith)
    exact resets.mono maxRight
  push Not at passed
  by_cases reset :
      exists earlier step,
        index <= earlier
        /\ trace.stepAt earlier = some step
        /\ time step.before < deadline point node
        /\ ElectionReset step node
  · obtain ⟨earlier, step, afterStart, stepped, early, resets⟩ := reset
    exact ⟨earlier, step, afterStart, stepped, by linarith, Or.inr resets⟩
  push Not at reset
  have reaches : exists later, index <= later
      /\ exists laterPoint, trace.stateAt later = some laterPoint
        /\ deadline point node <= time laterPoint := by
    obtain ⟨later, laterPoint, laterFound, late⟩ := diverges (deadline point node)
    by_cases le : index <= later
    · exact ⟨later, le, laterPoint, laterFound, late⟩
    · have := admissible.time_le (Nat.le_of_not_le le) laterFound found
      linarith
  obtain ⟨afterStart, firstPoint, firstFound, firstLate⟩ := Nat.find_spec reaches
  have minimal := fun j (lt : j < Nat.find reaches) => Nat.find_min reaches lt
  generalize Nat.find reaches = first at afterStart firstFound minimal
  have notIndex : Not (first = index) := by
    intro same
    rw [same, found, Option.some.injEq] at firstFound
    subst firstFound
    linarith
  obtain ⟨previous, previousEq⟩ : exists previous, first = previous + 1 :=
    ⟨first - 1, by omega⟩
  obtain ⟨step, stepped, rfl⟩ :=
    Trace.stateAt_succ_eq_some.mp (previousEq ▸ firstFound)
  have previousEarly : time step.before < deadline point node := by
    have := minimal previous (by omega)
    push Not at this
    exact this (by omega) step.before (admissible.before stepped)
  have quiet :
      forall earlier step',
        index <= earlier
        -> earlier < first
        -> trace.stepAt earlier = some step'
        -> Not (ElectionReset step' node) := by
    intro earlier step' afterStart' before stepped' resets
    have early : time step'.before <= time step.before :=
      admissible.time_le (by omega) (admissible.before stepped') (admissible.before stepped)
    exact absurd (reset earlier step' afterStart' stepped') (by
      push Not
      exact ⟨by linarith, resets⟩)
  have keepBefore :=
    deadline_keep admissible timers found (by omega) (admissible.before stepped)
      fun earlier step' afterStart' before stepped' =>
        quiet earlier step' afterStart' (by omega) stepped'
  have keepAfter :=
    deadline_keep admissible timers found afterStart firstFound quiet
  obtain ⟨liveBefore, beforeState, beforeFound, beforeCan⟩ :=
    ready previous step.before (by omega) (admissible.before stepped) (by linarith)
  have overshot : time step.after <= deadline point node + jump := by
    have := overshoot previous step (by omega) stepped previousEarly
      liveBefore ⟨beforeState, beforeFound, beforeCan⟩ (by rw [keepBefore]; exact previousEarly)
    rwa [keepBefore] at this
  have inBound : time step.after <= max (deadline point node + jump) (time point) := by
    linarith
  obtain ⟨liveAfter, afterState, afterFound, afterCan⟩ :=
    ready first step.after afterStart firstFound inBound
  obtain ⟨later, fired, le, firedAt, firedTime, fires⟩ :=
    due_resets admissible timers firing firstFound
      ⟨liveAfter, by rw [keepAfter]; exact firstLate, afterState, afterFound, afterCan⟩
      fun later laterPoint le laterFound early =>
        ready later laterPoint (by omega) laterFound (early.trans inBound)
  exact ⟨later, fired, by omega, firedAt, firedTime.trans inBound, fires⟩

/-- While the clock stays at or below `limit`, a deadline at most an election
timeout past `limit` stays so: every reset sets it at most an election timeout
past its step. -/
theorem deadline_le_later {electionTimeout limit : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID}
    (initial : deadline point node <= limit + electionTimeout) {later : Nat}
    {laterPoint : W} (le : index <= later)
    (laterFound : trace.stateAt later = some laterPoint)
    (early : time laterPoint <= limit)
    : deadline laterPoint node <= limit + electionTimeout := by
  have := admissible.coherent.induction (start := index)
    (motive := fun current currentPoint =>
      time currentPoint <= limit -> deadline currentPoint node <= limit + electionTimeout)
    (fun first firstFound _ => by
      rw [found, Option.some.injEq] at firstFound
      rw [<- firstFound]
      exact initial)
    (fun current step afterStart stepped held early' => by
      have mono := (admissible.timing.next stepped).1
      by_cases resets : ElectionReset step node
      · have := (((timers.next stepped) node).1 resets).2
        linarith
      · rw [((timers.next stepped) node).2.1 resets]
        exact held (by linarith))
    later laterPoint le laterFound
  exact this early

/-- A node that stays ready, with its deadline at most an election timeout past
`limit`, resets strictly after `limit` and no later than an election timeout plus
`jump` after it. -/
theorem resets_after {electionTimeout jump limit : Real} (nonneg : 0 <= jump)
    (positive : 0 <= electionTimeout)
    (timers : trace.Valid (timerModel electionTimeout)) (diverges : TimeDiverges trace)
    {node : NodeID}
    (firing
      : Scheduled trace (some 0) (fun point => TimeoutDue point node)
          (fun step => step.action = .local node (.timeout .election)))
    {index : Nat} {point : W} (found : trace.stateAt index = some point)
    (early : time point <= limit)
    (initial : deadline point node <= limit + electionTimeout)
    (overshoot
      : forall later step,
          index <= later
          -> trace.stepAt later = some step
          -> time step.before < limit + electionTimeout
          -> NoOvershoot (some jump) step node)
    (ready
      : forall later laterPoint,
          index <= later
          -> trace.stateAt later = some laterPoint
          -> time laterPoint <= limit + electionTimeout + jump
          -> TimeoutReady laterPoint node)
    : exists later step,
        index <= later
        /\ trace.stepAt later = some step
        /\ limit < time step.before
        /\ time step.before <= limit + electionTimeout + jump
        /\ (step.action = .local node (.timeout .election)
            \/ ElectionReset step node) := by
  classical
  have reaches : exists later, index <= later
      /\ exists laterPoint, trace.stateAt later = some laterPoint
        /\ limit < time laterPoint := by
    obtain ⟨later, laterPoint, laterFound, late⟩ := diverges (limit + 1)
    by_cases le : index <= later
    · exact ⟨later, le, laterPoint, laterFound, by linarith⟩
    · have := admissible.time_le (Nat.le_of_not_le le) laterFound found
      linarith
  obtain ⟨afterStart, firstPoint, firstFound, firstLate⟩ := Nat.find_spec reaches
  have minimal := fun j (lt : j < Nat.find reaches) => Nat.find_min reaches lt
  generalize Nat.find reaches = first at afterStart firstFound minimal
  have notIndex : Not (first = index) := by
    intro same
    rw [same, found, Option.some.injEq] at firstFound
    subst firstFound
    linarith
  obtain ⟨previous, previousEq⟩ : exists previous, first = previous + 1 :=
    ⟨first - 1, by omega⟩
  subst previousEq
  obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp firstFound
  have previousEarly : time step.before <= limit := by
    have := minimal previous (by omega)
    push Not at this
    exact this (by omega) step.before (admissible.before stepped)
  have previousDeadline :=
    deadline_le_later admissible timers found initial (by omega) (admissible.before stepped)
      previousEarly
  have bound :
      max (deadline step.before node + jump) (time step.before)
        <= limit + electionTimeout + jump :=
    max_le (by linarith) (by linarith)
  obtain ⟨later, fired, le, firedAt, firedTime, fires⟩ :=
    resets_by admissible nonneg timers diverges firing (admissible.before stepped)
      (fun later step' le stepped' before =>
        overshoot later step' (by omega) stepped' (by linarith))
      fun later laterPoint le laterFound inBound =>
        ready later laterPoint (by omega) laterFound (inBound.trans bound)
  have notPrevious : Not (later = previous) := by
    intro same
    subst same
    rw [stepped, Option.some.injEq] at firedAt
    subst firedAt
    have busy : Not (step.action = .idle) := by
      rcases fires with timeout | resets
      · rw [timeout]
        simp
      · exact ElectionReset.busy resets
    have := (admissible.timing.next stepped).2 busy
    linarith
  have late :=
    admissible.time_le (show previous + 1 <= later by omega) firstFound
      (admissible.before firedAt)
  exact ⟨later, fired, by omega, firedAt, by linarith, firedTime.trans bound, fires⟩

end Trace

end CCFRaft.Proofs.Leadership
