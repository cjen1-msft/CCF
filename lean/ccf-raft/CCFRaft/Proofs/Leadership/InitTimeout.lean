module

public import CCFRaft.Proofs.Liveness.Admissible
public import CCFRaft.Liveness.Model.Timers
public import Mathlib.Tactic.Linarith

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A due node that stays ready resets

A live node that may start an election keeps its deadline until its timer is
reset (`deadline_keep`). Once the deadline has passed, timeout scheduling fires
it without the clock advancing (`due_resets`).
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

/-- A step from `index` that times `node` out or resets its timer, starting no later
than `bound`. -/
def ResetsBy (trace : Trace W Liveness.Event) (index : Nat) (node : NodeID) (bound : Real)
    : Prop :=
  exists later step,
    index <= later
    /\ trace.stepAt later = some step
    /\ time step.before <= bound
    /\ (step.action = .local node (.timeout .election) \/ ElectionReset step node)

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

end Trace

end CCFRaft.Proofs.Leadership
