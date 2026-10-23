module

public import CCFRaft.Liveness.Model.Timers
public import CCFRaft.Proofs.Liveness.Trace
public import Mathlib.Tactic.Linarith

@[expose] public section

/-!
# Election deadlines

The deadline timer model implies the election-scheduling lower bound: each reset
draws a deadline at least half an election timeout after its time, a later reset
only draws one later still, and a node times out only once its deadline has passed.
-/

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open HasTime (time)
open HasTimers (deadline)

/-- Time never runs backwards between recorded states. -/
theorem time_mono {W : Type} [HasTime W] {trace : Trace W Liveness.Event}
    (coherent : trace.Coherent) (timing : trace.Valid timingModel)
    {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : time first <= time last :=
  coherent.chain (relation := fun first last => time first <= time last)
    (fun _ => le_rfl) (fun _ _ _ => le_trans)
    (fun _ _ stepped => (timing.next stepped).1) le firstFound lastFound

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasTimers W]
  {trace : Trace W Liveness.Event}

/-- After an election-timer reset, the node's deadline stays at least half an
election timeout past the reset's time. -/
theorem deadline_after_reset {electionTimeout : Real} (coherent : trace.Coherent)
    (timing : trace.Valid timingModel) (timers : trace.Valid (timerModel electionTimeout))
    {earlier : Nat} {reset : CCF.Execution.Step W Liveness.Event}
    {node : Model.Node.NodeID} (resetAt : trace.stepAt earlier = some reset)
    (resets : ElectionReset reset node) {index : Nat} {point : W}
    (after : earlier < index) (found : trace.stateAt index = some point)
    : time reset.before + electionTimeout / 2 <= deadline point node :=
  coherent.induction
    (start := earlier + 1)
    (motive :=
      fun _ point => time reset.before + electionTimeout / 2 <= deadline point node)
    (fun point found => by
      rw [Trace.stateAt_succ_of_stepAt resetAt, Option.some.injEq] at found
      exact found ▸ (((timers.next resetAt) node).1 resets).1)
    (fun later step afterReset stepped held => by
      by_cases stepResets : ElectionReset step node
      · have elapsed :=
          time_mono coherent timing (Nat.le_of_succ_le afterReset) (coherent.before resetAt)
            (coherent.before stepped)
        have drawn := (((timers.next stepped) node).1 stepResets).1
        linarith
      · rw [((timers.next stepped) node).2.1 stepResets]
        exact held)
    index point after found

/-- Idealized deadlines respect the election-scheduling lower bound of half an
election timeout. -/
theorem electionScheduling_of_timerModel {electionTimeout : Real}
    (coherent : trace.Coherent) (timing : trace.Valid timingModel)
    (timers : trace.Valid (timerModel electionTimeout))
    : trace.ElectionScheduling (some (electionTimeout / 2)) := by
  intro earlier index reset timeout node lt resetAt timeoutAt fires resets
  have drawn :=
    deadline_after_reset coherent timing timers resetAt resets lt (coherent.before timeoutAt)
  have passed := ((timers.next timeoutAt) node).2.2 fires
  linarith

end CCFRaft.Proofs.Liveness
