module

public import CCFRaft.Liveness.Model.Trace
public import CCFRaft.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

open HasTime (time)

/-- Absolute time is nondecreasing, with an unrestricted initial value.
Any event, including idle, may advance time or take zero time.
A step happens at its before-time; the time it advances elapses after it.
Every timing constraint on a step reads its before-time. -/
def timingModel {W : Type} [HasTime W] : Model W Event where
  init _ := True
  next step := time step.before <= time step.after

/-- Index `index` is at or after `start` and happens within `duration` of it:
a window bounded in real time, not in the number of steps. -/
def Within {W A : Type} [HasTime W] (trace : Trace W A) (start : Nat) (duration : Real)
    (index : Nat)
    : Prop :=
  start <= index
  /\ forall first point,
      trace.stateAt start = some first
      -> trace.stateAt index = some point
      -> time point <= time first + duration

end CCFRaft.Liveness
