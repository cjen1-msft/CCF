module

public import CCFRaft.Liveness.Model.Trace
public import CCFRaft.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

open HasTime (time)

/-- Absolute time is nondecreasing, with an unrestricted initial value.
Any event, including idle, may advance time or take zero time. -/
def timingModel {W : Type} [HasTime W] : Model W Event where
  init _ := True
  next step := time step.before <= time step.after

/-- A future recorded state bounded in real time, not in the number of steps. -/
def Within {W A : Type} [HasTime W] (trace : Trace W A) (start : Nat) (bound : Real)
    (predicate : Nat -> W -> Prop) : Prop :=
  exists first index point,
    trace.stateAt start = some first
    /\ start <= index
    /\ trace.stateAt index = some point
    /\ time point <= time first + bound
    /\ predicate index point

end CCFRaft.Liveness
