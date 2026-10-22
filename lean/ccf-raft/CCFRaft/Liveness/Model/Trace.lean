module

public import CCFRaft.Liveness.Model.Timing
public import CCF.Execution

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

/-- A finite or infinite recording for the supplied protocol transition system,
including the zero-step execution. Safety and timing use this same protocol system. -/
structure Trace (system : CCF.TransitionSystem Model.State Model.Action)
    extends CCF.Execution.Trace TracedState TimedEvent where

variable {system : CCF.TransitionSystem Model.State Model.Action}

/-- Map events to model actions, retaining environment-only positions as `none`.
No search through the remaining execution is needed. -/
def Trace.modelActions (trace : Trace system) : Stream'.Seq (Option Model.Action) :=
  trace.actions.map fun timed => timed.event.action

/-- The full recording as a shared initial-state/action trace. -/
def Trace.timingTrace (trace : Trace system) : CCF.Execution.Trace TracedState TimedEvent :=
  trace.toTrace

/-- The initial live set and every event, preserving timing-trace indices. -/
def Trace.crashTrace (trace : Trace system) : CCF.Execution.Trace (Finset NodeID) Event :=
  { initial := trace.initial.live, actions := trace.actions.map fun timed => timed.event }

/-- A future event bounded in real time, not in the number of protocol steps. -/
def Within (trace : Trace system) (start : Nat) (bound : Real)
    (predicate : Nat -> TracedState -> Prop)
    : Prop :=
  exists first index point,
    trace.timingTrace.stateAt (timingSystem system) start = some first
    /\ start <= index
    /\ trace.timingTrace.stateAt (timingSystem system) index = some point
    /\ point.time <= first.time + bound
    /\ predicate index point

/-- Eventually, at or after `index`, a point satisfies `predicate`. -/
def Eventually (trace : Trace system) (index : Nat)
    (predicate : Nat -> TracedState -> Prop) : Prop :=
  exists later point,
    index <= later
    /\ trace.timingTrace.stateAt (timingSystem system) later = some point
    /\ predicate later point

end CCFRaft.Liveness
