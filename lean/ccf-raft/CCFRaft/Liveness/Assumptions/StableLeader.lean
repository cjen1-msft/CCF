module

public import CCFRaft.Liveness.Model.Trace

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

variable {system : CCF.TransitionSystem Model.State Model.Action}

/-- At `index`, `leader` is live and the primary of `term`, and its retirement has
not committed. -/
abbrev Leads (trace : Trace system) (index : Nat) (leader : NodeID) (term : Nat) : Prop :=
  exists point state,
      trace.timingTrace.stateAt (timingSystem system) index = some point
      /\ leader ∈ point.live
      /\ CCF.MultiNodeTransitionSystem.nodeState point.state leader = some state
      /\ state.role = .primary
      /\ state.currentTerm = term
      /\ Not (state.isRetiredCommitted leader)

/-- From index `start` on, `leader` leads `term`.
Other primaries, for example a partitioned primary of an older term, are allowed.
Needed: nodes can keep timing out and electing a new primary, each deposed before
its first signature is acknowledged. CCF makes this unlikely, not impossible, with
randomized election timeouts. `Properties.stable_leader` derives it from timing
when the primary is the newest at `start`, under further assumptions. -/
def StableLeader (trace : Trace system) (start : Nat) (leader : NodeID) (term : Nat) : Prop :=
  (exists point, trace.timingTrace.stateAt (timingSystem system) start = some point)
  /\ forall index point,
      start <= index
      -> trace.timingTrace.stateAt (timingSystem system) index = some point
      -> Leads trace index leader term

end CCFRaft.Liveness
