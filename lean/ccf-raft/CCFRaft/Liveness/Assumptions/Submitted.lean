module

public import CCFRaft.Liveness.Model.Trace

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

variable {system : CCF.TransitionSystem Model.State Model.Action}

/-- Request identity, independent of its log position or election term. -/
def HasRequest (log : List Entry) (request : ReqID) : Prop :=
  exists entry,
    entry ∈ log /\ exists metadata, entry.content = .transaction request metadata

/-- The request reaches the primary at or after index `start`: the primary then
has it, or the client then submits it to the primary. With a primary stable from
`start`, one submission is enough. Needed: a request that is never submitted is
never committed. -/
def Submitted (trace : Trace system) (start : Nat) (leader : NodeID) (request : ReqID) : Prop :=
  exists index point,
    start <= index
    /\ trace.timingTrace.stateAt (timingSystem system) index = some point
    /\ ((exists state,
          CCF.MultiNodeTransitionSystem.nodeState point.state leader = some state
          /\ HasRequest state.log request)
        \/ exists step entries,
            trace.timingTrace.stepAt (timingSystem system) index = some step
            /\ step.action.event = .local leader (.append entries)
            /\ .transaction request {} ∈ entries)

end CCFRaft.Liveness
