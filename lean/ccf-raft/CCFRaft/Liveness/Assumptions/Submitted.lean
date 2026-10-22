module

public import CCFRaft.Liveness.Model.Timing

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)

variable {W : Type} [HasProtocol W Model.State]

/-- Request identity, independent of its log position or election term. -/
def HasRequest (log : List Entry) (request : ReqID) : Prop :=
  exists entry,
    entry ∈ log /\ exists metadata, entry.content = .transaction request metadata

/-- The request reaches the primary at or after index `start`: the primary then
has it, or the client then submits it to the primary. With a primary stable from
`start`, one submission is enough. Needed: a request that is never submitted is
never committed. -/
def Submitted (trace : Trace W Event) (start : Nat) (leader : NodeID) (request : ReqID) : Prop :=
  exists index point,
    start <= index
    /\ trace.stateAt index = some point
    /\ ((exists state,
          CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
          /\ HasRequest state.log request)
        \/ exists step entries,
            trace.stepAt index = some step
            /\ step.action = .local leader (.append entries)
            /\ .transaction request {} ∈ entries)

end CCFRaft.Liveness
