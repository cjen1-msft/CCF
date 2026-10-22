module

public import CCFRaft.Liveness.Model.Trace

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

variable {system : CCF.TransitionSystem Model.State Model.Action}

/-- The packet really was emitted at its claimed step and output position. -/
def Trace.Sent (trace : Trace system) (packet : Packet) : Prop :=
  exists step,
    trace.timingTrace.stepAt (timingSystem system) packet.sent = some step
    /\ (step.action.event.action.bind (outgoing step.before.state)).bind
          (fun messages => messages[packet.ordinal]?)
        = some packet.envelope

end CCFRaft.Liveness
