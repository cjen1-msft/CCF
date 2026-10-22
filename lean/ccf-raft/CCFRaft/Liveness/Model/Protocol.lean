module

public import CCFRaft.Liveness.Model.Trace
public import CCFRaft.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

open HasProtocol (proto)

/-- Lift the protocol through its world projection.
Local actions and deliveries execute the supplied system; all other events stutter.
The action type is fixed by `Event.action`, while the protocol state is generic. -/
def protocolModel {W S : Type} [HasProtocol W S]
    (system : CCF.TransitionSystem S Model.Action) : Model W Event where
  init world := system.init (proto world)
  next step :=
    match step.action.action with
    | some action => system.step (proto step.before) action = some (proto step.after)
    | none => proto step.after = proto step.before

/-- Re-run the same recording callback used by the network to identify sends. -/
def outgoing (state : Model.State) (action : Model.Action)
    : Option (List Model.Envelope) := do
  let (node, event) :=
    match action with
    | .local node input => (node, Model.Node.Event.internal input)
    | .deliver envelope =>
        (envelope.target, Model.Node.Event.receive envelope.source envelope.payload)
  let before <- CCF.MultiNodeTransitionSystem.nodeState state node
  let (_, effects) <- (Model.Node.step (CCF.Capabilities.record node) node before
                        event).run
                        {}
  return effects.outgoing

end CCFRaft.Liveness
