module

public import CCFRaft.Liveness.Model.Crash
public import Mathlib.Basic.NNReal.Defs
public import Mathlib.Basic.Real.Basic

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

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

/-- One point of an execution, without an attached action. -/
structure TracedState where
  state : Model.State
  time : Real
  live : Finset NodeID
  /-- Index of the next event, used to identify its outgoing packets. -/
  nextStep : Nat := 0
  pendingPackets : List Packet := []

/-- An event happens at the current state's time; `elapsed` is the time until
the resulting state, and hence the next event. It may be zero, but not negative. -/
structure TimedEvent where
  event : Event
  elapsed : NNReal

/-- Execute a recorded event using the supplied protocol transition system.
A disabled protocol action or consumption of an unavailable packet returns `none`.
Deliveries and drops consume before this step's outputs are registered. -/
def TracedState.step (before : TracedState)
    (system : CCF.TransitionSystem Model.State Model.Action) (event : TimedEvent)
    : Option TracedState := do
  let pendingPackets <- match event.event.consumedPacket with
    | some packet => do
        guard (before.pendingPackets.contains packet)
        pure (before.pendingPackets.erase packet)
    | none => pure before.pendingPackets
  let (state, emitted) <- match event.event.action with
    | some action => do
        let state <- system.step before.state action
        let emitted <- outgoing before.state action
        pure (state, emitted)
    | none => pure (before.state, [])
  let pendingPackets := pendingPackets ++
    (emitted.zipIdx 0).map fun (envelope, ordinal) =>
      { sent := before.nextStep, ordinal, envelope }
  return {
    state
    time := before.time + (event.elapsed : Real)
    live := event.event.liveAfter before.live
    nextStep := before.nextStep + 1
    pendingPackets
  }

/-- Lift a protocol transition system to timed events.
Protocol initialization is inherited; the initial clock and live set have no
additional restrictions.
Nonnegative durations are enforced by `TimedEvent`.
The packet ledger starts empty at event index zero; replay generates send
identities and allows each occurrence to be delivered or dropped only once.
Crash validity and scheduling remain separate premises. -/
def timingSystem (system : CCF.TransitionSystem Model.State Model.Action)
    : CCF.TransitionSystem TracedState TimedEvent where
  init before :=
    system.init before.state
    /\ before.nextStep = 0
    /\ before.pendingPackets = []
  step before event := before.step system event

end CCFRaft.Liveness
