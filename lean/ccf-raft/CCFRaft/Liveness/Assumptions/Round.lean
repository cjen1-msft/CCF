module

public import CCFRaft.Liveness.Model

@[expose] public section

/-!
# Round starts

A duel round of `term + 1` starts at the step that first moves a participant past
every term held by participants or carried between them. `Properties` does not
use it directly; the duel's rounds and the initial phase of a good period meet
at it.
-/

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasNetwork (pending)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasNetwork W]

/-- A round of `term + 1` starts at `c`: every participant and every packet between
participants is at most `term`, and step `c` moves a participant past `term`. -/
structure RoundStart (trace : Trace W Event) (participants : Finset NodeID) (c term : Nat)
    : Prop where
  low
    : forall point node state,
        trace.stateAt c = some point
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm <= term
  messages
    : forall point packet,
        trace.stateAt c = some point
        -> packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> packet.envelope.payload.term <= term
  raise
    : exists step node state,
        trace.stepAt c = some step
        /\ node ∈ participants
        /\ nodeState (proto step.after) node = some state
        /\ term < state.currentTerm

end CCFRaft.Liveness
