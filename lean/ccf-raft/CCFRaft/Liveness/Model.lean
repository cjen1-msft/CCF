module

public import CCFRaft.Liveness.Model.Trace
public import CCFRaft.Liveness.Model.World
public import CCFRaft.Liveness.Model.WitnessWorld
public import CCFRaft.Liveness.Model.Protocol
public import CCFRaft.Liveness.Model.Timing
public import CCFRaft.Liveness.Model.Crash
public import CCFRaft.Liveness.Model.Delivery
public import CCFRaft.Liveness.Model.Packets
public import CCFRaft.Liveness.Model.Scheduling
public import Mathlib.Data.Set.Card

@[expose] public section

/-!
A recorded relational environment for the unchanged Raft protocol.
`Trace W Event` stores the initial world and every step's before-state, event and
after-state. Accessors read this recording without replay or filtered projections.
Coherence connects adjacent endpoints and the initial state.

Each `Model` is a TLA-style initial predicate and next-state relation.
Validity against several models is ordinary conjunction, with no composition
operator, variable ownership or model ordering. Contradictory constraints simply
admit fewer traces; unmentioned fields are unrestricted by that model.

Small accessor classes let each model use only the world fields it needs.
Public statements quantify over any world `W` with the accessors they need, so
the world is an open row; `World S` is one closed instantiation used by witnesses.
No scheduling state is stored.
Protocol, timing, crash and delivery models are independent premises.
`boundedDelayModel` is an optional deadline constraint, not a delivery guarantee.
Drops stutter in the underlying protocol, whose untagged queue may retain the
envelope; the packet ledger still prevents reusing that dropped occurrence.

Scheduling is read-only over the whole trace and is separate from model validity.
Untimed obligations must resolve or cease to be due before a finite trace ends.
The timed model retains eventual heartbeat progress and additionally constrains
each later crossing of a heartbeat deadline, without assuming divergent time.
Stable leadership, live quorums, fair-loss links and submission remain separate
assumptions in `Liveness.Assumptions`.
-/

