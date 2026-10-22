module

public import CCFRaft.Liveness.Model.Crash
public import CCFRaft.Liveness.Model.Timing
public import CCFRaft.Liveness.Model.Trace
public import CCFRaft.Liveness.Model.Packets
public import CCFRaft.Liveness.Model.Scheduling
public import CCF.Execution
public import Mathlib.Data.Set.Card

@[expose] public section

/-!
A timed, crash-stop environment for the untimed Raft model.
This module reexports the systems, shared trace definitions, packet bookkeeping,
and CCF scheduling assumptions from `Liveness/Model/`.
Protocol steps are unchanged. Idle, crash and drop events stutter in the
underlying state. A dropped envelope remains in the underlying model's queue,
where loss is represented by never delivering that occurrence.

An execution (`Trace`) stores an initial state and a finite or infinite sequence
of timed events.
Protocol states, clocks and live nodes are derived by deterministic replay.
`Trace.modelActions` computably maps each event to an optional model action.
`Properties.lean` defines the filtered safety action trace; its
`Valid` premise takes the protocol's explicit configuration and nodes.
`Trace.timingTrace` retains the initial timed state and every timed event.
The projections use the shared `CCF.Execution.Trace.Valid` to check their
initial state and every recorded action against the appropriate system.
`Trace.crashTrace` projects the initial live set and every event to `crashSystem`.
Timing validity enforces packet bookkeeping; crash validity and whole-execution
scheduling are separate premises.
A property about an intermediate state names its index `start` explicitly.

This module does not assume delivery or commitment, and every
constraint either cites the CCF code it models or states a counterexample showing
why a liveness theorem needs it. Constraints that no theorem needs are left out,
even where CCF meets them, such as positive intervals, divergent time and the
quorum-check timer. Stable leadership, a live quorum and delivery fairness are
separate assumptions (`Liveness.Assumptions`). All constraints are propositions
over finite or infinite executions. An obligation to act must be met before a
finite execution ends, so a finite execution can only end once nothing is due.
-/
