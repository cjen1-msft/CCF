# Grammar-safe cuts and symbolic trace alignment

## Status

Proposed

## Context

CCF `raft_trace` events and CCFRaft model actions have different atomicity.
One model action may correspond to several events from one node. For example,
processing AppendEntries may emit receive, entry execution, follower commit,
and response events. Other mappings may emit no model action or several model
actions.

Production trace windows may begin or end inside one of these reductions.
Events from other nodes can appear between the events in a reduction. Moving
each node to its next locally valid grammar prefix would create a vector of
different local times rather than one cut in the collected trace.

An arbitrary trace window also lacks the complete CCFRaft state required for
executable replay. The trace exposes local terms, roles, indices, selected
packets, configurations, and peer indices. It does not expose complete logs,
message queues, election state, transaction history, or lifetime join history.

The deterministic event grammar should remain the fast path. Symbolic solving
is a candidate for reconstructing a missing entry state and action parameters
when validation starts mid-trace, and for explaining inconsistent constraints.

## Decision

### Define grammar safety over one global event order

Assign every collected NDJSON event a stable ordinal. A grammar reduction
consumes a set of events and emits a list of zero or more CCFRaft action
templates. The consumed events may be non-contiguous in the global order
because unrelated nodes can interleave events.

Number events by zero-based position. A cut position `p` denotes the prefix of
length `p`; events with positions below `p` are before the cut. Associate each
reduction with the closed interval `[s, e]` from its earliest consumed event to
its latest consumed event. The interval crosses the cut exactly when
`s < p <= e`. A cut is grammar-safe when no reduction interval crosses it.

Do not independently trim each node queue. To move a requested cut:

Compute the previous and next safe cuts separately:

- `previousSafeCut`: repeatedly move `p` to the minimum `s` among crossing
  intervals. This is monotone decreasing.
- `nextSafeCut`: repeatedly move `p` to the maximum `e + 1` among crossing
  intervals. This is monotone increasing.

This computes the closure of overlapping reduction intervals. Interleaving can
make the closure large. A nearby safe cut may not exist, although the beginning
and end of a finite parsed trace are safe when every reduction touching that
trace is complete and known. For a retained window with missing surrounding
events, the parser must over-read until reductions close or report that it
cannot certify an outer cut.

Grammar safety is syntactic. It is not a coordinated distributed snapshot.
A cut may have messages in flight. Exact replay can cross such a cut only when
the materialized model checkpoint includes those messages.

### Keep event-to-action cardinality general

Each grammar production returns a list of action templates:

```text
N implementation events -> M CCFRaft actions
```

Both `N` and `M` may vary by production. Common cases include many events to
one action, one event to one action, and assertion-only events that contribute
to a larger reduction. The design must not assume one event per action.

The parser consumes every event exactly once. An event that belongs to no
production is an exact-validation failure.

### Separate exact checkpoints from symbolic entry states

An exact mid-trace checkpoint comes from replaying the prefix from the
historical bootstrap, or from a previously certified checkpoint. It contains
the complete model state and stable mappings for node IDs, transaction IDs,
and projected ledger indices.

The model world remains 15 lifetime identities. The historical initial
configuration occupies nodes 0 through 4, with node 0 as its initial leader.
Current and pending configurations are derived independently from each node's
log and commit index. Lifetime join history includes retired and currently
inactive nodes.

A solver-derived entry state is a different claim. It establishes only:

```text
there exists an entry state and concrete action parameters
that satisfy the bounded transition and observation constraints
```

It does not prove that CCF reached that state from the historical bootstrap.
Call this result segment consistency, not reachable trace validation.

### Encode trace alignment as labelled SMT constraints

Define the validation question once, as a Lean proposition over the canonical
CCFRaft state, actions, `Enabled`, and `next`:

```lean
def LabeledStep
    (before : State TxId)
    (action : Action TxId)
    (after : State TxId) : Prop :=
  Enabled before action /\ after = next before action

def MidtraceSatisfiable
    (skeleton : Fin n -> Action TxId -> Prop)
    (observations :
      (Fin (n + 1) -> State TxId) ->
      (Fin n -> Action TxId) ->
      Prop)
    (entryConstraint : State TxId -> Prop) : Prop :=
  Exists fun states : Fin (n + 1) -> State TxId =>
  Exists fun actions : Fin n -> Action TxId =>
    entryConstraint (states 0) /\
    (forall i, skeleton i (actions i)) /\
    (forall i,
      LabeledStep
        (states i.castSucc)
        (actions i)
        (states i.succ)) /\
    observations states actions
```

The grammar fixes action constructors and parameters that the events determine.
Unknown transaction IDs, message contents, action parameters, and documented
finite constructor ambiguities remain existential.

SMT is a backend for this proposition, not a second Raft model. Lower the
bounded proposition to a first-order formula equivalent to:

```text
Compatible(observations, S0)
and Transition(S0, A0, S1)
and ...
and Transition(Sn, An, Sn+1)
```

If the lowering replaces Lean functions and lists with finite arrays and
bounded buffers, prove that the sparse representation preserves the state,
action, transition, and observation predicates. The intended result is:

```text
Bounded MidtraceSatisfiable <-> generated SMT formula
```

This is not a state isomorphism. Many concrete prefixes and unsupported queue
lanes may intentionally map to one sparse state. Define a trace-indexed
`Concretizes` relation between sparse and canonical states. Require:

- every bounded canonical state has a well-formed sparse projection;
- every well-formed sparse state has at least one bounded concretization;
- entry constraints and observations are equivalent under `Concretizes`;
- for each grammar-permitted action, sparse and canonical steps correspond in
  both directions for the current concrete representative.

The last condition prevents the solver from choosing unrelated opaque prefixes
at adjacent steps. This is a skeleton-restricted, finite-horizon bisimulation.
Without it, a hand-maintained transition encoding is a separate model and
cannot establish the stated proposition.

Label these constraint groups separately:

- each raw event or event group;
- each event-to-action mapping;
- each transition relation instance;
- each entry-state well-formedness condition.

Handle solver results as follows:

- `sat`: extract concrete witnesses for the existential states, actions, and
  parameters. With a proved lowering and checked decoding, this is a witness
  for `MidtraceSatisfiable`. Re-evaluating the proposition in Lean is useful
  defense in depth but logically redundant. Until the equivalence and decoder
  are proved, recheck the decoded witness against the canonical proposition
  and do not treat the hand-written encoding alone as acceptance.
- `unsat`: return an unsatisfiable core mapped to event ranges, action
  templates, encoding assumptions, and bounds. This is a conflicting subset
  within that bounded encoding, not necessarily the smallest conflict and not
  a counterexample execution. Unless the bounds are complete for this trace,
  classify the production result as inconclusive rather than invalid.
- `unknown` or timeout: report an inconclusive result.

Label trace-specific bounds and entry-state conditions as well as events and
actions. Permanent theory axioms remain part of every query and must be named
in the diagnostic metadata. For more useful failures, shrink an unsatisfiable
core by repeatedly removing labels and rechecking. This can produce a locally
minimal bounded conflict, but it runs only on the diagnostic path.

### Use a bounded symbolic encoding

The current higher-order Lean `State` contains functions and unbounded lists,
so it cannot be lowered directly by the current solver path. Define explicit
finite bounds as part of the Lean proposition. Represent node functions as
fixed arrays and bounded lists as length-plus-buffer structures, then prove
their correspondence to the bounded canonical state. The inductive invariant
additionally contains existential proof histories and does not characterize
reachability; it is not a replacement initializer.

Build a trace-specific first-order encoding with explicit bounds for:

- relevant nodes and log indices;
- log entry kinds and terms;
- in-flight queue slots;
- transaction identities;
- action parameters.

Start with deterministic action families produced by the grammar. Add symbolic
action tags only for reductions with a documented finite ambiguity.

### Derive bounds automatically from the trace

Do not require callers to choose ledger, queue, node, or transaction bounds.
Implement an executable footprint extractor over the parsed event grammar:

```lean
structure TraceFootprint where
  nodes : Finset Node
  logFootprint : Node -> SparseLogFootprint
  queueWindow : Node -> Node -> QueueWindow
  transactionSlots : Nat

def inferFootprint :
    ParsedTrace -> Except FootprintError TraceFootprint

def Covers
    (trace : ParsedTrace)
    (footprint : TraceFootprint) : Prop
```

The extractor starts with every node, index, packet, configuration, and action
parameter named by the trace. It repeatedly adds every state component read or
written by the corresponding canonical `Enabled` and `next` definitions. It
stops at the least fixed point.

Keep physical indices absolute. Production indices may be large, and
`commitIndex`, `sentIndex`, `matchIndex`, configuration entries, packets, and
action parameters expose those values. Do not renumber a retained suffix to
start at zero.

A log footprint is not merely a contiguous suffix. It contains:

- the absolute log length;
- exact entries or entry projections at touched indices;
- exact short ranges used by AppendEntries overlap checks;
- current, latest, and pending configuration summaries with absolute indices;
- rightmost-signature witnesses and absence summaries at queried frontiers;
- rightmost qualifying term witnesses for NACK prefix searches;
- opaque gaps for ordinary entries whose contents no action or observation
  reads.

A prefix commitment can identify equality of omitted prefixes, but it does not
replace these summaries. Raft reads historical terms, signatures, and
configuration membership directly.

Each action family contributes a checked footprint rule. For example, an
AppendEntries action adds its previous index, retained entry range, source and
destination cursor entries, affected source queue, active configurations, and
leader commit frontier. A receive adds the selected queued message and every
log/configuration position its handler may inspect or replace.

Receive dependencies are branch-sensitive. Introduce branch variables and
close the footprint under the selected handler branch. In particular:

- AppendEntries rejection reads the local tail term and may search the prefix
  for the rightmost term below a threshold.
- Conflict and already-done handling compare terms over overlap ranges.
- Extension compares full entries over the retained overlap.
- Follower commit searches signatures up to the leader frontier.
- A NACK can move `sentIndex` into an old prefix, making that prefix relevant to
  a later send.

Index-producing summaries can introduce new dependencies. Iterate these
queries and the action footprint together to a fixed point.

Compile full scans as witnessed summary queries rather than enumerating every
omitted index. Examples include a rightmost signature plus a
no-later-signature condition, and a rightmost NACK term match plus a
no-later-match condition. Share summary witnesses between state versions so
the solver cannot invent incompatible answers to the same historical query.

The extractor must not guess when closure cannot be established. Unsupported
actions, an open grammar reduction, a dependency crossing an unavailable
prefix, or a resource ceiling returns `FootprintError`. The validator reports
this as unsupported or inconclusive rather than silently increasing a
handwritten bound.

Prove the extraction and encoding in separate directions:

```lean
theorem inferFootprint_covers
    (found : inferFootprint trace = .ok footprint) :
    Covers trace footprint

theorem bounded_sound
    (coverage : Covers trace footprint) :
    BoundedMidtraceSatisfiable trace footprint ->
      MidtraceSatisfiable trace

theorem bounded_complete
    (coverage : Covers trace footprint) :
    MidtraceSatisfiable trace ->
      BoundedMidtraceSatisfiable trace footprint
```

`bounded_sound` makes every decoded SAT witness a witness for the canonical
proposition. `bounded_complete` is also required before bounded UNSAT can rule
out a canonical trace.

These are generic theorems about the extractor and projection, not bespoke
proofs generated for each production trace. A concrete successful extraction
instantiates `inferFootprint_covers` by evaluation.

Keep this layer separate from `CCFRaft.Model`. It imports the canonical model
and proves a projection of its existing state and transitions. It must not add
bounded fields or hash summaries to the canonical protocol state merely to
make SMT translation easier. Existing safety and preservation proofs therefore
remain unchanged.

### Prove the projection incrementally

Start with a slice whose opaque prefix is demonstrably inert:

1. exact canonical actions and transaction IDs;
2. `clientRequest` and `signCommittableMessages` only;
3. fixed absolute base index and exact retained suffix;
4. full bounded submitted-transaction membership;
5. role, term, absolute log length, commit index, and retained-entry
   observations.

These actions inspect leader role, freshness or log non-emptiness, and append
one entry. They do not search or replace the omitted prefix.

Add `appendEntries` next, initially requiring `sentIndex[destination]` at or
after the retained base and preserving the relevant destination queue exactly.
AppendEntries receive, NACK repair, commit advancement, reconfiguration, and
elections require the richer prefix query summaries and come later.

Do not quotient node identities in the first encoding. The world has only 15
nodes, while configurations, messages, votes, and peer-index tables all expose
their identities. Likewise, use exact bounded transaction identities until an
equivariance theorem proves that coherent renaming preserves logs, messages,
actions, observations, and submitted-ID membership.

The pinned Veil stack already supports symbolic trace queries from its declared
initializer, existential action parameters, structured SAT models, and unsat
cores. It is not currently connected to CCFRaft, and its trace language does
not start from an arbitrary symbolic entry state. The implementation needs a
bounded representation of the canonical CCFRaft proposition, an entry-state
query path, and the preservation theorem for its lowering. Rewriting CCFRaft
independently in Veil without that theorem would recreate the separate-model
problem.

## Feasibility probe

`lean/CCFRaft/trace_alignment_smt_probe.smt2` is a scalar cvc5 plumbing probe
with:

- an unknown entry state;
- an unknown client command used to update a submitted-command array;
- scalar metadata for an unknown response already in flight;
- simplified scalar effects for three mapped actions;
- labelled event and mapping constraints.

The first query returns a concrete entry state and action parameters. The
second adds a conflicting commit observation and returns the event/action
labels in the unsatisfiable assumptions.

Run it with:

```bash
cd lean
./check_ccfraft_trace_alignment_smt_probe.sh
```

The probe establishes that cvc5 can return scalar models and labelled
unsatisfiable assumptions in the required two-query workflow. It does not use
Veil, encode the CCFRaft state or transitions, parse the event grammar, perform
canonical Lean replay, or establish encoding completeness or performance.

### Longer real-scenario experiment

`lean/check_ccfraft_long_trace_smt_probe.sh` runs the repository's
`tests/raft_scenarios/replicate` scenario and preprocesses its 53 real
`raft_trace` events. A fixture-specific deterministic reducer selects a cut at
event 20, validates the prefix that produced two pending responses, and maps
the remaining 34 events to 26 canonical Lean actions.

The generated SMT formula reconstructs the observed and derived scalar
checkpoint fields, the two responses already in flight, and a symmetric fresh
transaction representative. Lean then checks 30 selected observations at 24
distinct replay states and applies all 26 actions through canonical
`system.applyAction`, `stateChecks`, and `edgeChecks`.

On the development machine, 30 direct cvc5 runs of the generated formula had a
157 ms median, 470 ms p95, and 478 ms maximum. The formula remains a scalar
abstraction. Python owns the fixture-specific event reduction, the four-entry
log prefix is supplied from validated earlier events, and unobserved checkpoint
fields use a manual completion. The experiment demonstrates feasibility for
this suffix, not a complete CCFRaft SMT encoding or a scaling result for 1,000
events. Its hand-written scalar transition equations are specifically not the
architecture selected above.

## Consequences

- Clean whole traces continue to use deterministic parsing and concrete replay.
- Grammar-safe checkpoints are recorded only when no reduction interval is
  open across the global cut.
- Exact production windows restore a replay-derived checkpoint and warm up to
  the requested assertion boundary.
- Arbitrary production windows may use symbolic segment consistency, with a
  visibly weaker result.
- SAT models must pass canonical Lean replay.
- Bounded UNSAT diagnostics can identify a small set of event, mapping, and
  bound labels involved in a conflict without relying on the current
  depth-first search's last failure.

## Risks

- Reduction intervals can overlap transitively across a large trace region,
  leaving no useful nearby grammar-safe cut.
- Unknown initial queues and logs require explicit bounds. Bounds can make a
  satisfiable production segment appear unsatisfiable, so bounded UNSAT is not
  by itself a production trace rejection.
- An existential entry state may be locally consistent but unreachable.
- Unsatisfiable cores are solver-dependent and are not guaranteed minimum.
- A symbolic trace near 1,000 actions may exceed the latency target. The design
  requires benchmarks before setting a service-level objective.

## Deferred decisions

- The first bounded CCFRaft SMT representation.
- Bounds for logs, queues, terms, nodes, and action ambiguity.
- Whether segment consistency asks for one compatible entry state or all
  compatible entry states.
- Checkpoint storage and certification format.
- Diagnostic core minimization budget.
- Visualization of reductions, concrete models, and conflicting cores.

## References

- `lean/CCFRaft/Model.lean`: executable state, actions, `Enabled`, and `next`.
- `lean/CCFRaft/TraceValidation.lean`: current concrete replay and observation
  checkpoint checks.
- `lean/CCFRaft/Properties.lean`: proof-only inductive invariant witnesses.
- `tests/raft_scenarios_runner.py`: existing event preprocessing.
- `tla/consensus/Traceccfraft.tla`: current whole-trace TLA mapping.
- `src/consensus/aft/raft.h`: implementation event timing.
- `veil/.lake/packages/veil/Veil/Core/Tools/ModelChecker/Symbolic/TraceLang.lean`:
  symbolic trace queries and SAT trace extraction.
- `veil/.lake/packages/veil/Veil/Backend/SMT/Result.lean`: structured SAT models
  and unsat-core result types.
