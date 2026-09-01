# CCFRaft trace-validation prototype issues

This file records unresolved engineering issues found while prototyping
scenario trace validation. It is not a list of model safety defects.

## Trace-derived capacities couple the formula to the input

The naive bounded prototype derives log, queue, transaction, and action
capacities from the complete preprocessed trace. This keeps scenario formulas
small, but it couples the generated state type and SMT formula shape to the
observations being checked.

Consequences:

- the formula generator becomes part of the completeness argument;
- a missing reduction can make a capacity too small;
- two traces with the same model behavior may produce different encodings;
- bounded UNSAT cannot reject a canonical trace before the extraction and
  lowering are proved complete.

The production design needs a proved automatic footprint extractor. The naive
prototype records all inferred capacities in its witness.

## Minimized bounded generation remains engineering work

The hybrid sparse-log and ordered-queue representation is a design proposal,
not an implementation. Its abstract evaluator, support metadata, certificate
checker, SMT lowering, and witness decoder are specific to the reads, writes,
and branches in `CCFRaft.Model`.

Production use requires an engineered bounded generator that:

- derives a compact support timeline from the trace and entry constraints;
- proves that the timeline covers every permitted canonical evaluation;
- preserves one canonical representative as support grows;
- binds the checked footprint to the trace, action skeleton, and generated
  formula;
- rejects a missing, stale, or altered footprint before SMT generation; and
- proves the bounded lowering sound and complete.

Solver-driven capacity growth and the current search-bound minimizer can find
missing rules during development. Neither establishes that a minimized bounded
UNSAT result covers the unbounded canonical model.

## Arbitrary bootstrap configuration changes the canonical model family

The scenario driver starts with arbitrary initial configurations, while the
current canonical model starts with a fixed five-node configuration and leader.
The model should become parameterized by a nonempty initial configuration and
a leader contained in that configuration.

This must preserve the existing five-node instance, proofs, checked traces, and
public theorem names.

## Event grammar determines action and queue bounds

One implementation event may map to zero, one, or several canonical actions.
In particular, a C++ AppendEntries batch may expand to multiple one-entry Lean
sends, receives, and responses. The deterministic grammar therefore determines
both action count and maximum queue occupancy.

A grammar bug can under-allocate the bounded state even when the SMT transition
encoding is otherwise correct.

## Bounded lowering equivalence is not proved

The prototype may generate a full bounded first-order encoding and decode its
SAT witness for canonical checking. This supports a positive scenario result
when the decoded witness passes `Enabled`, `next`, observations, and executable
checks.

Until the bounded lowering is proved sound and complete:

- SAT that fails canonical checking is an encoding bug;
- UNSAT is inconclusive rather than a trace rejection.

## Mid-trace reachability is not established

An existential entry state can explain a trace segment without being reachable
from the historical bootstrap. The prototype checks structural state
conditions and canonical forward transitions, but does not establish
`Reachable` or synthesize the proof-only `SystemInductiveInvariant` histories.

## Unobserved-node symmetry may dominate solver cost

The naive state instantiates all 15 nodes. Scenario events may constrain only a
small subset, leaving many symmetric solutions for unobserved nodes. The first
prototype keeps these nodes existential to measure the cost honestly.

Potential symmetry breaking or projection is deferred.

## Large absolute ledger indices need a sparse production representation

Full bounded logs are acceptable for repository scenarios whose indices remain
small. They are not suitable for production windows near large ledger indices.
The production design needs absolute sparse log cells and proved summaries for
historical configuration, signature, and term queries.

## Solver and checker performance are separate

Measure scenario execution, preprocessing, grammar reduction, formula
generation, SMT solving, witness decoding, and canonical checking separately.
Running `lake env lean --run` includes Lean startup and compilation and is not
a replay-only measurement.
