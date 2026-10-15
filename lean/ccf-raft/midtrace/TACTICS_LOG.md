# Mid-trace validation: generic encoding + tactics (research log, part 2)

Part 1 is [RESEARCH_LOG.md](RESEARCH_LOG.md). Part 1 ended with a bespoke
SSA encoder (`SmtModel`) that meets the target. Most of its speed comes from
two model-specific devices: hand-lowered logs (K cells plus `present`/escape)
and hand-lowered channels (positions, ranks, named heads).

## Goal

A pipeline whose model-facing part is mechanical and whose reductions are
generic:

```
actions + observations
  -> mechanical encoding (arrays, folds, queues; constant size per step)
  -> tactics (equisatisfiable rewrites that know nothing about Raft)
  -> QF_LIA script -> yices -> SAT / UNSAT
```

Targets:

- under 60 s per scenario, with the first 10 events missing;
- roughly linear scaling in trace length;
- both VALID and INVALID traces;
- no Raft knowledge in the tactics.

Constraints agreed with the user:

- A per-queue bound on in-flight messages at the cut (Q) is fine.
- The ledger should be represented compactly.
- Streaming (emit a chunk, reduce, repeat) is optional: keep it possible, but
  don't build it.

## Framing

A naive mechanical encoding fixes a maximum ledger length K and a maximum
queue length, then over-approximates every step over all cells. That is
O(n * K) and in practice quadratic. Part 1's `--no-refine` ablation measured
this: max 1.3 s -> 105 s.

The question is which generic rewrites recover the bespoke encoder's linear
size from an encoding that represents logs and queues abstractly (arrays,
stores, folds).

## Research questions

- Q1. Is the mechanical encoding constant size per step (IR nodes per
  instruction flat)?
- Q2. Lowered size and solve time compared with the bespoke encoder.
- Q3. Which tactics matter (ablations)?
- Q4. Fused forward pass vs separate passes.
- Q5. Negative cases: do the 1045 mutants agree with the bespoke encoder,
  and how fast are INVALID verdicts?
- Q6. Ledger compaction: absolute indices that are large (real systems) or
  windows that don't start at 1.
- Q7. Generality: which tactics are model independent, and what does the
  model author still have to supply?

## Log
