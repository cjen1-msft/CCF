# Rationale

## Revised premise

The first proposal still described representation thresholds and capacity
exhaustion too much like a sizing policy. That is not enough for complete
trace validation.

The production claim must be:

```text
derive X from the ordered trace, entry constraint, and every permitted action
then prove FootprintSufficient trace skeleton entry X
then generate bounded SMT from X
```

Trying capacities until a solver result stabilizes is not a proof. It may miss
a branch, an old log query, an initial queued message, or a hidden action. I
now keep iteration only as a development check against the abstract evaluator.

The same rule applies to S0. A final footprint with 40 carrier cells does not
mean that the existential entry state contains a 40-slot log and queue. S0 has
only the support demanded at the first cut. Later abstract closure may split
an opaque prefix, expose an old absolute index, or add a message token.

## Evidence inspected

I used these current sources and artifacts:

- `lean/adr/0002-grammar-safe-cuts-and-symbolic-trace-alignment.md`
- `lean/CCFRaft/ISSUES.md`
- `lean/CCFRaft/Model.lean`
- `lean/CCFRaft/naive_full_state_smt.py`
- `lean/CCFRaft/cheap_full_state_smt.py`
- `lean/CCFRaft/NaiveFullStateWitness.lean`
- `lean/check_ccfraft_cheap_full_state_prototype.sh`
- `lean/check_ccfraft_naive_full_state_prototype.sh`
- `lean/.lake/build/cheap-full-state-smt/report.md`
- `lean/.lake/build/naive-full-state-smt/report.md`
- `lean/.lake/build/cheap-full-state-smt/benchmark-v1.json`

The execution environment prohibits all `/tmp` access, so I could not read
`/tmp/ccfraft-trace-validation-handoff.md`.

The ADR already points at the right proof shape:

- define a trace-indexed `Concretizes` relation and prove sparse and canonical
  steps in both directions (`0002...md:155-165`);
- keep physical indices absolute (`:244-247`);
- include exact cells, configuration summaries, rightmost signature and term
  witnesses, and opaque gaps (`:249-286`);
- prove `inferFootprint_covers`, `bounded_sound`, and `bounded_complete`
  (`:299-316`).

The issue tracker says trace-derived capacities make the generator part of the
completeness argument (`lean/CCFRaft/ISSUES.md:6-18`). The answer is not to
hide that dependency. The answer is to make extraction executable and prove
its sufficiency.

## Why unknown entry state changes the queue answer

My earlier answer recommended fixed buffers for queues without a strong enough
qualification.

That is correct when an exact checkpoint supplies the initial queue or an
entry constraint proves it empty. Abstract execution can then count every
live message on every path and derive an exact maximum occupancy.

It is not complete for an arbitrary unknown entry queue. The canonical
`takeFirstFrom source` can skip arbitrarily many messages from other sources
(`Model.lean:670-683`). `enqueueNoDup` scans the whole queue for exact equality
(`:658-667`). No finite length follows from a finite suffix trace.

There are only two honest choices:

1. reject the symbolic window unless its entry constraint bounds the queue; or
2. represent the finite observations of the unknown queue with exact message
   tokens separated by opaque ordered gaps.

The revised recommendation supports both. Ordered gaps carry source-absence
and message-equality facts needed by later receives and coalescing. If those
facts cannot close under the action skeleton, `deriveFootprint` fails. A fixed
numeric capacity must not stand in for the missing argument.

## Alternatives considered

### Iterative capacity growth

Rejected as the production method.

A SAT result at capacity `k` can provide a canonical witness after checking.
An UNSAT result at `k` says nothing about capacity `k+1` without completeness.
Even repeated UNSAT up to a large number does not cover a missed branch or an
unbounded entry queue. Capacity growth is useful only to find counterexamples
to a transfer rule or to estimate solver cost.

### Fixed length-plus-buffer arrays

Accepted after certification for dense log windows and known finite queues.
Rejected as a universal representation.

The SMT shape is good: direct selects, store chains, finite domains, and easy
decoding. A full log prefix still turns a large physical index into a large
formula. An unknown initial queue has no derivable finite length.

The abstract evaluator may choose a fixed array only after
`FootprintSufficient` proves that the exact range or maximum occupancy covers
every path.

### Linked cells

Rejected as the default for logs and queues.

A linked update touches few cells, but canonical lookup becomes a symbolic
pointer chase. A complete bounded graph needs address bounds, uniqueness,
acyclicity, reachability, chain length, and canonical order. The generator
must unroll those facts or introduce quantified reachability. Neither helps
the current `QF_AUFLIA` formula.

Linked queues do not eliminate the source-filtered scan. They only make the
unlink smaller after the scan finds a predecessor. The design remains a
benchmark contender if certified queue token counts become large.

### Pure sparse absolute-index maps

Accepted for exact log lookups. Rejected as the whole log abstraction.

An SMT array can select index `1000003` without declaring earlier entries.
This property is necessary. It is not sufficient. Unconstrained positions do
not prove absence, rightmost signature, latest configuration, prefix equality,
or term order across an omitted interval.

Adding universal axioms over all integer indices changes solver behavior and
still leaves a difficult witness checker. Finite query summaries provide the
missing proof objects while retaining a quantifier-free formula. That produces
the log hybrid.

Sparse rank maps are a poor queue representation because canonical rank
changes after source-filtered removal. Stable message identities plus ordered
gaps model the finite observation more directly.

### Hybrid logs and queues

Accepted, with different forms.

The log hybrid has a dense exact mutation suffix, sparse older absolute cells,
and query summaries. The queue hybrid has exact relevant message tokens and
opaque ordered gaps. If the entry queue is known finite, every gap expands to
an exact finite sequence and the lowering simplifies to a compact fixed
buffer.

This is not one generic container abstraction. Logs and queues have different
canonical queries and need different sufficiency lemmas.

## Abstract evaluator obligations

The evaluator must cover all paths permitted by the grammar, including hidden
actions and branch ambiguity. Each transfer records:

```text
guard
canonical reads
canonical writes
new exact cells or tokens
summary carry, update, and invalidation
next abstract state
```

Append adds a tail cell and updates signature or configuration summaries.
Truncation removes suffix cells and invalidates every crossed summary.
Replacement adds an exact range. Send snapshots immutable message fields.
Receive branches on the selected token and handler, then preserves queue
order. Coalescing branches on exact equality across tokens and gaps.

Joining paths unions resources but retains guards. A simple maximum over one
chosen action path is not enough.

For an unknown entry log, the evaluator starts with an opaque prefix and
generates query summaries on demand. For an unknown entry queue, it starts
with an opaque gap. Any operation that cannot be summarized in the current
domain causes `FootprintError`.

### Monotone support plan

The evaluator records a compact support state before and after demand closure
at every step. The support includes exact log keys, exact ranges, query
summaries, queue tokens, opaque gaps, and equality facts.

The required invariant is:

```text
supportBefore[i] <= supportClosed[i] <= supportBefore[i + 1]
PreStepSufficient(i, supportClosed[i])
```

The order is an information and identity order. Exact keys and token identities
never disappear. Unknown facts may refine to exact facts. A summary may split.
Canonical liveness is separate.

This separation handles non-monotone Raft operations:

- append activates a new tail key after the step;
- conflict truncation marks suffix keys nonlive but retains their provenance;
- enqueue adds a token only on the nonduplicate branch;
- dequeue marks a selected token nonlive and joins adjacent gaps.

The final SMT schema may use fixed arrays for the union of all support
identities. Step-indexed support and live guards keep cells demanded later
inactive and unconstrained at S0. That is compilation of a proved finite
support plan, not allocation-and-retry.

### Later old-index references

Suppose S0 summarizes indices 1 through 999999 and step 20 first reads index
500000. Demand closure at step 20 splits the prefix summary into a symbolic
exact cell and residual summaries.

This support refinement does not change the canonical state. A refinement
lemma supplies a bounded view of the same canonical state. The evaluator then
propagates the cell's provenance through earlier steps that could not modify
the index. If an earlier branch may have truncated or replaced that position,
the plan records guarded versions. If it cannot establish one of those cases,
extraction fails.

## How sufficiency supports completeness

`FootprintSufficient` is a semantic coverage statement. It says every
canonical evaluation required by the trace and every permitted action path is
representable in `X`.

`Concretizes X bounded canonical` gives meaning to one bounded state. It must
relate:

- exact log cells to canonical entries at absolute indices;
- dense suffix order and absolute length;
- exact queue tokens and opaque gaps to one canonical ordered list;
- each summary witness to the canonical omitted region.

Step correspondence then preserves that relation. The forward direction shows
that every canonical step has a bounded step. The backward direction shows
that every bounded solver step has a canonical step from the same current
representative. The post-state relation prevents opaque history from changing
without a canonical action.

Use `Concretizes supportClosed[i] bounded[i] canonical[i]` at each concrete
step. A separate support-refinement theorem relates `supportBefore[i]` and
`supportClosed[i]` to the same canonical state. Ghost support growth therefore
cannot masquerade as a Raft transition.

Together:

- projection plus forward correspondence proves `bounded_complete`;
- concretization plus backward correspondence proves `bounded_sound`;
- observation equivalence connects both runs to the trace.

Only then does bounded UNSAT reject a canonical trace.

## Formula evidence

Exact measurement command:

```bash
python3 - <<'PY'
from pathlib import Path
import json
root = Path("lean/.lake/build")
for name in ("cheap-full-state-smt", "naive-full-state-smt"):
    path = root / name / "formula.smt2"
    text = path.read_text()
    witness = json.loads((root / name / "witness-v1.json").read_text())
    def leaves(value):
        if isinstance(value, dict):
            return sum(leaves(item) for item in value.values())
        if isinstance(value, list):
            return sum(leaves(item) for item in value)
        return 1
    print(name, path.stat().st_size, text.count("(select "),
          text.count("(store "), text.count("(ite "),
          text.count("(forall "), leaves(witness))
PY
```

Observed output:

```text
cheap-full-state-smt 7352853 121419 2149 2237 0 24873
naive-full-state-smt 127566439 2212107 3735 11753 0 46973
```

Both formulas declare 1,539 arrays. The checked report records a 3,857 ms
solver median and 4,661 ms p95 for the cheap footprint, versus 102,710 ms for
naive full state. Decode drops from 13,249 ms to 798 ms. A fresh read-only
three-run sample of the cheap formula was 3,972, 4,038, and 4,135 ms.

The cheap footprint is hardcoded and unproved. It is performance evidence for
a small referenced footprint, not evidence of completeness. The revised
pipeline keeps its useful formula shape and replaces its manual assumptions
with `deriveFootprint_sufficient`.

## Witness and checker

The witness must include:

- the footprint hash and checked sufficiency-certificate identity;
- guarded action and branch choices;
- active exact log cells and dense suffix fields;
- log summary witnesses and exclusion intervals;
- exact queue tokens, gap lengths, source-absence facts, and equality facts;
- absolute lengths, indices, and action parameters.

The decoder checks the representation. It does not recreate one default JSON
record for each omitted absolute position. The theorem connects the checked
bounded value to an unbounded canonical concretization.

Until these proofs land, SAT still needs canonical replay from a materialized
checkpoint, and UNSAT remains inconclusive.

## Final position

The primary artifact is the sufficiency certificate, not the capacity number.
Use hybrid logs. Use certified fixed queues for known finite entry queues and
ordered gap queues for unknown entry states. Lower either form to finite arrays
only after `FootprintSufficient`.

If diagnostic capacity growth finds a new SAT witness, treat it as a failing
test for the abstract evaluator or certificate checker. Repair the proof story.
Do not promote the larger number to production policy.
