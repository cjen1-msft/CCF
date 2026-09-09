# Recommendation: certify the footprint before generating SMT

## Decision

Do not discover container bounds by generating a formula, observing exhaustion,
and increasing capacities. The production pipeline must derive one footprint
from the ordered trace and action skeleton, then prove that the footprint is
sufficient:

```lean
def deriveFootprint :
    ParsedTrace -> ActionSkeleton -> EntryConstraint ->
      Except FootprintError TraceFootprint

def FootprintSufficient
    (trace : ParsedTrace)
    (skeleton : ActionSkeleton)
    (entry : EntryConstraint)
    (footprint : TraceFootprint) : Prop :=
  -- Every canonical read and write on every permitted finite path
  -- has an exact cell, ordered gap, or proved query summary in footprint.

theorem deriveFootprint_sufficient
    (found : deriveFootprint trace skeleton entry = .ok footprint) :
    FootprintSufficient trace skeleton entry footprint
```

Only this theorem, or a checked certificate that instantiates it, may authorize
bounded SMT generation. A resource ceiling may stop `deriveFootprint`, but the
result is `FootprintError` and `INCONCLUSIVE`. Increasing a ceiling and retrying
is useful during development. It is not a completeness argument.

Keep `CCFRaft.Model` generic and unbounded. The footprint, bounded state, SMT
formula, and witness live in a separate lowering layer.

## Recommended representation

Use representation-specific finite carriers chosen from the certified
footprint:

- **Logs:** a hybrid of a dense exact mutation suffix, sparse exact cells at
  absolute indices, and proved summaries for omitted history.
- **Queues restored from an exact checkpoint or known empty:** a compact
  fixed length-plus-buffer array, sized to the certified maximum occupancy.
- **Queues in an arbitrary unknown entry state:** an ordered hybrid of exact
  relevant messages and opaque gap summaries. Lower the finite token and gap
  skeleton to fixed arrays after sufficiency is proved.

Reject linked cells as the default. They reduce some write footprints but add
symbolic reachability, address uniqueness, acyclicity, and bounded pointer
chases. Reject a pure sparse map for logs because exact cells do not prove
rightmost, absence, configuration-history, or prefix-equality queries. Reject
a sparse rank map for queues because removal changes later ranks.

This recommendation separates two questions. `TraceFootprint` says which
canonical facts a finite trace can need. The bounded representation says how
to encode those facts for SMT.

## What `TraceFootprint` contains

### Shared trace data

```text
relevantNodes
transactionIdentities
actionAlternatives[step]
branchGuards[step]
observationReads[step]
hiddenActionClosure
resourceUse
```

`actionAlternatives` contains every grammar-permitted constructor and finite
parameter ambiguity. `hiddenActionClosure` contains every permitted hidden
action between observations, not only the path preferred by preprocessing.
If the grammar admits an unbounded hidden loop, the extractor cannot issue a
finite certificate without a separate proved loop bound.

### Per-node log footprint

```text
absoluteLength expressions at each step
exact absolute indices
exact contiguous overlap and replacement ranges
dense mutable suffix windows
prefix-equality classes between states and nodes
configuration records needed by current and active configuration queries
rightmost-signature queries:
  frontier, witness index, witness entry, no-later interval
rightmost-term queries for NACK repair:
  frontier, threshold, witness index and term, no-later-match interval
term-order summaries across opaque intervals
summary provenance and invalidation edges
```

Physical indices stay absolute. The ADR requires this at
`lean/adr/0002-grammar-safe-cuts-and-symbolic-trace-alignment.md:244-247`.
Index `1000003` changes numeral size, not the number of log cells.

The summaries are part of `X`, not hints added by the SMT generator. The
canonical model scans log history for:

- current and pending configurations (`Model.lean:562-585`);
- the rightmost signature (`Model.lean:608-640`);
- the rightmost term match used by NACK repair (`Model.lean:777-818`);
- overlap term equality and full entry equality (`Model.lean:693-728`).

Each summary names its canonical query, frontier, witness, and exclusion
interval. `FootprintSufficient` proves that these facts answer that query for
every path covered by the skeleton.

### Per-destination queue footprint

For a known finite initial queue, `X` contains:

```text
initial ordered messages
generated message tokens
exact message fields
enqueue and coalescing equality classes
source-filtered receive selections
live token order after each step
maximum live occupancy
```

The maximum occupancy is an output of abstract evaluation. It is not a guessed
capacity.

For an unknown entry queue, a length bound cannot be derived from the trace
alone. A later `receive source destination` may select a message after an
arbitrarily long prefix, and `enqueueNoDup` may find an equal message anywhere
in the queue. `X` therefore uses an ordered queue skeleton:

```text
gap0, exactMessage0, gap1, exactMessage1, ..., gapN

gap summary:
  opaque length expression
  sources absent from the gap
  equality classes absent or present for messages tested by enqueueNoDup
  preserved-order identity across adjacent states
```

The first selected message from a source has a preceding gap summary that
excludes that source. A dequeue removes the exact selected token and joins its
adjacent gaps while preserving their order facts. An enqueue either follows a
proved equality hit and leaves the queue unchanged, or follows absence facts
for every gap and exact token and appends a new token.

If the summary domain cannot decide a later selection or equality test, the
extractor returns `FootprintError`. It must not pick a finite initial queue
capacity and hope that it is enough.

This matches canonical `enqueueNoDup` and `takeFirstFrom`
(`Model.lean:658-683`).

## How abstract evaluation derives `X`

Run a path-sensitive abstract interpreter over the ordered action skeleton.
Its initial abstract state comes from `EntryConstraint`, not from a guessed
bounded state.

### Compact support states, not a full bounded S0

`deriveFootprint` constructs a support plan:

```lean
structure SupportState where
  logLength : AbstractNat
  logKeys : Finset AbsoluteIndex
  logRanges : Finset AbsoluteRange
  logSummaries : Finset SummaryQuery
  queueTokens : Finset MessageToken
  queueGaps : List GapSummary
  equalityFacts : Finset EqualityQuery

structure FootprintPlan where
  before : Fin (n + 1) -> SupportState
  afterClosure : Fin n -> SupportState
  finalFootprint : TraceFootprint
```

`before 0` is compact. It contains observed entry-state scalars, exact cells
that the first observation or action reads, and summaries for the remaining
unknown log prefixes and queue gaps. It is not a log or queue buffer of size
`finalFootprint`.

Before concrete step `i`, the evaluator closes `before i` under all reads of
the observation, every guarded action alternative, and every summary that
those reads produce. This gives `afterClosure i`. The abstract action transfer
then produces `before (i + 1)`.

The support universe grows monotonically:

```lean
SupportLe (before i) (afterClosure i)
SupportLe (afterClosure i) (before (i + 1))
PreStepSufficient trace skeleton i (afterClosure i)
```

`SupportLe` means that every exact key, message token, gap identity, equality
query, and summary query remains represented. A fact may refine from unknown
to exact. A summary may split into smaller summaries and one exact cell. A
truncated log cell or dequeued message remains in the support universe as
inactive provenance. The canonical live log and queue do not grow
monotonically.

The invariant is:

```text
support knowledge grows monotonically
and the closed support is sufficient before each canonical step
and the abstract transfer covers every possible concrete result
```

This is semantic support growth. It is not runtime allocation of a larger
static SMT buffer. After the full abstract pass, the generator may declare one
finite carrier for the union `finalFootprint`. Per-state presence, live, and
known guards ensure that S0 uses only `before 0`. Cells first demanded at step
20 are not asserted active or exact at S0 merely because their carrier exists
in the final formula.

### Unknown entry state

Start every unobserved scalar at `top`, every log as an absolute length plus
an opaque history, and every relevant queue as an opaque ordered gap.
Observations and entry constraints refine these values. A canonical operation
does not force the interpreter to materialize an entire list. It requests an
exact cell, an exact finite range, or a query summary from the footprint
domain.

If a canonical operation depends on a property that the domain cannot
summarize, abstract evaluation fails. This is the honest result for a truly
unbounded unknown entry state.

When a later step first names an old absolute index, closure splits the opaque
prefix summary at that index. The new support has an exact symbolic cell plus
left and right summaries. The refinement denotes the same canonical state; it
is a ghost support step, not a Raft action. The evaluator propagates the cell
back through prior abstract states whose actions provably did not modify that
index, or records the action version that created it. If provenance crosses an
unknown write, abstract evaluation branches or returns `FootprintError`.

### Append

For `clientRequest`, `changeConfiguration`, and
`signCommittableMessages`, record:

- the current absolute length expression;
- the new tail index;
- the exact appended entry;
- submitted transaction or join-history effects;
- summaries that the new entry updates.

Append keeps earlier opaque history unchanged. A reconfiguration adds a
configuration-history record. A signature updates rightmost-signature queries
whose frontier includes the new tail.

The appended absolute index joins the support universe after the action. It
is inactive before the action and live afterward. No S0 slot is allocated as
an active canonical entry for a future append.

### Truncation and replacement

For conflict truncation, record the cut index, every exact overlap read, and
the relationship between the old and new absolute lengths. Remove exact cells
above the cut. Invalidate each configuration, signature, term, or prefix
summary whose witness or exclusion interval crosses the removed suffix.

For extension, add the request entries as an exact contiguous range. Recompute
only the summaries invalidated by the cut or affected by the new range.

Truncation changes liveness, not support membership. Removed keys stay as
tombstoned provenance so `SupportLe` remains monotone. If a later append reuses
the same absolute index, its state-versioned value comes from the append, not
from the removed entry.

If the cut is symbolic, split on the finite order relationships that affect
the skeleton. Join the resulting footprints by union while retaining branch
guards. Do not choose one branch early.

### Send, receive, FIFO order, and coalescing

A send reads the source log cells and summaries required to construct the
message. It creates a message token with immutable fields. Abstract enqueue
splits on exact duplicate presence. Each absence branch adds the equality
facts needed to justify append.

A receive splits on the canonical handler branches and on the identity of the
first message from the chosen source. It adds the selected token, the
source-absence fact for every preceding gap, every log query made by the
handler, and the response token. The interpreter applies dequeue and response
enqueue to every branch.

The fixed queue capacity for a known entry queue is the maximum live token
count across all joined paths. For an unknown queue, the bound is the count of
exact tokens and gaps, not total canonical queue length.

Enqueue adds a token to the support universe only on the nonduplicate branch.
The duplicate branch refines an equality query and leaves the live order
unchanged. Dequeue marks the selected token nonlive and joins adjacent gaps;
the token remains as provenance. These transfers preserve monotone support
while modeling a non-monotone live queue.

### Configuration and signature scans

Compile a scan request to a witnessed summary query. For a rightmost signature,
record an exact signature at `i` and a no-signature summary for `(i, frontier]`.
For current configuration, record the chosen reconfiguration and the absence
of later reconfigurations through the commit frontier. Retain pending
configuration records after that frontier.

Share summaries between state versions when no action can affect their
interval. An append, cut, or replacement emits explicit carry, update, or
invalidation edges. This prevents adjacent SMT states from inventing unrelated
opaque histories.

### Branches and hidden actions

Evaluate every finite action alternative. Each abstract transfer returns:

```text
guard, reads, writes, summary effects, next abstract state
```

At a join, `X` contains the union of resources and guarded relationships. The
certificate proves coverage for every permitted path. A solver may select a
path later, but it cannot select an action whose reads were omitted from `X`.

## From sufficiency to completeness

Define:

```lean
Concretizes X bounded canonical
```

The relation says that exact cells match, dense suffixes preserve absolute
order, queue tokens and gaps form the canonical queue in order, and every
summary is true of the omitted canonical region.

Use the step-indexed form
`Concretizes (plan.afterClosure i) bounded canonical` immediately before each
step. A support-refinement lemma shows that if `s <= s'`, then any canonical
state concretized by `s` has a compatible refinement concretized by `s'`.
The lemma connects ghost support growth to the same canonical state.

Prove these obligations:

1. `deriveFootprint_sufficient`.
2. `SupportLe` is reflexive and transitive, and every planned closure and
   transfer is monotone.
3. `PreStepSufficient` holds for every observation and guarded action branch.
4. Support refinement preserves the represented canonical state.
5. Every canonical entry state satisfying `EntryConstraint` projects to a
   well-formed bounded state under `X`.
6. Every well-formed bounded state has at least one canonical concretization.
7. Observations and action skeleton predicates are equivalent under
   `Concretizes`.
8. For each guarded action alternative, a canonical step has a bounded step.
9. Every bounded step has a canonical step from the same current canonical
   representative.
10. The next bounded and canonical states satisfy `Concretizes`.
11. The witness decoder produces exactly the well-formed bounded state it
   claims.

Items 8 through 10 are step correspondence in both directions. They prevent
the solver from choosing one opaque prefix before a step and an unrelated
prefix after it. The ADR requires this skeleton-restricted finite-horizon
bisimulation at lines 155-165.

Then prove:

```lean
theorem bounded_sound
    (sufficient : FootprintSufficient trace skeleton entry X) :
    BoundedMidtraceSatisfiable trace skeleton entry X ->
      MidtraceSatisfiable trace

theorem bounded_complete
    (sufficient : FootprintSufficient trace skeleton entry X) :
    MidtraceSatisfiable trace ->
      BoundedMidtraceSatisfiable trace skeleton entry X
```

`bounded_sound` authorizes a decoded SAT witness. `bounded_complete` authorizes
bounded UNSAT as a canonical rejection. The ADR states the same split at
`0002-grammar-safe-cuts-and-symbolic-trace-alignment.md:299-316`.

## SMT and witness shape

After certification, lower `X` to quantifier-free arrays and linear integer
arithmetic:

- split field arrays for exact log cells and message tokens;
- fixed arrays for the certified number of suffix cells, sparse cells, queue
  tokens, gaps, and summaries;
- guarded store chains for each action alternative;
- no universal array axioms over absolute indices;
- witness aliases only for active cells, gaps, summaries, branch choices, and
  action parameters.

Declaring the union carrier does not turn S0 into a full fixed-capacity state.
Each carrier cell has step-indexed support and live guards. The formula
constrains a field only when the support plan needs that field at that step.
This preserves the compact existential entry state even if later steps refine
many old indices.

The current prototype is already `QF_AUFLIA`
(`naive_full_state_smt.py:3157`). It declares state field arrays at lines
590-596, unrolls log constraints at lines 741-918, and unrolls queue slots at
lines 919-1034. Its decoder materializes every fixed log and queue slot
(`NaiveFullStateWitness.lean:209-248` and `:447-472`). The production witness
must instead serialize certified active cells and summary evidence.

## Measured cost evidence

Current checked artifacts show why the proof should minimize referenced facts,
not merely array declarations:

| Measurement | Certified-like two-node footprint prototype | Naive 15-node state |
| --- | ---: | ---: |
| Formula bytes | 7,352,853 | 127,566,439 |
| `(select ...)` terms | 121,419 | 2,212,107 |
| `(ite ...)` terms | 2,237 | 11,753 |
| SMT arrays | 1,539 | 1,539 |
| Witness bytes | 669,245 | 1,921,992 |
| Decode | 798 ms | 13,249 ms |
| cvc5 | 3,857 ms median, 4,661 ms p95 | 102,710 ms |

The cheap prototype uses a hardcoded footprint, so it is not yet certified.
The comparison changes node scope as well as formula references. It supports
one limited conclusion: declared array count did not predict cost, while
expanded selects, conditionals, witness fields, and constrained indices did.

## Staged design

1. Define `TraceFootprint`, the abstract domain, transfer results, and
   `FootprintSufficient`.
2. Implement append-only evaluation from an opaque entry log. Prove
   `deriveFootprint_sufficient` for `clientRequest` and signatures.
3. Add known-empty and exact-checkpoint queues. Derive maximum occupancy by
   path join, then prove fixed-buffer correspondence.
4. Add sends, duplicate coalescing, and exact queue tokens.
5. Add unknown entry queues with ordered gaps, source-absence summaries, and
   equality summaries.
6. Add receive branches, overlap ranges, truncation, and replacement.
7. Add configuration, signature, term, and prefix summaries.
8. Enable authoritative UNSAT only for the action grammar covered by
   `bounded_complete`.

Each phase rejects unsupported abstract operations. No phase uses
capacity-doubling as evidence of completeness.

## Falsifiable design gates

These gates can change the representation, not the sufficiency requirement:

- Use a dense log window for a certified exact range when its width is at most
  64 and no more than twice the number of exact indices. Otherwise use the log
  hybrid.
- Use a compact fixed queue when `EntryConstraint` proves a finite initial
  queue and abstract evaluation proves maximum occupancy. Use ordered gaps
  whenever the initial queue remains unbounded.
- Reconsider linked queues only if certified real traces have p95 exact-token
  count above 16, compaction exceeds 35% of generated `store` terms, and a
  linked encoding improves solve p95 by at least 30% without adding
  quantifiers.
- Fail generation at a configured resource ceiling, such as 25 MiB formula
  text or 10-second solve p95. Classify the result as `INCONCLUSIVE_RESOURCE`.
  A larger ceiling may diagnose the case but cannot turn an unproved
  footprint into a sufficient one.

## Reproduction commands

Run from the repository root:

```bash
python3 - <<'PY'
from pathlib import Path
import re
for name in ("cheap-full-state-smt", "naive-full-state-smt"):
    root = Path("lean/.lake/build") / name
    text = (root / "formula.smt2").read_text()
    print(name, {
        "bytes": len(text.encode()),
        "arrays": len(re.findall(r"^\(declare-const .*\(Array ", text, re.M)),
        "selects": text.count("(select "),
        "stores": text.count("(store "),
        "ites": text.count("(ite "),
        "forall": text.count("(forall "),
        "witness_bytes": (root / "witness-v1.json").stat().st_size,
    })
PY

cd lean
./check_ccfraft_cheap_full_state_prototype.sh
./check_ccfraft_naive_full_state_prototype.sh --existing-witness
```

Iteration remains useful for finding a missing transfer rule. For example,
if a larger diagnostic footprint changes UNSAT to SAT, that is a
counterexample to the current sufficiency proof or certificate checker. The
production fix is to repair the abstract evaluator and theorem, not to retain
the larger guessed capacity.
