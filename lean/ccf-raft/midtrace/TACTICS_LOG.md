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

### T1. Exact IR with declared bounds (GenIr / GenLib / GenModel)

Approach. `GenModel` is a line-by-line transliteration of the Lean model's
handlers into `GenLib` combinators. The combinators build `GenIr` nodes:

- scalars, `ite`, `and`/`or`, `le`/`eq`, `add`/`sub`/`min`/`max`;
- arrays as `store`/`lam`/`scan`/`select`;
- `fold` (max/sum/last/first/any/all) over an index range;
- commands `require` (guards, observations), `assume` (invariants and caps).

The unknown initial state is a set of declared bounds:

- log length <= L, where L = (largest natural number the suffix mentions) +
  slack (4);
- at most Q = 4 packets per channel;
- at most one effect per entry (E = 1).

Within those bounds the IR is exact: SAT(IR) <=> exists s0 that replays the
suffix. UNSAT therefore means "invalid within bounds", and a SAT model is
turned into an initial state and certified with `Replay.replayFrom`.

Result: all 50 positive scenarios are VALID with certified witnesses (max
7.1 s). 1032 of 1045 mutants are INVALID; the 13 that differ from the bespoke
encoder are capacity cases, where bespoke says UNKNOWN and is VALID at Q=32.

### T2. Capacity retry

Approach. On INVALID, re-run once with Q and slack multiplied by 4. A VALID
retry is reported as VALID ("needed relaxed bounds") because its witness is
certified.

Result: 1019 INVALID, 26 VALID (22 of them mutants that happen to be
valid), 0 ENGINE-BUG. One capacity case still needs more than Q = 16.

Implication: bounds are a declared over-approximation knob, not a soundness
risk. The witness check makes VALID exact, and UNSAT is exact relative to
the bounds.

### T3. Linear normalisation and syntactic read-over-write

Profiling attributed SMT lines to instructions (`; instr i` comments). Two
generic gaps showed up:

- `(v + 1) - 1` was not simplified;
- long runs of stores whose lowered indices were equal but never compared.

Rules added (shared `SmtCore`, so the bespoke encoder also uses them):

- `offsetOf`: every int term is base + constant; `le`/`eq`/`add` decide or
  canonicalise same-base comparisons;
- read-over-write when the store index equals the read index plus a known
  offset (equal -> value, different -> skip);
- shadowing: consecutive stores at the same lowered index skip each other.

Result on suffix_collision.3: SMT lines 966k -> 55k, lowering 3.3 s -> 0.44 s,
solve 2.0 s -> 0.22 s. Verdicts unchanged; the bespoke encoder is unchanged
(50/50).

### T4. Scaling on the repo scenarios

Every cut of every scenario (442 runs, `scaling.py`, MIDTRACE_SUB=gen) was
VALID. The fitted log-log exponent against instruction count was taken over
the 11 scenarios with >= 800 instructions:

| quantity | median | max |
| --- | --- | --- |
| time (gen) | 1.15 | 1.30 |
| IR nodes | 1.04 | - |
| SMT lines | 1.14 | - |
| time (bespoke) | 0.83 | 1.10 |

The cut position barely matters.

### T5. Long synthetic traces: both encoders are quadratic

The repo scenarios are short (< 3k instructions), so `longgen.py` generates:

- `rep_N`: steady replication;
- `elect_N`: rotating elections plus replication.

N = 10..160, up to 28k instructions; each entry below is time in ms / SMT
lines.

| trace | gen | bespoke |
| --- | --- | --- |
| rep_10 | 691 / 20k | 144 / 20k |
| rep_40 | 4084 / 166k | 1066 / 155k |
| rep_160 | 51156 / 2.1M | 14443 / 1.8M |
| elect_10 | 2008 / 51k | 360 / 38k |
| elect_40 | 18270 / 758k | 6218 / 403k |
| elect_160 | 367424 / 25.4M | 459138 / 5.8M |

IR build time is linear. SMT size and lowering time grow about 3.5x per
doubling in both encoders.

### T6. Diagnosis: the queue offset at the cut stays symbolic

Profiling wide case splits (`--profile` prints splits of width >= 16) showed
where the cost went. Most of it was in follower state observations after an
AppendEntries receive. Each one has a `fold-max` for the last signature
below `min(leaderCommit, lastNewIndex)`, whose bound has an interval of
width 17-21.

The bound is wide because the popped message is a mux:

```
pop at position p = ite(len0 = p, push_0, ite(len0 = p - 1, push_1, ..., init_p))
```

Here `len0` (the channel's packet count at the cut) is symbolic in [0, Q].
Once one mux enters a node's state, every later fold over that state splits.

Experiments:

- Pinning every `len0` to its true value (debug `--fix-len`) makes the
  encoding linear: rep_80 goes from 577k to 15k SMT lines.
- The full formula does determine every `len0` (one yices query per value).
- Interval narrowing never finds them. The observed head packet always
  matches both the pushed message and a free initial packet that can mimic
  it. Which of the two it was is only decided by contradictions several pops
  later.
- Adding exclusion sets ("holes") to the interval domain changed nothing (the
  SMT output was byte-identical). The missing deduction is case analysis,
  not representation.

Implication: local propagation (intervals, holes, unit propagation) cannot
resolve a selector whose wrong values are refuted only by a later conflict.
That needs search.

### T7. Backbone tactic: solver-pinned selectors

Approach (generic, `GenDriver.runOnce`):

1. Lower the IR command by command, streaming SMT lines into an incremental
   yices session.
2. `SmtCore` records "selectors": integer terms of domain width <= 16 that
   are compared with a constant (`(= x k)`).
3. At instruction 32, 64, 128, ... (doubling), if some selector is still
   open: `check-sat`.
   - If UNSAT, the prefix is already inconsistent: INVALID.
   - If SAT, read the model value m of each open selector, then
     `check-sat-assuming (not (= x m))`.
   - If that is UNSAT, x = m is implied by the prefix. Assert it as a
     background requirement, which narrows intervals, so later lowering
     sees a constant.

Each pin is a consequence of the prefix, which is a subset of the final
formula, so it preserves SAT and UNSAT. This is the standard backbone
computation (cf. z3's `ctx-solver-simplify`, and backbone extraction in SAT
preprocessing). Nothing in it is Raft-specific: it acts on any small-domain
integer that the encoding branches on.

Results (time ms / SMT lines; probes = solver checks):

| trace | before (T5) | backbone | probes / pinned | probe ms |
| --- | --- | --- | --- | --- |
| rep_10 | 691 / 20k | 557 / 4.2k | 20 / 6 | 8 |
| rep_40 | 4084 / 166k | 2256 / 8.6k | 22 / 6 | 9 |
| rep_80 | 13783 / 577k | 5140 / 17k | 23 / 6 | 15 |
| rep_160 | 51156 / 2.1M | 13172 / 44k | 24 / 6 | 28 |
| elect_10 | 2008 / 51k | 1458 / 6.0k | 26 / 8 | 11 |
| elect_40 | 18270 / 758k | 6290 / 11k | 28 / 8 | 12 |
| elect_80 | 73426 / 4.05M | 13666 / 18k | 29 / 8 | 9 |
| elect_160 | 367424 / 25.4M | 31682 / 32k | 30 / 8 | 13 |

- SMT size is now linear, and smaller than bespoke at every size
  (elect_160: 32k vs 5.8M lines).
- Time per doubling is about 2.1-2.3x. Build is linear (63% of elect_160).
  Lowering is still about 3x per doubling.
- The 50 repo positives are all VALID, max 2.2 s.

Implications:

- The single largest generic win so far is search, not rewriting: a handful
  of solver calls on a small prefix removes a branch that rewriting cannot
  decide.
- Probing cost is negligible (<= 30 ms) because the selectors are decided
  early, while the prefix is small.
- A selector that only becomes determined late would be decided at the next
  doubling checkpoint, so it costs at most 2x of the muxed stretch.

Negatives with the backbone: the verdicts on all 1045 mutants are identical
to T2 (1019 INVALID, 26 VALID, 0 ENGINE-BUG). Under 12-way load, p50 is
0.85 s, p90 2.9 s and max 6.7 s. Build time dominates at these sizes.

### T8. Deep cuts: lowering is O(len0) per instruction

Test bed: `shift.py` adds D to every log index in a repo trace (state
fields, packet indices, configuration indices), which gives the same run on
top of a log that already holds D entries. A real service cuts deep into a
long ledger, so D = 10^6 is realistic.

Before gap compaction (backbone on, D = 1000):

| trace | total | backbone probes | lowering | solve | SMT lines | wide ops |
| --- | --- | --- | --- | --- | --- | --- |
| replicate | 15.6 s | 13.7 s | ~1.5 s | 0.37 s | 148k | 125 |
| reconfiguration | 26.1 s | 14.3 s | - | 7.5 s | 462k | 327 |

- The wide operations are whole-log folds and scans of width ~1004-1008.
  They come from the model's configuration history, retirement and
  `maxCommittableIndex`.
- The first instruction observes `logLength` and `commitIndex`, so most
  fold bounds are literals early. The cost is the size, not symbolic
  bounds: every fold emits one term per cell, and each solver check
  (including backbone probes) pays for them.
- Cost is linear in D. At D = 10^6 every fold exceeds `SPLIT_LIMIT` and the
  trace is "unsupported".

Implication: an encoding of an abstract log must not mention every cell. It
must summarize runs of cells that the suffix cannot distinguish.

### T9. Gap compaction (generic tactic + declared bound)

Bound (declared, like Q). Let E be the union of [v - slack, v + slack] over
every natural number v in the suffix, plus [-slack, Q + slack]. Intervals
separated by fewer than 32 indices are merged. Cells of initial-state arrays
outside E are *gap cells*:

- `--gaps zero` (default): every gap cell is 0 / false / the zero array.
- `--gaps uniform`: the cells of one gap share one unknown per base array
  and path.
- `--gaps off`: every cell is its own unknown (the T7 behaviour).

The bound only removes initial states, so VALID stays sound and is
certified by witness replay. INVALID becomes "INVALID within L, Q and the
gap fill", exactly like Q. The capacity retry (T2) re-runs with 4x slack,
which widens E.

Tactic (`GenLower`, model independent). It acts on the IR's arrays, folds
and scans, not on Raft:

1. Pieces. Any index range is cut into explicit runs and gap parts
   (`pieces`, binary search over E).
2. Symbolic reads. `select a i` with a symbolic i is an ite chain over the
   explicit cells, plus one term per gap part: the gap cell read at
   `clamp(i)`, pushed through stores (skipping stores whose range is
   disjoint), lambdas (beta reduction with the symbolic index) and scans.
3. Folds over a gap part wider than 32 are probed. Lower the body twice,
   with two fresh indices k1 and k2 declared over the part.
   - If the conditions are the same term and the values are the same term
     (or both are "index + same offset"), the fold is uniform over the
     part. Then any / all / first / last / max / sum have closed forms in
     the clipped bounds s = max(a, lo) and e = min(b, hi).
   - Otherwise SmtCore reports the literals that k1 was compared with
     (`watch` / `hits`). Split the part around them (h - 1, h, h + 1) and
     re-probe, up to depth 4. Otherwise enumerate, and record a fallback.
4. Scans over a gap part are probed with a fresh accumulator x:
   - absorbing if step(k2, step(k1, x)) == step(k2, x) as terms, so
     s[k] = step(k, s[a - 1]);
   - additive if step(k, x) = x + d for one d independent of k and x, so
     s[k] = s[a - 1] + (k - a + 1) * d;
   - otherwise split at the hits, or enumerate.

Soundness argument: hash-consing is by SMT text, so two probes giving the
same term means the term does not depend on the index. Simplifications made
while lowering with a probe index use only its declared range [a, b], which
holds for every index the summary is used at. The probe definitions that
are left in the script are unasserted.

Results (`replicate` / `reconfiguration`, D = 1000):

| mode | replicate | reconfiguration | SMT lines |
| --- | --- | --- | --- |
| off | 15.7 s | 26.2 s | 148k / 462k |
| zero | 0.13 s | 0.54 s | 8.9k / 24.9k |

Sweep over the 50 repo positives (decision time = total - certify; 6-way
parallel; 3 traces have fewer than 10 actions):

| D | verdicts | decision max | fallbacks | certified |
| --- | --- | --- | --- | --- |
| 10^3 | 50 VALID | 3.3 s | 0 | yes |
| 10^4 | 50 VALID | 3.4 s (6.6 s under certify load) | 0 | yes |
| 10^6 | 50 VALID | 3.1 s | 0 | no (see below) |

- Lowering at D = 10^4, 10^5 and 10^6 for replicate: 73 / 69 / 87 ms, with
  identical SMT (8934 lines). Lowering no longer depends on D.
- Negatives (1045 mutants): unshifted, and at D = 10^6, both give 1019
  INVALID / 26 VALID, identical to T7, with 0 ENGINE-BUG. The max is 6.9 s
  unshifted and 11.5 s at D = 10^6 (INVALID pays for the retry).
- Unshifted positives: identical verdicts and SMT (+-1 line). The gaps are
  never used because E covers the whole log.

Certification is the new bottleneck. The witness replay runs the reference
model, whose `maxCommittableIndex` does `List.get?` inside a fold over the
log, which is O(L^2) per step. It took 31 ms / 484 ms / 35 s at
D = 10^3 / 10^4 / 10^5 (`perf`: 47% in `List.get?` under that fold), and
building a 10^6-entry witness alone takes 5.6 s. Above `--certify-limit`
(default 20000), VALID is reported "uncertified" and no witness is built.
This is not part of the decision. It only limits the self-check, and would
go away with an Array-based or `csimp` implementation of the model's log
functions.

Uniform fill (D = 1000): 50 VALID, but every trace falls back (up to 500
enumerated parts), and it is 3.8x slower (max 10.6 s). At D = 10^6 it times
out (> 300 s). Cause: a gap's mask cell is an unknown c, so the ranks scan
over the gap is rank(k) = r0 + ite(c, k - a + 1, 0). Comparisons such as
`le(n, rank(k))` then have a symbolic threshold inside a sum. That is not a
literal hit, so neither the split nor the closed forms apply. Fixing it
would need linear normal forms (solve `n <= r0 + (k - a + 1) * d` for k) or
representative-point reasoning. YAGNI until a trace needs a non-zero gap.

Implications:

- A declared bound that makes unmentioned cells *literal* is what turns
  folds into closed forms. A symbolic default is almost as expensive as no
  bound, because every threshold becomes symbolic.
- "Probe with two fresh indices and compare terms" is a cheap, generic
  uniformity test. It reuses the lowering itself, so no per-operator rules
  are needed. Splitting at hit literals localizes the non-uniformity to the
  few cells near mentioned indices.
- Related work: abstract interpretation over array segments (Cousot,
  Cousot and Logozzo, "A parametric segmentation functor for fully
  automatic and scalable array content analysis", POPL 2011). Here the
  segment bounds come from the trace's literals, not from program
  variables.

Status of Q6: deep cuts are solved for the zero fill. Decision time is
independent of D up to at least 10^6.

### T10. Incremental folds: reuse an earlier lowering of the same fold

After T7 the SMT is linear, but lowering is still about 3x per doubling.
Cause: the model re-evaluates whole-log folds and scans on every step
(`maxCommittableIndex`, configuration history, `SList.append` overlays).
Each step lowers O(L) fold points, and almost all of them are the same as
the previous step's. elect_160 lowered 2.08M fold points to emit 32k SMT
lines.

Approach (generic, `GenLower.lowerFold` / `deltaArr`; `--reuse on|off`):

1. Template. The fold body with its binder-free subterms replaced by holes.
   Templates are interned structurally, so two folds with the same template
   differ only in their holes (and in lo / hi / default).
2. Hole use. Each hole is classified by how the body uses it:
   - `select(h, k + c)`: `.read c` (only cells near k matter);
   - `le` / `eq` against `k + c`: `.cmp c` (only the cut point matters);
   - anything else: `.exact` (the hole must be identical).
3. Delta. For a new fold, take the most recent memo (up to 16) with the same
   template and compute a "may differ" set D of indices:
   - `.read`: the region where the two arrays may differ, shifted by c;
   - `.cmp`: two integer literals give the interval between them;
   - `.exact`: the same term, or an array with an empty delta;
   - otherwise top (no reuse).
   Array deltas walk "overwrite steps" back from both arrays in lockstep
   until they meet:
   - `store(a, i, v)` overwrites [i, i] (or [lo, hi] if i has a small range);
   - `lam k. ite(c, a[k], e)` overwrites the complement of the indices
     where c is surely true. "Surely" is an interval analysis of c over
     k, using the ranges of the k-free subterms (`surely`).
   The delta is the union of the regions above the meet point. If both
   chains end without meeting, compare the bases (same `ite` condition, or
   lam / scan with the same template). This is O(distance), memoized per
   array pair and depth.
4. Reuse. A point that the old fold covered and that is not in D reuses
   the old lowered condition and value (shared terms, nothing re-lowered).
   Points in D, and points outside the old cover, are lowered fresh. Scans
   are seeded the same way: the accumulator before the first changed index
   is taken from the memo.

Soundness: hash-consed terms are the meaning of the subterm, and a reused
term was a valid lowering of the same template at the same index under an
environment that agrees outside D. D over-approximates the differing
indices. Simplifications in the old term used only facts that still hold,
because assertions and pins only grow. So the reused term is equivalent to
a fresh lowering under the current assertions, though not always the same
text (the SMT differs by about 1%, and the backbone pinned 9 selectors
instead of 8 on elect). Eager lowering inside `surely` can emit dead
definitions, which are never asserted.

Results (sequential, unloaded; all VALID):

| trace | reuse | total | build | lower | solve | fresh fold points | SMT lines |
| --- | --- | --- | --- | --- | --- | --- | --- |
| elect_40 | off | 6.4 s | 4.8 s | 1.33 s | 0.22 s | 146k | 11.2k |
| elect_40 | on | 6.1 s | 4.8 s | 1.02 s | 0.22 s | 16k | 11.3k |
| elect_80 | off | 14.2 s | 9.9 s | 3.72 s | 0.49 s | 540k | 18.2k |
| elect_80 | on | 12.6 s | 9.9 s | 2.21 s | 0.47 s | 54k | 18.3k |
| elect_160 | off | 33.3 s | 20.0 s | 11.97 s | 1.21 s | 2.08M | 32.1k |
| elect_160 | on | 26.3 s | 19.9 s | 5.15 s | 1.24 s | 197k | 32.2k |
| rep_80 | off | 5.4 s | 3.2 s | 2.00 s | 0.19 s | 406k | 17.2k |
| rep_80 | on | 4.3 s | 3.2 s | 0.89 s | 0.19 s | 34k | 10.9k |
| rep_160 | off | 13.9 s | 6.5 s | 6.85 s | 0.46 s | 1.55M | 44.1k |
| rep_160 | on | 9.1 s | 6.5 s | 2.06 s | 0.46 s | 118k | 18.4k |

- Total time is now 2.07x per doubling on elect (6.1 -> 12.6 -> 26.3 s).
  Lowering is 2.2-2.3x per doubling (was 2.8-3.2x).
- Fresh fold points drop 9-13x, but still grow about 3.5x per doubling.
  They are no longer the cost driver.
- Reuse also shrinks the SMT on rep (44k -> 18k lines): reused conditions
  are shared terms, so the solver sees one definition, not one per step.
- Build (constructing the IR, mostly hash-consing in `mk`) is linear and
  now 75% of elect_160.
- Soundness suites, all identical to T9: 50 positives VALID (max 2.2 s,
  certified); deep cuts D = 1000 and 10^6, 50 VALID; 1045 negatives give
  the same per-mutant verdicts (1019 INVALID, 26 VALID, 0 ENGINE-BUG, max
  7.1 s under load).

What did not work first, and why (from per-template profiling):

- The first version reused only 3x. 88% of fresh points had a memo whose
  delta was top:
  - `SList.append` is a lam overlay `ite(k < aEnd, x[k], y[k - aEnd + off])`,
    so each append adds one level. A structural delta recursed one level per
    append and ran out of depth. Fix: treat the overlay as an overwrite step
    (above), so a chain of appends is a walk, not a recursion.
  - Arrays used `.exact` (e.g. the log passed whole into a helper) were top
    even when unchanged. Fix: an empty array delta counts as equal.
  - A depth-limited failure was cached and poisoned later, deeper queries.
    Fix: cache the depth with the result.
- The remaining fresh points are genuine. An `.exact` integer such as
  `currentTerm` or `commitIndex` appears in a fold body that spans the whole
  log. When it changes (every election, every commit advance), the whole fold
  is different as a term, so all L points are lowered again. That is
  O(changes * L).

Implications:

- Structural "may differ" sets are cheap and generic, but only as precise as
  the hole classification. Integers that are compared (`.cmp`) give tight
  deltas. Integers used arithmetically (`.exact`) give none.
- The next step would be value-aware deltas for `.exact` integers: for
  example, `ite(term(k) = currentTerm, ...)` only changes at indices whose
  term equals the old or new value. That needs the solver or a range
  analysis per index. YAGNI: the targets are met and build now dominates.
- Overwrite steps generalize stores. Any `lam k. ite(c, a[k], e)` whose
  condition has a decidable interval over k is a store to a region. This
  covers append, truncate and splice without naming them.

### T11. Q-free channels: an unbounded cut network makes every receive free

Question: can the per-channel bound Q on packets in flight at the cut go?

Semantics (`Replay.runStep`): channels are FIFO per (source, destination). A
receive takes the oldest pending packet; the traces only drop the head. The
traces observe every send with `last` and every receive or drop with
occurrence 0 just before it. Part 2 puts no constraint on initial packets
beyond field ranges.

Argument: positions are independent of the initial count p (the i-th consume
on a channel reads position i; an occurrence-k observation reads consumed + k).
Take any satisfying p. Raise it to N_c, beyond every position read, and set
each initial packet to the message that p's alignment put at that position.
Every read gets the same value, every "pending" check still holds, and `last`
still reads the newest send if there is one. So with no bound, "p beyond every
read" is as permissive as any p, and the exact unbounded check is "every
receive delivers a free message; sends are read only by `last`". No receive is
ever "definitely sent". Generically, p is a pure variable: raising it only
turns constrained reads into free ones, so fixing it at its top preserves
SAT (cf. pure-literal elimination, Z3's `elim-uncnstr`).

Experiment (no Lean change): `build/research/scripts/netfree.py` pins every
channel with `--fix-len` at N_c = (largest position read) + 2. The +2 keeps the
initial packet `last` may read apart from consumed ones. It raises `--Q` so
those positions are explicit cells, not zero gaps. `negatives.py` gained
`NETFREE=1` and `KINDS=`, plus a new mutation, `dup_receive`: deliver the same
packet twice (repeat its observation and receive).

| set, cut 10 | bounded (Q 4, retry 16) | Q-free |
| --- | --- | --- |
| 50 positives | 50 VALID, max 2.2 s | 50 VALID, all certified, max 2.7 s |
| 1045 mutants | 1019 INVALID / 26 VALID | 1018 INVALID / 27 VALID |
| 148 `dup_receive` (all fail replay from the true state) | 10 INVALID | 0 INVALID |

- The only mutant that changed is `suffix_collision.2 late del_receive`,
  which is VALID with more than 16 packets in flight (it was T2's case). Its
  new VALID is certified. 1018 equals part 1 after dropping `cap`.
- `msg_term` and `del_receive` stay INVALID without Q: the receiver's later
  state observations catch them, not the channel alignment.
- Duplicate delivery is mostly invisible even with Q (138 of 148 VALID):
  consecutive packets on a channel are often equal (heartbeats and their
  responses), so a shift of one changes nothing observable.
- Timing is a hack artifact: raising `--Q` makes [0, Q + slack] explicit for
  every array, logs included. Mutant INVALID medians are 1.1 s vs 0.87 s,
  maxima 11.8 s vs 7.1 s. A direct encoding (a fresh message per consumed
  position, no channel arrays, no count selector) would be smaller than
  either. Not built.

Implications:

- Q is a semantic assumption, not just an encoding device. It is the only
  thing that links a sender's packets to a receiver's, and on these traces it
  buys 1 of 1045 mutants and 10 of 148 duplicate deliveries.
- To keep some network checking without a size bound, packets in flight need
  a sender-relative invariant at the cut, e.g. `term <= currentTerm(source)`
  (senders stamp their current term, which never decreases). A receive whose
  term exceeds the sender's cut term is then definitely post-cut, and FIFO
  makes every later receive on that channel post-cut too. The alignment
  selector returns, but only until that first receive; T7 pins it.
