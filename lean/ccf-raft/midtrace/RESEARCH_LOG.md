# Mid-trace validation research log

Branch: `lean-mid-trace-validation-tests` (fork `cjen1-msft/CCF`), based on
`lean-ccfraft-simplify` at 1a3a83104.

## Problem statement

Today `ccfraft-replay` replays a reduced trace (`ccfraft-replay/v4`) from the
known bootstrap state. For a real system the start of the stream is missing.

**Mid-trace validation** of a suffix `S` (the instructions after the first `N`
reduced actions and their recorded observations): accept iff there exists a
well-typed replay state `s0` (every declared node's `NodeState` plus the live
messages in flight) such that `Replay.replayFrom header s0 S` succeeds.

Constraints (from the user):

- After log extraction (raw capture -> `reduction.py`), everything is Lean.
  Mirrors `lean/disaster-recovery/DisasterRecovery/TraceValidation.lean` on
  `main`, which is a pure Lean parse -> replay pipeline.
- No loosening: acceptance must mean exactly "some concrete initial state makes
  the unchanged replay pass". Restricting `s0` further (for example to states
  satisfying model invariants) is allowed, because it only rejects more.
- Target: < 60 s per scenario in `tests/raft_scenarios`, with `N = 10`, and
  roughly linear scaling in the suffix length. Both acceptance (valid) and
  rejection (invalid) count. Explaining a rejection may take up to ~10 min.
- Cut: drop the first `N` reduced actions (`MidTrace/Cut.lean`). The cut also
  drops observations whose raw log lines belong to action `N`, so the suffix
  starts at the first raw record after that action.
- `InitialConfig` (bootstrap configuration, leader, pre-vote modes) stays
  known: it is model configuration, not state.

## Infrastructure

- `CCFRaft/Replay.lean` now exposes `runInstruction`, `replayFrom` and
  `parseDocument`. `replay` is `replayFrom` from `header.initial`; checks are
  unchanged.
- `midtrace/MidTrace/StateJson.lean`: JSON encoding of a complete replay state.
- `midtrace/MidTrace/Cut.lean`: the cut.
- `ccfraft-midtrace cut | true-state | replay-from`.

## Baseline (full traces, known initial state)

- 53 scenarios, 13,298 raw trace events, 34,995 instructions
  (5,464 actions, 29,531 observations).
- Full Lean replay: all pass, 0.037 s to 0.103 s each (2.79 s total, process
  start dominated).
- `true-state DOC 10` + `replay-from`: all 50 scenarios with >= 10 actions pass
  (`append`, `startup`, `nominate_without_successor` have < 10 actions).

## What the observations reveal

Counts over all 53 reduced traces.

- Actions: receive 3124, sendEntries 1306, append 518, drop 413, timeout 99,
  nominateSuccessor 4.
- State observation fields: currentTerm, role, commitIndex, logLength,
  membership/retirement fields (~8-10k each); `sentIndex`/`matchIndex` for one
  peer (2903); `configurations` only 303 times. `committableIndices` never.
- Entry observations: only `kind`, `committed`, `configurations`. **Never the
  entry term or transaction id.** Signature markers assert a signature at an
  index but absent markers assert nothing.
- Message observations: full header (`term`, `prev_idx`, `prev_term`, `idx`,
  `term_of_idx`, `leader_commit_idx`, response fields) but never AppendEntries
  entry contents.
- Never observed: `votedFor`, `leaderKnown`, `isNewFollower`, `votesGranted`,
  `preVotesGranted`, entry terms (only indirectly via message headers and
  vote-request `term_of_last_committable_idx`).
- Pre-observations (`*-pre`) give the acting node's role, term, commit index,
  log length and retirement fields before every action except election
  timeouts.

## Size of the unknown at the cut

`true-state DOC N` gives the real state at the cut. Over the 50 scenarios:

| cut              | max log | max entries (all nodes) | config entries | in-flight msgs | AE entries in flight |
| ---------------- | ------- | ----------------------- | -------------- | -------------- | -------------------- |
| after 10 actions | 6       | 10                      | 5              | 8              | 0                    |
| half the actions | 22      | 84                      | 25             | 15             | 8                    |

At cut 10, 169 of 309 initial entries get a `kind` observation somewhere in
the suffix, and 67 of 156 configuration-carrying entries get a
`configurations` observation. Every node's scalars (role, currentTerm,
logLength, commitIndex, retiredCommittedIndex) are observed before its first
action (168/168 node instances), via the `*-pre` observations.

## Which unknowns matter (perturbation study)

`build/research/scripts/perturb.py` (research only, not part of validation)
perturbs one unknown of the true cut-10 state and reruns the real
`replay-from`. 5164 runs, 28 s:

| unknown         | still passes | rejected | rejection instruction (p50 / p90 / max) |
| --------------- | ------------ | -------- | --------------------------------------- |
| entry content   | 110          | 864      | 19 / 81 / 224                           |
| entry term      | 230          | 388      | 19 / 103 / 305                          |
| matchIndex      | 220          | 492      | 14 / - / 269                            |
| sentIndex       | 344          | 368      | 3 / - / 68                              |
| votedFor        | 604          | 0        | -                                       |
| leaderKnown     | 168          | 0        | -                                       |
| isNewFollower   | 168          | 0        | -                                       |
| votesGranted    | 604          | 0        | -                                       |
| preVotesGranted | 604          | 0        | -                                       |

Implications:

- Hidden booleans and vote sets almost never matter at cut 10: forking on
  them lazily is cheap.
- Entry content and term errors are often detected far from the cut (p90
  ~100 instructions, max ~300): any approach must carry the uncertainty
  forward a long way, so eager guessing plus backtracking from the end is
  expensive, and the explanation of a failure can be far from its cause.
- Many perturbations of content/terms still pass: the witness is not unique,
  so a search must not demand it.

## Message access pattern

In the cut-10 suffixes every `receive` (2885) is immediately preceded by an
observation of the same channel at occurrence 0, and every `drop` (413) is at
occurrence 0 and preceded by such an observation. `selection: "last"` (3204
uses) only follows sends. So the network can be modelled per channel as
`pre-cut messages ++ post-cut messages` with head deletion, and pre-cut
messages can be materialized lazily from the head observation that precedes
their use.

## Raw-log coverage

In the raw driver logs, `configurations` is emitted only on
commit/add_configuration/become_*/step_down events, and `committable_indices`
in ~96% of events (but `reduction.py` does not forward it). Emitting more of
the existing fields would pin far more of the unknowns (see "engineering
alternatives" below).

## Approaches

Literature (details in the session notes; nothing found that validates a
consensus implementation trace from an unknown mid-stream state):

- Trace validation against TLA+/Lean specs (Howard et al., NSDI 2025, CCF;
  Cirstea, Kuppe, Loillier, Merz, SEFM 2024; etcd raft `tla/`) all assume a
  known initial state. Davis et al. (PVLDB 2020) abandoned model-based trace
  checking partly over state-alignment cost.
- PObserve (AWS P) checks production logs mid-stream by making each event
  carry enough data for the monitor's own state: an engineering answer
  (richer logs), not a search.
- Discrete-event-system diagnosis with unknown initial conditions
  (Sampath et al. 1995 diagnoser, belief states): exact, but over finite
  state spaces.
- Generalized symbolic execution with lazy initialization (Khurshid,
  Pasareanu, Visser, TACAS 2003): materialize unknown heap only when read.
  This is the closest fit and the basis of approach 3.
- IC3/PDR and array-based model checking (MCMT): backward reachability for
  "is some state consistent", heavy machinery for a single trace.
- Linear-time history checkers (Elle; Porcupine with P-compositionality,
  Lowe): decompose by key/object so cost adds instead of multiplies. Per-node
  projection below is the same idea.
- QuickXplain / MUS extraction for explanations.

Candidates, as assessed:

| #   | approach                                  | VALID                     | INVALID             | verdict                                                                                    |
| --- | ----------------------------------------- | ------------------------- | ------------------- | ------------------------------------------------------------------------------------------ |
| 1   | Observation-seeded concrete witness       | fast when the guess works | cannot prove        | the user's earlier hack; subsumed by 3 (3 builds and certifies a witness)                  |
| 2   | Belief sets (explicit set of states)      | exact                     | exact               | state is unbounded (logs, terms): needs a symbolic representation, i.e. 3                  |
| 3   | Lazy symbolic execution (BFS over worlds) | certified by `replayFrom` | exhaustive search   | meets the target at cut 10; blows up at large cuts                                         |
| 4   | Abstract interpretation                   | no                        | fast but incomplete | useful only as a pre-filter; 3 already rejects in 31 ms p50                                |
| 5   | SSA SMT encoding (+ external solver)      | certified by `replayFrom` | unsat               | **meets the target at every cut; simplest model; unsat cores for explanations**            |
| 6   | CEGIS / concolic with nogoods             | yes                       | slow to converge    | errors surface ~100 instructions after the cause (perturbation study), so nogoods are weak |
| 7   | Richer logs / periodic snapshots          | trivial                   | trivial             | complementary; removes most unknowns at the source                                         |

## Approach 3: lazy symbolic execution in Lean

`ccfraft-midtrace validate DOC N`. All code is in `midtrace/MidTrace/Sym*.lean`;
Python is used only by research harnesses under `build/research/` (not committed).

- **World**: a partial initial state per node (`Option` per field), the
  current symbolic state, channels and a constraint store.
  - Integers are `SInt = x + k` over variables with a closed difference-bound
    matrix (`DBM`); comparisons decide from the store or fork.
  - Unknown entry contents are atoms with a candidate list drawn from a
    finite domain (every configuration/retirement shape over the declared
    nodes, plus a plain transaction); a query partitions the candidates by
    its answer and forks once per answer.
  - Finite initial fields (role, votedFor, vote sets) keep a candidate list.
  - A channel is `pre` (pre-cut messages materialized so far) `++ post`
    (sent after the cut), plus `initial` (every materialized pre-cut message,
    for the witness) and `tail` (see projection).
- **Lazy initialization**: the first read of an unknown field creates a fresh
  symbol (or forks a finite domain); observations then constrain or fix it.
  `SymModel.lean` is a symbolic transcription of the replayed model.
- **Monad** `M = World -> List (Res)` with `ok | dead | unsupported`.
  `unsupported` marks a branch the engine cannot represent; it never counts
  as a rejection.
- **Verdicts**:
  - VALID: a surviving world is concretized into a full replay state
    (smallest consistent integers, first content candidate, materialized
    messages) and **checked by the unchanged `Replay.replayFrom`**. Only a
    witness that passes gives VALID; so VALID never loosens the replay.
  - INVALID: every branch died and none was unsupported.
  - UNKNOWN: otherwise (unsupported branch, frontier cap, budget).
- **Initial-state restrictions** (allowed: they only reject more): every
  declared node is active, no dropped history, and with invariants on, terms
  > = 1, monotone log terms, last log term <= currentTerm, and well-formed
  > materialized AppendEntries. `--no-invariants` gives the same 50/50 VALID.

### Iterations

| version | change                                           | cut-10 VALID / 50          | VALID time p50 / p90 / max |
| ------- | ------------------------------------------------ | -------------------------- | -------------------------- |
| v1      | lazy BFS, no dedup                               | 37 (11 UNKNOWN, 2 timeout) | 1.2 s / 5.3 s / 30 s       |
| v2      | world keys: dedup + slot merging, txId interning | 38 (12 timeout at 120 s)   | 3.2 s / 28 s / 80 s        |
| v3      | phantom-always delivery                          | 49 (1 timeout)             | 0.26 s / 10 s / 25 s       |
| v3b     | keys only at block boundaries                    | 50                         | suffix_collision.3 64 s    |
| v4      | per-node projection                              | 50                         | 45 ms / 0.73 s / 5.5 s     |
| v5      | channel `tail` for `last` selections             | 50                         | 46 ms / 0.70 s / 2.9 s     |
| v6      | log-length hints, bind budget                    | 50                         | 58 ms / 0.72 s / 2.7 s     |

Total wall time for the 50 scenarios at v6 (8 parallel): ~6 s.

Key steps:

- **Dedup and slot merging** (v2): worlds are keyed by a canonical string;
  identical keys are dropped, and keys that differ only in one content atom's
  candidate list are merged into one world with the union. Dedup alone did
  nothing (forks rarely produce identical worlds); merging was required.
  Key rendering dominated runtime (perf), so txIds were interned.
- **Phantom-always delivery** (v3): receiving from an open channel head could
  either close the channel (deliver the first post-cut message) or deliver a
  materialized pre-cut copy. The copy branch subsumes the close branch: give
  the phantom the post-cut message's value; the channel then holds
  `p :: rest` instead of `rest`, so every later choice of the close branch is
  still available and `last` selections agree. So only the copy branch is
  explored. Consequence: deliveries never link to sends, which decouples
  nodes.
- **Block-boundary keying** (v3b): forks inside an action's block are mostly
  pruned by the block's own observations; keying only before the next action
  cut key cost ~10x.
- **Per-node projection** (v4): with phantom delivery each instruction reads
  and writes exactly one node's symbolic state (owner: local actions and
  state/entry observations -> `node`; `sendEntries` -> source;
  `receive`/`drop` -> destination; message observations -> destination, or
  source for `last`). Each node's projection is validated alone; channel
  close branches become `unsupported` in projections. The joint search space
  is the product of the projections', so a projection INVALID is a global
  INVALID, and multiplicative frontiers (343 = 7^3 in suffix_collision.3)
  become additive. The joined witness (each node's state from its
  projection, plus the pre-cut messages it consumes) is certified by global
  `replayFrom`.
- **Channel tail** (v5): a `last` observation on a channel with no post-cut
  send in the projection refers to a pre-cut message the destination may
  never consume; the projection materializes it as the channel `tail`, placed
  after `initial` in the witness. Removed all 95 UNKNOWN negatives.
- **Log-length hints** (v6): a log read before any `logLength` observation
  (an election timeout as a node's first instruction) tries each length the
  node is later observed with, plus an unsupported catch-all.
- **Bind budget** (v6): `bind` stops after `cap` results and appends one
  `unsupported` result. This bounds work inside a single action (an election
  on a fresh 13-entry log forked ~10M ways). Truncation behaves like a beam:
  VALID is still certified, INVALID becomes UNKNOWN.

### Negative traces

`build/research/scripts/negatives.py`: 1045 mutated cut-10 documents, 7
mutation kinds at 2%, 50% and 90% of the suffix (state term/commit/logLength/
role +1 or changed, entry kind, message term, deleted receive). Soundness
check: every INVALID is compared with `replay-from` of the true state.

| version | INVALID | VALID | UNKNOWN | INVALID time p50 / p90 / p99 / max | unsound INVALID |
| ------- | ------- | ----- | ------- | ---------------------------------- | --------------- |
| v4      | 925     | 25    | 95      | -                                  | 0               |
| v5      | 1018    | 27    | 0       | 31 ms / 0.72 s / 4.1 s / 4.8 s     | 0               |
| v6      | 1018    | 27    | 0       | 31 ms / 0.70 s / 4.3 s / 4.8 s     | 0               |
| final   | 1018    | 27    | 0       | 31 ms / 0.72 s / 4.4 s / 5.0 s     | 0               |

- All 27 VALID mutants are certified by `replayFrom`. 23 of them are
  rejected from the true state but accepted from another one: under "exists
  an initial state" a mutated delivered message or a deleted receive can be
  explained by a pre-cut message, and an early state mutation can be absorbed
  by the initial state. This is inherent to the problem statement, not a
  loosening of replay (each acceptance names a concrete state that replays).
  By kind: deleted receive 11, message term 8, commit index 5, entry kind 2,
  logLength 1; role and term mutations are always caught.
- Cross-check with `--global` (no projection, v5): 679 agree INVALID, 339
  INVALID vs UNKNOWN, 2 VALID vs UNKNOWN, 25 agree VALID; no VALID/INVALID
  conflict. All 341 global UNKNOWNs are the unsupported case "last pending
  message is an unmaterialized pre-cut message": channel tails exist only in
  projected search.
- INVALID reports the node, instruction, raw log line and the dead reasons of
  the last live branches, e.g. `node 0: instruction 492 at ...stdout:773
[send-pre]: [logLength: observed 9, canonical 8]`.

### Scaling and larger cuts

`build/research/scripts/scaling.py`: per scenario, the cut-10 suffix
truncated to 1/8, 1/4, 1/2 and all of its length; cuts at 1, 5, 20, 40 and
half the actions; and `--no-invariants`.

Length scaling (cut 10, all 50 VALID at every length):

- Time is roughly proportional to the sum of frontier sizes, so it is linear
  in length when the frontier stays narrow. Median log-log slope of time vs
  suffix length (1/4 -> full, the 19 scenarios above 20 ms) is 0.51; max
  1.77 (suffix_collision.3), where the time is a step at one hard region
  (224 ms at 1/4 and 340 ms at 1/2, then 2.6 s at full), not steady growth.
- Slowest full-length suffixes: retire_backup 2.8 s (619 instructions),
  retire_backup_pre_vote 2.8 s, suffix_collision.3 2.6 s (2539 instructions),
  ackuracy 1.0 s (1577).

Cut sweep (v6; 300 s timeout):

| cut (actions) | VALID | UNKNOWN | VALID time p50 / p90 / max |
| ------------- | ----- | ------- | -------------------------- |
| 1             | 50/50 | 0       | 27 ms / 0.11 s / 1.8 s     |
| 5             | 50/50 | 0       | 47 ms / 0.69 s / 2.8 s     |
| 10            | 50/50 | 0       | 45 ms / 0.69 s / 2.8 s     |
| 20            | 48/48 | 0       | 0.16 s / 1.6 s / 8.5 s     |
| 40            | 41/44 | 3       | 0.23 s / 1.9 s / 94 s      |
| half          | 42/50 | 8       | 0.25 s / 4.5 s / 125 s     |

(`--no-invariants` at cut 10: 50/50 VALID, max 3.0 s.)

- v5 -> v6 at larger cuts: log-length hints plus the bind budget turned 10
  UNKNOWNs into VALIDs (for example soft_rollback half, retire_backup half,
  delayed_vote_requests half, bad_network cut 40).
- Remaining UNKNOWNs all exceed the 100k frontier cap. Dumped keys show the
  surviving worlds differ in correlated candidate sets of several unknown
  initial log entries (which configuration or retirement each carries), each
  split by a different membership query. Slot merging merges only
  single-slot differences, so these do not collapse. Runtime is spread over
  stepping (~45%), merging (26%) and keys (21%); there is no single hotspot.
- Two VALIDs exceed 60 s: fancy_election.2 cut 40 (94 s) and rollback_safety
  half (125 s).

## SMT approach: one SSA formula for the whole suffix

`ccfraft-midtrace smt DOC N [--explain]`. Code: `midtrace/MidTrace/SmtCore.lean`
(terms and simplifier), `SmtModel.lean` (the model's handlers over terms),
`SmtDriver.lean` (system state, observations, solver session, diagnosis).
The solver (yices 2, QF_LIA) runs as a subprocess. Encoding, verdicts and
witness checking are Lean.

Motivation (from the user): a model that is conceptually simpler than the
engine (no forking, merging, projection or subsumption arguments), and
better INVALID explanations (unsat cores over individual guards and
observations). The user's earlier encodings went quadratic, so the first
step was to find out which encodings stay linear.

### Microbenchmarks

`build/research/smt/micro.py`: a synthetic follower log under T
AppendEntries with an unknown initial log, phantom (free) entries and a
commit index, observed after every step. Same semantics, five encodings;
negative instances (unsat), z3, growing logs (length ~1.3 T):

| encoding | idea                                          | T=400  | T=800  | T=1600  | T=3200 |
| -------- | --------------------------------------------- | ------ | ------ | ------- | ------ |
| arr-sym  | SMT arrays, observations as equalities        | 4.3 s  | 25 s   | timeout | -      |
| arr-conc | SMT arrays, observed values substituted       | 2.1 s  | 5.6 s  | 23 s    | -      |
| seq-sym  | SMT sequences, symbolic indices               | 9.4 s  | 55 s   | -       | -      |
| ssa-fold | one constant per cell, fold over log per step | 0.27 s | 0.99 s | 2.4 s   | 11 s   |
| ssa-sum  | per-cell SSA + memoized prefix summaries      | 0.04 s | 0.07 s | 0.15 s  | 0.30 s |

- Script size tells the story: ssa-sum grows linearly (0.17 MB -> 1.5 MB),
  ssa-fold and the array/sequence encodings grow quadratically (array
  store chains and per-step folds over the whole log are re-emitted).
- cvc5 on ssa-sum: 1.2 s at T=800, 100 s at T=3200 (z3 0.30 s).
- With bounded logs (as in the real scenarios, <= ~30 entries) ssa-sum is
  1.1 s at T=25600.
- Literature agrees: lemmas-on-demand arrays are quadratic when reads
  propagate through store chains (Brummayer and Biere, JSAT 2009); CBMC's
  field sensitivity turns constant-index array accesses into per-index SSA
  symbols, the precedent for per-cell logs.

### Design

- **Pure SSA, no case splits.** A node's state is a record of terms. Every
  `if` of `Model/Node.lean` becomes an `ite` over both branches' states, and
  each send records its path condition. The solver sees one formula whose
  models are exactly the runs of the suffix. `SmtModel` is a line-by-line
  transcription, so it is much easier to review against the model than the
  engine's world/fork machinery.
- **Logs as cells.** `K` cells per node (`K` = largest number in the
  suffix + slack 4); index queries are `ite` chains over cells; prefix
  summaries (last signature, last configuration, ...) are shared.
- **Hash-consed definitions plus an interval simplifier.** Each term is a
  `define-fun` keyed by its text, so re-reading an unchanged value costs
  nothing. Every definition carries an interval; hard assertions narrow
  intervals and propagate the narrowing to operands, so an observed value
  becomes a literal and everything downstream folds. This is only a
  simplifier: every narrowing is implied by the emitted assertions.
- **Channels as positions.** The first `p` positions of each channel are
  messages in flight at the cut (phantoms, `p <= Q`, symbolic) and the rest
  are the suffix's sends in order. The `i`-th receive consumes position `i`,
  so only `p` and earlier send conditions are symbolic.
- **Head naming.** Each received message is a fresh tuple of constants,
  constrained to equal one of the alternatives that can be at that
  position. The dispatch observation before each receive pins the message
  kind, so the handler runs one branch. Without naming, the receive's
  value was a nested `ite` over all alternatives, uncertainty fed back
  into later sends and per-receive cost grew with trace position
  (suffix_collision.3: 48.8 s and 5.1M definitions before, 0.47 s after).
- **Assumptions.** `cap` (logs fit in `K` cells, at most `Q` phantoms; reads
  past the cells return fresh values, which over-approximates) and `inv`
  (cheap invariants of the initial state, which only rejects more) are
  literals passed to `check-sat-assuming`. An unsat core containing `cap` is
  rechecked without it, and if that is not unsat the run is retried with
  `Q` and slack multiplied by 4 (twice at most).
- **Verdicts.** `sat`: the model's initial state is replayed with the
  unchanged `Replay.replayFrom`, and the verdict is VALID only if replay
  passes. `unsat` (or a hard assertion folding to `false` while encoding):
  INVALID.
- **Solver.** yices 2 by default; z3 and cvc5 also work through `--solver`.
  See "Solver choice" below for why yices is 10x to 100x faster on these
  formulas.

### Results (cut 10, yices, Q=32)

| run                                     | verdicts               | time p50 / p90 / max           |
| --------------------------------------- | ---------------------- | ------------------------------ |
| scenarios                               | 50/50 VALID            | 0.23 s / 0.77 s / 1.3 s        |
| mutants (1045)                          | 1018 INVALID, 27 VALID | INVALID 12 ms / 52 ms / 0.28 s |
| pinned to the true state (differential) | 1041 INVALID, 4 VALID  | 3 ms p50, max 56 ms            |
| scenarios, z3                           | 50/50 VALID            | 0.22 s / 1.1 s / 3.3 s         |
| scenarios, `--no-refine`                | 50/50 VALID            | 1.6 s / 16 s / 105 s           |
| scenarios, Q=4                          | 50/50 VALID            | 70 ms / 0.22 s / 0.48 s        |

- Same verdicts as the engine on all 1045 mutants (0 disagreements); the 27
  VALID mutants are the same, each certified by replay (max 0.45 s).
- 1016 of the 1018 INVALIDs are refuted while encoding: an observation
  narrows to `false`, so the solver is never called.
- Pinned mode (`--pin`) fixes the initial state to the one replay reaches
  at the cut: verdicts equal replay on all 1045 mutants and all 50
  scenarios. This is the main evidence that the transcription is faithful.
- `--no-refine` (no interval narrowing) is the ablation that matters: the
  simplifier is what keeps the formula small enough.

Scaling (`scale_smt.txt`, all VALID): suffix truncated to 1/8, 1/4, 1/2, 1
gives p50 67 ms, 86 ms, 130 ms, 0.24 s and max 0.30 s, 0.51 s, 0.68 s,
1.9 s. Median log-log slope vs suffix length: definitions 0.85, time 0.79;
definitions per instruction are flat (14 to 35). Larger cuts, where the
engine left UNKNOWNs and 94 s / 125 s VALIDs, are easy here:

| cut  | VALID | time p50 / p90 / max    | engine           |
| ---- | ----- | ----------------------- | ---------------- |
| 1    | 50/50 | 0.32 s / 0.87 s / 1.9 s | 50/50            |
| 5    | 50/50 | 0.25 s / 0.66 s / 1.9 s | 50/50            |
| 20   | 48/48 | 0.23 s / 0.78 s / 1.8 s | 48/48            |
| 40   | 44/44 | 0.24 s / 0.92 s / 1.7 s | 41/44, max 94 s  |
| half | 50/50 | 0.21 s / 0.63 s / 1.3 s | 42/50, max 125 s |

(`--no-invariants` at cut 10: 50/50, max 2.1 s.) The engine's blowups came
from correlated unknown log contents split differently by each membership
query; in SSA these are just shared unknown cells, so nothing multiplies.

### Solver choice: why yices

`build/research/smt/why.py` runs the same dumped scripts through every
solver we could install. `cap`, `inv` and all guards are asserted and
checked once. Times are wall clock, one process at a time
(`results/why_serial.txt`, `why_big.txt`, `why_ablate.txt`). The scripts
are VALID cut-10 suffixes:

- bad_network (0.8 MB, 15k definitions);
- ackuracy (1.6 MB, 29k);
- suffix_collision.3 (4.1 MB, 74k);
- bad_network and ackuracy with `--no-refine`, i.e. without narrowing
  (24 MB and 117 MB).

| solver                      | bad_network | ackuracy | suffix_collision.3 | bad_network no-refine | ackuracy no-refine | `check-sat-assuming` |
| --------------------------- | ----------- | -------- | ------------------ | --------------------- | ------------------ | -------------------- |
| yices 2.7.0                 | 0.03 s      | 0.05 s   | 0.13 s             | 0.93 s                | 4.4 s              | yes (0.06 s, 0.15 s) |
| yices `--mcsat`             | 0.17 s      | 0.32 s   | 1.4 s              | 28 s                  | -                  | -                    |
| MathSAT 5.6.19              | 0.27 s      | 0.43 s   | 0.97 s             | 205 s                 | > 300 s            | yes (0.66 s, 1.1 s)  |
| z3 5.1.0, tuned (see below) | 0.26 s      | 0.50 s   | 1.4 s              | > 300 s               | -                  | yes                  |
| z3 5.1.0                    | 0.91 s      | 2.0 s    | 6.5 s              | > 300 s               | > 300 s            | yes (0.64 s, 2.1 s)  |
| OpenSMT 2.9.2               | 1.3 s       | 1.1 s    | 9.2 s              | > 300 s               | > 300 s            | no (push/pop only)   |
| cvc4 1.8                    | 1.7 s       | 2.7 s    | 7.1 s              | > 300 s               | > 300 s            | yes (3.0 s, 12 s)    |
| cvc5 1.4.0                  | 2.2 s       | 3.3 s    | 13 s               | 145 s                 | > 300 s            | yes (7.2 s, 21 s)    |
| SMTInterpol 2.5-1453        | 2.7 s       | 3.0 s    | 14 s               | > 300 s               | > 300 s            | crashes (NPE)        |
| veriT 2021.06.2             | 162 s       | ~33 s    | -                  | -                     | -                  | no                   |

The last column gives times on ackuracy and suffix_collision.3.

Parsing is not the cost. Load-only times are:

- yices 0.04 to 0.09 s;
- MathSAT 0.07 to 0.16 s;
- z3 0.2 to 0.5 s;
- cvc5 0.4 to 0.7 s;
- OpenSMT 0.9 to 7.3 s;
- SMTInterpol (JVM) 1.9 to 5.5 s.

The gap comes from how each solver treats a large, nearly functional QF_LIA
formula: Booleans, integer `ite`s and difference/bound atoms. Three
mechanisms, each shown by an ablation:

1. **No theory combination in yices.** yices builds its solver stack from
   the declared logic. For QF_LIA it uses only CDCL plus simplex, and
   integer `ite`s are flattened into clauses over simplex atoms. Changing
   only the `set-logic` line to QF_UFLIA adds an egraph, so the same `ite`
   terms need Nelson-Oppen equality exchange between the egraph and
   arithmetic. That change makes yices 70x slower on ackuracy (0.05 s to
   3.4 s, 2.6k to 513k decisions), 190x on suffix_collision.3 (0.13 s to
   25 s, 9.6k to 3.3M decisions) and 19x on bad_network no-refine
   (0.95 s to 18 s). That is z3/cvc5 territory. z3 and cvc5 always keep an
   equality engine over arithmetic terms:
   - z3 propagates 306k (ackuracy) and 495k (suffix_collision.3)
     arithmetic equalities into its egraph. Most are offset equalities
     `x = y + k`, which SSA updates produce everywhere.
     `smt.arith.propagate_eqs=false` cuts suffix_collision.3 from 6.1 s
     to 4.9 s.
   - cvc5's arithmetic equality engine holds 71k terms on ackuracy.
2. **Preprocessing.** z3's default QF_LIA strategy probes ILP,
   pseudo-Boolean and bounded-integer tactics and runs ctx-simplify,
   solve-eqs and elim-term-ite before its SMT core. Skipping these
   (`tactic.default_tactic=smt`) halves z3's time (suffix_collision.3
   6.1 s to 2.8 s). cvc5 spends 1.1 to 1.9 s of 2.2 to 3.9 s in
   preprocessing passes (static-rewrite, apply-substs, theory-preprocess
   and non-clausal-simp are about 0.25 s each). Its static learning for
   arithmetic `ite`s alone costs 1.7 s (ackuracy 3.9 s to 2.2 s without
   it). yices simplifies while building terms (hash-consing, comparisons
   of `ite`s against constants fold) and ends with 4k atoms on ackuracy.
   cvc5 has 15k CNF atoms and z3 14k Boolean variables.
3. **Search barely happens when propagation works.** Once the few unknown
   initial values are chosen, unit propagation fixes everything else.
   yices needs 0 conflicts (ackuracy), 20 (suffix_collision.3) and 75
   (bad_network no-refine). The others make 10x to 50x more decisions:
   - z3: 94k decisions, 81 conflicts;
   - cvc5: 82k decisions, 574 arithmetic conflicts;
   - MathSAT: 130k decisions, 46 conflicts.
     MathSAT is the closest at 0.43 s. It also builds an egraph (24k nodes,
     364k merges), but it exchanges no interface equalities with its LA
     solver (0 needed, 0 extra), so it pays for egraph upkeep but not for
     theory combination.

Tuning the others narrows the gap only on small inputs. z3 with the SMT
tactic and the legacy simplex solver (`smt.arith.solver=2`) takes 0.45 s on
ackuracy and 1.1 s on suffix_collision.3: 5x faster than default, still
about 9x behind yices. It still times out on bad_network no-refine. The best
cvc5 combination (`--simplification=none --sat-solver=minisat
--no-static-learning --no-arith-static-learning`) takes 2.6 s. The overheads
grow faster than linearly with formula size: without narrowing (24 MB),
yices takes 0.95 s, cvc5 145 s and MathSAT 205 s, and the rest exceed
300 s. The simplifier therefore matters most for the other solvers.

Tuning yices changes nothing: branching polarity, var-elim, arith-elim,
flatten, learn-eq, keep-ite, simplex-prop, cache-tclauses and randomness
give identical decision and conflict counts. MCSAT is a different
architecture, model-constructing rather than CDCL(T). It is 7x to 30x
slower than the default yices, but still beats default z3 and cvc5 on the
refined scripts.

Diagnosis needs `check-sat-assuming` with unsat assumptions in one session:

- yices, z3, cvc4, cvc5 and MathSAT support it.
- OpenSMT 2.9.2 and veriT reject it. OpenSMT has push/pop (1.0 s on
  ackuracy), but cores would need named assertions instead.
- SMTInterpol supports it on a small example, but throws a
  NullPointerException on our scripts.

Consequences:

- yices wins because the encoding is pure QF_LIA. Adding uninterpreted
  functions or arrays would bring in the egraph and lose most of the
  advantage. Keep the encoding egraph-free.
- MathSAT is the runner-up (incremental, 0.3 to 1 s), but its license is
  research and evaluation only.
- z3, tuned, is usable for validation on refined scripts, not for
  diagnosis loops.
- For proof-producing solving, cvc5 (with Lean-SMT reconstruction) is the
  slowest here. An untested alternative is a bit-vector encoding checked by
  Lean's `bv_decide`, which runs CaDiCaL and checks its LRAT certificate in
  the Lean kernel; values here are small.
- Not benchmarked:
  - bit-vector-only solvers (Bitwuzla, Boolector, STP), which need a BV
    encoding;
  - SMT-COMP variants that are not packaged (Z3++, Z3alpha, SMT-RAT);
  - Princess.

### INVALID diagnosis

Goal: a small set of hard assertions (action guards and observation
fields) that is already unsat, i.e. "this observation contradicts these
earlier facts". Three designs were tried; all keep `inv` assumed and report
whether the final core used it.

1. **Window, then solver-core minimization (first version).** Find the
   shortest invalid prefix (binary search on the end) and the latest cut
   that keeps it invalid (binary search on the start; each check is cheap
   because most refutations happen at encode time). Encode the window with
   one named literal per assertion and minimize the solver's core in that
   session. Sample of 100 mutants: p50 0.15 s, p90 0.49 s, max 77 s;
   window p50 7 instructions (p90 36, max 371); core p50 3 (max 6).
2. **The user's hierarchical scheme by re-encoding.** Label each
   instruction's assertions as one group; stochastically delete groups,
   then individual assertions, re-encoding the remainder each time (deleted
   assertions also stop narrowing). Delta-debugging style (Zeller's ddmin
   over a random permutation, halving chunk sizes). Failed on long-range
   windows: ackuracy 33 s; suffix_collision.3 entry_kind (window 255
   actions) did not finish in 900 s. Every probe of a small candidate core
   re-encodes the window without narrowing (5.5M definitions, ~150 s each).
3. **The user's hierarchical scheme in one session (current, `--explain`).**
   Encode the window once with a guard literal per assertion (narrowing
   only from message-kind observations, which stay unnamed so dispatch is
   concrete), load it into yices once, and run the scheme with
   `check-sat-assuming` over guard subsets: first over instruction groups
   (a trial assumes all of a group's guards; an unsat result keeps only the
   groups in the solver's core), then over the remaining single guards.
   Timeout per check: twice the first check's time; a timeout counts as
   "needed" (kept), so cores are 1-minimal modulo timeouts.

| case (window)                       | old (1) | re-encode (2) | session (3) | core          |
| ----------------------------------- | ------- | ------------- | ----------- | ------------- |
| retire_one                          | -       | -             | 0.21 s      | 3             |
| startup_2nodes                      | -       | -             | 0.09 s      | 6, uses `inv` |
| fancy_election.2 del_receive        | -       | -             | 0.37 s      | 2             |
| ackuracy del_receive (83 actions)   | 4.4 s   | 33 s          | 10 s        | 4             |
| suffix_collision.3 entry_kind (255) | 474 s   | > 900 s       | 428 s       | 3             |

- In one session the solver keeps learned lemmas, so later unsat checks
  are fast (ackuracy ~60 ms, suffix_collision.3 1 to 15 s). Re-encoding
  throws this away.
- SAT checks dominate: every "needed" decision is a satisfiable (or timed
  out) check, so cost is at least core size x levels x a SAT check. For
  suffix_collision.3 every SAT check hit the 25 s timeout (13 of them,
  ~325 s of the 428 s).
- Example core (suffix_collision.3, entry kind mutated at instruction
  2286): `entry 3[14].committed` (787), `entry 3[9].configurations` (789),
  `entry 3[9].kind` (2286). Read: on node 3, entry 14 was committed (so
  entry 9 can never be rolled back) and entry 9 was a configuration entry,
  1500 instructions before the mutated kind observation.
- yices quirks: `:timeout` is in seconds (1 s floor, which makes small
  windows pay ~1 s per SAT check), and changing it mid-session only works
  if a nonzero timeout was set before `set-logic`; otherwise the check
  after a timeout crashes ("unexpected context status"). SIGINT kills
  yices, so a check cannot be interrupted externally. z3 and cvc5 recover
  from timeouts (millisecond limits), but were too slow for whole windows.

Full run of `--explain` (current design) over all 1018 INVALID mutants
(`build/research/scripts/explain.py`, wall time per process, 8 in
parallel):

| measure               | p50    | p90    | p99   | max                        |
| --------------------- | ------ | ------ | ----- | -------------------------- |
| wall time             | 0.12 s | 0.30 s | 1.1 s | 438 s (suffix_collision.3) |
| window (instructions) | 7      | 33     | 139   | 1504                       |
| window (actions)      | 1      | 4      | -     | 255                        |
| core (assertions)     | 2      | 4      | -     | 8                          |

- All 1018 explained; 1 over 60 s, 2 more over 5 s (ackuracy del_receive
  11 s, candidate_viability and election_while_reconfiguration ~5.5 s).
  Only 3 runs hit any timeout.
- Core sizes: 2 (572), 3 (319), 4 (68), 6 (33), 5 (21), 1 (3), 8 (2).
- 40 cores also use the initial-state invariants (28 message-term, 8
  commit-index, 4 deleted-receive mutants): the contradiction relies on,
  for example, monotone initial log terms.

## Implications

- **Cost is frontier width x length.** The per-instruction step is cheap;
  runtime is the sum of frontier sizes. Anything that bounds the frontier
  gives linear scaling.
- **SMT is linear when every value is defined once and shared.** Per-cell
  SSA constants with hash-consed, memoized summaries keep script size
  linear; arrays, sequences and per-step folds over the whole log do not.
  The user's quadratic encodings re-derived the ledger at each
  AppendEntries receive.
- **Let observations simplify before the solver sees anything.** Interval
  narrowing from hard assertions turns most of the formula into literals;
  without it the same encoding is 7x slower at p50 and 80x at max (105 s),
  and 1016 of 1018 refutations happen at encode time with it.
- **Break uncertainty feedback loops.** A receive whose value is an `ite`
  over every candidate message makes later sends uncertain, which makes
  later receives worse. Naming the received message as fresh constants
  (constrained to one of the candidates) and letting the dispatch
  observation pin its kind keeps per-receive cost flat.
- **Keep the solver session for core minimization.** Learned lemmas make
  repeated unsat checks of subsets cheap; re-encoding subsets loses both
  lemmas and narrowing.
- **Exploit subsumption before searching.** Phantom delivery was the largest
  single win: a semantic argument that one branch subsumes another removed
  a whole fork class and, as a side effect, made nodes independent.
- **Decompose, then join and certify.** Per-node projection turned
  multiplicative forks additive. The join need not be proved correct: it is
  checked by replay, and only projection INVALID needs the product argument.
- **Merge, do not just dedup.** Exact duplicates are rare; worlds that differ
  in one unknown's candidate set are common.
- **Key cost matters.** Canonical keys are strings; computing them at every
  instruction cost more than stepping. Key only at block boundaries.
- **Certify VALID with the real replay.** This makes the engine untrusted for
  acceptance; only INVALID depends on the engine's completeness (tested, not
  proved).
- **Observation coverage determines difficulty.** Pre-observations pin every
  scalar before each action except election timeouts; entry terms and
  contents are never observed directly. Forks that survive are almost all
  about unknown initial log contents (configuration/retirement shape) and
  peers' sentIndex/matchIndex.
- **Inherent weakness of "exists s0".** Message contents delivered from
  pre-cut copies can always be explained away; only causality to post-cut
  sends (which phantom delivery deliberately ignores) or extra logging (send
  ids) would catch mutated or deleted deliveries.

## Report

### Result

The target is met at cut 10 by two independent approaches, entirely in
Lean after reduction (plus a yices subprocess for SMT). Both certify every
VALID with the unchanged `Replay.replayFrom`.

| cut 10 unless noted       | engine (`validate`)                       | SMT (`smt`)                                         |
| ------------------------- | ----------------------------------------- | --------------------------------------------------- |
| scenarios                 | 50/50 VALID, p50 47 ms, max 2.8 s         | 50/50 VALID, p50 0.23 s, max 1.3 s                  |
| 1045 mutants              | 1018 INVALID, p50 31 ms, max 5.0 s        | 1018 INVALID, p50 12 ms, max 0.28 s                 |
| scaling (median log-log)  | 0.51                                      | 0.79 (definitions 0.85)                             |
| cut 40 / half the actions | 41/44 / 42/50, max 125 s                  | 44/44 / 50/50, max 1.7 s                            |
| INVALID explanation       | node, instruction, dead branches' reasons | unsat core, p50 2 assertions, p50 0.12 s, max 438 s |
| INVALID trusts            | engine completeness                       | encoding faithfulness, solver                       |
| model size                | `Sym*.lean`, forks/merging/projection     | `SmtModel.lean`, line-by-line port                  |

- Same verdicts on all 1045 mutants. 0 INVALIDs where the true initial
  state replays. The 27 VALID mutants are explicable from some initial
  state (pre-cut messages, early mutations absorbed by `s0`).
- No loosening: every VALID comes with a concrete initial replay state
  (`--witness` prints it).

Usage: `ccfraft-midtrace smt DOC N [--explain] [--witness] [--no-invariants]
[--Q n] [--slack n] [--solver PATH]` and `ccfraft-midtrace validate DOC N
[--witness] [--global] [--no-invariants] [--cap K]`. `N` is the number of
reduced actions dropped.

### Trust argument

- VALID (both): trusted only as far as `Replay.replayFrom` and the
  witness's well-formedness (full `NodeState` per declared node, network,
  `active` = declared, no dropped history).
- INVALID, engine: relies on the engine being complete over the allowed
  initial states (every fork enumerated, `unsupported` wherever it cannot
  represent a case, phantom subsumption, projection product argument).
  Tested (0 unsound in 1018, no conflict with `--global`), not proved.
- INVALID, SMT: relies on `SmtModel` over-approximating the model and
  replay's observation checks (outside `cap`, reads are fresh values), on
  the simplifier only using implied facts, and on yices. Tested by the
  pinned differential run (verdicts equal replay on 1095 documents) and by
  agreement with the engine. 1016 of the 1018 INVALIDs never reach the
  solver. A proof is more tractable than for the engine: it is one
  denotation lemma per handler ("under any assignment, the terms evaluate
  to the model's step"), with no search-completeness argument. Solver
  trust would need proof-producing solving (cvc5 + Lean-SMT
  reconstruction), but cvc5 was far too slow here.
- The allowed initial states are restricted (active = declared, no
  dropped history, and by default cheap reachable-state invariants). This
  only rejects more, so it cannot accept anything replay would not. Cores
  report when they depend on the invariants.

### Limitations

- Both: "exists an initial state" cannot detect mutated or deleted
  deliveries explicable by pre-cut messages. Only causal links (message
  ids in the log) can close this gap.
- Engine: larger cuts blow up (41/44 at cut 40, 42/50 at half; two VALIDs
  take 94 s and 125 s). A log read before any `logLength` observation uses
  only lengths the node is later observed with (else UNKNOWN).
- SMT: entries with effects other than one reconfiguration or retirement
  record, and drops of a non-head packet, are `unsupported` (UNKNOWN; none
  occur in the scenarios). Capacities `K`/`Q` are retried upward when a
  core uses them.
- SMT diagnosis: cost is dominated by satisfiable trial checks; long-range
  windows (suffix_collision.3) take ~7 min. Cores are 1-minimal only
  modulo timeouts.

### Recommendation and future work

1. Use the SMT encoder as the primary mid-trace validator: it meets the
   target with large margin at every cut, scales better at large cuts,
   its model is a direct port of `Node.lean`, and it explains INVALID
   with small cores. Keep the engine as a solver-free differential oracle
   only if that is worth its maintenance.
2. Log more at the source (approach 7): forward `committable_indices`,
   emit `configurations` on every event, log entry terms or a periodic
   per-node snapshot. This shrinks the unknowns for any approach and
   makes cores shorter-range.
3. Correctness: keep the pinned differential run (`smt --pin`) as a
   regression test; if a proof is wanted, prove `SmtModel`'s per-handler
   denotation lemmas (option 2 applied to the SMT model, which is smaller
   than the engine).
4. Diagnosis speed-ups, in expected value order: start with the latest
   instruction groups (the contradiction is usually near the end of the
   window); run trial checks in parallel solver sessions; use a solver with
   millisecond timeouts for the trial phase only; accept a non-minimal core
   after a time budget.
5. If the engine is kept: represent "set of configurations above the commit
   index" symbolically or subsume worlds whose candidate sets are pointwise
   supersets (fixes the large-cut blowups); parallel per-node projections;
   bitmask candidate sets; a symbolic log length instead of hints.
