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
  This is the closest fit and the basis of the chosen approach.
- IC3/PDR and array-based model checking (MCMT): backward reachability for
  "is some state consistent", heavy machinery for a single trace.
- Linear-time history checkers (Elle; Porcupine with P-compositionality,
  Lowe): decompose by key/object so cost adds instead of multiplies. Per-node
  projection below is the same idea.
- QuickXplain / MUS extraction for explanations.

Candidates, as assessed:

| #   | approach                                  | VALID                     | INVALID             | verdict                                                                                        |
| --- | ----------------------------------------- | ------------------------- | ------------------- | ---------------------------------------------------------------------------------------------- |
| 1   | Observation-seeded concrete witness       | fast when the guess works | cannot prove        | the user's earlier hack; subsumed by 3 (3 builds and certifies a witness)                      |
| 2   | Belief sets (explicit set of states)      | exact                     | exact               | state is unbounded (logs, terms): needs a symbolic representation, i.e. 3                      |
| 3   | Lazy symbolic execution (BFS over worlds) | certified by `replayFrom` | exhaustive search   | **chosen; meets the target**                                                                   |
| 4   | Abstract interpretation                   | no                        | fast but incomplete | useful only as a pre-filter; 3 already rejects in 31 ms p50                                    |
| 5   | SAT/SMT encoding (+ LRAT checked in Lean) | yes                       | yes                 | the user's quadratic encoding problems; an in-Lean bit-blaster of the model is a large project |
| 6   | CEGIS / concolic with nogoods             | yes                       | slow to converge    | errors surface ~100 instructions after the cause (perturbation study), so nogoods are weak     |
| 7   | Richer logs / periodic snapshots          | trivial                   | trivial             | complementary; removes most unknowns at the source                                             |

## Chosen approach: lazy symbolic execution in Lean

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
  INVALID vs UNKNOWN (global hits its cap), 2 VALID vs UNKNOWN, 25 agree
  VALID; no VALID/INVALID conflict.
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

## Implications

- **Cost is frontier width x length.** The per-instruction step is cheap;
  runtime is the sum of frontier sizes. Anything that bounds the frontier
  gives linear scaling. In the SMT encodings the analogous cost was terms
  that grow with the trace (each AppendEntries recv rewrites the ledger),
  giving the quadratic behaviour.
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

The target is met at cut 10 by lazy symbolic execution, entirely in Lean
after reduction:

- 50/50 scenarios VALID, max 2.8 s, p50 47 ms; about 6 s wall for all of them.
- 1018/1045 mutated suffixes INVALID, max 5.0 s, p50 31 ms. 0 UNKNOWN.
  0 INVALIDs where the true initial state replays. The 27 VALID mutants are
  certified by `replayFrom`; they are explicable from some initial state.
- Roughly linear in suffix length (median log-log slope 0.51).
- No loosening: every VALID verdict comes with a concrete initial replay state
  that the unchanged `Replay.replayFrom` accepts (`--witness` prints it).
- INVALID pinpoints the node, instruction and raw log line where the last
  live branches died, with their reasons. This is a cheap first-cut
  explanation; projection already isolates one node's instructions.

Usage: `ccfraft-midtrace validate DOC N [--witness] [--global]
[--no-invariants] [--cap K]`. `N` is the number of reduced actions dropped.

### Trust argument

- VALID: trusted only as far as `Replay.replayFrom` and the witness's
  well-formedness (full `NodeState` per declared node, network, `active` =
  declared, no dropped history).
- INVALID: relies on the engine being complete over the allowed initial
  states (every fork enumerated, `unsupported` wherever it cannot
  represent a case, phantom subsumption, projection product argument). It
  is tested (0 unsound in 1018, no VALID/INVALID conflict with `--global`
  mode) but not proved. A Lean proof that
  `SymModel` over-approximates `Replay` is feasible because both are Lean,
  but it is a large project.
- The allowed initial states are restricted (active = declared, no
  dropped history, and by default cheap reachable-state invariants). This
  only rejects more, so it cannot accept anything replay would not.

### Limitations

- Larger cuts: 48/48 at cut 20, 41/44 at cut 40 and 42/50 at half the
  actions. Failures are frontier blowups from unknown initial log contents
  (configuration/retirement shape) split differently by each membership
  query. Two VALIDs take 94 s and 125 s.
- A log read before any `logLength` observation uses only lengths the node
  is later observed with; other lengths are `unsupported`, giving UNKNOWN
  rather than a wrong INVALID.
- "Exists an initial state" cannot detect mutated or deleted deliveries
  explicable by pre-cut messages. Only causal links (message ids in the log)
  can close this gap.

### Recommendation and future work

1. Adopt the engine for cut-sized gaps (tens of actions): it meets the target
   with margin and needs no external solver.
2. Log more at the source (approach 7), which shrinks the unknowns that
   cause large-cut blowups: forward `committable_indices`, emit
   `configurations` on every event, and log entry terms or a periodic
   per-node snapshot (term, log terms, commit index, configs). A snapshot
   every K events bounds the gap regardless of where validation starts.
3. Engine improvements, in expected value order:
   - represent "set of configurations above the commit index" symbolically
     (one atom per membership question instead of per entry), or subsume
     worlds whose candidate sets are pointwise supersets (generalized
     merging);
   - parallel per-node projections (`Task`), trivially parallel;
   - bitmask candidate sets instead of `List Content` to cut key cost;
   - a symbolic log length, removing the hint heuristic.
4. Explanations: INVALID already names node and instruction. For a minimal
   explanation, run QuickXplain/delta debugging over that node's projection
   (each check is ~30 ms p50), well inside the 10 min budget.
5. SAT/SMT (approach 5) is not recommended: the user's encodings were
   quadratic, and the subsumption/projection insights here are what kept
   the search linear; they would need re-deriving as encoding tricks.
