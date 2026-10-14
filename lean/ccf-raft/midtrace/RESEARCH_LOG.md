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

| cut | max log | max entries (all nodes) | config entries | in-flight msgs | AE entries in flight |
| --- | --- | --- | --- | --- | --- |
| after 10 actions | 6 | 10 | 5 | 8 | 0 |
| half the actions | 22 | 84 | 25 | 15 | 8 |

At cut 10, 169 of 309 initial entries get a `kind` observation somewhere in
the suffix, and 67 of 156 configuration-carrying entries get a
`configurations` observation. Every node's scalars (role, currentTerm,
logLength, commitIndex, retiredCommittedIndex) are observed before its first
action (168/168 node instances), via the `*-pre` observations.

## Which unknowns matter (perturbation study)

`build/research/scripts/perturb.py` (research only, not part of validation)
perturbs one unknown of the true cut-10 state and reruns the real
`replay-from`. 5164 runs, 28 s:

| unknown | still passes | rejected | rejection instruction (p50 / p90 / max) |
| --- | --- | --- | --- |
| entry content | 110 | 864 | 19 / 81 / 224 |
| entry term | 230 | 388 | 19 / 103 / 305 |
| matchIndex | 220 | 492 | 14 / - / 269 |
| sentIndex | 344 | 368 | 3 / - / 68 |
| votedFor | 604 | 0 | - |
| leaderKnown | 168 | 0 | - |
| isNewFollower | 168 | 0 | - |
| votesGranted | 604 | 0 | - |
| preVotesGranted | 604 | 0 | - |

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

(See sections below; updated as work proceeds.)
