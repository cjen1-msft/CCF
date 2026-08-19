# CCF Raft Lean model

This directory models the selected `ccfraft.tla` Raft core as an executable
Lean transition system with kernel-checked safety proofs.

## Model

`Model.lean` defines the arbitrary-term transition system, including
`Enabled`, deterministic `next`, `system`, `runActions`, and `Reachable`.
`Properties.lean` and `Proofs.lean` are the canonical property and proof
modules. Git history contains the earlier development stages.

The combined model has:

- five fixed nodes and one fixed configuration;
- node 0 as the initial leader in term 1;
- empty initial logs;
- opaque, externally allocated unique transaction IDs;
- every transaction treated as immediately signed and commit-eligible;
- explicit ordered/no-duplicate per-destination message queues;
- AppendEntries sends one entry when behind and an empty heartbeat when caught
  up;
- executable `ClientRequest`, `AppendEntries`, `Receive`,
  `AdvanceCommitIndex`, `Timeout`, `RequestVote`, `UpdateTerm`, and
  `BecomeLeader` actions;
- split request/response handlers including reject, already-done,
  no-conflict extension, conflict truncation, ACK, and NACK behavior;
- highest current-term index committed after ACKs from a majority, including
  the leader;
- follower and candidate timeouts into successor-term candidacy with a
  self-vote;
- RequestVote request/response snapshots, log-up-to-date voting, and
  three-of-five leader promotion;
- explicit newer-term observation that does not consume the selected message;
- coexisting leaders in different terms while an isolated old leader remains
  unaware of the election;
- arbitrary-term client entries, AppendEntries, acknowledgements, and
  current-term majority commit;
- reachable conflict truncation replacing an old leader's uncommitted suffix;
- candidates timing out repeatedly while partitioned;
- direct term jumps when delayed messages finally reach other nodes;
- later leaders proposing and committing entries in terms three, four, and
  beyond.

Partitions remain implicit: the scheduler simply does not select a
source/destination receive channel while other actions continue.

`Action`, `Enabled`, and `next` are the authoritative semantics. Proofs and the
compiled simulator call these same definitions.

## Proved

For every arbitrary-term reachable state:

- `CommittedLogsPrefix`: committed logs are prefix-comparable;
- `LogMatching`;
- `MonoLog`: entry terms are monotonic;
- `ElectionSafety`: at most one leader exists in each term;
- `LeaderCompleteness`: every active higher-term leader contains
  each lower-term node's committed prefix.

The arbitrary-term proof is inductive over every enabled action, including
conflict truncation, delayed AppendEntries acknowledgements, delayed votes,
repeated elections, and skipped terms.

### How the arbitrary-term invariant works

The invariant stores proof evidence, not the safety conclusions themselves:

- local bounds keep commit indices, terms, and replication cursors valid;
- immutable message histories retain the exact ledger snapshots carried by
  delayed AppendEntries and RequestVote messages;
- canonical histories and frozen election records preserve ballot ancestry;
- temporal ACK and vote histories connect delayed replication support to later
  elections;
- commit evidence records the quorum and ledger frontier supporting each live
  committed prefix.

Log matching and monotonic terms are derived from canonical histories.
Election safety is derived from persistent voter choices. Committed-prefix
consistency is derived by intersecting commit-support quorums. Leader
completeness is derived by following ballot ancestry across frozen elections,
including elections which occurred before a delayed ACK completed its quorum.

## Build and simulate

```bash
cd lean
lake build
lake build ccf-raft-simulator
.lake/build/bin/ccf-raft-simulator simulate 5000 1 1000
.lake/build/bin/ccf-raft-simulator replay CCFRaft/arbitrary-terms.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/delayed-ack.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/follower-overcommit.trace
```

Simulation runs for the requested number of milliseconds. It reports proposals
and accepted actions per family. A failure writes a replayable semantic action
trace.

Replay lines support `client`, `append`, `receive`, `commit`, `timeout`, `vote`,
`term`, and `leader` actions.

`candidateChoicesComplete` proves every enabled action in the finite simulator
instance appears in its finite candidate list. The reusable
`SimulationAdapter.complete` theorem proves it can be materialized by a
simulator choice.
Random scheduling is only a bug-finding policy; it is not proof evidence.

## Out of scope

- unbounded node sets;
- explicit message loss and remaining stale-message behavior;
- reconfiguration;
- pre-vote and remaining CCF-specific actions.
