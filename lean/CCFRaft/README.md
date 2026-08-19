# CCF Raft Lean model

This directory builds `ccfraft.tla` incrementally as an executable Lean
transition system with kernel-checked safety proofs.

## Slice 3: arbitrary terms

`CCFRaft.system` retains the completed slice-two election checkpoint.
`CCFRaft.Slice25.system` extends the same local handlers so any selected leader
can append, replicate, and commit entries in its current term.
`CCFRaft.Slice3.system` additionally permits repeated elections in arbitrary
natural-numbered terms.

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
  the leader.
- follower timeouts into term-two candidacy with a self-vote;
- RequestVote request/response snapshots, log-up-to-date voting, and
  three-of-five leader promotion;
- explicit newer-term observation that does not consume the selected message.
- coexisting leaders in different terms while an isolated old leader remains
  unaware of the election;
- term-two client entries, AppendEntries, acknowledgements, and current-term
  majority commit;
- reachable conflict truncation replacing an old leader's uncommitted suffix.
- candidates timing out repeatedly while partitioned;
- direct term jumps when delayed messages finally reach other nodes;
- later leaders proposing and committing entries in terms three, four, and
  beyond.

Partitions remain implicit: the scheduler simply does not select a
source/destination receive channel while other actions continue.

`Action`, `Enabled`, and `next` are the authoritative semantics. Proofs and the
compiled simulator call these same definitions.

## Proved

For every reachable state:

- `CommittedLogsPrefix`: committed logs are prefixes of each other;
- `LogMatching`;
- same index and term imply the same transaction ID;
- entry terms are monotonic;
- `ElectionSafety`: at most one leader exists in each term;
- `TermTwoLeaderCompleteness`: every term-two leader contains node zero's
  term-one committed prefix.

For every enabled transition from a reachable state:

- `CommittedLogMonotonicity`: every node's committed log is append-only.

Slice 3 additionally proves these properties for arbitrary terms:

- committed-log prefix consistency;
- log matching and monotonic entry terms;
- election safety;
- TLA-style `LeaderCompleteness`: every active higher-term leader contains
  each lower-term node's committed prefix.

The arbitrary-term proof is inductive over every enabled action, including
conflict truncation, delayed AppendEntries acknowledgements, delayed votes,
repeated elections, and skipped terms.

## Build and simulate

```bash
cd lean
lake build
lake build ccf-raft-simulator
.lake/build/bin/ccf-raft-simulator simulate 5000 1 1000
.lake/build/bin/ccf-raft-simulator replay ccf-raft-failure.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/slice2-election.trace
.lake/build/bin/ccf-raft-simulator simulate25 5000 1 1000
.lake/build/bin/ccf-raft-simulator replay25 CCFRaft/slice25-happy.trace
.lake/build/bin/ccf-raft-simulator replay25 CCFRaft/slice25-conflict.trace
.lake/build/bin/ccf-raft-simulator simulate3 5000 1 1000
.lake/build/bin/ccf-raft-simulator replay3 CCFRaft/slice3-arbitrary.trace
.lake/build/bin/ccf-raft-simulator replay3 CCFRaft/slice3-delayed-ack.trace
.lake/build/bin/ccf-raft-simulator replay3 CCFRaft/slice3-follower-overcommit.trace
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

   ## Future slices

   4. Prove the unbounded-node AppendEntries/RequestVote core.
   4.5. Add explicit message loss and remaining stale-message behavior.
   5. Add reconfiguration.
   6. Add pre-vote and remaining CCF-specific actions.

Later slices remain roadmap notes, not current claims.
