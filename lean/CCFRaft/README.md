# CCF Raft Lean model

This directory builds `ccfraft.tla` incrementally as an executable Lean
transition system with kernel-checked safety proofs.

## Slice 1: single-term AppendEntries

The current slice has:

- five fixed nodes and one fixed configuration;
- node 0 as the sole leader in term 1;
- empty initial logs;
- opaque, externally allocated unique transaction IDs;
- every transaction treated as immediately signed and commit-eligible;
- explicit ordered/no-duplicate per-destination message queues;
- AppendEntries sends one entry when behind and an empty heartbeat when caught
  up;
- executable `ClientRequest`, `AppendEntries`, `Receive`, and
  `AdvanceCommitIndex` actions;
- split request/response handlers including reject, already-done,
  no-conflict extension, conflict truncation, ACK, and NACK behavior;
- highest current-term index committed after ACKs from a majority, including
  the leader.

`Action`, `Enabled`, and `next` are the authoritative semantics. Proofs and the
compiled simulator call these same definitions.

## Proved

For every reachable state:

- `CommittedLogsPrefix`: committed logs are prefixes of each other;
- `LogMatching`;
- same index and term imply the same transaction ID;
- entry terms are monotonic.

For every enabled transition from a reachable state:

- `CommittedLogMonotonicity`: every node's committed log is append-only.

Each action also has a frame theorem proving nodes other than the acting node
are unchanged. Conflict truncation is implemented but proved unreachable in
this single-leader, single-term slice.

## Build and simulate

```bash
cd lean
lake build
lake build ccf-raft-simulator
.lake/build/bin/ccf-raft-simulator simulate 5000 1 1000
.lake/build/bin/ccf-raft-simulator replay ccf-raft-failure.trace
```

Simulation runs for the requested number of milliseconds. It reports proposals
and accepted actions per family. A failure writes a replayable semantic action
trace.

`candidateChoicesComplete` proves every enabled action in the finite simulator
instance appears in its finite candidate list. The reusable
`SimulationAdapter.complete` theorem proves it can be materialized by a
simulator choice.
Random scheduling is only a bug-finding policy; it is not proof evidence.

## Future slices

2. Add term-2 timeout and RequestVote request/response flows, prove majority
   intersection, election safety, and term-2 leader completeness.
3. Prove committed-log safety across commits in terms 1 and 2.
4. Generalize adjacent terms.
5. Generalize skipped election terms.
6. Prove the unbounded AppendEntries/RequestVote core.
6.5. Add message loss and stale-message handling.
7. Add reconfiguration.
8. Add pre-vote and remaining CCF-specific actions.

Later slices remain roadmap notes, not current claims.
