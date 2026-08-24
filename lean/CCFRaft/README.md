# CCF Raft Lean model

This directory models the selected `ccfraft.tla` Raft core as an executable
Lean transition system. Kernel-checked safety proofs cover every modeled
action, including variable-size configuration changes and partial follower
commits.

The signature-aware milestone is called **Slice 4** in development history.
Canonical module names remain slice-neutral so later milestones build directly
on this artifact.

## Model

`Model.lean` defines the arbitrary-term transition system, including
`Enabled`, deterministic `next`, `system`, `runActions`, and `Reachable`.
`Properties.lean` defines the named ghost state and invariant components.
`ReconfigurationPreservation.lean` proves preservation and reachable safety.
`ConfigurationCoverage.lean` contains the causal configuration API.
`UpdateTermAuthority.lean` isolates the mixed-state quorum argument for
`UpdateTerm`. `Proofs.lean` keeps the public reachable-safety names stable.
The default `CCFRaft` target exports the reconfiguration proof. Git history
retains the earlier fixed-membership proof stages.

The combined model has:

- a fixed 15-node world with implicit initial configuration `{0,1,2,3,4}`;
- node 0 as the initial leader in term 1, other initial members as followers,
  and nodes outside the initial configuration as term-zero `.none` nodes;
- empty initial logs;
- opaque, externally allocated unique transaction IDs;
- explicit ordinary transaction, signature, and reconfiguration log entries;
- log-derived current and pending configurations;
- global one-time join history and arbitrary nonempty configuration changes;
- explicit ordered/no-duplicate per-destination message queues;
- AppendEntries sends one entry when behind and an empty heartbeat when caught
  up;
- executable `ClientRequest`, `ChangeConfiguration`, `AppendEntries`,
  `Receive`, `SignCommittableMessages`, `AdvanceCommitIndex`, `Timeout`,
  `RequestVote`, `UpdateTerm`, and `BecomeLeader` actions;
- split request/response handlers including reject, already-done,
  no-conflict extension, conflict truncation, ACK, and NACK behavior;
- highest current-term signature committed after ACKs form a strict majority
  in every configuration governing that index;
- follower and candidate timeouts into successor-term candidacy with a
  self-vote;
- RequestVote request/response snapshots of the last committable entry,
  signature-based log-up-to-date voting, and promotion after a strict majority
  in every candidate-active configuration;
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

## Proved for the reconfiguring transition set

For every arbitrary-term reachable state:

- `CommittedLogsPrefix`: committed logs are prefix-comparable;
- `LogMatching`;
- `MonoLog`: entry terms are monotonic;
- `ElectionSafety`: at most one leader exists in each term;
- `LeaderCompleteness`: every active higher-term leader contains
  each lower-term node's committed prefix;
- `CommittedFrontierIsSignature`: every positive commit index points to a
  signature entry.

The arbitrary-term proof is inductive over every enabled action, including
signature creation and replication, conflict truncation, delayed AppendEntries
acknowledgements, delayed votes, repeated elections, and skipped terms.
The induction also covers configuration changes, joint old/new quorums,
stacked disjoint configurations, follower exposure of intermediate
configurations, and elections after reconfiguration.

### How the arbitrary-term invariant works

The invariant stores proof evidence, not the safety conclusions themselves.
`InvariantFacts` stores runtime bounds and message transport facts.
`HistoricalSafetyFacts` names the election, activation, and commit evidence.

See [CCF Raft inductive invariant](INVARIANT.md) for every stored field and its
role in the final safety proof.

Log matching and monotonic terms are derived from canonical histories.
Election safety is derived from persistent voter choices. Committed-prefix
consistency is derived by intersecting commit-support quorums. Leader
completeness is derived by following ballot ancestry across frozen elections,
including elections which occurred before a delayed ACK completed its quorum.

## Build and simulate

```bash
cd lean
lake build CCFRaft.Model
lake build CCFRaft.Simulation
lake build ccf-raft-simulator
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/signature-commit.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/reconfiguration-5-to-5.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/reconfiguration-5-to-5-to-5.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/reconfiguration-5-to-1.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/arbitrary-terms.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/delayed-ack.trace
.lake/build/bin/ccf-raft-simulator replay CCFRaft/traces/follower-overcommit.trace
.lake/build/bin/ccf-raft-simulator simulate 5000 1 1000
```

Simulation runs for the requested number of milliseconds. It reports proposals
and accepted actions per family. A failure writes a replayable semantic action
trace.

Replay lines support `client`, variable-length `reconfigure`, `sign`, `append`,
`receive`, `commit`, `timeout`, `vote`, `term`, and `leader` actions.
Reconfiguration nodes render in stable identifier order.
The stacked reconfiguration trace moves through three disjoint five-node
configurations and elects a leader from each successor configuration.
The shrinking trace commits `5 -> 4 -> 3 -> 2 -> 1`, then commits another
signature with the singleton configuration. It immediately promotes the
singleton member, grows to three members, catches up a new follower after a
NACK, and commits the larger configuration.

`candidateChoicesComplete` proves every enabled action in the finite simulator
instance appears in its finite candidate list. The reusable
`SimulationAdapter.complete` theorem proves it can be materialized by a
simulator choice.
Random scheduling is only a bug-finding policy; it is not proof evidence.
Successful replay reports the action count, maximum current term, and final
per-node commit indices. Every replayed state checks that each positive commit
index points to a signature.

## Validate CCF implementation traces

`TraceValidation.lean` maps a five-event slice of preprocessed CCF
`raft_trace` NDJSON to exact semantic actions. It handles CCF's bootstrap index
offset and opaque node IDs, checks visible state and packet fields at their C++
pre-action timing, and uses bounded whole-trace backtracking. The search may
insert only hidden AppendEntries response deliveries. It requires every
observed send to have a later matching receive.

```bash
cd lean
./check_ccfraft_trace_validation.sh
```

See [CCF Raft implementation-trace validation](TRACE_VALIDATION.md) for the
supported records, bounds, trust boundary, and current limits.

## Out of scope

- unbounded node sets;
- explicit message loss and remaining stale-message behavior;
- retirement state and retirement transactions;
- pre-vote and remaining CCF-specific reconfiguration actions.
