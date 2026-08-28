# Arbitrary-term correspondence with `ccfraft.tla`

This document is the review surface for the selected TLA-to-Lean transition
mapping. It records deliberate projections rather than claiming literal
state-shape equality.

`CCFRaft.system` is the active transition system. Followers and
candidates may time out in any term, and RequestVote and promotion are not
fixed to term two.

The checked proof covers `changeConfiguration`, configuration-aware quorums,
and every other action in the active transition system. Its proof-only
histories retain ballot provenance: the ledger snapshot, election term,
quorum, delayed replication support, commit evidence, and signed
configuration activations.

The minimized invariant does not store log matching, quorum-log coverage,
potential-commit safety, or leader completeness. Those are derived from the
canonical ballot histories and commit evidence. This keeps the invariant
focused on facts that transitions must actually preserve.

Earlier development stages remain available in Git history; they are not
active modules in the current tree.

## Scope and deliberate projections

| Source concept                     | Lean representation                                            |
| ---------------------------------- | -------------------------------------------------------------- |
| `Servers`                          | Abstract `Node` with `DecidableEq Node`                         |
| Bounded tooling                    | `Node := Fin NODE_COUNT`, with `NODE_COUNT = 15`               |
| Bootstrap                          | `Bootstrap Node` selects a configuration and member leader      |
| Canonical bootstrap                | `{0,1,2,3,4}`, leader 0, at projected index 0                  |
| Configuration                      | `Configuration` records derived from each node's physical log  |
| `configurations`                   | `currentConfiguration` plus later `activeConfigurations` views |
| `hasJoined`                        | Global `Finset Node`, initially the initial configuration      |
| Initial log                        | Empty; the CCF bootstrap prefix is projected away              |
| Signature entries                  | Explicit `EntryContent.signature` entries                      |
| Reconfiguration entries            | Explicit `EntryContent.reconfiguration` at one-based indices   |
| Transaction entries                | `EntryContent.transaction` with an opaque unique `txId`        |
| Terms                              | Natural-numbered terms starting from bootstrap term 1          |
| Network guarantee                  | Ordered/no-duplicate FIFO queue per destination                |
| Variables outside selected actions | Omitted                                                        |

Removed bootstrap prefixes rebase all later indices by the removed prefix
length.

## Locality and action mapping

| Lean action/helper                | `ccfraft.tla` operator                | Reads current node state                   | Writes node state         |
| --------------------------------- | ------------------------------------- | ------------------------------------------ | ------------------------- |
| `clientRequest`                   | `ClientRequest`                       | acting leader                              | acting leader             |
| `changeConfiguration`             | `ChangeConfigurationInt`              | acting leader and global join history      | leader and join history   |
| `signCommittableMessages`         | `SignCommittableMessages`             | acting leader                              | acting leader             |
| `appendEntries`                   | `AppendEntries`                       | source                                     | source                    |
| `receive`                         | selected AppendEntries receive branch | destination and selected message           | destination               |
| `rejectAppendEntriesRequest?`     | `RejectAppendEntriesRequest`          | destination                                | destination               |
| `appendEntriesAlreadyDone?`       | `AppendEntriesAlreadyDone`            | destination                                | destination               |
| `conflictAppendEntriesRequest?`   | `ConflictAppendEntriesRequest`        | destination                                | destination               |
| `noConflictAppendEntriesRequest?` | `NoConflictAppendEntriesRequest`      | destination                                | destination               |
| `handleAppendEntriesResponse?`    | `HandleAppendEntriesResponse`         | destination leader                         | destination leader        |
| `advanceCommitIndex`              | `AdvanceCommitIndex`                  | acting leader's local `matchIndex`         | acting leader             |
| `timeout`                         | `Timeout` / `BecomeCandidate`         | timing-out follower or candidate           | timing-out node           |
| `requestVote`                     | `RequestVote`                         | source candidate                           | source network queue only |
| `updateTerm`                      | `UpdateTerm`                          | destination and selected immutable message | destination               |
| RequestVote request receive       | `HandleRequestVoteRequest`            | destination and selected request           | destination               |
| RequestVote response receive      | `HandleRequestVoteResponse`           | destination and selected response          | destination               |
| `becomeLeader`                    | `BecomeLeader`                        | candidate-local votes                      | candidate                 |

Receive handlers never inspect the source node's current state. They use only
the immutable request/response snapshot selected from the destination queue.
Global comparisons occur only in proof predicates.

## Semantic details retained

- AppendEntries uses
  `batchEnd = min (sentIndex + 1) leaderLog.length`: one entry when behind,
  or an empty heartbeat when caught up.
- Initial roles and terms come from `Bootstrap`. Its leader starts as the
  term-one leader, its other members start as term-one followers, and the node
  store omits outsiders.
- The `Bootstrap` parameter constructs `initialState` and the implicit
  configuration. Runtime `State` does not store it.
- A configuration change appends a current-term physical log entry, marks only
  newly added nodes joined, allocates fresh local state for them, and
  initializes their `sentIndex` to the old log length. Other peer cursors are
  preserved. The inductive invariant proves that allocated identities are
  exactly the one-time join history. The target may be any nonempty finite set
  of node identities.
- Configuration 0 remains implicit. A node's current configuration is its
  latest reconfiguration at or before `commitIndex`; later log
  reconfigurations remain active and pending.
- Timeout is available only to a node in its own active configuration union.
  RequestVote and AppendEntries sends are limited to the source's active
  configuration union.
- At the raw receive-handler boundary, AppendEntries and RequestVote requests
  may come from an unallocated sender. Responses from an unallocated sender are
  consumed without changing local state. The transition system does not
  generate these inbound messages from unallocated nodes.
- Election support requires a strict majority in every active configuration
  known by the candidate.
- Replication support at index `i` requires a strict majority in every active
  configuration whose reconfiguration index is at most `i`.
- Committing signature 2 after reconfiguration 1 therefore requires majorities
  in both the old and new configurations. Once commit 2 advances, only the new
  configuration remains active.
- Sending updates `sentIndex` optimistically.
- Exact duplicate messages are not enqueued twice.
- `Receive(source,destination)` selects the first message from that source in
  the destination queue; earlier messages from other sources do not block it.
- ACKs raise `matchIndex` monotonically.
- NACKs back `sentIndex` up but never below `matchIndex`.
- Conflict detection compares terms; overlap acceptance compares full entries.
- Conflict truncation is guarded above `commitIndex`.
- Commit chooses the greatest signature index above the current commit whose
  entry term equals the leader term and whose local ACK set contains a strict
  majority in each configuration governing that index.
- Timeout advances a follower or candidate to its successor term, records its
  self-vote, and starts an election.
- `UpdateTerm` observes but does not consume a newer queued message.
- Future requests and ordinary responses require `UpdateTerm` before their
  normal same-term handler can run.
- Stale successful AppendEntries responses are consumed without changing node
  state, preventing an old ACK from blocking later traffic from that source.
- AppendEntries NACKs are handled regardless of their overloaded `term` field,
  which carries last-match metadata; `UpdateTerm` may independently be enabled
  for the same message, matching the source receive disjunction.
- A voter grants at most one candidate per term and only when the candidate log
  is at least as up to date as its own.
- A candidate becomes leader after recording a strict majority in every active
  configuration known from its log.
- Leader promotion truncates its log to the latest signature, initializes
  `sentIndex` from that truncated length, and clears `matchIndex`.
- Truncating an unsigned reconfiguration removes it from every derived
  configuration view.
- Leaders in different terms may append and replicate while they remain
  locally unaware of each other.
- A same-term candidate receiving AppendEntries first executes
  `ReturnToFollowerState`; the request remains queued and is retried by a later
  receive action.
- Commit advancement still requires the chosen frontier entry to belong to the
  acting leader's current term.

## Executable regression evidence

`CCFRaft/traces/signature-commit.trace` appends a transaction and signature, replicates
both entries to a majority, and commits the signature frontier.

`CCFRaft/traces/reconfiguration-5-to-5.trace` changes from `{0,1,2,3,4}` to
`{5,6,7,8,9}`, replicates reconfiguration 1 and signature 2 to old and new
majorities, commits on node 0, propagates that commit to node 5 by heartbeat,
then elects node 5 in term 2 using the new configuration.

`CCFRaft/traces/reconfiguration-5-to-5-to-5.trace` continues with a second disjoint
configuration `{10,11,12,13,14}`. The new nodes first reject an optimistic
AppendEntries request, catch up from index 1, commit the second configuration,
and elect node 10 in term 3.

`CCFRaft/traces/arbitrary-terms.trace` leaves node one partitioned long enough to
timeout twice, elects it directly in term three, commits a term-three
signature, then elects node two in term four and commits another current-term
signature.

`CCFRaft/traces/delayed-ack.trace` elects a higher-term leader before node zero
processes the final ACK for its current-term signature. Node zero then forms a
stale local majority and commits; the elected higher-term leader already
contains that signed prefix.

`CCFRaft/traces/follower-overcommit.trace` exposed a Lean-reachable safety
issue: an already-done partial AppendEntries request carried signed commit
frontier six while its verified tail ended at signature four, beyond which the
follower had a divergent signed suffix. The follower now commits only through
signature four. The Lean model bounds follower commit by
`prevLogIndex + entries.length`, matching the standard Raft "last new entry"
bound. The checked-in `ccfraft.tla` and C++ implementation contain the same
missing local bound, but equivalent end-to-end reachability has not yet been
demonstrated there. This is an explicit evidence-backed correction rather than
an accidental projection.

The conflict helpers are also translated, but no conflict transition is
reachable before elections or term changes. Later grounded fixtures may project
`matching_partial`, `suffix_collision`, or
`follower_rollback_match_index` by removing irrelevant old messages/log
prefixes and translating every term by the same offset while preserving term
deltas.

## Current evidence and limitations

- The default `CCFRaft` target checks reconfiguration preservation and the
  reachable safety exports.
- Executable traces cover explicit transaction/signature replication,
  signature-only commits, stacked `5 -> 5 -> 5` configuration changes,
  shrinking `5 -> 4 -> 3 -> 2 -> 1` configuration changes, repeated elections,
  skipped terms, delayed ACKs, and follower commit bounds.
- The simulator uses exactly `Enabled` and `next`.
- There is not yet a machine-checked semantics or bisimulation theorem between
  TLA+ and Lean.
- Differential edge comparison is deferred.
- The model has no mutable retirement state. A removed node
  may remain a stale local leader, but active-union send/election guards and
  one-time `hasJoined` history constrain its reconfiguration behavior.
- `RcvDropIgnoredMessage` and other stale/ignored message branches are deferred
  to future message-loss and staleness work.

## Review status

Independent transition-correspondence, proof-soundness, and adversarial/vacuity
reviews during development produced:

- exact one-entry/heartbeat source batching;
- source-compatible NACK match index and term fields;
- explicit transaction/signature replication and signature-only commits;
- complete finite simulator candidate enumeration;
- runtime checks for commit bounds, committed-prefix consistency, log
  matching, log-term bounds, and election safety.

Those earlier proofs and review checkpoints remain available in Git history.
The default target checks the canonical reconfiguration proof.
