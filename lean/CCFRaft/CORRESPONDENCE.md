# Arbitrary-term correspondence with `ccfraft.tla`

This document is the review surface for the selected TLA-to-Lean transition
mapping. It records deliberate projections rather than claiming literal
state-shape equality.

`CCFRaft.system` is the active transition system. Followers and
candidates may time out in any term, and RequestVote and promotion are not
fixed to term two.

Canonical `CCFRaft.Proofs` proves this arbitrary-term transition system
inductive. Its proof-only histories retain ballot provenance: the ledger
snapshot, election term, quorum, delayed replication support, and commit
evidence. Runtime state and wire messages are unchanged.

The minimized invariant does not store log matching, quorum-log coverage,
potential-commit safety, or leader completeness. Those are derived from the
canonical ballot histories and commit evidence. This keeps the invariant
focused on facts that transitions must actually preserve.

Earlier development stages remain available in Git history; they are not
active modules in the current tree.

## Scope and deliberate projections

| Source concept                     | Lean representation                                              |
| ---------------------------------- | ---------------------------------------------------------------- |
| `Servers`                          | `Node := Fin NODE_COUNT`, with `NODE_COUNT = 5`                  |
| Configuration                      | Fixed set of all five nodes; not mutable state                   |
| Initial log                        | Empty; the CCF bootstrap prefix is projected away                |
| Signature entries                  | Each transaction and following signature collapse to one `Entry` |
| Entry payload                      | Opaque unique `txId`; erased by the source consensus algorithm   |
| Terms                              | Natural-numbered terms starting from bootstrap term 1             |
| Network guarantee                  | Ordered/no-duplicate FIFO queue per destination                  |
| Variables outside selected actions | Omitted                                                          |

The signature-pair projection maps source signature index `2n` to model index
`n`. Removed bootstrap prefixes rebase all later indices by the removed prefix
length.

## Locality and action mapping

| Lean action/helper                | `ccfraft.tla` operator                                    | Reads current node state                   | Writes node state         |
| --------------------------------- | --------------------------------------------------------- | ------------------------------------------ | ------------------------- |
| `clientRequest`                   | `ClientRequest` followed by `SignCommittableMessages`     | acting leader                              | acting leader             |
| `appendEntries`                   | projected pair of `AppendEntries` sends                   | source                                     | source                    |
| `receive`                         | projected pair of selected AppendEntries receive branches | destination and selected message           | destination               |
| `rejectAppendEntriesRequest?`     | `RejectAppendEntriesRequest`                              | destination                                | destination               |
| `appendEntriesAlreadyDone?`       | `AppendEntriesAlreadyDone`                                | destination                                | destination               |
| `conflictAppendEntriesRequest?`   | `ConflictAppendEntriesRequest`                            | destination                                | destination               |
| `noConflictAppendEntriesRequest?` | `NoConflictAppendEntriesRequest`                          | destination                                | destination               |
| `handleAppendEntriesResponse?`    | `HandleAppendEntriesResponse`                             | destination leader                         | destination leader        |
| `advanceCommitIndex`              | `AdvanceCommitIndex`                                      | acting leader's local `matchIndex`         | acting leader             |
| `timeout`                         | `Timeout` / `BecomeCandidate`                             | timing-out follower or candidate           | timing-out node           |
| `requestVote`                     | `RequestVote`                                             | source candidate                           | source network queue only |
| `updateTerm`                      | `UpdateTerm`                                              | destination and selected immutable message | destination               |
| RequestVote request receive       | `HandleRequestVoteRequest`                                | destination and selected request           | destination               |
| RequestVote response receive      | `HandleRequestVoteResponse`                               | destination and selected response          | destination               |
| `becomeLeader`                    | `BecomeLeader`                                            | candidate-local votes                      | candidate                 |

Receive handlers never inspect the source node's current state. They use only
the immutable request/response snapshot selected from the destination queue.
Global comparisons occur only in proof predicates.

### Collapsed-pair weak transitions

The entry projection hides odd source indices. One Lean entry represents a
source transaction followed immediately by its signature. Consequently one
Lean AppendEntries request/ACK exchange represents the source sequence that
replicates and acknowledges both raw entries.

The intermediate source state where only the transaction is replicated is
hidden. This is a weak/macro-step correspondence, not a one-to-one transition
mapping. The hidden state cannot advance `commitIndex` because it does not end at a
signature. Elections and delayed traffic make this a weak correspondence
rather than a one-to-one transition mapping.

## Semantic details retained

- AppendEntries uses
  `batchEnd = min (sentIndex + 1) leaderLog.length`: one entry when behind,
  or an empty heartbeat when caught up.
- Sending updates `sentIndex` optimistically.
- Exact duplicate messages are not enqueued twice.
- `Receive(source,destination)` selects the first message from that source in
  the destination queue; earlier messages from other sources do not block it.
- ACKs raise `matchIndex` monotonically.
- NACKs back `sentIndex` up but never below `matchIndex`.
- Conflict detection compares terms; overlap acceptance compares full entries.
- Conflict truncation is guarded above `commitIndex`.
- Commit chooses the greatest index above the current commit whose entry term
  equals the leader term and whose local ACK set is a five-node majority.
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
- A candidate becomes leader after recording a strict three-of-five majority.
- Leader promotion initializes local replication indices as in the source, but
  the collapsed signed-entry projection makes source signature-prefix
  truncation a no-op.
- Leaders in different terms may append and replicate while they remain
  locally unaware of each other.
- A same-term candidate receiving AppendEntries first executes
  `ReturnToFollowerState`; the request remains queued and is retried by a later
  receive action.
- Commit advancement still requires the chosen frontier entry to belong to the
  acting leader's current term.

## Executable regression evidence

`CCFRaft/arbitrary-terms.trace` leaves node one partitioned long enough to
timeout twice, elects it directly in term three, commits a term-three entry,
then elects node two in term four and commits another current-term entry.

`CCFRaft/delayed-ack.trace` elects a higher-term leader before node zero
processes its final old-term ACK. Node zero then forms a stale local majority
and commits; the elected higher-term leader already contains that prefix.

`CCFRaft/follower-overcommit.trace` exposed a Lean-reachable safety
issue: an already-done partial AppendEntries request carried a later leader
commit frontier, allowing the follower to commit a divergent signed suffix
beyond the request tail. The Lean model now additionally bounds follower
commit by `prevLogIndex + entries.length`, matching the standard Raft "last new
entry" bound. The checked-in `ccfraft.tla` and C++ implementation contain the
same missing local bound, but equivalent end-to-end reachability has not yet
been demonstrated there. This is an explicit evidence-backed correction rather
than an accidental projection.

The conflict helpers are also translated, but no conflict transition is
reachable before elections or term changes. Later grounded fixtures may project
`matching_partial`, `suffix_collision`, or
`follower_rollback_match_index` by removing irrelevant old messages/log
prefixes and translating every term by the same offset while preserving term
deltas.

## Current evidence and limitations

- Lean proofs establish safety over every execution of the active semantics.
- Executable traces cover repeated elections, skipped terms, delayed ACKs,
  and follower commit bounds.
- The simulator uses exactly `Enabled` and `next`.
- There is not yet a machine-checked semantics or bisimulation theorem between
  TLA+ and Lean.
- Differential edge comparison is deferred.
- `RcvDropIgnoredMessage` and other stale/ignored message branches are deferred
  to future message-loss and staleness work.

## Review status

Independent transition-correspondence, proof-soundness, and adversarial/vacuity
reviews during development produced:

- exact one-entry/heartbeat source batching;
- source-compatible NACK match index and term fields;
- explicit weak/macro-step documentation for collapsed transaction/signature
  replication;
- complete finite simulator candidate enumeration;
- runtime checks for commit bounds, committed-prefix consistency, log
  matching, log-term bounds, and election safety.

Those earlier proofs and review checkpoints remain available in Git history.
The current tree contains only the canonical arbitrary-term proof.
