# Slice 2 correspondence with `ccfraft.tla`

This document is the review surface for the selected TLA-to-Lean transition
mapping. It records deliberate projections rather than claiming literal
state-shape equality.

Slice 2.5 is implemented as `CCFRaft.Slice25.system`, preserving the completed
slice-two checkpoint while reusing the same message and local-handler
definitions.

Slice 3 is `CCFRaft.Slice3.system`. It changes only election guards: followers
and candidates may time out in any term, RequestVote and promotion are no
longer fixed to term two, and the existing deterministic updates carry the
selected node's current term.

`CCFRaft.Slice3Proofs` proves the resulting arbitrary-term transition system
inductive. Its proof-only histories retain ballot provenance: the ledger
snapshot, election term, quorum, delayed replication support, and commit
evidence. Runtime state and wire messages are unchanged.

## Scope and deliberate projections

| Source concept                     | Slice 2 representation                                           |
| ---------------------------------- | ---------------------------------------------------------------- |
| `Servers`                          | `Node := Fin NODE_COUNT`, with `NODE_COUNT = 5`                  |
| Configuration                      | Fixed set of all five nodes; not mutable state                   |
| Initial log                        | Empty; the CCF bootstrap prefix is projected away                |
| Signature entries                  | Each transaction and following signature collapse to one `Entry` |
| Entry payload                      | Opaque unique `txId`; erased by the source consensus algorithm   |
| Terms                              | Log entries remain in term 1; node terms are 1 or 2              |
| Network guarantee                  | Ordered/no-duplicate FIFO queue per destination                  |
| Variables outside selected actions | Omitted                                                          |

The signature-pair projection maps source signature index `2n` to slice index
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
| `timeout`                         | `Timeout` / `BecomeCandidate`                             | timing-out follower                        | timing-out follower       |
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
mapping. In this slice the hidden state cannot advance `commitIndex` because it
does not end at a signature, and terms never change. Later slices must revisit
this projection when elections, loss, or reordering make the hidden
intermediate traffic observable.

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
- Timeout advances a term-one follower directly to term two, records its
  self-vote, and starts an election.
- `UpdateTerm` observes but does not consume a newer queued message.
- Future requests and ordinary responses require `UpdateTerm` before their
  normal same-term handler can run.
- Stale successful AppendEntries responses are consumed without changing node
  state, preventing an old ACK from blocking later traffic from that source.
- AppendEntries NACKs are handled regardless of their overloaded `term` field,
  which carries last-match metadata; `UpdateTerm` may independently be enabled
  for the same message, matching the source receive disjunction.
- A voter grants at most one candidate in term two and only when the candidate
  log is at least as up to date as its own.
- A candidate becomes leader after recording a strict three-of-five majority.
- Leader promotion initializes local replication indices as in the source, but
  the collapsed signed-entry projection makes source signature-prefix
  truncation a no-op.
- Slice 2.5 allows both term-one and term-two leaders to append and replicate
  while they remain locally unaware of each other.
- A same-term candidate receiving AppendEntries first executes
  `ReturnToFollowerState`; the request remains queued and is retried by a later
  receive action.
- Commit advancement still requires the chosen frontier entry to belong to the
  acting leader's current term.

## Synthetic non-vacuity evidence

`Examples.requestReplicateCommitReachable` is a synthetic non-vacuity path
using the same semantic actions as the model:

Projection assumptions are the removed bootstrap prefix and collapsed
transaction/signature pairs. The executable path then:

1. submits one transaction;
2. performs projected request/response exchanges with two followers;
3. forms a majority with the leader;
4. commits the resulting non-empty prefix.

The resulting Lean path is proved reachable through eight enabled executable
actions. It is not claimed to be projected from the checked-in one-node
`append` scenario. A grounded multi-node trace projection remains future
correspondence evidence.

`Examples.termTwoElectionReachable` extends that committed state with two
competing candidates. Candidate one receives votes from nodes three and four
and becomes the term-two leader; candidate two retains only its self-vote.
`Examples.splitVoteHasNoWinner` separately checks the intermediate two-candidate
state has no enabled promotion.

`CCFRaft/slice25-conflict.trace` is the required cross-term witness:

1. nodes one, two, and three elect node one in term two;
2. isolated node zero appends and replicates an uncommitted term-one suffix to
   node four;
3. node one appends a term-two entry;
4. node four advances term, truncates the conflicting old suffix, and accepts
   the new entry;
5. node one records a majority and commits the term-two entry plus its inherited
   prefix.

`CCFRaft/slice3-arbitrary.trace` leaves node one partitioned long enough to
timeout twice, elects it directly in term three, commits a term-three entry,
then elects node two in term four and commits another current-term entry.

`CCFRaft/slice3-delayed-ack.trace` elects a higher-term leader before node zero
processes its final old-term ACK. Node zero then forms a stale local majority
and commits; the elected higher-term leader already contains that prefix.

`Examples.slice3SameTermCompetitorCannotWin` advances an isolated follower into
an already-owned term and checks that the frozen winning quorum prevents a
second leader in that term.

`CCFRaft/slice3-follower-overcommit.trace` exposed a Lean-reachable safety
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

- Lean proofs establish safety over every execution of the slice semantics.
- Non-vacuity examples establish an ordinary quorum-commit path exists.
- The simulator uses exactly `Enabled` and `next`.
- There is not yet a machine-checked semantics or bisimulation theorem between
  TLA+ and Lean.
- Differential edge comparison is deferred.
- Slice 2.5 still contains only one election-term transition.
- `RcvDropIgnoredMessage` and other stale/ignored message branches are deferred
  to the dedicated message-loss/staleness slice.

## Review status

Independent transition-correspondence, proof-soundness, and adversarial/vacuity
reviews were completed for slice 1. Slice 2 retains those corrections and adds
kernel-checked election majority intersection, vote soundness, election safety,
and term-two leader completeness.

The slice 1 findings led to:

- exact one-entry/heartbeat source batching;
- source-compatible NACK match index and term fields;
- explicit weak/macro-step documentation for collapsed transaction/signature
  replication;
- complete finite simulator candidate enumeration;
- synthetic examples labelled separately from grounded trace evidence;
- runtime checks for every supporting invariant category.
