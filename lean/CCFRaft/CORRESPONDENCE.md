# Slice 1 correspondence with `ccfraft.tla`

This document is the review surface for the selected TLA-to-Lean transition
mapping. It records deliberate projections rather than claiming literal
state-shape equality.

## Scope and deliberate projections

| Source concept | Slice 1 representation |
| --- | --- |
| `Servers` | `Node := Fin NODE_COUNT`, with `NODE_COUNT = 5` |
| Configuration | Fixed set of all five nodes; not mutable state |
| Initial log | Empty; the CCF bootstrap prefix is projected away |
| Signature entries | Each transaction and following signature collapse to one `Entry` |
| Entry payload | Opaque unique `txId`; erased by the source consensus algorithm |
| Terms | All nodes and entries remain in term 1 |
| Network guarantee | Ordered/no-duplicate FIFO queue per destination |
| Variables outside selected actions | Omitted |

The signature-pair projection maps source signature index `2n` to slice index
`n`. Removed bootstrap prefixes rebase all later indices by the removed prefix
length.

## Locality and action mapping

| Lean action/helper | `ccfraft.tla` operator | Reads current node state | Writes node state |
| --- | --- | --- | --- |
| `clientRequest` | `ClientRequest` followed by `SignCommittableMessages` | acting leader | acting leader |
| `appendEntries` | projected pair of `AppendEntries` sends | source | source |
| `receive` | projected pair of selected AppendEntries receive branches | destination and selected message | destination |
| `rejectAppendEntriesRequest?` | `RejectAppendEntriesRequest` | destination | destination |
| `appendEntriesAlreadyDone?` | `AppendEntriesAlreadyDone` | destination | destination |
| `conflictAppendEntriesRequest?` | `ConflictAppendEntriesRequest` | destination | destination |
| `noConflictAppendEntriesRequest?` | `NoConflictAppendEntriesRequest` | destination | destination |
| `handleAppendEntriesResponse?` | `HandleAppendEntriesResponse` | destination leader | destination leader |
| `advanceCommitIndex` | `AdvanceCommitIndex` | acting leader's local `matchIndex` | acting leader |

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
- `RcvDropIgnoredMessage` and other stale/ignored message branches are deferred
  to the dedicated message-loss/staleness slice; current `receive` correspondence
  is limited to request/response handlers selected above.

## Review status

Independent transition-correspondence, proof-soundness, and adversarial/vacuity
reviews were completed for slice 1. Their findings led to:

- exact one-entry/heartbeat source batching;
- source-compatible NACK match index and term fields;
- explicit weak/macro-step documentation for collapsed transaction/signature
  replication;
- complete finite simulator candidate enumeration;
- synthetic examples labelled separately from grounded trace evidence;
- runtime checks for every supporting invariant category.
