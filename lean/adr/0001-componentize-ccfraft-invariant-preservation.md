# Componentize CCFRaft invariant preservation

## Status

Proposed

## Context

The CCFRaft proof uses one inductive invariant to prove safety for every
reachable state. The signature baseline at commit `160701209` contains
runtime bounds and proof-only histories for messages, votes, elections,
acknowledgements, and commits.

The current representation packages many witnesses through nested
existentials and positional conjunctions. Each action proof unpacks the full
package and reconstructs it for the post-state.

Semantic preservation is necessary. For example, commit advancement must
create commit evidence, and leader promotion must freeze the winning ballot.
The current representation also repeats work that is not semantic:

- adding one witness changes every positional destructuring;
- adding one fact shifts every constructor branch;
- each action reproves role, term, log, commit, and network frames;
- unchanged commit facts are rebuilt inside unrelated actions.

This repetition hides the useful proof failures. A reader must separate a
tuple-shape error from a real failure to preserve the invariant.

Six representative action proofs contain 5,632 lines but mutate only seven
ghost fields in total. The remaining proof code mostly reconstructs facts
that the action does not change.

The reconfiguration work made this cost clear. Each new history field
required repairs across all action proofs, even when most actions only
preserved the field unchanged.

The development history before this refactor is preserved in Git. The
reconfiguration attempt is preserved in stash
`fa7d140835c76e1645cbac12148c206a7f68c3a7`.

## Decision

Represent proof-only data in one named `GhostState`. Group invariant facts by
their role in the proof. Make each action prove a runtime delta and a ghost
delta. Preserve each invariant component through a small component API.

### Store proof-only data in one record

Use one witness instead of many positional witnesses:

```lean
structure GhostState (TxId : Type) where
  votes : VoteHistory
  appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)
  responseHistory : AppendEntriesResponse -> List (Entry TxId)
  voteRequestHistory : RequestVoteRequest -> List (Entry TxId)
  voteCandidateHistory : RequestVoteResponse -> List (Entry TxId)
  voteVoterHistory : RequestVoteResponse -> List (Entry TxId)
  owners : TermOwners
  canonicalHistory : Nat -> List (Entry TxId)
  elections : ElectionHistory TxId
  nodeEvidence : NodeCommitEvidence TxId
  requestEvidence : RequestCommitEvidence TxId
  processedAcks : ProcessedAckHistory TxId
```

This record contains exactly the 12 witnesses in the signature baseline.
Configuration activation history belongs to the later reconfiguration
extension, not this structural refactor.

The record makes witness updates explicit:

```lean
let nextGhost :=
  { ghost with
    appendHistory := Function.update ghost.appendHistory request sourceLog }
```

Adding one witness no longer changes every positional `rcases`.

### Use named invariant components

Group facts by their causal role in the proof. The components form a
dependency graph rather than five broad buckets:

```lean
structure LocalWF (state : State TxId) : Prop where
  commitIndicesBounded : CommitIndicesBounded state
  currentTermsPositive : CurrentTermsPositive state
  entriesDoNotExceedCurrentTerm : EntriesDoNotExceedCurrentTerm state
  candidatesSelfVote : CandidatesSelfVote state
  leaderProgressBounded : LeaderProgressBounded state
  committedFrontierIsSignature : CommittedFrontierIsSignature state
  leadersHaveElectionMajority : LeadersHaveElectionMajority state

structure VoteTransport
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  requests : VoteRequestHistoryFacts ...
  responses : VoteResponseHistoryFacts ...

structure AppendTransport
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  requests : AppendRequestHistoryFacts ...
  responses : AppendResponseHistoryFacts ...

structure ReplicationAck
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  responses : ResponseHistoryFacts ...
  processed : ProcessedAckHistoryFacts ...

structure Ballot
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  votes : VoteHistoryFacts state ghost.votes
  owners : TermOwnershipFacts ...
  elections : ElectionHistoryFacts ...
  snapshots : GrantedVoteSnapshots ...

structure LogProvenance
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  canonical : CanonicalHistoryFacts ...
  ownership : LogOwnershipFacts ...

structure AckElectionBridge
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  current : AckerCurrentHistory ...
  votes : AckerVoteHistory ...
  elections : AckerElectionHistory ...

structure CommitClosure
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  existing : CommitEvidenceFacts ...
  prospective : ProspectiveCommitEvidenceFacts ...
```

The exact field allocation follows the existing predicates. Shared facts such
as term ownership may be inputs to several component preservation theorems.
The component boundary must not duplicate those facts.

The complete invariant names these components:

```lean
structure InvariantFacts
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  localWF : LocalWF state
  votes : VoteTransport state ghost
  appends : AppendTransport state ghost
  acknowledgements : ReplicationAck state ghost
  ballots : Ballot state ghost
  logs : LogProvenance state ghost
  ackElections : AckElectionBridge state ghost
  commits : CommitClosure state ghost

def SystemInductiveInvariant (state : State TxId) : Prop :=
  Exists fun ghost => InvariantFacts state ghost
```

Public safety properties remain derived results. They do not become fields of
the inductive invariant.

Before the reachable-state proof uses this representation, prove equivalence
for the same ghost witness:

```lean
theorem invariantFacts_iff
    (state : State TxId)
    (ghost : GhostState TxId) :
    LegacyInvariantFacts state ghost ↔ InvariantFacts state ghost
```

Then lift this theorem through the existential. Existential equivalence alone
is insufficient because it can choose different ghost histories on each side.

### Describe each transition once

Each action proves a named delta. The common part contains only monotone facts
shared by most transitions:

```lean
structure CommonProgress
    (before after : State TxId) : Prop where
  termMonotone : ...
  commitIndexMonotone : ...
  committedLogPrefix : ...
```

Action-specific deltas describe exact runtime changes and ghost projections:

```lean
structure AppendEntriesSendDelta
    (before after : State TxId)
    (oldGhost newGhost : GhostState TxId) : Prop where
  progress : CommonProgress before after
  request : AppendEntriesRequest TxId
  rolesEq : ...
  termsEq : ...
  logsEq : ...
  requestQueued : ...
  appendHistoryAtRequest : ...
  appendHistoryAtOther : ...
  requestEvidenceAtRequest : ...
  requestEvidenceAtOther : ...
  otherGhostProjectionsEq : ...
```

Do not require whole-record ghost equality. Ghost histories are functions, and
several updates are conditional. Each delta supplies the lookup equations its
consumers need.

Enqueue and dequeue operations also need separate capabilities. A duplicate
AppendEntries send can leave `enqueueNoDup` unchanged while updating proof
history at the same request key. The send delta must cover both the same-key
and different-key cases.

### Give each component a preservation API

Use a small namespace for each component:

```lean
namespace AppendTransport

theorem frame ...
theorem onAppendEntriesSend ...

end AppendTransport
```

An AppendEntries send proof then has this shape:

```lean
rcases invariant with ⟨ghost, facts⟩

let nextGhost := ghost.enqueueAppendEntries request sourceLog sourceEvidence
have delta := appendEntriesSendDelta ...

exact
  ⟨nextGhost,
    { localWF := LocalWF.preserve facts delta
      votes := VoteTransport.frame facts delta
      appends := AppendTransport.onAppendEntriesSend facts delta
      acknowledgements := ReplicationAck.frame facts delta
      ballots := Ballot.frame facts delta
      logs := LogProvenance.frame facts delta
      ackElections := AckElectionBridge.frame facts delta
      commits := CommitClosure.onAppendEntriesSend facts delta }⟩
```

Each component consumes the common pre-state aggregate and the action delta.
A component must not consume a sibling post-state component. That rule keeps
the dependency graph acyclic and prevents action proofs from depending on
construction order.

## Why this helps

### It separates three kinds of failure

The compiler errors become easier to classify:

- a delta construction error means the runtime transition was described
  incorrectly;
- a component frame error means the component depends on more state than its
  API declares;
- an action-specific component error means the invariant lacks a semantic
  fact or the model is unsafe.

Positional tuple errors no longer obscure these cases.

### It keeps semantic work visible

The refactor does not remove real preservation obligations:

- commit advancement still creates commit evidence;
- leader promotion still freezes a ballot;
- AppendEntries receive still proves truncation, extension, and learned
  commit facts;
- the later reconfiguration extension still proves joint quorum support and
  authority ordering.

The refactor removes repeated framing around those obligations.

### It limits repair scope

Today, adding one history field changes almost every action proof. With
component APIs, unrelated actions keep using the same projection laws.

### It makes the invariant reviewable

The top-level invariant becomes a short list of causal components. A reviewer
can answer:

- which facts constrain local state;
- which facts describe immutable messages;
- which facts identify ballots;
- which facts justify commits;
- which facts connect acknowledgements to elections and commits.

## Migration

Refactor the committed signature proof before restoring reconfiguration work.

1. Lock all eight reachable theorem names. Add deterministic final-state
   checks for the four signature traces after a clean build.
2. Add `GhostState` with exactly the baseline witnesses. Keep the legacy
   invariant definition.
3. Add the named components without changing their primitive predicates.
4. Prove fixed-ghost equivalence, then prove existential equivalence.
5. Add `CommonProgress` and action-specific delta records. Reuse current frame
   helpers and deterministic handler postconditions.
6. Convert AppendEntries send first. Its narrow mutation set tests network
   deduplication and function-update laws.
7. Convert `updateTerm`, sends, timeout, leader append, promotion, commit
   advancement, receive handlers, and the receive dispatcher. Build after
   each action family.
8. Switch reachable induction only after all actions use component APIs.
9. Remove the legacy representation.
10. Port the stashed reconfiguration work in a separate worktree. Add
    configuration authority and activation history through the new APIs.

## Acceptance criteria

- `Action`, `Enabled`, and `next` are unchanged by the refactor.
- The canonical `CCFRaft` target builds without `sorry`.
- All eight public reachable safety theorem names remain stable.
- The signature commit, arbitrary terms, delayed ACK, and follower overcommit
  traces replay with pinned final-state projections.
- `LegacyInvariantFacts state ghost ↔ InvariantFacts state ghost` holds for
  every state and fixed ghost witness during migration.
- Each action theorem proves one delta and calls component preservation
  functions.
- Adding a field to one component does not require positional repairs in
  unrelated action proofs.

## Consequences

The proof gains more named records and preservation theorems. This is
intentional. The names expose dependencies that positional conjunctions hide.

The migration has an upfront cost. During migration, the old and new invariant
representations coexist. The equivalence theorem keeps that period
reviewable.

This design does not solve reconfiguration safety by itself. The later
extension adds a `ConfigurationAuthority` component and parameterizes
quorum-sensitive components over configuration context. That work remains
separate from the signature-baseline refactor.

## Alternatives considered

### Keep the positional invariant and add more frame helpers

This reduces some repetition but preserves tuple-shape repair across every
action. It does not give the invariant a readable top-level structure.

### Add one universal frame theorem

A universal frame must encode every log, term, network, vote, and commit case.
It either rejects valid actions through false equalities or accumulates
conditionals until it becomes another monolithic invariant. Use a small common
progress record and action-specific capabilities instead.

### Store safety conclusions in the invariant

This can shorten individual proofs but makes the invariant harder to explain
and preserve. Continue to store causal evidence and derive public safety
properties.
