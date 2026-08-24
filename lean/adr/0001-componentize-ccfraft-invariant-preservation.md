# Componentize CCFRaft invariant preservation

## Status

Superseded

The reconfiguration proof now owns the public invariant. Commit history retains
the fixed-membership implementation described below, but the current tree
removes that implementation and its component/delta API. See
`lean/CCFRaft/INVARIANT.md` for the current invariant.

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
their role in the proof. Make the named component invariant canonical for
reachable induction and public safety theorems.

Keep the existing fixed-membership preservation proof as one checked base
implementation. Isolate that implementation in
`FixedMembershipPreservation.lean`. The public `Proofs.lean` module converts
through the fixed-witness equivalence and exposes only the component invariant.

New components, including configuration authority, preserve themselves
alongside this base. They consume action deltas that expose the runtime and
ghost projections they need. Do not rewrite a fixed-membership action proof
unless the fixed-membership component itself changes.

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
structure ComponentInvariantFacts
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

def ComponentSystemInductiveInvariant (state : State TxId) : Prop :=
  Exists fun ghost => ComponentInvariantFacts state ghost

structure SystemInductiveInvariant (state : State TxId) : Prop where
  fixedMembership : ComponentSystemInductiveInvariant state
```

Public safety properties remain derived results. They do not become fields of
the inductive invariant. Each later protocol component gets its own witness.
The fixed-membership proof does not choose or constrain that witness.

Before the reachable-state proof uses this representation, prove equivalence
for the same ghost witness:

```lean
theorem invariantFacts_iff
    (state : State TxId)
    (ghost : GhostState TxId) :
    FixedMembershipInvariantFacts state ghost ↔
      ComponentInvariantFacts state ghost
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

Action-specific deltas describe exact runtime changes:

```lean
structure AppendEntriesSendDelta
  (before after : State TxId)
  progress : CommonProgress before after
  request : AppendEntriesRequest TxId
  rolesEq : ...
  termsEq : ...
  logsEq : ...
  requestQueued : ...
```

A component records its own ghost update separately. Do not require
whole-record ghost equality. Ghost histories are functions, and several
updates are conditional. `AppendEntriesSendGhostDelta` supplies same-key,
different-key, and unchanged-projection equations for the fixed-membership
ghost.

Enqueue and dequeue operations also need separate capabilities. A duplicate
AppendEntries send can leave `enqueueNoDup` unchanged while updating proof
history at the same request key. The send delta must cover both the same-key
and different-key cases.

### Add preservation APIs for new components

The fixed-membership proof remains one independently witnessed base
preservation API. A new component uses the same runtime delta and its own ghost
delta, then proves only its own post-state facts:

```lean
rcases invariant with ⟨ghost, facts⟩
have baseAfter :=
  liftFixedMembershipPreservation fixedMembershipAction facts.base
have configurationAfter :=
  ConfigurationAuthority.onAppendEntriesSend facts.configuration delta
exact
  { base := baseAfter
    configuration := configurationAfter }
```

Each new component consumes the common pre-state aggregate and the action
delta. A component must not consume a sibling post-state component. That rule
keeps the dependency graph acyclic and prevents action proofs from depending
on construction order.

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

Adding a configuration witness does not change the fixed-membership proof.
Configuration actions and existing actions preserve configuration authority
through its own API. A change to the fixed-membership component can still
require changes inside `FixedMembershipPreservation.lean`.

### It makes the invariant reviewable

The top-level invariant becomes a short list of causal components. A reviewer
can answer:

- which facts constrain local state;
- which facts describe immutable messages;
- which facts identify ballots;
- which facts justify commits;
- which facts connect acknowledgements to elections and commits.

## Migration

The signature-baseline refactor is complete:

1. `check_ccfraft_signature_refactor.sh` locks `Model.lean`, all eight
   reachable theorem names, proof placeholders, and four trace projections.
2. `GhostState` contains exactly the 12 signature-baseline witnesses.
3. `Properties.lean` defines the named components and canonical system
   invariant.
4. `FixedMembershipPreservation.lean` contains the positional base proof and
   both fixed-witness and existential equivalence theorems.
5. `Proofs.lean` exposes component preservation and reachable safety.
6. `AppendEntriesSendDelta` records projection and lookup laws for future
   components.

Port reconfiguration in a separate worktree. Keep fixed-membership
preservation unchanged. Add configuration authority, activation history, and
their preservation APIs alongside the base.

## Acceptance criteria

- `Action`, `Enabled`, and `next` are unchanged by the refactor.
- The canonical `CCFRaft` target builds without `sorry`.
- All eight public reachable safety theorem names remain stable.
- The signature commit, arbitrary terms, delayed ACK, and follower overcommit
  traces replay with pinned final-state projections.
- `FixedMembershipInvariantFacts state ghost ↔
ComponentInvariantFacts state ghost` holds for every state and fixed ghost
  witness.
- `Properties.lean` contains no positional invariant.
- `Proofs.lean` does not destructure positional witnesses.
- New components can preserve themselves without modifying the
  fixed-membership action proofs or sharing their ghost witness.

## Consequences

The proof gains named records and one isolated compatibility boundary. The
names expose dependencies that positional conjunctions hide. The compatibility
boundary avoids rewriting thousands of checked proof lines solely to change
their packaging.

Changes to the fixed-membership facts still affect the isolated positional
proof. New protocol layers do not. They add components alongside the base and
use action deltas for their own preservation.

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

### Rewrite every fixed-membership action proof

The AppendEntries prototype showed that a complete rewrite would replace
thousands of checked lines without reducing the work required for the new
configuration-authority component. Isolating the fixed-membership proof behind
fixed-witness equivalence gives the new component a stable boundary with less
proof churn.

### Store safety conclusions in the invariant

This can shorten individual proofs but makes the invariant harder to explain
and preserve. Continue to store causal evidence and derive public safety
properties.
