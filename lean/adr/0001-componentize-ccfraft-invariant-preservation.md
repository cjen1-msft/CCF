# Componentize CCFRaft invariant preservation

## Status

Proposed

## Context

The CCFRaft proof uses one inductive invariant to prove safety for every
reachable state. The invariant contains runtime bounds and proof-only
histories for messages, votes, elections, acknowledgements, commits, and
configuration activations.

The current representation packages many witnesses through nested
existentials and positional conjunctions. Each action proof unpacks the full
package and reconstructs it for the post-state.

Semantic preservation is necessary. For example, commit advancement must
create commit evidence, and leader promotion must freeze the winning ballot.
The current representation also repeats work that is not semantic:

- adding one witness changes every positional destructuring;
- adding one fact shifts every constructor branch;
- each action reproves role, term, log, commit, and network frames;
- unchanged activation or commit facts are rebuilt inside unrelated actions.

This repetition hides the useful proof failures. A reader must separate a
tuple-shape error from a real failure to preserve the invariant.

The reconfiguration work made this cost clear. The proof grew activation
history, activation canonicality, election closure, and supporter chronology
one field at a time. Every field required repairs across all action proofs,
even when most actions only framed the field unchanged.

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
  activations : ActivationHistory TxId
  nodeEvidence : NodeCommitEvidence TxId
  requestEvidence : RequestCommitEvidence TxId
  processedAcks : ProcessedAckHistory TxId
```

The record makes witness updates explicit:

```lean
let nextGhost :=
  { ghost with
    appendHistory := Function.update ghost.appendHistory request sourceLog }
```

Adding one witness no longer changes every positional `rcases`.

### Use named invariant components

Group facts by the protocol state that they explain:

```lean
structure LocalInvariant (state : State TxId) : Prop where
  commitIndicesBounded : CommitIndicesBounded state
  currentTermsPositive : CurrentTermsPositive state
  entriesDoNotExceedCurrentTerm : EntriesDoNotExceedCurrentTerm state
  candidatesSelfVote : CandidatesSelfVote state
  leaderProgressBounded : LeaderProgressBounded state

structure NetworkInvariant
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  messages : NetworkHistoryFacts ...

structure BallotInvariant
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  voteHistory : VoteHistoryFacts state ghost.votes
  ownership : TermOwnershipFacts ...
  elections : ElectionHistoryFacts ...
  snapshots : GrantedVoteSnapshots ...

structure CommitInvariant
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  evidence : CommitEvidenceFacts ...
  prospective : ProspectiveCommitEvidenceFacts ...
  processedAcks : ProcessedAckHistoryFacts ...

structure ReconfigurationInvariant
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  activations : ActivationHistoryFacts ...
  canonical : ActivationCanonicalFacts ...
  elections : ActivationElectionFacts ...
  supporterProgress : ActivationSupporterProgress ...
```

The complete invariant names these components:

```lean
structure InvariantFacts
    (state : State TxId)
    (ghost : GhostState TxId) : Prop where
  local : LocalInvariant state
  network : NetworkInvariant state ghost
  ballots : BallotInvariant state ghost
  commits : CommitInvariant state ghost
  reconfiguration : ReconfigurationInvariant state ghost

def SystemInductiveInvariant (state : State TxId) : Prop :=
  Exists fun ghost => InvariantFacts state ghost
```

Public safety properties remain derived results. They do not become fields of
the inductive invariant.

### Describe each transition once

Each action proves a named delta. A common frame records facts used by several
components:

```lean
structure StateFrame
    (before after : State TxId) : Prop where
  roleEq : ...
  termMonotone : ...
  commitEq : ...
  logEq : ...
  networkEq : ...
```

Action-specific deltas add the facts that the common frame cannot express:

```lean
structure AppendEntriesSendDelta
    (before after : State TxId)
    (oldGhost newGhost : GhostState TxId) : Prop where
  frame : StateFrame before after
  request : AppendEntriesRequest TxId
  requestQueued : ...
  historyStored : ...
  evidenceStored : ...
```

The action theorem proves the delta once. Invariant components consume the
same proof instead of independently proving that only `sentIndex` and the
network changed.

### Give each component a preservation API

Use a small namespace for each component:

```lean
namespace ReconfigurationInvariant

theorem frame ...
theorem onAppendEntriesSend ...
theorem onElection ...
theorem onActivation ...

end ReconfigurationInvariant
```

An AppendEntries send proof then has this shape:

```lean
rcases invariant with ⟨ghost, facts⟩

let nextGhost := ghost.enqueueAppendEntries request sourceLog sourceEvidence
have delta := appendEntriesSendDelta ...

exact
  ⟨nextGhost,
    { local := LocalInvariant.frame facts.local delta.frame
      network := NetworkInvariant.onAppendEntriesSend facts.network delta
      ballots := BallotInvariant.frame facts.ballots delta.frame
      commits := CommitInvariant.onAppendEntriesSend facts.commits delta
      reconfiguration :=
        ReconfigurationInvariant.onAppendEntriesSend
          facts.reconfiguration delta }⟩
```

If `ReconfigurationInvariant` gains one primitive fact, update its
preservation functions. Do not repair every outer action theorem.

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

- commit advancement still creates commit and activation evidence;
- leader promotion still freezes a ballot;
- AppendEntries receive still proves truncation, extension, and learned
  commit facts;
- reconfiguration still proves joint quorum support and authority ordering.

The refactor removes repeated framing around those obligations.

### It limits repair scope

Today, adding one activation field changes almost every action proof. With
component APIs, most actions keep calling `ReconfigurationInvariant.frame`.
Only actions that change activation evidence need a new proof.

### It makes the invariant reviewable

The top-level invariant becomes a short list of causal components. A reviewer
can answer:

- which facts constrain local state;
- which facts describe immutable messages;
- which facts identify ballots;
- which facts justify commits;
- which facts order configuration activations.

## Migration

Refactor the committed signature proof before restoring reconfiguration work.

1. Add `GhostState` and named component records.
2. Express the existing invariant through the new records without changing
   `Action`, `Enabled`, or `next`.
3. Prove equivalence between the old and new invariant representations.
4. Move existing frame helpers into component namespaces.
5. Convert one action family at a time.
6. Keep the canonical reachable safety theorems and four signature traces
   green after every step.
7. Remove the old invariant representation after every action uses the new
   component APIs.
8. Port the stashed reconfiguration work into the new architecture. Use the
   stash as a reference rather than applying it directly to the refactored
   files.

## Acceptance criteria

- `Action`, `Enabled`, and `next` are unchanged by the refactor.
- The canonical `CCFRaft` target builds without `sorry`.
- The public reachable safety theorem names remain stable.
- The signature commit, arbitrary terms, delayed ACK, and follower overcommit
  traces still replay with their expected final states.
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

This design does not solve reconfiguration safety by itself. It gives the
remaining causal activation proof a stable place to live and keeps future
repairs inside that component.

## Alternatives considered

### Keep the positional invariant and add more frame helpers

This reduces some repetition but preserves tuple-shape repair across every
action. It does not give the invariant a readable top-level structure.

### Add one universal frame theorem

A universal frame must encode every log, term, network, vote, commit, and
activation case. It becomes another monolithic invariant and hides
action-specific semantics.

### Store safety conclusions in the invariant

This can shorten individual proofs but makes the invariant harder to explain
and preserve. Continue to store causal evidence and derive public safety
properties.

