module

import CCF.Proofs.Function

public import Consensus.Model
import Consensus.Proofs.VoteFacts
import Consensus.Proofs.LogFacts

import all Init.Control.State

public import Consensus.Model.Node
public import CCF.Proofs.Execution
public import CCF.Proofs.Finset
import Relevance.Split

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node

/-- The initial membership passed to the model, possibly empty. -/
private class InitialConfiguration where
  configuration : Finset NodeID

end Consensus.Proofs.Config

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node
section Initial
variable [config : InitialConfiguration]

private abbrev INITIAL_CONFIGURATION : Finset NodeID := config.configuration

/-- The smallest initial member, which the model makes the bootstrap primary.
Meaningful only for a nonempty initial membership. -/
private abbrev INITIAL_PRIMARY : NodeID := INITIAL_CONFIGURATION.min?.getD 0

/-- The unsigned bootstrap configuration transaction of the initial primary. -/
private abbrev GENESIS : Entry :=
  {
    term := Model.BOOTSTRAP_TERM
    content := .transaction 0 { configuration := some INITIAL_CONFIGURATION }
  }

end Initial
end Consensus.Proofs.Config

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node

/-- Collect the reconfiguration entries of a log with their one-based indices. -/
private def configurationsInLogFrom : Nat -> List Entry -> List Configuration
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      (entry.content.metadata.configuration.map fun nodes => { index, nodes }).toList
      ++ remaining

/-- The current configuration and every later configuration in the node's log. -/
private def activeConfigurationsOf (state : NodeState) : List Configuration :=
  Model.Node.activeConfigurations state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
private def activeNodeUnion (state : NodeState) : Finset NodeID :=
  (activeConfigurationsOf state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

end Consensus.Proofs.Config

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

/-- Replace the state of `node` in a node table. -/
private def replaceNode (nodes : List (NodeID × NodeState)) (node : NodeID)
    (value : NodeState)
    : List (NodeID × NodeState) :=
  nodes.map fun entry => if entry.1 == node then (node, value) else entry

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}

/-- Every successful run of `m` returns a value satisfying `P`. -/
private def Keeps {α : Type} (P : α -> Prop) (m : Effect Node Message Notification α)
    : Prop :=
  forall outputs result after, m.run outputs = some (result, after) -> P result

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}

/-- Every successful run of `m` appends `new` to the outgoing envelopes and
returns `result` with `P result new`. -/
private def Sends {α : Type} (P : α -> List (Envelope Node Message) -> Prop)
    (m : Effect Node Message Notification α)
    : Prop :=
  forall outputs result after,
    m.run outputs = some (result, after)
    -> exists new, after.outgoing = outputs.outgoing ++ new /\ P result new

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete Direct
open Model.Node
variable [Config.InitialConfiguration]

/-- One node step: the actor's local step, other nodes unchanged, the network
losing at most the delivered envelope and gaining the actor's sends. -/
private structure LocalTransition (before after : Model.State) where
  actor : NodeID
  pre : NodeState
  post : NodeState
  event : Event
  outputs : Outputs NodeID (Message) Notification
  pending : List Model.Envelope
  found : nodeState before actor = some pre
  ran
    : (Model.Node.step (Capabilities.record actor) actor pre event).run {}
      = some (post, outputs)
  nodesEq : after.nodes = replaceNode before.nodes actor post
  networkEq : after.network = pending ++ outputs.outgoing
  pendingSub : forall envelope, envelope ∈ pending -> envelope ∈ before.network
  source
    : (exists input, event = .internal input /\ pending = before.network)
      \/ (exists envelope,
            envelope ∈ before.network
            /\ envelope.target = actor
            /\ event = .receive envelope.source envelope.payload
            /\ pending = removeOne envelope before.network)
  available
    : forall entries,
        event = .internal (.initAsBackup entries)
        -> Model.committedPrefixOf before entries = true

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Model.Node

/-- The one-based index of the first overlapping entry whose term conflicts. -/
private def conflictIndex (log : List Entry) (request : AppendEntriesRequest)
    : Option Nat :=
  ((((log.drop request.prevLogIndex).zip request.entries).zipIdx
      (request.prevLogIndex + 1)).find?
    fun ((existing, incoming), _) => existing.term != incoming.term).map
    Prod.snd

/-- The follower log after accepting `request` on `log`. -/
private def acceptLog (log : List Entry) (request : AppendEntriesRequest) : List Entry :=
  let kept :=
    match conflictIndex log request with
    | some index => log.take (index - 1)
    | none => log
  kept ++ request.entries.drop (kept.length - request.prevLogIndex)

/-- A nonempty log starts with `root`. -/
private def Rooted (root : Entry) (log : List Entry) : Prop :=
  log ≠ [] -> log.take 1 = [root]

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Ledger
end Consensus.Proofs.Ledger

namespace Consensus.Proofs.Direct.Keeps
end Consensus.Proofs.Direct.Keeps

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node

/-- The commit index lies within the log and, when positive, is a signature. -/
private def CommitFrontier (state : NodeState) : Prop :=
  state.commitIndex <= state.log.length
  /\ (0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

/-- `after` commits no less than `before` and its log extends the committed log
of `before`. No relation between `before`'s commit index and log is assumed. -/
private def Extends (before after : NodeState) : Prop :=
  before.commitIndex <= after.commitIndex /\ before.committedLog <+: after.log

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Safety.Sends
end Consensus.Proofs.Safety.Sends

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

/-- An AppendEntries request consistent with its sender's resulting state. -/
private def AEOk (self target : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : Prop :=
  Not (target = self)
  /\ request.term = state.currentTerm
  /\ request.prevLogIndex <= state.log.length
  /\ request.prevLogTerm = termAt state.log request.prevLogIndex
  /\ request.entries <+: state.log.drop request.prevLogIndex
  /\ request.primaryCommit <= state.commitIndex

/-- The state change of `advanceCommit`: the commit index does not move back, and
if it moves it reaches the highest committable index. Committing a retirement
may clear the role. -/
private def Advance (self : NodeID) (middle state : NodeState) : Prop :=
  state.log = middle.log
  /\ state.currentTerm = middle.currentTerm
  /\ state.votedFor = middle.votedFor
  /\ state.matchIndex = middle.matchIndex
  /\ state.sentIndex = middle.sentIndex
  /\ state.votesGranted = middle.votesGranted
  /\ (state.role = middle.role \/ state.role = .none)
  /\ middle.commitIndex <= state.commitIndex
  /\ (middle.commitIndex < state.commitIndex
      -> state.commitIndex = highestCommittableIndex middle self)

/-- Messages whose receipt may raise the receiver's term. -/
private def Bumping : Message -> Prop
  | .appendEntriesResponse _ => False
  | .proposeRequestVoteRequest _ => False
  | _ => True

/-- A node taking part in elections: it has a role and is not a joined node
still waiting, in term zero with an empty log, for its first consensus message. -/
private def Engaged (state : NodeState) : Prop :=
  Not (state.role = .none)
  /\ Not (state.role = .follower /\ state.currentTerm = 0 /\ state.log = [])

/-- The candidate state a step campaigns with: a fresh election or the
existing candidacy with possibly more votes. -/
private def Campaign (self : NodeID) (before : NodeState) (event : Event)
    (candidate : NodeState)
    : Prop :=
  candidate.role = .candidate
  /\ candidate.log = before.log
  /\ candidate.commitIndex = before.commitIndex
  /\ ((Engaged before
        /\ candidate.currentTerm = before.currentTerm + 1
        /\ candidate.votedFor = some self
        /\ candidate.votesGranted = {self})
      \/ (before.role = .candidate
          /\ candidate.currentTerm = before.currentTerm
          /\ (before.votedFor = none \/ before.votedFor = candidate.votedFor)
          /\ forall voter,
              voter ∈ candidate.votesGranted
              -> Not (voter ∈ before.votesGranted)
              -> exists response,
                  event = .receive voter (.requestVoteResponse response)
                  /\ response.term = before.currentTerm
                  /\ response.voteGranted = true))

/-- The events on which a node can win an election: an election timeout, a vote, a
pre-vote that starts a won campaign, or a proposal to campaign. -/
private def Electing : Event -> Prop
  | .internal (.timeout .election) => True
  | .receive _ (.requestVoteResponse _) => True
  | .receive _ (.requestPreVoteResponse _) => True
  | .receive _ (.proposeRequestVoteRequest _) => True
  | _ => False

/-- The step wins an election with `candidate`. -/
private def Wins (self : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    : Prop :=
  exists candidate,
    Campaign self before event candidate
    /\ hasQuorum (candidate.activeConfigurations) candidate.votesGranted
    /\ Advance self (primaryState candidate) after
    /\ Electing event

/-- The follower accepted AppendEntries `request`. -/
private def Accepted (before : NodeState) (request : AppendEntriesRequest)
    (after : NodeState)
    : Prop :=
  request.term = after.currentTerm
  /\ before.currentTerm <= request.term
  /\ before.commitIndex <= request.prevLogIndex
  /\ request.prevLogIndex <= before.log.length
  /\ termAt before.log request.prevLogIndex = request.prevLogTerm
  /\ after.log = acceptLog before.log request
  /\ after.commitIndex
      = max before.commitIndex
          (maxCommittableIndexUpTo after.log
            (min request.primaryCommit (request.prevLogIndex + request.entries.length)))

/-- How a step changes the log and commit index. -/
private inductive Kind (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState)
    : Prop where
  | same (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
  | append (entries : List Entry) (sent : NodeID -> Nat)
    (leader : before.role = .primary)
    (terms : forall entry, entry ∈ entries -> entry.term = before.currentTerm)
    (advance
      : Advance self { before with log := before.log ++ entries, sentIndex := sent }
          after)
  | ack (source : NodeID) (response : AppendEntriesResponse)
    (received : event = .receive source (.appendEntriesResponse response))
    (leader : before.role = .primary) (success : response.success = true)
    (term : response.term = before.currentTerm)
    (advance
      : Advance self
          {
            before with
              matchIndex :=
                Function.update before.matchIndex source
                  (max (before.matchIndex source) response.lastLogIndex)
          }
          after)
  | accept (source : NodeID) (request : AppendEntriesRequest)
    (received : event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted before request after)
  | elect (elected : Wins self before event after)
  | install (entries : List Entry)
    (initialized : event = .internal (.initAsBackup entries))
    (signed : 0 < entries.length -> isSignatureAt entries entries.length = true)
    (fresh : before.isFresh) (log : after.log = entries)
    (commit : after.commitIndex = entries.length)
    (term : after.currentTerm = termAt entries entries.length)
    (role : after.role = .follower)

/-- What a step may send, relative to its sender's states. -/
private def SendOK (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState) (envelope : Model.Envelope)
    : Prop :=
  envelope.source = self
  /\ match envelope.payload with
      | .appendEntriesRequest request =>
          AEOk self envelope.target after request
          /\ Not (after.role = .candidate)
          /\ ((before.role = .primary /\ after.currentTerm = before.currentTerm)
              \/ Wins self before event after)
      | .appendEntriesResponse response =>
          response.success = true
          -> exists source request,
              event = .receive source (.appendEntriesRequest request)
              /\ Accepted before request after
              /\ response.term = after.currentTerm
              /\ response.lastLogIndex = request.prevLogIndex + request.entries.length
      | .requestVoteRequest request =>
          request.term = after.currentTerm
          /\ before.currentTerm < after.currentTerm
          /\ (after.role = .candidate -> makeRequestVoteRequest after = request)
      | .requestVoteResponse response =>
          response.term = after.currentTerm
          /\ (response.voteGranted = true
              -> exists request,
                  event = .receive envelope.target (.requestVoteRequest request)
                  /\ request.term = after.currentTerm
                  /\ voteLogUpToDate before request
                  /\ after.votedFor = some envelope.target)
      | message => message.term = after.currentTerm

/-- Why a node that takes part in elections after a step, or sends a term-bumping
message in it, has a term of at least two: it took part before, already had such a
term, received a term-bumping message, or installed a signed snapshot. -/
private def Activated (before : NodeState) (event : Event) (after : NodeState) : Prop :=
  Engaged before
  \/ 2 <= before.currentTerm
  \/ (exists source message,
        event = .receive source message
        /\ Bumping message
        /\ message.term <= after.currentTerm)
  \/ exists entries,
      event = .internal (.initAsBackup entries)
      /\ 0 < entries.length
      /\ isSignatureAt entries entries.length = true
      /\ after.currentTerm = termAt entries entries.length

/-- Everything the safety proof needs to know about one local step. -/
private structure Summary (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState) (sent : List Model.Envelope)
    : Prop where
  term_le : before.currentTerm <= after.currentTerm
  vote_keep
    : after.currentTerm = before.currentTerm
      -> forall voted, before.votedFor = some voted -> after.votedFor = some voted
  active : Engaged after -> Activated before event after
  bumps
    : (exists envelope, envelope ∈ sent /\ Bumping envelope.payload)
      -> Activated before event after
  candidate : after.role = .candidate -> Campaign self before event after
  leader
    : after.role = .primary
      -> (before.role = .primary /\ after.currentTerm = before.currentTerm)
          \/ Wins self before event after
  matchIndex
    : after.role = .primary -> before.role = .primary
      -> after.currentTerm = before.currentTerm
      -> after.matchIndex = before.matchIndex
          \/ exists source response,
              event = .receive source (.appendEntriesResponse response)
              /\ response.success = true
              /\ response.term = before.currentTerm
              /\ after.matchIndex
                  = Function.update before.matchIndex source
                      (max (before.matchIndex source) response.lastLogIndex)
  kind : Kind self before event after
  sends : forall envelope, envelope ∈ sent -> SendOK self before event after envelope

/-- An AppendEntries request from `self` consistent with `log` and `commit`. -/
private def AEFrom (self : NodeID) (term commit : Nat) (log : List Entry)
    (envelope : Model.Envelope)
    : Prop :=
  envelope.source = self
  /\ Not (envelope.target = self)
  /\ exists request,
      envelope.payload = .appendEntriesRequest request
      /\ request.term = term
      /\ request.prevLogIndex <= log.length
      /\ request.prevLogTerm = termAt log request.prevLogIndex
      /\ request.entries <+: log.drop request.prevLogIndex
      /\ request.primaryCommit <= commit

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node
section Effects
variable (self : NodeID)

/-- The sends of a new leader: nominations, then heartbeats. -/
private def LeaderStart (self : NodeID) (term : Nat) (state : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  exists nominated beats,
    sent = nominated ++ beats
    /\ (forall e,
          e ∈ nominated
          -> e.source = self /\ e.payload = .proposeRequestVoteRequest term)
    /\ forall e, e ∈ beats -> AEFrom self state.currentTerm state.commitIndex state.log e

/-- The candidate state `becomeCandidate` builds from `state`. -/
private def freshCandidate (self : NodeID) (state : NodeState) : NodeState :=
  {
    state with
      role := .candidate
      currentTerm := state.currentTerm + 1
      votedFor := some self
      primaryKnown := false
      votesGranted := {self}
      preVotesGranted := ∅
  }

end Effects
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

/-- Whether the campaign of `candidate` won: the candidate is unchanged and sends
nothing, or it has a quorum and starts as leader. -/
private def Outcome (self : NodeID) (candidate after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  (after = candidate /\ sent = [])
  \/ (hasQuorum (candidate.activeConfigurations) candidate.votesGranted
      /\ Advance self (primaryState candidate) after
      /\ LeaderStart self candidate.currentTerm after sent)

/-- What a campaigning step becomes and sends: the sends of its outcome, then the
vote requests of a fresh candidate. -/
private def CampaignResult (self : NodeID) (before candidate after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  exists started requests,
    sent = started ++ requests
    /\ (forall e,
          e ∈ requests
          -> e.source = self
              /\ e.payload = .requestVoteRequest (makeRequestVoteRequest candidate)
              /\ before.currentTerm < candidate.currentTerm)
    /\ Outcome self candidate after started

/-- What a campaign gives about the state it started from, whichever way it started. -/
private def CampaignStart (before candidate : NodeState) : Prop :=
  before.currentTerm <= candidate.currentTerm
  /\ Engaged before
  /\ Not (before.role = .primary /\ candidate.currentTerm = before.currentTerm)
  /\ (candidate.currentTerm = before.currentTerm
      -> forall voted, before.votedFor = some voted -> candidate.votedFor = some voted)

/-- The state after adopting a newer term. -/
private def bumpedState (state : NodeState) (term : Nat) : NodeState :=
  {
    state with
      role := .follower,
      currentTerm := term,
      votedFor := none,
      primaryKnown := false,
      isNewFollower := true,
      votesGranted := ∅,
      preVotesGranted := ∅
  }

/-- What the AppendEntries request handler does: its effect on the observed state
`state`, and its log change and sends relative to the state `before` the step. -/
private def AEReply (self source : NodeID) (before state : NodeState)
    (request : AppendEntriesRequest) (after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  after.currentTerm = state.currentTerm
  /\ after.votedFor = state.votedFor
  /\ after.matchIndex = state.matchIndex
  /\ (after.role = .primary -> state.role = .primary)
  /\ (after.role = .candidate -> after = state)
  /\ Kind self before (.receive source (.appendEntriesRequest request)) after
  /\ forall e,
      e ∈ sent
      -> SendOK self before (.receive source (.appendEntriesRequest request)) after e

/-- A partially appended batch: new entries at the leader's term, and
packets consistent with the current log. -/
private def BatchState (self : NodeID) (before state : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  (exists entries sentIndex,
    state = { before with log := before.log ++ entries, sentIndex := sentIndex }
    /\ forall entry, entry ∈ entries -> entry.term = before.currentTerm)
  /\ forall e, e ∈ sent -> AEFrom self before.currentTerm before.commitIndex state.log e

end Consensus.Proofs.Safety

/-! The proofs about the two ghost modules are here, not beside their definitions. The
coverage generator reads proof bodies only from this module and `Direct.lean`; a case split
in a proof it cannot read is neither counted nor audited. -/

namespace Consensus.Proofs.VoteFacts

open Model.Node

private theorem mem_advance {g : Ghost} {s : Model.State} {b : Stamp} :
    b ∈ advance g s ↔ (∃ n st, (n, st) ∈ s.nodes ∧ stamp n st = b) ∨ b ∈ g := by
  simp [advance, List.mem_map, Prod.exists]

private structure Inv (s : Model.State) (g : Ghost) : Prop where
  bounds : ∀ b ∈ g, ∀ st, (b.voter, st) ∈ s.nodes → b.term ≤ st.currentTerm
  keeps : ∀ b ∈ g, ∀ st, (b.voter, st) ∈ s.nodes → b.term = st.currentTerm →
    ∀ c, b.vote = some c → st.votedFor = some c
  unique : ∀ n k a b, ⟨n, k, some a⟩ ∈ g → ⟨n, k, some b⟩ ∈ g → a = b

/-- The two premises about node states are discharged by the original CCF transition proof. -/
private theorem preserve {s t : Model.State} {g : Ghost} (prior : Inv s g)
    (uniqueNow : ∀ n a b, (n, a) ∈ t.nodes → (n, b) ∈ t.nodes → a = b)
    (localStep : ∀ n b, (n, b) ∈ t.nodes →
      ∃ a, (n, a) ∈ s.nodes ∧ a.currentTerm ≤ b.currentTerm ∧
        (a.currentTerm = b.currentTerm → ∀ c, a.votedFor = some c → b.votedFor = some c)) :
    Inv t (advance g t) := by
  have current {b : Stamp} (observed : b ∈ advance g t) {st : NodeState}
      (now : (b.voter, st) ∈ t.nodes) :
      b.term ≤ st.currentTerm ∧ (b.term = st.currentTerm → ∀ c, b.vote = some c → st.votedFor = some c) := by
    split_rel observed := (rcases mem_advance.1 observed with ⟨n, x, mem, rfl⟩ | old) with
    | inl =>
      obtain rfl := uniqueNow _ _ _ mem now
      exact ⟨Nat.le_refl _, fun _ _ h => h⟩
    | inr =>
      obtain ⟨a, pre, le, keep⟩ := localStep _ _ now
      have bound := prior.bounds b old a pre
      refine ⟨Nat.le_trans bound le, fun eq c v => ?_⟩
      have termEq := Nat.le_antisymm le (eq ▸ bound)
      exact keep termEq c (prior.keeps b old a pre (eq.trans termEq.symm) c v)
  refine ⟨fun _ h _ mem => (current h mem).1, fun _ h _ mem => (current h mem).2, ?_⟩
  intro n k a b left right
  -- A voter now in term `k` has one current vote, which both stamps name. Otherwise
  -- neither stamp is of its current state, so both are old.
  split_rel voting := (by_cases voting : ∃ st, (n, st) ∈ t.nodes ∧ st.currentTerm = k) with
  | pos =>
    obtain ⟨st, mem, term⟩ := voting
    have first := (current left mem).2 term.symm a rfl
    have second := (current right mem).2 term.symm b rfl
    exact Option.some.inj (first.symm.trans second)
  | neg =>
    have old {x : NodeID} (stamp : ⟨n, k, some x⟩ ∈ advance g t) : ⟨n, k, some x⟩ ∈ g := by
      split_rel stamp := (rcases mem_advance.1 stamp with ⟨n', st, mem, eq⟩ | old) with
      | inl =>
        obtain rfl : n' = n := congrArg Stamp.voter eq
        exact absurd ⟨st, mem, congrArg Stamp.term eq⟩ voting
      | inr => exact old
    exact prior.unique n k a b (old left) (old right)

private theorem initial (s : Model.State)
    (uniqueNow : ∀ n a b, (n, a) ∈ s.nodes → (n, b) ∈ s.nodes → a = b) :
    Inv s (advance [] s) :=
  preserve (s := s) ⟨by simp, by simp, by simp⟩ uniqueNow
    (fun _ st h => ⟨st, h, Nat.le_refl _, fun _ _ v => v⟩)

end Consensus.Proofs.VoteFacts

namespace Consensus.Proofs.LogFacts

private theorem chain_step {bootstrap g prev s} (old : Chain g)
    (grows : ∀ n st k, (advance bootstrap g prev s).canonNow bootstrap s n st k →
      ∀ l, (advance bootstrap g prev s).canon k l → l <+: st.log) :
    Chain (advance bootstrap g prev s) := by
  intro k a b ca cb m ma mb
  -- A leader log recorded by this state extends every leader log of its term.
  have extended {α : Type} {x y : List α} (sub : x <+: y) (mx : m ≤ x.length) :
      x.take m = y.take m := by
    obtain ⟨rest, rfl⟩ := sub
    rw [List.take_append_of_le_length mx]
  split_rel right := (rcases cb with past | ⟨n, st, now, rfl⟩) with
  | inl =>
    split_rel left := (rcases ca with past' | ⟨n, st, now, rfl⟩) with
    | inl => exact old k a b past' past m ma mb
    | inr => exact (extended (grows n st k now b (.inl past)) mb).symm
  | inr => exact extended (grows n st k now a ca) ma

end Consensus.Proofs.LogFacts

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]

/-- The protocol state and the facts that survive its transitions. -/
private structure Frame where
  current : Model.State
  logs : LogFacts.Ghost
  votes : VoteFacts.Ghost

private def Frame.start (s : Model.State) : Frame :=
  ⟨s, LogFacts.advance INITIAL_PRIMARY LogFacts.empty none s, VoteFacts.advance [] s⟩

private def Frame.advance (f : Frame) (s : Model.State) : Frame :=
  ⟨s, LogFacts.advance INITIAL_PRIMARY f.logs (some f.current) s, VoteFacts.advance f.votes s⟩

private def Now (f : Frame) (n : NodeID) (st : NodeState) := (n, st) ∈ f.current.nodes
private def Pending (f : Frame) (e : Model.Envelope) := e ∈ f.current.network

private structure Observation where
  currentTerm : Nat
  log : List Entry

private def observe (st : NodeState) : Observation := ⟨st.currentTerm, st.log⟩
private def Seen (f : Frame) (n : NodeID) (o : Observation) := f.logs.seen n o.currentTerm o.log
private abbrev vals := LogFacts.requestAt
private def Granted (f : Frame) := f.logs.grant
private def Elected (f : Frame) := f.logs.elected
private def ElectStep (f : Frame) (after : Model.State) :=
  LogFacts.ElectionAt f.current after (f.advance after).logs.grant
private def Led (f : Frame) := f.logs.led INITIAL_PRIMARY
private def CanonNow (f : Frame) := f.logs.canonNow INITIAL_PRIMARY f.current
private def Canon (f : Frame) := f.logs.canon

/-- Signed quorum evidence for a prefix of a leader log: a signature of the leader's
term at `i`, held in that term by a quorum of the configurations active at `base`. -/
private structure CommitFacts (g : LogFacts.Ghost) (l : List Entry) (t base i : Nat) : Prop where
  canon : g.canon t l
  baseLe : base ≤ i
  indexLe : i ≤ l.length
  signature : isSignatureAt l i = true
  termAtIndex : termAt l i = t
  acks : ∃ xs, hasQuorum ((activeConfigurations l base).filter (·.index ≤ i)) xs ∧
    ∀ x ∈ xs, ∃ p, g.seen x t p ∧ l.take i <+: p

/-- Committed prefixes: the empty prefix, and every prefix with signed quorum evidence
whose base lies within a prefix committed no later. This is a closure over the leader
logs and observations recorded so far, not recorded state: no constructor names a
snapshot or a position in the execution, and a step that records nothing commits
nothing. -/
private inductive Commit (g : LogFacts.Ghost) : Nat → List Entry → Prop where
  | base : Commit g 0 []
  | link {l t b i e p} (facts : CommitFacts g l t b i) (prior : Commit g e p) (le : e ≤ t)
      (within : l.take b <+: p) : Commit g t (l.take i)

private theorem Commit.advance {g bootstrap prev s t p} (c : Commit g t p) :
    Commit (LogFacts.advance bootstrap g prev s) t p := by
  have lift {l t b i} (f : CommitFacts g l t b i) :
      CommitFacts (LogFacts.advance bootstrap g prev s) l t b i := by
    obtain ⟨xs, q, obs⟩ := f.acks
    refine { f with canon := .inl f.canon, acks := ⟨xs, q, ?_⟩ }
    intro x mem
    obtain ⟨p, seen, sub⟩ := obs x mem
    exact ⟨p, .inl seen, sub⟩
  split_rel commit := (induction c) with
  | base => exact .base
  | link =>
    rename_i facts _ le within ih
    exact .link (lift facts) ih le within

private def Committed (f : Frame) := Commit f.logs

/-- The first `commit` entries of `log` lie within a part committed by `term`. -/
private def Backed (frame : Frame) (log : List Entry) (commit term : Nat) : Prop :=
  exists earlier part,
    Committed frame earlier part /\ earlier <= term /\ log.take commit <+: part

/-- `voter` held the first `index` entries of a leader log of `term` in `term`. -/
private def Acked (frame : Frame) (voter : NodeID) (term index : Nat) : Prop :=
  exists acker log,
    Seen frame voter acker
    /\ acker.currentTerm = term
    /\ Canon frame term log
    /\ index <= log.length
    /\ log.take index <+: acker.log

/-- A leader of a term in `(term, bound]` lacked `part`. -/
private def Bad (frame : Frame) (part : List Entry) (term bound : Nat) : Prop :=
  exists later log,
    term < later /\ later <= bound /\ Canon frame later log /\ Not (part <+: log)

/-- A snapshot is a signed prefix of a leader log, within a committed part. -/
private def SnapOK (frame : Frame) (entries : List Entry) : Prop :=
  0 < entries.length
  /\ isSignatureAt entries entries.length = true
  /\ (exists log, Canon frame (termAt entries entries.length) log /\ entries <+: log)
  /\ exists term part, Committed frame term part /\ entries <+: part

/-- Evidence carried by a queued append. Its commit bound is the one advertised on
the wire, not the sender's (possibly since advanced) commit index. -/
private structure AppendEvidence (h : Frame) (source target : NodeID)
    (r : AppendEntriesRequest) (log : List Entry) : Prop where
  different : target ≠ source
  led : Led h source r.term
  canon : Canon h r.term log
  prevBound : r.prevLogIndex ≤ log.length
  prevTerm : r.prevLogTerm = termAt log r.prevLogIndex
  entries : r.entries <+: log.drop r.prevLogIndex
  backed : Backed h log r.primaryCommit r.term

/-- What a queued message tells about its sender. -/
private def MessageOK (frame : Frame) (envelope : Model.Envelope) : Prop :=
  match envelope.payload with
  | .appendEntriesRequest request =>
      ∃ log, AppendEvidence frame envelope.source envelope.target request log
  | .appendEntriesResponse response =>
      response.success = true
      -> Acked frame envelope.source response.term response.lastLogIndex
  | .requestVoteRequest request =>
      (exists state,
        Seen frame envelope.source state /\ state.currentTerm = request.term)
      /\ forall state,
          Now frame envelope.source state
          -> state.role = .candidate
          -> state.currentTerm = request.term
          -> makeRequestVoteRequest state = request
  | .requestVoteResponse response =>
      response.voteGranted = true
      -> exists request,
          Granted frame envelope.source envelope.target response.term request
          /\ (exists state,
                Seen frame envelope.target state /\ state.currentTerm = response.term)
          /\ forall state,
              Now frame envelope.target state
              -> state.role = .candidate
              -> state.currentTerm = response.term
              -> makeRequestVoteRequest state = request
  | _ => True

private def Terms (frame : Frame) : Prop :=
  forall node state,
    Now frame node state
    -> forall entry, entry ∈ state.log -> entry.term <= state.currentTerm

private def Sorted (frame : Frame) : Prop :=
  forall node state,
    Now frame node state
    -> state.log.Pairwise fun first second => first.term <= second.term

/-- Each node has one state. -/
private def Unique (frame : Frame) : Prop :=
  forall node first second, Now frame node first -> Now frame node second -> first = second

private def Active (frame : Frame) : Prop :=
  forall node state, Now frame node state -> Engaged state -> 2 <= state.currentTerm

private def TermMono (frame : Frame) : Prop :=
  forall node state earlier,
    Now frame node state
    -> Seen frame node earlier
    -> earlier.currentTerm <= state.currentTerm

private def Ballots (f : Frame) : Prop := VoteFacts.Inv f.current f.votes

private structure ElectionCert (g : LogFacts.Ghost) (v : VoteFacts.Ghost)
    (n : NodeID) (k : Nat) (l : List Entry) (i : Nat) : Prop where
  above : 3 ≤ k
  rooted : Rooted GENESIS l
  frontier : i ≤ l.length
  backing : ∃ e p, Commit g e p ∧ e < k ∧ l.take i <+: p
  quorum : ∃ voters, hasQuorum (activeConfigurations l i) voters ∧
    ∀ x ∈ voters, ⟨x, k, some n⟩ ∈ v

private theorem ElectionCert.weaken {g g' : LogFacts.Ghost} {v v' : VoteFacts.Ghost}
    {n k l i} (c : ElectionCert g v n k l i)
    (cs : ∀ t p, Commit g t p → Commit g' t p) (vs : ∀ b ∈ v, b ∈ v') :
    ElectionCert g' v' n k l i := by
  obtain ⟨voters, q, observed⟩ := c.quorum
  obtain ⟨e, p, mem, lt, sub⟩ := c.backing
  exact ⟨c.above, c.rooted, c.frontier, ⟨e, p, cs _ _ mem, lt, sub⟩,
    ⟨voters, q, fun x m => vs _ (observed x m)⟩⟩

private def ElectionCerts (g : LogFacts.Ghost) (v : VoteFacts.Ghost) : Prop :=
  ∀ n k l i, g.elected n k l i → ElectionCert g v n k l i

/-- What a later vote says about a signed prefix previously held by the voter:
the request ranks at least as high, or a leader in the intervening terms lacked it. -/
private def VoteRank (r : RequestVoteRequest) (k i : Nat) : Prop :=
  k ≤ r.lastCommittableTerm ∧ (k = r.lastCommittableTerm → i ≤ r.lastCommittableIndex)

private def RankOrLoss (canon : Nat → List Entry → Prop) (bound : Nat)
    (r : RequestVoteRequest) (k i : Nat) (p : List Entry) : Prop :=
  VoteRank r k i ∨ ∃ e l, k < e ∧ e ≤ bound ∧ canon e l ∧ ¬ p <+: l

private def VoterRank (g : LogFacts.Ghost) (canon : Nat → List Entry → Prop)
    (v : NodeID) (t bound : Nat) (r : RequestVoteRequest) : Prop :=
  ∀ k l i, g.seen v k l → k < t → isSignatureAt l i = true → termAt l i = k →
    RankOrLoss canon bound r k i (l.take i)

private def GrantFacts (g : LogFacts.Ghost) (votes : VoteFacts.Ghost)
    (canon : Nat → List Entry → Prop) : Prop :=
  ∀ v n t r, g.grant v n t r →
    (⟨v, t, some n⟩ ∈ votes ∧ VoterRank g canon v t t r) ∧ ∃ l, g.seen n t l

private theorem RankOrLoss.map {a b : Nat → List Entry → Prop} {j j' r k i p}
    (h : RankOrLoss a j r k i p) (keep : ∀ t l, t ≤ j → a t l → t ≤ j' ∧ b t l) :
    RankOrLoss b j' r k i p :=
  h.imp_right fun ⟨t, l, lt, le, canon, missing⟩ =>
    ⟨t, l, lt, (keep t l le canon).1, (keep t l le canon).2, missing⟩

/-- The campaign's last committable entry and the ranks certified by its voters.
`bound` excludes the winning term once election safety is known. -/
private structure CampaignFacts (g : LogFacts.Ghost) (v : VoteFacts.Ghost)
    (canon : Nat → List Entry → Prop) (n : NodeID) (t : Nat) (l : List Entry) (i bound : Nat) :
    Prop where
  rooted : Rooted GENESIS l
  frontier : i ≤ l.length
  anchor : let j := max i (maxCommittableIndex l)
           0 < j → termAt l j < t ∧ ∃ a, canon (termAt l j) a ∧ j ≤ a.length ∧ l.take j = a.take j
  voters : ∃ voters, hasQuorum (activeConfigurations l i) voters ∧ ∀ x ∈ voters,
    ⟨x, t, some n⟩ ∈ v ∧ VoterRank g canon x t bound (vals t l i)

private def RankedElections (g : LogFacts.Ghost) (v : VoteFacts.Ghost) : Prop :=
  ∀ n t l i, g.elected n t l i → CampaignFacts g v g.canon n t l i (t - 1)

/-- Every recorded election has its certificate and the ranks certified by its voters. -/
private def Elections (g : LogFacts.Ghost) (v : VoteFacts.Ghost) : Prop :=
  ∀ n t l i, g.elected n t l i →
    ElectionCert g v n t l i ∧ CampaignFacts g v g.canon n t l i (t - 1)

private theorem CampaignFacts.transport {g g' : LogFacts.Ghost} {v v' : VoteFacts.Ghost}
    {a b : Nat → List Entry → Prop} {n t l i j j'} (c : CampaignFacts g v a n t l i j)
    (votes : ∀ x ∈ v, x ∈ v') (canon : ∀ k p, a k p → b k p)
    (bound : ∀ k p, a k p → k ≤ j → k ≤ j')
    (prior : ∀ x, (⟨x, t, some n⟩ : VoteFacts.Stamp) ∈ v → ∀ k p, g'.seen x k p → k < t → g.seen x k p) :
    CampaignFacts g' v' b n t l i j' := by
  obtain ⟨xs, q, ranks⟩ := c.voters
  refine ⟨c.rooted, c.frontier, ?_, ⟨xs, q, ?_⟩⟩
  · dsimp only
    intro pos
    obtain ⟨lt, p, witnessed, le, eq⟩ := c.anchor pos
    exact ⟨lt, p, canon _ _ witnessed, le, eq⟩
  · intro x mem
    obtain ⟨stamp, ranked⟩ := ranks x mem
    exact ⟨votes _ stamp, fun k p m obs lt sig atM =>
      (ranked k p m (prior x stamp k p obs lt) lt sig atM).map
        (fun e l le a => ⟨bound e l a le, canon e l a⟩)⟩

private def LedCur (frame : Frame) : Prop :=
  forall node state term,
    Now frame node state
    -> Led frame node term
    -> term < state.currentTerm
        \/ (term = state.currentTerm /\ Not (state.role = .candidate))

private def LeaderLed (frame : Frame) : Prop :=
  forall node state,
    Now frame node state -> state.role = .primary -> Led frame node state.currentTerm

/-- Every possible election quorum has a voter that has not granted the request and
has seen a signature too recent to grant it on any subsequent step. -/
private def Blocked (g : LogFacts.Ghost) (n : NodeID) (t : Nat) (l : List Entry) (i : Nat) : Prop :=
  ∀ xs, hasQuorum (activeConfigurations l i) xs → ∃ v ∈ xs,
    ¬g.grant v n t (vals t l i) ∧ ∃ k a j, g.seen v k a ∧ t ≤ k ∧
      isSignatureAt a j = true ∧ termAt a j = k ∧ (vals t l i).lastCommittableTerm < k

private def Candidate (frame : Frame) : Prop :=
  forall node state,
    Now frame node state
    -> state.role = .candidate
    -> 3 <= state.currentTerm
        /\ state.votedFor = some node
        /\ (forall voter,
              voter ∈ state.votesGranted
              -> Granted frame voter node state.currentTerm
                  (vals state.currentTerm state.log state.commitIndex))
        /\ (Backed frame state.log state.commitIndex (state.currentTerm - 1)
            \/ Blocked frame.logs node state.currentTerm state.log state.commitIndex)
        /\ forall entry, entry ∈ state.log -> entry.term < state.currentTerm

private def ElectionSafety (frame : Frame) : Prop :=
  forall node other term, Led frame node term -> Led frame other term -> node = other

/-- A leader's log is the greatest recorded leader log of its term. -/
private def CanonMono (frame : Frame) : Prop :=
  forall node state,
    Now frame node state
    -> Not (state.role = .candidate)
    -> Led frame node state.currentTerm
    -> Canon frame state.currentTerm state.log
        /\ forall log, Canon frame state.currentTerm log -> log <+: state.log

private def Anchor (frame : Frame) : Prop :=
  forall node state index,
    Now frame node state
    -> 0 < index
    -> index <= state.log.length
    -> exists log,
        Canon frame (termAt state.log index) log
        /\ index <= log.length
        /\ state.log.take index = log.take index

/-- What a follower can rely on when copying a leader log, even after its sender changes. -/
private structure CopyLog (g : LogFacts.Ghost) (term : Nat) (log : List Entry) : Prop where
  rooted : Rooted GENESIS log
  terms : ∀ e ∈ log, e.term ≤ term
  sorted : log.Pairwise fun x y => x.term ≤ y.term
  anchor : ∀ i, 0 < i → i ≤ log.length → ∃ l,
    g.canon (termAt log i) l ∧ i ≤ l.length ∧ log.take i = l.take i

private def CopyLogs (g : LogFacts.Ghost) : Prop :=
  ∀ k l, g.canon k l → CopyLog g k l

/-- A ghost update keeps what a follower can rely on. -/
private theorem CopyLog.advance {g bootstrap prev s k l} (copy : CopyLog g k l) :
    CopyLog (LogFacts.advance bootstrap g prev s) k l := by
  obtain ⟨rooted, terms, sorted, anchors⟩ := copy
  refine ⟨rooted, terms, sorted, fun i pos bound => ?_⟩
  obtain ⟨a, ca, le, eq⟩ := anchors i pos bound
  exact ⟨a, .inl ca, le, eq⟩

/-- What every leader log satisfies: a follower may copy it, its term has a leader, and
above the bootstrap term it extends the winning prefix of an election of its term. -/
private structure CanonLog (g : LogFacts.Ghost) (k : Nat) (l : List Entry) : Prop where
  copy : CopyLog g k l
  owner : ∃ n, g.led INITIAL_PRIMARY n k
  winning : BOOTSTRAP_TERM < k →
    ∃ n p i, g.elected n k p i ∧ p.take (maxCommittableIndex p) <+: l

private def CanonLogs (g : LogFacts.Ghost) : Prop :=
  ∀ k l, g.canon k l → CanonLog g k l

private theorem CanonLog.advance {g prev s k l} (old : CanonLog g k l) :
    CanonLog (LogFacts.advance INITIAL_PRIMARY g prev s) k l := by
  obtain ⟨copy, ⟨n, led⟩, winning⟩ := old
  refine ⟨copy.advance, ⟨n, led.imp_right fun ⟨p, i, e⟩ => ⟨p, i, .inl e⟩⟩, fun gt => ?_⟩
  obtain ⟨n, p, i, elect, sub⟩ := winning gt
  exact ⟨n, p, i, .inl elect, sub⟩

/-- Earlier leader logs keep their facts; the logs of this state's leaders supply theirs. -/
private theorem canonLogs_step {g prev s} (old : CanonLogs g)
    (current : ∀ n st k,
      (LogFacts.advance INITIAL_PRIMARY g prev s).canonNow INITIAL_PRIMARY s n st k →
        CanonLog (LogFacts.advance INITIAL_PRIMARY g prev s) k st.log) :
    CanonLogs (LogFacts.advance INITIAL_PRIMARY g prev s) := by
  intro k l canon
  split_rel canon := (rcases canon with past | ⟨n, st, now, rfl⟩) with
  | inl => exact (old k l past).advance
  | inr => exact current n st k now

private def Completeness (frame : Frame) : Prop :=
  forall term part node later log commit,
    Committed frame term part
    -> Elected frame node later log commit
    -> term < later
    -> part <+: log

/--
Committed prefixes lie within committed parts; a leader's of its current term,
even after it steps down, within one committed no later than that term. A node
joined from a snapshot may have a committed prefix that only a later term committed.
-/
private def CommitBacked (frame : Frame) : Prop :=
  forall node state,
    Now frame node state
    -> (exists term, Backed frame state.log state.commitIndex term)
        /\ (state.role = .primary
            -> Backed frame state.log state.commitIndex state.currentTerm)

private def Persist (frame : Frame) : Prop :=
  forall node state earlier index,
    Now frame node state
    -> Seen frame node earlier
    -> isSignatureAt earlier.log index = true
    -> earlier.log.take index <+: state.log
        \/ Bad frame (earlier.log.take index) (termAt earlier.log index)
            state.currentTerm

private def MatchAck (frame : Frame) : Prop :=
  forall node state peer,
    Now frame node state
    -> state.role = .primary
    -> Not (peer = node)
    -> 0 < state.matchIndex peer
    -> Acked frame peer state.currentTerm (state.matchIndex peer)

private def Messages (frame : Frame) : Prop :=
  forall envelope, Pending frame envelope -> MessageOK frame envelope

/-- Every log is empty or starts with the bootstrap configuration. -/
private def RootedLogs (frame : Frame) : Prop :=
  forall node state, Now frame node state -> Rooted GENESIS state.log

private theorem currentCopyLog {f : Frame} (rooted : RootedLogs f) (terms : Terms f)
    (sorted : Sorted f) (anchor : Anchor f) (n st) (mem : Now f n st) :
    CopyLog f.logs st.currentTerm st.log :=
  ⟨rooted n st mem, terms n st mem, sorted n st mem, fun i pos bound => anchor n st i mem pos bound⟩

/-- Every node's log is one a follower may copy: rooted, within the node's term, sorted
by term, and anchored in leader logs. -/
private def NodeLogs (frame : Frame) : Prop :=
  forall node state, Now frame node state -> CopyLog frame.logs state.currentTerm state.log

private theorem CopyLog.mono {f : Frame} {k l} (copy : CopyLog f.logs k l) (s : Model.State) :
    CopyLog (f.advance s).logs k l :=
  copy.advance

private def LeaderLogs (frame : Frame) : Prop :=
  forall node state, Now frame node state -> state.role = .primary -> state.log ≠ []

private def MessageTerms (frame : Frame) : Prop :=
  forall envelope,
    Pending frame envelope -> Bumping envelope.payload -> 2 <= envelope.payload.term

/-- Every committed prefix is in the log of every election of a later term. -/
private def Complete (g : LogFacts.Ghost) : Prop :=
  ∀ k p n t l i, Commit g k p → g.elected n t l i → k < t → p <+: l

/-- Every committed prefix is in every leader log of a later term. -/
private def Later (g : LogFacts.Ghost) : Prop :=
  ∀ k t p l, Commit g k p → g.canon t l → k < t → p <+: l

/-- `Complete`, for elections of terms up to `bound`. -/
private def CompleteUpTo (g : LogFacts.Ghost) (bound : Nat) : Prop :=
  ∀ k p n t l i, Commit g k p → g.elected n t l i → k < t → t ≤ bound → p <+: l

/-- `Later`, for leader logs of terms up to `bound`. -/
private def LaterUpTo (g : LogFacts.Ghost) (bound : Nat) : Prop :=
  ∀ k t p l, Commit g k p → g.canon t l → k < t → t ≤ bound → p <+: l

/-- Committed prefixes are comparable. -/
private def Comparable (frame : Frame) : Prop :=
  forall first second left right,
    Committed frame first left
    -> Committed frame second right
    -> left <+: right \/ right <+: left

private structure Inv (frame : Frame) : Prop where
  node_logs : NodeLogs frame
  active : Active frame
  ballots : Ballots frame
  grantFacts : GrantFacts frame.logs frame.votes frame.logs.canon
  led_cur : LedCur frame
  leader_led : LeaderLed frame
  candidate : Candidate frame
  elections : Elections frame.logs frame.votes
  election_safety : ElectionSafety frame
  canon_mono : CanonMono frame
  chains : LogFacts.Chain frame.logs
  canonLogs : CanonLogs frame.logs
  commit_backed : CommitBacked frame
  persist : Persist frame
  match_ack : MatchAck frame
  messages : Messages frame
  message_terms : MessageTerms frame
  leader_logs : LeaderLogs frame
  comparable : Comparable frame
  unique : Unique frame
  frontier : ∀ n st, Now frame n st → Direct.CommitFrontier st
  observed : ∀ n st, Now frame n st → Seen frame n (observe st)
  term_mono : TermMono frame

private theorem Inv.electionCerts {h : Frame} (inv : Inv h) : ElectionCerts h.logs h.votes :=
  fun n k l i e => (inv.elections n k l i e).1

private theorem Inv.rankedElections {h : Frame} (inv : Inv h)
    : RankedElections h.logs h.votes :=
  fun n t l i e => (inv.elections n t l i e).2

private theorem Inv.terms {h : Frame} (inv : Inv h) : Terms h :=
  fun node state now => (inv.node_logs node state now).terms

private theorem Inv.sorted {h : Frame} (inv : Inv h) : Sorted h :=
  fun node state now => (inv.node_logs node state now).sorted

private theorem Inv.anchor {h : Frame} (inv : Inv h) : Anchor h :=
  fun node state index now positive bound =>
    (inv.node_logs node state now).anchor index positive bound

private theorem Inv.rooted {h : Frame} (inv : Inv h) : RootedLogs h :=
  fun node state now => (inv.node_logs node state now).rooted

private theorem Inv.copyLogs {h : Frame} (inv : Inv h) : CopyLogs h.logs :=
  fun k l canon => (inv.canonLogs k l canon).copy

private theorem Inv.winningPrefix {h : Frame} (inv : Inv h) : LogFacts.WinningPrefix h.logs :=
  fun k l canon gt => (inv.canonLogs k l canon).winning gt

private theorem Inv.copyLog {h : Frame} (i : Inv h) {k l} (canon : Canon h k l) :
    CopyLog h.logs k l := (i.canonLogs k l canon).copy

private theorem Inv.owner {h : Frame} (inv : Inv h) {k l} (canon : h.logs.canon k l) :
    ∃ n, Led h n k :=
  (inv.canonLogs k l canon).owner

/-- A leader's term is at least the bootstrap term. -/
private theorem led_floor {g : LogFacts.Ghost} {v : VoteFacts.Ghost} (certs : ElectionCerts g v)
    {n k} (led : g.led INITIAL_PRIMARY n k) : 2 ≤ k := by
  split_rel led := (rcases led with ⟨rfl, _⟩ | ⟨p, i, e⟩) with
  | inl => decide
  | inr => exact Nat.le_trans (by decide : 2 ≤ 3) (certs n k p i e).above

private theorem Inv.leader_floor {h : Frame} (inv : Inv h) {n k} (led : Led h n k) :
    2 ≤ k :=
  led_floor inv.electionCerts led

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
section Initial

/-- The model's initial node state, with the bootstrap primary named directly. -/
private def initialLocal (node : NodeID) : NodeState where
  role :=
    if node = INITIAL_PRIMARY then
      .primary
    else if node ∈ INITIAL_CONFIGURATION then
      .follower
    else
      .none
  currentTerm := if node ∈ INITIAL_CONFIGURATION then BOOTSTRAP_TERM else 0
  log := if node = INITIAL_PRIMARY then [GENESIS] else []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  primaryKnown := node = INITIAL_PRIMARY
  votesGranted := ∅

end Initial
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

/-- One step of an execution, the invariant holding before it. -/
private structure Ctx (f : Frame) (after : Model.State) where
  tr : LocalTransition f.current after
  inv : Inv f

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {f : Frame} {after : Model.State} (c : Ctx f after)
include c

private abbrev actor : NodeID := c.tr.actor

private abbrev pre : NodeState := c.tr.pre

private abbrev post : NodeState := c.tr.post

private abbrev event : Event := c.tr.event

private abbrev sent : List Model.Envelope := c.tr.outputs.outgoing

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node
section Initial
variable [config : InitialConfiguration]

private theorem initial_primary_iff (nonempty : INITIAL_CONFIGURATION.Nonempty)
    {node : NodeID}
    : INITIAL_CONFIGURATION.min? = some node <-> node = INITIAL_PRIMARY := by
  obtain ⟨least, found⟩ := Option.isSome_iff_exists.mp (Finset.min?_isSome nonempty)
  simp only [INITIAL_PRIMARY, found, Option.getD_some, Option.some.injEq]
  exact eq_comm

private theorem INITIAL_PRIMARY_mem (nonempty : INITIAL_CONFIGURATION.Nonempty)
    : INITIAL_PRIMARY ∈ INITIAL_CONFIGURATION := by
  obtain ⟨least, found⟩ := Option.isSome_iff_exists.mp (Finset.min?_isSome nonempty)
  simp only [INITIAL_PRIMARY, found, Option.getD_some]
  exact Finset.min?_mem found

private theorem GENESIS_configured : GENESIS.content.metadata.configuration.isSome := by
  simp [EntryContent.metadata]

end Initial
end Consensus.Proofs.Config

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
section Steps
variable [Config.InitialConfiguration]

private theorem step_next
    {nodes : List NodeID} {before after : Model.State} {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : next (Model.protocol Config.INITIAL_CONFIGURATION) before action = some after := by
  simp only [Model.transitionSystem, Model.networkStep] at stepped
  split_rel stepped := (split at stepped) with
  | pos =>
    split_rel stepped := (split at stepped) with
    | pos => exact stepped
    | neg => cases stepped
  | neg => exact stepped

private theorem step_local
    {nodes : List NodeID} {before after : Model.State}
    {node : NodeID} {input : Model.Node.Input}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.local node input)
        = some after)
    : exists state next outputs,
        nodeState before node = some state
        /\ (Model.Node.act (Capabilities.record node) node state input).run {}
            = some (next, outputs)
        /\ after
            = {
              before with
                nodes := replaceNode before.nodes node next
                network := before.network ++ outputs.outgoing
            } := by
  replace stepped := step_next stepped
  simp only [next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff] at stepped
  obtain ⟨state, found, next, outputs, ran, rfl⟩ := stepped
  refine ⟨state, next, outputs, found, ?_, by simp [replaceNode]⟩
  exact ran

private theorem step_deliver
    {nodes : List NodeID} {before after : Model.State}
    {envelope : Model.Envelope}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.deliver envelope)
        = some after)
    : envelope ∈ before.network
      /\ exists state next outputs,
          nodeState before envelope.target = some state
          /\ (Model.Node.receive (Capabilities.record envelope.target)
                envelope.target envelope.source state
                envelope.payload).run
                {}
              = some (next, outputs)
          /\ after
              = {
                before with
                  nodes := replaceNode before.nodes envelope.target next
                  network := removeOne envelope before.network ++ outputs.outgoing
              } := by
  replace stepped := step_next stepped
  simp only [next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff, guard] at stepped
  obtain ⟨queued, state, found, next, outputs, ran, rfl⟩ := stepped
  exact ⟨queued, state, next, outputs, found, ran, by simp [replaceNode]⟩

end Steps
end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

private theorem mem_replaceNode {nodes : List (NodeID × NodeState)} {node member : NodeID}
    {value state : NodeState}
    (found : (member, state) ∈ replaceNode nodes node value)
    : (member = node /\ state = value)
      \/ (Not (member = node) /\ (member, state) ∈ nodes) := by
  simp only [replaceNode, List.mem_map] at found
  obtain ⟨⟨key, old⟩, listed, same⟩ := found
  split_rel here := (by_cases here : key = node) with
  | pos =>
    simp only [here, beq_self_eq_true, ite_true, Prod.mk.injEq] at same
    exact Or.inl ⟨same.1.symm, same.2.symm⟩
  | neg =>
    have different : (key == node) = false := by simpa using here
    simp only [different, Bool.false_eq_true, ite_false, Prod.mk.injEq] at same
    obtain ⟨rfl, rfl⟩ := same
    exact Or.inr ⟨here, listed⟩

private theorem replaceNode_keys (nodes : List (NodeID × NodeState)) (node : NodeID)
    (value : NodeState)
    : (replaceNode nodes node value).map Prod.fst = nodes.map Prod.fst := by
  simp only [replaceNode, List.map_map]
  congr 1
  funext entry
  split_rel here := (by_cases here : entry.1 = node) with
  | pos => simp [here]
  | neg => simp [here]

private theorem mem_of_nodeState {concrete : Model.State} {node : NodeID}
    {state : NodeState} (found : nodeState concrete node = some state)
    : (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

private theorem observeTerm_log (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).log = state.log := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split_rel message := (split) with
  | proposeRequestVoteRequest => rfl
  | appendEntriesResponse =>
    split_rel primary := (split) with
    | pos =>
      split_rel newer := (split) with
      | pos => rfl
      | neg => rfl
    | neg => rfl
  | other =>
    split_rel newer := (split) with
    | pos => rfl
    | neg => rfl

private theorem observeTerm_commitIndex (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).commitIndex = state.commitIndex := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split_rel message := (split) with
  | proposeRequestVoteRequest => rfl
  | appendEntriesResponse =>
    split_rel primary := (split) with
    | pos =>
      split_rel newer := (split) with
      | pos => rfl
      | neg => rfl
    | neg => rfl
  | other =>
    split_rel newer := (split) with
    | pos => rfl
    | neg => rfl

@[simp]
private theorem run_failure {σ α : Type} (s : σ)
    : (failure : StateT σ Option α).run s = none :=
  Option.eq_none_iff_forall_ne_some.mpr fun _ ran => nomatch ran

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Ledger

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open Consensus.Model.Node

/-- A successful one-based lookup proves the index lies within the log. -/
private theorem entryAtSomeIndexBound
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : index <= log.length := by
  unfold entryAt? at found
  split_rel found := (split at found) with
  | pos => simp_all
  | neg =>
    rename_i indexNotZero
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, _⟩
    rw [← Nat.sub_add_cancel (Nat.pos_of_ne_zero indexNotZero)]
    exact within

/-- A successful one-based lookup is membership evidence. -/
private theorem entryAt_mem
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : entry ∈ log := by
  unfold entryAt? at found
  split_rel found := (split at found) with
  | pos => simp_all
  | neg =>
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, value⟩
    rw [← value]
    exact List.getElem_mem within

/-- A successful lookup is unchanged when the log is extended at the end. -/
private theorem entryAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    {entry : Entry}
    (found : entryAt? left index = some entry)
    : entryAt? right index = some entry := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  unfold entryAt? at found ⊢
  split_rel zero := (by_cases zero : index = 0) with
  | pos => simp [zero] at found
  | neg =>
    simp only [zero, ↓reduceIte] at found ⊢
    have within : index - 1 < left.length := by
      rw [List.getElem?_eq_some_iff] at found
      exact found.1
    rw [List.getElem?_append_left within]
    exact found

/-- A positive signature test identifies a concrete signature entry. -/
private theorem isSignatureAtTrue
    {log : List Entry}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : Exists
        fun entry =>
          entryAt? log index = some entry /\ entry.content.isSignature = true := by
  split_rel found := (cases found : entryAt? log index) with
  | none =>
      simp [isSignatureAt, found] at signature
  | some =>
      rename_i entry
      refine ⟨entry, rfl, ?_⟩
      simpa [isSignatureAt, found] using signature

/-- One step of the conditional-maximum fold does not go below its start, stays there
unless it moves to a selected value, and reaches a selected value. -/
private theorem select_max_step (P : Nat -> Prop) [DecidablePred P] (best index : Nat)
    : let next := if P index then max best index else best
      best <= next /\ (Not (P next) -> next = best) /\ (P index -> index <= next) := by
  split_rel chosen := (by_cases chosen : P index) with
  | pos =>
    rw [ite_eq_left chosen]
    refine ⟨Nat.le_max_left _ _, fun unselected => ?_, fun _ => Nat.le_max_right _ _⟩
    exact Nat.max_eq_left (Nat.le_of_not_lt fun above =>
      unselected (by rw [Nat.max_eq_right (Nat.le_of_lt above)]; exact chosen))
  | neg =>
    rw [ite_eq_right chosen]
    exact ⟨Nat.le.refl, fun _ => rfl, fun holds => (chosen holds).elim⟩

/-- The conditional-maximum fold does not go below its start, stays there unless it
moves to a selected value, and bounds every selected value. -/
private theorem foldl_select_max (P : Nat -> Prop) [DecidablePred P] (values : List Nat)
    (init : Nat)
    : let result :=
        values.foldl (fun best index => if P index then max best index else best) init
      init <= result /\ (Not (P result) -> result = init)
        /\ forall index, index ∈ values -> P index -> index <= result := by
  split_rel values := (induction values generalizing init) with
  | nil => exact ⟨Nat.le.refl, fun _ => rfl, fun _ member => nomatch member⟩
  | cons =>
    rename_i head tail ih
    simp only [List.foldl_cons]
    obtain ⟨start, stayed, reached⟩ := select_max_step P init head
    obtain ⟨le, unmoved, bound⟩ := ih (if P head then max init head else init)
    generalize (if P head then max init head else init) = next
      at start stayed reached le unmoved bound ⊢
    refine ⟨Nat.le_trans start le, fun unselected => ?_, fun index member holds => ?_⟩
    · -- An unselected result is where the tail started, which is then unselected too.
      have same := unmoved unselected
      rw [same] at unselected ⊢
      exact stayed unselected
    · split_rel mem_cons := (rcases List.mem_cons.mp member with rfl | later) with
      | inl => exact Nat.le_trans (reached holds) le
      | inr => exact bound index later holds

/-- A positive latest committable index points to a signature. -/
private theorem maxCommittableIndexPositiveIsSignature
    {log : List Entry}
    (positive : 0 < maxCommittableIndex log)
    : isSignatureAt log (maxCommittableIndex log) = true := by
  unfold maxCommittableIndex at positive ⊢
  exact Classical.byContradiction fun unsigned => Nat.lt_irrefl 0
    (by
      rw [(foldl_select_max (fun index => isSignatureAt log index = true) _ 0).2.1 unsigned]
        at positive
      exact positive)

/-- The latest signature index lies within the log. -/
private theorem maxCommittableIndexBounded (log : List Entry)
    : maxCommittableIndex log <= log.length := by
  refine Nat.le_of_not_lt fun beyond => ?_
  obtain ⟨entry, found, _⟩ := isSignatureAtTrue
    (maxCommittableIndexPositiveIsSignature (Nat.lt_of_le_of_lt (Nat.zero_le _) beyond))
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le beyond (entryAtSomeIndexBound found))

/-- Every signature index is no later than the latest signature index. -/
private theorem signatureIndex_le_maxCommittableIndex
    {log : List Entry}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= maxCommittableIndex log := by
  have indexBound : index <= log.length := by
    rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
    exact entryAtSomeIndexBound found
  unfold maxCommittableIndex
  exact (foldl_select_max (fun index => isSignatureAt log index = true) _ 0).2.2 index
    (List.mem_range.mpr (Nat.lt_succ_of_le indexBound)) signature

/-- Extending a log preserves every earlier signature lookup. -/
private theorem isSignatureAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    (signature : isSignatureAt left index = true)
    : isSignatureAt right index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have extended := entryAt_of_prefix isPrefix found
  simp [isSignatureAt, extended, content]

/-- Extending a log cannot move its latest signature backwards. -/
private theorem maxCommittableIndex_le_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    : maxCommittableIndex left <= maxCommittableIndex right := by
  refine Nat.le_of_not_lt fun shorter => ?_
  exact Nat.lt_irrefl _
    (Nat.lt_of_lt_of_le shorter
      (signatureIndex_le_maxCommittableIndex
        (isSignatureAt_of_prefix isPrefix
          (maxCommittableIndexPositiveIsSignature
            (Nat.lt_of_le_of_lt (Nat.zero_le _) shorter)))))

/-- Taking a log prefix leaves lookups inside that prefix unchanged. -/
private theorem isSignatureAt_take_of_le
    {log : List Entry}
    {index count : Nat}
    (within : index <= count)
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take count) index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have taken : entryAt? (log.take count) index = some entry := by
    split_rel zero := (by_cases zero : index = 0) with
    | pos =>
      subst index
      simp [entryAt?] at found
    | neg =>
      unfold entryAt? at found ⊢
      simp only [zero, ↓reduceIte] at found ⊢
      rw [List.getElem?_take]
      split_rel within := (split) with
      | pos => exact found
      | neg =>
        rename_i outside
        exact absurd (Nat.lt_of_lt_of_le (Nat.sub_one_lt zero) within) outside
  simp [isSignatureAt, taken, content]

/-- The bounded committable frontier does not exceed the complete log. -/
private theorem maxCommittableIndexUpTo_le_length (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= log.length := by
  unfold maxCommittableIndexUpTo
  have bounded :=
    maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at bounded
  exact Nat.le_trans bounded (Nat.min_le_right _ _)

/-- Restricting the search frontier cannot reveal a later signature. -/
private theorem maxCommittableIndexUpTo_le (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= maxCommittableIndex log := by
  unfold maxCommittableIndexUpTo
  exact
    maxCommittableIndex_le_of_prefix
      (List.take_prefix frontier log)

/-- A positive bounded committable frontier points to a signature in the log. -/
private theorem maxCommittableIndexUpToPositiveIsSignature
    {log : List Entry}
    {frontier : Nat}
    (positive : 0 < maxCommittableIndexUpTo log frontier)
    : isSignatureAt log (maxCommittableIndexUpTo log frontier) = true := by
  unfold maxCommittableIndexUpTo at positive ⊢
  exact
    isSignatureAt_of_prefix
      (List.take_prefix frontier log)
      (maxCommittableIndexPositiveIsSignature positive)

private theorem configurationHistory_filterMap (index : Nat) (log : List Entry)
    : (log.zipIdx index).filterMap
        (fun (entry, index) =>
          entry.content.metadata.configuration.map
            (fun nodes => ({ index, nodes } : Configuration)))
      = configurationsInLogFrom index log := by
  split_rel log := (induction log generalizing index) with
  | nil => rfl
  | cons =>
      rename_i entry entries ih
      rcases entry with ⟨term, content⟩
      split_rel h := (cases h : content.metadata.configuration) with
      | none => simp [configurationsInLogFrom, h, ih]
      | some => simp [configurationsInLogFrom, h, ih]

@[simp]
private theorem activeConfigurations_eq (state : NodeState)
    : Model.Node.activeConfigurations state.log state.commitIndex
      = activeConfigurationsOf state := by
  rfl

@[simp]
private theorem NodeState.activeConfigurations_eq (state : NodeState)
    : state.activeConfigurations = activeConfigurationsOf state :=
  Consensus.Proofs.Ledger.activeConfigurations_eq state

@[simp]
private theorem NodeState.activeMembers_eq (state : NodeState)
    : state.activeMembers = activeNodeUnion state := by
  simp [Model.Node.NodeState.activeMembers, activeNodeUnion, configurationMembers]

/-- Recording a commit changes the commit index and retirement latch, and may
clear the role and primary knowledge. -/
private theorem NodeState.recordCommit_eq (node : NodeID) (state : NodeState)
    (index : Nat)
    : exists retiredCommittedIndex role primaryKnown,
        state.recordCommit node index
          = { state with commitIndex := index, retiredCommittedIndex, role, primaryKnown }
        /\ (role = state.role \/ role = .none) := by
  unfold NodeState.recordCommit
  dsimp only
  split_rel retire := (split) with
  | pos => exact ⟨_, _, _, rfl, Or.inr rfl⟩
  | neg => exact ⟨_, _, _, rfl, Or.inl rfl⟩

@[simp]
private theorem NodeState.recordCommit_log (node : NodeID) (state : NodeState)
    (index : Nat)
    : (state.recordCommit node index).log = state.log := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

@[simp]
private theorem NodeState.recordCommit_commitIndex (node : NodeID) (state : NodeState)
    (index : Nat)
    : (state.recordCommit node index).commitIndex = index := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

/-- Extending a log cannot move its bounded committable frontier backwards. -/
private theorem maxCommittableIndexUpTo_mono {left right : List Entry}
    (isPrefix : left <+: right) (frontier : Nat)
    : maxCommittableIndexUpTo left frontier <= maxCommittableIndexUpTo right frontier :=
  maxCommittableIndex_le_of_prefix
    (List.prefix_take_iff.mpr
      ⟨(List.take_prefix _ _).trans isPrefix, List.length_take_le _ _⟩)

/-- The follower append loop changes only the log, commit and retirement
fields, and may clear the role. -/
private theorem fromLeader_loop (self : NodeID) (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        exists commitIndex retiredCommittedIndex role primaryKnown,
          entries.foldl
              (fun state entry =>
                let state := { state with log := state.log ++ [entry] }
                if entry.content.isSignature then
                  state.recordCommit self
                    (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
                else
                  state)
              state
            = {
              state with
                log := state.log ++ entries,
                commitIndex,
                retiredCommittedIndex,
                role,
                primaryKnown
            }
          /\ (Not (role = .none) -> role = state.role)
          /\ state.commitIndex <= commitIndex
          /\ commitIndex
              <= max state.commitIndex
                  (maxCommittableIndexUpTo (state.log ++ entries) limit) := by
  split_rel entries := (induction entries) with
  | nil =>
      intro state
      exact ⟨
        state.commitIndex,
        state.retiredCommittedIndex,
        state.role,
        state.primaryKnown,
        by simp,
        fun _ => rfl,
        Nat.le.refl,
        Nat.le_max_left _ _
      ⟩
  | cons =>
      rename_i entry entries ih
      intro state
      simp only [List.foldl_cons]
      have mono :=
        maxCommittableIndexUpTo_mono (List.prefix_append (state.log ++ [entry]) entries) limit
      simp only [List.append_assoc, List.cons_append, List.nil_append] at mono
      split_rel signature := (by_cases signature : entry.content.isSignature) with
      | pos =>
        simp only [signature, ↓reduceIte]
        obtain ⟨retired₀, role₀, known₀, eq₀, roleCase₀⟩ :=
          NodeState.recordCommit_eq self { state with log := state.log ++ [entry] }
            (max state.commitIndex
              (maxCommittableIndexUpTo (state.log ++ [entry]) limit))
        rw [eq₀]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        exact ⟨commitIndex, retired, role, known, rfl,
          fun kept => (roleCase kept).trans
            (roleCase₀.resolve_right fun cleared => kept ((roleCase kept).trans cleared)),
          Nat.le_trans (Nat.le_max_left _ _) lower,
          Nat.le_trans upper (Nat.max_le.mpr ⟨Nat.max_le.mpr ⟨Nat.le_max_left _ _,
            Nat.le_trans mono (Nat.le_max_right _ _)⟩, Nat.le_max_right _ _⟩)⟩
      | neg =>
        simp only [signature, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        exact ⟨commitIndex, retired, role, known, rfl, roleCase, lower, upper⟩

/--
Intermediate commits use prefixes of the final log, so the follower's final
commit index is the bounded committable frontier of the extended log.
-/
private theorem handleAppendEntiresFromPrimary_eq (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : let log :=
        state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      exists retiredCommittedIndex role primaryKnown,
        handleAppendEntiresFromPrimary self state request
          = (
            {
              state with
                log
                commitIndex :=
                  max state.commitIndex
                    (maxCommittableIndexUpTo log
                      (min request.primaryCommit
                        (request.prevLogIndex + request.entries.length)))
                retiredCommittedIndex
                role
                primaryKnown
            },
            {
              term := state.currentTerm
              success := true
              lastLogIndex := request.prevLogIndex + request.entries.length
            }
          )
        /\ (Not (role = .none) -> role = state.role) := by
  intro log
  obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ :=
    fromLeader_loop self
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
      (request.entries.drop (state.log.length - request.prevLogIndex)) state
  unfold handleAppendEntiresFromPrimary
  dsimp only
  rw [eq]
  obtain ⟨retired', role', known', eq', roleCase'⟩ := NodeState.recordCommit_eq self _ _
  rw [eq']
  refine ⟨retired', role', known', ?_, ?_⟩
  · simp only [log]
    congr 2
    exact Nat.le_antisymm (Nat.max_le.mpr ⟨upper, Nat.le_max_right _ _⟩)
      (Nat.max_le.mpr ⟨Nat.le_trans lower (Nat.le_max_left _ _), Nat.le_max_right _ _⟩)
  · exact fun kept => (roleCase'.resolve_right kept).trans
      (roleCase fun cleared => kept ((roleCase'.resolve_right kept).trans cleared))

/-- A rollback point lies after the request's previous index. -/
private theorem firstTermConflictIndex_ge {state : NodeState}
    {request : AppendEntriesRequest} {index : Nat}
    (conflict : firstTermConflictIndex state request = some index)
    : request.prevLogIndex + 1 <= index := by
  unfold firstTermConflictIndex at conflict
  obtain ⟨pair, found, rfl⟩ := Option.map_eq_some_iff.mp conflict
  obtain ⟨_, offset, lt, rfl, _⟩ := List.find?_eq_some_iff_getElem.mp found
  simp

end Consensus.Proofs.Ledger

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
open Model (initialNodeState)
variable [Config.InitialConfiguration]

private theorem keys_nodup {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : (state.nodes.map Prod.fst).Nodup := by
  split_rel reachable :=
      (induction reachable using
        (@TransitionSystem.Reachable.rec
          (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes))) with
  | initial =>
      rename_i initialized
      exact initialized.2.2.1
  | step =>
      rename_i before after action _ stepped ih
      split_rel action := (cases action) with
      | «local» =>
          rename_i actor input
          obtain ⟨_, _, _, _, _, rfl⟩ := step_local stepped
          simpa [replaceNode_keys] using ih
      | deliver =>
          rename_i envelope
          obtain ⟨_, _, _, _, _, _, rfl⟩ := step_deliver stepped
          simpa [replaceNode_keys] using ih

private theorem find_of_mem {entries : List (NodeID × NodeState)} {node : NodeID}
    {local_ : NodeState} (distinct : (entries.map Prod.fst).Nodup)
    (member : (node, local_) ∈ entries)
    : entries.find? (fun entry => entry.1 == node) = some (node, local_) := by
  split_rel entries := (induction entries) with
  | nil => simp at member
  | cons =>
      rename_i head tail ih
      obtain ⟨key, value⟩ := head
      simp only [List.map_cons, List.nodup_cons] at distinct
      split_rel here := (by_cases here : key = node) with
      | pos =>
        subst here
        split_rel mem_cons := (rcases List.mem_cons.mp member with same | later) with
        | inl =>
          rw [same]
          simp
        | inr => exact absurd (List.mem_map.mpr ⟨_, later, rfl⟩) distinct.1
      | neg =>
        split_rel mem_cons := (rcases List.mem_cons.mp member with same | later) with
        | inl =>
          simp only [Prod.mk.injEq] at same
          exact absurd same.1.symm here
        | inr => simp [here, ih distinct.2 later]

private theorem nodeState_of_mem {state : Model.State} {node : NodeID}
    {local_ : NodeState} (distinct : (state.nodes.map Prod.fst).Nodup)
    (member : (node, local_) ∈ state.nodes)
    : nodeState state node = some local_ := by
  simp [nodeState, find_of_mem distinct member]

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct.Keeps

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}
variable {α β : Type}

private theorem pure' {P : α -> Prop} {value : α} (holds : P value)
    : Keeps (Node := Node) (Message := Message) (Notification := Notification) P
        (pure value) := by
  intro _ _ _ ran
  cases ran
  exact holds

private theorem trivial' (m : Effect Node Message Notification α)
    : Keeps (fun _ => True) m :=
  fun _ _ _ _ => True.intro

private theorem guard' {c : Prop} [Decidable c]
    : Keeps (Node := Node) (Message := Message) (Notification := Notification)
        (fun _ => c) (guard c) := by
  intro outputs _ after ran
  split_rel holds := (by_cases holds : c) with
  | pos => exact holds
  | neg => simp [guard, holds] at ran

private theorem bind' {Q : α -> Prop} {P : β -> Prop}
    {m : Effect Node Message Notification α} {f : α -> Effect Node Message Notification β}
    (first : Keeps Q m) (rest : forall value, Q value -> Keeps P (f value))
    : Keeps P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  split_rel ranFirst := (cases ranFirst : m.run outputs) with
  | none => simp [ranFirst] at ran
  | some =>
      rename_i pair
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      exact rest value (first _ _ _ ranFirst) _ _ _ ran

private theorem seq' {P : β -> Prop} {m : Effect Node Message Notification α}
    {f : α -> Effect Node Message Notification β}
    (rest : forall value, Keeps P (f value))
    : Keeps P (m >>= f) :=
  bind' (trivial' m) fun value _ => rest value

private theorem mono {P Q : α -> Prop} {m : Effect Node Message Notification α}
    (kept : Keeps P m) (weaker : forall value, P value -> Q value)
    : Keeps Q m :=
  fun outputs result after ran => weaker _ (kept outputs result after ran)

private theorem ite' {P : α -> Prop} {c : Prop} [Decidable c]
    {m n : Effect Node Message Notification α}
    (yes : c -> Keeps P m) (no : Not c -> Keeps P n)
    : Keeps P (if c then m else n) := by
  split_rel condition := (split) with
  | pos => exact yes ‹_›
  | neg => exact no ‹_›

private theorem foldlM' {γ : Type} {P : α -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step : forall value item, P value -> Keeps P (f value item))
    : forall (items : List γ) (init : α), P init -> Keeps P (items.foldlM f init) := by
  intro items
  split_rel items := (induction items) with
  | nil =>
    intro _ holds
    simpa using pure' holds
  | cons =>
    rename_i item items ih
    intro init holds
    simp only [List.foldlM_cons]
    exact bind' (step init item holds) fun value kept => ih value kept

end Consensus.Proofs.Direct.Keeps

namespace Consensus.Proofs.Safety.Sends

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}
variable {α β γ : Type}

private theorem pure' {P : α -> List (Envelope Node Message) -> Prop} {value : α}
    (holds : P value [])
    : Sends (Notification := Notification) P (pure value) := by
  intro outputs _ _ ran
  cases ran
  exact ⟨[], by simp, holds⟩

private theorem bind' {Q : α -> List (Envelope Node Message) -> Prop}
    {P : β -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} {f : α -> Effect Node Message Notification β}
    (first : Sends Q m)
    (rest
      : forall value sent,
          Q value sent -> Sends (fun result later => P result (sent ++ later)) (f value))
    : Sends P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  split_rel ranFirst := (cases ranFirst : m.run outputs) with
  | none => simp [ranFirst] at ran
  | some =>
      rename_i pair
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      obtain ⟨sent, sentEq, holds⟩ := first _ _ _ ranFirst
      obtain ⟨later, laterEq, done⟩ := rest value sent holds _ _ _ ran
      exact ⟨sent ++ later, by rw [laterEq, sentEq, List.append_assoc], done⟩

private theorem mono {P Q : α -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} (sends : Sends P m)
    (weaker : forall value sent, P value sent -> Q value sent)
    : Sends Q m := by
  intro outputs result after ran
  obtain ⟨sent, eq, holds⟩ := sends _ _ _ ran
  exact ⟨sent, eq, weaker _ _ holds⟩

private theorem ite' {P : α -> List (Envelope Node Message) -> Prop} {c : Prop}
    [Decidable c] {m n : Effect Node Message Notification α} (yes : c -> Sends P m)
    (no : Not c -> Sends P n)
    : Sends P (if c then m else n) := by
  split_rel condition := (split) with
  | pos => exact yes ‹_›
  | neg => exact no ‹_›

private theorem guard' {c : Prop} [Decidable c]
    : Sends (Node := Node) (Message := Message) (Notification := Notification)
        (fun _ sent => c /\ sent = []) (guard c) := by
  intro outputs _ after ran
  split_rel holds := (by_cases holds : c) with
  | pos =>
    simp [guard, holds] at ran
    obtain ⟨_, rfl⟩ := ran
    exact ⟨[], by simp, holds, rfl⟩
  | neg => simp [guard, holds] at ran

private theorem guard_bind {P : α -> List (Envelope Node Message) -> Prop} {c : Prop}
    [Decidable c] {m : Effect Node Message Notification α} (rest : c -> Sends P m)
    : Sends P (guard c >>= fun _ => m) :=
  bind' guard'
    fun _ _ ⟨holds, empty⟩ => by
      subst empty
      exact mono (rest holds) fun _ _ done => by simpa using done

private theorem send (source target : Node) (payload : Message)
    : Sends (Notification := Notification)
        (fun _ sent => sent = [{ source, target, payload }])
        ((Capabilities.record source).send payload target) := by
  intro outputs _ after ran
  simp only [Capabilities.record, modify, modifyGet, StateT.run] at ran
  cases ran
  exact ⟨_, rfl, rfl⟩

/-- A `for` loop that never exits early, whose bodies each only send envelopes satisfying
`R`. -/
private theorem forIn' {β : Type} {items : List γ} {init : β}
    {f : γ -> β -> Effect Node Message Notification (ForInStep β)}
    {R : Envelope Node Message -> Prop}
    (each
      : forall item value,
          item ∈ items
          -> Sends
              (fun step sent =>
                (exists next, step = ForInStep.yield next) /\ forall e, e ∈ sent -> R e)
              (f item value))
    : Sends (fun _ sent => forall e, e ∈ sent -> R e) (forIn items init f) := by
  split_rel items := (induction items generalizing init) with
  | nil =>
      simpa using pure' (P := fun (_ : β) sent => forall e, e ∈ sent -> R e) (by simp)
  | cons =>
      rename_i head tail ih
      rw [List.forIn_cons]
      refine bind' (each head init List.mem_cons_self) fun step sent ⟨yields, first⟩ => ?_
      split_rel step := (cases step) with
      | done =>
          obtain ⟨_, eq⟩ := yields
          cases eq
      | yield =>
          rename_i value
          refine mono (ih fun item value member => each item value (List.mem_cons_of_mem _ member))
            fun _ later rest e member => ?_
          split_rel mem_append := (rcases List.mem_append.mp member with old | new) with
          | inl => exact first e old
          | inr => exact rest e new

/-- A fold that keeps `I` of its accumulator and everything sent so far. -/
private theorem foldlM' {I : α -> List (Envelope Node Message) -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step
      : forall value sent item,
          I value sent -> Sends (fun next later => I next (sent ++ later)) (f value item))
    : forall (items : List γ) (init : α) (sent : List (Envelope Node Message)),
        I init sent
        -> Sends (fun result later => I result (sent ++ later)) (items.foldlM f init) := by
  intro items
  split_rel items := (induction items) with
  | nil =>
    intro _ _ holds
    simpa using pure' (P := fun result later => I result (_ ++ later)) (by simpa using holds)
  | cons =>
    rename_i item items ih
    intro init sent holds
    simp only [List.foldlM_cons]
    refine bind' (step init sent item holds) fun value later kept => ?_
    refine mono (ih value (sent ++ later) kept) fun _ rest done => ?_
    simpa [List.append_assoc] using done

end Consensus.Proofs.Safety.Sends

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete Direct
open Model.Node
variable [Config.InitialConfiguration]

private theorem mem_removeOne {α : Type} [BEq α] {value item : α} {items : List α}
    (member : item ∈ removeOne value items)
    : item ∈ items := by
  split_rel items := (induction items) with
  | nil => simp [removeOne] at member
  | cons =>
      rename_i head tail ih
      simp only [removeOne] at member
      split_rel member := (split at member) with
      | pos => exact List.mem_cons_of_mem _ member
      | neg =>
        split_rel mem_cons := (rcases List.mem_cons.mp member with same | later) with
        | inl =>
          subst same
          exact List.mem_cons_self
        | inr => exact List.mem_cons_of_mem _ (ih later)

private theorem LocalTransition.ofStep {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : Nonempty (LocalTransition before after) := by
  split_rel action := (cases action) with
  | «local» =>
      rename_i actor input
      have available : forall entries, input = .initAsBackup entries
          -> Model.committedPrefixOf before entries = true := by
        intro entries rfl
        refine Decidable.by_contra fun absent => ?_
        simp [Model.transitionSystem, Model.networkStep, absent] at stepped
      obtain ⟨pre, post, outputs, found, ran, rfl⟩ := step_local stepped
      exact ⟨{
              actor,
              pre,
              post,
              event := .internal input,
              outputs,
              pending := before.network
              found
              ran := by
                split_rel input := (cases input) with
                | append => exact ran
                | sendEntries => exact ran
                | timeout => exact ran
                | nominateSuccessor => exact ran
                | initAsBackup => exact ran
              nodesEq := rfl
              networkEq := rfl
              pendingSub := fun _ member => member
              source := Or.inl ⟨input, rfl, rfl⟩
              available := fun entries eq => available entries (Event.internal.inj eq)
            }⟩
  | deliver =>
      rename_i envelope
      obtain ⟨queued, pre, post, outputs, found, ran, rfl⟩ := step_deliver stepped
      exact ⟨{
        actor := envelope.target, pre, post
        event := .receive envelope.source envelope.payload, outputs
        pending := removeOne envelope before.network
        found, ran
        nodesEq := rfl
        networkEq := rfl
        pendingSub := fun _ member => mem_removeOne member
        source := Or.inr ⟨envelope, queued, rfl, rfl, rfl⟩
        available := fun _ eq => by cases eq
      }⟩

private theorem LocalTransition.mem_after {before after : Model.State}
    (transition : LocalTransition before after) {node : NodeID}
    {state : NodeState} (member : (node, state) ∈ after.nodes)
    : (node = transition.actor /\ state = transition.post)
      \/ (Not (node = transition.actor) /\ (node, state) ∈ before.nodes) := by
  rw [transition.nodesEq] at member
  exact mem_replaceNode member

private theorem LocalTransition.pre_mem {before after : Model.State}
    (transition : LocalTransition before after)
    : (transition.actor, transition.pre) ∈ before.nodes :=
  mem_of_nodeState transition.found

private theorem LocalTransition.post_mem {before after : Model.State}
    (transition : LocalTransition before after)
    : (transition.actor, transition.post) ∈ after.nodes := by
  rw [transition.nodesEq]
  simp only [replaceNode, List.mem_map]
  exact ⟨_, transition.pre_mem, by simp⟩

private theorem LocalTransition.mem_network {before after : Model.State}
    (transition : LocalTransition before after) {envelope : Model.Envelope}
    (member : envelope ∈ after.network)
    : envelope ∈ before.network \/ envelope ∈ transition.outputs.outgoing := by
  rw [transition.networkEq] at member
  split_rel mem_append := (rcases List.mem_append.mp member with old | new) with
  | inl => exact Or.inl (transition.pendingSub _ old)
  | inr => exact Or.inr new

/-- Two entries of one reachable state for the same node agree. -/
private theorem state_unique {state : Model.State}
    (distinct : (state.nodes.map Prod.fst).Nodup) {node : NodeID}
    {first second : NodeState} (left : (node, first) ∈ state.nodes)
    (right : (node, second) ∈ state.nodes)
    : first = second := by
  have := (nodeState_of_mem distinct left).symm.trans (nodeState_of_mem distinct right)
  exact Option.some.inj this

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF (Finset)
open Model.Node

private theorem take_eq_of_prefix {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (bound : n <= small.length)
    : large.take n = small.take n := by
  obtain ⟨rest, rfl⟩ := sub
  rw [List.take_append_of_le_length bound]

private theorem take_prefix_take {α : Type} (list : List α) {m n : Nat} (le : m <= n)
    : list.take m <+: list.take n := by
  have := List.take_prefix m (list.take n)
  rwa [List.take_take, Nat.min_eq_left le] at this

private theorem comparable_of_prefix {α : Type} {left right common : List α}
    (leftSub : left <+: common) (rightSub : right <+: common)
    : left <+: right \/ right <+: left :=
  List.prefix_or_prefix_of_prefix leftSub rightSub

private theorem termAt_eq {log : List Entry} {index : Nat} (positive : 0 < index)
    (bound : index <= log.length)
    : termAt log index = (log[index - 1]'(Nat.lt_of_lt_of_le
        (Nat.sub_one_lt (Nat.ne_of_gt positive)) bound)).term := by
  simp [termAt, entryAt?, Nat.pos_iff_ne_zero.mp positive,
    List.getElem?_eq_getElem (Nat.lt_of_lt_of_le (Nat.sub_one_lt (Nat.ne_of_gt positive)) bound)]

private theorem termAt_zero (log : List Entry) : termAt log 0 = 0 := by
  simp [termAt, entryAt?]

private theorem termAt_take {log : List Entry} {index n : Nat} (le : index <= n)
    : termAt (log.take n) index = termAt log index := by
  unfold termAt entryAt?
  split_rel zero := (split) with
  | pos => rfl
  | neg =>
    rename_i nonzero
    rw [List.getElem?_take_of_lt (Nat.lt_of_lt_of_le (Nat.sub_one_lt nonzero) le)]

private theorem termAt_of_prefix {small large : List Entry} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : termAt large index = termAt small index := by
  rw [List.prefix_iff_eq_take.mp sub, termAt_take bound]

private theorem firstTermConflictIndex_eq (state : NodeState)
    (request : AppendEntriesRequest)
    : firstTermConflictIndex state request = conflictIndex state.log request :=
  rfl

/--
The accepted log is the sender's prefix up to the end of the batch, followed by
the follower's own suffix exactly when the follower already agreed with that
prefix. `aligned` is log matching between the two logs.
-/
private theorem acceptLog_eq {follower sender : List Entry}
    {request : AppendEntriesRequest}
    (prevBound : request.prevLogIndex <= follower.length)
    (prevSender : request.prevLogIndex <= sender.length)
    (prevAgree : follower.take request.prevLogIndex = sender.take request.prevLogIndex)
    (entries : request.entries <+: sender.drop request.prevLogIndex)
    (aligned
      : forall j,
          0 < j
          -> j <= follower.length
          -> j <= sender.length
          -> termAt follower j = termAt sender j
          -> follower.take j = sender.take j)
    : acceptLog follower request
      = sender.take (request.prevLogIndex + request.entries.length)
        ++ (if follower.take (request.prevLogIndex + request.entries.length)
                = sender.take (request.prevLogIndex + request.entries.length) then
              follower.drop (request.prevLogIndex + request.entries.length)
            else
              []) := by
  obtain ⟨term, prev, prevTerm, batch, primaryCommit⟩ := request
  simp only at prevBound prevSender prevAgree entries ⊢
  have batchEq : batch = (sender.drop prev).take batch.length :=
    List.prefix_iff_eq_take.mp entries
  have batchBound : prev + batch.length <= sender.length := by
    exact Nat.add_le_of_le_sub' prevSender
      (Nat.le_trans entries.length_le (Nat.le_of_eq List.length_drop))
  have senderTake : sender.take (prev + batch.length) = sender.take prev ++ batch := by
    rw [List.take_add, ← batchEq]
  unfold acceptLog
  simp only
  split_rel conflict := (split) with
  | some => -- A conflicting term: the follower keeps only the agreeing prefix.
    rename_i index conflict
    unfold conflictIndex at conflict
    obtain ⟨pair, found, indexEq⟩ := Option.map_eq_some_iff.mp conflict
    obtain ⟨different, offset, lt, pairEq, before⟩ :=
      List.find?_eq_some_iff_getElem.mp found
    simp only [List.length_zipIdx, List.length_zip, List.length_drop] at lt
    rw [List.getElem_zipIdx] at pairEq
    subst pairEq indexEq
    simp only [List.getElem_zip, List.getElem_drop, bne_iff_ne, ne_eq] at different
    have offFollower : prev + offset < follower.length :=
      Nat.add_lt_of_lt_sub' (Nat.lt_of_lt_of_le lt (Nat.min_le_left _ _))
    have offBatch : offset < batch.length := Nat.lt_of_lt_of_le lt (Nat.min_le_right _ _)
    have offSender : prev + offset < sender.length :=
      Nat.lt_of_lt_of_le (Nat.add_lt_add_left offBatch prev) batchBound
    have prefixTerms : forall j (jLt : j < offset),
        (follower[prev + j]'(Nat.lt_trans (Nat.add_lt_add_left jLt prev) offFollower)).term
          = (sender[prev + j]'(Nat.lt_trans (Nat.add_lt_add_left jLt prev) offSender)).term := by
      intro j jLt
      have := before j jLt
      simp only [List.getElem_zipIdx, List.getElem_zip, List.getElem_drop,
        Bool.not_eq_true', bne_eq_false_iff_eq] at this
      rw [this]
      congr 1
      rw [List.getElem_of_eq batchEq]
      simp
    have keptEq : prev + 1 + offset - 1 = prev + offset := by
      rw [Nat.add_right_comm, Nat.add_sub_cancel]
    simp only [keptEq]
    have keptAgree : follower.take (prev + offset) = sender.take (prev + offset) := by
      split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos offset with zero | positive) with
      | inl =>
        simp only [zero, Nat.add_zero]
        exact prevAgree
      | inr =>
        have pos : 0 < prev + offset := Nat.lt_of_lt_of_le positive (Nat.le_add_left _ _)
        apply aligned _ pos (Nat.le_of_lt offFollower) (Nat.le_of_lt offSender)
        rw [termAt_eq pos (Nat.le_of_lt offFollower), termAt_eq pos (Nat.le_of_lt offSender)]
        have := prefixTerms (offset - 1) (Nat.sub_lt positive Nat.one_pos)
        simpa only [(Nat.add_sub_assoc positive prev).symm] using this
    have takeLength : (follower.take (prev + offset)).length = prev + offset := by
      rw [List.length_take, Nat.min_eq_left (Nat.le_of_lt offFollower)]
    have senderOffset : sender.take (prev + offset) = sender.take prev ++ batch.take offset := by
      rw [List.take_add]
      congr 1
      conv => rhs; rw [batchEq]
      rw [List.take_take, Nat.min_eq_left (Nat.le_of_lt offBatch)]
    rw [takeLength, Nat.add_sub_cancel_left, keptAgree, senderOffset,
      List.append_assoc, List.take_append_drop, ← senderTake]
    have differ : Not (follower.take (prev + batch.length) = sender.take (prev + batch.length)) := by
      intro same
      have := congrArg (fun list => list[prev + offset]?) same
      have inBatch := Nat.add_lt_add_left offBatch prev
      rw [List.getElem?_take_of_lt inBatch, List.getElem?_take_of_lt inBatch,
        List.getElem?_eq_getElem offFollower, List.getElem?_eq_getElem offSender] at this
      have entryEq := Option.some.inj this
      have senderEntry : sender[prev + offset]'offSender = batch[offset] := by
        rw [List.getElem_of_eq batchEq]
        simp
      rw [entryEq, senderEntry] at different
      exact different rfl
    simp [differ]
  | none => -- No conflicting term: the overlap agrees, so the follower log is extended.
    rename_i noConflict
    unfold conflictIndex at noConflict
    have notFound := Option.map_eq_none_iff.mp noConflict
    have overlapTerms : forall offset (lt : offset < batch.length)
        (inFollower : prev + offset < follower.length),
        follower[prev + offset].term
          = (sender[prev + offset]'
              (Nat.lt_of_lt_of_le (Nat.add_lt_add_left lt prev) batchBound)).term := by
      intro offset lt inFollower
      have member : ((follower[prev + offset], batch[offset]), prev + 1 + offset)
          ∈ ((follower.drop prev).zip batch).zipIdx (prev + 1) := by
        apply List.mem_iff_getElem.mpr
        refine ⟨offset, ?_, ?_⟩
        · simp only [List.length_zipIdx, List.length_zip, List.length_drop]
          exact Nat.lt_min.mpr ⟨Nat.lt_sub_iff_add_lt'.mpr inFollower, lt⟩
        simp
      have := List.find?_eq_none.mp notFound _ member
      simp only [Bool.not_eq_true, bne_eq_false_iff_eq] at this
      rw [this]
      congr 1
      rw [List.getElem_of_eq batchEq]
      simp
    split_rel long := (by_cases long : prev + batch.length <= follower.length) with
    | pos =>
      have agree : follower.take (prev + batch.length) = sender.take (prev + batch.length) := by
        split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos batch.length with empty | nonempty) with
        | inl =>
          simp only [empty, Nat.add_zero]
          exact prevAgree
        | inr =>
          have pos : 0 < prev + batch.length := Nat.lt_of_lt_of_le nonempty (Nat.le_add_left _ _)
          have last := Nat.sub_lt nonempty Nat.one_pos
          apply aligned _ pos long batchBound
          rw [termAt_eq pos long, termAt_eq pos batchBound]
          have := overlapTerms (batch.length - 1) last
            (Nat.lt_of_lt_of_le (Nat.add_lt_add_left last prev) long)
          simpa only [(Nat.add_sub_assoc nonempty prev).symm] using this
      rw [ite_eq_left agree, ← agree, List.take_append_drop,
        List.drop_eq_nil_of_le (Nat.le_sub_of_add_le' long), List.append_nil]
    | neg =>
      have agree : follower = sender.take follower.length := by
        split_rel eq_or_lt_of_le := (rcases Nat.eq_or_lt_of_le prevBound with same | ahead) with
        | inl =>
          rw [← same]
          have := prevAgree
          rwa [List.take_of_length_le (Nat.le_of_eq same.symm)] at this
        | inr =>
          have pos : 0 < follower.length := Nat.lt_of_le_of_lt (Nat.zero_le _) ahead
          have fs : follower.length <= sender.length :=
            Nat.le_of_lt (Nat.lt_of_lt_of_le (Nat.lt_of_not_le long) batchBound)
          have := aligned follower.length pos Nat.le.refl fs (by
            rw [termAt_eq pos Nat.le.refl, termAt_eq pos fs]
            have eq : prev + (follower.length - 1 - prev) = follower.length - 1 :=
              Nat.add_sub_of_le (Nat.le_sub_one_of_lt ahead)
            have lastLt : prev + (follower.length - 1 - prev) < follower.length := by
              rw [eq]
              exact Nat.sub_one_lt (Nat.ne_of_gt pos)
            have := overlapTerms (follower.length - 1 - prev)
              (Nat.lt_of_add_lt_add_left
                (Nat.lt_trans lastLt (Nat.lt_of_not_le long)))
              lastLt
            simpa only [eq] using this)
          rwa [List.take_of_length_le Nat.le.refl] at this
      have differ : Not (follower.take (prev + batch.length)
          = sender.take (prev + batch.length)) := by
        intro same
        have := congrArg List.length same
        simp only [List.length_take] at this
        rw [Nat.min_eq_right (Nat.le_of_lt (Nat.lt_of_not_le long)),
          Nat.min_eq_left batchBound] at this
        exact long (Nat.le_of_eq this.symm)
      rw [ite_eq_right differ, List.append_nil]
      have followerEq : follower = sender.take prev ++ batch.take (follower.length - prev) := by
        have viaTake : follower = (sender.take (prev + batch.length)).take follower.length := by
          rw [List.take_take, Nat.min_eq_left (Nat.le_of_lt (Nat.lt_of_not_le long))]
          exact agree
        rw [senderTake, List.take_append, List.length_take, Nat.min_eq_left prevSender,
          List.take_of_length_le (Nat.le_trans (List.length_take_le _ _) prevBound)] at viaTake
        exact viaTake
      rw (occs := .pos [1]) [followerEq]
      rw [List.append_assoc, List.take_append_drop, senderTake]

private theorem mem_history_filterMap {log : List Entry} {start : Nat}
    {configuration : Configuration}
    (member
      : configuration
        ∈ (log.zipIdx start).filterMap
            fun (entry, index) =>
              entry.content.metadata.configuration.map
                fun nodes => ({ index, nodes } : Configuration))
    : start <= configuration.index /\ configuration.index < start + log.length := by
  obtain ⟨⟨entry, index⟩, pairMember, configMember⟩ := List.mem_filterMap.mp member
  obtain ⟨nodes, _, rfl⟩ := Option.map_eq_some_iff.mp configMember
  have := List.mem_zipIdx pairMember
  simp only
  exact ⟨this.1, this.2.1⟩

/-- The configuration history of a log extends that of any of its prefixes by
configurations from later positions. -/
private theorem configurationHistory_split (log : List Entry) (k : Nat)
    : exists rest,
        configurationHistory log = configurationHistory (log.take k) ++ rest
        /\ forall configuration, configuration ∈ rest -> k < configuration.index := by
  have split : log = log.take k ++ log.drop k := (List.take_append_drop k log).symm
  refine ⟨((log.drop k).zipIdx (1 + (log.take k).length)).filterMap fun (entry, index) =>
      entry.content.metadata.configuration.map
        fun nodes => ({ index, nodes } : Configuration),
    ?_, ?_⟩
  · unfold configurationHistory
    conv => lhs; rw [split]
    rw [List.zipIdx_append, List.filterMap_append]
  · intro configuration member
    have := mem_history_filterMap member
    split_rel short := (by_cases short : log.length <= k) with
    | pos => simp [List.drop_eq_nil_of_le short] at member
    | neg =>
      simp at this
      rw [Nat.min_eq_left (Nat.le_of_lt (Nat.lt_of_not_le short))] at this
      exact Nat.le_trans (Nat.le_of_eq (Nat.add_comm k 1)) this.1

/-- A log with a configuration history is nonempty. -/
private theorem ne_nil_of_configurationHistory {log : List Entry}
    (nonempty : configurationHistory log ≠ [])
    : log ≠ [] := by
  rintro rfl
  exact nonempty rfl

/-- Active configurations are drawn from the configuration history. -/
private theorem activeConfigurations_sublist (log : List Entry) (commit : Nat)
    : (activeConfigurations log commit).Sublist (configurationHistory log) :=
  List.drop_sublist _ _

private theorem filter_index_append {front rest : List Configuration} {bound k : Nat}
    (le : bound <= k)
    (later : forall configuration, configuration ∈ rest -> k < configuration.index)
    : ((front ++ rest).filter fun configuration => configuration.index <= bound)
      = front.filter fun configuration => configuration.index <= bound := by
  have empty : (rest.filter fun configuration => configuration.index <= bound) = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro configuration member
    have := later configuration member
    simp
    exact Nat.lt_of_le_of_lt le this
  rw [List.filter_append, empty, List.append_nil]

private theorem length_filter_index_mono (configurations : List Configuration)
    {small large : Nat} (le : small <= large)
    : (configurations.filter fun configuration => configuration.index <= small).length
      <= (configurations.filter
            fun configuration => configuration.index <= large).length := by
  simp only [← List.countP_eq_length_filter]
  apply List.countP_mono_left
  intro configuration _ holds
  simp at holds ⊢
  exact Nat.le_trans holds le

private theorem length_filter_le (configurations : List Configuration) (bound : Nat)
    : (configurations.filter fun configuration => configuration.index <= bound).length
      <= configurations.length :=
  List.length_filter_le _ _

private theorem zipIdx_sorted {α : Type} (log : List α) (start : Nat)
    : (log.zipIdx start).Pairwise fun first second => first.2 < second.2 := by
  rw [List.pairwise_iff_getElem]
  intro i j _ _ lt
  rw [List.getElem_zipIdx, List.getElem_zipIdx]
  exact Nat.add_lt_add_left lt start

/-- Configuration histories are ordered by index. -/
private theorem configurationHistory_sorted (log : List Entry)
    : (configurationHistory log).Pairwise
        fun first second => first.index < second.index := by
  unfold configurationHistory
  refine List.Pairwise.filterMap _ (fun first second lt left leftMem right rightMem => ?_)
    (zipIdx_sorted log 1)
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp leftMem
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp rightMem
  exact lt

/-- In an index-sorted list, the positions counted by an index bound hold
configurations within it. -/
private theorem getElem_le_of_lt_length_filter {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    {bound i : Nat}
    (lt
      : i
        < (configurations.filter
            fun configuration => configuration.index <= bound).length)
    : (configurations[i]'(Nat.lt_of_lt_of_le lt (List.length_filter_le _ _))).index
      <= bound := by
  have inRange : i < configurations.length :=
    Nat.lt_of_lt_of_le lt (List.length_filter_le _ _)
  refine Nat.le_of_not_lt fun above => ?_
  -- Otherwise every configuration from position `i` on is beyond the bound, and at most
  -- the `i` before it are within it.
  have later : ((configurations.drop (i + 1)).filter
      fun configuration => configuration.index <= bound) = [] := by
    refine List.filter_eq_nil_iff.mpr fun configuration member => ?_
    obtain ⟨j, inDrop, rfl⟩ := List.mem_iff_getElem.mp member
    rw [List.length_drop] at inDrop
    have ordered := List.pairwise_iff_getElem.mp sorted i (i + 1 + j) inRange
      (Nat.add_lt_of_lt_sub' inDrop)
      (Nat.lt_of_lt_of_le (Nat.lt_succ_self i) (Nat.le_add_right _ _))
    simp only [List.getElem_drop, decide_eq_true_eq, Nat.not_le]
    exact Nat.lt_trans above ordered
  have count : (configurations.filter fun configuration => configuration.index <= bound).length
      <= i := by
    calc (configurations.filter fun configuration => configuration.index <= bound).length
        = ((configurations.take i ++ configurations.drop i).filter
            fun configuration => configuration.index <= bound).length := by
          rw [List.take_append_drop]
      _ = ((configurations.take i).filter
            fun configuration => configuration.index <= bound).length := by
          rw [List.drop_eq_getElem_cons inRange, List.filter_append,
            List.filter_cons_of_neg (by simpa using above), later, List.append_nil]
      _ <= i := Nat.le_trans (List.length_filter_le _ _) (List.length_take_le _ _)
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt count)

/-- The configuration chosen by an index bound is within it, or is the first: so its index
is within any limit that covers the bound and the index of some configuration. -/
private theorem chosen_bound {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    (bound : Nat) (positive : 0 < configurations.length)
    {limit : Nat} (within : bound <= limit)
    {low : Configuration} (member : low ∈ configurations) (lowLe : low.index <= limit)
    : let chosen :=
        configurations[
          (configurations.filter fun configuration => configuration.index <= bound).length
          - 1
          ]'(by
              exact Nat.lt_of_le_of_lt
                (Nat.sub_le_sub_right (List.length_filter_le _ _) 1)
                (Nat.sub_one_lt (Nat.ne_of_gt positive)))
      chosen.index <= limit := by
  intro chosen
  split_rel counted := (by_cases counted : 0 < (configurations.filter
      fun configuration => configuration.index <= bound).length) with
  | pos =>
    exact Nat.le_trans
      (getElem_le_of_lt_length_filter sorted (Nat.sub_one_lt (Nat.ne_of_gt counted))) within
  | neg =>
    -- No configuration is within the bound: the first one is chosen, and it is the lowest.
    split_rel configurations := (rcases configurations with _ | ⟨head, tail⟩) with
    | inl => simp at positive
    | inr =>
      simp only [chosen, Nat.eq_zero_of_not_pos counted, Nat.zero_sub, List.getElem_cons_zero]
      split_rel mem_cons := (rcases List.mem_cons.mp member with same | later) with
      | inl =>
        subst same
        exact lowLe
      | inr =>
        exact Nat.le_trans (Nat.le_of_lt ((List.pairwise_cons.mp sorted).1 low later)) lowLe

/--
Two logs agreeing up to `k`, with commit indices at most `k` and a configuration
among their first `k` entries, share an active configuration: the last one
committed by the larger commit index, or the first one if neither commits one. Its
index is within any limit that covers both commit indices and some configuration
among those entries.
-/
private theorem activeConfigurations_overlap {left right : List Entry}
    {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k)
    {limit : Nat} (within : max leftCommit rightCommit <= limit)
    {low : Configuration} (member : low ∈ configurationHistory (right.take k))
    (lowLe : low.index <= limit)
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit
        /\ configuration.index <= limit := by
  obtain ⟨leftRest, leftEq, leftLater⟩ := configurationHistory_split left k
  obtain ⟨rightRest, rightEq, rightLater⟩ := configurationHistory_split right k
  rw [agree] at leftEq
  have sorted := configurationHistory_sorted (right.take k)
  generalize configurationHistory (right.take k) = common at leftEq rightEq member sorted ⊢
  have commonPos : 0 < common.length := List.length_pos_of_mem member
  have count : forall {log : List Entry} {rest commit},
      configurationHistory log = common ++ rest
      -> (forall configuration, configuration ∈ rest -> k < configuration.index)
      -> commit <= k
      -> ((configurationHistory log).filter
            fun configuration => configuration.index <= commit)
          = common.filter fun configuration => configuration.index <= commit := by
    intro log rest commit eq later le
    rw [eq]
    exact filter_index_append le later
  have inDrop : forall {log : List Entry} {rest} {m p : Nat}
      (lt : p < common.length),
      configurationHistory log = common ++ rest -> m <= p
      -> common[p] ∈ (configurationHistory log).drop m := by
    intro log rest m p lt eq le
    rw [eq, List.mem_iff_getElem]
    refine ⟨p - m, ?_, ?_⟩
    · rw [List.length_drop, List.length_append]
      exact Nat.sub_lt_sub_right le (Nat.lt_of_lt_of_le lt (Nat.le_add_right _ _))
    simp only [List.getElem_drop]
    rw [List.getElem_append_left (Nat.lt_of_le_of_lt (Nat.le_of_eq (Nat.add_sub_of_le le)) lt)]
    congr 1
    exact Nat.add_sub_of_le le
  unfold activeConfigurations
  simp only
  rw [count leftEq leftLater leftLe, count rightEq rightLater rightLe]
  have leftBound := length_filter_le common leftCommit
  have rightBound := length_filter_le common rightCommit
  have last : common.length - 1 < common.length := Nat.sub_one_lt (Nat.ne_of_gt commonPos)
  split_rel le_total := (rcases Nat.le_total leftCommit rightCommit with ordered | ordered) with
  | inl =>
    have mono := length_filter_index_mono common ordered
    have chosenLt := Nat.lt_of_le_of_lt (Nat.sub_le_sub_right rightBound 1) last
    exact ⟨common[_ - 1]'chosenLt, inDrop chosenLt leftEq (Nat.sub_le_sub_right mono 1),
      inDrop chosenLt rightEq Nat.le.refl,
      chosen_bound sorted rightCommit commonPos
        (Nat.le_trans (Nat.le_max_right _ _) within) member lowLe⟩
  | inr =>
    have mono := length_filter_index_mono common ordered
    have chosenLt := Nat.lt_of_le_of_lt (Nat.sub_le_sub_right leftBound 1) last
    exact ⟨common[_ - 1]'chosenLt, inDrop chosenLt leftEq Nat.le.refl,
      inDrop chosenLt rightEq (Nat.sub_le_sub_right mono 1),
      chosen_bound sorted leftCommit commonPos
        (Nat.le_trans (Nat.le_max_left _ _) within) member lowLe⟩

/-- Two strict majorities of one configuration share a member. -/
private theorem majorities_intersect {configuration : Configuration}
    {left right : Finset NodeID}
    (leftMajority : hasConfigurationMajority left configuration)
    (rightMajority : hasConfigurationMajority right configuration)
    : exists node, node ∈ left /\ node ∈ right := by
  unfold hasConfigurationMajority at leftMajority rightMajority
  obtain ⟨node, member⟩ := Finset.inter_nonempty_of_card_lt_card_add_card
    (show left ∩ configuration.nodes ⊆ configuration.nodes from Finset.inter_subset_right)
    (show right ∩ configuration.nodes ⊆ configuration.nodes from Finset.inter_subset_right)
    (by
      apply Nat.lt_of_mul_lt_mul_right (a := 2)
      rw [Nat.add_mul, Nat.mul_two]
      exact Nat.add_lt_add leftMajority rightMajority)
  simp only [Finset.mem_inter] at member
  exact ⟨node, member.1.1, member.2.1⟩

private theorem hasQuorum_majority {configurations : List Configuration}
    {voters : Finset NodeID} (quorum : hasQuorum configurations voters)
    {configuration : Configuration} (member : configuration ∈ configurations)
    : hasConfigurationMajority voters configuration := by
  have := List.all_eq_true.mp quorum.2 configuration member
  simpa using this

private theorem Rooted.prefix {root : Entry} {small large : List Entry}
    (rooted : Rooted root large) (sub : small <+: large)
    : Rooted root small := by
  intro nonempty
  have positive := List.length_pos_iff.mpr nonempty
  rw [← take_eq_of_prefix sub (Nat.succ_le_of_lt positive)]
  exact rooted fun empty => nonempty (List.prefix_nil.mp (empty ▸ sub))

private theorem Rooted.append {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (nonempty : log ≠ []) (entries : List Entry)
    : Rooted root (log ++ entries) := by
  intro _
  have := List.length_pos_iff.mpr nonempty
  rw [List.take_append_of_le_length (Nat.succ_le_of_lt this), rooted nonempty]

private theorem Rooted.head {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (nonempty : log ≠ [])
    : log.take 1 = [root] :=
  rooted nonempty

private theorem hasQuorum_nonempty {log : List Entry} {commit : Nat}
    {voters : Finset NodeID} (quorum : hasQuorum (activeConfigurations log commit) voters)
    : log ≠ [] := by
  apply ne_nil_of_configurationHistory
  intro empty
  apply quorum.1
  have := activeConfigurations_sublist log commit
  rw [empty] at this
  exact List.sublist_nil.mp this

/-- Two nonempty rooted logs agreeing on both committed prefixes share an active
configuration within both commit indices or at the root's index; a
configuration-bearing root supplies it. -/
private theorem rooted_overlap {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (leftNonempty : left ≠ []) (rightNonempty : right ≠ [])
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k)
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit
        /\ configuration.index <= max (max leftCommit rightCommit) 1 := by
  have leftHead := leftRooted.head leftNonempty
  have rightHead := rightRooted.head rightNonempty
  have agree' : left.take (max k 1) = right.take (max k 1) := by
    split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos k with zero | positive) with
    | inl =>
      subst zero
      simp [leftHead, rightHead]
    | inr => rwa [Nat.max_eq_left positive]
  have rooted : (right.take (max k 1)).take 1 = [root] := by
    rw [List.take_take, Nat.min_eq_left (Nat.le_max_right _ _), rightHead]
  -- The root's configuration, at index one, is among the agreed entries.
  obtain ⟨rest, eq, _⟩ := configurationHistory_split (right.take (max k 1)) 1
  obtain ⟨nodes, some⟩ := Option.isSome_iff_exists.mp configured
  have genesis : ({ index := 1, nodes } : Configuration)
      ∈ configurationHistory (right.take (max k 1)) := by
    rw [eq, rooted]
    simp [configurationHistory, some]
  exact activeConfigurations_overlap agree' (Nat.le_trans leftLe (Nat.le_max_left _ _))
    (Nat.le_trans rightLe (Nat.le_max_left _ _)) (Nat.le_max_left _ _) genesis
    (Nat.le_max_right _ _)

/-- Quorums for two rooted logs agreeing on both committed prefixes share a
voter; a configuration-bearing root supplies a common configuration. -/
private theorem quorums_intersect {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) {leftVoters rightVoters : Finset NodeID}
    (leftQuorum : hasQuorum (activeConfigurations left leftCommit) leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  obtain ⟨configuration, leftMember, rightMember, _⟩ :=
    rooted_overlap configured leftRooted rightRooted (hasQuorum_nonempty leftQuorum)
      (hasQuorum_nonempty rightQuorum) agree leftLe rightLe
  exact majorities_intersect (hasQuorum_majority leftQuorum leftMember)
    (hasQuorum_majority rightQuorum rightMember)

/-- As `quorums_intersect`, with the left quorum taken over the active
configurations no later than a positive `bound` covering both commit indices. -/
private theorem quorums_intersect_bounded {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k bound : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (leftBound : leftCommit <= bound)
    (rightBound : rightCommit <= bound) (positive : 0 < bound)
    {leftVoters rightVoters : Finset NodeID}
    (leftQuorum
      : hasQuorum
          ((activeConfigurations left leftCommit).filter
            fun configuration => configuration.index <= bound)
          leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  have leftNonempty : left ≠ [] := by
    apply ne_nil_of_configurationHistory
    intro empty
    apply leftQuorum.1
    have := activeConfigurations_sublist left leftCommit
    rw [empty] at this
    rw [List.sublist_nil.mp this, List.filter_nil]
  obtain ⟨configuration, leftMember, rightMember, within⟩ :=
    rooted_overlap configured leftRooted rightRooted leftNonempty
      (hasQuorum_nonempty rightQuorum) agree leftLe rightLe
  have filtered : configuration
      ∈ (activeConfigurations left leftCommit).filter
          fun configuration => configuration.index <= bound := by
    refine List.mem_filter.mpr ⟨leftMember, ?_⟩
    simp only [decide_eq_true_eq]
    exact Nat.le_trans within (Nat.max_le.mpr ⟨Nat.max_le.mpr ⟨leftBound, rightBound⟩, positive⟩)
  exact majorities_intersect (hasQuorum_majority leftQuorum filtered)
    (hasQuorum_majority rightQuorum rightMember)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem CommitFrontier.of_log {state after : NodeState}
    (frontier : CommitFrontier state) (logEq : after.log = state.log)
    (commitEq : after.commitIndex = state.commitIndex)
    : CommitFrontier after := by
  unfold CommitFrontier at *
  rw [logEq, commitEq]
  exact frontier

private theorem CommitFrontier.extend {state : NodeState}
    (frontier : CommitFrontier state) {log : List Entry}
    (extends_ : state.log <+: log)
    : CommitFrontier { state with log } := by
  refine ⟨Nat.le_trans frontier.1 extends_.length_le, fun positive => ?_⟩
  exact isSignatureAt_of_prefix extends_ (frontier.2 positive)

private theorem CommitFrontier.keep {state : NodeState}
    (frontier : CommitFrontier state) {count : Nat} (within : state.commitIndex <= count)
    {suffix : List Entry}
    : CommitFrontier { state with log := state.log.take count ++ suffix } := by
  refine ⟨?_, fun positive => ?_⟩
  · simp only [List.length_append, List.length_take]
    exact Nat.le_trans (Nat.le_min.mpr ⟨within, frontier.1⟩) (Nat.le_add_right _ _)
  · exact isSignatureAt_of_prefix (List.prefix_append _ _)
      (isSignatureAt_take_of_le within (frontier.2 positive))

/-- A new commit frontier chosen from the latest covered signature. -/
private theorem CommitFrontier.advance {state : NodeState}
    {log : List Entry} {bound : Nat}
    (extends_ : CommitFrontier { state with log })
    : CommitFrontier
        {
          state with
            log, commitIndex := max state.commitIndex (maxCommittableIndexUpTo log bound)
        } := by
  refine ⟨Nat.max_le.mpr ⟨extends_.1, maxCommittableIndexUpTo_le_length log bound⟩,
    fun positive => ?_⟩
  simp only at positive ⊢
  split_rel le_total :=
      (rcases Nat.le_total state.commitIndex (maxCommittableIndexUpTo log bound) with le | le) with
  | inl =>
    rw [Nat.max_eq_right le] at positive ⊢
    exact maxCommittableIndexUpToPositiveIsSignature positive
  | inr =>
    rw [Nat.max_eq_left le] at positive ⊢
    exact extends_.2 positive

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )
section Handlers
variable (caps : Caps) (self : NodeID)

/-- Successor nomination only sends; on success it returns its input state. -/
private theorem Keeps.nominateSuccessor (state : NodeState)
    : Keeps (fun result => result = state)
        (Model.Node.nominateSuccessor caps state self) := by
  unfold Model.Node.nominateSuccessor
  refine Keeps.seq' fun _ => ?_
  split_rel successor := (split) with
  | some => exact Keeps.seq' fun _ => Keeps.pure' rfl
  | none => exact Keeps.pure' rfl

end Handlers
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

private theorem Extends.committedLog {before after : NodeState}
    (extended : Extends before after)
    : before.committedLog <+: after.committedLog :=
  List.prefix_take_iff.mpr ⟨extended.2, Nat.le_trans (List.length_take_le _ _) extended.1⟩

private theorem Extends.refl (state : NodeState) : Extends state state :=
  ⟨Nat.le.refl, List.take_prefix _ _⟩

private theorem Extends.trans {first second third : NodeState}
    (left : Extends first second) (right : Extends second third)
    : Extends first third :=
  ⟨Nat.le_trans left.1 right.1, left.committedLog.trans right.2⟩

/-- Keeping the log below `count`, at or above the commit index, and committing no
less extends the committed log. -/
private theorem Extends.of_prefix {before after : NodeState} {count : Nat}
    (within : before.commitIndex <= count) (kept : before.log.take count <+: after.log)
    (grows : before.commitIndex <= after.commitIndex)
    : Extends before after := by
  refine ⟨grows, List.IsPrefix.trans ?_ kept⟩
  unfold NodeState.committedLog
  exact List.take_prefix_take_left within

private theorem Extends.of_log {before after : NodeState}
    (logEq : after.log = before.log) (commitEq : after.commitIndex = before.commitIndex)
    : Extends before after :=
  ⟨Nat.le_of_eq commitEq.symm, logEq ▸ List.take_prefix _ _⟩

private theorem Extends.append {state : NodeState} (entry : Entry)
    : Extends state { state with log := state.log ++ [entry] } :=
  ⟨Nat.le.refl, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section AppendEntries
variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

private theorem Extends.fromLeader
    : Extends state (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, -⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact ⟨Nat.le_max_left _ _, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

private theorem Extends.handleAppendEntriesRequest (caps : Caps) (source : NodeID)
    : Keeps (Extends state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Extends state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split_rel stepDown := (split) with
    | pos => exact Extends.of_log rfl rfl
    | neg => exact Extends.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split_rel stepDown := (split) with
    | pos => exact Keeps.seq' fun _ => Keeps.pure' stepped
    | neg => exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.trans (Extends.of_log rfl rfl)))
    fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split_rel conflict := (split) with
  | none =>
    exact Keeps.seq' fun _ => Keeps.pure'
      ((stepped.trans (Extends.of_log (after := { current with primaryKnown := true }) rfl
        rfl)).trans Extends.fromLeader)
  | some =>
    rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    have truncated : Extends current {
        current with
          primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
      } :=
      Extends.of_prefix (count := index - 1)
        (Nat.le_trans within (Nat.le_sub_of_add_le this)) (List.prefix_refl _) Nat.le.refl
    exact Keeps.seq' fun _ => Keeps.pure' ((stepped.trans truncated).trans Extends.fromLeader)

end AppendEntries
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem Extends.advanced (state : NodeState)
    : Keeps (Extends state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun ahead => ?_
  have advanced : Extends state
      (state.recordCommit self (highestCommittableIndex state self)) :=
    ⟨by
      rw [Ledger.NodeState.recordCommit_commitIndex]
      exact Nat.le_of_lt (Nat.lt_of_not_le ahead),
      by rw [Ledger.NodeState.recordCommit_log]; exact List.take_prefix _ _⟩
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite'
      (fun _ => Keeps.seq' fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
      fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
    fun _ => Keeps.pure' advanced

private theorem Extends.appendEntry (state : NodeState) (content : EntryContent)
    : Keeps (Extends state) (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((Extends.append _).trans (Extends.of_log rfl rfl))
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
  all_goals
    split_rel configuration := (split) with
    | none => exact Keeps.pure' ((Extends.append _).trans (Extends.of_log rfl rfl))
    | some =>
      refine Keeps.seq' fun _ => ?_
      refine Keeps.seq' fun _ => ?_
      exact Keeps.pure' ((Extends.append _).trans (Extends.of_log rfl rfl))

private theorem Extends.becomePrimary (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary Model.Node.primaryState
  have promoted : Extends state
      {
        state with
          role := .primary
          log :=
            if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
            else state.log
          primaryKnown := true
          sentIndex := fun _ =>
            (if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
              else state.log).length
          matchIndex := fun _ => 0
      } := by
    split_rel committed := (split) with
    | pos =>
      exact Extends.of_prefix (by unfold lastCommittableIndex; exact Nat.le_max_left _ _)
        (List.prefix_refl _) Nat.le.refl
    | neg => exact Extends.of_log rfl rfl
  exact Keeps.bind' (Extends.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (promoted.trans kept)

private theorem Extends.electIfQuorum (state : NodeState)
    : Keeps (Extends state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Extends.becomePrimary caps self state)
    fun _ => Keeps.pure' (Extends.refl _)

private theorem Extends.becomeCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  exact Keeps.bind' (Extends.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' ((Extends.of_log rfl rfl).trans kept)

private theorem Extends.becomePreVoteCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.seq' fun _ =>
    Keeps.pure' (Extends.of_log rfl rfl)
  exact (Extends.becomeCandidate caps self _).mono fun _ kept =>
    (Extends.of_log rfl rfl).trans kept

private theorem Extends.act (state : NodeState) (input : Input)
    : Keeps (Extends state) (Model.Node.act caps self state input) := by
  split_rel input := (cases input) with
  | append =>
      rename_i entries
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := Extends state) (fun current entry kept =>
          Keeps.bind' (Extends.appendEntry caps self current entry.content)
            fun appended next => Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept)
              entry.flushes appended (kept.trans next))
          entries state (Extends.refl _))
        fun current kept => (Extends.advanced caps self current).mono fun _ next =>
          kept.trans next
  | sendEntries =>
      rename_i destination endIndex
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | timeout =>
      rename_i kind
      split_rel kind := (cases kind) with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Extends.becomePreVoteCandidate caps self state
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | nominateSuccessor =>
      exact (Keeps.nominateSuccessor caps self state).mono fun _ same =>
        same ▸ Extends.of_log rfl rfl
  | initAsBackup =>
      rename_i entries
      unfold Model.Node.act Model.Node.initAsBackup
      refine Keeps.bind' Keeps.guard' fun _ ⟨⟨_, _, empty, zero⟩, _⟩ => Keeps.pure' ?_
      exact ⟨
        by simp [becomeAwareOfNewTerm, zero],
        by simp [NodeState.committedLog, empty]
      ⟩

private theorem Extends.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Extends state) (Model.Node.receive caps self source state message) := by
  have observedExtends : Extends state (observeTerm state message) :=
    Extends.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observedExtends ⊢
  refine Keeps.mono (P := Extends current) ?_ fun _ next => observedExtends.trans next
  split_rel message := (cases message) with
  | appendEntriesRequest =>
      rename_i request
      exact Extends.handleAppendEntriesRequest caps source
  | appendEntriesResponse =>
      rename_i response
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.advanced caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestVoteRequest =>
      rename_i request
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by
        split_rel vote := (split) with
        | pos => exact Extends.of_log rfl rfl
        | neg => exact Extends.of_log rfl rfl)
  | requestVoteResponse =>
      rename_i response
      unfold Model.Node.handleRequestVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.electIfQuorum caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestPreVoteRequest =>
      rename_i request
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (Extends.refl _)
  | requestPreVoteResponse =>
      rename_i response
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      exact (Extends.becomeCandidate caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | proposeRequestVoteRequest =>
      rename_i term
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => Extends.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Extends.refl _)

end Handlers
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section Global
variable [Config.InitialConfiguration]

/-- From any state with distinct node identifiers, a step keeps every other node's
state and extends the actor's committed log. -/
private theorem committed_log_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (distinct : (before.nodes.map Prod.fst).Nodup)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    {node : NodeID} {beforeState afterState : NodeState}
    (beforeMember : (node, beforeState) ∈ before.nodes)
    (afterMember : (node, afterState) ∈ after.nodes)
    : beforeState.committedLog <+: afterState.committedLog := by
  have extended : forall {actor : NodeID} {old : NodeState}
      {new : NodeState},
      nodeState before actor = some old
      -> Extends old new
      -> (node, afterState) ∈ replaceNode before.nodes actor new
      -> beforeState.committedLog <+: afterState.committedLog := by
    intro actor old new found grown member
    split_rel mem_replaceNode := (rcases mem_replaceNode member with ⟨nodeEq, stateEq⟩ | ⟨other, listed⟩) with
    | inl =>
      subst nodeEq stateEq
      have same : beforeState = old :=
        Option.some.inj ((nodeState_of_mem distinct beforeMember).symm.trans found)
      subst same
      exact grown.committedLog
    | inr =>
      have same : afterState = beforeState :=
        Option.some.inj
          ((nodeState_of_mem distinct listed).symm.trans (nodeState_of_mem distinct beforeMember))
      subst same
      exact List.prefix_refl _
  split_rel action := (cases action) with
  | «local» =>
      rename_i actor input
      obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
      exact extended found (Extends.act _ actor old input _ _ _ acted) afterMember
  | deliver =>
      rename_i envelope
      obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
      exact extended found (Extends.receive _ _ old _ _ _ _ _ received) afterMember

/-- A node present before a step is present after it. -/
private theorem present_after_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    {node : NodeID} {beforeState : NodeState}
    (member : (node, beforeState) ∈ before.nodes)
    : exists afterState, (node, afterState) ∈ after.nodes := by
  have present : forall {actor : NodeID} {value : NodeState},
      exists afterState, (node, afterState) ∈ replaceNode before.nodes actor value := by
    intro actor value
    split_rel same := (by_cases same : node = actor) with
    | pos =>
      subst same
      exact ⟨value, List.mem_map.mpr ⟨_, member, by simp⟩⟩
    | neg => exact ⟨beforeState, List.mem_map.mpr ⟨_, member, by simp [same]⟩⟩
  split_rel action := (cases action) with
  | «local» =>
      rename_i actor input
      obtain ⟨_, _, _, _, _, rfl⟩ := step_local stepped
      exact present
  | deliver =>
      rename_i envelope
      obtain ⟨_, _, _, _, _, _, rfl⟩ := step_deliver stepped
      exact present

/-- A node's committed log at one state of a trace is a prefix of the same node's
committed log at every later state of the trace. -/
private theorem committed_log_later {nodes : List NodeID}
    {trace
      : CCF.Execution.Trace (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)}
    {index : Nat} {state : Model.State} (found : trace.stateAt index = some state)
    {node : NodeID} {firstState : NodeState} (member : (node, firstState) ∈ state.nodes)
    : forall offset later,
        trace.stateAt (index + offset) = some later
        -> exists laterState,
            (node, laterState) ∈ later.nodes
            /\ firstState.committedLog <+: laterState.committedLog := by
  intro offset
  split_rel offset := (induction offset) with
  | zero =>
      intro later atLater
      rw [Nat.add_zero, found] at atLater
      cases atLater
      exact ⟨firstState, member, List.prefix_refl _⟩
  | succ =>
      rename_i offset ih
      intro later atLater
      rw [← Nat.add_assoc] at atLater
      split_rel atMiddle := (cases atMiddle : trace.stateAt (index + offset)) with
      | none => simp [trace.states.le_stable (Nat.le_succ _) atMiddle] at atLater
      | some =>
          rename_i middle
          obtain ⟨middleState, middleMember, prefixed⟩ := ih middle atMiddle
          obtain ⟨action, stepped⟩ := trace.step (index + offset) middle later atMiddle atLater
          obtain ⟨laterState, laterMember⟩ := present_after_step stepped middleMember
          refine ⟨laterState, laterMember, prefixed.trans ?_⟩
          exact committed_log_step (keys_nodup (trace.reachable (CCF.Execution.Trace.stateAt_mem atMiddle)))
            stepped middleMember laterMember

end Global
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

/-- A fold that only moves its accumulator to elements satisfying `P` keeps any
property those moves keep. -/
private theorem foldl_select_step (P : Nat -> Nat -> Prop) [forall a b, Decidable (P a b)]
    (Q : Nat -> Prop) (values : List Nat) (init : Nat) (start : Q init)
    (step : forall acc value, value ∈ values -> Q acc -> P acc value -> Q value)
    : Q (values.foldl (fun acc value => if P acc value then value else acc) init) := by
  split_rel values := (induction values generalizing init) with
  | nil => exact start
  | cons =>
      rename_i head tail ih
      simp only [List.foldl_cons]
      refine ih _ ?_ fun acc value mem => step acc value (List.mem_cons_of_mem _ mem)
      split_rel selected := (split) with
      | isTrue => exact step init head (List.mem_cons.mpr (Or.inl rfl)) start ‹_›
      | isFalse => exact start

private theorem highestCommittableIndex_signature (state : NodeState) (self : NodeID)
    (ahead : state.commitIndex < highestCommittableIndex state self)
    : isSignatureAt state.log (highestCommittableIndex state self) = true := by
  have holds
      : highestCommittableIndex state self = state.commitIndex
        \/ isSignatureAt state.log (highestCommittableIndex state self) = true := by
    dsimp only [highestCommittableIndex]
    exact foldl_select_step _
      (fun index => index = state.commitIndex \/ isSignatureAt state.log index = true) _ _
      (Or.inl rfl) fun _ _ _ _ selected => Or.inr selected.2.1
  exact holds.resolve_left (Nat.ne_of_gt ahead)

private theorem AEFrom.extend {self : NodeID} {term commit commit' : Nat}
    {log log' : List Entry} {envelope : Model.Envelope}
    (sent : AEFrom self term commit log envelope) (extends_ : log <+: log')
    (le : commit <= commit')
    : AEFrom self term commit' log' envelope := by
  obtain ⟨source, target, request, payload, term, prev, prevTerm, entries, primaryCommit⟩ := sent
  refine ⟨source, target, request, payload, term, Nat.le_trans prev extends_.length_le, ?_, ?_,
    Nat.le_trans primaryCommit le⟩
  · rw [prevTerm, termAt_of_prefix extends_ prev]
  · obtain ⟨rest, rfl⟩ := extends_
    rw [List.drop_append_of_le_length prev]
    exact entries.trans (List.prefix_append _ _)

private theorem AEFrom.ok {self : NodeID} {state : NodeState}
    {envelope : Model.Envelope}
    (sent : AEFrom self state.currentTerm state.commitIndex state.log envelope)
    : exists request,
        envelope.payload = .appendEntriesRequest request
        /\ AEOk self envelope.target state request := by
  obtain ⟨_, target, request, payload, term, prev, prevTerm, entries, primaryCommit⟩ := sent
  exact ⟨request, payload, target, term, prev, prevTerm, entries, primaryCommit⟩

private theorem Advance.log {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.log = middle.log :=
  advance.1

private theorem Advance.term {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.currentTerm = middle.currentTerm :=
  advance.2.1

private theorem Advance.votedFor {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.votedFor = middle.votedFor :=
  advance.2.2.1

private theorem Advance.matchIndex {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.matchIndex = middle.matchIndex :=
  advance.2.2.2.1

private theorem Advance.sentIndex {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.sentIndex = middle.sentIndex :=
  advance.2.2.2.2.1

private theorem Advance.votesGranted {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.votesGranted = middle.votesGranted :=
  advance.2.2.2.2.2.1

private theorem Advance.role {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.role = middle.role \/ state.role = .none :=
  advance.2.2.2.2.2.2.1

/-- The role is the old one unless committing a retirement cleared it. -/
private theorem Advance.role_kept {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state) (kept : Not (state.role = .none))
    : state.role = middle.role :=
  advance.role.resolve_right kept

private theorem Advance.commit_le {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : middle.commitIndex <= state.commitIndex :=
  advance.2.2.2.2.2.2.2.1

private theorem Advance.commit_eq {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state) (ahead : middle.commitIndex < state.commitIndex)
    : state.commitIndex = highestCommittableIndex middle self :=
  advance.2.2.2.2.2.2.2.2 ahead

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node
section Effects
variable (self : NodeID)

private theorem nominate_sends (state : NodeState) (excluded : Finset NodeID := ∅)
    : Sends
        (fun result sent =>
          result = state
          /\ state.role = .primary
          /\ forall e,
              e ∈ sent
              -> e.source = self
                  /\ e.payload = .proposeRequestVoteRequest state.currentTerm)
        (nominateSuccessor (Capabilities.record self : Caps) state self excluded) := by
  unfold nominateSuccessor
  refine Sends.bind' Sends.guard' fun _ _ ⟨leader, empty⟩ => ?_
  subst empty
  split_rel successor := (split) with
  | some =>
    exact Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
      Sends.pure' ⟨rfl, leader, by simp [eq]⟩
  | none => exact Sends.pure' ⟨rfl, leader, by simp⟩

private theorem advanceCommit_sends (middle : NodeState)
    : Sends
        (fun state sent =>
          Advance self middle state
          /\ forall e,
              e ∈ sent
              -> e.source = self
                  /\ e.payload = .proposeRequestVoteRequest middle.currentTerm)
        (advanceCommit (Capabilities.record self : Caps) middle self) := by
  unfold advanceCommit
  dsimp only
  refine Sends.ite'
    (fun _ => Sends.pure'
      ⟨⟨rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl, Nat.le.refl, fun lt => (Nat.lt_irrefl _ lt).elim⟩,
        by simp⟩)
    fun ahead => ?_
  have advanced : Advance self middle
      (middle.recordCommit self (highestCommittableIndex middle self)) := by
    obtain ⟨_, _, _, eq, roleCase⟩ :=
      NodeState.recordCommit_eq self middle (highestCommittableIndex middle self)
    rw [eq]
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, roleCase, Nat.le_of_lt (Nat.lt_of_not_le ahead),
      fun _ => rfl⟩
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' ⟨advanced, by simp⟩)
    fun _ => Sends.pure' ⟨advanced, by simp⟩
  exact Sends.bind' (nominate_sends self middle _)
    fun _ sent nominated =>
      Sends.pure' ⟨advanced, by simpa using nominated.2.2⟩

private theorem broadcast_sends (state : NodeState) (message : Message)
    : Sends
        (fun _ sent =>
          forall e,
            e ∈ sent -> e.source = self /\ Not (e.target = self) /\ e.payload = message)
        (broadcastToOthers (Capabilities.record self : Caps) self state message) := by
  unfold broadcastToOthers
  refine Sends.bind'
    (Sends.forIn'
      (R := fun e => e.source = self /\ Not (e.target = self) /\ e.payload = message)
      fun peer _ member => ?_)
    fun _ sent done => Sends.pure' (by simpa using done)
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ⟨⟨_, rfl⟩, ?_⟩
  have : Not (peer = self) := by simp [Finset.mem_sort] at member; exact member.1
  simp [eq, this]

private theorem becomePrimary_sends (candidate : NodeState)
    : Sends
        (fun state sent =>
          Advance self (primaryState candidate) state
          /\ LeaderStart self candidate.currentTerm state sent)
        (becomePrimary (Capabilities.record self : Caps) self candidate) := by
  unfold becomePrimary
  refine Sends.bind' (advanceCommit_sends self _)
    fun leader sent ⟨advance, nominated⟩ => ?_
  refine Sends.bind' (Q := fun _ later => forall e, e ∈ later ->
      AEFrom self leader.currentTerm leader.commitIndex leader.log e)
    (Sends.forIn' fun peer _ member => ?_) fun _ later beats =>
      Sends.pure' ⟨advance, sent, later, by simp,
        fun e member => ⟨(nominated e member).1,
          by simpa [primaryState] using (nominated e member).2⟩, beats⟩
  · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
      Sends.pure' ⟨⟨_, rfl⟩, fun e member => ?_⟩
    simp only [eq, List.append_nil, List.mem_singleton] at member
    subst member
    have other : Not (peer = self) := by simp [Finset.mem_sort, eligiblePeers] at member; exact member.1
    have sentEq : leader.sentIndex peer = leader.log.length := by
      rw [advance.sentIndex, advance.log]
      simp [primaryState]
    refine ⟨rfl, other, _, rfl, rfl, ?_, rfl, ?_, Nat.le.refl⟩ <;>
      simp [makeAppendEntriesRequest, sentEq, messageEntries]

/-- Electing on a quorum leaves the candidate unchanged or makes it the leader. -/
private theorem electIfQuorum_sends (candidate : NodeState)
    : Sends (fun state sent => Outcome self candidate state sent)
        (electIfQuorum (Capabilities.record self : Caps) self candidate) := by
  unfold electIfQuorum
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (Or.inl ⟨rfl, rfl⟩)
  exact Sends.mono (becomePrimary_sends self candidate) fun _ _ done =>
    Or.inr ⟨won.2.1, done⟩

/-- A fresh candidate also broadcasts its vote request. -/
private theorem becomeCandidate_result (state : NodeState)
    (before : NodeState) (term : state.currentTerm = before.currentTerm)
    : Sends
        (fun next sent =>
          CampaignResult self before (freshCandidate self state) next sent)
        (becomeCandidate (Capabilities.record self : Caps) state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_sends self (freshCandidate self state))
    fun next sent outcome => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ later requests => Sends.pure' ?_
  have lt : before.currentTerm < (freshCandidate self state).currentTerm := by
    simp [freshCandidate, term]
  exact ⟨sent, later, by simp,
    fun e member => ⟨(requests e member).1, (requests e member).2.2, lt⟩, outcome⟩

end Effects
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

private theorem campaign_summary {self : NodeID} {before candidate after : NodeState}
    {event : Event} {sent : List Model.Envelope}
    (campaign : Campaign self before event candidate)
    (start : CampaignStart before candidate)
    (result : CampaignResult self before candidate after sent)
    (electing : Electing event)
    : Summary self before event after sent := by
  obtain ⟨termLe, engaged, notLeaderKeep, voteKeep⟩ := start
  obtain ⟨started, requests, rfl, requested, outcome⟩ := result
  have request : forall e, e ∈ requests -> after.currentTerm = candidate.currentTerm
      -> (after.role = .candidate -> after = candidate)
      -> SendOK self before event after e := by
    intro e member termEq same
    obtain ⟨source, payload, lt⟩ := requested e member
    refine ⟨source, ?_⟩
    rw [payload]
    exact ⟨termEq.symm, termEq ▸ lt, fun role => by rw [same role]⟩
  split_rel result := (rcases outcome with ⟨afterEq, nothing⟩ | ⟨quorum, advance, leaderStart⟩) with
  | inl =>
    subst afterEq nothing
    exact ⟨termLe, voteKeep, fun _ => Or.inl engaged, fun _ => Or.inl engaged, fun _ => campaign,
      fun leader => (by rw [campaign.1] at leader; cases leader),
      fun _ leader same => (notLeaderKeep ⟨leader, same⟩).elim,
      Kind.same campaign.2.1 campaign.2.2.1,
      fun e member => request e (by simpa using member) rfl fun _ => rfl⟩
  | inr =>
    obtain ⟨nominated, beats, rfl, nominations, heartbeats⟩ := leaderStart
    have termEq : after.currentTerm = candidate.currentTerm := by
      rw [advance.term]; rfl
    have elected : Wins self before event after :=
      ⟨candidate, campaign, quorum, advance, electing⟩
    have notCandidate : Not (after.role = .candidate) := fun candidate' => by
      have kept := advance.role_kept (by rw [candidate']; simp)
      rw [candidate'] at kept
      simp [primaryState] at kept
    refine ⟨termEq ▸ termLe, fun same voted votedEq => ?_, fun _ => Or.inl engaged, fun _ => Or.inl engaged,
      fun candidate' => (notCandidate candidate').elim, fun _ => Or.inr elected,
      fun _ leader same => (notLeaderKeep ⟨leader, termEq ▸ same⟩).elim,
      Kind.elect elected, fun e member => ?_⟩
    · rw [advance.votedFor]
      exact voteKeep (termEq ▸ same) voted votedEq
    · split_rel sent := (rcases List.mem_append.mp member with start | requested) with
      | inl =>
        split_rel started := (rcases List.mem_append.mp start with nominated | beat) with
        | inl =>
          obtain ⟨source, payload⟩ := nominations e nominated
          refine ⟨source, ?_⟩
          rw [payload]
          exact termEq.symm
        | inr =>
          have beat := heartbeats e beat
          obtain ⟨request, payload, ok⟩ := beat.ok
          refine ⟨beat.1, ?_⟩
          rw [payload]
          exact ⟨ok, notCandidate, Or.inr elected⟩
      | inr => exact request e requested termEq fun role => (notCandidate role).elim

private theorem quiet_summary {self : NodeID} {before after : NodeState}
    {event : Event} {sent : List Model.Envelope}
    (role : after.role = before.role) (term : after.currentTerm = before.currentTerm)
    (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
    (voted : after.votedFor = before.votedFor)
    (votes : after.votesGranted = before.votesGranted)
    (matchEq : after.matchIndex = before.matchIndex)
    (bumps
      : (exists envelope, envelope ∈ sent /\ Bumping envelope.payload)
        -> Activated before event after)
    (sends : forall e, e ∈ sent -> SendOK self before event after e)
    : Summary self before event after sent :=
  ⟨
    Nat.le_of_eq term.symm,
    fun _ voted' votedEq => voted ▸ votedEq,
    fun engaged => Or.inl (by simpa only [Engaged, role, term, log] using engaged),
    bumps,
    fun candidate =>
      ⟨
        candidate,
        log,
        commit,
        Or.inr
          ⟨
            role ▸ candidate,
            term,
            Or.inr voted.symm,
            fun voter member fresh => absurd (votes ▸ member) fresh
          ⟩
      ⟩,
    fun leader => Or.inl ⟨role ▸ leader, term⟩,
    fun _ _ _ => Or.inl matchEq,
    Kind.same log commit,
    sends
  ⟩

/-- No envelope in an empty send list is a term-bumping message. -/
private theorem no_bumping_sends {P : Prop}
    : (exists envelope, envelope ∈ ([] : List Model.Envelope) /\ Bumping envelope.payload)
      -> P :=
  fun ⟨_, member, _⟩ => by simp at member

private theorem bumped_summary {self : NodeID} {before after : NodeState}
    {event : Event} {sent : List Model.Envelope}
    (lt : before.currentTerm < after.currentTerm)
    (notCandidate : Not (after.role = .candidate))
    (notLeader : Not (after.role = .primary))
    (active
      : exists source message,
          event = .receive source message
          /\ Bumping message
          /\ message.term <= after.currentTerm)
    (kind : Kind self before event after)
    (sends : forall e, e ∈ sent -> SendOK self before event after e)
    : Summary self before event after sent :=
  ⟨
    Nat.le_of_lt lt,
    fun same => (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt (Nat.le_of_eq same))).elim,
    fun _ => Or.inr (Or.inr (Or.inl active)), fun _ => Or.inr (Or.inr (Or.inl active)),
    fun candidate => (notCandidate candidate).elim,
    fun leader => (notLeader leader).elim,
    fun leader => (notLeader leader).elim,
    kind,
    sends
  ⟩

/-- A message that always carries its sender's term either bumps the receiver to that term
or leaves it unchanged. The receiver observes the term once, before any handler runs, so
every handler reads the outcome here. -/
private theorem observe_bumping {motive : NodeState -> Prop} (before : NodeState)
    {message : Message}
    (bumping : observeTerm before message = updateTerm before message.term)
    (bumped : before.currentTerm < message.term -> motive (bumpedState before message.term))
    (same : message.term <= before.currentTerm -> motive before)
    : motive (observeTerm before message) := by
  rw [bumping]
  split_rel bump := (by_cases bump : before.currentTerm < message.term) with
  | pos =>
    have eq : updateTerm before message.term = bumpedState before message.term := by
      simp [updateTerm, bump, becomeAwareOfNewTerm, bumpedState, Nat.ne_of_lt bump]
    rw [eq]
    exact bumped bump
  | neg =>
    have eq : updateTerm before message.term = before := by simp [updateTerm, bump]
    rw [eq]
    exact same (Nat.not_lt.mp bump)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node
section Election
variable (self : NodeID)

/-- A node that can start an election has a ledger, so it is engaged. -/
private theorem canStartElection_engaged {state : NodeState} {self : NodeID}
    (can : canStartElection state self)
    : Engaged state := by
  refine ⟨fun none => ?_, fun ⟨_, _, empty⟩ => ?_⟩
  · -- None of the three roles that may campaign is `none`.
    split_rel role := (rcases can.1 with eq | eq | eq) with
    | inl => rw [none] at eq; cases eq
    | inr_inl => rw [none] at eq; cases eq
    | inr_inr => rw [none] at eq; cases eq
  split_rel can := (rcases can.2.1 with member | member) with
  | inl =>
    simp [empty, NodeState.signedActiveConfigurations, NodeState.activeConfigurations,
      activeConfigurations, configurationHistory, configurationMembers] at member
  | inr =>
    simp [empty, configurationHistory, configurationMembers,
      NodeState.retirementCompletedNodes, NodeState.committedLog] at member

private theorem fresh_campaign {self : NodeID} {before state : NodeState}
    {event : Event} (active : Engaged before)
    (term : state.currentTerm = before.currentTerm) (log : state.log = before.log)
    (commit : state.commitIndex = before.commitIndex)
    : Campaign self before event (freshCandidate self state) := by
  refine ⟨rfl, log, commit, Or.inl ⟨active, ?_, rfl, rfl⟩⟩
  simp [freshCandidate, term]

/-- A fresh campaign starts from an engaged node, one term earlier. -/
private theorem fresh_start {self : NodeID} {before state : NodeState}
    (active : Engaged before) (term : state.currentTerm = before.currentTerm)
    : CampaignStart before (freshCandidate self state) := by
  have next : (freshCandidate self state).currentTerm = before.currentTerm + 1 := by
    simp [freshCandidate, term]
  exact ⟨next ▸ Nat.le_succ _, active,
    fun ⟨_, same⟩ => Nat.succ_ne_self _ (next.symm.trans same),
    fun same => (Nat.succ_ne_self _ (next.symm.trans same)).elim⟩

private theorem checkQuorum_summary (state : NodeState) (input : Input)
    : Sends (fun after sent => Summary self state (.internal input) after sent)
        (checkQuorum state self) := by
  unfold checkQuorum
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => Sends.pure' ?_
  subst empty
  refine ⟨
    Nat.le.refl,
    fun _ voted eq => eq,
    fun _ => Or.inl (by simp [Engaged, leader]), fun _ => Or.inl (by simp [Engaged, leader]),
    fun c => by simp at c,
    fun c => by simp at c,
    fun c => by simp at c,
    Kind.same rfl rfl,
    by simp
  ⟩

private theorem nominate_summary (state : NodeState)
    : Sends
        (fun after sent => Summary self state (.internal .nominateSuccessor) after sent)
        (act (Capabilities.record self : Caps) self state .nominateSuccessor) := by
  refine Sends.mono (nominate_sends self state) fun _ sent ⟨same, leader, nominated⟩ => ?_
  subst same
  refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
    (fun _ => Or.inl (by simp [Engaged, leader])) fun e member => ?_
  obtain ⟨source, payload⟩ := nominated e member
  refine ⟨source, ?_⟩
  rw [payload]
  rfl

private theorem sendEntries_summary (state : NodeState) (destination : NodeID)
    (endIndex : Nat)
    : Sends
        (fun after sent =>
          Summary self state (.internal (.sendEntries destination endIndex)) after sent)
        (sendEntries (Capabilities.record self : Caps) self state destination
          endIndex) := by
  unfold sendEntries
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, peer, le, bound, _⟩, empty⟩ => ?_
  subst empty
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  subst eq
  refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
    (fun _ => Or.inl (by simp [Engaged, leader])) fun e member => ?_
  simp only [List.nil_append, List.append_nil, List.mem_singleton] at member
  subst member
  have other : Not (destination = self) := by
    simp [eligiblePeers] at peer; exact peer.1
  refine ⟨
    rfl,
    ⟨other, rfl, Nat.le_trans le bound, rfl, ?_, Nat.le.refl⟩,
    by simp [leader],
    Or.inl ⟨leader, rfl⟩
  ⟩
  exact List.take_prefix _ _

private theorem startElection_summary (state : NodeState)
    : Sends
        (fun after sent => Summary self state (.internal (.timeout .election)) after sent)
        (startElection (Capabilities.record self : Caps) state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨can, empty⟩ => ?_
  subst empty
  have engaged := canStartElection_engaged can
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · exact Sends.mono (becomeCandidate_result self _ state rfl) fun after sent result =>
      campaign_summary (fresh_campaign engaged rfl rfl rfl) (fresh_start engaged rfl) result
        trivial
  · refine Sends.bind' (broadcast_sends self _ _) fun _ sent requests => Sends.pure' ?_
    simp only [List.append_nil]
    refine ⟨Nat.le.refl, fun _ voted eq => eq, fun _ => Or.inl engaged, fun _ => Or.inl engaged, fun c => by simp at c,
      fun c => by simp at c, fun c => by simp at c, Kind.same rfl rfl, fun e member => ?_⟩
    obtain ⟨source, _, payload⟩ := requests e member
    refine ⟨source, ?_⟩
    rw [payload]
    rfl

private theorem voteRequest_summary (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestVoteRequest request)) after sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestVoteRequest request)) := by
  simp only [receive]
  refine observe_bumping
    (motive := fun z => Sends _ (handleRequestVoteRequest (Capabilities.record self) z source request))
    before (message := .requestVoteRequest request) rfl (fun bump => ?_) (fun le => ?_)
  · simp only [handleRequestVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have active : exists source' message,
        Event.receive source (Message.requestVoteRequest request)
          = (Event.receive source' message : Event)
        /\ Bumping message /\ message.term <= (bumpedState before request.term).currentTerm :=
      ⟨source, _, rfl, trivial, Nat.le.refl⟩
    split_rel granted := (split) with
    | pos =>
      rename_i granted
      simp only [decide_eq_true_eq] at granted
      refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState]) active
        (Kind.same rfl rfl) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun _ => ⟨request, rfl, granted.1, granted.2.1, rfl⟩⟩
    | neg =>
      rename_i granted
      simp only [decide_eq_true_eq] at granted
      refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState]) active
        (Kind.same rfl rfl) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun yes => by simp_all⟩
  · simp only [handleRequestVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have active : exists source' message,
        Event.receive source (Message.requestVoteRequest request)
          = (Event.receive source' message : Event)
        /\ Bumping message /\ message.term <= before.currentTerm :=
      ⟨source, _, rfl, trivial, le⟩
    split_rel granted := (split) with
    | pos =>
      rename_i granted
      simp only [decide_eq_true_eq] at granted
      refine ⟨Nat.le.refl, fun _ voted votedEq => ?_, fun _ => Or.inr (Or.inr (Or.inl active)), fun _ => Or.inr (Or.inr (Or.inl active)),
        fun candidate => ⟨candidate, rfl, rfl, Or.inr ⟨candidate, rfl, granted.2.2.2,
          fun voter member fresh => absurd member fresh⟩⟩,
        fun leader => Or.inl ⟨leader, rfl⟩, fun _ _ _ => Or.inl rfl, Kind.same rfl rfl,
        fun e member => ?_⟩
      · split_rel granted := (rcases granted.2.2.2 with none | some) with
        | inl => rw [none] at votedEq; cases votedEq
        | inr => rw [some] at votedEq; exact votedEq
      · simp at member
        subst member
        exact ⟨rfl, rfl, fun _ => ⟨request, rfl, granted.1, granted.2.1, rfl⟩⟩
    | neg =>
      rename_i granted
      simp only [decide_eq_true_eq] at granted
      refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
        (fun _ => Or.inr (Or.inr (Or.inl active))) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun yes => by simp_all⟩

private theorem preVoteRequest_summary (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestPreVoteRequest request)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestPreVoteRequest request)) := by
  simp only [receive]
  refine observe_bumping
    (motive := fun z => Sends _ (handleRequestPreVoteRequest (Capabilities.record self) z source request))
    before (message := .requestPreVoteRequest request) rfl (fun bump => ?_) (fun le => ?_)
  · simp only [handleRequestPreVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
      ⟨source, _, rfl, trivial, Nat.le.refl⟩ (Kind.same rfl rfl) fun e member => ?_
    simp only [List.mem_singleton, List.append_nil] at member
    subst member
    exact ⟨rfl, rfl⟩
  · simp only [handleRequestPreVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
      (fun _ => Or.inr (Or.inr (Or.inl ⟨source, _, rfl, trivial, le⟩))) fun e member => ?_
    simp only [List.mem_singleton, List.append_nil] at member
    subst member
    exact ⟨rfl, rfl⟩

private theorem proposeVote_summary (before : NodeState) (source : NodeID) (term : Nat)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.proposeRequestVoteRequest term)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  refine Sends.ite' (fun start => ?_)
    fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp))
  have engaged := canStartElection_engaged start.2
  exact Sends.mono (becomeCandidate_result self before before rfl)
    fun after sent result =>
      campaign_summary (fresh_campaign engaged rfl rfl rfl) (fresh_start engaged rfl) result
        trivial

/-- A fresh node installs a snapshot, which may be empty. -/
private theorem initAsBackup_summary (before : NodeState) (entries : List Entry)
    : Sends
        (fun after sent =>
          Summary self before (.internal (.initAsBackup entries)) after sent)
        (initAsBackup before entries : NodeEffect NodeState) := by
  unfold initAsBackup
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨fresh, signed⟩, empty⟩ => Sends.pure' ?_
  subst empty
  obtain ⟨none, zero, emptyLog, noCommit⟩ := fresh
  have signature (positive : 0 < entries.length)
      : isSignatureAt entries entries.length = true := by
    split_rel signed := (rcases signed with nil | signature) with
    | inl =>
      subst nil
      simp at positive
    | inr => exact signature
  refine ⟨by simp [becomeAwareOfNewTerm, zero], fun same voted eq => ?_, fun engaged => ?_,
    no_bumping_sends,
    fun c => by simp [becomeAwareOfNewTerm] at c, fun c => by simp [becomeAwareOfNewTerm] at c,
    fun c => by simp [becomeAwareOfNewTerm] at c,
    Kind.install entries rfl signature ⟨none, zero, emptyLog, noCommit⟩
      (by simp [becomeAwareOfNewTerm]) (by simp [becomeAwareOfNewTerm])
      (by simp [becomeAwareOfNewTerm]) (by simp [becomeAwareOfNewTerm]), by simp⟩
  · -- The term is unchanged, so the vote is.
    have kept : before.currentTerm = termAt entries entries.length := by
      simpa [becomeAwareOfNewTerm] using same.symm
    simpa [becomeAwareOfNewTerm, kept] using eq
  · -- A node engaged after an empty snapshot would still be a follower in term zero.
    have positive : 0 < entries.length := Nat.pos_of_ne_zero fun length => by
      have nil : entries = [] := List.eq_nil_of_length_eq_zero length
      subst nil
      exact engaged.2 ⟨by simp [becomeAwareOfNewTerm],
        by simp [becomeAwareOfNewTerm, termAt, entryAt?], by simp [becomeAwareOfNewTerm]⟩
    exact Or.inr (Or.inr (Or.inr ⟨entries, rfl, positive, signature positive,
      by simp [becomeAwareOfNewTerm]⟩))

private theorem voteResponse_summary (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestVoteResponse response)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  refine observe_bumping
    (motive := fun z => Sends _ (handleRequestVoteResponse (Capabilities.record self) self z source response))
    before (message := .requestVoteResponse response) rfl (fun bump => ?_) (fun le => ?_)
  · simp only [handleRequestVoteResponse]
    refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
        ⟨source, _, rfl, trivial, Nat.le.refl⟩ (Kind.same rfl rfl) (by simp))
  · simp only [handleRequestVoteResponse]
    refine Sends.ite' (fun won => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        no_bumping_sends (by simp))
    have campaign : Campaign self before (.receive source (.requestVoteResponse response))
        { before with votesGranted := insert source before.votesGranted } := by
      refine ⟨won.1, rfl, rfl, Or.inr ⟨won.1, rfl, Or.inr rfl, fun voter member fresh => ?_⟩⟩
      split_rel mem_insert := (rcases Finset.mem_insert.mp member with same | old) with
      | inl =>
        subst same
        exact ⟨response, rfl, won.2.1, won.2.2⟩
      | inr => exact absurd old fresh
    exact Sends.mono (electIfQuorum_sends self _) fun after sent outcome =>
      campaign_summary campaign
        ⟨Nat.le.refl, by simp [Engaged, won.1], fun ⟨leader, _⟩ => by simp [won.1] at leader,
          fun _ _ voted => voted⟩
        ⟨sent, [], (List.append_nil sent).symm, by simp, outcome⟩ trivial

private theorem preVoteResponse_summary (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestPreVoteResponse response)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  refine observe_bumping
    (motive := fun z => Sends _ (handleRequestPreVoteResponse (Capabilities.record self) self z source response))
    before (message := .requestPreVoteResponse response) rfl (fun bump => ?_) (fun le => ?_)
  · simp only [handleRequestPreVoteResponse]
    refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
        ⟨source, _, rfl, trivial, Nat.le.refl⟩ (Kind.same rfl rfl) (by simp))
  · simp only [handleRequestPreVoteResponse]
    refine Sends.ite' (fun won => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        no_bumping_sends (by simp))
    have engaged : Engaged before := by simp [Engaged, won.1]
    refine Sends.ite' (fun _ => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        no_bumping_sends (by simp))
    exact Sends.mono (becomeCandidate_result self _ before rfl) fun after sent result =>
      campaign_summary (fresh_campaign engaged rfl rfl rfl) (fresh_start engaged rfl) result
        trivial

/-- Only a primary observes the term of an AppendEntries response. -/
private theorem observe_response (before : NodeState) (response : AppendEntriesResponse)
    (follower : Not (before.role = .primary))
    : observeTerm before (.appendEntriesResponse response) = before := by
  simp [observeTerm, follower]

/-- A response handled in the receiver's own term. -/
private theorem appendEntriesResponse_quiet (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesResponse response)) after
            sent)
        (handleAppendEntriesResponse (Capabilities.record self : Caps) self before source
          response) := by
  simp only [handleAppendEntriesResponse]
  have quiet := fun (after : NodeState) (role : after.role = before.role)
      (term : after.currentTerm = before.currentTerm) (log : after.log = before.log)
      (commit : after.commitIndex = before.commitIndex)
      (voted : after.votedFor = before.votedFor)
      (votes : after.votesGranted = before.votesGranted)
      (matchEq : after.matchIndex = before.matchIndex) =>
    quiet_summary (self := self) (event := .receive source (.appendEntriesResponse response))
      (sent := []) role term log commit voted votes matchEq
      no_bumping_sends (by simp)
  refine Sends.ite' (fun _ => Sends.pure' (quiet before rfl rfl rfl rfl rfl rfl rfl))
    fun leader => ?_
  simp only [bne_iff_ne, ne_eq, Decidable.not_not] at leader
  refine Sends.ite' (fun success => ?_) fun _ =>
    Sends.pure' (quiet _ rfl rfl rfl rfl rfl rfl rfl)
  refine Sends.ite' (fun term => ?_) fun _ => Sends.pure' (quiet before rfl rfl rfl rfl rfl rfl rfl)
  refine Sends.mono (advanceCommit_sends self _) fun after sent ⟨advance, nominated⟩ => ?_
  have notCandidate : Not (after.role = .candidate) := fun candidate => by
    have kept := advance.role_kept (by rw [candidate]; simp)
    rw [candidate] at kept
    simp [leader] at kept
  refine ⟨Nat.le_of_eq advance.term.symm, fun _ voted eq => by rw [advance.votedFor]; exact eq,
    fun _ => Or.inl (by simp [Engaged, leader]), fun _ => Or.inl (by simp [Engaged, leader]), fun c => (notCandidate c).elim,
    fun _ => Or.inl ⟨leader, advance.term⟩,
    fun _ _ _ => Or.inr ⟨source, response, rfl, success, term, advance.matchIndex⟩,
    Kind.ack source response rfl leader success term advance, fun e member => ?_⟩
  obtain ⟨source', payload⟩ := nominated e member
  refine ⟨source', ?_⟩
  rw [payload]
  exact advance.term.symm

private theorem appendEntriesResponse_summary (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesResponse response)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  split_rel leader := (by_cases leader : before.role = .primary) with
  | pos =>
    refine observe_bumping
      (motive := fun z => Sends _
        (handleAppendEntriesResponse (Capabilities.record self) self z source response))
      before (message := .appendEntriesResponse response)
      (by simp [observeTerm, leader, Message.term]) (fun bump => ?_)
      (fun _ => appendEntriesResponse_quiet self before source response)
    simp only [handleAppendEntriesResponse]
    refine Sends.ite' (fun _ => Sends.pure' ?_) fun notFollower => absurd notFollower
      (by simp [bumpedState])
    refine ⟨Nat.le_of_lt bump,
      fun same => (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le bump (Nat.le_of_eq same))).elim,
      fun _ => Or.inl (by simp [Engaged, leader]), fun _ => Or.inl (by simp [Engaged, leader]), fun c => by simp [bumpedState] at c,
      fun c => by simp [bumpedState] at c, fun c => by simp [bumpedState] at c,
      Kind.same rfl rfl, by simp⟩
  | neg =>
    rw [observe_response before response leader]
    exact appendEntriesResponse_quiet self before source response

end Election
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

private theorem fromLeader_spec (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : let result := handleAppendEntiresFromPrimary self state request
      result.1.currentTerm = state.currentTerm
      /\ result.1.votedFor = state.votedFor
      /\ result.1.matchIndex = state.matchIndex
      /\ result.1.votesGranted = state.votesGranted
      /\ (Not (result.1.role = .none) -> result.1.role = state.role)
      /\ result.1.log
          = state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      /\ result.1.commitIndex
          = max state.commitIndex
              (maxCommittableIndexUpTo result.1.log
                (min request.primaryCommit
                  (request.prevLogIndex + request.entries.length)))
      /\ result.2
          = {
            term := state.currentTerm,
            success := true,
            lastLogIndex := request.prevLogIndex + request.entries.length
          } := by
  obtain ⟨_, _, _, eq, roleCase⟩ := Ledger.handleAppendEntiresFromPrimary_eq self state request
  simp [eq]
  exact roleCase

private theorem aeReply (self source : NodeID) (before z : NodeState)
    (r : AppendEntriesRequest) (le : r.term <= z.currentTerm)
    (zLog : z.log = before.log) (zCommit : z.commitIndex = before.commitIndex)
    (termLe : before.currentTerm <= z.currentTerm)
    : Sends (AEReply self source before z r)
        (handleAppendEntriesRequest (Capabilities.record self) self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have wTerm : w.currentTerm = z.currentTerm := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => rename_i h; simp [becomeAwareOfNewTerm, h.1]
    | neg => rfl
  have wLog : w.log = z.log := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => rfl
    | neg => rfl
  have wCommit : w.commitIndex = z.commitIndex := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => rfl
    | neg => rfl
  have wVoted : w.votedFor = z.votedFor := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => rename_i h; simp [becomeAwareOfNewTerm, h.1]
    | neg => rfl
  have wMatch : w.matchIndex = z.matchIndex := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => rfl
    | neg => rfl
  have wLead : w.role = .primary -> z.role = .primary := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => simp [becomeAwareOfNewTerm]
    | neg => exact id
  have wCand : w.role = .candidate -> w = z := by
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => simp [becomeAwareOfNewTerm]
    | neg => intro _; rfl
  have wSame : r.term = z.currentTerm -> Not (w.role = .candidate) := by
    intro same
    rw [← hw]
    split_rel stepDown := (split) with
    | pos => simp [becomeAwareOfNewTerm]
    | neg =>
      rename_i keep
      intro role
      exact keep ⟨same, by simp [role]⟩
  have common := fun (after : NodeState) (sent : List Model.Envelope)
      (rest : Kind self before (.receive source (.appendEntriesRequest r)) after
        /\ forall e, e ∈ sent
          -> SendOK self before (.receive source (.appendEntriesRequest r)) after e)
      (term : after.currentTerm = w.currentTerm) (voted : after.votedFor = w.votedFor)
      (matchEq : after.matchIndex = w.matchIndex)
      (role : Not (after.role = .none) -> after.role = w.role)
      (cand : after.role = .candidate -> after = w) =>
    (⟨term.trans wTerm, voted.trans wVoted, matchEq.trans wMatch,
      fun leader => wLead ((role (by rw [leader]; simp)).symm.trans leader),
      fun c => (cand c).trans (wCand ((role (by rw [c]; simp)).symm.trans c)), rest⟩
      : AEReply self source before z r after sent)
  -- The log and commit index are unchanged and every reply is a rejection.
  have quiet := fun (after : NodeState) (sent : List Model.Envelope)
      (log : after.log = z.log) (commit : after.commitIndex = z.commitIndex)
      (nacks : forall e, e ∈ sent -> e.source = self /\ exists response,
        e.payload = .appendEntriesResponse response /\ response.success = false) =>
    (⟨Kind.same (log.trans zLog) (commit.trans zCommit), fun e member => by
        obtain ⟨source', response, payload, failed⟩ := nacks e member
        refine ⟨source', ?_⟩
        rw [payload]
        intro success
        rw [failed] at success
        cases success⟩
      : Kind self before (.receive source (.appendEntriesRequest r)) after
        /\ forall e, e ∈ sent
          -> SendOK self before (.receive source (.appendEntriesRequest r)) after e)
  refine Sends.ite' (fun reject => ?_) fun accept => ?_
  · have nack : forall payload, (exists response, payload = Message.appendEntriesResponse response
        /\ response.success = false) -> Sends (AEReply self source before z r)
        (do (Capabilities.record self).send payload source; pure w
          : NodeEffect _) :=
      fun payload isNack => Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' (by
        subst eq
        refine common w _ (quiet w _ wLog wCommit fun e member => ?_) rfl rfl rfl
          (fun _ => rfl) fun _ => rfl
        simp at member
        subst member
        exact ⟨rfl, isNack⟩)
    exact Sends.ite' (fun _ => nack _ ⟨_, rfl, rfl⟩) fun _ => nack _ ⟨_, rfl, rfl⟩
  have same : r.term = z.currentTerm := Nat.le_antisymm le
    (Nat.le_trans (Nat.le_of_eq wTerm.symm) (Nat.le_of_not_lt fun lt => accept (Or.inl lt)))
  have notCand := wSame same
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (common _ [] (quiet _ [] wLog wCommit (by simp))
          rfl rfl rfl (fun _ => rfl) fun c => (notCand c).elim))
    fun go => ?_
  have matches_ : appendEntryMatchesLog z r := by
    have m : appendEntryMatchesLog w r := Classical.not_not.mp (not_or.mp accept).2
    unfold appendEntryMatchesLog at m ⊢
    rw [wLog] at m
    exact m
  have commitLe : z.commitIndex <= r.prevLogIndex := by
    rw [← wCommit]
    exact Nat.le_of_not_lt fun lt => go (Or.inl lt)
  have tail : forall v : NodeState,
      v.log
          = (match conflictIndex z.log r with
            | some index => z.log.take (index - 1)
            | none => z.log)
      -> v.currentTerm = w.currentTerm -> v.commitIndex = w.commitIndex
      -> v.votedFor = w.votedFor -> v.matchIndex = w.matchIndex -> v.role = w.role
      -> Sends (AEReply self source before z r)
          (do
            let (state, response) := handleAppendEntiresFromPrimary self v r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            return state : NodeEffect _) := by
    intro v vLog vTerm vCommit vVoted vMatch vRole
    have spec := fromLeader_spec self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    simp only [hres] at spec ⊢
    obtain ⟨term, voted, matchEq, _, role, log, commit, response⟩ := spec
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have term' : result.currentTerm = z.currentTerm := (term.trans vTerm).trans wTerm
    have accepted : Accepted before r result := by
      unfold appendEntryMatchesLog at matches_
      rw [zLog] at matches_
      refine ⟨same.trans term'.symm, same ▸ termLe, zCommit ▸ commitLe, matches_.1,
        matches_.2, ?_, ?_⟩
      · rw [log, vLog, ← zLog]
        rfl
      · rw [commit, vCommit, wCommit, zCommit]
    refine common _ _ ⟨Kind.accept source r rfl accepted, fun e member => ?_⟩
      (term.trans vTerm) (voted.trans vVoted) (matchEq.trans vMatch)
      (fun kept => (role kept).trans vRole)
      fun c => (notCand (((role (by rw [c]; simp)).trans vRole).symm.trans c)).elim
    simp only [List.append_nil, List.mem_singleton] at member
    subst member
    refine ⟨rfl, ?_⟩
    rw [response]
    exact fun _ => ⟨source, r, rfl, accepted, (vTerm.trans wTerm).trans term'.symm, rfl⟩
  have conflictEq : firstTermConflictIndex { w with primaryKnown := true } r
      = conflictIndex z.log r := by
    rw [firstTermConflictIndex_eq]
    simp only [wLog]
  split_rel conflict := (split) with
  | none =>
    rename_i heq
    rw [conflictEq] at heq
    exact tail _ (by simp only [heq]; exact wLog) rfl rfl rfl rfl rfl
  | some =>
    rename_i index heq
    rw [conflictEq] at heq
    exact tail _ (by simp only [heq, wLog]) rfl rfl rfl rfl rfl

private theorem appendEntriesRequest_summary (self : NodeID) (before : NodeState)
    (source : NodeID) (request : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesRequest request)) after
            sent)
        (receive (Capabilities.record self) self source before
          (.appendEntriesRequest request)) := by
  simp only [receive]
  refine observe_bumping
    (motive := fun z => Sends _ (handleAppendEntriesRequest (Capabilities.record self) self source z request))
    before (message := .appendEntriesRequest request) rfl (fun bump => ?_) (fun le => ?_)
  · refine Sends.mono
      (aeReply self source before _ request (Nat.le.refl) rfl rfl (Nat.le_of_lt bump))
      fun after sent reply => ?_
    obtain ⟨term, _, _, lead, cand, kind, sends⟩ := reply
    exact bumped_summary (term ▸ bump)
      (fun candidate => by
        rw [cand candidate] at candidate
        simp [bumpedState] at candidate)
      (fun leader => by
        have := lead leader
        simp [bumpedState] at this)
      ⟨source, _, rfl, trivial, term ▸ Nat.le.refl⟩ kind sends
  · refine Sends.mono (aeReply self source before _ request le rfl rfl Nat.le.refl)
      fun after sent reply => ?_
    obtain ⟨term, voted, matchEq, lead, cand, kind, sends⟩ := reply
    refine ⟨Nat.le_of_eq term.symm, fun _ voted' eq => voted ▸ eq,
      fun _ => Or.inr (Or.inr (Or.inl ⟨source, _, rfl, trivial, term ▸ le⟩)), fun _ => Or.inr (Or.inr (Or.inl ⟨source, _, rfl, trivial, term ▸ le⟩)), fun c => ?_,
      fun leader => ?_, fun _ _ _ => Or.inl matchEq, kind, sends⟩
    · have eq := cand c
      rw [eq] at c ⊢
      exact ⟨c, rfl, rfl, Or.inr ⟨c, rfl, Or.inr rfl,
        fun voter member fresh => absurd member fresh⟩⟩
    · exact Or.inl ⟨lead leader, term⟩

private theorem BatchState.push {self : NodeID} {before state : NodeState}
    {sent : List Model.Envelope} (batch : BatchState self before state sent)
    (content : EntryContent)
    : BatchState self before
        { state with log := state.log ++ [{ term := state.currentTerm, content }] }
        sent := by
  obtain ⟨⟨entries, sentIndex, rfl, terms⟩, beats⟩ := batch
  refine ⟨
    ⟨entries ++ [{ term := before.currentTerm, content }], sentIndex, by simp, ?_⟩,
    fun e member => (beats e member).extend (List.prefix_append _ _) Nat.le.refl
  ⟩
  intro entry member
  split_rel mem_append := (rcases List.mem_append.mp member with old | new) with
  | inl => exact terms entry old
  | inr => simp at new; rw [new]

private theorem appendEntry_batch (self : NodeID) (before : NodeState)
    (state : NodeState) (sent : List Model.Envelope)
    (content : EntryContent) (batch : BatchState self before state sent)
    : Sends (fun next later => BatchState self before next (sent ++ later))
        (appendEntry (Capabilities.record self) self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split_rel peers := (split) with
    | none => exact Sends.pure' (by simpa using batch.push content)
    | some =>
      rename_i nodes _
      refine Sends.guard_bind fun _ => ?_
      obtain ⟨⟨entries, sentIndex, rfl, terms⟩, beats⟩ := batch
      refine Sends.bind'
        (Sends.forIn' (R := AEFrom self before.currentTerm before.commitIndex
          (before.log ++ entries)) fun peer _ member => ?_)
        fun _ later sentBeats => Sends.pure' ?_
      · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
          Sends.pure' ⟨⟨_, rfl⟩, fun e member' => ?_⟩
        simp only [eq, List.append_nil, List.mem_singleton] at member'
        subst member'
        have added := Finset.mem_sort.mp member
        have other : Not (peer = self) := (Finset.mem_erase.mp added).1
        refine ⟨rfl, other, _, rfl, rfl, ?_, ?_, ?_, Nat.le.refl⟩ <;>
          simp only [makeAppendEntriesRequest, ite_eq_left added, messageEntries] <;> simp
      · have batch : BatchState self before
            { before with
                log := before.log ++ entries
                sentIndex := fun peer =>
                  if peer ∈ (nodes \ eligiblePeers
                      { before with log := before.log ++ entries, sentIndex } self).erase self
                  then (before.log ++ entries).length else sentIndex peer }
            (sent ++ later) :=
          ⟨⟨entries, _, rfl, terms⟩, fun e member => by
            split_rel mem_append := (rcases List.mem_append.mp member with old | new) with
            | inl => exact beats e old
            | inr => exact sentBeats e new⟩
        simpa using batch.push content

private theorem sendEntries_batch (self : NodeID) (before state : NodeState)
    (sent : List Model.Envelope) (destination : NodeID) (endIndex : Nat)
    (batch : BatchState self before state sent)
    : Sends (fun next later => BatchState self before next (sent ++ later))
        (sendEntries (Capabilities.record self) self state destination endIndex) := by
  unfold sendEntries
  refine Sends.guard_bind fun ⟨_, peer, le, bound, _⟩ => ?_
  refine Sends.bind' (Sends.send _ _ _) fun _ later eq => Sends.pure' ?_
  obtain ⟨⟨entries, sentIndex, rfl, terms⟩, packets⟩ := batch
  refine ⟨⟨entries, _, rfl, terms⟩, fun e member => ?_⟩
  simp only [List.append_nil] at member
  split_rel mem_append := (rcases List.mem_append.mp member with old | new) with
  | inl => exact packets e old
  | inr =>
    simp only [eq, List.mem_singleton] at new
    subst e
    have other : Not (destination = self) := (Finset.mem_erase.mp peer).1
    exact ⟨rfl, other, _, rfl, rfl, Nat.le_trans le bound, rfl, List.take_prefix _ _, Nat.le.refl⟩

private theorem appendBatch_summary (self : NodeID) (state : NodeState)
    (contents : List AppendEntryInput)
    : Sends
        (fun after sent => Summary self state (.internal (.append contents)) after sent)
        (act (Capabilities.record self) self state (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => ?_
  subst empty
  have start : BatchState self state state [] :=
    ⟨⟨[], state.sentIndex, by simp, by simp⟩, by simp⟩
  refine Sends.bind' (Sends.mono (Sends.foldlM' (I := BatchState self state)
      (fun value sent' item batch =>
        Sends.bind' (appendEntry_batch self state value sent' item.content batch)
          fun appended later kept =>
            (Sends.foldlM'
              (fun value sent' (destination, endIndex) batch =>
                sendEntries_batch self state value sent' destination endIndex batch)
              item.flushes appended (sent' ++ later) kept).mono
              fun _ _ done => by simpa [List.append_assoc] using done)
      contents state [] start) fun _ _ done => by simpa using done)
    fun appended sent batch => ?_
  refine Sends.mono (advanceCommit_sends self appended)
    fun after later ⟨advance, nominated⟩ => ?_
  obtain ⟨⟨entries, sentIndex, eq, terms⟩, beats⟩ := batch
  have term : after.currentTerm = state.currentTerm := by rw [advance.term, eq]
  have log : after.log = appended.log := advance.log
  have notCandidate : Not (after.role = .candidate) := fun candidate => by
    have kept := advance.role_kept (by rw [candidate]; simp)
    rw [candidate, eq] at kept
    exact (by simp : Not (Role.candidate = Role.primary)) (kept.trans leader)
  have commit : state.commitIndex <= after.commitIndex := by
    have := advance.commit_le; rw [eq] at this; exact this
  refine ⟨
    Nat.le_of_eq term.symm,
    fun _ voted votedEq => by rw [advance.votedFor, eq]; exact votedEq,
    fun _ => Or.inl (by simp [Engaged, leader]), fun _ => Or.inl (by simp [Engaged, leader]),
    fun candidate => (notCandidate candidate).elim,
    fun _ => Or.inl ⟨leader, term⟩,
    fun _ _ _ => Or.inl (by rw [advance.matchIndex, eq]),
    Kind.append entries sentIndex leader terms (eq ▸ advance),
    fun e member => ?_
  ⟩
  split_rel mem_append := (rcases List.mem_append.mp (by simpa using member) with old | new) with
  | inl =>
    have from_ : AEFrom self after.currentTerm after.commitIndex after.log e :=
      term ▸ (beats e old).extend (log ▸ List.prefix_refl _) commit
    obtain ⟨request, payload, ok⟩ := from_.ok
    refine ⟨from_.1, ?_⟩
    rw [payload]
    exact ⟨ok, notCandidate, Or.inl ⟨leader, term⟩⟩
  | inr =>
    obtain ⟨source, payload⟩ := nominated e new
    refine ⟨source, ?_⟩
    rw [payload]
    show appended.currentTerm = after.currentTerm
    rw [advance.term]

/-- Every local step satisfies the step summary. -/
private theorem summary (self : NodeID) (before : NodeState) (event : Event)
    : Sends (fun after sent => Summary self before event after sent)
        (Model.Node.step (Capabilities.record self) self before event) := by
  split_rel event := (cases whichEvent : event) with
  | internal =>
      rename_i input
      split_rel input := (cases whichInput : input) with
      | append =>
          rename_i contents
          exact appendBatch_summary self before contents
      | sendEntries =>
          rename_i destination endIndex
          exact sendEntries_summary self before destination endIndex
      | timeout =>
          rename_i kind
          split_rel kind := (cases whichKind : kind) with
          | election => exact startElection_summary self before
          | checkQuorum => exact checkQuorum_summary self before _
      | nominateSuccessor => exact nominate_summary self before
      | initAsBackup =>
          rename_i entries
          exact initAsBackup_summary self before entries
  | receive =>
      rename_i source message
      split_rel message := (cases whichMessage : message) with
      | appendEntriesRequest =>
          rename_i request
          exact appendEntriesRequest_summary self before source request
      | appendEntriesResponse =>
          rename_i response
          exact appendEntriesResponse_summary self before source response
      | requestVoteRequest =>
          rename_i request
          exact voteRequest_summary self before source request
      | requestVoteResponse =>
          rename_i response
          exact voteResponse_summary self before source response
      | requestPreVoteRequest =>
          rename_i request
          exact preVoteRequest_summary self before source request
      | requestPreVoteResponse =>
          rename_i response
          exact preVoteResponse_summary self before source response
      | proposeRequestVoteRequest =>
          rename_i term
          exact proposeVote_summary self before source term

private theorem LocalTransition.summary {before after : Model.State}
    (transition : LocalTransition before after)
    : Summary transition.actor transition.pre transition.event transition.post
        transition.outputs.outgoing := by
  obtain ⟨new, eq, holds⟩ := Safety.summary transition.actor transition.pre transition.event {}
    _ _ transition.ran
  simpa [eq] using holds

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
variable [Config.InitialConfiguration]
section Mono
variable {f : Frame} {s : Model.State}

private theorem Seen.mono {n o} (p : Seen f n o) (s : Model.State) : Seen (f.advance s) n o := .inl p
private theorem Granted.mono {v n t r} (p : Granted f v n t r) (s : Model.State) :
    Granted (f.advance s) v n t r := .inl p
private theorem Led.mono {n t} (p : Led f n t) (s : Model.State) : Led (f.advance s) n t :=
  p.imp_right fun ⟨l, i, e⟩ => ⟨l, i, .inl e⟩
private theorem Canon.mono {k l} (p : Canon f k l) (s : Model.State) : Canon (f.advance s) k l := .inl p
private theorem Committed.mono {k p} (m : Committed f k p) (s : Model.State) :
    Committed (f.advance s) k p := Commit.advance m
private theorem Backed.mono {l i k} (b : Backed f l i k) (s : Model.State) : Backed (f.advance s) l i k := by
  obtain ⟨t, p, m, le, sub⟩ := b
  exact ⟨t, p, m.mono s, le, sub⟩

variable {frame : Frame}

private theorem Backed.weaken {log : List Entry} {commit term term' : Nat}
    (backed : Backed frame log commit term) (le : term <= term')
    : Backed frame log commit term' := by
  obtain ⟨earlier, part, committed, le', within⟩ := backed
  exact ⟨earlier, part, committed, Nat.le_trans le' le, within⟩

private theorem Backed.shorten {log : List Entry} {i j term : Nat}
    (backed : Backed frame log j term) (le : i ≤ j) : Backed frame log i term := by
  obtain ⟨k, p, com, bound, sub⟩ := backed
  exact ⟨k, p, com, bound, (take_prefix_take log le).trans sub⟩

private theorem Acked.mono {n t i} (a : Acked f n t i) (s : Model.State) : Acked (f.advance s) n t i := by
  obtain ⟨o, l, seen, term, canon, bound, sub⟩ := a
  exact ⟨o, l, .inl seen, term, .inl canon, bound, sub⟩

private theorem Bad.mono {p k t} (b : Bad f p k t) (s : Model.State) : Bad (f.advance s) p k t := by
  obtain ⟨e, l, lo, hi, canon, absent⟩ := b
  exact ⟨e, l, lo, hi, .inl canon, absent⟩

end Mono
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
section Initial

private theorem initialNodeState_eq (nonempty : INITIAL_CONFIGURATION.Nonempty)
    (node : NodeID)
    : initialNodeState INITIAL_CONFIGURATION node = initialLocal node := by
  simp only [initialNodeState, initialLocal, initial_primary_iff nonempty]

end Initial
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
section Initial
variable {nodes : List NodeID} {initial : Model.State}
  (initialized : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init initial)
include initialized

private theorem initial_state {node : NodeID} {state : NodeState}
    (member : (node, state) ∈ initial.nodes)
    : state = initialLocal node := by
  rw [← initialNodeState_eq initialized.1]
  exact initialized.2.2.2.2 _ member

private theorem initial_seen {n : NodeID} {o : Observation}
    (seen : Seen (Frame.start initial) n o) : o = observe (initialLocal n) := by
  split_rel seen := (rcases seen with no | ⟨st, mem, term, log⟩) with
  | inl => contradiction
  | inr =>
    rw [initial_state initialized mem] at term log
    cases o; cases term; cases log; rfl

omit initialized in
private theorem not_elected_single {current : Model.State} {node : NodeID}
    {term commit : Nat} {log : List Entry} : ¬ Elected (Frame.start current) node term log commit := by
  intro elected
  split_rel elected := (rcases elected with no | ⟨_, impossible, _⟩) with
  | inl => contradiction
  | inr => cases impossible

omit initialized in
private theorem led_single {current : Model.State} {node : NodeID} {term : Nat}
    (led : Led (Frame.start current) node term)
    : term = BOOTSTRAP_TERM /\ node = INITIAL_PRIMARY := by
  split_rel led := (rcases led with bootstrap | ⟨log, commit, elected⟩) with
  | inl => exact bootstrap
  | inr => exact absurd elected not_elected_single

private theorem initial_canon {term : Nat} {log : List Entry}
    (canon : Canon (Frame.start initial) term log)
    : term = BOOTSTRAP_TERM /\ log = (initialLocal INITIAL_PRIMARY).log := by
  split_rel canon := (rcases canon with no | ⟨n, st, ⟨mem, _, _, led⟩, rfl⟩) with
  | inl => contradiction
  | inr =>
    obtain ⟨boot, rfl⟩ := led_single led
    exact ⟨boot, by rw [initial_state initialized mem]⟩

/-- The initial leader log has no signature: only the empty prefix is committed. -/
private theorem initial_commit {term : Nat} {part : List Entry}
    (commit : Committed (Frame.start initial) term part) : part = [] := by
  split_rel commit := (cases commit) with
  | base => rfl
  | link =>
    have facts := ‹CommitFacts _ _ term _ _›
    obtain ⟨_, logEq⟩ := initial_canon initialized facts.canon
    obtain ⟨entry, found, signed⟩ := Ledger.isSignatureAtTrue facts.signature
    have mem := Ledger.entryAt_mem found
    rw [logEq] at mem
    simp [initialLocal] at mem
    subst mem
    simp [EntryContent.isSignature] at signed

private theorem inv_initial : Inv (Frame.start initial) := by
  have leaderMem := INITIAL_PRIMARY_mem initialized.1
  have stateOf : forall {node : NodeID} {state : NodeState},
      Now (Frame.start initial) node state -> state = initialLocal node :=
    fun now => initial_state initialized now
  have sorted : Sorted (Frame.start initial) := by
    intro node state now
    rw [stateOf now]
    unfold initialLocal
    split_rel primary := (split) with
    | pos => simp
    | neg => simp
  have rooted : RootedLogs (Frame.start initial) := by
    intro node state now
    rw [stateOf now]
    split_rel isLeader := (by_cases isLeader : node = INITIAL_PRIMARY) with
    | pos =>
      subst isLeader
      exact fun _ => by simp [initialLocal]
    | neg => exact fun nonempty => absurd (by simp [initialLocal, isLeader]) nonempty
  have terms : Terms (Frame.start initial) := by
    intro node state now entry member
    rw [stateOf now] at member ⊢
    split_rel leader := (by_cases leader : node = INITIAL_PRIMARY) with
    | pos =>
      subst leader
      simp_all [initialLocal]
    | neg => simp [initialLocal, leader] at member
  have anchor : Anchor (Frame.start initial) := by
    intro node state index now positive bound
    rw [stateOf now] at bound ⊢
    split_rel isLeader := (by_cases isLeader : node = INITIAL_PRIMARY) with
    | pos =>
      subst isLeader
      have one : index = 1 := by
        simp [initialLocal] at bound
        exact Nat.le_antisymm bound (Nat.succ_le_of_lt positive)
      subst one
      refine ⟨_, .inr ⟨_, _,
        ⟨now, ?_, ?_, Or.inl ⟨?_, rfl⟩⟩, rfl⟩, ?_, ?_⟩
      · rw [stateOf now]
        simp [initialLocal, leaderMem, BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        simp [initialLocal]
      · simp [initialLocal, BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        exact bound
      · rw [stateOf now]
    | neg =>
      simp [initialLocal, isLeader] at bound
      exact absurd (Nat.lt_of_lt_of_le positive (Nat.le_of_eq bound)) (Nat.lt_irrefl 0)
  constructor
  · exact currentCopyLog rooted terms sorted anchor
  · intro node state now active
    rw [stateOf now] at active ⊢
    simp only [Engaged, initialLocal] at active ⊢
    split_rel primary := (by_cases primary : node = INITIAL_PRIMARY) with
    | pos =>
      split_rel member := (by_cases member : node ∈ INITIAL_CONFIGURATION) with
      | pos => simp_all [BOOTSTRAP_TERM]
      | neg => simp_all [BOOTSTRAP_TERM]
    | neg =>
      split_rel member := (by_cases member : node ∈ INITIAL_CONFIGURATION) with
      | pos => simp_all [BOOTSTRAP_TERM]
      | neg => simp_all
  · exact VoteFacts.initial initial fun _ _ _ => state_unique initialized.2.2.1
  · intro _ _ _ _ h
    split_rel grant := (rcases h with no | ⟨_, impossible, _⟩) with
    | inl => exact False.elim no
    | inr => cases impossible
  · intro node state term now led
    obtain ⟨rfl, rfl⟩ := led_single led
    rw [stateOf now]
    right
    simp [initialLocal, leaderMem]
  · intro node state now leader
    left
    rw [stateOf now] at leader ⊢
    split_rel isLeader := (by_cases isLeader : node = INITIAL_PRIMARY) with
    | pos =>
      subst isLeader
      simp [initialLocal, leaderMem]
    | neg =>
      simp only [initialLocal, isLeader, ite_false] at leader
      split_rel leader := (split at leader) with
      | pos => cases leader
      | neg => cases leader
  · intro node state now candidate
    rw [stateOf now] at candidate
    simp only [initialLocal] at candidate
    split_rel primary := (by_cases primary : node = INITIAL_PRIMARY) with
    | pos =>
      split_rel member := (by_cases member : node ∈ INITIAL_CONFIGURATION) with
      | pos => simp [primary] at candidate
      | neg => simp [primary] at candidate
    | neg =>
      split_rel member := (by_cases member : node ∈ INITIAL_CONFIGURATION) with
      | pos => simp [primary, member] at candidate
      | neg => simp [primary, member] at candidate
  · intro n k l i e
    exact (not_elected_single (e)).elim
  · intro node other term left right
    rw [(led_single left).2, (led_single right).2]
  · intro node state now role led
    refine ⟨.inr ⟨node, state, ⟨now, rfl, role, led⟩, rfl⟩, fun log canon => ?_⟩
    obtain ⟨-, rfl⟩ := led_single led
    rw [(initial_canon initialized canon).2, stateOf now]
    exact List.prefix_refl _
  · intro k a b ca cb
    rw [(initial_canon initialized (ca)).2,
      (initial_canon initialized (cb)).2]
    exact fun _ _ _ => rfl
  · apply canonLogs_step (g := LogFacts.empty) (prev := none) (s := initial)
      (fun _ _ h => False.elim h)
    rintro n st k ⟨now, rfl, _, led⟩
    refine ⟨currentCopyLog rooted terms sorted anchor n st now, ⟨n, led⟩, fun gt => ?_⟩
    exact (Nat.not_lt_of_ge (Nat.le_of_eq (led_single led).1) gt).elim
  · intro node state now
    have zero : state.commitIndex = 0 := by rw [stateOf now]; rfl
    have backed (term : Nat) : Backed (Frame.start initial) state.log state.commitIndex term :=
      ⟨0, [], .base, Nat.zero_le _, by rw [zero]; exact List.nil_prefix⟩
    exact ⟨⟨0, backed 0⟩, fun _ => backed _⟩
  · intro node state earlier index now seen _
    left
    rw [stateOf now, initial_seen initialized seen]
    exact List.take_prefix _ _
  · intro node state peer now _ _ positive
    rw [stateOf now] at positive
    simp [initialLocal] at positive
  · intro envelope pending
    change envelope ∈ initial.network at pending
    simp [initialized.2.2.2.1] at pending
  · intro envelope pending
    change envelope ∈ initial.network at pending
    simp [initialized.2.2.2.1] at pending
  · intro node state now leader
    rw [stateOf now] at leader ⊢
    split_rel isLeader := (by_cases isLeader : node = INITIAL_PRIMARY) with
    | pos =>
      subst isLeader
      simp [initialLocal]
    | neg =>
      simp only [initialLocal, isLeader, ite_false] at leader
      split_rel leader := (split at leader) with
      | pos => cases leader
      | neg => cases leader

  · intro first second left right leftCommit _
    rw [initial_commit initialized leftCommit]
    exact Or.inl List.nil_prefix
  · exact fun _ _ _ => state_unique initialized.2.2.1
  · intro n st mem
    have eq : st = Model.initialNodeState INITIAL_CONFIGURATION n := initialized.2.2.2.2 _ mem
    rw [eq]
    exact ⟨Nat.zero_le _, fun positive => by simp [Model.initialNodeState] at positive⟩
  · exact fun n st mem => .inr ⟨st, mem, rfl, rfl⟩
  · intro n st o now seen
    rw [initial_seen initialized seen, stateOf now]
    exact Nat.le_refl _

end Initial
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

private theorem termAt_mono {log : List Entry}
    (sorted : log.Pairwise fun first second => first.term <= second.term) {i j : Nat}
    (le : i <= j) (bound : j <= log.length)
    : termAt log i <= termAt log j := by
  split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos i with zero | positive) with
  | inl =>
    subst zero
    rw [termAt_zero]
    exact Nat.zero_le _
  | inr =>
    rw [termAt_eq positive (Nat.le_trans le bound), termAt_eq (Nat.lt_of_lt_of_le positive le) bound]
    split_rel eq_or_lt_of_le := (rcases Nat.eq_or_lt_of_le le with same | lt) with
    | inl =>
      subst same
      exact Nat.le.refl
    | inr =>
      exact List.pairwise_iff_getElem.mp sorted _ _ _ _
        (Nat.sub_lt_sub_right (Nat.succ_le_of_lt positive) lt)

private theorem termAt_le_of_mem {log : List Entry} {bound : Nat}
    (terms : forall entry, entry ∈ log -> entry.term <= bound) (index : Nat)
    : termAt log index <= bound := by
  unfold termAt
  split_rel found := (cases found : entryAt? log index) with
  | none => exact Nat.zero_le _
  | some =>
    rename_i entry
    exact terms entry (entryAt_mem found)

private theorem signature_pos {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : 0 < index := by
  split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos index with zero | positive) with
  | inl =>
    subst zero
    simp [isSignatureAt, entryAt?] at signature
  | inr => exact positive

private theorem signature_bound {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := isSignatureAtTrue signature
  exact entryAtSomeIndexBound found

/-- The winning prefix `log.take (maxCommittableIndex log)` contains every
prefix of `log` ending in a signature. -/
private theorem prefix_committable {part log : List Entry} (sub : part <+: log)
    (signature : isSignatureAt part part.length = true)
    : part <+: log.take (maxCommittableIndex log) := by
  have le := signatureIndex_le_maxCommittableIndex (isSignatureAt_of_prefix sub signature)
  rw [List.prefix_iff_eq_take.mp sub]
  exact take_prefix_take log le

private theorem take_signature {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take index) (log.take index).length = true := by
  rw [List.length_take, Nat.min_eq_left (signature_bound signature)]
  exact isSignatureAt_take_of_le Nat.le.refl signature

private theorem Led.elected {frame : Frame} {node : NodeID} {term : Nat}
    (led : Led frame node term) (above : 2 < term)
    : exists log commit, Elected frame node term log commit := by
  split_rel led := (rcases led with ⟨same, -⟩ | elected) with
  | inl =>
    subst same
    exact absurd above (by decide)
  | inr => exact elected

/-- A commit of a positive term has signed quorum evidence. -/
private theorem Commit.origin {g : LogFacts.Ghost} {t p} (commit : Commit g t p)
    (pos : 0 < t) : ∃ l b i, CommitFacts g l t b i ∧ p = l.take i := by
  split_rel commit := (cases commit) with
  | base => exact absurd pos (Nat.lt_irrefl 0)
  | link => exact ⟨_, _, _, ‹CommitFacts g _ t _ _›, rfl⟩

/-- Leader logs start at the bootstrap term, so term zero commits only the empty prefix. -/
private theorem Commit.nil_of_zero {g : LogFacts.Ghost}
    (floor : ∀ k l, g.canon k l → 2 ≤ k) {p} (commit : Commit g 0 p) : p = [] := by
  split_rel commit := (cases commit) with
  | base => rfl
  | link => exact absurd (floor _ _ (‹CommitFacts g _ 0 _ _›).canon) (by decide)

/-- A leader log of a later term extends the winning prefix of its election, which holds
every earlier commit. -/
private theorem later_upto {g : LogFacts.Ghost} {bound : Nat} (wins : LogFacts.WinningPrefix g)
    (complete : CompleteUpTo g bound) (floor : ∀ k l, g.canon k l → 2 ≤ k) :
    LaterUpTo g bound := by
  intro k t p l commit canon lt below
  have whole := commit
  split_rel commit := (cases commit) with
  | base => exact List.nil_prefix
  | link =>
    have facts := ‹CommitFacts g _ k _ _›
    obtain ⟨n, e, i, elect, sub⟩ :=
      wins t l canon (Nat.lt_of_le_of_lt (floor _ _ facts.canon) lt)
    exact (prefix_committable (complete _ _ n t e i whole elect lt below)
      (take_signature facts.signature)).trans sub

private theorem later_of_complete {g : LogFacts.Ghost} (wins : LogFacts.WinningPrefix g)
    (complete : Complete g) (floor : ∀ k l, g.canon k l → 2 ≤ k) : Later g :=
  fun k t p l commit canon lt =>
    later_upto (bound := t) wins (fun k p n e l i c elect lt _ => complete k p n e l i c elect lt)
      floor k t p l commit canon lt (Nat.le_refl t)

/-- Committed prefixes of terms up to `bound` agree wherever both are defined: a leader
log of a later term holds an earlier commit, and leader logs of one term agree. -/
private theorem agree_upto {g : LogFacts.Ghost} {bound : Nat} (chains : LogFacts.Chain g)
    (later : LaterUpTo g bound) (floor : ∀ k l, g.canon k l → 2 ≤ k) {k t p q}
    (hp : Commit g k p) (hq : Commit g t q) (kb : k ≤ bound) (tb : t ≤ bound) :
    ∀ n, n ≤ p.length → n ≤ q.length → p.take n = q.take n := by
  intro n np nq
  split_rel terms := (rcases Nat.lt_trichotomy k t with lt | same | gt) with
  | inl =>
    -- Both are prefixes of the later leader log.
    obtain ⟨b, _, _, fb, rfl⟩ := hq.origin (Nat.zero_lt_of_lt lt)
    exact (take_eq_of_prefix (later _ _ _ _ hp fb.canon lt tb) np).symm.trans
      (take_eq_of_prefix (List.take_prefix _ _) nq)
  | inr_inl =>
    subst same
    split_rel started := (rcases Nat.eq_zero_or_pos k with zero | pos) with
    | inl =>
      subst zero
      rw [hp.nil_of_zero floor] at np ⊢
      rw [Nat.le_zero.mp np, List.take_zero, List.take_zero]
    | inr =>
      obtain ⟨a, _, _, fa, rfl⟩ := hp.origin pos
      obtain ⟨b, _, _, fb, rfl⟩ := hq.origin pos
      rw [← take_eq_of_prefix (List.take_prefix _ a) np,
        ← take_eq_of_prefix (List.take_prefix _ b) nq]
      exact chains k a b fa.canon fb.canon n
        (Nat.le_trans np (List.take_prefix _ _).length_le)
        (Nat.le_trans nq (List.take_prefix _ _).length_le)
  | inr_inr =>
    obtain ⟨a, _, _, fa, rfl⟩ := hp.origin (Nat.zero_lt_of_lt gt)
    exact (take_eq_of_prefix (List.take_prefix _ _) np).symm.trans
      (take_eq_of_prefix (later _ _ _ _ hq fa.canon gt kb) nq)

/-- Committed prefixes are comparable: they agree up to the shorter one. -/
private theorem comparable_of {g : LogFacts.Ghost} (chains : LogFacts.Chain g)
    (later : Later g) (floor : ∀ k l, g.canon k l → 2 ≤ k) {k t p q}
    (hp : Commit g k p) (hq : Commit g t q) : p <+: q ∨ q <+: p := by
  have agree := agree_upto (bound := max k t) chains
    (fun k t p l c canon lt _ => later k t p l c canon lt)
    floor hp hq (Nat.le_max_left k t) (Nat.le_max_right k t)
  split_rel shorter := (rcases Nat.le_total p.length q.length with le | le) with
  | inl =>
    have eq := agree p.length (Nat.le_refl _) le
    rw [List.take_length] at eq
    exact Or.inl (eq ▸ List.take_prefix _ _)
  | inr =>
    have eq := agree q.length le (Nat.le_refl _)
    rw [List.take_length] at eq
    exact Or.inr (eq ▸ List.take_prefix _ _)

private theorem Inv.canon_floor {h : Frame} (inv : Inv h) {k l} (canon : h.logs.canon k l) :
    2 ≤ k := by
  obtain ⟨n, led⟩ := inv.owner canon
  exact inv.leader_floor led

/-- Committed parts are comparable. -/
private theorem committed_comparable {frame : Frame} (inv : Inv frame)
    {first second : Nat} {left right : List Entry}
    (leftCommitted : Committed frame first left)
    (rightCommitted : Committed frame second right)
    : left <+: right \/ right <+: left :=
  inv.comparable first second left right leftCommitted rightCommitted

/--
A committed prefix is committed no later than `bound`, or signed quorum evidence of a
later term covers it from a base within it; `crossing` says what that evidence yields.
-/
private theorem backing_split {g : LogFacts.Ghost} {log : List Entry}
    {commit term bound : Nat} {part : List Entry} {crossed : Prop}
    (cert : Commit g term part) (within : log.take commit <+: part)
    (length : commit <= log.length)
    (crossing : ∀ l k b i, CommitFacts g l k b i → bound < k → b ≤ commit
      → log.take commit <+: l.take i → crossed)
    : (∃ e p, Commit g e p ∧ e ≤ bound ∧ log.take commit <+: p) ∨ crossed := by
  have lengthEq : (log.take commit).length = commit := List.length_take_of_le length
  split_rel cert := (induction cert) with
  | base => exact .inl ⟨0, [], .base, Nat.zero_le _, within⟩
  | link =>
      rename_i l term base index earlier part' f prior le inBacking ih
      split_rel low := (by_cases low : term <= bound) with
      | pos => exact .inl ⟨term, _, .link f prior le inBacking, low, within⟩
      | neg =>
        split_rel baseLe := (by_cases baseLe : base <= commit) with
        | pos => exact .inr (crossing l term base index f (Nat.lt_of_not_le low) baseLe within)
        | neg =>
          have commitIndex : commit <= index := Nat.le_trans (Nat.le_of_lt (Nat.lt_of_not_le baseLe)) f.baseLe
          have short : log.take commit <+: l.take base := by
            have eq := List.prefix_iff_eq_take.mp within
            rw [lengthEq, List.take_take, Nat.min_eq_left commitIndex] at eq
            rw [eq]
            exact take_prefix_take _ (Nat.le_of_lt (Nat.lt_of_not_le baseLe))
          exact ih (short.trans inBacking)

/-- A new leader's log is a prefix of the candidate's that keeps its committed and its
committable entries, and is nonempty if the candidate's is. -/
private theorem primaryState_log (state : NodeState)
    : exists n,
        state.commitIndex <= n
        /\ maxCommittableIndex state.log <= n
        /\ (state.log ≠ [] -> 0 < n)
        /\ (primaryState state).log = state.log.take n := by
  simp only [primaryState]
  split_rel commit := (split) with
  | pos =>
    rename_i positive
    have le : state.commitIndex <= lastCommittableIndex state := by
      unfold lastCommittableIndex; exact Nat.le_max_left _ _
    exact ⟨lastCommittableIndex state, le,
      by unfold lastCommittableIndex; exact Nat.le_max_right _ _,
      fun _ => Nat.lt_of_lt_of_le positive le, rfl⟩
  | neg =>
    exact ⟨max state.commitIndex state.log.length, Nat.le_max_left _ _,
      Nat.le_trans (maxCommittableIndexBounded _) (Nat.le_max_right _ _),
      fun nonempty => Nat.lt_of_lt_of_le (List.length_pos_iff.mpr nonempty)
        (Nat.le_max_right _ _),
      (List.take_of_length_le (Nat.le_max_right _ _)).symm⟩

private theorem primaryState_log_prefix (state : NodeState)
    : (primaryState state).log <+: state.log := by
  obtain ⟨n, _, _, _, eq⟩ := primaryState_log state
  rw [eq]
  exact List.take_prefix _ _

/-- The facts of a won election used by the safety proof. -/
private theorem Wins.facts {self : NodeID} {before' : NodeState} {event : Event}
    {after' : NodeState} (wins : Wins self before' event after')
    : exists candidate,
        Campaign self before' event candidate
        /\ hasQuorum
            (activeConfigurations before'.log before'.commitIndex)
            candidate.votesGranted
        /\ after'.log = (primaryState candidate).log
        /\ after'.currentTerm = candidate.currentTerm
        /\ after'.votedFor = candidate.votedFor
        /\ (forall peer, after'.matchIndex peer = 0)
        /\ (after'.role = .primary \/ after'.role = .none)
        /\ candidate.commitIndex <= after'.commitIndex := by
  obtain ⟨candidate, campaign, quorum, advance, _⟩ := wins
  have ⟨_, logEq, commitEq, _⟩ := campaign
  refine ⟨candidate, campaign, ?_, ?_⟩
  · have : candidate.activeConfigurations
        = activeConfigurations before'.log before'.commitIndex := by
      rw [← logEq, ← commitEq]
      rfl
    rw [← this]
    exact quorum
  exact ⟨advance.log, advance.term, advance.votedFor,
    fun peer => by rw [advance.matchIndex]; rfl, advance.role, advance.commit_le⟩

/-- A node that keeps its term and was not a candidate of it does not win it. -/
private theorem Wins.fresh {self : NodeID} {before after : NodeState} {event : Event}
    (wins : Wins self before event after)
    (sameTerm : after.currentTerm = before.currentTerm)
    (role : Not (before.role = .candidate))
    : False := by
  obtain ⟨candidate, ⟨_, _, _, campaign⟩, _, advance, _⟩ := wins
  have term : after.currentTerm = candidate.currentTerm := advance.term
  split_rel campaign := (rcases campaign with ⟨_, fresh, _⟩ | ⟨kept, _⟩) with
  | inl => exact Nat.succ_ne_self _ ((fresh.symm.trans term.symm).trans sameTerm)
  | inr => exact role kept

/-- A commit frontier survives `advanceCommit`. -/
private theorem Advance.frontier {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state) (frontier : Direct.CommitFrontier middle)
    : Direct.CommitFrontier state := by
  split_rel moved := (rcases Nat.eq_or_lt_of_le advance.commit_le with same | ahead) with
  | inl => exact frontier.of_log advance.log same.symm
  | inr =>
    have eq := advance.commit_eq ahead
    have signature := highestCommittableIndex_signature middle self (eq ▸ ahead)
    exact ⟨by rw [advance.log, eq]; exact signature_bound signature,
      fun _ => by rw [advance.log, eq]; exact signature⟩

private theorem primaryState_frontier {state : NodeState}
    (frontier : Direct.CommitFrontier state)
    : Direct.CommitFrontier (primaryState state) := by
  obtain ⟨n, le, _, _, eq⟩ := primaryState_log state
  exact (frontier.keep (count := n) le (suffix := [])).of_log (by rw [eq]; simp) rfl

/-- A rollback point lies after the request's previous index. -/
private theorem conflictIndex_ge {log : List Entry} {request : AppendEntriesRequest}
    {index : Nat} (conflict : conflictIndex log request = some index)
    : request.prevLogIndex + 1 <= index := by
  unfold conflictIndex at conflict
  obtain ⟨pair, found, rfl⟩ := Option.map_eq_some_iff.mp conflict
  obtain ⟨_, offset, lt, rfl, _⟩ := List.find?_eq_some_iff_getElem.mp found
  simp

/-- Accepting a request keeps the entries up to its previous index. -/
private theorem acceptLog_keep (log : List Entry) (request : AppendEntriesRequest)
    : exists n suffix,
        request.prevLogIndex <= n /\ acceptLog log request = log.take n ++ suffix := by
  unfold acceptLog
  simp only
  split_rel conflict := (split) with
  | some =>
    rename_i index conflict
    exact ⟨index - 1, _, Nat.le_sub_of_add_le (conflictIndex_ge conflict), rfl⟩
  | none =>
    exact ⟨max request.prevLogIndex log.length, _, Nat.le_max_left _ _,
      by rw [List.take_of_length_le (Nat.le_max_right _ _)]⟩

/-- Accepting a request keeps the commit frontier. -/
private theorem Accepted.frontier {before after : NodeState}
    {request : AppendEntriesRequest} (accepted : Accepted before request after)
    (frontier : Direct.CommitFrontier before)
    : Direct.CommitFrontier after := by
  obtain ⟨_, _, commitLe, _, _, log, commit⟩ := accepted
  obtain ⟨n, suffix, le, eq⟩ := acceptLog_keep before.log request
  have kept : Direct.CommitFrontier { before with log := after.log } := by
    rw [log, eq]
    exact frontier.keep (Nat.le_trans commitLe le)
  exact (Direct.CommitFrontier.advance
    (bound := min request.primaryCommit (request.prevLogIndex + request.entries.length))
    kept).of_log rfl commit

/-- Every kind of step keeps the commit index within the log and at a signature. -/
private theorem Kind.frontier {self : NodeID} {before after : NodeState} {event : Event}
    (kind : Kind self before event after) (frontier : Direct.CommitFrontier before)
    : Direct.CommitFrontier after := by
  split_rel kind := (cases kind) with
  | same =>
    rename_i log commit
    exact frontier.of_log log commit
  | append =>
    rename_i entries sent leader terms advance
    exact advance.frontier ((frontier.extend (List.prefix_append _ entries)).of_log rfl rfl)
  | ack =>
    rename_i _ _ _ _ _ _ advance
    exact advance.frontier (frontier.of_log rfl rfl)
  | accept =>
    rename_i _ _ _ accepted
    exact accepted.frontier frontier
  | elect =>
    rename_i wins
    obtain ⟨candidate, ⟨_, logEq, commitEq, _⟩, _, advance, _⟩ := wins
    exact advance.frontier (primaryState_frontier (frontier.of_log logEq commitEq))
  | install =>
    rename_i entries _ signed _ log commit _ _
    exact ⟨by rw [log, commit]; exact Nat.le.refl,
      fun positive => by
        rw [commit] at positive
        rw [log, commit]
        exact signed positive⟩

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {f : Frame} {after : Model.State} (c : Ctx f after)
include c

private theorem sum : Summary c.actor c.pre c.event c.post c.sent := c.tr.summary

private theorem pre_now : Now f c.actor c.pre := c.tr.pre_mem

private theorem post_now : Now (f.advance after) c.actor c.post := c.tr.post_mem

private theorem now_pre {state : NodeState} (now : Now f c.actor state)
    : state = c.pre :=
  c.inv.unique c.actor state c.pre now c.pre_now

private theorem now_after {node : NodeID} {state : NodeState}
    (now : Now (f.advance after) node state)
    : (node = c.actor /\ state = c.post)
      \/ (Not (node = c.actor) /\ Now f node state) :=
  c.tr.mem_after now

private theorem now_post {state : NodeState}
    (now : Now (f.advance after) c.actor state)
    : state = c.post := by
  split_rel now_after := (rcases c.now_after now with ⟨_, eq⟩ | ⟨other, _⟩) with
  | inl => exact eq
  | inr => exact absurd rfl other

/-- Each node still has one state: the actor its new one, every other node its old one. -/
private theorem unique : Unique (f.advance after) := by
  intro node first second left right
  split_rel now_after := (rcases c.now_after left with ⟨rfl, rfl⟩ | ⟨other, old⟩) with
  | inl => exact (c.now_post right).symm
  | inr =>
    refine c.inv.unique node first second old ?_
    split_rel now_after := (rcases c.now_after right with ⟨actor, _⟩ | ⟨_, old'⟩) with
    | inl => exact absurd actor other
    | inr => exact old'

private theorem seen_after {n : NodeID} {o : Observation} (seen : Seen (f.advance after) n o) :
    Seen f n o ∨ (n = c.actor ∧ o = observe c.post) := by
  split_rel seen := (rcases seen with old | ⟨st, mem, term, log⟩) with
  | inl => exact .inl old
  | inr =>
    have eq : o = observe st := by cases o; cases term; cases log; rfl
    split_rel now_after := (rcases c.now_after mem with ⟨rfl, rfl⟩ | ⟨_, pre⟩) with
    | inl => exact .inr ⟨rfl, eq⟩
    | inr => exact .inl (eq ▸ c.inv.observed _ _ pre)

private theorem post_seen : Seen (f.advance after) c.actor (observe c.post) :=
  .inr ⟨c.post, c.post_now, rfl, rfl⟩

private theorem frontier_pre : c.pre.commitIndex <= c.pre.log.length :=
  (c.inv.frontier _ _ c.pre_now).1

private theorem received {source : NodeID} {message : Message}
    (eq : c.event = .receive source message)
    : exists envelope,
        Pending f envelope
        /\ envelope.source = source
        /\ envelope.target = c.actor
        /\ envelope.payload = message := by
  split_rel source :=
      (rcases c.tr.source with ⟨input, internal, _⟩ | ⟨envelope, queued, target, receive, _⟩) with
  | inl =>
    have : c.tr.event = _ := eq
    rw [internal] at this
    cases this
  | inr =>
    have : c.tr.event = _ := eq
    rw [receive] at this
    cases this
    exact ⟨envelope, queued, rfl, target, rfl⟩

/-- The evidence carried by a received message. -/
private theorem received_ok {source : NodeID} {message : Message}
    (eq : c.event = .receive source message)
    : exists envelope,
        MessageOK f envelope
        /\ envelope.source = source
        /\ envelope.target = c.actor
        /\ envelope.payload = message := by
  obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eq
  exact ⟨envelope, c.inv.messages envelope pending, sourceEq, targetEq, payload⟩

private theorem received_term {source : NodeID} {message : Message}
    (eq : c.event = .receive source message) (bumping : Bumping message)
    : 2 <= message.term := by
  obtain ⟨envelope, pending, _, _, rfl⟩ := c.received eq
  exact c.inv.message_terms envelope pending bumping

private theorem term_le : c.pre.currentTerm <= c.post.currentTerm := Summary.term_le c.sum

/-- A node's committed prefix ending at a signature is a signed prefix of a leader log. -/
private theorem snap_of_committed {node : NodeID} {state : NodeState}
    (now : Now f node state) {index : Nat} (positive : 0 < index)
    (le : index <= state.commitIndex) (signature : isSignatureAt state.log index = true)
    : SnapOK f (state.log.take index) := by
  have bound := signature_bound signature
  have lengthEq : (state.log.take index).length = index := List.length_take_of_le bound
  refine ⟨
    by omega,
    by rw [lengthEq]; exact isSignatureAt_take_of_le Nat.le.refl signature,
    ?_,
    ?_
  ⟩
  · obtain ⟨log, canon, _, agree⟩ := c.inv.anchor node state index now positive bound
    refine ⟨log, ?_, ?_⟩
    · rw [lengthEq, termAt_take Nat.le.refl]
      exact canon
    · rw [agree]
      exact List.take_prefix _ _
  · obtain ⟨⟨_, term, part, committed, _, inPart⟩, _⟩ := c.inv.commit_backed node state now
    exact ⟨term, part, committed, (take_prefix_take _ le).trans inPart⟩

/-- A node initializes from a committed, signed prefix of a leader log. -/
private theorem snap_available {entries : List Entry}
    (eq : c.event = .internal (.initAsBackup entries)) (positive : 0 < entries.length)
    (signature : isSignatureAt entries entries.length = true)
    : SnapOK f entries := by
  have available := c.tr.available entries eq
  simp only [Model.committedPrefixOf, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq,
    beq_iff_eq] at available
  obtain ⟨⟨node, state⟩, member, le, prefixEq⟩ := available
  have sub : entries <+: state.log := prefixEq ▸ List.take_prefix _ _
  have ok := c.snap_of_committed member positive le (isSignatureAt_of_prefix sub signature)
  rwa [prefixEq] at ok

/-- An installed snapshot is empty, or a committed, signed prefix of a leader log. -/
private theorem snap_cases {motive : Prop} {entries : List Entry}
    (eq : c.event = .internal (.initAsBackup entries))
    (signed : 0 < entries.length -> isSignatureAt entries entries.length = true)
    (empty : entries = [] -> motive) (snap : SnapOK f entries -> motive)
    : motive := by
  split_rel empty := (rcases Nat.eq_zero_or_pos entries.length with zero | positive) with
  | inl => exact empty (List.eq_nil_of_length_eq_zero zero)
  | inr => exact snap (c.snap_available eq positive (signed positive))

private theorem pre_two (active : Engaged c.pre) : 2 <= c.pre.currentTerm :=
  c.inv.active c.actor c.pre c.pre_now active

/-- An engaged node, or a sender of a term-bumping message, has term at least two. -/
private theorem post_two (activated : Activated c.pre c.event c.post)
    : 2 <= c.post.currentTerm := by
  have le := c.term_le
  split_rel active :=
      (rcases activated with role | two | ⟨source, message, eq, bumping, bound⟩
        | ⟨entries, stash, positive, signature, termEq⟩) with
  | inl => exact Nat.le_trans (c.pre_two role) le
  | inr_inl => exact Nat.le_trans two le
  | inr_inr_inl => exact Nat.le_trans (c.received_term eq bumping) bound
  | inr_inr_inr =>
    obtain ⟨_, _, ⟨_, canon, _⟩, _⟩ := c.snap_available stash positive signature
    obtain ⟨_, led⟩ := c.inv.owner (canon)
    rw [termEq]
    exact c.inv.leader_floor led

private theorem elected_after {node : NodeID} {term commit : Nat} {log : List Entry}
    (elected : Elected (f.advance after) node term log commit)
    : Elected f node term log commit
      \/ ElectStep f after node term log commit := by
  apply elected.imp_right
  rintro ⟨p, eq, step⟩
  obtain rfl : f.current = p := Option.some.inj eq
  exact step

/-- A new election is the actor's, campaigning with its state before the step. -/
private theorem electStep {node : NodeID} {term commit : Nat} {log : List Entry}
    (step : ElectStep f after node term log commit)
    : node = c.actor
      /\ c.pre.log = log
      /\ c.pre.commitIndex = commit
      /\ (c.pre.currentTerm < term
          \/ (c.pre.currentTerm = term /\ c.pre.role = .candidate))
      /\ c.post.currentTerm = term
      /\ (c.post.role = .primary \/ c.post.role = .none)
      /\ log.take (maxCommittableIndex log) <+: c.post.log
      /\ 3 <= term := by
  obtain ⟨candidate, leader, candidateMem, leaderMem, logEq, commitEq, _, termCase, leaderTerm,
    leaderRole, winning, three, _⟩ := step
  split_rel now_after :=
      (rcases c.now_after leaderMem with ⟨nodeEq, stateEq⟩ | ⟨different, old⟩) with
  | inl =>
    subst nodeEq stateEq
    have := c.now_pre candidateMem
    subst this
    exact ⟨rfl, logEq, commitEq, termCase, leaderTerm, leaderRole, winning, three⟩
  | inr =>
    have := c.inv.unique _ _ _ old candidateMem
    subst this
    split_rel termCase := (rcases termCase with lt | ⟨_, role⟩) with
    | inl => exact absurd leaderTerm (Nat.ne_of_lt lt)
    | inr =>
      split_rel leaderRole := (rcases leaderRole with role' | role') with
      | inl => rw [role'] at role <;> cases role
      | inr => rw [role'] at role <;> cases role

/-- A leadership recorded after the step was recorded before it, or is won in it. -/
private theorem led_after {motive : Prop} {node : NodeID} {term : Nat}
    (led : Led (f.advance after) node term)
    (old : Led f node term -> motive)
    (won : forall log commit, ElectStep f after node term log commit -> motive)
    : motive := by
  split_rel led := (rcases led with bootstrap | ⟨log, commit, elected⟩) with
  | inl => exact old (Or.inl bootstrap)
  | inr =>
    split_rel elected_after := (rcases c.elected_after elected with prior | step) with
    | inl => exact old (Or.inr ⟨log, commit, prior⟩)
    | inr => exact won log commit step

private theorem led_other {node : NodeID} {term : Nat} (different : Not (node = c.actor))
    (led : Led (f.advance after) node term)
    : Led f node term :=
  c.led_after led id fun _ _ step => absurd (c.electStep step).1 different

private theorem canon_after {term : Nat} {log : List Entry}
    (canon : Canon (f.advance after) term log)
    : Canon f term log
      \/ exists node state,
          CanonNow (f.advance after) node state term /\ state.log = log := by
  exact canon

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

private theorem Advance.facts {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.log = middle.log
      /\ state.currentTerm = middle.currentTerm
      /\ (state.role = middle.role \/ state.role = .none) :=
  ⟨advance.log, advance.term, advance.role⟩

private theorem makeRequestVoteRequest_eq (state : NodeState)
    : makeRequestVoteRequest state = vals state.currentTerm state.log state.commitIndex :=
  rfl

/-- A candidate's own vote request ranks at least as high as its log. -/
private theorem vals_outranks {state : NodeState} (term : Nat)
    (sorted : state.log.Pairwise fun first second => first.term <= second.term)
    (frontier : state.commitIndex <= state.log.length)
    : LogFacts.Outranks (vals term state.log state.commitIndex) state.log :=
  ⟨termAt_mono sorted (Nat.le_max_right _ _)
      (Nat.max_le.mpr ⟨frontier, maxCommittableIndexBounded state.log⟩),
    fun _ => Nat.le_max_right _ _⟩

/-- A vote request that a log is up to date for ranks at least as high as the log. -/
private theorem outranks_of_upToDate {state : NodeState} {request : RequestVoteRequest}
    (upToDate : voteLogUpToDate state request)
    : LogFacts.Outranks request state.log := by
  simp only [voteLogUpToDate, CCF.TxID.le] at upToDate
  split_rel up_to_date := (rcases upToDate with lt | ⟨eq, le⟩) with
  | inl => exact ⟨Nat.le_of_lt lt, fun same => absurd same (Nat.ne_of_lt lt)⟩
  | inr => exact ⟨Nat.le_of_eq eq, fun _ => le⟩

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {f : Frame} {after : Model.State} (c : Ctx f after)
include c

private theorem pre_sorted
    : c.pre.log.Pairwise fun first second => first.term <= second.term :=
  c.inv.sorted c.actor c.pre c.pre_now

/-- A received AppendEntries request was sent by the leader of its term, from its log. -/
private theorem accept_evidence {source : NodeID} {request : AppendEntriesRequest}
    (eq : c.event = .receive source (.appendEntriesRequest request))
    : exists leaderLog : List Entry, AppendEvidence f source c.actor request leaderLog := by
  obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok eq
  simp only [MessageOK, payload, sourceEq, targetEq] at ok
  exact ok

/-- An accepted request copies its sender's log up to the end of the batch,
keeping the follower's suffix exactly when the follower already agreed. -/
private theorem accept_shape {source : NodeID} {request : AppendEntriesRequest}
    (eq : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post)
    : exists leaderLog : List Entry,
        AppendEvidence f source c.actor request leaderLog
        /\ request.prevLogIndex + request.entries.length <= leaderLog.length
        /\ c.post.log.take (request.prevLogIndex + request.entries.length)
            = leaderLog.take (request.prevLogIndex + request.entries.length)
        /\ (c.post.log = c.pre.log
            \/ (c.post.log
                  = leaderLog.take (request.prevLogIndex + request.entries.length)
                /\ Not
                    (c.pre.log.take (request.prevLogIndex + request.entries.length)
                      = leaderLog.take (request.prevLogIndex + request.entries.length))))
        /\ c.pre.log.take request.prevLogIndex
            = leaderLog.take request.prevLogIndex := by
  obtain ⟨leaderLog, evidence⟩ := c.accept_evidence eq
  refine ⟨leaderLog, evidence, ?_⟩
  obtain ⟨_, _, canon, prevBound, prevTerm, entries, _⟩ := evidence
  obtain ⟨_, _, _, followerBound, termEq, logEq, _⟩ := accepted
  have batchBound : request.prevLogIndex + request.entries.length <= leaderLog.length := by
    exact Nat.le_trans (Nat.add_le_add_left (Nat.le_trans entries.length_le (Nat.le_of_eq List.length_drop))
      _) (Nat.le_of_eq (Nat.add_sub_of_le prevBound))
  have match' : forall j, 0 < j -> j <= c.pre.log.length -> j <= leaderLog.length
      -> termAt c.pre.log j = termAt leaderLog j -> c.pre.log.take j = leaderLog.take j := by
    intro j positive left right same
    obtain ⟨a, ca, la, ea⟩ := c.inv.anchor _ _ j c.pre_now positive left
    obtain ⟨b, cb, lb, eb⟩ := (c.inv.copyLog canon).anchor j positive right
    rw [same] at ca
    rw [ea, eb]
    exact c.inv.chains _ _ _ ca cb j la lb
  have prevAgree : c.pre.log.take request.prevLogIndex = leaderLog.take request.prevLogIndex := by
    split_rel eq_zero_or_pos :=
        (rcases Nat.eq_zero_or_pos request.prevLogIndex with zero | positive) with
    | inl => rw [zero, List.take_zero, List.take_zero]
    | inr => exact match' _ positive followerBound prevBound (termEq.trans prevTerm)
  have shape := acceptLog_eq followerBound prevBound prevAgree entries match'
  rw [← logEq] at shape
  refine ⟨batchBound, ?_⟩
  split_rel shape := (split at shape) with
  | pos =>
    rename_i agree
    have same : c.post.log = c.pre.log := by
      rw [shape, ← agree, List.take_append_drop]
    rw [same]
    exact ⟨agree, Or.inl rfl, prevAgree⟩
  | neg =>
    rename_i differ
    rw [List.append_nil] at shape
    rw [shape, List.take_take, Nat.min_self]
    exact ⟨rfl, Or.inr ⟨rfl, differ⟩, prevAgree⟩

private theorem active : Active (f.advance after) := by
  intro node state now role
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    exact c.post_two (Summary.active c.sum role)
  | inr => exact c.inv.active node state old role

omit c in
/-- Every node after a step had a state before it, in a term no later, and keeps its vote
if the term is unchanged. -/
private theorem vote_step {before after : Model.State} (tr : LocalTransition before after)
    {n : NodeID} {st : NodeState} (now : (n, st) ∈ after.nodes)
    : ∃ a, (n, a) ∈ before.nodes ∧ a.currentTerm ≤ st.currentTerm ∧
        (a.currentTerm = st.currentTerm → ∀ c, a.votedFor = some c → st.votedFor = some c) := by
  split_rel mem_after := (rcases tr.mem_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩) with
  | inl => exact ⟨tr.pre, tr.pre_mem, Summary.term_le tr.summary,
      fun same => Summary.vote_keep tr.summary same.symm⟩
  | inr => exact ⟨st, old, Nat.le_refl _, fun _ _ h => h⟩

omit c in
private theorem ballot_step {before after : Model.State} {g : VoteFacts.Ghost}
    (tr : LocalTransition before after)
    (unique : forall node first second,
      (node, first) ∈ after.nodes -> (node, second) ∈ after.nodes -> first = second)
    (prior : VoteFacts.Inv before g) : VoteFacts.Inv after (VoteFacts.advance g after) :=
  VoteFacts.preserve prior unique fun _ _ now => vote_step tr now

private theorem ballots : Ballots (f.advance after) :=
  ballot_step c.tr c.unique c.inv.ballots

private theorem rankAtGrant {v n t r k l i}
    (fresh : LogFacts.GrantAt f.current after v n t r) (obs : f.logs.seen v k l)
    (sig : isSignatureAt l i = true) (atI : termAt l i = k) :
    RankOrLoss f.logs.canon t r k i (l.take i) := by
  obtain ⟨st, _, preMem, _, le, _, _, up⟩ := fresh
  split_rel persist := (rcases c.inv.persist v st ⟨k, l⟩ i preMem obs sig with sub | lost) with
  | inl =>
    have bound := Nat.le_of_eq (List.length_take_of_le (signature_bound sig)).symm
    have signed := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl sig)
    have index := signatureIndex_le_maxCommittableIndex signed
    have rank := termAt_mono (c.inv.sorted v st preMem) index (maxCommittableIndexBounded _)
    rw [termAt_of_prefix sub bound, termAt_take Nat.le.refl, atI] at rank
    change k ≤ maxCommittableTerm st.log at rank
    exact .inl ⟨Nat.le_trans rank up.1,
      fun same => Nat.le_trans index (up.2 (Nat.le_antisymm up.1 (same ▸ rank)))⟩
  | inr =>
    obtain ⟨e, l', lo, hi, canon, missing⟩ := lost
    exact .inr ⟨e, l', atI ▸ lo, Nat.le_trans hi le, canon, missing⟩

/-- Seal the evidence for this step's grants before recording any new leader logs. -/
private theorem grantFactsBefore : GrantFacts (f.advance after).logs
    (f.advance after).votes f.logs.canon := by
  intro v n t r grant
  have extend (stamp : ⟨v, t, some n⟩ ∈ (f.advance after).votes)
      (old : VoterRank f.logs f.logs.canon v t t r) :
      VoterRank (f.advance after).logs f.logs.canon v t t r := by
    intro k l i obs lt sig atI
    split_rel observed := (rcases obs with past | ⟨st, now, term, _⟩) with
    | inl => exact old k l i past lt sig atI
    | inr =>
      have later : t ≤ st.currentTerm := c.ballots.bounds _ stamp st now
      omega
  split_rel grant := (rcases grant with old | ⟨p, eq, fresh, supported⟩) with
  | inl =>
    obtain ⟨⟨stamp, ranked⟩, l, seen⟩ := c.inv.grantFacts v n t r old
    have stamp' := (VoteFacts.mem_advance (s := after)).2 (.inr stamp)
    exact ⟨⟨stamp', extend stamp' ranked⟩, l, .inl seen⟩
  | inr =>
    change some f.current = some p at eq
    cases eq
    have rank : VoterRank f.logs f.logs.canon v t t r :=
      fun _ _ _ obs _ sig atI => c.rankAtGrant fresh obs sig atI
    obtain ⟨_, post, _, postMem, _, term, vote, _⟩ := fresh
    have stamp : ⟨v, t, some n⟩ ∈ (f.advance after).votes :=
      VoteFacts.mem_advance.2 (.inl ⟨v, post, postMem, by simp [VoteFacts.stamp, term, vote]⟩)
    exact ⟨⟨stamp, extend stamp rank⟩, supported⟩

private theorem grantFacts : GrantFacts (f.advance after).logs
    (f.advance after).votes (f.advance after).logs.canon := by
  intro v n t r grant
  obtain ⟨⟨stamp, ranked⟩, seen⟩ := c.grantFactsBefore v n t r grant
  exact ⟨⟨stamp, fun k l i obs lt sig atI =>
    (ranked k l i obs lt sig atI).map (fun _ _ le old => ⟨le, .inl old⟩)⟩, seen⟩

/-- The actor's own vote in the step. -/
private theorem self_granted {term : Nat} (le : c.pre.currentTerm <= term)
    (termEq : c.post.currentTerm = term) (voted : c.post.votedFor = some c.actor)
    : Granted (f.advance after) c.actor c.actor term
        (vals term c.pre.log c.pre.commitIndex) :=
  .inr ⟨
    f.current,
    rfl,
    ⟨
      c.pre,
      c.post,
      c.tr.pre_mem,
      c.tr.post_mem,
      le,
      termEq,
      voted,
      vals_outranks term c.pre_sorted c.frontier_pre
    ⟩,
    ⟨c.post.log, .inr ⟨c.post, c.tr.post_mem, termEq, rfl⟩⟩
  ⟩

/-- A campaign's term is above the bootstrap term and no earlier than the term before the
step, and every vote it counts was granted for its vote request. -/
private theorem campaign_facts {candidate : NodeState}
    (campaign : Campaign c.actor c.pre c.event candidate)
    : 3 <= candidate.currentTerm
      /\ (c.pre.currentTerm < candidate.currentTerm
          \/ (c.pre.currentTerm = candidate.currentTerm /\ c.pre.role = .candidate))
      /\ (c.post.currentTerm = candidate.currentTerm
          -> c.post.votedFor = candidate.votedFor
          -> forall voter,
              voter ∈ candidate.votesGranted
              -> Granted (f.advance after) voter c.actor candidate.currentTerm
                  (vals candidate.currentTerm c.pre.log c.pre.commitIndex)) := by
  split_rel campaign :=
      (obtain ⟨_, _, _, ⟨active, freshTerm, freshVote, freshVotes⟩
        | ⟨preRole, sameTerm, _, more⟩⟩ := campaign) with
  | inl =>
    have two := c.pre_two active
    have lt : c.pre.currentTerm < candidate.currentTerm :=
      Nat.lt_of_lt_of_le (Nat.lt_add_one _) (Nat.le_of_eq freshTerm.symm)
    refine ⟨Nat.le_trans (Nat.add_le_add_right two 1) (Nat.le_of_eq freshTerm.symm),
      Or.inl lt, fun termEq votedEq voter mem => ?_⟩
    rw [freshVotes, Finset.mem_singleton] at mem
    subst mem
    exact c.self_granted (Nat.le_of_lt lt) termEq (votedEq.trans freshVote)
  | inr =>
    have old := c.inv.candidate c.actor c.pre c.pre_now preRole
    refine ⟨Nat.le_trans old.1 (Nat.le_of_eq sameTerm.symm), Or.inr ⟨sameTerm.symm, preRole⟩,
      fun _ _ voter mem => ?_⟩
    rw [sameTerm]
    split_rel more := (by_cases counted : voter ∈ c.pre.votesGranted) with
    | pos => exact (old.2.2.1 voter counted).mono after
    | neg =>
      obtain ⟨response, eq, responseTerm, granted⟩ := more voter mem counted
      obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok eq
      simp only [MessageOK, payload] at ok
      obtain ⟨request, granted', _, forNow⟩ := ok granted
      rw [targetEq] at forNow
      rw [sourceEq, targetEq, responseTerm] at granted'
      have requestEq := forNow c.pre c.pre_now preRole responseTerm.symm
      rw [makeRequestVoteRequest_eq] at requestEq
      rw [← requestEq] at granted'
      exact granted'.mono after

/-- Winning an election records it in the updated ghost. -/
private theorem wins_elect (wins : Wins c.actor c.pre c.event c.post)
    : ElectStep f after c.actor c.post.currentTerm c.pre.log
        c.pre.commitIndex := by
  obtain ⟨candidate, campaign, quorum, logEq, termEq, votedEq, _, role, _⟩ := Wins.facts wins
  have ⟨_, candidateLog, candidateCommit, _⟩ := campaign
  obtain ⟨three, termCase, votes⟩ := c.campaign_facts campaign
  refine ⟨
    c.pre,
    c.post,
    c.tr.pre_mem,
    c.tr.post_mem,
    rfl,
    rfl,
    c.frontier_pre,
    ?_,
    rfl,
    role,
    ?_,
    Nat.le_trans three (Nat.le_of_eq termEq.symm),
    candidate.votesGranted,
    quorum,
    ?_
  ⟩
  · rw [termEq]
    exact termCase
  · obtain ⟨n, _, committable, _, eq⟩ := primaryState_log candidate
    rw [logEq, eq, candidateLog] at *
    exact take_prefix_take _ committable
  · intro voter mem
    rw [termEq]
    exact votes termEq votedEq voter mem

private theorem led_cur : LedCur (f.advance after) := by
  intro node state term now led
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨different, old⟩) with
  | inl =>
    subst nodeEq stateEq
    refine c.led_after led (fun led => ?_) fun _ _ step => ?_
    · have le := c.term_le
      split_rel led_cur :=
          (rcases c.inv.led_cur c.actor c.pre term c.pre_now led with lt | ⟨termEq, role⟩) with
      | inl => exact Or.inl (Nat.lt_of_lt_of_le lt le)
      | inr =>
        split_rel lt_or_eq_of_le := (rcases Nat.lt_or_eq_of_le le with lt | same) with
        | inl => exact Or.inl (Nat.lt_of_le_of_lt (Nat.le_of_eq termEq) lt)
        | inr =>
          refine Or.inr ⟨termEq.trans same, fun candidate => ?_⟩
          split_rel candidate :=
              (obtain ⟨_, _, _, ⟨_, fresh, _⟩ | ⟨preRole, _⟩⟩ :=
                Summary.candidate c.sum candidate) with
          | inl => exact Nat.succ_ne_self _ (fresh.symm.trans same.symm)
          | inr => exact role preRole
    · obtain ⟨_, _, _, _, termEq, role, _⟩ := c.electStep step
      refine Or.inr ⟨termEq.symm, ?_⟩
      split_rel role := (rcases role with role | role) with
      | inl => rw [role] <;> simp
      | inr => rw [role] <;> simp
  | inr => exact c.inv.led_cur node state term old (c.led_other different led)

private theorem leader_led : LeaderLed (f.advance after) := by
  intro node state now role
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    split_rel leader := (rcases Summary.leader c.sum role with ⟨preRole, termEq⟩ | wins) with
    | inl =>
      rw [termEq]
      exact (c.inv.leader_led c.actor c.pre c.pre_now preRole).mono after
    | inr => exact Or.inr ⟨_, _, .inr ⟨f.current, rfl, c.wins_elect wins⟩⟩
  | inr => exact (c.inv.leader_led node state old role).mono after

private theorem blocked_step {n t l i} (old : Blocked f.logs n t l i) :
    Blocked (f.advance after).logs n t l i := by
  intro xs quorum
  obtain ⟨v, mem, noGrant, k, a, j, seen, le, sig, term, low⟩ := old xs quorum
  refine ⟨v, mem, ?_, k, a, j, .inl seen, le, sig, term, low⟩
  intro grant
  split_rel grant := (rcases grant with past | ⟨p, eq, fresh, _⟩) with
  | inl => exact noGrant past
  | inr =>
    change some f.current = some p at eq
    cases eq
    split_rel rank := (rcases c.rankAtGrant fresh seen sig term with ranked | ⟨e, _, above, below, _⟩) with
    | inl => exact absurd ranked.1 (Nat.not_le_of_gt low)
    | inr => omega

private theorem blocked_no_election {n t l i} (blocked : Blocked f.logs n t l i)
    (elect : ElectStep f after n t l i) : False := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, voters, quorum, granted⟩ := elect
  obtain ⟨v, mem, noGrant, _⟩ := c.blocked_step blocked voters quorum
  exact noGrant ((granted v mem))

/-- At campaign start no grant for the fresh term exists. If the backing chain crosses
that term, its acknowledgment quorum supplies a blocker in every campaigning quorum. -/
private theorem pre_split {t : Nat} (fresh : c.pre.currentTerm < t) :
    Backed f c.pre.log c.pre.commitIndex (t - 1) ∨
      Blocked f.logs c.actor t c.pre.log c.pre.commitIndex := by
  obtain ⟨⟨_, e, p, committed, _, sub⟩, _⟩ := c.inv.commit_backed c.actor c.pre c.pre_now
  -- Evidence of a term from `t` on covers the prefix: its quorum blocks the campaign.
  refine backing_split (bound := t - 1) committed sub c.frontier_pre
    fun l k b i f gt base sub voters quorum => ?_
  have len := List.length_take_of_le c.frontier_pre
  have len' := List.length_take_of_le f.indexLe
  have ge := sub.length_le
  rw [len, len'] at ge
  have agree := List.prefix_iff_eq_take.mp sub
  rw [len, List.take_take, Nat.min_eq_left ge] at agree
  obtain ⟨xs, q, obs⟩ := f.acks
  obtain ⟨v, ack, vote⟩ := quorums_intersect_bounded Config.GENESIS_configured
    (c.inv.copyLog f.canon).rooted
    (c.inv.rooted c.actor c.pre c.pre_now) agree.symm base (Nat.le_refl _) f.baseLe ge
    (signature_pos f.signature) q quorum
  obtain ⟨a, seen, held⟩ := obs v ack
  have low := termAt_le_of_mem (c.inv.terms c.actor c.pre c.pre_now)
    (max c.pre.commitIndex (maxCommittableIndex c.pre.log))
  have later : t ≤ k :=
    Nat.le_of_lt_succ ((Nat.sub_lt_iff_lt_add (Nat.zero_lt_of_lt fresh)).mp gt)
  refine ⟨v, vote, ?_, k, a, i, seen, later,
    isSignatureAt_of_prefix held (isSignatureAt_take_of_le Nat.le.refl f.signature), ?_, ?_⟩
  · intro grant
    obtain ⟨l', observed⟩ := (c.inv.grantFacts v c.actor t _ grant).2
    have bound : t ≤ c.pre.currentTerm := c.inv.term_mono c.actor c.pre ⟨t, l'⟩ c.pre_now observed
    exact (Nat.not_le_of_gt fresh) bound
  · rw [termAt_of_prefix held (Nat.le_of_eq len'.symm), termAt_take Nat.le.refl, f.termAtIndex]
  · exact Nat.lt_of_le_of_lt low (Nat.lt_of_lt_of_le fresh later)

/-- A fresh campaign's committed prefix is backed, or doomed from the start. -/
private theorem campaign_backed {state : NodeState} (logEq : state.log = c.pre.log)
    (commitEq : state.commitIndex = c.pre.commitIndex)
    (termEq : state.currentTerm = c.pre.currentTerm + 1)
    : Backed (f.advance after) state.log state.commitIndex (state.currentTerm - 1)
      \/ Blocked (f.advance after).logs c.actor state.currentTerm state.log state.commitIndex := by
  rw [logEq, commitEq]
  split_rel pre_split := (rcases c.pre_split (t := state.currentTerm) (by omega) with backed | blocked) with
  | inl => exact .inl (backed.mono after)
  | inr => exact .inr (c.blocked_step blocked)

private theorem candidate : Candidate (f.advance after) := by
  intro node state now role
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    have campaign := Summary.candidate c.sum role
    have ⟨_, logEq, commitEq, kind⟩ := campaign
    obtain ⟨three, _, votes⟩ := c.campaign_facts campaign
    refine ⟨three, ?_, ?_, ?_, ?_⟩
    · split_rel kind := (rcases kind with ⟨_, _, voted, _⟩ | ⟨preRole, _, voted, _⟩) with
      | inl => exact voted
      | inr =>
        have own := (c.inv.candidate c.actor c.pre c.pre_now preRole).2.1
        split_rel voted := (rcases voted with none | voted) with
        | inl =>
          rw [own] at none
          cases none
        | inr => rw [← voted, own]
    · intro voter mem
      rw [logEq, commitEq]
      exact votes rfl rfl voter mem
    · split_rel kind := (rcases kind with ⟨_, fresh, _⟩ | ⟨preRole, same, _⟩) with
      | inl => exact c.campaign_backed logEq commitEq fresh
      | inr =>
        split_rel candidate :=
            (rcases (c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.2.1 with
              backed | doomed) with
        | inl =>
          left
          rw [logEq, commitEq, same]
          exact backed.mono after
        | inr =>
          rw [logEq, commitEq, same]
          exact .inr (c.blocked_step doomed)
    · intro entry member
      rw [logEq] at member
      split_rel kind := (rcases kind with ⟨_, fresh, _⟩ | ⟨preRole, same, _⟩) with
      | inl =>
        have := c.inv.terms c.actor c.pre c.pre_now entry member
        omega
      | inr =>
        rw [same]
        exact (c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.2.2 entry member
  | inr =>
    obtain ⟨three, voted, votes, backed, low⟩ := c.inv.candidate node state old role
    refine ⟨three, voted, fun voter mem => (votes voter mem).mono after, ?_, low⟩
    split_rel backed := (rcases backed with backed | doomed) with
    | inl => exact Or.inl (backed.mono after)
    | inr => exact .inr (c.blocked_step doomed)

/-- The candidate of an election step: its entries are of earlier terms, and its committed
prefix is backed below the election's term unless the election is blocked. -/
private theorem elect_candidate {node term log commit}
    (step : ElectStep f after node term log commit)
    : (forall entry, entry ∈ log -> entry.term < term)
      /\ (Backed f log commit (term - 1) ∨ Blocked f.logs node term log commit) := by
  have ⟨actorEq, logEq, commitEq, termCase, _⟩ := c.electStep step
  subst actorEq logEq commitEq
  split_rel termCase := (rcases termCase with lt | ⟨same, preRole⟩) with
  | inl =>
    exact ⟨fun entry mem =>
        Nat.lt_of_le_of_lt (c.inv.terms c.actor c.pre c.pre_now entry mem) lt,
      c.pre_split lt⟩
  | inr =>
    subst same
    have candidate := c.inv.candidate c.actor c.pre c.pre_now preRole
    exact ⟨candidate.2.2.2.2, candidate.2.2.2.1⟩

private theorem elect_backed {node term log commit}
    (step : ElectStep f after node term log commit) : Backed f log commit (term - 1) := by
  split_rel backed := (rcases (c.elect_candidate step).2 with backed | blocked) with
  | inl => exact backed
  | inr => exact (c.blocked_no_election blocked step).elim

private theorem freshCampaign {n t l i} (elect : ElectStep f after n t l i) :
    CampaignFacts (f.advance after).logs (f.advance after).votes
      f.logs.canon n t l i t := by
  have earlier := (c.elect_candidate elect).1
  obtain ⟨st, _, mem, _, logEq, _, front, _, _, _, _, floor, xs, q, grants⟩ := elect
  refine ⟨logEq ▸ c.inv.rooted n st mem, front, ?_, ⟨xs, q, fun x m =>
    (c.grantFactsBefore x n t _ ((grants x m))).1⟩⟩
  dsimp only
  intro pos
  let j := max i (maxCommittableIndex l)
  have jBound : j ≤ l.length := Nat.max_le.mpr ⟨front, maxCommittableIndexBounded _⟩
  have ⟨a, canon, le, eq⟩ := c.inv.anchor n st j mem pos (logEq ▸ jBound)
  rw [logEq] at canon eq
  refine ⟨?_, a, canon, le, eq⟩
  change termAt l j < t
  have le' := termAt_le_of_mem (log := l) (bound := t - 1)
    (fun e h => Nat.le_sub_one_of_lt (earlier e h)) j
  exact Nat.lt_of_le_of_lt le' (Nat.sub_one_lt (by omega))

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
open Consensus.Proofs.Config
variable [Config.InitialConfiguration]

/-- Prefix of a list of known length. -/
private theorem take_of_prefix_length {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (length : small.length = n)
    : small = large.take n := by
  rw [← length]
  exact List.prefix_iff_eq_take.mp sub

/-- Quorum intersection and log matching from the two certificates. In particular no
ordering of grant and acknowledgment events, or invariant at a past state, is an input. -/
private theorem core {g : LogFacts.Ghost} {v n t b i later commit bound k l log}
    (chain : LogFacts.Chain g) (step : CommitFacts g l t b i) (copy : CopyLog g t l)
    (floor : 2 ≤ t) (campaign : CampaignFacts g v g.canon n later log commit bound)
    (lt : t < later) (window : later - 1 ≤ bound)
    (agree : l.take k = log.take k) (baseLe : b ≤ k) (commitLe : commit ≤ k)
    (clean : ∀ e a, t < e → e ≤ bound → g.canon e a → l.take i <+: a) :
    l.take i <+: log := by
  obtain ⟨acks, ackQuorum, acked⟩ := step.acks
  obtain ⟨voters, voteQuorum, ranked⟩ := campaign.voters
  -- An elector committed through `index` already agrees on the committed part.
  split_rel covered := (by_cases covered : i <= commit) with
  | pos =>
    have agreeIndex : l.take i = log.take i := by
      have := congrArg (List.take i) agree
      rwa [List.take_take, List.take_take, Nat.min_eq_left (Nat.le_trans covered commitLe)] at this
    rw [agreeIndex]
    exact List.take_prefix _ _
  | neg =>
    obtain ⟨voter, ackMem, voteMem⟩ :=
      quorums_intersect_bounded GENESIS_configured copy.rooted campaign.rooted
        agree baseLe commitLe step.baseLe (Nat.le_of_lt (Nat.lt_of_not_le covered))
        (Nat.lt_of_le_of_lt (Nat.zero_le _) (Nat.lt_of_not_le covered)) ackQuorum voteQuorum
    obtain ⟨p, seen, sub⟩ := acked voter ackMem
    have partLength := List.length_take_of_le step.indexLe
    have partTerm : termAt (l.take i) i = t := by rw [termAt_take Nat.le.refl, step.termAtIndex]
    have atI : termAt p i = t := by rw [termAt_of_prefix sub (Nat.le_of_eq partLength.symm), partTerm]
    have signed := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl step.signature)
    let j := max commit (maxCommittableIndex log)
    have rank : t ≤ termAt log j ∧ (t = termAt log j → i ≤ j) := by
      split_rel rank := (rcases (ranked voter voteMem).2 t p i seen lt signed atI with rank | lost) with
      | inl => exact rank
      | inr =>
        obtain ⟨e, a, lo, hi, canon, missing⟩ := lost
        rw [← take_of_prefix_length sub partLength] at missing
        exact (missing (clean e a lo hi canon)).elim
    have termGe : t ≤ termAt log j := rank.1
    have jPos : 0 < j := by
      split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos j with zero | positive) with
      | inl =>
        rw [zero, termAt_zero] at termGe
        exact (Nat.not_succ_le_zero 1 (Nat.le_trans floor termGe)).elim
      | inr => exact positive
    obtain ⟨lower, anchored, canon, anchoredLength, anchoredTake⟩ := campaign.anchor jPos
    change termAt log j < later at lower
    change g.canon (termAt log j) anchored at canon
    change log.take j = anchored.take j at anchoredTake
    have viaAnchor (le : i ≤ j) (same : l.take i = anchored.take i) : l.take i <+: log := by
      have : log.take i = anchored.take i := by
        have := congrArg (List.take i) anchoredTake
        simp only [List.take_take, Nat.min_eq_left le] at this
        exact this
      rw [same, ← this]
      exact List.take_prefix _ _
    split_rel lt_or_eq_of_le := (rcases Nat.lt_or_eq_of_le termGe with above | same) with
    | inl =>
      have sub := clean _ anchored above (Nat.le_trans (Nat.le_sub_one_of_lt lower) window) canon
      split_rel lt_or_ge := (rcases Nat.lt_or_ge j i with short | long) with
      | inl =>
        exfalso
        have partSorted := copy.sorted.sublist (List.take_sublist i l)
        have mono := termAt_mono partSorted (Nat.le_of_lt short) (Nat.le_of_eq partLength.symm)
        have atJ : termAt (l.take i) j = termAt log j := by
          rw [← termAt_of_prefix sub (Nat.le_of_lt (Nat.lt_of_lt_of_eq short partLength.symm)),
            ← termAt_take (n := j) Nat.le.refl, ← anchoredTake,
            termAt_take Nat.le.refl]
        rw [atJ, partTerm] at mono
        exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le above mono)
      | inr =>
        exact viaAnchor long (take_of_prefix_length sub partLength)
    | inr =>
      have indexLeJ : i ≤ j := rank.2 same
      rw [← same] at canon
      have anchoredIndex := Nat.le_trans indexLeJ anchoredLength
      exact viaAnchor indexLeJ
        (chain _ _ _ canon step.canon i anchoredIndex step.indexLe).symm

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
open Consensus.Proofs.Config
open Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]

/--
The committed part is in `log`: it is already there, or the two logs agree on a prefix
covering both commit indices, which is what quorum intersection (`agreed`) needs. Above
the base, both lie along one committed `part`.
-/
private theorem contained_of_agree {α : Type} {state log : List α}
    {base index commit : Nat} (baseLe : base <= index) (indexLe : index <= state.length)
    (frontier : commit <= log.length) (low : commit <= base -> state.take base <+: log)
    (high
      : base < commit
        -> exists part,
            log.take commit <+: part
            /\ forall n, n <= (state.take index).length -> n <= part.length
                -> (state.take index).take n = part.take n)
    (agreed
      : forall k, state.take k = log.take k -> base <= k -> commit <= k
        -> state.take index <+: log)
    : state.take index <+: log := by
  split_rel lt_or_ge := (rcases (Nat.lt_or_ge base commit).symm with le | lt) with
  | inl => exact agreed base (take_of_prefix_length (low le)
      (List.length_take_of_le (Nat.le_trans baseLe indexLe))) Nat.le.refl le
  | inr =>
    obtain ⟨part, inPart, along⟩ := high lt
    have commitLength : (log.take commit).length = commit := List.length_take_of_le frontier
    have partLong : commit <= part.length := commitLength ▸ inPart.length_le
    have indexLength : (state.take index).length = index := List.length_take_of_le indexLe
    split_rel lt_or_ge := (rcases (Nat.lt_or_ge index commit).symm with le | short) with
    | inl =>
      refine agreed commit ?_ (Nat.le_of_lt lt) Nat.le.refl
      calc
        state.take commit = (state.take index).take commit := by
          rw [List.take_take, Nat.min_eq_left le]
        _ = part.take commit :=
          along commit (Nat.le_trans le (Nat.le_of_eq indexLength.symm)) partLong
        _ = log.take commit := by
          rw [take_eq_of_prefix inPart (Nat.le_of_eq commitLength.symm), List.take_take,
            Nat.min_self]
    | inr =>
      -- The whole part lies below the commit index, where `log` follows `part`.
      have eq := along index (Nat.le_of_eq indexLength.symm)
        (Nat.le_trans (Nat.le_of_lt short) partLong)
      rw [List.take_take, Nat.min_self,
        take_eq_of_prefix inPart (Nat.le_trans (Nat.le_of_lt short) (Nat.le_of_eq commitLength.symm)),
        List.take_take, Nat.min_eq_left (Nat.le_of_lt short)] at eq
      rw [eq]
      exact List.take_prefix _ _

private theorem termAt_append_right {front back : List Entry} {index : Nat}
    (above : front.length < index) (bound : index <= (front ++ back).length)
    : exists entry, entry ∈ back /\ termAt (front ++ back) index = entry.term := by
  rw [termAt_eq (Nat.lt_of_le_of_lt (Nat.zero_le _) above) bound,
    List.getElem_append_right (Nat.le_sub_one_of_lt above)]
  exact ⟨_, List.getElem_mem _, rfl⟩

/-- A prefix of a copyable log is copyable, at its term or any later one. -/
private theorem CopyLog.prefix {g : LogFacts.Ghost} {term later : Nat}
    {log small : List Entry} (copy : CopyLog g term log) (sub : small <+: log)
    (le : term <= later)
    : CopyLog g later small := by
  refine ⟨copy.rooted.prefix sub,
    fun entry mem => Nat.le_trans (copy.terms entry (sub.subset mem)) le,
    copy.sorted.sublist sub.sublist, fun index positive bound => ?_⟩
  obtain ⟨anchored, canon, length, take⟩ :=
    copy.anchor index positive (Nat.le_trans bound sub.length_le)
  refine ⟨anchored, ?_, length, ?_⟩
  · rw [← termAt_of_prefix sub bound]
    exact canon
  · rw [← take_eq_of_prefix sub bound]
    exact take

/-- A leader extends a copyable log by entries of its term; the extended log, being a
leader log of that term, anchors the new positions. -/
private theorem CopyLog.append {g : LogFacts.Ghost} {term : Nat} {log entries : List Entry}
    (copy : CopyLog g term log) (nonempty : log ≠ [])
    (terms : forall entry, entry ∈ entries -> entry.term = term)
    (canon : g.canon term (log ++ entries))
    : CopyLog g term (log ++ entries) := by
  refine ⟨copy.rooted.append nonempty entries, fun entry mem => ?_, ?_,
    fun index positive bound => ?_⟩
  · split_rel mem_append := (rcases List.mem_append.mp mem with old | new) with
    | inl => exact copy.terms entry old
    | inr => exact Nat.le_of_eq (terms entry new)
  · rw [List.pairwise_append]
    refine ⟨copy.sorted, ?_, ?_⟩
    · exact List.pairwise_of_forall_mem_list fun first firstMem second secondMem => by
        rw [terms first firstMem, terms second secondMem]
        exact Nat.le_refl _
    · intro first firstMem second secondMem
      rw [terms second secondMem]
      exact copy.terms first firstMem
  · split_rel lt_or_ge :=
        (rcases (Nat.lt_or_ge log.length index).symm with within | above) with
    | inl =>
      obtain ⟨anchored, anchoredCanon, length, take⟩ := copy.anchor index positive within
      refine ⟨anchored, ?_, length, ?_⟩
      · rw [termAt_of_prefix (List.prefix_append log entries) within]
        exact anchoredCanon
      · rw [take_eq_of_prefix (List.prefix_append log entries) within]
        exact take
    | inr =>
      obtain ⟨entry, mem, eq⟩ := termAt_append_right above bound
      refine ⟨log ++ entries, ?_, bound, rfl⟩
      rw [eq, terms entry mem]
      exact canon

/-- A committed prefix of an earlier term is in the log of an election whose voters
certified their ranks, given that leader logs of the terms in between already hold every
earlier commit. By induction on the derivation of the commit, not on execution steps. -/
private theorem carried_of_chain {g : LogFacts.Ghost} {v n later log commit bound t p}
    (campaign : CampaignFacts g v g.canon n later log commit bound)
    (window : later - 1 ≤ bound)
    (backing : ∃ e q, Commit g e q ∧ e ≤ later - 1 ∧ log.take commit <+: q)
    (chains : LogFacts.Chain g) (prior : LaterUpTo g bound) (logs : CopyLogs g)
    (floor : ∀ k l, g.canon k l → 2 ≤ k)
    (cert : Commit g t p) (lt : t < later) : p <+: log := by
  split_rel certificate := (induction cert) with
  | base => exact List.nil_prefix
  | link =>
    rename_i l t b i e q facts old le within ih
    have mem : Commit g t (l.take i) := .link facts old le within
    have low : commit ≤ b → l.take b <+: log :=
      fun _ => within.trans (ih (Nat.lt_of_le_of_lt le lt))
    have high (_ : b < commit) :
        ∃ q, log.take commit <+: q
          ∧ ∀ n, n ≤ (l.take i).length → n ≤ q.length → (l.take i).take n = q.take n := by
      obtain ⟨_, q, held, below, sub⟩ := backing
      exact ⟨q, sub, agree_upto chains prior floor mem held
        (Nat.le_trans (Nat.le_sub_one_of_lt lt) window) (Nat.le_trans below window)⟩
    exact contained_of_agree facts.baseLe facts.indexLe campaign.frontier low high
      fun k agree baseLe commitLe =>
        core chains facts (logs _ _ facts.canon) (floor _ _ facts.canon) campaign lt window
          agree baseLe commitLe (fun e a above below canon => prior t e _ a mem canon above below)

/-- Every committed prefix is in the log of every election of a later term. The
argument reads the certificates of one frame only: it visits no step and no
earlier frame. It is by induction on the election's term; within a term,
`carried_of_chain` inducts on the derivation of the commit. -/
private theorem complete_of {g : LogFacts.Ghost} {v : VoteFacts.Ghost}
    (ranked : RankedElections g v) (certs : ElectionCerts g v)
    (wins : LogFacts.WinningPrefix g) (chains : LogFacts.Chain g)
    (logs : CopyLogs g) (floor : ∀ k l, g.canon k l → 2 ≤ k) : Complete g := by
  suffices all : forall later term part node log commit,
      Commit g term part -> g.elected node later log commit -> term < later
      -> part <+: log from
    fun term part node later log commit committed elected lt =>
      all later term part node log commit committed elected lt
  intro later
  induction later using Nat.strongRecOn with
  | _ later outer =>
    intro term part node log commit committed elected lt
    have earlier : CompleteUpTo g (later - 1) := fun k p n t l i com elect lt' below =>
      outer t (Nat.lt_of_le_of_lt below (Nat.sub_one_lt (Nat.ne_of_gt (Nat.zero_lt_of_lt lt))))
        k p n l i com elect lt'
    obtain ⟨e, q, backing, below, inPart⟩ := (certs node later log commit elected).backing
    exact carried_of_chain (ranked node later log commit elected) (Nat.le_refl _)
      ⟨e, q, backing, Nat.le_sub_one_of_lt below, inPart⟩ chains
      (later_upto wins earlier floor) logs floor committed lt

/-- Completeness is not a clause of the invariant: the election certificates and leader
logs of a frame already imply it. -/
private theorem Inv.completeness {h : Frame} (inv : Inv h) : Completeness h :=
  complete_of inv.rankedElections inv.electionCerts inv.winningPrefix inv.chains inv.copyLogs
    (fun _ _ canon => inv.canon_floor canon)

private theorem Inv.later {h : Frame} (inv : Inv h) : Later h.logs :=
  later_of_complete inv.winningPrefix inv.completeness (fun _ _ canon => inv.canon_floor canon)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
open Consensus.Proofs.Config
open Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
variable {f : Frame} {after : Model.State} (c : Ctx f after)
include c

/-- A part committed before the step is in the log of a new election. -/
private theorem old_in_new {node : NodeID} {later commit : Nat} {log : List Entry}
    (elect : ElectStep f after node later log commit)
    {term : Nat} {part : List Entry}
    (committed : Committed f term part)
    (lt : term < later)
    : part <+: log := by
  have campaign := (c.freshCampaign elect).transport (g' := f.logs)
    (fun _ m => m) (fun _ _ h => h) (fun _ _ _ le => le) (fun _ _ _ _ obs _ => .inl obs)
  exact carried_of_chain campaign (Nat.sub_le _ _) (c.elect_backed elect) c.inv.chains
    (fun k t p l com canon above _ => c.inv.later k t p l com canon above)
    c.inv.copyLogs (fun _ _ canon => c.inv.canon_floor canon) committed lt

private theorem freshCert {node : NodeID} {term commit : Nat} {log : List Entry}
    (elect : ElectStep f after node term log commit) :
    ElectionCert f.logs (f.advance after).votes
      node term log commit := by
  obtain ⟨e, p, com, le, sub⟩ := c.elect_backed elect
  obtain ⟨st, _, mem, _, logEq, _, front, _, _, _, _, above, voters, quorum, granted⟩ := elect
  have pos := Nat.lt_of_lt_of_le (by decide : 0 < 3) above
  exact ⟨above, logEq ▸ c.inv.rooted _ _ mem, front,
    ⟨e, p, com, Nat.lt_of_le_of_lt le (Nat.sub_one_lt (Nat.ne_of_gt pos)), sub⟩,
    ⟨voters, quorum, fun v m =>
      (c.grantFactsBefore v node term _ ((granted v m))).1.1⟩⟩

omit c in
private theorem certificates_agree {g : LogFacts.Ghost} {v : VoteFacts.Ghost}
    {s : Model.State} {n m k l i l' i'} (a : ElectionCert g v n k l i)
    (b : ElectionCert g v m k l' i') (votes : VoteFacts.Inv s v)
    (carriedA : ∀ t p, Commit g t p → t < k → p <+: l)
    (carriedB : ∀ t p, Commit g t p → t < k → p <+: l') : n = m := by
  have takeEq {x y : List Entry} {j : Nat} (front : j ≤ x.length)
      (back : ∃ e p, Commit g e p ∧ e < k ∧ x.take j <+: p)
      (carry : ∀ t p, Commit g t p → t < k → p <+: y) : x.take j = y.take j := by
    obtain ⟨e, p, com, lt, sub⟩ := back
    exact take_of_prefix_length (sub.trans (carry e p com lt)) (List.length_take_of_le front)
  have agree : ∃ j, l.take j = l'.take j ∧ i ≤ j ∧ i' ≤ j := by
    split_rel le_total := (rcases Nat.le_total i' i with le | le) with
    | inl => exact ⟨i, takeEq a.frontier a.backing carriedB, Nat.le_refl _, le⟩
    | inr => exact ⟨i', (takeEq b.frontier b.backing carriedA).symm, le, Nat.le_refl _⟩
  obtain ⟨j, eq, le, le'⟩ := agree
  obtain ⟨xs, q, observed⟩ := a.quorum
  obtain ⟨ys, q', observed'⟩ := b.quorum
  obtain ⟨voter, mem, mem'⟩ := quorums_intersect GENESIS_configured a.rooted b.rooted eq le le' q q'
  exact votes.unique voter k n m (observed voter mem) (observed' voter mem')

private theorem new_old_unique {node other : NodeID} {term commit : Nat}
    {log : List Entry}
    (elect : ElectStep f after node term log commit)
    (led : Led f other term)
    : node = other := by
  have fresh := c.freshCert elect
  split_rel led := (rcases led with ⟨same, _⟩ | ⟨l, i, old⟩) with
  | inl =>
    have := fresh.above
    simp [same, BOOTSTRAP_TERM] at this
  | inr =>
    have cert := c.inv.electionCerts other term l i (old)
    apply certificates_agree fresh (cert.weaken (fun _ _ h => h)
      (fun _ h => VoteFacts.mem_advance.2 (.inr h))) c.ballots
    · exact fun _ _ com => c.old_in_new elect com
    · exact fun _ _ com => c.inv.completeness _ _ _ _ _ _ (com) old

private theorem election_safety : ElectionSafety (f.advance after) := by
  intro node other term left right
  refine c.led_after left (fun left => ?_) fun _ _ leftStep => ?_
  · refine c.led_after right (fun right => ?_) fun _ _ rightStep => ?_
    · exact c.inv.election_safety node other term left right
    · exact (c.new_old_unique rightStep left).symm
  · refine c.led_after right (fun right => ?_) fun _ _ rightStep => ?_
    · exact c.new_old_unique leftStep right
    · exact (c.electStep leftStep).1.trans (c.electStep rightStep).1.symm

/-- Every election keeps its certificate and ranks; the election of the step has those of
its campaign. -/
private theorem elections : Elections (f.advance after).logs (f.advance after).votes := by
  intro n t l i e
  split_rel elected := (rcases c.elected_after (e) with old | new) with
  | inl =>
    obtain ⟨cert, ranked⟩ := c.inv.elections n t l i old
    refine ⟨cert.weaken (fun _ _ h => Commit.advance h)
      (fun _ h => VoteFacts.mem_advance.2 (.inr h)), ?_⟩
    apply ranked.transport (fun _ m => VoteFacts.mem_advance.2 (.inr m))
      (fun _ _ m => .inl m) (fun _ _ _ le => le)
    intro x stamp k p seen lt
    split_rel seen := (rcases seen with past | ⟨st, now, term, _⟩) with
    | inl => exact past
    | inr =>
      have ge : t ≤ st.currentTerm := c.ballots.bounds _
        (VoteFacts.mem_advance.2 (.inr stamp)) st now
      omega
  | inr =>
    refine ⟨(c.freshCert new).weaken (fun _ _ h => Commit.advance h) (fun _ h => h), ?_⟩
    apply (c.freshCampaign new).transport (fun _ m => m) (fun _ _ m => .inl m) ?_
      (fun _ _ _ _ obs _ => obs)
    intro k p witnessed le
    suffices ne : k ≠ t from Nat.le_sub_one_of_lt (Nat.lt_of_le_of_ne le ne)
    rintro rfl
    obtain ⟨other, old⟩ := c.inv.owner witnessed
    have same := c.new_old_unique new old
    subst other
    obtain ⟨st', _, mem, _, _, _, _, termCase, _⟩ := new
    split_rel led := (rcases c.inv.led_cur n st' k mem old with lt | ⟨eq, notCandidate⟩) with
    | inl =>
      split_rel term_when_older := (rcases termCase with lt' | ⟨eq', _⟩) with
      | inl => exact (Nat.not_lt_of_ge (Nat.le_of_lt lt)) lt'
      | inr => exact (Nat.ne_of_gt lt) eq'
    | inr =>
      split_rel term_when_equal := (rcases termCase with lt' | ⟨_, role⟩) with
      | inl => exact (Nat.not_lt_of_ge (Nat.le_of_eq eq)) lt'
      | inr => exact notCandidate role

private theorem electionCerts : ElectionCerts (f.advance after).logs
    (f.advance after).votes :=
  fun n k l i e => (c.elections n k l i e).1

private theorem rankedElections : RankedElections (f.advance after).logs
    (f.advance after).votes :=
  fun n t l i e => (c.elections n t l i e).2

/-- A leader continuing in its term keeps its log. -/
private theorem keep_log (sameTerm : c.post.currentTerm = c.pre.currentTerm)
    (role : Not (c.pre.role = .candidate))
    (led : Led f c.actor c.pre.currentTerm)
    : c.pre.log <+: c.post.log := by
  split_rel kind := (cases Summary.kind c.sum) with
  | same =>
    rename_i log _
    rw [log]; exact List.prefix_refl _
  | append =>
    rename_i _ _ _ _ advance
    rw [(Advance.facts advance).1]
    exact List.prefix_append _ _
  | ack =>
    rename_i _ _ _ _ _ _ advance
    rw [(Advance.facts advance).1]; exact List.prefix_refl _
  | accept =>
    rename_i source request eq accepted
    exfalso
    obtain ⟨_, evidence⟩ := c.accept_evidence eq
    have : source = c.actor :=
      c.inv.election_safety source c.actor request.term evidence.led
        (by rw [accepted.1, sameTerm]; exact led)
    exact evidence.different this.symm
  | elect =>
    rename_i wins
    exact (wins.fresh sameTerm role).elim
  | install =>
    rename_i _ _ _ fresh _ _ _ _
    have := c.inv.leader_floor led
    rw [fresh.2.1] at this
    omega

/-- Every leader log is nonempty: an elected log holds its quorum's configuration. -/
private theorem leader_logs : LeaderLogs (f.advance after) := by
  intro node state now role
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    split_rel leader := (rcases Summary.leader c.sum role with ⟨preRole, termEq⟩ | wins) with
    | inl =>
      have keep := c.keep_log termEq (by rw [preRole]; simp)
        (c.inv.leader_led c.actor c.pre c.pre_now preRole)
      have nonempty := c.inv.leader_logs c.actor c.pre c.pre_now preRole
      intro empty
      rw [empty] at keep
      exact nonempty (List.prefix_nil.mp keep)
    | inr =>
      obtain ⟨candidate, campaign, quorum, logEq, _⟩ := Wins.facts wins
      have ⟨_, candidateLog, _, _⟩ := campaign
      have nonempty := hasQuorum_nonempty quorum
      obtain ⟨n, _, _, positive, eq⟩ := primaryState_log candidate
      rw [logEq, eq, candidateLog] at *
      simp only [ne_eq, List.take_eq_nil_iff, not_or]
      exact ⟨Nat.ne_of_gt (positive nonempty), nonempty⟩
  | inr => exact c.inv.leader_logs node state old role

/-- An earlier leadership of the actor in its new term continues. -/
private theorem old_led_actor (led : Led f c.actor c.post.currentTerm)
    : c.pre.currentTerm = c.post.currentTerm /\ Not (c.pre.role = .candidate) := by
  have le := c.term_le
  split_rel led_cur := (rcases c.inv.led_cur c.actor c.pre _ c.pre_now led with lt | ⟨eq, role⟩) with
  | inl => exact (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt le)).elim
  | inr => exact ⟨eq.symm, role⟩

/-- The cases of a step for a node that leads its term afterwards. Another node is
unchanged. The actor keeps its log, extends it with entries of its term, or wins an
election; it neither accepts a request, whose sender leads the same term, nor installs a
snapshot. -/
private theorem leader_cases {motive : NodeID -> NodeState -> Prop} {node : NodeID}
    {state : NodeState} (now : Now (f.advance after) node state)
    (led : Led (f.advance after) node state.currentTerm)
    (other : Now f node state -> motive node state)
    (keeps : c.post.log = c.pre.log -> motive c.actor c.post)
    (appends
      : forall (entries : List Entry) (sent : NodeID -> Nat),
          c.pre.role = .primary
          -> (forall entry, entry ∈ entries -> entry.term = c.pre.currentTerm)
          -> Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent }
              c.post
          -> motive c.actor c.post)
    (wins : Wins c.actor c.pre c.event c.post -> motive c.actor c.post)
    : motive node state := by
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨_, old⟩) with
  | inl =>
    subst nodeEq stateEq
    split_rel kind := (cases Summary.kind c.sum) with
    | same =>
      rename_i log _
      exact keeps log
    | append =>
      rename_i entries sent leader terms advance
      exact appends entries sent leader terms advance
    | ack =>
      rename_i _ _ _ _ _ _ advance
      exact keeps (Advance.facts advance).1
    | accept =>
      rename_i source request eq accepted
      exfalso
      obtain ⟨_, evidence⟩ := c.accept_evidence eq
      have : source = c.actor :=
        c.election_safety source c.actor request.term (evidence.led.mono after)
          (by rw [accepted.1]; exact led)
      exact evidence.different this.symm
    | elect =>
      rename_i won
      exact wins won
    | install =>
      rename_i _ _ _ fresh _ _ _ role
      exfalso
      refine c.led_after led (fun old => ?_) fun _ _ step => ?_
      · have floor := c.inv.leader_floor old
        have zero : c.pre.currentTerm = 0 := fresh.2.1
        split_rel led_cur :=
            (rcases c.inv.led_cur c.actor c.pre _ c.pre_now old with lt | ⟨eq, _⟩) with
        | inl => omega
        | inr => omega
      · have roleCase := (c.electStep step).2.2.2.2.2.1
        rw [role] at roleCase
        split_rel roleCase := (rcases roleCase with primary | none) with
        | inl => cases primary
        | inr => cases none
  | inr => exact other old

/-- A node that already led its term continues from an earlier state of that term. -/
private theorem continuing {node : NodeID} {state : NodeState}
    (now : Now (f.advance after) node state) (role : Not (state.role = .candidate))
    (led : Led f node state.currentTerm) :
    ∃ before, Now f node before ∧ before.currentTerm = state.currentTerm
      ∧ Not (before.role = .candidate) ∧ before.log <+: state.log := by
  have extends_ (keep : c.pre.log <+: c.post.log) (led : Led f c.actor c.post.currentTerm) :
      ∃ before, Now f c.actor before ∧ before.currentTerm = c.post.currentTerm
        ∧ Not (before.role = .candidate) ∧ before.log <+: c.post.log := by
    obtain ⟨eq, preRole⟩ := c.old_led_actor led
    exact ⟨c.pre, c.pre_now, eq, preRole, keep⟩
  refine c.leader_cases
    (motive := fun node state =>
      Not (state.role = .candidate) -> Led f node state.currentTerm
      -> ∃ before, Now f node before ∧ before.currentTerm = state.currentTerm
          ∧ Not (before.role = .candidate) ∧ before.log <+: state.log)
    now (led.mono after)
    (fun old role _ => ⟨state, old, rfl, role, List.prefix_refl _⟩)
    (fun log _ led => extends_ (by rw [log]; exact List.prefix_refl _) led)
    (fun entries sent _ _ advance _ led =>
      extends_ (by rw [(Advance.facts advance).1]; exact List.prefix_append _ _) led)
    (fun won _ led => ?_) role led
  -- A node that led the term before the step does not win it again.
  obtain ⟨eq, preRole⟩ := c.old_led_actor led
  exact (won.fresh eq.symm preRole).elim

private theorem canon_mono : CanonMono (f.advance after) := by
  intro node state now role led
  refine ⟨.inr ⟨node, state, ⟨now, rfl, role, led⟩, rfl⟩, fun log canon => ?_⟩
  split_rel canon_after :=
      (rcases c.canon_after canon with canon | ⟨node', state', ⟨now', _, _, led'⟩, logEq⟩) with
  | inl =>
    -- An earlier leader log of the term is its one leader's, whose log only grew.
    obtain ⟨node', led'⟩ := c.inv.owner canon
    have := c.election_safety node' node _ (led'.mono after) led
    subst this
    obtain ⟨before, old, term, oldRole, keep⟩ := c.continuing now role led'
    rw [← term] at canon led'
    exact ((c.inv.canon_mono node' before old oldRole led').2 _ canon).trans keep
  | inr =>
    -- A leader log recorded by this state is that of the one leader of the term.
    have := c.election_safety node' node _ led' led
    subst this logEq
    rw [c.unique _ _ _ now' now]
    exact List.prefix_refl _

/-- A leader that appends entries of its term keeps a copyable log: the extended log
becomes the leader log of its term. -/
private theorem append_copy {entries : List Entry} {sent : NodeID -> Nat}
    (leader : c.pre.role = .primary)
    (terms : forall entry, entry ∈ entries -> entry.term = c.pre.currentTerm)
    (advance
      : Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post)
    : CopyLog (f.advance after).logs c.post.currentTerm c.post.log := by
  obtain ⟨log, term, role⟩ := Advance.facts advance
  have notCandidate : Not (c.post.role = .candidate) := fun candidate => by
    have kept := role.resolve_right (by rw [candidate]; simp)
    rw [candidate] at kept
    simp [leader] at kept
  rw [log, term]
  refine ((c.inv.node_logs c.actor c.pre c.pre_now).mono after).append
    (c.inv.leader_logs c.actor c.pre c.pre_now leader) terms ?_
  exact .inr ⟨c.actor, c.post, ⟨c.post_now, term, notCandidate,
    (c.inv.leader_led c.actor c.pre c.pre_now leader).mono after⟩, log⟩

/-- The log of a node that leads its term stays copyable. -/
private theorem leader_copy {node : NodeID} {state : NodeState}
    (now : Now (f.advance after) node state)
    (led : Led (f.advance after) node state.currentTerm)
    : CopyLog (f.advance after).logs state.currentTerm state.log := by
  have shorter (sub : c.post.log <+: c.pre.log) :
      CopyLog (f.advance after).logs c.post.currentTerm c.post.log :=
    ((c.inv.node_logs c.actor c.pre c.pre_now).prefix sub c.term_le).mono after
  refine c.leader_cases
    (motive := fun _ state => CopyLog (f.advance after).logs state.currentTerm state.log)
    now led
    (fun old => (c.inv.node_logs node state old).mono after)
    (fun log => shorter (by rw [log]; exact List.prefix_refl _))
    (fun _ _ leader terms advance => c.append_copy leader terms advance)
    (fun won => ?_)
  obtain ⟨_, ⟨_, candidateLog, _⟩, _, log, _⟩ := Wins.facts won
  exact shorter (by rw [log, ← candidateLog]; exact primaryState_log_prefix _)

private theorem chains : LogFacts.Chain (f.advance after).logs := by
  apply LogFacts.chain_step c.inv.chains
  rintro n st k ⟨now, rfl, role, led⟩ l canon
  exact (c.canon_mono n st now role led).2 l canon

/-- Every log stays one a follower may copy: a prefix of the old log, the leader's own
extension of it, or a prefix of a leader log. -/
private theorem node_logs : NodeLogs (f.advance after) := by
  intro node state now
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    have pre := c.inv.node_logs c.actor c.pre c.pre_now
    -- A prefix of the old log stays copyable, and so does a prefix of a leader log.
    have shorter (sub : c.post.log <+: c.pre.log) :
        CopyLog (f.advance after).logs c.post.currentTerm c.post.log :=
      (pre.prefix sub c.term_le).mono after
    have copied {leaderLog : List Entry} {n : Nat}
        (copy : CopyLog f.logs c.post.currentTerm leaderLog)
        (log : c.post.log = leaderLog.take n) :
        CopyLog (f.advance after).logs c.post.currentTerm c.post.log := by
      rw [log]
      exact (copy.prefix (List.take_prefix n leaderLog) (Nat.le_refl _)).mono after
    split_rel kind := (cases Summary.kind c.sum) with
    | same =>
      rename_i log _
      exact shorter (by rw [log]; exact List.prefix_refl _)
    | append =>
      rename_i entries sent leader terms advance
      exact c.append_copy leader terms advance
    | ack =>
      rename_i _ _ _ _ _ _ advance
      obtain ⟨log, _, _⟩ := Advance.facts advance
      exact shorter (by rw [log]; exact List.prefix_refl _)
    | accept =>
      rename_i source request eq accepted
      split_rel accept_shape :=
          (obtain ⟨leaderLog, evidence, bound, _, same | ⟨fresh, _⟩, _⟩ :=
            c.accept_shape eq accepted) with
      | inl => exact shorter (by rw [same]; exact List.prefix_refl _)
      | inr => exact copied (accepted.1 ▸ c.inv.copyLog evidence.canon) fresh
    | elect =>
      rename_i wins
      obtain ⟨_, ⟨_, candidateLog, _⟩, _, log, _⟩ := Wins.facts wins
      exact shorter (by rw [log, ← candidateLog]; exact primaryState_log_prefix _)
    | install =>
      rename_i entries initialized signed _ log _ term _
      refine c.snap_cases initialized signed
        (fun nil => shorter (by rw [log, nil]; exact List.nil_prefix))
        fun ⟨_, _, ⟨leaderLog, canon, inLog⟩, _⟩ => ?_
      exact copied (by rw [term]; exact c.inv.copyLog canon)
        (by rw [log]; exact List.prefix_iff_eq_take.mp inLog)
  | inr => exact (c.inv.node_logs node state old).mono after

/-- Every leader log is copyable, has a leader, and extends its election's winning prefix. -/
private theorem canonLogs : CanonLogs (f.advance after).logs := by
  apply canonLogs_step c.inv.canonLogs
  rintro n st k ⟨now, rfl, role, led⟩
  refine ⟨c.leader_copy now led, ⟨_, led⟩, fun gt => ?_⟩
  refine c.led_after led (fun oldLed => ?_) fun l i step => ?_
  · -- A continuing leader extends its previous log, which already held the prefix.
    obtain ⟨before, old, term, oldRole, keep⟩ := c.continuing now role oldLed
    rw [← term] at oldLed gt ⊢
    obtain ⟨m, p, i, elect, sub⟩ := c.inv.winningPrefix _ _
      (c.inv.canon_mono n before old oldRole oldLed).1 gt
    exact ⟨m, p, i, .inl elect, sub.trans keep⟩
  · obtain ⟨rfl, _, _, _, _, _, winning, _⟩ := c.electStep step
    obtain rfl := c.now_post now
    exact ⟨_, l, i, .inr ⟨f.current, rfl, step⟩, winning⟩

private theorem winningPrefix : LogFacts.WinningPrefix (f.advance after).logs :=
  fun k l canon gt => (c.canonLogs k l canon).winning gt

private theorem copyLogs : CopyLogs (f.advance after).logs :=
  fun k l canon => (c.canonLogs k l canon).copy

private theorem canon_floor {k : Nat} {l : List Entry} (canon : Canon (f.advance after) k l) :
    2 ≤ k := by
  obtain ⟨n, led⟩ := (c.canonLogs k l canon).owner
  exact led_floor c.electionCerts led

private theorem completeness : Completeness (f.advance after) :=
  complete_of c.rankedElections c.electionCerts c.winningPrefix c.chains c.copyLogs
    (fun _ _ canon => c.canon_floor canon)

private theorem later : Later (f.advance after).logs :=
  later_of_complete c.winningPrefix c.completeness (fun _ _ canon => c.canon_floor canon)

private theorem comparable : Comparable (f.advance after) :=
  fun _ _ _ _ left right =>
    comparable_of c.chains c.later (fun _ _ canon => c.canon_floor canon) left right

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

private theorem Backed.transfer {frame : Frame} {log log' : List Entry}
    {commit term : Nat} (backed : Backed frame log commit term)
    (agree : log'.take commit = log.take commit)
    : Backed frame log' commit term := by
  obtain ⟨earlier, part, committed, le, within⟩ := backed
  exact ⟨earlier, part, committed, le, agree ▸ within⟩

private theorem maxCommittableIndexUpTo_le (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= frontier :=
  Nat.le_trans (maxCommittableIndexBounded (log.take frontier)) (List.length_take_le _ _)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {f : Frame} {after : Model.State} (c : Ctx f after)
include c

private theorem pre_led (leader : c.pre.role = .primary)
    : Led f c.actor c.pre.currentTerm :=
  c.inv.leader_led c.actor c.pre c.pre_now leader

private theorem post_led
    (origin
      : (c.pre.role = .primary /\ c.post.currentTerm = c.pre.currentTerm)
        \/ Wins c.actor c.pre c.event c.post)
    : Led (f.advance after) c.actor c.post.currentTerm := by
  split_rel origin := (rcases origin with ⟨leader, termEq⟩ | wins) with
  | inl =>
    rw [termEq]
    exact (c.pre_led leader).mono after
  | inr => exact Or.inr ⟨_, _, .inr ⟨f.current, rfl, c.wins_elect wins⟩⟩

/-- An acknowledgement of a leader's term holds a prefix of the leader's log. -/
private theorem acked_pre (leader : c.pre.role = .primary) {voter : NodeID} {index : Nat}
    (acked : Acked f voter c.pre.currentTerm index)
    : exists acker,
        Seen (f.advance after) voter acker
        /\ acker.currentTerm = c.pre.currentTerm
        /\ index <= c.pre.log.length
        /\ c.pre.log.take index <+: acker.log := by
  obtain ⟨acker, log, seen, termEq, canon, bound, sub⟩ := acked
  have notCandidate : Not (c.pre.role = .candidate) := by
    rw [leader]
    intro h
    cases h
  have inLog :=
    (c.inv.canon_mono c.actor c.pre c.pre_now notCandidate (c.pre_led leader)).2 log canon
  refine ⟨acker, seen.mono after, termEq, Nat.le_trans bound inLog.length_le, ?_⟩
  rw [take_eq_of_prefix inLog bound]
  exact sub

/-- An advanced commit index is a commit step backed by the earlier one. -/
private theorem advance_backed {middle : NodeState}
    (advance : Advance c.actor middle c.post)
    (old : Backed f c.post.log middle.commitIndex c.post.currentTerm)
    (led : Led (f.advance after) c.actor c.post.currentTerm)
    (role : middle.role = .primary)
    (acks
      : forall voter,
          Not (voter = c.actor)
          -> 0 < middle.matchIndex voter
          -> exists acker,
              Seen (f.advance after) voter acker
              /\ acker.currentTerm = c.post.currentTerm
              /\ c.post.log.take (middle.matchIndex voter) <+: acker.log)
    : Backed (f.advance after) c.post.log c.post.commitIndex
        c.post.currentTerm := by
  have log := advance.log
  have term := advance.term
  split_rel advance :=
      (rcases Nat.eq_or_lt_of_le advance.commit_le with same | lt) with
  | inl =>
    rw [← same]
    exact old.mono after
  | inr =>
    have eq := advance.commit_eq lt
    have notCandidate : Not (c.post.role = .candidate) := fun candidate => by
      have kept := advance.role_kept (by rw [candidate]; simp)
      rw [candidate, role] at kept
      cases kept
    rw [eq]
    dsimp only [highestCommittableIndex]
    refine foldl_select_step _
      (fun commit => Backed (f.advance after) c.post.log commit c.post.currentTerm)
      _ _ (old.mono after) fun commit index member backed selected => ?_
    obtain ⟨above, signature, termEq, quorum⟩ := selected
    have bound : index <= middle.log.length := Nat.lt_succ_iff.mp (List.mem_range.mp member)
    obtain ⟨voters, quorum, members⟩
        : exists voters,
            hasQuorum
              ((activeConfigurations middle.log commit).filter
                fun configuration => configuration.index <= index)
              voters
            /\ forall voter, voter ∈ voters
                -> voter = c.actor \/ middle.matchIndex voter >= index :=
      ⟨_, quorum, fun _ mem => (Finset.mem_filter.mp mem).2⟩
    have facts : CommitFacts (f.advance after).logs c.post.log c.post.currentTerm
        commit index := by
      refine ⟨.inr ⟨c.actor, c.post, ⟨c.post_now, rfl, notCandidate, led⟩, rfl⟩,
        Nat.le_of_lt above, ?_, ?_, ?_, voters, ?_, ?_⟩
      · rw [log]
        exact bound
      · rw [log]
        exact signature
      · rw [log, termEq, term]
      · rw [log]
        exact quorum
      · intro voter mem
        split_rel self := (by_cases self : voter = c.actor) with
        | pos =>
          subst self
          exact ⟨c.post.log, c.post_seen, List.take_prefix _ _⟩
        | neg =>
          have ge := (members voter mem).resolve_left self
          obtain ⟨acker, seen, ackerTerm, sub⟩ :=
            acks voter self (Nat.lt_of_le_of_lt (Nat.zero_le _) (Nat.lt_of_lt_of_le above ge))
          exact ⟨acker.log, ackerTerm ▸ seen,
            (take_prefix_take _ ge).trans sub⟩
    obtain ⟨earlier, part, prior, le, within⟩ := backed
    exact ⟨_, _, .link facts prior le within, Nat.le.refl, List.prefix_refl _⟩

private theorem pre_backed
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    (leader : c.pre.role = .primary)
    : Backed f c.post.log c.pre.commitIndex c.post.currentTerm :=
  (((c.inv.commit_backed c.actor c.pre c.pre_now).2 leader).weaken c.term_le).transfer
    agree

private theorem pre_backed_any
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    : exists term,
        Backed (f.advance after) c.post.log c.pre.commitIndex term := by
  obtain ⟨⟨term, backed⟩, _⟩ := c.inv.commit_backed c.actor c.pre c.pre_now
  exact ⟨term, (backed.transfer agree).mono after⟩

/-- A step keeping the committed prefix keeps a leader's backing in its term. -/
private theorem keep_backed
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    (commitEq : c.post.commitIndex = c.pre.commitIndex)
    (origin
      : (c.pre.role = .primary /\ c.post.currentTerm = c.pre.currentTerm)
        \/ Wins c.actor c.pre c.event c.post)
    : Backed (f.advance after) c.post.log c.post.commitIndex
        c.post.currentTerm := by
  rw [commitEq]
  split_rel origin := (rcases origin with ⟨leader, _⟩ | wins) with
  | inl => exact (c.pre_backed agree leader).mono after
  | inr =>
    have backed := c.elect_backed (c.wins_elect wins)
    exact ((backed.weaken (Nat.sub_le _ _)).transfer agree).mono after

/-- A leader's acknowledged prefix, from its match index. -/
private theorem match_pre (leader : c.pre.role = .primary) {voter : NodeID}
    (different : Not (voter = c.actor)) (positive : 0 < c.pre.matchIndex voter)
    : exists acker,
        Seen (f.advance after) voter acker
        /\ acker.currentTerm = c.pre.currentTerm
        /\ c.pre.matchIndex voter <= c.pre.log.length
        /\ c.pre.log.take (c.pre.matchIndex voter) <+: acker.log :=
  c.acked_pre leader
    (c.inv.match_ack c.actor c.pre voter c.pre_now leader different positive)

private theorem accept_backed {source : NodeID} {request : AppendEntriesRequest}
    (received : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post)
    : exists term,
        Backed (f.advance after) c.post.log c.post.commitIndex term := by
  obtain ⟨leaderLog, evidence, _, postTake, shape, prevAgree⟩ :=
    c.accept_shape received accepted
  obtain ⟨_, _, commitLe, _, _, _, commitEq⟩ := accepted
  rw [commitEq]
  split_rel max_eq_or :=
      (rcases Std.max_eq_or (a := c.pre.commitIndex)
        (b := maxCommittableIndexUpTo c.post.log
          (min request.primaryCommit (request.prevLogIndex + request.entries.length))) with
        choice | choice) with
  | inl =>
    rw [choice]
    refine c.pre_backed_any ?_
    split_rel shape := (rcases shape with same | ⟨fresh, _⟩) with
    | inl => rw [same]
    | inr =>
      rw [fresh]
      calc
        (leaderLog.take (request.prevLogIndex + request.entries.length)).take
              c.pre.commitIndex
            = leaderLog.take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left (Nat.le_trans commitLe (Nat.le_add_right _ _))]
        _ = (leaderLog.take request.prevLogIndex).take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left commitLe]
        _ = (c.pre.log.take request.prevLogIndex).take c.pre.commitIndex := by
          rw [prevAgree]
        _ = c.pre.log.take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left commitLe]
  | inr =>
    rw [choice]
    have kLe := maxCommittableIndexUpTo_le c.post.log
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
    generalize maxCommittableIndexUpTo c.post.log
      (min request.primaryCommit (request.prevLogIndex + request.entries.length)) = k at kLe ⊢
    refine ⟨request.term,
      ((evidence.backed.shorten (Nat.le_trans kLe (Nat.min_le_left ..))).transfer ?_).mono after⟩
    have eq := congrArg (List.take k) postTake
    simpa only [List.take_take, Nat.min_eq_left (Nat.le_trans kLe (Nat.min_le_right ..))] using eq

/-- A leader that appends entries keeps its commit index backed within its term. -/
private theorem append_backing {entries : List Entry} {sent : NodeID -> Nat}
    (leader : c.pre.role = .primary)
    (advance
      : Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post)
    : Backed (f.advance after) c.post.log c.post.commitIndex c.post.currentTerm := by
  have logEq : c.post.log = c.pre.log ++ entries := (Advance.facts advance).1
  have termEq : c.post.currentTerm = c.pre.currentTerm := (Advance.facts advance).2.1
  refine c.advance_backed advance (c.pre_backed ?_ leader) ?_ leader ?_
  · rw [logEq]
    exact List.take_append_of_le_length c.frontier_pre
  · rw [termEq]
    exact (c.pre_led leader).mono after
  · intro voter different positive
    obtain ⟨acker, seen, ackerTerm, bound, sub⟩ := c.match_pre leader different positive
    refine ⟨acker, seen, by rw [ackerTerm, termEq], ?_⟩
    dsimp only
    rw [logEq, List.take_append_of_le_length bound]
    exact sub

/-- A leader that counts an acknowledgement keeps its commit index backed within its
term. -/
private theorem ack_backing {source : NodeID} {response : AppendEntriesResponse}
    (received : c.event = .receive source (.appendEntriesResponse response))
    (leader : c.pre.role = .primary) (success : response.success = true)
    (responseTerm : response.term = c.pre.currentTerm)
    (advance
      : Advance c.actor
          {
            c.pre with
              matchIndex :=
                Function.update c.pre.matchIndex source
                  (max (c.pre.matchIndex source) response.lastLogIndex)
          }
          c.post)
    : Backed (f.advance after) c.post.log c.post.commitIndex c.post.currentTerm := by
  have logEq : c.post.log = c.pre.log := (Advance.facts advance).1
  have termEq : c.post.currentTerm = c.pre.currentTerm := (Advance.facts advance).2.1
  refine c.advance_backed advance (c.pre_backed (by rw [logEq]) leader) ?_ leader ?_
  · rw [termEq]
    exact (c.pre_led leader).mono after
  · intro voter different positive
    dsimp only at positive ⊢
    rw [logEq, termEq]
    split_rel fromSource := (by_cases fromSource : voter = source) with
    | pos =>
      subst fromSource
      rw [Function.update_self] at positive ⊢
      split_rel max_eq_or :=
          (rcases Std.max_eq_or (a := c.pre.matchIndex voter) (b := response.lastLogIndex) with
            choice | choice) with
      | inl =>
        rw [choice] at positive ⊢
        obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.match_pre leader different positive
        exact ⟨acker, seen, ackerTerm, sub⟩
      | inr =>
        rw [choice] at positive ⊢
        obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
        simp only [MessageOK, payload] at ok
        have acked := ok success
        rw [sourceEq, responseTerm] at acked
        obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.acked_pre leader acked
        exact ⟨acker, seen, ackerTerm, sub⟩
    | neg =>
      rw [Function.update_of_ne fromSource] at positive ⊢
      obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.match_pre leader different positive
      exact ⟨acker, seen, ackerTerm, sub⟩

/-- A new leader's commit index is backed within its term: its log keeps the committed
prefix it campaigned with. -/
private theorem wins_backing (wins : Wins c.actor c.pre c.event c.post)
    : Backed (f.advance after) c.post.log c.post.commitIndex c.post.currentTerm := by
  have elect := c.wins_elect wins
  have winning := (c.electStep elect).2.2.2.2.2.2.1
  obtain ⟨candidate, ⟨_, candidateLog, candidateCommit, _⟩, _, advance, _⟩ := wins
  have committable : c.pre.commitIndex <= maxCommittableIndex c.pre.log := by
    split_rel eq_zero_or_pos := (rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | positive) with
    | inl => exact Nat.le_trans (Nat.le_of_eq zero) (Nat.zero_le _)
    | inr =>
      exact signatureIndex_le_maxCommittableIndex
        ((c.inv.frontier _ _ c.pre_now).2 positive)
  have agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex := by
    rw [take_eq_of_prefix winning
        (by rw [List.length_take]; exact Nat.le_min.mpr ⟨committable, c.frontier_pre⟩),
      List.take_take, Nat.min_eq_left committable]
  refine c.advance_backed advance ?_ (Or.inr ⟨_, _, .inr ⟨f.current, rfl, elect⟩⟩) rfl ?_
  · show Backed _ _ candidate.commitIndex _
    rw [candidateCommit]
    exact ((c.elect_backed elect).weaken (Nat.sub_le _ _)).transfer agree
  · intro voter _ positive
    exact absurd positive (Nat.lt_irrefl 0)

/-- The cases of a step for the backing of the actor's commit index. A step that appends,
counts an acknowledgement or wins an election backs the commit index within the new
term; the other steps keep the log and commit index, accept a request, or install a
snapshot. -/
private theorem backing_cases {motive : Prop}
    (keeps : c.post.log = c.pre.log -> c.post.commitIndex = c.pre.commitIndex -> motive)
    (leads
      : Backed (f.advance after) c.post.log c.post.commitIndex c.post.currentTerm -> motive)
    (accepts
      : forall (source : NodeID) (request : AppendEntriesRequest),
          c.event = .receive source (.appendEntriesRequest request)
          -> Accepted c.pre request c.post -> motive)
    (installs
      : forall entries : List Entry,
          c.event = .internal (.initAsBackup entries)
          -> (0 < entries.length -> isSignatureAt entries entries.length = true)
          -> c.pre.isFresh -> c.post.log = entries -> c.post.commitIndex = entries.length
          -> motive)
    : motive := by
  split_rel kind := (cases Summary.kind c.sum) with
  | same =>
      rename_i log commit
      exact keeps log commit
  | append =>
      rename_i entries sent leader _ advance
      exact leads (c.append_backing leader advance)
  | ack =>
      rename_i source response received leader success responseTerm advance
      exact leads (c.ack_backing received leader success responseTerm advance)
  | accept =>
      rename_i source request received accepted
      exact accepts source request received accepted
  | elect =>
      rename_i wins
      exact leads (c.wins_backing wins)
  | install =>
      rename_i entries initialized signed fresh log commit _ _
      exact installs entries initialized signed fresh log commit

/-- The actor's commit index is backed in some term. -/
private theorem post_backed_any
    : exists term, Backed (f.advance after) c.post.log c.post.commitIndex term := by
  refine c.backing_cases (fun log commit => ?_) (fun backed => ⟨_, backed⟩)
    (fun _ _ received accepted => c.accept_backed received accepted)
    fun entries initialized signed _ log commit => ?_
  · rw [commit]
    exact c.pre_backed_any (by rw [log])
  · refine c.snap_cases initialized signed
      (fun nil => ⟨0, 0, [], Commit.base, Nat.le.refl,
        by rw [log, nil, List.take_nil]; exact List.nil_prefix⟩)
      fun ⟨_, _, _, term, part, committed, inPart⟩ => ?_
    refine ⟨term, term, part, committed.mono after, Nat.le.refl, ?_⟩
    rw [log, commit, List.take_length]
    exact inPart

/-- The commit index of a node that continues or begins to lead is backed within its
term. Such a node neither accepts a request, whose sender leads the same term, nor
installs a snapshot. -/
private theorem origin_backing
    (origin
      : (c.pre.role = .primary /\ c.post.currentTerm = c.pre.currentTerm)
        \/ Wins c.actor c.pre c.event c.post)
    : Backed (f.advance after) c.post.log c.post.commitIndex c.post.currentTerm := by
  refine c.backing_cases (fun log commit => c.keep_backed (by rw [log]) commit origin) id
    (fun source request received accepted => ?_)
    fun entries initialized _ fresh _ _ => ?_
  · exfalso
    split_rel origin := (rcases origin with ⟨leader, termEq⟩ | wins) with
    | inl =>
      -- The sender leads the term of the request, so the receiver did not.
      obtain ⟨_, evidence⟩ := c.accept_evidence received
      have : source = c.actor :=
        c.inv.election_safety source c.actor request.term evidence.led
          (by rw [accepted.1, termEq]; exact c.pre_led leader)
      exact evidence.different this.symm
    | inr =>
      obtain ⟨_, _, _, _, electing⟩ := wins
      rw [received] at electing
      exact electing
  · exfalso
    split_rel origin := (rcases origin with ⟨leader, _⟩ | wins) with
    | inl =>
      -- A fresh node has no role.
      rw [fresh.1] at leader
      cases leader
    | inr =>
      obtain ⟨_, _, _, _, electing⟩ := wins
      rw [initialized] at electing
      exact electing

private theorem commit_backed : CommitBacked (f.advance after) := by
  intro node state now
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨_, old⟩) with
  | inl =>
    subst nodeEq stateEq
    exact ⟨c.post_backed_any, fun role => c.origin_backing (Summary.leader c.sum role)⟩
  | inr =>
    obtain ⟨⟨term, backed⟩, strong⟩ := c.inv.commit_backed node state old
    exact ⟨⟨term, backed.mono after⟩, fun role => (strong role).mono after⟩

/-- A signed prefix of the follower's log survives an accepted request, unless
the sender's leader log of a later term lacks it. -/
private theorem accept_persist {source : NodeID} {request : AppendEntriesRequest}
    (received : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post) {part : List Entry}
    (signature : isSignatureAt part part.length = true) (inPre : part <+: c.pre.log)
    : part <+: c.post.log
      \/ Bad (f.advance after) part (termAt part part.length)
          c.post.currentTerm := by
  obtain ⟨leaderLog, evidence, batchBound, _, shape, _⟩ :=
    c.accept_shape received accepted
  split_rel shape := (rcases shape with same | ⟨fresh, differ⟩) with
  | inl =>
    left
    rw [same]
    exact inPre
  | inr =>
    have requestTerm : request.term = c.post.currentTerm := accepted.1
    have senderCanon : Canon f c.post.currentTerm leaderLog := requestTerm ▸ evidence.canon
    generalize request.prevLogIndex + request.entries.length = n at batchBound fresh differ
    -- A part agreeing with the sender beyond the batch end contradicts the truncation.
    have beyond : n < part.length -> Not (part.take n = leaderLog.take n) := by
      intro long agree
      apply differ
      rw [← agree]
      exact take_eq_of_prefix inPre (Nat.le_of_lt long)
    split_rel inSender := (by_cases inSender : part <+: leaderLog) with
    | pos =>
      split_rel lt_or_ge := (rcases (Nat.lt_or_ge n part.length).symm with short | long) with
      | inl =>
        left
        have := take_prefix_take leaderLog short
        rw [← List.prefix_iff_eq_take.mp inSender] at this
        rw [fresh]
        exact this
      | inr => exact (beyond long (take_eq_of_prefix inSender (Nat.le_of_lt long)).symm).elim
    | neg =>
      have positive := signature_pos signature
      have termLe : termAt part part.length <= c.post.currentTerm :=
        Nat.le_trans (termAt_le_of_mem (fun entry mem => c.inv.terms c.actor c.pre c.pre_now entry
          (inPre.subset mem)) _) c.term_le
      split_rel lt_or_ge :=
          (rcases Nat.lt_or_ge (termAt part part.length) c.post.currentTerm with lower | upper) with
      | inl =>
        exact Or.inr ⟨c.post.currentTerm, leaderLog, lower, Nat.le.refl,
          senderCanon.mono after, inSender⟩
      | inr =>
        exfalso
        obtain ⟨log, logCanon, length, take⟩ :=
          c.inv.anchor c.actor c.pre part.length c.pre_now positive inPre.length_le
        have partEq : c.pre.log.take part.length = part :=
          (List.prefix_iff_eq_take.mp inPre).symm
        have termEq : termAt c.pre.log part.length = c.post.currentTerm := by
          have := termAt_take (log := c.pre.log) (Nat.le_refl part.length)
          rw [partEq] at this
          exact this.symm.trans (Nat.le_antisymm termLe upper)
        rw [termEq] at logCanon
        have partLog : part = log.take part.length := partEq.symm.trans take
        have agree := c.inv.chains _ _ _ logCanon senderCanon
        split_rel lt_or_ge :=
            (rcases (Nat.lt_or_ge leaderLog.length part.length).symm with fits | long) with
        | inl =>
          apply inSender
          rw [partLog, agree _ length fits]
          exact List.take_prefix _ _
        | inr =>
          have short := Nat.lt_of_le_of_lt batchBound long
          apply beyond short
          rw [partLog, List.take_take, Nat.min_eq_left (Nat.le_of_lt short)]
          exact agree _ (Nat.le_trans batchBound (Nat.le_trans (Nat.le_of_lt long) length))
            batchBound

/-- A signed prefix of the actor's log survives the step, unless a leader log
of a later term lacks it. -/
private theorem persist_pre {part : List Entry}
    (signature : isSignatureAt part part.length = true) (inPre : part <+: c.pre.log)
    : part <+: c.post.log
      \/ Bad (f.advance after) part (termAt part part.length)
          c.post.currentTerm := by
  split_rel kind := (cases Summary.kind c.sum) with
  | same =>
      rename_i log _
      left
      rw [log]
      exact inPre
  | append =>
      rename_i _ _ _ _ advance
      left
      rw [(Advance.facts advance).1]
      exact inPre.trans (List.prefix_append _ _)
  | ack =>
      rename_i _ _ _ _ _ _ advance
      left
      rw [(Advance.facts advance).1]
      exact inPre
  | accept =>
      rename_i _ _ received accepted
      exact c.accept_persist received accepted signature inPre
  | elect =>
      rename_i wins
      left
      have winning : c.pre.log.take (maxCommittableIndex c.pre.log) <+: c.post.log :=
        (c.electStep (c.wins_elect wins)).2.2.2.2.2.2.1
      exact (prefix_committable inPre signature).trans winning
  | install =>
      rename_i _ _ _ fresh _ _ _ _
      rw [fresh.2.2.1, List.prefix_nil] at inPre
      subst inPre
      simp [isSignatureAt, entryAt?] at signature

private theorem persist : Persist (f.advance after) := by
  intro node state earlier index now seen signature
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨different, old⟩) with
  | inl =>
    subst nodeEq stateEq
    split_rel seen_after := (rcases c.seen_after seen with oldSeen | ⟨same, stateEq⟩) with
    | inl =>
      split_rel persist :=
          (rcases c.inv.persist c.actor c.pre earlier index c.pre_now oldSeen signature with
            inPre | ⟨later, log, lt, le, canon, missing⟩) with
      | inl =>
        have termEq : termAt (earlier.log.take index) (earlier.log.take index).length
            = termAt earlier.log index := by
          rw [List.length_take, Nat.min_eq_left (signature_bound signature),
            termAt_take Nat.le.refl]
        rw [← termEq]
        exact c.persist_pre (take_signature signature) inPre
      | inr => exact Or.inr ⟨later, log, lt, Nat.le_trans le c.term_le, canon.mono after, missing⟩
    | inr =>
      subst stateEq
      exact Or.inl (List.take_prefix _ _)
  | inr =>
    split_rel seen_after := (rcases c.seen_after seen with oldSeen | ⟨same, _⟩) with
    | inl =>
      split_rel persist := (rcases c.inv.persist node state earlier index old oldSeen signature with sub | bad) with
      | inl => exact Or.inl sub
      | inr => exact Or.inr (bad.mono after)
    | inr => exact (different same).elim

private theorem match_ack : MatchAck (f.advance after) := by
  intro node state peer now leader different positive
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    split_rel leader := (rcases Summary.leader c.sum leader with ⟨preLeader, termEq⟩ | wins) with
    | inl =>
      rw [termEq]
      have kept (positive : 0 < c.pre.matchIndex peer) :=
        (c.inv.match_ack c.actor c.pre peer c.pre_now preLeader different positive).mono after
      split_rel matchIndex :=
          (rcases Summary.matchIndex c.sum leader preLeader termEq with
            same | ⟨source, response, received, success, responseTerm, matchEq⟩) with
      | inl =>
        rw [same] at positive ⊢
        exact kept positive
      | inr =>
        -- The response raises the sender's match index to what it acknowledged, if higher.
        rw [matchEq] at positive ⊢
        split_rel fromSource := (by_cases fromSource : peer = source) with
        | pos =>
          subst fromSource
          rw [Function.update_self] at positive ⊢
          split_rel max_eq_or :=
              (rcases Std.max_eq_or (a := c.pre.matchIndex peer) (b := response.lastLogIndex) with
                choice | choice) with
          | inl =>
            rw [choice] at positive ⊢
            exact kept positive
          | inr =>
            rw [choice]
            obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
            simp only [MessageOK, payload] at ok
            have acked := ok success
            rw [sourceEq, responseTerm] at acked
            exact acked.mono after
        | neg =>
          rw [Function.update_of_ne fromSource] at positive ⊢
          exact kept positive
    | inr =>
      obtain ⟨_, _, _, _, _, _, zero, _⟩ := Wins.facts wins
      rw [zero] at positive
      exact absurd positive (Nat.lt_irrefl 0)
  | inr => exact (c.inv.match_ack node state peer old leader different positive).mono after

/-- Vote requests recorded for a candidacy stay accurate while it lasts. -/
private theorem rv_stable {node : NodeID} {term : Nat} {request : RequestVoteRequest}
    (seen : exists state, Seen f node state /\ state.currentTerm = term)
    (stable
      : forall state,
          Now f node state
          -> state.role = .candidate
          -> state.currentTerm = term
          -> makeRequestVoteRequest state = request)
    : forall state,
        Now (f.advance after) node state
        -> state.role = .candidate
        -> state.currentTerm = term
        -> makeRequestVoteRequest state = request := by
  intro state now role termEq
  split_rel now_after := (rcases c.now_after now with ⟨nodeEq, stateEq⟩ | ⟨other, old⟩) with
  | inl =>
    subst nodeEq stateEq
    split_rel candidate :=
        (obtain ⟨_, logEq, commitEq, ⟨_, freshTerm, _⟩ | ⟨preRole, sameTerm, _⟩⟩ :=
          Summary.candidate c.sum role) with
    | inl =>
      obtain ⟨earlier, earlierSeen, earlierTerm⟩ := seen
      have := c.inv.term_mono c.actor c.pre earlier c.pre_now earlierSeen
      exact absurd (Nat.le_trans
        (Nat.le_of_eq (earlierTerm.trans (termEq.symm.trans freshTerm)).symm) this)
        (Nat.not_succ_le_self _)
    | inr =>
      have preTerm : c.pre.currentTerm = term := by
        rw [← sameTerm]
        exact termEq
      have := stable c.pre c.pre_now preRole preTerm
      rw [makeRequestVoteRequest_eq] at this ⊢
      rw [logEq, commitEq, sameTerm]
      exact this
  | inr => exact stable state old role termEq

private theorem seen_term {node : NodeID} {term : Nat}
    (seen : exists state, Seen f node state /\ state.currentTerm = term)
    : exists state,
        Seen (f.advance after) node state /\ state.currentTerm = term := by
  obtain ⟨state, seen, termEq⟩ := seen
  exact ⟨state, seen.mono after, termEq⟩

private theorem old_message {envelope : Model.Envelope}
    (ok : MessageOK f envelope)
    : MessageOK (f.advance after) envelope := by
  split_rel h := (cases h : envelope.payload) with
  | appendEntriesRequest =>
      simp only [MessageOK, h] at ok ⊢
      obtain ⟨log, o⟩ := ok
      exact ⟨log, o.different, o.led.mono after, o.canon.mono after,
        o.prevBound, o.prevTerm, o.entries, o.backed.mono after⟩
  | appendEntriesResponse =>
      simp only [MessageOK, h] at ok ⊢
      exact fun success => (ok success).mono after
  | requestVoteRequest =>
      simp only [MessageOK, h] at ok ⊢
      obtain ⟨seen, stable⟩ := ok
      exact ⟨c.seen_term seen, c.rv_stable seen stable⟩
  | requestVoteResponse =>
      simp only [MessageOK, h] at ok ⊢
      intro granted
      obtain ⟨request, grantedBy, seen, stable⟩ := ok granted
      exact ⟨request, grantedBy.mono after, c.seen_term seen, c.rv_stable seen stable⟩
  | requestPreVoteRequest => simp only [MessageOK, h]
  | requestPreVoteResponse => simp only [MessageOK, h]
  | proposeRequestVoteRequest => simp only [MessageOK, h]

private theorem new_message {envelope : Model.Envelope} (new : envelope ∈ c.sent)
    : MessageOK (f.advance after) envelope := by
  obtain ⟨sourceEq, ok⟩ := Summary.sends c.sum envelope new
  split_rel h := (cases h : envelope.payload) with
  | appendEntriesRequest =>
      simp only [h] at ok
      simp only [MessageOK, h]
      rw [sourceEq]
      obtain ⟨aeok, notCandidate, origin⟩ := ok
      obtain ⟨different, term, bound, prevTerm, entries, commitLe⟩ := aeok
      have led := c.post_led origin
      refine ⟨c.post.log, different, term ▸ led, ?_, bound, prevTerm, entries, ?_⟩
      · exact .inr ⟨c.actor, c.post, ⟨c.post_now, term.symm,
          notCandidate, term ▸ led⟩, rfl⟩
      · rw [term]
        exact (c.origin_backing origin).shorten commitLe
  | appendEntriesResponse =>
      simp only [h] at ok
      simp only [MessageOK, h]
      intro success
      obtain ⟨source, request, received, accepted, responseTerm, lastEq⟩ := ok success
      obtain ⟨leaderLog, evidence, batchBound, postTake, _, _⟩ :=
        c.accept_shape received accepted
      rw [sourceEq, responseTerm, lastEq]
      refine ⟨observe c.post, leaderLog, c.post_seen, rfl, ?_, batchBound, ?_⟩
      · rw [← accepted.1]
        exact evidence.canon.mono after
      · rw [← postTake]
        exact List.take_prefix _ _
  | requestVoteRequest =>
      simp only [h] at ok
      simp only [MessageOK, h]
      rw [sourceEq]
      obtain ⟨termEq, _, stable⟩ := ok
      refine ⟨⟨observe c.post, c.post_seen, termEq.symm⟩, fun state now role _ => ?_⟩
      rw [c.now_post now] at role ⊢
      exact stable role
  | requestVoteResponse =>
      simp only [h] at ok
      simp only [MessageOK, h]
      obtain ⟨termEq, grants⟩ := ok
      intro granted
      obtain ⟨request, received, requestTerm, upToDate, voted⟩ := grants granted
      obtain ⟨_, ok', sourceEq', _, payload'⟩ := c.received_ok received
      simp only [MessageOK, payload'] at ok'
      obtain ⟨seen, stable⟩ := ok'
      rw [sourceEq', requestTerm] at seen stable
      rw [termEq]
      refine ⟨request, ?_, c.seen_term seen, c.rv_stable seen stable⟩
      rw [sourceEq]
      obtain ⟨o, seen, atT⟩ := seen
      exact .inr ⟨f.current, rfl, ⟨c.pre, c.post, c.tr.pre_mem,
        c.tr.post_mem, c.term_le, rfl, voted, outranks_of_upToDate upToDate⟩,
        ⟨o.log, .inl (atT ▸ seen)⟩⟩
  | requestPreVoteRequest => simp only [MessageOK, h]
  | requestPreVoteResponse => simp only [MessageOK, h]
  | proposeRequestVoteRequest => simp only [MessageOK, h]

private theorem messages : Messages (f.advance after) := by
  intro envelope pending
  split_rel mem_network := (rcases c.tr.mem_network pending with old | new) with
  | inl => exact c.old_message (c.inv.messages envelope old)
  | inr => exact c.new_message new

private theorem message_terms : MessageTerms (f.advance after) := by
  intro envelope pending bumping
  split_rel mem_network := (rcases c.tr.mem_network pending with old | new) with
  | inl => exact c.inv.message_terms envelope old bumping
  | inr =>
    have two := c.post_two (Summary.bumps c.sum ⟨envelope, new, bumping⟩)
    obtain ⟨_, ok⟩ := Summary.sends c.sum envelope new
    split_rel h := (cases h : envelope.payload) with
    | appendEntriesRequest =>
        simp only [h] at ok
        simp only [Message.term]
        exact Nat.le_trans two (Nat.le_of_eq ok.1.2.1.symm)
    | appendEntriesResponse =>
        rw [h] at bumping
        exact bumping.elim
    | requestVoteRequest =>
        simp only [h] at ok
        simp only [Message.term]
        exact Nat.le_trans two (Nat.le_of_eq ok.1.symm)
    | requestVoteResponse =>
        simp only [h] at ok
        simp only [Message.term]
        exact Nat.le_trans two (Nat.le_of_eq ok.1.symm)
    | requestPreVoteRequest =>
        simp only [h, Message.term] at ok ⊢
        exact Nat.le_trans two (Nat.le_of_eq ok.symm)
    | requestPreVoteResponse =>
        simp only [h, Message.term] at ok ⊢
        exact Nat.le_trans two (Nat.le_of_eq ok.symm)
    | proposeRequestVoteRequest =>
        rw [h] at bumping
        exact bumping.elim

private theorem inv_step : Inv (f.advance after) :=
  {
    node_logs := c.node_logs
    active := c.active
    ballots := c.ballots
    grantFacts := c.grantFacts
    led_cur := c.led_cur
    leader_led := c.leader_led
    candidate := c.candidate
    elections := c.elections
    election_safety := c.election_safety
    canon_mono := c.canon_mono
    chains := c.chains
    canonLogs := c.canonLogs
    commit_backed := c.commit_backed
    persist := c.persist
    match_ack := c.match_ack
    messages := c.messages
    message_terms := c.message_terms
    leader_logs := c.leader_logs
    comparable := c.comparable
    unique := c.unique
    observed := fun _ st mem => .inr ⟨st, mem, rfl, rfl⟩
    term_mono := by
      intro n st o mem seen
      split_rel term_mono_seen := (rcases c.seen_after seen with old | ⟨rfl, rfl⟩) with
      | inl =>
        split_rel term_mono_now := (rcases c.now_after mem with ⟨rfl, rfl⟩ | ⟨_, pre⟩) with
        | inl => exact Nat.le_trans (c.inv.term_mono _ _ _ c.pre_now old) c.term_le
        | inr => exact c.inv.term_mono _ _ _ pre old
      | inr =>
        rw [c.now_post mem]
        exact Nat.le_refl _
    frontier := by
      intro n st mem
      split_rel frontier_now := (rcases c.now_after mem with ⟨rfl, rfl⟩ | ⟨_, old⟩) with
      | inl => exact (Summary.kind c.sum).frontier (c.inv.frontier _ _ c.pre_now)
      | inr => exact c.inv.frontier n st old
  }

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

/-- Every reachable protocol state has current ghost evidence satisfying the invariant. -/
private theorem inv_of_reachable {nodes : List NodeID} {state : Model.State}
    (reachable : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state) :
    ∃ f : Frame, f.current = state ∧ Inv f := by
  split_rel reachable := (induction reachable using
    (@TransitionSystem.Reachable.rec (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes))) with
  | initial =>
    rename_i init
    exact ⟨Frame.start _, rfl, inv_initial init⟩
  | step =>
    rename_i _ stepped ih
    obtain ⟨f, rfl, prior⟩ := ih
    obtain ⟨tr⟩ := LocalTransition.ofStep stepped
    exact ⟨f.advance _, rfl, (Ctx.mk tr prior).inv_step⟩

/-- The committed logs of two nodes in one state are comparable. -/
private theorem committed_logs_comparable {frame : Frame}
    (inv : Inv frame) {left right : NodeID}
    {leftState rightState : NodeState} (leftNow : Now frame left leftState)
    (rightNow : Now frame right rightState)
    : leftState.committedLog <+: rightState.committedLog
      \/ rightState.committedLog <+: leftState.committedLog := by
  unfold NodeState.committedLog
  obtain ⟨_, _, part, committed, _, within⟩ := (inv.commit_backed left leftState leftNow).1
  obtain ⟨_, _, part', committed', _, within'⟩ :=
    (inv.commit_backed right rightState rightNow).1
  split_rel committed_comparable :=
      (rcases committed_comparable inv committed committed' with sub | sub) with
  | inl => exact comparable_of_prefix (within.trans sub) within'
  | inr => exact comparable_of_prefix within (within'.trans sub)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Election

open CCF (Finset)
open Model.Node

private theorem primary_eq_of_reachable [Config.InitialConfiguration]
    {nodes : List Model.Node.NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    {left right : Model.Node.NodeID} {leftState rightState : Model.Node.NodeState}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    (leftLeader : leftState.role = .primary) (rightLeader : rightState.role = .primary)
    (sameTerm : leftState.currentTerm = rightState.currentTerm)
    : left = right := by
  obtain ⟨f, rfl, inv⟩ := Safety.inv_of_reachable reachable
  have leftLed := inv.leader_led left leftState leftMember leftLeader
  rw [sameTerm] at leftLed
  exact inv.election_safety left right _ leftLed
    (inv.leader_led right rightState rightMember rightLeader)

public theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID)
              (trace : CCF.Execution.Trace (Model.transitionSystem config nodes))
              (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (state ∈ trace
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  intro config nodes trace state left right leftState rightState
    ⟨member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Election.primary_eq_of_reachable (trace.reachable member)
    leftMember rightMember leftLeader rightLeader sameTerm

end Consensus.Proofs.Election

namespace Consensus.Proofs.CommittedLogs

open CCF (Finset)
open Model.Node
open Consensus.Proofs.Config

private theorem committed_logs_prefix_of_le [Config.InitialConfiguration]
    {nodes : List Model.Node.NodeID}
    {trace
      : CCF.Execution.Trace (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)}
    {earlierIndex laterIndex : Nat} {earlier later : Model.State}
    {earlierNode laterNode : Model.Node.NodeID}
    {earlierState laterState : Model.Node.NodeState}
    (ordered : earlierIndex <= laterIndex)
    (earlierFound : trace.stateAt earlierIndex = some earlier)
    (laterFound : trace.stateAt laterIndex = some later)
    (earlierMember : (earlierNode, earlierState) ∈ earlier.nodes)
    (laterMember : (laterNode, laterState) ∈ later.nodes)
    : earlierState.committedLog <+: laterState.committedLog
      \/ laterState.committedLog <+: earlierState.committedLog := by
  obtain ⟨carried, carriedMember, grown⟩ :=
    Direct.committed_log_later earlierFound earlierMember (laterIndex - earlierIndex)
      later (by rwa [Nat.add_sub_cancel' ordered])
  obtain ⟨f, rfl, inv⟩ :=
    Safety.inv_of_reachable (trace.reachable (CCF.Execution.Trace.stateAt_mem laterFound))
  split_rel committed_logs_comparable :=
      (rcases Safety.committed_logs_comparable inv carriedMember laterMember with
        carriedFirst | laterFirst) with
  | inl => exact Or.inl (grown.trans carriedFirst)
  | inr => exact List.prefix_or_prefix_of_prefix grown laterFirst

public theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID)
              (trace : CCF.Execution.Trace (Model.transitionSystem config nodes)),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (stateA ∈ trace
          /\ stateB ∈ trace
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  intro config nodes trace stateA stateB left right leftState rightState
    ⟨memberA, memberB, leftMember, rightMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  obtain ⟨indexA, foundA⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp memberA
  obtain ⟨indexB, foundB⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp memberB
  split_rel le_total := (rcases Nat.le_total indexA indexB with ordered | ordered) with
  | inl =>
    exact Proofs.CommittedLogs.committed_logs_prefix_of_le ordered
      foundA.symm foundB.symm leftMember rightMember
  | inr =>
    exact (Proofs.CommittedLogs.committed_logs_prefix_of_le ordered
      foundB.symm foundA.symm rightMember leftMember).symm

end Consensus.Proofs.CommittedLogs
