module

public import CCFRaft.Liveness.Model.Timing

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasTime (time)

variable {W : Type} [HasProtocol W Model.State] [HasTime W]

/-! ## Premises of a stable primary

`Properties.stable_leader` derives `StableLeader` from timing. Each premise rules
out a way to depose the primary that the timing bounds do not.
-/

/-- No node or message has moved past `term`, no node is a pre-vote candidate in
it, no vote is proposed for it, and `leader` is its primary. -/
structure Quiet (leader : NodeID) (term : Nat) (state : Model.State) : Prop where
  /-- Needed: a node in a newer term, such as a candidate of the next term, sends
  messages of that term, which depose the primary. -/
  terms : forall node local_, (node, local_) ∈ state.nodes -> local_.currentTerm <= term
  /-- Needed: CCF grants pre-votes whatever leader it knows (`raft.h`,
  `recv_request_vote_unsafe`), so a pre-vote candidate of the term can gather a
  quorum and start the next term. -/
  preVotes
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> local_.role = .preVoteCandidate
        -> local_.currentTerm < term
  /-- Needed: delivering a message of a newer term deposes the primary. -/
  messages : forall envelope, envelope ∈ state.network -> envelope.payload.term <= term
  /-- Needed: a proposal for the term makes its target start the next term
  (`raft.h`, `recv_propose_request_vote`). -/
  proposals
    : forall envelope,
        envelope ∈ state.network
        -> Not (envelope.payload = .proposeRequestVoteRequest term)
  leader
    : exists local_,
        (leader, local_) ∈ state.nodes
        /\ local_.role = .primary
        /\ local_.currentTerm = term

/-- At index `start`, `leader` is the newest primary, and no node of the term times
out within half an election timeout of `start`.
Needed: a node of the term whose timer expires before the primary's first heartbeat
arrives starts a pre-vote, which others may grant, and then the next term. -/
structure QuietStart (trace : Trace W Event) (start : Nat) (leader : NodeID) (term : Nat)
    (electionTimeout : Real)
    : Prop where
  /-- The starting point is an actual point of this execution. -/
  quiet
    : exists first, trace.stateAt start = some first /\ Quiet leader term (proto first)
  timers
    : forall first index step node state,
        trace.stateAt start = some first
        -> start <= index
        -> trace.stepAt index = some step
        -> step.action = .local node (.timeout .election)
        -> CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node = some state
        -> state.currentTerm = term
        -> (time first) + electionTimeout / 2 <= (time step.before)

end CCFRaft.Liveness
