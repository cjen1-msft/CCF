module

public import CCFRaft.Liveness.Assumptions.Window

@[expose] public section

/-!
# An anchored start

`Properties.signature_settles` constrains only an anchor: a quorum of the
primary's configurations that knows the primary, stays in its term and keeps
its election timer fresh. Other participants may lag, time out and become
pre-vote candidates of the term, but they cannot win a pre-vote: an anchor node
grants none while it knows a primary, and every quorum a participant can count
meets the anchor (`Blocks`).
-/

namespace CCFRaft.Liveness

open Model.Node
open CCF.MultiNodeTransitionSystem (nodeState)
open HasProtocol (proto)
open HasTime (time)

/-- Every majority of `nodes` meets `anchor`. -/
def Blocked (anchor nodes : Finset NodeID) : Prop :=
  2 * (nodes \ anchor).card <= nodes.card

instance (anchor nodes : Finset NodeID) : Decidable (Blocked anchor nodes) := by
  unfold Blocked
  infer_instance

/-- `anchor` is a quorum of the primary's configurations among `participants`
whose nodes know the primary in `term`, and whose pre-votes no participant has
counted or can still count in `term`. -/
structure Anchor (participants anchor : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  subset : anchor ⊆ participants
  leaderIn : leader ∈ anchor
  quorum
    : forall local_,
        (leader, local_) ∈ state.nodes -> hasQuorum local_.activeConfigurations anchor
  /-- Every anchor node other than the primary is one of its replication peers. -/
  members
    : forall local_,
        (leader, local_) ∈ state.nodes
        -> forall node,
            node ∈ anchor
            -> Not (node = leader)
            -> node ∈ latestConfigurationMembers local_.activeConfigurations
  /-- An anchor node is in `term` and knows its primary, so it grants no pre-vote. -/
  settled
    : forall node,
        node ∈ anchor
        -> exists local_,
            (node, local_) ∈ state.nodes
            /\ local_.currentTerm = term
            /\ local_.primaryKnown = true
            /\ (local_.role = .follower \/ local_.role = .primary)
  noGrants
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ anchor
        -> envelope.target ∈ participants
        -> Not (envelope.payload = .requestPreVoteResponse { term, voteGranted := true })
  notCounted
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> node ∈ participants
        -> local_.role = .preVoteCandidate
        -> local_.currentTerm = term
        -> Disjoint local_.preVotesGranted anchor

/-- Every configuration a participant can count votes in has each majority
meeting `anchor`: every configuration active at a participant, and every
configuration above a participant's commit index in a participant's log or in an
AppendEntries in flight between participants. A configuration becomes active at
a participant only as an entry landing above its commit index, which only grows,
so the form is inductive without a safety invariant.

Needed in this form. Narrower, over active configurations only, is false: a
configuration inactive at the primary, above a laggard's commit index, becomes
active at the laggard from a short AppendEntries, and laggards outside the
anchor then pre-vote each other past `term`. Stronger, over whole logs, would
force every node of an ancient one-node configuration into the anchor.

It over-approximates: one blocked active configuration per participant suffices
for a step, since `hasQuorum` needs a majority in every configuration, but only
the all-configurations form stays inductive; with log matching only the
primary's log would matter. -/
def Blocks (participants anchor : Finset NodeID) (state : Model.State) : Prop :=
  forall node local_,
    (node, local_) ∈ state.nodes
    -> node ∈ participants
    -> (forall configuration,
          configuration ∈ local_.activeConfigurations
          -> Blocked anchor configuration.nodes)
        /\ (forall holder held,
              (holder, held) ∈ state.nodes
              -> holder ∈ participants
              -> forall configuration,
                  configuration ∈ configurationHistory held.log
                  -> local_.commitIndex < configuration.index
                  -> Blocked anchor configuration.nodes)
        /\ (forall envelope request,
              envelope ∈ state.network
              -> envelope.source ∈ participants
              -> envelope.target ∈ participants
              -> envelope.payload = .appendEntriesRequest request
              -> forall configuration,
                  configuration ∈ configurationHistory request.entries
                  -> local_.commitIndex < request.prevLogIndex + configuration.index
                  -> Blocked anchor configuration.nodes)

variable {W : Type} [HasProtocol W Model.State] [HasTime W]

/-- An anchored start: at `start` the term is quiet among participants without
the pre-vote clause, `anchor` anchors it and blocks every quorum participants can
count, and no anchor node of the term times out before `fresh` after it. -/
structure AnchoredStart (trace : Trace W Event) (start : Nat) (leader : NodeID)
    (term : Nat) (participants anchor : Finset NodeID) (fresh : Real)
    : Prop where
  quiet
    : exists first,
        trace.stateAt start = some first
        /\ QuietTerm participants leader term (proto first)
        /\ Anchor participants anchor leader term (proto first)
        /\ Blocks participants anchor (proto first)
  timers
    : forall first index step node state,
        trace.stateAt start = some first
        -> start <= index
        -> trace.stepAt index = some step
        -> step.action = .local node (.timeout .election)
        -> nodeState (proto step.before) node = some state
        -> node ∈ anchor
        -> state.currentTerm = term
        -> time first + fresh <= time step.before

end CCFRaft.Liveness
