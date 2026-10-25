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
that contains the primary itself (`leaderIn`), whose nodes know the primary in
`term`, and whose pre-votes no participant has counted or can still count in
`term`. -/
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

/-- Every configuration a participant can count votes in has a node set
satisfying `P`: every configuration active at a participant, and every
configuration above a participant's commit index in a participant's log or in an
AppendEntries in flight between participants. A configuration becomes active at
a participant only as an entry landing above its commit index, which only grows,
so the form is inductive without a safety invariant. -/
def Configured (P : Finset NodeID -> Prop) (participants : Finset NodeID)
    (state : Model.State)
    : Prop :=
  forall node local_,
    (node, local_) ∈ state.nodes
    -> node ∈ participants
    -> (forall configuration,
          configuration ∈ local_.activeConfigurations -> P configuration.nodes)
        /\ (forall holder held,
              (holder, held) ∈ state.nodes
              -> holder ∈ participants
              -> forall configuration,
                  configuration ∈ configurationHistory held.log
                  -> local_.commitIndex < configuration.index
                  -> P configuration.nodes)
        /\ (forall envelope request,
              envelope ∈ state.network
              -> envelope.source ∈ participants
              -> envelope.target ∈ participants
              -> envelope.payload = .appendEntriesRequest request
              -> forall configuration,
                  configuration ∈ configurationHistory request.entries
                  -> local_.commitIndex < request.prevLogIndex + configuration.index
                  -> P configuration.nodes)

/-- `Configured` is monotone in its predicate. -/
theorem Configured.mono {P Q : Finset NodeID -> Prop} {participants : Finset NodeID}
    {state : Model.State} (configured : Configured P participants state)
    (implies : forall nodes, P nodes -> Q nodes)
    : Configured Q participants state := by
  intro node local_ member nodeIn
  obtain ⟨active, held, sent⟩ := configured node local_ member nodeIn
  exact ⟨
    fun configuration found => implies _ (active configuration found),
    fun holder held' now holderIn configuration found high =>
      implies _ (held holder held' now holderIn configuration found high),
    fun envelope request queued sourceIn targetIn payload configuration found high =>
      implies _ (sent envelope request queued sourceIn targetIn payload configuration found high)
  ⟩

/-- Every configuration a participant can count votes in (`Configured`) has each
majority meeting `anchor`.

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
  Configured (Blocked anchor) participants state

/-- Every configuration a participant can count votes in (`Configured`) has the
nodes `members`.

Needed for a duel, where membership must not differ between views. A primary
sends heartbeats only to the members of its own active configurations, while
`canStartElection` checks a participant's own signed active configurations. With
participants `{1, 2, 3}`, a primary `1` that has committed a configuration
`{1, 2}`, and a lagging `3` still holding the earlier signed configuration
`{1, 2, 3}` above its commit index, `1` never sends to `3`, so `3` times out and
campaigns. -/
def Membership (participants members : Finset NodeID) (state : Model.State) : Prop :=
  Configured (fun nodes => nodes = members) participants state

/-- A fixed membership with a majority in the anchor blocks every countable
quorum. -/
theorem Membership.blocks {participants members anchor : Finset NodeID}
    {state : Model.State} (membership : Membership participants members state)
    (majority : 2 * (members \ anchor).card <= members.card)
    : Blocks participants anchor state :=
  Configured.mono membership
    fun nodes eq => by
      rw [eq]
      exact majority

/-- Under a fixed membership, every participant's latest active configuration is
the membership, unless it has none. -/
theorem Membership.latest {participants members : Finset NodeID} {state : Model.State}
    (membership : Membership participants members state) {node : NodeID}
    {local_ : NodeState} (member : (node, local_) ∈ state.nodes)
    (nodeIn : node ∈ participants)
    : local_.activeConfigurations = []
      \/ latestConfigurationMembers local_.activeConfigurations = members := by
  obtain ⟨active, _, _⟩ := membership node local_ member nodeIn
  unfold latestConfigurationMembers
  cases last : local_.activeConfigurations.getLast? with
  | none => exact Or.inl (List.getLast?_eq_none_iff.mp last)
  | some configuration =>
      exact Or.inr (active configuration (List.mem_of_getLast? last))

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
