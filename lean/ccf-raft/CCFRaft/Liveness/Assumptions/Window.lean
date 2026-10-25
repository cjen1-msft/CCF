module

public import CCFRaft.Liveness.Model
public import CCFRaft.Liveness.Assumptions.QuietStart
public import CCFRaft.Liveness.Assumptions.Submitted

@[expose] public section

/-!
# Stable windows

The deterministic commit argument runs inside a window of real time in which
one primary is uncontested, live, quorate and reachable. The window is the
conclusion of `Properties.signature_settles` and the premise of
`Properties.commit_liveness`. Every window predicate is bounded by the window;
none holds forever.
-/

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

/-- The local ledger has one active configuration, and every completed removal
has a committed retirement confirmation. An uncommitted confirmation is still
unfinished work. The sole initial configuration need not yet be committed. -/
def ReconfigurationSettled (state : NodeState) : Prop :=
  state.activeConfigurations.length = 1 /\ state.retirementCompletedNodes = ∅

instance (state : NodeState) : Decidable (ReconfigurationSettled state) := by
  unfold ReconfigurationSettled
  infer_instance

/-- `Quiet` among `participants`: no participant or message between participants
has moved past `term`, no participant is a pre-vote candidate in it, no proposal
for it is in flight between participants, and `leader` is its primary.
Nodes outside `participants`, such as a crashed or partitioned pre-vote
candidate of a newer term, are unconstrained; isolation keeps them from
reaching participants. -/
structure QuietAmong (participants : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  terms
    : forall node local_,
        (node, local_) ∈ state.nodes -> node ∈ participants -> local_.currentTerm <= term
  preVotes
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> node ∈ participants
        -> local_.role = .preVoteCandidate
        -> local_.currentTerm < term
  messages
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> envelope.payload.term <= term
  proposals
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> Not (envelope.payload = .proposeRequestVoteRequest term)
  leader
    : exists local_,
        (leader, local_) ∈ state.nodes
        /\ local_.role = .primary
        /\ local_.currentTerm = term

/-- `QuietAmong` without its pre-vote clause: no participant or message between
participants has moved past `term`, no proposal for it is in flight between
participants, and `leader` is its primary. Participants may be pre-vote
candidates of `term`; an anchor (`Liveness.Anchor`) keeps them from winning. -/
structure QuietTerm (participants : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  terms
    : forall node local_,
        (node, local_) ∈ state.nodes -> node ∈ participants -> local_.currentTerm <= term
  messages
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> envelope.payload.term <= term
  proposals
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> Not (envelope.payload = .proposeRequestVoteRequest term)
  leader
    : exists local_,
        (leader, local_) ∈ state.nodes
        /\ local_.role = .primary
        /\ local_.currentTerm = term

/-- A term quiet among participants is quiet without its pre-vote clause. -/
theorem QuietAmong.quietTerm {participants : Finset NodeID} {leader : NodeID} {term : Nat}
    {state : Model.State} (quiet : QuietAmong participants leader term state)
    : QuietTerm participants leader term state :=
  ⟨quiet.terms, quiet.messages, quiet.proposals, quiet.leader⟩

/-- A term quiet everywhere is quiet among any participants. -/
theorem Quiet.among {leader : NodeID} {term : Nat} {state : Model.State}
    (quiet : Quiet leader term state) (participants : Finset NodeID)
    : QuietAmong participants leader term state :=
  ⟨
    fun node local_ member _ => quiet.terms node local_ member,
    fun node local_ member _ => quiet.preVotes node local_ member,
    fun envelope member _ _ => quiet.messages envelope member,
    fun envelope member _ _ => quiet.proposals envelope member,
    quiet.leader
  ⟩

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]

namespace Window

/-- Throughout the window `leader` is the primary of `term`, and `term` is the
newest term among `participants`: no participant, participant pre-vote
candidate, or message or proposal between participants has moved past it. -/
def StableLeader (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (term : Nat) (participants : Finset NodeID)
    : Prop :=
  forall index point,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> QuietAmong participants leader term (proto point)

/-- `StableLeader` without the pre-vote clause: throughout the window `leader` is
the primary of `term`, and no participant, or message or proposal between
participants, has moved past it. Participants outside an anchor may be pre-vote
candidates of `term`. -/
def StableTerm (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (term : Nat) (participants : Finset NodeID)
    : Prop :=
  forall index point,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> QuietTerm participants leader term (proto point)

/-- Throughout the window the primary is live and its retirement has not committed. -/
structure StaysActive (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID)
    : Prop where
  live
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> leader ∈ live point
  notRetired
    : forall index point state,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
        -> Not (state.isRetiredCommitted leader)

/-- Throughout the window no anchor node has its retirement committed. Assumed,
not derived. A node whose retirement commits knows no primary (`recordCommit`)
and grants pre-votes, since the pre-vote handler does not check the role, so a
retired anchor node can complete a lagging participant's pre-vote quorum; a
retired primary also steps down (CCF's `become_retired`). Under
`GoodPeriod.noReconfiguration`, another anchor node, being in the primary's
latest configuration, retires in the window only through configurations already
in the log that remove it and later re-add it. CCF allows such a rejoin: once a
retirement is confirmed the node ID can be reused, as the checks that would
refuse it no longer have the information. -/
def AnchorActive (trace : Trace W Event) (start : Nat) (duration : Real)
    (anchor : Finset NodeID)
    : Prop :=
  forall index point node state,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> node ∈ anchor
    -> CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
    -> Not (state.isRetiredCommitted node)

/-- Throughout the window every configuration active at the primary has a live
majority among `participants`. -/
def LiveQuorum (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (participants : Finset NodeID)
    : Prop :=
  forall index point state,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    -> hasQuorum state.activeConfigurations (Inter.inter (live point) participants)

/-- Reconfiguration work is finished at the leader throughout the window.
This excludes both inherited cleanup and new pending configuration changes,
without requiring followers to have learned that completion. It is separate
from `StableWindow`: stable leadership alone does not finish retirement work. -/
def ReconfigurationSettled (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID)
    : Prop :=
  forall index point state,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    -> Liveness.ReconfigurationSettled state

/-- No packet between the primary and a participant is dropped in the window.
With `boundedDelayModel maxDelay`, each is delivered within `maxDelay`. -/
def Lossless (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (participants : Finset NodeID)
    : Prop :=
  forall index step packet,
    Within trace start duration index
    -> trace.stepAt index = some step
    -> step.action = .drop packet
    -> Not
        ((packet.envelope.source = leader /\ packet.envelope.target ∈ participants)
          \/ (packet.envelope.source ∈ participants /\ packet.envelope.target = leader))

end Window

/-- A window of real time, from index `start` for `duration`, in which `leader`
is the uncontested primary of `term`, stays live and unretired, keeps a live
majority among `participants`, and exchanges packets with them without loss. -/
structure StableWindow (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID) (term : Nat) (participants : Finset NodeID)
    : Prop where
  stableLeader : Window.StableLeader trace start duration leader term participants
  staysActive : Window.StaysActive trace start duration leader
  liveQuorum : Window.LiveQuorum trace start duration leader participants
  lossless : Window.Lossless trace start duration leader participants

/-- The length of the common prefix of two logs. -/
def agreedPrefix (leaderLog followerLog : List Entry) : Nat :=
  ((leaderLog.zip followerLog).takeWhile fun pair => decide (pair.1 = pair.2)).length

/-- At `start`, for every participant, the primary's log beyond their common
prefix spans at most `backlog` distinct terms (terms, not entries). A rejected AppendEntries moves the
primary's probe back past a whole term of its log (CCF's
`find_highest_possible_match`), so catching a participant up takes at most two
rounds per such term, plus two for the entries the primary appends in its own
term. A log `n` entries beyond the common prefix spans at most `n` terms. -/
def BacklogTerms (trace : Trace W Event) (start : Nat) (leader : NodeID)
    (participants : Finset NodeID) (backlog : Nat)
    : Prop :=
  forall first leaderState follower followerState,
    trace.stateAt start = some first
    -> CCF.MultiNodeTransitionSystem.nodeState (proto first) leader = some leaderState
    -> follower ∈ participants
    -> CCF.MultiNodeTransitionSystem.nodeState (proto first) follower = some followerState
    -> ((leaderState.log.drop (agreedPrefix leaderState.log followerState.log)).map
          Entry.term).toFinset.card
        <= backlog

/-- At `start` every participant is a node that has adopted `term`. With
`Window.LiveQuorum`, a live quorum is then in `term` throughout the window. The
voters that elected `leader` qualify, as do nodes that acknowledged its
AppendEntries: terms only grow, and `Window.StableLeader` caps them at `term`.
Naming the voters instead would be too strong, since a reconfiguration in `term`
can leave them short of a quorum of the active configuration.
Needed: a participant behind `term` still accepts AppendEntries of an older term.
Let `leader` and another node alternate as primary for `2 n` terms, each appending
one entry per term, with `leader`'s entries replicated to a participant and the
other's to nobody. A delayed AppendEntries from the other's last term can then
replace that participant's log, which matched `leader`'s at `start`, with `n`
entries of alternating terms. Each rejection moves the primary's probe back one
entry, so catching it up takes `n` rounds for any `n`. -/
def InTermAt (trace : Trace W Event) (start : Nat) (term : Nat)
    (participants : Finset NodeID)
    : Prop :=
  forall follower,
    follower ∈ participants
    -> exists first state,
        trace.stateAt start = some first
        /\ CCF.MultiNodeTransitionSystem.nodeState (proto first) follower = some state
        /\ state.currentTerm = term

/-- At `start` the primary's log holds `request`, or the step at `start` appends
it. A longer stable window may be cut down to start here. -/
def SubmittedAt (trace : Trace W Event) (start : Nat) (leader : NodeID) (request : ReqID)
    : Prop :=
  (exists point state,
    trace.stateAt start = some point
    /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ HasRequest state.log request)
  \/ exists step entries,
      trace.stepAt start = some step
      /\ step.action = .local leader (.append entries)
      /\ .transaction request {} ∈ entries

/-- A good period (Keidar and Shraer 2006) from index `start` for `duration`:
every participant stays live, no configuration change is appended, no primary is
asked to hand over, no participant steps down on a quorum check, every live
node's active configurations keep a live majority among `participants`, packets
between participants are not dropped, and no packet from outside reaches a
participant. The windowed form of the partial-synchrony premise;
`Properties.duelling_leaders_resolve` needs one long enough for its rounds. -/
structure GoodPeriod (trace : Trace W Event) (start : Nat) (duration : Real)
    (participants : Finset NodeID)
    : Prop where
  /-- Needed: otherwise the adversary crashes every node at `start`, which
  satisfies `quorum` vacuously, and nothing commits. -/
  participantsLive
    : forall index point node,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> node ∈ participants
        -> node ∈ live point
  quorum
    : forall index point node state,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> node ∈ live point
        -> CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
        -> hasQuorum state.activeConfigurations (Inter.inter (live point) participants)
  /-- Essential: the theorems are about windows with fixed membership. The
  commit argument fixes one configuration for the whole window, whereas a
  change in flight needs joint quorums, and committing the primary's own
  removal makes it step down (`become_retired` in CCF). Liveness across a
  reconfiguration is a different property. -/
  noReconfiguration
    : forall index step node entries,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action = .local node (.append entries)
        -> forall entry, entry ∈ entries -> entry.metadata.configuration = none
  noNominations
    : forall index step node,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> Not (step.action = .local node .nominateSuccessor)
  /-- Needed: the model does not constrain quorum checks, so otherwise every new
  primary of a multi-node configuration steps down before it signs, and nothing
  commits. Assumed, not derived, as `Incumbent.quorumChecks` explains. -/
  noQuorumChecks
    : forall index step node,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> node ∈ participants
        -> Not (step.action = .local node (.timeout .checkQuorum))
  lossless
    : forall index step packet,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action = .drop packet
        -> Not
            (packet.envelope.source ∈ participants
              /\ packet.envelope.target ∈ participants)
  /-- Needed: nodes outside `participants` are unconstrained, so their terms,
  logs and timers are arbitrary. One at a later term deposes the primary when
  one of its messages arrives (`observeTerm`), for example a node that became a
  candidate for a later term before `start` and then lost contact. CCF behaves
  the same: its AppendEntries and vote handlers, pre-votes included, adopt the
  later term (`become_aware_of_new_term`). This is the windowed form of "the
  rest of the network is partitioned off". Narrowing it is not attempted. -/
  isolated
    : forall index step envelope,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action.delivered = some envelope
        -> envelope.target ∈ participants
        -> envelope.source ∈ participants

end CCFRaft.Liveness
