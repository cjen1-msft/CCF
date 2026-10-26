module

public import CCFRaft.Liveness.Model
public import CCFRaft.Liveness.Assumptions.StableLeader
public import CCFRaft.Liveness.Assumptions.QuietStart
public import CCFRaft.Liveness.Assumptions.FairLoss
public import CCFRaft.Liveness.Assumptions.Submitted
public import CCFRaft.Liveness.Assumptions.Duel
public import CCFRaft.Liveness.Assumptions.Window
public import CCFRaft.Liveness.Assumptions.Settles
public import CCFRaft.Liveness.Assumptions.Anchor
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

/-!
Assumptions of the liveness theorems about an execution: a stable primary, a
live quorum, fair-loss links and a submitted request, and the premises from which
`Proofs.Leadership.stable_leader` derives a stable primary.
Short, single-declaration assumptions are defined here.
Larger groups of related declarations are imported from `Liveness/Assumptions/`.
Unlike the scheduling constraints, these are not
environment constraints; each theorem states the ones it needs.
-/

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- AppendEntries requests the primary sends from index `start` on arrive within
`delay`, unless their target crashes. Other messages may be lost or delayed.
Send and delivery times are the respective steps' before-times.
Needed: with only `FairLoss`, the network may drop every heartbeat to a follower
for a whole election timeout, and the follower then starts an election. -/
def Timely (trace : Trace W Event) (start : Nat) (leader : NodeID) (delay : Real)
    : Prop :=
  forall sent packet,
    trace.SentAt sent packet
    -> start <= sent
    -> packet.envelope.source = leader
    -> (exists request, packet.envelope.payload = .appendEntriesRequest request)
    -> exists index step,
        sent < index
        /\ trace.stepAt index = some step
        /\ time step.before <= packet.sentAt + delay
        /\ (step.action = .deliver packet
            \/ Not (Membership.mem (live step.after) packet.envelope.target))

/-- From index `start` on, every AppendEntries request from the primary that reaches
a node of `term`, other than a candidate or pre-vote candidate, passes the node's
log check: the node's log holds `prevLogTerm` at `prevLogIndex`. For simplicity this also covers
nodes with no role, such as retired nodes, which cannot start an election.
Needed: CCF resets the election timer on an AppendEntries of the node's term only
once this check passes (`raft.h`, `recv_append_entries`), unlike Raft, which
resets on any AppendEntries from the current leader. Take three nodes, where the
primary was elected with the vote of a follower whose log is shorter than the
primary's, as is the third node's. Each heartbeat fails the follower's log check
until one of its rejections reaches the primary. If those are lost, the follower
times out, the third node grants it a pre-vote, and it starts the next term. -/
def Matching (trace : Trace W Event) (start : Nat) (leader : NodeID) (term : Nat)
    : Prop :=
  forall index step packet request state,
    start <= index
    -> trace.stepAt index = some step
    -> step.action = .deliver packet
    -> packet.envelope.source = leader
    -> packet.envelope.payload = .appendEntriesRequest request
    -> CCF.MultiNodeTransitionSystem.nodeState (proto step.before) packet.envelope.target
        = some state
    -> state.currentTerm = term
    -> Not (state.role = .candidate)
    -> Not (state.role = .preVoteCandidate)
    -> termAt state.log request.prevLogIndex = request.prevLogTerm

/-- Every node that times out in `term` from index `start` on has been a replication
peer of the primary since `start`, so the primary has been sending it heartbeats.
Needed by this proof, which resets only the timers of nodes the primary sends to.
Whether CCF needs it is open: once a removed node's confirmation commits, the
primary stops sending to it (`raft.h`, `set_retired_committed`), and if the node
has not learned this it still times out, but it then also needs a quorum of
pre-votes to start the next term. -/
def Covered (trace : Trace W Event) (start : Nat) (leader : NodeID) (term : Nat) : Prop :=
  forall index step node state,
    start <= index
    -> trace.stepAt index = some step
    -> step.action = .local node (.timeout .election)
    -> Not (node = leader)
    -> CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node = some state
    -> state.currentTerm = term
    -> forall earlier earlierPoint leaderState,
        start <= earlier
        -> earlier <= index
        -> trace.stateAt earlier = some earlierPoint
        -> CCF.MultiNodeTransitionSystem.nodeState (proto earlierPoint) leader
            = some leaderState
        -> node ∈ eligiblePeers leaderState leader

/-- From index `start` on, the primary stays live, its retirement does not commit,
it is not asked to hand over, and it does not step down on a quorum check. -/
structure Incumbent (trace : Trace W Event) (start : Nat) (leader : NodeID) : Prop where
  /-- Needed: a crashed primary leads nothing. -/
  live
    : forall index point,
        start <= index
        -> trace.stateAt index = some point
        -> Membership.mem (live point) leader
  /-- Needed: a primary whose retirement commits nominates a successor and steps
  down (`raft.h`, `become_retired`). It may be removed, as long as its retirement
  does not commit. -/
  notRetired
    : forall index point state,
        start <= index
        -> trace.stateAt index = some point
        -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
        -> Not (state.isRetiredCommitted leader)
  /-- Needed: a stop notice makes the primary propose a vote to a successor
  (`raft.h`, `nominate_successor`), which starts the next term. -/
  nominations
    : forall index step,
        start <= index
        -> trace.stepAt index = some step
        -> Not (step.action = .local leader .nominateSuccessor)
  /-- Needed: the environment does not constrain quorum checks, and a failed one
  makes the primary a follower (`raft.h`, `Aft::periodic`). Not derived from
  timing: `Timely` does not bound responses. Bounding them would not suffice in
  this model either. A follower silently ignores an AppendEntries whose `prev_idx`
  is below its commit index (`raft.h`, `recv_append_entries`), and a stale
  rejection, sent before an acceptance that raised the follower's commit index
  and handled before that acceptance's acknowledgement, can move the primary's
  `sent_idx` back below it. Heartbeat scheduling now requires completing the
  send pass through the log
  end, matching CCF's `send_append_entries`. Deriving this premise still needs
  a round-trip bound and a model of the acknowledgement-age check. -/
  quorumChecks
    : forall index step,
        start <= index
        -> trace.stepAt index = some step
        -> Not (step.action = .local leader (.timeout .checkQuorum))

/-- From some point on, every configuration active for the primary has a majority
of live participants. That point must exist, even in a finite execution.
The majority may change over time. Needed: if every node
but the primary of a three-node configuration crashes, nothing more can commit. -/
def LiveQuorum (trace : Trace W Event) (leader : NodeID) (participants : Finset NodeID)
    : Prop :=
  exists start first,
    trace.stateAt start = some first
    /\ forall index point state,
        start <= index
        -> trace.stateAt index = some point
        -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
        -> hasQuorum state.activeConfigurations (Inter.inter (live point) participants)

/-- The request is in the primary's committed prefix, not merely replicated or signed. -/
def RequestCommitted (trace : Trace W Event) (leader : NodeID) (request : ReqID)
    (index : Nat)
    : Prop :=
  exists point state,
    trace.stateAt index = some point
    /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ HasRequest state.committedLog request

/-- The concrete predicate tested by the primary's signature-commit scan. -/
def SignatureReady (state : NodeState) (self : NodeID) (index : Nat) : Prop :=
  index <= state.log.length
  /\ isSignatureAt state.log index = true
  /\ termAt state.log index = state.currentTerm
  /\ hasQuorum (state.activeConfigurations.filter fun config => config.index <= index)
      (state.activeMembers.filter
        fun node => node = self \/ state.matchIndex node >= index)

end CCFRaft.Liveness
