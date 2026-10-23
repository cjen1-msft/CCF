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

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]

namespace Window

/-- Throughout the window `leader` is the primary of `term`, and `term` is the
newest term: no node, pre-vote candidate, message or proposal has moved past it. -/
def StableLeader (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (term : Nat)
    : Prop :=
  forall index point,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> Quiet leader term (proto point)

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
  stableLeader : Window.StableLeader trace start duration leader term
  staysActive : Window.StaysActive trace start duration leader
  liveQuorum : Window.LiveQuorum trace start duration leader participants
  lossless : Window.Lossless trace start duration leader participants

/-- The length of the common prefix of two logs. -/
def agreedPrefix (leaderLog followerLog : List Entry) : Nat :=
  ((leaderLog.zip followerLog).takeWhile fun pair => decide (pair.1 = pair.2)).length

/-- At `start` no participant's log diverges from the primary's by more than
`backlog` entries. Catching a participant up takes at most `backlog` rounds. -/
def Backlog (trace : Trace W Event) (start : Nat) (leader : NodeID)
    (participants : Finset NodeID) (backlog : Nat)
    : Prop :=
  forall first leaderState follower followerState,
    trace.stateAt start = some first
    -> CCF.MultiNodeTransitionSystem.nodeState (proto first) leader = some leaderState
    -> follower ∈ participants
    -> CCF.MultiNodeTransitionSystem.nodeState (proto first) follower = some followerState
    -> leaderState.log.length - agreedPrefix leaderState.log followerState.log <= backlog

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

/-- Provisional: `backlog` catch-up rounds, one replication round, a signature,
and its acknowledgement round. The timed commit proof fixes the formula. -/
def commitLatency (bounds : Bounds) (maxDelay : Real) (backlog : Nat) : Real :=
  (backlog + 2) * (bounds.heartbeatInterval + 2 * maxDelay) + bounds.signatureInterval

/-- A good period (Keidar and Shraer 2006) from index `start` for `duration`: no
configuration change is appended, no primary is asked to hand over, every live
node's active configurations keep a live majority among `participants`, packets
between participants are not dropped, and no packet from outside reaches a
participant. The windowed form of the partial-synchrony premise;
`Properties.duelling_leaders_resolve` needs one long enough for its rounds. -/
structure GoodPeriod (trace : Trace W Event) (start : Nat) (duration : Real)
    (participants : Finset NodeID)
    : Prop where
  quorum
    : forall index point node state,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> node ∈ live point
        -> CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
        -> hasQuorum state.activeConfigurations (Inter.inter (live point) participants)
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
  lossless
    : forall index step packet,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action = .drop packet
        -> Not
            (packet.envelope.source ∈ participants
              /\ packet.envelope.target ∈ participants)
  isolated
    : forall index step envelope,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action.delivered = some envelope
        -> envelope.target ∈ participants
        -> envelope.source ∈ participants

end CCFRaft.Liveness
