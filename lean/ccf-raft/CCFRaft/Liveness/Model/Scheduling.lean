module

public import CCFRaft.Liveness.Model.Trace

@[expose] public section

/-!
CCF background-task and election-timer scheduling assumptions.
The untimed predicates retain eventual execution without a quantitative deadline;
the timed model adds heartbeat deadlines and election-timer lower bounds.
Network fairness is a separate assumption in `FairLoss`.
-/

namespace CCFRaft.Liveness

open Model.Node

variable {system : CCF.TransitionSystem Model.State Model.Action}

/-- Abstract wall-clock bounds. -/
structure Bounds where
  /-- An upper bound on the real time a primary takes to send a due
  AppendEntries. CCF sends once `request_timeout` has elapsed, checked on each
  `periodic` tick (`raft.h`, `Aft::periodic`), so this is at least
  `request_timeout` plus the tick interval, if the host ticks on time. -/
  heartbeatInterval : Real
  /-- Twice a lower bound on the real time from an election-timer reset to an
  election timeout. CCF draws a timeout between half and all of its configured
  `election_timeout` (`raft.h`, `restart_election_timeout`), but counts it in
  `periodic` ticks on the node's own clock, and the first tick after a reset also
  counts the time before it. So this is at most `election_timeout` minus twice
  the tick interval, and less if node clocks drift. -/
  electionTimeout : Real

/-- Timing parameters only. Protocol initialization belongs to the explicit
`config` and `nodes` arguments of the safety transition system. -/
structure LivenessModel where
  bounds : Bounds

/-- An active primary with an eligible, live replication peer. -/
def PeerDue (point : TracedState) (leader peer : NodeID) : Prop :=
  leader ∈ point.live
  /\ peer ∈ point.live
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState point.state leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ peer ∈ eligiblePeers state leader

/-- A send must carry entries when its current frontier has a backlog. -/
def ProductiveSend (step : CCF.Execution.Step TracedState TimedEvent) (leader peer : NodeID) : Prop :=
  exists state frontier,
    CCF.MultiNodeTransitionSystem.nodeState step.before.state leader = some state
    /\ step.action.event = .local leader (.sendEntries peer frontier)
    /\ (state.sentIndex peer < state.log.length -> state.sentIndex peer < frontier)

/-- A primary sends AppendEntries from `sent_idx + 1` to every other node each
time `request_timeout` elapses (`raft.h`, `Aft::periodic`); `eligiblePeers`
is a subset of `all_other_nodes`, from which CCF drops a node only once its
retirement confirmation commits (`set_retired_committed`). Needed: without it a
primary that appends a signature and then never sends again leaves a lagging
follower, whose acknowledgement the signature needs, behind forever.
A due send must eventually happen or cease to be due, before a finite execution ends. -/
def Trace.HeartbeatScheduling (trace : Trace system) : Prop :=
  forall index point leader peer,
    trace.timingTrace.stateAt (timingSystem system) index = some point
    -> PeerDue point leader peer
    -> Eventually trace index fun later point =>
        Not (PeerDue point leader peer)
        \/ exists step,
            trace.timingTrace.stepAt (timingSystem system) later = some step
            /\ ProductiveSend step leader peer

/-- Unsigned entries or a signature from an older term require a new signature. -/
def SignatureDue (point : TracedState) (leader : NodeID) : Prop :=
  leader ∈ point.live
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState point.state leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ (maxCommittableIndex state.log < state.log.length
          \/ maxCommittableTerm state.log ≠ state.currentTerm)

/-- The input actually appends a signature, rather than merely enabling one. -/
def Signs (step : CCF.Execution.Step TracedState TimedEvent) (leader : NodeID) : Prop :=
  exists entries, step.action.event = .local leader (.append entries) /\ .signature ∈ entries

/-- CCF's periodic signature task signs every `sig_ms_interval` when there are
unsigned entries (`committable_gap() > 0`) or the consensus asks for one
(`src/node/history.h`, `start_signature_emit_timer`); `raft.h` asks
(`get_signature_disposition`) while `should_sign`, which `become_leader` sets.
Needed: `Proofs.LivenessWitness.unsigned_starvation_witness` is a stable,
reliable execution with a submitted request that never commits because it
never signs. -/
def Trace.SignatureScheduling (trace : Trace system) : Prop :=
  forall index point leader,
    trace.timingTrace.stateAt (timingSystem system) index = some point
    -> SignatureDue point leader
    -> Eventually trace index fun later point =>
        Not (SignatureDue point leader)
        \/ exists step,
            trace.timingTrace.stepAt (timingSystem system) later = some step
            /\ Signs step leader

/-- The primary may append a retirement confirmation: a committed configuration
removed a node with no confirmation in the log. This is the enabling condition
of the confirmation guard in `appendEntry`. -/
def ConfirmationDue (point : TracedState) (leader : NodeID) : Prop :=
  leader ∈ point.live
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState point.state leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ (state.retirementCompletedNodes \ retiredCommittedNodes state.log).Nonempty

/-- The input actually appends a retirement confirmation. -/
def Confirms (step : CCF.Execution.Step TracedState TimedEvent) (leader : NodeID) : Prop :=
  exists entries,
    step.action.event = .local leader (.append entries)
    /\ exists content,
        content ∈ entries /\ content.metadata.retirementConfirmations.Nonempty

/-- A primary calls `retired_node_cleanup` whenever a commit retires a
configuration (`raft.h`, `Aft::commit`) or it is elected (`become_leader`), and
that runs `set_retired_committed` (`src/node/rpc/node_frontend.h`), which
confirms every retired node whose retirement is committed. This assumes that
request succeeds: CCF sends it once and does not retry it. Needed: when a commit
retires every other member of the configurations before a signature, the
primary alone makes that signature committable, but only another append or
acknowledgement reruns the commit scan; see `LIVENESS.md`. -/
def Trace.ConfirmationScheduling (trace : Trace system) : Prop :=
  forall index point leader,
    trace.timingTrace.stateAt (timingSystem system) index = some point
    -> ConfirmationDue point leader
    -> Eventually trace index fun later point =>
        Not (ConfirmationDue point leader)
        \/ exists step,
            trace.timingTrace.stepAt (timingSystem system) later = some step
            /\ Confirms step leader

/-- Events that reset a node's election timer in CCF: starting an election
(`become_pre_vote_candidate`), and an AppendEntries of a newer term, or of the
node's term that finds it a candidate or pre-vote candidate (both through
`become_aware_of_new_term`), or that passes the log check. An AppendEntries of the
node's term that fails the log check does not reset the timer (`raft.h`,
`recv_append_entries`, which calls `restart_election_timeout` only after the
`prev_term` check). -/
def ElectionReset (step : CCF.Execution.Step TracedState TimedEvent) (node : NodeID) : Prop :=
  step.action.event = .local node (.timeout .election)
  \/ exists envelope request state,
      step.action.event.delivered = some envelope
      /\ envelope.target = node
      /\ envelope.payload = .appendEntriesRequest request
      /\ CCF.MultiNodeTransitionSystem.nodeState step.before.state node = some state
      /\ (state.currentTerm < request.term
          \/ (state.currentTerm = request.term
              /\ (state.role = .candidate
                  \/ state.role = .preVoteCandidate
                  \/ termAt state.log request.prevLogIndex = request.prevLogTerm)))

/-- Timed heartbeat, signature and confirmation scheduling, and CCF's
election-timer constraints. This does not assume eventual commitment. -/
structure LivenessModel.Timed (model : LivenessModel) (trace : Trace system) : Prop where
  /-- `Trace.HeartbeatScheduling`, within `heartbeatInterval`. Needed: if the
  primary could wait longer than half an election timeout between heartbeats, a
  follower could time out and depose it. -/
  heartbeats
    : forall index point leader peer,
        trace.timingTrace.stateAt (timingSystem system) index = some point
        -> PeerDue point leader peer
        -> Within trace index model.bounds.heartbeatInterval fun later point =>
            Not (PeerDue point leader peer)
            \/ exists step,
                trace.timingTrace.stepAt (timingSystem system) later = some step
                /\ ProductiveSend step leader peer
  /-- `Trace.SignatureScheduling`. CCF signs within `sig_ms_interval`, but no
  theorem needs the deadline. -/
  signatures : trace.SignatureScheduling
  /-- `Trace.ConfirmationScheduling`. The cleanup request has no deadline. -/
  confirmations : trace.ConfirmationScheduling
  /-- No election timeout within `electionTimeout / 2` of a reset (see `Bounds`).
  CCF also resets on other events, such as granting a vote or stepping down;
  leaving those out allows more timeouts. Needed: without it any node may time out
  at any time, and depose the primary. -/
  electionTimers
    : forall earlier index reset timeout node,
        earlier < index
        -> trace.timingTrace.stepAt (timingSystem system) earlier = some reset
        -> trace.timingTrace.stepAt (timingSystem system) index = some timeout
        -> timeout.action.event = .local node (.timeout .election)
        -> ElectionReset reset node
        -> reset.before.time + model.bounds.electionTimeout / 2 <= timeout.before.time

/-- The timed obligations imply the untimed ones. -/
theorem LivenessModel.Timed.scheduling {model : LivenessModel} {trace : Trace system}
    (timed : model.Timed trace)
    : trace.HeartbeatScheduling /\ trace.SignatureScheduling /\ trace.ConfirmationScheduling := by
  refine
    {
      heartbeats := fun index point leader peer found due => ?_
      signatures := timed.signatures
      confirmations := timed.confirmations
    }
  obtain ⟨_, later, point', _, le, found', _, holds⟩ :=
    timed.heartbeats index point leader peer found due
  exact ⟨later, point', le, found', holds⟩

end CCFRaft.Liveness
