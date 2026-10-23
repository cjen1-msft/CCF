module

public import CCFRaft.Liveness.Model.Timing

@[expose] public section

/-!
CCF background-task and election-timer scheduling assumptions.
Each takes an optional real-time bound: `none` requires only eventual execution,
`some bound` additionally requires it before `bound` has elapsed.
Network fairness is a separate assumption in `FairLoss`.
-/

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]

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
  /-- An upper bound on the real time a primary with unsigned entries takes to
  append a signature. CCF signs once `sig_ms_interval` elapses, checked on each
  tick, so this is at least that plus the tick interval. -/
  signatureInterval : Real

/-- No deadline, or at most `bound` after `origin`. -/
def Deadline (bound : Option Real) (origin point : W) : Prop :=
  match bound with
  | none => True
  | some bound => time point <= time origin + bound

/-- Whenever `Due` holds, it later ceases to hold or `Fires` runs, from a state
within the optional bound. A due obligation must resolve before a finite
execution ends. -/
def Scheduled (trace : Trace W Event) (bound : Option Real) (Due : W -> Prop)
    (Fires : CCF.Execution.Step W Event -> Prop)
    : Prop :=
  forall index point,
    trace.stateAt index = some point
    -> Due point
    -> Eventually trace index
        fun later laterPoint =>
          Deadline bound point laterPoint
          /\ (Not (Due laterPoint)
              \/ exists step, trace.stepAt later = some step /\ Fires step)

/-- An active primary with an eligible, live replication peer. -/
def PeerDue (point : W) (leader peer : NodeID) : Prop :=
  Membership.mem (live point) leader
  /\ Membership.mem (live point) peer
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ peer ∈ eligiblePeers state leader

/-- A send must carry entries when its current frontier has a backlog. -/
def ProductiveSend (step : CCF.Execution.Step W Event) (leader peer : NodeID) : Prop :=
  exists state frontier,
    CCF.MultiNodeTransitionSystem.nodeState (proto step.before) leader = some state
    /\ step.action = .local leader (.sendEntries peer frontier)
    /\ (state.sentIndex peer < state.log.length -> state.sentIndex peer < frontier)

/-- A primary sends AppendEntries from `sent_idx + 1` to every other node each
time `request_timeout` elapses (`raft.h`, `Aft::periodic`); `eligiblePeers`
is a subset of `all_other_nodes`, from which CCF drops a node only once its
retirement confirmation commits (`set_retired_committed`). Needed: without it a
primary that appends a signature and then never sends again leaves a lagging
follower, whose acknowledgement the signature needs, behind forever.
With `some bound`, every later state past the deadline follows a productive send.
Needed: if the primary could wait longer than half an election timeout between
heartbeats, a follower could time out and depose it. -/
def Trace.HeartbeatScheduling (trace : Trace W Event) (bound : Option Real) : Prop :=
  forall leader peer,
    Scheduled trace bound (fun point => PeerDue point leader peer)
      (fun step => ProductiveSend step leader peer)

/-- Unsigned entries or a signature from an older term require a new signature. -/
def SignatureDue (point : W) (leader : NodeID) : Prop :=
  Membership.mem (live point) leader
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ (maxCommittableIndex state.log < state.log.length
          \/ maxCommittableTerm state.log ≠ state.currentTerm)

/-- The input actually appends a signature, rather than merely enabling one. -/
def Signs (step : CCF.Execution.Step W Event) (leader : NodeID) : Prop :=
  exists entries,
    step.action = .local leader (.append entries) /\ List.Mem .signature entries

/-- CCF's periodic signature task signs every `sig_ms_interval` when there are
unsigned entries (`committable_gap() > 0`) or the consensus asks for one
(`src/node/history.h`, `start_signature_emit_timer`); `raft.h` asks
(`get_signature_disposition`) while `should_sign`, which `become_leader` sets.
Needed: `Proofs.LivenessWitness.unsigned_starvation_witness` is a stable,
reliable execution with a submitted request that never commits because it
never signs. CCF signs within `sig_ms_interval`, but no theorem needs the bound. -/
def Trace.SignatureScheduling (trace : Trace W Event) (bound : Option Real) : Prop :=
  forall leader,
    Scheduled trace bound (fun point => SignatureDue point leader)
      (fun step => Signs step leader)

/-- The primary may append a retirement confirmation: a committed configuration
removed a node with no confirmation in the log. This is the enabling condition
of the confirmation guard in `appendEntry`. -/
def ConfirmationDue (point : W) (leader : NodeID) : Prop :=
  Membership.mem (live point) leader
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ (state.retirementCompletedNodes \ retiredCommittedNodes state.log).Nonempty

/-- The input actually appends a retirement confirmation. -/
def Confirms (step : CCF.Execution.Step W Event) (leader : NodeID) : Prop :=
  exists entries,
    step.action = .local leader (.append entries)
    /\ exists content,
        content ∈ entries /\ content.metadata.retirementConfirmations.Nonempty

/-- A primary calls `retired_node_cleanup` whenever a commit retires a
configuration (`raft.h`, `Aft::commit`) or it is elected (`become_leader`), and
that runs `set_retired_committed` (`src/node/rpc/node_frontend.h`), which
confirms every retired node whose retirement is committed. This assumes that
request succeeds: CCF sends it once and does not retry it. Needed: when a commit
retires every other member of the configurations before a signature, the
primary alone makes that signature committable, but only another append or
acknowledgement reruns the commit scan; see `LIVENESS.md`. The cleanup request
has no deadline. -/
def Trace.ConfirmationScheduling (trace : Trace W Event) (bound : Option Real) : Prop :=
  forall leader,
    Scheduled trace bound (fun point => ConfirmationDue point leader)
      (fun step => Confirms step leader)

/-- Steps that call `restart_election_timeout` in CCF: starting a pre-vote or
regular election, stepping down on a quorum check, adopting a newer term,
granting a regular vote, or accepting an AppendEntries term/log check.
On a valid protocol step, an increased local term records `become_candidate` or
`become_aware_of_new_term`; inspecting the actual transition preserves the
message-specific guards (unknown responses, non-primary AE responses, and vote
proposals cannot cause spurious resets).
A same-term AppendEntries also resets a candidate through `become_follower`,
even if its log check fails; an established follower resets only after that
check. Multiple resets within one atomic step record the final draw. -/
def ElectionReset (step : CCF.Execution.Step W Event) (node : NodeID) : Prop :=
  match step.action with
  | .local actor (.timeout _) => actor = node
  | .deliver packet =>
      packet.envelope.target = node
      /\ match CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node with
          | none => False
          | some state =>
              (match CCF.MultiNodeTransitionSystem.nodeState (proto step.after) node with
                | some after => state.currentTerm < after.currentTerm
                | none => False)
              \/ match packet.envelope.payload with
                  | .appendEntriesRequest request =>
                      state.currentTerm < request.term
                      \/ (state.currentTerm = request.term
                          /\ (state.role = .candidate
                              \/ state.role = .preVoteCandidate
                              \/ termAt state.log request.prevLogIndex
                                  = request.prevLogTerm))
                  | .requestVoteRequest request =>
                      state.currentTerm = request.term
                      /\ voteLogUpToDate state request
                      /\ !state.primaryKnown
                      /\ (state.votedFor = none
                          \/ state.votedFor = some packet.envelope.source)
                  | _ => False
  | _ => False

/-- No election timeout within `minimum` of a reset; `none` allows a timeout at
any time. Pass half of `Bounds.electionTimeout`.
Needed: without it any node may time out at any time, and depose the primary. -/
def Trace.ElectionScheduling (trace : Trace W Event) (minimum : Option Real) : Prop :=
  match minimum with
  | none => True
  | some minimum =>
      forall earlier index reset timeout node,
        earlier < index
        -> trace.stepAt earlier = some reset
        -> trace.stepAt index = some timeout
        -> timeout.action = .local node (.timeout .election)
        -> ElectionReset reset node
        -> time reset.before + minimum <= time timeout.before

end CCFRaft.Liveness
