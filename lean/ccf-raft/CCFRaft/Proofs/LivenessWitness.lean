module

public import CCFRaft.Proofs.Liveness
public import Mathlib.Tactic.NormNum

@[expose] public section

namespace CCFRaft.Proofs.LivenessWitness

open Model.Node
open CCFRaft.Liveness
open CCF.MultiNodeTransitionSystem (nodeState)

private def initialNode : NodeState := Model.initialNodeState {0} 0

private def initialState : Model.State := { nodes := [(0, initialNode)] }

private def requestEntries (signed : Bool) : List EntryContent :=
  [.transaction 10 {}] ++ if signed then [.signature] else []

private def requestedNode (signed : Bool) : NodeState :=
  {
    initialNode with
      log :=
        initialNode.log
        ++ (requestEntries signed).map
            fun content => { term := Model.BOOTSTRAP_TERM, content }
      commitIndex := if signed then 3 else 0
  }

private def requestedState (signed : Bool) : Model.State :=
  { nodes := [(0, requestedNode signed)] }

private def fixture (signed : Bool) : Trace where
  state index := if index = 0 then initialState else requestedState signed
  event index := if index = 0 then .local 0 (.append (requestEntries signed)) else .idle
  time index := index
  live _ := {0}

private def environment : LivenessModel where
  initialConfiguration := {0}
  nodes := [0]
  bounds :=
    {
      heartbeatInterval := 1
      electionTimeout := 4
    }

private theorem request_step (signed : Bool)
    : (Model.transitionSystem {0} [0]).step initialState
        (.local 0 (.append (requestEntries signed)))
      = some (requestedState signed) := by
  cases signed <;> rfl

private theorem request_outgoing (signed : Bool)
    : outgoing initialState (.local 0 (.append (requestEntries signed))) = some [] := by
  cases signed <;> rfl

private theorem core_valid (signed : Bool) : (fixture signed).Valid {0} [0] := by
  refine {
    initial := ?_
    step := ?_
    stutter := ?_
    running := ?_
    failures := ?_
    resolution := ?_
    inFlight := ?_
  }
  · apply CCF.TransitionSystem.Reachable.initial
    simp [fixture, initialState, Model.transitionSystem, CCF.MultiNodeTransitionSystem.lift,
      Model.protocol, initialNode]
  · intro index action selected
    by_cases zero : index = 0
    · subst index
      simp [fixture, Event.action] at selected
      subst action
      simpa [fixture] using request_step signed
    · simp [fixture, zero, Event.action] at selected
  · intro index noAction
    by_cases zero : index = 0
    · simp [fixture, zero, Event.action] at noAction
    · simp [fixture, zero]
  · intro index node selected
    by_cases zero : index = 0
    · simp [fixture, zero, Event.actor] at selected
      subst node
      simp [fixture]
    · simp [fixture, zero, Event.actor] at selected
  · intro index
    by_cases zero : index = 0 <;> simp [fixture, zero]
  · intro index packet resolved
    by_cases zero : index = 0 <;> simp [fixture, zero, Event.resolution] at resolved
  · refine Set.finite_empty.subset ?_
    rintro index ⟨envelope, delivered⟩
    by_cases zero : index = 0 <;> simp [fixture, zero] at delivered

private theorem stable (signed : Bool)
    : StableLeader (fixture signed) 0 Model.BOOTSTRAP_TERM := by
  intro index
  refine ⟨by simp [fixture], ?_⟩
  cases index with
  | zero => exact ⟨initialNode, rfl, by decide, rfl, by decide⟩
  | succ index =>
      refine ⟨requestedNode signed, rfl, ?_, ?_, ?_⟩ <;> cases signed <;> decide

private theorem monotone (signed : Bool) : Monotone (fixture signed).time :=
  fun _ _ less => Nat.cast_le.mpr less

private theorem live_quorum (signed : Bool) : LiveQuorum (fixture signed) 0 {0} := by
  refine ⟨0, fun index state _ found => ?_⟩
  show hasQuorum state.activeConfigurations ({0} ∩ {0})
  cases index with
  | zero =>
      have same : state = initialNode := by simpa [fixture, initialState, nodeState] using found.symm
      subst state
      decide
  | succ index =>
      have same : state = requestedNode signed := by
        simpa [fixture, requestedState, nodeState] using found.symm
      subst state
      cases signed <;> decide

private theorem requested (signed : Bool) : HasRequest (requestedNode signed).log 10 := by
  refine ⟨{ term := Model.BOOTSTRAP_TERM, content := .transaction 10 {} }, ?_, {}, rfl⟩
  cases signed <;> simp [requestedNode, requestEntries]

private theorem submitted (signed : Bool) : Submitted (fixture signed) 0 10 :=
  ⟨0, Or.inr ⟨requestEntries signed, rfl, by cases signed <;> simp [requestEntries]⟩⟩

private theorem no_packets (signed : Bool) (packet : Packet)
    : Not ((fixture signed).Sent packet) := by
  by_cases zero : packet.sent = 0
  · simp [Trace.Sent, fixture, zero, Event.action, request_outgoing]
  · simp [Trace.Sent, fixture, zero, Event.action]

private theorem reliable (signed : Bool) : Reliable (fixture signed) {0} 0 :=
  fun packet sent _ _ _ => False.elim (no_packets signed packet sent)

private theorem no_peers (signed : Bool) (index leader peer : Nat)
    : Not ((fixture signed).PeerDue leader peer index) := by
  rintro ⟨leaderLive, peerLive, state, _, _, _, eligible⟩
  have leaderZero : leader = 0 := by simpa [fixture] using leaderLive
  have peerZero : peer = 0 := by simpa [fixture] using peerLive
  subst leader peer
  simp [eligiblePeers] at eligible

private theorem signed_valid : environment.Valid (fixture true) := by
  refine {
    execution := core_valid true
    clockMonotone := monotone true
    heartbeats :=
      fun index leader peer due => False.elim (no_peers true index leader peer due)
    signatures := ?_
    confirmations := ?_
    electionTimers := ?_
  }
  · intro index leader due
    obtain ⟨live, state, found, _, _, unsigned⟩ := due
    have leaderZero : leader = 0 := by simpa [fixture] using live
    subst leader
    cases index with
    | zero =>
        exact ⟨0, by omega, Or.inr ⟨requestEntries true, rfl, by simp [requestEntries]⟩⟩
    | succ index =>
        have same : state = requestedNode true := by
          simpa [fixture, requestedState, nodeState] using found.symm
        subst state
        have covered : Not (maxCommittableIndex (requestedNode true).log < (requestedNode true).log.length \/
            maxCommittableTerm (requestedNode true).log ≠ (requestedNode true).currentTerm) := by decide
        exact False.elim (covered unsigned)
  · intro index leader due
    obtain ⟨live, state, found, _, _, owed⟩ := due
    have leaderZero : leader = 0 := by simpa [fixture] using live
    subst leader
    cases index with
    | zero =>
        have same : state = initialNode := by
          simpa [fixture, initialState, nodeState] using found.symm
        subst state
        exact absurd owed (by decide)
    | succ index =>
        have same : state = requestedNode true := by
          simpa [fixture, requestedState, nodeState] using found.symm
        subst state
        exact absurd owed (by decide)
  · intro index node _ timeout
    by_cases zero : index = 0 <;> simp [fixture, zero] at timeout

/-- All environment and stable-primary assumptions have an actual infinite witness. -/
theorem commit_liveness_witness
    : exists (model : LivenessModel) (trace : Trace),
    exists (leader : NodeID) (term : Nat) (participants : Finset NodeID) (request
                                                                          : ReqID),
      model.Valid trace
      /\ StableLeader (trace.shift 0) leader term
      /\ LiveQuorum trace leader participants
      /\ FairLoss trace (insert leader participants)
      /\ Submitted (trace.shift 0) leader request
      /\ exists index, RequestCommitted trace leader request index := by
  refine ⟨
    environment,
    fixture true,
    0,
    Model.BOOTSTRAP_TERM,
    {0},
    10,
    signed_valid,
    fun index => by simpa [Trace.shift] using stable true index,
    live_quorum true,
    Proofs.Liveness.reliable_suffix_fair_loss (fixture true) {0} 0 (reliable true),
    ⟨0, Or.inr ⟨requestEntries true, rfl, by simp [requestEntries]⟩⟩,
    1,
    ?_
  ⟩
  refine ⟨requestedNode true, rfl, ?_⟩
  simpa [NodeState.committedLog, requestedNode, requestEntries, initialNode,
    Model.initialNodeState]
    using requested true

private theorem quiet_start
    : QuietStart (fixture true) 0 Model.BOOTSTRAP_TERM
        environment.bounds.electionTimeout := by
  refine ⟨⟨?_, ?_, ?_, ?_, ?_⟩, ?_⟩
  · intro node local_ member
    simp only [fixture, ↓reduceIte, initialState, List.mem_singleton, Prod.mk.injEq] at member
    obtain ⟨_, rfl⟩ := member
    decide
  · intro node local_ member preVote
    simp only [fixture, ↓reduceIte, initialState, List.mem_singleton, Prod.mk.injEq] at member
    obtain ⟨_, rfl⟩ := member
    exact absurd preVote (by decide)
  · intro envelope member
    simp [fixture, initialState] at member
  · intro envelope member
    simp [fixture, initialState] at member
  · exact ⟨initialNode, by simp [fixture, initialState], by decide, by decide⟩
  · intro index node state timeout
    by_cases zero : index = 0 <;> simp [fixture, zero] at timeout

private theorem timely : Timely (fixture true) 0 0 :=
  fun packet sent _ _ => False.elim (no_packets true packet sent)

private theorem matching : Matching (fixture true) 0 Model.BOOTSTRAP_TERM := by
  intro index packet request state deliver
  by_cases zero : index = 0 <;> simp [fixture, zero] at deliver

private theorem covered : Covered (fixture true) 0 Model.BOOTSTRAP_TERM := by
  intro index node state timeout
  by_cases zero : index = 0 <;> simp [fixture, zero] at timeout

private theorem incumbent : Incumbent (fixture true) 0 := by
  refine ⟨fun _ => by simp [fixture], fun index state found => ?_, fun index => ?_,
    fun index => ?_⟩
  · cases index with
    | zero =>
        have same : state = initialNode := by
          simpa [fixture, initialState, nodeState] using found.symm
        subst state
        decide
    | succ index =>
        have same : state = requestedNode true := by
          simpa [fixture, requestedState, nodeState] using found.symm
        subst state
        decide
  · by_cases zero : index = 0 <;> simp [fixture, zero]
  · by_cases zero : index = 0 <;> simp [fixture, zero]

/-- The premises of `Properties.stable_leader` have an infinite witness. It has a
single node, so it exercises no timer or heartbeat. -/
theorem stable_leader_witness
    : exists (model : LivenessModel) (trace : Trace),
    exists (leader : NodeID) (term : Nat) (delay : Real),
      model.Valid trace
      /\ QuietStart trace leader term model.bounds.electionTimeout
      /\ Timely trace leader delay
      /\ 0 <= delay
      /\ Matching trace leader term
      /\ model.bounds.heartbeatInterval + delay < model.bounds.electionTimeout / 2
      /\ Covered trace leader term
      /\ Incumbent trace leader
      /\ StableLeader trace leader term :=
  ⟨
    environment,
    fixture true,
    0,
    Model.BOOTSTRAP_TERM,
    0,
    signed_valid,
    quiet_start,
    timely,
    le_rfl,
    matching,
    by norm_num [environment],
    covered,
    incumbent,
    stable true
  ⟩

/-- The premises of `Properties.commit_liveness_timed` have an infinite witness. -/
theorem commit_liveness_timed_witness
    : exists (model : LivenessModel) (trace : Trace),
    exists (leader : NodeID) (term : Nat) (participants : Finset NodeID) (delay : Real),
    exists (request : ReqID),
      model.Valid trace
      /\ QuietStart trace leader term model.bounds.electionTimeout
      /\ Timely trace leader delay
      /\ 0 <= delay
      /\ Matching trace leader term
      /\ model.bounds.heartbeatInterval + delay < model.bounds.electionTimeout / 2
      /\ Covered trace leader term
      /\ Incumbent trace leader
      /\ LiveQuorum trace leader participants
      /\ FairLoss trace (insert leader participants)
      /\ Submitted trace leader request
      /\ exists index, RequestCommitted trace leader request index := by
  refine ⟨
    environment,
    fixture true,
    0,
    Model.BOOTSTRAP_TERM,
    {0},
    0,
    10,
    signed_valid,
    quiet_start,
    timely,
    le_rfl,
    matching,
    by norm_num [environment],
    covered,
    incumbent,
    live_quorum true,
    Proofs.Liveness.reliable_suffix_fair_loss (fixture true) {0} 0 (reliable true),
    submitted true,
    1,
    ?_
  ⟩
  refine ⟨requestedNode true, rfl, ?_⟩
  simpa [NodeState.committedLog, requestedNode, requestEntries, initialNode,
    Model.initialNodeState]
    using requested true

/-- Even a non-Zeno, failure-free stable primary can retain a request forever without signing. -/
private theorem unsigned_never_commits (index : Nat)
    : Not (RequestCommitted (fixture false) 0 10 index) := by
  cases index <;>
    simp [RequestCommitted, fixture, initialState, requestedState, nodeState,
      NodeState.committedLog, requestedNode, initialNode, Model.initialNodeState, HasRequest]

private theorem unsigned_due (index : Nat) : (fixture false).SignatureDue 0 index := by
  cases index with
  | zero =>
      exact ⟨
        by simp [fixture],
        initialNode,
        rfl,
        by decide,
        by decide,
        Or.inl (by decide)
      ⟩
  | succ index =>
      exact ⟨
        by simp [fixture],
        requestedNode false,
        rfl,
        by decide,
        by decide,
        Or.inl (by decide)
      ⟩

/-- The signature deadline rejects that infinite starvation execution. -/
private theorem unsigned_rejected : Not (environment.Valid (fixture false)) := by
  intro valid
  obtain ⟨index, _, cancelled | signed⟩ := valid.signatures 0 0 (unsigned_due 0)
  · exact cancelled (unsigned_due index)
  · by_cases zero : index = 0 <;> simp [Trace.Signs, fixture, zero, requestEntries] at signed

/-- A stable, reliable execution with a submitted request can still starve if signature
scheduling is omitted. -/
theorem unsigned_starvation_witness
    : exists (model : LivenessModel),
    exists (trace : Trace),
      trace.Valid model.initialConfiguration model.nodes
      /\ StableLeader trace 0 Model.BOOTSTRAP_TERM
      /\ LiveQuorum trace 0 {0}
      /\ Reliable trace {0} 0
      /\ Submitted trace 0 10
      /\ (forall index, Not (RequestCommitted trace 0 10 index))
      /\ Not (model.Valid trace) :=
  ⟨
    environment,
    fixture false,
    core_valid false,
    stable false,
    live_quorum false,
    reliable false,
    submitted false,
    unsigned_never_commits,
    unsigned_rejected
  ⟩

private def oldTermPrimary : NodeState :=
  { requestedNode true with currentTerm := Model.BOOTSTRAP_TERM + 1, commitIndex := 0 }

example : maxCommittableIndex oldTermPrimary.log = oldTermPrimary.log.length := by decide

example : highestCommittableIndex oldTermPrimary 0 = 0 := by decide

example
    : ({ fixture true with state := fun _ => { nodes := [(0, oldTermPrimary)] } }
        : Trace).SignatureDue
        0 0 :=
  ⟨by simp [fixture], oldTermPrimary, rfl, by decide, by decide, Or.inr (by decide)⟩

end CCFRaft.Proofs.LivenessWitness
