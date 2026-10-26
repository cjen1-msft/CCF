module

public import CCFRaft.Proofs.Liveness
public import Mathlib.Tactic.NormNum

@[expose] public section

namespace CCFRaft.Proofs.LivenessWitness

open Model.Node
open CCFRaft.Liveness
open CCF.MultiNodeTransitionSystem (nodeState)

def initialNode : NodeState := Model.initialNodeState {0} 0

private def initialState : Model.State := { nodes := [(0, initialNode)] }

def requestEntries (signed : Bool) : List EntryContent :=
  [.transaction 10 {}] ++ if signed then [.signature] else []

def requestedNode (signed : Bool) : NodeState :=
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

def fixtureNode (signed : Bool) : Nat -> NodeState
  | 0 => initialNode
  | _ + 1 => requestedNode signed

def fixtureWorld (signed : Bool) (index : Nat) : World Model.State where
  proto := { nodes := [(0, fixtureNode signed index)] }
  time := ((index - 1 : Nat) : Real)
  live := {0}
  pending := []
  issued := 0

def fixtureStep (signed : Bool) (index : Nat)
    : CCF.Execution.Step (World Model.State) Liveness.Event where
  before := fixtureWorld signed index
  action := if index = 0 then .local 0 (.append (requestEntries signed)) else .idle
  after := fixtureWorld signed (index + 1)

/-- One append at time zero, which takes no time, followed by infinitely many idle
steps that each advance time by one.
There are no peers, hence no sends and no packet identities to advance. -/
def fixture (signed : Bool) : Trace (World Model.State) Liveness.Event where
  initial := fixtureWorld signed 0
  steps := Stream'.Seq.ofStream (fixtureStep signed)

def bounds : Bounds where
  heartbeatInterval := 1
  electionTimeout := 4
  signatureInterval := 1

theorem fixture_stepAt (signed : Bool) (index : Nat)
    : (fixture signed).stepAt index = some (fixtureStep signed index) :=
  rfl

theorem fixture_stateAt (signed : Bool) (index : Nat)
    : (fixture signed).stateAt index = some (fixtureWorld signed index) := by
  cases index <;> rfl

theorem fixture_live (signed : Bool) (index : Nat)
    : HasLive.live (fixtureWorld signed index) = {0} :=
  rfl

theorem coherent (signed : Bool) : (fixture signed).Coherent := by
  constructor
  · intro step stepped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    rfl
  · intro index previous next previousStepped nextStepped
    rw [fixture_stepAt, Option.some.injEq] at previousStepped nextStepped
    subst previous next
    rfl

private theorem request_step (signed : Bool)
    : (Model.transitionSystem {0} [0]).step initialState
        (.local 0 (.append (requestEntries signed)))
      = some (requestedState signed) := by
  cases signed <;> rfl

private theorem request_outgoing (signed : Bool)
    : outgoing initialState (.local 0 (.append (requestEntries signed))) = some [] := by
  cases signed <;> rfl

theorem protocol_valid (signed : Bool)
    : (fixture signed).Valid (protocolModel {0} [0]) := by
  refine ⟨?_, ?_⟩
  · change (Model.transitionSystem {0} [0]).init initialState
    simp [initialState, Model.protocol, initialNode]
  · intro index step stepped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index with
    | zero =>
        change (Model.transitionSystem {0} [0]).step initialState
          (.local 0 (.append (requestEntries signed))) = some (requestedState signed)
        exact request_step signed
    | succ index => rfl

theorem timing_valid (signed : Bool) : (fixture signed).Valid timingModel := by
  refine ⟨trivial, ?_⟩
  intro index step stepped
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  cases index with
  | zero => exact ⟨le_rfl, fun _ => rfl⟩
  | succ index =>
      refine ⟨?_, fun busy => by simp [fixtureStep] at busy⟩
      change ((index + 1 - 1 : Nat) : Real) <= ((index + 1 + 1 - 1 : Nat) : Real)
      exact Nat.cast_le.mpr (by omega)

theorem crash_valid (signed : Bool) : (fixture signed).Valid crashModel := by
  refine ⟨trivial, ?_⟩
  intro index step stepped
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  cases index <;> rfl

theorem delivery_valid (signed : Bool)
    : (fixture signed).Valid (deliveryModel {0} [0]) := by
  refine ⟨⟨rfl, rfl⟩, ?_⟩
  intro index step stepped
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  cases index with
  | zero =>
      refine ⟨trivial, trivial, [], ?_, rfl, rfl⟩
      change (do
        let _ <- (Model.transitionSystem {0} [0]).step initialState
          (.local 0 (.append (requestEntries signed)))
        outgoing initialState (.local 0 (.append (requestEntries signed)))) = some []
      rw [request_step]
      exact request_outgoing signed
  | succ index => exact ⟨trivial, trivial, [], rfl, rfl, rfl⟩

theorem stable (signed : Bool)
    : StableLeader (fixture signed) 0 0 Model.BOOTSTRAP_TERM := by
  refine ⟨⟨fixtureWorld signed 0, fixture_stateAt signed 0⟩, ?_⟩
  intro index point _ found
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  refine ⟨fixtureWorld signed index, fixtureNode signed index, fixture_stateAt signed index,
    Finset.mem_singleton_self 0, rfl, ?_, ?_, ?_⟩
  all_goals cases index <;> cases signed <;> simp only [fixtureNode] <;> decide

private theorem live_quorum (signed : Bool) : LiveQuorum (fixture signed) 0 {0} := by
  refine ⟨0, fixtureWorld signed 0, fixture_stateAt signed 0, ?_⟩
  intro index point state _ found nodeFound
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  change some (fixtureNode signed index) = some state at nodeFound
  have same := Option.some.inj nodeFound
  subst state
  cases index <;> cases signed <;> simp only [fixtureNode, fixture_live] <;> decide

private theorem requested (signed : Bool) : HasRequest (requestedNode signed).log 10 := by
  refine ⟨{ term := Model.BOOTSTRAP_TERM, content := .transaction 10 {} }, ?_, {}, rfl⟩
  cases signed <;> simp [requestedNode, requestEntries]

private theorem submitted (signed : Bool) : Submitted (fixture signed) 0 0 10 := by
  refine ⟨0, fixtureWorld signed 0, le_rfl, fixture_stateAt signed 0,
    Or.inr ⟨fixtureStep signed 0, requestEntries signed, fixture_stepAt signed 0, rfl, ?_⟩⟩
  cases signed <;> simp [requestEntries]

private theorem committed : RequestCommitted (fixture true) 0 10 1 := by
  refine ⟨fixtureWorld true 1, requestedNode true, fixture_stateAt true 1, rfl, ?_⟩
  simpa [NodeState.committedLog, requestedNode, requestEntries, initialNode,
    Model.initialNodeState] using requested true

private theorem no_packets (signed : Bool) (index : Nat) (packet : Packet)
    : Not ((fixture signed).SentAt index packet) := by
  rintro ⟨step, stepped, sent, _⟩
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  change packet ∈ ([] : List Packet) at sent
  cases sent

private theorem reliable (signed : Bool) : Reliable (fixture signed) {0} 0 :=
  fun index packet sent _ _ _ => False.elim (no_packets signed index packet sent)

private theorem fair (signed : Bool) : FairLoss (fixture signed) {0} :=
  Proofs.Liveness.reliable_suffix_fair_loss (reliable signed)

private theorem no_peers (signed : Bool) (index leader peer : Nat)
    : Not (PeerDue (fixtureWorld signed index) leader peer) := by
  rintro ⟨leaderLive, peerLive, state, _, _, _, eligible⟩
  have leaderZero : leader = 0 := Finset.mem_singleton.mp leaderLive
  have peerZero : peer = 0 := Finset.mem_singleton.mp peerLive
  subst leader peer
  simp [eligiblePeers] at eligible

theorem heartbeats (signed : Bool) (bound : Option Real)
    : (fixture signed).HeartbeatScheduling bound := by
  intro leader peer index point found due
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  exact False.elim (no_peers signed index leader peer due)

private theorem signatures_with_deadline (bound : Option Real)
    (onTime : Deadline bound (fixtureWorld true 0) (fixtureWorld true 0))
    : (fixture true).SignatureScheduling bound := by
  intro leader index point found due
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  obtain ⟨leaderLive, state, nodeFound, _, _, unsigned⟩ := due
  have leaderZero : leader = 0 := Finset.mem_singleton.mp leaderLive
  subst leader
  cases index with
  | zero =>
      refine ⟨0, fixtureWorld true 0, le_rfl, fixture_stateAt true 0, onTime, Or.inr ?_⟩
      exact ⟨
        fixtureStep true 0,
        fixture_stepAt true 0,
        requestEntries true,
        rfl,
        show EntryContent.signature ∈ requestEntries true by decide
      ⟩
  | succ index =>
      change some (requestedNode true) = some state at nodeFound
      have same := Option.some.inj nodeFound
      subst state
      have covered :
          Not (maxCommittableIndex (requestedNode true).log < (requestedNode true).log.length
            \/ maxCommittableTerm (requestedNode true).log
              ≠ (requestedNode true).currentTerm) := by decide
      exact False.elim (covered unsigned)

private theorem signatures : (fixture true).SignatureScheduling none :=
  signatures_with_deadline none trivial

private theorem no_confirmations (signed : Bool) (index leader : Nat)
    : Not (ConfirmationDue (fixtureWorld signed index) leader) := by
  rintro ⟨leaderLive, state, found, _, _, owed⟩
  have leaderZero : leader = 0 := Finset.mem_singleton.mp leaderLive
  subst leader
  change some (fixtureNode signed index) = some state at found
  have same := Option.some.inj found
  subst state
  cases index <;> cases signed <;> simp only [fixtureNode] at owed <;>
    exact absurd owed (by decide)

private theorem confirmations (signed : Bool) (bound : Option Real)
    : (fixture signed).RetirementConfirmedScheduling bound := by
  intro leader index point found due
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  exact False.elim (no_confirmations signed index leader due)

theorem no_deliveries (signed : Bool) (index : Nat) (packet : Packet)
    : Not ((fixtureStep signed index).action = .deliver packet) := by
  cases index <;> simp [fixtureStep]

theorem no_timeouts (signed : Bool) (index node : Nat)
    : Not ((fixtureStep signed index).action = .local node (.timeout .election)) := by
  cases index <;> simp [fixtureStep]

private theorem elections (signed : Bool) (minimum : Real)
    : (fixture signed).ElectionScheduling (some minimum) := by
  intro _ index _ step node _ _ stepped timeout _
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  exact False.elim (no_timeouts signed index node timeout)

private theorem quiet (index : Nat)
    : Quiet 0 Model.BOOTSTRAP_TERM (HasProtocol.proto (fixtureWorld true index)) := by
  change Quiet 0 Model.BOOTSTRAP_TERM { nodes := [(0, fixtureNode true index)] }
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro node local_ member
    simp only [List.mem_singleton, Prod.mk.injEq] at member
    obtain ⟨_, rfl⟩ := member
    cases index <;> simp only [fixtureNode] <;> decide
  · intro node local_ member preVote
    simp only [List.mem_singleton, Prod.mk.injEq] at member
    obtain ⟨_, rfl⟩ := member
    cases index <;> simp only [fixtureNode] at preVote <;> exact absurd preVote (by decide)
  · intro envelope member
    simp at member
  · intro envelope member
    simp at member
  · refine ⟨fixtureNode true index, by simp, ?_, ?_⟩
    all_goals cases index <;> simp only [fixtureNode] <;> decide

theorem quiet_start
    : QuietStart (fixture true) 0 0 Model.BOOTSTRAP_TERM bounds.electionTimeout := by
  refine ⟨⟨fixtureWorld true 0, fixture_stateAt true 0, quiet 0⟩, ?_⟩
  intro _ index step node _ _ _ stepped timeout
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  exact False.elim (no_timeouts true index node timeout)

private theorem timely : Timely (fixture true) 0 0 0 :=
  fun index packet sent _ _ _ => False.elim (no_packets true index packet sent)

private theorem matching : Matching (fixture true) 0 0 Model.BOOTSTRAP_TERM := by
  intro index step packet _ _ _ stepped deliver
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  exact False.elim (no_deliveries true index packet deliver)

private theorem covered : Covered (fixture true) 0 0 Model.BOOTSTRAP_TERM := by
  intro index step node _ _ stepped timeout
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  exact False.elim (no_timeouts true index node timeout)

private theorem incumbent : Incumbent (fixture true) 0 0 := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro index point le found
    exact (stable true).live le found
  · intro index point state le found nodeFound
    apply (stable true).notRetired le
    rw [Trace.nodeAt_of_stateAt found]
    exact nodeFound
  · intro index step _ stepped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep]
  · intro index step _ stepped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep]

/-- A single-node execution satisfies every commit-liveness premise.
Its first append includes request 10 and a signature, committing both immediately. -/
theorem commit_liveness_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists
    (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event) (start : Nat),
    exists (leader : NodeID) (term : Nat) (participants : Finset NodeID) (request
                                                                          : ReqID),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel config nodes)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel config nodes)
      /\ trace.HeartbeatScheduling none
      /\ trace.SignatureScheduling none
      /\ trace.RetirementConfirmedScheduling none
      /\ Liveness.StableLeader trace start leader term
      /\ Liveness.LiveQuorum trace leader participants
      /\ Liveness.FairLoss trace (insert leader participants)
      /\ Liveness.Submitted trace start leader request
      /\ exists index, Liveness.RequestCommitted trace leader request index := by
  exact ⟨
    {0},
    [0],
    fixture true,
    0,
    0,
    Model.BOOTSTRAP_TERM,
    {0},
    10,
    coherent true,
    protocol_valid true,
    timing_valid true,
    crash_valid true,
    delivery_valid true,
    heartbeats true none,
    signatures,
    confirmations true none,
    stable true,
    live_quorum true,
    by simpa using fair true,
    submitted true,
    1,
    committed
  ⟩

/-- The same infinite single-node execution satisfies the timed leadership premises.
There are no peers, deliveries or election timeouts. -/
theorem stable_leader_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists
    (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event) (bounds
                                                                          : Liveness.Bounds) (start
                                                                                              : Nat)
      ,
    exists (leader : NodeID) (term : Nat) (delay : Real),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel config nodes)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel config nodes)
      /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
      /\ trace.SignatureScheduling none
      /\ trace.RetirementConfirmedScheduling none
      /\ trace.ElectionScheduling (some (bounds.electionTimeout / 2))
      /\ Liveness.QuietStart trace start leader term bounds.electionTimeout
      /\ Liveness.Timely trace start leader delay
      /\ 0 <= delay
      /\ Liveness.Matching trace start leader term
      /\ bounds.heartbeatInterval + delay < bounds.electionTimeout / 2
      /\ Liveness.Covered trace start leader term
      /\ Liveness.Incumbent trace start leader
      /\ Liveness.StableLeader trace start leader term := by
  exact ⟨
    {0},
    [0],
    fixture true,
    bounds,
    0,
    0,
    Model.BOOTSTRAP_TERM,
    0,
    coherent true,
    protocol_valid true,
    timing_valid true,
    crash_valid true,
    delivery_valid true,
    heartbeats true (some bounds.heartbeatInterval),
    signatures,
    confirmations true none,
    elections true (bounds.electionTimeout / 2),
    quiet_start,
    timely,
    le_rfl,
    matching,
    by norm_num [bounds],
    covered,
    incumbent,
    stable true
  ⟩

/-- The signed execution also satisfies every timed commit-liveness premise. -/
theorem commit_liveness_timed_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists
    (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event) (bounds
                                                                          : Liveness.Bounds) (start
                                                                                              : Nat)
      ,
    exists
    (leader : NodeID) (term : Nat) (participants : Finset NodeID) (delay : Real),
    exists (request : ReqID),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel config nodes)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel config nodes)
      /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
      /\ trace.SignatureScheduling none
      /\ trace.RetirementConfirmedScheduling none
      /\ trace.ElectionScheduling (some (bounds.electionTimeout / 2))
      /\ Liveness.QuietStart trace start leader term bounds.electionTimeout
      /\ Liveness.Timely trace start leader delay
      /\ 0 <= delay
      /\ Liveness.Matching trace start leader term
      /\ bounds.heartbeatInterval + delay < bounds.electionTimeout / 2
      /\ Liveness.Covered trace start leader term
      /\ Liveness.Incumbent trace start leader
      /\ Liveness.LiveQuorum trace leader participants
      /\ Liveness.FairLoss trace (insert leader participants)
      /\ Liveness.Submitted trace start leader request
      /\ exists index, Liveness.RequestCommitted trace leader request index := by
  exact ⟨
    {0},
    [0],
    fixture true,
    bounds,
    0,
    0,
    Model.BOOTSTRAP_TERM,
    {0},
    0,
    10,
    coherent true,
    protocol_valid true,
    timing_valid true,
    crash_valid true,
    delivery_valid true,
    heartbeats true (some bounds.heartbeatInterval),
    signatures,
    confirmations true none,
    elections true (bounds.electionTimeout / 2),
    quiet_start,
    timely,
    le_rfl,
    matching,
    by norm_num [bounds],
    covered,
    incumbent,
    live_quorum true,
    by simpa using fair true,
    submitted true,
    1,
    committed
  ⟩

/-- Every fixture state is in a stable window, whatever its length. -/
private theorem fixture_window (duration : Real)
    : StableWindow (fixture true) 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  refine ⟨?_, ⟨?_, ?_⟩, ?_, ?_⟩
  · intro index point _ found
    rw [fixture_stateAt, Option.some.injEq] at found
    subst point
    exact ⟨(quiet index).among {0}, fun _ member => by cases member⟩
  · intro index point within found
    exact (stable true).live within.1 found
  · intro index point state within found nodeFound
    apply (stable true).notRetired within.1
    rw [Trace.nodeAt_of_stateAt found]
    exact nodeFound
  · intro index point state _ found nodeFound
    rw [fixture_stateAt, Option.some.injEq] at found
    subst point
    change some (fixtureNode true index) = some state at nodeFound
    have same := Option.some.inj nodeFound
    subst state
    cases index <;> simp only [fixtureNode, fixture_live] <;> decide
  · intro index step packet _ stepped dropped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep] at dropped

private theorem fixture_settled (duration : Real)
    : Window.ReconfigurationSettled (fixture true) 0 duration 0 := by
  intro index point state _ found nodeFound
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  change some (fixtureNode true index) = some state at nodeFound
  have same := Option.some.inj nodeFound
  subst state
  cases index <;> simp only [fixtureNode] <;> decide

private theorem initial_backlog : BacklogTerms (fixture true) 0 0 {0} 0 := by
  intro first leaderState follower followerState found leaderFound member followerFound
  have zero := Finset.mem_singleton.mp member
  subst follower
  rw [fixture_stateAt, Option.some.injEq] at found
  subst first
  change some initialNode = some leaderState at leaderFound
  change some initialNode = some followerState at followerFound
  have leaderSame := Option.some.inj leaderFound
  have followerSame := Option.some.inj followerFound
  subst leaderState followerState
  decide

private theorem initial_in_term : InTermAt (fixture true) 0 Model.BOOTSTRAP_TERM {0} := by
  intro follower member
  rw [Finset.mem_singleton.mp member]
  exact ⟨fixtureWorld true 0, initialNode, fixture_stateAt true 0, rfl, by decide⟩

/-- For every nonnegative window length, the windowed timed commit-liveness
premises and conclusion hold together, with positive heartbeat and signature
bounds of `1 / 4`.
The first append commits request 10 at time zero. It takes no time, so its
after-state is recorded inside the window, even one of length zero. -/
theorem timed_commit_window_witness
    : let bounds : Bounds :=
        { heartbeatInterval := 1 / 4, electionTimeout := 4, signatureInterval := 1 / 4 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Trace (World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (protocolModel {0} [0])
              /\ trace.Valid timingModel
              /\ trace.Valid crashModel
              /\ trace.Valid (deliveryModel {0} [0])
              /\ trace.Valid (boundedDelayModel 0)
              /\ TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ trace.SignatureScheduling (some bounds.signatureInterval)
              /\ StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
              /\ Window.ReconfigurationSettled trace 0 duration 0
              /\ BacklogTerms trace 0 0 {0} 0
              /\ InTermAt trace 0 Model.BOOTSTRAP_TERM {0}
              /\ SubmittedAt trace 0 0 10)
            /\ exists index,
                Within trace 0 duration index /\ RequestCommitted trace 0 10 index := by
  intro bounds duration nonnegative
  refine ⟨fixture true, ?_, 1, ?_, committed⟩
  · refine ⟨coherent true, protocol_valid true, timing_valid true, crash_valid true,
      delivery_valid true, ?_, ?_, by norm_num, heartbeats true _, ?_,
      fixture_window duration, fixture_settled duration, initial_backlog,
      initial_in_term, ?_⟩
    · refine ⟨?_, ?_⟩
      · intro packet member
        change packet ∈ ([] : List Packet) at member
        cases member
      · intro index step stepped
        rw [fixture_stepAt, Option.some.injEq] at stepped
        subst step
        intro packet member
        change packet ∈ ([] : List Packet) at member
        cases member
    · intro limit
      obtain ⟨index, enough⟩ := exists_nat_ge limit
      refine ⟨index + 1, fixtureWorld true (index + 1), fixture_stateAt true (index + 1), ?_⟩
      change limit <= ((index + 1 - 1 : Nat) : Real)
      simpa using enough
    · apply signatures_with_deadline
      apply le_add_of_nonneg_right
      norm_num
    · refine Or.inr ⟨fixtureStep true 0, requestEntries true, fixture_stepAt true 0, rfl, ?_⟩
      decide
  · refine ⟨Nat.zero_le 1, fun first point firstFound found => ?_⟩
    rw [fixture_stateAt, Option.some.injEq] at firstFound found
    subst first point
    change ((0 : Nat) : Real) <= ((0 : Nat) : Real) + duration
    simpa using nonnegative

private theorem unsigned_never_commits (index : Nat)
    : Not (RequestCommitted (fixture false) 0 10 index) := by
  rintro ⟨point, state, found, nodeFound, request⟩
  rw [fixture_stateAt, Option.some.injEq] at found
  subst point
  change some (fixtureNode false index) = some state at nodeFound
  have same := Option.some.inj nodeFound
  subst state
  have empty : (fixtureNode false index).committedLog = [] := by
    cases index <;> rfl
  rw [empty] at request
  obtain ⟨entry, member, _⟩ := request
  cases member

private theorem unsigned_due (index : Nat)
    : SignatureDue (fixtureWorld false index) 0 := by
  refine ⟨Finset.mem_singleton_self 0, fixtureNode false index, rfl, ?_, ?_, Or.inl ?_⟩
  all_goals cases index <;> simp only [fixtureNode] <;> decide

/-- Signing remains due forever, and no recorded step signs. -/
private theorem unsigned_rejected : Not ((fixture false).SignatureScheduling none) := by
  intro scheduled
  obtain ⟨index, point, _, found, _, outcome⟩ :=
    scheduled 0 0 (fixtureWorld false 0) (fixture_stateAt false 0) (unsigned_due 0)
  rcases outcome with cancelled | signed
  · rw [fixture_stateAt, Option.some.injEq] at found
    subst point
    exact cancelled (unsigned_due index)
  · obtain ⟨step, stepped, entries, action, signature⟩ := signed
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index with
    | zero =>
        have same : requestEntries false = entries := by simpa [fixtureStep] using action
        subst entries
        exact absurd (show EntryContent.signature ∈ requestEntries false from signature)
          (by decide)
    | succ index => simp [fixtureStep] at action

/-- Every commit-liveness premise except signature scheduling holds.
The failure-free, reliable, non-Zeno execution submits request 10 but never signs, so no state commits it. -/
theorem unsigned_starvation_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists
    (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event) (start : Nat),
    exists (leader : NodeID) (term : Nat) (participants : Finset NodeID) (request
                                                                          : ReqID),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel config nodes)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel config nodes)
      /\ trace.HeartbeatScheduling none
      /\ trace.RetirementConfirmedScheduling none
      /\ Liveness.StableLeader trace start leader term
      /\ Liveness.LiveQuorum trace leader participants
      /\ Liveness.FairLoss trace (insert leader participants)
      /\ Liveness.Submitted trace start leader request
      /\ Not (exists index, Liveness.RequestCommitted trace leader request index)
      /\ Liveness.Reliable trace (insert leader participants) start
      /\ Not (trace.SignatureScheduling none) := by
  refine ⟨
    {0},
    [0],
    fixture false,
    0,
    0,
    Model.BOOTSTRAP_TERM,
    {0},
    10,
    coherent false,
    protocol_valid false,
    timing_valid false,
    crash_valid false,
    delivery_valid false,
    heartbeats false none,
    confirmations false none,
    stable false,
    live_quorum false,
    by simpa using fair false,
    submitted false,
    ?_,
    by simpa using reliable false,
    unsigned_rejected
  ⟩
  rintro ⟨index, committed⟩
  exact unsigned_never_commits index committed

private def oldTermPrimary : NodeState :=
  { requestedNode true with currentTerm := Model.BOOTSTRAP_TERM + 1, commitIndex := 0 }

example : maxCommittableIndex oldTermPrimary.log = oldTermPrimary.log.length := by decide

example : highestCommittableIndex oldTermPrimary 0 = 0 := by decide

example
    : SignatureDue
        ({ fixtureWorld true 0 with proto := { nodes := [(0, oldTermPrimary)] } }
          : World Model.State)
        0 :=
  ⟨by decide, oldTermPrimary, rfl, by decide, by decide, Or.inr (by decide)⟩

end CCFRaft.Proofs.LivenessWitness
