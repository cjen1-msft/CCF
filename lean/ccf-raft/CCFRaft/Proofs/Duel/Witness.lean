module

public import CCFRaft.Liveness.Model.Policy
public import CCFRaft.Liveness.Assumptions.Round
public import CCFRaft.Proofs.Config
public import CCFRaft.Proofs.Duel.Laws
public import CCFRaft.Proofs.LivenessWitness

@[expose] public section

/-!
# A one-node witness for the duel premises

The run is constant in the sample: node 0 is primary throughout, so no participant reset consumes a draw.
The witness exercises the premises, not the probabilistic rounds.
The window starts at index one, after the first append commits the bootstrap configuration.
-/

namespace CCFRaft.Proofs.Duel.Witness

open CCFRaft.Liveness
open CCFRaft.Proofs.LivenessWitness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCF.MultiNodeTransitionSystem (nodeState)
open MeasureTheory

/-- The fixture's one-node initial configuration. -/
@[instance_reducible]
def initialConfiguration : Config.InitialConfiguration := ⟨{0}⟩

attribute [local instance] initialConfiguration

def nodes : List NodeID := [0]

def E : Real := bounds.electionTimeout

def maxDelay : Real := 0

def rho : Real := 0

noncomputable def law : Measure Real := uniform E

/-- Add a constant zero election deadline to the fixture. -/
def lift (world : World Model.State) : DuelWorld where
  toWorld := world
  deadlines := fun _ => 0

def liftStep (step : CCF.Execution.Step (World Model.State) Liveness.Event)
    : DuelStep where
  before := lift step.before
  action := step.action
  after := lift step.after

/-- Replay the signed fixture, independently of any draws. -/
def policy : Policy where
  initial := lift (fixtureWorld true 0)
  next history _ :=
    some
      (
        (fixtureStep true history.length).action,
        lift (fixtureWorld true (history.length + 1))
      )

private theorem no_resets (index node : Nat)
    : Not (ElectionReset (liftStep (fixtureStep true index)) node) := by
  cases index <;> simp [ElectionReset, liftStep, fixtureStep]

private theorem stamp_fixture (sample : Sample) (history : List DuelStep) (index : Nat)
    : stamp {0} sample history (lift (fixtureWorld true index))
        (fixtureStep true index).action (lift (fixtureWorld true (index + 1)))
      = liftStep (fixtureStep true index) := by
  cases index <;> simp [stamp, ElectionReset, fixtureStep, liftStep, lift]

private noncomputable def advance (sample : Sample) (state : List DuelStep × DuelWorld)
    : Option (DuelStep × (List DuelStep × DuelWorld)) :=
  (policy.next state.1 state.2).map
    fun choice =>
      let step := stamp {0} sample state.1 state.2 choice.1 choice.2
      (step, (state.1 ++ [step], step.after))

private theorem advance_fixture (sample : Sample) (history : List DuelStep)
    : advance sample (history, lift (fixtureWorld true history.length))
      = some
          (
            liftStep (fixtureStep true history.length),
            (
              history ++ [liftStep (fixtureStep true history.length)],
              lift (fixtureWorld true (history.length + 1))
            )
          ) := by
  simp only [advance, policy, Option.map_some, stamp_fixture]
  rfl

private theorem get?_fixture (sample : Sample) (history : List DuelStep) (index : Nat)
    : (Stream'.Seq.corec (advance sample)
        (history, lift (fixtureWorld true history.length))).get?
        index
      = some (liftStep (fixtureStep true (history.length + index))) := by
  induction index generalizing history with
  | zero =>
      rw [Stream'.Seq.corec_cons (advance_fixture sample history)]
      simp
  | succ index ih =>
      rw [Stream'.Seq.corec_cons (advance_fixture sample history)]
      simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]
        using ih (history ++ [liftStep (fixtureStep true history.length)])

/-- Every recorded step is the corresponding lifted fixture step. -/
theorem run_stepAt (sample : Sample) (index : Nat)
    : (run {0} policy sample).stepAt index
      = some (liftStep (fixtureStep true index)) := by
  change (Stream'.Seq.corec (advance sample)
    ([], lift (fixtureWorld true 0))).get? index = _
  simpa using get?_fixture sample [] index

/-- Every recorded state is the corresponding lifted fixture state. -/
theorem run_stateAt (sample : Sample) (index : Nat)
    : (run {0} policy sample).stateAt index = some (lift (fixtureWorld true index)) := by
  cases index with
  | zero => rfl
  | succ index =>
      simp only [Trace.stateAt, run_stepAt, Option.map_some]
      rfl

/-- Constant dependence on the sample is measurable. -/
theorem borel : Borel {0} policy := by
  intro index
  simpa only [run_stepAt]
    using (measurable_const
            : Measurable[MeasurableSpace.pi, stepSpace]
                fun _ : Sample => some (liftStep (fixtureStep true index)))

/-- The continuous uniform law on `[2, 4]` has zero mass at any point. -/
theorem law_valid : Law E (4 * maxDelay) rho law := by
  simpa [law, maxDelay, rho]
    using (Rounds.uniform_law (E := E) (margin := 4 * maxDelay)
            (by norm_num [E, bounds]) (by norm_num [maxDelay]))

/-- Lifting the fixture preserves all five admissibility obligations. -/
theorem admissible (sample : Sample)
    : CCFRaft.Proofs.Liveness.Admissible
        (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)
        (run {0} policy sample) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · constructor
    · intro step stepped
      rw [run_stepAt, Option.some.injEq] at stepped
      subst step
      rfl
    · intro index previous next previousStepped nextStepped
      rw [run_stepAt, Option.some.injEq] at previousStepped nextStepped
      subst previous next
      rfl
  · refine ⟨(protocol_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (protocol_valid true).2 index _ (fixture_stepAt true index)
  · refine ⟨(timing_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (timing_valid true).2 index _ (fixture_stepAt true index)
  · refine ⟨(crash_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (crash_valid true).2 index _ (fixture_stepAt true index)
  · refine ⟨(delivery_valid true).1, ?_⟩
    intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact (delivery_valid true).2 index _ (fixture_stepAt true index)

/-- Admissibility in the conjunction form used by `Properties`. -/
theorem admissible_unfolded (sample : Sample)
    : let trace := run {0} policy sample
      let system := Model.transitionSystem Config.INITIAL_CONFIGURATION nodes
      trace.Coherent
      /\ trace.Valid (protocolModel system)
      /\ trace.Valid timingModel
      /\ trace.Valid crashModel
      /\ trace.Valid (deliveryModel system) :=
  ⟨
    (admissible sample).coherent,
    (admissible sample).protocol,
    (admissible sample).timing,
    (admissible sample).crash,
    (admissible sample).delivery
  ⟩

/-- There are no pending packets, so the zero delay bound holds. -/
theorem bounded_delay (sample : Sample)
    : (run {0} policy sample).Valid (boundedDelayModel maxDelay) := by
  refine ⟨?_, ?_⟩
  · intro packet member
    change packet ∈ ([] : List Packet) at member
    cases member
  · intro index step stepped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    intro packet member
    change packet ∈ ([] : List Packet) at member
    cases member

/-- No reset or timeout constrains the unchanged zero deadlines. -/
theorem timers (sample : Sample) : (run {0} policy sample).Valid (timerModel E) := by
  refine ⟨trivial, ?_⟩
  intro index step stepped node
  rw [run_stepAt, Option.some.injEq] at stepped
  subst step
  exact ⟨fun reset => False.elim (no_resets index node reset), fun _ => rfl,
    fun timeout => False.elim (no_timeouts true index node timeout)⟩

/-- Infinitely many idle steps advance the clock without bound. -/
theorem diverges (sample : Sample) : TimeDiverges (run {0} policy sample) := by
  intro bound
  obtain ⟨index, large⟩ := exists_nat_ge bound
  refine ⟨index + 1, lift (fixtureWorld true (index + 1)),
    run_stateAt sample (index + 1), ?_⟩
  change bound <= ((index + 1 - 1 : Nat) : Real)
  simpa using large

private theorem cannot_start (index : Nat)
    : Not (canStartElection (fixtureNode true index) 0) := by
  cases index <;> simp only [fixtureNode] <;> decide +kernel

/-- The only participant is always primary, hence never due to time out. -/
theorem firing (sample : Sample)
    : forall node,
        node ∈ ({0} : Finset NodeID)
        -> Scheduled (run {0} policy sample) (some 0) (fun point => TimeoutDue point node)
            (fun step => step.action = .local node (.timeout .election)) := by
  intro node member
  rw [Finset.mem_singleton.mp member]
  intro index point found due
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  obtain ⟨_, _, state, nodeFound, can⟩ := due
  change some (fixtureNode true index) = some state at nodeFound
  have same := Option.some.inj nodeFound
  subst state
  exact False.elim (cannot_start index can)

/-- No exceptional overshoot steps are needed, for any budget or jump bound. -/
theorem overshoot (sample : Sample) (start : Nat) (duration : Real) (N : Nat)
    (jump : Real)
    : exists bad : Finset Nat,
        bad.card <= N
        /\ forall index step node,
            node ∈ ({0} : Finset NodeID)
            -> Within (run {0} policy sample) start duration index
            -> (run {0} policy sample).stepAt index = some step
            -> NoOvershoot (some (if index ∈ bad then jump else 0)) step node := by
  refine ⟨∅, by simp, ?_⟩
  intro index step node member _ stepped
  rw [run_stepAt, Option.some.injEq] at stepped
  subst step
  rw [Finset.mem_singleton.mp member]
  change NoOvershoot (some 0) (liftStep (fixtureStep true index)) 0
  intro _ ⟨state, nodeFound, can⟩
  change some (fixtureNode true index) = some state at nodeFound
  have same := Option.some.inj nodeFound
  subst state
  exact False.elim (cannot_start index can)

/-- Every window is a good period for the sole participant. -/
theorem good_period (sample : Sample) (start : Nat) (duration : Real)
    : GoodPeriod (run {0} policy sample) start duration {0} := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro index point node _ found member
    rw [run_stateAt, Option.some.injEq] at found
    subst point
    exact member
  · intro index point node state _ found member nodeFound
    rw [run_stateAt, Option.some.injEq] at found
    subst point
    have zero : node = 0 := Finset.mem_singleton.mp member
    subst node
    change some (fixtureNode true index) = some state at nodeFound
    have same := Option.some.inj nodeFound
    subst state
    change hasQuorum (fixtureNode true index).activeConfigurations
      (Inter.inter ({0} : Finset NodeID) {0})
    cases index <;> simp only [fixtureNode] <;> decide +kernel
  · intro index step node entries _ stepped append entry member
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    cases index with
    | zero =>
        simp [liftStep, fixtureStep] at append
        obtain ⟨_, rfl⟩ := append
        revert entry
        decide +kernel
    | succ index => simp [liftStep, fixtureStep] at append
  · intro index step node _ stepped nominate
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [liftStep, fixtureStep] at nominate
  · intro index step node _ stepped _ check
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [liftStep, fixtureStep] at check
  · intro index step packet _ stepped dropped
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [liftStep, fixtureStep] at dropped
  · intro index step envelope _ stepped delivered
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [liftStep, fixtureStep, Event.delivered] at delivered

/-- There are no deliveries whose logs need to match. -/
theorem matching (sample : Sample) (start : Nat) (duration : Real)
    : Window.Matching (run {0} policy sample) start duration {0} := by
  intro index step packet _ _ _ stepped delivered
  rw [run_stepAt, Option.some.injEq] at stepped
  subst step
  exact False.elim (no_deliveries true index packet delivered)

/-- The sole participant never retires. -/
theorem anchor_active (sample : Sample) (start : Nat) (duration : Real)
    : Window.AnchorActive (run {0} policy sample) start duration {0} := by
  intro index point node state _ found member nodeFound
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  rw [Finset.mem_singleton.mp member] at nodeFound ⊢
  change some (fixtureNode true index) = some state at nodeFound
  have same := Option.some.inj nodeFound
  subst state
  cases index <;> simp only [fixtureNode] <;> decide +kernel

/-- All countable configurations after the first append have membership `{0}`. -/
theorem membership_one (sample : Sample)
    : forall point,
        (run {0} policy sample).stateAt 1 = some point
        -> Membership {0} {0} (proto point) := by
  intro point found
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  change Membership {0} {0} { nodes := [(0, requestedNode true)] }
  intro node local_ member _
  simp only [List.mem_singleton, Prod.mk.injEq] at member
  obtain ⟨_, rfl⟩ := member
  refine ⟨?_, fun holder held member' _ => ?_, fun envelope _ member' => ?_⟩
  · decide +kernel
  · simp only [List.mem_singleton, Prod.mk.injEq] at member'
    obtain ⟨_, rfl⟩ := member'
    intro configuration history _
    revert configuration
    decide +kernel
  · simp at member'

/-- The first append commits the configuration, which stays committed thereafter. -/
theorem configuration_committed_succ (sample : Sample) (index : Nat)
    : forall point,
        (run {0} policy sample).stateAt (index + 1) = some point
        -> ConfigurationCommitted {0} (proto point) := by
  intro point found
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  change ConfigurationCommitted {0} { nodes := [(0, requestedNode true)] }
  intro node local_ member _
  simp only [List.mem_singleton, Prod.mk.injEq] at member
  obtain ⟨_, rfl⟩ := member
  exact ⟨{ index := 1, nodes := {0} }, by decide +kernel, by decide +kernel⟩

/-- The configuration is committed at the window's start. -/
theorem configured_one (sample : Sample)
    : forall point,
        (run {0} policy sample).stateAt 1 = some point
        -> ConfigurationCommitted {0} (proto point) :=
  configuration_committed_succ sample 0

/-- Every recorded participant has a role throughout the execution. -/
theorem has_role (sample : Sample) (index : Nat)
    : forall point,
        (run {0} policy sample).stateAt index = some point
        -> forall node local_,
            (node, local_) ∈ (proto point).nodes
            -> node ∈ ({0} : Finset NodeID)
            -> Not (local_.role = .none) := by
  intro point found node local_ member _
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  change (node, local_) ∈ [(0, fixtureNode true index)] at member
  simp only [List.mem_singleton, Prod.mk.injEq] at member
  obtain ⟨_, rfl⟩ := member
  cases index <;> simp only [fixtureNode] <;> decide +kernel

/-- The primary anchors the configured window with arbitrarily long freshness. -/
theorem anchored_start_one (sample : Sample) (fresh : Real)
    : AnchoredStart (run {0} policy sample) 1 0 Model.BOOTSTRAP_TERM {0} {0} fresh := by
  refine ⟨
    ⟨
      lift (fixtureWorld true 1),
      run_stateAt sample 1,
      ?_,
      ?_,
      ?_,
      (membership_one sample _ (run_stateAt sample 1)).blocks (by decide)
    ⟩,
    ?_
  ⟩
  · change QuietTerm {0} 0 Model.BOOTSTRAP_TERM { nodes := [(0, requestedNode true)] }
    refine ⟨?_, ?_, requestedNode true, by simp, by decide +kernel, by decide +kernel⟩
    · intro node local_ member _
      simp only [List.mem_singleton, Prod.mk.injEq] at member
      obtain ⟨_, rfl⟩ := member
      decide +kernel
    · intro envelope member
      simp at member
  · intro packet member
    simp [HasNetwork.pending, lift, fixtureWorld] at member
  · change Anchor {0} {0} 0 Model.BOOTSTRAP_TERM { nodes := [(0, requestedNode true)] }
    refine ⟨subset_refl _, Finset.mem_singleton_self 0, ?_, ?_, ?_, ?_, ?_⟩
    · intro local_ member
      simp only [List.mem_singleton, Prod.mk.injEq, true_and] at member
      subst local_
      decide +kernel
    · intro _ _ node member different
      exact absurd (Finset.mem_singleton.mp member) different
    · intro node member
      rw [Finset.mem_singleton.mp member]
      exact ⟨requestedNode true, by simp, by decide +kernel, by decide +kernel,
        Or.inr (by decide +kernel)⟩
    · intro envelope member
      simp at member
    · intro node local_ member _ role
      simp only [List.mem_singleton, Prod.mk.injEq] at member
      obtain ⟨_, rfl⟩ := member
      exact absurd role (by decide +kernel)
  · intro _ index step node _ _ _ stepped timeout
    rw [run_stepAt, Option.some.injEq] at stepped
    subst step
    exact False.elim (no_timeouts true index node timeout)

/-- The handoff is already present at index one, for every freshness and bound. -/
theorem handoff_one (sample : Sample) (fresh bound : Real) (nonnegative : 0 <= bound)
    : HandoffBy (run {0} policy sample) {0} 1 bound fresh :=
  ⟨
    1,
    0,
    Model.BOOTSTRAP_TERM,
    {0},
    lift (fixtureWorld true 1),
    lift (fixtureWorld true 1),
    le_rfl,
    run_stateAt sample 1,
    run_stateAt sample 1,
    le_add_of_nonneg_right nonnegative,
    anchored_start_one sample fresh
  ⟩

/-- With no replication peers, every heartbeat interval is sufficient. -/
theorem heartbeats (sample : Sample) (interval : Real)
    : (run {0} policy sample).HeartbeatScheduling (some interval) := by
  intro leader peer index point found due
  rw [run_stateAt, Option.some.injEq] at found
  subst point
  obtain ⟨leaderLive, peerLive, _, _, _, _, eligible⟩ := due
  have leaderZero : leader = 0 := Finset.mem_singleton.mp leaderLive
  have peerZero : peer = 0 := Finset.mem_singleton.mp peerLive
  subst leader peer
  simp [eligiblePeers] at eligible

end CCFRaft.Proofs.Duel.Witness
