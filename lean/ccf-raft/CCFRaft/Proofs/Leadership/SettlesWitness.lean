module

public import CCFRaft.Proofs.Leadership.Settles
public import CCFRaft.Proofs.Leadership.InSync
public import CCFRaft.Proofs.Leadership.AnchorSync
public import CCFRaft.Proofs.LivenessWitness

@[expose] public section

/-!
# The stable-window premises are satisfiable

The single-node execution of `Proofs.LivenessWitness` meets every premise of
`Leadership.stable_window`, `Leadership.stable_window_inSync` and
`Leadership.stable_window_anchored`, and hence their conclusion, for every window
length. The anchor of the last is the single node.
The world carries a constant election deadline of zero: the execution has no
deliveries and no election timeouts, so no timer is ever reset and no timeout
needs its deadline to have passed.
-/

namespace CCFRaft.Proofs.Leadership

open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.LivenessWitness
open CCF.MultiNodeTransitionSystem (nodeState)

/-- Every node's election deadline is zero, at every point. -/
@[instance_reducible]
def constantDeadline : HasTimers (World Model.State) where
  deadline _ _ := 0

attribute [local instance] constantDeadline

private theorem timers_valid
    : (fixture true).Valid (timerModel bounds.electionTimeout) := by
  refine ⟨trivial, ?_⟩
  intro index step stepped node
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  refine ⟨fun reset => ?_, fun _ => rfl, fun timeout => ?_⟩
  · cases index <;> simp [ElectionReset, fixtureStep] at reset
  · exact False.elim (no_timeouts true index node timeout)

private theorem bounded_valid (maxDelay : Real)
    : (fixture true).Valid (boundedDelayModel maxDelay) := by
  refine ⟨?_, ?_⟩
  · intro packet member
    change packet ∈ ([] : List Packet) at member
    cases member
  · intro index step stepped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    intro packet member
    change packet ∈ ([] : List Packet) at member
    cases member

private theorem good (duration : Real) : GoodPeriod (fixture true) 0 duration {0} := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro index point node _ found member
    rw [fixture_stateAt, Option.some.injEq] at found
    subst point
    rw [fixture_live]
    exact member
  · intro index point node state _ found _ nodeFound
    rw [fixture_stateAt, Option.some.injEq] at found
    subst point
    have zero : node = 0 := by
      by_contra other
      change nodeState { nodes := [(0, fixtureNode true index)] } node = some state at nodeFound
      simp [nodeState] at nodeFound
      exact other nodeFound.1.symm
    subst node
    change some (fixtureNode true index) = some state at nodeFound
    have same := Option.some.inj nodeFound
    subst state
    cases index <;> simp only [fixtureNode, fixture_live] <;> decide
  · intro index step node entries _ stepped append entry member
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index with
    | zero =>
        simp [fixtureStep] at append
        obtain ⟨_, rfl⟩ := append
        revert entry
        decide +kernel
    | succ index => simp [fixtureStep] at append
  · intro index step node _ stepped nominate
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep] at nominate
  · intro index step node _ stepped _ check
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep] at check
  · intro index step packet _ stepped dropped
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep] at dropped
  · intro index step envelope _ stepped delivered
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    cases index <;> simp [fixtureStep, Event.delivered] at delivered

private theorem window_matching (duration : Real)
    : WindowMatching (fixture true) 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro index step packet _ _ _ stepped deliver
  rw [fixture_stepAt, Option.some.injEq] at stepped
  subst step
  exact False.elim (no_deliveries true index packet deliver)

private theorem in_sync : InSync (fixture true) 0 0 Model.BOOTSTRAP_TERM {0} := by
  intro _ peer _ member different
  exact absurd (Finset.mem_singleton.mp member) different

private theorem latest_members : LatestMembers (fixture true) 0 0 {0} := by
  intro _ _ node _ _ member different
  exact absurd (Finset.mem_singleton.mp member) different

private theorem stays_active (duration : Real)
    : Window.StaysActive (fixture true) 0 duration 0 := by
  refine ⟨?_, ?_⟩
  · intro index point within found
    exact (stable true).live within.1 found
  · intro index point state within found nodeFound
    apply (stable true).notRetired within.1
    rw [Trace.nodeAt_of_stateAt found]
    exact nodeFound

/-- For every nonnegative window length, the premises of `stable_window` and its
conclusion hold together on one admissible execution, with heartbeat interval 1,
election timeout 4 and no message delay. -/
theorem stable_window_witness
    : let bounds : Bounds :=
        { heartbeatInterval := 1, electionTimeout := 4, signatureInterval := 1 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Trace (World Model.State) Liveness.Event,
            (Liveness.Admissible (Model.transitionSystem {0} [0]) trace
              /\ trace.Valid (timerModel bounds.electionTimeout)
              /\ trace.Valid (boundedDelayModel 0)
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ bounds.heartbeatInterval + 0 < bounds.electionTimeout / 2
              /\ 0 ∈ ({0} : Finset NodeID)
              /\ QuietStart trace 0 0 Model.BOOTSTRAP_TERM bounds.electionTimeout
              /\ LatestMembers trace 0 0 {0}
              /\ GoodPeriod trace 0 duration {0}
              /\ Window.StaysActive trace 0 duration 0
              /\ WindowMatching trace 0 duration 0 Model.BOOTSTRAP_TERM {0})
            /\ StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro windowBounds duration _
  have admissible : Liveness.Admissible (Model.transitionSystem {0} [0]) (fixture true) :=
    ⟨coherent true, protocol_valid true, timing_valid true, crash_valid true,
      delivery_valid true⟩
  have ratio : windowBounds.heartbeatInterval + 0 < windowBounds.electionTimeout / 2 := by
    norm_num [windowBounds]
  let _ : Config.InitialConfiguration := ⟨{0}⟩
  refine ⟨fixture true, ⟨admissible, timers_valid, bounded_valid 0, le_rfl,
    heartbeats true _, ratio, Finset.mem_singleton_self 0, quiet_start, latest_members,
    good duration, stays_active duration, window_matching duration⟩, ?_⟩
  exact stable_window (bounds := windowBounds) admissible timers_valid (bounded_valid 0)
    le_rfl (heartbeats true _) ratio (Finset.mem_singleton_self 0) quiet_start
    latest_members (good duration) (stays_active duration) (window_matching duration)

/-- For every nonnegative window length, the premises of `stable_window_inSync`
and its conclusion hold together on one admissible execution, with heartbeat
interval 1, election timeout 4, freshness 2 and no message delay. -/
theorem stable_window_inSync_witness
    : let bounds : Bounds :=
        { heartbeatInterval := 1, electionTimeout := 4, signatureInterval := 1 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Trace (World Model.State) Liveness.Event,
            (Liveness.Admissible (Model.transitionSystem {0} [0]) trace
              /\ trace.Valid (timerModel bounds.electionTimeout)
              /\ trace.Valid (boundedDelayModel 0)
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ bounds.heartbeatInterval + 0 < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ 0 ∈ ({0} : Finset NodeID)
              /\ FreshStart trace 0 0 Model.BOOTSTRAP_TERM {0} 2
              /\ LatestMembers trace 0 0 {0}
              /\ GoodPeriod trace 0 duration {0}
              /\ Window.StaysActive trace 0 duration 0
              /\ InSync trace 0 0 Model.BOOTSTRAP_TERM {0})
            /\ StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro windowBounds duration _
  have admissible : Liveness.Admissible (Model.transitionSystem {0} [0]) (fixture true) :=
    ⟨coherent true, protocol_valid true, timing_valid true, crash_valid true,
      delivery_valid true⟩
  have ratio : windowBounds.heartbeatInterval + 0 < 2 := by norm_num [windowBounds]
  have freshLe : (2 : Real) <= windowBounds.electionTimeout / 2 := by norm_num [windowBounds]
  have fresh : FreshStart (fixture true) 0 0 Model.BOOTSTRAP_TERM {0} 2 := by
    have half : LivenessWitness.bounds.electionTimeout / 2 = (2 : Real) := by
      norm_num [LivenessWitness.bounds]
    have := FreshStart.of_quietStart quiet_start {0}
    rwa [half] at this
  let _ : Config.InitialConfiguration := ⟨{0}⟩
  refine ⟨fixture true, ⟨admissible, timers_valid, bounded_valid 0, le_rfl,
    heartbeats true _, ratio, freshLe, Finset.mem_singleton_self 0, fresh, latest_members,
    good duration, stays_active duration, in_sync⟩, ?_⟩
  exact stable_window_inSync (bounds := windowBounds) admissible timers_valid
    (bounded_valid 0) le_rfl (heartbeats true _) ratio freshLe
    (Finset.mem_singleton_self 0) fresh latest_members (good duration)
    (stays_active duration) in_sync

private theorem anchored_start
    : AnchoredStart (fixture true) 0 0 Model.BOOTSTRAP_TERM {0} {0} 2 := by
  have quiet := (quiet_start.quiet)
  obtain ⟨first, found, quiet⟩ := quiet
  rw [fixture_stateAt, Option.some.injEq] at found
  subst first
  refine ⟨
    ⟨fixtureWorld true 0, fixture_stateAt true 0, (quiet.among {0}).quietTerm, ?_, ?_⟩,
    ?_
  ⟩
  · change Anchor {0} {0} 0 Model.BOOTSTRAP_TERM { nodes := [(0, initialNode)] }
    refine ⟨subset_refl _, Finset.mem_singleton_self 0, ?_, ?_, ?_, ?_, ?_⟩
    · intro local_ member
      simp only [List.mem_singleton, Prod.mk.injEq, true_and] at member
      subst local_
      decide +kernel
    · intro _ _ node member different
      exact absurd (Finset.mem_singleton.mp member) different
    · intro node member
      rw [Finset.mem_singleton.mp member]
      exact ⟨initialNode, by simp, by decide +kernel, by decide +kernel,
        Or.inr (by decide +kernel)⟩
    · intro envelope member
      simp at member
    · intro node local_ member _ role
      simp only [List.mem_singleton, Prod.mk.injEq] at member
      obtain ⟨_, rfl⟩ := member
      exact absurd role (by decide +kernel)
  · change Blocks {0} {0} { nodes := [(0, initialNode)] }
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
  · intro _ index step node _ _ _ stepped timeout
    rw [fixture_stepAt, Option.some.injEq] at stepped
    subst step
    exact False.elim (no_timeouts true index node timeout)

private theorem anchor_active (duration : Real)
    : Window.AnchorActive (fixture true) 0 duration {0} := by
  intro index point node state within found member nodeFound
  rw [Finset.mem_singleton.mp member] at nodeFound ⊢
  exact (stays_active duration).notRetired index point state within found nodeFound

/-- For every nonnegative window length, the premises of `stable_window_anchored`
and its conclusion hold together on one admissible execution, with heartbeat
interval 1, election timeout 4, freshness 2, no message delay, and the single node
as participants and anchor. -/
theorem stable_window_anchored_witness
    : let bounds : Bounds :=
        { heartbeatInterval := 1, electionTimeout := 4, signatureInterval := 1 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Trace (World Model.State) Liveness.Event,
            (Liveness.Admissible (Model.transitionSystem {0} [0]) trace
              /\ trace.Valid (timerModel bounds.electionTimeout)
              /\ trace.Valid (boundedDelayModel 0)
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ bounds.heartbeatInterval + 0 < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ AnchoredStart trace 0 0 Model.BOOTSTRAP_TERM {0} {0} 2
              /\ GoodPeriod trace 0 duration {0}
              /\ Window.AnchorActive trace 0 duration {0}
              /\ InSync trace 0 0 Model.BOOTSTRAP_TERM {0})
            /\ StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
            /\ Window.StableTerm trace 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro windowBounds duration _
  have admissible : Liveness.Admissible (Model.transitionSystem {0} [0]) (fixture true) :=
    ⟨coherent true, protocol_valid true, timing_valid true, crash_valid true,
      delivery_valid true⟩
  have ratio : windowBounds.heartbeatInterval + 0 < 2 := by norm_num [windowBounds]
  have freshLe : (2 : Real) <= windowBounds.electionTimeout / 2 := by norm_num [windowBounds]
  let _ : Config.InitialConfiguration := ⟨{0}⟩
  refine ⟨fixture true, ⟨admissible, timers_valid, bounded_valid 0, le_rfl,
    heartbeats true _, ratio, freshLe, anchored_start, good duration,
    anchor_active duration, in_sync⟩, ?_⟩
  exact stable_window_anchored (bounds := windowBounds) admissible timers_valid
    (bounded_valid 0) le_rfl (heartbeats true _) ratio freshLe anchored_start
    (good duration) (anchor_active duration) in_sync

end CCFRaft.Proofs.Leadership
