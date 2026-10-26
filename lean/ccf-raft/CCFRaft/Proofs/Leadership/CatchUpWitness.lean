module

public import CCFRaft.Proofs.Leadership.CatchUp
public import CCFRaft.Proofs.Leadership.SettlesWitness

@[expose] public section

/-!
# The catch-up window premises are satisfiable

The single-node execution of `Proofs.LivenessWitness` meets every premise of
`Leadership.stable_window_catchup` and `Leadership.stable_window_catchup_anchored`,
and hence their conclusions, for every window length. The fixture lemmas below copy private ones from `SettlesWitness` and
`LivenessWitness`.
-/

namespace CCFRaft.Proofs.Leadership.CatchUpWitness

open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.LivenessWitness
open CCFRaft.Proofs.Leadership
open CCF.MultiNodeTransitionSystem (nodeState)

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

private theorem diverges : TimeDiverges (fixture true) := by
  intro limit
  obtain ⟨index, enough⟩ := exists_nat_ge limit
  refine ⟨index + 1, fixtureWorld true (index + 1), fixture_stateAt true (index + 1), ?_⟩
  change limit <= ((index + 1 - 1 : Nat) : Real)
  simpa using enough

/-- For every nonnegative window length, the premises of `stable_window_catchup`
and its conclusion hold together on one admissible execution, with heartbeat
interval `1 / 10`, election timeout 4, freshness 2, backlog 0 and no message
delay: the repair bound is `3 / 5`, and the gap `7 / 10` is below the freshness. -/
theorem stable_window_catchup_witness
    : let bounds : Bounds :=
        { heartbeatInterval := 1 / 10, electionTimeout := 4, signatureInterval := 1 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Trace (World Model.State) Liveness.Event,
            (Liveness.Admissible {0} [0] trace
              /\ trace.Valid (timerModel bounds.electionTimeout)
              /\ trace.Valid (boundedDelayModel 0)
              /\ TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ repair 0 (max bounds.heartbeatInterval 0) 0
                    + max bounds.heartbeatInterval 0
                    + 0
                  < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ 0 ∈ ({0} : Finset NodeID)
              /\ FreshStart trace 0 0 Model.BOOTSTRAP_TERM {0} 2
              /\ LatestMembers trace 0 0 {0}
              /\ GoodPeriod trace 0 duration {0}
              /\ Window.StaysActive trace 0 duration 0
              /\ InTermAt trace 0 Model.BOOTSTRAP_TERM {0}
              /\ BacklogTerms trace 0 0 {0} 0)
            /\ StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro windowBounds duration _
  have admissible : Liveness.Admissible {0} [0] (fixture true) :=
    ⟨coherent true, protocol_valid true, timing_valid true, crash_valid true,
      delivery_valid true⟩
  have ratio
      : repair 0 (max windowBounds.heartbeatInterval 0) 0
          + max windowBounds.heartbeatInterval 0 + 0 < 2 := by
    norm_num [windowBounds, repair]
  have freshLe : (2 : Real) <= windowBounds.electionTimeout / 2 := by norm_num [windowBounds]
  have fresh : FreshStart (fixture true) 0 0 Model.BOOTSTRAP_TERM {0} 2 := by
    have half : LivenessWitness.bounds.electionTimeout / 2 = (2 : Real) := by
      norm_num [LivenessWitness.bounds]
    have := FreshStart.of_quietStart quiet_start {0}
      (fun found member => by
        rw [fixture_stateAt, Option.some.injEq] at found
        subst found
        cases member)
    rwa [half] at this
  let _ : Config.InitialConfiguration := ⟨{0}⟩
  refine ⟨fixture true, ⟨admissible, timers_valid, bounded_valid 0, diverges, le_rfl,
    heartbeats true _, ratio, freshLe, Finset.mem_singleton_self 0, fresh, latest_members,
    good duration, stays_active duration, initial_in_term, initial_backlog⟩, ?_⟩
  exact stable_window_catchup (bounds := windowBounds) admissible timers_valid
    (bounded_valid 0) diverges le_rfl (heartbeats true _) ratio freshLe
    (Finset.mem_singleton_self 0) fresh latest_members (good duration)
    (stays_active duration) initial_in_term initial_backlog

private theorem anchored_start
    : AnchoredStart (fixture true) 0 0 Model.BOOTSTRAP_TERM {0} {0} 2 := by
  have quiet := (quiet_start.quiet)
  obtain ⟨first, found, quiet⟩ := quiet
  rw [fixture_stateAt, Option.some.injEq] at found
  subst first
  refine ⟨
    ⟨fixtureWorld true 0, fixture_stateAt true 0, (quiet.among {0}).quietTerm,
      (fun _ member => by cases member), ?_, ?_⟩,
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

/-- For every nonnegative window length, the premises of
`stable_window_catchup_anchored` and its conclusion hold together on one admissible
execution, with heartbeat interval `1 / 10`, election timeout 4, freshness 2,
backlog 0, no message delay, and the single node as participants and anchor. -/
theorem stable_window_catchup_anchored_witness
    : let bounds : Bounds :=
        { heartbeatInterval := 1 / 10, electionTimeout := 4, signatureInterval := 1 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Trace (World Model.State) Liveness.Event,
            (Liveness.Admissible {0} [0] trace
              /\ trace.Valid (timerModel bounds.electionTimeout)
              /\ trace.Valid (boundedDelayModel 0)
              /\ TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ repair 0 (max bounds.heartbeatInterval 0) 0
                    + max bounds.heartbeatInterval 0
                    + 0
                  < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ AnchoredStart trace 0 0 Model.BOOTSTRAP_TERM {0} {0} 2
              /\ GoodPeriod trace 0 duration {0}
              /\ Window.AnchorActive trace 0 duration {0}
              /\ BacklogTerms trace 0 0 {0} 0)
            /\ StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
            /\ Window.StableTerm trace 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro windowBounds duration _
  have admissible : Liveness.Admissible {0} [0] (fixture true) :=
    ⟨coherent true, protocol_valid true, timing_valid true, crash_valid true,
      delivery_valid true⟩
  have ratio
      : repair 0 (max windowBounds.heartbeatInterval 0) 0
          + max windowBounds.heartbeatInterval 0 + 0 < 2 := by
    norm_num [windowBounds, repair]
  have freshLe : (2 : Real) <= windowBounds.electionTimeout / 2 := by norm_num [windowBounds]
  let _ : Config.InitialConfiguration := ⟨{0}⟩
  refine ⟨fixture true, ⟨admissible, timers_valid, bounded_valid 0, diverges, le_rfl,
    heartbeats true _, ratio, freshLe, anchored_start, good duration,
    anchor_active duration, initial_backlog⟩, ?_⟩
  exact stable_window_catchup_anchored (bounds := windowBounds) admissible timers_valid
    (bounded_valid 0) diverges le_rfl (heartbeats true _) ratio freshLe anchored_start
    (good duration) (anchor_active duration) initial_backlog

end CCFRaft.Proofs.Leadership.CatchUpWitness
