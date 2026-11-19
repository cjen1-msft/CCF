module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.BackingRead

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile CommitKeys

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def hits (bootstrap : NodeID) (after : Model.State) (history : List Model.State)
    (old : List Key) (support : NodeState → Nat → Bool) : Bool :=
  (here bootstrap after history support).any fun key => !old.contains key

/-- Two independent answers. A certificate at base zero can also use an
older prefix: the right arm does not require the base to be positive. -/
@[expose] public def read (bootstrap : NodeID) (after : Model.State) (history : List Model.State) :
    Bool × Bool :=
  let old := keys bootstrap history
  let hit := hits bootstrap after history old
  (hit (fun _ b => decide (b = 0)), hit (prior old))

private theorem step_at (s : Step) (n st k b i) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Historical.CommitStep (s.after :: s.before :: s.past) n st k b i ↔
      CommitStep (s.frame.advance s.after) n st k b i := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let hist := s.after :: s.before :: s.past
  change _ ↔ (StateCoverage.frame s.after (s.before :: s.past)).logs.commitAt _ s.after n st k b i
  rw [StateCoverage.frame_logs]
  symm
  apply Historical.commitAt_iff _ (Historical.logFacts_correct hist).seen
  intro n st k
  simp only [LogFacts.Ghost.canonNow, LogFacts.Ghost.led, Historical.CanonNow, Historical.Led,
    Historical.Now, (Historical.logFacts_correct hist).elected]
  rfl

private theorem hits_iff (s : Step) (support : NodeState → Nat → Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    hits Config.INITIAL_PRIMARY s.after (s.before :: s.past)
      (keys Config.INITIAL_PRIMARY (s.before :: s.past)) support = true ↔
      ∃ n st k b i, CommitStep (s.frame.advance s.after) n st k b i ∧
        ¬Committed s.frame k (st.log.take i) ∧ support st b = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [hits, List.any_eq_true, Prod.exists, mem_here, step_at s, Bool.not_eq_true',
    Bool.eq_false_iff]
  constructor
  · rintro ⟨k, _, ⟨n, st, b, i, step, rfl, back⟩, fresh⟩
    exact ⟨n, st, k, b, i, step, fun h => fresh (List.contains_iff_mem.mpr ((step_mem s ..).mpr h)), back⟩
  · rintro ⟨n, st, k, b, i, step, fresh, back⟩
    exact ⟨k, _, ⟨n, st, b, i, step, rfl, back⟩,
      fun h => fresh ((step_mem s ..).mp (List.contains_iff_mem.mp h))⟩

private theorem zero_spec (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    (read Config.INITIAL_PRIMARY s.after (s.before :: s.past)).1 = true ↔
      ∃ n st k i, CommitStep (s.frame.advance s.after) n st k 0 i ∧
        ¬Committed s.frame k (st.log.take i) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change hits _ _ _ _ _ = true ↔ _
  rw [hits_iff s]
  simp only [decide_eq_true_eq]
  constructor
  · rintro ⟨n, st, k, _, i, step, fresh, rfl⟩
    exact ⟨n, st, k, i, step, fresh⟩
  · rintro ⟨n, st, k, i, step, fresh⟩
    exact ⟨n, st, k, 0, i, step, fresh, rfl⟩

private theorem prior_spec (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    (read Config.INITIAL_PRIMARY s.after (s.before :: s.past)).2 = true ↔
      ∃ n st k b i, CommitStep (s.frame.advance s.after) n st k b i ∧
        ¬Committed s.frame k (st.log.take i) ∧
        ∃ e p, Committed s.frame e p ∧ e ≤ k ∧ st.log.take b <+: p := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change hits _ _ _ _ _ = true ↔ _
  rw [hits_iff s]
  simp only [prior, List.any_eq_true, Prod.exists, decide_eq_true_eq]
  constructor <;> rintro ⟨n, st, k, b, i, step, fresh, e, p, old, le, sub⟩
  · exact ⟨n, st, k, b, i, step, fresh, e, p, (step_mem s ..).mp old, step.1.2.1 ▸ le, sub⟩
  · exact ⟨n, st, k, b, i, step, fresh, e, p, (step_mem s ..).mpr old, step.1.2.1.symm ▸ le, sub⟩

public theorem zero_answer (s : Step) :
    (read (s.cfg.min?.getD 0) s.after (s.before :: s.past)).1 =
      label s (.step .commitChains_step_backing_inl) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact Bool.eq_iff_iff.mpr (((zero_spec s).trans (BackingArms.zero_iff s.context).symm).trans
    (label_true s (.step .commitChains_step_backing_inl)).symm)

public theorem prior_answer (s : Step) :
    (read (s.cfg.min?.getD 0) s.after (s.before :: s.past)).2 =
      label s (.step .commitChains_step_backing_inr) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact Bool.eq_iff_iff.mpr (((prior_spec s).trans (BackingArms.prior_iff s.context).symm).trans
    (label_true s (.step .commitChains_step_backing_inr)).symm)

/-- The two tests refine the old fresh-commit bit: at least one, but not
necessarily just one, is true whenever this action establishes a key. -/
public theorem any_eq (s : Step) :
    let reasons := read (s.cfg.min?.getD 0) s.after (s.before :: s.past)
    (reasons.1 || reasons.2) = !noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  dsimp only
  apply Bool.eq_iff_iff.mpr
  rw [Bool.or_eq_true, fresh_answer, label_true]
  change _ ↔ PinnedClasses.sig s.context .commitChains_step_committed_inr
  rw [fresh_iff]
  constructor
  · rintro (zero | prior)
    · obtain ⟨n, st, k, i, step, fresh⟩ := (zero_spec s).mp zero
      exact ⟨k, _, .inr ⟨n, st, 0, i, step, rfl, .inl rfl⟩, fresh⟩
    · obtain ⟨n, st, k, b, i, step, fresh, back⟩ := (prior_spec s).mp prior
      exact ⟨k, _, .inr ⟨n, st, b, i, step, rfl, .inr back⟩, fresh⟩
  · rintro ⟨k, p, old | ⟨n, st, b, i, step, rfl, back⟩, fresh⟩
    · exact (fresh old).elim
    · rcases back with rfl | prior
      · exact .inl ((zero_spec s).mpr ⟨n, st, k, i, step, fresh⟩)
      · exact .inr ((prior_spec s).mpr ⟨n, st, k, b, i, step, fresh, prior⟩)

end ConsensusCoverage.BackingRead
