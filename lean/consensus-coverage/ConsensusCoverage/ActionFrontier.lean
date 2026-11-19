module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.PinnedLeader
public import ConsensusCoverage.Projection
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.Projection
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.LeaderEffect

namespace ConsensusCoverage.ActionFrontier

open ActionProfile FullProfile

public theorem frontier_eq (s : Step) :
    Projection.project (label s) = FrontierRows.historyLabel s.cfg s.before s.after s.past := by
  have won := @PinnedLeader.won_iff ⟨s.cfg⟩ _ _ s.context
  rw [s.current_eq] at won
  exact Projection.row_eq
    (congrFun (pre_answers s) .committed_logs_comparable_left_backed_inl)
    (congrFun (pre_answers s) .committed_logs_comparable_left_backed_inr)
    (Bool.eq_iff_iff.mpr ((label_true s _).trans won))
    (congrFun (post_answers s) .committed_logs_comparable_left_backed_inl)
    (congrFun (post_answers s) .committed_logs_comparable_left_backed_inr)

public def project (p : Profile) : FrontierRows.Row × Bool :=
  (Projection.project p, p (.step .leader_led_now_after_inl))

public theorem project_eq (s : Step) : project (label s) =
    (FrontierRows.historyLabel s.cfg s.before s.after s.past, LeaderEffect.changedPrimary s.before s.after) := by
  have changed := @PinnedLeader.changedPrimary_iff ⟨s.cfg⟩ _ _ s.context
  rw [s.current_eq] at changed
  exact Prod.ext (frontier_eq s) (Bool.eq_iff_iff.mpr ((label_true s _).trans changed))

/-- No third independent leader bit: the incumbent branch means change without election. -/
public theorem incumbent_eq (s : Step) :
    label s (.step .leader_led_leader_inl) =
      ((project (label s)).2 && !(project (label s)).1.wonPrimary) := by
  have incumbent := @PinnedLeader.changedIncumbent_iff ⟨s.cfg⟩ _ _ s.context
  rw [s.current_eq] at incumbent
  rw [project_eq]
  exact Bool.eq_iff_iff.mpr ((label_true s _).trans incumbent)

/-- Which of the 457 coordinates this projection promises to distinguish. -/
@[expose] public def selected : Question → Bool
  | .pre _ | .post _ => true
  | .step .leader_led_leader_inr | .step .leader_led_leader_inl
  | .step .leader_led_now_after_inl => true
  | .step _ => false

/-- Equal keys iff all 12 pre-state, three leader-step and 12 post-state
answers agree. The two-bit endpoint encoding and redundant incumbent column
neither add nor lose any distinction on this slice. -/
public theorem same_key {s t : Step} :
    project (label s) = project (label t) ↔
      ∀ q, selected q = true → label s q = label t q := by
  constructor
  · intro eq q sel
    cases q with
    | pre b =>
      have key := congrArg (fun (k : FrontierRows.Row × Bool) => (k.1.zeroBefore, k.1.backedBefore)) eq
      rw [project_eq, project_eq] at key
      change StateCoverage.read _ _ _ = StateCoverage.read _ _ _ at key
      exact congrFun ((pre_answers s).trans ((congrArg ProofContexts.answers key).trans (pre_answers t).symm)) b
    | post b =>
      have key := congrArg (fun (k : FrontierRows.Row × Bool) => (k.1.zeroAfter, k.1.backedAfter)) eq
      rw [project_eq, project_eq] at key
      change StateCoverage.read _ _ _ = StateCoverage.read _ _ _ at key
      exact congrFun ((post_answers s).trans ((congrArg ProofContexts.answers key).trans (post_answers t).symm)) b
    | step b =>
      have won := congrArg (fun (k : FrontierRows.Row × Bool) => k.1.wonPrimary) eq
      have changed := congrArg Prod.snd eq
      have incumbent := (incumbent_eq s).trans (eq ▸ (incumbent_eq t).symm)
      cases b <;> first | exact won | exact changed | exact incumbent | contradiction
  · intro h
    exact Prod.ext (Projection.row_eq (h _ rfl) (h _ rfl) (h _ rfl) (h _ rfl) (h _ rfl)) (h _ rfl)

/-- Reachability of all nine rows also holds for profiles pinned to the recorded action. -/
public theorem exact_frontier (r : FrontierRows.Row) :
    r ∈ FrontierRows.table ↔ ∃ s : Step, Projection.project (label s) = r := by
  rw [FrontierRows.ghost_exact]
  constructor
  · rintro ⟨cfg, ns, s, t, past, a, run, ran, rfl⟩
    exact ⟨⟨cfg, ns, s, past, a, t, run, ran⟩, frontier_eq _⟩
  · rintro ⟨s, rfl⟩
    exact ⟨s.cfg, s.nodes, s.before, s.after, s.past, s.act, s.run, s.ran, (frontier_eq s).symm⟩

end ConsensusCoverage.ActionFrontier
