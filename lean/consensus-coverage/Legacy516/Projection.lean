module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FullProfile
public import ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.PairWitnesses
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.CrossCheck
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.Projection

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open FullProfile

public def project (p : Profile) : FrontierRows.Row :=
  ⟨p (.pre .committed_logs_comparable_left_backed_inl), p (.pre .committed_logs_comparable_left_backed_inr),
   p (.step .leader_led_leader_inr), p (.post .committed_logs_comparable_left_backed_inl),
   p (.post .committed_logs_comparable_left_backed_inr)⟩

private theorem run_folded {cfg ns s past} (run : StateCoverage.Run cfg ns s past) :
    Folded cfg ns (@StateCoverage.frame ⟨cfg⟩ s past) := by
  induction run with
  | initial init => exact .initial init
  | step prior step ih =>
    apply Folded.step ih
    rwa [show ∀ x h, current (@StateCoverage.frame ⟨cfg⟩ x h) = x from
      fun x h => @StateCoverage.frame_current ⟨cfg⟩ x h]

private theorem Folded.history {cfg ns f} (folded : Folded cfg ns f) :
    ∃ s past, StateCoverage.Run cfg ns s past ∧ @StateCoverage.frame ⟨cfg⟩ s past = f := by
  induction folded with
  | initial h => exact ⟨_, [], .initial h, rfl⟩
  | step _ stepped ih =>
    obtain ⟨s, past, run, rfl⟩ := ih
    change (transitionSystem _ _).step (@StateCoverage.frame ⟨cfg⟩ s past).current _ = _ at stepped
    rw [@StateCoverage.frame_current ⟨cfg⟩ s past] at stepped
    exact ⟨_, s :: past, .step run stepped, rfl⟩

private theorem row_eq {r u : FrontierRows.Row}
    (a : r.zeroBefore = u.zeroBefore) (b : r.backedBefore = u.backedBefore)
    (c : r.wonPrimary = u.wonPrimary) (d : r.zeroAfter = u.zeroAfter)
    (e : r.backedAfter = u.backedAfter) : r = u := by
  cases r; cases u; congr

private theorem project_frame {cfg ns s t past act} (run : StateCoverage.Run cfg ns s past)
    (step : (transitionSystem cfg ns).step s act = some t) :
    project (frameProfile cfg (@StateCoverage.frame ⟨cfg⟩ s past) t) =
      FrontierRows.historyLabel cfg s t past := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨a, b, c, d, e⟩ := FrontierRows.generated_iff run step
  apply row_eq <;> apply Bool.eq_iff_iff.mpr
  all_goals first
    | exact (frameProfile_true ..).trans a.symm
    | exact (frameProfile_true ..).trans b.symm
    | exact (frameProfile_true ..).trans c.symm
    | exact (frameProfile_true ..).trans d.symm
    | exact (frameProfile_true ..).trans e.symm

/-- The nine rows are exactly the image of the full observations. Only whole
profiles supported by one compatible run are projected. -/
public theorem exact_image (r : FrontierRows.Row) :
    r ∈ FrontierRows.table ↔ ∃ s t p, p ∈ observe s t ∧ project p = r := by
  rw [FrontierRows.ghost_exact]
  constructor
  · rintro ⟨cfg, ns, s, t, past, act, run, step, rfl⟩
    let f := @StateCoverage.frame ⟨cfg⟩ s past
    exact ⟨s, t, frameProfile cfg f t,
      ⟨cfg, ns, f, act, run_folded run, @StateCoverage.frame_current ⟨cfg⟩ s past, step, rfl⟩,
      project_frame run step⟩
  · rintro ⟨s, t, p, ⟨cfg, ns, f, act, folded, currentEq, step, rfl⟩, rfl⟩
    obtain ⟨x, past, run, rfl⟩ := Folded.history folded
    have same := (@StateCoverage.frame_current ⟨cfg⟩ x past).symm.trans currentEq
    rw [← same] at step
    exact ⟨cfg, ns, x, t, past, act, run, step, (project_frame run step).symm⟩

private theorem no_primary_question (cfg : FullProfile.Configuration) (f : ProofFrame) :
    ¬ questionHolds cfg f CrossCheck.s1 (.step .leader_led_now_after_inl) := by
  rintro ⟨_, _, _, ⟨_, n, st, now, role, _⟩, _⟩
  have : (n, st) ∈ CrossCheck.s1.nodes.filter (fun p => p.2.role == .primary) :=
    List.mem_filter.mpr ⟨now, by simp [role]⟩
  simp [CrossCheck.s1_primaries] at this

/-- Sending entries and stepping down from the same initial state have the same
projected row. Their full observations differ, regardless of how the hidden frame
is chosen on the step-down side. -/
public theorem strict : ∃ cfg ns s t u past a b,
    StateCoverage.Run cfg ns s past ∧ (transitionSystem cfg ns).step s a = some t ∧
    (transitionSystem cfg ns).step s b = some u ∧
    FrontierRows.historyLabel cfg s t past = FrontierRows.historyLabel cfg s u past ∧
    observe s t ≠ observe s u := by
  open CrossCheck in
    refine ⟨config, [0,1,2], s0, s2, s1, [], a2, .local 0 (.timeout .checkQuorum),
      .initial initialized, s2_step, rfl, ?_, ?_⟩
    · decide +kernel
    · let f := startFrame config s0
      let p := frameProfile config f s2
      have member : p ∈ observe s0 s2 := ⟨config, [0,1,2], f, a2, .initial initialized, rfl, s2_step, rfl⟩
      have yes : p (.step .leader_led_now_after_inl) = true :=
        (frameProfile_true ..).mpr leader_led_now_after_inl_s2
      intro eq
      rw [eq] at member
      obtain ⟨cfg, _, frame, _, _, _, _, bits⟩ := mem_observe_iff.mp member
      exact no_primary_question cfg frame ((bits _).mp yes)

private abbrev EndpointKey := Bool × Bool × Bool

private noncomputable def endpointKey (o : FullProfile.Observation) : EndpointKey :=
  open Classical in
  if h : ∃ p, p ∈ o then (project h.choose).pair else (false, false, false)

private theorem endpointKey_eq {s t : Model.State} (h : IsReachableStep s t) :
    endpointKey (observe s t) = PairQuestions.label s t := by
  classical
  have someProfile := observe_nonempty_iff.mpr h
  unfold endpointKey
  rw [dite_eq_left someProfile]
  obtain ⟨cfg, ns, f, act, folded, curr, step, eq⟩ := someProfile.choose_spec
  obtain ⟨x, past, run, rfl⟩ := Folded.history folded
  have same := (@StateCoverage.frame_current ⟨cfg⟩ x past).symm.trans curr
  rw [← same] at step
  rw [← eq, project_frame run step, FrontierRows.historyLabel_pair, same]

/-- This lower bound counts *different sets of compatible profiles*, not profiles
within a set. Five endpoint keys are reachable. Removing one of the two distinct
observations in `strict` still leaves every endpoint key represented. -/
public theorem full_lower_bound {rows : List FullProfile.Observation} (h : ExactTable rows) :
    6 ≤ rows.length := by
  classical
  obtain ⟨cfg, ns, s, t, u, past, a, b, run, left, right, same, diff⟩ := strict
  have reach := (run_folded run).reachable
  rw [show ∀ x h, current (@StateCoverage.frame ⟨cfg⟩ x h) = x from
    fun x h => @StateCoverage.frame_current ⟨cfg⟩ x h] at reach
  have lt : IsReachableStep s t := ⟨cfg, ns, a, reach, left⟩
  have rt : IsReachableStep s u := ⟨cfg, ns, b, reach, right⟩
  have inL := h.complete ⟨(s, t), lt⟩
  have inR := h.complete ⟨(s, u), rt⟩
  change observe s t ∈ rows at inL
  change observe s u ∈ rows at inR
  have eqKey : endpointKey (observe s t) = endpointKey (observe s u) := by
    rw [endpointKey_eq lt, endpointKey_eq rt]
    exact congrArg FrontierRows.Row.pair same
  have sub : PairQuestions.table ⊆ (rows.erase (observe s t)).map endpointKey := by
    intro r mem
    obtain ⟨c, nodes, x, y, act, reachable, ran, rfl⟩ := (PairQuestions.exact _).mp mem
    have stepped : IsReachableStep x y := ⟨c, nodes, act, reachable, ran⟩
    have eq := endpointKey_eq stepped
    by_cases collision : observe x y = observe s t
    · rw [collision, eqKey] at eq
      exact List.mem_map.mpr ⟨_, (List.mem_erase_of_ne (Ne.symm diff)).mpr inR, eq⟩
    · exact List.mem_map.mpr ⟨_, (List.mem_erase_of_ne collision).mpr (h.complete ⟨(x, y), stepped⟩), eq⟩
  have bound := (show PairQuestions.table.Nodup by decide).length_le_of_subset sub
  rw [List.length_map, List.length_erase_of_mem inL] at bound
  change 5 ≤ rows.length - 1 at bound
  omega

end ConsensusCoverage.Projection
