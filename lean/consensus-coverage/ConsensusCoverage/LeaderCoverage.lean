module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionFrontier
public import ConsensusCoverage.LeaderWitnesses
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.LeaderCoverage

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile LeaderWitnesses

/-- All deployments together: at least fourteen distinct *full* actual-action labels. -/
public theorem full_lower_bound {rows : List FullProfile.Profile} (complete : ∀ s, label s ∈ rows) :
    14 ≤ rows.length := by
  rw [← table_count.2]
  apply projected_lower_bound ActionFrontier.project table_count.1 _ complete
  intro key mem
  obtain ⟨cfg, ns, s, t, past, a, run, ran, rfl⟩ := table_occurs mem
  exact ⟨⟨cfg, ns, s, past, a, t, run, ran⟩, ActionFrontier.project_eq _⟩

public def MultiNode (ns : List NodeID) : Prop := ∃ i ∈ ns, ∃ j ∈ ns, i ≠ j

/-- Without backing, every node is at commit index zero. A step changes only
one node, so a distinct node stays at zero. This uses the deployed node IDs,
not the size of the voting configuration. -/
public theorem unbacked_keeps_zero (s : Step) (multi : MultiNode s.nodes)
    (unbacked : (read s.cfg s.before s.after s.past).1.backedBefore = false) :
    (read s.cfg s.before s.after s.past).1.zeroAfter = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨i, hi, j, hj, ne⟩ := multi
  obtain ⟨id, mem, diff⟩ : ∃ id ∈ s.nodes, id ≠ c.actor := by
    by_cases h : i = c.actor
    · exact ⟨j, hj, fun eq => ne (h.trans eq.symm)⟩
    · exact ⟨i, hi, h⟩
  have keys : s.frame.current.nodes.map Prod.fst = s.nodes := by
    rw [show s.frame.current = s.before from s.current_eq]
    exact NoBackingWitness.run_keys s.run _ List.mem_cons_self
  rw [← keys] at mem
  obtain ⟨⟨node, st⟩, old, rfl⟩ := List.mem_map.mp mem
  have z : st.commitIndex = 0 := by
    obtain ⟨_, zero | ⟨k, part, cert, _⟩⟩ := (c.inv.commit_backed _ st old).1
    · exact zero
    · have yes := (FrontierRows.inr_iff c.inv (List.ne_nil_of_mem old)).mpr ⟨k, part, cert⟩
      have backed := (FrontierRows.generated_iff s.run s.ran).2.1.mpr yes
      exact Bool.noConfusion (unbacked.symm.trans backed)
  apply (PairQuestions.zero_mem s.after).mpr
  refine ⟨node, st, ?_, z⟩
  rw [c.tr.nodesEq]
  exact List.mem_map.mpr ⟨_, old, by simp [diff]⟩

/-- One remaining possible key outside the fourteen witnesses. Any witness
would have to create the first certificate, remove the last zero, and leave
no changed primary. -/
public def remaining : Key := (⟨true, false, false, false, true⟩, false)

private theorem all_cases (key : Key) (frontier : key.1 ∈ FrontierRows.table)
    (won : key.1.wonPrimary = true → key.2 = true) : key ∈ table ∨ key = remaining := by
  rcases key with ⟨⟨a, b, c, d, e⟩, f⟩
  revert a b c d e f
  decide

public theorem upper (s : Step) : ActionFrontier.project (label s) ∈ table ∨
    ActionFrontier.project (label s) = remaining := by
  rw [ActionFrontier.project_eq]
  apply all_cases _ (FrontierRows.complete s.run s.ran)
  have ran := s.ran
  rw [← s.current_eq] at ran
  have win := LeaderEffect.wonPrimary_implies_changedPrimary s.folded ran
  rwa [s.current_eq] at win

public theorem multi_no_leap (s : Step) (multi : MultiNode s.nodes) :
    (ActionFrontier.project (label s)).1.backedBefore = true ∨
    (ActionFrontier.project (label s)).1.zeroAfter = true := by
  rw [ActionFrontier.project_eq]
  cases h : (read s.cfg s.before s.after s.past).1.backedBefore with
  | true => exact .inl h
  | false => exact .inr (unbacked_keeps_zero s multi h)

public def multiTable : List Key := table.filter fun k => k.1.backedBefore || k.1.zeroAfter

public theorem multi_count : multiTable.Nodup ∧ multiTable.length = 13 := by decide

/-- Exact image of the 27 selected proof answers across all initialized
deployments with at least two distinct nodes. No voting-set size is assumed. -/
public theorem multi_exact (key : Key) :
    key ∈ multiTable ↔ ∃ s : Step, MultiNode s.nodes ∧ ActionFrontier.project (label s) = key := by
  constructor
  · intro mem
    obtain ⟨listed, test⟩ := List.mem_filter.mp mem
    have ne : key ≠ soloCommitKey := by rintro rfl; contradiction
    obtain ⟨cfg, ns, s, t, past, a, multi, run, ran, rfl⟩ := table_occurs_multi listed ne
    exact ⟨⟨cfg, ns, s, past, a, t, run, ran⟩, multi, ActionFrontier.project_eq _⟩
  · rintro ⟨s, multi, rfl⟩
    have guard := multi_no_leap s multi
    apply List.mem_filter.mpr
    refine ⟨?_, by simpa only [Bool.or_eq_true] using guard⟩
    rcases upper s with mem | eq
    · exact mem
    · rw [eq] at guard
      rcases guard with h | h <;> contradiction

end ConsensusCoverage.LeaderCoverage
