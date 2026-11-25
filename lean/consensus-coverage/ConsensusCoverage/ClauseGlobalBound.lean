module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ActionFrontier
import all ConsensusCoverage.BoundedWitnesses
import all ConsensusCoverage.CensusWidth
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.HandReadersBSummary
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.MessageWitnesses
import all ConsensusCoverage.Projection
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.ReducedQuestions

namespace ConsensusCoverage.ClauseGlobalBound

open ClauseQuestions FullProfile ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private abbrev old := CensusWidth.keys BoundedWitnesses.keys
private abbrev splitKey := 1855426265091

private def refine (p : Profile) : (Nat × Bool) × Bool :=
  let k := CensusWidth.refineKey p
  (k, k.1 == splitKey && p (.step .summary_input_nominateSuccessor))

private def restored (r : RestrictedProfile) : Profile
  | .pre b => ProofContexts.answers r.pre b
  | .post b => ProofContexts.answers r.post b
  | .step b => ((ReadersTotal.covered.zip r.bits).lookup b).getD false

private theorem step_eq (s : Step) {b : Classes.StepBranch} (mem : b ∈ ReadersTotal.covered) :
    restored (restrictedLabel ReadersTotal.covered s) (.step b) = label s (.step b) := by
  change ((ReadersTotal.covered.zip (ReadersTotal.covered.map fun b => label s (.step b))).lookup b).getD false = _
  rw [CensusWidth.lookup_zip mem, Option.getD_some]

private theorem restore_key (s : Step) :
    refine (restored (restrictedLabel ReadersTotal.covered s)) = refine (label s) := by
  let p := restored (restrictedLabel ReadersTotal.covered s)
  have before (b) : p (.pre b) = label s (.pre b) := (congrFun (pre_answers s) b).symm
  have after (b) : p (.post b) = label s (.post b) := (congrFun (post_answers s) b).symm
  have bit (b) (hb : b ∈ ReadersTotal.covered) : p (.step b) = label s (.step b) := step_eq s hb
  have guarded : ∀ b ∈ GuardedQuestions.covered, b ∈ ReadersTotal.covered := by decide +kernel
  have reduced : ∀ k ∈ ReducedQuestions.columns, k.branch ∈ ReadersTotal.covered := by decide +kernel
  have msg : MessageWitnesses.project p = MessageWitnesses.project (label s) := by
    unfold MessageWitnesses.project ActionFrontier.project Projection.project
    rw [List.map_congr_left (fun k hk => step_eq s (reduced k hk) : ∀ k ∈ ReducedQuestions.columns, _)]
    simp only [before, after, bit .leader_led_leader_inr (by decide +kernel),
      bit .leader_led_now_after_inl (by decide +kernel)]
  have narrow : ExploredWitnesses.project p = ExploredWitnesses.project (label s) := by
    unfold ExploredWitnesses.project JointWitnesses.project
    rw [msg, List.map_congr_left (fun b hb => step_eq s (guarded b hb) : ∀ b ∈ GuardedQuestions.covered, _)]
    rw [bit .commitChains_step_committed_inr (by decide +kernel),
      bit .rooted_now_after_inl (by decide +kernel), bit .commitChains_step_backing_inl (by decide +kernel),
      bit .commitChains_step_backing_inr (by decide +kernel), bit .rooted_post_log_inl (by decide +kernel)]
  have wide : CensusWidth.wide p = CensusWidth.wide (label s) := by
    have incl : ∀ b ∈ CensusWidth.extra, b ∈ ReadersTotal.covered := by decide +kernel
    unfold CensusWidth.wide
    rw [narrow, List.map_congr_left (fun b hb => step_eq s (incl b hb) : ∀ b ∈ CensusWidth.extra, _)]
  change refine p = _
  simp only [refine, ← CensusWidth.reduce_wide, wide, bit .summary_input_nominateSuccessor (by decide +kernel)]

private def keys := old.map (·,false) ++ [((splitKey,false),true)]

private theorem split_hit (v : Bool) : ∃ s : Step, refine (label s) = ((splitKey,false),v) := by
  let pos := if v then (21,7) else (58,2)
  have check : (ReadersCorpus.stepAt pos.1 pos.2).any (fun s =>
      (JointWitnesses.read s).map ExploredWitnesses.encode == some splitKey &&
      HandReadersBSummary.answer s.cfg s.before s.act s.after s.past .nominate == v) = true := by
    cases v <;> decide +kernel
  obtain ⟨s, _, test⟩ := (Option.any_eq_true _ _).mp check
  simp only [Bool.and_eq_true, beq_iff_eq, JointWitnesses.read_eq, Option.map_some,
    Option.some.injEq] at test
  have found : CensusWidth.lookup splitKey = none := by decide +kernel
  have nom := HandReadersBSummary.exact_answer s .nominate
  change label s (.step .summary_input_nominateSuccessor) = _ at nom
  exact ⟨s, by simp [refine, CensusWidth.refineKey, ExploredWitnesses.project, test.1, found,
    nom.trans test.2]⟩

private theorem occurs (k) (hk : k ∈ keys) : ∃ s : Step, refine (label s) = k := by
  rcases List.mem_append.mp hk with base | last
  · obtain ⟨x,hx,rfl⟩ := List.mem_map.mp base
    obtain ⟨s,_,hit⟩ := CensusWidth.occurs (scope := fun _ => True) (fun _ _ => trivial)
      (fun k hk => by obtain ⟨s,e⟩ := BoundedWitnesses.occurs hk; exact ⟨s,trivial,e⟩) hx
    by_cases eq : x.1 = splitKey
    · have h : x = (splitKey,false) := by
        rw [←hit] at eq ⊢
        change ExploredWitnesses.project (label s) = splitKey at eq
        have no : CensusWidth.lookup splitKey = none := by decide +kernel
        simp [CensusWidth.refineKey, eq, no]
      exact h ▸ split_hit false
    · exact ⟨s, by simp [refine, hit, eq]⟩
  · simpa only [List.mem_singleton.mp last] using split_hit true

/-- One unsplit old key has both nomination and backup dispatch witnesses.
The statement counts only the 435 readable bits and the two endpoint keys. -/
public theorem global_lower_bound (rows : List RestrictedProfile)
    (complete : ∀ s : Step, restrictedLabel ReadersTotal.covered s ∈ rows) : 251 ≤ rows.length := by
  have count : keys.length = 251 ∧ keys.Nodup := by decide +kernel
  have sub : keys ⊆ rows.map (fun r => refine (restored r)) := by
    intro k hm
    obtain ⟨s, eq⟩ := occurs k hm
    exact List.mem_map.mpr ⟨_, complete s, (restore_key s).trans eq⟩
  simpa only [←count.1, List.length_map] using count.2.length_le_of_subset sub

end ConsensusCoverage.ClauseGlobalBound
