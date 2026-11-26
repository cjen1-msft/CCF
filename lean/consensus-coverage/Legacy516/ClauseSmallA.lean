module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseSmallA

open ActionProfile ClauseQuestions ClauseExactTables

public abbrev nonTrunk := ClauseMatchAck.nonTrunk

public noncomputable def nonTrunkLabel (c : Clause) (s : Step) : RestrictedProfile :=
  restrictedLabel (nonTrunk c) s

def readRow (qs : List Classes.StepBranch) (s : Step) : RestrictedProfile :=
  ⟨(endpoints s).1, qs.map (fun b =>
    (ReadersTotal.read s.cfg s.before s.act s.after s.past b).getD false), (endpoints s).2⟩

theorem readRow_eq (qs : List Classes.StepBranch)
    (covered : ∀ b ∈ qs, b ∈ ReadersTotal.covered) (s : Step) :
    readRow qs s = restrictedLabel qs s := by
  unfold readRow restrictedLabel
  congr 1
  apply List.map_congr_left
  intro b hb
  rw [ReadersTotal.read_total s (covered b hb), Option.getD_some]

theorem sampled (qs : List Classes.StepBranch)
    (covered : ∀ b ∈ qs, b ∈ ReadersTotal.covered) (steps : List Step) (rows : List RestrictedProfile)
    (checked : rows.all (steps.map (readRow qs)).contains = true) {r : RestrictedProfile}
    (mem : r ∈ rows) : ∃ s : Step, restrictedLabel qs s = r := by
  obtain ⟨s, _, eq⟩ := List.mem_map.mp
    (List.contains_iff_mem.mp (List.all_eq_true.mp checked r mem))
  exact ⟨s, (readRow_eq qs covered s).symm.trans eq⟩

theorem patterns_exact {c : Clause} {rows : List RestrictedProfile}
    (upper : ∀ s : Step, nonTrunkLabel c s ∈ rows)
    (lower : ∀ r ∈ rows, ∃ s : Step, nonTrunkLabel c s = r) (p : List Bool) :
    p ∈ (rows.map RestrictedProfile.bits).eraseDups ↔
      ∃ s : Step, (nonTrunkLabel c s).bits = p := by
  simp only [List.mem_eraseDups, List.mem_map]
  constructor
  · rintro ⟨r, hr, rfl⟩
    obtain ⟨s, eq⟩ := lower r hr
    exact ⟨s, congrArg RestrictedProfile.bits eq⟩
  · rintro ⟨s, rfl⟩
    exact ⟨_, upper s, rfl⟩

end ConsensusCoverage.ClauseSmallA
