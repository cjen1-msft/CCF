module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseSmallBGrantFacts
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseRankRead
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseSmallB.GrantProjection

open ActionProfile ClauseQuestions

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

private def indices : List Nat := [0,1,3,4,5,6,7,8,9,10,11,12,18,19,20,21,22,23]

public def project (bs : List Bool) : List Bool := indices.map fun i => bs[i]?.getD false

private def readBit (s : Step) (q : Classes.StepBranch) : Bool :=
  if q = .rankAtGrant_persist_inl then ClauseRankRead.retained s
  else (ReadersTotal.read s.cfg s.before s.act s.after s.past q).getD false

private def readProjected (s : Step) : List Bool :=
  indices.map fun i => ((nonTrunk .grantFacts)[i]?.map (readBit s)).getD false

private theorem readProjected_eq (s : Step) :
    readProjected s = project (nonTrunkLabel .grantFacts s).bits := by
  unfold readProjected project nonTrunkLabel restrictedLabel
  simp only
  apply List.map_congr_left
  intro i _
  rw [List.getElem?_map]
  cases h : (nonTrunk .grantFacts)[i]? with
  | none => rfl
  | some q =>
    change readBit s q = label s (.step q)
    unfold readBit
    split
    · subst q
      exact (ClauseRankRead.retained_eq s).symm
    · have covered := covered_of_check (c := .grantFacts) (by decide +kernel)
      rw [ReadersTotal.read_total s (covered q (List.mem_of_getElem? h)), Option.getD_some]

private def dropStars (str : String) : List Bool :=
  (str.toList.filter (· != '*')).map (· == '1')

private def picks : List (String × Nat × Nat) :=
  [("00*0000000000*****000000",2,4), ("00*0001100000*****000011",0,0),
    ("00*1011100000*****000011",3,5), ("00*1011111101*****011011",4,11),
    ("00*1011111101*****011111",22,15), ("00*1011111111*****011111",181,19),
    ("00*1101100000*****011011",102,13), ("00*1101111101*****011011",3,4),
    ("00*1101111101*****011111",22,12), ("00*1101111111*****011111",179,16),
    ("00*1111110101*****011011",3,6), ("00*1111110101*****011111",28,11),
    ("00*1111110111*****011111",181,20), ("00*1111111111*****011111",179,18)]

public def patterns : List (List Bool) := picks.map fun (text, _, _) => dropStars text

public theorem count : patterns.Nodup ∧ patterns.length = 14 := by decide +kernel

private def check (pick : String × Nat × Nat) : Bool :=
  let (text, i, j) := pick
  decide ((ReadersCorpus.stepAt i j).map readProjected = some (dropStars text))

private theorem checked : picks.all check = true :=
  all_split 7 (by decide +kernel) (by decide +kernel)

public theorem lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s : Step, project (nonTrunkLabel .grantFacts s).bits = bs := by
  obtain ⟨⟨text, i, j⟩, found, rfl⟩ := List.mem_map.mp mem
  have yes : (ReadersCorpus.stepAt i j).map readProjected = some (dropStars text) :=
    of_decide_eq_true (List.all_eq_true.mp checked _ found)
  obtain ⟨s, _, eq⟩ := Option.map_eq_some_iff.mp yes
  exact ⟨s, (readProjected_eq s).symm.trans eq⟩

private def novel {α : Type} (known : List α) (view : α → List Bool) : List (List Bool) :=
  patterns.filter fun bits => !(known.map view).contains bits

private theorem split_count {α : Type} (keep : α → Bool) (table : List α) :
    (table.filter keep).length + (table.filter fun a => !keep a).length = table.length := by
  induction table with
  | nil => rfl
  | cons a rest ih =>
    cases h : keep a <;> simp_all <;> omega

private theorem combined {α : Type} [DecidableEq α] (known table : List α) (view : α → List Bool)
    (distinct : known.Nodup) (included : known ⊆ table)
    (covered : ∀ bits ∈ patterns, ∃ x ∈ table, view x = bits) :
    known.length + (novel known view).length ≤ table.length := by
  have previous := distinct.length_le_of_subset (l₂ := table.filter known.contains)
    (fun a mem => List.mem_filter.mpr ⟨included mem, List.contains_iff_mem.mpr mem⟩)
  have unique : (novel known view).Nodup :=
    List.Pairwise.sublist List.filter_sublist count.1
  have extra : (novel known view).length ≤
      ((table.filter fun a => !(known.contains a)).map view).length := by
    apply unique.length_le_of_subset
    intro bs mem
    obtain ⟨seen, new⟩ := List.mem_filter.mp mem
    obtain ⟨x, belongs, eq⟩ := covered bs seen
    have notKnown : ¬ x ∈ known := by
      intro old
      have inView := List.contains_iff_mem.mpr (List.mem_map.mpr ⟨x, old, eq⟩)
      rw [inView] at new
      exact Bool.noConfusion new
    exact List.mem_map.mpr ⟨x, List.mem_filter.mpr ⟨belongs, by simpa using notKnown⟩, eq⟩
  rw [List.length_map] at extra
  rw [← split_count known.contains table]
  omega

/-- Eight witnessed projections are absent from the explicit eight-pattern table. -/
public theorem full_lower_bound (table : List (List Bool))
    (covers : ∀ s : Step, (nonTrunkLabel .grantFacts s).bits ∈ table) : 16 ≤ table.length := by
  have countNew : GrantFacts.patterns.length + (novel GrantFacts.patterns project).length = 16 := by
    decide +kernel
  rw [← countNew]
  apply combined GrantFacts.patterns table project GrantFacts.counts.2.2.1
  · intro bs mem
    obtain ⟨s, eq⟩ := GrantFacts.patterns_lower bs mem
    simpa only [eq] using covers s
  · intro bs mem
    obtain ⟨s, eq⟩ := lower bs mem
    exact ⟨_, covers s, eq⟩

private def viewRow (r : RestrictedProfile) := project r.bits

public theorem full_rows_lower_bound (table : List RestrictedProfile)
    (covers : ∀ s : Step, nonTrunkLabel .grantFacts s ∈ table) : 22 ≤ table.length := by
  have countNew : GrantFacts.rows.length + (novel GrantFacts.rows viewRow).length = 22 := by
    decide +kernel
  rw [← countNew]
  apply combined GrantFacts.rows table viewRow GrantFacts.counts.1
  · intro r mem
    obtain ⟨s, eq⟩ := GrantFacts.lower r mem
    simpa only [eq] using covers s
  · intro bs mem
    obtain ⟨s, eq⟩ := lower bs mem
    exact ⟨_, covers s, eq⟩

end ConsensusCoverage.ClauseSmallB.GrantProjection
