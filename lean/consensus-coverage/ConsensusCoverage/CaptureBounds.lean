module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.ReplayAnswers

/-! Distinguish full labels within a capture even before all coordinates have
readers. A positive/negative disagreement proves two labels different; a
difference in which questions are unknown does not. -/

namespace ConsensusCoverage.CaptureBounds

open ActionProfile FullProfile

set_option maxRecDepth 8192

public structure Row where
  yes : BitVec questionCount
  no : BitVec questionCount

/-- Evaluate each coordinate once; retain both masks so unknown is not false. -/
public def read (e : ReplayAnswers.Evidence) : Row :=
  let a := questions.map (ReplayAnswers.answer e)
  let atSlot := fun i : Fin questionCount => a[i.val]'(by simp [a, questions_size])
  ⟨encodeBits fun i => atSlot i == some true, encodeBits fun i => atSlot i == some false⟩

private def Fits (r : Row) (p : Profile) : Prop :=
  ∀ i : Fin questionCount,
    (r.yes.getLsbD i.val = true → p (questionAt i) = true) ∧
    (r.no.getLsbD i.val = true → p (questionAt i) = false)

private theorem fits (s : Step) :
    Fits (read (ReplayAnswers.read s.cfg s.before s.act s.after s.past)) (label s) := by
  intro i
  simp only [read, encodeBits_get, Array.getElem_map, beq_iff_eq]
  exact ⟨ReplayAnswers.sound s _, ReplayAnswers.sound s _⟩

private def conflict (a b : Row) : Bool :=
  ((a.yes &&& b.no) ||| (a.no &&& b.yes)) != 0

private theorem consistent {a b : Row} {p : Profile} (x : Fits a p) (y : Fits b p) :
    conflict a b = false := by
  apply bne_eq_false_iff_eq.mpr
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have ha := x ⟨i, hi⟩
  have hb := y ⟨i, hi⟩
  rw [show (0 : BitVec questionCount).getLsbD i = false from BitVec.getLsbD_zero]
  simp only [BitVec.getLsbD_or, BitVec.getLsbD_and]
  apply Bool.or_eq_false_iff.mpr
  constructor <;> apply Bool.eq_false_iff.mpr <;> intro yes
  · have h := Bool.and_eq_true_iff.mp yes
    exact Bool.noConfusion ((ha.1 h.1).symm.trans (hb.2 h.2))
  · have h := Bool.and_eq_true_iff.mp yes
    exact Bool.noConfusion ((hb.1 h.2).symm.trans (ha.2 h.1))

/-- Retain a row only when it disagrees on a *known* bit with every retained
row. This gives a lower bound, not a maximum-clique claim. -/
public def select : List Row → List Row
  | [] => []
  | r :: rs =>
    let tail := select rs
    if tail.all (conflict r) then r :: tail else tail

private theorem selected {rs : List Row} :
    select rs ⊆ rs ∧ (select rs).Pairwise (fun a b => conflict a b = true) := by
  induction rs with
  | nil => exact ⟨List.Subset.refl _, .nil⟩
  | cons r rs ih =>
    simp only [select]
    split
    · rename_i h
      exact ⟨List.cons_subset_cons _ ih.1, List.pairwise_cons.mpr ⟨List.all_eq_true.mp h, ih.2⟩⟩
    · exact ⟨fun _ h => List.mem_cons_of_mem _ (ih.1 h), ih.2⟩

private theorem lower {rs : List Row} (incompatible : rs.Pairwise (fun a b => conflict a b = true))
    (ps : List Profile) (cover : ∀ r ∈ rs, ∃ p ∈ ps, Fits r p) : rs.length ≤ ps.length := by
  classical
  induction rs generalizing ps with
  | nil => simp
  | cons r rs ih =>
    obtain ⟨p, mem, matchR⟩ := cover r (by simp)
    have rel := List.pairwise_cons.mp incompatible
    have bound := ih rel.2 (ps.erase p) (by
      intro s hs
      obtain ⟨q, hq, matchS⟩ := cover s (List.mem_cons_of_mem _ hs)
      have ne : q ≠ p := by
        rintro rfl
        exact Bool.noConfusion ((rel.1 s hs).symm.trans (consistent matchR matchS))
      exact ⟨q, (List.mem_erase_of_ne ne).mpr hq, matchS⟩)
    have len := List.length_erase_of_mem mem
    have pos := List.length_pos_of_mem mem
    simp only [List.length_cons]
    omega

public def observed (s : Step) := read (ReplayAnswers.read s.cfg s.before s.act s.after s.past)

/-- Compare the known coordinates of any recorded action with a fixed step
signature. One contrary bit refutes it; confirmation needs every step answer. -/
public def signature? (r : Row) (target : Classes.StepBranch → Bool) : Option Bool :=
  let agrees (b : Classes.StepBranch) := if target b then r.yes else r.no
  let disagrees (b : Classes.StepBranch) := if target b then r.no else r.yes
  if stepBranches.toList.any (fun b => (disagrees b).getLsbD (Question.step b).slot.val) then some false
  else if stepBranches.toList.all (fun b => (agrees b).getLsbD (Question.step b).slot.val) then some true
  else none

public theorem signature?_sound (s : Step) (target : Classes.StepBranch → Bool) {v : Bool}
    (known : signature? (observed s) target = some v) : (label s).step = target ↔ v = true := by
  have bit (b : Classes.StepBranch) :
      ((observed s).yes.getLsbD (Question.step b).slot.val = true → (label s).step b = true) ∧
      ((observed s).no.getLsbD (Question.step b).slot.val = true → (label s).step b = false) := by
    simpa only [observed, questionAt_slot, Profile.step] using fits s (Question.step b).slot
  dsimp only [signature?] at known
  split at known
  · rename_i contrary
    cases known
    obtain ⟨b, _, h⟩ := List.any_eq_true.mp contrary
    refine ⟨fun eq => ?_, Bool.noConfusion⟩
    cases t : target b
    · have h := (bit b).1 (by simpa [t] using h)
      exact (t.symm.trans (congrFun eq b).symm).trans h
    · have h := (bit b).2 (by simpa [t] using h)
      exact h.symm.trans ((congrFun eq b).trans t)
  · split at known
    · rename_i agrees
      cases known
      refine ⟨fun _ => rfl, fun _ => funext fun b => ?_⟩
      have mem : b ∈ stepBranches.toList := by rw [← step_get b]; exact Array.getElem_mem_toList ..
      have h := List.all_eq_true.mp agrees b mem
      cases t : target b
      · exact (bit b).2 (by simpa [t] using h)
      · exact (bit b).1 (by simpa [t] using h)
    · contradiction

/-- This bounds the number of distinct full labels in *these* actions, not
the number reachable in the entire model. The action count is an upper bound. -/
public theorem bounds (ss : List Step) (ps : List Profile) (distinct : ps.Nodup)
    (exactRows : ∀ p, p ∈ ps ↔ p ∈ ss.map label) :
    (select (ss.map observed)).length ≤ ps.length ∧ ps.length ≤ ss.length := by
  refine ⟨lower selected.2 ps (rs := select (ss.map observed)) ?_, ?_⟩
  · intro r hr
    obtain ⟨s, hs, rfl⟩ := List.mem_map.mp (selected.1 hr)
    exact ⟨label s, (exactRows _).mpr (List.mem_map.mpr ⟨s, hs, rfl⟩), fits s⟩
  · simpa only [List.length_map] using
      distinct.length_le_of_subset (l₂ := ss.map label) fun {_} h => (exactRows _).mp h

end ConsensusCoverage.CaptureBounds
