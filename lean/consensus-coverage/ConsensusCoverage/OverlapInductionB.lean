module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.OverlapInductionB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open SolvedWitnesses

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

structure Seed (c : Ctx f t) where
  left : List Entry
  right : List Entry
  a : Nat
  b : Nat
  k : Nat
  origin : (reach% step_rooted_overlap_eq_zero_or_pos_inr[5]) f t c left right a b k
  lr : Rooted Config.GENESIS left
  rr : Rooted Config.GENESIS right
  ln : left ≠ []
  rn : right ≠ []
  agree : left.take k = right.take k
  la : a ≤ k
  rb : b ≤ k

private abbrev K (s : Seed c) := max s.k 1
private abbrev hs (s : Seed c) := configurationHistory (s.right.take (K s))
private abbrev filt (xs : List Configuration) (n : Nat) := xs.filter fun x => x.index ≤ n

private theorem eqK (s : Seed c) : s.left.take (K s) = s.right.take (K s) := by
  rcases Nat.eq_zero_or_pos s.k with zero | pos
  · simp [K, zero, s.lr.head s.ln, s.rr.head s.rn]
  · simpa [K, Nat.max_eq_left pos] using s.agree

private theorem headK (s : Seed c) : (s.right.take (K s)).take 1 = [Config.GENESIS] := by
  rw [List.take_take, Nat.min_eq_left (Nat.le_max_right _ _)]
  exact s.rr.head s.rn

private theorem configured (s : Seed c) : hs s ≠ [] :=
  configurationHistory_ne_nil (headK s) Config.GENESIS_configured

private theorem source (s : Seed c) :
    (reach% step_activeConfigurations_overlap_le_total_inl[5]) f t c s.left s.right s.a s.b (K s) :=
  ⟨s.k, s.origin, s.lr, s.rr, s.ln, s.rn, s.agree, s.la, s.rb,
    s.lr.head s.ln, s.rr.head s.rn, eqK s, headK s, rfl⟩

omit [Config.InitialConfiguration] in
private theorem countFilter {xs rest : List Configuration} {log : List Entry} {k commit : Nat}
    (eq : configurationHistory log = xs ++ rest) (later : ∀ x ∈ rest, k < x.index)
    (bound : commit ≤ k) : filt (configurationHistory log) commit = filt xs commit := by
  rw [eq]
  exact filter_index_append bound later

omit [Config.InitialConfiguration] in
private theorem inDrop {xs rest : List Configuration} {log : List Entry} {m p : Nat}
    (lt : p < xs.length) (eq : configurationHistory log = xs ++ rest) (le : m ≤ p) :
    xs[p] ∈ (configurationHistory log).drop m := by
  rw [eq, List.mem_iff_getElem]
  refine ⟨p - m, ?_, ?_⟩
  · rw [List.length_drop, List.length_append]
    exact Nat.sub_lt_sub_right le (Nat.lt_of_lt_of_le lt (Nat.le_add_right _ _))
  · simp only [List.getElem_drop]
    rw [List.getElem_append_left (Nat.lt_of_le_of_lt (Nat.le_of_eq (Nat.add_sub_of_le le)) lt)]
    congr 1
    exact Nat.add_sub_of_le le

private theorem sorted (s : Seed c) : (hs s).Pairwise (fun x y => x.index < y.index) :=
  configurationHistory_sorted _

private theorem boundOrigin (s : Seed c) (order : s.a ≤ s.b) :
    (reach% step_chosen_bound_counted_pos[5]) f t c (hs s) s.b := by
  obtain ⟨ls, l⟩ := configurationHistory_split s.left (K s)
  obtain ⟨rs, r⟩ := configurationHistory_split s.right (K s)
  have la := Nat.le_trans s.la (Nat.le_max_left s.k 1)
  have rb := Nat.le_trans s.rb (Nat.le_max_left s.k 1)
  have pos := List.length_pos_iff.mpr (configured s)
  have last := Nat.sub_one_lt (Nat.ne_of_gt pos)
  have mono := length_filter_index_mono (hs s) order
  exact Or.inl ⟨s.left, s.right, s.a, K s, source s, ls, l, l.1, l.2, rs, r, r.1, r.2,
    order, eqK s, la, rb, configured s, sorted s, pos, countFilter, inDrop,
    length_filter_le _ _, length_filter_le _ _, last, mono,
    Nat.lt_of_le_of_lt (Nat.sub_le_sub_right (length_filter_le _ _) 1) last, rfl⟩

theorem ordered (s : Seed c) (ab : s.a = s.b) :
    step_activeConfigurations_overlap_le_total_inl f t c ∧ step_activeConfigurations_overlap_le_total_inr f t c := by
  obtain ⟨ls, l⟩ := configurationHistory_split s.left (K s)
  obtain ⟨rs, r⟩ := configurationHistory_split s.right (K s)
  have la := Nat.le_trans s.la (Nat.le_max_left s.k 1)
  have rb := Nat.le_trans s.rb (Nat.le_max_left s.k 1)
  have pos := List.length_pos_iff.mpr (configured s)
  constructor <;> iterate 5 right
  all_goals refine Or.inl ⟨s.left, s.right, s.a, s.b, K s, source s, ls, l, l.1, l.2, rs, r, r.1, r.2,
    ?_, la, rb, length_filter_le _ _, length_filter_le _ _, eqK s, configured s, sorted s, pos,
    countFilter, inDrop, Nat.sub_one_lt (Nat.ne_of_gt pos)⟩
  · exact Nat.le_of_eq ab
  · exact Nat.le_of_eq ab.symm

theorem zip (s : Seed c) (order : s.a ≤ s.b) :
    step_zipIdx_sorted_log_nil f t c ∧ step_zipIdx_sorted_log_cons f t c := by
  obtain ⟨ls, l⟩ := configurationHistory_split s.left (K s)
  obtain ⟨rs, r⟩ := configurationHistory_split s.right (K s)
  have pos := List.length_pos_iff.mpr (configured s)
  have last := Nat.sub_one_lt (Nat.ne_of_gt pos)
  have p : (reach% step_zipIdx_sorted_log_nil[5]) f t c := by
    left
    exact ⟨s.left, s.right, s.a, s.b, K s, source s, ls, l, l.1, l.2, rs, r, r.1, r.2,
      order, Nat.le_trans s.la (Nat.le_max_left _ _), Nat.le_trans s.rb (Nat.le_max_left _ _),
      length_filter_le _ _, length_filter_le _ _, length_filter_index_mono (hs s) order,
      Nat.lt_of_le_of_lt (Nat.sub_le_sub_right (length_filter_le _ _) 1) last,
      eqK s, configured s, pos, countFilter, inDrop, last⟩
  constructor <;> iterate 5 right
  · exact Or.inl p
  · exact Or.inl ⟨p, [], by simp⟩

theorem zero (s : Seed c) (order : s.a ≤ s.b)
    (no : ¬0 < (filt (hs s) s.b).length) :
    step_chosen_bound_counted_neg f t c ∧ step_chosen_bound_mem_cons_inl f t c := by
  obtain ⟨x, hx⟩ := List.exists_mem_of_ne_nil (hs s) (configured s)
  have root := boundOrigin s order
  have pos := List.length_pos_iff.mpr (configured s)
  have out : ¬ x.index ≤ s.b := fun le => no (List.length_pos_iff.mpr
    (List.ne_nil_of_mem (List.mem_filter.mpr ⟨hx, by simpa using le⟩)))
  constructor <;> iterate 5 right
  · exact Or.inl ⟨_, _, root, no, sorted s, pos⟩
  · exact Or.inl ⟨_, _, root, no, x, hx, [], by simp, by simp, by simp [out], .head _, sorted s, pos⟩

theorem laterMember (s : Seed c) (order : s.a ≤ s.b) (no : ¬0 < (filt (hs s) s.b).length)
    (x : Configuration) (hx : x ∈ hs s) (gap : s.b + 1 < x.index) : step_chosen_bound_mem_cons_inr f t c := by
  let h : Configuration := ⟨s.b+1, ∅⟩
  have bad : ¬ x.index ≤ s.b := by omega
  iterate 5 right
  exact Or.inl ⟨_, _, boundOrigin s order, no, x, hx, h, [x], by simpa [h] using gap,
    by simp, by simp [h, bad], .tail _ (.head _), .head _, sorted s, List.length_pos_iff.mpr (configured s)⟩

theorem positive (s : Seed c) (order : s.a ≤ s.b) (positive : 0 < s.b)
    (yes : 0 < (filt (hs s) s.b).length) :
    step_chosen_bound_counted_pos f t c ∧ step_getElem_le_of_lt_length_filter_i_inl f t c ∧
      step_getElem_le_of_lt_length_filter_i_inr f t c := by
  let i := (filt (hs s) s.b).length - 1
  have sub : i < (filt (hs s) s.b).length := Nat.sub_one_lt (Nat.ne_of_gt yes)
  have pos := List.length_pos_iff.mpr (configured s)
  have root := boundOrigin s order
  have index : (reach% step_getElem_le_of_lt_length_filter_i_inl[5]) f t c (hs s) s.b i :=
    ⟨root, yes, sorted s, pos, rfl⟩
  let h : Configuration := ⟨0, ∅⟩
  let j : Configuration := ⟨1, ∅⟩
  have one : 1 ≤ s.b := by omega
  have shape : (filt [h,j] s.b) = [h,j] := by simp [filt,h,j,one]
  have tail : (filt [j] s.b) = [j] := by simp [filt,j,one]
  have pair : [h,j].Pairwise (fun x y => x.index < y.index) := by decide
  refine ⟨?_, ?_, ?_⟩ <;> iterate 5 right
  · exact Or.inl ⟨_, _, root, yes, sorted s, pos⟩
  · refine Or.inl ⟨_, _, _, index, h, [j], ?_, pair, 0, ?_, Nat.zero_le _, ?_, ?_, sub, sorted s⟩
    · exact fun so _ lt => getElem_le_of_lt_length_filter so lt
    · change 0 < (filt [h,j] s.b).length; simp [shape]
    · change 0 < (filt [h,j] s.b).length; simp [shape]
    · change 0 < (h :: filt [j] s.b).length; simp
  · refine Or.inl ⟨_, _, _, index, h, [j], ?_, pair, 1, ?_, Nat.zero_le _, 0, ?_, ?_, sub, sorted s⟩
    · exact fun so _ lt => getElem_le_of_lt_length_filter so lt
    · change 1 < (filt [h,j] s.b).length; simp [shape]
    · change 1 < (filt [h,j] s.b).length; simp [shape]
    · change 1 < (h :: filt [j] s.b).length; simp [tail]

end
end ConsensusCoverage.OverlapInductionB
