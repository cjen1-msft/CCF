module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSampleBound
import all ConsensusCoverage.ClauseSampleBound
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.CensusWidth
import all ConsensusCoverage.ReadersCorpus

namespace ConsensusCoverage.ClauseSharedTrees

open ClauseQuestions ClauseSampleBound ActionProfile

public def slots : Tree → List Nat
  | .leaf _ => []
  | .ask i l r => i :: (slots l ++ slots r)

private theorem run_congr (t : Tree) {a b : Nat → Option Bool}
    (agree : ∀ i ∈ slots t, a i = b i) : t.run a = t.run b := by
  induction t with
  | leaf => rfl
  | ask i l r il ir =>
    simp only [slots,List.mem_cons,List.mem_append] at agree
    simp only [Tree.run,agree i (.inl rfl),il (fun j h => agree j (.inr (.inl h))),
      ir (fun j h => agree j (.inr (.inr h)))]

private def asSource (from_ to_ : Clause) (r : RestrictedProfile) : RestrictedProfile :=
  {r with bits := (questions from_).map fun b => ((questions to_).zip r.bits).lookup b |>.getD false}

public def usesOnly (from_ to_ : Clause) (trees : Forest) : Bool :=
  (List.range 16).all fun k => (slots (trees k)).all fun i =>
    (questions from_)[i]?.any ((questions to_).contains ·)

private theorem same (from_ to_ : Clause) (trees : Forest) (support : usesOnly from_ to_ trees) (s : Step) :
    project trees (clauseLabel from_ s) = project trees (asSource from_ to_ (clauseLabel to_ s)) := by
  let r := clauseLabel from_ s
  let k := endpointCode r.pre r.post
  have bounded (a b : StateCoverage.Row) : endpointCode a b < 16 := by
    rcases a with ⟨a,b'⟩; rcases b with ⟨c,d⟩
    cases a <;> cases b' <;> cases c <;> cases d <;> decide
  apply run_congr (trees k)
  intro i hi
  obtain ⟨b,slot,mem⟩ := (Option.any_eq_true _ _).mp
    (List.all_eq_true.mp (List.all_eq_true.mp support k (List.mem_range.mpr (bounded _ _))) i hi)
  change ((questions from_).map _)[i]? = ((questions from_).map _)[i]?
  simp only [List.getElem?_map,slot,Option.map_some]
  exact congrArg some (CensusWidth.lookup_zip (List.contains_iff_mem.mp mem)
    (fun b => label s (.step b)) ▸ Eq.refl _)

public theorem bound (from_ to_ : Clause) (trees : Forest) (support : usesOnly from_ to_ trees)
    (picks : List (Nat × Nat)) (n : Nat)
    (checked : (picks.filterMap (lookup from_ trees)).length = n ∧ (picks.filterMap (lookup from_ trees)).Nodup)
    (rows : List RestrictedProfile) (all : ∀ s, clauseLabel to_ s ∈ rows) : n ≤ rows.length := by
  have sub : picks.filterMap (lookup from_ trees) ⊆ rows.filterMap (project trees ∘ asSource from_ to_) := by
    intro k hm
    obtain ⟨_,_,h⟩ := List.mem_filterMap.mp hm
    obtain ⟨s,_,hit⟩ := Option.bind_eq_some_iff.mp h
    exact List.mem_filterMap.mpr ⟨_,all s,(same from_ to_ trees support s).symm.trans (correct _ _ s hit)⟩
  exact checked.1 ▸ Nat.le_trans (checked.2.length_le_of_subset sub) (List.length_filterMap_le _ _)

end ConsensusCoverage.ClauseSharedTrees
