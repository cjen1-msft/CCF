module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseSampleBound

open ClauseQuestions ActionProfile

public inductive Tree where
  | leaf (code : Nat)
  | ask (slot : Nat) (no yes : Tree)
  deriving Inhabited

public def Tree.run (answer : Nat → Option Bool) : Tree → Option Nat
  | .leaf k => some k
  | .ask i l r => (answer i).bind fun yes => if yes then r.run answer else l.run answer

private theorem Tree.sound (t : Tree) {a b : Nat → Option Bool}
    (agree : ∀ i v, a i = some v → b i = some v) {v} (hit : t.run a = some v) : t.run b = some v := by
  induction t with
  | leaf => exact hit
  | ask i l r il ir =>
    cases found : a i with
    | none => simp [Tree.run,found] at hit
    | some v =>
      have hb := agree i v found
      cases v <;> simp only [Tree.run,found,hb,Option.bind_some,Bool.false_eq_true,↓reduceIte] at hit ⊢
      · exact il hit
      · exact ir hit

public def endpointCode (r t : StateCoverage.Row) :=
  r.1.toNat + 2*r.2.toNat + 4*t.1.toNat + 8*t.2.toNat

public abbrev Forest := Nat → Tree

public def project (trees : Forest) (r : RestrictedProfile) : Option Nat :=
  (trees (endpointCode r.pre r.post)).run (r.bits[·]?)

public def read (c : Clause) (trees : Forest) (s : Step) : Option Nat :=
  let tree := trees (endpointCode (StateCoverage.read s.cfg s.before s.past)
    (StateCoverage.read s.cfg s.after (s.before :: s.past)))
  let query := ReadersTotal.read s.cfg s.before s.act s.after s.past
  tree.run (fun i => (questions c)[i]?.bind query)

public theorem correct (c : Clause) (trees : Forest) (s : Step) {k} (hit : read c trees s = some k) :
    project trees (clauseLabel c s) = some k := by
  apply Tree.sound _ _ hit
  intro i v h
  obtain ⟨b,hb,e⟩ := Option.bind_eq_some_iff.mp h
  change ((questions c).map fun b => label s (.step b))[i]? = some v
  rw [List.getElem?_map,hb,Option.map_some,ReadersTotal.read_correct s e]

public def lookup (c : Clause) (trees : Forest) (p : Nat × Nat) :=
  (ReadersCorpus.stepAt p.1 p.2).bind (read c trees)

public theorem bound (c : Clause) (trees : Forest) (picks : List (Nat × Nat)) (n : Nat)
    (certificate : (picks.filterMap (lookup c trees)).length = n ∧ (picks.filterMap (lookup c trees)).Nodup)
    (rows : List RestrictedProfile) (complete : ∀ s, clauseLabel c s ∈ rows) : n ≤ rows.length := by
  have sub : picks.filterMap (lookup c trees) ⊆ rows.filterMap (project trees) := by
    intro k mem
    obtain ⟨_,_,h⟩ := List.mem_filterMap.mp mem
    obtain ⟨s,_,hit⟩ := Option.bind_eq_some_iff.mp h
    exact List.mem_filterMap.mpr ⟨_,complete s,correct _ _ s hit⟩
  exact certificate.1 ▸ Nat.le_trans (certificate.2.length_le_of_subset sub) (List.length_filterMap_le _ _)

end ConsensusCoverage.ClauseSampleBound
