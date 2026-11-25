module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactCover
public import ConsensusCoverage.ClauseFrontierExactSamples
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseFrontierExactCover
import all ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.ClauseFrontierExactSamples
import all ConsensusCoverage.ClauseQuestions

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile ClauseQuestions

set_option maxRecDepth 8192

/-- The symbolic cover minus the proved witnesses. Membership does not
assert either realizability or impossibility. -/
public def unresolvedPatterns : List (List Bool) :=
  upperPatterns.eraseDups.filter (!witnessedPatterns.contains ·)

private def endpointCompatible (r : RestrictedProfile) : Bool :=
  decide (r.pre = r.post) || (r.bits.head? == some true)

public def unresolvedRows : List RestrictedProfile :=
  upperRows.eraseDups.filter fun r => endpointCompatible r && !witnessedRows.contains r

public theorem unresolved_pattern_iff (bits : List Bool) :
    bits ∈ unresolvedPatterns ↔ bits ∈ upperPatterns ∧ bits ∉ witnessedPatterns := by
  have no : witnessedPatterns.contains bits = false ↔ bits ∉ witnessedPatterns :=
    Bool.eq_false_iff.trans (not_congr List.contains_iff_mem)
  simp only [unresolvedPatterns, List.mem_filter, List.mem_eraseDups, Bool.not_eq_true',
    no]

public theorem unresolved_row_iff (r : RestrictedProfile) :
    r ∈ unresolvedRows ↔
      r ∈ upperRows ∧ (r.pre = r.post ∨ r.bits.head? = some true) ∧ r ∉ witnessedRows := by
  have no : witnessedRows.contains r = false ↔ r ∉ witnessedRows :=
    Bool.eq_false_iff.trans (not_congr List.contains_iff_mem)
  simp only [unresolvedRows, endpointCompatible, List.mem_filter, List.mem_eraseDups,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq, Bool.not_eq_true',
    no]

public theorem pattern_partition (s : Step) :
    let bits := (nonTrunkLabel .frontier s).bits
    bits ∈ witnessedPatterns ∨ bits ∈ unresolvedPatterns := by
  dsimp only
  by_cases h : (nonTrunkLabel .frontier s).bits ∈ witnessedPatterns
  · exact .inl h
  · exact .inr ((unresolved_pattern_iff _).mpr ⟨patterns_upper s,h⟩)

/-- Any surviving off-diagonal candidate with the frontier entry bit clear is
impossible, even though the coarse endpoint product includes it. -/
public theorem off_diagonal (s : Step)
    (changed : (nonTrunkLabel .frontier s).pre ≠ (nonTrunkLabel .frontier s).post) :
    (nonTrunkLabel .frontier s).bits.head? = some true := by
  have head : (nonTrunk .frontier).head? = some .inv_step_frontier_now_inl := by decide +kernel
  have bit : label s (.step .inv_step_frontier_now_inl) = true := by
    rw [← Bool.not_eq_false]
    intro no
    exact changed (unchanged_endpoints s no)
  simpa only [nonTrunkLabel, restrictedLabel, List.head?_map, head, Option.map_some] using
    congrArg some bit

public theorem row_partition (s : Step) :
    nonTrunkLabel .frontier s ∈ witnessedRows ∨ nonTrunkLabel .frontier s ∈ unresolvedRows := by
  by_cases h : nonTrunkLabel .frontier s ∈ witnessedRows
  · exact .inl h
  · refine .inr ((unresolved_row_iff _).mpr ⟨rows_upper s,?_,h⟩)
    by_cases diagonal : (nonTrunkLabel .frontier s).pre = (nonTrunkLabel .frontier s).post
    · exact .inl diagonal
    · exact .inr (off_diagonal s diagonal)

public theorem pattern_cardinality (rows : List (List Bool)) (nodup : rows.Nodup)
    (exactTable : ∀ r, r ∈ rows ↔ ∃ s : Step, (nonTrunkLabel .frontier s).bits = r) :
    40 ≤ rows.length ∧ rows.length ≤ 204288 := by
  constructor
  · rw [← witnessed_patterns_count.2]
    exact witnessed_patterns_count.1.length_le_of_subset fun {r} h =>
      (exactTable r).mpr (witnessed_pattern_realized h)
  · refine Nat.le_trans (nodup.length_le_of_subset (l₂ := upperPatterns) ?_) upper_patterns_size
    intro r mem
    obtain ⟨s,rfl⟩ := (exactTable r).mp mem
    exact patterns_upper s

public theorem row_cardinality (rows : List RestrictedProfile) (nodup : rows.Nodup)
    (exactTable : ∀ r, r ∈ rows ↔ ∃ s : Step, nonTrunkLabel .frontier s = r) :
    91 ≤ rows.length ∧ rows.length ≤ 1225728 := by
  constructor
  · rw [← witnessed_rows_count.2]
    exact witnessed_rows_count.1.length_le_of_subset fun {r} h =>
      (exactTable r).mpr (witnessed_row_realized h)
  · refine Nat.le_trans (nodup.length_le_of_subset (l₂ := upperRows) ?_) upper_rows_bound
    intro r mem
    obtain ⟨s,rfl⟩ := (exactTable r).mp mem
    exact rows_upper s

end ConsensusCoverage.ClauseFrontierExact
