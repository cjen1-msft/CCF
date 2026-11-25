module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactSamples
public import ConsensusCoverage.ClauseFrontierExactCapacity
import all ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ClauseFrontierExactSamples
import all ConsensusCoverage.ClauseFrontierExactTight
import all ConsensusCoverage.ClauseQuestions

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile ClauseQuestions

set_option maxRecDepth 8192

public theorem full_width (s : Step) :
    (nonTrunkLabel .frontier s).bits.length = 61 := by
  simpa only [nonTrunkLabel, restrictedLabel, List.length_map] using column_count

public theorem witnessed_patterns_width : ∀ p ∈ witnessedPatterns, p.length = 61 := by
  intro p hp
  obtain ⟨s,rfl⟩ := witnessed_pattern_realized hp
  exact full_width s

public theorem witnessed_rows_width : ∀ r ∈ witnessedRows, r.bits.length = 61 := by
  intro r hr
  obtain ⟨s,rfl⟩ := witnessed_row_realized hr
  exact full_width s

/-- All candidates not yet given an initialized witness. The cover can still
contain unrealizable combinations of different proof origins. -/
public def tightUnresolvedRows : List RestrictedProfile :=
  tightRows.eraseDups.filter (!witnessedRows.contains ·)

public theorem tight_unresolved_iff (r : RestrictedProfile) :
    r ∈ tightUnresolvedRows ↔ r ∈ tightRows ∧ r ∉ witnessedRows := by
  have no : witnessedRows.contains r = false ↔ r ∉ witnessedRows :=
    Bool.eq_false_iff.trans (not_congr List.contains_iff_mem)
  simp only [tightUnresolvedRows, List.mem_filter, List.mem_eraseDups, Bool.not_eq_true', no]

public theorem tight_pattern_cardinality (rows : List (List Bool)) (nodup : rows.Nodup)
    (exactTable : ∀ r, r ∈ rows ↔ ∃ s : Step, (nonTrunkLabel .frontier s).bits = r) :
    40 ≤ rows.length ∧ rows.length ≤ 3024 := by
  constructor
  · rw [← witnessed_patterns_count.2]
    exact witnessed_patterns_count.1.length_le_of_subset fun {r} h =>
      (exactTable r).mpr (witnessed_pattern_realized h)
  · rw [← tight_patterns_size]
    apply nodup.length_le_of_subset
    intro r hr
    obtain ⟨s,rfl⟩ := (exactTable r).mp hr
    exact tight_patterns_upper s

public theorem tight_row_cardinality (rows : List RestrictedProfile) (nodup : rows.Nodup)
    (exactTable : ∀ r, r ∈ rows ↔ ∃ s : Step, nonTrunkLabel .frontier s = r) :
    91 ≤ rows.length ∧ rows.length ≤ 17622 := by
  constructor
  · rw [← witnessed_rows_count.2]
    exact witnessed_rows_count.1.length_le_of_subset fun {r} h =>
      (exactTable r).mpr (witnessed_row_realized h)
  · rw [← tight_rows_size]
    apply nodup.length_le_of_subset
    intro r hr
    obtain ⟨s,rfl⟩ := (exactTable r).mp hr
    exact tight_rows_upper s

end ConsensusCoverage.ClauseFrontierExact
