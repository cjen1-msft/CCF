module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.ClauseDistinct
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersRefuted

namespace ConsensusCoverage.ClauseSmallA.Ballots

open ActionProfile ClauseQuestions ClauseExactTables
open HandReadersElectionB

set_option maxHeartbeats 0
set_option maxRecDepth 8192

public theorem columns : nonTrunk .ballots =
    [.ballot_step_mem_after_inl, .ballot_step_mem_after_inr, .replaceNode_keys_here_pos,
     .replaceNode_keys_here_neg, .find_of_mem_here_pos, .find_of_mem_here_neg] :=
  by decide +kernel

private def pack (k : Bool) := [false, false, k, k, k, k]

private def row (e : Endpoints) (k : Bool) : RestrictedProfile := ⟨e.1, pack k, e.2⟩

public def rows : List RestrictedProfile :=
  endpointRows.flatMap fun e => row e true :: if e.1 = e.2 then [row e false] else []

public def patterns : List (List Bool) := [pack true, pack false]

public theorem counts :
    patterns.Nodup ∧ patterns.length = 2 ∧ rows.Nodup ∧ rows.length = 9 := by decide +kernel

private theorem shape (s : Step) :
    nonTrunkLabel .ballots s = row (endpoints s) (label s (.step .replaceNode_keys_here_pos)) := by
  have no (b : Classes.StepBranch) (h : ReadersRefuted.read? b = some false) :=
    ReadersRefuted.read?_correct s h
  have replace := Keys.negative.eq_label s |>.trans (Keys.positive.eq_label s).symm
  have findPos := Find.positive.eq_label s |>.trans (Keys.positive.eq_label s).symm
  have findNeg := Find.negative.eq_label s |>.trans (Keys.positive.eq_label s).symm
  simp only [nonTrunkLabel, columns, restrictedLabel, row, endpoints, pack, List.map_cons, List.map_nil,
    no .ballot_step_mem_after_inl (by decide +kernel),
    no .ballot_step_mem_after_inr (by decide +kernel)]
  rw [show label s (.step .replaceNode_keys_here_neg) =
      label s (.step .replaceNode_keys_here_pos) from replace,
    show label s (.step .find_of_mem_here_pos) = label s (.step .replaceNode_keys_here_pos)
      from findPos,
    show label s (.step .find_of_mem_here_neg) = label s (.step .replaceNode_keys_here_pos)
      from findNeg]

public theorem upper (s : Step) : nonTrunkLabel .ballots s ∈ rows := by
  rw [shape]
  apply List.mem_flatMap.mpr
  refine ⟨_, (endpoint_exact _).mpr ⟨s, rfl⟩, ?_⟩
  cases h : label s (.step .replaceNode_keys_here_pos) with
  | true => exact List.mem_cons_self
  | false => simp [ClauseDistinct.false_diagonal s h]

private def picks : List (Nat × Nat) :=
  [(0,0),(0,1),(1,0),(2,0),(34,1),(46,1),(25,4),(25,1),(18,1)]

private noncomputable def steps := picks.filterMap fun (i,j) => ReadersCorpus.stepAt i j

private theorem checked : rows.all (steps.map (readRow (nonTrunk .ballots))).contains = true :=
  by decide +kernel

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s : Step, nonTrunkLabel .ballots s = r :=
  sampled _ (by rw [columns]; decide +kernel) _ _ checked mem

public theorem exact_rows (r : RestrictedProfile) :
    r ∈ rows ↔ ∃ s : Step, nonTrunkLabel .ballots s = r :=
  ⟨lower r, by rintro ⟨s, rfl⟩; exact upper s⟩

public theorem exact_patterns (p : List Bool) :
    p ∈ patterns ↔ ∃ s : Step, (nonTrunkLabel .ballots s).bits = p := by
  have eq : patterns = (rows.map RestrictedProfile.bits).eraseDups := by decide +kernel
  rw [eq]
  exact patterns_exact upper lower p

end ConsensusCoverage.ClauseSmallA.Ballots
