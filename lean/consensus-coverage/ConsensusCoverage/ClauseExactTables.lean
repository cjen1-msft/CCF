module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.StateCoverage

namespace ConsensusCoverage.ClauseExactTables

open ClauseQuestions ActionProfile

public abbrev Endpoints := StateCoverage.Row × StateCoverage.Row

public def endpoints (s : Step) : Endpoints :=
  (StateCoverage.read s.cfg s.before s.past, StateCoverage.read s.cfg s.after (s.before :: s.past))

private def endpointProjection (r : FrontierRows.Row) : Endpoints :=
  ((r.zeroBefore, r.backedBefore), (r.zeroAfter, r.backedAfter))

/-- Forget the election-result bit of the exact nine-row frontier table. -/
public def endpointRows : List Endpoints := (FrontierRows.table.map endpointProjection).eraseDups

public theorem endpoint_rows :
    endpointRows =
      [((true,false), (true,false)), ((true,false), (true,true)), ((true,false), (false,true)),
       ((true,true), (true,true)), ((true,true), (false,true)), ((false,true), (false,true))] :=
  by decide +kernel

public theorem endpoint_count : endpointRows.Nodup ∧ endpointRows.length = 6 := by decide +kernel

public theorem endpoint_exact (p : Endpoints) : p ∈ endpointRows ↔ ∃ s : Step, endpoints s = p := by
  simp only [endpointRows, List.mem_eraseDups, List.mem_map, FrontierRows.ghost_exact]
  constructor
  · rintro ⟨_, ⟨cfg, ns, s, t, h, a, run, ran, rfl⟩, rfl⟩
    exact ⟨⟨cfg, ns, s, h, a, t, run, ran⟩, rfl⟩
  · rintro ⟨s, rfl⟩
    exact ⟨_, ⟨_, _, _, _, _, _, s.run, s.ran, rfl⟩, rfl⟩

private def noBits (p : Endpoints) : RestrictedProfile := ⟨p.1, [], p.2⟩

public def emptyRows := endpointRows.map noBits

public theorem empty_count : emptyRows.Nodup ∧ emptyRows.length = 6 := by decide +kernel

public theorem empty_exact (c : Clause) (empty : questions c = []) : ClauseExactTable c emptyRows := by
  refine ⟨empty_count.1, fun p => ?_⟩
  have eq (s : Step) : clauseLabel c s = noBits (endpoints s) := by
    simp only [clauseLabel, empty, restrictedLabel, List.map_nil, noBits, endpoints]
  constructor
  · intro mem
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp mem
    obtain ⟨s, rfl⟩ := (endpoint_exact e).mp he
    exact ⟨s, eq s⟩
  · rintro ⟨s, rfl⟩
    exact List.mem_map.mpr ⟨_, (endpoint_exact _).mpr ⟨s, rfl⟩, (eq s).symm⟩

public theorem owners_exact : ClauseExactTable .owners emptyRows := empty_exact _ (by decide +kernel)
public theorem observed_exact : ClauseExactTable .observed emptyRows := empty_exact _ (by decide +kernel)

/-- No other step coordinate can split the `distinct` table. -/
public theorem distinct_reduction (s : Step) :
    clauseLabel .distinct s =
      ⟨(endpoints s).1, [label s (.step .replaceNode_keys_here_pos),
        label s (.step .replaceNode_keys_here_neg)], (endpoints s).2⟩ := by
  have h : questions .distinct = [.replaceNode_keys_here_pos, .replaceNode_keys_here_neg] :=
    by decide +kernel
  simp only [clauseLabel, h, restrictedLabel, endpoints, List.map_cons, List.map_nil]

end ConsensusCoverage.ClauseExactTables
