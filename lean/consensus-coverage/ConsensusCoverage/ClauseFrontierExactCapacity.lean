module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactTight
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseFrontierExactTight
import all ConsensusCoverage.EventSupport

namespace ConsensusCoverage.ClauseFrontierExact

open ClauseExactTables EventSupport

set_option maxHeartbeats 0
set_option maxRecDepth 16384

private theorem endpoints_count (changed : Bool) :
    (endpointRows.filter (fits changed)).length = if changed then 6 else 3 := by
  cases changed <;> decide +kernel

private def capacity (tag : Tag) : Nat × Nat :=
  let keys := candidates tag
  (keys.length, (keys.map fun yes => if yes.contains changeActor then 6 else 3).sum)

private theorem pattern_size (tag : Tag) : (tightFor tag).length = (capacity tag).1 := by
  simp only [tightFor,capacity,List.length_map]

private theorem row_size (tag : Tag) : (rowsFor tag).length = (capacity tag).2 := by
  simp only [rowsFor,capacity,List.length_flatMap,List.length_map,endpoints_count]

private theorem sum_sizes {α : Type} (tags : List Tag) (f : Tag → List α)
    (project : Nat × Nat → Nat) (size : ∀ t, (f t).length = project (capacity t)) :
    (tags.flatMap f).length = ((tags.map capacity).map project).sum := by
  rw [List.length_flatMap, List.map_map]
  apply congrArg List.sum
  exact List.map_congr_left (fun t _ => size t)

/-- These are cover sizes, not counts of realizable rows. A pattern admitted
by more than one tag can still be counted more than once. -/
private theorem capacities :
    ActionCover.tags.map capacity =
      [(6,36),(24,126),(324,1782),(6,18),(18,108),(522,3078),
       (132,774),(600,3528),(504,2970),(150,882),(504,2970),(234,1350)] := by
  change [capacity .append,capacity .sendEntries,capacity .timeout,capacity .nominateSuccessor,
    capacity .initAsBackup,capacity .appendEntriesRequest,capacity .appendEntriesResponse,
    capacity .requestVoteRequest,capacity .requestVoteResponse,capacity .requestPreVoteRequest,
    capacity .requestPreVoteResponse,capacity .proposeRequestVoteRequest] = _
  simp only [List.cons.injEq, and_true]
  repeat' apply And.intro
  all_goals decide +kernel

public theorem tight_patterns_size : tightPatterns.length = 3024 := by
  unfold tightPatterns
  exact (sum_sizes ActionCover.tags tightFor Prod.fst pattern_size).trans
    (congrArg (fun xs : List (Nat × Nat) => (xs.map Prod.fst).sum) capacities)

public theorem tight_rows_size : tightRows.length = 17622 := by
  unfold tightRows
  exact (sum_sizes ActionCover.tags rowsFor Prod.snd row_size).trans
    (congrArg (fun xs : List (Nat × Nat) => (xs.map Prod.snd).sum) capacities)

end ConsensusCoverage.ClauseFrontierExact
