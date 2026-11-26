module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallBMessageTerms
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseSmallBMessageTerms
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseSmallB.MessageCorpusRows

open ActionProfile ClauseQuestions

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

private def additional : List Pick :=
  [(row (b, b) (bits "00000011101001"), 178, 14),
    (row (p, p) (bits "11000011001001"), 132, 6),
    (row (b, b) (bits "11000011001001"), 141, 6),
    (row (p, p) (bits "11000011100101"), 179, 18),
    (row (p, p) (bits "11000011101001"), 181, 20),
    (row (b, b) (bits "11000011101001"), 121, 9)]

/-- One initialized witness for each row observed by a complete corpus scan. -/
public def rows : List RestrictedProfile := MessageTerms.rows ++ additional.map Prod.fst

public def patterns : List (List Bool) := patternsOf rows

public theorem count :
    rows.Nodup ∧ rows.length = 57 ∧ patterns.Nodup ∧ patterns.length = 21 := by
  decide +kernel

private theorem checked : additional.all (checkPick .message_terms) = true :=
  all_split 3 (by decide +kernel) (by decide +kernel)

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel .message_terms s = r := by
  rcases List.mem_append.mp mem with earlier | extra
  · exact MessageTerms.lower r earlier
  · exact replay_picks (covered_of_check (by decide +kernel)) checked extra

public theorem patterns_lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s, (nonTrunkLabel .message_terms s).bits = bs :=
  pattern_witness lower mem

public def unresolvedRows : List RestrictedProfile := unresolved MessageTerms.upperRows rows

public theorem covered_or_unresolved (s : Step) :
    nonTrunkLabel .message_terms s ∈ rows ∨ nonTrunkLabel .message_terms s ∈ unresolvedRows :=
  witnessed_or_unresolved (MessageTerms.complete s)

end ConsensusCoverage.ClauseSmallB.MessageCorpusRows
