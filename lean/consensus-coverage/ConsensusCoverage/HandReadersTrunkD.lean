module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersTrunkDTerm
import all ConsensusCoverage.HandReadersTrunkDTable
import all ConsensusCoverage.HandReadersTrunkDSignature
import all ConsensusCoverage.HandReadersTrunkDAtZero
import all ConsensusCoverage.HandReadersTrunkDRecord
import all ConsensusCoverage.HandReadersTrunkDNominate
import all ConsensusCoverage.HandReadersTrunkDCondition

namespace ConsensusCoverage.HandReadersTrunkD

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .term_advance_inl => some (Term.exactReader false)
  | .term_advance_inr => some (Term.exactReader true)
  | .termAt_take_zero_pos => some Prefix.zero
  | .ite__condition_pos_2 => some (Condition.exactReader true)
  | .ite__condition_neg_2 => some (Condition.exactReader false)
  | .recordCommit_eq_retire_pos => some (Record.exactReader true)
  | .recordCommit_eq_retire_neg => some (Record.exactReader false)
  | .nominate_sends_successor_some => some (Nominate.exactReader true)
  | .nominate_sends_successor_none => some (Nominate.exactReader false)
  | .mem_replaceNode_here_pos => some (Table.exactReader true)
  | .mem_replaceNode_here_neg => some (Table.exactReader false)
  | .signatureIndex_le_maxCommittableIndex_values_nil => some (Signed.exactReader .nil)
  | .signatureIndex_le_maxCommittableIndex_values_cons => some (Signed.exactReader .cons)
  | .signatureIndex_le_maxCommittableIndex_mem_cons_inl => some (Signed.exactReader .head)
  | .signatureIndex_le_maxCommittableIndex_mem_cons_inr => some (Signed.exactReader .tail)
  | .signatureIndex_le_maxCommittableIndex_signature_pos => some (Signed.exactReader .signed)
  | .signatureIndex_le_maxCommittableIndex_signature_neg => some (Signed.exactReader .unsigned)
  | _ => none

public def covered : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter fun b => (lookup b).isSome

public def read (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) (b : Classes.StepBranch) : Option Bool :=
  (lookup b).map fun r => r.eval cfg before act after past

public theorem read_correct (s : Step) {b v} (h : read s.cfg s.before s.act s.after s.past b = some v) :
    label s (.step b) = v := by
  obtain ⟨r,_,rfl⟩ := Option.map_eq_some_iff.mp h
  exact r.eq_label s

public theorem read_total (s : Step) {b} (h : b ∈ covered) :
    (read s.cfg s.before s.act s.after s.past b).isSome = true := by
  simpa only [read, Option.isSome_map] using (List.mem_filter.mp h).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 17 := by decide +kernel

end ConsensusCoverage.HandReadersTrunkD
