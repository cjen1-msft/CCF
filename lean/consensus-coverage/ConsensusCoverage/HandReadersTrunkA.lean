module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkAPackets
import all ConsensusCoverage.HandReadersTrunkAConflict
import all ConsensusCoverage.HandReadersTrunkARest
import all ConsensusCoverage.HandReadersTrunkALoop
import all ConsensusCoverage.HandReadersTrunkAAdvance

namespace ConsensusCoverage.HandReadersTrunkA

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .appendEntry_batch_peers_none => some Batch.peersNone
  | .appendEntry_batch_peers_some => some Batch.peersSome
  | .appendEntry_batch_mem_append_inl => some Batch.entryOld
  | .appendEntry_batch_mem_append_inr => some Batch.entryNew
  | .sendEntries_batch_mem_append_inl => some Batch.sendOld
  | .sendEntries_batch_mem_append_inr => some Batch.sendNew
  | .push_mem_append_inl => some Batch.pushOld
  | .push_mem_append_inr => some Batch.pushNew
  | .foldlM__items_nil_2 => some Batch.foldNil
  | .foldlM__items_cons_2 => some Batch.foldCons
  | .aeReply_conflict_none => some (Request.conflictReader false)
  | .aeReply_conflict_some => some (Request.conflictReader true)
  | .aeReply_summary_rest_inl => some (Request.restReader false)
  | .aeReply_summary_rest_inr => some (Request.restReader true)
  | .fromLeader_loop_entries_nil => some Loop.nilCase
  | .fromLeader_loop_entries_cons => some Loop.cons
  | .fromLeader_loop_signature_pos => some Loop.signature
  | .fromLeader_loop_signature_neg => some Loop.transaction
  | .fromLeader_loop_roleCase_inl => some Loop.sameRole
  | .fromLeader_loop_roleCase_inr => some Loop.noneRole
  | .commit_le_advance_inl => some Batch.commitIdentity
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

public theorem read_total (s : Step) {b} (mem : b ∈ covered) :
    (read s.cfg s.before s.act s.after s.past b).isSome = true := by
  simpa only [read, Option.isSome_map] using (List.mem_filter.mp mem).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 21 := by decide +kernel

end ConsensusCoverage.HandReadersTrunkA
