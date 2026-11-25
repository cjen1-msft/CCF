module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersALeader
import all ConsensusCoverage.HandReadersAObserve

namespace ConsensusCoverage.HandReadersA

open Consensus ActionProfile

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .leader_logs_commit_pos => some (Leader.exactReader true)
  | .leader_logs_commit_neg => some (Leader.exactReader false)
  | .appendEntry_configuration_none => some (Append.exactReader .none)
  | .appendEntry_configuration_some => some (Append.exactReader .some)
  | .foldlM__items_cons => some (Append.exactReader .cons)
  | .observeTerm_log_message_appendEntriesResponse => some (Observe.ackAlias true)
  | .observeTerm_commitIndex_message_appendEntriesResponse => some (Observe.ackAlias false)
  | .observeTerm_log_message_proposeRequestVoteRequest => some (Observe.exactReader true .call)
  | .observeTerm_log_primary_pos => some (Observe.exactReader true .primary)
  | .observeTerm_log_primary_neg => some (Observe.exactReader true .backup)
  | .observeTerm_log_newer_pos => some (Observe.exactReader true .higher)
  | .observeTerm_log_newer_neg => some (Observe.exactReader true .stable)
  | .observeTerm_log_message_other => some (Observe.exactReader true .other)
  | .observeTerm_commitIndex_message_proposeRequestVoteRequest => some (Observe.exactReader false .call)
  | .observeTerm_commitIndex_primary_pos => some (Observe.exactReader false .primary)
  | .observeTerm_commitIndex_primary_neg => some (Observe.exactReader false .backup)
  | .observeTerm_commitIndex_newer_pos => some (Observe.exactReader false .higher)
  | .observeTerm_commitIndex_newer_neg => some (Observe.exactReader false .stable)
  | .observeTerm_commitIndex_message_other => some (Observe.exactReader false .other)
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
    (read s.cfg s.before s.act s.after s.past b).isSome := by
  simpa only [read, Option.isSome_map] using (List.mem_filter.mp h).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 19 := by decide +kernel

end ConsensusCoverage.HandReadersA
