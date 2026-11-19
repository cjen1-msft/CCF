module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FrontierRows
public import ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.PairWitnesses

namespace ConsensusCoverage.LeaderWitnesses

open Consensus Consensus.Model Consensus.Model.Node

public abbrev Key := FrontierRows.Row × Bool

@[expose] public def read (cfg : CCF.Finset NodeID) (s t : Model.State)
    (past : List Model.State) : Key :=
  (FrontierRows.historyLabel cfg s t past, LeaderEffect.changedPrimary s t)

@[expose] public def Occurs (key : Key) : Prop :=
  ∃ (cfg : CCF.Finset NodeID) (nodes : List NodeID) (s t : Model.State)
    (past : List Model.State) (act : Model.Action), StateCoverage.Run cfg nodes s past ∧
      (transitionSystem cfg nodes).step s act = some t ∧ read cfg s t past = key

@[expose] public def MultiOccurs (key : Key) : Prop :=
  ∃ (cfg : CCF.Finset NodeID) (nodes : List NodeID) (s t : Model.State)
    (past : List Model.State) (act : Model.Action),
      (∃ i ∈ nodes, ∃ j ∈ nodes, i ≠ j) ∧ StateCoverage.Run cfg nodes s past ∧
      (transitionSystem cfg nodes).step s act = some t ∧ read cfg s t past = key

open FrontierRows

private def recorded (r : FrontierRows.Run) : Option (List Key) :=
  replay read r (initial r) [] r.schedule

/-- Select just the steps that supply a new key. Every scheduled action still
has to succeed for this check to return any keys. -/
private def selected (r : FrontierRows.Run) (indices : List Nat) : Option (List Key) :=
  (recorded r).map fun keys =>
    indices.filterMap fun i => keys[i]?

private theorem selected_occurs {r : FrontierRows.Run} (valid : r.valid) {indices keys}
    {P : Key → Prop} (check : selected r indices = some keys)
    (lift : ∀ {s t past act}, StateCoverage.Run r.cfg r.nodes s past →
      (transitionSystem r.cfg r.nodes).step s act = some t → P (read r.cfg s t past)) :
    ∀ key ∈ keys, P key := by
  obtain ⟨observed, replayed, rfl⟩ := Option.map_eq_some_iff.mp check
  intro key mem
  obtain ⟨i, _, found⟩ := List.mem_filterMap.mp mem
  exact replay_sound (.initial (initialized r valid)) lift replayed key
    (List.mem_of_getElem? found)

private theorem selected_multi_occurs {r : FrontierRows.Run} (valid : r.valid)
    (multi : ∃ i ∈ r.nodes, ∃ j ∈ r.nodes, i ≠ j) {indices keys}
    (check : selected r indices = some keys) : ∀ key ∈ keys, MultiOccurs key :=
  selected_occurs valid check fun {s t past act} run step =>
    ⟨r.cfg, r.nodes, s, t, past, act, multi, run, step, rfl⟩

private theorem frontier_multi_occurs {i : Nat} (hi : i < runs.length)
    (multi : ∃ a ∈ runs[i].nodes, ∃ b ∈ runs[i].nodes, a ≠ b) {indices keys}
    (check : selected runs[i] indices = some keys) : ∀ key ∈ keys, MultiOccurs key :=
  selected_multi_occurs (valid_runs _ (List.getElem_mem hi)) multi check

private def extraNode : FrontierRows.Run := ⟨{0}, [0, 1], [signature]⟩

-- Append again after the first commit index has reached both replicas.
private def committedAppend : FrontierRows.Run :=
  { runs[2] with schedule := runs[2].schedule.take 6 ++ [signature] }

-- Elect node 1 before it learns node 0's commit index. The final ack advances
-- node 1's index from zero while node 0's is already positive.
private def laggingSuccessor : FrontierRows.Run :=
  ⟨{0, 1}, [0, 1],
    [signature, .input 0 (.sendEntries 1 2), .deliver 0 1, .deliver 1 0, stepDown] ++
      election 1 0 ++
    [.input 1 (.append [{content := .signature}]), .input 1 (.sendEntries 0 3),
      .deliver 1 0, .deliver 0 1, .deliver 1 0, .deliver 0 1]⟩

/-- Keys in replay order, including repeats, from the six multi-node witness
schedules. A disabled action in any schedule fails the entire replay. -/
public def multiWitnessRows : Option (List Key) :=
  ([extraNode, committedAppend, runs[1], runs[2], runs[3], laggingSuccessor].mapM recorded).map
    List.flatten

/-- The first backing appears on the same step as the last zero index goes away. -/
public abbrev soloCommitKey : Key := (⟨true, false, false, false, true⟩, true)

/-- Distinct concrete keys from initialized runs; this table asserts no exclusion. -/
@[expose] public def table : List Key :=
  [-- Single voter with an extra deployed node
   (⟨true, false, false, true, true⟩, true),
   -- Solo commit and an append after both replicas have committed
   soloCommitKey, (⟨false, true, false, false, true⟩, true),
   -- Re-election before backing
   (⟨true, false, false, true, false⟩, true), (⟨true, false, false, true, false⟩, false),
   (⟨true, false, true, true, false⟩, true),
   -- Replication and election after commit
   (⟨true, false, false, true, true⟩, false), (⟨true, true, false, true, true⟩, true),
   (⟨true, true, false, true, true⟩, false), (⟨true, true, false, false, true⟩, false),
   (⟨false, true, false, false, true⟩, false), (⟨false, true, true, false, true⟩, true),
   -- Election with a spare node, then commit with a lagging successor
   (⟨true, true, true, true, true⟩, true), (⟨true, true, false, false, true⟩, true)]

public theorem table_count : table.Nodup ∧ table.length = 14 := by decide

private def chunk (start size : Nat) : List Key := (table.drop start).take size

private theorem extraNode_ok : selected extraNode [0] = some (chunk 0 1) := by decide +kernel
private theorem solo_ok : selected runs[0] [0] = some [soloCommitKey] := by decide +kernel

set_option maxRecDepth 8192 in
private theorem committedAppend_ok : selected committedAppend [6] = some (chunk 2 1) := by
  decide +kernel

set_option maxRecDepth 8192 in
private theorem elect_ok : selected runs[1] [0, 1, 6] = some (chunk 3 3) := by decide +kernel

set_option maxRecDepth 8192 in
private theorem commit_ok : selected runs[2] [2, 3, 4, 5, 6, 12] = some (chunk 6 6) := by
  decide +kernel

set_option maxRecDepth 8192 in
private theorem spareNode_ok : selected runs[3] [12] = some (chunk 12 1) := by decide +kernel

set_option maxRecDepth 8192 in
private theorem successor_ok : selected laggingSuccessor [15] = some (chunk 13 1) := by
  decide +kernel

/-- All keys except `soloCommitKey` have witnesses with two distinct deployed IDs. -/
public theorem table_occurs_multi {key : Key} (mem : key ∈ table)
    (other : key ≠ soloCommitKey) : MultiOccurs key := by
  have mem := (List.mem_erase_of_ne other).2 mem
  change key ∈ [chunk 0 1, chunk 2 1, chunk 3 3, chunk 6 6, chunk 12 1, chunk 13 1].flatten at mem
  obtain ⟨group, member, seen⟩ := List.mem_flatten.mp mem
  simp only [List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl
  · exact selected_multi_occurs (by unfold FrontierRows.Run.valid; decide)
      (by decide) extraNode_ok _ seen
  · exact selected_multi_occurs (by unfold FrontierRows.Run.valid; decide)
      (by decide) committedAppend_ok _ seen
  · exact frontier_multi_occurs (by decide : 1 < runs.length) (by decide) elect_ok _ seen
  · exact frontier_multi_occurs (by decide : 2 < runs.length) (by decide) commit_ok _ seen
  · exact frontier_multi_occurs (by decide : 3 < runs.length) (by decide) spareNode_ok _ seen
  · exact selected_multi_occurs (by unfold FrontierRows.Run.valid; decide)
      (by decide) successor_ok _ seen

/-- Each key has an initialized run and a successful concrete action witnessing it. -/
public theorem table_occurs {key : Key} (mem : key ∈ table) : Occurs key := by
  by_cases solo : key = soloCommitKey
  · subst key
    exact selected_occurs (P := Occurs) (valid_runs _ (List.getElem_mem (by decide)))
      solo_ok (fun run step => ⟨_, _, _, _, _, _, run, step, rfl⟩) _ (by decide)
  · obtain ⟨cfg, nodes, s, t, past, act, _, run, step, eq⟩ := table_occurs_multi mem solo
    exact ⟨cfg, nodes, s, t, past, act, run, step, eq⟩

end ConsensusCoverage.LeaderWitnesses
