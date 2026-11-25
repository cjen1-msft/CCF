module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseLogCluster
public import ConsensusCoverage.ClauseLogClusterReplayA
public import ConsensusCoverage.ClauseLogClusterReplayB
public import ConsensusCoverage.ClauseLogClusterReplayC
public import ConsensusCoverage.ClauseLogClusterReplayD
public import ConsensusCoverage.ClauseLogClusterReplayE
public import ConsensusCoverage.ClauseLogClusterRoutes
import all ConsensusCoverage.ClauseLogCluster
import all ConsensusCoverage.ClauseLogClusterReplay
import all ConsensusCoverage.ClauseLogClusterReplayA
import all ConsensusCoverage.ClauseLogClusterReplayB
import all ConsensusCoverage.ClauseLogClusterReplayC
import all ConsensusCoverage.ClauseLogClusterReplayD
import all ConsensusCoverage.ClauseLogClusterReplayE
import all ConsensusCoverage.ClauseLogClusterRoutes
import all ConsensusCoverage.HandReadersElectionBPrefixAccept
import all ConsensusCoverage.HandReadersElectionBPrefixCopies
import all ConsensusCoverage.HandReadersElectionBPrefixDirect
import all ConsensusCoverage.HandReadersElectionBPrefixLogs
meta import Lean

namespace ConsensusCoverage.ClauseLogCluster.Witnesses

open ActionProfile ClauseQuestions Replay

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option pp.maxSteps 150
set_option Elab.async false

private def samples : List Sample := batchA ++ batchB ++ batchC ++ batchD ++ batchE

private def common := List.range' 25 22 ++ List.range' 49 10

private def columnPositions : Clause → List Nat
  | .sorted => List.range' 7 5 ++ common
  | .terms => List.range 7 ++ common
  | .anchor => List.range' 12 7 ++ common
  | .rooted => List.range' 19 5 ++ List.range' 25 22 ++ List.range' 47 12
  | .copyLogs => List.range 59
  | c => (nonTrunk c).map ((nonTrunk .copyLogs).idxOf ·)

private theorem columnPositions_eq {c : Clause} (hc : c ∈ clauses) :
    columnPositions c = (nonTrunk c).map ((nonTrunk .copyLogs).idxOf ·) := by
  have check : clauses.all (fun c =>
      columnPositions c == (nonTrunk c).map ((nonTrunk .copyLogs).idxOf ·)) = true := by decide +kernel
  exact beq_iff_eq.mp (List.all_eq_true.mp check c hc)

private def projectFast (c : Clause) (r : RestrictedProfile) : RestrictedProfile :=
  ⟨r.pre, (columnPositions c).map fun i => r.bits[i]?.getD false, r.post⟩

private theorem projectFast_eq {c : Clause} (hc : c ∈ clauses) (r : RestrictedProfile) :
    projectFast c r = project c r := by
  simp only [projectFast, project, columnPositions_eq hc, List.map_map]
  rfl

/-- The first representative of each observed value. These are sample
indices, not Lean proof-caller or question IDs. -/
private def rowPicks : Clause → List Nat
  | .sorted | .terms | .anchor => List.range 32 ++ [33,34]
  | .rooted | .copyLogs => List.range 35
  | _ => []

private def patternPicks : Clause → List Nat
  | .sorted => [0,2,3,4,5,6,7,8,10,11,12,13,14,18,27,28,29,33,34]
  | .terms | .anchor => [0,3,4,5,6,7,8,9,10,11,12,13,14,18,24,27,28,29,33]
  | .rooted => [0,2,3,4,5,6,7,8,10,11,12,13,14,18,27,28,29,32,33,34]
  | .copyLogs => [0,2,3,4,5,6,7,8,9,10,11,12,13,14,18,24,27,28,29,32,33,34]
  | _ => []

private def projected (c : Clause) (source : List Sample) (picks : List Nat) :
    List RestrictedProfile :=
  picks.filterMap fun i => source[i]?.map fun s => projectFast c s.val

private theorem projected_realized {c : Clause} (hc : c ∈ clauses) {source : List Sample}
    {picks : List Nat} {r : RestrictedProfile} (hr : r ∈ projected c source picks) :
    ∃ s : Step, nonTrunkLabel c s = r := by
  obtain ⟨_,_,hit⟩ := List.mem_filterMap.mp hr
  obtain ⟨sample, _, eq⟩ := Option.map_eq_some_iff.mp hit
  obtain ⟨s, hs⟩ := sample.property
  exact ⟨s, (project_label hc s).symm.trans
    ((congrArg (project c) hs).trans ((projectFast_eq hc _).symm.trans eq))⟩

private def vectorKey (bs : List Bool) : Nat := bs.foldl (fun n b => 2*n + b.toNat) 0
private def rowKey (r : RestrictedProfile) : Nat :=
  vectorKey ([r.pre.1,r.pre.2] ++ r.bits ++ [r.post.1,r.post.2])

private theorem nodup_of_key {xs : List α} {key : α → β} (h : (xs.map key).Nodup) : xs.Nodup :=
  (List.pairwise_map.mp h).imp fun unequal eq => unequal (congrArg key eq)

public def rows (c : Clause) : List RestrictedProfile :=
  projected c samples (rowPicks c)

public def patterns (c : Clause) : List (List Bool) :=
  (projected c samples (patternPicks c)).map RestrictedProfile.bits

public theorem rows_realized {c : Clause} (hc : c ∈ clauses) {r : RestrictedProfile}
    (hr : r ∈ rows c) : ∃ s : Step, nonTrunkLabel c s = r :=
  projected_realized hc hr

public theorem patterns_realized {c : Clause} (hc : c ∈ clauses) {p : List Bool}
    (hp : p ∈ patterns c) : ∃ s : Step, (nonTrunkLabel c s).bits = p := by
  obtain ⟨r, hr, eq⟩ := List.mem_map.mp hp
  obtain ⟨s, hs⟩ := projected_realized hc hr
  exact ⟨s, (congrArg RestrictedProfile.bits hs).trans eq⟩

public theorem sorted_count : (patterns .sorted).length = 19 ∧ (rows .sorted).length = 34 :=
  by decide +kernel

public theorem terms_count : (patterns .terms).length = 19 ∧ (rows .terms).length = 34 :=
  by decide +kernel

public theorem anchor_count : (patterns .anchor).length = 19 ∧ (rows .anchor).length = 34 :=
  by decide +kernel

public theorem rooted_count : (patterns .rooted).length = 20 ∧ (rows .rooted).length = 35 :=
  by decide +kernel

public theorem copyLogs_count : (patterns .copyLogs).length = 22 ∧ (rows .copyLogs).length = 35 :=
  by decide +kernel

private def sortedSlice (r : RestrictedProfile) : List Bool :=
  r.bits.take 5

private theorem sortedSlice_eq (s : Step) :
    sortedSlice (nonTrunkLabel .sorted s) = Routes.sortedActorBits s := by
  have columns : (nonTrunk .sorted).take 5 = Routes.sortedColumns := by decide +kernel
  change ((nonTrunk .sorted).map fun b => label s (.step b)).take 5 = Routes.sortedActorBits s
  simp only [← List.map_take, columns, Routes.sortedActorBits]

private theorem sortedSlice_checked :
    Routes.sortedActorPatterns.all ((rows .sorted).map sortedSlice).contains = true :=
  by decide +kernel

/-- On the five sorted-specific proof questions, all nine and only those
nine vectors occur. The other 32 non-trunk questions are not projected here. -/
public theorem sorted_actor_exact (p : List Bool) :
    p ∈ Routes.sortedActorPatterns ↔ ∃ s : Step, Routes.sortedActorBits s = p := by
  constructor
  · intro mem
    have hit := List.contains_iff_mem.mp (List.all_eq_true.mp sortedSlice_checked p mem)
    obtain ⟨r, hr, eq⟩ := List.mem_map.mp hit
    obtain ⟨s, hs⟩ := rows_realized (c := .sorted) (by decide) hr
    exact ⟨s, (sortedSlice_eq s).symm.trans ((congrArg sortedSlice hs).trans eq)⟩
  · rintro ⟨s,rfl⟩
    exact Routes.sortedActorBits_complete s

public theorem rooted_actor_exact (p : List Bool) :
    p ∈ Routes.sortedActorPatterns ↔ ∃ s : Step, (Routes.rootedColumns.map fun b => label s (.step b)) = p := by
  simp only [Routes.rootedActorBits_eq]
  exact sorted_actor_exact p

/-- Snapshot installs on the last zero-index node and on one of several
zero-index nodes both occur, with the same log bits. -/
private def installs : List Sample := [
  sample! 25 2 3 "10000101001010000101001000000000001000000000000110000000000" 1,
  sample! 83 8 3 "10000101001010000101001000000000001000000000000110000000000" 3]

public def lowerRows (c : Clause) : List RestrictedProfile :=
  rows c ++ projected c installs [0,1]

public def lowerPatterns (c : Clause) : List (List Bool) :=
  patterns c ++ (projected c installs [0]).map RestrictedProfile.bits

private def keys (c : Clause) : List Nat × List Nat :=
  ((lowerPatterns c).map vectorKey, (lowerRows c).map rowKey)

open Lean Meta Elab Term in
local elab "keyTable%" : term => do
  let value ← elabTerm (← `(clauses.map keys)) none
  withTransparency .all <| reduce value

/-- Check the packed keys against the replayed rows once. Pairwise distinctness
then compares only integers; it does not decode the rows on every comparison. -/
private def keyTable : List (List Nat × List Nat) := keyTable%

private theorem keyTable_eq : keyTable = clauses.map keys := by decide +kernel

private theorem keyTable_nodup : ∀ r ∈ keyTable, r.1.Nodup ∧ r.2.Nodup := by decide +kernel

public theorem lower_nodup {c : Clause} (hc : c ∈ clauses) :
    (lowerPatterns c).Nodup ∧ (lowerRows c).Nodup := by
  have mem : keys c ∈ keyTable := by
    rw [keyTable_eq]
    exact List.mem_map_of_mem (f := keys) hc
  have checked := keyTable_nodup _ mem
  exact ⟨nodup_of_key checked.1, nodup_of_key checked.2⟩

public theorem nodup {c : Clause} (hc : c ∈ clauses) : (patterns c).Nodup ∧ (rows c).Nodup :=
  ⟨(List.nodup_append.mp (lower_nodup hc).1).1, (List.nodup_append.mp (lower_nodup hc).2).1⟩

public theorem lowerRows_realized {c : Clause} (hc : c ∈ clauses) {r : RestrictedProfile}
    (hr : r ∈ lowerRows c) : ∃ s : Step, nonTrunkLabel c s = r := by
  exact (List.mem_append.mp hr).elim (rows_realized hc) (projected_realized hc)

public theorem lowerPatterns_realized {c : Clause} (hc : c ∈ clauses) {p : List Bool}
    (hp : p ∈ lowerPatterns c) : ∃ s : Step, (nonTrunkLabel c s).bits = p := by
  rcases List.mem_append.mp hp with base | new
  · exact patterns_realized hc base
  · obtain ⟨r, hr, eq⟩ := List.mem_map.mp new
    obtain ⟨s, hs⟩ := projected_realized hc hr
    exact ⟨s, (congrArg RestrictedProfile.bits hs).trans eq⟩

public theorem lower_counts :
    clauses.map (fun c => ((lowerPatterns c).length, (lowerRows c).length)) =
      [(20,36),(20,36),(20,36),(21,37),(23,37)] := by decide +kernel

public def remaining (c : Clause) : List RestrictedProfile :=
  (Routes.upper c).filter (fun r => !(lowerRows c).contains r)

public theorem unresolved_complete {c : Clause} (hc : c ∈ clauses) (s : Step) :
    nonTrunkLabel c s ∈ lowerRows c ∨ nonTrunkLabel c s ∈ remaining c := by
  by_cases h : nonTrunkLabel c s ∈ lowerRows c
  · exact .inl h
  · right
    apply List.mem_filter.mpr
    refine ⟨Routes.upper_complete hc s, ?_⟩
    rw [Bool.not_eq_true', ← Bool.not_eq_true, List.contains_iff_mem]
    exact h

end ConsensusCoverage.ClauseLogCluster.Witnesses
