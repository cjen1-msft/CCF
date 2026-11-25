module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusObserved
public import ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.GuardedDomain

namespace ConsensusCoverage.CensusRequests

open Consensus Consensus.Model Consensus.Model.Node ReadersShapes

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev Observation := NodeID × Nat × List Entry

/-- The request cut domains need observed terms and logs, not full node
records, past commit indices, queues, or their chronological order. -/
public def requests (seen : List Observation) : List RequestVoteRequest :=
  let terms := seen.map (fun o => maxCommittableTerm o.2.2) ++ seen.map (·.2.1)
  let indices := seen.map (fun o => maxCommittableIndex o.2.2) ++
    seen.flatMap (fun o => GuardedDomain.signatureIndices o.2.2)
  (cuts terms).eraseDups.flatMap fun t => (cuts indices).eraseDups.map fun i => ⟨0, t, i⟩

private theorem map_mem {l r : List α} (same : ∀ a, a ∈ l ↔ a ∈ r) (f : α → β) (b : β) :
    b ∈ l.map f ↔ b ∈ r.map f := by simp only [List.mem_map, same]

private theorem flat_mem {l r : List α} (same : ∀ a, a ∈ l ↔ a ∈ r) (f : α → List β) (b : β) :
    b ∈ l.flatMap f ↔ b ∈ r.flatMap f := by simp only [List.mem_flatMap, same]

private theorem cut_mem {l r : List Nat} (same : ∀ a, a ∈ l ↔ a ∈ r) (v : Nat) :
    v ∈ cuts l ↔ v ∈ cuts r := by simp only [cuts, List.mem_append, List.mem_cons, same, map_mem same]

private theorem congr_mem {l r : List Observation} (same : ∀ a, a ∈ l ↔ a ∈ r) (v : RequestVoteRequest) :
    v ∈ requests l ↔ v ∈ requests r := by
  have terms (n : Nat) : n ∈ (l.map (fun o => maxCommittableTerm o.2.2) ++ l.map (·.2.1)) ↔
      n ∈ (r.map (fun o => maxCommittableTerm o.2.2) ++ r.map (·.2.1)) := by
    simp only [List.mem_append, map_mem same]
  have indices (n : Nat) : n ∈ (l.map (fun o => maxCommittableIndex o.2.2) ++
      l.flatMap (fun o => GuardedDomain.signatureIndices o.2.2)) ↔
      n ∈ (r.map (fun o => maxCommittableIndex o.2.2) ++
      r.flatMap (fun o => GuardedDomain.signatureIndices o.2.2)) := by
    simp only [List.mem_append, map_mem same, flat_mem same]
  simp only [requests, List.mem_flatMap, List.mem_map, List.mem_eraseDups, cut_mem terms, cut_mem indices]

public theorem mem_iff (g : ExplorerGhost.Ghost) (h : List Model.State) (r : RequestVoteRequest)
    (tracks : CensusObserved.Tracks g h) : r ∈ requests g.seen ↔ r ∈ replayRequests h := by
  rw [congr_mem tracks.1]
  simp only [requests, List.map_map, List.flatMap_map, Function.comp_def, CensusObserved.observe,
    replayRequests, requestTerms, requestIndices, historicalTerms, historicalIndices, seenTerms, seenIndices]

end ConsensusCoverage.CensusRequests
