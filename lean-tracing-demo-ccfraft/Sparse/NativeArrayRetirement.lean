-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFirstMatch
import Sparse.RetirementScan

set_option autoImplicit false

namespace CCFRaft.NativeArrayRetirement

open NativeArrayCheckQuorum NativeArrayFirstMatch Sparse.RetirementScan

variable {N T : Type} [DecidableEq N]

theorem signature_scan_correct [DecidableEq T] (log : Log N T)
    (retirement : Nat) (position : Option Nat) :
    FirstMatch log (fun index entry => decide (retirement < 1 + index /\ entry.content = .signature)) position <->
      retirementCommittableIndexInLog log.decode retirement = position.map (1 + ·) := by
  rw [retirementCommittableIndexInLog, signature_after_correct]
  exact first_match_shift_correct log (fun index entry => decide (retirement < index /\ entry.content = .signature))
    1 position

theorem retired_index_scan_correct (log : Log N T) (node : N) (position : Option Nat) :
    FirstMatch log (fun _ entry => namesRetiredNode node entry) position <->
      retiredCommittedIndexInLog node log.decode = position.map (1 + ·) := by
  rw [retiredCommittedIndexInLog, retired_committed_index_correct]
  exact first_match_shift_correct log (fun _ entry => namesRetiredNode node entry) 1 position

theorem retired_nodes_correct (log : Log N T) (node : N) (commit : Nat) :
    node ∈ retiredCommittedNodesUpTo log.decode commit <->
      exists position, position < log.length /\ 1 + position <= commit /\
        namesRetiredNode node (log.entries position) = true := by
  rw [retiredCommittedNodesUpTo, committed_nodes_correct, indexed_decode_shift log 1, indexed_decode]
  simp only [List.map_ofFn, List.mem_ofFn]
  constructor
  · rintro ⟨indexed, ⟨position, rfl⟩, committed, named⟩
    exact ⟨position.val, position.isLt, committed, named⟩
  · rintro ⟨position, live, committed, named⟩
    exact ⟨_, ⟨⟨position, live⟩, rfl⟩, committed, named⟩

theorem all_retired_nodes_correct (log : Log N T) (node : N) :
    node ∈ allRetiredCommittedNodes log.decode <->
      exists position, position < log.length /\ namesRetiredNode node (log.entries position) = true := by
  change (node ∈ retiredCommittedNodesUpTo log.decode log.decode.length) <-> _
  rw [retired_nodes_correct]
  simp only [Log.decode, List.length_ofFn]
  constructor
  · rintro ⟨position, live, _, named⟩
    exact ⟨position, live, named⟩
  · rintro ⟨position, live, named⟩
    exact ⟨position, live, by omega, named⟩

end CCFRaft.NativeArrayRetirement

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayRetirement).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
