-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFirstMatch
import Sparse.NativeArrayConfiguration
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

def PreviouslyIncluded [Bootstrap N] (log : Log N T) (frontier : Nat) (node : N) : Prop :=
  (0 < frontier /\ node ∈ INITIAL_CONFIGURATION) \/
    exists index nodes, index < frontier /\ Reconfiguration log index nodes /\ node ∈ nodes

theorem previously_included_correct [DecidableEq T] [Bootstrap N]
    (log : Log N T) (frontier : Nat) (node : N) :
    PreviouslyIncluded log frontier node <->
      exists configuration, configuration ∈ allConfigurations log.decode /\
        configuration.index < frontier /\ node ∈ configuration.nodes := by
  constructor
  · rintro (⟨before, member⟩ | ⟨index, nodes, before, physical, member⟩)
    · exact ⟨implicitConfiguration, by simp [allConfigurations], before, member⟩
    · refine ⟨{ index, nodes }, ?_, before, member⟩
      apply List.mem_cons_of_mem
      rw [Sparse.ConfigurationSnapshot.mem_configurations_iff]
      exact (reconfiguration_correct log index nodes).mp physical
  · rintro ⟨configuration, member, before, included⟩
    simp only [allConfigurations, List.mem_cons] at member
    rcases member with implicit | physical
    · subst configuration
      exact Or.inl ⟨before, included⟩
    · refine Or.inr ⟨configuration.index, configuration.nodes, before, ?_, included⟩
      apply (reconfiguration_correct log _ _).mpr
      rw [Sparse.ConfigurationSnapshot.mem_configurations_iff] at physical
      exact physical

theorem completed_nodes_from_scans_correct [DecidableEq T] [Bootstrap N]
    (log : Log N T) (commit current : Nat) (members : Finset N) (node : N)
    (currentIndex : CurrentIndex log commit current)
    (configuration : NativeArrayConfiguration.At log current members) :
    node ∈ retirementCompletedNodes log.decode commit <->
      PreviouslyIncluded log current node /\ node ∉ members /\
      (forall position, position < log.length -> 1 + position <= commit ->
        namesRetiredNode node (log.entries position) = false) /\
      (retirementIndexInLog node (log.decode.take commit)).isSome = true := by
  have selected := (NativeArrayConfiguration.current_configuration_correct log commit current members).mp
    ⟨currentIndex, configuration⟩
  rw [completed_nodes_correct, selected, <- previously_included_correct, retired_nodes_correct]
  simp only [not_exists, not_and, Bool.not_eq_true]

def refresh (row : Local N T) (retirement signature retired : Option Nat) : Local N T :=
  let committedRetired := retired.filter fun index => index <= row.commit
  let membershipState := match retirement with
    | none => MembershipState.active
    | some index =>
      if committedRetired.isSome then .retiredCommitted
      else if index <= row.commit then .retirementCompleted
      else if signature.isSome then .retirementSigned
      else .retirementOrdered
  { row with
    membershipState
    retirementIndex := retirement
    retirementCommittableIndex := signature
    retiredCommittedIndex := committedRetired }

theorem refresh_correct [DecidableEq T] [Bootstrap N] (row : Local N T) (node : N)
    (retirement signature retired : Option Nat)
    (retirementCorrect : retirementIndexInLog node row.log.decode = retirement)
    (signatureCorrect : retirement.bind (retirementCommittableIndexInLog row.log.decode) = signature)
    (retiredCorrect : retiredCommittedIndexInLog node row.log.decode = retired) :
    (refresh row retirement signature retired).toModel = refreshRetirementState node row.toModel := by
  simp [refresh, refreshRetirementState, Local.toModel, retirementCorrect, signatureCorrect, retiredCorrect]
  cases retirement <;> rfl

theorem refresh_from_scans_correct [DecidableEq T] [Bootstrap N] (row : Local N T) (node : N)
    (retirement signaturePosition retiredPosition : Option Nat)
    (retirementCorrect : retirementIndexInLog node row.log.decode = retirement)
    (signatureCorrect : match retirement with
      | none => signaturePosition = none
      | some index => FirstMatch row.log
          (fun position entry => decide (index < 1 + position /\ entry.content = .signature)) signaturePosition)
    (retiredCorrect : FirstMatch row.log (fun _ entry => namesRetiredNode node entry) retiredPosition) :
    (refresh row retirement (signaturePosition.map (1 + ·)) (retiredPosition.map (1 + ·))).toModel =
      refreshRetirementState node row.toModel := by
  apply refresh_correct row node retirement _ _ retirementCorrect
  · cases retirement with
    | none => simp_all
    | some index =>
      exact (signature_scan_correct row.log index signaturePosition).mp signatureCorrect
  · exact (retired_index_scan_correct row.log node retiredPosition).mp retiredCorrect

end CCFRaft.NativeArrayRetirement

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayRetirement).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
