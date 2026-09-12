-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Configuration

set_option autoImplicit false

namespace CCFRaft.Sparse.RetirementScan

variable {N T : Type} [DecidableEq N]

def afterInclusion (node : N) (previouslyIncluded : Bool) (configurations : List (Configuration N)) :
    List (Configuration N) :=
  if previouslyIncluded then configurations
  else configurations.dropWhile (fun configuration => decide (node ∉ configuration.nodes))

theorem first_exclusion_correct (node : N) (previouslyIncluded : Bool)
    (configurations : List (Configuration N)) :
    retirementIndexFromConfigurations node previouslyIncluded configurations =
      ((afterInclusion node previouslyIncluded configurations).find?
        (fun configuration => decide (node ∉ configuration.nodes))).map Configuration.index := by
  induction configurations generalizing previouslyIncluded with
  | nil => cases previouslyIncluded <;> simp [retirementIndexFromConfigurations, afterInclusion]
  | cons configuration rest ih =>
    by_cases member : node ∈ configuration.nodes
    · cases previouslyIncluded <;>
        simp [retirementIndexFromConfigurations, afterInclusion, member, ih]
    · cases previouslyIncluded <;>
        simp [retirementIndexFromConfigurations, afterInclusion, member, ih]

theorem found_survives_append (node : N) (previouslyIncluded : Bool)
    (configurations rest : List (Configuration N)) (index : Nat)
    (found : retirementIndexFromConfigurations node previouslyIncluded configurations = some index) :
    retirementIndexFromConfigurations node previouslyIncluded (configurations ++ rest) = some index := by
  induction configurations generalizing previouslyIncluded with
  | nil => simp [retirementIndexFromConfigurations] at found
  | cons configuration configurations ih =>
    by_cases member : node ∈ configuration.nodes
    · simp only [retirementIndexFromConfigurations, if_pos member] at found
      simpa only [List.cons_append, retirementIndexFromConfigurations, if_pos member] using ih true found
    · cases previouslyIncluded
      · simp only [retirementIndexFromConfigurations, if_neg member, Bool.false_eq_true, if_false] at found
        simpa only [List.cons_append, retirementIndexFromConfigurations, if_neg member,
          Bool.false_eq_true, if_false] using ih false found
      · simpa only [List.cons_append, retirementIndexFromConfigurations, if_neg member] using found

theorem never_included (node : N) (configurations : List (Configuration N))
    (absent : forall configuration, configuration ∈ configurations -> node ∉ configuration.nodes) :
    retirementIndexFromConfigurations node false configurations = none := by
  induction configurations with
  | nil => rfl
  | cons configuration rest ih =>
    have missing := absent configuration (by simp)
    have later : forall configuration, configuration ∈ rest -> node ∉ configuration.nodes := by
      intro configuration member
      exact absent configuration (by simp [member])
    simp [retirementIndexFromConfigurations, missing, ih later]

theorem always_included (node : N) (previouslyIncluded : Bool) (configurations : List (Configuration N))
    (present : forall configuration, configuration ∈ configurations -> node ∈ configuration.nodes) :
    retirementIndexFromConfigurations node previouslyIncluded configurations = none := by
  induction configurations generalizing previouslyIncluded with
  | nil => rfl
  | cons configuration rest ih =>
    have included := present configuration (by simp)
    have later : forall configuration, configuration ∈ rest -> node ∈ configuration.nodes := by
      intro configuration member
      exact present configuration (by simp [member])
    simp [retirementIndexFromConfigurations, included, ih true later]

theorem log_retirement_correct [Bootstrap N] (node : N) (log : List (Entry N T)) :
    retirementIndexInLog node log =
      (((allConfigurations log).dropWhile (fun configuration => decide (node ∉ configuration.nodes))).find?
        (fun configuration => decide (node ∉ configuration.nodes))).map Configuration.index := by
  exact first_exclusion_correct node false (allConfigurations log)

theorem log_found_survives_append [Bootstrap N] (node : N) (log rest : List (Entry N T)) (index : Nat)
    (found : retirementIndexInLog node log = some index) :
    retirementIndexInLog node (log ++ rest) = some index := by
  have configurations : allConfigurations (log ++ rest) =
      allConfigurations log ++ configurationsInLogFrom (1 + log.length) rest := by
    simp [allConfigurations, configurationsInLog, Configuration.configurations_append]
  change retirementIndexFromConfigurations node false (allConfigurations (log ++ rest)) = some index
  rw [configurations]
  exact found_survives_append node false (allConfigurations log) _ index found

theorem signature_after_correct [DecidableEq T] (retirement start : Nat) (log : List (Entry N T)) :
    signatureIndexAfterFrom retirement start log =
      ((log.zipIdx start).find? fun indexed =>
        decide (retirement < indexed.2 /\ indexed.1.content = .signature)).map Prod.snd := by
  induction log generalizing start with
  | nil => rfl
  | cons entry rest ih =>
    by_cases hit : retirement < start /\ entry.content = .signature
    · simp [signatureIndexAfterFrom, List.zipIdx_cons, hit]
    · simp [signatureIndexAfterFrom, List.zipIdx_cons, hit, ih]

def namesRetiredNode (node : N) (entry : Entry N T) : Bool :=
  match entry.content with
  | .retiredCommitted nodes => decide (node ∈ nodes)
  | _ => false

theorem retired_committed_index_correct (node : N) (start : Nat) (log : List (Entry N T)) :
    retiredCommittedIndexFrom node start log =
      ((log.zipIdx start).find? fun indexed => namesRetiredNode node indexed.1).map Prod.snd := by
  induction log generalizing start with
  | nil => rfl
  | cons entry rest ih =>
    cases content : entry.content <;>
      simp [retiredCommittedIndexFrom, List.zipIdx_cons, namesRetiredNode, content, ih]
    split <;> simp_all

theorem committed_nodes_correct (node : N) (commit start : Nat) (log : List (Entry N T)) :
    node ∈ retiredCommittedNodesUpToFrom commit start log <->
      exists indexed, indexed ∈ log.zipIdx start /\ indexed.2 <= commit /\ namesRetiredNode node indexed.1 = true := by
  induction log generalizing start with
  | nil => simp [retiredCommittedNodesUpToFrom]
  | cons entry rest ih =>
    by_cases within : start <= commit
    · cases content : entry.content <;>
        simp [retiredCommittedNodesUpToFrom, List.zipIdx_cons, within, namesRetiredNode, content, ih]
    · simp [retiredCommittedNodesUpToFrom, List.zipIdx_cons, within, ih]

theorem previous_nodes_correct (node : N) (frontier : Nat) (configurations : List (Configuration N))
    (initial : Finset N) :
    node ∈ configurations.foldl
      (fun nodes configuration => if configuration.index < frontier then nodes ∪ configuration.nodes else nodes)
      initial <->
      node ∈ initial \/ exists configuration, configuration ∈ configurations /\
        configuration.index < frontier /\ node ∈ configuration.nodes := by
  induction configurations generalizing initial with
  | nil => simp
  | cons configuration rest ih =>
    by_cases before : configuration.index < frontier
    · simp only [List.foldl_cons, if_pos before, ih, Finset.mem_union, List.mem_cons]
      aesop
    · simp only [List.foldl_cons, if_neg before, ih, List.mem_cons]
      constructor
      · rintro (member | ⟨candidate, member, lower, included⟩)
        · exact Or.inl member
        · exact Or.inr ⟨candidate, Or.inr member, lower, included⟩
      · rintro (member | ⟨candidate, rfl | member, lower, included⟩)
        · exact Or.inl member
        · exact False.elim (before lower)
        · exact Or.inr ⟨candidate, member, lower, included⟩

theorem completed_nodes_correct [Bootstrap N] (node : N) (log : List (Entry N T)) (commit : Nat) :
    node ∈ retirementCompletedNodes log commit <->
      (exists configuration, configuration ∈ allConfigurations log /\
        configuration.index < (currentConfigurationAt log commit).index /\ node ∈ configuration.nodes) /\
      node ∉ (currentConfigurationAt log commit).nodes /\
      node ∉ retiredCommittedNodesUpTo log commit /\
      (retirementIndexInLog node (log.take commit)).isSome = true := by
  simp [retirementCompletedNodes, Finset.mem_filter, Finset.mem_sdiff, previous_nodes_correct, and_assoc]

end CCFRaft.Sparse.RetirementScan

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.RetirementScan).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
