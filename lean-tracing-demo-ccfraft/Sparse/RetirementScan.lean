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

end CCFRaft.Sparse.RetirementScan

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.RetirementScan).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
