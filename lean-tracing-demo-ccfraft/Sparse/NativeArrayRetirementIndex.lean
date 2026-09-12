-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFirstMatch
import Sparse.NativeArrayLogWrite
import Sparse.RetirementScan

set_option autoImplicit false

namespace CCFRaft.NativeArrayRetirementIndex

open NativeArrayCheckQuorum NativeArrayFirstMatch

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def bootstrapEntry : Entry N T :=
  { term := 0, content := .reconfiguration INITIAL_CONFIGURATION }

def virtualLog (log : Log N T) : Log N T :=
  NativeArrayLogWrite.append (Log.ofList [bootstrapEntry]) log

def configurationPredicate (predicate : Configuration N -> Bool)
    (position : Nat) (entry : Entry N T) : Bool :=
  match entry.content with
  | .reconfiguration nodes => predicate { index := position, nodes }
  | _ => false

def includes (node : N) (position : Nat) (entry : Entry N T) : Bool :=
  configurationPredicate (fun configuration => decide (node ∈ configuration.nodes))
    position entry

def excludesAfter (node : N) (firstIndex position : Nat) (entry : Entry N T) : Bool :=
  configurationPredicate
    (fun configuration => decide (firstIndex < configuration.index /\ node ∉ configuration.nodes))
    position entry

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem configurations_find_index (start : Nat) (entries : List (Entry N T))
    (predicate : Configuration N -> Bool) :
    ((configurationsInLogFrom start entries).find? predicate).map Configuration.index =
      ((entries.zipIdx start).find? fun indexed =>
        configurationPredicate predicate indexed.2 indexed.1).map Prod.snd := by
  induction entries generalizing start with
  | nil => rfl
  | cons entry rest ih =>
    cases content : entry.content <;>
      simp [configurationsInLogFrom, List.zipIdx_cons, configurationPredicate, content, ih]
    case reconfiguration nodes =>
      cases hit : predicate { index := start, nodes } <;>
        simp [configurationPredicate, content, hit, ih]

@[simp] theorem virtual_log_decode (log : Log N T) :
    (virtualLog log).decode = bootstrapEntry :: log.decode := by
  simp [virtualLog, NativeArrayLogWrite.append_correct, bootstrapEntry]

theorem virtual_configurations (log : Log N T) :
    configurationsInLogFrom 0 (virtualLog log).decode = allConfigurations log.decode := by
  simp [allConfigurations, configurationsInLog, implicitConfiguration, bootstrapEntry,
    configurationsInLogFrom]

theorem first_inclusion_correct (log : Log N T) (node : N) (first : Option Nat) :
    FirstMatch (virtualLog log) (includes node) first <->
      ((allConfigurations log.decode).find?
        (fun configuration => decide (node ∈ configuration.nodes))).map Configuration.index = first := by
  rw [first_match_correct]
  change
    (((virtualLog log).decode.zipIdx).find? fun indexed =>
      configurationPredicate (fun configuration => decide (node ∈ configuration.nodes))
        indexed.2 indexed.1).map Prod.snd = first <-> _
  rw [<- configurations_find_index 0]
  simp only [virtual_configurations]

theorem first_exclusion_correct (log : Log N T) (node : N) (firstIndex : Nat)
    (retirement : Option Nat) :
    FirstMatch (virtualLog log) (excludesAfter node firstIndex) retirement <->
      ((allConfigurations log.decode).find? (fun configuration =>
        decide (firstIndex < configuration.index /\ node ∉ configuration.nodes))).map
          Configuration.index = retirement := by
  rw [first_match_correct]
  change
    (((virtualLog log).decode.zipIdx).find? fun indexed =>
      configurationPredicate
        (fun configuration =>
          decide (firstIndex < configuration.index /\ node ∉ configuration.nodes))
        indexed.2 indexed.1).map Prod.snd = retirement <-> _
  rw [<- configurations_find_index 0]
  simp only [virtual_configurations]

theorem retirement_index_correct (log : Log N T) (node : N)
    (first retirement : Option Nat)
    (firstCorrect : FirstMatch (virtualLog log) (includes node) first) :
    (match first with
      | none => retirement = none
      | some firstIndex => FirstMatch (virtualLog log) (excludesAfter node firstIndex) retirement) <->
      retirementIndexInLog node log.decode = retirement := by
  cases first with
  | none =>
    have selected := (first_inclusion_correct log node none).mp firstCorrect
    rw [Sparse.RetirementScan.log_first_removal_from_first_inclusion]
    cases found : (allConfigurations log.decode).find?
        (fun configuration => decide (node ∈ configuration.nodes)) with
    | none => simp [eq_comm]
    | some configuration =>
      rw [found] at selected
      cases selected
  | some firstIndex =>
    have selected := (first_inclusion_correct log node (some firstIndex)).mp firstCorrect
    rw [Sparse.RetirementScan.log_first_removal_from_first_inclusion]
    cases found : (allConfigurations log.decode).find?
        (fun configuration => decide (node ∈ configuration.nodes)) with
    | none =>
      rw [found] at selected
      cases selected
    | some configuration =>
      rw [found] at selected
      have same : configuration.index = firstIndex := by
        exact Option.some.inj selected
      subst firstIndex
      simp only [Option.bind_some]
      exact first_exclusion_correct log node configuration.index retirement

end CCFRaft.NativeArrayRetirementIndex

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayRetirementIndex).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
