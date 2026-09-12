-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayRetirement
import Sparse.NativeArrayRetirementIndex

set_option autoImplicit false

namespace CCFRaft.NativeArrayRetirementCompleted

open NativeArrayCheckQuorum NativeArrayFirstMatch

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem first_match_before_iff (log : Log N T)
    (predicate : Nat -> Entry N T -> Bool) (choice : Option Nat)
    (frontier : Nat) (frontierBound : frontier <= log.length)
    (correct : FirstMatch log predicate choice) :
    (exists index, index < frontier /\ predicate index (log.entries index) = true) <->
      exists first, choice = some first /\ first < frontier := by
  cases choice with
  | none =>
    constructor
    · rintro ⟨index, before, hit⟩
      have missing := correct index (by omega)
      simp_all
    · rintro ⟨_, impossible, _⟩
      contradiction
  | some first =>
    rcases correct with ⟨live, hit, earlier⟩
    constructor
    · rintro ⟨index, before, observed⟩
      refine ⟨first, rfl, ?_⟩
      by_contra tooLate
      have missing := earlier index (by omega)
      simp_all
    · rintro ⟨selected, same, before⟩
      have sameIndex := Option.some.inj same
      subst selected
      exact ⟨first, before, hit⟩

omit [DecidableEq T] in
theorem virtual_take_entry_of_pos (log : Log N T) (commit index : Nat)
    (positive : 0 < index) :
    (NativeArrayRetirementIndex.virtualLog
      (NativeArrayLogWrite.take log commit)).entries index =
        log.entries (index - 1) := by
  simp [NativeArrayRetirementIndex.virtualLog, NativeArrayLogWrite.append,
    NativeArrayLogWrite.take, NativeArrayCheckQuorum.Log.ofList, Nat.ne_of_gt positive]

omit [DecidableEq T] in
theorem previously_included_prefix_hit (log : Log N T) (commit current : Nat)
    (node : N) (currentBound : current <= min commit log.length) :
    NativeArrayRetirement.PreviouslyIncluded log current node <->
      exists index, index < current /\
        NativeArrayRetirementIndex.includes node index
          ((NativeArrayRetirementIndex.virtualLog
            (NativeArrayLogWrite.take log commit)).entries index) = true := by
  constructor
  · rintro (⟨before, member⟩ | ⟨index, nodes, before, physical, member⟩)
    · refine ⟨0, before, ?_⟩
      simp [NativeArrayRetirementIndex.virtualLog,
        NativeArrayRetirementIndex.includes,
        NativeArrayRetirementIndex.configurationPredicate,
        NativeArrayRetirementIndex.bootstrapEntry,
        NativeArrayLogWrite.append, NativeArrayCheckQuorum.Log.ofList, member]
    · refine ⟨index, before, ?_⟩
      rcases physical with ⟨positive, within, content⟩
      rw [virtual_take_entry_of_pos log commit index positive]
      simp [NativeArrayRetirementIndex.includes,
        NativeArrayRetirementIndex.configurationPredicate, content, member]
  · rintro ⟨index, before, hit⟩
    by_cases zero : index = 0
    · subst index
      left
      simpa [NativeArrayRetirementIndex.virtualLog,
        NativeArrayRetirementIndex.includes,
        NativeArrayRetirementIndex.configurationPredicate,
        NativeArrayRetirementIndex.bootstrapEntry,
        NativeArrayLogWrite.append, NativeArrayCheckQuorum.Log.ofList] using
          And.intro before hit
    · have positive : 0 < index := by omega
      have within : index <= log.length := by omega
      have virtualEntry :
        (NativeArrayRetirementIndex.virtualLog
          (NativeArrayLogWrite.take log commit)).entries index =
          log.entries (index - 1) := by
        exact virtual_take_entry_of_pos log commit index positive
      rw [virtualEntry] at hit
      unfold NativeArrayRetirementIndex.includes
        NativeArrayRetirementIndex.configurationPredicate at hit
      cases content : (log.entries (index - 1)).content with
      | signature => simp [content] at hit
      | transaction value => simp [content] at hit
      | reconfiguration nodes =>
        right
        exact ⟨index, nodes, before, ⟨positive, within, content⟩,
          by simpa [content] using hit⟩
      | retiredCommitted nodes => simp [content] at hit

omit [DecidableEq T] in
theorem previously_included_from_first_match (log : Log N T) (commit current : Nat)
    (node : N) (firstChoice : Option Nat)
    (currentBound : current <= min commit log.length)
    (firstCorrect : FirstMatch
      (NativeArrayRetirementIndex.virtualLog (NativeArrayLogWrite.take log commit))
      (NativeArrayRetirementIndex.includes node) firstChoice) :
    NativeArrayRetirement.PreviouslyIncluded log current node <->
      exists first, firstChoice = some first /\ first < current := by
  rw [previously_included_prefix_hit log commit current node currentBound]
  apply first_match_before_iff
    (NativeArrayRetirementIndex.virtualLog (NativeArrayLogWrite.take log commit))
    (NativeArrayRetirementIndex.includes node) firstChoice current
  · simp [NativeArrayRetirementIndex.virtualLog, NativeArrayLogWrite.append,
      NativeArrayLogWrite.take]
    omega
  · exact firstCorrect

omit [DecidableEq T] [Bootstrap N] in
theorem no_committed_retired_record_iff (log : Log N T) (commit : Nat)
    (node : N) (retiredChoice : Option Nat)
    (retiredCorrect : FirstMatch (NativeArrayLogWrite.take log commit)
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry) retiredChoice) :
    (forall position, position < log.length -> 1 + position <= commit ->
      Sparse.RetirementScan.namesRetiredNode node (log.entries position) = false) <->
      retiredChoice = none := by
  cases retiredChoice with
  | none =>
    constructor
    · intro _
      rfl
    · intro _ position live committed
      exact retiredCorrect position (by simp [NativeArrayLogWrite.take]; omega)
  | some position =>
    rcases retiredCorrect with ⟨live, hit, _⟩
    constructor
    · intro absent
      have missing := absent position (by simp [NativeArrayLogWrite.take] at live; omega)
        (by simp [NativeArrayLogWrite.take] at live; omega)
      have sameEntry :
          (NativeArrayLogWrite.take log commit).entries position =
            log.entries position := rfl
      rw [sameEntry] at hit
      simp_all
    · intro impossible
      contradiction

theorem completed_nodes_from_prefix_scans_correct
    (log : Log N T) (commit current : Nat) (members : Finset N) (node : N)
    (firstChoice retirementChoice retiredChoice : Option Nat)
    (currentIndex : CurrentIndex log commit current)
    (configuration : NativeArrayConfiguration.At log current members)
    (firstCorrect : FirstMatch
      (NativeArrayRetirementIndex.virtualLog (NativeArrayLogWrite.take log commit))
      (NativeArrayRetirementIndex.includes node) firstChoice)
    (retirementCorrect :
      retirementIndexInLog node (NativeArrayLogWrite.take log commit).decode =
        retirementChoice)
    (retiredCorrect : FirstMatch (NativeArrayLogWrite.take log commit)
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry) retiredChoice) :
    node ∈ retirementCompletedNodes log.decode commit <->
      (exists first, firstChoice = some first /\ first < current) /\
        node ∉ members /\ retiredChoice = none /\ retirementChoice.isSome = true := by
  rw [NativeArrayRetirement.completed_nodes_from_scans_correct
    log commit current members node currentIndex configuration]
  rw [previously_included_from_first_match log commit current node firstChoice
    currentIndex.1 firstCorrect]
  rw [no_committed_retired_record_iff log commit node retiredChoice retiredCorrect]
  rw [<- NativeArrayLogWrite.take_correct log commit, retirementCorrect]

end CCFRaft.NativeArrayRetirementCompleted

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayRetirementCompleted).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
