-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayConfiguration

set_option autoImplicit false

namespace CCFRaft.NativeArrayVotingMajority

open NativeArrayCheckQuorum NativeArrayConfiguration

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def Majority (row : Local N T) (current : Nat) (support : Finset N) : Prop :=
  AllActive row.log current fun _ nodes =>
    (support ∩ nodes).card * 2 > nodes.card

theorem majority_correct (row : Local N T) (current : Nat) (support : Finset N)
    (selected : CurrentIndex row.log row.commit current) :
    Majority row current support <->
      (activeConfigurations row.toModel).all fun configuration =>
        decide (hasConfigurationMajority support configuration) := by
  have currentEq : (currentConfiguration row.toModel).index = current :=
    (current_index_correct row.log row.commit current).mp selected
  rw [Majority, <- currentEq,
    all_active_correct row.log row.toModel rfl]
  simp only [List.all_eq_true, decide_eq_true_eq, hasConfigurationMajority]

theorem election_majority_correct
    (row : Local N T) (state : State N T) (source : N) (current : Nat)
    (same : state.nodes source = row.toModel)
    (selected : CurrentIndex row.log row.commit current) :
    Majority row current row.votesGranted <->
      hasElectionMajority state source := by
  rw [majority_correct row current row.votesGranted selected,
    hasElectionMajority, same]
  rfl

theorem pre_vote_majority_correct
    (row : Local N T) (state : State N T) (source : N) (current : Nat)
    (same : state.nodes source = row.toModel)
    (selected : CurrentIndex row.log row.commit current) :
    Majority row current row.preVotesGranted <->
      hasPreVoteMajority state source := by
  rw [majority_correct row current row.preVotesGranted selected,
    hasPreVoteMajority, same]
  rfl

end CCFRaft.NativeArrayVotingMajority

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayVotingMajority).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
