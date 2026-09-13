-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayConfiguration

set_option autoImplicit false

namespace CCFRaft.NativeArrayMajority

open NativeArrayCheckQuorum NativeArrayConfiguration

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

theorem configuration_majority_correct (state : State N T) (leader : N) (index : Nat)
    (configuration : Configuration N)
    (active : configuration ∈ activeConfigurations (state.nodes leader)) :
    hasConfigurationMajority (acknowledgingNodes state leader index) configuration <->
      (configuration.nodes.filter
        (fun peer => peer = leader \/ index <= (state.nodes leader).matchIndex peer)).card * 2 >
          configuration.nodes.card := by
  have intersection :
      acknowledgingNodes state leader index ∩ configuration.nodes =
        configuration.nodes.filter
          (fun peer => peer = leader \/ index <= (state.nodes leader).matchIndex peer) := by
    ext peer
    simp only [acknowledgingNodes, Finset.mem_inter, Finset.mem_filter]
    constructor
    · rintro ⟨⟨_, supports⟩, member⟩
      exact ⟨member, supports⟩
    · rintro ⟨member, supports⟩
      refine ⟨⟨?_, supports⟩, member⟩
      exact (mem_union _ ∅ peer).mpr (Or.inr ⟨configuration, active, member⟩)
  rw [hasConfigurationMajority, intersection]

def MajorityAt (row : Local N T) (leader : N) (current index : Nat) : Prop :=
  AllActive row.log current fun configurationIndex nodes =>
    configurationIndex <= index ->
      (nodes.filter (fun peer => peer = leader \/ index <= row.matchIndex peer)).card * 2 >
        nodes.card

theorem majority_at_correct (row : Local N T) (state : State N T) (leader : N)
    (current index : Nat) (same : state.nodes leader = row.toModel)
    (selected : CurrentIndex row.log row.commit current) :
    MajorityAt row leader current index <-> hasMajorityAt state leader index := by
  have currentEq : (currentConfiguration (state.nodes leader)).index = current := by
    rw [same]
    exact (current_index_correct row.log row.commit current).mp selected
  rw [MajorityAt, <- currentEq,
    all_active_correct row.log (state.nodes leader) (by rw [same]; rfl)]
  simp only [hasMajorityAt, List.all_eq_true, decide_eq_true_eq]
  apply forall_congr'
  intro configuration
  apply forall_congr'
  intro active
  rw [configuration_majority_correct state leader index configuration active, same]
  rfl

end CCFRaft.NativeArrayMajority

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayMajority).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
