-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum

set_option autoImplicit false

namespace CCFRaft.NativeArrayConfiguration

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def At (log : Log N T) (index : Nat) (nodes : Finset N) : Prop :=
  (index = 0 /\ nodes = INITIAL_CONFIGURATION) \/ Reconfiguration log index nodes

theorem current_configuration_correct (log : Log N T) (commit index : Nat) (nodes : Finset N) :
    CurrentIndex log commit index /\ At log index nodes <->
      currentConfigurationAt log.decode commit = { index, nodes } := by
  constructor
  · rintro ⟨current, atIndex⟩
    apply (Sparse.Configuration.currentConfigurationAt_exclusion_iff _ _ _).mpr
    refine ⟨by simpa using current.1, ?_, ?_⟩
    · rcases atIndex with bootstrap | physical
      · exact Or.inl bootstrap
      · exact Or.inr ((reconfiguration_correct log index nodes).mp physical)
    · intro candidate members lower upper physical
      exact current.2.2 candidate members lower (by simpa using upper)
        ((reconfiguration_correct log candidate members).mpr physical)
  · intro actual
    refine ⟨(current_index_correct log commit index).mpr (congrArg Configuration.index actual), ?_⟩
    have shape := (Sparse.Configuration.currentConfigurationAt_exclusion_iff _ _ _).mp actual
    rcases shape.2.1 with bootstrap | physical
    · exact Or.inl bootstrap
    · exact Or.inr ((reconfiguration_correct log index nodes).mpr physical)

end CCFRaft.NativeArrayConfiguration

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayConfiguration).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
