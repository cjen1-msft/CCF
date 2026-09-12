-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScriptRun
import Sparse.NativeTraceCompleteness

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem compiled_script_iff {width : PNat} [Bootstrap (Fin width)]
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (initial started final : Encoding width) (index : Nat) (groups result : Array Group) (named : Bool)
    (initialColumns : initial.toColumns = {})
    (empty : initial.assertions = #[]) (valid : ReferencesValid initial)
    (start : (initialDomains width).run initial = .ok ((), started))
    (run : (compileInstructions index groups items).run started = .ok (result, final))
    (sameBootstrap : decodeBits initial.bootstrap = INITIAL_CONFIGURATION) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript final.assertions.toList named) = some true) <->
      (exists model : State (Fin width) Nat, NativeArrayCheckQuorum.modelFollows model items) := by
  simp only [script_text_holds]
  exact compiled_trace_iff items initial started final index groups result initialColumns
    empty valid start run sameBootstrap

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name || (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
