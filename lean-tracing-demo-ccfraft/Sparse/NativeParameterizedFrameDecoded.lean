-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

def ParameterizedFrameDecoded.ModelConsistent (input : ParameterizedFrameDecoded) : Prop :=
  exists bootstrap : Bootstrap (Fin input.frame.width),
    letI := bootstrap
    INITIAL_CONFIGURATION = input.frame.bootstrap /\
      exists values : Fin input.unknowns.size -> Nat,
        exists model : State (Fin input.frame.width) Nat,
          NativeArrayVote.modelFollows model
            (input.frame.instructions.toList.map
              (ParameterizedFrameInstruction.materialize values))

def ParameterizedFrameDocumentConsistent (document : Json) : Prop :=
  exists input,
    decodeParameterizedFrameDocument document = .ok input /\ input.ModelConsistent

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
