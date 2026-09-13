-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeClientRequest
import Sparse.NativeCompilerEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure ClientRequestExecutionStates (width : PNat) where
  appended : NodeRowTerms width
  prepared : Encoding width
  retired : Encoding width

structure ClientRequestExecutionResult {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width) (states : ClientRequestExecutionStates width) :
    Prop where
  prepareRun :
    (prepareLeaderLog source (.inr (.inl transaction))).run before =
      .ok (states.appended, states.prepared)
  tailRun :
    (retirementTail before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)).run states.prepared =
        .ok ((), states.retired)
  submittedRun :
    (insertSubmitted transaction).run states.retired = .ok ((), after)

theorem client_request_execution {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after)) :
    exists states : ClientRequestExecutionStates width,
      ClientRequestExecutionResult source transaction before after states := by
  rw [clientRequest, get_bind_run] at run
  obtain ⟨appended, prepared, prepareRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨⟨⟩, retired, tailRun, submittedRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  exact ⟨⟨appended, prepared, retired⟩, prepareRun, tailRun, submittedRun⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
