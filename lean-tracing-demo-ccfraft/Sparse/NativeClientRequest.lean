-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLeaderLogWrite
import Sparse.NativeClientRequestTerms
import Sparse.NativeRetirementTail
import Sparse.NativeSubmittedWrite

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def clientRequest {width : PNat} (source : Fin width) (transaction : Expr .int) :
    EncodeM width Unit := do
  let before <- get
  let old := nodeRowSnapshot before.toColumns source
  let appended <- prepareLeaderLog source (.inr (.inl transaction))
  retirementTail before.bootstrap source appended old.commit
    (clientRequestGuards before.toColumns source transaction)
  insertSubmitted transaction

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
