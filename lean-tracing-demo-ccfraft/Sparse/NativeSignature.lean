-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSignatureTerms
import Sparse.NativeRetirementTail

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def signCommittableMessages {width : PNat} (source : Fin width) : EncodeM width Unit := do
  let before <- get
  let old := nodeRowSnapshot before.toColumns source
  let entriesId <- define (leaderLogEntriesTerm old (contentTerm .signature))
  let lengthId <- define (.add old.logLength (.integer 1))
  let appended := leaderLogRowTerms old (.free .int lengthId) (.free _ entriesId)
  retirementTail before.bootstrap source appended old.commit
    (signatureGuards before.toColumns source)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
