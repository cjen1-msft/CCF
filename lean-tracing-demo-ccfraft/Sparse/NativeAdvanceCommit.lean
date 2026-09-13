-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitIndexTerms
import Sparse.NativeRetirementTail

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def advanceCommitIndex {width : PNat} (source : Fin width) : EncodeM width Unit := do
  let before <- get
  let old := nodeRowSnapshot before.toColumns source
  let current <- fresh
  assertion (currentConfigurationIndexTerm width old.logLength old.logEntries
    old.commit (.free .int current))
  let best <- fresh
  assertion (highestCommitIndexTerm width before.bootstrap old.logLength old.logEntries
    old.matchIndex source old.commit old.currentTerm (.free .int current) (.free .int best))
  retirementTail before.bootstrap source old (.free .int best)
    (commitGuards before.toColumns source (.free .int best))

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
