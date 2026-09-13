-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitTerms
import Sparse.NativeRetirementRefreshConstraints
import Sparse.NativeRetirementCompletedConstraints
import Sparse.NativeRetirementWrites

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def retirementTail {width : PNat} (bootstrap : BitVec width) (source : Fin width)
    (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) : EncodeM width Unit := do
  let first <- fresh
  let retirement <- fresh
  let signature <- fresh
  let retired <- fresh
  assertion (retirementRefreshConstraints width bootstrap row.logLength row.logEntries
    source (.free .int first) (.free .int retirement) (.free .int signature) (.free .int retired))
  let values := commitRowTerms row commit (.free .int retirement)
    (.free .int signature) (.free .int retired)
  assertAll (guards values.membershipState)
  let current <- fresh
  assertion (currentConfigurationIndexTerm width row.logLength row.logEntries
    commit (.free .int current))
  let completed <- retirementCompletedConstraints bootstrap (.boolean true)
    row.logLength row.logEntries commit (.free .int current)
  writeRetirementRow source values (.free (.bits width) completed)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
