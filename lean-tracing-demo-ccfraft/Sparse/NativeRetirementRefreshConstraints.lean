-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementIndexEncoding
import Sparse.NativeRetirementEncoding
import Sparse.NativeRetirementRefreshTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def retirementRefreshConstraints {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (first retirement signature retired : Term context .int) :
    Term context .bool :=
  all [
    retirementIndexTerm width bootstrap length entries node first retirement,
    .ite (.equal retirement (.integer (-1))) (.equal signature (.integer (-1)))
      (signatureAfterRetirementTerm width length entries retirement signature),
    retiredRecordTerm width length entries node retired]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
