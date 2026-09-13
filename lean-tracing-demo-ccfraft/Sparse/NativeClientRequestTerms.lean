-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSignatureTerms
import Sparse.NativeNatSet

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def clientRequestGuards {width : PNat} (columns : Columns) (source : Fin width)
    (transaction membership : Expr .int) : List (Expr .bool) :=
  let old := nodeRowSnapshot columns source
  [allocated columns source.val,
    .equal old.role (.integer (roleCode .leader)),
    .not (.equal old.membershipState (.integer (membershipCode .retiredCommitted))),
    .le (.integer 0) transaction,
    .not (natSetMember columns.submittedTxIds columns.submittedTxLimit transaction),
    .not (.equal membership (.integer (membershipCode .retiredCommitted)))]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
