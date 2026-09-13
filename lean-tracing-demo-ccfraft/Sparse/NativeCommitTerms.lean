-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites
import Sparse.NativeRetirementRefreshTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def commitRowTerms {width : PNat} (old : NodeRowTerms width)
    (best retirement signature retired : Expr .int) : NodeRowTerms width :=
  let refreshed := retirementRefreshTerms best retirement signature retired
  { old with
    commit := best
    retirementIndex := refreshed.retirementIndex
    retirementCommittableIndex := refreshed.retirementCommittableIndex
    retiredCommittedIndex := refreshed.retiredCommittedIndex
    membershipState := refreshed.membershipState }

def commitGuards {width : PNat} (columns : Columns) (source : Fin width)
    (best membership : Expr .int) : List (Expr .bool) :=
  let old := nodeRowSnapshot columns source
  [allocated columns source.val,
    .equal old.role (.integer (roleCode .leader)),
    lt old.commit best,
    .not (.equal membership (.integer (membershipCode .retiredCommitted)))]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
