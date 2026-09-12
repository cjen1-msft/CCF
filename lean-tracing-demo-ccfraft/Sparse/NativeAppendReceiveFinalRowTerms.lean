-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites
import Sparse.NativeRetirementRefreshTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendReceiveFinalRowTerms {width : PNat} (candidate : NodeRowTerms width)
    (stepDown : Expr .bool) (retirement signature retired : Expr .int) :
    NodeRowTerms width :=
  let refreshed := retirementRefreshTerms candidate.commit retirement signature retired
  { candidate with
    role := .ite stepDown (.integer (roleCode .follower)) candidate.role
    newFollower := .ite stepDown (.boolean true) candidate.newFollower
    retirementIndex :=
      .ite stepDown candidate.retirementIndex refreshed.retirementIndex
    retirementCommittableIndex :=
      .ite stepDown candidate.retirementCommittableIndex refreshed.retirementCommittableIndex
    retiredCommittedIndex :=
      .ite stepDown candidate.retiredCommittedIndex refreshed.retiredCommittedIndex
    membershipState :=
      .ite stepDown candidate.membershipState refreshed.membershipState }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
