-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def membershipSentIndexTerm {width : PNat} (old : Expr (.array .int .int))
    (added : Expr (.bits width)) (oldLength : Expr .int) : Expr (.array .int .int) :=
  (List.finRange width).foldl (fun result peer =>
    .store result (.integer peer.val)
      (.ite (.bit added peer) oldLength (.select old (.integer peer.val)))) old

def membershipRowTerms {width : PNat} (columns : Columns) (source : Fin width)
    (logLength : Expr .int) (logEntries : Expr (.array .int (entryTy width)))
    (added : Expr (.bits width)) (retirement signature retired : Expr .int) :
    NodeRowTerms width :=
  let old := nodeRowSnapshot columns source
  let refreshed := retirementRefreshTerms old.commit retirement signature retired
  { old with
    logLength := logLength
    logEntries := logEntries
    sentIndex := membershipSentIndexTerm old.sentIndex added old.logLength
    retirementIndex := refreshed.retirementIndex
    retirementCommittableIndex := refreshed.retirementCommittableIndex
    retiredCommittedIndex := refreshed.retiredCommittedIndex
    membershipState := refreshed.membershipState }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
