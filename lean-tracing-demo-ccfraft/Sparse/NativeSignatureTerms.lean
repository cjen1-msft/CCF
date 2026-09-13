-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitTerms
import Sparse.NativeLogSummaryTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def leaderLogEntriesTerm {width : PNat} (old : NodeRowTerms width)
    (content : Expr (contentTy width)) : Expr (.array .int (entryTy width)) :=
  .store old.logEntries old.logLength (.pair old.currentTerm content)

def leaderLogRowTerms {width : PNat} (old : NodeRowTerms width)
    (length : Expr .int) (entries : Expr (.array .int (entryTy width))) :
    NodeRowTerms width :=
  { old with logLength := length, logEntries := entries }

def signatureGuards {width : PNat} (columns : Columns) (source : Fin width)
    (membership : Expr .int) : List (Expr .bool) :=
  let old := nodeRowSnapshot columns source
  [allocated columns source.val,
    .equal old.role (.integer (roleCode .leader)),
    .not (.equal old.membershipState (.integer (membershipCode .retiredCommitted))),
    lt (.integer 0) old.logLength,
    .not (.equal membership (.integer (membershipCode .retiredCommitted)))]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
