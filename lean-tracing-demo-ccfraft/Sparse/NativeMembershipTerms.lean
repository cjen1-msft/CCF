-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites
import Sparse.NativeRetirementRefreshConstraints
import Sparse.NativeLogSummaryTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def membershipAddedTerm {width : PNat} (configuration : Finset (Fin width))
    (previous : Expr (.bits width)) : Expr (.bits width) :=
  .bitsAnd (.bits (encodeBits configuration)) (.bitsNot previous)

def membershipLogEntriesTerm {width : PNat} (columns : Columns) (source : Fin width)
    (configuration : Finset (Fin width)) : Expr (.array .int (entryTy width)) :=
  let old := nodeRowSnapshot columns source
  .store old.logEntries old.logLength
    (.pair old.currentTerm (contentTerm (.reconfiguration configuration)))

def membershipGuards {width : PNat} (columns : Columns) (source : Fin width)
    (configuration : Finset (Fin width)) (previous : Expr (.bits width))
    (refreshedMembership : Expr .int) : List (Expr .bool) :=
  let currentMembership : Expr .int :=
    read columns columns.membershipState source.val (.integer 0)
  leadingGuards columns columns.role source.val ++ [
    .not (.equal currentMembership (.integer (membershipCode .retiredCommitted))),
    .not (.equal (.bits (encodeBits configuration)) (.bits 0)),
    .not (.equal (.bits (encodeBits configuration)) previous),
    .equal (.bitsAnd (membershipAddedTerm configuration previous)
      (.free (.bits width) columns.hasJoined)) (.bits 0),
    .not (.equal refreshedMembership (.integer (membershipCode .retiredCommitted)))]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
