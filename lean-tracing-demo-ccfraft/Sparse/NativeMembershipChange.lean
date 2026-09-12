-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipWrites
import Sparse.NativeMembershipRowTerms
import Sparse.NativeRetirementCompletedConstraints

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def membershipChange {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) : EncodeM width Unit := do
  let before <- get
  let columns := before.toColumns
  let old := nodeRowSnapshot columns source
  let current <- fresh
  assertion (currentConfigurationIndexTerm width old.logLength old.logEntries
    old.logLength (.free .int current))
  let previous <- define (currentConfigurationMembersTerm width before.bootstrap
    old.logEntries (.free .int current))
  let addedId <- define (membershipAddedTerm configuration (.free (.bits width) previous))
  let added : Expr (.bits width) := .free _ addedId
  let entriesId <- define (membershipLogEntriesTerm columns source configuration)
  let entries : Expr (.array .int (entryTy width)) := .free _ entriesId
  let lengthId <- define (.add old.logLength (.integer 1))
  let count : Expr .int := .free .int lengthId
  let first <- fresh
  let retirement <- fresh
  let signature <- fresh
  let retired <- fresh
  assertion (retirementRefreshConstraints width before.bootstrap count entries source
    (.free .int first) (.free .int retirement) (.free .int signature) (.free .int retired))
  let values := membershipRowTerms columns source count entries added
    (.free .int retirement) (.free .int signature) (.free .int retired)
  assertAll (membershipGuards columns source configuration
    (.free (.bits width) previous) values.membershipState)
  let committedCurrent <- fresh
  assertion (currentConfigurationIndexTerm width count entries old.commit
    (.free .int committedCurrent))
  let completed <- retirementCompletedConstraints before.bootstrap (.boolean true)
    count entries old.commit (.free .int committedCurrent)
  membershipWrites source added values (.free (.bits width) completed)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
