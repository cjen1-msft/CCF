-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementCompletedTerm
import Sparse.NativeLogRangeEncoding
import Sparse.NativeLogSummaryTerms
import Sparse.NativeRetirementEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def retirementCompletedPeerConstraints {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed : Nat) :
    List (Fin width) -> EncodeM width Unit
  | [] => pure ()
  | peer :: rest => do
    let first <- fresh
    let retirement <- fresh
    let retired <- fresh
    assertion (implies enabled
      (retirementIndexTerm width bootstrap committedLength entries peer
        (.free .int first) (.free .int retirement)))
    assertion (implies enabled
      (retiredRecordTerm width committedLength entries peer (.free .int retired)))
    assertion (implies enabled
      (.equal (.bit (.free (.bits width) completed) peer)
        (retirementCompletedMemberTerm peer current members
          (.free .int first) (.free .int retirement) (.free .int retired))))
    retirementCompletedPeerConstraints bootstrap enabled entries committedLength current
      members completed rest

def retirementCompletedConstraints {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int) :
    EncodeM width Nat := do
  let before <- get
  if enabled.symbols.all (fun symbol => symbol.2 < before.next) &&
      length.symbols.all (fun symbol => symbol.2 < before.next) &&
      entries.symbols.all (fun symbol => symbol.2 < before.next) &&
      commit.symbols.all (fun symbol => symbol.2 < before.next) &&
      current.symbols.all (fun symbol => symbol.2 < before.next) then
    let members := currentConfigurationMembersTerm width bootstrap entries current
    let completed <- fresh
    retirementCompletedPeerConstraints bootstrap enabled entries
      (logRangeMinTerm commit length) current members completed (List.finRange width)
    return completed
  else
    throw "internal encoder error: retirement completed constraints reference an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
