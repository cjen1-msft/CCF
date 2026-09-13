-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeActiveConfigurationEncoding
import Sparse.NativeReplicationMajority
import Sparse.NativeMaxMatchEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def majorityAtTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (current candidate : Term context .int) : Term context .bool :=
  allActiveTerm width length current entries
    (replicationMajorityTerm (.bits bootstrap) matchIndex source candidate)
    (implies (.le (.add (.bound .here) (.integer 1)) (candidate.weaken .int))
      (replicationMajorityTerm (members (.snd (selectedLogEntry entries)))
        (matchIndex.weaken .int) source (candidate.weaken .int)))

def commitEligiblePredicate {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (commit currentTerm current : Term context .int) :
    Term (.int :: context) .bool :=
  let candidate : Term (.int :: context) .int := .add (.bound .here) (.integer 1)
  let entry := selectedLogEntry entries
  all [
    lt (commit.weaken .int) candidate,
    isSignature (.snd entry),
    .equal (.fst (normalizedEntryTerm entry)) (currentTerm.weaken .int),
    majorityAtTerm width bootstrap (length.weaken .int) (entries.weaken .int)
      (matchIndex.weaken .int) source (current.weaken .int) candidate]

def highestCommitIndexTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (commit currentTerm current selected : Term context .int) :
    Term context .bool :=
  maxMatchTerm length length selected
    (commitEligiblePredicate width bootstrap length entries matchIndex source
      commit currentTerm current)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
