-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMaxMatchEncoding
import Sparse.NativeRetirementEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def boundedSignatureTerm {context : List Ty} (width : PNat)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (cap selected : Term context .int) : Term context .bool :=
  maxMatchTerm length cap selected (isSignature (.snd (selectedLogEntry entries)))

def currentConfigurationIndexTerm {context : List Ty} (width : PNat)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit selected : Term context .int) : Term context .bool :=
  maxMatchTerm length commit selected (isConfiguration (.snd (selectedLogEntry entries)))

def currentConfigurationMembersTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (entries : Term context (.array .int (entryTy width))) (selected : Term context .int) :
    Term context (.bits width) :=
  .ite (.equal selected (.integer 0)) (.bits bootstrap)
    (members (.snd (.select entries (.sub selected (.integer 1)))))

def nackMatchTerm {context : List Ty} (width : PNat)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (previous threshold selected : Term context .int) : Term context .bool :=
  maxMatchTerm length previous selected
    (.le (.fst (normalizedEntryTerm (selectedLogEntry entries))) (threshold.weaken .int))

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
