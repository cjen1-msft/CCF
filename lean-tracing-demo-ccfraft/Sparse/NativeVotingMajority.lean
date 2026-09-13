-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeActiveConfigurationEncoding
import Sparse.NativeMajorityTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def votingMajorityTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (length current : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (support : Term context (.bits width)) : Term context .bool :=
  allActiveTerm width length current entries
    (configurationMajorityTerm (.bits bootstrap) fun peer => .bit support peer)
    (configurationMajorityTerm (members (.snd (selectedLogEntry entries)))
      fun peer => .bit (support.weaken .int) peer)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
