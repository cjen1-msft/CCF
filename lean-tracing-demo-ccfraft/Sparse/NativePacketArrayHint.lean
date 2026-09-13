-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketDomain

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def logPrefixCells {context : List Ty} {width : PNat}
    (cells : Term context (.array .int (entryTy width))) :
    Nat -> Term context (.array .int (entryTy width))
  | 0 => .defaultValue _
  | count + 1 =>
    .store (logPrefixCells cells count) (.integer count)
      (.select cells (.integer count))

def logPrefixHint {context : List Ty} {width : PNat}
    (count : Nat) (value : Term context (logTy width)) : Term context .bool :=
  implies (.equal value.fst (.integer count))
    (.equal value.snd (logPrefixCells value.snd count))

def packetArrayHint {context : List Ty} {width : PNat}
    (count : Nat) (value : Term context (packetTy width)) : Term context .bool :=
  .cases value.snd
    (logPrefixHint count (.snd (.snd (.snd (.bound .here)))))
    (.boolean true)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
