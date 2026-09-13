-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNatSet
import Sparse.NativeRenaming

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def natSetInsertConstraints {context : List Ty}
    (oldCells oldLimit newCells newLimit : Nat) (value : Term context .int) :
    Term context .bool :=
  .and (.le (.integer 0) (.free .int newLimit))
    (.forall_ .int
      (.equal (natSetMember newCells newLimit (.bound .here))
        (.or (natSetMember oldCells oldLimit (.bound .here))
          (.equal (.bound .here) (value.weaken .int)))))

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
