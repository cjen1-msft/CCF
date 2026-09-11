-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.MembershipState

def equiv : Fin 5 ≃ MembershipState where
  toFun := fun i => match i.val with
    | 0 => .active | 1 => .retirementOrdered | 2 => .retirementSigned
    | 3 => .retirementCompleted | _ => .retiredCommitted
  invFun := fun r => match r with
    | .active => 0 | .retirementOrdered => 1 | .retirementSigned => 2
    | .retirementCompleted => 3 | .retiredCommitted => 4
  left_inv := by intro i; fin_cases i <;> rfl
  right_inv := by intro r; cases r <;> rfl

end CCFRaft.MembershipState

run_cmd do
  for axiomName in (<- Lean.collectAxioms ``CCFRaft.MembershipState.equiv) do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "unexpected axiom in membership equivalence: {axiomName}"
