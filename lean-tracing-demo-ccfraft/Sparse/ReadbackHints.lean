-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Readback
import Sparse.Smt

set_option autoImplicit false

namespace CCFRaft.Sparse.ReadbackHints

theorem arguments_ne {K H : Type} (projection : K -> H) (left right : K)
    (leftValue rightValue : H) (leftFact : projection left = leftValue)
    (rightFact : projection right = rightValue) (different : Not (leftValue = rightValue)) :
    Not (left = right) := by
  intro same
  apply different
  exact leftFact.symm.trans ((congrArg projection same).trans rightFact)

theorem skip_store {K V H : Type} [DecidableEq K] {size : Nat}
    (graph : Readback.Graph K V size) (root : K -> V) (index : Fin size) (key : K)
    (projection : K -> H) (queryValue storedValue : H)
    (queryFact : projection key = queryValue)
    (storedFact : projection (graph.stores index).key = storedValue)
    (different : Not (queryValue = storedValue)) :
    Readback.array graph root index.succ key =
      Readback.array graph root (graph.stores index).prior key := by
  rw [Readback.array_store]
  exact if_neg (arguments_ne projection key (graph.stores index).key
    queryValue storedValue queryFact storedFact different)

theorem asserted_headers_ne (assignment : Smt.Assignment) (functionID : Nat)
    (left right : Smt.Term .int) (leftValue rightValue : Int)
    (leftFact : (Smt.Term.equal (.app .int .int functionID left)
      (.integer leftValue)).eval assignment = true)
    (rightFact : (Smt.Term.equal (.app .int .int functionID right)
      (.integer rightValue)).eval assignment = true)
    (different : Not (leftValue = rightValue)) :
    Not (left.eval assignment = right.eval assignment) := by
  have observedLeft :
      assignment.unary .int .int functionID (left.eval assignment) = leftValue :=
    of_decide_eq_true leftFact
  have observedRight :
      assignment.unary .int .int functionID (right.eval assignment) = rightValue :=
    of_decide_eq_true rightFact
  exact arguments_ne (assignment.unary .int .int functionID)
    (left.eval assignment) (right.eval assignment) leftValue rightValue
    observedLeft observedRight different

end CCFRaft.Sparse.ReadbackHints

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.ReadbackHints.arguments_ne,
      ``CCFRaft.Sparse.ReadbackHints.skip_store,
      ``CCFRaft.Sparse.ReadbackHints.asserted_headers_ne] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
  Lean.logInfo "Projection-backed readback hint audit passed."
