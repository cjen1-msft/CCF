-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

inductive NatArgument (count : Nat) where
  | literal (value : Nat)
  | parameter (index : Fin count)

def NatArgument.value {count : Nat} (values : Fin count -> Nat) : NatArgument count -> Nat
  | .literal value => value
  | .parameter index => values index

def NatArgument.term {count : Nat} (base : Nat) : NatArgument count -> Expr .int
  | .literal value => .integer value
  | .parameter index => .free .int (base + index.val)

def NatParametersRep {count : Nat} (assignment : Assignment) (base : Nat)
    (values : Fin count -> Nat) : Prop :=
  forall index, assignment .int (base + index.val) = (values index : Int)

def declareNatParameters {width : PNat} : Nat -> EncodeM width Unit
  | 0 => pure ()
  | count + 1 => do
    let id <- fresh
    assertion (.le (.integer 0) (.free .int id))
    declareNatParameters count

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
