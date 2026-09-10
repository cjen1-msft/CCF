-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

namespace TraceSmt

inductive NatTerm (holes : Nat) where
  | literal (value : Nat)
  | unknown (index : Fin holes)
  | add (left right : NatTerm holes)
  | sub (left right : NatTerm holes)
  | iteEqual (left right whenEqual whenDifferent : NatTerm holes)
  | named (group slot : Nat) (label : String) (value : NatTerm holes)
  | min (left right : NatTerm holes)
  | max (left right : NatTerm holes)
  | clampIfEqual (left right old lower upper : NatTerm holes)
  deriving Repr, DecidableEq

end TraceSmt
