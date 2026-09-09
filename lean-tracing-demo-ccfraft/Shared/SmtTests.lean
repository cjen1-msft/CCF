-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt

set_option autoImplicit false

namespace TraceSmt.Tests

def namedValue (group : Nat) (value : Nat) : NatTerm 0 :=
  .named group 0 "stored value" (.literal value)

def equality (term : NatTerm 0) : Clause 0 :=
  { label := "observed value", expression := .equal term (.literal 1) }

#guard (.sub (.literal 2) (.literal 1) : NatTerm 0).eval Fin.elim0 == 1
#guard (.sub (.literal 1) (.literal 2) : NatTerm 0).eval Fin.elim0 == 0
#guard (.sub (.literal 2) (.literal 2) : NatTerm 0).eval Fin.elim0 == 0
#guard (.sub (.literal 2) (.literal 1) : NatTerm 0).toSmt ==
  "(ite (< 2 1) 0 (- 2 1))"
#guard (.sub (.unknown 0) (.unknown 1) : NatTerm 2).toSmt ==
  "(ite (< unknown_0 unknown_1) 0 (- unknown_0 unknown_1))"

def dequeued : Formula 0 :=
  [{ label := "enqueue", clauses := [] },
   { label := "receive", clauses := [] },
   { label := "observation", clauses :=
      [equality (.named 1 0 "remaining queue"
        (.sub (namedValue 0 2) (.literal 1)))] }]

#guard match dequeued.prepare with
  | .ok prepared =>
      (prepared.groups.map fun group => group.clauses.length) == [1, 1, 1] &&
        match prepared.groups[1]? >>= fun group => group.clauses[0]? with
        | some clause => clause.expression ==
            "(= state_1_0 (ite (< state_0_0 1) 0 (- state_0_0 1)))"
        | none => false
  | .error _ => false

def rejected (formula : Formula 0) : Bool :=
  match formula.prepare with
  | .error _ => true
  | .ok _ => false

def repeated : Formula 0 :=
  [{ label := "action", clauses := [equality (namedValue 0 1), equality (namedValue 0 1)] }]

#guard !rejected repeated

#guard match repeated.prepare with
  | .ok prepared =>
      prepared.declarations.length == 2 &&
        (prepared.groups.map fun group => group.clauses.length) == [3]
  | .error _ => false

#guard rejected
  [{ label := "action", clauses := [equality (namedValue 0 1), equality (namedValue 0 2)] }]

#guard rejected
  [{ label := "action", clauses := [equality (namedValue 1 1)] }]

#guard rejected
  [{ label := "action", clauses :=
      [equality (.add (.literal 0) (namedValue 1 1))] }]

#guard rejected
  [{ label := "action", clauses :=
      [equality (.sub (namedValue 1 1) (.literal 0))] }]

#guard rejected
  [{ label := "action", clauses :=
      [equality (.sub (.literal 2) (namedValue 1 1))] }]

#guard rejected
  [{ label := "action", clauses :=
      [equality (.sub (namedValue 0 2) (namedValue 0 1))] }]

#guard match (Formula.prepare
    [{ label := "action", clauses :=
        [equality (.sub (.literal 3) (namedValue 0 2))] }]) with
  | .ok prepared =>
      prepared.declarations.length == 2 &&
        (prepared.groups.map fun group => group.clauses.length) == [2]
  | .error _ => false

#guard rejected
  [{ label := "observation", clauses := [equality (namedValue 1 1)] },
   { label := "future action", clauses := [] }]

#guard match (Formula.prepare ([] : Formula 0)) with
  | .ok prepared => prepared.toSmt == "(set-logic QF_LIA)\n(check-sat)\n"
  | .error _ => false

#guard match repeated.prepare with
  | .ok prepared =>
      prepared.toSmt (some 0) ==
        "(set-logic QF_LIA)\n" ++
        "(declare-const state_0_0 Int)\n" ++
        "(assert (>= state_0_0 0))\n" ++
        "(assert (! (= state_0_0 1) :named group_0_clause_0))\n" ++
        "(assert (! (= state_0_0 1) :named group_0_clause_1))\n" ++
        "(assert (! (= state_0_0 1) :named group_0_clause_2))\n" ++
        "(check-sat)\n"
  | .error _ => false

end TraceSmt.Tests
