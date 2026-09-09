-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

namespace TraceSmt

inductive NatTerm (holes : Nat) where
  | literal (value : Nat)
  | unknown (index : Fin holes)
  | add (left right : NatTerm holes)
  | named (group slot : Nat) (label : String) (value : NatTerm holes)
  deriving Repr, DecidableEq

def NatTerm.eval {holes : Nat}
    (assignment : Fin holes -> Nat) : NatTerm holes -> Nat
  | .literal value => value
  | .unknown index => assignment index
  | .add left right => left.eval assignment + right.eval assignment
  | .named _ _ _ value => value.eval assignment

inductive Expr (holes : Nat) where
  | boolean (value : Bool)
  | equal (left right : NatTerm holes)
  | lessThan (left right : NatTerm holes)
  | not (value : Expr holes)
  | and (left right : Expr holes)
  deriving Repr

def Expr.Holds {holes : Nat}
    (assignment : Fin holes -> Nat) : Expr holes -> Prop
  | .boolean value => value = true
  | .equal left right => left.eval assignment = right.eval assignment
  | .lessThan left right => left.eval assignment < right.eval assignment
  | .not value => Not (value.Holds assignment)
  | .and left right => left.Holds assignment /\ right.Holds assignment

structure Clause (holes : Nat) where
  label : String
  expression : Expr holes

structure Group (holes : Nat) where
  label : String
  clauses : List (Clause holes)

def Group.Holds {holes : Nat}
    (assignment : Fin holes -> Nat) (group : Group holes) : Prop :=
  forall clause, clause ∈ group.clauses -> clause.expression.Holds assignment

abbrev Formula (holes : Nat) := List (Group holes)

def Formula.Holds {holes : Nat}
    (assignment : Fin holes -> Nat) (formula : Formula holes) : Prop :=
  forall group, group ∈ formula -> group.Holds assignment

def Formula.Satisfiable {holes : Nat} (formula : Formula holes) : Prop :=
  Exists fun assignment => formula.Holds assignment

@[simp]
theorem Formula.holds_nil {holes : Nat} (assignment : Fin holes -> Nat) :
    (Formula.Holds assignment []) := by
  simp [Formula.Holds]

@[simp]
theorem Formula.holds_cons {holes : Nat}
    (assignment : Fin holes -> Nat)
    (group : Group holes) (rest : Formula holes) :
    Formula.Holds assignment (group :: rest) <->
      group.Holds assignment /\ rest.Holds assignment := by
  simp [Formula.Holds]

def NatTerm.toSmt {holes : Nat} : NatTerm holes -> String
  | .literal value => toString value
  | .unknown index => s!"unknown_{index.val}"
  | .add left right => s!"(+ {left.toSmt} {right.toSmt})"
  | .named group slot _ _ => s!"state_{group}_{slot}"

def Expr.toSmt {holes : Nat} : Expr holes -> String
  | .boolean true => "true"
  | .boolean false => "false"
  | .equal left right => s!"(= {left.toSmt} {right.toSmt})"
  | .lessThan left right => s!"(< {left.toSmt} {right.toSmt})"
  | .not value => s!"(not {value.toSmt})"
  | .and left right => s!"(and {left.toSmt} {right.toSmt})"

def conjunction (expressions : List String) : String :=
  match expressions with
  | [] => "true"
  | [expression] => expression
  | _ => "(and " ++ String.intercalate " " expressions ++ ")"

/-- Assertion names are generated from positions, never from input labels. -/
def groupName (index : Nat) : String := s!"group_{index}"

def clauseName (group clause : Nat) : String :=
  s!"group_{group}_clause_{clause}"

def assertion (name expression : String) : String :=
  s!"(assert (! {expression} :named {name}))"

structure Binding (holes : Nat) where
  group : Nat
  slot : Nat
  label : String
  value : NatTerm holes
  deriving DecidableEq

def NatTerm.bindings {holes : Nat} : NatTerm holes -> List (Binding holes)
  | .literal _ => []
  | .unknown _ => []
  | .add left right => left.bindings ++ right.bindings
  | .named group slot label value =>
      value.bindings ++ [{ group, slot, label, value }]

def Expr.bindings {holes : Nat} : Expr holes -> List (Binding holes)
  | .boolean _ => []
  | .equal left right => left.bindings ++ right.bindings
  | .lessThan left right => left.bindings ++ right.bindings
  | .not value => value.bindings
  | .and left right => left.bindings ++ right.bindings

structure PrintedClause where
  label : String
  expression : String

structure PrintedGroup where
  label : String
  clauses : List PrintedClause

structure Prepared where
  declarations : List String
  groups : List PrintedGroup

/--
Named intermediate values become defining equalities in their owning action.
Reject conflicting names rather than silently merging distinct definitions.
-/
def Formula.prepare {holes : Nat}
    (formula : Formula holes) : Except String Prepared := do
  let mut bindings : List (Binding holes) := []
  for (group, index) in formula.zipIdx do
    for clause in group.clauses do
      for binding in clause.expression.bindings do
        if binding.group >= formula.length then
          throw s!"intermediate value refers to absent group {binding.group}"
        if binding.group > index then
          throw s!"group {index} refers to a future intermediate value in group {binding.group}"
        match bindings.find? (fun prior =>
            prior.group == binding.group && prior.slot == binding.slot) with
        | some prior =>
            unless prior == binding do
              throw s!"conflicting intermediate definition: state_{binding.group}_{binding.slot}"
        | none => bindings := bindings ++ [binding]
  let declarations := (List.range holes).flatMap fun index =>
    [s!"(declare-const unknown_{index} Int)",
     s!"(assert (>= unknown_{index} 0))"]
  let stateDeclarations := bindings.flatMap fun binding =>
    let name := s!"state_{binding.group}_{binding.slot}"
    [s!"(declare-const {name} Int)", s!"(assert (>= {name} 0))"]
  let groups := formula.zipIdx.map fun (group, index) =>
    let original := group.clauses.map fun clause =>
      { label := clause.label
        expression := clause.expression.toSmt : PrintedClause }
    let definitions := (bindings.filter fun binding => binding.group == index).map fun binding =>
      { label := binding.label
        expression := s!"(= state_{binding.group}_{binding.slot} {binding.value.toSmt})" :
          PrintedClause }
    { label := group.label, clauses := original ++ definitions : PrintedGroup }
  pure { declarations := declarations ++ stateDeclarations, groups }

/--
Selecting a group changes assertion granularity, not the formula's constraints.
Natural-number domains are shared background constraints in both modes.
-/
def Prepared.toSmt
    (formula : Prepared)
    (inspectGroup : Option Nat := none) : String :=
  let assertions := formula.groups.zipIdx |>.flatMap fun (group, groupIndex) =>
    if inspectGroup = some groupIndex then
      group.clauses.zipIdx |>.map fun (clause, clauseIndex) =>
        assertion (clauseName groupIndex clauseIndex) clause.expression
    else
      [assertion (groupName groupIndex)
        (conjunction (group.clauses.map fun clause => clause.expression))]
  String.intercalate "\n"
    (["(set-logic QF_LIA)"] ++ formula.declarations ++ assertions ++ ["(check-sat)", ""])

end TraceSmt
