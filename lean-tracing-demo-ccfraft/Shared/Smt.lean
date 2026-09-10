-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtSharing

set_option autoImplicit false

namespace TraceSmt

def NatTerm.eval {holes : Nat}
    (assignment : Fin holes -> Nat) : NatTerm holes -> Nat
  | .literal value => value
  | .unknown index => assignment index
  | .add left right => left.eval assignment + right.eval assignment
  | .sub left right => left.eval assignment - right.eval assignment
  | .iteEqual left right whenEqual whenDifferent =>
      if left.eval assignment = right.eval assignment then
        whenEqual.eval assignment
      else whenDifferent.eval assignment
  | .named _ _ _ value => value.eval assignment
  | .min left right => Nat.min (left.eval assignment) (right.eval assignment)
  | .max left right => Nat.max (left.eval assignment) (right.eval assignment)
  | .clampIfEqual left right old lower upper =>
      if left.eval assignment = right.eval assignment then
        Nat.max (Nat.min (old.eval assignment) (upper.eval assignment)) (lower.eval assignment)
      else old.eval assignment

@[simp]
theorem NatTerm.clampIfEqual_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (left right old lower upper : NatTerm holes) :
    (clampIfEqual left right old lower upper).eval assignment =
      if left.eval assignment = right.eval assignment then
        Nat.max (Nat.min (old.eval assignment) (upper.eval assignment)) (lower.eval assignment)
      else old.eval assignment :=
  rfl

@[simp]
theorem NatTerm.min_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (left right : NatTerm holes) :
    (left.min right).eval assignment = Nat.min (left.eval assignment) (right.eval assignment) :=
  rfl

@[simp]
theorem NatTerm.max_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (left right : NatTerm holes) :
    (left.max right).eval assignment = Nat.max (left.eval assignment) (right.eval assignment) :=
  rfl

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

instance Expr.decidableHolds {holes : Nat} (assignment : Fin holes -> Nat) :
    (expression : Expr holes) -> Decidable (expression.Holds assignment)
  | .boolean value => inferInstanceAs (Decidable (value = true))
  | .equal left right =>
      inferInstanceAs (Decidable (left.eval assignment = right.eval assignment))
  | .lessThan left right =>
      inferInstanceAs (Decidable (left.eval assignment < right.eval assignment))
  | .not value => @instDecidableNot _ (value.decidableHolds assignment)
  | .and left right =>
      @instDecidableAnd _
        _ (left.decidableHolds assignment) (right.decidableHolds assignment)

def Expr.ite {holes : Nat} (condition : Expr holes)
    (whenTrue whenFalse : NatTerm holes) : NatTerm holes :=
  match condition with
  | .boolean value => if value then whenTrue else whenFalse
  | .equal left right => .iteEqual left right whenTrue whenFalse
  | .lessThan left right =>
      .iteEqual (.sub right left) (.literal 0) whenFalse whenTrue
  | .not value => value.ite whenFalse whenTrue
  | .and left right =>
      -- Keep each branch once even when the guard contains several conditions.
      .iteEqual (left.ite (right.ite (.literal 1) (.literal 0)) (.literal 0))
        (.literal 1) whenTrue whenFalse

theorem Expr.ite_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (condition : Expr holes) (whenTrue whenFalse : NatTerm holes) :
    (condition.ite whenTrue whenFalse).eval assignment =
      if condition.Holds assignment then whenTrue.eval assignment else whenFalse.eval assignment := by
  induction condition generalizing whenTrue whenFalse with
  | boolean value => cases value <;> simp [ite, Holds]
  | equal left right => rfl
  | lessThan left right =>
      by_cases less : left.eval assignment < right.eval assignment
      · have nonzero : right.eval assignment - left.eval assignment ≠ 0 := by omega
        simp [ite, Holds, NatTerm.eval, less, nonzero]
      · have zero : right.eval assignment - left.eval assignment = 0 := by omega
        simp [ite, Holds, NatTerm.eval, less, zero]
  | not value ih =>
      by_cases holds : value.Holds assignment <;> simp [ite, Holds, ih, holds]
  | and left right leftIH rightIH =>
      by_cases leftHolds : left.Holds assignment <;>
        by_cases rightHolds : right.Holds assignment <;>
          simp [ite, Holds, NatTerm.eval, leftIH, rightIH, leftHolds, rightHolds]

/-- Conditional clamping stores the unchanged operand only once. -/
def Expr.clamp {holes : Nat} (condition : Expr holes)
    (old lower upper : NatTerm holes) : NatTerm holes :=
  .clampIfEqual (condition.ite (.literal 1) (.literal 0)) (.literal 1) old lower upper

theorem Expr.clamp_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (condition : Expr holes) (old lower upper : NatTerm holes) :
    (condition.clamp old lower upper).eval assignment =
      if condition.Holds assignment then
        Nat.max (Nat.min (old.eval assignment) (upper.eval assignment)) (lower.eval assignment)
      else old.eval assignment := by
  by_cases holds : condition.Holds assignment <;>
    simp [clamp, NatTerm.eval, ite_eval, holds]

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

private def NatTerm.toSmtTree {holes : Nat} : NatTerm holes -> String
  | .literal value => toString value
  | .unknown index => s!"unknown_{index.val}"
  | .add left right => s!"(+ {left.toSmtTree} {right.toSmtTree})"
  | .sub left right =>
      s!"(ite (< {left.toSmtTree} {right.toSmtTree}) 0 (- {left.toSmtTree} {right.toSmtTree}))"
  | .iteEqual left right whenEqual whenDifferent =>
      s!"(ite (= {left.toSmtTree} {right.toSmtTree}) {whenEqual.toSmtTree} {whenDifferent.toSmtTree})"
  | .named group slot _ _ => s!"state_{group}_{slot}"
  | .min left right =>
      s!"(let ((min_left {left.toSmtTree}) (min_right {right.toSmtTree})) (ite (< min_left min_right) min_left min_right))"
  | .max left right =>
      s!"(let ((max_left {left.toSmtTree}) (max_right {right.toSmtTree})) (ite (< max_left max_right) max_right max_left))"
  | .clampIfEqual left right old lower upper =>
      s!"(let ((clamp_left {left.toSmtTree}) (clamp_right {right.toSmtTree}) (clamp_old {old.toSmtTree}) (clamp_lower {lower.toSmtTree}) (clamp_upper {upper.toSmtTree})) (let ((clamp_min (ite (< clamp_old clamp_upper) clamp_old clamp_upper))) (ite (= clamp_left clamp_right) (ite (< clamp_min clamp_lower) clamp_lower clamp_min) clamp_old)))"

private def Expr.toSmtTree {holes : Nat} : Expr holes -> String
  | .boolean true => "true"
  | .boolean false => "false"
  | .equal left right => s!"(= {left.toSmtTree} {right.toSmtTree})"
  | .lessThan left right => s!"(< {left.toSmtTree} {right.toSmtTree})"
  | .not value => s!"(not {value.toSmtTree})"
  | .and left right => s!"(and {left.toSmtTree} {right.toSmtTree})"

private abbrev TermCache (holes : Nat) (α : Type) :=
  Std.HashMap UInt64 (List (NatTerm holes × α))

private structure TermPrinting (holes : Nat) where
  cache : TermCache holes String := {}
  definitions : Array (String × String) := #[]
  shared : Bool := false

private def NatTerm.atomic {holes : Nat} : NatTerm holes -> Bool
  | .literal _ | .unknown _ | .named _ _ _ _ => true
  | _ => false

private def NatTerm.printMemo {holes : Nat} (term : NatTerm holes) :
    StateM (TermPrinting holes) String := do
  if term.atomic then
    return term.toSmtTree
  let key := term.memoKey
  if let some reference := NatTerm.lookup term ((← get).cache[key]?.getD []) then
    modify fun state => { state with shared := true }
    return reference
  let body ← match term with
    | .literal _ | .unknown _ | .named _ _ _ _ => pure term.toSmtTree
    | .add left right => do
        let a ← left.printMemo
        let b ← right.printMemo
        pure s!"(+ {a} {b})"
    | .sub left right => do
        let a ← left.printMemo
        let b ← right.printMemo
        -- Saturating subtraction uses each operand twice in its SMT body.
        if !left.atomic || !right.atomic then
          modify fun state => { state with shared := true }
        pure s!"(ite (< {a} {b}) 0 (- {a} {b}))"
    | .iteEqual left right whenEqual whenDifferent => do
        let a ← left.printMemo
        let b ← right.printMemo
        let c ← whenEqual.printMemo
        let d ← whenDifferent.printMemo
        pure s!"(ite (= {a} {b}) {c} {d})"
    | .min left right => do
        let a ← left.printMemo
        let b ← right.printMemo
        pure s!"(let ((min_left {a}) (min_right {b})) (ite (< min_left min_right) min_left min_right))"
    | .max left right => do
        let a ← left.printMemo
        let b ← right.printMemo
        pure s!"(let ((max_left {a}) (max_right {b})) (ite (< max_left max_right) max_right max_left))"
    | .clampIfEqual left right old lower upper => do
        let a ← left.printMemo
        let b ← right.printMemo
        let c ← old.printMemo
        let d ← lower.printMemo
        let e ← upper.printMemo
        pure s!"(let ((clamp_left {a}) (clamp_right {b}) (clamp_old {c}) (clamp_lower {d}) (clamp_upper {e})) (let ((clamp_min (ite (< clamp_old clamp_upper) clamp_old clamp_upper))) (ite (= clamp_left clamp_right) (ite (< clamp_min clamp_lower) clamp_lower clamp_min) clamp_old)))"
  let state ← get
  let reference := s!"dag_{state.definitions.size}"
  set { state with
    cache := state.cache.insert key ((term, reference) :: state.cache[key]?.getD [])
    definitions := state.definitions.push (reference, body) }
  return reference
termination_by sizeOf term

private def Expr.printMemo {holes : Nat} : Expr holes -> StateM (TermPrinting holes) String
  | .boolean value => pure (if value then "true" else "false")
  | .equal left right => do
      let a ← left.printMemo
      let b ← right.printMemo
      pure s!"(= {a} {b})"
  | .lessThan left right => do
      let a ← left.printMemo
      let b ← right.printMemo
      pure s!"(< {a} {b})"
  | .not value => do pure s!"(not {← value.printMemo})"
  | .and left right => do
      let a ← left.printMemo
      let b ← right.printMemo
      pure s!"(and {a} {b})"

private def TermPrinting.wrap {holes : Nat} (state : TermPrinting holes) (body : String) : String :=
  String.join (state.definitions.toList.map fun (name, value) => s!"(let (({name} {value})) ") ++
    body ++ String.ofList (List.replicate state.definitions.size ')')

/-- Preserve tree printing when no repeated non-atomic operand needs a let. -/
def NatTerm.toSmt {holes : Nat} (term : NatTerm holes) : String :=
  let (body, state) := term.printMemo.run {}
  if state.shared then state.wrap body else term.toSmtTree

def Expr.toSmt {holes : Nat} (expression : Expr holes) : String :=
  let (body, state) := expression.printMemo.run {}
  if state.shared then state.wrap body else expression.toSmtTree

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

private structure BindingCollection (holes : Nat) where
  cache : TermCache holes (Option Nat) := {}
  bindings : Array (Binding holes) := #[]
  error : Option String := none

private def latestOwner (left right : Option Nat) : Option Nat :=
  match left, right with
  | none, other | other, none => other
  | some a, some b => some (Nat.max a b)

private def NatTerm.collectBindings {holes : Nat} (term : NatTerm holes) :
    StateM (BindingCollection holes) (Option Nat) := do
  let key := term.memoKey
  if let some owner := NatTerm.lookup term ((← get).cache[key]?.getD []) then
    return owner
  let mut owner := none
  for child in term.children.attach do
    owner := latestOwner owner (← child.val.collectBindings)
  if let .named group slot label value := term then
    if let some dependency := owner then
      if dependency > group then
        let message := s!"intermediate value in group {group} refers to future group {dependency}"
        modify fun state => { state with error := state.error.orElse (fun _ => some message) }
    modify fun state => { state with bindings := state.bindings.push { group, slot, label, value } }
    owner := latestOwner owner (some group)
  modify fun state =>
    { state with cache := state.cache.insert key ((term, owner) :: state.cache[key]?.getD []) }
  return owner
termination_by sizeOf term
decreasing_by exact NatTerm.child_smaller _ _ child.property

private def Expr.collectBindings {holes : Nat} :
    Expr holes -> StateM (BindingCollection holes) (Option Nat)
  | .boolean _ => pure none
  | .equal left right | .lessThan left right => do
      let a ← left.collectBindings
      let b ← right.collectBindings
      return latestOwner a b
  | .not value => value.collectBindings
  | .and left right => do
      let a ← left.collectBindings
      let b ← right.collectBindings
      return latestOwner a b

/-- Reachable distinct definitions, in child-before-parent order. -/
def NatTerm.bindings {holes : Nat} (term : NatTerm holes) : List (Binding holes) :=
  (term.collectBindings.run {}).2.bindings.toList

def Expr.bindings {holes : Nat} (expression : Expr holes) : List (Binding holes) :=
  (expression.collectBindings.run {}).2.bindings.toList

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
  let mut collection : BindingCollection holes := {}
  for (group, index) in formula.zipIdx do
    for clause in group.clauses do
      let (owner, collected) := clause.expression.collectBindings.run collection
      if let some message := collected.error then
        throw message
      if let some latest := owner then
        if latest >= formula.length then
          throw s!"intermediate value refers to absent group {latest}"
        if latest > index then
          throw s!"group {index} refers to a future intermediate value in group {latest}"
      let discovered := collected.bindings.extract collection.bindings.size collected.bindings.size
      collection := collected
      for binding in discovered do
        match bindings.find? (fun prior =>
            prior.group == binding.group && prior.slot == binding.slot) with
        | some prior =>
            unless prior.label == binding.label &&
                @decide (prior.value = binding.value) (NatTerm.sharedDecEq prior.value binding.value) do
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
