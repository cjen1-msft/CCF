-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt
import MachineGenerated.ControlTraceConfigurations

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceValues

open TraceSmt

structure Scalar (holes : Nat) where
  actual : Nat
  expression : NatTerm holes

structure Condition (holes : Nat) where
  actual : Bool
  expression : Expr holes

def Scalar.Correct {holes : Nat} (assignment : Fin holes -> Nat) (value : Scalar holes) : Prop :=
  value.expression.eval assignment = value.actual

def Condition.Correct {holes : Nat} (assignment : Fin holes -> Nat) (value : Condition holes) : Prop :=
  value.expression.Holds assignment ↔ value.actual = true

def literal {holes : Nat} (value : Nat) : Scalar holes := ⟨value, .literal value⟩

def named {holes : Nat} (group slot : Nat) (label : String) (value : Scalar holes) : Scalar holes :=
  ⟨value.actual, .named group slot label value.expression⟩

def add {holes : Nat} (left right : Scalar holes) : Scalar holes :=
  ⟨left.actual + right.actual, .add left.expression right.expression⟩

def sub {holes : Nat} (left right : Scalar holes) : Scalar holes :=
  ⟨left.actual - right.actual, .sub left.expression right.expression⟩

def minimum {holes : Nat} (left right : Scalar holes) : Scalar holes :=
  ⟨min left.actual right.actual, .min left.expression right.expression⟩

def maximum {holes : Nat} (left right : Scalar holes) : Scalar holes :=
  ⟨max left.actual right.actual, .max left.expression right.expression⟩

def equal {holes : Nat} (left right : Scalar holes) : Condition holes :=
  ⟨decide (left.actual = right.actual), .equal left.expression right.expression⟩

def less {holes : Nat} (left right : Scalar holes) : Condition holes :=
  ⟨decide (left.actual < right.actual), .lessThan left.expression right.expression⟩

def notCondition {holes : Nat} (value : Condition holes) : Condition holes :=
  ⟨!value.actual, .not value.expression⟩

def andCondition {holes : Nat} (left right : Condition holes) : Condition holes :=
  ⟨left.actual && right.actual, .and left.expression right.expression⟩

def orCondition {holes : Nat} (left right : Condition holes) : Condition holes :=
  notCondition (andCondition (notCondition left) (notCondition right))

def choose {holes : Nat} (condition : Condition holes) (yes no : Scalar holes) : Scalar holes :=
  ⟨if condition.actual then yes.actual else no.actual, condition.expression.ite yes.expression no.expression⟩

def boolean {holes : Nat} (condition : Condition holes) : Scalar holes :=
  choose condition (literal 1) (literal 0)

def conditionalClamp {holes : Nat} (condition : Condition holes)
    (old lower upper : Scalar holes) : Scalar holes :=
  ⟨if condition.actual then max (min old.actual upper.actual) lower.actual else old.actual,
    condition.expression.clamp old.expression lower.expression upper.expression⟩

@[simp] theorem named_actual {holes : Nat} (group slot : Nat) (label : String) (value : Scalar holes) :
    (named group slot label value).actual = value.actual := rfl

theorem conditionalClamp_actual {holes : Nat} (condition : Condition holes)
    (old lower upper : Scalar holes) :
    (conditionalClamp condition old lower upper).actual =
      if condition.actual then max (min old.actual upper.actual) lower.actual else old.actual := rfl

@[simp] theorem choose_actual {holes : Nat} (condition : Condition holes) (yes no : Scalar holes) :
    (choose condition yes no).actual = if condition.actual then yes.actual else no.actual := rfl

@[simp] theorem equal_actual {holes : Nat} (left right : Scalar holes) :
    (equal left right).actual = decide (left.actual = right.actual) := rfl

@[simp] theorem less_actual {holes : Nat} (left right : Scalar holes) :
    (less left right).actual = decide (left.actual < right.actual) := rfl

@[simp] theorem orCondition_actual {holes : Nat} (left right : Condition holes) :
    (orCondition left right).actual = (left.actual || right.actual) := by
  change (!(!left.actual && !right.actual)) = (left.actual || right.actual)
  cases left.actual <;> cases right.actual <;> rfl

def remember {holes : Nat} (group slot : Nat) (label : String)
    (fallback : Nat -> NatTerm holes) (value : Scalar holes) : Nat -> NatTerm holes :=
  Function.update fallback value.actual (named group slot label value).expression

def install {holes : Nat} (fallback : Nat -> NatTerm holes) (value : Scalar holes) : Nat -> NatTerm holes :=
  Function.update fallback value.actual value.expression

@[simp] theorem literal_correct {holes : Nat} (assignment : Fin holes -> Nat) (value : Nat) :
    (literal (holes := holes) value).Correct assignment := rfl

@[simp] theorem named_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (group slot : Nat) (label : String) (value : Scalar holes) :
    (named group slot label value).Correct assignment ↔ value.Correct assignment := Iff.rfl

theorem add_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Scalar holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (add left right).Correct assignment := by
  simp_all [Scalar.Correct, add, NatTerm.eval]

theorem sub_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Scalar holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (sub left right).Correct assignment := by
  simp_all [Scalar.Correct, sub, NatTerm.eval]

theorem minimum_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Scalar holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (minimum left right).Correct assignment := by
  simp_all [Scalar.Correct, minimum, NatTerm.eval]

theorem maximum_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Scalar holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (maximum left right).Correct assignment := by
  simp_all [Scalar.Correct, maximum, NatTerm.eval]

theorem equal_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Scalar holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (equal left right).Correct assignment := by
  simp_all [Scalar.Correct, Condition.Correct, equal, Expr.Holds]

theorem less_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Scalar holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (less left right).Correct assignment := by
  simp_all [Scalar.Correct, Condition.Correct, less, Expr.Holds]

theorem notCondition_correct {holes : Nat} (assignment : Fin holes -> Nat) (condition : Condition holes)
    (correct : condition.Correct assignment) :
    (notCondition condition).Correct assignment := by
  simp_all [Condition.Correct, notCondition, Expr.Holds]

theorem andCondition_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Condition holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (andCondition left right).Correct assignment := by
  simp_all [Condition.Correct, andCondition, Expr.Holds]

theorem orCondition_correct {holes : Nat} (assignment : Fin holes -> Nat) (left right : Condition holes)
    (hl : left.Correct assignment) (hr : right.Correct assignment) :
    (orCondition left right).Correct assignment :=
  notCondition_correct assignment _ (andCondition_correct assignment _ _
    (notCondition_correct assignment left hl) (notCondition_correct assignment right hr))

theorem choose_correct {holes : Nat} (assignment : Fin holes -> Nat) (condition : Condition holes)
    (yes no : Scalar holes) (hc : condition.Correct assignment)
    (hy : yes.Correct assignment) (hn : no.Correct assignment) :
    (choose condition yes no).Correct assignment := by
  simp_all [Scalar.Correct, Condition.Correct, choose, Expr.ite_eval]

theorem boolean_correct {holes : Nat} (assignment : Fin holes -> Nat) (condition : Condition holes)
    (correct : condition.Correct assignment) :
    (boolean condition).Correct assignment :=
  choose_correct assignment condition _ _ correct rfl rfl

theorem conditionalClamp_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (condition : Condition holes) (old lower upper : Scalar holes)
    (hc : condition.Correct assignment) (ho : old.Correct assignment)
    (hl : lower.Correct assignment) (hu : upper.Correct assignment) :
    (conditionalClamp condition old lower upper).Correct assignment := by
  simp_all [Scalar.Correct, Condition.Correct, conditionalClamp, Expr.clamp_eval]

theorem remember_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (group slot : Nat) (label : String) (fallback : Nat -> NatTerm holes)
    (fallbackCorrect : ∀ value, (fallback value).eval assignment = value)
    (value : Scalar holes) (correct : value.Correct assignment) (input : Nat) :
    (remember group slot label fallback value input).eval assignment = input := by
  by_cases same : input = value.actual
  · subst input
    simpa [remember, named, NatTerm.eval] using correct
  · simp [remember, same, fallbackCorrect]

theorem install_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (fallback : Nat -> NatTerm holes) (fallbackCorrect : ∀ value, (fallback value).eval assignment = value)
    (value : Scalar holes) (correct : value.Correct assignment) (input : Nat) :
    (install fallback value input).eval assignment = input := by
  by_cases same : input = value.actual
  · subst input
    simpa [install] using correct
  · simp [install, same, fallbackCorrect]

end CCFRaft.ReceiveTraceValues
