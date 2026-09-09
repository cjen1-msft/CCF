-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

namespace Symbolic

inductive Ty where
  | nat | bool | unit
  | pair (left right : Ty)
  | sum (left right : Ty)
  | seq (element : Ty)
  deriving DecidableEq, Repr

@[reducible] def Ty.Value : Ty → Type
  | .nat => Nat
  | .bool => Bool
  | .unit => Unit
  | .pair a b => a.Value × b.Value
  | .sum a b => Sum a.Value b.Value
  | .seq a => List a.Value

instance valueDecidableEq : (s : Ty) → DecidableEq s.Value
  | .nat => inferInstance
  | .bool => inferInstance
  | .unit => inferInstance
  | .pair a b => by
      letI := valueDecidableEq a
      letI := valueDecidableEq b
      exact inferInstance
  | .sum a b => by
      letI := valueDecidableEq a
      letI := valueDecidableEq b
      exact inferInstance
  | .seq a => by
      letI := valueDecidableEq a
      exact inferInstance

abbrev Assignment := Nat → Nat

inductive Expr : Ty → Type where
  | nat (value : Nat) : Expr .nat
  | bool (value : Bool) : Expr .bool
  | unit : Expr .unit
  | unknown (index : Nat) : Expr .nat
  | add : Expr .nat → Expr .nat → Expr .nat
  | sub : Expr .nat → Expr .nat → Expr .nat
  | lt : Expr .nat → Expr .nat → Expr .bool
  | eq {s : Ty} : Expr s → Expr s → Expr .bool
  | not : Expr .bool → Expr .bool
  | and : Expr .bool → Expr .bool → Expr .bool
  | ite {s : Ty} : Expr .bool → Expr s → Expr s → Expr s
  | pair {a b : Ty} : Expr a → Expr b → Expr (.pair a b)
  | fst {a b : Ty} : Expr (.pair a b) → Expr a
  | snd {a b : Ty} : Expr (.pair a b) → Expr b
  | inl {a b : Ty} : Expr a → Expr (.sum a b)
  | inr {a b : Ty} : Expr b → Expr (.sum a b)
  | isLeft {a b : Ty} : Expr (.sum a b) → Expr .bool
  | leftD {a b : Ty} : Expr (.sum a b) → Expr a → Expr a
  | rightD {a b : Ty} : Expr (.sum a b) → Expr b → Expr b
  | nil {a : Ty} : Expr (.seq a)
  | cons {a : Ty} : Expr a → Expr (.seq a) → Expr (.seq a)
  | append {a : Ty} : Expr (.seq a) → Expr (.seq a) → Expr (.seq a)
  | length {a : Ty} : Expr (.seq a) → Expr .nat
  | take {a : Ty} : Expr .nat → Expr (.seq a) → Expr (.seq a)
  | drop {a : Ty} : Expr .nat → Expr (.seq a) → Expr (.seq a)
  | get? {a : Ty} : Expr (.seq a) → Expr .nat → Expr (.sum .unit a)
  | set {a : Ty} : Expr (.seq a) → Expr .nat → Expr a → Expr (.seq a)
  | contains {a : Ty} : Expr (.seq a) → Expr a → Expr .bool

def Expr.eval (ρ : Assignment) : {s : Ty} → Expr s → s.Value
  | _, .nat n => n
  | _, .bool b => b
  | _, .unit => ()
  | _, .unknown i => ρ i
  | _, .add a b => a.eval ρ + b.eval ρ
  | _, .sub a b => a.eval ρ - b.eval ρ
  | _, .lt a b => decide (a.eval ρ < b.eval ρ)
  | _, .eq a b => decide (a.eval ρ = b.eval ρ)
  | _, .not a => !(a.eval ρ)
  | _, .and a b => a.eval ρ && b.eval ρ
  | _, .ite c a b => if c.eval ρ then a.eval ρ else b.eval ρ
  | _, .pair a b => (a.eval ρ, b.eval ρ)
  | _, .fst a => (a.eval ρ).1
  | _, .snd a => (a.eval ρ).2
  | _, .inl a => .inl (a.eval ρ)
  | _, .inr a => .inr (a.eval ρ)
  | _, .isLeft a => match a.eval ρ with | .inl _ => true | .inr _ => false
  | _, .leftD a d => match a.eval ρ with | .inl v => v | .inr _ => d.eval ρ
  | _, .rightD a d => match a.eval ρ with | .inr v => v | .inl _ => d.eval ρ
  | _, .nil => []
  | _, .cons a b => a.eval ρ :: b.eval ρ
  | _, .append a b => a.eval ρ ++ b.eval ρ
  | _, .length a => (a.eval ρ).length
  | _, .take n a => (a.eval ρ).take (n.eval ρ)
  | _, .drop n a => (a.eval ρ).drop (n.eval ρ)
  | _, .get? a n =>
      match (a.eval ρ)[n.eval ρ]? with | none => .inl () | some v => .inr v
  | _, .set a n v => (a.eval ρ).set (n.eval ρ) (v.eval ρ)
  | _, .contains a v => decide (v.eval ρ ∈ a.eval ρ)

def Expr.or (a b : Expr .bool) : Expr .bool := .not (.and (.not a) (.not b))
def Expr.le (a b : Expr .nat) : Expr .bool := .not (.lt b a)
def Expr.implies (a b : Expr .bool) : Expr .bool := a.not.or b

-- Defaults occur only behind constructor tests, never as entry observations.
def defaultExpr : (s : Ty) → Expr s
  | .nat => .nat 0
  | .bool => .bool false
  | .unit => .unit
  | .pair a b => .pair (defaultExpr a) (defaultExpr b)
  | .sum a _ => .inl (defaultExpr a)
  | .seq _ => .nil

def Expr.ofList {a : Ty} (xs : List (Expr a)) : Expr (.seq a) :=
  xs.foldr Expr.cons .nil

@[simp] theorem eval_ofList {a : Ty} (ρ : Assignment) (xs : List (Expr a)) :
    (Expr.ofList xs).eval ρ = xs.map (Expr.eval ρ) := by
  induction xs <;> simp_all [Expr.ofList, Expr.eval]

@[simp] theorem eval_or (ρ : Assignment) (a b : Expr .bool) :
    (a.or b).eval ρ = (a.eval ρ || b.eval ρ) := by
  simp [Expr.or, Expr.eval]

@[simp] theorem eval_le (ρ : Assignment) (a b : Expr .nat) :
    (a.le b).eval ρ = decide (a.eval ρ ≤ b.eval ρ) := by
  apply Bool.eq_iff_iff.mpr
  simp [Expr.le, Expr.eval]

@[simp] theorem eval_implies (ρ : Assignment) (a b : Expr .bool) :
    (a.implies b).eval ρ = decide (a.eval ρ = true → b.eval ρ = true) := by
  cases ha : a.eval ρ <;> cases hb : b.eval ρ <;>
    simp [Expr.implies, Expr.eval, ha, hb]

end Symbolic
