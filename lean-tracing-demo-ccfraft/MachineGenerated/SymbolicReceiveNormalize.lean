-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalize
import Shared.SymbolicData

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic

def constantLess (a b : Expr .nat) : Expr .bool :=
  match a, b with
  | .nat x, .nat y => .bool (decide (x < y))
  | _, _ => .lt a b

theorem constantLess_correct (ρ : Assignment) (a b : Expr .nat) :
    (constantLess a b).eval ρ = decide (a.eval ρ < b.eval ρ) := by
  cases a <;> cases b <;> rfl

def constantNot (a : Expr .bool) : Expr .bool :=
  match a with | .bool value => .bool (!value) | _ => .not a

theorem constantNot_correct (ρ : Assignment) (a : Expr .bool) :
    (constantNot a).eval ρ = !(a.eval ρ) := by
  cases a <;> rfl

def constantEqual : {s : Ty} → Expr s → Expr s → Expr .bool
  | _, .nat x, .nat y => .bool (decide (x = y))
  | _, .bool x, .bool y => .bool (decide (x = y))
  | _, .unit, .unit => .bool true
  | _, .pair x xs, .pair y ys => Expr.both (constantEqual x y) (constantEqual xs ys)
  | _, .inl x, .inl y => constantEqual x y
  | _, .inr x, .inr y => constantEqual x y
  | _, .inl _, .inr _ => .bool false
  | _, .inr _, .inl _ => .bool false
  | _, .nil, .nil => .bool true
  | _, .cons x xs, .cons y ys => Expr.both (constantEqual x y) (constantEqual xs ys)
  | _, .nil, .cons _ _ => .bool false
  | _, .cons _ _, .nil => .bool false
  | _, x, y => .eq x y

theorem constantEqual_correct {s : Ty} (ρ : Assignment) (a b : Expr s) :
    (constantEqual a b).eval ρ = decide (a.eval ρ = b.eval ρ) := by
  fun_induction constantEqual a b <;>
    simp_all [Expr.eval, Expr.both_correct]

def sameLiteral : {s : Ty} → Expr s → Expr s → Bool
  | _, .nat a, .nat b => a == b
  | _, .bool a, .bool b => a == b
  | _, .unit, .unit => true
  | _, .inl a, .inl b => sameLiteral a b
  | _, .inr a, .inr b => sameLiteral a b
  | _, .nil, .nil => true
  | _, _, _ => false

theorem sameLiteral_correct {s : Ty} (ρ : Assignment) (a b : Expr s) :
    sameLiteral a b = true → a.eval ρ = b.eval ρ := by
  fun_induction sameLiteral a b <;> simp_all [Expr.eval]

def chooseLiteral {s : Ty} (condition : Expr .bool) (yes no : Expr s) : Expr s :=
  if sameLiteral yes no then yes else Expr.choose condition yes no

theorem chooseLiteral_correct {s : Ty} (ρ : Assignment)
    (condition : Expr .bool) (yes no : Expr s) :
    (chooseLiteral condition yes no).eval ρ =
      if condition.eval ρ then yes.eval ρ else no.eval ρ := by
  by_cases h : sameLiteral yes no = true
  · simp [chooseLiteral, h, sameLiteral_correct ρ yes no h]
  · simp [chooseLiteral, h]

-- Fold constructor-level constants only. Unknowns and causal names stay symbolic.
def compact : {s : Ty} → Expr s → Expr s
  | _, .nat n => .nat n
  | _, .bool b => .bool b
  | _, .unit => .unit
  | _, .unknown i => .unknown i
  | _, .named group slot value => .named group slot value
  | _, .add a b => Expr.plus (compact a) (compact b)
  | _, .sub a b => Expr.minus (compact a) (compact b)
  | _, .lt a b => constantLess (compact a) (compact b)
  | _, .eq a b => constantEqual (compact a) (compact b)
  | _, .not a => constantNot (compact a)
  | _, .and a b => Expr.both (compact a) (compact b)
  | _, .ite c a b =>
    match compact c with
    | .bool true => compact a
    | .bool false => compact b
    | c => chooseLiteral c (compact a) (compact b)
  | _, .pair a b => .pair (compact a) (compact b)
  | _, .fst (.pair a _) => compact a
  | _, .fst e => Expr.first (compact e)
  | _, .snd (.pair _ b) => compact b
  | _, .snd e => Expr.second (compact e)
  | _, .inl e => .inl (compact e)
  | _, .inr e => .inr (compact e)
  | _, .isLeft (.inl _) => .bool true
  | _, .isLeft (.inr _) => .bool false
  | _, .isLeft e => Expr.testLeft (compact e)
  | _, .leftD (.inl e) _ => compact e
  | _, .leftD (.inr _) d => compact d
  | _, .leftD e d => Expr.fromLeft (compact e) (compact d)
  | _, .rightD (.inr e) _ => compact e
  | _, .rightD (.inl _) d => compact d
  | _, .rightD e d => Expr.fromRight (compact e) (compact d)
  | _, .nil => .nil
  | _, .cons a b => .cons (compact a) (compact b)
  | _, .append a b => .append (compact a) (compact b)
  | _, .length e => Expr.size (compact e)
  | _, .take n e => .take (compact n) (compact e)
  | _, .drop n e => .drop (compact n) (compact e)
  | _, .get? e n => Expr.select (compact e) (compact n)
  | _, .set e n v => .set (compact e) (compact n) (compact v)
  | _, .contains e v => .contains (compact e) (compact v)

theorem compact_correct {s : Ty} (ρ : Assignment) (e : Expr s) :
    (compact e).eval ρ = e.eval ρ := by
  fun_induction compact e <;>
    simp_all [compact, Expr.eval, constantLess_correct, constantNot_correct, constantEqual_correct,
      chooseLiteral_correct]

theorem decode_compact {A : Type} (c : Codec A) (ρ : Assignment) (value : Expr c.ty) :
    c.decode ρ (compact value) = c.decode ρ value := by
  simp only [Codec.decode, compact_correct]

end CCFRaft.SymbolicReceive
