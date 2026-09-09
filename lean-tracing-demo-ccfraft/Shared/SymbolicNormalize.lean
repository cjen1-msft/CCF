-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Symbolic

set_option autoImplicit false

namespace Symbolic.Expr

def choose {s : Ty} (c : Expr .bool) (a b : Expr s) : Expr s :=
  match c with | .bool true => a | .bool false => b | _ => .ite c a b

@[simp] theorem choose_correct {s : Ty} (ρ : Assignment)
    (c : Expr .bool) (a b : Expr s) :
    (choose c a b).eval ρ = if c.eval ρ then a.eval ρ else b.eval ρ := by
  fun_cases choose c a b <;> simp_all [eval]

def first {a b : Ty} : Expr (.pair a b) → Expr a
  | .pair x _ => x
  | .ite c x y => choose c (first x) (first y)
  | e => .fst e

@[simp] theorem first_correct {a b : Ty} (ρ : Assignment) (e : Expr (.pair a b)) :
    (first e).eval ρ = (e.eval ρ).1 := by
  fun_induction first e <;> simp_all [eval]
  split <;> rfl

def second {a b : Ty} : Expr (.pair a b) → Expr b
  | .pair _ y => y
  | .ite c x y => choose c (second x) (second y)
  | e => .snd e

@[simp] theorem second_correct {a b : Ty} (ρ : Assignment) (e : Expr (.pair a b)) :
    (second e).eval ρ = (e.eval ρ).2 := by
  fun_induction second e <;> simp_all [eval]
  split <;> rfl

def testLeft {a b : Ty} : Expr (.sum a b) → Expr .bool
  | .inl _ => .bool true
  | .inr _ => .bool false
  | .ite c x y => choose c (testLeft x) (testLeft y)
  | e => .isLeft e

@[simp] theorem testLeft_correct {a b : Ty} (ρ : Assignment) (e : Expr (.sum a b)) :
    (testLeft e).eval ρ = (Expr.isLeft e).eval ρ := by
  fun_induction testLeft e <;> simp_all [eval]
  split <;> rfl

def fromLeft {a b : Ty} : Expr (.sum a b) → Expr a → Expr a
  | .inl x, _ => x
  | .inr _, d => d
  | .ite c x y, d => choose c (fromLeft x d) (fromLeft y d)
  | e, d => .leftD e d

@[simp] theorem fromLeft_correct {a b : Ty} (ρ : Assignment)
    (e : Expr (.sum a b)) (d : Expr a) :
    (fromLeft e d).eval ρ = (Expr.leftD e d).eval ρ := by
  fun_induction fromLeft e d <;> simp_all [eval]
  split <;> rfl

def fromRight {a b : Ty} : Expr (.sum a b) → Expr b → Expr b
  | .inl _, d => d
  | .inr y, _ => y
  | .ite c x y, d => choose c (fromRight x d) (fromRight y d)
  | e, d => .rightD e d

@[simp] theorem fromRight_correct {a b : Ty} (ρ : Assignment)
    (e : Expr (.sum a b)) (d : Expr b) :
    (fromRight e d).eval ρ = (Expr.rightD e d).eval ρ := by
  fun_induction fromRight e d <;> simp_all [eval]
  split <;> rfl

def plus (a b : Expr .nat) : Expr .nat :=
  match a, b with | .nat x, .nat y => .nat (x + y) | _, _ => .add a b

@[simp] theorem plus_correct (ρ : Assignment) (a b : Expr .nat) :
    (plus a b).eval ρ = a.eval ρ + b.eval ρ := by
  cases a <;> cases b <;> rfl

def minus (a b : Expr .nat) : Expr .nat :=
  match a, b with | .nat x, .nat y => .nat (x - y) | _, _ => .sub a b

@[simp] theorem minus_correct (ρ : Assignment) (a b : Expr .nat) :
    (minus a b).eval ρ = a.eval ρ - b.eval ρ := by
  cases a <;> cases b <;> rfl

def select {a : Ty} : Expr (.seq a) → Expr .nat → Expr (.sum .unit a)
  | .nil, _ => .inl .unit
  | .cons x xs, n =>
      choose (.eq n (.nat 0)) (.inr x) (select xs (minus n (.nat 1)))
  | .take count xs, n =>
      choose (.lt n count) (select xs n) (.inl .unit)
  | .drop count xs, n => select xs (plus count n)
  | .ite c xs ys, n => choose c (select xs n) (select ys n)
  | xs, n => .get? xs n

@[simp] theorem select_correct {a : Ty} (ρ : Assignment)
    (xs : Expr (.seq a)) (n : Expr .nat) :
    (select xs n).eval ρ = (Expr.get? xs n).eval ρ := by
  fun_induction select xs n <;> simp_all [eval, List.getElem?_drop]
  case case2 x xs n ih =>
    cases hn : n.eval ρ <;> simp [hn] at *
  case case3 count xs n ih =>
    by_cases h : n.eval ρ < count.eval ρ <;> simp [h]
  case case5 c xs ys n ihx ihy =>
    split <;> rfl

def size {a : Ty} : Expr (.seq a) → Expr .nat
  | .nil => .nat 0
  | .cons _ tail => plus (.nat 1) (size tail)
  | .append xs ys => plus (size xs) (size ys)
  | .take n xs => choose (n.le (size xs)) n (size xs)
  | .drop n xs => .sub (size xs) n
  | .ite c xs ys => choose c (size xs) (size ys)
  | e => .length e

@[simp] theorem size_correct {a : Ty} (ρ : Assignment) (e : Expr (.seq a)) :
    (size e).eval ρ = (e.eval ρ).length := by
  fun_induction size e <;> simp_all [eval, Nat.add_comm, Nat.min_def]
  all_goals split_ifs <;> simp_all

def equal {s : Ty} (a b : Expr s) : Expr .bool :=
  match a, b with
  | .nat x, .nat y => .bool (decide (x = y))
  | .bool x, .bool y => .bool (decide (x = y))
  | .unit, .unit => .bool true
  | _, _ => .eq a b

@[simp] theorem equal_correct {s : Ty} (ρ : Assignment) (a b : Expr s) :
    (equal a b).eval ρ = decide (a.eval ρ = b.eval ρ) := by
  cases a <;> cases b <;> rfl

def both (a b : Expr .bool) : Expr .bool :=
  match a, b with
  | .bool false, _ | _, .bool false => .bool false
  | .bool true, _ => b
  | _, .bool true => a
  | _, _ => .and a b

@[simp] theorem both_correct (ρ : Assignment) (a b : Expr .bool) :
    (both a b).eval ρ = (a.eval ρ && b.eval ρ) := by
  fun_cases both a b <;> simp_all [eval]

def normalize : {s : Ty} → Expr s → Expr s
  | _, .nat n => .nat n
  | _, .bool b => .bool b
  | _, .unit => .unit
  | _, .unknown i => .unknown i
  -- Normalize each definition once during printing, not at every reference.
  | _, .named group slot value => .named group slot value
  | _, .add a b => plus a.normalize b.normalize
  | _, .sub a b => minus a.normalize b.normalize
  | _, .lt a b => .lt a.normalize b.normalize
  | _, .eq a b => equal a.normalize b.normalize
  | _, .not a => .not a.normalize
  | _, .and a b => both a.normalize b.normalize
  | _, .ite c a b => choose c.normalize a.normalize b.normalize
  | _, .pair a b => .pair a.normalize b.normalize
  | _, .fst e => first e.normalize
  | _, .snd e => second e.normalize
  | _, .inl e => .inl e.normalize
  | _, .inr e => .inr e.normalize
  | _, .isLeft e => testLeft e.normalize
  | _, .leftD e d => fromLeft e.normalize d.normalize
  | _, .rightD e d => fromRight e.normalize d.normalize
  | _, .nil => .nil
  | _, .cons a b => .cons a.normalize b.normalize
  | _, .append a b => .append a.normalize b.normalize
  | _, .length e => size e.normalize
  | _, .take n e => .take n.normalize e.normalize
  | _, .drop n e => .drop n.normalize e.normalize
  | _, .get? e n => select e.normalize n.normalize
  | _, .set e n v => .set e.normalize n.normalize v.normalize
  | _, .contains e v => .contains e.normalize v.normalize

theorem normalize_correct {s : Ty} (ρ : Assignment) (e : Expr s) :
    e.normalize.eval ρ = e.eval ρ := by
  induction e <;> simp_all [normalize, eval]

end Symbolic.Expr
