-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveNormalize

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic

def andLazy (condition : Expr .bool) (body : Unit → Expr .bool) : Expr .bool :=
  match SymbolicReceive.compact condition with
  | .bool false => .bool false
  | condition => .and condition (body ())

theorem andLazy_correct (ρ : Assignment) (condition : Expr .bool) (body : Unit → Expr .bool) :
    (andLazy condition body).eval ρ = (condition.eval ρ && (body ()).eval ρ) := by
  unfold andLazy
  split
  · rename_i h
    have value := congrArg (Expr.eval ρ) h
    simp only [SymbolicReceive.compact_correct, Expr.eval] at value
    simp only [Expr.eval, value, Bool.false_and]
  · simp only [Expr.eval, SymbolicReceive.compact_correct]

def takeKnown {a : Ty} : Nat → Expr (.seq a) → Expr (.seq a)
  | 0, _ => .nil
  | _ + 1, .nil => .nil
  | n + 1, .cons head tail => .cons head (takeKnown n tail)
  | n + 1, xs => .take (.nat (n + 1)) xs

theorem takeKnown_correct {a : Ty} (ρ : Assignment) (n : Nat) (xs : Expr (.seq a)) :
    (takeKnown n xs).eval ρ = (xs.eval ρ).take n := by
  induction n generalizing xs with
  | zero => simp [takeKnown, Expr.eval]
  | succ n ih => cases xs <;> simp [takeKnown, Expr.eval, ih]

def takeCompact {a : Ty} (count : Expr .nat) (xs : Expr (.seq a)) : Expr (.seq a) :=
  match SymbolicReceive.compact count with
  | .nat n => takeKnown n (SymbolicReceive.compact xs)
  | count => .take count (SymbolicReceive.compact xs)

theorem takeCompact_correct {a : Ty} (ρ : Assignment) (count : Expr .nat) (xs : Expr (.seq a)) :
    (takeCompact count xs).eval ρ = (xs.eval ρ).take (count.eval ρ) := by
  unfold takeCompact
  split
  · rename_i n h
    have value := congrArg (Expr.eval ρ) h
    simp only [SymbolicReceive.compact_correct, Expr.eval] at value
    simp only [takeKnown_correct, SymbolicReceive.compact_correct, value]
  · simp only [Expr.eval, SymbolicReceive.compact_correct]

end CCFRaft.SymbolicTransition
