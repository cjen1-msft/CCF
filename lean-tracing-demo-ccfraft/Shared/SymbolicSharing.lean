-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Symbolic

set_option autoImplicit false

namespace Symbolic

private abbrev PackedExpr := (s : Ty) × Expr s

private structure Signature where
  tag : Nat
  scalars : List Nat
  children : List PackedExpr

private def signature {s : Ty} : Expr s -> Signature
  | .nat value => ⟨0, [value], []⟩
  | .bool value => ⟨1, [if value then 1 else 0], []⟩
  | .unit => ⟨2, [], []⟩
  | .unknown index => ⟨3, [index], []⟩
  | .named group slot value => ⟨4, [group, slot], [⟨_, value⟩]⟩
  | .add a b => ⟨5, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .sub a b => ⟨6, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .lt a b => ⟨7, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .eq a b => ⟨8, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .not a => ⟨9, [], [⟨_, a⟩]⟩
  | .and a b => ⟨10, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .ite c a b => ⟨11, [], [⟨_, c⟩, ⟨_, a⟩, ⟨_, b⟩]⟩
  | .pair a b => ⟨12, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .fst a => ⟨13, [], [⟨_, a⟩]⟩
  | .snd a => ⟨14, [], [⟨_, a⟩]⟩
  | .inl a => ⟨15, [], [⟨_, a⟩]⟩
  | .inr a => ⟨16, [], [⟨_, a⟩]⟩
  | .isLeft a => ⟨17, [], [⟨_, a⟩]⟩
  | .leftD a b => ⟨18, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .rightD a b => ⟨19, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .nil => ⟨20, [], []⟩
  | .cons a b => ⟨21, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .append a b => ⟨22, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .length a => ⟨23, [], [⟨_, a⟩]⟩
  | .take a b => ⟨24, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .drop a b => ⟨25, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .get? a b => ⟨26, [], [⟨_, a⟩, ⟨_, b⟩]⟩
  | .set a b c => ⟨27, [], [⟨_, a⟩, ⟨_, b⟩, ⟨_, c⟩]⟩
  | .contains a b => ⟨28, [], [⟨_, a⟩, ⟨_, b⟩]⟩

private def boundedHash : Nat -> {s : Ty} -> Expr s -> UInt64
  | 0, _, _ => 0
  | depth + 1, _, expression =>
      let head := signature expression
      head.children.foldl (fun result child =>
        mixHash result (boundedHash depth child.2)) (hash (head.tag, head.scalars))

/-- A bounded-cost bucket key. Cache hits must still compare exact typed syntax. -/
def Expr.memoKey {s : Ty} (expression : Expr s) : UInt64 :=
  boundedHash 4 expression

private theorem signature_injective {s : Ty} :
    Function.Injective (@signature s) := by
  intro a b equal
  cases a <;> cases b <;>
    simp_all [signature, Signature.mk.injEq]
  split_ifs at equal <;> simp_all

private theorem child_smaller {s : Ty} (e : Expr s) (child : PackedExpr)
    (member : child ∈ (signature e).children) :
    sizeOf child.2 < sizeOf e := by
  cases e <;> simp only [signature, List.mem_cons, List.not_mem_nil, or_false] at member
  all_goals rcases member with rfl | rfl | rfl <;> simp <;> omega

private def childrenDecEq (left right : List PackedExpr)
    (compare : ∀ child ∈ left, ∀ other, Decidable (child = other)) :
    Decidable (left = right) :=
  match left, right with
  | [], [] => .isTrue rfl
  | [], _ :: _ => .isFalse (by simp)
  | _ :: _, [] => .isFalse (by simp)
  | a :: as, b :: bs =>
      match compare a (by simp) b with
      | .isFalse different => .isFalse (fun equal => different (List.cons.inj equal).1)
      | .isTrue same =>
          match childrenDecEq as bs (fun child member other =>
              compare child (List.mem_cons_of_mem _ member) other) with
          | .isFalse different => .isFalse (fun equal => different (List.cons.inj equal).2)
          | .isTrue rest => .isTrue (by cases same; cases rest; rfl)

private def structuralExprEq (left right : PackedExpr) : Decidable (left = right) :=
  match left, right with
  | ⟨s, a⟩, ⟨t, b⟩ =>
      match withPtrEqDecEq s t (fun _ => inferInstance) with
      | .isFalse different => .isFalse (fun equal => different (congrArg Sigma.fst equal))
      | .isTrue same => by
          subst t
          let comparison : Decidable (a = b) := withPtrEqDecEq a b fun _ =>
            let left := signature a
            let right := signature b
            if header : left.tag = right.tag ∧ left.scalars = right.scalars then
              match childrenDecEq left.children right.children
                  (fun child member other => structuralExprEq child other) with
              | .isTrue children =>
                  .isTrue (signature_injective (by
                    cases ha : signature a
                    cases hb : signature b
                    simp_all [left, right]))
              | .isFalse different =>
                  .isFalse (fun equal => different (congrArg (fun e => (signature e).children) equal))
            else
              .isFalse (fun equal => header (by cases equal; exact ⟨rfl, rfl⟩))
          exact @decidable_of_iff ((⟨s, a⟩ : PackedExpr) = ⟨s, b⟩)
            (a = b) (by simp) comparison
termination_by sizeOf left.2
decreasing_by exact child_smaller _ _ member

private structure Compared where
  left : PackedExpr
  right : PackedExpr
  decision : Decidable (left = right)

private abbrev ComparisonCache := Std.HashMap (USize × USize) (List Compared)

private def findComparison (left right : PackedExpr) :
    List Compared -> Option (Decidable (left = right))
  | [] => none
  | prior :: rest =>
      match structuralExprEq prior.left left, structuralExprEq prior.right right with
      | .isTrue sameLeft, .isTrue sameRight =>
          some (by simpa only [← sameLeft, ← sameRight] using prior.decision)
      | _, _ => findComparison left right rest

private def childrenMemo {goal : Prop} (left right : List PackedExpr)
    (compare : ∀ child ∈ left, ∀ other, ComparisonCache ->
      (Decidable (child = other) -> ComparisonCache -> Decidable goal) -> Decidable goal)
    (cache : ComparisonCache)
    (done : Decidable (left = right) -> ComparisonCache -> Decidable goal) : Decidable goal :=
  match left, right with
  | [], [] => done (.isTrue rfl) cache
  | [], _ :: _ => done (.isFalse (by simp)) cache
  | _ :: _, [] => done (.isFalse (by simp)) cache
  | a :: as, b :: bs =>
      compare a (by simp) b cache fun head cache =>
        match head with
        | .isFalse different => done (.isFalse (fun equal =>
            different (List.cons.inj equal).1)) cache
        | .isTrue same =>
            childrenMemo as bs (fun child member other =>
                compare child (List.mem_cons_of_mem _ member) other) cache fun tail cache =>
              match tail with
              | .isFalse different => done (.isFalse (fun equal =>
                  different (List.cons.inj equal).2)) cache
              | .isTrue rest => done (.isTrue (by cases same; cases rest; rfl)) cache

-- Addresses select buckets, never establish equality. A decision of a fixed
-- proposition is unique, so the continuation's result is address-independent.
private def compareMemo {goal : Prop} :
    (left right : PackedExpr) -> ComparisonCache ->
    (Decidable (left = right) -> ComparisonCache -> Decidable goal) -> Decidable goal
  | ⟨s, a⟩, ⟨t, b⟩, cache, done =>
      withPtrAddr a (fun leftAddress =>
        withPtrAddr b (fun rightAddress =>
          let key := (leftAddress, rightAddress)
          let finish := fun decision cache =>
            done decision (cache.insert key
              (⟨⟨s, a⟩, ⟨t, b⟩, decision⟩ :: cache[key]?.getD []))
          if leftAddress == rightAddress then
            finish (structuralExprEq ⟨s, a⟩ ⟨t, b⟩) cache
          else
            match findComparison ⟨s, a⟩ ⟨t, b⟩ (cache[key]?.getD []) with
            | some decision => done decision cache
            | none =>
                match withPtrEqDecEq s t (fun _ => inferInstance) with
                | .isFalse different => finish (.isFalse (fun equal =>
                    different (congrArg Sigma.fst equal))) cache
                | .isTrue same => by
                    subst t
                    let lhs := signature a
                    let rhs := signature b
                    let packed := fun (decision : Decidable (a = b)) =>
                      @decidable_of_iff ((⟨s, a⟩ : PackedExpr) = ⟨s, b⟩)
                        (a = b) (by simp) decision
                    exact if header : lhs.tag = rhs.tag ∧ lhs.scalars = rhs.scalars then
                      childrenMemo (signature a).children (signature b).children
                        (fun child member other cache continuation =>
                          compareMemo child other cache continuation) cache fun children cache =>
                            match children with
                            | .isTrue equal =>
                                finish (packed (.isTrue (signature_injective (by
                                  cases ha : signature a
                                  cases hb : signature b
                                  simp_all [lhs, rhs])))) cache
                            | .isFalse different =>
                                finish (packed (.isFalse (fun equal =>
                                  different (congrArg (fun e => (signature e).children) equal)))) cache
                    else
                      finish (packed (.isFalse (fun equal =>
                        header (by cases equal; exact ⟨rfl, rfl⟩)))) cache)
          (fun _ _ => Subsingleton.elim _ _))
        (fun _ _ => Subsingleton.elim _ _)
termination_by left _ _ _ => sizeOf left.2
decreasing_by all_goals exact child_smaller _ _ member

/-- Exact typed equality, including independently allocated shared subgraphs. -/
def packedExprEq (left right : (s : Ty) × Expr s) : Decidable (left = right) :=
  compareMemo left right {} (fun decision _ => decision)

/-- Opt-in equality for local memo tables, without changing the global instance. -/
def Expr.sharedDecEq {s : Ty} (a b : Expr s) : Decidable (a = b) :=
  @decidable_of_iff (a = b) ((⟨s, a⟩ : (s : Ty) × Expr s) = ⟨s, b⟩)
    (by simp) (packedExprEq ⟨s, a⟩ ⟨s, b⟩)

theorem Expr.sharedDecEq_correct {s : Ty} (a b : Expr s) :
    @decide (a = b) (a.sharedDecEq b) = decide (a = b) := by
  exact congrArg (fun decision => @decide (a = b) decision)
    (Subsingleton.elim (a.sharedDecEq b) inferInstance)

theorem packedExprEq_correct (a b : (s : Ty) × Expr s) :
    @decide (a = b) (packedExprEq a b) = decide (a = b) := by
  exact congrArg (fun decision => @decide (a = b) decision)
    (Subsingleton.elim (packedExprEq a b) inferInstance)

end Symbolic
