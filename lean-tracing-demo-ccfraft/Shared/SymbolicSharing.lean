-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicTypeSharing

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
      match s.sharedDecEq t with
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

-- These frames replace higher-order continuations: completed siblings must not
-- keep native call frames alive while the rest of a wide expression is compared.
private inductive ComparisonKont (goal : Prop) : Prop -> Type where
  | done : ComparisonKont goal goal
  | save (left right : PackedExpr) (key : USize × USize)
      (next : ComparisonKont goal (left = right)) : ComparisonKont goal (left = right)
  | convert {p q : Prop} (equivalent : p ↔ q)
      (next : ComparisonKont goal q) : ComparisonKont goal p
  | tail (a b : PackedExpr) (as bs : List PackedExpr)
      (next : ComparisonKont goal (a :: as = b :: bs)) : ComparisonKont goal (a = b)

private inductive ComparisonWork (goal : Prop) where
  | compare (left right : PackedExpr) (next : ComparisonKont goal (left = right))
  | children (left right : List PackedExpr) (next : ComparisonKont goal (left = right))
  | resume {p : Prop} (decision : Decidable p) (next : ComparisonKont goal p)

-- Proof-only work budget: a constructor has at most three children, and each
-- child adds fewer than 64 frame-processing steps. No size traversal runs.
private noncomputable def childrenCost : List PackedExpr -> Nat
  | [] => 1
  | child :: rest => 64 * sizeOf child.2 + 7 + childrenCost rest

private noncomputable def ComparisonKont.cost {goal p : Prop} : ComparisonKont goal p -> Nat
  | .done => 0
  | .save _ _ _ next => next.cost + 1
  | .convert _ next => next.cost + 1
  | .tail _ _ as _ next => childrenCost as + 2 + next.cost

private noncomputable def ComparisonWork.cost {goal : Prop} : ComparisonWork goal -> Nat
  | .compare left _ next => 64 * sizeOf left.2 + 4 + next.cost
  | .children left _ next => childrenCost left + next.cost
  | .resume _ next => next.cost

private theorem childrenCost_smaller {s : Ty} (e : Expr s) :
    childrenCost (signature e).children + 2 < 64 * sizeOf e + 4 := by
  cases e <;> simp [signature, childrenCost] <;> omega

@[inline] private def withAddresses {goal : Prop} (left right : PackedExpr)
    (run : USize × USize -> Decidable goal) : Decidable goal :=
  withPtrAddr left.2 (fun a =>
    withPtrAddr right.2 (fun b => run (a, b)) (fun _ _ => Subsingleton.elim _ _))
    (fun _ _ => Subsingleton.elim _ _)

-- Addresses select buckets, never establish equality. All recursive calls
-- return to this same loop; address independence follows from the fixed goal.
private def compareLoop {goal : Prop} (work : ComparisonWork goal)
    (cache : ComparisonCache) : Decidable goal :=
  match work with
  | .compare ⟨s, a⟩ ⟨t, b⟩ next =>
      withAddresses ⟨s, a⟩ ⟨t, b⟩ (fun key =>
          let saved := ComparisonKont.save ⟨s, a⟩ ⟨t, b⟩ key next
          if key.1 == key.2 then
            compareLoop (.resume (structuralExprEq ⟨s, a⟩ ⟨t, b⟩) saved) cache
          else
            match findComparison ⟨s, a⟩ ⟨t, b⟩ (cache[key]?.getD []) with
            | some decision => compareLoop (.resume decision next) cache
            | none =>
                match s.sharedDecEq t with
                | .isFalse different => compareLoop (.resume (.isFalse (fun equal =>
                    different (congrArg Sigma.fst equal))) saved) cache
                | .isTrue same =>
                    let typedB : Expr s := same.symm ▸ b
                    have packedEqual :
                        a = typedB ↔ (⟨s, a⟩ : PackedExpr) = ⟨t, b⟩ := by
                      cases same
                      simp [typedB]
                    let lhs := signature a
                    let rhs := signature typedB
                    if header : lhs.tag = rhs.tag ∧ lhs.scalars = rhs.scalars then
                      compareLoop (.children lhs.children rhs.children (.convert (by
                        constructor
                        · intro equal
                          apply packedEqual.mp
                          exact signature_injective (by
                            cases ha : signature a
                            cases hb : signature typedB
                            simp_all [lhs, rhs])
                        · intro equal
                          exact congrArg (fun e => (signature e).children)
                            (packedEqual.mpr equal)) saved)) cache
                    else
                      compareLoop (.resume (.isFalse (fun equal =>
                        header (by
                          have expressionEqual := packedEqual.mpr equal
                          simp_all [lhs, rhs]))) saved) cache)
  | .children [] [] next => compareLoop (.resume (.isTrue rfl) next) cache
  | .children [] (_ :: _) next => compareLoop (.resume (.isFalse (by simp)) next) cache
  | .children (_ :: _) [] next => compareLoop (.resume (.isFalse (by simp)) next) cache
  | .children (a :: as) (b :: bs) next =>
      compareLoop (.compare a b (.tail a b as bs next)) cache
  | .resume decision continuation =>
      match continuation, decision with
      | .done, decision => decision
      | .save left right key next, decision =>
          compareLoop (.resume decision next)
            (cache.insert key (⟨left, right, decision⟩ :: cache[key]?.getD []))
      | .convert equivalent next, decision =>
          compareLoop (.resume (@decidable_of_iff _ _ equivalent decision) next) cache
      | .tail a b as bs next, .isFalse different =>
          compareLoop (.resume (.isFalse (fun equal =>
            different (List.cons.inj equal).1)) next) cache
      | .tail a b as bs next, .isTrue same =>
          compareLoop (.children as bs (.convert (by
            simp only [List.cons.injEq, same, true_and]) next)) cache
termination_by work.cost
decreasing_by
  all_goals dsimp only [ComparisonWork.cost, ComparisonKont.cost]
  all_goals first
    | omega
    | have := childrenCost_smaller a; omega
    | simp only [childrenCost]; omega

/-- Exact typed equality, including independently allocated shared subgraphs. -/
def packedExprEq (left right : (s : Ty) × Expr s) : Decidable (left = right) :=
  compareLoop (.compare left right .done) {}

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
