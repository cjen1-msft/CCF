-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtTerm

set_option autoImplicit false

namespace TraceSmt.NatTerm

def children {holes : Nat} : NatTerm holes -> List (NatTerm holes)
  | .literal _ | .unknown _ => []
  | .add a b | .sub a b | .min a b | .max a b => [a, b]
  | .iteEqual a b c d => [a, b, c, d]
  | .named _ _ _ value => [value]
  | .clampIfEqual a b c d e => [a, b, c, d, e]

private def header {holes : Nat} : NatTerm holes -> Nat × List Nat × String
  | .literal value => (0, [value], "")
  | .unknown index => (1, [index.val], "")
  | .add _ _ => (2, [], "")
  | .sub _ _ => (3, [], "")
  | .iteEqual _ _ _ _ => (4, [], "")
  | .named group slot label _ => (5, [group, slot], label)
  | .min _ _ => (6, [], "")
  | .max _ _ => (7, [], "")
  | .clampIfEqual _ _ _ _ _ => (8, [], "")

private theorem parts_equal {holes : Nat} (a b : NatTerm holes)
    (head : header a = header b) : a.children = b.children ↔ a = b := by
  cases a <;> cases b <;> simp_all [header, children]
  all_goals exact Fin.ext head

theorem child_smaller {holes : Nat} (term child : NatTerm holes)
    (member : child ∈ term.children) : sizeOf child < sizeOf term := by
  cases term <;> simp only [children, List.mem_cons, List.not_mem_nil, or_false] at member
  all_goals rcases member with rfl | rfl | rfl | rfl | rfl <;> simp <;> omega

private def boundedHash {holes : Nat} : Nat -> NatTerm holes -> UInt64
  | 0, _ => 0
  | depth + 1, term =>
      term.children.foldl (fun result child => mixHash result (boundedHash depth child))
        (hash (header term))

/-- A bounded-cost hint, never a substitute for exact syntax comparison. -/
def memoKey {holes : Nat} (term : NatTerm holes) : UInt64 := boundedHash 3 term

private def childrenEq {holes : Nat} (left right : List (NatTerm holes))
    (compare : ∀ child ∈ left, ∀ other, Decidable (child = other)) :
    Decidable (left = right) :=
  match left, right with
  | [], [] => .isTrue rfl
  | [], _ :: _ | _ :: _, [] => .isFalse (by simp)
  | a :: as, b :: bs =>
      match compare a (by simp) b with
      | .isFalse different => .isFalse (fun equal => different (List.cons.inj equal).1)
      | .isTrue same =>
          match childrenEq as bs (fun child member other =>
              compare child (List.mem_cons_of_mem _ member) other) with
          | .isFalse different => .isFalse (fun equal => different (List.cons.inj equal).2)
          | .isTrue rest => .isTrue (by cases same; cases rest; rfl)

private def structuralEq {holes : Nat} (a b : NatTerm holes) : Decidable (a = b) :=
  withPtrEqDecEq a b fun _ =>
    if head : header a = header b then
      @decidable_of_iff _ _ (parts_equal a b head)
        (childrenEq a.children b.children (fun child _member other => structuralEq child other))
    else .isFalse (fun equal => head (congrArg header equal))
termination_by sizeOf a
decreasing_by exact child_smaller _ _ _member

private structure Compared (holes : Nat) where
  left : NatTerm holes
  right : NatTerm holes
  decision : Decidable (left = right)

private abbrev Comparisons (holes : Nat) :=
  Std.HashMap (USize × USize) (List (Compared holes))

private def findComparison {holes : Nat} (left right : NatTerm holes) :
    List (Compared holes) -> Option (Decidable (left = right))
  | [] => none
  | prior :: rest =>
      match structuralEq prior.left left, structuralEq prior.right right with
      | .isTrue sameLeft, .isTrue sameRight =>
          some (by simpa only [← sameLeft, ← sameRight] using prior.decision)
      | _, _ => findComparison left right rest

private inductive Kont (holes : Nat) (goal : Prop) : Prop -> Type where
  | done : Kont holes goal goal
  | save (left right : NatTerm holes) (key : USize × USize)
      (next : Kont holes goal (left = right)) : Kont holes goal (left = right)
  | convert {p q : Prop} (equivalent : p ↔ q)
      (next : Kont holes goal q) : Kont holes goal p
  | tail (a b : NatTerm holes) (as bs : List (NatTerm holes))
      (next : Kont holes goal (a :: as = b :: bs)) : Kont holes goal (a = b)

private inductive Work (holes : Nat) (goal : Prop) where
  | compare (left right : NatTerm holes) (next : Kont holes goal (left = right))
  | children (left right : List (NatTerm holes)) (next : Kont holes goal (left = right))
  | resume {p : Prop} (decision : Decidable p) (next : Kont holes goal p)

private noncomputable def childrenCost {holes : Nat} : List (NatTerm holes) -> Nat
  | [] => 1
  | child :: rest => 64 * sizeOf child + 7 + childrenCost rest

private noncomputable def Kont.cost {holes : Nat} {goal p : Prop} : Kont holes goal p -> Nat
  | .done => 0
  | .save _ _ _ next | .convert _ next => next.cost + 1
  | .tail _ _ as _ next => childrenCost as + 2 + next.cost

private noncomputable def Work.cost {holes : Nat} {goal : Prop} : Work holes goal -> Nat
  | .compare left _ next => 64 * sizeOf left + 4 + next.cost
  | .children left _ next => childrenCost left + next.cost
  | .resume _ next => next.cost

private theorem childrenCost_smaller {holes : Nat} (term : NatTerm holes) :
    childrenCost term.children + 2 < 64 * sizeOf term + 4 := by
  cases term <;> simp [children, childrenCost] <;> omega

@[inline] private def withAddresses {holes : Nat} {goal : Prop}
    (left right : NatTerm holes) (run : USize × USize -> Decidable goal) : Decidable goal :=
  withPtrAddr left (fun a =>
    withPtrAddr right (fun b => run (a, b)) (fun _ _ => Subsingleton.elim _ _))
    (fun _ _ => Subsingleton.elim _ _)

-- Exact checks guard address buckets. Explicit frames avoid retaining a native
-- continuation for every previously visited node of a wide expression.
private def compareLoop {holes : Nat} {goal : Prop}
    (work : Work holes goal) (cache : Comparisons holes) : Decidable goal :=
  match work with
  | .compare a b next =>
      withAddresses a b fun key =>
        let saved := Kont.save a b key next
        if key.1 == key.2 then
          compareLoop (.resume (structuralEq a b) saved) cache
        else
          match findComparison a b (cache[key]?.getD []) with
          | some decision => compareLoop (.resume decision next) cache
          | none =>
              if head : header a = header b then
                compareLoop (.children a.children b.children
                  (.convert (parts_equal a b head) saved)) cache
              else compareLoop (.resume (.isFalse (fun equal =>
                head (congrArg header equal))) saved) cache
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
      | .tail _ _ _ _ next, .isFalse different =>
          compareLoop (.resume (.isFalse (fun equal =>
            different (List.cons.inj equal).1)) next) cache
      | .tail _ _ as bs next, .isTrue same =>
          compareLoop (.children as bs (.convert (by
            simp only [List.cons.injEq, same, true_and]) next)) cache
termination_by work.cost
decreasing_by
  all_goals dsimp only [Work.cost, Kont.cost]
  all_goals first
    | omega
    | have := childrenCost_smaller a; omega
    | simp only [childrenCost]; omega

/-- Exact equality for one fixed hole type; no global instance is installed. -/
def sharedDecEq {holes : Nat} (a b : NatTerm holes) : Decidable (a = b) :=
  compareLoop (.compare a b .done) {}

theorem sharedDecEq_correct {holes : Nat} (a b : NatTerm holes) :
    @decide (a = b) (sharedDecEq a b) = decide (a = b) :=
  congrArg (fun decision => @decide (a = b) decision) (Subsingleton.elim _ _)

/-- All callers share the same exact check, including shallow-hash collisions. -/
def lookup {holes : Nat} {α : Type} (term : NatTerm holes) :
    List (NatTerm holes × α) -> Option α
  | [] => none
  | (prior, value) :: rest =>
      match sharedDecEq term prior with
      | .isTrue _ => some value
      | .isFalse _ => lookup term rest

theorem lookup_sound {holes : Nat} {α : Type} (term : NatTerm holes)
    (entries : List (NatTerm holes × α)) (value : α)
    (found : lookup term entries = some value) : (term, value) ∈ entries := by
  induction entries with
  | nil => simp [lookup] at found
  | cons entry rest ih =>
      rcases entry with ⟨prior, stored⟩
      unfold lookup at found
      split at found
      · simp_all
      · exact List.mem_cons_of_mem _ (ih found)

end TraceSmt.NatTerm
