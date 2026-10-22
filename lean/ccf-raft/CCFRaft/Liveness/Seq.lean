module

public import Mathlib.Data.Seq.Defs
public import Mathlib.Data.Nat.Find

@[expose] public section

/-!
Generic sequence helpers, independent of the Raft model.
Filtering an arbitrary infinite sequence is noncomputable: there may be no next
retained element, even though the input never ends.
-/

namespace Stream'.Seq

universe u v

variable {α : Type u} {β : Type v}

/-- Map and retain the `some` results, preserving order and repeated values. -/
noncomputable def filterMap (transform : α -> Option β) (sequence : Seq α) : Seq β := by
  classical
  exact corec (fun (start : Nat) =>
    if remaining : exists index, start <= index
        /\ ((sequence.get? index).bind transform).isSome = true then
      let index := Nat.find remaining
      ((sequence.get? index).bind transform).map fun value => (value, index + 1)
    else none) 0

/-- Retain exactly the elements satisfying `predicate`, in their original order. -/
noncomputable def filter (predicate : α -> Bool) (sequence : Seq α) : Seq α :=
  sequence.filterMap fun value => if predicate value then some value else none

end Stream'.Seq
