module

public import DisasterRecovery.Properties.Utils
public import CCF.Proofs.Execution

@[expose] public section

/-!
Helpers for checking concrete executions by evaluation. `List.merge` and `List.mergeSort`
are defined by well-founded recursion, so the kernel cannot evaluate `insertGossip` or
`insertVote`. `insertGossip_eval` and `insertVote_eval` restate them with structurally
recursive equivalents; after rewriting with `evalSimps`, concrete steps close by `rfl`.
-/

namespace DisasterRecovery.Proofs.Evaluation

open CCF
open Model.Local

/-- `List.merge` by structural recursion on fuel, so the kernel can evaluate it. -/
def mergeFuel {α : Type} (le : α -> α -> Bool) : Nat -> List α -> List α -> List α
  | 0, xs, ys => xs ++ ys
  | _ + 1, [], ys => ys
  | _ + 1, x :: xs, [] => x :: xs
  | fuel + 1, x :: xs, y :: ys =>
      if le x y then
        x :: mergeFuel le fuel xs (y :: ys)
      else
        y :: mergeFuel le fuel (x :: xs) ys

theorem merge_eq_mergeFuel {α : Type} (le : α -> α -> Bool)
    : forall (fuel : Nat) (xs ys : List α),
        xs.length + ys.length <= fuel -> List.merge xs ys le = mergeFuel le fuel xs ys := by
  sorry

/-- `List.mergeSort` by structural recursion on fuel, so the kernel can evaluate it. -/
def mergeSortFuel {α : Type} (le : α -> α -> Bool) : Nat -> List α -> List α
  | 0, xs => xs
  | fuel + 1, xs =>
      if xs.length < 2 then
        xs
      else
        mergeFuel le xs.length (mergeSortFuel le fuel (xs.take ((xs.length + 1) / 2)))
          (mergeSortFuel le fuel (xs.drop ((xs.length + 1) / 2)))

theorem mergeSort_eq_mergeSortFuel {α : Type} (le : α -> α -> Bool)
    : forall (fuel : Nat) (xs : List α),
        xs.length <= fuel -> xs.mergeSort le = mergeSortFuel le fuel xs := by
  sorry

theorem insertGossip_eval (source : Location) (txid : TxID)
    (gossips : List (Location × TxID))
    : insertGossip source txid gossips
      = if gossips.any (fun entry => entry.1 == source) then
          gossips
        else
          mergeSortFuel (fun left right => decide (left.1 <= right.1))
            (gossips.length + 1) ((source, txid) :: gossips) := by
  sorry

theorem insertVote_eval (source : Location) (votes : List Location)
    : insertVote source votes
      = if votes.contains source then
          votes
        else
          mergeSortFuel (fun left right => decide (left <= right)) (votes.length + 1)
            (source :: votes) := by
  sorry

end DisasterRecovery.Proofs.Evaluation
