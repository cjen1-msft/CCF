module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.GrantFrontier

namespace ConsensusCoverage.CensusGrants
open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev Key := NodeID × NodeID × Nat
private abbrev Table := List (Key × (Nat × Nat))

private noncomputable def candidate (g : Ghost) (before : Model.State) (p : NodeID × NodeState) :
    Option (Key × (Nat × Nat)) := do
  let (v, y) := p
  let c ← y.votedFor
  let x ← before.nodes.lookup v
  let k := y.currentTerm
  guard (x.currentTerm ≤ k && (v == c || g.seen.any fun (n, term, _) => n == c && term == k))
  let min := GrantFrontier.minimum x k
  guard (!g.granted v c k min)
  return ((v, c, k), (min.lastCommittableTerm, min.lastCommittableIndex))

private noncomputable def insert (g : Ghost) (s : Model.State) (a : Table × Bool) (p : NodeID × NodeState) :
    Table × Bool :=
  match candidate g s p with
  | none => a
  | some (key, val) => ((key, val) :: a.1.filter (·.1 != key), true)

private theorem for_fold {α β : Type} (xs : List α) (init : β) (f : β → α → β) :
    (forIn xs init (fun x b => (pure (.yield (f b x)) : Id (ForInStep β)))).run =
      xs.foldl f init := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih =>
    rw [List.forIn_cons]
    exact ih (f init x)

private theorem extend_fold (g : Ghost) (s t : Model.State) :
    extendGrants g s t = t.nodes.foldl (insert g s) (g.grants, false) := by
  rw [← for_fold]
  unfold extendGrants
  change (forIn t.nodes (g.grants, false) _ : Id (Table × Bool)) = forIn t.nodes (g.grants, false) _
  congr 1
  funext ⟨v, y⟩ ⟨a, fresh⟩
  cases vote : y.votedFor with
  | none => simp [candidate, insert, vote]
  | some c =>
    cases pre : s.nodes.lookup v with
    | none => simp [candidate, insert, vote, pre]
    | some x =>
      by_cases e : (x.currentTerm ≤ y.currentTerm &&
        (v == c || g.seen.any fun (n, term, _) => n == c && term == y.currentTerm)) = true
      <;> cases old : g.granted v c y.currentTerm (GrantFrontier.minimum x y.currentTerm)
      <;> simp [candidate, insert, pre, vote, e, old, guard] <;> rfl

private theorem lookup_remove_other (other key : Key) (ne : key ≠ other) (as : Table) :
    (as.filter (·.1 != other)).lookup key = as.lookup key := by
  induction as with
  | nil => rfl
  | cons p ps ih =>
    rcases p with ⟨k, val⟩
    by_cases h : k = other
    · subst k
      simp [List.lookup_cons, beq_eq_false_iff_ne.mpr ne, ih]
    · simp [h, List.lookup_cons, ih]

private theorem lookup_after_insert (g : Ghost) (s : Model.State) (a : Table × Bool)
    (p : NodeID × NodeState) (k : Key) :
    (insert g s a p).1.lookup k =
      ((candidate g s p).bind fun (key, val) => if k = key then some val else none).or
        (a.1.lookup k) := by
  cases h : candidate g s p with
  | none => simp [insert, h]
  | some kv =>
    rcases kv with ⟨key, val⟩
    by_cases eq : k = key
    · simp [insert, h, eq]
    · simp [insert, h, eq, List.lookup_cons, beq_eq_false_iff_ne.mpr eq, lookup_remove_other _ _ eq]

private theorem fold_lookup (g : Ghost) (s : Model.State) (a : Table × Bool)
    (rows : List (NodeID × NodeState)) (k : Key) :
    (rows.foldl (insert g s) a).1.lookup k =
      ((rows.reverse.filterMap (candidate g s)).lookup k).or (a.1.lookup k) := by
  induction rows generalizing a with
  | nil => rfl
  | cons p ps ih =>
    rw [List.foldl_cons, ih, lookup_after_insert]
    simp only [List.reverse_cons, List.filterMap_append, List.lookup_append]
    cases opt : (ps.reverse.filterMap (candidate g s)).lookup k with
    | some v => rfl
    | none =>
      cases entry : candidate g s p with
      | none => simp [List.filterMap, entry]
      | some kv =>
        rcases kv with ⟨key, val⟩
        by_cases eq : k = key
        · simp [List.filterMap, entry, eq]
        · simp [List.filterMap, entry, eq, List.lookup_cons, beq_eq_false_iff_ne.mpr eq]

private def select (k : Key) (p : Option (Key × (Nat × Nat))) : Option (Nat × Nat) :=
  p.bind fun (key, val) => if k = key then some val else none

private theorem select_other (g : Ghost) (s : Model.State) (v w c k : Nat) (y : NodeState)
    (ne : v ≠ w) : select (v, c, k) (candidate g s (w, y)) = none := by
  cases vote : y.votedFor with
  | none => simp [candidate, vote, select]
  | some c' =>
    cases pre : s.nodes.lookup w with
    | none => simp [candidate, vote, pre, select]
    | some x =>
      by_cases e : (x.currentTerm ≤ y.currentTerm &&
          (w == c' || g.seen.any fun (n, term, _) => n == c' && term == y.currentTerm)) = true
      <;> cases old : g.granted w c' y.currentTerm (GrantFrontier.minimum x y.currentTerm)
      <;> simp [candidate, vote, pre, select, e, old, guard, ne,
        show (failure : Option Unit) = none from rfl]

private theorem select_cons (g : Ghost) (s : Model.State) (p : NodeID × NodeState)
    (ps : List (NodeID × NodeState)) (k : Key) :
    ((p :: ps).filterMap (candidate g s)).lookup k =
      (select k (candidate g s p)).or ((ps.filterMap (candidate g s)).lookup k) := by
  cases e : candidate g s p with
  | none => simp [List.filterMap, e, select]
  | some kv =>
    rcases kv with ⟨key, val⟩
    by_cases eq : k = key
    · simp [List.filterMap, e, select, eq]
    · simp [List.filterMap, e, select, eq, List.lookup_cons, beq_eq_false_iff_ne.mpr eq]

private theorem select_rows (g : Ghost) (s : Model.State) (rows : List (NodeID × NodeState))
    (target : Option NodeState) (v c k : Nat)
    (ok : ∀ w y, (w, y) ∈ rows → w = v → target = some y) :
    (rows.filterMap (candidate g s)).lookup (v, c, k) =
      if rows.any (fun p => p.1 == v) then
        target.bind (fun y => select (v, c, k) (candidate g s (v, y))) else none := by
  induction rows with
  | nil => rfl
  | cons p ps ih =>
    rcases p with ⟨w, y⟩
    rw [select_cons, ih (fun w y h => ok w y (.tail _ h))]
    by_cases eq : w = v
    · subst w
      rw [ok v y (.head _) rfl]
      simp only [List.any_cons, beq_self_eq_true, Bool.true_or, ite_true, Option.bind_some]
      cases select (v, c, k) (candidate g s (v, y)) <;> cases ps.any (fun p => p.1 == v) <;> rfl
    · rw [select_other g s v w c k y (Ne.symm eq), List.any_cons]
      change _ = if (w == v || ps.any _) then _ else _
      rw [show (w == v) = false from beq_eq_false_iff_ne.mpr eq]
      rfl

private theorem extend_lookup (g : Ghost) (s t : Model.State) (v c k : Nat)
    (ok : ∀ y, (v, y) ∈ t.nodes ↔ t.nodes.lookup v = some y) :
    (extendGrants g s t).1.lookup (v, c, k) =
      ((t.nodes.lookup v).bind fun y => select (v, c, k) (candidate g s (v, y))).or
        (g.grants.lookup (v, c, k)) := by
  rw [extend_fold, fold_lookup, select_rows g s t.nodes.reverse (t.nodes.lookup v) v c k
    (fun w y h e => e ▸ (ok _).mp (by simpa [e] using h))]
  cases post : t.nodes.lookup v with
  | none => simp
  | some y =>
    have mem : (v, y) ∈ t.nodes.reverse := by simpa using (ok _).mpr post
    rw [ite_eq_left (List.any_eq_true.mpr ⟨_, mem, by simp⟩)]

/-- With unambiguous lookup for the queried voter, the full update answers
exactly as the single-voter update, regardless of all other voters. -/
public theorem by_voter (g : Ghost) (s t : Model.State) (v c k : Nat) (r : RequestVoteRequest)
    (y : NodeState) (post : t.nodes.lookup v = some y)
    (lookup : ∀ z, (v, z) ∈ t.nodes ↔ t.nodes.lookup v = some z) :
    ({g with grants := (extendGrants g s t).1}).granted v c k r =
      ({g with grants := (extendGrants g s {t with nodes := [(v, y)]}).1}).granted v c k r := by
  unfold Ghost.granted
  rw [extend_lookup _ _ _ _ _ _ lookup, extend_lookup]
  · simp [post]
  · intro z
    simp [eq_comm]

/-- A voter absent from the after-table contributes no new threshold. -/
public theorem absent (g : Ghost) (s t : Model.State) (v c k : Nat) (r : RequestVoteRequest)
    (post : t.nodes.lookup v = none)
    (lookup : ∀ z, (v, z) ∈ t.nodes ↔ t.nodes.lookup v = some z) :
    ({g with grants := (extendGrants g s t).1}).granted v c k r = g.granted v c k r := by
  unfold Ghost.granted
  rw [extend_lookup _ _ _ _ _ _ lookup]
  simp [post]

end ConsensusCoverage.CensusGrants
