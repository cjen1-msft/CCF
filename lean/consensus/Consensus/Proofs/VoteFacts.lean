module

public import Consensus.Model
import Relevance.Split

namespace Consensus.Proofs.VoteFacts

open Model.Node

public structure Stamp where
  voter : NodeID
  term : Nat
  vote : Option NodeID
deriving DecidableEq

public abbrev Ghost := List Stamp

@[expose] public def stamp (n : NodeID) (s : NodeState) : Stamp := ⟨n, s.currentTerm, s.votedFor⟩

/-- Duplicate observations carry no information. No ordering or past snapshots are read. -/
public def advance (g : Ghost) (s : Model.State) : Ghost :=
  ((s.nodes.map fun (n, st) => stamp n st) ++ g).eraseDups

public theorem mem_advance {g : Ghost} {s : Model.State} {b : Stamp} :
    b ∈ advance g s ↔ (∃ n st, (n, st) ∈ s.nodes ∧ stamp n st = b) ∨ b ∈ g := by
  simp [advance, List.mem_map, Prod.exists]

public structure Inv (s : Model.State) (g : Ghost) : Prop where
  bounds : ∀ b ∈ g, ∀ st, (b.voter, st) ∈ s.nodes → b.term ≤ st.currentTerm
  keeps : ∀ b ∈ g, ∀ st, (b.voter, st) ∈ s.nodes → b.term = st.currentTerm →
    ∀ c, b.vote = some c → st.votedFor = some c
  unique : ∀ n k a b, ⟨n, k, some a⟩ ∈ g → ⟨n, k, some b⟩ ∈ g → a = b

/-- The two premises about node states are discharged by the original CCF transition proof. -/
public theorem preserve {s t : Model.State} {g : Ghost} (prior : Inv s g)
    (uniqueNow : ∀ n a b, (n, a) ∈ t.nodes → (n, b) ∈ t.nodes → a = b)
    (localStep : ∀ n b, (n, b) ∈ t.nodes →
      ∃ a, (n, a) ∈ s.nodes ∧ a.currentTerm ≤ b.currentTerm ∧
        (a.currentTerm = b.currentTerm → ∀ c, a.votedFor = some c → b.votedFor = some c)) :
    Inv t (advance g t) := by
  have current {b : Stamp} (observed : b ∈ advance g t) {st : NodeState}
      (now : (b.voter, st) ∈ t.nodes) :
      b.term ≤ st.currentTerm ∧ (b.term = st.currentTerm → ∀ c, b.vote = some c → st.votedFor = some c) := by
    split_rel observed := (rcases mem_advance.1 observed with ⟨n, x, mem, rfl⟩ | old) with
    | inl =>
      obtain rfl := uniqueNow _ _ _ mem now
      exact ⟨Nat.le_refl _, fun _ _ h => h⟩
    | inr =>
      obtain ⟨a, pre, le, keep⟩ := localStep _ _ now
      have bound := prior.bounds b old a pre
      refine ⟨Nat.le_trans bound le, fun eq c v => ?_⟩
      have termEq := Nat.le_antisymm le (eq ▸ bound)
      exact keep termEq c (prior.keeps b old a pre (eq.trans termEq.symm) c v)
  refine ⟨fun _ h _ mem => (current h mem).1, fun _ h _ mem => (current h mem).2, ?_⟩
  intro n k a b left right
  have compare {x y : NodeID} (left : ⟨n, k, some x⟩ ∈ advance g t)
      {st : NodeState} (mem : (n, st) ∈ t.nodes) (term : st.currentTerm = k)
      (vote : st.votedFor = some y) : x = y :=
    Option.some.inj (((current left mem).2 term.symm _ rfl).symm.trans vote)
  split_rel right := (rcases mem_advance.1 right with ⟨n', st, mem, eq⟩ | oldR) with
  | inl =>
    obtain ⟨rfl, term, vote⟩ := Stamp.mk.inj eq
    exact compare left mem term vote
  | inr =>
    split_rel left := (rcases mem_advance.1 left with ⟨n', st, mem, eq⟩ | oldL) with
    | inl =>
      obtain ⟨rfl, term, vote⟩ := Stamp.mk.inj eq
      exact (compare right mem term vote).symm
    | inr => exact prior.unique n k a b oldL oldR

public theorem initial (s : Model.State)
    (uniqueNow : ∀ n a b, (n, a) ∈ s.nodes → (n, b) ∈ s.nodes → a = b) :
    Inv s (advance [] s) :=
  preserve (s := s) ⟨by simp, by simp, by simp⟩ uniqueNow
    (fun _ st h => ⟨st, h, Nat.le_refl _, fun _ _ v => v⟩)

end Consensus.Proofs.VoteFacts
