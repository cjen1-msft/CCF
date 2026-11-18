module

public import Consensus.Model
import Relevance.Split

namespace Consensus.Proofs.LogFacts

open Model.Node

@[expose] public section

/-- Relations over proof witnesses, not snapshots or positions in a run. -/
structure Ghost where
  seen : NodeID → Nat → List Entry → Prop
  grant : NodeID → NodeID → Nat → RequestVoteRequest → Prop
  elected : NodeID → Nat → List Entry → Nat → Prop
  canon : Nat → List Entry → Prop
  committed : Nat → List Entry → Prop

def empty : Ghost :=
  ⟨fun _ _ _ => False, fun _ _ _ _ => False, fun _ _ _ _ => False,
   fun _ _ => False, fun _ _ => False⟩

def requestAt (term : Nat) (log : List Entry) (commit : Nat) : RequestVoteRequest where
  term
  lastCommittableTerm := termAt log (max commit (maxCommittableIndex log))
  lastCommittableIndex := max commit (maxCommittableIndex log)

def GrantAt (s t : Model.State) (v c : NodeID) (k : Nat) (r : RequestVoteRequest) : Prop :=
  ∃ x y, (v, x) ∈ s.nodes ∧ (v, y) ∈ t.nodes ∧ x.currentTerm ≤ k ∧
    y.currentTerm = k ∧ y.votedFor = some c ∧ voteLogUpToDate x r

def ElectionAt (s t : Model.State) (grants : NodeID → NodeID → Nat → RequestVoteRequest → Prop)
    (n : NodeID) (k : Nat) (log : List Entry) (commit : Nat) : Prop :=
  ∃ x y, (n, x) ∈ s.nodes ∧ (n, y) ∈ t.nodes ∧ x.log = log ∧ x.commitIndex = commit ∧
    commit ≤ log.length ∧ (x.currentTerm < k ∨ (x.currentTerm = k ∧ x.role = .candidate)) ∧
    y.currentTerm = k ∧ (y.role = .primary ∨ y.role = .none) ∧
    log.take (maxCommittableIndex log) <+: y.log ∧ 3 ≤ k ∧
    ∃ voters, hasQuorum (activeConfigurations log commit) voters ∧
      ∀ v ∈ voters, grants v n k (requestAt k log commit)

def Ghost.led (g : Ghost) (bootstrap n : NodeID) (k : Nat) : Prop :=
  (k = Model.BOOTSTRAP_TERM ∧ n = bootstrap) ∨ ∃ l i, g.elected n k l i

def Ghost.canonNow (g : Ghost) (bootstrap : NodeID) (s : Model.State)
    (n : NodeID) (st : NodeState) (k : Nat) : Prop :=
  (n, st) ∈ s.nodes ∧ st.currentTerm = k ∧ st.role ≠ .candidate ∧ g.led bootstrap n k

def Ghost.commitAt (g : Ghost) (bootstrap : NodeID) (s : Model.State)
    (n : NodeID) (st : NodeState) (k base i : Nat) : Prop :=
  g.canonNow bootstrap s n st k ∧ base ≤ i ∧ i ≤ st.log.length ∧
    isSignatureAt st.log i = true ∧ termAt st.log i = k ∧
    ∃ voters, hasQuorum ((activeConfigurations st.log base).filter (·.index ≤ i)) voters ∧
      ∀ v ∈ voters, ∃ l, g.seen v k l ∧ st.log.take i <+: l

/-- Initialisation has no incoming step; it can observe logs, but not grants or elections.
New elections may count new grants. New commits may use only *old* committed backing. -/
def advance (bootstrap : NodeID) (g : Ghost) (prev : Option Model.State) (s : Model.State) : Ghost := Id.run do
  let g := { g with grant := fun v c k r => g.grant v c k r ∨
    ∃ p, prev = some p ∧ GrantAt p s v c k r ∧ (v = c ∨ ∃ l, g.seen c k l) }
  let g := { g with elected := fun n k l i => g.elected n k l i ∨
    ∃ p, prev = some p ∧ ElectionAt p s g.grant n k l i }
  let g := { g with seen := fun n k l => g.seen n k l ∨
    ∃ st, (n, st) ∈ s.nodes ∧ st.currentTerm = k ∧ st.log = l }
  let g := { g with canon := fun k l => g.canon k l ∨
    ∃ n st, g.canonNow bootstrap s n st k ∧ st.log = l }
  return { g with committed := fun k l => g.committed k l ∨
    ∃ n st base i, g.commitAt bootstrap s n st k base i ∧ l = st.log.take i ∧
      (base = 0 ∨ ∃ earlier part, g.committed earlier part ∧ earlier ≤ k ∧ st.log.take base <+: part) }

def Origin (g : Ghost) : Prop :=
  ∀ k p, g.committed k p → ∃ l, g.canon k l ∧ p <+: l

def Chain (g : Ghost) : Prop :=
  ∀ k a b, g.canon k a → g.canon k b → a <+: b ∨ b <+: a

/-- A non-bootstrap leader log carries the winning committable prefix. This is what
the original proof used to recover by visiting the instant the leader log was seen. -/
def WinningPrefix (g : Ghost) : Prop :=
  ∀ k l, g.canon k l → Model.BOOTSTRAP_TERM < k →
    ∃ n p i, g.elected n k p i ∧ p.take (maxCommittableIndex p) <+: l

theorem winningPrefix_step {bootstrap g prev s} (old : WinningPrefix g)
    (wins : ∀ n st k, (advance bootstrap g prev s).canonNow bootstrap s n st k →
      Model.BOOTSTRAP_TERM < k → ∃ p i, (advance bootstrap g prev s).elected n k p i ∧
        p.take (maxCommittableIndex p) <+: st.log) :
    WinningPrefix (advance bootstrap g prev s) := by
  intro k l canon gt
  split_rel canon := (rcases canon with past | ⟨n, st, now, rfl⟩) with
  | inl =>
    obtain ⟨n, p, i, elect, sub⟩ := old k l past gt
    exact ⟨n, p, i, .inl elect, sub⟩
  | inr =>
    obtain ⟨p, i, elect, sub⟩ := wins n st k now gt
    exact ⟨n, p, i, elect, sub⟩

def Complete (g : Ghost) : Prop :=
  ∀ k p n t l i, g.committed k p → g.elected n t l i → k < t → p <+: l

def Later (g : Ghost) : Prop :=
  ∀ k t p l, g.committed k p → g.canon t l → k < t → p <+: l

theorem later_of_complete {g : Ghost} (wins : WinningPrefix g) (complete : Complete g)
    (signed : ∀ k p, g.committed k p →
      Model.BOOTSTRAP_TERM ≤ k ∧ isSignatureAt p p.length = true)
    (kept : ∀ {p l : List Entry}, p <+: l → isSignatureAt p p.length = true →
      p <+: l.take (maxCommittableIndex l)) : Later g := by
  intro k t p l commit canon lt
  obtain ⟨floor, sig⟩ := signed k p commit
  obtain ⟨n, e, i, elect, sub⟩ := wins t l canon (Nat.lt_of_le_of_lt floor lt)
  exact (kept (complete k p n t e i commit elect lt) sig).trans sub

theorem origin_step {bootstrap g prev s} (old : Origin g) :
    Origin (advance bootstrap g prev s) := by
  intro k p c
  rcases c with past | ⟨n, st, _, i, step, rfl, _⟩
  · obtain ⟨l, canon, sub⟩ := old _ _ past
    exact ⟨l, Or.inl canon, sub⟩
  · exact ⟨st.log, Or.inr ⟨n, st, step.1, rfl⟩, List.take_prefix ..⟩

theorem chain_step {bootstrap g prev s} (old : Chain g)
    (grows : ∀ n st k, (advance bootstrap g prev s).canonNow bootstrap s n st k →
      ∀ l, (advance bootstrap g prev s).canon k l → l <+: st.log) :
    Chain (advance bootstrap g prev s) := by
  intro k a b ca cb
  split_rel right := (rcases cb with past | ⟨n, st, now, rfl⟩) with
  | inl =>
    split_rel left := (rcases ca with past' | ⟨n, st, now, rfl⟩) with
    | inl => exact old k a b past' past
    | inr => exact .inr (grows n st k now b (.inl past))
  | inr => exact .inl (grows n st k now a ca)

/-- These are the inputs the original comparison proof actually uses. The same-term
and different-term cases need no positions, witnesses' histories, or temporal induction. -/
theorem comparable (g : Ghost)
    (backed : Origin g) (chain : Chain g)
    (later : Later g)
    {k t p q} (hp : g.committed k p) (hq : g.committed t q) : p <+: q ∨ q <+: p := by
  obtain ⟨a, ca, pa⟩ := backed k p hp
  obtain ⟨b, cb, qb⟩ := backed t q hq
  split_rel terms := (rcases Nat.lt_trichotomy k t with lt | rfl | gt) with
  | inl => exact List.prefix_or_prefix_of_prefix (later _ _ _ _ hp cb lt) qb
  | inr_inl =>
    split_rel chain := (rcases chain k a b ca cb with sub | sub) with
    | inl => exact List.prefix_or_prefix_of_prefix (pa.trans sub) qb
    | inr => exact List.prefix_or_prefix_of_prefix pa (qb.trans sub)
  | inr_inr => exact List.prefix_or_prefix_of_prefix pa (later _ _ _ _ hq ca gt)

end
end Consensus.Proofs.LogFacts
