module

public import Consensus.Model

/-! The log ghost. Definitions only: the proofs about them are in `SafetyInvariant.lean`,
the module whose proof bodies the coverage generator reads. -/

namespace Consensus.Proofs.LogFacts

open Model.Node

@[expose] public section

/-- Relations over proof witnesses, not snapshots or positions in a run. Committed
prefixes are not recorded: they are determined by the leader logs and observations
(`Commit` in `SafetyInvariant.lean`). -/
structure Ghost where
  seen : NodeID → Nat → List Entry → Prop
  grant : NodeID → NodeID → Nat → RequestVoteRequest → Prop
  elected : NodeID → Nat → List Entry → Nat → Prop
  canon : Nat → List Entry → Prop

def empty : Ghost :=
  ⟨fun _ _ _ => False, fun _ _ _ _ => False, fun _ _ _ _ => False, fun _ _ => False⟩

def requestAt (term : Nat) (log : List Entry) (commit : Nat) : RequestVoteRequest where
  term
  lastCommittableTerm := termAt log (max commit (maxCommittableIndex log))
  lastCommittableIndex := max commit (maxCommittableIndex log)

/-- The request ranks at least as high as `log`: its last committable term is no earlier,
and at equal terms its last committable index is no earlier. This is `voteLogUpToDate` as
a bound and an implication. -/
def Outranks (r : RequestVoteRequest) (log : List Entry) : Prop :=
  maxCommittableTerm log ≤ r.lastCommittableTerm ∧
    (maxCommittableTerm log = r.lastCommittableTerm →
      maxCommittableIndex log ≤ r.lastCommittableIndex)

def GrantAt (s t : Model.State) (v c : NodeID) (k : Nat) (r : RequestVoteRequest) : Prop :=
  ∃ x y, (v, x) ∈ s.nodes ∧ (v, y) ∈ t.nodes ∧ x.currentTerm ≤ k ∧
    y.currentTerm = k ∧ y.votedFor = some c ∧ Outranks r x.log

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

/-- Initialisation has no incoming step; it can observe logs, but not grants or elections.
A grant is recorded once its candidate has been observed in the term, in this state or
earlier. New elections may count new grants. -/
def advance (bootstrap : NodeID) (g : Ghost) (prev : Option Model.State) (s : Model.State) : Ghost := Id.run do
  let g := { g with seen := fun n k l => g.seen n k l ∨
    ∃ st, (n, st) ∈ s.nodes ∧ st.currentTerm = k ∧ st.log = l }
  let g := { g with grant := fun v c k r => g.grant v c k r ∨
    ∃ p, prev = some p ∧ GrantAt p s v c k r ∧ ∃ l, g.seen c k l }
  let g := { g with elected := fun n k l i => g.elected n k l i ∨
    ∃ p, prev = some p ∧ ElectionAt p s g.grant n k l i }
  return { g with canon := fun k l => g.canon k l ∨
    ∃ n st, g.canonNow bootstrap s n st k ∧ st.log = l }

def Chain (g : Ghost) : Prop :=
  ∀ k a b, g.canon k a → g.canon k b →
    ∀ n, n ≤ a.length → n ≤ b.length → a.take n = b.take n

/-- A non-bootstrap leader log carries the winning committable prefix. This is what
the original proof used to recover by visiting the instant the leader log was seen. -/
def WinningPrefix (g : Ghost) : Prop :=
  ∀ k l, g.canon k l → Model.BOOTSTRAP_TERM < k →
    ∃ n p i, g.elected n k p i ∧ p.take (maxCommittableIndex p) <+: l

end
end Consensus.Proofs.LogFacts
