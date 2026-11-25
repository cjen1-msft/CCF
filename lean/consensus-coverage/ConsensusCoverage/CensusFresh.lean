module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.CanonicalLogs

namespace ConsensusCoverage.CensusFresh

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

private def possibleElection (s t : Model.State) : Bool :=
  s.nodes.any fun (n, x) => t.nodes.any fun (m, y) =>
    decide (n = m ∧ (x.currentTerm < y.currentTerm ∨
      (x.currentTerm = y.currentTerm ∧ x.role = .candidate)) ∧
      (y.role = .primary ∨ y.role = .none))

private theorem possible_of_election {t s : Model.State} {h : List Model.State} {n k : Nat}
    {l : List Entry} {i : Nat} (e : electionExact t s h n k l i = true) :
    possibleElection s t = true := by
  simp only [electionExact, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq] at e
  obtain ⟨_, x, hx, _, y, hy, ⟨rfl, rfl, _, _, _, campaign, rfl, role, _, _⟩, _⟩ := e
  simp only [possibleElection, List.any_eq_true, Prod.exists, decide_eq_true_eq]
  exact ⟨_, x, hx, _, y, hy, rfl, campaign, role⟩

@[noinline] private def present (keys : List (Nat × List Entry)) (q : Nat × List Entry) : Bool :=
  keys.any fun k => decide (k = q)

private theorem present_iff (keys : List (Nat × List Entry)) (q : Nat × List Entry) :
    present keys q = true ↔ q ∈ keys := by
  simp [present, List.any_eq_true]

public def changed (x : XView) : Bool :=
  !(x.committedAfter.all (present x.committedBefore)) || possibleElection x.base.before x.base.after

private theorem raw2 [Config.InitialConfiguration] (x : XView) (no : changed x = false)
    (k : Nat) (l : List Entry) (n term : Nat) (log : List Entry) (i : Nat) :
    ReadersCompiler.R.reach_2 x k l n term log i = false := by
  have old : ∀ key ∈ x.committedAfter, key ∈ x.committedBefore := by
    simpa [changed, present_iff] using (Bool.or_eq_false_iff.mp no).1
  have election : electionExact x.base.after x.base.before x.base.past n term log i = false :=
    Bool.eq_false_iff.mpr fun yes => by
      have := possible_of_election yes
      simp [changed, this] at no
  simp only [ReadersCompiler.R.reach_2, electedExact, election, Bool.false_or]
  by_cases inAfter : (k, l) ∈ x.committedAfter
  · simp [inAfter, old _ inAfter]; grind
  · simp [inAfter]

private theorem emptyAny (xs : List α) (p : α → Bool) (empty : ∀ a, p a = false) : xs.any p = false := by
  simp [empty]

private theorem falseLeft (a b : Bool) (ha : a = false) : (a && b) = false := by simp [ha]
private theorem falseBoth (a b : Bool) (ha : a = false) (hb : b = false) : (a || b) = false := by simp [ha, hb]

local macro "no_reach" h:term : tactic => `(tactic| (repeat' first
    | rfl
    | exact raw2 _ $h _ _ _ _ _ _
    | apply emptyAny; intro a
    | apply falseLeft
    | apply falseBoth
    | split))

private theorem raw3 [Config.InitialConfiguration] (x : XView) (no : changed x = false) :
    ReadersCompiler.R.reach_3 x = false := by
  unfold ReadersCompiler.R.reach_3
  no_reach no

private theorem raw4 [Config.InitialConfiguration] (x : XView) (no : changed x = false)
    (n : NodeID) (st : NodeState) (k base i : Nat) : ReadersCompiler.R.reach_4 x n st k base i = false := by
  unfold ReadersCompiler.R.reach_4
  no_reach no

/-- If neither a commit key nor even an election transition can be new,
the expensive quantified historical reader is false before enumerating
any historical marginal. -/
public theorem raw8 [Config.InitialConfiguration] (x : XView) (no : changed x = false) :
    ReadersCompiler.R.reach_8 x = false := by
  unfold ReadersCompiler.R.reach_8
  repeat' first
    | rfl
    | exact raw3 _ no
    | exact raw4 _ no _ _ _ _ _
    | apply emptyAny; intro a
    | apply falseLeft
    | apply falseBoth
    | split

public def guarded [Config.InitialConfiguration] (x : XView) : Bool :=
  if changed x then ReadersCompiler.R.reach_8 x else false

public theorem guarded_eq [Config.InitialConfiguration] (x : XView) :
    guarded x = ReadersCompiler.R.reach_8 x := by
  unfold guarded
  split
  · rfl
  · exact (raw8 _ (Bool.eq_false_iff.mpr ‹_›)).symm

end ConsensusCoverage.CensusFresh
