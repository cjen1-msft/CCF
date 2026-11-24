module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusCanonical
import all ConsensusCoverage.CensusCanonical
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CommitMonitor
import Init.Data.Range.Lemmas

namespace ConsensusCoverage.CensusCommitFold

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev Keys := List (Nat × List Entry)
private abbrev Seen := List (NodeID × Nat × List Entry)

private noncomputable def seenNow (g : Ghost) (s : Model.State) : Seen :=
  union g.seen (s.nodes.map CensusObserved.observe)

private noncomputable def ack (seen : Seen) (k : Nat) (l : List Entry) (v : NodeID) : Bool :=
  seen.any fun (n, term, log) => n == v && term == k && decide (l <+: log)

private noncomputable def quorum (seen : Seen) (st : NodeState) (i base : Nat) : Bool :=
  CommitMonitor.quorum ((activeConfigurations st.log base).filter (·.index ≤ i))
    (ack seen st.currentTerm (st.log.take i))

private noncomputable def support (seen : Seen) (old : Keys) (st : NodeState) (i : Nat) : Bool :=
  quorum seen st i 0 || (!old.isEmpty && (List.range (i + 1)).any fun base =>
    CommitKeys.prior old st base && quorum seen st i base)

private def signature (st : NodeState) (i : Nat) : Bool :=
  isSignatureAt st.log i && termAt st.log i == st.currentTerm

private noncomputable def addIndex (seen : Seen) (old : Keys) (st : NodeState) (ks : Keys) (i : Nat) : Keys :=
  let key := (st.currentTerm, st.log.take i)
  if signature st i && !old.contains key && support seen old st i then union ks [key] else ks

private noncomputable def addNode (g : Ghost) (seen : Seen) (b : NodeID) (ks : Keys)
    (p : NodeID × NodeState) : Keys :=
  if p.2.role != .candidate && g.led b p.1 p.2.currentTerm then
    (List.range (p.2.log.length + 1)).foldl (addIndex seen g.committed p.2) ks else ks

private theorem log_committed (g : Ghost) (b : NodeID) (s : Model.State) :
    (logDelta g b s).1.committed = s.nodes.foldl (addNode g (seenNow g s) b) g.committed := by
  unfold logDelta
  change (forIn s.nodes (g.canonical, g.committed, false, false) _ : Id (Keys × Keys × Bool × Bool)).2.1 = _
  apply CensusCanonical.fold_project (project := fun a : Keys × Keys × Bool × Bool => a.2.1)
  rintro ⟨n, st⟩ ⟨can, ks, z, p⟩
  by_cases lead : (st.role != .candidate && g.led b n st.currentTerm) = true
  · simp only [lead, ite_true, addNode]
    refine ⟨_, rfl, ?_⟩
    change (forIn [:st.log.length + 1] (ks, z, p) _ : Id (Keys × Bool × Bool)).1 = _
    rw [Std.Legacy.Range.forIn_eq_forIn_range']
    simp only [Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one, ← List.range_eq_range']
    apply CensusCanonical.fold_project (project := fun a : Keys × Bool × Bool => a.1)
    intro i ⟨ks, z, p⟩
    change ∃ out : Keys × Bool × Bool,
      (if signature st i then
        if g.committed.contains (st.currentTerm, st.log.take i) then _
        else if support (seenNow g s) g.committed st i then _ else _
       else _) = (.yield out : ForInStep _) ∧ out.1 = addIndex (seenNow g s) g.committed st ks i
    cases sig : signature st i <;> cases prior : g.committed.contains (st.currentTerm, st.log.take i)
      <;> cases back : support (seenNow g s) g.committed st i
      <;> simp only [addIndex, sig, prior, back, Bool.true_and, Bool.false_and, Bool.not_true, Bool.not_false,
        Bool.false_eq_true, ite_true, ite_false]
      <;> exact ⟨_, rfl, rfl⟩
  · simp only [lead, addNode]
    exact ⟨_, rfl, rfl⟩

private theorem mem_indices (seen : Seen) (old : Keys) (st : NodeState) (is : List Nat) (ks : Keys)
    (key : Nat × List Entry) :
    key ∈ is.foldl (addIndex seen old st) ks ↔ key ∈ ks ∨
      ∃ i ∈ is, key = (st.currentTerm, st.log.take i) ∧ signature st i = true ∧
        key ∉ old ∧ support seen old st i = true := by
  induction is generalizing ks with
  | nil => simp
  | cons i is ih =>
    rw [List.foldl_cons, ih]
    dsimp only [addIndex]
    split <;> simp only [CensusObserved.mem_union, List.mem_cons, Bool.and_eq_true,
      Bool.not_eq_true', Bool.eq_false_iff] at * <;> grind

private def produces (g : Ghost) (seen : Seen) (b : NodeID) (key : Nat × List Entry)
    (p : NodeID × NodeState) : Prop :=
  p.2.role ≠ .candidate ∧ g.led b p.1 p.2.currentTerm = true ∧
    ∃ i ≤ p.2.log.length, key = (p.2.currentTerm, p.2.log.take i) ∧
      signature p.2 i = true ∧ support seen g.committed p.2 i = true

private theorem mem_node (g : Ghost) (seen : Seen) (b : NodeID) (ks : Keys)
    (p : NodeID × NodeState) (key : Nat × List Entry) :
    key ∈ addNode g seen b ks p ↔ key ∈ ks ∨ (key ∉ g.committed ∧ produces g seen b key p) := by
  unfold addNode produces
  split
  · rename_i yes
    have lead : p.2.role ≠ .candidate ∧ g.led b p.1 p.2.currentTerm = true := by simpa using yes
    simp only [mem_indices, List.mem_range, Nat.lt_succ_iff, lead.2, true_and]
    apply or_congr_right
    constructor
    · rintro ⟨i, hi, key, sig, fresh, backing⟩
      exact ⟨fresh, lead.1, i, hi, key, sig, backing⟩
    · rintro ⟨fresh, _, i, hi, key, sig, backing⟩
      exact ⟨i, hi, key, sig, fresh, backing⟩
  · rename_i no
    simp only [Bool.and_eq_true, bne_iff_ne] at no
    grind

/-- The cumulative commit-key set produced by the actual doubly nested
fold. Processing an old key again cannot alter the membership result. -/
public theorem committed_step (g : Ghost) (b : NodeID) (s : Model.State) (key : Nat × List Entry) :
    key ∈ (logDelta g b s).1.committed ↔ key ∈ g.committed ∨
      ∃ n st, (n, st) ∈ s.nodes ∧ st.role ≠ .candidate ∧ g.led b n st.currentTerm = true ∧
        ∃ i ≤ st.log.length, key = (st.currentTerm, st.log.take i) ∧
          signature st i = true ∧ support (seenNow g s) g.committed st i = true := by
  rw [log_committed]
  have mem (ps : List (NodeID × NodeState)) (ks : Keys) :
      key ∈ ps.foldl (addNode g (seenNow g s) b) ks ↔ key ∈ ks ∨
        ∃ p ∈ ps, key ∉ g.committed ∧ produces g (seenNow g s) b key p := by
    induction ps generalizing ks with
    | nil => simp
    | cons p ps ih =>
      rw [List.foldl_cons, ih, mem_node]
      simp only [List.mem_cons]
      grind
  rw [mem]
  by_cases old : key ∈ g.committed <;> simp [old, produces]

end ConsensusCoverage.CensusCommitFold
