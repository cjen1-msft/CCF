module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusCommitFold
import all ConsensusCoverage.CensusCommitFold
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.CommitKeys

namespace ConsensusCoverage.CensusCommitHistory

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost CensusObserved CensusCommitFold

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev SeenExact (g : Ghost) (h : List Model.State) :=
  ∀ o, o ∈ g.seen ↔ o ∈ (ReadersAtoms.histNodes h).map observe

private theorem ack_eq {g : Ghost} {h : List Model.State} (tracked : SeenExact g h)
    (s : Model.State) (k : Nat) (l : List Entry) (v : NodeID) :
    ack (seenNow g s) k l v = CommitKeys.acknowledges (s :: h) k l v := by
  apply Bool.eq_iff_iff.mpr
  simp only [ack, seenNow, List.any_eq_true, Prod.exists, mem_union, tracked, List.mem_map,
    ReadersAtoms.histNodes, List.mem_flatMap, observe, Prod.mk.injEq, Bool.and_eq_true, beq_iff_eq,
    decide_eq_true_eq, CommitKeys.acknowledges, List.any_cons, Bool.or_eq_true]
  constructor
  · rintro ⟨_, _, _, (⟨n, st, ⟨snap, hs, mem⟩, rfl, rfl, rfl⟩ |
        ⟨n, st, mem, rfl, rfl, rfl⟩), ⟨rfl, rfl⟩, pre⟩
    · exact Or.inr ⟨snap, hs, n, st, mem, rfl, rfl, pre⟩
    · exact Or.inl ⟨n, st, mem, rfl, rfl, pre⟩
  · rintro (⟨n, st, mem, rfl, rfl, pre⟩ | ⟨snap, hs, n, st, mem, rfl, rfl, pre⟩)
    · exact ⟨n, st.currentTerm, st.log, Or.inr ⟨n, st, mem, rfl, rfl, rfl⟩, ⟨rfl, rfl⟩, pre⟩
    · exact ⟨n, st.currentTerm, st.log, Or.inl ⟨n, st, ⟨snap, hs, mem⟩, rfl, rfl, rfl⟩, ⟨rfl, rfl⟩, pre⟩

/-- Exact membership, not list order or duplicate count, is required for
the previous snapshot's commit certificates. -/
public def CommitHistory (b : NodeID) (g : Ghost) (h : List Model.State) : Prop :=
  ∀ key, key ∈ g.committed ↔ key ∈ CommitKeys.keys b h

private theorem prior_eq (old past : Keys) (eq : ∀ key, key ∈ old ↔ key ∈ past)
    (st : NodeState) (base : Nat) : CommitKeys.prior old st base = CommitKeys.prior past st base := by
  apply Bool.eq_iff_iff.mpr
  simp only [CommitKeys.prior, List.any_eq_true, Prod.exists, eq]

private theorem support_iff (seen : Seen) (old : Keys) (st : NodeState) (i : Nat) :
    support seen old st i = true ↔
      ∃ base ≤ i, CommitKeys.backed old st base = true ∧ quorum seen st i base = true := by
  have nonempty (base : Nat) (yes : CommitKeys.prior old st base = true) : !old.isEmpty = true := by
    cases old <;> simp_all [CommitKeys.prior]
  simp only [support, Bool.or_eq_true, Bool.and_eq_true, List.any_eq_true, List.mem_range,
    Nat.lt_succ_iff, CommitKeys.backed, decide_eq_true_eq]
  constructor
  · rintro (zero | ⟨_, base, le, prior, voted⟩)
    · exact ⟨0, Nat.zero_le _, Or.inl rfl, zero⟩
    · exact ⟨base, le, Or.inr prior, voted⟩
  · rintro ⟨base, le, zero | prior, voted⟩
    · subst base; exact Or.inl voted
    · exact Or.inr ⟨nonempty base prior, base, le, prior, voted⟩

private theorem cert_iff {g : Ghost} {b : NodeID} {h : List Model.State}
    (tracked : SeenExact g h) (old : CommitHistory b g h) (s : Model.State) (st : NodeState) (i : Nat) :
    (signature st i = true ∧ support (seenNow g s) g.committed st i = true) ↔
      CommitKeys.certified s h (CommitKeys.backed (CommitKeys.keys b h)) st i = true := by
  rw [support_iff]
  have a : ack (seenNow g s) st.currentTerm (st.log.take i) =
      CommitKeys.acknowledges (s :: h) st.currentTerm (st.log.take i) := funext (ack_eq tracked s _ _)
  simp only [signature, CommitKeys.certified, quorum, a, CommitKeys.backed, prior_eq _ _ old,
    Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, List.any_eq_true, List.mem_range, Nat.lt_succ_iff]
  grind

private theorem add_state {b : NodeID} {g : Ghost} {h : List Model.State} (s : Model.State)
    (tracked : SeenExact g h) (old : CommitHistory b g h) (elect : ElectionHistory g (s :: h)) :
    CommitHistory b (logDelta g b s).1 (s :: h) := by
  rintro ⟨k, l⟩
  rw [committed_step, CommitKeys.keys, List.mem_eraseDups, List.mem_append, or_comm, old]
  apply or_congr_left
  simp only [CommitKeys.here, List.mem_flatMap, List.mem_filter, List.mem_map, Prod.exists, List.mem_range,
    Nat.lt_succ_iff, CommitKeys.leader, Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq,
    CensusLed.led_eq elect, GuardedDomain.ledAt, beq_iff_eq, ← cert_iff tracked old]
  constructor
  · rintro ⟨n, st, here, role, led, i, len, eq, sig, back⟩
    exact ⟨n, st, ⟨here, role, led⟩, i, ⟨len, sig, back⟩, eq.symm⟩
  · rintro ⟨n, st, ⟨here, role, led⟩, i, ⟨len, sig, back⟩, eq⟩
    exact ⟨n, st, here, role, led, i, len, eq.symm, sig, back⟩

public theorem committed_start (b : NodeID) (s : Model.State) : CommitHistory b (start b s) [s] := by
  apply add_state
  · intro o; simp [ReadersAtoms.histNodes]
  · intro key; simp [CommitKeys.keys]
  · intro n k l i
    change _ ∈ ([] : List (NodeID × Nat × List Entry × Nat)) ↔ false = true
    simp

public theorem committed_read {cfg : FullProfile.Configuration} {g : Ghost} {s t : Model.State}
    {act : Model.Action} {edge : Edge} {h : List Model.State}
    (run : ExplorerGhost.read cfg g s t act = some edge) (observed : Tracks g (s :: h))
    (old : CommitHistory (cfg.min?.getD 0) g (s :: h)) (elect : ElectionHistory edge.ghost (t :: s :: h)) :
    CommitHistory (cfg.min?.getD 0) edge.ghost (t :: s :: h) := by
  unfold ExplorerGhost.read at run
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at run
  obtain ⟨view, hv, _, _, _, _, _, _, eq⟩ := run
  cases eq
  have boot : view.bootstrap = cfg.min?.getD 0 := by
    unfold GuardedDomain.ofAction at hv
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at hv
    obtain ⟨_, _, _, _, heq⟩ := hv
    cases heq
    rfl
  simp only [boot] at elect ⊢
  exact add_state t observed.1 old elect

end ConsensusCoverage.CensusCommitHistory
