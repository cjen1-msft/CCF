module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.NoBackingWitness

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

private theorem run_keys {cfg ns s past} (run : StateCoverage.Run cfg ns s past) :
    ∀ snap ∈ s :: past, snap.nodes.map Prod.fst = ns := by
  induction run with
  | initial init =>
    intro snap mem
    rw [List.mem_singleton.mp mem]
    exact init.2.1
  | @step before hist a after _ step ih =>
    intro snap mem
    rcases List.mem_cons.mp mem with current | old
    · subst snap
      obtain ⟨tr⟩ := @LocalTransition.ofStep ⟨cfg⟩ ns before after a step
      rw [tr.nodesEq, Concrete.replaceNode_keys]
      exact ih before List.mem_cons_self
    · exact ih snap old

private theorem commit_point [Config.InitialConfiguration] {history : List Model.State}
    (backed : CommitMonitor.anyCommit Config.INITIAL_PRIMARY history = true) :
    ∃ snap rest n st k i, snap ∈ history ∧ Historical.CommitStep (snap :: rest) n st k 0 i := by
  induction history with
  | nil => simp [CommitMonitor.anyCommit] at backed
  | cons snap rest ih =>
    rw [CommitMonitor.anyCommit, Bool.or_eq_true] at backed
    rcases backed with old | fresh
    · obtain ⟨t, h, n, st, k, i, mem, commit⟩ := ih old
      exact ⟨t, h, n, st, k, i, List.mem_cons_of_mem _ mem, commit⟩
    · obtain ⟨n, st, k, i, commit⟩ := (CommitMonitor.fresh_iff snap rest).mp fresh
      exact ⟨snap, rest, n, st, k, i, List.mem_cons_self, commit⟩

-- A commit in the history would require a signature on this same node.
-- Losing that signature requires a term strictly later than its signing term.
private theorem no_commit {cfg ns s past n st} (run : StateCoverage.Run cfg ns s past)
    (singleton : s.nodes = [(n, st)]) (term : st.currentTerm ≤ BOOTSTRAP_TERM)
    (empty : st.log = []) : CommitMonitor.anyCommit (cfg.min?.getD 0) (s :: past) = false := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  apply Bool.eq_false_iff.mpr
  intro backed
  obtain ⟨snap, _, id, old, _, i, inHistory, ⟨mem, _, _, led⟩, _, _, sig, atTerm, _⟩ :=
    commit_point backed
  have key := List.mem_map_of_mem (f := Prod.fst) mem
  rw [run_keys run snap inHistory, ← run_keys run s List.mem_cons_self, singleton] at key
  have same : id = n := by simpa using key
  subst id
  have signedAt : BOOTSTRAP_TERM ≤ termAt old.log i := by
    rw [atTerm]
    rcases led with ⟨rfl, _⟩ | ⟨_, _, _, _, _, _, election⟩
    · exact Nat.le_refl _
    · obtain ⟨_, _, _, _, _, _, _, _, _, _, _, floor, _⟩ := election
      exact Nat.le_trans (by decide : BOOTSTRAP_TERM ≤ 3) floor
  have seen : Seen (StateCoverage.frame s past) n (observe old) := by
    change (StateCoverage.frame s past).logs.seen n old.currentTerm old.log
    rw [StateCoverage.frame_logs]
    exact ((Historical.logFacts_correct (s :: past)).seen _ _ _).mpr
      ⟨old, ⟨snap, inHistory, mem⟩, rfl, rfl⟩
  have now : Now (StateCoverage.frame s past) n st := by
    simp [Now, StateCoverage.frame_current, singleton]
  rcases (StateCoverage.run_inv run).persist n st (observe old) i now seen sig with
    kept | ⟨later, _, newer, bounded, _, _⟩
  · have inEmpty : isSignatureAt st.log i = true :=
      Ledger.isSignatureAt_of_prefix kept (Ledger.isSignatureAt_take_of_le (Nat.le_refl i) sig)
    simp [empty, isSignatureAt, entryAt?] at inEmpty
  · change termAt old.log i < later at newer
    omega

private abbrev witnessCfg : CCF.Finset NodeID := {0, 1}

private def followerSnapshot : Model.State :=
  {nodes := [(1, initialNodeState witnessCfg 1)]}

/-- The initial singleton follower has exactly the unbacked zero-index profile.
The initializing run uses configuration `{0, 1}`; the exclusion of backing
holds for every configuration, node list, and history reaching this snapshot. -/
public theorem exists_unbacked :
    ∃ s : Model.State, s.nodes ≠ [] ∧ (∃ cfg ns past, StateCoverage.Run cfg ns s past) ∧
      ∀ {cfg ns past}, StateCoverage.Run cfg ns s past → StateCoverage.read cfg s past = (true, false) := by
  refine ⟨followerSnapshot, List.cons_ne_nil _ _, ⟨witnessCfg, [1], [], .initial ?_⟩, ?_⟩
  · refine ⟨⟨0, by decide⟩, ?_, ?_⟩ <;> simp [followerSnapshot, protocol]
  · intro cfg ns past run
    have unbacked := no_commit run (rfl : followerSnapshot.nodes = [(1, initialNodeState witnessCfg 1)])
      (by decide) (by rfl)
    rw [StateCoverage.read, unbacked]
    rfl

end ConsensusCoverage.NoBackingWitness
