module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.Historical
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.DelayedNomination

open ActionProfile CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def Single (n : NodeID) (h : List Model.State) : Prop :=
  ∀ s ∈ h, ∀ {v st}, (v, st) ∈ s.nodes → v = n

private def Majorities (n : NodeID) (log : List Entry) : Prop :=
  ∀ cfg ∈ configurationHistory log, hasConfigurationMajority {n} cfg

private theorem configuration_prefix {a b : List Entry} (p : a <+: b) :
    configurationHistory a ⊆ configurationHistory b := by
  obtain ⟨rest, eq, _⟩ := configurationHistory_split b a.length
  rw [← List.prefix_iff_eq_take.mp p] at eq
  rw [eq]
  exact fun _ h => List.mem_append_left _ h

private theorem active_of_later {log : List Entry} {b : Nat} {cfg : Node.Configuration}
    (mem : cfg ∈ configurationHistory log) (later : b < cfg.index) :
    cfg ∈ activeConfigurations log b := by
  obtain ⟨j, hj, eq⟩ := List.mem_iff_getElem.mp mem
  let d := ((configurationHistory log).filter fun c => c.index ≤ b).length - 1
  have le : d ≤ j := by
    by_cases h : d ≤ j
    · exact h
    have bound : j < ((configurationHistory log).filter fun c => c.index ≤ b).length := by
      dsimp [d] at h
      omega
    have h := getElem_le_of_lt_length_filter (configurationHistory_sorted log) bound
    rw [eq] at h
    omega
  unfold activeConfigurations
  apply List.mem_iff_getElem.mpr
  refine ⟨j - d, by rw [List.length_drop]; omega, ?_⟩
  rw [List.getElem_drop]
  have idx : d + (j - d) = j := by omega
  change (configurationHistory log)[d + (j - d)] = cfg
  simpa only [idx] using eq

private theorem majority_of_observed {n : NodeID} {h : List Model.State} (one : Single n h)
    {l : List Node.Configuration} {voters : Finset NodeID}
    (quorum : hasQuorum l voters)
    (seen : ∀ v ∈ voters, ∃ st, Historical.Seen h v st)
    {cfg : Node.Configuration} (mem : cfg ∈ l) : hasConfigurationMajority {n} cfg := by
  have sub : voters ⊆ ({n} : Finset NodeID) := by
    intro v hv
    obtain ⟨_, s, inHistory, obs⟩ := seen v hv
    exact Finset.mem_singleton.mpr (one s inHistory obs)
  have sub' : voters ∩ cfg.nodes ⊆ ({n} : Finset NodeID) ∩ cfg.nodes := by
    intro v hv
    obtain ⟨inVoters, inCfg⟩ := Finset.mem_inter.mp hv
    exact Finset.mem_inter.mpr ⟨sub inVoters, inCfg⟩
  have le := Finset.card_le_card sub'
  have gt := of_decide_eq_true (List.all_eq_true.mp quorum.2 cfg mem)
  unfold hasConfigurationMajority at gt ⊢
  omega

variable [Config.InitialConfiguration]
set_option linter.unusedSectionVars false

private theorem step_majorities {n : NodeID} {h : List Model.State} {leader st k b i}
    (one : Single n h) (step : Historical.CommitStep h leader st k b i)
    (backed : Majorities n (st.log.take b)) : Majorities n (st.log.take i) := by
  intro cfg mem
  have configMem := configuration_prefix (List.take_prefix i st.log) mem
  have upper : cfg.index ≤ i := by
    have bounds := mem_history_filterMap mem
    simp only [List.length_take] at bounds
    omega
  by_cases earlier : cfg.index ≤ b
  · obtain ⟨rest, eq, later⟩ := configurationHistory_split st.log b
    rw [eq, List.mem_append] at configMem
    exact backed cfg (configMem.resolve_right fun h => (Nat.not_lt_of_ge earlier) (later cfg h))
  · obtain ⟨voters, quorum, acks⟩ := step.2.2.2.2.2
    exact majority_of_observed one quorum (fun v hv => by
      obtain ⟨x, obs, _⟩ := acks v hv
      exact ⟨x, obs⟩)
      (List.mem_filter.mpr ⟨active_of_later configMem (Nat.lt_of_not_ge earlier), decide_eq_true upper⟩)

private theorem committed_majorities {n : NodeID} {h : List Model.State} {k part}
    (commit : Historical.Committed h k part) : Single n h → Majorities n part := by
  induction commit with
  | fresh step =>
    intro one
    exact step_majorities one step (by simp [Majorities, configurationHistory])
  | chained step back le sub ih =>
    intro one
    exact step_majorities one step (fun cfg mem =>
      ih (fun s hs => one s (List.mem_cons_of_mem _ hs)) cfg (configuration_prefix sub mem))
  | past old ih =>
    exact fun one => ih (fun s hs => one s (List.mem_cons_of_mem _ hs))

private theorem singleton_base_zero {n : NodeID} {h : List Model.State} {leader st k b i}
    (one : Single n h) (id : n = leader) (step : Historical.CommitStep h leader st k b i)
    (backed : Majorities n (st.log.take b)) : Historical.CommitStep h leader st k 0 i := by
  have all := step_majorities one step backed
  obtain ⟨voters, quorum, _⟩ := step.2.2.2.2.2
  have zero : activeConfigurations st.log 0 = configurationHistory st.log := by
    unfold activeConfigurations
    have empty : ((configurationHistory st.log).filter fun c => c.index ≤ 0) = [] := by
      apply List.filter_eq_nil_iff.mpr
      intro cfg mem
      have bounds := mem_history_filterMap mem
      simp
      omega
    dsimp only
    rw [empty]
    rfl
  refine ⟨step.1, Nat.zero_le _, step.2.2.1, step.2.2.2.1, step.2.2.2.2.1, {n}, ⟨?_, ?_⟩, ?_⟩
  · intro empty
    apply quorum.1
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro cfg mem
    have m := List.mem_filter.mp mem
    have pre := (activeConfigurations_sublist st.log b).subset m.1
    have bad : cfg ∈ (activeConfigurations st.log 0).filter (·.index ≤ i) :=
      List.mem_filter.mpr ⟨zero.symm ▸ pre, m.2⟩
    simp [empty] at bad
  · apply List.all_eq_true.mpr
    intro cfg mem
    rw [zero] at mem
    obtain ⟨inLog, le⟩ := List.mem_filter.mp mem
    obtain ⟨rest, eq, later⟩ := configurationHistory_split st.log i
    rw [eq, List.mem_append] at inLog
    have inTake := inLog.resolve_right (fun h => (Nat.not_lt_of_ge (of_decide_eq_true le)) (later cfg h))
    exact decide_eq_true (all cfg inTake)
  · intro v mem
    rw [Finset.mem_singleton] at mem
    subst v n
    exact ⟨st, (show Historical.Now h leader st from step.1.1) |> fun now => by
      cases h with
      | nil => exact False.elim now
      | cons s rest => exact ⟨s, List.mem_cons_self, now⟩,
      step.1.2.1, List.take_prefix ..⟩

/-- In a singleton deployment every dropped configuration already had a
majority of the same single node. A backed certificate is thus base-zero too. -/
public theorem singleton_noNew (s : Step) (n : NodeID) (one : s.nodes = [n])
    (nodes : s.after.nodes = s.before.nodes) :
    CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply (CommitKeys.step_noNew s).2
  intro k p fresh
  change (StateCoverage.frame s.after (s.before :: s.past)).logs.committed k p at fresh
  rw [StateCoverage.frame_logs, (Historical.logFacts_correct _).committed, Historical.commit_cons] at fresh
  have single : Single n (s.after :: s.before :: s.past) := by
    intro snap inHistory v st mem
    have key := List.mem_map_of_mem (f := Prod.fst) mem
    simpa [NoBackingWitness.run_keys (.step s.run s.ran) snap inHistory, one] using key
  rcases fresh with old | ⟨leader, st, b, i, step, rfl, backed⟩
  · change (StateCoverage.frame s.before s.past).logs.committed k p
    rw [StateCoverage.frame_logs, (Historical.logFacts_correct _).committed]
    exact old
  · have id := single s.after List.mem_cons_self step.1.1
    have maj : Majorities n (st.log.take b) := by
      rcases backed with rfl | ⟨_, _, old, _, within⟩
      · simp [Majorities, configurationHistory]
      · exact fun cfg mem => committed_majorities old
          (fun snap hs => single snap (List.mem_cons_of_mem _ hs)) cfg (configuration_prefix within mem)
    have zero := singleton_base_zero single id.symm step maj
    have step_zero : CommitStep (s.frame.advance s.after) leader st k 0 i := by
      let history := s.after :: s.before :: s.past
      rw [show (s.frame.advance s.after) = StateCoverage.frame s.after (s.before :: s.past) from rfl]
      change (StateCoverage.frame s.after (s.before :: s.past)).logs.commitAt _ s.after leader st k 0 i
      rw [StateCoverage.frame_logs]
      exact (Historical.commitAt_iff (s := s.after) (h := s.before :: s.past)
        (fun n st k => by simp [history, LogFacts.Ghost.canonNow, LogFacts.Ghost.led, Historical.CanonNow,
          Historical.Led, Historical.Now, (Historical.logFacts_correct history).elected])
        (Historical.logFacts_correct history).seen _ _ _ _ _).mpr zero
    have atBefore := (BackingStutter.commitStep_iff_of_nodes s.folded.invariant
      (nodes.trans (congrArg (fun st : Model.State => st.nodes) s.current_eq).symm)).mp step_zero
    exact BackingStutter.committed_of_zero s.folded atBefore

end ConsensusCoverage.DelayedNomination

#print axioms ConsensusCoverage.DelayedNomination.singleton_noNew
